#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DADEREZO — Collecteur réseau local (100 % lecture seule).

Compatible Windows, Linux / Raspberry Pi et macOS :
- Découvre l'interface active, l'IP locale, le masque, la passerelle, la MAC et les DNS
- Lit la table ARP / voisins (et balaye optionnellement le sous-réseau en ping lecture seule)
- Teste en parallèle la disponibilité et la latence des équipements locaux
- Vérifie la sortie Internet (distinction panne locale vs panne FAI)
- Persiste l'inventaire dans SQLite pour éviter les fausses alertes en boucle
"""
import argparse
import ipaddress
import json
import os
import platform
import re
import socket
import sqlite3
import subprocess
import time
import urllib.request
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from typing import Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "daderezo.db")
OUT = os.path.join(HERE, "logs.json")
LOG = os.path.join(HERE, "collector.log")
CONFIG_PATH = os.path.join(HERE, "devices.json")

IS_WINDOWS = platform.system().lower() == "windows"
IS_DARWIN = platform.system().lower() == "darwin"

DEFAULT_CONFIG = {
    "site_name": "Communauté Sainte Marie de Bouaké",
    "internet_targets": ["1.1.1.1", "8.8.8.8"],
    "https_check_url": "https://github.com",
    "dns_check_host": "github.com",
    "fail_threshold": 2,
    "devices": {
        "192.168.8.1": {
            "name": "Box FAI principale",
            "type": "fai_box",
            "zone": "Accès FAI",
            "critical": true if False else True,
        }
    },
    "authorized_macs": {},
}


def now() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_config(config_path: str = CONFIG_PATH) -> dict:
    cfg = dict(DEFAULT_CONFIG)
    if os.path.exists(config_path):
        try:
            with open(config_path, "r", encoding="utf-8") as f:
                user_cfg = json.load(f)
            if isinstance(user_cfg, dict):
                cfg.update(user_cfg)
        except Exception:
            pass
    return cfg


def normalize_mac(raw: Optional[str]) -> Optional[str]:
    if not raw:
        return None
    cleaned = raw.strip().replace("-", ":").lower()
    if re.fullmatch(r"([0-9a-f]{2}:){5}[0-9a-f]{2}", cleaned):
        if cleaned in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
            return None
        return cleaned
    return None


def run_cmd(cmd: List[str], timeout: int = 15) -> Tuple[int, str]:
    enc = "cp850" if IS_WINDOWS else "utf-8"
    try:
        r = subprocess.run(
            cmd,
            capture_output=True,
            timeout=timeout,
        )
        raw = r.stdout or b""
        try:
            text = raw.decode("utf-8")
        except UnicodeDecodeError:
            text = raw.decode(enc, errors="replace")
        return r.returncode, text
    except Exception:
        return 1, ""


def prefix_to_netmask(prefix_len: int) -> str:
    return str(ipaddress.IPv4Network(f"0.0.0.0/{prefix_len}").netmask)


def parse_windows_ipconfig(ipconfig_out: str, route_out: str = "") -> dict:
    """Extrait la configuration réseau Windows par carte en privilégiant celle qui a une passerelle."""
    adapters = []
    current = {"ip": None, "mask": None, "gw": None, "dns": [], "mac": None}

    for line in ipconfig_out.splitlines():
        if line and not line.startswith(" ") and not line.startswith("\t") and line.rstrip().endswith(":"):
            if current["ip"] or current["mac"] or current["gw"]:
                adapters.append(current)
            current = {"ip": None, "mask": None, "gw": None, "dns": [], "mac": None}
            continue

        low = line.lower()
        if "adresse ipv4" in low or "ipv4 address" in low or "ip address" in low:
            m = re.search(r":\s*([\d.]+)", line)
            if m and not current["ip"]:
                current["ip"] = m.group(1)
        elif "masque de sous" in low or "subnet mask" in low:
            m = re.search(r":\s*([\d.]+)", line)
            if m and not current["mask"]:
                current["mask"] = m.group(1)
        elif "passerelle par" in low or "default gateway" in low:
            m = re.search(r":\s*([\d.]+)", line)
            if m and not current["gw"]:
                current["gw"] = m.group(1)
        elif "serveurs dns" in low or "dns servers" in low:
            m = re.search(r":\s*([\d.]+)", line)
            if m:
                current["dns"].append(m.group(1))
        elif "adresse physique" in low or "physical address" in low:
            m = re.search(r":\s*([0-9a-fA-F:-]{17})", line)
            if m and not current["mac"]:
                current["mac"] = normalize_mac(m.group(1))

    if current["ip"] or current["mac"] or current["gw"]:
        adapters.append(current)

    chosen = None
    for ad in adapters:
        if ad["ip"] and ad["gw"] and not ad["ip"].startswith("127."):
            chosen = ad
            break
    if not chosen:
        for ad in adapters:
            if ad["ip"] and not ad["ip"].startswith("127.") and not ad["ip"].startswith("169.254."):
                chosen = ad
                break
    if not chosen:
        for ad in adapters:
            if ad["ip"]:
                chosen = ad
                break
    info = chosen or {"ip": None, "mask": None, "gw": None, "dns": [], "mac": None}

    if not info["gw"] and route_out:
        for line in route_out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                if re.fullmatch(r"[\d.]+", parts[2]):
                    info["gw"] = parts[2]
                    break
    return info


def parse_linux_ip(addr_out: str, route_out: str, link_out: str = "", resolv_out: str = "") -> dict:
    """Extrait la configuration réseau Linux (`ip route`, `ip -4 addr`, `ip link`, `/etc/resolv.conf`)."""
    info = {"ip": None, "mask": None, "gw": None, "dns": [], "mac": None}
    primary_dev = None

    for line in route_out.splitlines():
        if line.startswith("default"):
            m_gw = re.search(r"via\s+([\d.]+)", line)
            m_dev = re.search(r"dev\s+(\S+)", line)
            if m_gw and not info["gw"]:
                info["gw"] = m_gw.group(1)
            if m_dev and not primary_dev:
                primary_dev = m_dev.group(1)
            if info["gw"]:
                break

    iface_ips: Dict[str, Tuple[str, str]] = {}
    current_iface = None
    for line in addr_out.splitlines():
        m_hdr = re.match(r"^\d+:\s+([^:@\s]+)", line)
        if m_hdr:
            current_iface = m_hdr.group(1)
            continue
        if current_iface and "inet " in line:
            m_inet = re.search(r"inet\s+([\d.]+)/(\d+)", line)
            if m_inet:
                ip_val = m_inet.group(1)
                prefix = int(m_inet.group(2))
                if not ip_val.startswith("127.") and current_iface not in iface_ips:
                    iface_ips[current_iface] = (ip_val, prefix_to_netmask(prefix))

    chosen_iface = primary_dev if primary_dev in iface_ips else (next(iter(iface_ips), None))
    if chosen_iface and chosen_iface in iface_ips:
        info["ip"], info["mask"] = iface_ips[chosen_iface]

    if link_out:
        cur_link = None
        mac_by_iface: Dict[str, str] = {}
        for line in link_out.splitlines():
            m_hdr = re.match(r"^\d+:\s+([^:@\s]+)", line)
            if m_hdr:
                cur_link = m_hdr.group(1)
                continue
            if cur_link and "link/ether" in line:
                m_mac = re.search(r"link/ether\s+([0-9a-fA-F:]{17})", line)
                if m_mac:
                    norm = normalize_mac(m_mac.group(1))
                    if norm:
                        mac_by_iface[cur_link] = norm
        target_if = chosen_iface or primary_dev
        if target_if and target_if in mac_by_iface:
            info["mac"] = mac_by_iface[target_if]
        elif mac_by_iface:
            info["mac"] = next(iter(mac_by_iface.values()))

    for line in resolv_out.splitlines():
        line = line.strip()
        if line.startswith("nameserver"):
            parts = line.split()
            if len(parts) >= 2 and re.fullmatch(r"[\d.]+", parts[1]):
                info["dns"].append(parts[1])

    return info


def local_info() -> dict:
    """Détecte l'IP locale, le masque, la passerelle, les DNS et l'adresse MAC."""
    if IS_WINDOWS:
        _, ip_out = run_cmd(["ipconfig", "/all"])
        _, route_out = run_cmd(["route", "print", "-4"])
        info = parse_windows_ipconfig(ip_out, route_out)
    else:
        _, addr_out = run_cmd(["ip", "-4", "addr", "show"])
        _, route_out = run_cmd(["ip", "route", "show", "default"])
        _, link_out = run_cmd(["ip", "link", "show"])
        resolv_out = ""
        if os.path.exists("/etc/resolv.conf"):
            try:
                with open("/etc/resolv.conf", "r", encoding="utf-8", errors="replace") as f:
                    resolv_out = f.read()
            except Exception:
                pass
        info = parse_linux_ip(addr_out, route_out, link_out, resolv_out)

        # Fallback macOS / BSD (`ifconfig` + `netstat -rn`)
        if not info["ip"] and IS_DARWIN:
            _, ifc = run_cmd(["ifconfig"])
            m_ip = re.search(r"inet\s+(?!127\.)([\d.]+)", ifc)
            if m_ip:
                info["ip"] = m_ip.group(1)
            _, rn = run_cmd(["netstat", "-rn"])
            for line in rn.splitlines():
                parts = line.split()
                if len(parts) >= 2 and parts[0] == "default" and re.fullmatch(r"[\d.]+", parts[1]):
                    info["gw"] = parts[1]
                    break

    # Fallback universel sans paquet envoyé (socket UDP non connecté)
    if not info["ip"]:
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
            s.connect(("8.8.8.8", 80))
            info["ip"] = s.getsockname()[0]
            s.close()
        except Exception:
            pass

    return info


def parse_arp_output(text: str) -> Dict[str, Optional[str]]:
    """Extrait {ip: mac} depuis `arp -a`, `ip neigh` ou `/proc/net/arp`."""
    mapping: Dict[str, Optional[str]] = {}
    for line in text.splitlines():
        m_ip = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", line)
        if not m_ip:
            continue
        ip = m_ip.group(1)
        try:
            addr = ipaddress.IPv4Address(ip)
            if addr.is_multicast or addr.is_loopback or ip.endswith(".255") or ip == "255.255.255.255":
                continue
        except ValueError:
            continue
        m_mac = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
        mac = normalize_mac(m_mac.group(0)) if m_mac else None
        if ip not in mapping or (mac and not mapping[ip]):
            mapping[ip] = mac
    return mapping


def read_arp_table() -> Dict[str, Optional[str]]:
    """Lit la table ARP / voisins en une seule passe."""
    combined = []
    if IS_WINDOWS:
        _, out = run_cmd(["arp", "-a"])
        combined.append(out)
    else:
        rc, out = run_cmd(["ip", "neigh", "show"])
        if rc == 0 and out:
            combined.append(out)
        if os.path.exists("/proc/net/arp"):
            try:
                with open("/proc/net/arp", "r", encoding="utf-8", errors="replace") as f:
                    combined.append(f.read())
            except Exception:
                pass
        if not combined:
            _, out_arp = run_cmd(["arp", "-an"])
            combined.append(out_arp)
    return parse_arp_output("\n".join(combined))


def ping_host(ip: str, timeout_ms: int = 1500) -> Tuple[bool, Optional[float]]:
    """Effectue un ping unique en lecture seule et mesure la latence en ms."""
    if IS_WINDOWS:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip]
    elif IS_DARWIN:
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip]
    else:
        wait_sec = max(1, int(round(timeout_ms / 1000.0)))
        cmd = ["ping", "-c", "1", "-W", str(wait_sec), ip]

    t0 = time.perf_counter()
    rc, out = run_cmd(cmd, timeout=max(4, int(timeout_ms / 1000) + 3))
    elapsed_ms = round((time.perf_counter() - t0) * 1000.0, 2)
    if rc != 0:
        return False, None

    # Extraction RTT précise depuis la sortie de ping
    m_rtt = re.search(r"(?:time|temps)\s*[=<]\s*([\d.,]+)\s*ms", out, re.IGNORECASE)
    if m_rtt:
        try:
            return True, round(float(m_rtt.group(1).replace(",", ".")), 2)
        except ValueError:
            pass
    return True, elapsed_ms


def tcp_probe(ip: str, ports: Tuple[int, ...] = (53, 80, 443), timeout: float = 0.8) -> Tuple[bool, Optional[float]]:
    """Sonde TCP SYN/connect en lecture seule (utile si un routeur bloque le ping ICMP)."""
    for port in ports:
        try:
            t0 = time.perf_counter()
            with socket.create_connection((ip, port), timeout=timeout):
                rtt = round((time.perf_counter() - t0) * 1000.0, 2)
                return True, rtt
        except ConnectionRefusedError:
            # RST reçu = la pile IP de l'équipement est bien active sur le réseau !
            rtt = round((time.perf_counter() - t0) * 1000.0, 2)
            return True, rtt
        except Exception:
            continue
    return False, None


def same_subnet(ip_a: Optional[str], ip_b: Optional[str], mask: Optional[str]) -> bool:
    if not ip_a or not ip_b or not mask:
        return False
    try:
        net = ipaddress.IPv4Network(f"{ip_a}/{mask}", strict=False)
        return ipaddress.IPv4Address(ip_b) in net
    except ValueError:
        return False


def sweep_subnet(local_ip: Optional[str], mask: Optional[str], max_hosts: int = 254) -> None:
    """Balayage léger en lecture seule (ping court parallèle) pour peupler le cache ARP."""
    if not local_ip or not mask:
        return
    try:
        net = ipaddress.IPv4Network(f"{local_ip}/{mask}", strict=False)
    except ValueError:
        return
    hosts = [str(h) for h in net.hosts()]
    if len(hosts) > max_hosts:
        return
    with ThreadPoolExecutor(max_workers=32) as pool:
        list(pool.map(lambda h: ping_host(h, timeout_ms=500), hosts))


def check_internet(cfg: dict) -> dict:
    """Vérifie la connectivité Internet (ICMP + repli HTTPS/DNS en lecture seule)."""
    targets = cfg.get("internet_targets") or ["1.1.1.1", "8.8.8.8"]
    for target in targets:
        ok, rtt = ping_host(target, timeout_ms=1500)
        if ok:
            return {"status": "up", "latency_ms": rtt, "method": f"icmp:{target}"}

    # Repli HTTPS HEAD (utile lorsque l'ICMP sortant est filtré par le routeur/pare-feu)
    https_url = cfg.get("https_check_url") or "https://github.com"
    try:
        t0 = time.perf_counter()
        req = urllib.request.Request(https_url, method="HEAD", headers={"User-Agent": "DADEREZO-Probe/2.0"})
        with urllib.request.urlopen(req, timeout=4) as _:
            rtt = round((time.perf_counter() - t0) * 1000.0, 2)
            return {"status": "up", "latency_ms": rtt, "method": f"https:{https_url}"}
    except Exception:
        pass

    # Dernier repli : résolution DNS uniquement
    dns_host = cfg.get("dns_check_host")
    if dns_host:
        try:
            t0 = time.perf_counter()
            socket.getaddrinfo(dns_host, 443)
            rtt = round((time.perf_counter() - t0) * 1000.0, 2)
            return {"status": "degraded", "latency_ms": rtt, "method": f"dns:{dns_host}"}
        except Exception:
            pass

    return {"status": "down", "latency_ms": None, "method": "none"}


def classify_device(ip: str, mac: Optional[str], gateway: Optional[str], local_ip: Optional[str], cfg: dict) -> dict:
    devices_cfg = cfg.get("devices") or {}
    auth_macs = {normalize_mac(k): v for k, v in (cfg.get("authorized_macs") or {}).items() if normalize_mac(k)}

    if ip in devices_cfg:
        meta = devices_cfg[ip]
        return {
            "name": meta.get("name") or f"Équipement {ip}",
            "type": meta.get("type") or ("gateway" if ip == gateway else "host"),
            "zone": meta.get("zone") or "Réseau local",
            "critical": bool(meta.get("critical", ip == gateway)),
            "authorized": True,
        }
    if mac and mac in auth_macs:
        meta = auth_macs[mac] if isinstance(auth_macs[mac], dict) else {"name": str(auth_macs[mac])}
        return {
            "name": meta.get("name") or f"Poste {ip}",
            "type": meta.get("type") or "host",
            "zone": meta.get("zone") or "Autorisé",
            "critical": bool(meta.get("critical", False)),
            "authorized": True,
        }
    if ip == gateway:
        return {
            "name": "Passerelle par défaut",
            "type": "gateway",
            "zone": "Cœur réseau",
            "critical": True,
            "authorized": True,
        }
    if ip == local_ip:
        return {
            "name": f"Sonde DADEREZO ({platform.node() or 'local'})",
            "type": "probe",
            "zone": "Supervision",
            "critical": False,
            "authorized": True,
        }
    return {
        "name": f"Poste {ip}",
        "type": "host",
        "zone": "Réseau local",
        "critical": False,
        "authorized": False,
    }


def _ensure_column(conn: sqlite3.Connection, table: str, column: str, col_def: str) -> None:
    cols = {row[1] for row in conn.execute(f"PRAGMA table_info({table})").fetchall()}
    if column not in cols:
        conn.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")


def init_db(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS probes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            ip TEXT,
            mac TEXT,
            name TEXT,
            status TEXT,
            type TEXT,
            latency_ms REAL
        )
        """
    )
    _ensure_column(conn, "probes", "name", "TEXT")
    _ensure_column(conn, "probes", "latency_ms", "REAL")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            severity TEXT,
            message TEXT,
            synced INTEGER DEFAULT 0
        )
        """
    )
    _ensure_column(conn, "alerts", "synced", "INTEGER DEFAULT 0")

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS state (
            key TEXT PRIMARY KEY,
            value TEXT
        )
        """
    )

    conn.execute(
        """
        CREATE TABLE IF NOT EXISTS known_devices (
            key TEXT PRIMARY KEY,
            ip TEXT,
            mac TEXT,
            name TEXT,
            type TEXT,
            zone TEXT,
            authorized INTEGER DEFAULT 0,
            first_seen TEXT,
            last_seen TEXT,
            last_status TEXT,
            fail_count INTEGER DEFAULT 0,
            alerted_down INTEGER DEFAULT 0
        )
        """
    )
    conn.commit()


def log_alert(conn: sqlite3.Connection, severity: str, message: str, ts: Optional[str] = None) -> None:
    conn.execute(
        "INSERT INTO alerts(ts, severity, message, synced) VALUES(?, ?, ?, 0)",
        (ts or now(), severity, message),
    )


def mark_alerts_synced(alert_ids: List[int], db_path: str = DB) -> None:
    if not alert_ids or not os.path.exists(db_path):
        return
    conn = sqlite3.connect(db_path)
    try:
        placeholders = ",".join("?" for _ in alert_ids)
        conn.execute(f"UPDATE alerts SET synced = 1 WHERE id IN ({placeholders})", list(alert_ids))
        conn.commit()
    finally:
        conn.close()


def collect(
    db_path: str = DB,
    out_path: str = OUT,
    log_path: str = LOG,
    config_path: str = CONFIG_PATH,
    do_sweep: bool = False,
) -> dict:
    cfg = load_config(config_path)
    fail_threshold = max(1, int(cfg.get("fail_threshold", 2)))
    ts = now()

    conn = sqlite3.connect(db_path)
    conn.row_factory = sqlite3.Row
    try:
        init_db(conn)
        info = local_info()
        local_ip = info.get("ip")
        mask = info.get("mask")
        gateway = info.get("gw")
        local_mac = info.get("mac")

        if do_sweep or os.environ.get("DADEREZO_SWEEP") == "1":
            sweep_subnet(local_ip, mask)

        arp_map = read_arp_table()
        if local_ip and local_mac:
            arp_map[local_ip] = local_mac

        # Construction de la liste unique d'adresses IP à sonder
        target_ips: List[str] = []
        seen_ips = set()

        def add_target(ip_candidate: Optional[str]) -> None:
            if ip_candidate and ip_candidate not in seen_ips:
                seen_ips.add(ip_candidate)
                target_ips.append(ip_candidate)

        add_target(gateway)
        add_target(local_ip)
        for cfg_ip, meta in (cfg.get("devices") or {}).items():
            if meta.get("always_probe") or same_subnet(local_ip, cfg_ip, mask) or cfg_ip == gateway:
                add_target(cfg_ip)
        for arp_ip in sorted(arp_map.keys()):
            add_target(arp_ip)

        # Sondage parallèle rapide en lecture seule
        ping_results: Dict[str, Tuple[bool, Optional[float]]] = {}
        if target_ips:
            with ThreadPoolExecutor(max_workers=min(16, len(target_ips))) as pool:
                future_map = {
                    pool.submit(ping_host, ip): ip
                    for ip in target_ips
                }
                for fut in as_completed(future_map):
                    ip = future_map[fut]
                    try:
                        ping_results[ip] = fut.result()
                    except Exception:
                        ping_results[ip] = (False, None)

        # Vérification sortie Internet (WAN) en amont pour qualifier l'état réel de la passerelle
        wan = check_internet(cfg)

        # Rafraîchir le cache ARP après les pings et le test WAN pour récupérer les MAC résolues
        post_arp = read_arp_table()
        arp_map.update({k: v for k, v in post_arp.items() if v})
        if local_ip and local_mac:
            arp_map[local_ip] = local_mac

        probes = []
        for ip in target_ips:
            is_up, rtt = ping_results.get(ip, (False, None))
            mac = arp_map.get(ip)
            meta = classify_device(ip, mac, gateway, local_ip, cfg)
            # Le poste local est toujours actif si son interface est montée
            if ip == local_ip and not is_up:
                is_up, rtt = True, 0.1
            # Repli TCP lecture seule pour les équipements critiques qui filtrent l'ICMP
            if not is_up and meta["critical"]:
                tcp_ok, tcp_rtt = tcp_probe(ip)
                if tcp_ok:
                    is_up, rtt = True, tcp_rtt
                elif ip == gateway and wan["status"] == "up" and mac:
                    # La passerelle a routé le trafic Internet avec succès mais ignore l'ICMP direct
                    is_up, rtt = True, wan["latency_ms"]
            status = "up" if is_up else "down"
            probe_entry = {
                "ip": ip,
                "mac": mac,
                "name": meta["name"],
                "zone": meta["zone"],
                "status": status,
                "type": meta["type"],
                "latency_ms": rtt,
            }
            probes.append(probe_entry)

            conn.execute(
                "INSERT INTO probes(ts, ip, mac, name, status, type, latency_ms) VALUES(?, ?, ?, ?, ?, ?, ?)",
                (ts, ip, mac, meta["name"], status, meta["type"], rtt),
            )

            # Gestion d'inventaire persistant et déduplication d'alertes
            dev_key = mac if mac else f"ip:{ip}"
            existing = conn.execute("SELECT * FROM known_devices WHERE key = ?", (dev_key,)).fetchone()
            threshold = 1 if meta["critical"] else fail_threshold

            if existing is None:
                fail_count = 0 if status == "up" else 1
                alerted_down = 0
                if mac and not meta["authorized"]:
                    log_alert(conn, "nouveau", f"Nouvel appareil détecté : {ip} ({mac})", ts)
                if status == "down" and fail_count >= threshold:
                    sev = "critique" if meta["critical"] else "panne"
                    log_alert(conn, sev, f"Équipement hors ligne : {meta['name']} ({ip})", ts)
                    alerted_down = 1
                conn.execute(
                    """
                    INSERT INTO known_devices
                    (key, ip, mac, name, type, zone, authorized, first_seen, last_seen, last_status, fail_count, alerted_down)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                    """,
                    (
                        dev_key,
                        ip,
                        mac,
                        meta["name"],
                        meta["type"],
                        meta["zone"],
                        1 if meta["authorized"] else 0,
                        ts,
                        ts if status == "up" else None,
                        status,
                        fail_count,
                        alerted_down,
                    ),
                )
            else:
                prev_fail = int(existing["fail_count"] or 0)
                alerted_down = int(existing["alerted_down"] or 0)
                if status == "up":
                    if alerted_down == 1:
                        log_alert(conn, "retabli", f"Équipement rétabli : {meta['name']} ({ip})", ts)
                    fail_count = 0
                    alerted_down = 0
                    last_seen_val = ts
                else:
                    fail_count = prev_fail + 1
                    last_seen_val = existing["last_seen"]
                    if fail_count >= threshold and alerted_down == 0:
                        sev = "critique" if meta["critical"] else "panne"
                        log_alert(conn, sev, f"Équipement hors ligne : {meta['name']} ({ip})", ts)
                        alerted_down = 1

                conn.execute(
                    """
                    UPDATE known_devices
                    SET ip = ?, mac = COALESCE(?, mac), name = ?, type = ?, zone = ?,
                        last_seen = ?, last_status = ?, fail_count = ?, alerted_down = ?
                    WHERE key = ?
                    """,
                    (
                        ip,
                        mac,
                        meta["name"],
                        meta["type"],
                        meta["zone"],
                        last_seen_val,
                        status,
                        fail_count,
                        alerted_down,
                        dev_key,
                    ),
                )

        # Alertes de transition sur la sortie Internet (WAN)
        prev_wan_row = conn.execute("SELECT value FROM state WHERE key = 'internet_status'").fetchone()
        prev_wan = prev_wan_row["value"] if prev_wan_row else None
        gw_probe = next((p for p in probes if p["ip"] == gateway), None)
        gw_status = gw_probe["status"] if gw_probe else "unknown"
        gw_latency = gw_probe["latency_ms"] if gw_probe else None

        if wan["status"] == "down" and prev_wan != "down":
            if gw_status == "up":
                log_alert(
                    conn,
                    "panne",
                    f"Passerelle locale active ({gateway}) mais accès Internet coupé (panne FAI probable)",
                    ts,
                )
            elif gateway:
                log_alert(
                    conn,
                    "critique",
                    f"Coupure réseau complète : passerelle ({gateway}) et Internet injoignables",
                    ts,
                )
        elif wan["status"] == "up" and prev_wan == "down":
            log_alert(conn, "retabli", "Accès Internet rétabli", ts)

        state_pairs = {
            "site_name": cfg.get("site_name", "Sainte Marie de Bouaké"),
            "ip_local": local_ip,
            "mask": mask,
            "gw": gateway,
            "mac_local": local_mac,
            "dns": ", ".join(info.get("dns") or []),
            "gw_status": gw_status,
            "gw_latency_ms": str(gw_latency) if gw_latency is not None else "",
            "internet_status": wan["status"],
            "wan_latency_ms": str(wan["latency_ms"]) if wan["latency_ms"] is not None else "",
            "wan_method": wan["method"],
            "last_scan": ts,
        }
        for k, v in state_pairs.items():
            conn.execute("INSERT OR REPLACE INTO state(key, value) VALUES(?, ?)", (k, v))

        # Rétention automatique de la table historique `probes` (max 5000 entrées locales)
        conn.execute(
            "DELETE FROM probes WHERE id NOT IN (SELECT id FROM probes ORDER BY id DESC LIMIT 5000)"
        )
        conn.commit()

        recent_alerts = [
            {"id": r["id"], "ts": r["ts"], "severity": r["severity"], "message": r["message"]}
            for r in conn.execute("SELECT id, ts, severity, message FROM alerts ORDER BY id DESC LIMIT 30").fetchall()
        ]
        unsynced_alerts = [
            {"id": r["id"], "ts": r["ts"], "severity": r["severity"], "message": r["message"]}
            for r in conn.execute(
                "SELECT id, ts, severity, message FROM alerts WHERE synced = 0 ORDER BY id ASC LIMIT 100"
            ).fetchall()
        ]
    finally:
        conn.close()

    out = {
        "ts": ts,
        "site_name": cfg.get("site_name", "Sainte Marie de Bouaké"),
        "ip_local": info.get("ip"),
        "mask": info.get("mask"),
        "gw": info.get("gw"),
        "dns": info.get("dns") or [],
        "mac_local": info.get("mac"),
        "gw_status": gw_status,
        "gw_latency_ms": gw_latency,
        "internet_status": wan["status"],
        "wan_latency_ms": wan["latency_ms"],
        "probes": probes,
        "alerts": recent_alerts,
        "unsynced_alerts": unsynced_alerts,
    }

    with open(out_path, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)

    with open(log_path, "a", encoding="utf-8") as f:
        f.write(
            f"{ts} | gw={gw_status} | internet={wan['status']} | postes={len(probes)} | nouvelles_alertes={len(unsynced_alerts)}\n"
        )

    return out


def main() -> None:
    parser = argparse.ArgumentParser(description="DADEREZO — Collecteur réseau local (lecture seule)")
    parser.add_argument("--sweep", action="store_true", help="Balayer le sous-réseau en ping court avant lecture ARP")
    parser.add_argument("--quiet", action="store_true", help="Ne pas afficher le JSON sur la sortie standard")
    args = parser.parse_args()

    result = collect(do_sweep=args.sweep)
    if not args.quiet:
        print(json.dumps(result, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
