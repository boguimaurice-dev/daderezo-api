#!/usr/bin/env python3
# DADEREZO - collecteur local, lecture seule
import sqlite3, subprocess, json, re, os
from datetime import datetime, timezone

HERE = os.path.dirname(os.path.abspath(__file__))
DB = os.path.join(HERE, "daderezo.db")
OUT = os.path.join(HERE, "logs.json")
LOG = os.path.join(HERE, "collector.log")

KNOWN_MACS = set()

# Inventaire des équipements connus
KNOWN_DEVICES = {
    "192.168.8.1": {"name": "Box FAI principale", "type": "fai_box"},
}


def now():
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def run_cmd(cmd):
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=30, encoding="cp1252", errors="replace")
        return r.stdout
    except Exception:
        return ""


def local_info():
    out = run_cmd(["ipconfig", "/all"])
    info = {"ip": None, "mask": None, "gw": None, "dns": [], "mac": None}
    for line in out.splitlines():
        low = line.lower()
        if "adresse ipv4" in low or "ipv4 address" in low or "ip address" in low:
            m = re.search(r":\s*([\d.]+)", line)
            if m and not info["ip"]:
                info["ip"] = m.group(1)
        if "masque de sous" in low or "subnet mask" in low:
            m = re.search(r":\s*([\d.]+)", line)
            if m and not info["mask"]:
                info["mask"] = m.group(1)
        if "passerelle par" in low or "default gateway" in low:
            m = re.search(r":\s*([\d.]+)", line)
            if m and not info["gw"]:
                info["gw"] = m.group(1)
        if "serveurs dns" in low or "dns servers" in low:
            m = re.search(r":\s*([\d.]+)", line)
            if m:
                info["dns"].append(m.group(1))
        if "adresse physique" in low or "physical address" in low:
            m = re.search(r":\s*([0-9a-fA-F-]{17})", line)
            if m and not info["mac"]:
                info["mac"] = m.group(1).replace("-", ":").lower()
    # Fallback: get IPv4 gateway from routing table
    if not info["gw"]:
        route_out = run_cmd(["route", "print"])
        for line in route_out.splitlines():
            parts = line.split()
            if len(parts) >= 4 and parts[0] == "0.0.0.0" and parts[1] == "0.0.0.0":
                info["gw"] = parts[2]
                break
    return info


def probe_device(ip):
    r = subprocess.run(["ping", "-n", "1", "-w", "2000", ip],
                       capture_output=True, text=True, timeout=10, encoding="cp1252", errors="replace")
    status = "up" if r.returncode == 0 else "down"
    mac = None
    arp_out = run_cmd(["arp", "-a"])
    for line in arp_out.splitlines():
        if ip in line:
            m = re.search(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}", line)
            if m:
                mac = m.group(0).replace("-", ":").lower()
                break
    gw = local_info().get("gw")
    if ip in KNOWN_DEVICES:
        dtype = KNOWN_DEVICES[ip]["type"]
    elif ip == gw:
        dtype = "gateway"
    else:
        dtype = "host"
    return {"ip": ip, "mac": mac, "status": status, "type": dtype}


def scan_local():
    ips = set()
    out = run_cmd(["arp", "-a"])
    for line in out.splitlines():
        m = re.search(r"(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})", line)
        if m:
            ip = m.group(1)
            if not ip.endswith(".255") and not ip.startswith("224.") and not ip.startswith("239."):
                ips.add(ip)
    return list(ips)


def log_alert(conn, severity, message):
    conn.execute("INSERT INTO alerts(ts,severity,message) VALUES(?,?,?)",
                 (now(), severity, message))


def init_db(conn):
    conn.execute("""
        CREATE TABLE IF NOT EXISTS probes (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            ip TEXT,
            mac TEXT,
            status TEXT,
            type TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS alerts (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            ts TEXT,
            severity TEXT,
            message TEXT
        )
    """)
    conn.execute("""
        CREATE TABLE IF NOT EXISTS state (
            key TEXT PRIMARY KEY,
            value TEXT
        )
    """)
    conn.commit()


def main():
    conn = sqlite3.connect(DB)
    init_db(conn)
    info = local_info()
    gateway = info.get("gw")
    probes = []
    if gateway:
        probes.append(probe_device(gateway))
    local_ip = info.get("ip")
    if local_ip:
        probes.append(probe_device(local_ip))
    if gateway:
        for ip in scan_local():
            if ip != gateway and ip != local_ip:
                probes.append(probe_device(ip))
    for p in probes:
        conn.execute("INSERT INTO probes(ts,ip,mac,status,type) VALUES(?,?,?,?,?)",
                     (now(), p["ip"], p["mac"], p["status"], p["type"]))
    for p in probes:
        if p["mac"] and p["mac"] not in KNOWN_MACS:
            KNOWN_MACS.add(p["mac"])
            log_alert(conn, "nouveau", f"Nouvel appareil détecté: {p['ip']} ({p['mac']})")
    conn.execute("INSERT OR REPLACE INTO state(key,value) VALUES('ip_local',?)", (info.get("ip"),))
    conn.execute("INSERT OR REPLACE INTO state(key,value) VALUES('mask',?)", (info.get("mask"),))
    conn.execute("INSERT OR REPLACE INTO state(key,value) VALUES('gw',?)", (gateway,))
    conn.execute("INSERT OR REPLACE INTO state(key,value) VALUES('mac_local',?)", (info.get("mac"),))
    conn.commit()
    gw_probe = probe_device(gateway) if gateway else {"status": "inconnu"}
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(now() + " | probe gw=" + str(gw_probe.get("status")) + " | postes=" + str(len(probes)) + "\n")
    out = {
        "ip_local": info.get("ip"),
        "mask": info.get("mask"),
        "gw": gateway,
        "dns": info.get("dns"),
        "mac_local": info.get("mac"),
        "probes": probes,
        "alerts": []
    }
    conn2 = sqlite3.connect(DB)
    out["alerts"] = conn2.execute("SELECT severity, message FROM alerts ORDER BY id DESC").fetchall()
    conn2.close()
    with open(OUT, "w", encoding="utf-8") as f:
        json.dump(out, f, ensure_ascii=False, indent=2)
    with open(LOG, "a", encoding="utf-8") as f:
        f.write(now() + " | export json OK\n")
    conn.close()
    print(json.dumps(out, ensure_ascii=False, indent=2))


if __name__ == "__main__":
    main()
