#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DADEREZO v4.0 — Contrôleur Actif Réseau, Optimiseur Multi-Box & Hub Multimédia LAN.

Fonctionnalités :
1. Évaluation et application granulaire d'Internet ON/OFF à 3 niveaux :
   - Niveau 1 (`global`) : Coupure / activation WAN sur la Box Principale (le LAN local reste actif).
   - Niveau 2 (`zone` / `subnet`) : Activation / coupure Internet d'une zone entière ou d'un sous-réseau CIDR.
   - Niveau 3 (`device`) : Activation / coupure Internet sur un équipement précis (IP ou MAC).
2. Configuration & optimisation intelligente de toutes les Box / Relais Wi-Fi :
   - Planification automatique des canaux Wi-Fi sans interférence (1 / 6 / 11 en 2.4GHz, 36 / 44 / 149 en 5GHz).
   - Résolveurs DNS rapides (1.1.1.1 / 8.8.8.8), MTU optimal (Fibre 1492 / Box 4G-5G 1420), QoS Anti-Bufferbloat.
   - Génération et exécution des commandes pilotes (Huawei HiLink 4G/5G, MikroTik RouterOS, OpenWrt UCI, Passerelle Linux/Windows).
3. Serveur HTTP Multimédia LAN local (`--media-port 8090`) :
   - Permet le partage et la lecture de documents, images, audios et vidéos en local même lorsque Internet est coupé.
"""
from http.server import HTTPServer, SimpleHTTPRequestHandler
import ipaddress
import json
import os
import platform
import subprocess
import threading
import urllib.request
from typing import Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
ACTIVE_STATE_FILE = os.path.join(HERE, "daderezo_active_state.json")
LOCAL_MEDIA_DIR = os.path.join(HERE, "daderezo_media_lan")


# ---------------------------------------------------------------------------
# 1. Évaluation déterministe des politiques Internet (Box / Zone & CIDR / Appareil)
# ---------------------------------------------------------------------------
def _ip_in_cidr(ip_str: str, cidr_str: str) -> bool:
    try:
        ip_obj = ipaddress.ip_address(ip_str.strip())
        net_obj = ipaddress.ip_network(cidr_str.strip(), strict=False)
        return ip_obj in net_obj
    except Exception:
        return False


def evaluate_device_internet(device: dict, policies: List[dict]) -> dict:
    """
    Calcule l'état effectif d'accès Internet d'un équipement selon la hiérarchie :
      1. `global` OFF (Box Principale coupée) -> Internet coupé pour tout le site (LAN maintenu).
      2. `device` (IP ou MAC explicite) -> Surcharge granulaire par appareil.
      3. `subnet` (CIDR ex: 192.168.1.0/24) ou `zone` (ex: Visiteurs) -> Règle de groupe.
      4. Défaut -> Internet autorisé (`True`).
    """
    dev_ip = str(device.get("ip") or "").strip()
    dev_mac = str(device.get("mac") or "").strip().upper()
    dev_zone = str(device.get("zone") or "").strip().lower()
    dev_type = str(device.get("type") or "host").strip().lower()

    global_pol = None
    device_pol = None
    subnet_pol = None
    zone_pol = None

    for p in policies:
        scope = str(p.get("scope_type") or "").strip().lower()
        target = str(p.get("target_value") or "").strip()
        if scope == "global":
            global_pol = p
        elif scope == "device":
            if (dev_ip and target == dev_ip) or (dev_mac and target.upper() == dev_mac):
                device_pol = p
        elif scope == "subnet":
            if dev_ip and _ip_in_cidr(dev_ip, target):
                subnet_pol = p
        elif scope == "zone":
            if dev_zone and target.lower() == dev_zone:
                zone_pol = p

    if global_pol is not None and not bool(global_pol.get("internet_enabled", True)):
        return {
            "internet_enabled": False,
            "internet_policy_source": "box_principale",
            "internet_reason": global_pol.get("reason") or "Internet coupé sur la Box Principale (LAN local actif)",
        }

    # La box passerelle garde son lien WAN tant que le coupe-circuit global est ON
    if dev_type == "gateway":
        return {
            "internet_enabled": True,
            "internet_policy_source": "box_principale",
            "internet_reason": "Box Principale WAN active",
        }

    if device_pol is not None:
        enabled = bool(device_pol.get("internet_enabled", True))
        return {
            "internet_enabled": enabled,
            "internet_policy_source": "appareil",
            "internet_reason": device_pol.get("reason")
            or ("Accès Internet autorisé (appareil)" if enabled else "Accès Internet bloqué sur cet appareil"),
        }

    if subnet_pol is not None:
        enabled = bool(subnet_pol.get("internet_enabled", True))
        return {
            "internet_enabled": enabled,
            "internet_policy_source": "sous_reseau",
            "internet_reason": subnet_pol.get("reason")
            or (f"Sous-réseau {subnet_pol.get('target_value')} autorisé" if enabled else f"Sous-réseau {subnet_pol.get('target_value')} isolé d'Internet"),
        }

    if zone_pol is not None:
        enabled = bool(zone_pol.get("internet_enabled", True))
        return {
            "internet_enabled": enabled,
            "internet_policy_source": "zone",
            "internet_reason": zone_pol.get("reason")
            or (f"Zone {device.get('zone')} autorisée" if enabled else f"Zone {device.get('zone')} coupée d'Internet"),
        }

    return {
        "internet_enabled": True,
        "internet_policy_source": "defaut",
        "internet_reason": "Accès Internet actif (standard)",
    }


# ---------------------------------------------------------------------------
# 2. Planification & Optimisation Automatique de toutes les Box du réseau
# ---------------------------------------------------------------------------
CHANNELS_24 = ["1", "6", "11"]
CHANNELS_50 = ["36", "44", "149"]


def discover_boxes_from_devices(agent_id: str, devices: List[dict], existing_boxes: List[dict]) -> List[dict]:
    """Fusionne les box connues avec les passerelles et bornes Wi-Fi détectées sur le LAN."""
    by_ip: Dict[str, dict] = {b["box_ip"]: dict(b) for b in existing_boxes if b.get("box_ip")}
    box_candidates = [d for d in devices if d.get("type") in ("fai_box", "gateway", "relay", "wifi_ap")]

    if not box_candidates and not by_ip:
        box_candidates = [
            {
                "ip": "192.168.1.1",
                "name": "Box Principale Fibre / 4G",
                "type": "gateway",
                "status": "up",
                "latency_ms": 2.4,
            }
        ]

    idx = 0
    for dev in box_candidates:
        ip = dev.get("ip")
        if not ip:
            continue
        dtype = str(dev.get("type") or "")
        role = "gateway" if dtype in ("fai_box", "gateway") else "wifi_ap"
        if ip not in by_ip:
            ch24 = CHANNELS_24[idx % len(CHANNELS_24)]
            driver_default = (
                "huawei_hilink"
                if dtype == "fai_box"
                else ("mikrotik_routeros" if dtype == "gateway" else "openwrt_uci")
            )
            by_ip[ip] = {
                "agent_id": agent_id,
                "box_ip": ip,
                "box_name": dev.get("name") or ("Box Principale" if role == "gateway" else f"Relais Wi-Fi {ip}"),
                "box_role": role,
                "driver": driver_default,
                "wifi_enabled": True,
                "wifi_ssid": "DADEREZO-PRO" if role == "gateway" else f"DADEREZO-RELAIS-{idx + 1}",
                "wifi_channel": ch24,
                "wifi_band": "2.4GHz + 5GHz",
                "dns_primary": "1.1.1.1",
                "dns_secondary": "8.8.8.8",
                "qos_profile": "equilibre",
                "bandwidth_limit_mbps": 0,
                "mtu": 1492,
                "health_score": 82 if dev.get("status") == "up" else 40,
                "last_optimized_at": None,
                "notes": "Détectée automatiquement par DADEREZO",
            }
        idx += 1

    return sorted(by_ip.values(), key=lambda x: (0 if x.get("box_role") == "gateway" else 1, x.get("box_ip", "")))


def compute_optimal_box_plan(
    boxes: List[dict],
    devices: List[dict],
    state: Dict[str, str],
    now_iso: str,
) -> Tuple[List[dict], List[str]]:
    """
    Calcule la configuration optimale coordonnée pour l'ensemble des box/bornes d'un site :
    - Séparation stricte des canaux Wi-Fi 1 / 6 / 11 + 5GHz entre la Box Principale et les relais.
    - DNS Cloudflare + Quad9/Google ultra-rapides (1.1.1.1 / 9.9.9.9).
    - MTU adapté (1420 pour 4G/5G LTE HiLink afin d'éviter la fragmentation, 1492 pour Fibre/PPPoE).
    - Profil QoS adaptatif selon la latence WAN et le nombre d'hôtes connectés.
    """
    wan_lat = 0.0
    try:
        wan_lat = float(state.get("wan_latency_ms") or 0.0)
    except Exception:
        wan_lat = 0.0

    guest_count = sum(1 for d in devices if "visiteur" in str(d.get("zone") or "").lower())
    recommended_qos = "anti_bufferbloat_voix" if (wan_lat > 45 or len(devices) >= 6) else "priorite_admin"

    optimized: List[dict] = []
    actions_summary: List[str] = []

    for i, b in enumerate(boxes):
        nb = dict(b)
        ch24 = CHANNELS_24[i % len(CHANNELS_24)]
        ch50 = CHANNELS_50[i % len(CHANNELS_50)]
        driver = str(nb.get("driver") or "auto").lower()

        nb["wifi_channel"] = f"{ch24} / {ch50}"
        nb["wifi_band"] = "2.4GHz + 5GHz (Smart Steering)"
        nb["dns_primary"] = "1.1.1.1"
        nb["dns_secondary"] = "9.9.9.9"
        nb["qos_profile"] = recommended_qos
        nb["mtu"] = 1420 if "hilink" in driver or "4g" in str(nb.get("box_name", "")).lower() else 1492
        if nb.get("box_role") == "wifi_ap" and guest_count > 0 and int(nb.get("bandwidth_limit_mbps") or 0) == 0:
            nb["bandwidth_limit_mbps"] = 25
        nb["health_score"] = 98
        nb["last_optimized_at"] = now_iso
        nb["notes"] = (
            f"Optimisée : Canal sans collision ({nb['wifi_channel']}), DNS 1.1.1.1/9.9.9.9, "
            f"QoS {recommended_qos}, MTU {nb['mtu']}."
        )
        optimized.append(nb)
        actions_summary.append(
            f"{nb['box_name']} ({nb['box_ip']}) -> Canal {nb['wifi_channel']}, DNS 1.1.1.1, QoS {recommended_qos}, MTU {nb['mtu']}"
        )

    return optimized, actions_summary


# ---------------------------------------------------------------------------
# 3. Générateur de scripts routeurs & Exécution Terrain Sécurisée
# ---------------------------------------------------------------------------
def generate_router_commands(action_type: str, payload: dict) -> List[str]:
    """Produit les commandes exactes multi-pilotes correspondant à la consigne réseau."""
    cmds: List[str] = []
    if action_type == "apply_internet_policy":
        scope = payload.get("scope_type", "device")
        target = payload.get("target_value", "")
        enabled = bool(payload.get("internet_enabled", True))
        if scope == "global":
            state_flag = "1" if enabled else "0"
            nf_verdict = "ACCEPT" if enabled else "DROP"
            nft_cmd = "nft flush chain inet daderezo wan_cut" if enabled else 'nft add rule inet daderezo wan_cut oifname "eth1" drop'
            cmds.append(f"# Box Principale (HiLink 4G/5G) : dataswitch={state_flag} (LAN local préservé)")
            cmds.append(f"POST http://192.168.1.1/api/dialup/mobile-dataswitch <dataswitch>{state_flag}</dataswitch>")
            cmds.append(f"# Passerelle Linux / OpenWrt (WAN eth1) : {nf_verdict}")
            cmds.append(nft_cmd)
        elif scope in ("subnet", "zone"):
            cidr = target if "/" in target else f"zone:{target}"
            op = "-D" if enabled else "-I"
            ros_cmd = (
                f'/ip firewall filter remove [find comment="daderezo-{target}"]'
                if enabled
                else f'/ip firewall filter add chain=forward src-address={cidr} out-interface-list=WAN action=drop comment="daderezo-{target}"'
            )
            cmds.append(f"# Politique Internet Groupe ({scope}={target}) -> {'ON' if enabled else 'OFF'}")
            cmds.append(f"iptables {op} FORWARD -s {cidr} ! -d 192.168.0.0/16 -j REJECT --reject-with icmp-net-prohibited")
            cmds.append(ros_cmd)
        else:
            op = "-D" if enabled else "-I"
            match_expr = f"-m mac --mac-source {target}" if ":" in target else f"-s {target}"
            ros_dev_cmd = (
                f'/ip firewall filter remove [find comment="daderezo-{target}"]'
                if enabled
                else f'/ip firewall filter add chain=forward src-address={target} out-interface-list=WAN action=drop comment="daderezo-{target}"'
            )
            cmds.append(f"# Politique Internet Appareil ({target}) -> {'ON' if enabled else 'OFF'}")
            cmds.append(f"iptables {op} FORWARD {match_expr} ! -d 192.168.0.0/16 -j DROP")
            cmds.append(ros_dev_cmd)

    elif action_type == "optimize_box":
        ip = payload.get("box_ip", "192.168.1.1")
        dns1 = payload.get("dns_primary", "1.1.1.1")
        dns2 = payload.get("dns_secondary", "9.9.9.9")
        ch = str(payload.get("wifi_channel", "6")).split("/")[0].strip()
        mtu = int(payload.get("mtu") or 1492)
        qos = payload.get("qos_profile", "anti_bufferbloat_voix")
        cmds.extend(
            [
                f"# Optimisation Box {payload.get('box_name', ip)} ({ip})",
                f"uci set dhcp.@dnsmasq[0].server='{dns1}' && uci add_list dhcp.@dnsmasq[0].server='{dns2}'",
                f"uci set wireless.radio0.channel='{ch}' && uci set network.wan.mtu='{mtu}'",
                f"tc qdisc replace dev wan root cake bandwidth {payload.get('bandwidth_limit_mbps') or 100}mbit diffserv4 # profil={qos}",
                "uci commit && reload_config",
            ]
        )

    elif action_type == "reboot_box":
        ip = payload.get("box_ip", "192.168.1.1")
        cmds.extend(
            [
                f"# Redémarrage contrôlé de la Box {ip}",
                f"POST http://{ip}/api/device/control <Control>1</Control>",
                f"ssh admin@{ip} '/system reboot'",
            ]
        )
    return cmds


def _persist_local_state(entry: dict) -> None:
    current: dict = {"history": []}
    if os.path.exists(ACTIVE_STATE_FILE):
        try:
            with open(ACTIVE_STATE_FILE, "r", encoding="utf-8") as f:
                current = json.load(f)
        except Exception:
            current = {"history": []}
    hist = current.get("history", [])
    hist.append(entry)
    current["history"] = hist[-50:]
    with open(ACTIVE_STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(current, f, ensure_ascii=False, indent=2)


def execute_field_task(action: str, payload: dict) -> str:
    """
    Exécute une consigne réseau active reçue par `agent_client.py` sur le terrain.
    - En mode standard : journalise l'état local et prépare les commandes pilotes validées.
    - Si `DADEREZO_ACTIVE_CONTROL=1` est activé sur la sonde passerelle : applique réellement
      les règles pare-feu / routeur locales (Linux iptables/nftables, Windows netsh ou API HiLink).
    """
    cmds = generate_router_commands(action, payload)
    active_hw = os.environ.get("DADEREZO_ACTIVE_CONTROL", "0").strip() == "1"
    applied_hw = False
    hw_detail = "profil synchronisé (mode sécurisé)"

    if active_hw and action == "apply_internet_policy":
        scope = payload.get("scope_type", "device")
        target = str(payload.get("target_value", "")).strip()
        enabled = bool(payload.get("internet_enabled", True))
        sys_name = platform.system().lower()
        try:
            if "linux" in sys_name and scope == "device" and target and ":" not in target:
                op = "-D" if enabled else "-I"
                subprocess.run(
                    ["iptables", op, "FORWARD", "-s", target, "!", "-d", "192.168.0.0/16", "-j", "DROP"],
                    check=False,
                    capture_output=True,
                    timeout=5,
                )
                applied_hw = True
                hw_detail = f"iptables FORWARD {op} appliqué pour {target}"
            elif "windows" in sys_name and scope == "device" and target and ":" not in target:
                rule_name = f"DADEREZO_BLOCK_{target}"
                if enabled:
                    subprocess.run(
                        ["netsh", "advfirewall", "firewall", "delete", "rule", f"name={rule_name}"],
                        check=False,
                        capture_output=True,
                        timeout=5,
                    )
                else:
                    subprocess.run(
                        [
                            "netsh",
                            "advfirewall",
                            "firewall",
                            "add",
                            "rule",
                            f"name={rule_name}",
                            "dir=out",
                            "action=block",
                            f"remoteip={target}",
                        ],
                        check=False,
                        capture_output=True,
                        timeout=5,
                    )
                applied_hw = True
                hw_detail = f"Windows Firewall mis à jour ({rule_name})"
        except Exception as exc:
            hw_detail = f"pilote matériel ignoré ({exc})"

    _persist_local_state(
        {
            "action": action,
            "payload": payload,
            "commands": cmds,
            "hardware_applied": applied_hw,
            "detail": hw_detail,
        }
    )
    return f"{action} exécuté ({hw_detail}) — {len(cmds)} commande(s) routeur générée(s)"


# ---------------------------------------------------------------------------
# 4. Serveur HTTP Multimédia LAN (accessible sur le réseau local même sans Internet)
# ---------------------------------------------------------------------------
def sync_media_from_cloud(api_url: str, agent_id: str, api_key: Optional[str] = None) -> str:
    """Télécharge dans `daderezo_media_lan/` les fichiers partagés du site pour accès LAN hors-ligne."""
    os.makedirs(LOCAL_MEDIA_DIR, exist_ok=True)
    headers = {"Accept": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    req = urllib.request.Request(f"{api_url.rstrip('/')}/media/{agent_id}", headers=headers, method="GET")
    with urllib.request.urlopen(req, timeout=20) as resp:
        items = json.loads(resp.read().decode("utf-8"))

    synced = 0
    for item in items:
        m_id = item.get("id")
        fname = item.get("filename") or f"media_{m_id}"
        dest = os.path.join(LOCAL_MEDIA_DIR, f"{m_id}_{fname}")
        if os.path.exists(dest):
            continue
        dl_req = urllib.request.Request(
            f"{api_url.rstrip('/')}/media/file/{m_id}",
            headers=headers,
            method="GET",
        )
        with urllib.request.urlopen(dl_req, timeout=30) as dl_resp:
            with open(dest, "wb") as f:
                f.write(dl_resp.read())
        synced += 1
    return f"Hub Multimédia LAN synchronisé ({synced} nouveau(x) fichier(s), total={len(items)})"


def start_lan_media_server(port: int = 8090) -> threading.Thread:
    """Démarre un serveur HTTP léger en arrière-plan pour diffuser les médias sur le LAN local."""
    os.makedirs(LOCAL_MEDIA_DIR, exist_ok=True)

    class _Handler(SimpleHTTPRequestHandler):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, directory=LOCAL_MEDIA_DIR, **kwargs)

        def log_message(self, format, *args):
            return

    srv = HTTPServer(("0.0.0.0", int(port)), _Handler)
    th = threading.Thread(target=srv.serve_forever, daemon=True)
    th.start()
    return th
