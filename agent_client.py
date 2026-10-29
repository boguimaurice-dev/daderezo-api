#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DADEREZO v4.0 — Client Sonde & Contrôleur Actif SaaS.

Fonctions :
- Collecte et transmet en temps réel la télémétrie réseau et les alertes vers le Cloud DADEREZO.
- Exécute sous contrôle sécurisé les ordres du Superviseur Général :
  * `scan`, `sweep`, `rapport`
  * `apply_internet_policy` (coupure/activation Internet Box Principale, Sous-réseau/Zone ou Appareil)
  * `optimize_box`, `reboot_box` (configuration DNS, canaux Wi-Fi, QoS, MTU des box et relais)
  * `sync_media` (synchronisation locale des fichiers & multimédias partagés sur le LAN)
- Peut exposer un Hub Multimédia HTTP local (`--media-port 8090`) accessible sur le LAN même sans Internet.
"""
import argparse
import json
import os
import time
import urllib.parse
import urllib.request
from typing import Optional

from collector import collect, mark_alerts_synced
import make_dashboard
import net_controller


def _build_headers(api_key: Optional[str]) -> dict:
    headers = {"Content-Type": "application/json", "Accept": "application/json"}
    if api_key:
        headers["X-API-Key"] = api_key
    return headers


def register(api_url: str, agent_id: str, nom: str, api_key: Optional[str] = None) -> dict:
    payload = {"agent_id": agent_id, "nom": nom}
    req = urllib.request.Request(
        f"{api_url.rstrip('/')}/register",
        data=json.dumps(payload).encode("utf-8"),
        headers=_build_headers(api_key),
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=20) as rep:
        return json.loads(rep.read().decode("utf-8"))


def send_data(api_url: str, agent_id: str, nom: str, data: dict, api_key: Optional[str] = None) -> dict:
    raw_alerts = data.get("unsynced_alerts")
    if raw_alerts is None:
        raw_alerts = data.get("alerts", [])

    alerts = []
    sent_ids = []
    for a in raw_alerts:
        if isinstance(a, (list, tuple)) and len(a) >= 2:
            alerts.append({"severity": str(a[0]), "message": str(a[1])})
        elif isinstance(a, dict):
            alerts.append(
                {
                    "severity": str(a.get("severity", "info")),
                    "message": str(a.get("message", "")),
                    "ts": a.get("ts"),
                }
            )
            if "id" in a and a["id"] is not None:
                sent_ids.append(int(a["id"]))
        else:
            alerts.append({"severity": "info", "message": str(a)})

    payload = {
        "agent_id": agent_id,
        "nom": nom,
        "site_name": data.get("site_name"),
        "ip_local": data.get("ip_local"),
        "mask": data.get("mask"),
        "gw": data.get("gw"),
        "mac_local": data.get("mac_local"),
        "dns": data.get("dns") or [],
        "gw_status": data.get("gw_status"),
        "gw_latency_ms": data.get("gw_latency_ms"),
        "internet_status": data.get("internet_status"),
        "wan_latency_ms": data.get("wan_latency_ms"),
        "probes": data.get("probes", []),
        "alerts": alerts,
    }
    req = urllib.request.Request(
        f"{api_url.rstrip('/')}/data",
        data=json.dumps(payload).encode("utf-8"),
        headers=_build_headers(api_key),
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=30) as rep:
        resp = json.loads(rep.read().decode("utf-8"))

    if sent_ids:
        mark_alerts_synced(sent_ids)
    return resp


def ack_task(api_url: str, agent_id: str, task_id: int, result_msg: str, api_key: Optional[str] = None) -> None:
    q = urllib.parse.urlencode({"result": result_msg})
    req = urllib.request.Request(
        f"{api_url.rstrip('/')}/tasks/{urllib.parse.quote(agent_id)}/{task_id}/ack?{q}",
        data=b"",
        headers=_build_headers(api_key),
        method="POST",
    )
    with urllib.request.urlopen(req, timeout=15) as _:
        pass


def fetch_pending_tasks(api_url: str, agent_id: str, api_key: Optional[str] = None) -> list:
    req = urllib.request.Request(
        f"{api_url.rstrip('/')}/tasks/{urllib.parse.quote(agent_id)}?limit=5",
        headers=_build_headers(api_key),
        method="GET",
    )
    with urllib.request.urlopen(req, timeout=15) as rep:
        rows = json.loads(rep.read().decode("utf-8"))
        return [r for r in rows if isinstance(r, dict) and r.get("status") == "pending"]


def _parse_payload(raw_payload) -> dict:
    if isinstance(raw_payload, dict):
        return raw_payload
    if isinstance(raw_payload, str) and raw_payload.strip():
        try:
            return json.loads(raw_payload)
        except Exception:
            return {}
    return {}


def execute_pending_tasks(api_url: str, agent_id: str, nom: str, tasks: list, api_key: Optional[str] = None) -> None:
    for task in tasks:
        t_id = task.get("id")
        action = task.get("action", "scan")
        payload = _parse_payload(task.get("payload_json"))
        print(f"[ORDRE TEMPS RÉEL] Exécution : {action} (#{t_id})")

        if action == "sweep":
            fresh = collect(do_sweep=True)
            send_data(api_url, agent_id, nom, fresh, api_key=api_key)
            ack_task(api_url, agent_id, t_id, "Balayage sous-réseau 254 IP terminé", api_key)
        elif action == "rapport":
            make_dashboard.build()
            ack_task(api_url, agent_id, t_id, "Rapport local dashboard.html régénéré", api_key)
        elif action in ("apply_internet_policy", "optimize_box", "reboot_box"):
            msg = net_controller.execute_field_task(action, payload)
            ack_task(api_url, agent_id, t_id, msg, api_key)
        elif action == "sync_media":
            try:
                msg = net_controller.sync_media_from_cloud(api_url, agent_id, api_key=api_key)
            except Exception as exc:
                msg = f"Synchronisation média différée : {exc}"
            ack_task(api_url, agent_id, t_id, msg, api_key)
        else:
            fresh = collect(do_sweep=False)
            send_data(api_url, agent_id, nom, fresh, api_key=api_key)
            ack_task(api_url, agent_id, t_id, f"Diagnostic {action} terminé", api_key)


def run_cycle(api_url: str, agent_id: str, nom: str, api_key: Optional[str] = None, do_sweep: bool = False) -> bool:
    data = collect(do_sweep=do_sweep)
    try:
        result = send_data(api_url, agent_id, nom, data, api_key=api_key)
        print(
            f"[OK] Envoyé : {result.get('received', 0)} équipements, "
            f"{result.get('alerts_recorded', 0)} nouvelles alertes"
        )
        execute_pending_tasks(api_url, agent_id, nom, result.get("pending_tasks", []), api_key=api_key)
        return True
    except Exception as e:
        print(f"[ATTENTE] Envoi différé (API injoignable : {e}). Les alertes restent conservées localement.")
        return False


def main() -> None:
    parser = argparse.ArgumentParser(description="DADEREZO v4.0 — Client Sonde & Contrôleur Actif SaaS")
    parser.add_argument("--api", default=os.environ.get("DADEREZO_API_URL", "https://daderezo-api-nine.vercel.app"), help="URL de l'API SaaS")
    parser.add_argument("--agent", default=os.environ.get("DADEREZO_AGENT_ID", "mon-site-principal"), help="ID du site / agent")
    parser.add_argument("--nom", default=os.environ.get("DADEREZO_AGENT_NAME", ""), help="Nom lisible du site")
    parser.add_argument("--api-key", default=os.environ.get("DADEREZO_API_KEY", ""), help="Clé privée organisation (X-API-Key)")
    parser.add_argument("--interval", type=int, default=300, help="Intervalle entre deux collectes complètes (secondes)")
    parser.add_argument("--task-poll", type=int, default=5, help="Écoute rapide des ordres du Superviseur (secondes)")
    parser.add_argument("--media-port", type=int, default=0, help="Port du Hub Multimédia LAN local (ex: 8090, 0 = désactivé)")
    parser.add_argument("--sweep", action="store_true", help="Activer le balayage ping du sous-réseau")
    parser.add_argument("--once", action="store_true", help="Exécuter un seul cycle puis quitter")
    args = parser.parse_args()

    nom = args.nom or f"Site {args.agent}"
    api_key = args.api_key or None
    print(
        f"DADEREZO Agent v4.0 [{args.agent}] -> {args.api} "
        f"(collecte={args.interval}s, écoute ordres={args.task_poll}s)"
    )

    if args.media_port and args.media_port > 0:
        net_controller.start_lan_media_server(args.media_port)
        print(f"[MEDIA-HUB LAN] Partage local de fichiers & multimédias actif sur http://0.0.0.0:{args.media_port}")

    try:
        reg = register(args.api, args.agent, nom, api_key=api_key)
        print("Enregistré :", reg)
    except Exception as e:
        print("Avertissement enregistrement initial :", e)

    if args.once:
        run_cycle(args.api, args.agent, nom, api_key=api_key, do_sweep=args.sweep)
        return

    poll_sec = max(3, args.task_poll)
    full_interval = max(10, args.interval)
    while True:
        run_cycle(args.api, agent_id=args.agent, nom=nom, api_key=api_key, do_sweep=args.sweep)
        elapsed = 0
        while elapsed < full_interval:
            sleep_step = min(poll_sec, full_interval - elapsed)
            time.sleep(sleep_step)
            elapsed += sleep_step
            if elapsed < full_interval:
                try:
                    pending = fetch_pending_tasks(args.api, args.agent, api_key=api_key)
                    if pending:
                        execute_pending_tasks(args.api, args.agent, nom, pending, api_key=api_key)
                except Exception:
                    pass


if __name__ == "__main__":
    main()
