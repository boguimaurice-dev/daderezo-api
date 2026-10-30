# -*- coding: utf-8 -*-
"""
DADEREZO v4.2 — Agent Sentinelle Autonome 24/7 pour VPS Contabo (`contabo_watchdog.py`).

Contrairement à un hébergement serverless (qui ne s'exécute qu'à la demande), ce démon
tourne en permanence sur votre VPS Contabo pour :
  1. Surveiller toutes les 60s la fraîcheur (`last_seen`) de vos sondes réelles.
  2. Détecter proactivement une coupure FAI, une passerelle hors ligne, une MAC inconnue ou un spoofing ARP.
  3. Journaliser dans l'audit multi-agents (`SENTINEL-SEC` / `DIAG-NET`) et alerter instantanément
     le Superviseur sur Telegram / WhatsApp / Discord / Slack sans doublon.
"""
from datetime import datetime, timezone
import json
import os
import time
from typing import Any, Dict, List
import urllib.request

import storage

CHECK_INTERVAL = int(os.environ.get("DADEREZO_WATCHDOG_INTERVAL", "60"))
OFFLINE_SECONDS = int(os.environ.get("DADEREZO_OFFLINE_SECONDS", "300"))
WEBHOOK_URL = os.environ.get("DADEREZO_ALERT_WEBHOOK_URL", "").strip()
TELEGRAM_BOT_TOKEN = os.environ.get("DADEREZO_TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("DADEREZO_TELEGRAM_CHAT_ID", "").strip()

_SENT_SIGNATURES: Dict[str, Any] = {}


def _send_notification(message: str) -> None:
    if TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID:
        tg_url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": message}).encode("utf-8")
        req = urllib.request.Request(tg_url, data=payload, headers={"Content-Type": "application/json"}, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=8):
                pass
        except Exception:
            pass

    if WEBHOOK_URL:
        payload = json.dumps({"text": message, "content": message}).encode("utf-8")
        req = urllib.request.Request(
            WEBHOOK_URL, data=payload, headers={"Content-Type": "application/json"}, method="POST"
        )
        try:
            with urllib.request.urlopen(req, timeout=8):
                pass
        except Exception:
            pass


def evaluate_once() -> List[Dict[str, Any]]:
    """Exécute un cycle complet de veille proactive sur toutes les sondes réelles."""
    now = datetime.now(timezone.utc)
    now_iso = now.isoformat()
    emitted: List[Dict[str, Any]] = []

    agents = storage.list_agents_raw(org_slug=None, include_all_orgs=True)
    for ag in agents:
        aid = ag.get("id") or ""
        if not aid or aid.startswith("simulation-"):
            continue

        last_raw = ag.get("last_seen") or ""
        age_sec = 999999
        if last_raw:
            try:
                dt = datetime.fromisoformat(last_raw.replace("Z", "+00:00"))
                if dt.tzinfo is None:
                    dt = dt.replace(tzinfo=timezone.utc)
                age_sec = int((now - dt).total_seconds())
            except Exception:
                pass

        st = storage.get_state_raw(aid) or {}
        devs = storage.get_devices_raw(aid) or []
        alerts_raw = storage.get_alerts_raw(aid) or []
        unknowns = [d for d in devs if "inconnu" in (d.get("name") or "").lower()]
        sec_alerts = [
            a for a in alerts_raw
            if any(k in (a.get("message") or "").lower() for k in ("mac", "suspect", "intrusion", "spoof"))
        ]

        probe_state = "offline" if age_sec > OFFLINE_SECONDS else "online"
        wan_state = (st.get("internet_status") or "unknown").lower()
        if wan_state not in ("ok", "down") and devs:
            if all(not bool(d.get("internet_ok")) for d in devs):
                wan_state = "down"

        site_lbl = st.get("site_name") or ag.get("name") or ag.get("nom") or aid

        # 1. Probe heartbeat check
        sig_probe = f"{aid}:probe:{probe_state}"
        if probe_state == "offline" and _SENT_SIGNATURES.get(f"{aid}:probe") != sig_probe:
            _SENT_SIGNATURES[f"{aid}:probe"] = sig_probe
            msg = f"🚨 [DADEREZO VPS 24/7] Sonde « {site_lbl} » ({aid}) injoignable depuis {age_sec}s."
            storage.record_audit_log(now_iso, "contabo-watchdog", "SENTINEL-SEC", "watchdog", "probe_heartbeat", "OFFLINE", 1, msg)
            _send_notification(msg)
            emitted.append({"agent_id": aid, "kind": "probe_offline", "message": msg})
        elif probe_state == "online":
            _SENT_SIGNATURES[f"{aid}:probe"] = sig_probe

        # 2. WAN Internet outage check (when probe is online)
        sig_wan = f"{aid}:wan:{wan_state}"
        if probe_state == "online" and wan_state == "down" and _SENT_SIGNATURES.get(f"{aid}:wan") != sig_wan:
            _SENT_SIGNATURES[f"{aid}:wan"] = sig_wan
            msg = f"⚡ [DADEREZO VPS 24/7] Coupure Internet FAI détectée sur « {site_lbl} » (LAN actif)."
            storage.record_audit_log(now_iso, "contabo-watchdog", "DIAG-NET", "watchdog", "wan_monitor", "WAN_DOWN", 1, msg)
            _send_notification(msg)
            emitted.append({"agent_id": aid, "kind": "wan_down", "message": msg})
        elif wan_state == "ok":
            _SENT_SIGNATURES[f"{aid}:wan"] = sig_wan

        # 3. Security / MAC change / Unknown device check
        sec_key = f"{aid}:sec:{len(unknowns)}:{len(sec_alerts)}"
        if (unknowns or sec_alerts) and _SENT_SIGNATURES.get(f"{aid}:sec") != sec_key:
            _SENT_SIGNATURES[f"{aid}:sec"] = sec_key
            detail = sec_alerts[0].get("message") if sec_alerts else ", ".join(u.get("ip") or "?" for u in unknowns[:4])
            msg = f"🕵️ [DADEREZO VPS 24/7] Alerte sécurité sur « {site_lbl} » : {detail}"
            storage.record_audit_log(now_iso, "contabo-watchdog", "SENTINEL-SEC", "watchdog", "mac_watch", "INTRUSION", 1, msg)
            _send_notification(msg)
            emitted.append({"agent_id": aid, "kind": "security_alert", "message": msg})

    return emitted


def run_forever() -> None:
    storage.init_db()
    print(f"[CONTABO-WATCHDOG] Sentinelle autonome 24/7 démarrée (intervalle={CHECK_INTERVAL}s, db={storage.get_backend_mode()})")
    while True:
        try:
            evaluate_once()
        except Exception as exc:
            print(f"[CONTABO-WATCHDOG] Erreur cycle : {exc}")
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    run_forever()
