# -*- coding: utf-8 -*-
"""
DADEREZO v4.3 — Agent Sentinelle Autonome 24/7 pour VPS Contabo (`contabo_watchdog.py`).

Tourne en permanence sur votre VPS Contabo pour :
  1. Surveiller toutes les 60s la fraîcheur (`last_seen`) de toutes vos sondes réelles.
  2. Détecter proactivement une coupure FAI, une passerelle hors ligne, une MAC inconnue ou un spoofing ARP.
  3. Enrichir automatiquement l'alerte avec un diagnostic racine **DeepSeek IA** (si `DEEPSEEK_API_KEY` est défini)
     et notifier instantanément le Superviseur sur Telegram / WhatsApp / Discord / Slack sans doublon.
"""
from datetime import datetime, timezone
import json
import os
import time
from typing import Any, Dict, List, Optional
import urllib.request

import agent_engine
import storage

CHECK_INTERVAL = int(os.environ.get("DADEREZO_WATCHDOG_INTERVAL", "60"))
OFFLINE_SECONDS = int(os.environ.get("DADEREZO_OFFLINE_SECONDS", "300"))
WEBHOOK_URL = os.environ.get("DADEREZO_ALERT_WEBHOOK_URL", "").strip()
TELEGRAM_BOT_TOKEN = os.environ.get("DADEREZO_TELEGRAM_BOT_TOKEN", "").strip()
TELEGRAM_CHAT_ID = os.environ.get("DADEREZO_TELEGRAM_CHAT_ID", "").strip()

_SENT_SIGNATURES: Dict[str, Any] = {}


def _ai_enrich_incident(site_lbl: str, incident_kind: str, context_summary: dict) -> Optional[str]:
    """Appelle DeepSeek (ou le LLM configuré sur Contabo) pour ajouter un diagnostic court en 2 lignes."""
    llm_cfg = agent_engine._detect_llm_config()
    if not llm_cfg:
        return None
    prompt = (
        f"Site: {site_lbl} | Incident: {incident_kind}\n"
        f"Données télémétrie: {json.dumps(context_summary, ensure_ascii=False)}\n"
        "Donne en 2 phrases courtes maximum : (1) la cause racine la plus probable, (2) l'action immédiate recommandée."
    )
    payload: dict = {
        "model": llm_cfg["model"],
        "messages": [
            {"role": "system", "content": "Tu es DIAG-NET de DADEREZO. Sois ultra-concis, factuel, sans inventer d'IP."},
            {"role": "user", "content": prompt},
        ],
        "max_tokens": 140,
    }
    if "reasoner" not in llm_cfg["model"].lower():
        payload["temperature"] = 0.1
    req = urllib.request.Request(
        f"{llm_cfg['base_url']}/chat/completions",
        data=json.dumps(payload).encode("utf-8"),
        headers={
            "Authorization": f"Bearer {llm_cfg['api_key']}",
            "Content-Type": "application/json",
            "User-Agent": "DADEREZO-ContaboWatchdog/4.3",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            txt = (data.get("choices", [{}])[0].get("message", {}).get("content") or "").strip()
            return txt if txt else None
    except Exception:
        return None


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


def evaluate_once(enable_ai_enrichment: bool = True) -> List[Dict[str, Any]]:
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
        ctx_summary = {
            "gateway": st.get("gw"),
            "dns": st.get("dns"),
            "devices_count": len(devs),
            "unknown_count": len(unknowns),
            "probe_age_sec": age_sec,
        }

        # 1. Probe heartbeat check
        sig_probe = f"{aid}:probe:{probe_state}"
        if probe_state == "offline" and _SENT_SIGNATURES.get(f"{aid}:probe") != sig_probe:
            _SENT_SIGNATURES[f"{aid}:probe"] = sig_probe
            msg = f"🚨 [DADEREZO VPS 24/7] Sonde « {site_lbl} » ({aid}) injoignable depuis {age_sec}s."
            if enable_ai_enrichment:
                ai_note = _ai_enrich_incident(site_lbl, "probe_offline", ctx_summary)
                if ai_note:
                    msg += f"\n🤖 Diagnostic IA : {ai_note}"
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
            if enable_ai_enrichment:
                ai_note = _ai_enrich_incident(site_lbl, "wan_down", ctx_summary)
                if ai_note:
                    msg += f"\n🤖 Diagnostic IA : {ai_note}"
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
            if enable_ai_enrichment:
                ai_note = _ai_enrich_incident(site_lbl, "security_alert", {**ctx_summary, "detail": detail})
                if ai_note:
                    msg += f"\n🤖 Diagnostic IA : {ai_note}"
            storage.record_audit_log(now_iso, "contabo-watchdog", "SENTINEL-SEC", "watchdog", "mac_watch", "INTRUSION", 1, msg)
            _send_notification(msg)
            emitted.append({"agent_id": aid, "kind": "security_alert", "message": msg})

    return emitted


def run_forever() -> None:
    storage.init_db()
    llm_cfg = agent_engine._detect_llm_config()
    llm_lbl = f"{llm_cfg['provider']}/{llm_cfg['model']}" if llm_cfg else "deterministe"
    print(f"[CONTABO-WATCHDOG] Sentinelle autonome 24/7 démarrée (intervalle={CHECK_INTERVAL}s, db={storage.get_backend_mode()}, ia={llm_lbl})")
    while True:
        try:
            evaluate_once()
        except Exception as exc:
            print(f"[CONTABO-WATCHDOG] Erreur cycle : {exc}")
        time.sleep(CHECK_INTERVAL)


if __name__ == "__main__":
    run_forever()
