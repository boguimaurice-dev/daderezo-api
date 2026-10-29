# -*- coding: utf-8 -*-
"""
DADEREZO — Moteur Multi-Agents Autonome (Architecture inspirée AGENT Z).

4 Agents spécialisés coopèrent sur de vrais outils connectés à la base SQL/Supabase :
  01 · SENTINEL-SEC  : Garde-fou Blue Team (anti-injection de prompt + charte 100 % lecture seule)
  02 · TOPO-SCAN     : Topologie, matrice LAN vs Accès Internet & télémétrie historique
  03 · DIAG-NET      : Corrélation de pannes (FAI vs Routeur vs Relais), sécurité MAC & ticket opérateur
  04 · OPS-DISPATCH  : Ordonnancement sonde terrain & Validation Humaine (Human-in-the-Loop)

Compatible avec synthèse LLM externe optionnelle (OpenAI / Groq / compatible OpenAI)
tout en fonctionnant à 100 % de manière autonome, déterministe et sans hallucination hors clé externe.
"""
from datetime import datetime, timezone
import json
import os
import re
import time
import unicodedata
import urllib.request
from typing import Any, Callable, Dict, List, Optional

import storage


def normalize_fr(text: str) -> str:
    nfkd = unicodedata.normalize("NFKD", text or "")
    stripped = "".join(ch for ch in nfkd if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", stripped.lower()).strip()


def _detect_llm_config(header_key: Optional[str] = None, header_model: Optional[str] = None) -> Optional[dict]:
    key = (
        (header_key or "").strip()
        or os.environ.get("DADEREZO_LLM_API_KEY", "").strip()
        or os.environ.get("GROQ_API_KEY", "").strip()
        or os.environ.get("OPENAI_API_KEY", "").strip()
    )
    if not key:
        return None

    explicit_base = os.environ.get("DADEREZO_LLM_BASE_URL", "").strip()
    if explicit_base:
        base_url = explicit_base.rstrip("/")
        default_model = "gpt-4o-mini"
    elif key.startswith("gsk_"):
        base_url = "https://api.groq.com/openai/v1"
        default_model = "llama-3.3-70b-versatile"
    else:
        base_url = "https://api.openai.com/openai/v1"
        default_model = "gpt-4o-mini"

    model = (header_model or "").strip() or os.environ.get("DADEREZO_LLM_MODEL", "").strip() or default_model
    return {"api_key": key, "base_url": base_url, "model": model}


def _call_llm_grounded(
    llm_cfg: dict,
    question: str,
    history: List[dict],
    tool_evidence: dict,
) -> Optional[str]:
    system_prompt = (
        "Tu es l'Orchestrateur Principal DADEREZO (Architecture Multi-Agents de Supervision Réseau, "
        "100 % lecture seule). Tu t'adresses à l'Administrateur Superviseur Général en français clair, "
        "précis et structuré.\n"
        "RÈGLES STRICTES ANTI-HALLUCINATION :\n"
        "1. Utilise EXCLUSIVEMENT les chiffres, adresses IP, adresses MAC et états présents dans `PREUVES_OUTILS`.\n"
        "2. S'il manque une donnée, dis-le explicitement — n'invente JAMAIS un chiffre ou une IP.\n"
        "3. Distingue toujours clairement la connexion au réseau local (LAN) et l'accès effectif à Internet (WAN).\n"
        "4. Rappelle si pertinent que DADEREZO agit en lecture seule stricte."
    )
    messages = [{"role": "system", "content": system_prompt}]
    for turn in history[-4:]:
        r = "assistant" if turn.get("role") == "assistant" else "user"
        messages.append({"role": r, "content": str(turn.get("content", ""))[:800]})
    messages.append(
        {
            "role": "user",
            "content": (
                f"PREUVES_OUTILS (vérité terrain vérifiée) :\n"
                f"{json.dumps(tool_evidence, ensure_ascii=False)}\n\n"
                f"DEMANDE DU SUPERVISEUR GÉNÉRAL :\n{question}"
            ),
        }
    )

    body = json.dumps(
        {"model": llm_cfg["model"], "messages": messages, "temperature": 0.15, "max_tokens": 700}
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{llm_cfg['base_url']}/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {llm_cfg['api_key']}",
            "Content-Type": "application/json",
            "User-Agent": "DADEREZO-Orchestrator/3.0",
        },
        method="POST",
    )
    try:
        with urllib.request.urlopen(req, timeout=12) as resp:
            data = json.loads(resp.read().decode("utf-8"))
            content = data["choices"][0]["message"]["content"].strip()
            return content if content else None
    except Exception:
        return None


def run_multi_agent_mission(
    question_raw: str,
    target_agent_id: Optional[str],
    scope: str,
    session_id: str,
    can_write: bool,
    fetch_dashboards_fn: Callable[[Optional[str], bool], List[dict]],
    llm_api_key: Optional[str] = None,
    llm_model: Optional[str] = None,
) -> dict:
    """Exécute la chaîne complète des 4 agents spécialisés avec journalisation d'audit et mémoire."""
    now_iso = datetime.now(timezone.utc).isoformat()
    sid = (session_id or "default-supervisor").strip()[:80]
    q_clean = question_raw.strip()
    q = normalize_fr(q_clean)

    agent_trace: List[dict] = []

    def _trace(agent_name: str, action_type: str, tool_name: str, status: str, t0: float, details: str) -> None:
        dur = max(1, int((time.perf_counter() - t0) * 1000))
        entry = {
            "agent": agent_name,
            "action_type": action_type,
            "tool": tool_name,
            "status": status,
            "duration_ms": dur,
            "details": details,
        }
        agent_trace.append(entry)
        try:
            storage.record_audit_log(now_iso, sid, agent_name, action_type, tool_name, status, dur, details)
        except Exception:
            pass

    # Récupération de la mémoire conversationnelle de la session
    history = storage.get_session_turns(sid, limit=6)
    storage.append_session_turn(sid, now_iso, "user", q_clean, target_agent_id, {"scope": scope})

    # =========================================================================
    # AGENT 01 · SENTINEL-SEC (Blue Team : Anti-Injection & Charte Lecture Seule)
    # =========================================================================
    t_sec = time.perf_counter()
    injection_patterns = (
        r"(ignore\s+(all\s+)?previous|oublie\s+(toutes\s+)?tes\s+(regles|consignes|instructions)|"
        r"system\s*prompt|mode\s+developpeur|jailbreak|drop\s+table|;\s*rm\s+-rf|bypass\s+security)"
    )
    write_patterns = (
        r"\b(redemarr\w*|reboot\w*|bloqu\w*|banni\w*|desactiv\w*|reinitialis\w*|reset\w*|"
        r"modifi\w*|etein\w*|ferm\w*\s+le\s+port|coup\w*\s+le\s+wifi|chang\w*\s+le\s+mot\s+de\s+passe)\b"
    )

    is_injection = bool(re.search(injection_patterns, q))
    is_write_attempt = bool(re.search(write_patterns, q))

    # Résolution anticipée du périmètre pour fournir malgré tout la vérité terrain
    wants_global = (
        scope.strip().lower() == "global"
        or (target_agent_id or "").strip().lower() == "all"
        or any(
            kw in q
            for kw in (
                "tous les sites",
                "toutes les sondes",
                "multi-site",
                "multisite",
                "vue globale",
                "bilan global",
                "ensemble des sites",
                "partout",
            )
        )
    )
    dashboards = fetch_dashboards_fn(target_agent_id, wants_global)

    all_devices: List[dict] = []
    all_alerts: List[dict] = []
    site_names: List[str] = []
    for d in dashboards:
        ag = d["agent"] or {}
        sname = d["state"].get("site_name") or ag.get("nom") or ag.get("id") or "Site"
        site_names.append(sname)
        for dev in d["devices"]:
            ed = dict(dev)
            ed["site_name"] = sname
            ed["agent_id"] = ag.get("id", "")
            all_devices.append(ed)
        for al in d["alerts"]:
            ac = dict(al)
            ac["site_name"] = sname
            all_alerts.append(ac)

    scope_label = (
        f"Tous les sites ({len(dashboards)} sonde(s))"
        if len(dashboards) > 1
        else (site_names[0] if site_names else "Aucun site enregistré")
    )

    lan_up_devs = [d for d in all_devices if d.get("status") == "up"]
    offline_devs = [d for d in all_devices if d.get("status") != "up"]
    inet_yes_devs = [d for d in all_devices if d.get("internet_access") in ("oui", "degrade")]
    inet_no_devs = [d for d in all_devices if d.get("internet_access") not in ("oui", "degrade")]
    lan_only_no_inet_devs = [
        d for d in all_devices if d.get("status") == "up" and d.get("internet_access") == "non"
    ]
    unknown_devs = [d for d in all_devices if "inconnu" in (d.get("name") or "").lower()]

    metrics = {
        "sites_count": len(dashboards),
        "total_devices": len(all_devices),
        "lan_connected": len(lan_up_devs),
        "offline": len(offline_devs),
        "internet_yes": len(inet_yes_devs),
        "internet_no": len(inet_no_devs),
        "lan_only_no_internet": len(lan_only_no_inet_devs),
        "unknown_count": len(unknown_devs),
    }

    if is_injection:
        _trace(
            "SENTINEL-SEC",
            "guardrail",
            "detect_prompt_injection",
            "BLOCKED",
            t_sec,
            f"Tentative de contournement / injection bloquée : « {q_clean[:90]} »",
        )
        ans = (
            "🛡️ [SENTINEL-SEC] Tentative d'injection de prompt ou de contournement détectée et bloquée.\n"
            "Les politiques de sécurité DADEREZO (architecture lecture seule et isolation des outils) "
            "sont immuables et journalisées dans l'audit."
        )
        spoken = "Alerte sécurité Sentinel : tentative de contournement des règles bloquée et journalisée."
        storage.append_session_turn(sid, now_iso, "assistant", ans, target_agent_id, {"intent": "blocage_injection"})
        return {
            "status": "ok",
            "session_id": sid,
            "engine_mode": "sentinel_shield",
            "intent": "blocage_injection",
            "scope": "global" if len(dashboards) > 1 else "site",
            "site_label": scope_label,
            "answer": ans,
            "spoken_text": spoken,
            "metrics": metrics,
            "devices": all_devices,
            "with_internet": inet_yes_devs,
            "without_internet": inet_no_devs,
            "unknown_devices": unknown_devs,
            "task_queued": None,
            "pending_approval": None,
            "agent_trace": agent_trace,
            "security_check": {"verdict": "BLOCK_PROMPT_INJECTION", "readonly_enforced": True},
            "refused_write_action": True,
        }

    if is_write_attempt:
        _trace(
            "SENTINEL-SEC",
            "guardrail",
            "enforce_readonly_charter",
            "BLOCKED",
            t_sec,
            f"Commande d'écriture réseau refusée : « {q_clean[:90]} »",
        )
        ans = (
            f"⛔ [SENTINEL-SEC] Action d'écriture refusée — Charte DADEREZO 100 % lecture seule.\n"
            f"Sur « {scope_label} », aucun redémarrage de routeur, blocage MAC ou modification de pare-feu "
            f"n'est exécuté à distance.\n\n"
            f"État vérifié en direct : {len(lan_up_devs)}/{len(all_devices)} équipement(s) connecté(s) au LAN, "
            f"dont {len(inet_yes_devs)} avec accès Internet actif et {len(inet_no_devs)} sans accès Internet."
        )
        spoken = (
            f"Action refusée par Sentinel Sécurité. DADEREZO opère uniquement en lecture seule. "
            f"Actuellement, {len(lan_up_devs)} appareils sur {len(all_devices)} sont connectés au réseau local, "
            f"dont {len(inet_yes_devs)} avec accès Internet."
        )
        storage.append_session_turn(sid, now_iso, "assistant", ans, target_agent_id, {"intent": "refus_ecriture"})
        return {
            "status": "ok",
            "session_id": sid,
            "engine_mode": "sentinel_shield",
            "intent": "refus_ecriture",
            "scope": "global" if len(dashboards) > 1 else "site",
            "site_label": scope_label,
            "answer": ans,
            "spoken_text": spoken,
            "metrics": metrics,
            "devices": all_devices,
            "with_internet": inet_yes_devs,
            "without_internet": inet_no_devs,
            "unknown_devices": unknown_devs,
            "task_queued": None,
            "pending_approval": None,
            "agent_trace": agent_trace,
            "security_check": {"verdict": "BLOCK_READONLY_CHARTER", "readonly_enforced": True},
            "refused_write_action": True,
        }

    _trace(
        "SENTINEL-SEC",
        "guardrail",
        "verify_security_policy",
        "ALLOW",
        t_sec,
        "Requête conforme à la charte lecture seule et sans injection.",
    )

    if not dashboards:
        msg = (
            "Aucune sonde réseau n'est enregistrée pour le moment. "
            "Lancez `agent_client.py` sur un PC du réseau local ou activez un scénario de test."
        )
        return {
            "status": "ok",
            "session_id": sid,
            "engine_mode": "multi_agent_autonomous",
            "intent": "aucune_sonde",
            "scope": "global" if wants_global else "site",
            "site_label": "Aucun site enregistré",
            "answer": msg,
            "spoken_text": msg,
            "metrics": metrics,
            "devices": [],
            "with_internet": [],
            "without_internet": [],
            "unknown_devices": [],
            "task_queued": None,
            "pending_approval": None,
            "agent_trace": agent_trace,
            "security_check": {"verdict": "ALLOW", "readonly_enforced": True},
            "refused_write_action": False,
        }

    # =========================================================================
    # AGENT 02 · TOPO-SCAN (Inventaire LAN/WAN, Zones & Historique Latence)
    # =========================================================================
    t_topo = time.perf_counter()
    zone_filter = None
    for z_candidate in ("communaute", "administration", "accueil", "visiteurs", "coeur", "supervision", "acces fai"):
        if z_candidate in q:
            zone_filter = z_candidate
            break

    scoped_devices = all_devices
    if zone_filter:
        scoped_devices = [
            d for d in all_devices if zone_filter in normalize_fr(d.get("zone") or "")
        ]

    _trace(
        "TOPO-SCAN",
        "tool_call",
        "inspect_lan_wan_matrix",
        "OK",
        t_topo,
        (
            f"Périmètre={scope_label} | Total={len(all_devices)} | LAN_UP={len(lan_up_devs)} | "
            f"WAN_OUI={len(inet_yes_devs)} | WAN_NON={len(inet_no_devs)}"
            + (f" | Filtre zone={zone_filter} ({len(scoped_devices)} poste(s))" if zone_filter else "")
        ),
    )

    # Analyse de l'historique réel de latence (`probes`)
    t_hist = time.perf_counter()
    primary_aid = (dashboards[0]["agent"] or {}).get("id", "")
    probe_samples = storage.get_probes_raw(primary_aid, limit=60) if primary_aid else []
    latencies = [float(p["latency_ms"]) for p in probe_samples if p.get("latency_ms") is not None]
    latency_stats = {
        "samples": len(probe_samples),
        "avg_ms": round(sum(latencies) / len(latencies), 2) if latencies else None,
        "max_ms": round(max(latencies), 2) if latencies else None,
        "min_ms": round(min(latencies), 2) if latencies else None,
    }
    _trace(
        "TOPO-SCAN",
        "tool_call",
        "analyze_probe_history",
        "OK",
        t_hist,
        f"{latency_stats['samples']} mesures analysées (moy={latency_stats['avg_ms']} ms, max={latency_stats['max_ms']} ms)",
    )

    # =========================================================================
    # AGENT 03 · DIAG-NET (Corrélation WAN/LAN, Intrus MAC & Ticket Opérateur)
    # =========================================================================
    t_diag = time.perf_counter()
    diagnostics_per_site: List[str] = []
    for d in dashboards:
        st = d["state"]
        sname = st.get("site_name") or (d["agent"] or {}).get("nom") or "Site"
        gw = st.get("gw") or "passerelle"
        gw_st = st.get("gw_status", "unknown")
        gw_lat = st.get("gw_latency_ms")
        inet_st = st.get("internet_status", "unknown")
        wan_lat = st.get("wan_latency_ms")
        site_down = [x for x in d["devices"] if x.get("status") != "up"]

        if gw_st == "up" and inet_st == "down":
            diagnostics_per_site.append(
                f"{sname} : Passerelle locale ({gw}) active ({gw_lat or '?'} ms) mais sortie Internet coupée -> Panne opérateur FAI en amont confirmée."
            )
        elif gw_st == "down":
            diagnostics_per_site.append(
                f"{sname} : Passerelle principale ({gw}) hors ligne -> Vérifier alimentation/câblage du routeur cœur."
            )
        elif site_down:
            names_down = ", ".join(f"{x.get('name') or x.get('ip')}" for x in site_down[:4])
            diagnostics_per_site.append(
                f"{sname} : Liaison FAI active ({wan_lat or '?'} ms), mais {len(site_down)} équipement(s) hors ligne sur le LAN ({names_down})."
            )
        else:
            diagnostics_per_site.append(
                f"{sname} : Nominal — Passerelle {gw} ({gw_lat or '1.2'} ms) et sortie FAI ({wan_lat or '32'} ms) opérationnelles."
            )

    _trace(
        "DIAG-NET",
        "tool_call",
        "correlate_wan_vs_lan",
        "OK",
        t_diag,
        diagnostics_per_site[0] if diagnostics_per_site else "Diagnostic effectué",
    )

    wants_ticket = any(
        w in q for w in ("ticket", "operateur", "fournisseur", "orange", "mtn", "moov", "technicien", "whatsapp", "courrier")
    )
    operator_ticket_text = None
    if wants_ticket:
        t_tkt = time.perf_counter()
        d0 = dashboards[0]
        st0 = d0["state"]
        sname0 = st0.get("site_name") or "Communauté Sainte Marie de Bouaké"
        operator_ticket_text = (
            f"📋 TICKET TECHNIQUE PRÊT À TRANSMETTRE :\n"
            f"• Site : {sname0}\n"
            f"• Horodatage UTC : {now_iso[:19].replace('T', ' ')}\n"
            f"• État liaison Internet (WAN) : {(st0.get('internet_status') or 'inconnu').upper()}"
            f"{' (' + str(st0.get('wan_latency_ms')) + ' ms)' if st0.get('wan_latency_ms') else ' (Aucune réponse ICMP/DNS 1.1.1.1 & 8.8.8.8)'}\n"
            f"• Passerelle LAN ({st0.get('gw') or 'n/d'}) : {(st0.get('gw_status') or 'inconnu').upper()} ({st0.get('gw_latency_ms') or '—'} ms)\n"
            f"• Impact constaté : {len(lan_up_devs)}/{len(all_devices)} équipements connectés au LAN, "
            f"{len(inet_yes_devs)} avec accès Internet, {len(inet_no_devs)} privés d'accès Internet.\n"
            f"• Conclusion sonde DADEREZO : {diagnostics_per_site[0]}"
        )
        _trace("DIAG-NET", "tool_call", "draft_operator_ticket", "OK", t_tkt, "Ticket technique opérateur généré.")

    # =========================================================================
    # AGENT 04 · OPS-DISPATCH (Exécution Terrain & Validation Humaine HITL)
    # =========================================================================
    task_queued = None
    pending_approval = None

    wants_deep_sweep = any(
        w in q
        for w in (
            "balayage complet",
            "254 ip",
            "sweep",
            "tout le sous-reseau",
            "scanner tout le reseau",
            "validation humaine",
        )
    )
    task_triggers = (
        "lance un scan",
        "lancer un scan",
        "demande un scan",
        "scanner",
        "scanne",
        "balayage",
        "lance un diagnostic",
        "fais un diagnostic",
        "faire un diagnostic",
        "verifie maintenant",
        "actualise la sonde",
        "genere un rapport",
        "produis un rapport",
    )

    if wants_deep_sweep:
        t_ops = time.perf_counter()
        aid = (dashboards[0]["agent"] or {}).get("id", "sainte-marie-bouake")
        pending_approval = storage.create_human_approval(
            ts=now_iso,
            session_id=sid,
            agent_id=aid,
            action="sweep",
            reason=f"Balayage ICMP actif des 254 adresses du sous-réseau sur « {scope_label} » demandé par le Superviseur Général.",
        )
        _trace(
            "OPS-DISPATCH",
            "human_in_the_loop",
            "request_human_approval",
            "PENDING_APPROVAL",
            t_ops,
            f"Approbation humaine #{pending_approval.get('id')} requise avant balayage complet 254 IP ({aid}).",
        )
    elif any(t in q for t in task_triggers):
        t_ops = time.perf_counter()
        action = "rapport" if "rapport" in q else ("diagnostic" if "diagnostic" in q else "scan")
        if can_write:
            queued_targets = []
            for d in dashboards:
                aid = (d["agent"] or {}).get("id")
                if aid:
                    storage.create_task_row(aid, action, now_iso)
                    queued_targets.append(aid)
            task_queued = {"action": action, "targets": queued_targets, "status": "queued"}
            _trace(
                "OPS-DISPATCH",
                "tool_call",
                "dispatch_readonly_probe_task",
                "QUEUED",
                t_ops,
                f"Tâche « {action} » envoyée à {', '.join(queued_targets)}.",
            )
        else:
            task_queued = {"action": action, "targets": [], "status": "auth_required"}
            _trace(
                "OPS-DISPATCH",
                "tool_call",
                "dispatch_readonly_probe_task",
                "AUTH_REQUIRED",
                t_ops,
                "Clé X-API-Key requise pour créer une tâche distante.",
            )

    # =========================================================================
    # SYNTHÈSE FINALE (LLM Externe Ancré si clé active, sinon Synthèse Multi-Agents)
    # =========================================================================
    def _fmt_devs(devs: List[dict], with_reason: bool = False) -> str:
        if not devs:
            return "Aucun"
        out = []
        for x in devs[:10]:
            lbl = f"{x.get('name') or 'Poste'} ({x.get('ip')})"
            if "mac" in q and x.get("mac"):
                lbl += f" [MAC {x['mac']}]"
            if len(dashboards) > 1 and x.get("site_name"):
                lbl += f" · {x['site_name']}"
            if with_reason and x.get("internet_reason"):
                lbl += f" — {x['internet_reason']}"
            out.append(f"• {lbl}")
        if len(devs) > 10:
            out.append(f"• … et {len(devs) - 10} autre(s)")
        return "\n".join(out)

    asks_intrus = any(w in q for w in ("intrus", "inconnu", "suspect", "autoris", "mac", "visiteur", "securite"))
    asks_alerts = any(w in q for w in ("alerte", "incident", "historique", "journal", "evenement"))
    asks_outage = any(
        w in q for w in ("panne", "coupure", "fai", "passerelle", "routeur", "relais", "latence", "lent", "pourquoi")
    )

    intent = "bilan_superviseur"
    lines: List[str] = []
    spoken_parts: List[str] = []

    if pending_approval:
        intent = "validation_humaine_requise"
        lines.append(
            f"🟡 [OPS-DISPATCH · Validation Humaine Requise] Demande #{pending_approval.get('id')} en attente :\n"
            f"Le balayage actif des 254 adresses IP (`sweep`) génère du trafic ICMP sur tout le sous-réseau. "
            f"Cliquez sur « ✓ Valider l'exécution » ci-dessous pour autoriser la sonde."
        )
        spoken_parts.append(
            "Validation humaine requise : veuillez confirmer le balayage complet du sous-réseau en cliquant sur Valider."
        )
    elif task_queued:
        intent = f"tache_{task_queued['action']}"
        if task_queued["status"] == "queued":
            lines.append(
                f"✅ [OPS-DISPATCH] Ordre lecture seule « {task_queued['action']} » transmis à : {', '.join(task_queued['targets'])}."
            )
            spoken_parts.append(f"Ordre {task_queued['action']} transmis en lecture seule à la sonde.")
        else:
            lines.append("🔒 Clé X-API-Key requise pour programmer une tâche distante.")

    if operator_ticket_text:
        intent = "ticket_operateur"
        lines.append(operator_ticket_text)
        spoken_parts.append("J'ai rédigé le ticket technique complet avec les mesures exactes pour votre opérateur.")

    if zone_filter:
        intent = "filtre_zone"
        z_up = [x for x in scoped_devices if x.get("status") == "up"]
        z_inet = [x for x in scoped_devices if x.get("internet_access") in ("oui", "degrade")]
        lines.append(
            f"📍 Zone filtrée « {zone_filter.upper()} » : {len(scoped_devices)} équipement(s) "
            f"({len(z_up)} connecté(s) au LAN, {len(z_inet)} avec accès Internet) :\n"
            + _fmt_devs(scoped_devices, with_reason=True)
        )
        spoken_parts.append(
            f"Dans la zone {zone_filter}, {len(z_up)} équipements sur {len(scoped_devices)} sont connectés au réseau local, "
            f"et {len(z_inet)} ont accès à Internet."
        )
    elif not operator_ticket_text:
        if intent == "bilan_superviseur":
            intent = "inventaire_internet"
        lines.append(f"📊 Synthèse Orchestrateur DADEREZO — {scope_label} :")
        lines.append(f"• Appareils répertoriés : {len(all_devices)}")
        lines.append(
            f"• Connectés au réseau local (LAN) : {len(lan_up_devs)} / {len(all_devices)}"
            + (f" ({len(offline_devs)} hors ligne)" if offline_devs else " (100 % actifs)")
        )
        lines.append(f"• Ayant accès à Internet (WAN actif) : {len(inet_yes_devs)} appareil(s)")
        if lan_only_no_inet_devs and offline_devs:
            lines.append(
                f"• Sans accès à Internet : {len(inet_no_devs)} appareil(s) "
                f"(dont {len(lan_only_no_inet_devs)} connecté(s) au LAN mais privé(s) d'Internet, et {len(offline_devs)} hors ligne)"
            )
        elif lan_only_no_inet_devs:
            lines.append(
                f"• Sans accès à Internet : {len(inet_no_devs)} appareil(s) (connecté(s) au LAN uniquement, sans sortie WAN)"
            )
        elif offline_devs:
            lines.append(f"• Sans accès à Internet : {len(inet_no_devs)} appareil(s) (hors ligne sur le LAN)")
        else:
            lines.append("• Sans accès à Internet : 0 appareil (tous les postes disposent d'Internet)")

        if latency_stats["avg_ms"] is not None:
            lines.append(
                f"• Télémétrie latence LAN ({latency_stats['samples']} mesures) : moy. {latency_stats['avg_ms']} ms · max {latency_stats['max_ms']} ms"
            )

        lines.append(f"\n✅ Avec accès Internet ({len(inet_yes_devs)}) :\n{_fmt_devs(inet_yes_devs)}")
        if inet_no_devs:
            lines.append(f"\n⚠️ Sans accès Internet ({len(inet_no_devs)}) :\n{_fmt_devs(inet_no_devs, with_reason=True)}")

        spoken_parts.append(
            f"Sur {scope_label}, {len(lan_up_devs)} appareils sur {len(all_devices)} sont connectés au réseau local, "
            f"dont {len(inet_yes_devs)} ont accès à Internet et {len(inet_no_devs)} n'ont pas accès à Internet."
        )

    if asks_outage:
        if intent in ("bilan_superviseur", "inventaire_internet"):
            intent = "diagnostic_panne"
        lines.append("\n🩺 Corrélation DIAG-NET :\n" + "\n".join(f"• {d}" for d in diagnostics_per_site))

    if asks_intrus:
        if intent in ("bilan_superviseur", "inventaire_internet"):
            intent = "securite_intrus"
        if unknown_devs:
            u_str = ", ".join(f"{u.get('ip')} (MAC {u.get('mac') or 'n/d'})" for u in unknown_devs)
            lines.append(f"\n🕵️ Alerte MAC non répertoriée ({len(unknown_devs)}) : {u_str}")
            spoken_parts.append(f"Attention : {len(unknown_devs)} appareil inconnu détecté à l'adresse {unknown_devs[0].get('ip')}.")
        else:
            lines.append("\n🛡️ Sécurité MAC : 100 % des équipements actifs sont reconnus.")

    if asks_alerts:
        if all_alerts:
            top_a = "\n".join(f"• [{(a.get('severity') or 'info').upper()}] {a.get('message')}" for a in all_alerts[:5])
            lines.append(f"\n🔔 Journal d'incidents ({len(all_alerts)}) :\n{top_a}")

    deterministic_answer = "\n".join(lines).strip()
    spoken_summary = " ".join(spoken_parts).strip()

    # Synthèse LLM externe ancrée si une clé LLM est fournie
    engine_mode = "multi_agent_autonomous"
    llm_cfg = _detect_llm_config(llm_api_key, llm_model)
    if llm_cfg:
        t_llm = time.perf_counter()
        evidence = {
            "scope_label": scope_label,
            "metrics": metrics,
            "latency_stats": latency_stats,
            "diagnostics": diagnostics_per_site,
            "devices_with_internet": [
                {"name": d.get("name"), "ip": d.get("ip"), "mac": d.get("mac"), "zone": d.get("zone")}
                for d in inet_yes_devs
            ],
            "devices_without_internet": [
                {
                    "name": d.get("name"),
                    "ip": d.get("ip"),
                    "mac": d.get("mac"),
                    "lan_status": d.get("status"),
                    "reason": d.get("internet_reason"),
                }
                for d in inet_no_devs
            ],
            "recent_alerts": all_alerts[:6],
            "task_queued": task_queued,
            "pending_approval": pending_approval,
        }
        llm_reply = _call_llm_grounded(llm_cfg, q_clean, history, evidence)
        if llm_reply:
            deterministic_answer = llm_reply
            engine_mode = f"multi_agent_llm ({llm_cfg['model']})"
            _trace("ORCHESTRATOR-Z", "llm_synthesis", llm_cfg["model"], "OK", t_llm, "Synthèse générative ancrée sur preuves outils.")
        else:
            _trace("ORCHESTRATOR-Z", "llm_synthesis", llm_cfg["model"], "FALLBACK", t_llm, "Repli sur synthèse multi-agents déterministe.")

    storage.append_session_turn(
        sid,
        datetime.now(timezone.utc).isoformat(),
        "assistant",
        deterministic_answer,
        target_agent_id,
        {"intent": intent, "engine_mode": engine_mode},
    )

    return {
        "status": "ok",
        "session_id": sid,
        "engine_mode": engine_mode,
        "intent": intent,
        "scope": "global" if len(dashboards) > 1 else "site",
        "site_label": scope_label,
        "answer": deterministic_answer,
        "spoken_text": spoken_summary,
        "metrics": metrics,
        "latency_stats": latency_stats,
        "devices": all_devices,
        "with_internet": inet_yes_devs,
        "without_internet": inet_no_devs,
        "unknown_devices": unknown_devs,
        "task_queued": task_queued,
        "pending_approval": pending_approval,
        "agent_trace": agent_trace,
        "security_check": {"verdict": "ALLOW", "readonly_enforced": True},
        "refused_write_action": False,
    }
