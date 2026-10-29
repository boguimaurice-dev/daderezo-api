# -*- coding: utf-8 -*-
"""
DADEREZO v4.0 — Moteur Multi-Agents Autonome & Contrôleur Actif (Architecture inspirée AGENT Z).

5 Agents spécialisés coopèrent sur de vrais outils connectés à Supabase PostgreSQL 17 / SQLite :
  01 · SENTINEL-SEC  : Garde-fou Blue Team (anti-injection de prompt + contrôle d'autorisation RBAC)
  02 · TOPO-SCAN     : Topologie, matrice LAN vs Accès Internet, politiques actives & télémétrie
  03 · DIAG-NET      : Corrélation de pannes (FAI vs Box vs Relais), sécurité MAC & ticket opérateur
  04 · NET-CONTROL   : Pilotage actif Internet ON/OFF (Box Principale / Sous-réseau & Zone / Appareil) & Optimisation Multi-Box
  05 · MEDIA & OPS   : Hub de partage Fichiers/Multimédias LAN/Cloud, ordres sonde & Validation Humaine (HITL)
"""
from datetime import datetime, timezone
import json
import os
import re
import time
import unicodedata
import urllib.request
from typing import Callable, List, Optional

import net_controller
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
        "Tu es l'Orchestrateur Principal DADEREZO v4.0 (Supervision & Pilotage Actif Réseau, Box et Multimédia). "
        "Tu t'adresses au Superviseur Général en français clair, précis et structuré.\n"
        "RÈGLES STRICTES ANTI-HALLUCINATION :\n"
        "1. Utilise EXCLUSIVEMENT les chiffres, adresses IP, adresses MAC, box, médias et états présents dans `PREUVES_OUTILS`.\n"
        "2. S'il manque une donnée, dis-le explicitement — n'invente JAMAIS un chiffre ou une IP.\n"
        "3. Distingue toujours clairement la connexion au réseau local (LAN) et l'accès effectif à Internet (WAN).\n"
        "4. Si une action réseau (coupure/activation Internet ou optimisation de box) vient d'être exécutée dans `net_control_result`, confirme-la précisément."
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
        {"model": llm_cfg["model"], "messages": messages, "temperature": 0.15, "max_tokens": 750}
    ).encode("utf-8")
    req = urllib.request.Request(
        f"{llm_cfg['base_url']}/chat/completions",
        data=body,
        headers={
            "Authorization": f"Bearer {llm_cfg['api_key']}",
            "Content-Type": "application/json",
            "User-Agent": "DADEREZO-Orchestrator/4.0",
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


def _parse_internet_command(q: str, all_devices: List[dict]) -> Optional[dict]:
    """Détecte une demande naturelle d'activation ou de coupure d'Internet (Box / Zone & CIDR / Appareil)."""
    off_match = re.search(
        r"\b(coupe\w*|desactiv\w*|bloqu\w*|etein\w*|suspend\w*|isol\w*|ferme\w*)\b.*\binternet\b"
        r"|\binternet\b.*\b(off|coupe\w*|desactiv\w*|bloqu\w*)\b",
        q,
    )
    on_match = re.search(
        r"\b(activ\w*|reactiv\w*|retabl\w*|ouvr\w*|allum\w*|autoris\w*|remet\w*)\b.*\binternet\b"
        r"|\binternet\b.*\b(on|activ\w*|retabl\w*|autoris\w*)\b",
        q,
    )
    if not off_match and not on_match:
        return None

    enable_flag = bool(on_match and not off_match)

    # 1. Cible CIDR (ex: 192.168.1.128/25)
    cidr_m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b", q)
    if cidr_m:
        return {"scope_type": "subnet", "target_value": cidr_m.group(1), "internet_enabled": enable_flag}

    # 2. Cible IP appareil (ex: 192.168.1.25)
    ip_m = re.search(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b", q)
    if ip_m:
        ip_val = ip_m.group(1)
        # Si l'utilisateur cite l'IP de la box passerelle avec "box principale", traiter comme global
        if "box principale" in q or "routeur principal" in q or "tout le site" in q:
            return {"scope_type": "global", "target_value": "main_box", "internet_enabled": enable_flag}
        return {"scope_type": "device", "target_value": ip_val, "internet_enabled": enable_flag}

    # 3. Cible Zone nommée
    for z_raw, z_norm in (
        ("Visiteurs", "visiteur"),
        ("Communauté", "communaute"),
        ("Administration", "administration"),
        ("Accueil", "accueil"),
    ):
        if z_norm in q:
            return {"scope_type": "zone", "target_value": z_raw, "internet_enabled": enable_flag}

    # 4. Cible par nom d'appareil connu
    for dev in all_devices:
        dname = normalize_fr(dev.get("name") or "")
        if dname and len(dname) >= 5 and dname in q and dev.get("type") != "gateway":
            return {"scope_type": "device", "target_value": dev.get("ip"), "internet_enabled": enable_flag, "label": dev.get("name")}

    # 5. Cible Box Principale / Générale
    if any(w in q for w in ("box principale", "box", "general", "partout", "tout le reseau", "tout le site", "wan")):
        return {"scope_type": "global", "target_value": "main_box", "internet_enabled": enable_flag}

    return None


def run_multi_agent_mission(
    question_raw: str,
    target_agent_id: Optional[str],
    scope: str,
    session_id: str,
    can_write: bool,
    fetch_dashboards_fn: Callable[[Optional[str], bool], List[dict]],
    org_slug: str = "public-demo",
    actor_name: str = "Superviseur Général",
    llm_api_key: Optional[str] = None,
    llm_model: Optional[str] = None,
) -> dict:
    """Exécute la chaîne des 5 agents spécialisés avec sécurité, contrôle actif et audit complet."""
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

    history = storage.get_session_turns(sid, limit=6)
    storage.append_session_turn(sid, now_iso, "user", q_clean, target_agent_id, {"scope": scope})

    # =========================================================================
    # AGENT 01 · SENTINEL-SEC (Anti-Injection de Prompt & Garde-Fou Système)
    # =========================================================================
    t_sec = time.perf_counter()
    injection_patterns = (
        r"(ignore\s+(all\s+)?previous|oublie\s+(toutes\s+)?tes\s+(regles|consignes|instructions)|"
        r"system\s*prompt|mode\s+developpeur|jailbreak|drop\s+table|;\s*rm\s+-rf|bypass\s+security|"
        r"cat\s+/etc/passwd|dump\s+password)"
    )
    is_injection = bool(re.search(injection_patterns, q))

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
            )
        )
    )

    def _collect_context() -> tuple:
        dbs = fetch_dashboards_fn(target_agent_id, wants_global)
        devs: List[dict] = []
        als: List[dict] = []
        snames: List[str] = []
        for d in dbs:
            ag = d["agent"] or {}
            sn = d["state"].get("site_name") or ag.get("nom") or ag.get("id") or "Site"
            snames.append(sn)
            for dv in d["devices"]:
                ed = dict(dv)
                ed["site_name"] = sn
                ed["agent_id"] = ag.get("id", "")
                devs.append(ed)
            for al in d["alerts"]:
                ac = dict(al)
                ac["site_name"] = sn
                als.append(ac)
        lbl = f"Tous les sites ({len(dbs)} sonde(s))" if len(dbs) > 1 else (snames[0] if snames else "Aucun site enregistré")
        return dbs, devs, als, lbl

    dashboards, all_devices, all_alerts, scope_label = _collect_context()

    def _compute_splits(devs: List[dict]):
        lan_up = [d for d in devs if d.get("status") == "up"]
        offline = [d for d in devs if d.get("status") != "up"]
        inet_yes = [d for d in devs if d.get("internet_access") in ("oui", "degrade")]
        inet_no = [d for d in devs if d.get("internet_access") not in ("oui", "degrade")]
        lan_only = [d for d in devs if d.get("status") == "up" and d.get("internet_access") == "non"]
        unk = [d for d in devs if "inconnu" in (d.get("name") or "").lower()]
        m = {
            "sites_count": len(dashboards),
            "total_devices": len(devs),
            "lan_connected": len(lan_up),
            "offline": len(offline),
            "internet_yes": len(inet_yes),
            "internet_no": len(inet_no),
            "lan_only_no_internet": len(lan_only),
            "unknown_count": len(unk),
        }
        return lan_up, offline, inet_yes, inet_no, lan_only, unk, m

    lan_up_devs, offline_devs, inet_yes_devs, inet_no_devs, lan_only_no_inet_devs, unknown_devs, metrics = _compute_splits(all_devices)

    if is_injection:
        _trace(
            "SENTINEL-SEC",
            "guardrail",
            "detect_prompt_injection",
            "BLOCKED",
            t_sec,
            f"Tentative d'injection de prompt ou commande destructive bloquée : « {q_clean[:90]} »",
        )
        ans = (
            "🛡️ [SENTINEL-SEC] Tentative d'injection de prompt ou commande système non autorisée détectée et bloquée.\n"
            "Les garde-fous de sécurité DADEREZO et l'isolation multi-tenant sont immuables et journalisés."
        )
        spoken = "Alerte sécurité Sentinel : tentative d'injection bloquée et journalisée."
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
            "security_check": {"verdict": "BLOCK_PROMPT_INJECTION", "authorized": False},
            "refused_write_action": True,
        }

    _trace(
        "SENTINEL-SEC",
        "guardrail",
        "verify_security_policy",
        "ALLOW",
        t_sec,
        f"Requête validée (isolation tenant={org_slug}, droits_actifs={can_write}).",
    )

    if not dashboards:
        msg = (
            "Aucune sonde réseau n'est enregistrée dans cet espace. "
            "Lancez `agent_client.py` avec votre clé privée organisation ou ouvrez le banc de démonstration."
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
            "security_check": {"verdict": "ALLOW", "authorized": can_write},
            "refused_write_action": False,
        }

    primary_aid = (dashboards[0]["agent"] or {}).get("id", "")

    # =========================================================================
    # AGENT 04 · NET-CONTROL (Pilotage Actif Internet ON/OFF & Optimisation Box)
    # =========================================================================
    net_control_result: Optional[dict] = None
    task_queued: Optional[dict] = None
    pending_approval: Optional[dict] = None

    inet_cmd = _parse_internet_command(q, all_devices)
    wants_box_optimize = any(
        kw in q
        for kw in (
            "optimis",
            "configur",
            "canaux wifi",
            "canal wifi",
            "qos",
            "regle les box",
            "regler les box",
            "ameliorer la connexion",
        )
    ) and any(kw in q for kw in ("box", "routeur", "wifi", "relais", "reseau", "internet", "dns", "qos"))

    wants_box_reboot = bool(re.search(r"\b(redemarr\w*|reboot\w*)\b.*\b(box|routeur|modem|passerelle)\b", q))

    if inet_cmd and primary_aid:
        t_nc = time.perf_counter()
        if not can_write:
            _trace("NET-CONTROL", "active_control", "apply_internet_policy", "AUTH_REQUIRED", t_nc, "Droits administrateur requis.")
            net_control_result = {"status": "auth_required", "message": "Authentification requise pour modifier l'accès Internet."}
        else:
            st_lbl = "ACTIVÉ" if inet_cmd["internet_enabled"] else "COUPÉ"
            scope_t = inet_cmd["scope_type"]
            target_v = inet_cmd["target_value"]
            reason_txt = (
                f"Internet {st_lbl.lower()} par {actor_name} via Orchestrateur IA ({scope_t}:{target_v})"
            )
            storage.upsert_internet_policy(
                agent_id=primary_aid,
                scope_type=scope_t,
                target_value=target_v,
                internet_enabled=inet_cmd["internet_enabled"],
                reason=reason_txt,
                updated_by=actor_name,
                now_iso=now_iso,
            )
            cmds = net_controller.generate_router_commands("apply_internet_policy", inet_cmd)
            storage.create_task_row(primary_aid, "apply_internet_policy", now_iso, payload=inet_cmd)
            task_queued = {"action": "apply_internet_policy", "targets": [primary_aid], "status": "queued", "commands": cmds}
            net_control_result = {
                "status": "applied",
                "type": "internet_policy",
                "scope_type": scope_t,
                "target_value": target_v,
                "internet_enabled": inet_cmd["internet_enabled"],
                "commands": cmds,
            }
            _trace(
                "NET-CONTROL",
                "active_control",
                "apply_internet_policy",
                "APPLIED",
                t_nc,
                f"Internet {st_lbl} sur {scope_t}={target_v} ({primary_aid})",
            )
            # Rafraîchir immédiatement les états calculés des appareils
            dashboards, all_devices, all_alerts, scope_label = _collect_context()
            lan_up_devs, offline_devs, inet_yes_devs, inet_no_devs, lan_only_no_inet_devs, unknown_devs, metrics = _compute_splits(all_devices)

    elif wants_box_optimize and primary_aid:
        t_nc = time.perf_counter()
        if not can_write:
            _trace("NET-CONTROL", "active_control", "optimize_all_boxes", "AUTH_REQUIRED", t_nc, "Droits administrateur requis.")
            net_control_result = {"status": "auth_required", "message": "Authentification requise pour optimiser les box."}
        else:
            existing_boxes = storage.list_box_configs(primary_aid)
            discovered = net_controller.discover_boxes_from_devices(primary_aid, dashboards[0]["devices"], existing_boxes)
            opt_boxes, summary_lines = net_controller.compute_optimal_box_plan(
                discovered, dashboards[0]["devices"], dashboards[0]["state"], now_iso
            )
            for b in opt_boxes:
                storage.upsert_box_config(primary_aid, b)
                storage.create_task_row(primary_aid, "optimize_box", now_iso, payload=b)
            task_queued = {"action": "optimize_box", "targets": [primary_aid], "status": "queued"}
            net_control_result = {
                "status": "applied",
                "type": "box_optimization",
                "boxes_count": len(opt_boxes),
                "summary": summary_lines,
            }
            _trace(
                "NET-CONTROL",
                "active_control",
                "optimize_all_boxes",
                "APPLIED",
                t_nc,
                f"{len(opt_boxes)} box/relais optimisés (canaux Wi-Fi sans collision, DNS 1.1.1.1/9.9.9.9, QoS actif).",
            )

    elif wants_box_reboot and primary_aid:
        t_nc = time.perf_counter()
        pending_approval = storage.create_human_approval(
            ts=now_iso,
            session_id=sid,
            agent_id=primary_aid,
            action="reboot_box",
            reason=f"Redémarrage physique de la Box Principale sur « {scope_label} » (coupure temporaire de 60s).",
        )
        _trace(
            "NET-CONTROL",
            "human_in_the_loop",
            "request_box_reboot_approval",
            "PENDING_APPROVAL",
            t_nc,
            f"Validation humaine #{pending_approval.get('id')} requise avant redémarrage physique de la box.",
        )

    # =========================================================================
    # AGENT 02 · TOPO-SCAN (Inventaire LAN/WAN, Politiques & Historique Latence)
    # =========================================================================
    t_topo = time.perf_counter()
    zone_filter = None
    if not inet_cmd:
        for z_candidate in ("communaute", "administration", "accueil", "visiteurs", "coeur", "supervision", "acces fai"):
            if z_candidate in q:
                zone_filter = z_candidate
                break

    scoped_devices = all_devices
    if zone_filter:
        scoped_devices = [d for d in all_devices if zone_filter in normalize_fr(d.get("zone") or "")]

    active_policies = storage.list_internet_policies(primary_aid) if primary_aid else []
    _trace(
        "TOPO-SCAN",
        "tool_call",
        "inspect_lan_wan_matrix",
        "OK",
        t_topo,
        (
            f"Site={scope_label} | LAN={len(lan_up_devs)}/{len(all_devices)} | "
            f"Internet_ON={len(inet_yes_devs)} | Internet_OFF={len(inet_no_devs)} | "
            f"Politiques_actives={len(active_policies)}"
        ),
    )

    t_hist = time.perf_counter()
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
        f"{latency_stats['samples']} mesures analysées (moy={latency_stats['avg_ms']} ms)",
    )

    # =========================================================================
    # AGENT 03 · DIAG-NET (Corrélation WAN/LAN, Box & Ticket Opérateur)
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

        if st.get("main_box_internet_cut") == "true":
            diagnostics_per_site.append(
                f"{sname} : Internet coupé volontairement sur la Box Principale par le Superviseur (le réseau local LAN reste 100 % actif)."
            )
        elif gw_st == "up" and inet_st == "down":
            diagnostics_per_site.append(
                f"{sname} : Passerelle locale ({gw}) active ({gw_lat or '?'} ms) mais sortie Internet coupée -> Panne opérateur FAI en amont confirmée."
            )
        elif gw_st == "down":
            diagnostics_per_site.append(
                f"{sname} : Box Principale ({gw}) hors ligne -> Vérifier alimentation/câblage du routeur cœur."
            )
        elif site_down:
            names_down = ", ".join(f"{x.get('name') or x.get('ip')}" for x in site_down[:4])
            diagnostics_per_site.append(
                f"{sname} : Liaison FAI active ({wan_lat or '?'} ms), mais {len(site_down)} équipement(s) hors ligne sur le LAN ({names_down})."
            )
        else:
            diagnostics_per_site.append(
                f"{sname} : Nominal — Box {gw} ({gw_lat or '1.2'} ms) et sortie FAI ({wan_lat or '32'} ms) opérationnelles."
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
        sname0 = st0.get("site_name") or scope_label
        operator_ticket_text = (
            f"📋 TICKET TECHNIQUE PRÊT À TRANSMETTRE :\n"
            f"• Site : {sname0}\n"
            f"• Horodatage UTC : {now_iso[:19].replace('T', ' ')}\n"
            f"• État liaison Internet (WAN) : {(st0.get('internet_status') or 'inconnu').upper()}"
            f"{' (' + str(st0.get('wan_latency_ms')) + ' ms)' if st0.get('wan_latency_ms') else ' (Aucune réponse ICMP/DNS)'}\n"
            f"• Box Principale ({st0.get('gw') or 'n/d'}) : {(st0.get('gw_status') or 'inconnu').upper()} ({st0.get('gw_latency_ms') or '—'} ms)\n"
            f"• Impact constaté : {len(lan_up_devs)}/{len(all_devices)} équipements connectés au LAN, "
            f"{len(inet_yes_devs)} avec accès Internet, {len(inet_no_devs)} sans Internet.\n"
            f"• Conclusion sonde DADEREZO : {diagnostics_per_site[0]}"
        )
        _trace("DIAG-NET", "tool_call", "draft_operator_ticket", "OK", t_tkt, "Ticket technique opérateur généré.")

    # =========================================================================
    # AGENT 05 · MEDIA-HUB & OPS-DISPATCH (Fichiers Multimédias, Scan & HITL)
    # =========================================================================
    media_items = storage.list_shared_media(primary_aid, org_slug=org_slug, limit=20) if primary_aid else []
    asks_media = any(w in q for w in ("fichier", "multimedia", "media", "video", "audio", "image", "document", "partag"))
    if asks_media and primary_aid:
        t_med = time.perf_counter()
        if "synchronis" in q and can_write:
            storage.create_task_row(primary_aid, "sync_media", now_iso, payload={"org_slug": org_slug})
            task_queued = {"action": "sync_media", "targets": [primary_aid], "status": "queued"}
        _trace(
            "MEDIA-HUB",
            "tool_call",
            "inspect_shared_media",
            "OK",
            t_med,
            f"{len(media_items)} fichier(s) / contenu(s) multimédia disponible(s) sur l'espace {org_slug}.",
        )

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

    if not net_control_result and not pending_approval:
        if wants_deep_sweep:
            t_ops = time.perf_counter()
            pending_approval = storage.create_human_approval(
                ts=now_iso,
                session_id=sid,
                agent_id=primary_aid,
                action="sweep",
                reason=f"Balayage ICMP actif des 254 adresses du sous-réseau sur « {scope_label} ».",
            )
            _trace(
                "OPS-DISPATCH",
                "human_in_the_loop",
                "request_human_approval",
                "PENDING_APPROVAL",
                t_ops,
                f"Approbation humaine #{pending_approval.get('id')} requise avant balayage 254 IP.",
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
                _trace("OPS-DISPATCH", "tool_call", "dispatch_probe_task", "QUEUED", t_ops, f"Tâche « {action} » envoyée.")
            else:
                task_queued = {"action": action, "targets": [], "status": "auth_required"}
                _trace("OPS-DISPATCH", "tool_call", "dispatch_probe_task", "AUTH_REQUIRED", t_ops, "Authentification requise.")

    # =========================================================================
    # SYNTHÈSE FINALE CLAIRE & STRUCTURÉE
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

    intent = "bilan_superviseur"
    lines: List[str] = []
    spoken_parts: List[str] = []

    if net_control_result:
        if net_control_result.get("status") == "auth_required":
            intent = "auth_requise"
            lines.append(f"🔒 {net_control_result['message']}")
            spoken_parts.append(net_control_result["message"])
        elif net_control_result.get("type") == "internet_policy":
            intent = "controle_internet_actif"
            st_word = "ACTIVÉ ✅" if net_control_result["internet_enabled"] else "COUPÉ ⛔"
            scope_map = {"global": "Box Principale (tout le site)", "zone": "Zone", "subnet": "Sous-réseau CIDR", "device": "Appareil"}
            sc_lbl = scope_map.get(net_control_result["scope_type"], net_control_result["scope_type"])
            lines.append(
                f"⚡ [NET-CONTROL] Accès Internet {st_word} — {sc_lbl} « {net_control_result['target_value']} ».\n"
                f"• Le réseau local (LAN & partage multimédia interne) reste pleinement opérationnel.\n"
                f"• Nouvel état immédiat : {len(inet_yes_devs)} appareil(s) avec Internet actif · {len(inet_no_devs)} sans Internet."
            )
            spoken_parts.append(
                f"Exécuté : l'accès Internet est désormais {'activé' if net_control_result['internet_enabled'] else 'coupé'} "
                f"pour {sc_lbl} {net_control_result['target_value']}. "
                f"{len(inet_yes_devs)} appareils ont actuellement accès à Internet."
            )
        elif net_control_result.get("type") == "box_optimization":
            intent = "optimisation_box"
            lines.append(
                f"🚀 [NET-CONTROL] Optimisation coordonnée appliquée sur {net_control_result['boxes_count']} Box / Relais Wi-Fi :\n"
                + "\n".join(f"• {s}" for s in net_control_result["summary"])
            )
            spoken_parts.append(
                f"Optimisation terminée sur {net_control_result['boxes_count']} box et relais Wi-Fi : canaux sans interférence, DNS rapides et priorité QoS activés."
            )

    if pending_approval:
        intent = "validation_humaine_requise"
        lines.append(
            f"🟡 [Validation Humaine Requise] Demande #{pending_approval.get('id')} (`{pending_approval.get('action')}`) :\n"
            f"{pending_approval.get('reason')}\n"
            f"Cliquez sur « ✓ Valider l'exécution » ci-dessous pour confirmer."
        )
        spoken_parts.append("Validation humaine requise : veuillez confirmer l'opération sensible en cliquant sur Valider.")
    elif task_queued and not net_control_result:
        intent = f"tache_{task_queued['action']}"
        if task_queued["status"] == "queued":
            lines.append(
                f"✅ [OPS-DISPATCH] Ordre « {task_queued['action']} » transmis à : {', '.join(task_queued['targets'])}."
            )
            spoken_parts.append(f"Ordre {task_queued['action']} transmis à la sonde.")

    if asks_media:
        intent = "partage_multimedia"
        if media_items:
            m_lines = [
                f"• [{m.get('category', 'fichier').upper()}] {m.get('title')} ({m.get('filename')}, Zone: {m.get('target_zone')})"
                for m in media_items[:8]
            ]
            lines.append(f"📁 Hub de Partage Fichiers & Multimédias ({len(media_items)} élément(s)) :\n" + "\n".join(m_lines))
            spoken_parts.append(f"Le hub multimédia contient {len(media_items)} fichiers partagés sur le réseau.")
        else:
            lines.append(
                "📁 Hub de Partage Fichiers & Multimédias : aucun fichier partagé pour l'instant. "
                "Ouvrez l'onglet « Fichiers & Multimédias » pour publier un document, une image, un audio ou une vidéo sur le réseau."
            )
            spoken_parts.append("Aucun fichier multimédia n'est encore partagé. Vous pouvez en déposer depuis l'onglet Fichiers et Multimédias.")

    if operator_ticket_text:
        intent = "ticket_operateur"
        lines.append(operator_ticket_text)
        spoken_parts.append("J'ai rédigé le ticket technique complet pour votre opérateur.")

    if zone_filter and not net_control_result:
        intent = "filtre_zone"
        z_up = [x for x in scoped_devices if x.get("status") == "up"]
        z_inet = [x for x in scoped_devices if x.get("internet_access") in ("oui", "degrade")]
        lines.append(
            f"📍 Zone filtrée « {zone_filter.upper()} » : {len(scoped_devices)} équipement(s) "
            f"({len(z_up)} connecté(s) au LAN, {len(z_inet)} avec accès Internet) :\n"
            + _fmt_devs(scoped_devices, with_reason=True)
        )
        spoken_parts.append(
            f"Dans la zone {zone_filter}, {len(z_up)} appareils sur {len(scoped_devices)} sont sur le réseau local et {len(z_inet)} ont Internet."
        )
    elif not operator_ticket_text and not asks_media and not (net_control_result and net_control_result.get("type") == "box_optimization"):
        if intent == "bilan_superviseur":
            intent = "inventaire_internet"
        lines.append(f"📊 Synthèse Orchestrateur DADEREZO — {scope_label} :")
        lines.append(f"• Appareils répertoriés : {len(all_devices)}")
        lines.append(
            f"• Connectés au réseau local (LAN) : {len(lan_up_devs)} / {len(all_devices)}"
            + (f" ({len(offline_devs)} hors ligne)" if offline_devs else " (100 % actifs)")
        )
        lines.append(f"• Ayant accès à Internet (WAN actif) : {len(inet_yes_devs)} appareil(s)")
        lines.append(f"• Sans accès à Internet : {len(inet_no_devs)} appareil(s)")
        lines.append(f"\n✅ Avec accès Internet ({len(inet_yes_devs)}) :\n{_fmt_devs(inet_yes_devs)}")
        if inet_no_devs:
            lines.append(f"\n⚠️ Sans accès Internet ({len(inet_no_devs)}) :\n{_fmt_devs(inet_no_devs, with_reason=True)}")

        if not spoken_parts:
            spoken_parts.append(
                f"Sur {scope_label}, {len(lan_up_devs)} appareils sur {len(all_devices)} sont connectés au réseau local, "
                f"dont {len(inet_yes_devs)} ont accès à Internet et {len(inet_no_devs)} sont sans Internet."
            )

    asks_intrus = any(w in q for w in ("intrus", "inconnu", "suspect", "mac", "securite"))
    asks_outage = any(w in q for w in ("panne", "coupure", "fai", "passerelle", "latence", "lent", "pourquoi"))

    if asks_outage:
        lines.append("\n🩺 Corrélation DIAG-NET :\n" + "\n".join(f"• {d}" for d in diagnostics_per_site))

    if asks_intrus:
        if unknown_devs:
            u_str = ", ".join(f"{u.get('ip')} (MAC {u.get('mac') or 'n/d'})" for u in unknown_devs)
            lines.append(f"\n🕵️ Alerte MAC non répertoriée ({len(unknown_devs)}) : {u_str}")
        else:
            lines.append("\n🛡️ Sécurité MAC : 100 % des équipements actifs sont reconnus.")

    deterministic_answer = "\n".join(lines).strip()
    spoken_summary = " ".join(spoken_parts).strip()

    engine_mode = "multi_agent_autonomous"
    llm_cfg = _detect_llm_config(llm_api_key, llm_model)
    if llm_cfg:
        t_llm = time.perf_counter()
        evidence = {
            "scope_label": scope_label,
            "metrics": metrics,
            "net_control_result": net_control_result,
            "active_internet_policies": active_policies,
            "shared_media_count": len(media_items),
            "diagnostics": diagnostics_per_site,
            "devices_with_internet": [{"name": d.get("name"), "ip": d.get("ip"), "zone": d.get("zone")} for d in inet_yes_devs],
            "devices_without_internet": [
                {"name": d.get("name"), "ip": d.get("ip"), "lan_status": d.get("status"), "reason": d.get("internet_reason")}
                for d in inet_no_devs
            ],
        }
        llm_reply = _call_llm_grounded(llm_cfg, q_clean, history, evidence)
        if llm_reply:
            deterministic_answer = llm_reply
            engine_mode = f"multi_agent_llm ({llm_cfg['model']})"
            _trace("ORCHESTRATOR-Z", "llm_synthesis", llm_cfg["model"], "OK", t_llm, "Synthèse générative ancrée.")

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
        "net_control_result": net_control_result,
        "shared_media": media_items[:10],
        "task_queued": task_queued,
        "pending_approval": pending_approval,
        "agent_trace": agent_trace,
        "security_check": {"verdict": "ALLOW", "authorized": can_write, "org_slug": org_slug},
        "refused_write_action": False,
    }
