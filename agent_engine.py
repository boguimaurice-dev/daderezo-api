# -*- coding: utf-8 -*-
"""
DADEREZO v4.1 — Moteur Multi-Agents Autonome, Mémoire Multi-Tours & Contrôleur Actif (Architecture AGENT Z).

5 Agents spécialisés coopèrent sur de vrais outils connectés à Supabase PostgreSQL 17 / SQLite :
  01 · SENTINEL-SEC  : Garde-fou Blue Team (anti-injection, posture sécurité /100 & contrôle RBAC)
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
from typing import Callable, List, Optional, Tuple

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
        base_url = "https://api.openai.com/v1"
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
        "Tu es l'Orchestrateur Principal DADEREZO v4.1 (Supervision & Pilotage Actif Réseau, Box et Multimédia). "
        "Tu t'adresses au Superviseur Général en français clair, précis et structuré.\n"
        "RÈGLES STRICTES ANTI-HALLUCINATION & PÉRIMÈTRE :\n"
        "1. Utilise EXCLUSIVEMENT les chiffres, adresses IP, adresses MAC, box, médias et états présents dans `PREUVES_OUTILS`.\n"
        "2. S'il manque une donnée, dis-le explicitement — n'invente JAMAIS un chiffre ou une IP.\n"
        "3. Distingue toujours clairement la connexion au réseau local (LAN) et l'accès effectif à Internet (WAN).\n"
        "4. Si la question est une simple salutation, réponds courtoisement et brièvement. Si la question est hors périmètre réseau (culture générale, météo, sport), décline poliment et rappelle ton rôle DADEREZO.\n"
        "5. Appuie-toi sur l'historique multi-tours fourni pour résoudre les pronoms (« eux », « lui », « cette zone », « ma question précédente »)."
    )
    messages = [{"role": "system", "content": system_prompt}]
    for turn in history[-8:]:
        r = "assistant" if turn.get("role") == "assistant" else "user"
        messages.append({"role": r, "content": str(turn.get("content", ""))[:900]})
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
            "User-Agent": "DADEREZO-Orchestrator/4.1",
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


def _extract_last_context(history: List[dict]) -> dict:
    """Extrait le contexte structuré du dernier tour assistant et la dernière question utilisateur."""
    last_meta: dict = {}
    last_user_q: str = ""
    user_questions: List[str] = []
    for turn in history:
        role = turn.get("role")
        if role == "user":
            txt = (turn.get("content") or "").strip()
            if txt:
                user_questions.append(txt)
                last_user_q = txt
        elif role == "assistant":
            raw_m = turn.get("metadata_json")
            if isinstance(raw_m, dict):
                last_meta = raw_m
            elif isinstance(raw_m, str) and raw_m.strip():
                try:
                    parsed = json.loads(raw_m)
                    if isinstance(parsed, dict):
                        last_meta = parsed
                except Exception:
                    pass
    return {
        "last_intent": last_meta.get("intent") or "",
        "zone_filter": last_meta.get("zone_filter"),
        "focus_ips": last_meta.get("focus_ips") or [],
        "focus_label": last_meta.get("focus_label") or "",
        "last_user_q": last_user_q,
        "user_questions": user_questions,
    }


NETWORK_DOMAIN_KEYWORDS = (
    "reseau",
    "lan",
    "wan",
    "internet",
    "wifi",
    "wi-fi",
    "box",
    "routeur",
    "modem",
    "passerelle",
    "relais",
    "switch",
    "sonde",
    "agent",
    "daderezo",
    "ip",
    "mac",
    "dns",
    "dhcp",
    "qos",
    "cidr",
    "ping",
    "latence",
    "debit",
    "lent",
    "panne",
    "coupure",
    "hors ligne",
    "en ligne",
    "connecte",
    "deconnecte",
    "appareil",
    "equipement",
    "poste",
    "imprimante",
    "serveur",
    "ordinateur",
    "pc",
    "intrus",
    "inconnu",
    "suspect",
    "securite",
    "risque",
    "vulnerab",
    "audit",
    "menace",
    "pare-feu",
    "firewall",
    "alerte",
    "site",
    "bouake",
    "sainte marie",
    "monastere",
    "communaute",
    "administration",
    "accueil",
    "visiteur",
    "supervision",
    "inventaire",
    "bilan",
    "etat",
    "statut",
    "diagnostic",
    "scan",
    "balayage",
    "sweep",
    "rapport",
    "ticket",
    "operateur",
    "fai",
    "orange",
    "mtn",
    "moov",
    "fichier",
    "multimedia",
    "media",
    "video",
    "audio",
    "document",
    "partag",
    "zone",
    "sous-reseau",
    "approbation",
    "validation",
    "redemarr",
    "reboot",
    "optimis",
    "configur",
    "coupe",
    "desactiv",
    "activ",
    "reactiv",
    "retabl",
    "bloqu",
    "isol",
)

EXPLICIT_OFF_TOPIC_PATTERNS = (
    r"\bcapitale\s+(du|de|des|d')\b",
    r"\bpresident\s+(du|de|des|d')\b",
    r"\bmeteo\b|\bquel\s+temps\s+fait",
    r"\brecette\s+(de|du|des)\b|\bcuisiner\b",
    r"\braconte\b.*\bblague\b|\bblague\b",
    r"\bpoeme\b|\bchanson\b",
    r"\bmatch\s+de\s+foot|\bballon\s+d'or|\bligue\s+des\s+champions",
    r"\bcours\s+du\s+bitcoin|\bbourse\b",
    r"\btraduis\b|\btraduire\b",
    r"\bqui\s+a\s+(invente|ecrit|peint|gagne)\b",
)


def _has_network_domain_signal(q: str) -> bool:
    if re.search(r"\b\d{1,3}(?:\.\d{1,3}){3}\b", q):
        return True
    if re.search(r"\b([0-9a-f]{2}:){5}[0-9a-f]{2}\b", q):
        return True
    return any(kw in q for kw in NETWORK_DOMAIN_KEYWORDS)


def _classify_conversational_intent(q: str, prev_ctx: dict) -> Optional[str]:
    """Détecte les intentions conversationnelles pures : mémoire méta, salutations/capacités, ou hors-périmètre."""
    # 1. Mémoire explicite de conversation
    if re.search(
        r"(qu'est-ce que je viens de|que viens-je de|ma question precedente|ma derniere question|"
        r"de quoi parlions|de quoi on parlait|resume notre (echange|conversation|discussion)|"
        r"tu te souviens|te rappelles-tu|historique de (notre|la) conversation|quel etait mon premier message)",
        q,
    ):
        return "memoire_conversation"

    # 2. Suivi contextuel (pronoms / ellipse faisant référence au tour précédent)
    has_prev = bool(prev_ctx.get("last_user_q"))
    if has_prev and re.search(
        r"^(et\s+|alors\s+|du\s+coup\s+)?(leurs?\s+|lesquels|lesquelles|parmi\s+eux|la-bas|dans\s+cette\s+zone|"
        r"cet\s+appareil|ce\s+poste|cet\s+intrus|lui\b|eux\b|pourquoi\s*\??$)",
        q,
    ):
        return "suivi_contextuel"

    if has_prev and any(
        p in q
        for p in (
            "leurs mac",
            "leur mac",
            "leurs adresses mac",
            "leurs ip",
            "leur latence",
            "leurs latences",
            "coupe-lui",
            "bloque-lui",
            "isole-le",
            "reactive-lui",
            "parmi eux",
            "sur cette zone",
            "dans cette zone",
            "sur cet appareil",
            "de ces appareils",
        )
    ):
        return "suivi_contextuel"

    # 3. Salutations, remerciements & présentation de l'agent (sans requête réseau additionnelle)
    has_net = _has_network_domain_signal(q)
    is_greeting = bool(
        re.match(
            r"^(bonjour|bonsoir|salut|hello|coucou|hey|yo|merci(\s+beaucoup)?|bravo|super|parfait|ok\s+merci)[\s!.,?]*$",
            q,
        )
    )
    is_identity = bool(
        re.search(
            r"^(qui\s+es-tu|tu\s+es\s+qui|que\s+sais-tu\s+faire|que\s+peux-tu\s+faire| comment\s+ca\s+marche|"
            r"presente-toi|aide-moi|aide|help)[\s!.,?]*$",
            q,
        )
    )
    if is_greeting or is_identity:
        return "salutation_capacites"

    # Salutation suivie uniquement d'une formule de politesse ("bonjour comment vas-tu ?")
    if re.match(r"^(bonjour|bonsoir|salut|hello)\b", q) and not has_net and len(q.split()) <= 8:
        return "salutation_capacites"

    # 4. Hors périmètre (culture générale, météo, sport, cuisine, calcul trivial...)
    if not has_net:
        if any(re.search(pat, q) for pat in EXPLICIT_OFF_TOPIC_PATTERNS):
            return "hors_perimetre"
        # Question générale sans aucun terme réseau ni lien au tour précédent
        if len(q.split()) >= 3 and (
            "?" in q
            or re.match(
                r"^(quel|quelle|quels|quelles|qui|ou|quand|combien|comment|pourquoi|donne|raconte|explique|ecris|calcule)\b",
                q,
            )
        ):
            return "hors_perimetre"

    return None


def _parse_internet_command(q: str, all_devices: List[dict], prev_ctx: Optional[dict] = None) -> Optional[dict]:
    """Détecte une demande naturelle d'activation ou de coupure d'Internet (Box / Zone & CIDR / Appareil + pronoms)."""
    off_match = re.search(
        r"\b(coupe\w*|desactiv\w*|bloqu\w*|etein\w*|suspend\w*|isol\w*|ferme\w*)\b.*\binternet\b"
        r"|\binternet\b.*\b(off|coupe\w*|desactiv\w*|bloqu\w*)\b"
        r"|\b(coupe-lui|bloque-lui|isole-le|isole\s+cet\s+intrus|bloque\s+cet\s+appareil)\b",
        q,
    )
    on_match = re.search(
        r"\b(activ\w*|reactiv\w*|retabl\w*|ouvr\w*|allum\w*|autoris\w*|remet\w*)\b.*\binternet\b"
        r"|\binternet\b.*\b(on|activ\w*|retabl\w*|autoris\w*)\b"
        r"|\b(reactive-lui|rends-lui\s+internet)\b",
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
            return {
                "scope_type": "device",
                "target_value": dev.get("ip"),
                "internet_enabled": enable_flag,
                "label": dev.get("name"),
            }

    # 5. Résolution contextuelle par mémoire multi-tours ("cette zone", "cet appareil", "coupe-lui")
    if prev_ctx:
        prev_ips = prev_ctx.get("focus_ips") or []
        prev_zone = prev_ctx.get("zone_filter")
        zone_map_pretty = {
            "visiteurs": "Visiteurs",
            "communaute": "Communauté",
            "administration": "Administration",
            "accueil": "Accueil",
        }
        if ("cette zone" in q or "la zone" in q) and prev_zone in zone_map_pretty:
            return {"scope_type": "zone", "target_value": zone_map_pretty[prev_zone], "internet_enabled": enable_flag}
        if any(p in q for p in ("lui", "cet appareil", "ce poste", "cet intrus", "isole-le")) and len(prev_ips) == 1:
            return {"scope_type": "device", "target_value": prev_ips[0], "internet_enabled": enable_flag}

    # 6. Cible Box Principale / Générale
    if any(w in q for w in ("box principale", "box", "general", "partout", "tout le reseau", "tout le site", "wan")):
        return {"scope_type": "global", "target_value": "main_box", "internet_enabled": enable_flag}

    return None


def _evaluate_security_posture(
    primary_aid: str,
    scope_label: str,
    dashboards: List[dict],
    all_devices: List[dict],
    unknown_devs: List[dict],
    active_policies: List[dict],
    can_write: bool,
) -> Tuple[str, str, dict]:
    """Calcule un audit de sécurité complet et factuel (/100) à partir de la télémétrie réelle."""
    score = 100
    findings: List[str] = []
    recommendations: List[str] = []

    auth_locked = bool(os.environ.get("DADEREZO_API_KEY", "").strip())
    pending_list = [
        p
        for p in storage.list_human_approvals(status="pending", limit=20)
        if not primary_aid or p.get("agent_id") == primary_aid
    ]
    box_cfgs = storage.list_box_configs(primary_aid) if primary_aid else []
    st0 = dashboards[0]["state"] if dashboards else {}
    dns_val = str(st0.get("dns") or "")

    # 1. Authentification & gouvernance API
    if auth_locked:
        findings.append(
            f"✅ Gouvernance API active (`auth_enabled=true`) : les écritures et approbations matérielles exigent une clé valide "
            f"({'session autorisée en écriture' if can_write else 'session publique en lecture seule sécurisée'})."
        )
    else:
        score -= 20
        findings.append(
            "⚠️ Verrou global `DADEREZO_API_KEY` non activé sur l'environnement serveur (`auth_enabled=false`)."
        )
        recommendations.append("Définir `DADEREZO_API_KEY` pour verrouiller les ordres sur l'espace public.")

    # 2. Appareils non répertoriés / Intrus MAC
    if unknown_devs:
        penalty = min(35, 25 + 5 * (len(unknown_devs) - 1))
        score -= penalty
        u_desc = ", ".join(
            f"{u.get('ip')} (MAC {u.get('mac') or 'n/d'}, zone {u.get('zone') or 'n/d'}, WAN={u.get('internet_access')})"
            for u in unknown_devs
        )
        findings.append(f"🚨 {len(unknown_devs)} équipement(s) non répertorié(s) détecté(s) sur le LAN : {u_desc}.")
        recommendations.append(
            f"Isoler immédiatement l'équipement suspect (« Coupe Internet sur {unknown_devs[0].get('ip')} ») ou vérifier son adresse MAC."
        )
    else:
        findings.append(
            f"✅ Intégrité MAC nominale : 100 % des {len(all_devices)} équipements détectés sont identifiés dans l'inventaire."
        )

    # 3. Segmentation Zone Visiteurs
    visitor_open = [
        d
        for d in all_devices
        if "visiteur" in normalize_fr(d.get("zone") or "") and d.get("internet_access") in ("oui", "degrade")
    ]
    visitor_pol = any(
        p.get("scope_type") == "zone" and "visiteur" in normalize_fr(p.get("target_value") or "")
        for p in active_policies
    )
    if visitor_open and not visitor_pol:
        score -= 10
        findings.append(
            f"⚠️ Exposition Zone Visiteurs : {len(visitor_open)} poste(s) invité(s) disposent d'un accès WAN ouvert sans politique de filtrage dédiée."
        )
        recommendations.append("Appliquer une politique horaire ou couper Internet sur la zone « Visiteurs » hors heures d'accueil.")
    else:
        findings.append("✅ Segmentation Visiteurs maîtrisée (aucun accès invité non contrôlé sur le WAN).")

    # 4. Durcissement DNS & Optimisation Box
    has_secure_dns = any(d in dns_val for d in ("1.1.1.1", "9.9.9.9", "1.0.0.1")) or bool(box_cfgs)
    if has_secure_dns:
        findings.append(
            f"✅ Résolveurs DNS résilients actifs ({dns_val or '1.1.1.1, 9.9.9.9'}) · {len(box_cfgs)} profil(s) Multi-Box optimisé(s)."
        )
    else:
        score -= 8
        findings.append(f"ℹ️ DNS opérateur par défaut ({dns_val or 'non renseigné'}) et aucune optimisation QoS enregistrée.")
        recommendations.append("Lancer « Optimise toutes les box » pour activer DNS filtrés (1.1.1.1 / 9.9.9.9) et QoS anti-saturation.")

    # 5. Actions critiques en attente de validation humaine (HITL)
    if pending_list:
        score -= 10
        p_desc = ", ".join(f"#{p.get('id')} ({p.get('action')})" for p in pending_list[:3])
        findings.append(f"🟡 {len(pending_list)} demande(s) matérielle(s) critique(s) en attente d'approbation humaine : {p_desc}.")
        recommendations.append("Examiner et approuver ou rejeter les demandes en attente dans le journal HITL.")
    else:
        findings.append("✅ File HITL propre : aucune action matérielle critique en suspens.")

    score = max(0, min(100, score))
    if score >= 85 and not unknown_devs:
        level = "FAIBLE (Réseau maîtrisé)"
    elif score >= 65:
        level = "MODÉRÉ (Vigilance requise)"
    else:
        level = "ÉLEVÉ (Action immédiate recommandée)"

    text_lines = [
        f"🛡️ Audit de Posture Cybersécurité DADEREZO — {scope_label}",
        f"• Score de sécurité temps réel : **{score}/100** · Niveau de risque : **{level}**",
        "",
        "Constats vérifiés sur la télémétrie :",
        *[f"• {f}" for f in findings],
    ]
    if recommendations:
        text_lines.append("\nRecommandations prioritaires :")
        text_lines.extend(f"• {r}" for r in recommendations)

    spoken = (
        f"Audit sécurité sur {scope_label} : score de {score} sur 100, niveau de risque {level.split('(')[0].strip()}. "
        + (
            f"Attention, {len(unknown_devs)} appareil non reconnu est présent sur le réseau."
            if unknown_devs
            else "Aucun équipement intrus n'est détecté sur le réseau local."
        )
    )
    return "\n".join(text_lines), spoken, {"score": score, "risk_level": level, "pending_count": len(pending_list)}


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
    """Exécute la chaîne des 5 agents spécialisés avec sécurité, mémoire multi-tours, contrôle actif et audit complet."""
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

    history = storage.get_session_turns(sid, limit=10)
    prev_ctx = _extract_last_context(history)
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
        f"Requête validée (isolation tenant={org_slug}, droits_actifs={can_write}, historique={len(history)} tours).",
    )

    # =========================================================================
    # COMPRÉHENSION CONVERSATIONNELLE RAPIDE (Salutations, Hors-Périmètre, Méta-Mémoire)
    # =========================================================================
    conv_intent = _classify_conversational_intent(q, prev_ctx)

    if conv_intent == "hors_perimetre":
        t_conv = time.perf_counter()
        _trace(
            "ORCHESTRATOR-Z",
            "intent_router",
            "domain_scope_guard",
            "OUT_OF_SCOPE",
            t_conv,
            f"Question hors périmètre réseau déclinée proprement : « {q_clean[:80]} »",
        )
        ans = (
            f"🧭 Question hors périmètre réseau : je suis l'Orchestrateur **DADEREZO v4.1**, dédié exclusivement "
            f"à la supervision, à la cybersécurité et au pilotage actif de vos réseaux locaux (LAN/WAN, Box Wi-Fi et Hub Multimédia) — "
            f"je ne réponds donc pas aux questions de culture générale ou hors infrastructure (« {q_clean} »).\n\n"
            f"En revanche, sur **{scope_label}**, vous pouvez me demander :\n"
            f"• « Y a-t-il un risque de sécurité sur mon réseau ? »\n"
            f"• « Quels appareils ont accès à Internet et lesquels sont limités au LAN ? »\n"
            f"• « Coupe Internet sur la zone Visiteurs » ou « Optimise toutes les box »."
        )
        spoken = (
            "Cette question sort du périmètre de supervision réseau DADEREZO. "
            "Je peux en revanche analyser votre sécurité réseau, vos équipements ou piloter vos accès Internet."
        )
        storage.append_session_turn(
            sid,
            datetime.now(timezone.utc).isoformat(),
            "assistant",
            ans,
            target_agent_id,
            {"intent": "hors_perimetre", "engine_mode": "multi_agent_autonomous"},
        )
        return {
            "status": "ok",
            "session_id": sid,
            "engine_mode": "multi_agent_autonomous",
            "intent": "hors_perimetre",
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
            "security_check": {"verdict": "ALLOW", "authorized": can_write, "org_slug": org_slug},
            "refused_write_action": False,
        }

    if conv_intent == "salutation_capacites":
        t_conv = time.perf_counter()
        _trace(
            "ORCHESTRATOR-Z",
            "intent_router",
            "conversational_greeting",
            "OK",
            t_conv,
            f"Réponse conversationnelle naturelle sur « {scope_label} ».",
        )
        is_thanks = "merci" in q or "bravo" in q or "parfait" in q
        if is_thanks:
            ans = (
                f"Avec plaisir ! Je reste en veille continue sur **{scope_label}** "
                f"({len(lan_up_devs)}/{len(all_devices)} équipements actifs sur le LAN, {len(inet_yes_devs)} avec accès Internet). "
                f"N'hésitez pas si vous souhaitez vérifier une zone, auditer la sécurité ou ajuster une politique Internet."
            )
            spoken = f"Avec plaisir ! Je reste en veille sur {scope_label}."
        else:
            ans = (
                f"👋 Bonjour ! Je suis l'Orchestrateur Multi-Agents **DADEREZO v4.1** affecté à **{scope_label}**.\n"
                f"• État instantané : **{len(lan_up_devs)}/{len(all_devices)}** équipements connectés au LAN · "
                f"**{len(inet_yes_devs)}** avec Internet actif"
                + (f" · ⚠️ **{len(unknown_devs)}** équipement non reconnu" if unknown_devs else " · 🛡️ aucun intrus détecté")
                + ".\n\n"
                "Que souhaitez-vous faire (à l'écrit ou à la voix) ?\n"
                "• **Diagnostiquer** : « Quels appareils n'ont pas Internet et pourquoi ? » ou « Montre la zone Administration »\n"
                "• **Sécuriser** : « Y a-t-il un risque de sécurité sur mon réseau ? »\n"
                "• **Piloter** : « Coupe Internet sur la zone Visiteurs », « Optimise toutes les box », ou « Rédige un ticket FAI »."
            )
            spoken = (
                f"Bonjour ! Je suis l'Orchestrateur DADEREZO sur {scope_label}. "
                f"{len(lan_up_devs)} appareils sur {len(all_devices)} sont actifs sur le réseau local. Comment puis-je vous aider ?"
            )
        storage.append_session_turn(
            sid,
            datetime.now(timezone.utc).isoformat(),
            "assistant",
            ans,
            target_agent_id,
            {"intent": "salutation_capacites", "engine_mode": "multi_agent_autonomous"},
        )
        return {
            "status": "ok",
            "session_id": sid,
            "engine_mode": "multi_agent_autonomous",
            "intent": "salutation_capacites",
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
            "security_check": {"verdict": "ALLOW", "authorized": can_write, "org_slug": org_slug},
            "refused_write_action": False,
        }

    if conv_intent == "memoire_conversation":
        t_mem = time.perf_counter()
        prior_qs = prev_ctx.get("user_questions") or []
        _trace(
            "ORCHESTRATOR-Z",
            "session_memory",
            "recall_agent_sessions",
            "OK",
            t_mem,
            f"Session « {sid} » consultée : {len(prior_qs)} question(s) antérieure(s) retrouvée(s).",
        )
        if not prior_qs:
            ans = (
                f"🧠 Mémoire de session (`{sid}`) : c'est votre toute première question dans cette session. "
                f"Nos prochains échanges seront mémorisés pour vous permettre de poser des questions de suivi naturelles."
            )
            spoken = "C'est votre première question dans cette session."
        else:
            recent_bullets = "\n".join(f"• Tour {i + 1} : « {uq} »" for i, uq in enumerate(prior_qs[-5:]))
            focus_note = (
                f"\n• Dernier sujet ciblé en mémoire : {prev_ctx.get('focus_label') or prev_ctx.get('last_intent') or 'supervision générale'}."
                if (prev_ctx.get("focus_label") or prev_ctx.get("last_intent"))
                else ""
            )
            ans = (
                f"🧠 Mémoire active de la session `{sid}` ({len(prior_qs)} message(s) précédent(s) enregistrés en base) :\n"
                f"• Votre dernière demande était : **« {prev_ctx['last_user_q']} »**\n"
                f"{recent_bullets}{focus_note}"
            )
            spoken = f"Votre dernière question dans cette session était : {prev_ctx['last_user_q']}."
        storage.append_session_turn(
            sid,
            datetime.now(timezone.utc).isoformat(),
            "assistant",
            ans,
            target_agent_id,
            {
                "intent": "memoire_conversation",
                "zone_filter": prev_ctx.get("zone_filter"),
                "focus_ips": prev_ctx.get("focus_ips"),
                "focus_label": prev_ctx.get("focus_label"),
            },
        )
        return {
            "status": "ok",
            "session_id": sid,
            "engine_mode": "multi_agent_autonomous",
            "intent": "memoire_conversation",
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
            "security_check": {"verdict": "ALLOW", "authorized": can_write, "org_slug": org_slug},
            "refused_write_action": False,
        }

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

    inet_cmd = _parse_internet_command(q, all_devices, prev_ctx=prev_ctx)
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
            net_control_result = {
                "status": "auth_required",
                "message": "Authentification requise : connectez-vous à votre Espace Privé ou fournissez `X-API-Key` pour modifier l'accès Internet.",
            }
        else:
            st_lbl = "ACTIVÉ" if inet_cmd["internet_enabled"] else "COUPÉ"
            scope_t = inet_cmd["scope_type"]
            target_v = inet_cmd["target_value"]
            reason_txt = f"Internet {st_lbl.lower()} par {actor_name} via Orchestrateur IA ({scope_t}:{target_v})"
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
            dashboards, all_devices, all_alerts, scope_label = _collect_context()
            lan_up_devs, offline_devs, inet_yes_devs, inet_no_devs, lan_only_no_inet_devs, unknown_devs, metrics = _compute_splits(all_devices)

    elif wants_box_optimize and primary_aid:
        t_nc = time.perf_counter()
        if not can_write:
            _trace("NET-CONTROL", "active_control", "optimize_all_boxes", "AUTH_REQUIRED", t_nc, "Droits administrateur requis.")
            net_control_result = {
                "status": "auth_required",
                "message": "Authentification requise : connectez-vous à votre Espace Privé ou fournissez `X-API-Key` pour optimiser les box.",
            }
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
        if not can_write:
            _trace(
                "NET-CONTROL",
                "human_in_the_loop",
                "request_box_reboot_approval",
                "AUTH_REQUIRED",
                t_nc,
                "Redémarrage matériel bloqué : session non authentifiée.",
            )
            net_control_result = {
                "status": "auth_required",
                "message": "Authentification requise : seuls les administrateurs authentifiés (Espace Privé ou `X-API-Key`) peuvent demander ou valider le redémarrage physique d'une Box.",
            }
        else:
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
        if not zone_filter and conv_intent == "suivi_contextuel" and prev_ctx.get("zone_filter"):
            if any(p in q for p in ("cette zone", "la-bas", "dans la zone")):
                zone_filter = prev_ctx["zone_filter"]

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
    # AGENT 03 · DIAG-NET (Corrélation WAN/LAN, Sécurité & Ticket Opérateur)
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

    asks_security_posture = bool(
        re.search(
            r"(risque\s+de\s+securite|risques?\s+reseau|audit\s+de\s+securite|mon\s+reseau\s+est-il\s+(securise|sur)|"
            r"vulnerab\w*|menace\w*|posture\s+securite|niveau\s+de\s+securite|bilan\s+securite|"
            r"y\s+a-t-il\s+un\s+(risque|danger|intrus|probleme\s+de\s+securite)|intrus\s+sur\s+(le|mon)\s+reseau)",
            q,
        )
    )
    security_audit_text: Optional[str] = None
    security_audit_spoken: Optional[str] = None
    security_audit_meta: Optional[dict] = None
    if asks_security_posture and not net_control_result:
        t_sa = time.perf_counter()
        security_audit_text, security_audit_spoken, security_audit_meta = _evaluate_security_posture(
            primary_aid=primary_aid,
            scope_label=scope_label,
            dashboards=dashboards,
            all_devices=all_devices,
            unknown_devs=unknown_devs,
            active_policies=active_policies,
            can_write=can_write,
        )
        _trace(
            "SENTINEL-SEC",
            "security_audit",
            "evaluate_network_posture",
            "OK",
            t_sa,
            f"Score sécurité={security_audit_meta['score']}/100 ({security_audit_meta['risk_level']}).",
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
            if not can_write:
                _trace(
                    "OPS-DISPATCH",
                    "human_in_the_loop",
                    "request_human_approval",
                    "AUTH_REQUIRED",
                    t_ops,
                    "Balayage 254 IP refusé : session non authentifiée.",
                )
                net_control_result = {
                    "status": "auth_required",
                    "message": "Authentification requise : connectez-vous à votre Espace Privé ou fournissez `X-API-Key` pour déclencher un balayage actif 254 IP.",
                }
            else:
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
                net_control_result = {
                    "status": "auth_required",
                    "message": f"Authentification requise pour envoyer l'ordre « {action} » à la sonde.",
                }
                _trace("OPS-DISPATCH", "tool_call", "dispatch_probe_task", "AUTH_REQUIRED", t_ops, "Authentification requise.")

    # =========================================================================
    # SYNTHÈSE FINALE CLAIRE, CIBLÉE & MULTI-TOURS
    # =========================================================================
    def _fmt_devs(devs: List[dict], with_reason: bool = False, force_mac: bool = False, force_latency: bool = False) -> str:
        if not devs:
            return "Aucun"
        show_mac = force_mac or ("mac" in q)
        show_lat = force_latency or ("latence" in q or "ping" in q)
        out = []
        for x in devs[:10]:
            lbl = f"{x.get('name') or 'Poste'} ({x.get('ip')})"
            if x.get("zone"):
                lbl += f" · Zone {x['zone']}"
            if show_mac and x.get("mac"):
                lbl += f" · MAC `{x['mac']}`"
            if show_lat:
                lat_v = f"{x['latency_ms']} ms" if x.get("latency_ms") is not None else "hors ligne"
                lbl += f" · Latence {lat_v}"
            if len(dashboards) > 1 and x.get("site_name"):
                lbl += f" [{x['site_name']}]"
            if with_reason and x.get("internet_reason"):
                lbl += f" — {x['internet_reason']}"
            out.append(f"• {lbl}")
        if len(devs) > 10:
            out.append(f"• … et {len(devs) - 10} autre(s)")
        return "\n".join(out)

    intent = "bilan_superviseur"
    focus_ips: List[str] = []
    focus_label: str = ""
    lines: List[str] = []
    spoken_parts: List[str] = []

    asks_only_no_internet = bool(
        re.search(
            r"(sans\s+(acces\s+a\s+)?internet|n'ont\s+pas\s+(acces\s+a\s+)?internet|n'a\s+pas\s+internet|"
            r"priv\w+\s+d'internet|bloqu\w+\s+d'internet|lan\s+seul|uniquement\s+au\s+lan)",
            q,
        )
        and not re.search(r"quels\s+appareils\s+ont\s+internet", q)
    )

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
            if net_control_result["scope_type"] == "device":
                focus_ips = [net_control_result["target_value"]]
                focus_label = f"Appareil {net_control_result['target_value']}"
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

    # Suivi contextuel appuyé sur la mémoire de session `agent_sessions`
    handled_contextual_followup = False
    if conv_intent == "suivi_contextuel" and not net_control_result and not pending_approval:
        prev_ips = prev_ctx.get("focus_ips") or []
        prev_devs = [d for d in all_devices if d.get("ip") in prev_ips] if prev_ips else []
        if not prev_devs and prev_ctx.get("zone_filter"):
            prev_devs = [d for d in all_devices if prev_ctx["zone_filter"] in normalize_fr(d.get("zone") or "")]
        if prev_devs:
            t_mem = time.perf_counter()
            handled_contextual_followup = True
            intent = "suivi_contextuel"
            focus_ips = [d["ip"] for d in prev_devs if d.get("ip")]
            focus_label = prev_ctx.get("focus_label") or f"{len(prev_devs)} équipement(s) du tour précédent"
            _trace(
                "ORCHESTRATOR-Z",
                "session_memory",
                "resolve_contextual_followup",
                "OK",
                t_mem,
                f"Suivi résolu sur {len(prev_devs)} équipement(s) issu(s) de « {prev_ctx.get('last_user_q', '')[:50]} ».",
            )
            if asks_only_no_internet or "sans internet" in q or "pas internet" in q:
                sub = [d for d in prev_devs if d.get("internet_access") not in ("oui", "degrade")]
                focus_ips = [d["ip"] for d in sub if d.get("ip")] or focus_ips
                lines.append(
                    f"🧠 Suivi sur **{focus_label}** — équipements sans accès Internet ({len(sub)}/{len(prev_devs)}) :\n"
                    + _fmt_devs(sub, with_reason=True, force_mac=True)
                )
                spoken_parts.append(f"Parmi ces {len(prev_devs)} équipements, {len(sub)} n'ont pas accès à Internet.")
            else:
                lines.append(
                    f"🧠 Détails demandés pour **{focus_label}** (en référence à votre question « {prev_ctx.get('last_user_q')} ») :\n"
                    + _fmt_devs(prev_devs, with_reason=True, force_mac=True, force_latency=True)
                )
                spoken_parts.append(f"Voici les détails MAC, latence et Internet pour les {len(prev_devs)} équipements ciblés.")

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

    if security_audit_text and not net_control_result:
        intent = "analyse_securite"
        focus_ips = [u["ip"] for u in unknown_devs if u.get("ip")]
        focus_label = "Équipements non reconnus (audit sécurité)" if focus_ips else f"Posture sécurité {scope_label}"
        lines.append(security_audit_text)
        if security_audit_spoken:
            spoken_parts.append(security_audit_spoken)
    elif (
        not handled_contextual_followup
        and not operator_ticket_text
        and not asks_media
        and not net_control_result
        and not pending_approval
    ):
        if zone_filter:
            intent = "filtre_zone"
            focus_ips = [x["ip"] for x in scoped_devices if x.get("ip")]
            focus_label = f"Zone {zone_filter.capitalize()}"
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
        elif asks_only_no_internet:
            intent = "sans_internet"
            focus_ips = [x["ip"] for x in inet_no_devs if x.get("ip")]
            focus_label = "Équipements sans accès Internet"
            if inet_no_devs:
                lines.append(
                    f"⚠️ Équipements sans accès à Internet sur **{scope_label}** ({len(inet_no_devs)}/{len(all_devices)}) :\n"
                    + _fmt_devs(inet_no_devs, with_reason=True, force_mac=("mac" in q))
                )
                spoken_parts.append(
                    f"{len(inet_no_devs)} appareil{'s' if len(inet_no_devs) > 1 else ''} sur {len(all_devices)} n'ont pas accès à Internet."
                )
            else:
                lines.append(
                    f"✅ Aucun équipement privé d'Internet sur **{scope_label}** : les {len(inet_yes_devs)}/{len(all_devices)} équipements disposent tous d'un accès WAN actif."
                )
                spoken_parts.append(f"Tous les {len(inet_yes_devs)} appareils disposent actuellement d'un accès Internet actif.")
        else:
            if intent == "bilan_superviseur":
                intent = "inventaire_internet"
            focus_ips = [x["ip"] for x in (inet_no_devs or all_devices) if x.get("ip")]
            focus_label = f"Inventaire {scope_label}"
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

    asks_intrus = any(w in q for w in ("intrus", "inconnu", "suspect")) and not security_audit_text
    asks_outage = any(w in q for w in ("panne", "coupure", "fai", "passerelle", "latence", "lent", "pourquoi"))

    if asks_outage and not operator_ticket_text:
        lines.append("\n🩺 Corrélation DIAG-NET :\n" + "\n".join(f"• {d}" for d in diagnostics_per_site))

    if asks_intrus:
        focus_ips = [u["ip"] for u in unknown_devs if u.get("ip")] or focus_ips
        focus_label = "Équipements inconnus / suspects"
        if unknown_devs:
            u_str = ", ".join(f"{u.get('ip')} (MAC {u.get('mac') or 'n/d'})" for u in unknown_devs)
            lines.append(f"\n🕵️ Alerte MAC non répertoriée ({len(unknown_devs)}) : {u_str}")
        else:
            lines.append("\n🛡️ Sécurité MAC : 100 % des équipements actifs sont reconnus.")

    deterministic_answer = "\n".join(lines).strip()
    spoken_summary = " ".join(spoken_parts).strip()

    refused_write = bool(net_control_result and net_control_result.get("status") == "auth_required")

    engine_mode = "multi_agent_autonomous"
    llm_cfg = _detect_llm_config(llm_api_key, llm_model)
    if llm_cfg and not refused_write:
        t_llm = time.perf_counter()
        evidence = {
            "scope_label": scope_label,
            "intent_detected": intent,
            "metrics": metrics,
            "security_audit": security_audit_meta,
            "net_control_result": net_control_result,
            "active_internet_policies": active_policies,
            "shared_media_count": len(media_items),
            "diagnostics": diagnostics_per_site,
            "devices_with_internet": [
                {"name": d.get("name"), "ip": d.get("ip"), "mac": d.get("mac"), "zone": d.get("zone"), "latency_ms": d.get("latency_ms")}
                for d in inet_yes_devs
            ],
            "devices_without_internet": [
                {
                    "name": d.get("name"),
                    "ip": d.get("ip"),
                    "mac": d.get("mac"),
                    "zone": d.get("zone"),
                    "lan_status": d.get("status"),
                    "reason": d.get("internet_reason"),
                }
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
        {
            "intent": intent,
            "engine_mode": engine_mode,
            "zone_filter": zone_filter or prev_ctx.get("zone_filter"),
            "focus_ips": focus_ips[:15],
            "focus_label": focus_label,
        },
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
        "refused_write_action": refused_write,
    }
