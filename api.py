# -*- coding: utf-8 -*-
"""
DADEREZO v4.0 — Plateforme SaaS Multi-Agents de Supervision, Pilotage Actif Réseau,
Optimisation Multi-Box & Partage de Fichiers / Multimédias.

Architecture Multi-Agents :
  01 · SENTINEL-SEC : Anti-injection de prompt & Isolation Multi-Tenant Privée
  02 · TOPO-SCAN    : Topologie LAN/WAN, Politiques Internet actives & Latence
  03 · DIAG-NET     : Corrélation FAI vs Box vs Relais & Ticket Technique Opérateur
  04 · NET-CONTROL  : Interrupteurs Internet ON/OFF (Box / Sous-réseau & Zone / Appareil) & Optimisation Box
  05 · MEDIA-HUB    : Partage sécurisé de Documents, Images, Audios & Vidéos (Cloud + LAN local)
"""
import base64
from datetime import datetime, timezone
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import struct
import time
from typing import Dict, List, Optional, Tuple, Union

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, Response
from pydantic import BaseModel, Field

import agent_engine
import net_controller
import storage

HERE = os.path.dirname(os.path.abspath(__file__))

OFFLINE_THRESHOLD_SECONDS = int(os.environ.get("DADEREZO_OFFLINE_SECONDS", "600"))
PROTECT_READ = os.environ.get("DADEREZO_PROTECT_READ", "0") == "1"
ALLOWED_TASKS = {
    "scan",
    "sweep",
    "diagnostic",
    "rapport",
    "apply_internet_policy",
    "optimize_box",
    "reboot_box",
    "sync_media",
}
ALLOWED_DOWNLOADS = {
    "agent_client.py",
    "collector.py",
    "devices.json",
    "make_dashboard.py",
    "net_controller.py",
}

app = FastAPI(
    title="DADEREZO v4.1 Multi-Agent & Active Network Control API",
    description="Supervision réseau, mémoire multi-tours, audit sécurité, contrôle Internet granulaire (Box/Zone/Appareil), optimisation Multi-Box et partage Multimédia",
    version="4.1.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


def get_api_key() -> str:
    return os.environ.get("DADEREZO_API_KEY", "").strip()


def _jwt_secret() -> bytes:
    raw = (
        os.environ.get("DADEREZO_AUTH_SECRET", "").strip()
        or os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
        or get_api_key()
        or "daderezo-v4-stateless-hmac-key-2026"
    )
    return raw.encode("utf-8")


def get_sqlite_path() -> str:
    return storage.get_sqlite_path()


def init_db() -> None:
    storage.init_db()


init_db()


# ---------------------------------------------------------------------------
# Authentification SaaS Multi-Tenant & Jetons Stateless (compatibles Vercel)
# ---------------------------------------------------------------------------
def _hash_password(password: str, salt: Optional[str] = None) -> str:
    s = salt or secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode("utf-8"), s.encode("utf-8"), 120_000)
    return f"pbkdf2_sha256${s}${dk.hex()}"


def _verify_password(password: str, stored: str) -> bool:
    try:
        _, salt, expected_hex = stored.split("$", 2)
        candidate = _hash_password(password, salt=salt)
        return hmac.compare_digest(candidate, stored)
    except Exception:
        return False


def _sign_saas_token(user: dict, ttl_seconds: int = 86400 * 14) -> str:
    payload = {
        "email": user["email"],
        "full_name": user.get("full_name") or "",
        "org_slug": user["org_slug"],
        "org_name": user.get("org_name") or user["org_slug"],
        "exp": int(time.time()) + ttl_seconds,
    }
    b64 = base64.urlsafe_b64encode(json.dumps(payload, separators=(",", ":")).encode("utf-8")).decode("ascii").rstrip("=")
    sig = hmac.new(_jwt_secret(), b64.encode("ascii"), hashlib.sha256).hexdigest()
    return f"dzt_{b64}.{sig}"


def _verify_saas_token(token: str) -> Optional[dict]:
    if not token or not token.startswith("dzt_") or "." not in token:
        return None
    try:
        body_part, sig = token[4:].split(".", 1)
        expected_sig = hmac.new(_jwt_secret(), body_part.encode("ascii"), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(sig, expected_sig):
            return None
        pad = "=" * ((4 - len(body_part) % 4) % 4)
        payload = json.loads(base64.urlsafe_b64decode(body_part + pad).decode("utf-8"))
        if int(payload.get("exp", 0)) < int(time.time()):
            return None
        return payload
    except Exception:
        return None


def _slugify_org(name: str) -> str:
    base = re.sub(r"[^a-z0-9]+", "-", (name or "organisation").lower()).strip("-")[:28] or "org"
    return f"{base}-{secrets.token_hex(2)}"


def _extract_token(x_api_key: Optional[str], authorization: Optional[str]) -> str:
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    if x_api_key:
        return x_api_key.strip()
    return ""


def resolve_tenant_context(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> dict:
    """
    Résout l'espace organisationnel (`org_slug`) de l'appelant :
    - Jeton SaaS (`Bearer dzt_...`) -> espace privé de l'utilisateur connecté
    - Clé sonde privée (`X-API-Key: dzk_...`) -> espace privé rattaché à la sonde
    - Clé globale `DADEREZO_API_KEY` -> droits d'écriture sur l'espace courant
    - Visiteur public -> espace bac à sable isolé `public-demo` (aucune visibilité sur les réseaux privés)
    """
    bearer = ""
    if authorization and authorization.lower().startswith("bearer "):
        bearer = authorization[7:].strip()

    if bearer.startswith("dzt_"):
        claims = _verify_saas_token(bearer)
        if claims:
            return {
                "authenticated": True,
                "can_write": True,
                "mode": "private_org",
                "org_slug": claims["org_slug"],
                "org_name": claims.get("org_name") or claims["org_slug"],
                "actor": claims.get("full_name") or claims["email"],
                "email": claims["email"],
            }

    probe_candidate = (x_api_key or bearer or "").strip()
    if probe_candidate.startswith("dzk_"):
        u = storage.get_saas_user_by_probe_key(probe_candidate)
        if u:
            return {
                "authenticated": True,
                "can_write": True,
                "mode": "private_probe",
                "org_slug": u["org_slug"],
                "org_name": u.get("org_name") or u["org_slug"],
                "actor": f"Sonde ({u['org_name']})",
                "email": u["email"],
            }
        raise HTTPException(status_code=401, detail="Clé sonde privée (dzk_...) invalide.")

    global_expected = get_api_key()
    provided = _extract_token(x_api_key, authorization)
    can_write_public = (not global_expected) or (bool(provided) and hmac.compare_digest(provided, global_expected))
    return {
        "authenticated": bool(global_expected and can_write_public),
        "can_write": can_write_public,
        "mode": "public_demo",
        "org_slug": "public-demo",
        "org_name": "Espace Démo Public (Isolé)",
        "actor": "Superviseur Général",
        "email": None,
    }


def require_write_auth(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> dict:
    ctx = resolve_tenant_context(x_api_key=x_api_key, authorization=authorization)
    if not ctx["can_write"]:
        raise HTTPException(
            status_code=401,
            detail="Authentification requise (Connectez-vous à votre Espace Privé ou fournissez X-API-Key).",
        )
    return ctx


def require_read_auth(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> dict:
    ctx = resolve_tenant_context(x_api_key=x_api_key, authorization=authorization)
    if PROTECT_READ and not ctx["can_write"]:
        raise HTTPException(status_code=401, detail="Lecture protégée : authentification requise.")
    return ctx


def _ensure_agent_tenant_access(agent_id: str, ctx: dict) -> Optional[dict]:
    ag = storage.get_agent_raw(agent_id)
    if not ag:
        return None
    ag_org = ag.get("org_slug") or "public-demo"
    # L'espace démo `simulation-bouake` reste consultable pour tester, mais un réseau privé est strictement isolé
    if ag_org != "public-demo" and ag_org != ctx["org_slug"]:
        raise HTTPException(
            status_code=403,
            detail="Accès refusé : cette sonde appartient à un espace réseau privé isolé.",
        )
    return ag


def _compute_agent_liveness(agent_dict: dict) -> dict:
    last_seen_raw = agent_dict.get("last_seen")
    seconds_since = None
    if last_seen_raw:
        try:
            normalized = str(last_seen_raw).replace("Z", "+00:00")
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            seconds_since = max(0, int((datetime.now(timezone.utc) - dt).total_seconds()))
        except ValueError:
            seconds_since = None

    is_sim = str(agent_dict.get("id", "")).startswith("simulation-")
    if is_sim:
        live_status = "online"
        seconds_since = min(seconds_since if seconds_since is not None else 4, 12)
    else:
        live_status = "online" if (seconds_since is not None and seconds_since <= OFFLINE_THRESHOLD_SECONDS) else "offline"
    enriched = dict(agent_dict)
    enriched["status"] = live_status
    enriched["seconds_since_seen"] = seconds_since
    enriched["is_simulation"] = is_sim
    return enriched


# ---------------------------------------------------------------------------
# Schémas Pydantic
# ---------------------------------------------------------------------------
class SignupRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=160)
    password: str = Field(..., min_length=6, max_length=128)
    full_name: str = Field(default="Administrateur Réseau", max_length=120)
    org_name: str = Field(..., min_length=2, max_length=120)


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=5, max_length=160)
    password: str = Field(..., min_length=4, max_length=128)


class Probe(BaseModel):
    ip: str
    mac: Optional[str] = None
    name: Optional[str] = None
    zone: Optional[str] = None
    status: str
    type: str = "host"
    latency_ms: Optional[float] = None


class AlertInput(BaseModel):
    severity: str = "info"
    message: str = ""
    ts: Optional[str] = None


class AgentData(BaseModel):
    agent_id: str = Field(..., min_length=1, max_length=128)
    nom: str = Field(default="Agent DADEREZO", max_length=200)
    site_name: Optional[str] = None
    ip_local: Optional[str] = None
    mask: Optional[str] = None
    gw: Optional[str] = None
    mac_local: Optional[str] = None
    dns: Optional[Union[List[str], str]] = None
    gw_status: Optional[str] = None
    gw_latency_ms: Optional[float] = None
    internet_status: Optional[str] = None
    wan_latency_ms: Optional[float] = None
    probes: List[Probe] = Field(default_factory=list)
    alerts: List[Union[AlertInput, dict]] = Field(default_factory=list)


class DiagnosticTaskRequest(BaseModel):
    action: str = Field(default="scan")
    payload: Optional[dict] = Field(default=None)


class SupervisorAskRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=1500)
    agent_id: Optional[str] = Field(default=None)
    scope: str = Field(default="site")
    session_id: Optional[str] = Field(default="default-supervisor")


class HumanApprovalDecision(BaseModel):
    decision: str = Field(..., description="'approve' ou 'reject'")


class InternetPolicyRequest(BaseModel):
    scope_type: str = Field(..., description="'global', 'zone', 'subnet' ou 'device'")
    target_value: str = Field(..., min_length=1, max_length=120)
    internet_enabled: bool = Field(...)
    reason: Optional[str] = Field(default="")
    schedule: Optional[dict] = Field(default=None)


class BoxConfigRequest(BaseModel):
    box_ip: str = Field(..., min_length=3, max_length=60)
    box_name: Optional[str] = Field(default="Box Principale")
    box_role: Optional[str] = Field(default="gateway")
    driver: Optional[str] = Field(default="huawei_hilink")
    wifi_enabled: bool = Field(default=True)
    wifi_ssid: Optional[str] = Field(default="DADEREZO-LAN")
    wifi_channel: Optional[str] = Field(default="6")
    wifi_band: Optional[str] = Field(default="2.4GHz + 5GHz")
    dns_primary: Optional[str] = Field(default="1.1.1.1")
    dns_secondary: Optional[str] = Field(default="9.9.9.9")
    qos_profile: Optional[str] = Field(default="equilibre")
    bandwidth_limit_mbps: int = Field(default=0, ge=0, le=10000)
    mtu: int = Field(default=1492, ge=576, le=9000)
    notes: Optional[str] = Field(default="")


class BoxRebootRequest(BaseModel):
    box_ip: str = Field(..., min_length=3, max_length=60)


class SharedMediaUploadRequest(BaseModel):
    title: str = Field(..., min_length=1, max_length=160)
    filename: str = Field(..., min_length=1, max_length=120)
    mime_type: str = Field(default="application/octet-stream", max_length=100)
    category: Optional[str] = Field(default=None, max_length=30)
    target_zone: str = Field(default="Toutes les zones", max_length=60)
    description: str = Field(default="", max_length=400)
    content_b64: str = Field(..., min_length=1)


# ---------------------------------------------------------------------------
# Enrichissement Matrice LAN vs Internet + Politiques Actives
# ---------------------------------------------------------------------------
def _enrich_devices_internet(devices: List[dict], state: dict, policies: Optional[List[dict]] = None) -> List[dict]:
    gw = state.get("gw") or ""
    gw_dev = next((d for d in devices if d.get("ip") == gw), None)
    gw_status = state.get("gw_status") or (gw_dev.get("status") if gw_dev else "unknown")
    inet_status = state.get("internet_status") or "unknown"
    pol_list = policies or []

    enriched: List[dict] = []
    for d in devices:
        item = dict(d)
        is_lan_up = item.get("status") == "up"
        dev_type = (item.get("type") or "host").lower()
        dev_name = item.get("name") or ""
        is_static_lan_only = dev_type in ("local_only", "printer_lan") or "(lan seul)" in dev_name.lower()

        pol_eval = net_controller.evaluate_device_internet(item, pol_list)
        item["internet_policy_enabled"] = pol_eval["internet_enabled"]
        item["internet_policy_source"] = pol_eval["internet_policy_source"]
        item["lan_connected"] = is_lan_up

        if not is_lan_up:
            item["internet_access"] = "non"
            item["internet_reason"] = "Hors ligne sur le réseau local (LAN)"
        elif not pol_eval["internet_enabled"]:
            item["internet_access"] = "non"
            item["internet_reason"] = pol_eval["internet_reason"]
        elif is_static_lan_only and pol_eval["internet_policy_source"] == "defaut":
            item["internet_access"] = "non"
            item["internet_policy_enabled"] = False
            item["internet_reason"] = "Connecté au LAN uniquement (sortie Internet désactivée)"
        elif gw_status == "down":
            item["internet_access"] = "non"
            item["internet_reason"] = f"Connecté au LAN, mais passerelle locale ({gw or 'routeur'}) hors ligne"
        elif inet_status == "down":
            item["internet_access"] = "non"
            item["internet_reason"] = "Connecté au LAN, mais liaison FAI / Internet coupée en amont"
        elif inet_status == "degraded":
            item["internet_access"] = "degrade"
            item["internet_reason"] = "Connecté au LAN, accès Internet dégradé"
        elif inet_status == "up":
            item["internet_access"] = "oui"
            item["internet_reason"] = (
                pol_eval["internet_reason"]
                if pol_eval["internet_policy_source"] != "defaut"
                else "Connecté au LAN avec accès Internet actif"
            )
        else:
            item["internet_access"] = "inconnu"
            item["internet_reason"] = "Connecté au LAN (état WAN non mesuré)"
        enriched.append(item)
    return enriched


def _status_payload() -> dict:
    has_llm = bool(
        os.environ.get("DADEREZO_LLM_API_KEY", "").strip()
        or os.environ.get("GROQ_API_KEY", "").strip()
        or os.environ.get("OPENAI_API_KEY", "").strip()
    )
    return {
        "service": "DADEREZO API",
        "status": "ok",
        "mode": "active_governed",
        "version": "4.1.0",
        "architecture": "multi_agent_z_v4_1",
        "agents_pipeline": ["SENTINEL-SEC", "TOPO-SCAN", "DIAG-NET", "NET-CONTROL", "MEDIA-HUB"],
        "capabilities": [
            "internet_switch_global_subnet_device",
            "multi_box_auto_optimization",
            "multimedia_lan_cloud_sharing",
            "private_multitenant_saas",
            "multi_turn_session_memory",
            "security_posture_scoring",
        ],
        "db": storage.get_backend_mode(),
        "llm_configured": has_llm,
        "auth_enabled": bool(get_api_key()),
    }


BRAND_ASSETS = {
    "favicon.svg": ("favicon.svg", "image/svg+xml"),
    "favicon.ico": ("favicon.ico", "image/x-icon"),
    "apple-touch-icon.png": ("apple-touch-icon.png", "image/png"),
    "og-image.png": ("og-image.png", "image/png"),
}


def _serve_brand_asset(asset_key: str, request: Request) -> Response:
    fname, media_type = BRAND_ASSETS[asset_key]
    fpath = os.path.join(HERE, fname)
    if not os.path.exists(fpath):
        raise HTTPException(status_code=404, detail=f"Ressource {fname} introuvable.")
    with open(fpath, "rb") as f:
        raw = f.read()
    headers = {
        "Cache-Control": "public, max-age=86400",
        "Content-Length": str(len(raw)),
    }
    if request.method == "HEAD":
        return Response(content=b"", media_type=media_type, headers=headers)
    return Response(content=raw, media_type=media_type, headers=headers)


@app.api_route("/favicon.svg", methods=["GET", "HEAD"], include_in_schema=False)
def brand_favicon_svg(request: Request):
    return _serve_brand_asset("favicon.svg", request)


@app.api_route("/favicon.ico", methods=["GET", "HEAD"], include_in_schema=False)
def brand_favicon_ico(request: Request):
    return _serve_brand_asset("favicon.ico", request)


@app.api_route("/apple-touch-icon.png", methods=["GET", "HEAD"], include_in_schema=False)
def brand_apple_touch_icon(request: Request):
    return _serve_brand_asset("apple-touch-icon.png", request)


@app.api_route("/og-image.png", methods=["GET", "HEAD"], include_in_schema=False)
def brand_og_image(request: Request):
    return _serve_brand_asset("og-image.png", request)


# ---------------------------------------------------------------------------
# Pages HTML & Téléchargement Sonde
# ---------------------------------------------------------------------------
@app.api_route("/", methods=["GET", "HEAD"])
def root(request: Request):
    accept = request.headers.get("accept", "").lower()
    landing_path = os.path.join(HERE, "landing.html")
    ui_path = os.path.join(HERE, "DADEREZO.html")
    if "application/json" not in accept:
        target = landing_path if os.path.exists(landing_path) else ui_path
        if os.path.exists(target):
            with open(target, "r", encoding="utf-8") as f:
                return HTMLResponse(f.read())
    return JSONResponse(_status_payload())


@app.api_route("/landing", methods=["GET", "HEAD"], response_class=HTMLResponse)
def saas_landing():
    landing_path = os.path.join(HERE, "landing.html")
    if not os.path.exists(landing_path):
        raise HTTPException(status_code=404, detail="Page landing.html introuvable")
    with open(landing_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    return _status_payload()


@app.api_route("/ui", methods=["GET", "HEAD"], response_class=HTMLResponse)
@app.api_route("/app", methods=["GET", "HEAD"], response_class=HTMLResponse)
def supervision_ui():
    ui_path = os.path.join(HERE, "DADEREZO.html")
    if not os.path.exists(ui_path):
        raise HTTPException(status_code=404, detail="Interface DADEREZO.html introuvable")
    with open(ui_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


@app.get("/download/{filename}")
def download_probe_file(filename: str):
    if filename not in ALLOWED_DOWNLOADS:
        raise HTTPException(status_code=404, detail="Fichier non autorisé au téléchargement.")
    fpath = os.path.join(HERE, filename)
    if not os.path.exists(fpath):
        raise HTTPException(status_code=404, detail="Fichier introuvable.")
    with open(fpath, "r", encoding="utf-8") as f:
        content = f.read()
    return PlainTextResponse(
        content,
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.api_route("/simple", methods=["GET", "HEAD"], response_class=HTMLResponse)
def simple_ui():
    simple_path = os.path.join(HERE, "frontend.html")
    if not os.path.exists(simple_path):
        raise HTTPException(status_code=404, detail="Interface frontend.html introuvable")
    with open(simple_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


# ---------------------------------------------------------------------------
# Endpoints Comptes Privés SaaS (`/auth/*`)
# ---------------------------------------------------------------------------
@app.post("/auth/signup")
def auth_signup(req: SignupRequest):
    init_db()
    email = req.email.lower().strip()
    if "@" not in email:
        raise HTTPException(status_code=400, detail="Adresse e-mail invalide.")
    existing = storage.get_saas_user_by_email(email)
    if existing:
        raise HTTPException(status_code=409, detail="Un compte existe déjà avec cet e-mail. Connectez-vous.")

    now_iso = datetime.now(timezone.utc).isoformat()
    org_slug = _slugify_org(req.org_name)
    probe_key = f"dzk_{secrets.token_urlsafe(24)}"
    pw_hash = _hash_password(req.password)

    user = storage.create_saas_user(
        email=email,
        password_hash=pw_hash,
        full_name=req.full_name,
        org_slug=org_slug,
        org_name=req.org_name,
        probe_api_key=probe_key,
        now_iso=now_iso,
    )
    token = _sign_saas_token(user)
    storage.record_audit_log(
        now_iso,
        f"auth-{org_slug}",
        "SENTINEL-SEC",
        "tenant_provisioning",
        "create_private_workspace",
        "OK",
        4,
        f"Espace réseau privé créé pour « {req.org_name} » ({org_slug}).",
    )
    return {
        "status": "ok",
        "token": token,
        "user": {
            "email": user["email"],
            "full_name": user.get("full_name"),
            "org_slug": user["org_slug"],
            "org_name": user["org_name"],
            "probe_api_key": user["probe_api_key"],
        },
    }


@app.post("/auth/login")
def auth_login(req: LoginRequest):
    init_db()
    user = storage.get_saas_user_by_email(req.email)
    if not user or not _verify_password(req.password, user.get("password_hash", "")):
        raise HTTPException(status_code=401, detail="Identifiants incorrects.")
    token = _sign_saas_token(user)
    return {
        "status": "ok",
        "token": token,
        "user": {
            "email": user["email"],
            "full_name": user.get("full_name"),
            "org_slug": user["org_slug"],
            "org_name": user["org_name"],
            "probe_api_key": user["probe_api_key"],
        },
    }


@app.get("/auth/me")
def auth_me(ctx: dict = Depends(resolve_tenant_context)):
    if ctx["mode"] == "private_org" and ctx.get("email"):
        u = storage.get_saas_user_by_email(ctx["email"])
        return {
            "authenticated": True,
            "mode": "private_org",
            "org_slug": ctx["org_slug"],
            "org_name": ctx["org_name"],
            "user": {
                "email": ctx["email"],
                "full_name": ctx["actor"],
                "org_slug": ctx["org_slug"],
                "org_name": ctx["org_name"],
                "probe_api_key": u.get("probe_api_key") if u else None,
            },
        }
    return {
        "authenticated": ctx["authenticated"],
        "mode": ctx["mode"],
        "org_slug": ctx["org_slug"],
        "org_name": ctx["org_name"],
        "user": None,
    }


# ---------------------------------------------------------------------------
# Endpoints Sondes & Tableau de Bord (isolés par `org_slug`)
# ---------------------------------------------------------------------------
@app.post("/register")
def register_agent(data: AgentData, ctx: dict = Depends(require_write_auth)):
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    storage.upsert_agent(
        data.agent_id,
        data.nom,
        data.ip_local,
        data.mac_local,
        now_iso,
        org_slug=ctx["org_slug"],
    )
    return {"status": "registered", "agent_id": data.agent_id, "org_slug": ctx["org_slug"]}


@app.post("/data")
def receive_data(data: AgentData, ctx: dict = Depends(require_write_auth)):
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()

    probe_dicts = [
        {
            "ip": p.ip,
            "mac": p.mac,
            "name": p.name,
            "zone": p.zone,
            "status": p.status,
            "type": p.type,
            "latency_ms": p.latency_ms,
        }
        for p in data.probes
    ]

    alert_tuples: List[Tuple[str, str, str]] = []
    for a in data.alerts:
        if isinstance(a, AlertInput):
            alert_tuples.append((a.severity, a.message, a.ts or now_iso))
        else:
            alert_tuples.append(
                (
                    str(a.get("severity", "info")),
                    str(a.get("message", "")),
                    str(a.get("ts") or now_iso),
                )
            )

    dns_str = ", ".join(data.dns) if isinstance(data.dns, list) else (data.dns or "")
    state_items: Dict[str, Optional[str]] = {
        "site_name": data.site_name,
        "ip_local": data.ip_local,
        "mask": data.mask,
        "gw": data.gw,
        "mac_local": data.mac_local,
        "dns": dns_str if dns_str else None,
        "gw_status": data.gw_status,
        "gw_latency_ms": str(data.gw_latency_ms) if data.gw_latency_ms is not None else None,
        "internet_status": data.internet_status,
        "wan_latency_ms": str(data.wan_latency_ms) if data.wan_latency_ms is not None else None,
        "last_scan": now_iso,
    }

    recorded_alerts, pending_tasks = storage.ingest_telemetry(
        agent_id=data.agent_id,
        nom=data.nom,
        ip_local=data.ip_local,
        mac_local=data.mac_local,
        now_iso=now_iso,
        probes=probe_dicts,
        alerts=alert_tuples,
        state_items=state_items,
        org_slug=ctx["org_slug"],
    )

    return {
        "status": "ok",
        "org_slug": ctx["org_slug"],
        "received": len(data.probes),
        "alerts_recorded": recorded_alerts,
        "pending_tasks": pending_tasks,
    }


def _list_agents_for_ctx(ctx: dict) -> List[dict]:
    init_db()
    rows = storage.list_agents_raw(org_slug=ctx["org_slug"])
    # Si un nouvel utilisateur privé n'a pas encore lancé sa sonde terrain, lui laisser aussi accès au banc `simulation-bouake` pour comparer
    if ctx["org_slug"] != "public-demo" and not rows:
        sim = storage.get_agent_raw("simulation-bouake")
        if sim:
            rows = [sim]
    enriched = [_compute_agent_liveness(r) for r in rows]
    enriched.sort(key=lambda a: (1 if a.get("is_simulation") else 0, 0 if a.get("status") == "online" else 1))
    return enriched


@app.get("/agents")
def list_agents(ctx: dict = Depends(require_read_auth)):
    return _list_agents_for_ctx(ctx)


@app.get("/devices/{agent_id}")
def get_devices(agent_id: str, ctx: dict = Depends(require_read_auth)):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    raw_devices = storage.get_devices_raw(agent_id)
    state = storage.get_state_raw(agent_id)
    policies = storage.list_internet_policies(agent_id)
    return _enrich_devices_internet(raw_devices, state, policies)


@app.get("/probes/{agent_id}")
def get_probes(agent_id: str, limit: int = Query(default=20, ge=1, le=500), ctx: dict = Depends(require_read_auth)):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    return storage.get_probes_raw(agent_id, limit=limit)


@app.get("/alerts/{agent_id}")
def get_alerts(agent_id: str, limit: int = Query(default=20, ge=1, le=500), ctx: dict = Depends(require_read_auth)):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    return storage.get_alerts_raw(agent_id, limit=limit)


@app.get("/state/{agent_id}")
def get_state(agent_id: str, ctx: dict = Depends(require_read_auth)):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    return storage.get_state_raw(agent_id)


def _build_dashboard(agent_id: str, ctx: dict) -> dict:
    init_db()
    agent_raw = _ensure_agent_tenant_access(agent_id, ctx)
    agent = _compute_agent_liveness(agent_raw) if agent_raw else None

    raw_devices = storage.get_devices_raw(agent_id)
    if not raw_devices:
        raw_probes = storage.get_probes_raw(agent_id, limit=25)
        dedup: Dict[str, dict] = {}
        for p in raw_probes:
            ip = p.get("ip")
            if ip and ip not in dedup:
                dedup[ip] = {
                    "ip": ip,
                    "mac": p.get("mac"),
                    "name": p.get("name"),
                    "zone": p.get("zone"),
                    "status": p.get("status"),
                    "type": p.get("type"),
                    "latency_ms": p.get("latency_ms"),
                    "last_seen": p.get("ts"),
                }
        raw_devices = list(dedup.values())

    alerts = storage.get_alerts_raw(agent_id, limit=25)
    state = dict(storage.get_state_raw(agent_id))
    policies = storage.list_internet_policies(agent_id)
    global_pol = next((p for p in policies if p.get("scope_type") == "global"), None)
    main_box_inet_on = True if global_pol is None else bool(global_pol.get("internet_enabled", True))
    if not main_box_inet_on:
        state["main_box_internet_cut"] = "true"

    devices = _enrich_devices_internet(raw_devices, state, policies)
    boxes = net_controller.discover_boxes_from_devices(agent_id, devices, storage.list_box_configs(agent_id))

    up_count = sum(1 for d in devices if d["status"] == "up")
    down_count = sum(1 for d in devices if d["status"] != "up")
    with_inet = sum(1 for d in devices if d.get("internet_access") in ("oui", "degrade"))
    without_inet = len(devices) - with_inet
    lan_only_no_inet = sum(1 for d in devices if d["status"] == "up" and d.get("internet_access") == "non")

    eff_inet_status = "cut_by_admin" if not main_box_inet_on else state.get("internet_status", "unknown")

    return {
        "agent": agent,
        "state": state,
        "probes": devices,
        "devices": devices,
        "alerts": alerts,
        "internet_policies": policies,
        "boxes": boxes,
        "db_backend": storage.get_backend_mode(),
        "workspace_mode": ctx["mode"],
        "org_slug": ctx["org_slug"],
        "summary": {
            "total_devices": len(devices),
            "devices_up": up_count,
            "devices_down": down_count,
            "devices_with_internet": with_inet,
            "devices_without_internet": without_inet,
            "devices_lan_only_no_internet": lan_only_no_inet,
            "internet_status": eff_inet_status,
            "main_box_internet_enabled": main_box_inet_on,
            "active_policies_count": len(policies),
            "boxes_count": len(boxes),
        },
    }


@app.get("/dashboard/{agent_id}")
def dashboard(agent_id: str, ctx: dict = Depends(require_read_auth)):
    return _build_dashboard(agent_id, ctx)


# ---------------------------------------------------------------------------
# Contrôle Granulaire Internet ON / OFF (`/network/policies/*`)
# ---------------------------------------------------------------------------
@app.get("/network/policies/{agent_id}")
def get_internet_policies(agent_id: str, ctx: dict = Depends(require_read_auth)):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    policies = storage.list_internet_policies(agent_id)
    global_pol = next((p for p in policies if p.get("scope_type") == "global"), None)
    return {
        "agent_id": agent_id,
        "main_box_internet_enabled": True if global_pol is None else bool(global_pol.get("internet_enabled", True)),
        "policies": policies,
    }


@app.post("/network/policies/{agent_id}")
def set_internet_policy(agent_id: str, req: InternetPolicyRequest, ctx: dict = Depends(require_write_auth)):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    scope = req.scope_type.strip().lower()
    if scope not in ("global", "zone", "subnet", "device"):
        raise HTTPException(status_code=400, detail="scope_type invalide (global, zone, subnet ou device).")

    now_iso = datetime.now(timezone.utc).isoformat()
    target = "main_box" if scope == "global" else req.target_value.strip()
    state_lbl = "activé" if req.internet_enabled else "coupé"
    default_reason = {
        "global": f"Internet {state_lbl} depuis la Box Principale (LAN local maintenu)",
        "zone": f"Internet {state_lbl} sur la zone « {target} »",
        "subnet": f"Internet {state_lbl} sur le sous-réseau {target}",
        "device": f"Internet {state_lbl} sur l'équipement {target}",
    }[scope]

    saved = storage.upsert_internet_policy(
        agent_id=agent_id,
        scope_type=scope,
        target_value=target,
        internet_enabled=req.internet_enabled,
        reason=req.reason.strip() if req.reason else default_reason,
        updated_by=ctx["actor"],
        now_iso=now_iso,
        schedule=req.schedule,
    )
    payload_dict = {
        "scope_type": scope,
        "target_value": target,
        "internet_enabled": req.internet_enabled,
    }
    cmds = net_controller.generate_router_commands("apply_internet_policy", payload_dict)
    task = storage.create_task_row(agent_id, "apply_internet_policy", now_iso, payload=payload_dict)

    storage.record_audit_log(
        now_iso,
        f"netcontrol-{ctx['org_slug']}",
        "NET-CONTROL",
        "internet_switch",
        f"set_{scope}_internet",
        "ON" if req.internet_enabled else "OFF",
        3,
        f"{default_reason} par {ctx['actor']} ({agent_id})",
    )
    return {
        "status": "applied",
        "policy": saved,
        "router_commands": cmds,
        "task_queued": task,
    }


@app.delete("/network/policies/{agent_id}")
def remove_internet_policy(
    agent_id: str,
    scope_type: str = Query(...),
    target_value: str = Query(...),
    ctx: dict = Depends(require_write_auth),
):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    now_iso = datetime.now(timezone.utc).isoformat()
    storage.delete_internet_policy(agent_id, scope_type.strip().lower(), target_value.strip())
    payload_dict = {"scope_type": scope_type, "target_value": target_value, "internet_enabled": True}
    storage.create_task_row(agent_id, "apply_internet_policy", now_iso, payload=payload_dict)
    return {"status": "deleted", "agent_id": agent_id, "scope_type": scope_type, "target_value": target_value}


# ---------------------------------------------------------------------------
# Configuration & Optimisation Multi-Box (`/boxes/*`)
# ---------------------------------------------------------------------------
@app.get("/boxes/{agent_id}")
def get_boxes(agent_id: str, ctx: dict = Depends(require_read_auth)):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    raw_devices = storage.get_devices_raw(agent_id)
    existing = storage.list_box_configs(agent_id)
    boxes = net_controller.discover_boxes_from_devices(agent_id, raw_devices, existing)
    return {"agent_id": agent_id, "boxes": boxes}


@app.post("/boxes/{agent_id}/config")
def save_box_config(agent_id: str, req: BoxConfigRequest, ctx: dict = Depends(require_write_auth)):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    now_iso = datetime.now(timezone.utc).isoformat()
    box_dict = req.model_dump() if hasattr(req, "model_dump") else req.dict()
    box_dict["health_score"] = 96
    box_dict["last_optimized_at"] = now_iso
    if not box_dict.get("notes"):
        box_dict["notes"] = f"Configurée manuellement par {ctx['actor']} (DNS {req.dns_primary}, Canal {req.wifi_channel}, QoS {req.qos_profile})."
    saved = storage.upsert_box_config(agent_id, box_dict)
    cmds = net_controller.generate_router_commands("optimize_box", saved)
    task = storage.create_task_row(agent_id, "optimize_box", now_iso, payload=saved)
    storage.record_audit_log(
        now_iso,
        f"boxcfg-{ctx['org_slug']}",
        "NET-CONTROL",
        "box_config",
        "configure_box",
        "APPLIED",
        4,
        f"Box {req.box_name} ({req.box_ip}) configurée : Canal {req.wifi_channel}, DNS {req.dns_primary}, QoS {req.qos_profile}.",
    )
    return {"status": "saved", "box": saved, "router_commands": cmds, "task_queued": task}


@app.post("/boxes/{agent_id}/optimize-all")
def optimize_all_boxes(agent_id: str, ctx: dict = Depends(require_write_auth)):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    now_iso = datetime.now(timezone.utc).isoformat()
    raw_devices = storage.get_devices_raw(agent_id)
    state = storage.get_state_raw(agent_id)
    discovered = net_controller.discover_boxes_from_devices(agent_id, raw_devices, storage.list_box_configs(agent_id))
    optimized, summary = net_controller.compute_optimal_box_plan(discovered, raw_devices, state, now_iso)

    all_cmds: List[str] = []
    for b in optimized:
        storage.upsert_box_config(agent_id, b)
        all_cmds.extend(net_controller.generate_router_commands("optimize_box", b))
        storage.create_task_row(agent_id, "optimize_box", now_iso, payload=b)

    storage.record_audit_log(
        now_iso,
        f"boxopt-{ctx['org_slug']}",
        "NET-CONTROL",
        "auto_optimize",
        "optimize_all_boxes",
        "OPTIMIZED",
        6,
        f"{len(optimized)} box/relais optimisés automatiquement sur {agent_id}.",
    )
    return {
        "status": "optimized",
        "agent_id": agent_id,
        "boxes": optimized,
        "summary": summary,
        "router_commands": all_cmds,
    }


@app.post("/boxes/{agent_id}/reboot")
def reboot_box(agent_id: str, req: BoxRebootRequest, ctx: dict = Depends(require_write_auth)):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    now_iso = datetime.now(timezone.utc).isoformat()
    payload = {"box_ip": req.box_ip}
    cmds = net_controller.generate_router_commands("reboot_box", payload)
    task = storage.create_task_row(agent_id, "reboot_box", now_iso, payload=payload)
    storage.record_audit_log(
        now_iso,
        f"boxreboot-{ctx['org_slug']}",
        "NET-CONTROL",
        "box_reboot",
        "reboot_box",
        "QUEUED",
        2,
        f"Redémarrage contrôlé envoyé à la box {req.box_ip} ({agent_id}).",
    )
    return {"status": "queued", "box_ip": req.box_ip, "router_commands": cmds, "task_queued": task}


# ---------------------------------------------------------------------------
# Hub de Partage de Fichiers & Données Multimédias (`/media/*`)
# ---------------------------------------------------------------------------
def _infer_media_category(mime_type: str, filename: str) -> str:
    m = (mime_type or "").lower()
    fn = (filename or "").lower()
    if m.startswith("image/") or fn.endswith((".png", ".jpg", ".jpeg", ".svg", ".webp", ".gif")):
        return "image"
    if m.startswith("audio/") or fn.endswith((".mp3", ".wav", ".ogg", ".m4a", ".aac")):
        return "audio"
    if m.startswith("video/") or fn.endswith((".mp4", ".webm", ".mov", ".mkv")):
        return "video"
    return "document"


def _generate_welcome_wav() -> bytes:
    """Génère un carillon audio harmonique WAV léger (1.2s) pour démonstration multimédia immédiate."""
    sample_rate = 8000
    duration_s = 1.2
    n_samples = int(sample_rate * duration_s)
    pcm = bytearray()
    for i in range(n_samples):
        t = i / sample_rate
        freq = 523.25 if t < 0.4 else (659.25 if t < 0.8 else 783.99)
        env = max(0.0, 1.0 - (t % 0.4) * 1.8)
        val = int(14000 * env * math.sin(2 * math.pi * freq * t))
        pcm += struct.pack("<h", val)
    data_size = len(pcm)
    header = struct.pack(
        "<4sI4s4sIHHIIHH4sI",
        b"RIFF",
        36 + data_size,
        b"WAVE",
        b"fmt ",
        16,
        1,
        1,
        sample_rate,
        sample_rate * 2,
        2,
        16,
        b"data",
        data_size,
    )
    return header + bytes(pcm)


def _seed_demo_media_if_empty(agent_id: str) -> List[dict]:
    items = storage.list_shared_media(agent_id, org_slug="public-demo", limit=50)
    if items or agent_id != "simulation-bouake":
        return items

    now_iso = datetime.now(timezone.utc).isoformat()
    doc_bytes = (
        "GUIDE RÉSEAU LOCAL DADEREZO v4.0 — SAINTE MARIE DE BOUAKÉ\n"
        "=========================================================\n"
        "1. Réseau Local (LAN) : reste disponible même en cas de coupure Internet FAI.\n"
        "2. Partage Multimédia : les documents, images, audios et vidéos publiés ici\n"
        "   sont accessibles par tous les postes autorisés du site.\n"
        "3. Pilotage Internet : le Superviseur Général peut activer/couper Internet\n"
        "   sur la Box Principale, par Zone/Sous-réseau ou par Appareil.\n"
    ).encode("utf-8")
    storage.create_shared_media(
        org_slug="public-demo",
        agent_id=agent_id,
        title="Guide & Charte Réseau Local (LAN / Internet)",
        filename="guide_reseau_daderezo.txt",
        mime_type="text/plain; charset=utf-8",
        category="document",
        raw_bytes=doc_bytes,
        target_zone="Toutes les zones",
        description="Consignes d'utilisation du réseau et continuité LAN hors-ligne.",
        uploaded_by="Orchestrateur DADEREZO",
        now_iso=now_iso,
    )

    svg_diagram = (
        '<svg xmlns="http://www.w3.org/2000/svg" width="680" height="260" viewBox="0 0 680 260">'
        '<rect width="680" height="260" rx="18" fill="#0b1324"/>'
        '<rect x="24" y="85" width="170" height="90" rx="12" fill="#112240" stroke="#00f0ff" stroke-width="2"/>'
        '<text x="109" y="125" fill="#00f0ff" font-family="sans-serif" font-size="14" font-weight="bold" text-anchor="middle">BOX PRINCIPALE</text>'
        '<text x="109" y="148" fill="#9fb3c8" font-family="monospace" font-size="12" text-anchor="middle">192.168.8.1 · DNS 1.1.1.1</text>'
        '<line x1="194" y1="130" x2="260" y2="130" stroke="#10b981" stroke-width="3"/>'
        '<rect x="260" y="85" width="170" height="90" rx="12" fill="#112240" stroke="#10b981" stroke-width="2"/>'
        '<text x="345" y="125" fill="#10b981" font-family="sans-serif" font-size="14" font-weight="bold" text-anchor="middle">ROUTEUR CŒUR</text>'
        '<text x="345" y="148" fill="#9fb3c8" font-family="monospace" font-size="12" text-anchor="middle">192.168.8.57 · QoS Actif</text>'
        '<line x1="430" y1="130" x2="490" y2="130" stroke="#a855f7" stroke-width="3"/>'
        '<rect x="490" y="85" width="166" height="90" rx="12" fill="#112240" stroke="#a855f7" stroke-width="2"/>'
        '<text x="573" y="125" fill="#d8b4fe" font-family="sans-serif" font-size="14" font-weight="bold" text-anchor="middle">HUB MULTIMÉDIA</text>'
        '<text x="573" y="148" fill="#9fb3c8" font-family="monospace" font-size="12" text-anchor="middle">Cloud + LAN :8090</text>'
        "</svg>"
    ).encode("utf-8")
    storage.create_shared_media(
        org_slug="public-demo",
        agent_id=agent_id,
        title="Schéma Topologie Optimisée Multi-Box",
        filename="topologie_multibox.svg",
        mime_type="image/svg+xml",
        category="image",
        raw_bytes=svg_diagram,
        target_zone="Administration",
        description="Architecture visuelle Box FAI + Routeur Cœur + Hub Multimédia LAN.",
        uploaded_by="TOPO-SCAN",
        now_iso=now_iso,
    )

    storage.create_shared_media(
        org_slug="public-demo",
        agent_id=agent_id,
        title="Signal Sonore Test Diffusion Réseau (WAV)",
        filename="carillon_test_lan.wav",
        mime_type="audio/wav",
        category="audio",
        raw_bytes=_generate_welcome_wav(),
        target_zone="Communauté",
        description="Test de streaming audio immédiat via le Hub Multimédia DADEREZO.",
        uploaded_by="MEDIA-HUB",
        now_iso=now_iso,
    )
    return storage.list_shared_media(agent_id, org_slug="public-demo", limit=50)


@app.get("/media/{agent_id}")
def list_media(agent_id: str, ctx: dict = Depends(require_read_auth)):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    if ctx["org_slug"] == "public-demo" and agent_id == "simulation-bouake":
        return _seed_demo_media_if_empty(agent_id)
    return storage.list_shared_media(agent_id, org_slug=ctx["org_slug"], limit=50)


@app.post("/media/{agent_id}")
def upload_media(agent_id: str, req: SharedMediaUploadRequest, ctx: dict = Depends(require_write_auth)):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    b64_clean = req.content_b64.strip()
    if "," in b64_clean and b64_clean.startswith("data:"):
        b64_clean = b64_clean.split(",", 1)[1]
    try:
        raw_bytes = base64.b64decode(b64_clean)
    except Exception:
        raise HTTPException(status_code=400, detail="Contenu base64 invalide.")

    if len(raw_bytes) > 4 * 1024 * 1024:
        raise HTTPException(status_code=413, detail="Fichier trop volumineux pour l'envoi direct (max 4 Mo par fichier).")

    now_iso = datetime.now(timezone.utc).isoformat()
    cat = req.category or _infer_media_category(req.mime_type, req.filename)
    saved = storage.create_shared_media(
        org_slug=ctx["org_slug"],
        agent_id=agent_id,
        title=req.title,
        filename=req.filename,
        mime_type=req.mime_type,
        category=cat,
        raw_bytes=raw_bytes,
        target_zone=req.target_zone,
        description=req.description,
        uploaded_by=ctx["actor"],
        now_iso=now_iso,
    )
    storage.create_task_row(agent_id, "sync_media", now_iso, payload={"media_id": saved.get("id")})
    storage.record_audit_log(
        now_iso,
        f"media-{ctx['org_slug']}",
        "MEDIA-HUB",
        "share_file",
        "upload_shared_media",
        "OK",
        5,
        f"Média partagé « {req.title} » ({cat}, {len(raw_bytes)} octets) vers {req.target_zone}.",
    )
    return {"status": "shared", "media": saved}


@app.get("/media/file/{media_id}")
def stream_or_download_media(
    media_id: int,
    download: int = Query(default=0),
    token: Optional[str] = Query(default=None),
    ctx: dict = Depends(require_read_auth),
):
    init_db()
    eff_org = ctx["org_slug"]
    if token:
        claims = _verify_saas_token(token)
        if claims:
            eff_org = claims["org_slug"]

    found = storage.get_shared_media_payload(media_id)
    if not found:
        raise HTTPException(status_code=404, detail="Média introuvable.")
    meta, raw_bytes = found
    item_org = meta.get("org_slug") or "public-demo"
    if item_org != "public-demo" and item_org != eff_org:
        raise HTTPException(status_code=403, detail="Ce fichier appartient à un espace privé.")

    disp_type = "attachment" if download == 1 else "inline"
    fname = meta.get("filename") or f"media_{media_id}"
    return Response(
        content=raw_bytes,
        media_type=meta.get("mime_type") or "application/octet-stream",
        headers={"Content-Disposition": f'{disp_type}; filename="{fname}"'},
    )


@app.delete("/media/{media_id}")
def remove_media(media_id: int, ctx: dict = Depends(require_write_auth)):
    init_db()
    ok = storage.delete_shared_media(media_id, org_slug=ctx["org_slug"])
    if not ok:
        raise HTTPException(status_code=404, detail="Fichier introuvable ou non autorisé.")
    return {"status": "deleted", "media_id": media_id}


# ---------------------------------------------------------------------------
# File d'attente des Tâches Sondes & Banc de Simulation
# ---------------------------------------------------------------------------
@app.post("/tasks/{agent_id}")
def create_diagnostic_task(agent_id: str, req: DiagnosticTaskRequest, ctx: dict = Depends(require_write_auth)):
    action = req.action.strip().lower()
    if action not in ALLOWED_TASKS:
        raise HTTPException(
            status_code=400,
            detail=f"Action non reconnue. Actions autorisées : {sorted(ALLOWED_TASKS)}",
        )
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    now_iso = datetime.now(timezone.utc).isoformat()
    storage.create_task_row(agent_id, action, now_iso, payload=req.payload)
    return {"status": "queued", "agent_id": agent_id, "action": action}


@app.get("/tasks/{agent_id}")
def list_diagnostic_tasks(
    agent_id: str, limit: int = Query(default=10, ge=1, le=100), ctx: dict = Depends(require_read_auth)
):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    return storage.list_tasks_raw(agent_id, limit=limit)


@app.post("/tasks/{agent_id}/{task_id}/ack")
def ack_diagnostic_task(agent_id: str, task_id: int, result: str = "OK", ctx: dict = Depends(require_write_auth)):
    init_db()
    _ensure_agent_tenant_access(agent_id, ctx)
    now_iso = datetime.now(timezone.utc).isoformat()
    storage.ack_task_row(agent_id, task_id, result, now_iso)
    return {"status": "acknowledged", "task_id": task_id}


@app.post("/demo/scenario/{scenario}")
def run_demo_scenario(scenario: str, ctx: dict = Depends(require_read_auth)):
    """Banc d'essai interactif strictement confiné à l'agent isolé `simulation-bouake`."""
    if os.environ.get("DADEREZO_ENABLE_DEMO", "1") == "0":
        raise HTTPException(status_code=403, detail="Mode démonstration désactivé.")

    base_probes = [
        Probe(ip="192.168.8.1", mac="02:b4:f4:8d:bd:a1", name="Box FAI principale", zone="Accès FAI", status="up", type="fai_box", latency_ms=2.1),
        Probe(ip="192.168.8.57", mac="cc:d8:43:32:45:c8", name="Passerelle / Routeur principal", zone="Cœur réseau", status="up", type="gateway", latency_ms=1.2),
        Probe(ip="192.168.8.10", mac="74:ac:b9:12:44:10", name="Relais Wi-Fi Communauté", zone="Communauté", status="up", type="relay", latency_ms=3.4),
        Probe(ip="192.168.8.14", mac="58:38:79:60:02:5f", name="Poste Secrétariat", zone="Administration", status="up", type="host", latency_ms=2.8),
        Probe(ip="192.168.8.48", mac="36:d3:5a:59:75:bc", name="Poste Hôtellerie", zone="Accueil", status="up", type="host", latency_ms=4.1),
        Probe(ip="192.168.8.75", mac="e8:40:f2:95:3c:c4", name="Poste Bibliothèque / Studium", zone="Communauté", status="up", type="host", latency_ms=3.9),
        Probe(ip="192.168.8.162", mac="a0:51:0b:96:69:97", name="Mini-PC Sonde DADEREZO", zone="Supervision", status="up", type="probe", latency_ms=0.2),
    ]

    key = scenario.strip().lower()
    alerts: List[Union[AlertInput, dict]] = []
    gw_status = "up"
    gw_lat = 1.2
    inet_status = "up"
    wan_lat: Optional[float] = 32.0

    if key == "nominal":
        alerts = [AlertInput(severity="info", message="Contrôle périodique nominal : 7/7 équipements en ligne.")]
    elif key == "intrus":
        base_probes.append(
            Probe(ip="192.168.8.217", mac="0c:8b:fd:10:b1:89", name="Poste 192.168.8.217 (inconnu)", zone="Visiteurs", status="up", type="host", latency_ms=8.7)
        )
        alerts = [AlertInput(severity="nouveau", message="Nouvel appareil détecté : 192.168.8.217 (0c:8b:fd:10:b1:89)")]
    elif key == "panne_fai":
        base_probes[0].status = "down"
        base_probes[0].latency_ms = None
        inet_status = "down"
        wan_lat = None
        alerts = [
            AlertInput(severity="critique", message="Équipement hors ligne : Box FAI principale (192.168.8.1)"),
            AlertInput(severity="panne", message="Passerelle locale active (192.168.8.57) mais accès Internet coupé (panne FAI probable)"),
        ]
    elif key == "panne_relais":
        base_probes[2].status = "down"
        base_probes[2].latency_ms = None
        base_probes[5].status = "down"
        base_probes[5].latency_ms = None
        alerts = [
            AlertInput(severity="panne", message="Équipement hors ligne : Relais Wi-Fi Communauté (192.168.8.10)"),
            AlertInput(severity="panne", message="Équipement hors ligne : Poste Bibliothèque / Studium (192.168.8.75)"),
        ]
    elif key == "lan_seul":
        base_probes.append(
            Probe(
                ip="192.168.8.120",
                mac="a4:bb:6d:21:09:44",
                name="Imprimante Économat (LAN seul)",
                zone="Administration",
                status="up",
                type="printer_lan",
                latency_ms=1.9,
            )
        )
        alerts = [
            AlertInput(
                severity="info",
                message="Inventaire mis à jour : 8 appareils connectés au LAN (7 avec Internet, 1 restreint au LAN seul).",
            )
        ]
    elif key == "retablissement":
        # Réinitialise aussi les coupures manuelles sur le banc de démo lors d'un rétablissement complet
        for p in storage.list_internet_policies("simulation-bouake"):
            storage.delete_internet_policy("simulation-bouake", p["scope_type"], p["target_value"])
        alerts = [
            AlertInput(severity="retabli", message="Équipement rétabli : Box FAI principale (192.168.8.1)"),
            AlertInput(severity="retabli", message="Accès Internet rétabli (latence WAN 32 ms)"),
        ]
    else:
        raise HTTPException(
            status_code=400,
            detail="Scénario inconnu (nominal, intrus, panne_fai, panne_relais, lan_seul, retablissement).",
        )

    payload = AgentData(
        agent_id="simulation-bouake",
        nom="Simulation · Sainte Marie de Bouaké (192.168.8.0/24)",
        site_name="Sainte Marie de Bouaké (Banc de simulation)",
        ip_local="192.168.8.162",
        mask="255.255.255.0",
        gw="192.168.8.57",
        mac_local="a0:51:0b:96:69:97",
        dns=["192.168.8.57", "1.1.1.1"],
        gw_status=gw_status,
        gw_latency_ms=gw_lat,
        internet_status=inet_status,
        wan_latency_ms=wan_lat,
        probes=base_probes,
        alerts=alerts,
    )
    demo_ctx = dict(ctx)
    demo_ctx["org_slug"] = "public-demo"
    res = receive_data(payload, ctx=demo_ctx)
    return {"status": "ok", "agent_id": "simulation-bouake", "scenario": key, "result": res}


# ---------------------------------------------------------------------------
# Superviseur Général Multi-Sites & Orchestrateur IA
# ---------------------------------------------------------------------------
def _make_dashboards_fetcher(ctx: dict):
    def _fetcher(target_agent_id: Optional[str], force_global: bool) -> List[dict]:
        agents = _list_agents_for_ctx(ctx)
        if not agents:
            return []
        if force_global or (target_agent_id and target_agent_id.lower() == "all"):
            return [_build_dashboard(a["id"], ctx) for a in agents]
        chosen_id = target_agent_id if any(a["id"] == target_agent_id for a in agents) else agents[0]["id"]
        return [_build_dashboard(chosen_id, ctx)]

    return _fetcher


@app.get("/supervisor/overview")
def supervisor_overview(ctx: dict = Depends(require_read_auth)):
    agents = _list_agents_for_ctx(ctx)
    sites = []
    tot_dev = tot_up = tot_down = tot_inet_yes = tot_inet_no = tot_lan_only = tot_alerts = 0
    for a in agents:
        d = _build_dashboard(a["id"], ctx)
        s = d["summary"]
        tot_dev += s["total_devices"]
        tot_up += s["devices_up"]
        tot_down += s["devices_down"]
        tot_inet_yes += s["devices_with_internet"]
        tot_inet_no += s["devices_without_internet"]
        tot_lan_only += s["devices_lan_only_no_internet"]
        tot_alerts += len(d["alerts"])
        sites.append(
            {
                "agent_id": a["id"],
                "site_name": d["state"].get("site_name") or a.get("nom") or a["id"],
                "agent_status": a["status"],
                "is_simulation": a.get("is_simulation", False),
                "internet_status": s["internet_status"],
                "main_box_internet_enabled": s["main_box_internet_enabled"],
                "gw": d["state"].get("gw"),
                "gw_status": d["state"].get("gw_status", "unknown"),
                "summary": s,
                "alerts_count": len(d["alerts"]),
            }
        )
    return {
        "db_backend": storage.get_backend_mode(),
        "workspace_mode": ctx["mode"],
        "org_slug": ctx["org_slug"],
        "org_name": ctx["org_name"],
        "total_sites": len(agents),
        "sites_online": sum(1 for a in agents if a["status"] == "online"),
        "sites_offline": sum(1 for a in agents if a["status"] != "online"),
        "real_sites_count": sum(1 for a in agents if not a.get("is_simulation")),
        "total_devices": tot_dev,
        "devices_up": tot_up,
        "devices_down": tot_down,
        "devices_with_internet": tot_inet_yes,
        "devices_without_internet": tot_inet_no,
        "devices_lan_only_no_internet": tot_lan_only,
        "total_alerts": tot_alerts,
        "sites": sites,
    }


@app.post("/supervisor/ask")
def supervisor_ask(
    req: SupervisorAskRequest,
    ctx: dict = Depends(require_read_auth),
    x_llm_api_key: Optional[str] = Header(default=None, alias="X-LLM-Api-Key"),
    x_llm_model: Optional[str] = Header(default=None, alias="X-LLM-Model"),
):
    init_db()
    if req.agent_id and req.agent_id.lower() != "all":
        _ensure_agent_tenant_access(req.agent_id, ctx)

    return agent_engine.run_multi_agent_mission(
        question_raw=req.question,
        target_agent_id=req.agent_id,
        scope=req.scope,
        session_id=req.session_id or "default-supervisor",
        can_write=ctx["can_write"],
        fetch_dashboards_fn=_make_dashboards_fetcher(ctx),
        org_slug=ctx["org_slug"],
        actor_name=ctx["actor"],
        llm_api_key=x_llm_api_key,
        llm_model=x_llm_model,
    )


@app.get("/supervisor/audit")
def supervisor_audit(limit: int = Query(default=25, ge=1, le=100), ctx: dict = Depends(require_read_auth)):
    init_db()
    allowed_ids = {a["id"] for a in _list_agents_for_ctx(ctx)}
    pending = [
        p
        for p in storage.list_human_approvals(status="pending", limit=25)
        if (p.get("agent_id") in allowed_ids) or (ctx["org_slug"] == "public-demo" and p.get("agent_id") == "simulation-bouake")
    ]
    return {
        "db_backend": storage.get_backend_mode(),
        "audit_logs": storage.list_audit_logs(limit=limit),
        "pending_approvals": pending[:15],
    }


@app.get("/supervisor/session/{session_id}")
def supervisor_session_history(
    session_id: str, limit: int = Query(default=12, ge=1, le=50), ctx: dict = Depends(require_read_auth)
):
    init_db()
    return {"session_id": session_id, "turns": storage.get_session_turns(session_id, limit=limit)}


@app.post("/supervisor/approve/{approval_id}")
def supervisor_decide_approval(
    approval_id: int, body: HumanApprovalDecision, ctx: dict = Depends(require_write_auth)
):
    init_db()
    dec = body.decision.strip().lower()
    if dec not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="Décision invalide ('approve' ou 'reject').")

    existing = storage.get_human_approval(approval_id)
    if not existing:
        raise HTTPException(status_code=404, detail="Demande d'approbation introuvable.")
    target_aid = existing.get("agent_id") or "simulation-bouake"
    _ensure_agent_tenant_access(target_aid, ctx)
    if existing.get("status") != "pending":
        raise HTTPException(status_code=409, detail=f"Cette demande a déjà été traitée ({existing.get('status')}).")

    now_iso = datetime.now(timezone.utc).isoformat()
    resolved = storage.resolve_human_approval(approval_id, dec, now_iso)
    if not resolved:
        raise HTTPException(status_code=404, detail="Demande d'approbation introuvable.")

    queued_task = None
    if dec == "approve":
        aid = resolved.get("agent_id") or "simulation-bouake"
        act = resolved.get("action") or "sweep"
        queued_task = storage.create_task_row(aid, act, now_iso)
        storage.record_audit_log(
            now_iso,
            resolved.get("session_id") or "default-supervisor",
            "OPS-DISPATCH",
            "human_decision",
            "approve_and_dispatch",
            "APPROVED",
            2,
            f"Validation humaine #{approval_id} acceptée par {ctx['actor']} -> tâche '{act}' envoyée à '{aid}'.",
        )
    else:
        storage.record_audit_log(
            now_iso,
            resolved.get("session_id") or "default-supervisor",
            "OPS-DISPATCH",
            "human_decision",
            "reject_action",
            "REJECTED",
            1,
            f"Validation humaine #{approval_id} refusée par {ctx['actor']}.",
        )

    return {"status": "ok", "approval": resolved, "task_queued": queued_task}


if os.environ.get("VERCEL") or os.environ.get("DADEREZO_SEED_DEMO") == "1":
    try:
        public_ctx = {
            "authenticated": True,
            "can_write": True,
            "mode": "public_demo",
            "org_slug": "public-demo",
            "org_name": "Espace Démo Public",
            "actor": "Système",
        }
        if not storage.list_agents_raw(org_slug="public-demo"):
            run_demo_scenario("nominal", ctx=public_ctx)
    except Exception:
        pass
