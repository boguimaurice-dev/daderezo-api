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
from datetime import date, datetime, timezone
import hashlib
import hmac
import json
import math
import os
import re
import secrets
import struct
import time
import urllib.error
import urllib.request
import urllib.parse
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
    name: os.path.join(HERE, name)
    for name in (
        "agent_client.py", "collector.py", "devices.json", "make_dashboard.py",
        "net_controller.py", "contabo_watchdog.py", "docker-compose.contabo.yml", "contabo_bootstrap.sh",
    )
}

app = FastAPI(
    title="DADEREZO v4.7 Multi-Agent ReAct (DeepSeek / Contabo), Interactive Deep-Dive & Active Network Control API",
    description="Supervision réseau PWA installable, ReAct Function-Calling natif DeepSeek, inspection approfondie universelle, contrôle Internet granulaire, Multi-Box et partage Multimédia",
    version="4.7.0",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=False,
    allow_methods=["*"],
    allow_headers=["*"],
)


@app.exception_handler(PermissionError)
async def tenant_conflict_handler(request: Request, exc: PermissionError):
    return JSONResponse(status_code=403, content={"detail": "Cette sonde appartient à un autre espace."})


@app.middleware("http")
async def prevent_private_caching(request: Request, call_next):
    response = await call_next(request)
    if (request.headers.get("authorization") or request.headers.get("x-api-key")
            or request.url.path.startswith(("/auth/", "/platform/", "/probe/", "/media/"))):
        response.headers["Cache-Control"] = "no-store"
    return response


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


def _legacy_auth_enabled() -> bool:
    # Explicit opt-in for local legacy compatibility only, never use in production.
    return os.environ.get("DADEREZO_LEGACY_AUTH", "0") == "1"


def _application_active(app: Optional[dict]) -> bool:
    if not app or app.get("status") != "approved" or not app.get("org_slug") or not app.get("probe_api_key"):
        return False
    if app.get("payment_status") == "pilot":
        return True
    if app.get("payment_status") != "paid":
        return False
    try:
        return date.fromisoformat(app.get("subscription_end") or "") >= datetime.now(timezone.utc).date()
    except (ValueError, TypeError):
        return False


def _application_context(app: dict, mode: str) -> dict:
    return {"authenticated": True, "can_write": True, "mode": mode,
            "org_slug": app["org_slug"], "org_name": app["org_name"],
            "actor": app["contact_name"] if mode == "private_org" else "Sonde (" + app["org_name"] + ")",
            "email": app["email"], "probe_api_key": app["probe_api_key"]}


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

    if bearer and not bearer.startswith(("dzt_", "dzk_")) and bearer != get_api_key():
        identity = require_google_identity(authorization="Bearer " + bearer)
        application = storage.find_application(identity["id"])
        if not _application_active(application):
            raise HTTPException(status_code=403, detail="Candidature ou abonnement non actif.")
        return _application_context(application, "private_org")

    if bearer.startswith("dzt_"):
        if not _legacy_auth_enabled():
            raise HTTPException(status_code=403, detail="Ancien compte désactivé : une candidature Google est nécessaire.")
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
        application = storage.find_platform_application_by_probe_key(probe_candidate)
        if application:
            if not _application_active(application):
                raise HTTPException(status_code=403, detail="Sonde suspendue ou abonnement expiré.")
            return _application_context(application, "private_probe")
        u = storage.get_saas_user_by_probe_key(probe_candidate) if _legacy_auth_enabled() else None
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
    can_write_public = (not global_expected and _legacy_auth_enabled()) or (bool(global_expected) and bool(provided) and hmac.compare_digest(provided, global_expected))
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
        if not _legacy_auth_enabled() and ctx["org_slug"] != "public-demo" and not agent_id.startswith(ctx["org_slug"] + "-"):
            raise HTTPException(status_code=403, detail="Identifiant de sonde hors de votre espace.")
        return None
    ag_org = ag.get("org_slug") or "public-demo"
    if ctx["org_slug"] != "public-demo":
        # En Mode Travail Privé : séparation stricte, aucune lecture/mélange avec simulation-bouake ou un autre tenant
        if ag_org != ctx["org_slug"] or str(agent_id).startswith("simulation-"):
            raise HTTPException(
                status_code=403,
                detail="Mode Travail Actif isolé : cette sonde n'appartient pas à votre espace réseau privé.",
            )
    elif ag_org != "public-demo":
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
    voice_mode: bool = Field(default=False)


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
    llm_cfg = agent_engine._detect_llm_config()
    return {
        "service": "DADEREZO API",
        "status": "ok",
        "mode": "active_governed",
        "version": "4.7.0",
        "architecture": "multi_agent_z_v4_7_interactive_deep_dive",
        "agents_pipeline": ["SENTINEL-SEC", "TOPO-SCAN", "DIAG-NET", "NET-CONTROL", "MEDIA-HUB"],
        "capabilities": [
            "internet_switch_global_subnet_device",
            "multi_box_auto_optimization",
            "multimedia_lan_cloud_sharing",
            "private_multitenant_saas",
            "multi_turn_session_memory",
            "security_posture_scoring",
            "installable_pwa_offline_resilient",
            "deepseek_native_tool_calling",
            "contabo_gitops_autodeploy",
            "strict_work_vs_simulation_separation",
            "single_file_preconfigured_probe",
            "thoughtful_llm_voice_synthesis",
            "physical_vs_logical_control_audit",
            "interactive_duplex_vad_voice_turn_taking",
            "contextual_deep_dive_perspectives",
            "interactive_element_inspection",
        ],
        "db": storage.get_backend_mode(),
        "llm_configured": bool(llm_cfg),
        "llm_provider": llm_cfg["provider"] if llm_cfg else None,
        "llm_model": llm_cfg["model"] if llm_cfg else None,
        "auth_enabled": bool(get_api_key()),
    }


BRAND_ASSETS = {
    "favicon.svg": ("favicon.svg", "image/svg+xml"),
    "favicon.ico": ("favicon.ico", "image/x-icon"),
    "favicon.png": ("favicon.png", "image/png"),
    "favicon-32.png": ("favicon-32.png", "image/png"),
    "apple-touch-icon.png": ("apple-touch-icon.png", "image/png"),
    "icon-192.png": ("icon-192.png", "image/png"),
    "icon-512.png": ("icon-512.png", "image/png"),
    "icon-maskable-512.png": ("icon-maskable-512.png", "image/png"),
    "logo-icon.png": ("logo-icon.png", "image/png"),
    "logo-orbit.png": ("logo-orbit.png", "image/png"),
    "og-image.png": ("og-image.png", "image/png"),
    "banner-network.jpg": ("banner-network.jpg", "image/jpeg"),
    "banner-partner.jpg": ("banner-partner.jpg", "image/jpeg"),
    "manifest.webmanifest": ("manifest.webmanifest", "application/manifest+json"),
    "sw.js": ("sw.js", "application/javascript"),
    "offline.html": ("offline.html", "text/html; charset=utf-8"),
}


def _serve_brand_asset(asset_key: str, request: Request, extra_headers: Optional[Dict[str, str]] = None) -> Response:
    fname, media_type = BRAND_ASSETS[asset_key]
    fpath = os.path.join(HERE, fname)
    if not os.path.exists(fpath):
        raise HTTPException(status_code=404, detail=f"Ressource {fname} introuvable.")
    with open(fpath, "rb") as f:
        raw = f.read()
    if asset_key == "sw.js":
        cache_ctl = "no-cache"
    elif asset_key.startswith("favicon") or asset_key == "manifest.webmanifest":
        cache_ctl = "public, max-age=3600, must-revalidate"
    else:
        cache_ctl = "public, max-age=86400"
    headers = {
        "Cache-Control": cache_ctl,
        "Content-Length": str(len(raw)),
    }
    if extra_headers:
        headers.update(extra_headers)
    if request.method == "HEAD":
        return Response(content=b"", media_type=media_type, headers=headers)
    return Response(content=raw, media_type=media_type, headers=headers)


@app.api_route("/manifest.webmanifest", methods=["GET", "HEAD"], include_in_schema=False)
@app.api_route("/manifest.json", methods=["GET", "HEAD"], include_in_schema=False)
def pwa_manifest(request: Request):
    return _serve_brand_asset("manifest.webmanifest", request)


@app.api_route("/sw.js", methods=["GET", "HEAD"], include_in_schema=False)
def pwa_service_worker(request: Request):
    return _serve_brand_asset("sw.js", request, extra_headers={"Service-Worker-Allowed": "/"})


@app.api_route("/offline.html", methods=["GET", "HEAD"], include_in_schema=False)
def pwa_offline_fallback(request: Request):
    return _serve_brand_asset("offline.html", request)


@app.api_route("/icon-192.png", methods=["GET", "HEAD"], include_in_schema=False)
def pwa_icon_192(request: Request):
    return _serve_brand_asset("icon-192.png", request)


@app.api_route("/icon-512.png", methods=["GET", "HEAD"], include_in_schema=False)
def pwa_icon_512(request: Request):
    return _serve_brand_asset("icon-512.png", request)


@app.api_route("/icon-maskable-512.png", methods=["GET", "HEAD"], include_in_schema=False)
def pwa_icon_maskable_512(request: Request):
    return _serve_brand_asset("icon-maskable-512.png", request)


@app.api_route("/favicon.svg", methods=["GET", "HEAD"], include_in_schema=False)
def brand_favicon_svg(request: Request):
    return _serve_brand_asset("favicon.svg", request)


@app.api_route("/favicon.ico", methods=["GET", "HEAD"], include_in_schema=False)
def brand_favicon_ico(request: Request):
    return _serve_brand_asset("favicon.ico", request)


@app.api_route("/favicon.png", methods=["GET", "HEAD"], include_in_schema=False)
def brand_favicon_png(request: Request):
    return _serve_brand_asset("favicon.png", request)


@app.api_route("/favicon-32.png", methods=["GET", "HEAD"], include_in_schema=False)
def brand_favicon_32_png(request: Request):
    return _serve_brand_asset("favicon-32.png", request)


@app.api_route("/apple-touch-icon.png", methods=["GET", "HEAD"], include_in_schema=False)
def brand_apple_touch_icon(request: Request):
    return _serve_brand_asset("apple-touch-icon.png", request)


@app.api_route("/logo-icon.png", methods=["GET", "HEAD"], include_in_schema=False)
def brand_logo_icon(request: Request):
    return _serve_brand_asset("logo-icon.png", request)


@app.api_route("/logo-orbit.png", methods=["GET", "HEAD"], include_in_schema=False)
def brand_logo_orbit(request: Request):
    return _serve_brand_asset("logo-orbit.png", request)


@app.api_route("/og-image.png", methods=["GET", "HEAD"], include_in_schema=False)
def brand_og_image(request: Request):
    return _serve_brand_asset("og-image.png", request)


@app.api_route("/banner-network.jpg", methods=["GET", "HEAD"], include_in_schema=False)
def brand_banner_network(request: Request):
    return _serve_brand_asset("banner-network.jpg", request)


@app.api_route("/banner-partner.jpg", methods=["GET", "HEAD"], include_in_schema=False)
def brand_banner_partner(request: Request):
    return _serve_brand_asset("banner-partner.jpg", request)


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


def _build_single_file_probe_script(api_url: str, org_slug: str, org_name: str, probe_key: str) -> str:
    safe_api = json.dumps(api_url.rstrip("/"))
    safe_agent_id = json.dumps(f"{org_slug}-principal")
    safe_org_name = json.dumps(org_name)
    safe_probe_key = json.dumps(probe_key)
    return f'''#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
DADEREZO v4.5 — Sonde Terrain Réelle Autonome (1 seul fichier · Zéro dépendance externe).
Pré-configurée pour l'espace privé isolé : {org_name} ({org_slug})

Usage sur Windows, Linux ou macOS :
    python daderezo_sonde.py
    python daderezo_sonde.py --active-control   # (en Administrateur : active le filtrage pare-feu local / Hotspot)
"""
import concurrent.futures
import ctypes
import ipaddress
import json
import os
import platform
import re
import socket
import subprocess
import sys
import time
import urllib.parse
import urllib.request

API_URL = os.environ.get("DADEREZO_API_URL", {safe_api})
AGENT_ID = os.environ.get("DADEREZO_AGENT_ID", {safe_agent_id})
SITE_NAME = os.environ.get("DADEREZO_SITE_NAME", {safe_org_name})
PROBE_API_KEY = os.environ.get("DADEREZO_PROBE_KEY", {safe_probe_key})
SCAN_INTERVAL = int(os.environ.get("DADEREZO_INTERVAL", "15"))
TASK_POLL_SECONDS = int(os.environ.get("DADEREZO_TASK_POLL", "5"))
ACTIVE_CONTROL = ("--active-control" in sys.argv) or (os.environ.get("DADEREZO_ACTIVE_CONTROL", "0").strip() == "1")

OUI_VENDORS = {{
    "00:e0:4c": "Realtek", "fc:ec:da": "Ubiquiti", "74:ac:b9": "Ubiquiti", "24:5a:4c": "Ubiquiti",
    "b0:be:76": "TP-Link", "50:c7:bf": "TP-Link", "c0:25:e9": "TP-Link", "dc:a6:32": "Raspberry Pi",
    "b8:27:eb": "Raspberry Pi", "28:6c:07": "Xiaomi", "48:2c:a0": "Huawei / Box", "00:46:4b": "Huawei / Box",
    "f8:23:b2": "Orange / Livebox", "3c:22:fb": "Apple", "f0:18:98": "Apple", "a4:83:e7": "Apple",
    "38:f9:d3": "Apple", "dc:a9:04": "Apple", "e4:5f:01": "Raspberry Pi", "00:1a:2b": "Cisco",
}}


def _run_cmd(cmd, timeout=4.0):
    try:
        res = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout, errors="ignore")
        return res.stdout or ""
    except Exception:
        return ""


def _ping_host(ip_str, timeout_ms=900):
    sys_name = platform.system().lower()
    if "windows" in sys_name:
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), ip_str]
    elif "darwin" in sys_name:
        cmd = ["ping", "-c", "1", "-W", str(timeout_ms), ip_str]
    else:
        sec = max(1, int(round(timeout_ms / 1000.0)))
        cmd = ["ping", "-c", "1", "-W", str(sec), ip_str]
    t0 = time.perf_counter()
    out = _run_cmd(cmd, timeout=max(2.0, timeout_ms / 1000.0 + 1.2))
    elapsed = round((time.perf_counter() - t0) * 1000.0, 1)
    m = re.search(r"(?:time|temps)[=<]\\s*([0-9]+(?:[.,][0-9]+)?)\\s*ms", out, re.IGNORECASE)
    if m:
        return True, float(m.group(1).replace(",", "."))
    if "ttl=" in out.lower() or "1 received" in out.lower() or "perte 0%" in out.lower() or "0% packet loss" in out.lower():
        return True, elapsed
    return False, None


def _detect_local_network():
    ip_local = "127.0.0.1"
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.settimeout(1.5)
        s.connect(("1.1.1.1", 80))
        ip_local = s.getsockname()[0]
        s.close()
    except Exception:
        try:
            ip_local = socket.gethostbyname(socket.gethostname())
        except Exception:
            pass

    mask = "255.255.255.0"
    gw = ""
    mac_local = ""
    dns_list = []
    sys_name = platform.system().lower()

    if "windows" in sys_name:
        out = _run_cmd(["ipconfig", "/all"], timeout=5.0)
        blocks = re.split(r"\\r?\\n(?=\\S.*:)", out)
        for blk in blocks:
            if ip_local and ip_local in blk:
                m_mask = re.search(r"(?:Masque|Subnet Mask)[^:]*:\\s*([0-9.]+)", blk, re.I)
                if m_mask:
                    mask = m_mask.group(1)
                m_gw = re.search(r"(?:Passerelle|Default Gateway)[^:]*:\\s*([0-9.]+)", blk, re.I)
                if m_gw:
                    gw = m_gw.group(1)
                m_mac = re.search(r"(?:Adresse physique|Physical Address)[^:]*:\\s*([0-9A-Fa-f-]{17})", blk, re.I)
                if m_mac:
                    mac_local = m_mac.group(1).replace("-", ":").lower()
                for m_dns in re.findall(r"(?:Serveurs DNS|DNS Servers)[^:]*:\\s*([0-9.]+)", blk, re.I):
                    if m_dns not in dns_list:
                        dns_list.append(m_dns)
    else:
        r_out = _run_cmd(["ip", "route"], timeout=3.0) or _run_cmd(["route", "-n", "get", "default"], timeout=3.0)
        m_gw = re.search(r"default via ([0-9.]+)", r_out) or re.search(r"gateway:\\s*([0-9.]+)", r_out)
        if m_gw:
            gw = m_gw.group(1)
        a_out = _run_cmd(["ip", "-o", "-f", "inet", "addr", "show"], timeout=3.0)
        for line in a_out.splitlines():
            if ip_local in line:
                m_cidr = re.search(r"inet\\s+([0-9.]+/[0-9]+)", line)
                if m_cidr:
                    try:
                        mask = str(ipaddress.IPv4Interface(m_cidr.group(1)).netmask)
                    except Exception:
                        pass
        link_out = _run_cmd(["ip", "link"], timeout=3.0)
        m_mac = re.search(r"link/ether\\s+([0-9a-f:]{17})", link_out, re.I)
        if m_mac:
            mac_local = m_mac.group(1).lower()
        try:
            with open("/etc/resolv.conf", "r", encoding="utf-8", errors="ignore") as rf:
                for ln in rf:
                    if ln.strip().startswith("nameserver"):
                        parts = ln.split()
                        if len(parts) >= 2 and parts[1] not in dns_list:
                            dns_list.append(parts[1])
        except Exception:
            pass

    if not gw and ip_local.count(".") == 3 and not ip_local.startswith("127."):
        gw = ".".join(ip_local.split(".")[:3]) + ".1"
    return ip_local, mask, gw, mac_local, dns_list


def _parse_arp_table():
    entries = {{}}
    out = _run_cmd(["arp", "-a"], timeout=4.0) + "\\n" + _run_cmd(["ip", "neigh"], timeout=3.0)
    for line in out.splitlines():
        m_ip = re.search(r"\\b([0-9]{{1,3}}(?:\\.[0-9]{{1,3}}){{3}})\\b", line)
        m_mac = re.search(r"([0-9a-fA-F]{{1,2}}(?:[:-][0-9a-fA-F]{{1,2}}){{5}})", line)
        if not m_ip:
            continue
        ip_s = m_ip.group(1)
        try:
            ip_obj = ipaddress.IPv4Address(ip_s)
            if ip_obj.is_multicast or ip_obj.is_loopback or ip_s.endswith(".255") or ip_s.endswith(".0"):
                continue
        except Exception:
            continue
        mac_s = ""
        if m_mac:
            octets = re.split(r"[:-]", m_mac.group(1).lower())
            mac_s = ":".join(o.zfill(2) for o in octets)
            if mac_s in ("ff:ff:ff:ff:ff:ff", "00:00:00:00:00:00"):
                continue
        if ip_s not in entries or (mac_s and not entries[ip_s]):
            entries[ip_s] = mac_s
    return entries


def _friendly_name(ip_s, mac_s, ip_local, gw):
    if ip_s == gw:
        return "Box / Passerelle Principale", "gateway", "Cœur réseau"
    if ip_s == ip_local:
        host = platform.node() or "PC-Sonde"
        return f"Sonde DADEREZO ({{host}})", "probe", "Supervision"
    vendor = OUI_VENDORS.get((mac_s or "")[:8].lower(), "")
    hostname = ""
    try:
        socket.setdefaulttimeout(0.35)
        h, _, _ = socket.gethostbyaddr(ip_s)
        if h and h != ip_s:
            hostname = h.split(".")[0]
    except Exception:
        pass
    if hostname and vendor:
        label = f"{{hostname}} ({{vendor}})"
    elif hostname:
        label = hostname
    elif vendor:
        label = f"Équipement {{vendor}} ({{ip_s}})"
    else:
        label = f"Appareil réseau {{ip_s}}"
    role = "relay" if "ubiquiti" in vendor.lower() or "tp-link" in vendor.lower() else "host"
    return label, role, "Réseau local"


def collect_real_snapshot(do_sweep=False, known_macs=None):
    known_macs = known_macs if known_macs is not None else set()
    ip_local, mask, gw, mac_local, dns_list = _detect_local_network()

    if do_sweep and ip_local.count(".") == 3 and not ip_local.startswith("127."):
        prefix = ".".join(ip_local.split(".")[:3])
        targets = [f"{{prefix}}.{{i}}" for i in range(1, 255) if f"{{prefix}}.{{i}}" != ip_local]
        with concurrent.futures.ThreadPoolExecutor(max_workers=48) as ex:
            list(ex.map(lambda t: _ping_host(t, timeout_ms=450), targets))

    gw_ok, gw_lat = _ping_host(gw, timeout_ms=1000) if gw else (False, None)
    wan1_ok, wan1_lat = _ping_host("1.1.1.1", timeout_ms=1300)
    wan2_ok, wan2_lat = (True, wan1_lat) if wan1_ok else _ping_host("8.8.8.8", timeout_ms=1300)
    inet_up = wan1_ok or wan2_ok
    wan_lat = wan1_lat if wan1_ok else wan2_lat

    arp_map = _parse_arp_table()
    if gw and gw not in arp_map:
        arp_map[gw] = ""
    if ip_local and not ip_local.startswith("127."):
        arp_map[ip_local] = mac_local or arp_map.get(ip_local, "")

    candidate_ips = sorted(arp_map.keys(), key=lambda x: tuple(int(p) for p in x.split(".")))
    ping_results = {{}}
    with concurrent.futures.ThreadPoolExecutor(max_workers=24) as ex:
        futs = {{ex.submit(_ping_host, ip_s, 750): ip_s for ip_s in candidate_ips if ip_s != ip_local}}
        for f, ip_s in futs.items():
            try:
                ping_results[ip_s] = f.result()
            except Exception:
                ping_results[ip_s] = (False, None)
    ping_results[ip_local] = (True, 0.2)

    probes = []
    alerts = []
    for ip_s in candidate_ips:
        mac_s = arp_map.get(ip_s) or None
        ok, lat = ping_results.get(ip_s, (False, None))
        # Si présent fraîchement dans la table ARP mais bloque ICMP (ex: smartphone/Windows firewall), marquer en ligne
        is_up = bool(ok or mac_s)
        name, dev_type, zone = _friendly_name(ip_s, mac_s, ip_local, gw)
        probes.append({{
            "ip": ip_s,
            "mac": mac_s,
            "name": name,
            "zone": zone,
            "status": "up" if is_up else "down",
            "type": dev_type,
            "latency_ms": lat if lat is not None else (1.5 if is_up else None),
        }})
        if mac_s and mac_s not in known_macs and ip_s not in (ip_local, gw):
            if known_macs:
                alerts.append({{"severity": "nouveau", "message": f"Nouvel équipement réel détecté : {{name}} ({{ip_s}} · {{mac_s}})"}})
            known_macs.add(mac_s)
        elif mac_s:
            known_macs.add(mac_s)

    if gw and not gw_ok:
        alerts.append({{"severity": "critique", "message": f"Passerelle locale {{gw}} injoignable en ICMP."}})
    elif not inet_up:
        alerts.append({{"severity": "panne", "message": "Réseau local actif mais sortie Internet FAI indisponible (1.1.1.1 / 8.8.8.8)."}})

    return {{
        "agent_id": AGENT_ID,
        "nom": f"{{SITE_NAME}} (Sonde Réelle)",
        "site_name": SITE_NAME,
        "ip_local": ip_local,
        "mask": mask,
        "gw": gw,
        "mac_local": mac_local or None,
        "dns": dns_list,
        "gw_status": "up" if gw_ok else "down",
        "gw_latency_ms": gw_lat,
        "internet_status": "up" if inet_up else "down",
        "wan_latency_ms": wan_lat,
        "probes": probes,
        "alerts": alerts,
    }}


def _api_call(method, path, body=None):
    headers = {{
        "Accept": "application/json",
        "Content-Type": "application/json",
        "X-API-Key": PROBE_API_KEY,
    }}
    data = json.dumps(body).encode("utf-8") if body is not None else (b"" if method == "POST" else None)
    req = urllib.request.Request(f"{{API_URL}}{{path}}", data=data, headers=headers, method=method)
    with urllib.request.urlopen(req, timeout=20) as resp:
        return json.loads(resp.read().decode("utf-8"))


def _is_os_admin():
    try:
        if platform.system().lower() == "windows":
            return bool(ctypes.windll.shell32.IsUserAnAdmin())
        return hasattr(os, "geteuid") and os.geteuid() == 0
    except Exception:
        return False


def _apply_local_policy_task(task, snap):
    raw_p = task.get("payload_json")
    payload = {{}}
    if isinstance(raw_p, dict):
        payload = raw_p
    elif isinstance(raw_p, str) and raw_p.strip():
        try:
            payload = json.loads(raw_p)
        except Exception:
            payload = {{}}
    enabled = bool(payload.get("internet_enabled", True))
    scope_t = str(payload.get("scope_type") or "global")
    target_v = str(payload.get("target_value") or "main_box")
    gw_ip = snap.get("gw") or "la Box"
    admin_ok = _is_os_admin()

    if ACTIVE_CONTROL and admin_ok and platform.system().lower() == "windows":
        rule_name = f"DADEREZO_POLICY_{{re.sub(r'[^A-Za-z0-9_.-]', '_', target_v)}}"
        subprocess.run(["netsh", "advfirewall", "firewall", "delete", "rule", f"name={{rule_name}}"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        if not enabled and scope_t in ("device", "subnet") and re.match(r"^[0-9./]+$", target_v):
            subprocess.run(
                ["netsh", "advfirewall", "firewall", "add", "rule", f"name={{rule_name}}", "dir=in", "action=block", f"remoteip={{target_v}}"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            return f"Pare-feu Windows actif appliqué pour {{target_v}} (trafic direct Box {{gw_ip}} hors Hotspot nécessite driver routeur)."

    state_txt = "autorisée" if enabled else "coupée logiquement"
    return (
        f"Règle {{scope_t}}:{{target_v}} ({{state_txt}}) reçue par sonde cliente ({{snap.get('ip_local')}}). "
        f"Note physique : les appareils connectés directement au Wi-Fi de la Box {{gw_ip}} continuent de sortir par {{gw_ip}} tant que le pilotage API de la Box ou le mode passerelle Hotspot Administrateur n'est pas activé."
    )


def main():
    admin_flag = _is_os_admin()
    print("=" * 72)
    print(f"  DADEREZO v4.5 · SONDE TERRAIN RÉELLE ACTIVE")
    print(f"  Organisation : {{SITE_NAME}}")
    print(f"  Identifiant  : {{AGENT_ID}}")
    print(f"  Privilèges   : {{'Administrateur OS' if admin_flag else 'Utilisateur standard (observation LAN/WAN)'}}")
    print(f"  Serveur SaaS : {{API_URL}}")
    print("=" * 72)
    known_macs = set()
    first_cycle = True

    try:
        _api_call("POST", "/register", {{"agent_id": AGENT_ID, "nom": f"{{SITE_NAME}} (Sonde Réelle)"}})
        print("[OK] Sonde enregistrée dans votre Espace Privé isolé.")
    except Exception as exc:
        print(f"[INFO] Enregistrement initial : {{exc}}")

    last_scan_ts = 0.0
    while True:
        now = time.time()
        if first_cycle or (now - last_scan_ts >= SCAN_INTERVAL):
            try:
                if first_cycle:
                    print("[SCAN] Premier balayage réel de votre sous-réseau en cours (~3 secondes)...")
                snap = collect_real_snapshot(do_sweep=first_cycle, known_macs=known_macs)
                res = _api_call("POST", "/data", snap)
                up_n = sum(1 for p in snap["probes"] if p["status"] == "up")
                print(
                    f"[EN DIRECT] {{up_n}}/{{len(snap['probes'])}} équipements réels transmis "
                    f"| Passerelle {{snap['gw']}} ({{snap['gw_status']}}) | Internet : {{snap['internet_status']}}"
                )
                first_cycle = False
                last_scan_ts = time.time()
            except KeyboardInterrupt:
                raise
            except Exception as exc:
                print(f"[RECONNEXION] Envoi télémétrie différé : {{exc}}")
                last_scan_ts = time.time()

        try:
            tasks = _api_call("GET", f"/tasks/{{urllib.parse.quote(AGENT_ID)}}?limit=5")
            for t in (tasks if isinstance(tasks, list) else []):
                if t.get("status") != "pending":
                    continue
                tid = t.get("id")
                act = t.get("action", "scan")
                print(f"[ORDRE REÇU] Exécution immédiate de « {{act}} » (#{{tid}})...")
                snap = collect_real_snapshot(do_sweep=(act == "sweep"), known_macs=known_macs)
                _api_call("POST", "/data", snap)
                if act == "apply_internet_policy":
                    res_msg = _apply_local_policy_task(t, snap)
                else:
                    res_msg = f"Action réelle {{act}} exécutée ({{len(snap['probes'])}} équipements relevés)"
                q = urllib.parse.urlencode({{"result": res_msg}})
                _api_call("POST", f"/tasks/{{urllib.parse.quote(AGENT_ID)}}/{{tid}}/ack?{{q}}")
        except KeyboardInterrupt:
            raise
        except Exception:
            pass

        time.sleep(TASK_POLL_SECONDS)


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        print("\\nArrêt propre de la sonde DADEREZO.")
        sys.exit(0)
'''


@app.get("/probe/daderezo_sonde.py")
def download_preconfigured_single_probe(
    request: Request,
    probe_key: Optional[str] = Query(default=None),
    token: Optional[str] = Query(default=None),
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
):
    """Génère en 1 fichier autonome la sonde réelle pré-configurée pour l'Espace Privé de l'utilisateur."""
    init_db()
    if (probe_key or token) and not _legacy_auth_enabled():
        raise HTTPException(status_code=400, detail="Transmettez les identifiants dans les en-têtes, pas dans l'URL.")
    if _legacy_auth_enabled() and (probe_key or token):
        ctx = resolve_tenant_context(x_api_key=probe_key or x_api_key, authorization=("Bearer " + token) if token else authorization)
    else:
        ctx = resolve_tenant_context(x_api_key=x_api_key, authorization=authorization)
    if ctx["mode"] not in ("private_org", "private_probe"):
        raise HTTPException(status_code=401, detail="Espace privé actif requis.")
    user = {"org_slug": ctx["org_slug"], "org_name": ctx["org_name"], "probe_api_key": ctx.get("probe_api_key")}
    if not user["probe_api_key"] and _legacy_auth_enabled():
        old = storage.get_saas_user_by_email(ctx.get("email") or "")
        user["probe_api_key"] = old.get("probe_api_key") if old else None
    if not user["probe_api_key"]:
        raise HTTPException(status_code=401, detail="Clé sonde indisponible.")

    proto = request.headers.get("x-forwarded-proto") or request.url.scheme or "https"
    host = request.headers.get("x-forwarded-host") or request.headers.get("host") or "daderezo-api-nine.vercel.app"
    base_url = f"{proto}://{host}"
    script_text = _build_single_file_probe_script(
        api_url=base_url,
        org_slug=user["org_slug"],
        org_name=user["org_name"],
        probe_key=user["probe_api_key"],
    )
    return PlainTextResponse(
        script_text,
        media_type="text/x-python; charset=utf-8",
        headers={"Content-Disposition": 'attachment; filename="daderezo_sonde.py"'},
    )


@app.get("/download/{filename}")
def download_probe_file(filename: str):
    fpath = ALLOWED_DOWNLOADS.get(filename)
    if fpath is None:
        raise HTTPException(status_code=404, detail="Fichier non autorisé au téléchargement.")
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
class GoogleExchangeRequest(BaseModel):
    code: str = Field(..., min_length=1, max_length=2048)
    verifier: str = Field(..., min_length=43, max_length=128, pattern=r"^[A-Za-z0-9._~-]+$")


def _google_auth_settings() -> tuple:
    url = os.environ.get("SUPABASE_URL", "").strip().rstrip("/")
    key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    parsed = urllib.parse.urlparse(url)
    if parsed.scheme != "https" or not parsed.hostname or not parsed.hostname.endswith(".supabase.co") or parsed.path or parsed.query or parsed.fragment or parsed.username or parsed.password or parsed.port:
        raise HTTPException(status_code=503, detail="Connexion Google non configurée sur ce serveur.")
    if not key:
        raise HTTPException(status_code=503, detail="Connexion Google non configurée sur ce serveur.")
    return url, key


@app.get("/auth/google/config")
def google_auth_config():
    url, _ = _google_auth_settings()
    return {"supabase_url": url}


@app.post("/auth/google/exchange")
def google_auth_exchange(req: GoogleExchangeRequest):
    """Vérifie l'identité Google, sans créer de compte ni accorder d'accès réseau."""
    url, key = _google_auth_settings()
    body = json.dumps({"auth_code": req.code, "code_verifier": req.verifier}).encode("utf-8")
    try:
        exchange = urllib.request.Request(
            url + "/auth/v1/token?grant_type=pkce", data=body, method="POST",
            headers={"apikey": key, "Content-Type": "application/json"},
        )
        with urllib.request.urlopen(exchange, timeout=10) as response:
            result = json.load(response)
        access_token = result.get("access_token")
        if not isinstance(access_token, str) or not access_token:
            raise ValueError("missing access token")
        check = urllib.request.Request(
            url + "/auth/v1/user", headers={"apikey": key, "Authorization": "Bearer " + access_token}
        )
        with urllib.request.urlopen(check, timeout=10) as response:
            user = json.load(response)
        email = (user.get("email") or "").strip().lower()
        if not user.get("id") or not email or not user.get("email_confirmed_at") or any(
            identity.get("provider") != "google" for identity in (user.get("identities") or [])
        ) or not any(
            identity.get("provider") == "google"
            and (identity.get("identity_data") or {}).get("email", "").strip().lower() == email
            and (identity.get("identity_data") or {}).get("email_verified") is True
            for identity in (user.get("identities") or [])
        ):
            raise ValueError("Google identity not verified")
    except (urllib.error.URLError, ValueError, KeyError, TypeError, json.JSONDecodeError):
        raise HTTPException(status_code=401, detail="Impossible de vérifier la connexion Google. Réessayez.")
    return {"verified": True, "email": user["email"], "access_granted": False, "identity_token": access_token}


@app.post("/auth/google/logout")
def google_auth_logout(authorization: Optional[str] = Header(default=None, alias="Authorization")):
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Session Google requise.")
    token = authorization[7:].strip()
    if not token or len(token) > 8192:
        raise HTTPException(status_code=401, detail="Session Google invalide.")
    url, key = _google_auth_settings()
    request = urllib.request.Request(
        url + "/auth/v1/logout?scope=local", data=b"", method="POST",
        headers={"apikey": key, "Authorization": "Bearer " + token},
    )
    try:
        with urllib.request.urlopen(request, timeout=10) as response:
            if response.status not in (200, 204):
                raise ValueError("logout failed")
    except (urllib.error.URLError, ValueError):
        raise HTTPException(status_code=503, detail="Impossible de confirmer la déconnexion auprès de Supabase.")
    return {"status": "ok"}


def require_google_identity(authorization: Optional[str] = Header(default=None, alias="Authorization")) -> dict:
    if not authorization or not authorization.lower().startswith("bearer "):
        raise HTTPException(status_code=401, detail="Connexion Google requise.")
    token = authorization[7:].strip()
    if not token or len(token) > 8192:
        raise HTTPException(status_code=401, detail="Session invalide.")
    url, key = _google_auth_settings()
    try:
        request = urllib.request.Request(url + "/auth/v1/user", headers={"apikey": key, "Authorization": "Bearer " + token})
        with urllib.request.urlopen(request, timeout=10) as response:
            user = json.load(response)
        email = (user.get("email") or "").strip().lower()
        identities = user.get("identities") or []
        google = [x for x in identities if x.get("provider") == "google"]
        if not user.get("id") or not email or not user.get("email_confirmed_at") or not google or len(google) != len(identities):
            raise ValueError("unverified identity")
        # Ne jamais attribuer un droit à partir d'un e-mail non confirmé côté Google.
        if not any((x.get("identity_data") or {}).get("email", "").strip().lower() == email
                   and (x.get("identity_data") or {}).get("email_verified") is True for x in google):
            raise ValueError("unverified Google email")
        return {"id": str(user["id"]), "email": email}
    except (urllib.error.URLError, ValueError, TypeError, KeyError):
        raise HTTPException(status_code=401, detail="Session Google invalide ou expirée.")


def require_platform_admin(identity: dict = Depends(require_google_identity)) -> dict:
    configured = os.environ.get("DADEREZO_SUPERADMIN_EMAIL", "").strip().lower()
    if not configured or not hmac.compare_digest(configured, identity["email"]):
        raise HTTPException(status_code=403, detail="Accès super administrateur interdit.")
    return identity


class PlatformApplicationRequest(BaseModel):
    org_name: str = Field(..., min_length=2, max_length=120)
    contact_name: str = Field(..., min_length=2, max_length=120)
    site_description: str = Field(..., min_length=10, max_length=1000)
    authorization_confirmed: bool


class PlatformDecisionRequest(BaseModel):
    status: str
    payment_status: str
    subscription_end: Optional[str] = None


@app.get("/platform/me")
def platform_me(identity: dict = Depends(require_google_identity)):
    init_db()
    configured = os.environ.get("DADEREZO_SUPERADMIN_EMAIL", "").strip().lower()
    application = storage.find_application(identity["id"])
    visible = dict(application) if application else None
    if visible:
        visible.pop("probe_api_key", None)
    return {"email": identity["email"], "is_admin": bool(configured and hmac.compare_digest(configured, identity["email"])),
            "application": visible, "access_granted": _application_active(application)}


@app.post("/platform/applications")
def create_platform_application(req: PlatformApplicationRequest, identity: dict = Depends(require_google_identity)):
    init_db()
    if not req.authorization_confirmed or min(len(req.org_name.strip()), len(req.contact_name.strip())) < 2 or len(req.site_description.strip()) < 10:
        raise HTTPException(status_code=400, detail="Informations et attestation d'autorisation requises.")
    if storage.find_application(identity["id"]):
        raise HTTPException(status_code=409, detail="Une candidature existe déjà pour ce compte.")
    now = datetime.now(timezone.utc).isoformat()
    app_row = {"id": secrets.token_hex(16), "identity_id": identity["id"], "email": identity["email"],
               "org_name": req.org_name.strip(), "contact_name": req.contact_name.strip(),
               "site_description": req.site_description.strip(), "authorization_confirmed": 1,
               "status": "pending", "payment_status": "unpaid", "created_at": now, "updated_at": now,
               "org_slug": "org-" + secrets.token_hex(12), "probe_api_key": "dzk_" + secrets.token_urlsafe(32), "subscription_end": None}
    try:
        saved = storage.save_application(app_row)
    except Exception:
        # Une contrainte unique protège également contre les soumissions simultanées.
        if storage.find_application(identity["id"]):
            raise HTTPException(status_code=409, detail="Une candidature existe déjà pour ce compte.")
        raise
    saved.pop("probe_api_key", None)
    return {"application": saved, "access_granted": False}


class LegacyClaimRequest(BaseModel):
    legacy_token: str = Field(..., min_length=10, max_length=8192)


@app.post("/platform/claim-legacy")
def claim_legacy_account(req: LegacyClaimRequest, identity: dict = Depends(require_google_identity)):
    # Never accept the predictable development signing fallback for account migration.
    if len(os.environ.get("DADEREZO_AUTH_SECRET", "").strip()) < 32:
        raise HTTPException(status_code=503, detail="Migration indisponible : secret de signature non configuré.")
    claims = _verify_saas_token(req.legacy_token)
    if not claims or (claims.get("email") or "").strip().lower() != identity["email"]:
        raise HTTPException(status_code=401, detail="Ancienne session expirée ou ne correspondant pas au compte Google.")
    legacy_user = storage.get_saas_user_by_email(identity["email"])
    legacy_org = (legacy_user or {}).get("org_slug")
    if not legacy_org or legacy_org == "public-demo" or legacy_org != claims.get("org_slug"):
        raise HTTPException(status_code=403, detail="Ancien espace privé introuvable ou non vérifiable.")
    application = storage.find_application(identity["id"])
    if not application:
        raise HTTPException(status_code=409, detail="Déposez d'abord une candidature pour votre organisation.")
    try:
        linked = storage.claim_legacy_workspace(identity["id"], legacy_org, identity["email"], datetime.now(timezone.utc).isoformat())
    except Exception:
        # Concurrent claims are protected by a unique constraint; do not expose internals.
        raise HTTPException(status_code=409, detail="Rattachement impossible : contactez l'administrateur.")
    if not linked:
        raise HTTPException(status_code=409, detail="Rattachement impossible : candidature déjà traitée, espace déjà associé ou activité existante.")
    linked.pop("probe_api_key", None)
    return {"application": linked, "access_granted": False}


@app.get("/platform/admin/applications")
def admin_list_applications(admin: dict = Depends(require_platform_admin)):
    init_db()
    applications = storage.list_platform_applications()
    for application in applications:
        application.pop("probe_api_key", None)
    return {"applications": applications}


@app.get("/platform/admin/events")
def admin_platform_events(admin: dict = Depends(require_platform_admin)):
    init_db()
    return {"events": storage.list_platform_admin_events()}


@app.post("/platform/admin/applications/{application_id}/decision")
def admin_decide_application(application_id: str, req: PlatformDecisionRequest, admin: dict = Depends(require_platform_admin)):
    if req.status not in {"pending", "approved", "rejected", "suspended"} or req.payment_status not in {"unpaid", "paid", "pilot"}:
        raise HTTPException(status_code=400, detail="Statut invalide.")
    if req.status != "approved" and req.payment_status != "unpaid":
        raise HTTPException(status_code=400, detail="Le paiement ou le pilote exige une candidature approuvée.")
    if req.payment_status == "paid":
        try:
            end = date.fromisoformat(req.subscription_end or "")
            if end < datetime.now(timezone.utc).date():
                raise ValueError("past date")
        except ValueError:
            raise HTTPException(status_code=400, detail="Date de fin d'abonnement valide et future requise (AAAA-MM-JJ).")
        subscription_end = end.isoformat()
    else:
        subscription_end = None
    init_db()
    result = storage.decide_application(application_id, req.status, req.payment_status, admin["email"], datetime.now(timezone.utc).isoformat(), subscription_end)
    if not result:
        raise HTTPException(status_code=404, detail="Candidature introuvable.")
    active = _application_active(result)
    result.pop("probe_api_key", None)
    return {"application": result, "access_granted": active}


@app.post("/auth/signup")
def auth_signup(req: SignupRequest):
    if not _legacy_auth_enabled():
        raise HTTPException(status_code=403, detail="Inscription historique désactivée. Connectez-vous avec Google et déposez une candidature.")
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
        org_slug=org_slug,
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
    if not _legacy_auth_enabled():
        raise HTTPException(status_code=403, detail="Connexion historique désactivée. Connectez-vous avec Google.")
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
        u = storage.get_saas_user_by_email(ctx["email"]) if _legacy_auth_enabled() and not ctx.get("probe_api_key") else None
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
                "probe_api_key": ctx.get("probe_api_key") or (u.get("probe_api_key") if u else None),
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
def _check_ingest_tenant(data: AgentData, ctx: dict):
    _ensure_agent_tenant_access(data.agent_id, ctx)


@app.post("/register")
def register_agent(data: AgentData, ctx: dict = Depends(require_write_auth)):
    init_db()
    _check_ingest_tenant(data, ctx)
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
    _check_ingest_tenant(data, ctx)
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
    if ctx["org_slug"] != "public-demo":
        # Séparation stricte en Mode Travail Privé : ne jamais mélanger simulation-bouake avec les vraies sondes
        rows = [r for r in rows if not str(r.get("id", "")).startswith("simulation-")]
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

    raw_inet_status = state.get("internet_status", "unknown")
    is_sim_agent = bool((agent or {}).get("is_simulation") or str(agent_id).startswith("simulation-"))
    eff_inet_status = "cut_by_admin" if not main_box_inet_on else raw_inet_status
    logical_vs_physical_gap = bool((not is_sim_agent) and (not main_box_inet_on) and raw_inet_status == "up")

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
            "physical_wan_status": raw_inet_status,
            "logical_vs_physical_gap": logical_vs_physical_gap,
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
        org_slug=ctx["org_slug"],
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
        org_slug=ctx["org_slug"],
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
        org_slug=ctx["org_slug"],
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
        org_slug=ctx["org_slug"],
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
        org_slug=ctx["org_slug"],
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
    if token and _legacy_auth_enabled():
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
    x_llm_provider: Optional[str] = Header(default=None, alias="X-LLM-Provider"),
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
        llm_provider=x_llm_provider,
        voice_mode=req.voice_mode,
    )


@app.post("/supervisor/llm-check")
def supervisor_llm_check(
    ctx: dict = Depends(require_read_auth),
    x_llm_api_key: Optional[str] = Header(default=None, alias="X-LLM-Api-Key"),
    x_llm_model: Optional[str] = Header(default=None, alias="X-LLM-Model"),
    x_llm_provider: Optional[str] = Header(default=None, alias="X-LLM-Provider"),
):
    return agent_engine.test_llm_connection(
        header_key=x_llm_api_key,
        header_model=x_llm_model,
        header_provider=x_llm_provider,
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
    audit_logs = storage.list_audit_logs(limit=limit, org_slug=ctx["org_slug"])
    return {
        "db_backend": storage.get_backend_mode(),
        "workspace_mode": ctx["mode"],
        "audit_logs": audit_logs,
        "pending_approvals": pending[:15],
    }


@app.get("/supervisor/session/{session_id}")
def supervisor_session_history(
    session_id: str, limit: int = Query(default=12, ge=1, le=50), ctx: dict = Depends(require_read_auth)
):
    init_db()
    return {"session_id": session_id, "turns": storage.get_session_turns(session_id, limit=limit, org_slug=ctx["org_slug"])}


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
            org_slug=ctx["org_slug"],
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
            org_slug=ctx["org_slug"],
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
