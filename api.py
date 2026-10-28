# -*- coding: utf-8 -*-
"""
DADEREZO v3.0 — Système Multi-Agents de Supervision Réseau (100 % Lecture Seule).

Persistance unifiée : Supabase PostgreSQL (HTTPS PostgREST), PostgreSQL direct, ou SQLite.
Architecture Multi-Agents : SENTINEL-SEC · TOPO-SCAN · DIAG-NET · OPS-DISPATCH (HITL).
"""
from datetime import datetime, timezone
import hmac
import os
from typing import Dict, List, Optional, Tuple, Union

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse
from pydantic import BaseModel, Field

import agent_engine
import storage

HERE = os.path.dirname(os.path.abspath(__file__))

OFFLINE_THRESHOLD_SECONDS = int(os.environ.get("DADEREZO_OFFLINE_SECONDS", "600"))
PROTECT_READ = os.environ.get("DADEREZO_PROTECT_READ", "0") == "1"
ALLOWED_READONLY_TASKS = {"scan", "sweep", "diagnostic", "rapport"}

app = FastAPI(
    title="DADEREZO Multi-Agent API",
    description="Système multi-agents de supervision réseau en lecture seule — Communauté Sainte Marie de Bouaké",
    version="3.0.0",
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


def get_sqlite_path() -> str:
    return storage.get_sqlite_path()


def init_db() -> None:
    storage.init_db()


init_db()


def _extract_token(x_api_key: Optional[str], authorization: Optional[str]) -> str:
    if x_api_key:
        return x_api_key.strip()
    if authorization and authorization.lower().startswith("bearer "):
        return authorization[7:].strip()
    return ""


def require_write_auth(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> None:
    expected = get_api_key()
    if not expected:
        return
    provided = _extract_token(x_api_key, authorization)
    if not provided or not hmac.compare_digest(provided, expected):
        raise HTTPException(status_code=401, detail="Clé API invalide ou manquante (en-tête X-API-Key requis).")


def require_read_auth(
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
) -> None:
    if not PROTECT_READ:
        return
    require_write_auth(x_api_key=x_api_key, authorization=authorization)


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

    live_status = "online" if (seconds_since is not None and seconds_since <= OFFLINE_THRESHOLD_SECONDS) else "offline"
    enriched = dict(agent_dict)
    enriched["status"] = live_status
    enriched["seconds_since_seen"] = seconds_since
    enriched["is_simulation"] = str(agent_dict.get("id", "")).startswith("simulation-")
    return enriched


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
    action: str = Field(default="scan", description="Action lecture seule : scan, sweep, diagnostic ou rapport")


class SupervisorAskRequest(BaseModel):
    question: str = Field(..., min_length=1, max_length=1500)
    agent_id: Optional[str] = Field(default=None)
    scope: str = Field(default="site")
    session_id: Optional[str] = Field(default="default-supervisor")


class HumanApprovalDecision(BaseModel):
    decision: str = Field(..., description="'approve' ou 'reject'")


def _enrich_devices_internet(devices: List[dict], state: dict) -> List[dict]:
    gw = state.get("gw") or ""
    gw_dev = next((d for d in devices if d.get("ip") == gw), None)
    gw_status = state.get("gw_status") or (gw_dev.get("status") if gw_dev else "unknown")
    inet_status = state.get("internet_status") or "unknown"

    enriched: List[dict] = []
    for d in devices:
        item = dict(d)
        is_lan_up = item.get("status") == "up"
        dev_type = (item.get("type") or "host").lower()
        dev_name = item.get("name") or ""
        is_lan_only_policy = dev_type in ("local_only", "printer_lan") or "(lan seul)" in dev_name.lower()

        item["lan_connected"] = is_lan_up
        if not is_lan_up:
            item["internet_access"] = "non"
            item["internet_reason"] = "Hors ligne sur le réseau local (LAN)"
        elif is_lan_only_policy:
            item["internet_access"] = "non"
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
            item["internet_reason"] = "Connecté au LAN avec accès Internet actif"
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
        "mode": "read_only",
        "version": "3.0.0",
        "architecture": "multi_agent_z",
        "agents_pipeline": ["SENTINEL-SEC", "TOPO-SCAN", "DIAG-NET", "OPS-DISPATCH"],
        "db": storage.get_backend_mode(),
        "llm_configured": has_llm,
        "auth_enabled": bool(get_api_key()),
    }


ALLOWED_DOWNLOADS = {"agent_client.py", "collector.py", "devices.json", "make_dashboard.py"}


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


@app.post("/register", dependencies=[Depends(require_write_auth)])
def register_agent(data: AgentData):
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    storage.upsert_agent(data.agent_id, data.nom, data.ip_local, data.mac_local, now_iso)
    return {"status": "registered", "agent_id": data.agent_id}


@app.post("/data", dependencies=[Depends(require_write_auth)])
def receive_data(data: AgentData):
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
    )

    return {
        "status": "ok",
        "received": len(data.probes),
        "alerts_recorded": recorded_alerts,
        "pending_tasks": pending_tasks,
    }


@app.get("/agents", dependencies=[Depends(require_read_auth)])
def list_agents():
    init_db()
    rows = storage.list_agents_raw()
    # Prioriser toujours les vraies sondes terrain avant le banc de simulation
    enriched = [_compute_agent_liveness(r) for r in rows]
    enriched.sort(key=lambda a: (1 if a.get("is_simulation") else 0, 0 if a.get("status") == "online" else 1))
    return enriched


@app.get("/devices/{agent_id}", dependencies=[Depends(require_read_auth)])
def get_devices(agent_id: str):
    init_db()
    raw_devices = storage.get_devices_raw(agent_id)
    state = storage.get_state_raw(agent_id)
    return _enrich_devices_internet(raw_devices, state)


@app.get("/probes/{agent_id}", dependencies=[Depends(require_read_auth)])
def get_probes(agent_id: str, limit: int = Query(default=20, ge=1, le=500)):
    init_db()
    return storage.get_probes_raw(agent_id, limit=limit)


@app.get("/alerts/{agent_id}", dependencies=[Depends(require_read_auth)])
def get_alerts(agent_id: str, limit: int = Query(default=20, ge=1, le=500)):
    init_db()
    return storage.get_alerts_raw(agent_id, limit=limit)


@app.get("/state/{agent_id}", dependencies=[Depends(require_read_auth)])
def get_state(agent_id: str):
    init_db()
    return storage.get_state_raw(agent_id)


@app.get("/dashboard/{agent_id}", dependencies=[Depends(require_read_auth)])
def dashboard(agent_id: str):
    init_db()
    agent_raw = storage.get_agent_raw(agent_id)
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
    state = storage.get_state_raw(agent_id)
    devices = _enrich_devices_internet(raw_devices, state)

    up_count = sum(1 for d in devices if d["status"] == "up")
    down_count = sum(1 for d in devices if d["status"] != "up")
    with_inet = sum(1 for d in devices if d.get("internet_access") in ("oui", "degrade"))
    without_inet = len(devices) - with_inet
    lan_only_no_inet = sum(1 for d in devices if d["status"] == "up" and d.get("internet_access") == "non")

    return {
        "agent": agent,
        "state": state,
        "probes": devices,
        "devices": devices,
        "alerts": alerts,
        "db_backend": storage.get_backend_mode(),
        "summary": {
            "total_devices": len(devices),
            "devices_up": up_count,
            "devices_down": down_count,
            "devices_with_internet": with_inet,
            "devices_without_internet": without_inet,
            "devices_lan_only_no_internet": lan_only_no_inet,
            "internet_status": state.get("internet_status", "unknown"),
        },
    }


@app.post("/tasks/{agent_id}", dependencies=[Depends(require_write_auth)])
def create_diagnostic_task(agent_id: str, req: DiagnosticTaskRequest):
    action = req.action.strip().lower()
    if action not in ALLOWED_READONLY_TASKS:
        raise HTTPException(
            status_code=400,
            detail=f"Action refusée (mode lecture seule). Actions autorisées : {sorted(ALLOWED_READONLY_TASKS)}",
        )
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    storage.create_task_row(agent_id, action, now_iso)
    return {"status": "queued", "agent_id": agent_id, "action": action}


@app.get("/tasks/{agent_id}", dependencies=[Depends(require_read_auth)])
def list_diagnostic_tasks(agent_id: str, limit: int = Query(default=10, ge=1, le=100)):
    init_db()
    return storage.list_tasks_raw(agent_id, limit=limit)


@app.post("/tasks/{agent_id}/{task_id}/ack", dependencies=[Depends(require_write_auth)])
def ack_diagnostic_task(agent_id: str, task_id: int, result: str = "OK"):
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    storage.ack_task_row(agent_id, task_id, result, now_iso)
    return {"status": "acknowledged", "task_id": task_id}


@app.post("/demo/scenario/{scenario}", dependencies=[Depends(require_write_auth)])
def run_demo_scenario(scenario: str):
    """Banc d'essai interactif sur l'agent isolé `simulation-bouake`."""
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
    res = receive_data(payload)
    return {"status": "ok", "agent_id": "simulation-bouake", "scenario": key, "result": res}


def _collect_sites_dashboards(target_agent_id: Optional[str], force_global: bool) -> List[dict]:
    agents = list_agents()
    if not agents:
        return []
    if force_global or (target_agent_id and target_agent_id.lower() == "all"):
        return [dashboard(a["id"]) for a in agents]
    chosen_id = target_agent_id if any(a["id"] == target_agent_id for a in agents) else agents[0]["id"]
    return [dashboard(chosen_id)]


@app.get("/supervisor/overview", dependencies=[Depends(require_read_auth)])
def supervisor_overview():
    agents = list_agents()
    sites = []
    tot_dev = tot_up = tot_down = tot_inet_yes = tot_inet_no = tot_lan_only = tot_alerts = 0
    for a in agents:
        d = dashboard(a["id"])
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
                "gw": d["state"].get("gw"),
                "gw_status": d["state"].get("gw_status", "unknown"),
                "summary": s,
                "alerts_count": len(d["alerts"]),
            }
        )
    return {
        "db_backend": storage.get_backend_mode(),
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


@app.post("/supervisor/ask", dependencies=[Depends(require_read_auth)])
def supervisor_ask(
    req: SupervisorAskRequest,
    x_api_key: Optional[str] = Header(default=None, alias="X-API-Key"),
    authorization: Optional[str] = Header(default=None, alias="Authorization"),
    x_llm_api_key: Optional[str] = Header(default=None, alias="X-LLM-Api-Key"),
    x_llm_model: Optional[str] = Header(default=None, alias="X-LLM-Model"),
):
    init_db()
    expected = get_api_key()
    provided = _extract_token(x_api_key, authorization)
    can_write = (not expected) or (bool(provided) and hmac.compare_digest(provided, expected))

    return agent_engine.run_multi_agent_mission(
        question_raw=req.question,
        target_agent_id=req.agent_id,
        scope=req.scope,
        session_id=req.session_id or "default-supervisor",
        can_write=can_write,
        fetch_dashboards_fn=_collect_sites_dashboards,
        llm_api_key=x_llm_api_key,
        llm_model=x_llm_model,
    )


@app.get("/supervisor/audit", dependencies=[Depends(require_read_auth)])
def supervisor_audit(limit: int = Query(default=25, ge=1, le=100)):
    init_db()
    return {
        "db_backend": storage.get_backend_mode(),
        "audit_logs": storage.list_audit_logs(limit=limit),
        "pending_approvals": storage.list_human_approvals(status="pending", limit=15),
    }


@app.get("/supervisor/session/{session_id}", dependencies=[Depends(require_read_auth)])
def supervisor_session_history(session_id: str, limit: int = Query(default=12, ge=1, le=50)):
    init_db()
    return {"session_id": session_id, "turns": storage.get_session_turns(session_id, limit=limit)}


@app.post("/supervisor/approve/{approval_id}", dependencies=[Depends(require_write_auth)])
def supervisor_decide_approval(approval_id: int, body: HumanApprovalDecision):
    init_db()
    dec = body.decision.strip().lower()
    if dec not in ("approve", "reject"):
        raise HTTPException(status_code=400, detail="Décision invalide ('approve' ou 'reject').")
    now_iso = datetime.now(timezone.utc).isoformat()
    resolved = storage.resolve_human_approval(approval_id, dec, now_iso)
    if not resolved:
        raise HTTPException(status_code=404, detail="Demande d'approbation introuvable.")

    queued_task = None
    if dec == "approve":
        aid = resolved.get("agent_id") or "sainte-marie-bouake"
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
            f"Validation humaine #{approval_id} acceptée -> tâche '{act}' envoyée à '{aid}'.",
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
            f"Validation humaine #{approval_id} refusée par le Superviseur Général.",
        )

    return {"status": "ok", "approval": resolved, "task_queued": queued_task}


if os.environ.get("VERCEL") or os.environ.get("DADEREZO_SEED_DEMO") == "1":
    try:
        if not list_agents():
            run_demo_scenario("nominal")
    except Exception:
        pass
