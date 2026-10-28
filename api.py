# -*- coding: utf-8 -*-
"""
DADEREZO SaaS Backend & Interface de Supervision Réseau (Lecture seule).

Compatible SQLite (développement / autonome) et PostgreSQL (Render / Cloud via DATABASE_URL).
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hmac
import os
import re
import unicodedata
from typing import Dict, List, Optional, Union

from fastapi import Depends, FastAPI, Header, HTTPException, Query, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse
from pydantic import BaseModel, Field

HERE = os.path.dirname(os.path.abspath(__file__))

RAW_DATABASE_URL = os.environ.get("DATABASE_URL", "").strip()
if RAW_DATABASE_URL.startswith("postgres://"):
    DATABASE_URL = "postgresql://" + RAW_DATABASE_URL[len("postgres://") :]
else:
    DATABASE_URL = RAW_DATABASE_URL

OFFLINE_THRESHOLD_SECONDS = int(os.environ.get("DADEREZO_OFFLINE_SECONDS", "600"))
PROTECT_READ = os.environ.get("DADEREZO_PROTECT_READ", "0") == "1"
ALLOWED_READONLY_TASKS = {"scan", "sweep", "diagnostic", "rapport"}

app = FastAPI(
    title="DADEREZO API",
    description="API de supervision réseau locale en lecture seule — Communauté Sainte Marie de Bouaké",
    version="2.0.0",
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
    explicit = os.environ.get("DADEREZO_DB_PATH", "").strip()
    if explicit:
        return explicit
    default_local = os.path.join(HERE, "daderezo_saas.db")
    if os.access(HERE, os.W_OK):
        return default_local
    return "/tmp/daderezo_saas.db"


if DATABASE_URL:
    import psycopg2

    PH = "%s"

    def _raw_conn():
        conn = psycopg2.connect(DATABASE_URL)
        return conn
else:
    import sqlite3

    PH = "?"

    def _raw_conn():
        conn = sqlite3.connect(get_sqlite_path(), timeout=15)
        return conn


@contextmanager
def db_cursor():
    conn = _raw_conn()
    cur = conn.cursor()
    try:
        yield conn, cur
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    finally:
        cur.close()
        conn.close()


def _ensure_sqlite_column(cur, table: str, column: str, col_def: str) -> None:
    cur.execute(f"PRAGMA table_info({table})")
    existing = {row[1] for row in cur.fetchall()}
    if column not in existing:
        cur.execute(f"ALTER TABLE {table} ADD COLUMN {column} {col_def}")


def init_db() -> None:
    with db_cursor() as (_, c):
        if DATABASE_URL:
            c.execute(
                "CREATE TABLE IF NOT EXISTS agents ("
                "id TEXT PRIMARY KEY, nom TEXT, ip TEXT, mac TEXT, last_seen TEXT, status TEXT)"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS probes ("
                "id SERIAL PRIMARY KEY, agent_id TEXT, ts TEXT, ip TEXT, mac TEXT, "
                "name TEXT, zone TEXT, status TEXT, type TEXT, latency_ms DOUBLE PRECISION)"
            )
            c.execute("ALTER TABLE probes ADD COLUMN IF NOT EXISTS name TEXT")
            c.execute("ALTER TABLE probes ADD COLUMN IF NOT EXISTS zone TEXT")
            c.execute("ALTER TABLE probes ADD COLUMN IF NOT EXISTS latency_ms DOUBLE PRECISION")
            c.execute(
                "CREATE TABLE IF NOT EXISTS devices ("
                "agent_id TEXT, ip TEXT, mac TEXT, name TEXT, zone TEXT, status TEXT, "
                "type TEXT, latency_ms DOUBLE PRECISION, last_seen TEXT, "
                "PRIMARY KEY (agent_id, ip))"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS alerts ("
                "id SERIAL PRIMARY KEY, agent_id TEXT, ts TEXT, severity TEXT, message TEXT)"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS state ("
                "agent_id TEXT, key TEXT, value TEXT, PRIMARY KEY (agent_id, key))"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS tasks ("
                "id SERIAL PRIMARY KEY, agent_id TEXT, action TEXT, status TEXT, "
                "created_at TEXT, completed_at TEXT, result TEXT)"
            )
        else:
            c.execute(
                "CREATE TABLE IF NOT EXISTS agents ("
                "id TEXT PRIMARY KEY, nom TEXT, ip TEXT, mac TEXT, last_seen TEXT, status TEXT)"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS probes ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, ts TEXT, ip TEXT, mac TEXT, "
                "name TEXT, zone TEXT, status TEXT, type TEXT, latency_ms REAL)"
            )
            _ensure_sqlite_column(c, "probes", "name", "TEXT")
            _ensure_sqlite_column(c, "probes", "zone", "TEXT")
            _ensure_sqlite_column(c, "probes", "latency_ms", "REAL")
            c.execute(
                "CREATE TABLE IF NOT EXISTS devices ("
                "agent_id TEXT, ip TEXT, mac TEXT, name TEXT, zone TEXT, status TEXT, "
                "type TEXT, latency_ms REAL, last_seen TEXT, "
                "PRIMARY KEY (agent_id, ip))"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS alerts ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, ts TEXT, severity TEXT, message TEXT)"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS state ("
                "agent_id TEXT, key TEXT, value TEXT, PRIMARY KEY (agent_id, key))"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS tasks ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, action TEXT, status TEXT, "
                "created_at TEXT, completed_at TEXT, result TEXT)"
            )


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
            normalized = last_seen_raw.replace("Z", "+00:00")
            dt = datetime.fromisoformat(normalized)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=timezone.utc)
            seconds_since = max(0, int((datetime.now(timezone.utc) - dt).total_seconds()))
        except ValueError:
            seconds_since = None

    if seconds_since is not None and seconds_since <= OFFLINE_THRESHOLD_SECONDS:
        live_status = "online"
    else:
        live_status = "offline"

    enriched = dict(agent_dict)
    enriched["status"] = live_status
    enriched["seconds_since_seen"] = seconds_since
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
    question: str = Field(..., min_length=1, max_length=1000, description="Question ou consigne écrite/vocale du superviseur")
    agent_id: Optional[str] = Field(default=None, description="Identifiant du site ciblé (ou vide / 'all' pour tous les sites)")
    scope: str = Field(default="site", description="Portée : 'site' (site sélectionné) ou 'global' (tous les sites)")


def _enrich_devices_internet(devices: List[dict], state: dict) -> List[dict]:
    """Calcule pour chaque équipement s'il est connecté au LAN ET s'il dispose d'un accès Internet effectif."""
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
    return {
        "service": "DADEREZO API",
        "status": "ok",
        "mode": "read_only",
        "version": "2.0.0",
        "db": "postgresql" if DATABASE_URL else "sqlite",
        "auth_enabled": bool(get_api_key()),
    }


def _upsert_agent(c, agent_id: str, nom: str, ip: Optional[str], mac: Optional[str], now_iso: str) -> None:
    c.execute(
        f"INSERT INTO agents (id, nom, ip, mac, last_seen, status) "
        f"VALUES ({PH},{PH},{PH},{PH},{PH},{PH}) "
        f"ON CONFLICT (id) DO UPDATE SET "
        f"nom = {PH}, ip = COALESCE({PH}, agents.ip), mac = COALESCE({PH}, agents.mac), "
        f"last_seen = {PH}, status = {PH}",
        (agent_id, nom, ip, mac, now_iso, "online", nom, ip, mac, now_iso, "online"),
    )


def _upsert_state(c, agent_id: str, key: str, val: str) -> None:
    c.execute(
        f"INSERT INTO state (agent_id, key, value) VALUES ({PH},{PH},{PH}) "
        f"ON CONFLICT (agent_id, key) DO UPDATE SET value = {PH}",
        (agent_id, key, val, val),
    )


@app.api_route("/", methods=["GET", "HEAD"])
def root(request: Request):
    accept = request.headers.get("accept", "").lower()
    ui_path = os.path.join(HERE, "DADEREZO.html")
    if "application/json" not in accept and os.path.exists(ui_path):
        with open(ui_path, "r", encoding="utf-8") as f:
            return HTMLResponse(f.read())
    return JSONResponse(_status_payload())


@app.api_route("/health", methods=["GET", "HEAD"])
def health():
    return _status_payload()


@app.api_route("/ui", methods=["GET", "HEAD"], response_class=HTMLResponse)
def supervision_ui():
    ui_path = os.path.join(HERE, "DADEREZO.html")
    if not os.path.exists(ui_path):
        raise HTTPException(status_code=404, detail="Interface DADEREZO.html introuvable")
    with open(ui_path, "r", encoding="utf-8") as f:
        return HTMLResponse(f.read())


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
    with db_cursor() as (_, c):
        _upsert_agent(c, data.agent_id, data.nom, data.ip_local, data.mac_local, now_iso)
    return {"status": "registered", "agent_id": data.agent_id}


@app.post("/data", dependencies=[Depends(require_write_auth)])
def receive_data(data: AgentData):
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    recorded_alerts = 0

    with db_cursor() as (_, c):
        _upsert_agent(c, data.agent_id, data.nom, data.ip_local, data.mac_local, now_iso)

        # Remplacement propre de l'instantané des équipements actifs si un scan complet est transmis
        if data.probes:
            c.execute(f"DELETE FROM devices WHERE agent_id = {PH}", (data.agent_id,))

        seen_ips = set()
        for p in data.probes:
            c.execute(
                f"INSERT INTO probes (agent_id, ts, ip, mac, name, zone, status, type, latency_ms) "
                f"VALUES ({PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH})",
                (data.agent_id, now_iso, p.ip, p.mac, p.name, p.zone, p.status, p.type, p.latency_ms),
            )
            if p.ip not in seen_ips:
                seen_ips.add(p.ip)
                c.execute(
                    f"INSERT INTO devices (agent_id, ip, mac, name, zone, status, type, latency_ms, last_seen) "
                    f"VALUES ({PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH},{PH}) "
                    f"ON CONFLICT (agent_id, ip) DO UPDATE SET "
                    f"mac = {PH}, name = {PH}, zone = {PH}, status = {PH}, "
                    f"type = {PH}, latency_ms = {PH}, last_seen = {PH}",
                    (
                        data.agent_id,
                        p.ip,
                        p.mac,
                        p.name,
                        p.zone,
                        p.status,
                        p.type,
                        p.latency_ms,
                        now_iso,
                        p.mac,
                        p.name,
                        p.zone,
                        p.status,
                        p.type,
                        p.latency_ms,
                        now_iso,
                    ),
                )

        # Déduplication côté serveur contre les ré-envois accidentels
        c.execute(
            f"SELECT severity, message FROM alerts WHERE agent_id = {PH} ORDER BY id DESC LIMIT 20",
            (data.agent_id,),
        )
        recent_alert_keys = {(r[0], r[1]) for r in c.fetchall()}

        for a in data.alerts:
            if isinstance(a, AlertInput):
                sev, msg, alert_ts = a.severity, a.message, a.ts or now_iso
            else:
                sev = str(a.get("severity", "info"))
                msg = str(a.get("message", ""))
                alert_ts = str(a.get("ts") or now_iso)
            if not msg:
                continue
            if (sev, msg) in recent_alert_keys and sev == "nouveau":
                continue
            c.execute(
                f"INSERT INTO alerts (agent_id, ts, severity, message) VALUES ({PH},{PH},{PH},{PH})",
                (data.agent_id, alert_ts, sev, msg),
            )
            recent_alert_keys.add((sev, msg))
            recorded_alerts += 1

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
        for key, val in state_items.items():
            if val is not None:
                _upsert_state(c, data.agent_id, key, val)

        # Récupération des éventuelles tâches de diagnostic lecture seule en attente
        c.execute(
            f"SELECT id, action FROM tasks WHERE agent_id = {PH} AND status = 'pending' ORDER BY id ASC LIMIT 5",
            (data.agent_id,),
        )
        pending_tasks = [{"id": r[0], "action": r[1]} for r in c.fetchall()]

    return {
        "status": "ok",
        "received": len(data.probes),
        "alerts_recorded": recorded_alerts,
        "pending_tasks": pending_tasks,
    }


@app.get("/agents", dependencies=[Depends(require_read_auth)])
def list_agents():
    init_db()
    with db_cursor() as (_, c):
        c.execute("SELECT * FROM agents ORDER BY last_seen DESC")
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
    return [_compute_agent_liveness(dict(zip(cols, r))) for r in rows]


@app.get("/devices/{agent_id}", dependencies=[Depends(require_read_auth)])
def get_devices(agent_id: str):
    init_db()
    with db_cursor() as (_, c):
        c.execute(
            f"SELECT ip, mac, name, zone, status, type, latency_ms, last_seen "
            f"FROM devices WHERE agent_id = {PH} ORDER BY ip ASC",
            (agent_id,),
        )
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
        c.execute(f"SELECT key, value FROM state WHERE agent_id = {PH}", (agent_id,))
        state = {r[0]: r[1] for r in c.fetchall()}
    raw_devices = [dict(zip(cols, r)) for r in rows]
    return _enrich_devices_internet(raw_devices, state)


@app.get("/probes/{agent_id}", dependencies=[Depends(require_read_auth)])
def get_probes(agent_id: str, limit: int = Query(default=20, ge=1, le=500)):
    init_db()
    with db_cursor() as (_, c):
        c.execute(
            f"SELECT * FROM probes WHERE agent_id = {PH} ORDER BY id DESC LIMIT {PH}",
            (agent_id, limit),
        )
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
    return [dict(zip(cols, r)) for r in rows]


@app.get("/alerts/{agent_id}", dependencies=[Depends(require_read_auth)])
def get_alerts(agent_id: str, limit: int = Query(default=20, ge=1, le=500)):
    init_db()
    with db_cursor() as (_, c):
        c.execute(
            f"SELECT * FROM alerts WHERE agent_id = {PH} ORDER BY id DESC LIMIT {PH}",
            (agent_id, limit),
        )
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
    return [dict(zip(cols, r)) for r in rows]


@app.get("/state/{agent_id}", dependencies=[Depends(require_read_auth)])
def get_state(agent_id: str):
    init_db()
    with db_cursor() as (_, c):
        c.execute(f"SELECT key, value FROM state WHERE agent_id = {PH}", (agent_id,))
        rows = c.fetchall()
    return {r[0]: r[1] for r in rows}


@app.get("/dashboard/{agent_id}", dependencies=[Depends(require_read_auth)])
def dashboard(agent_id: str):
    init_db()
    with db_cursor() as (_, c):
        c.execute(f"SELECT * FROM agents WHERE id = {PH}", (agent_id,))
        agent_row = c.fetchone()
        agent_cols = [d[0] for d in c.description] if agent_row else []

        c.execute(
            f"SELECT ip, mac, name, zone, status, type, latency_ms, last_seen "
            f"FROM devices WHERE agent_id = {PH} ORDER BY ip ASC",
            (agent_id,),
        )
        device_rows = c.fetchall()

        # Repli sur `probes` si aucune entrée dans `devices` (compatibilité descendante)
        if not device_rows:
            c.execute(
                f"SELECT ip, mac, name, zone, status, type, latency_ms, ts "
                f"FROM probes WHERE agent_id = {PH} ORDER BY id DESC LIMIT 25",
                (agent_id,),
            )
            raw_probes = c.fetchall()
            dedup = {}
            for r in raw_probes:
                if r[0] not in dedup:
                    dedup[r[0]] = r
            device_rows = list(dedup.values())

        c.execute(
            f"SELECT id, ts, severity, message FROM alerts WHERE agent_id = {PH} ORDER BY id DESC LIMIT {PH}",
            (agent_id, 25),
        )
        alert_rows = c.fetchall()

        c.execute(f"SELECT key, value FROM state WHERE agent_id = {PH}", (agent_id,))
        state_rows = c.fetchall()

    agent = _compute_agent_liveness(dict(zip(agent_cols, agent_row))) if agent_row else None
    devices = [
        {
            "ip": r[0],
            "mac": r[1],
            "name": r[2],
            "zone": r[3],
            "status": r[4],
            "type": r[5],
            "latency_ms": r[6],
            "last_seen": r[7],
        }
        for r in device_rows
    ]
    alerts = [
        {"id": r[0], "ts": r[1], "severity": r[2], "message": r[3]}
        for r in alert_rows
    ]
    state = {r[0]: r[1] for r in state_rows}
    devices = _enrich_devices_internet(devices, state)
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
    with db_cursor() as (_, c):
        c.execute(
            f"INSERT INTO tasks (agent_id, action, status, created_at) VALUES ({PH},{PH},{PH},{PH})",
            (agent_id, action, "pending", now_iso),
        )
    return {"status": "queued", "agent_id": agent_id, "action": action}


@app.get("/tasks/{agent_id}", dependencies=[Depends(require_read_auth)])
def list_diagnostic_tasks(agent_id: str, limit: int = Query(default=10, ge=1, le=100)):
    init_db()
    with db_cursor() as (_, c):
        c.execute(
            f"SELECT id, action, status, created_at, completed_at, result "
            f"FROM tasks WHERE agent_id = {PH} ORDER BY id DESC LIMIT {PH}",
            (agent_id, limit),
        )
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
    return [dict(zip(cols, r)) for r in rows]


@app.post("/tasks/{agent_id}/{task_id}/ack", dependencies=[Depends(require_write_auth)])
def ack_diagnostic_task(agent_id: str, task_id: int, result: str = "OK"):
    init_db()
    now_iso = datetime.now(timezone.utc).isoformat()
    with db_cursor() as (_, c):
        c.execute(
            f"UPDATE tasks SET status = 'done', completed_at = {PH}, result = {PH} "
            f"WHERE id = {PH} AND agent_id = {PH}",
            (now_iso, result[:500], task_id, agent_id),
        )
    return {"status": "acknowledged", "task_id": task_id}


@app.post("/demo/scenario/{scenario}", dependencies=[Depends(require_write_auth)])
def run_demo_scenario(scenario: str):
    """Banc d'essai interactif : injecte un scénario réaliste sur l'agent isolé `simulation-bouake`."""
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
        site_name="Sainte Marie de Bouaké (Banc de test)",
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


def _normalize_fr(text: str) -> str:
    nfkd = unicodedata.normalize("NFKD", text or "")
    stripped = "".join(ch for ch in nfkd if not unicodedata.combining(ch))
    return re.sub(r"\s+", " ", stripped.lower()).strip()


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
    """Vue consolidée multi-sites pour l'Administrateur Superviseur Général."""
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
                "internet_status": s["internet_status"],
                "gw": d["state"].get("gw"),
                "gw_status": d["state"].get("gw_status", "unknown"),
                "summary": s,
                "alerts_count": len(d["alerts"]),
            }
        )
    return {
        "total_sites": len(agents),
        "sites_online": sum(1 for a in agents if a["status"] == "online"),
        "sites_offline": sum(1 for a in agents if a["status"] != "online"),
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
):
    """Console écrite & vocale de l'Administrateur Superviseur Général (100 % lecture seule)."""
    q_raw = req.question.strip()
    q = _normalize_fr(q_raw)

    wants_global = (
        req.scope.strip().lower() == "global"
        or (req.agent_id or "").strip().lower() == "all"
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

    dashboards = _collect_sites_dashboards(req.agent_id, force_global=wants_global)
    if not dashboards:
        msg = (
            "Aucune sonde réseau n'est enregistrée pour le moment. "
            "Démarrez `agent_client.py` sur le réseau local ou activez un scénario du banc de test."
        )
        return {
            "status": "ok",
            "intent": "aucune_sonde",
            "scope": "global" if wants_global else "site",
            "site_label": "Aucun site enregistré",
            "answer": msg,
            "spoken_text": msg,
            "metrics": {
                "sites_count": 0,
                "total_devices": 0,
                "lan_connected": 0,
                "offline": 0,
                "internet_yes": 0,
                "internet_no": 0,
                "lan_only_no_internet": 0,
            },
            "devices": [],
            "with_internet": [],
            "without_internet": [],
            "unknown_devices": [],
            "task_queued": None,
            "refused_write_action": False,
        }

    # Consolidation des équipements, états et alertes sur le périmètre demandé
    all_devices: List[dict] = []
    all_alerts: List[dict] = []
    site_names: List[str] = []
    for d in dashboards:
        ag = d["agent"] or {}
        sname = d["state"].get("site_name") or ag.get("nom") or ag.get("id") or "Site"
        site_names.append(sname)
        for dev in d["devices"]:
            enriched_dev = dict(dev)
            enriched_dev["site_name"] = sname
            enriched_dev["agent_id"] = ag.get("id", "")
            all_devices.append(enriched_dev)
        for al in d["alerts"]:
            al_copy = dict(al)
            al_copy["site_name"] = sname
            all_alerts.append(al_copy)

    scope_label = (
        f"Tous les sites ({len(dashboards)} sonde(s))"
        if len(dashboards) > 1
        else site_names[0]
    )

    total_dev = len(all_devices)
    lan_up_devs = [d for d in all_devices if d.get("status") == "up"]
    offline_devs = [d for d in all_devices if d.get("status") != "up"]
    inet_yes_devs = [d for d in all_devices if d.get("internet_access") in ("oui", "degrade")]
    inet_no_devs = [d for d in all_devices if d.get("internet_access") not in ("oui", "degrade")]
    lan_only_no_inet_devs = [
        d for d in all_devices if d.get("status") == "up" and d.get("internet_access") == "non"
    ]
    unknown_devs = [
        d for d in all_devices if "inconnu" in (d.get("name") or "").lower()
    ]

    metrics = {
        "sites_count": len(dashboards),
        "total_devices": total_dev,
        "lan_connected": len(lan_up_devs),
        "offline": len(offline_devs),
        "internet_yes": len(inet_yes_devs),
        "internet_no": len(inet_no_devs),
        "lan_only_no_internet": len(lan_only_no_inet_devs),
        "unknown_count": len(unknown_devs),
    }

    # 1. Garde-fou strict : refus de toute commande destructive / d'écriture sur les équipements
    write_patterns = (
        r"\b(redemarr\w*|reboot\w*|bloqu\w*|banni\w*|desactiv\w*|reinitialis\w*|reset\w*|"
        r"modifi\w*|etein\w*|ferm\w*\s+le\s+port|coup\w*\s+le\s+wifi|chang\w*\s+le\s+mot\s+de\s+passe)\b"
    )
    if re.search(write_patterns, q):
        answer = (
            f"⛔ Action d'écriture refusée (Charte de sécurité DADEREZO — mode 100 % lecture seule).\n"
            f"En tant qu'agent de supervision non intrusif sur « {scope_label} », je ne redémarre aucun routeur, "
            f"ne bloque aucune adresse MAC et ne modifie aucune configuration réseau à distance.\n\n"
            f"État observé actuellement : {len(lan_up_devs)}/{total_dev} appareil(s) connecté(s) au réseau local, "
            f"dont {len(inet_yes_devs)} avec accès Internet actif et {len(inet_no_devs)} sans accès Internet."
        )
        spoken = (
            f"Action refusée par sécurité. DADEREZO fonctionne exclusivement en lecture seule et ne modifie aucun routeur. "
            f"Actuellement sur {scope_label}, {len(lan_up_devs)} appareils sur {total_dev} sont connectés au réseau local, "
            f"et {len(inet_yes_devs)} ont accès à Internet."
        )
        return {
            "status": "ok",
            "intent": "refus_ecriture",
            "scope": "global" if len(dashboards) > 1 else "site",
            "site_label": scope_label,
            "answer": answer,
            "spoken_text": spoken,
            "metrics": metrics,
            "devices": all_devices,
            "with_internet": inet_yes_devs,
            "without_internet": inet_no_devs,
            "unknown_devices": unknown_devs,
            "task_queued": None,
            "refused_write_action": True,
        }

    # 2. Ordre de tâche de diagnostic en lecture seule (scan, balayage, diagnostic, rapport)
    task_queued = None
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
    if any(t in q for t in task_triggers):
        action = "scan"
        if "rapport" in q:
            action = "rapport"
        elif "balayage" in q or "sweep" in q:
            action = "sweep"
        elif "diagnostic" in q:
            action = "diagnostic"

        expected_key = get_api_key()
        provided_key = _extract_token(x_api_key, authorization)
        can_write = (not expected_key) or (bool(provided_key) and hmac.compare_digest(provided_key, expected_key))

        if can_write:
            now_iso = datetime.now(timezone.utc).isoformat()
            queued_targets = []
            with db_cursor() as (_, c):
                for d in dashboards:
                    aid = (d["agent"] or {}).get("id")
                    if aid:
                        c.execute(
                            f"INSERT INTO tasks (agent_id, action, status, created_at) VALUES ({PH},{PH},{PH},{PH})",
                            (aid, action, "pending", now_iso),
                        )
                        queued_targets.append(aid)
            task_queued = {"action": action, "targets": queued_targets, "status": "queued"}
        else:
            task_queued = {"action": action, "targets": [], "status": "auth_required"}

    # Helpers de formatage lisible
    def _fmt_dev_list(devs: List[dict], include_reason: bool = False) -> str:
        if not devs:
            return "Aucun"
        items = []
        for d in devs[:10]:
            label = f"{d.get('name') or 'Poste'} ({d.get('ip')})"
            if len(dashboards) > 1 and d.get("site_name"):
                label += f" [{d['site_name']}]"
            if include_reason and d.get("internet_reason"):
                label += f" — {d['internet_reason']}"
            items.append(f"• {label}")
        if len(devs) > 10:
            items.append(f"• … et {len(devs) - 10} autre(s) équipement(s)")
        return "\n".join(items)

    # 3. Détection de l'intention principale
    asks_intrus = any(w in q for w in ("intrus", "inconnu", "suspect", "autoris", "mac", "visiteur", "securite"))
    asks_alerts = any(w in q for w in ("alerte", "incident", "historique", "journal", "evenement"))
    asks_outage = any(
        w in q for w in ("panne", "coupure", "fai", "passerelle", "routeur", "relais", "latence", "lent", "pourquoi")
    )
    asks_inventory_or_inet = any(
        w in q
        for w in (
            "combien",
            "nombre",
            "appareil",
            "poste",
            "equipement",
            "connect",
            "internet",
            "acces",
            "en ligne",
            "hors ligne",
            "inventaire",
            "lesquels",
            "qui a",
            "n'ont pas",
            "sans internet",
        )
    )

    lines: List[str] = []
    spoken_parts: List[str] = []
    intent = "bilan_superviseur"

    if task_queued:
        intent = f"tache_{task_queued['action']}"
        if task_queued["status"] == "queued":
            t_list = ", ".join(task_queued["targets"])
            lines.append(
                f"✅ Tâche lecture seule « {task_queued['action']} » programmée pour la sonde : {t_list}."
            )
            spoken_parts.append(
                f"Tâche de diagnostic {task_queued['action']} programmée en lecture seule."
            )
        else:
            lines.append(
                "🔒 Programmation de tâche protégée : renseignez la clé X-API-Key dans Configuration pour envoyer un ordre actif à la sonde."
            )
            spoken_parts.append("Une clé API est requise pour programmer une tâche distante, voici néanmoins l'état en direct.")

    if asks_inventory_or_inet or (not asks_intrus and not asks_alerts and not asks_outage):
        if intent == "bilan_superviseur" and asks_inventory_or_inet:
            intent = "inventaire_internet"

        lines.append(f"📊 Synthèse Superviseur Général — {scope_label} :")
        lines.append(f"• Appareils répertoriés au total : {total_dev}")
        lines.append(
            f"• Connectés au réseau local (LAN actif) : {len(lan_up_devs)} sur {total_dev}"
            + (f" ({len(offline_devs)} hors ligne)" if offline_devs else " (100 % en ligne)")
        )
        lines.append(f"• Ayant accès à Internet (WAN actif) : {len(inet_yes_devs)} appareil(s)")
        if lan_only_no_inet_devs and offline_devs:
            lines.append(
                f"• Sans accès à Internet : {len(inet_no_devs)} appareil(s) "
                f"(dont {len(lan_only_no_inet_devs)} connecté(s) au LAN mais privé(s) d'Internet, "
                f"et {len(offline_devs)} hors ligne)"
            )
        elif lan_only_no_inet_devs:
            lines.append(
                f"• Sans accès à Internet : {len(inet_no_devs)} appareil(s) "
                f"(tous connectés au réseau local mais sans sortie Internet)"
            )
        elif offline_devs:
            lines.append(
                f"• Sans accès à Internet : {len(inet_no_devs)} appareil(s) (équipements hors ligne sur le LAN)"
            )
        else:
            lines.append("• Sans accès à Internet : 0 appareil (tous les postes connectés disposent d'Internet)")

        lines.append("\n✅ Appareils AVEC accès Internet (" + str(len(inet_yes_devs)) + ") :\n" + _fmt_dev_list(inet_yes_devs))
        if inet_no_devs:
            lines.append(
                "\n⚠️ Appareils SANS accès Internet (" + str(len(inet_no_devs)) + ") :\n"
                + _fmt_dev_list(inet_no_devs, include_reason=True)
            )

        spoken_parts.append(
            f"Sur {scope_label}, on compte {total_dev} appareils répertoriés. "
            f"{len(lan_up_devs)} appareils sont actuellement connectés au réseau local, "
            f"dont {len(inet_yes_devs)} ont accès à Internet et {len(inet_no_devs)} n'ont pas accès à Internet."
        )
        if lan_only_no_inet_devs:
            spoken_parts.append(
                f"Attention : {len(lan_only_no_inet_devs)} appareil connecté au réseau local est privé de sortie Internet."
                if len(lan_only_no_inet_devs) == 1
                else f"Attention : {len(lan_only_no_inet_devs)} appareils connectés au réseau local sont privés de sortie Internet."
            )

    if asks_outage:
        if intent == "bilan_superviseur":
            intent = "diagnostic_panne"
        for d in dashboards:
            st = d["state"]
            sname = st.get("site_name") or (d["agent"] or {}).get("nom") or "Site"
            gw = st.get("gw") or "passerelle"
            gw_st = st.get("gw_status", "unknown")
            gw_lat = st.get("gw_latency_ms")
            inet_st = st.get("internet_status", "unknown")
            wan_lat = st.get("wan_latency_ms")

            if gw_st == "up" and inet_st == "down":
                diag = (
                    f"Diagnostic {sname} : la passerelle locale ({gw}) répond normalement "
                    f"({gw_lat or '?'} ms), mais la sortie Internet est coupée. "
                    f"Il s'agit d'une panne FAI en amont et non d'une panne du réseau interne."
                )
            elif gw_st == "down":
                diag = (
                    f"Diagnostic {sname} : la passerelle principale ({gw}) est injoignable. "
                    f"Vérifiez l'alimentation électrique et le câblage du routeur principal."
                )
            elif offline_devs:
                down_names = ", ".join(f"{x.get('name') or x.get('ip')}" for x in offline_devs[:4])
                diag = (
                    f"Diagnostic {sname} : l'accès FAI est actif ({wan_lat or '?'} ms) et la passerelle ({gw}) répond, "
                    f"mais {len(offline_devs)} équipement(s) local/locaux ne répondent plus : {down_names}."
                )
            else:
                diag = (
                    f"Diagnostic {sname} : aucune panne détectée. Passerelle ({gw}) active "
                    f"({gw_lat or '1'} ms) et sortie Internet opérationnelle ({wan_lat or '32'} ms)."
                )
            lines.append("\n🩺 " + diag)
            if not spoken_parts or intent == "diagnostic_panne":
                spoken_parts.append(diag)

    if asks_intrus:
        if intent == "bilan_superviseur":
            intent = "securite_intrus"
        if unknown_devs:
            u_desc = ", ".join(f"{u.get('ip')} (MAC {u.get('mac') or 'n/d'})" for u in unknown_devs)
            lines.append(
                f"\n🕵️ Sécurité MAC : {len(unknown_devs)} appareil(s) non répertorié(s) détecté(s) sur le LAN : {u_desc}."
            )
            spoken_parts.append(
                f"Alerte sécurité : {len(unknown_devs)} appareil inconnu détecté sur le réseau local, adresse {unknown_devs[0].get('ip')}."
            )
        else:
            lines.append("\n🛡️ Sécurité MAC : aucun appareil inconnu ou non autorisé détecté sur le réseau.")
            spoken_parts.append("Aucun appareil inconnu n'est détecté sur le réseau.")

    if asks_alerts:
        if intent == "bilan_superviseur":
            intent = "alertes"
        if all_alerts:
            top_alerts = "\n".join(
                f"• [{(a.get('severity') or 'info').upper()}] {a.get('message')}"
                for a in all_alerts[:5]
            )
            lines.append(f"\n🔔 Dernières alertes enregistrées ({len(all_alerts)} au total) :\n{top_alerts}")
            spoken_parts.append(
                f"Le journal contient {len(all_alerts)} événements. Dernier événement : {all_alerts[0].get('message')}."
            )
        else:
            lines.append("\n🔔 Journal d'alertes : aucune alerte active.")
            spoken_parts.append("Aucune alerte active dans le journal.")

    answer_text = "\n".join(lines).strip()
    spoken_summary = " ".join(spoken_parts).strip()

    return {
        "status": "ok",
        "intent": intent,
        "scope": "global" if len(dashboards) > 1 else "site",
        "site_label": scope_label,
        "answer": answer_text,
        "spoken_text": spoken_summary,
        "metrics": metrics,
        "devices": all_devices,
        "with_internet": inet_yes_devs,
        "without_internet": inet_no_devs,
        "unknown_devices": unknown_devs,
        "task_queued": task_queued,
        "refused_write_action": False,
    }


if os.environ.get("VERCEL") or os.environ.get("DADEREZO_SEED_DEMO") == "1":
    try:
        if not list_agents():
            run_demo_scenario("nominal")
    except Exception:
        pass

