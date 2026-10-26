# -*- coding: utf-8 -*-
"""
DADEREZO SaaS Backend & Interface de Supervision Réseau (Lecture seule).

Compatible SQLite (développement / autonome) et PostgreSQL (Render / Cloud via DATABASE_URL).
"""
from contextlib import contextmanager
from datetime import datetime, timezone
import hmac
import os
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
    return [dict(zip(cols, r)) for r in rows]


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
    up_count = sum(1 for d in devices if d["status"] == "up")
    down_count = sum(1 for d in devices if d["status"] != "up")

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
    elif key == "retablissement":
        alerts = [
            AlertInput(severity="retabli", message="Équipement rétabli : Box FAI principale (192.168.8.1)"),
            AlertInput(severity="retabli", message="Accès Internet rétabli (latence WAN 32 ms)"),
        ]
    else:
        raise HTTPException(status_code=400, detail="Scénario inconnu (nominal, intrus, panne_fai, panne_relais, retablissement).")

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


if os.environ.get("VERCEL") or os.environ.get("DADEREZO_SEED_DEMO") == "1":
    try:
        if not list_agents():
            run_demo_scenario("nominal")
    except Exception:
        pass

