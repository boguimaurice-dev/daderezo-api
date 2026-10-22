# DADEREZO SaaS Backend — FastAPI
# Deploiement gratuit sur Render / Fly.io / Hugging Face Spaces
from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
import sqlite3, os, json

app = FastAPI(title="DADEREZO API", version="1.0.0")

# CORS pour Lovable
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

DB = os.path.join(os.path.dirname(__file__), "daderezo_saas.db")

def init_db():
    conn = sqlite3.connect(DB)
    conn.execute("""CREATE TABLE IF NOT EXISTS agents (
        id TEXT PRIMARY KEY, nom TEXT, ip TEXT, mac TEXT,
        last_seen TEXT, status TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS probes (
        id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT,
        ts TEXT, ip TEXT, mac TEXT, status TEXT, type TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS alerts (
        id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT,
        ts TEXT, severity TEXT, message TEXT)""")
    conn.execute("""CREATE TABLE IF NOT EXISTS state (
        agent_id TEXT, key TEXT, value TEXT,
        PRIMARY KEY (agent_id, key))""")
    conn.commit()
    conn.close()

init_db()

class Probe(BaseModel):
    ip: str
    mac: Optional[str] = None
    status: str
    type: str

class AgentData(BaseModel):
    agent_id: str
    nom: str
    ip_local: Optional[str] = None
    mask: Optional[str] = None
    gw: Optional[str] = None
    mac_local: Optional[str] = None
    probes: List[Probe] = []
    alerts: List[dict] = []

@app.get("/")
def root():
    return {"service": "DADEREZO API", "status": "ok", "version": "1.0.0"}

@app.post("/register")
def register_agent(data: AgentData):
    conn = sqlite3.connect(DB)
    conn.execute("""INSERT OR REPLACE INTO agents (id, nom, ip, mac, last_seen, status)
                    VALUES (?,?,?,?,?,?)""",
                 (data.agent_id, data.nom, data.ip_local, data.mac_local,
                  datetime.now(timezone.utc).isoformat(), "online"))
    conn.commit()
    conn.close()
    return {"status": "registered", "agent_id": data.agent_id}

@app.post("/data")
def receive_data(data: AgentData):
    conn = sqlite3.connect(DB)
    now = datetime.now(timezone.utc).isoformat()
    # Update agent
    conn.execute("""INSERT OR REPLACE INTO agents (id, nom, ip, mac, last_seen, status)
                    VALUES (?,?,?,?,?,?)""",
                 (data.agent_id, data.nom, data.ip_local, data.mac_local, now, "online"))
    # Store probes
    for p in data.probes:
        conn.execute("""INSERT INTO probes (agent_id, ts, ip, mac, status, type)
                        VALUES (?,?,?,?,?,?)""",
                     (data.agent_id, now, p.ip, p.mac, p.status, p.type))
    # Store alerts
    for a in data.alerts:
        conn.execute("""INSERT INTO alerts (agent_id, ts, severity, message)
                        VALUES (?,?,?,?)""",
                     (data.agent_id, now, a.get("severity", "info"), a.get("message", "")))
    # Store state
    for key, val in [("ip_local", data.ip_local), ("mask", data.mask),
                     ("gw", data.gw), ("mac_local", data.mac_local)]:
        if val:
            conn.execute("""INSERT OR REPLACE INTO state (agent_id, key, value)
                            VALUES (?,?,?)""", (data.agent_id, key, val))
    conn.commit()
    conn.close()
    return {"status": "ok", "received": len(data.probes)}

@app.get("/agents")
def list_agents():
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute("SELECT * FROM agents").fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/probes/{agent_id}")
def get_probes(agent_id: str, limit: int = 20):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM probes WHERE agent_id=? ORDER BY id DESC LIMIT ?",
        (agent_id, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/alerts/{agent_id}")
def get_alerts(agent_id: str, limit: int = 20):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT * FROM alerts WHERE agent_id=? ORDER BY id DESC LIMIT ?",
        (agent_id, limit)).fetchall()
    conn.close()
    return [dict(r) for r in rows]

@app.get("/state/{agent_id}")
def get_state(agent_id: str):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT key, value FROM state WHERE agent_id=?", (agent_id,)).fetchall()
    conn.close()
    return {r["key"]: r["value"] for r in rows}

@app.get("/dashboard/{agent_id}")
def dashboard(agent_id: str):
    conn = sqlite3.connect(DB)
    conn.row_factory = sqlite3.Row
    agent = conn.execute("SELECT * FROM agents WHERE id=?", (agent_id,)).fetchone()
    probes = conn.execute(
        "SELECT ip, mac, status, type FROM probes WHERE agent_id=? ORDER BY id DESC LIMIT 10",
        (agent_id,)).fetchall()
    alerts = conn.execute(
        "SELECT severity, message FROM alerts WHERE agent_id=? ORDER BY id DESC LIMIT 10",
        (agent_id,)).fetchall()
    state = {r["key"]: r["value"] for r in conn.execute(
        "SELECT key, value FROM state WHERE agent_id=?", (agent_id,)).fetchall()}
    conn.close()
    return {
        "agent": dict(agent) if agent else None,
        "state": state,
        "probes": [dict(p) for p in probes],
        "alerts": [dict(a) for a in alerts],
    }
