# DADEREZO SaaS Backend
from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import List, Optional
from datetime import datetime, timezone
import os

app = FastAPI(title='DADEREZO API', version='1.0.0')
app.add_middleware(CORSMiddleware, allow_origins=['*'], allow_credentials=True, allow_methods=['*'], allow_headers=['*'])

DATABASE_URL = os.environ.get('DATABASE_URL', '')

if DATABASE_URL:
    import psycopg2
    def get_conn():
        c = psycopg2.connect(DATABASE_URL); c.autocommit = True; return c
    PH = '%s'
else:
    import sqlite3
    DB = os.path.join(os.path.dirname(__file__), 'daderezo_saas.db')
    def get_conn():
        c = sqlite3.connect(DB); c.row_factory = sqlite3.Row; return c
    PH = '?'

def init_db():
    conn = get_conn(); c = conn.cursor()
    if DATABASE_URL:
        c.execute('CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, nom TEXT, ip TEXT, mac TEXT, last_seen TEXT, status TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS probes (id SERIAL PRIMARY KEY, agent_id TEXT, ts TEXT, ip TEXT, mac TEXT, status TEXT, type TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS alerts (id SERIAL PRIMARY KEY, agent_id TEXT, ts TEXT, severity TEXT, message TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS state (agent_id TEXT, key TEXT, value TEXT, PRIMARY KEY (agent_id, key))')
    else:
        c.execute('CREATE TABLE IF NOT EXISTS agents (id TEXT PRIMARY KEY, nom TEXT, ip TEXT, mac TEXT, last_seen TEXT, status TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS probes (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, ts TEXT, ip TEXT, mac TEXT, status TEXT, type TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS alerts (id INTEGER PRIMARY KEY AUTOINCREMENT, agent_id TEXT, ts TEXT, severity TEXT, message TEXT)')
        c.execute('CREATE TABLE IF NOT EXISTS state (agent_id TEXT, key TEXT, value TEXT, PRIMARY KEY (agent_id, key))')
    conn.commit(); conn.close()

init_db()

class Probe(BaseModel):
    ip: str; mac: Optional[str] = None; status: str; type: str

class AgentData(BaseModel):
    agent_id: str; nom: str
    ip_local: Optional[str] = None; mask: Optional[str] = None
    gw: Optional[str] = None; mac_local: Optional[str] = None
    probes: List[Probe] = []; alerts: List[dict] = []

@app.get('/')
def root():
    return {'service': 'DADEREZO API', 'status': 'ok', 'version': '1.0.0', 'db': 'postgresql' if DATABASE_URL else 'sqlite'}

@app.post('/register')
def register_agent(data: AgentData):
    conn = get_conn(); c = conn.cursor(); now = datetime.now(timezone.utc).isoformat()
    c.execute(f'INSERT INTO agents (id, nom, ip, mac, last_seen, status) VALUES ({PH},{PH},{PH},{PH},{PH},{PH})', (data.agent_id, data.nom, data.ip_local, data.mac_local, now, 'online'))
    conn.commit(); conn.close()
    return {'status': 'registered', 'agent_id': data.agent_id}

@app.post('/data')
def receive_data(data: AgentData):
    conn = get_conn(); c = conn.cursor(); now = datetime.now(timezone.utc).isoformat()
    if DATABASE_URL:
        c.execute(f'INSERT INTO agents (id, nom, ip, mac, last_seen, status) VALUES ({PH},{PH},{PH},{PH},{PH},{PH}) ON CONFLICT (id) DO UPDATE SET nom={PH}, ip={PH}, mac={PH}, last_seen={PH}, status={PH}', (data.agent_id, data.nom, data.ip_local, data.mac_local, now, 'online', data.nom, data.ip_local, data.mac_local, now, 'online'))
    else:
        c.execute(f'INSERT OR REPLACE INTO agents (id, nom, ip, mac, last_seen, status) VALUES ({PH},{PH},{PH},{PH},{PH},{PH})', (data.agent_id, data.nom, data.ip_local, data.mac_local, now, 'online'))
    for p in data.probes:
        c.execute(f'INSERT INTO probes (agent_id, ts, ip, mac, status, type) VALUES ({PH},{PH},{PH},{PH},{PH},{PH})', (data.agent_id, now, p.ip, p.mac, p.status, p.type))
    for a in data.alerts:
        c.execute(f'INSERT INTO alerts (agent_id, ts, severity, message) VALUES ({PH},{PH},{PH},{PH})', (data.agent_id, now, a.get('severity','info'), a.get('message','')))
    for key, val in [('ip_local', data.ip_local), ('mask', data.mask), ('gw', data.gw), ('mac_local', data.mac_local)]:
        if val:
            if DATABASE_URL:
                c.execute(f'INSERT INTO state (agent_id, key, value) VALUES ({PH},{PH},{PH}) ON CONFLICT (agent_id, key) DO UPDATE SET value={PH}', (data.agent_id, key, val, val))
            else:
                c.execute(f'INSERT OR REPLACE INTO state (agent_id, key, value) VALUES ({PH},{PH},{PH})', (data.agent_id, key, val))
    conn.commit(); conn.close()
    return {'status': 'ok', 'received': len(data.probes)}

@app.get('/agents')
def list_agents():
    conn = get_conn(); c = conn.cursor(); c.execute('SELECT * FROM agents'); rows = c.fetchall(); cols = [d[0] for d in c.description]; conn.close()
    return [dict(zip(cols, r)) for r in rows]

@app.get('/probes/{agent_id}')
def get_probes(agent_id: str, limit: int = 20):
    conn = get_conn(); c = conn.cursor(); c.execute(f'SELECT * FROM probes WHERE agent_id={PH} ORDER BY id DESC LIMIT {PH}', (agent_id, limit)); rows = c.fetchall(); cols = [d[0] for d in c.description]; conn.close()
    return [dict(zip(cols, r)) for r in rows]

@app.get('/alerts/{agent_id}')
def get_alerts(agent_id: str, limit: int = 20):
    conn = get_conn(); c = conn.cursor(); c.execute(f'SELECT * FROM alerts WHERE agent_id={PH} ORDER BY id DESC LIMIT {PH}', (agent_id, limit)); rows = c.fetchall(); cols = [d[0] for d in c.description]; conn.close()
    return [dict(zip(cols, r)) for r in rows]

@app.get('/state/{agent_id}')
def get_state(agent_id: str):
    conn = get_conn(); c = conn.cursor(); c.execute(f'SELECT key, value FROM state WHERE agent_id={PH}', (agent_id,)); rows = c.fetchall(); conn.close()
    return {r[0]: r[1] for r in rows}

@app.get('/dashboard/{agent_id}')
def dashboard(agent_id: str):
    conn = get_conn(); c = conn.cursor()
    c.execute(f'SELECT * FROM agents WHERE id={PH}', (agent_id,)); agent_row = c.fetchone(); agent_cols = [d[0] for d in c.description] if agent_row else []
    c.execute(f'SELECT ip, mac, status, type FROM probes WHERE agent_id={PH} ORDER BY id DESC LIMIT 10', (agent_id,)); probe_rows = c.fetchall()
    c.execute(f'SELECT severity, message FROM alerts WHERE agent_id={PH} ORDER BY id DESC LIMIT 10', (agent_id,)); alert_rows = c.fetchall()
    c.execute(f'SELECT key, value FROM state WHERE agent_id={PH}', (agent_id,)); state_rows = c.fetchall()
    conn.close()
    agent = dict(zip(agent_cols, agent_row)) if agent_row else None
    probes = [{'ip': r[0], 'mac': r[1], 'status': r[2], 'type': r[3]} for r in probe_rows]
    alerts = [{'severity': r[0], 'message': r[1]} for r in alert_rows]
    state = {r[0]: r[1] for r in state_rows}
    return {'agent': agent, 'state': state, 'probes': probes, 'alerts': alerts}
