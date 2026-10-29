# -*- coding: utf-8 -*-
"""
DADEREZO — Couche de persistance unifiée (Supabase PostgreSQL HTTPS, PostgreSQL direct, ou SQLite).

Priorité de sélection :
1. `DADEREZO_DB_PATH` explicite -> SQLite (utilisé notamment par les tests isolés et le mode local).
2. `SUPABASE_URL` + `SUPABASE_SERVICE_ROLE_KEY` -> Supabase PostgREST HTTPS (idéal Vercel Serverless IPv4/IPv6).
3. `DATABASE_URL` -> PostgreSQL direct via `psycopg2`.
4. Repli automatique -> SQLite (`daderezo_saas.db` ou `/tmp/daderezo_saas.db` en environnement lecture seule).
"""
from contextlib import contextmanager
import json
import os
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))


def get_sqlite_path() -> str:
    explicit = os.environ.get("DADEREZO_DB_PATH", "").strip()
    if explicit:
        return explicit
    default_local = os.path.join(HERE, "daderezo_saas.db")
    if os.access(HERE, os.W_OK):
        return default_local
    return "/tmp/daderezo_saas.db"


def get_backend_mode() -> str:
    if os.environ.get("DADEREZO_DB_PATH", "").strip():
        return "sqlite"
    sb_url = os.environ.get("SUPABASE_URL", "").strip()
    sb_key = os.environ.get("SUPABASE_SERVICE_ROLE_KEY", "").strip()
    if sb_url and sb_key:
        return "supabase"
    if os.environ.get("DATABASE_URL", "").strip():
        return "postgresql"
    return "sqlite"


def _normalize_pg_url(raw: str) -> str:
    raw = raw.strip()
    if raw.startswith("postgres://"):
        return "postgresql://" + raw[len("postgres://") :]
    return raw


# ---------------------------------------------------------------------------
# Client HTTPS léger pour Supabase PostgREST (zéro dépendance binaire)
# ---------------------------------------------------------------------------
class _SupabaseRest:
    def __init__(self, url: str, key: str) -> None:
        self.base = url.rstrip("/") + "/rest/v1"
        self.key = key

    def request(
        self,
        method: str,
        table: str,
        query: str = "",
        body: Any = None,
        prefer: str = "return=representation",
    ) -> Any:
        url = f"{self.base}/{table}"
        if query:
            url = f"{url}?{query}"
        headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Accept": "application/json",
        }
        if prefer:
            headers["Prefer"] = prefer
        data = None
        if body is not None:
            headers["Content-Type"] = "application/json"
            data = json.dumps(body).encode("utf-8")

        req = urllib.request.Request(url, data=data, headers=headers, method=method)
        with urllib.request.urlopen(req, timeout=15) as resp:
            raw = resp.read().decode("utf-8").strip()
            return json.loads(raw) if raw else None


def _sb() -> _SupabaseRest:
    return _SupabaseRest(
        os.environ["SUPABASE_URL"].strip(),
        os.environ["SUPABASE_SERVICE_ROLE_KEY"].strip(),
    )


# ---------------------------------------------------------------------------
# Connexion SQL (SQLite ou PostgreSQL direct)
# ---------------------------------------------------------------------------
@contextmanager
def _sql_cursor():
    mode = get_backend_mode()
    if mode == "postgresql":
        import psycopg2

        conn = psycopg2.connect(_normalize_pg_url(os.environ["DATABASE_URL"]))
        ph = "%s"
    else:
        conn = sqlite3.connect(get_sqlite_path(), timeout=15)
        ph = "?"

    cur = conn.cursor()
    try:
        yield conn, cur, ph
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
    mode = get_backend_mode()
    if mode == "supabase":
        # Le schéma PostgreSQL est provisionné sur Supabase via migration SQL dédiée
        return

    with _sql_cursor() as (_, c, _):
        if mode == "postgresql":
            c.execute(
                "CREATE TABLE IF NOT EXISTS agents ("
                "id TEXT PRIMARY KEY, nom TEXT, ip TEXT, mac TEXT, last_seen TEXT, status TEXT)"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS probes ("
                "id SERIAL PRIMARY KEY, agent_id TEXT, ts TEXT, ip TEXT, mac TEXT, "
                "name TEXT, zone TEXT, status TEXT, type TEXT, latency_ms DOUBLE PRECISION)"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS devices ("
                "agent_id TEXT, ip TEXT, mac TEXT, name TEXT, zone TEXT, status TEXT, "
                "type TEXT, latency_ms DOUBLE PRECISION, last_seen TEXT, PRIMARY KEY (agent_id, ip))"
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
            c.execute(
                "CREATE TABLE IF NOT EXISTS agent_sessions ("
                "id SERIAL PRIMARY KEY, session_id TEXT, ts TEXT, role TEXT, content TEXT, "
                "agent_id TEXT, metadata_json TEXT)"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS agent_audit_logs ("
                "id SERIAL PRIMARY KEY, ts TEXT, session_id TEXT, agent_name TEXT, "
                "action_type TEXT, tool_name TEXT, status TEXT, duration_ms INTEGER, details TEXT)"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS human_approvals ("
                "id SERIAL PRIMARY KEY, ts TEXT, session_id TEXT, agent_id TEXT, "
                "action TEXT, reason TEXT, status TEXT, decided_at TEXT)"
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
                "type TEXT, latency_ms REAL, last_seen TEXT, PRIMARY KEY (agent_id, ip))"
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
            c.execute(
                "CREATE TABLE IF NOT EXISTS agent_sessions ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, session_id TEXT, ts TEXT, role TEXT, "
                "content TEXT, agent_id TEXT, metadata_json TEXT)"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS agent_audit_logs ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, session_id TEXT, agent_name TEXT, "
                "action_type TEXT, tool_name TEXT, status TEXT, duration_ms INTEGER, details TEXT)"
            )
            c.execute(
                "CREATE TABLE IF NOT EXISTS human_approvals ("
                "id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT, session_id TEXT, agent_id TEXT, "
                "action TEXT, reason TEXT, status TEXT, decided_at TEXT)"
            )


# ---------------------------------------------------------------------------
# Opérations métier unifiées
# ---------------------------------------------------------------------------
def upsert_agent(agent_id: str, nom: str, ip: Optional[str], mac: Optional[str], now_iso: str) -> None:
    if get_backend_mode() == "supabase":
        sb = _sb()
        existing = sb.request("GET", "agents", f"id=eq.{urllib.parse.quote(agent_id)}&limit=1") or []
        prev = existing[0] if existing else {}
        row = {
            "id": agent_id,
            "nom": nom,
            "ip": ip if ip is not None else prev.get("ip"),
            "mac": mac if mac is not None else prev.get("mac"),
            "last_seen": now_iso,
            "status": "online",
        }
        sb.request("POST", "agents", "on_conflict=id", row, prefer="resolution=merge-duplicates,return=minimal")
        return

    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"INSERT INTO agents (id, nom, ip, mac, last_seen, status) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph}) "
            f"ON CONFLICT (id) DO UPDATE SET "
            f"nom = {ph}, ip = COALESCE({ph}, agents.ip), mac = COALESCE({ph}, agents.mac), "
            f"last_seen = {ph}, status = {ph}",
            (agent_id, nom, ip, mac, now_iso, "online", nom, ip, mac, now_iso, "online"),
        )


def list_agents_raw() -> List[dict]:
    if get_backend_mode() == "supabase":
        return _sb().request("GET", "agents", "order=last_seen.desc") or []
    with _sql_cursor() as (_, c, _):
        c.execute("SELECT * FROM agents ORDER BY last_seen DESC")
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
    return [dict(zip(cols, r)) for r in rows]


def get_agent_raw(agent_id: str) -> Optional[dict]:
    if get_backend_mode() == "supabase":
        rows = _sb().request("GET", "agents", f"id=eq.{urllib.parse.quote(agent_id)}&limit=1") or []
        return rows[0] if rows else None
    with _sql_cursor() as (_, c, ph):
        c.execute(f"SELECT * FROM agents WHERE id = {ph}", (agent_id,))
        row = c.fetchone()
        if not row:
            return None
        cols = [d[0] for d in c.description]
        return dict(zip(cols, row))


def ingest_telemetry(
    agent_id: str,
    nom: str,
    ip_local: Optional[str],
    mac_local: Optional[str],
    now_iso: str,
    probes: List[dict],
    alerts: List[Tuple[str, str, str]],
    state_items: Dict[str, Optional[str]],
) -> Tuple[int, List[dict]]:
    """Enregistre en une passe atomique (ou groupée PostgREST) télémétrie, alertes dédupliquées et état."""
    if get_backend_mode() == "supabase":
        sb = _sb()
        upsert_agent(agent_id, nom, ip_local, mac_local, now_iso)
        q_ag = urllib.parse.quote(agent_id)

        if probes:
            sb.request("DELETE", "devices", f"agent_id=eq.{q_ag}", prefer="return=minimal")
            probe_rows = [
                {
                    "agent_id": agent_id,
                    "ts": now_iso,
                    "ip": p["ip"],
                    "mac": p.get("mac"),
                    "name": p.get("name"),
                    "zone": p.get("zone"),
                    "status": p["status"],
                    "type": p.get("type", "host"),
                    "latency_ms": p.get("latency_ms"),
                }
                for p in probes
            ]
            sb.request("POST", "probes", "", probe_rows, prefer="return=minimal")

            dedup_devs: Dict[str, dict] = {}
            for p in probes:
                if p["ip"] not in dedup_devs:
                    dedup_devs[p["ip"]] = {
                        "agent_id": agent_id,
                        "ip": p["ip"],
                        "mac": p.get("mac"),
                        "name": p.get("name"),
                        "zone": p.get("zone"),
                        "status": p["status"],
                        "type": p.get("type", "host"),
                        "latency_ms": p.get("latency_ms"),
                        "last_seen": now_iso,
                    }
            sb.request(
                "POST",
                "devices",
                "on_conflict=agent_id,ip",
                list(dedup_devs.values()),
                prefer="resolution=merge-duplicates,return=minimal",
            )

        recent = (
            sb.request("GET", "alerts", f"agent_id=eq.{q_ag}&select=severity,message&order=id.desc&limit=20")
            or []
        )
        recent_keys = {(r.get("severity"), r.get("message")) for r in recent}
        new_alert_rows = []
        for sev, msg, a_ts in alerts:
            if not msg:
                continue
            if (sev, msg) in recent_keys and sev == "nouveau":
                continue
            new_alert_rows.append({"agent_id": agent_id, "ts": a_ts, "severity": sev, "message": msg})
            recent_keys.add((sev, msg))
        if new_alert_rows:
            sb.request("POST", "alerts", "", new_alert_rows, prefer="return=minimal")

        st_rows = [
            {"agent_id": agent_id, "key": k, "value": str(v)}
            for k, v in state_items.items()
            if v is not None
        ]
        if st_rows:
            sb.request(
                "POST",
                "state",
                "on_conflict=agent_id,key",
                st_rows,
                prefer="resolution=merge-duplicates,return=minimal",
            )

        pending = (
            sb.request(
                "GET",
                "tasks",
                f"agent_id=eq.{q_ag}&status=eq.pending&select=id,action&order=id.asc&limit=5",
            )
            or []
        )
        return len(new_alert_rows), pending

    recorded_alerts = 0
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"INSERT INTO agents (id, nom, ip, mac, last_seen, status) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph}) "
            f"ON CONFLICT (id) DO UPDATE SET "
            f"nom = {ph}, ip = COALESCE({ph}, agents.ip), mac = COALESCE({ph}, agents.mac), "
            f"last_seen = {ph}, status = {ph}",
            (agent_id, nom, ip_local, mac_local, now_iso, "online", nom, ip_local, mac_local, now_iso, "online"),
        )
        if probes:
            c.execute(f"DELETE FROM devices WHERE agent_id = {ph}", (agent_id,))

        seen_ips = set()
        for p in probes:
            c.execute(
                f"INSERT INTO probes (agent_id, ts, ip, mac, name, zone, status, type, latency_ms) "
                f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph})",
                (
                    agent_id,
                    now_iso,
                    p["ip"],
                    p.get("mac"),
                    p.get("name"),
                    p.get("zone"),
                    p["status"],
                    p.get("type", "host"),
                    p.get("latency_ms"),
                ),
            )
            if p["ip"] not in seen_ips:
                seen_ips.add(p["ip"])
                c.execute(
                    f"INSERT INTO devices (agent_id, ip, mac, name, zone, status, type, latency_ms, last_seen) "
                    f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph}) "
                    f"ON CONFLICT (agent_id, ip) DO UPDATE SET "
                    f"mac = {ph}, name = {ph}, zone = {ph}, status = {ph}, "
                    f"type = {ph}, latency_ms = {ph}, last_seen = {ph}",
                    (
                        agent_id,
                        p["ip"],
                        p.get("mac"),
                        p.get("name"),
                        p.get("zone"),
                        p["status"],
                        p.get("type", "host"),
                        p.get("latency_ms"),
                        now_iso,
                        p.get("mac"),
                        p.get("name"),
                        p.get("zone"),
                        p["status"],
                        p.get("type", "host"),
                        p.get("latency_ms"),
                        now_iso,
                    ),
                )

        c.execute(
            f"SELECT severity, message FROM alerts WHERE agent_id = {ph} ORDER BY id DESC LIMIT 20",
            (agent_id,),
        )
        recent_keys = {(r[0], r[1]) for r in c.fetchall()}
        for sev, msg, a_ts in alerts:
            if not msg:
                continue
            if (sev, msg) in recent_keys and sev == "nouveau":
                continue
            c.execute(
                f"INSERT INTO alerts (agent_id, ts, severity, message) VALUES ({ph},{ph},{ph},{ph})",
                (agent_id, a_ts, sev, msg),
            )
            recent_keys.add((sev, msg))
            recorded_alerts += 1

        for key, val in state_items.items():
            if val is not None:
                c.execute(
                    f"INSERT INTO state (agent_id, key, value) VALUES ({ph},{ph},{ph}) "
                    f"ON CONFLICT (agent_id, key) DO UPDATE SET value = {ph}",
                    (agent_id, key, str(val), str(val)),
                )

        c.execute(
            f"SELECT id, action FROM tasks WHERE agent_id = {ph} AND status = 'pending' ORDER BY id ASC LIMIT 5",
            (agent_id,),
        )
        pending_tasks = [{"id": r[0], "action": r[1]} for r in c.fetchall()]

    return recorded_alerts, pending_tasks


def get_devices_raw(agent_id: str) -> List[dict]:
    if get_backend_mode() == "supabase":
        q_ag = urllib.parse.quote(agent_id)
        return (
            _sb().request(
                "GET",
                "devices",
                f"agent_id=eq.{q_ag}&select=ip,mac,name,zone,status,type,latency_ms,last_seen&order=ip.asc",
            )
            or []
        )
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"SELECT ip, mac, name, zone, status, type, latency_ms, last_seen "
            f"FROM devices WHERE agent_id = {ph} ORDER BY ip ASC",
            (agent_id,),
        )
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
    return [dict(zip(cols, r)) for r in rows]


def get_probes_raw(agent_id: str, limit: int = 20) -> List[dict]:
    if get_backend_mode() == "supabase":
        q_ag = urllib.parse.quote(agent_id)
        return _sb().request("GET", "probes", f"agent_id=eq.{q_ag}&order=id.desc&limit={int(limit)}") or []
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"SELECT * FROM probes WHERE agent_id = {ph} ORDER BY id DESC LIMIT {ph}",
            (agent_id, limit),
        )
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
    return [dict(zip(cols, r)) for r in rows]


def get_alerts_raw(agent_id: str, limit: int = 20) -> List[dict]:
    if get_backend_mode() == "supabase":
        q_ag = urllib.parse.quote(agent_id)
        return (
            _sb().request(
                "GET",
                "alerts",
                f"agent_id=eq.{q_ag}&select=id,agent_id,ts,severity,message&order=id.desc&limit={int(limit)}",
            )
            or []
        )
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"SELECT * FROM alerts WHERE agent_id = {ph} ORDER BY id DESC LIMIT {ph}",
            (agent_id, limit),
        )
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
    return [dict(zip(cols, r)) for r in rows]


def get_state_raw(agent_id: str) -> Dict[str, str]:
    if get_backend_mode() == "supabase":
        q_ag = urllib.parse.quote(agent_id)
        rows = _sb().request("GET", "state", f"agent_id=eq.{q_ag}&select=key,value") or []
        return {r["key"]: r["value"] for r in rows}
    with _sql_cursor() as (_, c, ph):
        c.execute(f"SELECT key, value FROM state WHERE agent_id = {ph}", (agent_id,))
        rows = c.fetchall()
    return {r[0]: r[1] for r in rows}


def create_task_row(agent_id: str, action: str, now_iso: str) -> dict:
    if get_backend_mode() == "supabase":
        rows = _sb().request(
            "POST",
            "tasks",
            "",
            {"agent_id": agent_id, "action": action, "status": "pending", "created_at": now_iso},
        )
        return rows[0] if rows else {"agent_id": agent_id, "action": action, "status": "pending"}
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"INSERT INTO tasks (agent_id, action, status, created_at) VALUES ({ph},{ph},{ph},{ph})",
            (agent_id, action, "pending", now_iso),
        )
    return {"agent_id": agent_id, "action": action, "status": "pending"}


def list_tasks_raw(agent_id: str, limit: int = 10) -> List[dict]:
    if get_backend_mode() == "supabase":
        q_ag = urllib.parse.quote(agent_id)
        return (
            _sb().request(
                "GET",
                "tasks",
                f"agent_id=eq.{q_ag}&select=id,action,status,created_at,completed_at,result&order=id.desc&limit={int(limit)}",
            )
            or []
        )
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"SELECT id, action, status, created_at, completed_at, result "
            f"FROM tasks WHERE agent_id = {ph} ORDER BY id DESC LIMIT {ph}",
            (agent_id, limit),
        )
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
    return [dict(zip(cols, r)) for r in rows]


def ack_task_row(agent_id: str, task_id: int, result_msg: str, now_iso: str) -> None:
    if get_backend_mode() == "supabase":
        q_ag = urllib.parse.quote(agent_id)
        _sb().request(
            "PATCH",
            "tasks",
            f"id=eq.{int(task_id)}&agent_id=eq.{q_ag}",
            {"status": "done", "completed_at": now_iso, "result": result_msg[:500]},
            prefer="return=minimal",
        )
        return
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"UPDATE tasks SET status = 'done', completed_at = {ph}, result = {ph} "
            f"WHERE id = {ph} AND agent_id = {ph}",
            (now_iso, result_msg[:500], task_id, agent_id),
        )


# ---------------------------------------------------------------------------
# Mémoire de session, Journal d'Audit Multi-Agents & Validation Humaine (HITL)
# ---------------------------------------------------------------------------
def append_session_turn(
    session_id: str, ts: str, role: str, content: str, agent_id: Optional[str], metadata: Optional[dict] = None
) -> None:
    meta_str = json.dumps(metadata or {}, ensure_ascii=False)
    if get_backend_mode() == "supabase":
        _sb().request(
            "POST",
            "agent_sessions",
            "",
            {
                "session_id": session_id,
                "ts": ts,
                "role": role,
                "content": content[:4000],
                "agent_id": agent_id or "",
                "metadata_json": meta_str,
            },
            prefer="return=minimal",
        )
        return
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"INSERT INTO agent_sessions (session_id, ts, role, content, agent_id, metadata_json) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph})",
            (session_id, ts, role, content[:4000], agent_id or "", meta_str),
        )


def get_session_turns(session_id: str, limit: int = 8) -> List[dict]:
    if not session_id:
        return []
    if get_backend_mode() == "supabase":
        q_sid = urllib.parse.quote(session_id)
        rows = (
            _sb().request(
                "GET",
                "agent_sessions",
                f"session_id=eq.{q_sid}&select=id,ts,role,content,agent_id,metadata_json&order=id.desc&limit={int(limit)}",
            )
            or []
        )
        return list(reversed(rows))
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"SELECT id, ts, role, content, agent_id, metadata_json "
            f"FROM agent_sessions WHERE session_id = {ph} ORDER BY id DESC LIMIT {ph}",
            (session_id, limit),
        )
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
    return list(reversed([dict(zip(cols, r)) for r in rows]))


def record_audit_log(
    ts: str,
    session_id: str,
    agent_name: str,
    action_type: str,
    tool_name: str,
    status: str,
    duration_ms: int,
    details: str,
) -> None:
    if get_backend_mode() == "supabase":
        _sb().request(
            "POST",
            "agent_audit_logs",
            "",
            {
                "ts": ts,
                "session_id": session_id,
                "agent_name": agent_name,
                "action_type": action_type,
                "tool_name": tool_name,
                "status": status,
                "duration_ms": int(duration_ms),
                "details": details[:1000],
            },
            prefer="return=minimal",
        )
        return
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"INSERT INTO agent_audit_logs (ts, session_id, agent_name, action_type, tool_name, status, duration_ms, details) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph})",
            (ts, session_id, agent_name, action_type, tool_name, status, int(duration_ms), details[:1000]),
        )


def list_audit_logs(limit: int = 30) -> List[dict]:
    if get_backend_mode() == "supabase":
        return _sb().request("GET", "agent_audit_logs", f"order=id.desc&limit={int(limit)}") or []
    with _sql_cursor() as (_, c, ph):
        c.execute(f"SELECT * FROM agent_audit_logs ORDER BY id DESC LIMIT {ph}", (limit,))
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
    return [dict(zip(cols, r)) for r in rows]


def create_human_approval(ts: str, session_id: str, agent_id: str, action: str, reason: str) -> dict:
    if get_backend_mode() == "supabase":
        rows = _sb().request(
            "POST",
            "human_approvals",
            "",
            {
                "ts": ts,
                "session_id": session_id,
                "agent_id": agent_id,
                "action": action,
                "reason": reason[:500],
                "status": "pending",
            },
        )
        return rows[0] if rows else {"id": 1, "agent_id": agent_id, "action": action, "status": "pending"}
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"INSERT INTO human_approvals (ts, session_id, agent_id, action, reason, status) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph},'pending')",
            (ts, session_id, agent_id, action, reason[:500]),
        )
        new_id = c.lastrowid if hasattr(c, "lastrowid") and c.lastrowid else None
        if new_id is None:
            c.execute("SELECT MAX(id) FROM human_approvals")
            r = c.fetchone()
            new_id = r[0] if r else 1
    return {
        "id": new_id,
        "ts": ts,
        "session_id": session_id,
        "agent_id": agent_id,
        "action": action,
        "reason": reason[:500],
        "status": "pending",
    }


def list_human_approvals(status: Optional[str] = None, limit: int = 15) -> List[dict]:
    if get_backend_mode() == "supabase":
        q = f"order=id.desc&limit={int(limit)}"
        if status:
            q = f"status=eq.{urllib.parse.quote(status)}&" + q
        return _sb().request("GET", "human_approvals", q) or []
    with _sql_cursor() as (_, c, ph):
        if status:
            c.execute(
                f"SELECT * FROM human_approvals WHERE status = {ph} ORDER BY id DESC LIMIT {ph}",
                (status, limit),
            )
        else:
            c.execute(f"SELECT * FROM human_approvals ORDER BY id DESC LIMIT {ph}", (limit,))
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
    return [dict(zip(cols, r)) for r in rows]


def resolve_human_approval(approval_id: int, decision: str, now_iso: str) -> Optional[dict]:
    new_status = "approved" if decision == "approve" else "rejected"
    if get_backend_mode() == "supabase":
        rows = _sb().request("GET", "human_approvals", f"id=eq.{int(approval_id)}&limit=1") or []
        if not rows:
            return None
        item = rows[0]
        _sb().request(
            "PATCH",
            "human_approvals",
            f"id=eq.{int(approval_id)}",
            {"status": new_status, "decided_at": now_iso},
            prefer="return=minimal",
        )
        item["status"] = new_status
        item["decided_at"] = now_iso
        return item

    with _sql_cursor() as (_, c, ph):
        c.execute(f"SELECT * FROM human_approvals WHERE id = {ph}", (approval_id,))
        row = c.fetchone()
        if not row:
            return None
        cols = [d[0] for d in c.description]
        item = dict(zip(cols, row))
        c.execute(
            f"UPDATE human_approvals SET status = {ph}, decided_at = {ph} WHERE id = {ph}",
            (new_status, now_iso, approval_id),
        )
        item["status"] = new_status
        item["decided_at"] = now_iso
        return item
