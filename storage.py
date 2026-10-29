# -*- coding: utf-8 -*-
"""
DADEREZO v4.0 — Couche de persistance unifiée :
Supabase PostgreSQL 17 + Supabase Storage (HTTPS), PostgreSQL direct, ou SQLite.

Tables gérées :
  agents, probes, devices, alerts, state, tasks,
  agent_sessions, agent_audit_logs, human_approvals,
  saas_users, internet_policies, box_configs, shared_media.
"""
from contextlib import contextmanager
import base64
import json
import os
import sqlite3
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Dict, List, Optional, Tuple

HERE = os.path.dirname(os.path.abspath(__file__))
MEDIA_BUCKET = "daderezo-media"


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


class _SupabaseRest:
    def __init__(self, url: str, key: str) -> None:
        self.root = url.rstrip("/")
        self.base = self.root + "/rest/v1"
        self.storage_base = self.root + "/storage/v1"
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

    def put_object(self, object_key: str, raw_bytes: bytes, content_type: str) -> bool:
        encoded = "/".join(urllib.parse.quote(seg) for seg in object_key.split("/"))
        url = f"{self.storage_base}/object/{MEDIA_BUCKET}/{encoded}"
        headers = {
            "apikey": self.key,
            "Authorization": f"Bearer {self.key}",
            "Content-Type": content_type or "application/octet-stream",
            "x-upsert": "true",
        }
        req = urllib.request.Request(url, data=raw_bytes, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return 200 <= resp.status < 300
        except Exception:
            return False

    def get_object(self, object_key: str) -> Optional[bytes]:
        encoded = "/".join(urllib.parse.quote(seg) for seg in object_key.split("/"))
        url = f"{self.storage_base}/object/{MEDIA_BUCKET}/{encoded}"
        headers = {"apikey": self.key, "Authorization": f"Bearer {self.key}"}
        req = urllib.request.Request(url, headers=headers, method="GET")
        try:
            with urllib.request.urlopen(req, timeout=20) as resp:
                return resp.read()
        except Exception:
            return None

    def delete_object(self, object_key: str) -> None:
        encoded = "/".join(urllib.parse.quote(seg) for seg in object_key.split("/"))
        url = f"{self.storage_base}/object/{MEDIA_BUCKET}/{encoded}"
        headers = {"apikey": self.key, "Authorization": f"Bearer {self.key}"}
        req = urllib.request.Request(url, headers=headers, method="DELETE")
        try:
            with urllib.request.urlopen(req, timeout=10):
                pass
        except Exception:
            pass


def _sb() -> _SupabaseRest:
    return _SupabaseRest(
        os.environ["SUPABASE_URL"].strip(),
        os.environ["SUPABASE_SERVICE_ROLE_KEY"].strip(),
    )


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
        return

    with _sql_cursor() as (_, c, _):
        is_pg = mode == "postgresql"
        serial_pk = "SERIAL PRIMARY KEY" if is_pg else "INTEGER PRIMARY KEY AUTOINCREMENT"
        float_t = "DOUBLE PRECISION" if is_pg else "REAL"
        bool_true = "BOOLEAN DEFAULT TRUE" if is_pg else "INTEGER DEFAULT 1"

        c.execute(
            "CREATE TABLE IF NOT EXISTS agents ("
            "id TEXT PRIMARY KEY, nom TEXT, ip TEXT, mac TEXT, last_seen TEXT, status TEXT, "
            "org_slug TEXT DEFAULT 'public-demo')"
        )
        c.execute(
            f"CREATE TABLE IF NOT EXISTS probes ("
            f"id {serial_pk}, agent_id TEXT, ts TEXT, ip TEXT, mac TEXT, "
            f"name TEXT, zone TEXT, status TEXT, type TEXT, latency_ms {float_t})"
        )
        c.execute(
            f"CREATE TABLE IF NOT EXISTS devices ("
            f"agent_id TEXT, ip TEXT, mac TEXT, name TEXT, zone TEXT, status TEXT, "
            f"type TEXT, latency_ms {float_t}, last_seen TEXT, PRIMARY KEY (agent_id, ip))"
        )
        c.execute(
            f"CREATE TABLE IF NOT EXISTS alerts ("
            f"id {serial_pk}, agent_id TEXT, ts TEXT, severity TEXT, message TEXT)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS state ("
            "agent_id TEXT, key TEXT, value TEXT, PRIMARY KEY (agent_id, key))"
        )
        c.execute(
            f"CREATE TABLE IF NOT EXISTS tasks ("
            f"id {serial_pk}, agent_id TEXT, action TEXT, status TEXT, "
            f"created_at TEXT, completed_at TEXT, result TEXT, payload_json TEXT DEFAULT '{{}}')"
        )
        c.execute(
            f"CREATE TABLE IF NOT EXISTS agent_sessions ("
            f"id {serial_pk}, session_id TEXT, ts TEXT, role TEXT, content TEXT, "
            f"agent_id TEXT, metadata_json TEXT)"
        )
        c.execute(
            f"CREATE TABLE IF NOT EXISTS agent_audit_logs ("
            f"id {serial_pk}, ts TEXT, session_id TEXT, agent_name TEXT, "
            f"action_type TEXT, tool_name TEXT, status TEXT, duration_ms INTEGER, details TEXT)"
        )
        c.execute(
            f"CREATE TABLE IF NOT EXISTS human_approvals ("
            f"id {serial_pk}, ts TEXT, session_id TEXT, agent_id TEXT, "
            f"action TEXT, reason TEXT, status TEXT, decided_at TEXT)"
        )
        c.execute(
            f"CREATE TABLE IF NOT EXISTS saas_users ("
            f"id {serial_pk}, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, "
            f"full_name TEXT, org_slug TEXT NOT NULL, org_name TEXT NOT NULL, "
            f"probe_api_key TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL)"
        )
        c.execute(
            f"CREATE TABLE IF NOT EXISTS internet_policies ("
            f"id {serial_pk}, agent_id TEXT NOT NULL, scope_type TEXT NOT NULL, "
            f"target_value TEXT NOT NULL, internet_enabled {bool_true}, "
            f"schedule_json TEXT DEFAULT '{{}}', reason TEXT, updated_by TEXT, updated_at TEXT NOT NULL, "
            f"UNIQUE(agent_id, scope_type, target_value))"
        )
        c.execute(
            f"CREATE TABLE IF NOT EXISTS box_configs ("
            f"id {serial_pk}, agent_id TEXT NOT NULL, box_ip TEXT NOT NULL, box_name TEXT, "
            f"box_role TEXT DEFAULT 'gateway', driver TEXT DEFAULT 'auto', wifi_enabled {bool_true}, "
            f"wifi_ssid TEXT DEFAULT 'DADEREZO-LAN', wifi_channel TEXT DEFAULT 'auto', "
            f"wifi_band TEXT DEFAULT '2.4GHz + 5GHz', dns_primary TEXT DEFAULT '1.1.1.1', "
            f"dns_secondary TEXT DEFAULT '8.8.8.8', qos_profile TEXT DEFAULT 'equilibre', "
            f"bandwidth_limit_mbps INTEGER DEFAULT 0, mtu INTEGER DEFAULT 1492, "
            f"health_score INTEGER DEFAULT 92, last_optimized_at TEXT, notes TEXT, "
            f"UNIQUE(agent_id, box_ip))"
        )
        c.execute(
            f"CREATE TABLE IF NOT EXISTS shared_media ("
            f"id {serial_pk}, org_slug TEXT NOT NULL DEFAULT 'public-demo', agent_id TEXT NOT NULL, "
            f"title TEXT NOT NULL, filename TEXT NOT NULL, mime_type TEXT NOT NULL, "
            f"category TEXT NOT NULL DEFAULT 'document', size_bytes INTEGER NOT NULL DEFAULT 0, "
            f"target_zone TEXT DEFAULT 'Toutes les zones', description TEXT, "
            f"storage_mode TEXT NOT NULL DEFAULT 'inline', storage_key TEXT, content_b64 TEXT, "
            f"uploaded_by TEXT DEFAULT 'Superviseur Général', created_at TEXT NOT NULL)"
        )

        if not is_pg:
            _ensure_sqlite_column(c, "agents", "org_slug", "TEXT DEFAULT 'public-demo'")
            _ensure_sqlite_column(c, "tasks", "payload_json", "TEXT DEFAULT '{}'")
            _ensure_sqlite_column(c, "probes", "name", "TEXT")
            _ensure_sqlite_column(c, "probes", "zone", "TEXT")
            _ensure_sqlite_column(c, "probes", "latency_ms", "REAL")


def _as_bool(v: Any) -> bool:
    if isinstance(v, bool):
        return v
    if isinstance(v, (int, float)):
        return bool(v)
    return str(v).strip().lower() in ("1", "true", "t", "yes", "oui")


# ---------------------------------------------------------------------------
# Comptes SaaS Multi-Tenants (`saas_users`)
# ---------------------------------------------------------------------------
def create_saas_user(
    email: str,
    password_hash: str,
    full_name: str,
    org_slug: str,
    org_name: str,
    probe_api_key: str,
    now_iso: str,
) -> dict:
    row = {
        "email": email.lower().strip(),
        "password_hash": password_hash,
        "full_name": full_name.strip(),
        "org_slug": org_slug,
        "org_name": org_name.strip(),
        "probe_api_key": probe_api_key,
        "created_at": now_iso,
    }
    if get_backend_mode() == "supabase":
        res = _sb().request("POST", "saas_users", "", row)
        return res[0] if res else row

    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"INSERT INTO saas_users (email, password_hash, full_name, org_slug, org_name, probe_api_key, created_at) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph})",
            (
                row["email"],
                row["password_hash"],
                row["full_name"],
                row["org_slug"],
                row["org_name"],
                row["probe_api_key"],
                row["created_at"],
            ),
        )
    return get_saas_user_by_email(row["email"]) or row


def get_saas_user_by_email(email: str) -> Optional[dict]:
    em = email.lower().strip()
    if get_backend_mode() == "supabase":
        rows = _sb().request("GET", "saas_users", f"email=eq.{urllib.parse.quote(em)}&limit=1") or []
        return rows[0] if rows else None
    with _sql_cursor() as (_, c, ph):
        c.execute(f"SELECT * FROM saas_users WHERE email = {ph}", (em,))
        row = c.fetchone()
        if not row:
            return None
        cols = [d[0] for d in c.description]
        return dict(zip(cols, row))


def get_saas_user_by_probe_key(probe_key: str) -> Optional[dict]:
    pk = (probe_key or "").strip()
    if not pk:
        return None
    if get_backend_mode() == "supabase":
        rows = _sb().request("GET", "saas_users", f"probe_api_key=eq.{urllib.parse.quote(pk)}&limit=1") or []
        return rows[0] if rows else None
    with _sql_cursor() as (_, c, ph):
        c.execute(f"SELECT * FROM saas_users WHERE probe_api_key = {ph}", (pk,))
        row = c.fetchone()
        if not row:
            return None
        cols = [d[0] for d in c.description]
        return dict(zip(cols, row))


# ---------------------------------------------------------------------------
# Sondes & Télémétrie (`agents`, `devices`, `probes`, `alerts`, `state`, `tasks`)
# ---------------------------------------------------------------------------
def upsert_agent(
    agent_id: str,
    nom: str,
    ip: Optional[str],
    mac: Optional[str],
    now_iso: str,
    org_slug: Optional[str] = None,
) -> None:
    if get_backend_mode() == "supabase":
        sb = _sb()
        existing = sb.request("GET", "agents", f"id=eq.{urllib.parse.quote(agent_id)}&limit=1") or []
        prev = existing[0] if existing else {}
        effective_org = org_slug or prev.get("org_slug") or "public-demo"
        row = {
            "id": agent_id,
            "nom": nom,
            "ip": ip if ip is not None else prev.get("ip"),
            "mac": mac if mac is not None else prev.get("mac"),
            "last_seen": now_iso,
            "status": "online",
            "org_slug": effective_org,
        }
        sb.request("POST", "agents", "on_conflict=id", row, prefer="resolution=merge-duplicates,return=minimal")
        return

    with _sql_cursor() as (_, c, ph):
        eff = org_slug or "public-demo"
        c.execute(
            f"INSERT INTO agents (id, nom, ip, mac, last_seen, status, org_slug) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph}) "
            f"ON CONFLICT (id) DO UPDATE SET "
            f"nom = {ph}, ip = COALESCE({ph}, agents.ip), mac = COALESCE({ph}, agents.mac), "
            f"last_seen = {ph}, status = {ph}, "
            f"org_slug = CASE WHEN {ph} IS NOT NULL THEN {ph} ELSE COALESCE(agents.org_slug, 'public-demo') END",
            (
                agent_id,
                nom,
                ip,
                mac,
                now_iso,
                "online",
                eff,
                nom,
                ip,
                mac,
                now_iso,
                "online",
                org_slug,
                org_slug,
            ),
        )


def list_agents_raw(org_slug: Optional[str] = None) -> List[dict]:
    if get_backend_mode() == "supabase":
        rows = _sb().request("GET", "agents", "order=last_seen.desc") or []
    else:
        with _sql_cursor() as (_, c, _):
            c.execute("SELECT * FROM agents ORDER BY last_seen DESC")
            r_all = c.fetchall()
            cols = [d[0] for d in c.description]
        rows = [dict(zip(cols, r)) for r in r_all]

    if org_slug:
        return [r for r in rows if (r.get("org_slug") or "public-demo") == org_slug]
    # Sans session privée : ne montrer que les agents publics/legacy, jamais les organisations privées d'autres clients
    return [r for r in rows if (r.get("org_slug") or "public-demo") == "public-demo"]


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
    org_slug: Optional[str] = None,
) -> Tuple[int, List[dict]]:
    if get_backend_mode() == "supabase":
        sb = _sb()
        upsert_agent(agent_id, nom, ip_local, mac_local, now_iso, org_slug=org_slug)
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
                f"agent_id=eq.{q_ag}&status=eq.pending&select=id,action,payload_json&order=id.asc&limit=5",
            )
            or []
        )
        return len(new_alert_rows), pending

    upsert_agent(agent_id, nom, ip_local, mac_local, now_iso, org_slug=org_slug)
    recorded_alerts = 0
    with _sql_cursor() as (_, c, ph):
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
            f"SELECT id, action, payload_json FROM tasks WHERE agent_id = {ph} AND status = 'pending' ORDER BY id ASC LIMIT 5",
            (agent_id,),
        )
        pending_tasks = [{"id": r[0], "action": r[1], "payload_json": r[2] or "{}"} for r in c.fetchall()]

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


def create_task_row(agent_id: str, action: str, now_iso: str, payload: Optional[dict] = None) -> dict:
    p_str = json.dumps(payload or {}, ensure_ascii=False)
    if get_backend_mode() == "supabase":
        rows = _sb().request(
            "POST",
            "tasks",
            "",
            {
                "agent_id": agent_id,
                "action": action,
                "status": "pending",
                "created_at": now_iso,
                "payload_json": p_str,
            },
        )
        return rows[0] if rows else {"agent_id": agent_id, "action": action, "status": "pending", "payload_json": p_str}
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"INSERT INTO tasks (agent_id, action, status, created_at, payload_json) VALUES ({ph},{ph},{ph},{ph},{ph})",
            (agent_id, action, "pending", now_iso, p_str),
        )
    return {"agent_id": agent_id, "action": action, "status": "pending", "payload_json": p_str}


def list_tasks_raw(agent_id: str, limit: int = 10) -> List[dict]:
    if get_backend_mode() == "supabase":
        q_ag = urllib.parse.quote(agent_id)
        return (
            _sb().request(
                "GET",
                "tasks",
                f"agent_id=eq.{q_ag}&select=id,action,status,created_at,completed_at,result,payload_json&order=id.desc&limit={int(limit)}",
            )
            or []
        )
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"SELECT id, action, status, created_at, completed_at, result, payload_json "
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
# Contrôle d'Accès Internet Granulaire (`internet_policies`)
# ---------------------------------------------------------------------------
def upsert_internet_policy(
    agent_id: str,
    scope_type: str,
    target_value: str,
    internet_enabled: bool,
    reason: str,
    updated_by: str,
    now_iso: str,
    schedule: Optional[dict] = None,
) -> dict:
    sched_str = json.dumps(schedule or {}, ensure_ascii=False)
    row = {
        "agent_id": agent_id,
        "scope_type": scope_type,
        "target_value": target_value,
        "internet_enabled": bool(internet_enabled),
        "schedule_json": sched_str,
        "reason": reason[:300],
        "updated_by": updated_by[:120],
        "updated_at": now_iso,
    }
    if get_backend_mode() == "supabase":
        res = _sb().request(
            "POST",
            "internet_policies",
            "on_conflict=agent_id,scope_type,target_value",
            row,
            prefer="resolution=merge-duplicates,return=representation",
        )
        return res[0] if res else row

    mode = get_backend_mode()
    db_bool = bool(internet_enabled) if mode == "postgresql" else (1 if internet_enabled else 0)
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"INSERT INTO internet_policies (agent_id, scope_type, target_value, internet_enabled, schedule_json, reason, updated_by, updated_at) "
            f"VALUES ({ph},{ph},{ph},{ph},{ph},{ph},{ph},{ph}) "
            f"ON CONFLICT (agent_id, scope_type, target_value) DO UPDATE SET "
            f"internet_enabled = {ph}, schedule_json = {ph}, reason = {ph}, updated_by = {ph}, updated_at = {ph}",
            (
                agent_id,
                scope_type,
                target_value,
                db_bool,
                sched_str,
                row["reason"],
                row["updated_by"],
                now_iso,
                db_bool,
                sched_str,
                row["reason"],
                row["updated_by"],
                now_iso,
            ),
        )
    return row


def list_internet_policies(agent_id: str) -> List[dict]:
    if get_backend_mode() == "supabase":
        q_ag = urllib.parse.quote(agent_id)
        rows = _sb().request("GET", "internet_policies", f"agent_id=eq.{q_ag}&order=id.asc") or []
    else:
        with _sql_cursor() as (_, c, ph):
            c.execute(f"SELECT * FROM internet_policies WHERE agent_id = {ph} ORDER BY id ASC", (agent_id,))
            r_all = c.fetchall()
            cols = [d[0] for d in c.description]
        rows = [dict(zip(cols, r)) for r in r_all]
    for r in rows:
        r["internet_enabled"] = _as_bool(r.get("internet_enabled", True))
    return rows


def delete_internet_policy(agent_id: str, scope_type: str, target_value: str) -> None:
    if get_backend_mode() == "supabase":
        q = (
            f"agent_id=eq.{urllib.parse.quote(agent_id)}"
            f"&scope_type=eq.{urllib.parse.quote(scope_type)}"
            f"&target_value=eq.{urllib.parse.quote(target_value)}"
        )
        _sb().request("DELETE", "internet_policies", q, prefer="return=minimal")
        return
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"DELETE FROM internet_policies WHERE agent_id = {ph} AND scope_type = {ph} AND target_value = {ph}",
            (agent_id, scope_type, target_value),
        )


# ---------------------------------------------------------------------------
# Configuration & Optimisation des Box (`box_configs`)
# ---------------------------------------------------------------------------
def upsert_box_config(agent_id: str, box: dict) -> dict:
    row = {
        "agent_id": agent_id,
        "box_ip": str(box.get("box_ip", "")).strip(),
        "box_name": str(box.get("box_name") or "Box Réseau")[:120],
        "box_role": str(box.get("box_role") or "gateway")[:40],
        "driver": str(box.get("driver") or "auto")[:40],
        "wifi_enabled": _as_bool(box.get("wifi_enabled", True)),
        "wifi_ssid": str(box.get("wifi_ssid") or "DADEREZO-LAN")[:80],
        "wifi_channel": str(box.get("wifi_channel") or "auto")[:20],
        "wifi_band": str(box.get("wifi_band") or "2.4GHz + 5GHz")[:40],
        "dns_primary": str(box.get("dns_primary") or "1.1.1.1")[:45],
        "dns_secondary": str(box.get("dns_secondary") or "8.8.8.8")[:45],
        "qos_profile": str(box.get("qos_profile") or "equilibre")[:40],
        "bandwidth_limit_mbps": int(box.get("bandwidth_limit_mbps") or 0),
        "mtu": int(box.get("mtu") or 1492),
        "health_score": int(box.get("health_score") or 92),
        "last_optimized_at": box.get("last_optimized_at"),
        "notes": str(box.get("notes") or "")[:400],
    }
    if get_backend_mode() == "supabase":
        res = _sb().request(
            "POST",
            "box_configs",
            "on_conflict=agent_id,box_ip",
            row,
            prefer="resolution=merge-duplicates,return=representation",
        )
        return res[0] if res else row

    mode = get_backend_mode()
    db_wifi = row["wifi_enabled"] if mode == "postgresql" else (1 if row["wifi_enabled"] else 0)
    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"INSERT INTO box_configs ("
            f"agent_id, box_ip, box_name, box_role, driver, wifi_enabled, wifi_ssid, wifi_channel, "
            f"wifi_band, dns_primary, dns_secondary, qos_profile, bandwidth_limit_mbps, mtu, "
            f"health_score, last_optimized_at, notes"
            f") VALUES ({','.join([ph]*17)}) "
            f"ON CONFLICT (agent_id, box_ip) DO UPDATE SET "
            f"box_name={ph}, box_role={ph}, driver={ph}, wifi_enabled={ph}, wifi_ssid={ph}, "
            f"wifi_channel={ph}, wifi_band={ph}, dns_primary={ph}, dns_secondary={ph}, "
            f"qos_profile={ph}, bandwidth_limit_mbps={ph}, mtu={ph}, health_score={ph}, "
            f"last_optimized_at={ph}, notes={ph}",
            (
                agent_id,
                row["box_ip"],
                row["box_name"],
                row["box_role"],
                row["driver"],
                db_wifi,
                row["wifi_ssid"],
                row["wifi_channel"],
                row["wifi_band"],
                row["dns_primary"],
                row["dns_secondary"],
                row["qos_profile"],
                row["bandwidth_limit_mbps"],
                row["mtu"],
                row["health_score"],
                row["last_optimized_at"],
                row["notes"],
                row["box_name"],
                row["box_role"],
                row["driver"],
                db_wifi,
                row["wifi_ssid"],
                row["wifi_channel"],
                row["wifi_band"],
                row["dns_primary"],
                row["dns_secondary"],
                row["qos_profile"],
                row["bandwidth_limit_mbps"],
                row["mtu"],
                row["health_score"],
                row["last_optimized_at"],
                row["notes"],
            ),
        )
    return row


def list_box_configs(agent_id: str) -> List[dict]:
    if get_backend_mode() == "supabase":
        q_ag = urllib.parse.quote(agent_id)
        rows = _sb().request("GET", "box_configs", f"agent_id=eq.{q_ag}&order=box_ip.asc") or []
    else:
        with _sql_cursor() as (_, c, ph):
            c.execute(f"SELECT * FROM box_configs WHERE agent_id = {ph} ORDER BY box_ip ASC", (agent_id,))
            r_all = c.fetchall()
            cols = [d[0] for d in c.description]
        rows = [dict(zip(cols, r)) for r in r_all]
    for r in rows:
        r["wifi_enabled"] = _as_bool(r.get("wifi_enabled", True))
    return rows


# ---------------------------------------------------------------------------
# Hub de Partage de Fichiers & Données Multimédias (`shared_media`)
# ---------------------------------------------------------------------------
def create_shared_media(
    org_slug: str,
    agent_id: str,
    title: str,
    filename: str,
    mime_type: str,
    category: str,
    raw_bytes: bytes,
    target_zone: str,
    description: str,
    uploaded_by: str,
    now_iso: str,
) -> dict:
    size_bytes = len(raw_bytes)
    storage_mode = "inline"
    storage_key = None
    content_b64: Optional[str] = None

    safe_name = "".join(ch if ch.isalnum() or ch in "._-" else "_" for ch in filename)[:90] or "fichier.bin"
    if get_backend_mode() == "supabase":
        sb = _sb()
        obj_key = f"{org_slug}/{agent_id}/{now_iso[:19].replace(':','-')}_{safe_name}"
        if sb.put_object(obj_key, raw_bytes, mime_type):
            storage_mode = "supabase_storage"
            storage_key = obj_key
        else:
            content_b64 = base64.b64encode(raw_bytes).decode("ascii")
    else:
        content_b64 = base64.b64encode(raw_bytes).decode("ascii")

    row = {
        "org_slug": org_slug,
        "agent_id": agent_id,
        "title": title[:160],
        "filename": safe_name,
        "mime_type": mime_type[:100],
        "category": category[:30],
        "size_bytes": size_bytes,
        "target_zone": (target_zone or "Toutes les zones")[:60],
        "description": (description or "")[:400],
        "storage_mode": storage_mode,
        "storage_key": storage_key,
        "content_b64": content_b64,
        "uploaded_by": (uploaded_by or "Superviseur Général")[:100],
        "created_at": now_iso,
    }

    if get_backend_mode() == "supabase":
        res = _sb().request("POST", "shared_media", "", row)
        saved = res[0] if res else row
        saved.pop("content_b64", None)
        return saved

    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"INSERT INTO shared_media ("
            f"org_slug, agent_id, title, filename, mime_type, category, size_bytes, "
            f"target_zone, description, storage_mode, storage_key, content_b64, uploaded_by, created_at"
            f") VALUES ({','.join([ph]*14)})",
            (
                row["org_slug"],
                row["agent_id"],
                row["title"],
                row["filename"],
                row["mime_type"],
                row["category"],
                row["size_bytes"],
                row["target_zone"],
                row["description"],
                row["storage_mode"],
                row["storage_key"],
                row["content_b64"],
                row["uploaded_by"],
                row["created_at"],
            ),
        )
        new_id = c.lastrowid if hasattr(c, "lastrowid") and c.lastrowid else None
        if new_id is None:
            c.execute("SELECT MAX(id) FROM shared_media")
            r = c.fetchone()
            new_id = r[0] if r else 1
    out = dict(row)
    out["id"] = new_id
    out.pop("content_b64", None)
    return out


def list_shared_media(agent_id: str, org_slug: str = "public-demo", limit: int = 50) -> List[dict]:
    cols_sel = "id,org_slug,agent_id,title,filename,mime_type,category,size_bytes,target_zone,description,storage_mode,uploaded_by,created_at"
    if get_backend_mode() == "supabase":
        q = (
            f"agent_id=eq.{urllib.parse.quote(agent_id)}"
            f"&org_slug=eq.{urllib.parse.quote(org_slug)}"
            f"&select={cols_sel}&order=id.desc&limit={int(limit)}"
        )
        return _sb().request("GET", "shared_media", q) or []

    with _sql_cursor() as (_, c, ph):
        c.execute(
            f"SELECT {cols_sel} FROM shared_media WHERE agent_id = {ph} AND org_slug = {ph} ORDER BY id DESC LIMIT {ph}",
            (agent_id, org_slug, limit),
        )
        rows = c.fetchall()
        cols = [d[0] for d in c.description]
    return [dict(zip(cols, r)) for r in rows]


def get_shared_media_payload(media_id: int) -> Optional[Tuple[dict, bytes]]:
    if get_backend_mode() == "supabase":
        sb = _sb()
        rows = sb.request("GET", "shared_media", f"id=eq.{int(media_id)}&limit=1") or []
        if not rows:
            return None
        meta = rows[0]
        if meta.get("storage_mode") == "supabase_storage" and meta.get("storage_key"):
            raw = sb.get_object(meta["storage_key"])
            if raw is not None:
                return meta, raw
        if meta.get("content_b64"):
            return meta, base64.b64decode(meta["content_b64"])
        return None

    with _sql_cursor() as (_, c, ph):
        c.execute(f"SELECT * FROM shared_media WHERE id = {ph}", (media_id,))
        row = c.fetchone()
        if not row:
            return None
        cols = [d[0] for d in c.description]
        meta = dict(zip(cols, row))
        raw = base64.b64decode(meta.get("content_b64") or "")
        return meta, raw


def delete_shared_media(media_id: int, org_slug: str) -> bool:
    if get_backend_mode() == "supabase":
        sb = _sb()
        rows = sb.request("GET", "shared_media", f"id=eq.{int(media_id)}&limit=1") or []
        if not rows or rows[0].get("org_slug") != org_slug:
            return False
        if rows[0].get("storage_mode") == "supabase_storage" and rows[0].get("storage_key"):
            sb.delete_object(rows[0]["storage_key"])
        sb.request("DELETE", "shared_media", f"id=eq.{int(media_id)}", prefer="return=minimal")
        return True

    with _sql_cursor() as (_, c, ph):
        c.execute(f"SELECT org_slug FROM shared_media WHERE id = {ph}", (media_id,))
        r = c.fetchone()
        if not r or r[0] != org_slug:
            return False
        c.execute(f"DELETE FROM shared_media WHERE id = {ph}", (media_id,))
        return True


# ---------------------------------------------------------------------------
# Mémoire de session, Journal d'Audit & Validation Humaine
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
