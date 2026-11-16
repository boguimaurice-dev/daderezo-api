"""Audit isolation, security metadata, retention and limiter regressions."""
from datetime import datetime, timedelta, timezone
from unittest.mock import patch, MagicMock

import pytest
from fastapi.testclient import TestClient

import api
import storage
from audit_context import identity


@pytest.fixture
def db(tmp_path, monkeypatch):
    monkeypatch.setenv("DADEREZO_DB_PATH", str(tmp_path / "audit.db"))
    monkeypatch.setenv("DADEREZO_AUTH_SECRET", "isolated-test-secret")
    monkeypatch.delenv("DADEREZO_API_KEY", raising=False)
    storage.init_db()
    return tmp_path


def write(tenant, details="hello", ts=None):
    marker = identity.set({"org_slug": tenant, "actor": "tester", "request_id": "req-test"})
    try:
        storage.record_audit_log(ts or datetime.now(timezone.utc).isoformat(), "same-session", "TEST", "test", "test", "OK", 1, details)
    finally:
        identity.reset(marker)


def test_tenant_filter_not_text_matching(db):
    write("org-a", "org-b owns this")
    write("org-b", "org-a owns this")
    assert len(storage.list_audit_logs(100, "org-a")) == 1
    assert storage.list_audit_logs(100, "public-demo") == []
    assert storage.list_audit_logs(100, "org-b")[0]["tenant_id"] == "org-b"


def test_credentials_redacted(db):
    write("org-a", "password=supersecret token=dzt_abc123 api_key=dzk_private secret=totp")
    row = storage.list_audit_logs(1, "org-a")[0]
    for secret in ("supersecret", "dzt_abc123", "dzk_private", "totp"):
        assert secret not in row["details"]
    assert row["actor"] == "tester"
    assert row["request_id"] == "req-test"


def test_retention_and_legacy_quarantine(db):
    write("org-a", ts=(datetime.now(timezone.utc)-timedelta(days=91)).isoformat())
    write("org-a")
    with pytest.raises(ValueError):
        storage.purge_audit_logs(30)
    storage.purge_audit_logs(90)
    assert len(storage.list_audit_logs(100, "org-a")) == 1
    # Migration is idempotent.
    storage.init_db()


def test_failed_login_logged_not_public(db):
    client = TestClient(api.app)
    response = client.post("/auth/login", json={"email": "nobody@example.org", "password": "wrong-secret"})
    assert response.status_code == 401
    row = storage.list_audit_logs(1, "system")[0]
    assert row["status"] == "ERROR"
    assert row["request_id"] == response.headers["x-request-id"]
    assert "wrong-secret" not in row["details"]
    assert client.get("/supervisor/audit").json()["audit_logs"] == []


def test_login_logout_scoped(db):
    client = TestClient(api.app)
    payload = {"email": "audit@example.org", "password": "AuditStrong2026!", "full_name": "Audit User", "org_name": "Audit School"}
    signup = client.post("/auth/signup", json=payload)
    assert signup.status_code == 200
    tenant = signup.json()["user"]["org_slug"]
    assert client.post("/auth/login", json={"email": payload["email"], "password": payload["password"]}).status_code == 200
    assert client.post("/auth/logout").status_code == 200
    logs = storage.list_audit_logs(100, tenant)
    login = next(row for row in logs if row["tool_name"] == "/auth/login")
    assert '"session_issued": true' in login["details"]
    assert any(row["tool_name"] == "/auth/logout" for row in logs)
    assert identity.get() is None


def test_server_exception_no_secret_leak(db):
    client = TestClient(api.app, raise_server_exceptions=False)
    with patch.object(api, "_list_agents_for_ctx", side_effect=RuntimeError("password=never-record-me")):
        assert client.get("/supervisor/audit").status_code == 500
    row = storage.list_audit_logs(1, "public-demo")[0]
    assert row["status"] == "ERROR"
    assert "never-record-me" not in row["details"]


def test_redis_read_does_not_lock_first_attempt():
    limiter = api.AuthRateLimiter()
    limiter._redis = MagicMock()
    limiter._redis.get.return_value = None
    assert limiter.is_locked("new-user") == (False, 0)
    limiter._redis.set.assert_not_called()


def test_supabase_tenant_filter(db):
    backend = MagicMock()
    backend.request.return_value = []
    with patch.object(storage, "get_backend_mode", return_value="supabase"), patch.object(storage, "_sb", return_value=backend):
        storage.list_audit_logs(15, "org-a")
    assert "tenant_id=eq.org-a" in backend.request.call_args.args[2]


@pytest.mark.parametrize("payload", [
    '{"password": "sensitive with spaces", "nested": [{"refresh_token": "never-log"}]}',
    'Authorization: Bearer sensitive-jwt',
    "token='sensitive with spaces'",
    'details={"secret": "never-log"}',
])
def test_redaction_structured_and_bearer(db, payload):
    write("org-a", payload)
    details = storage.list_audit_logs(1, "org-a")[0]["details"]
    assert "sensitive" not in details
    assert "never-log" not in details


def test_ack_nonexistent_does_not_claim_execution(db):
    assert storage.ack_task_row("site-a", 999, "OK", datetime.now(timezone.utc).isoformat()) is False
    storage.create_task_row("site-a", "scan", datetime.now(timezone.utc).isoformat())
    task = storage.list_tasks_raw("site-a")[0]
    assert not storage.ack_task_row("site-b", task["id"], "OK", datetime.now(timezone.utc).isoformat())
    assert storage.ack_task_row("site-a", task["id"], "OK", datetime.now(timezone.utc).isoformat())


def test_session_protocol_stable_and_namespaced(db):
    client = TestClient(api.app)
    seen = []

    def mission(**kwargs):
        sid = kwargs["session_id"]
        seen.append(sid)
        storage.append_session_turn(sid, datetime.now(timezone.utc).isoformat(), "user", "test question", None)
        return {"session_id": sid}

    with patch.object(api.agent_engine, "run_multi_agent_mission", side_effect=mission):
        response = client.post("/supervisor/ask", json={"question": "test", "session_id": "a" * 120})
        assert response.status_code == 200
        sid = response.json()["session_id"]
        assert sid == "a" * 120
        second = client.post("/supervisor/ask", json={"question": "test", "session_id": sid})
        assert second.json()["session_id"] == sid
        assert seen[0] == seen[1] == "public-demo:" + sid
    assert len(client.get("/supervisor/session/" + sid).json()["turns"]) == 2


def test_deployment_includes_audit_imports():
    import json
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    included = json.loads((root / "vercel.json").read_text())["builds"][0]["config"]["includeFiles"]
    dockerfile = (root / "Dockerfile").read_text()
    for module in ("audit_context.py", "audit_redaction.py"):
        assert module in included
        assert module in dockerfile


def test_two_private_orgs_same_session_cannot_read_each_other(db):
    clients = []
    tenants = []
    for index in (1, 2):
        client = TestClient(api.app)
        response = client.post("/auth/signup", json={
            "email": f"tenant{index}@example.org", "password": "TenantStrong2026!",
            "full_name": f"User {index}", "org_name": f"School {index}",
        })
        assert response.status_code == 200
        clients.append(client)
        tenants.append(response.json()["user"]["org_slug"])
    assert tenants[0] != tenants[1]
    for tenant in tenants:
        storage.append_session_turn(tenant + ":same", datetime.now(timezone.utc).isoformat(), "user", tenant, None)
        write(tenant, tenant)
    for client, tenant in zip(clients, tenants):
        turns = client.get("/supervisor/session/same").json()["turns"]
        assert [turn["content"] for turn in turns] == [tenant]
        logs = client.get("/supervisor/audit").json()["audit_logs"]
        assert logs and all(row["tenant_id"] == tenant for row in logs)


def test_audit_storage_outage_does_not_break_response(db, caplog):
    client = TestClient(api.app)
    with patch.object(storage, "record_audit_log", side_effect=RuntimeError("private-storage-secret")):
        response = client.post("/auth/login", json={"email": "outage@example.org", "password": "bad"})
    assert response.status_code == 401
    assert "audit_write_failed" in caplog.text
    assert "private-storage-secret" not in caplog.text
