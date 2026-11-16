"""Google identity checks, TOTP enrollment/QR and work-mode navigation."""
import base64
import re
import time
from pathlib import Path
from unittest.mock import patch
import xml.etree.ElementTree as ET

import pytest
from fastapi.testclient import TestClient
import api
import storage


@pytest.fixture
def client(tmp_path, monkeypatch):
    monkeypatch.setenv("DADEREZO_DB_PATH", str(tmp_path / "auth.db"))
    monkeypatch.setenv("DADEREZO_AUTH_SECRET", "auth-tests-only-not-for-production-2026")
    monkeypatch.setenv("GOOGLE_CLIENT_ID", "tests.apps.googleusercontent.com")
    monkeypatch.delenv("DADEREZO_API_KEY", raising=False)
    monkeypatch.setattr(api, "auth_limiter", api.AuthRateLimiter())
    storage.init_db()
    return TestClient(api.app)


def signup(client, email="secure@example.org"):
    result = client.post("/auth/signup", json={"email": email, "password": "SecureTest2026!", "full_name": "Tester", "org_name": email})
    assert result.status_code == 200
    return result.json()


def claims(client, **overrides):
    config = client.get("/auth/google/config")
    assert config.headers["cache-control"] == "no-store"
    result = {"email": "google@example.org", "email_verified": True, "sub": "subject-123",
              "aud": "tests.apps.googleusercontent.com", "iss": "https://accounts.google.com",
              "nonce": config.json()["nonce"], "name": "Google Test"}
    result.update(overrides)
    return result


def login_google(client, profile):
    with patch.object(api.google_id_token, "verify_oauth2_token", return_value=profile) as verifier:
        response = client.post("/auth/google", json={"id_token": "test-google-credential"})
        verifier.assert_called_once()
        assert verifier.call_args.args[2] == "tests.apps.googleusercontent.com"
        return response


def test_google_disabled_without_configuration(client, monkeypatch):
    monkeypatch.delenv("GOOGLE_CLIENT_ID")
    assert not client.get("/auth/google/config").json()["enabled"]
    assert client.post("/auth/google", json={"id_token": "credential-placeholder"}).status_code == 503


def test_google_rejects_client_profile_and_forged_signature(client):
    response = client.post("/auth/google", json={"user_info": {"email": "victim@example.org", "email_verified": True}})
    assert response.status_code == 422
    with patch.object(api.google_id_token, "verify_oauth2_token", side_effect=ValueError("bad signature")):
        assert client.post("/auth/google", json={"id_token": "forged.jwt.token"}).status_code == 401
    assert storage.get_saas_user_by_email("victim@example.org") is None


@pytest.mark.parametrize("change", [
    {"iss": "https://evil.example"}, {"aud": "another-client"},
    {"email_verified": False}, {"email_verified": "true"}, {"sub": ""}, {"nonce": "wrong-nonce"}
])
def test_google_claims_must_match(client, change):
    assert login_google(client, claims(client, **change)).status_code == 401
    assert storage.get_saas_user_by_email("google@example.org") is None


def test_google_nonce_required_and_consumed(client):
    profile = claims(client)
    client.cookies.clear()
    assert login_google(client, profile).status_code == 401
    response = login_google(client, claims(client))
    assert response.status_code == 200
    assert "daderezo_google_nonce" not in client.cookies
    assert response.json()["user"]["auth_provider"] == "google"


def enroll(client):
    response = client.post("/auth/2fa/setup")
    assert response.status_code == 200
    setup = response.json()
    return setup, {"secret": setup["secret"], "enrollment_token": setup["enrollment_token"], "code": api.get_totp_token(setup["secret"])}


def test_qr_is_local_svg_and_enrollment_is_bound(client):
    signup(client)
    setup, payload = enroll(client)
    svg = base64.b64decode(setup["qr_code_data_uri"].split(",", 1)[1])
    assert ET.fromstring(svg).tag.endswith("svg")
    assert b"<script" not in svg
    assert "secret=" + setup["secret"] in setup["otpauth_url"]
    assert "digits=6" in setup["otpauth_url"]
    assert client.post("/auth/2fa/enable", json={**payload, "secret": api.generate_totp_secret()}).status_code == 400
    assert client.post("/auth/2fa/enable", json=payload).status_code == 200
    assert client.post("/auth/2fa/setup").status_code == 409
    assert client.post("/auth/2fa/enable", json=payload).status_code == 409


def test_enrollment_cannot_be_used_as_login_or_other_account(client):
    signup(client)
    setup, payload = enroll(client)
    assert client.post("/auth/2fa/verify", json={"temp_token": setup["enrollment_token"], "code": payload["code"]}).status_code == 401
    signup(client, "second@example.org")
    assert client.post("/auth/2fa/enable", json=payload).status_code == 400


def test_expired_enrollment_rejected(client):
    signup(client)
    _, payload = enroll(client)
    with patch.object(api.time, "time", return_value=time.time() + 700):
        assert client.post("/auth/2fa/enable", json=payload).status_code == 400


def test_google_does_not_bypass_totp_and_can_disable_with_current_factor(client):
    assert login_google(client, claims(client)).status_code == 200
    setup, payload = enroll(client)
    assert client.post("/auth/2fa/enable", json=payload).status_code == 200
    client.post("/auth/logout")
    response = login_google(client, claims(client))
    assert response.status_code == 200
    assert response.json()["status"] == "2fa_required"
    assert "daderezo_session" not in client.cookies
    assert not client.get("/auth/me").json()["authenticated"]
    verify = client.post("/auth/2fa/verify", json={"temp_token": response.json()["temp_token"], "code": api.get_totp_token(setup["secret"])})
    assert verify.status_code == 200
    assert client.post("/auth/2fa/disable", json={"code": api.get_totp_token(setup["secret"])}).status_code == 200


def test_totp_rfc6238_and_corrupt_secret():
    # Public RFC 6238 Appendix B SHA-1 vector, not an application credential.
    rfc_vector = base64.b32encode(b"12345678901234567890").decode("ascii")
    assert api.get_totp_token(rfc_vector, for_time=59, digits=8) == "94287082"
    assert not api.verify_totp_token("not-a-base32-secret", "123456")


def test_home_links_and_no_shared_private_cache():
    root = Path(__file__).resolve().parents[1]
    html = (root / "DADEREZO.html").read_text()
    for element in ("homePageLink", "homePageTopLink"):
        tag = re.search(r'<a[^>]*id="' + element + r'"[^>]*>', html).group(0)
        assert 'href="/"' in tag
        assert "data-sim-only" not in tag
    assert 'id="totpQrCode"' in html
    assert "promptEmail" not in html
    assert "accounts.google.com/gsi/client" in html
    sw = (root / "sw.js").read_text()
    assert "dataCache.match" not in sw
    assert "daderezo-shell-v4.9-auth" in sw


def test_legacy_sessions_rejected_after_insecure_google_flow_removed(client):
    import hashlib
    import hmac
    import json
    user = signup(client)["user"]
    payload = {"email": user["email"], "org_slug": user["org_slug"], "exp": int(time.time()) + 3600}
    body = base64.urlsafe_b64encode(json.dumps(payload).encode()).decode().rstrip("=")
    signature = hmac.new(api._jwt_secret(), body.encode(), hashlib.sha256).hexdigest()
    assert api._verify_saas_token("dzt_" + body + "." + signature) is None


def test_qr_requires_authenticated_account(client):
    assert client.post("/auth/2fa/setup").status_code in (400, 401, 403)


def test_factor_changes_are_rate_limited(client):
    signup(client)
    _, payload = enroll(client)
    # Choose a code that is not valid in the tolerated time window.
    invalid = next(f"{i:06d}" for i in range(10) if not api.verify_totp_token(payload["secret"], f"{i:06d}"))
    for _ in range(5):
        assert client.post("/auth/2fa/enable", json={**payload, "code": invalid}).status_code == 400
    assert client.post("/auth/2fa/enable", json=payload).status_code == 429


def test_internal_jwt_scope_and_algorithm_are_enforced(client):
    user = signup(client)["user"]
    token = api._sign_saas_token(user)
    import jwt
    payload = jwt.decode(token[4:], options={"verify_signature": False})
    assert api._verify_saas_token(token) is not None
    unsigned = jwt.encode(payload, key="", algorithm="none")
    assert api._verify_saas_token("dzt_" + unsigned) is None
    payload["aud"] = "daderezo-2fa"
    wrong_scope = jwt.encode(payload, api._jwt_secret(), algorithm="HS256")
    assert api._verify_saas_token("dzt_" + wrong_scope) is None
