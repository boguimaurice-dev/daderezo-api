"""Exercise legacy account upgrades; PostgreSQL tests run in CI, SQLite locally too."""
from pathlib import Path
import os
import sqlite3
import uuid

import pytest
import storage

LEGACY = """CREATE TABLE saas_users (
id INTEGER PRIMARY KEY, email TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL,
full_name TEXT, org_slug TEXT NOT NULL, org_name TEXT NOT NULL,
probe_api_key TEXT UNIQUE NOT NULL, created_at TEXT NOT NULL)"""
SEED = """INSERT INTO saas_users VALUES
(1, 'legacy@example.org', 'existing-hash', 'Legacy', 'legacy-org', 'Legacy Org',
'legacy-probe-fixture', '2026-01-01T00:00:00+00:00')"""


def check_legacy_upgrade():
    user = storage.get_saas_user_by_email('legacy@example.org')
    assert user['password_hash'] == 'existing-hash'
    assert user['probe_api_key'] == 'legacy-probe-fixture'
    assert user['auth_provider'] == 'local'
    assert user['totp_enabled'] == 0
    assert user['is_email_verified'] == 0  # Unknown legacy verification must not be invented.
    storage.update_saas_user_profile(user['email'], avatar_url='https://example.org/avatar.png')
    assert storage.get_saas_user_by_email(user['email'])['avatar_url'].endswith('/avatar.png')
    # A second init must preserve an already-enrolled factor.
    storage.update_saas_user_totp(user['email'], 'test-factor-preserved', True)
    storage.init_db()
    assert storage.get_saas_user_by_email(user['email'])['totp_secret'] == 'test-factor-preserved'
    assert storage.get_saas_user_by_email(user['email'])['totp_enabled'] == 1


def test_sqlite_legacy_account_upgrade(tmp_path, monkeypatch):
    db = tmp_path / 'legacy.db'
    with sqlite3.connect(db) as conn:
        conn.execute(LEGACY)
        conn.execute(SEED)
    monkeypatch.setenv('DADEREZO_DB_PATH', str(db))
    storage.init_db()
    check_legacy_upgrade()


@pytest.mark.skipif(not os.environ.get('DADEREZO_TEST_POSTGRES_URL'), reason='PostgreSQL integration enabled in CI')
@pytest.mark.parametrize('use_sql_migration', [False, True])
def test_postgres_legacy_account_upgrade(monkeypatch, use_sql_migration):
    import psycopg2
    from psycopg2 import sql
    from psycopg2.extensions import make_dsn
    # An isolated random schema: never reset or modify public accounts in tests.
    dsn = os.environ['DADEREZO_TEST_POSTGRES_URL']
    schema = 'test_accounts_' + uuid.uuid4().hex
    admin = psycopg2.connect(dsn)
    admin.autocommit = True
    try:
        with admin.cursor() as cur:
            cur.execute(sql.SQL('CREATE SCHEMA {}').format(sql.Identifier(schema)))
        scoped_dsn = make_dsn(dsn, options='-c search_path=' + schema)
        with psycopg2.connect(scoped_dsn) as conn:
            with conn.cursor() as cur:
                cur.execute(LEGACY)
                cur.execute(SEED)
            conn.commit()
        for name in ('DADEREZO_DB_PATH', 'SUPABASE_URL', 'SUPABASE_SERVICE_ROLE_KEY'):
            monkeypatch.delenv(name, raising=False)
        monkeypatch.setenv('DATABASE_URL', scoped_dsn)
        if use_sql_migration:
            migration = (Path(__file__).resolve().parents[1] / 'migrations/20261116_saas_users_google_totp.sql').read_text()
            # Verify the production SQL itself twice, in the isolated test schema.
            with admin.cursor() as cur:
                cur.execute(migration.replace('public.', schema + '.'))
                cur.execute(migration.replace('public.', schema + '.'))
        storage.init_db()
        check_legacy_upgrade()
    finally:
        with admin.cursor() as cur:
            cur.execute(sql.SQL('DROP SCHEMA IF EXISTS {} CASCADE').format(sql.Identifier(schema)))
        admin.close()
