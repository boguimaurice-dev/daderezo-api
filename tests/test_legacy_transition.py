import os
import tempfile
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
import api
import storage


class LegacyTransitionTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {'DADEREZO_DB_PATH': os.path.join(self.tmp.name, 'db'),
            'DADEREZO_AUTH_SECRET': 'test-secret-at-least-thirty-two-bytes-long',
            'DADEREZO_LEGACY_AUTH': '0', 'DADEREZO_TRANSITION_EMAIL': 'old@example.com',
            'DADEREZO_TRANSITION_UNTIL': '2099-01-01T00:00:00+00:00',
            'DADEREZO_SUPERADMIN_EMAIL': 'admin@example.com'})
        env.start(); self.addCleanup(env.stop)
        storage.init_db()
        self.old = storage.create_saas_user('old@example.com', api._hash_password('password'), 'Owner', 'old-site', 'Old Site', 'dzk_old', '2026-01-01')
        storage.upsert_agent('historic-site', 'Site', None, None, '2026-01-01', org_slug='old-site')
        self.client = TestClient(api.app)
        self.identity = {'id':'google', 'email':'old@example.com'}
        original = api.require_google_identity
        api.app.dependency_overrides[original] = lambda: self.identity
        self.addCleanup(api.app.dependency_overrides.clear)
        self.token = api._sign_saas_token(self.old)

    def test_only_preexisting_account_until_deadline_and_no_signup(self):
        headers = {'Authorization': 'Bearer ' + self.token}
        probe = {'X-API-Key': 'dzk_old'}
        self.assertEqual(self.client.get('/auth/me', headers=headers).status_code, 200)
        self.assertEqual(self.client.get('/dashboard/historic-site', headers=probe).status_code, 200)
        self.assertEqual(self.client.post('/auth/signup', json={'email':'new@example.com','password':'password','org_name':'New'}).status_code, 403)
        forged = api._sign_saas_token({**self.old, 'org_slug': 'other'})
        self.assertEqual(self.client.get('/auth/me', headers={'Authorization':'Bearer '+forged}).status_code, 403)
        with patch.dict(os.environ, {'DADEREZO_TRANSITION_UNTIL':'2000-01-01T00:00:00+00:00'}):
            self.assertEqual(self.client.get('/auth/me', headers=headers).status_code, 403)
            self.assertEqual(self.client.get('/dashboard/historic-site', headers=probe).status_code, 401)
        with patch.dict(os.environ, {'DADEREZO_TRANSITION_EMAIL':'other@example.com'}):
            self.assertEqual(self.client.get('/auth/me', headers=headers).status_code, 403)

    def test_legacy_login_is_limited_and_fails_closed(self):
        bad = {'email': 'old@example.com', 'password': 'incorrect'}
        for _ in range(5):
            self.assertEqual(self.client.post('/auth/login', json=bad).status_code, 401)
        self.assertEqual(self.client.post('/auth/login', json=bad).status_code, 429)
        with patch.object(storage, 'consume_legacy_login_attempt', side_effect=OSError('offline')):
            self.assertEqual(self.client.post('/auth/login', json=bad).status_code, 503)

    def test_legacy_login_only_for_eligible_existing_account(self):
        good = {'email':'old@example.com', 'password':'password'}
        self.assertEqual(self.client.post('/auth/login', json=good).status_code, 200)
        with patch.dict(os.environ, {'DADEREZO_TRANSITION_UNTIL':'2000-01-01T00:00:00+00:00'}):
            self.assertEqual(self.client.post('/auth/login', json=good).status_code, 403)

    def test_claim_then_approval_and_suspension_apply_to_old_credentials(self):
        data = {'org_name':'My site','contact_name':'Owner','site_description':'My authorized network','authorization_confirmed':True}
        app = self.client.post('/platform/applications', json=data).json()['application']
        self.assertEqual(self.client.post('/platform/claim-legacy', json={'legacy_token':self.token}).status_code, 200)
        headers = {'Authorization':'Bearer '+self.token}
        probe = {'X-API-Key':'dzk_old'}
        self.assertEqual(self.client.get('/auth/me', headers=headers).status_code, 403)
        self.assertEqual(self.client.get('/dashboard/historic-site', headers=probe).status_code, 401)
        self.identity = {'id':'admin', 'email':'admin@example.com'}
        endpoint = '/platform/admin/applications/' + app['id'] + '/decision'
        self.assertEqual(self.client.post(endpoint, json={'status':'approved','payment_status':'pilot'}).status_code, 200)
        self.assertEqual(self.client.get('/auth/me', headers=headers).status_code, 200)
        self.assertEqual(self.client.get('/dashboard/histororic-site', headers=probe).status_code, 403)
        self.assertEqual(self.client.get('/dashboard/historic-site', headers=probe).status_code, 200)
        self.assertEqual(self.client.post(endpoint, json={'status':'suspended','payment_status':'unpaid'}).status_code, 200)
        self.assertEqual(self.client.get('/auth/me', headers=headers).status_code, 403)
        self.assertEqual(self.client.get('/dashboard/historic-site', headers=probe).status_code, 401)
