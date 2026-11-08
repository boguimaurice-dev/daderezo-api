import os
import tempfile
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
import api
import storage


class PlatformTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.env = patch.dict(os.environ, {'DADEREZO_DB_PATH': os.path.join(self.temp.name, 'app.db'), 'DADEREZO_SUPERADMIN_EMAIL': 'admin@example.com'})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.client = TestClient(api.app)
        self.identity = {'id': 'user-123', 'email': 'client@example.com'}
        api.app.dependency_overrides[api.require_google_identity] = lambda: self.identity
        self.addCleanup(api.app.dependency_overrides.clear)
        storage.init_db()

    def test_application_admin_and_payment_do_not_grant_access(self):
        data = {'org_name': 'Site A', 'contact_name': 'Alice', 'site_description': 'Réseau de mon école', 'authorization_confirmed': False}
        self.assertEqual(self.client.post('/platform/applications', json=data).status_code, 400)
        data['authorization_confirmed'] = True
        created = self.client.post('/platform/applications', json=data)
        self.assertEqual(created.status_code, 200)
        self.assertFalse(created.json()['access_granted'])
        app_id = created.json()['application']['id']
        self.assertEqual(self.client.post('/platform/applications', json=data).status_code, 409)
        self.assertEqual(self.client.get('/platform/admin/applications').status_code, 403)
        self.identity = {'id': 'admin-456', 'email': 'admin@example.com'}
        self.assertEqual(len(self.client.get('/platform/admin/applications').json()['applications']), 1)
        endpoint = f'/platform/admin/applications/{app_id}/decision'
        self.assertEqual(self.client.post(endpoint, json={'status':'pending','payment_status':'paid'}).status_code, 400)
        decided = self.client.post(endpoint, json={'status':'approved','payment_status':'pilot'})
        self.assertEqual(decided.status_code, 200)
        self.assertTrue(decided.json()['access_granted'])
        self.assertEqual(decided.json()['application']['payment_status'], 'pilot')
        with storage._sql_cursor() as (_, c, ph):
            c.execute('SELECT actor, action FROM platform_admin_events')
            self.assertEqual(c.fetchall(), [('admin@example.com', 'decision')])

    def test_no_config_admin_means_fail_closed(self):
        self.identity = {'id': 'x', 'email': 'admin@example.com'}
        with patch.dict(os.environ, {'DADEREZO_SUPERADMIN_EMAIL': ''}):
            self.assertEqual(self.client.get('/platform/admin/applications').status_code, 403)


if __name__ == '__main__':
    unittest.main()

class RealAccessTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {'DADEREZO_DB_PATH': os.path.join(self.tmp.name, 'db.sqlite'), 'DADEREZO_LEGACY_AUTH': '0', 'DADEREZO_SUPERADMIN_EMAIL': 'admin@example.com'}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        storage.init_db()
        self.client = TestClient(api.app)
        self.identity = {'id': 'identity1', 'email': 'user@example.com'}
        api.app.dependency_overrides[api.require_google_identity] = lambda: self.identity
        self.addCleanup(api.app.dependency_overrides.clear)
        self.identity_patch = patch.object(api, 'require_google_identity', side_effect=lambda authorization=None: self.identity)
        self.identity_patch.start()
        self.addCleanup(self.identity_patch.stop)

    def test_pending_approval_payment_activation_and_suspension(self):
        signup = self.client.post('/auth/signup', json={'email':'a@b.com', 'password':'password', 'org_name':'Hello'})
        self.assertEqual(signup.status_code, 403)
        self.assertEqual(self.client.post('/register', json={'agent_id':'evil', 'nom':'evil'}).status_code, 401)
        google = {'Authorization': 'Bearer google-token'}
        data = {'org_name':'My Site', 'contact_name':'Alice', 'site_description':'Réseau école Bouaké', 'authorization_confirmed':True}
        resp = self.client.post('/platform/applications', json=data)
        self.assertEqual(resp.status_code, 200)
        self.assertNotIn('probe_api_key', resp.text)
        app_id = resp.json()['application']['id']
        self.assertEqual(self.client.get('/auth/me', headers=google).status_code, 403)
        self.identity = {'id':'admin', 'email':'admin@example.com'}
        endpoint = f'/platform/admin/applications/{app_id}/decision'
        invalid = self.client.post(endpoint, json={'status':'approved', 'payment_status':'paid'})
        self.assertEqual(invalid.status_code, 400)
        approved = self.client.post(endpoint, json={'status':'approved', 'payment_status':'unpaid'})
        self.assertFalse(approved.json()['access_granted'])
        pilot = self.client.post(endpoint, json={'status':'approved', 'payment_status':'pilot'})
        self.assertTrue(pilot.json()['access_granted'])
        self.assertNotIn('probe_api_key', self.client.get('/platform/admin/applications').text)
        self.identity = {'id':'identity1', 'email':'user@example.com'}
        me = self.client.get('/auth/me', headers=google).json()
        key = me['user']['probe_api_key']
        org = me['user']['org_slug']
        probe = {'X-API-Key': key}
        self.assertEqual(self.client.get('/probe/daderezo_sonde.py', headers=probe).status_code, 200)
        self.assertEqual(self.client.get('/probe/daderezo_sonde.py', params={'probe_key':key}).status_code, 400)
        self.assertEqual(self.client.post('/register', headers=probe, json={'agent_id':'unrelated-site', 'nom':'Bad'}).status_code, 403)
        self.assertEqual(self.client.post('/register', headers=probe, json={'agent_id':org+'-principal', 'nom':'Good'}).status_code, 200)
        self.identity = {'id':'admin', 'email':'admin@example.com'}
        self.assertEqual(self.client.post(endpoint, json={'status':'suspended', 'payment_status':'unpaid'}).status_code, 200)
        self.identity = {'id':'identity1', 'email':'user@example.com'}
        self.assertEqual(self.client.get('/auth/me', headers=google).status_code, 403)
        self.assertEqual(self.client.post('/register', headers=probe, json={'agent_id':org+'-principal', 'nom':'Good'}).status_code, 403)
        self.assertEqual(self.client.get('/probe/daderezo_sonde.py', headers=probe).status_code, 403)

    def test_expired_paid_application_is_denied(self):
        app = {'status':'approved', 'payment_status':'paid', 'subscription_end':'2000-01-01', 'org_slug':'org-a', 'probe_api_key':'dzk_test'}
        self.assertFalse(api._application_active(app))
        app['subscription_end'] = '9999-12-31'
        self.assertTrue(api._application_active(app))
        app['status'] = 'suspended'
        self.assertFalse(api._application_active(app))
