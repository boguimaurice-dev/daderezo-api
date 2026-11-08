import os
import tempfile
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
import api
import storage


class JournalIsolationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        env = patch.dict(os.environ, {'DADEREZO_DB_PATH': os.path.join(self.tmp.name, 'db.sqlite'), 'DADEREZO_AUTH_SECRET': 'test-secret', 'DADEREZO_LEGACY_AUTH': '1'}, clear=False)
        env.start()
        self.addCleanup(env.stop)
        storage.init_db()
        self.client = TestClient(api.app)

    def test_shared_session_id_and_unscoped_legacy_logs_are_isolated(self):
        a = self.client.post('/auth/signup', json={'email':'a@example.com','password':'password1','org_name':'Alpha'}).json()
        b = self.client.post('/auth/signup', json={'email':'b@example.com','password':'password1','org_name':'Beta'}).json()
        auth_a = {'Authorization': 'Bearer ' + a['token']}
        auth_b = {'Authorization': 'Bearer ' + b['token']}
        org_a = a['user']['org_slug']
        org_b = b['user']['org_slug']
        storage.append_session_turn('same', 'now', 'user', 'confidential alpha', None, org_slug=org_a)
        storage.append_session_turn('same', 'now', 'user', 'confidential beta', None, org_slug=org_b)
        storage.append_session_turn('same', 'now', 'user', 'legacy secret', None)
        storage.record_audit_log('now', 'same', 'test', 'test', 'test', 'OK', 1, 'alpha secret', org_slug=org_a)
        storage.record_audit_log('now', 'same', 'test', 'test', 'test', 'OK', 1, 'beta secret', org_slug=org_b)
        storage.record_audit_log('now', 'same', 'test', 'test', 'test', 'OK', 1, 'legacy secret')
        for headers, own, other in [(auth_a, 'alpha', 'beta'), (auth_b, 'beta', 'alpha')]:
            session = self.client.get('/supervisor/session/same', headers=headers).text
            self.assertIn('confidential ' + own, session)
            self.assertNotIn('confidential ' + other, session)
            self.assertNotIn('legacy secret', session)
            logs = self.client.get('/supervisor/audit', headers=headers).text
            self.assertIn(own + ' secret', logs)
            self.assertNotIn(other + ' secret', logs)
            self.assertNotIn('legacy secret', logs)
        for endpoint in ['/supervisor/audit', '/supervisor/session/same']:
            public = self.client.get(endpoint).text
            self.assertNotIn('alpha secret', public)
            self.assertNotIn('beta secret', public)
            self.assertNotIn('legacy secret', public)
            self.assertNotIn('confidential alpha', public)
            self.assertNotIn('confidential beta', public)

if __name__ == '__main__':
    unittest.main()
