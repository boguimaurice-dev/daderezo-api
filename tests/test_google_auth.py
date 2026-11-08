import io
import json
import os
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient
import api


class GoogleIdentityTests(unittest.TestCase):
    def setUp(self):
        self.client = TestClient(api.app)
        self.env = patch.dict(os.environ, {"SUPABASE_URL": "https://example.supabase.co", "SUPABASE_SERVICE_ROLE_KEY": "server-only-key"})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_config_never_returns_server_key(self):
        result = self.client.get('/auth/google/config')
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json(), {'supabase_url': 'https://example.supabase.co'})

    def test_google_exchange_verifies_user_but_grants_no_access(self):
        responses = [io.BytesIO(json.dumps({'access_token': 'test-token'}).encode()), io.BytesIO(json.dumps({'id': 'abc', 'email': 'user@example.org', 'email_confirmed_at': '2026-01-01', 'identities': [{'provider': 'google', 'identity_data': {'email': 'user@example.org', 'email_verified': True}}]}).encode())]
        with patch('api.urllib.request.urlopen', side_effect=responses) as request:
            result = self.client.post('/auth/google/exchange', json={'code': 'valid', 'verifier': 'a' * 43})
        self.assertEqual(result.json(), {'verified': True, 'email': 'user@example.org', 'access_granted': False, 'identity_token': 'test-token'})
        self.assertEqual(request.call_count, 2)
        self.assertNotIn('server-only-key', result.text)

    def test_reject_non_google_identity(self):
        responses = [io.BytesIO(b'{"access_token":"test-token"}'), io.BytesIO(b'{"email":"user@example.org","email_confirmed_at":"yes","identities":[]}')]
        with patch('api.urllib.request.urlopen', side_effect=responses):
            result = self.client.post('/auth/google/exchange', json={'code': 'valid', 'verifier': 'a' * 43})
        self.assertEqual(result.status_code, 401)

    def test_logout_revokes_session_via_supabase_without_sending_server_key_to_client(self):
        response = io.BytesIO(b'')
        response.status = 204
        with patch('api.urllib.request.urlopen', return_value=response) as request:
            result = self.client.post('/auth/google/logout', headers={'Authorization': 'Bearer session-token'})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json(), {'status': 'ok'})
        sent = request.call_args.args[0]
        self.assertEqual(sent.full_url, 'https://example.supabase.co/auth/v1/logout?scope=local')
        self.assertEqual(sent.get_header('Authorization'), 'Bearer session-token')
        self.assertNotIn('server-only-key', result.text)
        self.assertEqual(self.client.post('/auth/google/logout').status_code, 401)

    def test_invalid_verifier_and_invalid_url(self):
        self.assertEqual(self.client.post('/auth/google/exchange', json={'code': 'valid', 'verifier': 'short'}).status_code, 422)
        with patch.dict(os.environ, {'SUPABASE_URL': 'https://attacker.example'}):
            self.assertEqual(self.client.get('/auth/google/config').status_code, 503)


if __name__ == '__main__':
    unittest.main()
