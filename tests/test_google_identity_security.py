import io
import json
import os
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
import api

class IdentitySecurityTests(unittest.TestCase):
    def test_platform_admin_requires_google_verified_email_and_valid_session(self):
        with patch.dict(os.environ, {'SUPABASE_URL':'https://example.supabase.co','SUPABASE_SERVICE_ROLE_KEY':'dummy','DADEREZO_SUPERADMIN_EMAIL':'admin@example.com'}):
            client = TestClient(api.app)
            def resp(verified=True, provider='google', extra=None):
                identities = [{'provider':provider,'identity_data':{'email':'admin@example.com','email_verified':verified}}]
                if extra: identities.append({'provider':extra, 'identity_data':{}})
                return io.BytesIO(json.dumps({'id':'abc','email':'admin@example.com','email_confirmed_at':'now','identities':identities}).encode())
            for v, p, extra in [(False,'google',None),(True,'email',None),(True,'google','email')]:
                with patch('api.urllib.request.urlopen', return_value=resp(v,p,extra)):
                    self.assertEqual(client.get('/platform/admin/applications', headers={'Authorization':'Bearer x'}).status_code, 401)
            self.assertEqual(client.get('/platform/admin/applications').status_code, 401)

if __name__ == '__main__': unittest.main()
