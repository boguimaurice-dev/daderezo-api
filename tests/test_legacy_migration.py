import os
import tempfile
import unittest
from unittest.mock import patch
from fastapi.testclient import TestClient
import api
import storage

class LegacyMigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp=tempfile.TemporaryDirectory(); self.addCleanup(self.tmp.cleanup)
        env=patch.dict(os.environ, {'DADEREZO_DB_PATH':os.path.join(self.tmp.name,'db.sqlite'), 'DADEREZO_AUTH_SECRET':'very-long-signing-secret-with-at-least-32-bytes', 'DADEREZO_LEGACY_AUTH':'0', 'DADEREZO_SUPERADMIN_EMAIL':'admin@example.com'})
        env.start(); self.addCleanup(env.stop)
        storage.init_db(); self.client=TestClient(api.app)
        self.identity={'id':'google-id','email':'owner@example.com'}
        original=api.require_google_identity
        api.app.dependency_overrides[original]=lambda:self.identity
        self.addCleanup(api.app.dependency_overrides.clear)
        google=patch.object(api,'require_google_identity', side_effect=lambda authorization=None:self.identity)
        google.start(); self.addCleanup(google.stop)
        self.old=storage.create_saas_user('owner@example.com',api._hash_password('oldpassword'),'Owner','old-org-1234','Old Org','dzk_old','2026-01-01')
        storage.upsert_agent('historic-site', 'Mon réseau',None,None,'2026-01-01',org_slug='old-org-1234')
        storage.record_audit_log('yesterday','historic','SENTINEL','event','test','OK',1,'old private entry')
        result=self.client.post('/platform/applications',json={'org_name':'My Site','contact_name':'Owner','site_description':'Un réseau à Bouaké','authorization_confirmed':True})
        self.application=result.json()['application']
        self.token=api._sign_saas_token(self.old)

    def test_verified_claim_preserves_agent_and_old_key_after_approval(self):
        r=self.client.post('/platform/claim-legacy',json={'legacy_token':self.token})
        self.assertEqual(r.status_code,200)
        self.assertEqual(r.json()['application']['org_slug'],'old-org-1234')
        self.assertFalse(r.json()['access_granted'])
        self.assertNotIn('probe_api_key',r.text)
        self.assertEqual(self.client.post('/platform/claim-legacy',json={'legacy_token':self.token}).status_code,409)
        self.identity={'id':'admin','email':'admin@example.com'}
        r=self.client.post(f"/platform/admin/applications/{self.application['id']}/decision",json={'status':'approved','payment_status':'pilot'})
        self.assertEqual(r.status_code,200)
        self.identity={'id':'google-id','email':'owner@example.com'}
        me=self.client.get('/auth/me',headers={'Authorization':'Bearer google-test'}).json()
        self.assertEqual(me['user']['org_slug'],'old-org-1234')
        self.assertNotEqual(me['user']['probe_api_key'],'dzk_old')
        headers={'X-API-Key':me['user']['probe_api_key']}
        self.assertEqual(self.client.post('/register',headers=headers,json={'agent_id':'historic-site','nom':'Mon réseau'}).status_code,200)
        self.assertEqual(self.client.get('/dashboard/historic-site',headers=headers).status_code,200)
        self.assertEqual(self.client.post('/register',headers={'X-API-Key':'dzk_old'},json={'agent_id':'historic-site','nom':'Mon réseau'}).status_code,200)
        self.assertNotIn('old private entry',self.client.get('/supervisor/audit',headers=headers).text)

    def test_old_token_must_be_valid_for_same_google_email_and_org(self):
        bad=api._sign_saas_token({**self.old,'email':'attacker@example.com'})
        self.assertEqual(self.client.post('/platform/claim-legacy',json={'legacy_token':bad}).status_code,401)
        wrong=api._sign_saas_token({**self.old,'org_slug':'some-other-org'})
        self.assertEqual(self.client.post('/platform/claim-legacy',json={'legacy_token':wrong}).status_code,403)
        expired=api._sign_saas_token(self.old,ttl_seconds=-10)
        self.assertEqual(self.client.post('/platform/claim-legacy',json={'legacy_token':expired}).status_code,401)
        with patch.dict(os.environ,{'DADEREZO_AUTH_SECRET':''}):
            self.assertEqual(self.client.post('/platform/claim-legacy',json={'legacy_token':self.token}).status_code,503)

    def test_claim_after_decision_is_refused_and_other_tenant_cannot_take_agent(self):
        self.identity={'id':'admin','email':'admin@example.com'}
        self.client.post(f"/platform/admin/applications/{self.application['id']}/decision",json={'status':'rejected','payment_status':'unpaid'})
        self.client.post(f"/platform/admin/applications/{self.application['id']}/decision",json={'status':'pending','payment_status':'unpaid'})
        self.identity={'id':'google-id','email':'owner@example.com'}
        self.assertEqual(self.client.post('/platform/claim-legacy',json={'legacy_token':self.token}).status_code,409)
        with self.assertRaises(PermissionError):
            storage.upsert_agent('historic-site','Imposter',None,None,'now',org_slug='another-organization')
        self.assertEqual(storage.get_agent_raw('historic-site')['org_slug'],'old-org-1234')
