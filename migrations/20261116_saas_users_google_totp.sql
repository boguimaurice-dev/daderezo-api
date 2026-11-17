-- Apply before Google/2FA code on existing Supabase/PostgreSQL databases.
-- Additive and repeatable: no existing factor, key or account is overwritten.
BEGIN;
ALTER TABLE public.saas_users ADD COLUMN IF NOT EXISTS auth_provider TEXT DEFAULT 'local';
ALTER TABLE public.saas_users ADD COLUMN IF NOT EXISTS is_email_verified INTEGER DEFAULT 0;
ALTER TABLE public.saas_users ADD COLUMN IF NOT EXISTS totp_secret TEXT;
ALTER TABLE public.saas_users ADD COLUMN IF NOT EXISTS totp_enabled INTEGER DEFAULT 0;
ALTER TABLE public.saas_users ADD COLUMN IF NOT EXISTS avatar_url TEXT;
-- This table contains password hashes, probe keys and TOTP seeds. Only the API's
-- server-side service role may access it, not Supabase browser roles.
DO $$ BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'anon') THEN
    REVOKE ALL ON TABLE public.saas_users FROM anon;
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'authenticated') THEN
    REVOKE ALL ON TABLE public.saas_users FROM authenticated;
  END IF;
END $$;
NOTIFY pgrst, 'reload schema';
COMMIT;
