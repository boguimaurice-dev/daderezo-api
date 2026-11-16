-- Apply BEFORE deploying the updated API (Supabase SQL Editor / PostgreSQL).
-- No text-based backfill: legacy rows without a trusted tenant remain admin-only.
BEGIN;
ALTER TABLE public.agent_audit_logs ADD COLUMN IF NOT EXISTS tenant_id TEXT;
ALTER TABLE public.agent_audit_logs ADD COLUMN IF NOT EXISTS actor TEXT;
ALTER TABLE public.agent_audit_logs ADD COLUMN IF NOT EXISTS request_id TEXT;
CREATE INDEX IF NOT EXISTS idx_audit_tenant_id ON public.agent_audit_logs (tenant_id, id);
CREATE INDEX IF NOT EXISTS idx_audit_ts ON public.agent_audit_logs (ts);
COMMIT;
-- Supabase: table must not be accessible with anon/authenticated client keys.
-- Run separately on Supabase only (API uses the server-side service role):
-- ALTER TABLE public.agent_audit_logs ENABLE ROW LEVEL SECURITY;
-- REVOKE ALL ON public.agent_audit_logs FROM anon, authenticated;
