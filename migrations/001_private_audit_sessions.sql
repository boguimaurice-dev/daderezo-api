-- Legacy rows have unknown ownership and deliberately remain inaccessible.
ALTER TABLE public.agent_sessions ADD COLUMN IF NOT EXISTS org_slug text;
ALTER TABLE public.agent_audit_logs ADD COLUMN IF NOT EXISTS org_slug text;
CREATE INDEX IF NOT EXISTS agent_sessions_org_session_idx ON public.agent_sessions (org_slug, session_id, id DESC);
CREATE INDEX IF NOT EXISTS agent_audit_logs_org_id_idx ON public.agent_audit_logs (org_slug, id DESC);

-- Les lectures directes clients contournent l'API ; seul le serveur service_role y accède.
ALTER TABLE public.agent_sessions ENABLE ROW LEVEL SECURITY;
ALTER TABLE public.agent_audit_logs ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.agent_sessions, public.agent_audit_logs FROM anon, authenticated;
