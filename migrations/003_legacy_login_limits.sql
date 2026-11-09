-- Service-role only; stores a hash rather than an email address.
CREATE TABLE IF NOT EXISTS public.legacy_login_limits (
  subject_hash text PRIMARY KEY,
  window_start bigint NOT NULL,
  attempts integer NOT NULL
);
ALTER TABLE public.legacy_login_limits ENABLE ROW LEVEL SECURITY;
REVOKE ALL ON public.legacy_login_limits FROM PUBLIC, anon, authenticated;
GRANT ALL ON public.legacy_login_limits TO service_role;
CREATE OR REPLACE FUNCTION public.consume_legacy_login_attempt(p_subject text, p_now bigint)
RETURNS boolean LANGUAGE plpgsql SECURITY INVOKER SET search_path=public AS $$
DECLARE attempts_now integer;
BEGIN
  INSERT INTO public.legacy_login_limits(subject_hash, window_start, attempts)
  VALUES (p_subject, p_now, 1)
  ON CONFLICT (subject_hash) DO UPDATE SET
    window_start = CASE WHEN legacy_login_limits.window_start <= p_now - 900 THEN p_now ELSE legacy_login_limits.window_start END,
    attempts = CASE WHEN legacy_login_limits.window_start <= p_now - 900 THEN 1 ELSE legacy_login_limits.attempts + 1 END
  RETURNING attempts INTO attempts_now;
  RETURN attempts_now <= 5;
END $$;
REVOKE ALL ON FUNCTION public.consume_legacy_login_attempt(text,bigint) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.consume_legacy_login_attempt(text,bigint) TO service_role;
