-- Permit a verified owner to claim a workspace after a valid approval, without
-- altering the payment decision. Lock the application while checking status.
CREATE OR REPLACE FUNCTION public.claim_legacy_workspace(p_identity text, p_legacy_org text, p_actor text, p_ts text)
RETURNS SETOF public.platform_applications LANGUAGE plpgsql SECURITY INVOKER SET search_path=public AS $$
DECLARE target public.platform_applications%ROWTYPE;
BEGIN
 SELECT * INTO target FROM public.platform_applications WHERE identity_id=p_identity FOR UPDATE;
 IF NOT FOUND OR target.org_slug = p_legacy_org
    OR NOT COALESCE((target.status = 'pending' AND NOT EXISTS (SELECT 1 FROM public.platform_admin_events WHERE application_id=target.id)
       OR target.status = 'approved' AND target.probe_api_key IS NOT NULL
          AND (target.payment_status = 'pilot' OR (target.payment_status = 'paid' AND target.subscription_end >= left(p_ts, 10)))), false)
    OR EXISTS (SELECT 1 FROM public.platform_applications WHERE org_slug=p_legacy_org AND id<>target.id)
    OR EXISTS (SELECT 1 FROM public.agents WHERE org_slug=target.org_slug)
 THEN RETURN; END IF;
 UPDATE public.platform_applications SET org_slug=p_legacy_org, updated_at=p_ts WHERE id=target.id;
 INSERT INTO public.platform_admin_events(ts,actor,application_id,action,details)
 VALUES(p_ts,p_actor,target.id,'legacy_claim',json_build_object('org_slug',p_legacy_org)::text);
 RETURN QUERY SELECT * FROM public.platform_applications WHERE id=target.id;
END $$;
REVOKE ALL ON FUNCTION public.claim_legacy_workspace(text,text,text,text) FROM PUBLIC, anon, authenticated;
GRANT EXECUTE ON FUNCTION public.claim_legacy_workspace(text,text,text,text) TO service_role;
