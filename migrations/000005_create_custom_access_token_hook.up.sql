CREATE OR REPLACE FUNCTION public.custom_access_token_hook(event jsonb)
RETURNS jsonb
LANGUAGE plpgsql
STABLE
SECURITY INVOKER
SET search_path = public
AS $$
DECLARE
    claims jsonb;
    resolved_app_user_id uuid;
    resolved_app_roles jsonb;
BEGIN
    claims := event->'claims';

    SELECT au.id
    INTO resolved_app_user_id
    FROM public.app_users au
    WHERE au.auth_user_id = (event->>'user_id')::uuid
      AND au.deleted_at IS NULL
    LIMIT 1;

    -- A valid Supabase user may exist before the Central SSO profile or
    -- application membership has been created. In that case authentication
    -- remains valid, but no application authorization is granted.
    IF resolved_app_user_id IS NULL THEN
        claims := jsonb_set(
            claims,
            '{app_roles}',
            '{}'::jsonb,
            true
        );

        RETURN jsonb_set(event, '{claims}', claims);
    END IF;

    SELECT COALESCE(
        jsonb_object_agg(a.code, m.role),
        '{}'::jsonb
    )
    INTO resolved_app_roles
    FROM public.app_memberships m
    JOIN public.applications a
        ON a.id = m.application_id
    WHERE m.app_user_id = resolved_app_user_id
      AND m.status = 'approved'
      AND m.deleted_at IS NULL
      AND a.is_active = true;

    claims := jsonb_set(
        claims,
        '{app_user_id}',
        to_jsonb(resolved_app_user_id::text),
        true
    );

    claims := jsonb_set(
        claims,
        '{app_roles}',
        resolved_app_roles,
        true
    );

    RETURN jsonb_set(
        event,
        '{claims}',
        claims
    );
END;
$$;

-- Supabase Auth service is the only runtime caller that needs execute access.
GRANT USAGE ON SCHEMA public TO supabase_auth_admin;

GRANT EXECUTE
ON FUNCTION public.custom_access_token_hook(jsonb)
TO supabase_auth_admin;

REVOKE EXECUTE
ON FUNCTION public.custom_access_token_hook(jsonb)
FROM anon;

REVOKE EXECUTE
ON FUNCTION public.custom_access_token_hook(jsonb)
FROM authenticated;

REVOKE EXECUTE
ON FUNCTION public.custom_access_token_hook(jsonb)
FROM public;

-- The hook needs read access to the authorization source tables.
GRANT SELECT ON public.app_users TO supabase_auth_admin;
GRANT SELECT ON public.app_memberships TO supabase_auth_admin;
GRANT SELECT ON public.applications TO supabase_auth_admin;

CREATE POLICY "auth_hook_read_app_users"
ON public.app_users
FOR SELECT
TO supabase_auth_admin
USING (true);

CREATE POLICY "auth_hook_read_app_memberships"
ON public.app_memberships
FOR SELECT
TO supabase_auth_admin
USING (true);

CREATE POLICY "auth_hook_read_applications"
ON public.applications
FOR SELECT
TO supabase_auth_admin
USING (true);