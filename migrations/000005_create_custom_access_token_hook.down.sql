DROP POLICY IF EXISTS "auth_hook_read_app_users"
ON public.app_users;

DROP POLICY IF EXISTS "auth_hook_read_app_memberships"
ON public.app_memberships;

DROP POLICY IF EXISTS "auth_hook_read_applications"
ON public.applications;

REVOKE SELECT ON public.app_users FROM supabase_auth_admin;
REVOKE SELECT ON public.app_memberships FROM supabase_auth_admin;
REVOKE SELECT ON public.applications FROM supabase_auth_admin;

DROP FUNCTION IF EXISTS public.custom_access_token_hook(jsonb);