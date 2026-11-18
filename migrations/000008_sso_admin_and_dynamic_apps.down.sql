DROP INDEX IF EXISTS uq_applications_client_id;

ALTER TABLE public.applications
    DROP COLUMN IF EXISTS description,
    DROP COLUMN IF EXISTS launch_url,
    DROP COLUMN IF EXISTS post_logout_redirect_uris,
    DROP COLUMN IF EXISTS redirect_uris,
    DROP COLUMN IF EXISTS access_policy,
    DROP COLUMN IF EXISTS client_id;

ALTER TABLE public.app_users
    DROP COLUMN IF EXISTS is_sso_admin;
