ALTER TABLE public.app_users
DROP CONSTRAINT IF EXISTS fk_app_users_auth_user;

DROP INDEX IF EXISTS public.uq_app_users_auth_user_id;

ALTER TABLE public.app_users
DROP COLUMN IF EXISTS auth_user_id;