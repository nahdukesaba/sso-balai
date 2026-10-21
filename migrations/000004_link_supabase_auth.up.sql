-- Link internal SSO identities to Supabase Auth identities.
--
-- Existing users that were originally created through Supabase Auth already
-- use the same UUID in auth.users and public.app_users. We preserve app_users.id
-- as the internal application identity and store the Supabase identity
-- explicitly for future users whose UUID may differ.

ALTER TABLE public.app_users
ADD COLUMN IF NOT EXISTS auth_user_id uuid;

-- Safe backfill:
-- only link identities whose UUID already exists in auth.users.
UPDATE public.app_users au
SET auth_user_id = su.id
FROM auth.users su
WHERE au.id = su.id
  AND au.auth_user_id IS NULL;

-- One Supabase identity may map to only one Central SSO identity.
CREATE UNIQUE INDEX IF NOT EXISTS uq_app_users_auth_user_id
ON public.app_users (auth_user_id)
WHERE auth_user_id IS NOT NULL;

-- Keep the relationship explicit.
ALTER TABLE public.app_users
DROP CONSTRAINT IF EXISTS fk_app_users_auth_user;

ALTER TABLE public.app_users
ADD CONSTRAINT fk_app_users_auth_user
FOREIGN KEY (auth_user_id)
REFERENCES auth.users(id)
ON DELETE SET NULL;