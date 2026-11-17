ALTER TABLE public.sso_authorization_codes
    DROP COLUMN IF EXISTS scope,
    DROP COLUMN IF EXISTS nonce;
