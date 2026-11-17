-- OpenID Connect: keep the nonce and scope from /authorize until /oauth/token.
ALTER TABLE public.sso_authorization_codes
    ADD COLUMN nonce text NOT NULL DEFAULT '',
    ADD COLUMN scope text NOT NULL DEFAULT '';
