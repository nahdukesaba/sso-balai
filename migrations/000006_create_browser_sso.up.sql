CREATE TABLE public.sso_browser_sessions (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    token_hash bytea NOT NULL UNIQUE,
    auth_user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    app_user_id uuid NOT NULL REFERENCES public.app_users(id) ON DELETE CASCADE,
    created_at timestamptz NOT NULL DEFAULT now(),
    expires_at timestamptz NOT NULL,
    last_seen_at timestamptz NOT NULL DEFAULT now(),
    revoked_at timestamptz
);

CREATE INDEX idx_sso_browser_sessions_active
    ON public.sso_browser_sessions (token_hash, expires_at)
    WHERE revoked_at IS NULL;

CREATE TABLE public.sso_authorization_codes (
    code_hash bytea PRIMARY KEY,
    browser_session_id uuid NOT NULL
        REFERENCES public.sso_browser_sessions(id) ON DELETE CASCADE,
    client_id text NOT NULL,
    auth_user_id uuid NOT NULL REFERENCES auth.users(id) ON DELETE CASCADE,
    app_user_id uuid NOT NULL REFERENCES public.app_users(id) ON DELETE CASCADE,
    redirect_uri text NOT NULL,
    code_challenge text NOT NULL,
    expires_at timestamptz NOT NULL,
    used_at timestamptz,
    created_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_sso_authorization_client_id CHECK (btrim(client_id) <> ''),
    CONSTRAINT chk_sso_authorization_redirect_uri CHECK (btrim(redirect_uri) <> ''),
    CONSTRAINT chk_sso_authorization_challenge CHECK (btrim(code_challenge) <> '')
);

CREATE INDEX idx_sso_authorization_codes_expiry
    ON public.sso_authorization_codes (expires_at)
    WHERE used_at IS NULL;
