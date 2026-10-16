CREATE TABLE public.auth_credentials (
    app_user_id UUID PRIMARY KEY,

    password_hash TEXT NOT NULL,
    password_algorithm TEXT NOT NULL DEFAULT 'bcrypt',

    must_change_password BOOLEAN NOT NULL DEFAULT FALSE,

    failed_attempts INTEGER NOT NULL DEFAULT 0,
    locked_until TIMESTAMPTZ,

    password_changed_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_auth_credentials_app_user
        FOREIGN KEY (app_user_id)
        REFERENCES public.app_users(id)
        ON DELETE CASCADE,

    CONSTRAINT chk_auth_credentials_password_hash_not_blank
        CHECK (BTRIM(password_hash) <> ''),

    CONSTRAINT chk_auth_credentials_password_algorithm
        CHECK (
            password_algorithm IN (
                'bcrypt',
                'argon2id'
            )
        ),

    CONSTRAINT chk_auth_credentials_failed_attempts
        CHECK (failed_attempts >= 0)
);


CREATE TABLE public.auth_sessions (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    app_user_id UUID NOT NULL,
    application_id UUID NOT NULL,

    refresh_token_hash TEXT NOT NULL,

    expires_at TIMESTAMPTZ NOT NULL,
    last_used_at TIMESTAMPTZ,

    revoked_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_auth_sessions_app_user
        FOREIGN KEY (app_user_id)
        REFERENCES public.app_users(id)
        ON DELETE CASCADE,

    CONSTRAINT fk_auth_sessions_application
        FOREIGN KEY (application_id)
        REFERENCES public.applications(id)
        ON DELETE RESTRICT,

    CONSTRAINT uq_auth_sessions_refresh_token_hash
        UNIQUE (refresh_token_hash),

    CONSTRAINT chk_auth_sessions_refresh_token_hash_not_blank
        CHECK (BTRIM(refresh_token_hash) <> '')
);


CREATE INDEX idx_auth_sessions_app_user
    ON public.auth_sessions(app_user_id);

CREATE INDEX idx_auth_sessions_application
    ON public.auth_sessions(application_id);

CREATE INDEX idx_auth_sessions_active_user
    ON public.auth_sessions(app_user_id, revoked_at);


CREATE TABLE public.password_reset_tokens (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),

    app_user_id UUID NOT NULL,

    token_hash TEXT NOT NULL,

    expires_at TIMESTAMPTZ NOT NULL,
    used_at TIMESTAMPTZ,

    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),

    CONSTRAINT fk_password_reset_tokens_app_user
        FOREIGN KEY (app_user_id)
        REFERENCES public.app_users(id)
        ON DELETE CASCADE,

    CONSTRAINT uq_password_reset_tokens_hash
        UNIQUE (token_hash),

    CONSTRAINT chk_password_reset_tokens_hash_not_blank
        CHECK (BTRIM(token_hash) <> '')
);


CREATE INDEX idx_password_reset_tokens_app_user
    ON public.password_reset_tokens(app_user_id);

CREATE INDEX idx_password_reset_tokens_user_used
    ON public.password_reset_tokens(app_user_id, used_at);
