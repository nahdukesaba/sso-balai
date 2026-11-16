-- Browser SSO client registry: one row per application that signs in through
-- Central. Register or update rows with `go run ./cmd/sso-client`.
CREATE TABLE public.sso_clients (
    client_id text PRIMARY KEY,
    application_id uuid NOT NULL UNIQUE
        REFERENCES public.applications(id) ON DELETE RESTRICT,
    access_policy text NOT NULL DEFAULT 'RESTRICTED',
    -- SHA-256 of the introspection secret; the secret itself is never stored.
    introspection_secret_hash bytea NOT NULL,
    redirect_uris text[] NOT NULL,
    post_logout_redirect_uris text[] NOT NULL,
    launch_url text NOT NULL DEFAULT '',
    description text NOT NULL DEFAULT '',
    is_active boolean NOT NULL DEFAULT true,
    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    CONSTRAINT chk_sso_clients_client_id CHECK (btrim(client_id) <> ''),
    CONSTRAINT chk_sso_clients_access_policy
        CHECK (access_policy IN ('AUTO_USER', 'RESTRICTED')),
    CONSTRAINT chk_sso_clients_secret_hash
        CHECK (octet_length(introspection_secret_hash) = 32),
    CONSTRAINT chk_sso_clients_redirect_uris CHECK (cardinality(redirect_uris) > 0),
    CONSTRAINT chk_sso_clients_post_logout_uris
        CHECK (cardinality(post_logout_redirect_uris) > 0)
);

CREATE TRIGGER trg_sso_clients_updated_at
    BEFORE UPDATE ON public.sso_clients
    FOR EACH ROW
    EXECUTE FUNCTION public.sso_set_updated_at();

-- No policies: Supabase Data API roles cannot read the registry; the server
-- connects as the table owner, which RLS does not restrict.
ALTER TABLE public.sso_clients ENABLE ROW LEVEL SECURITY;
