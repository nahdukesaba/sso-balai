CREATE TABLE public.applications (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    code text NOT NULL,
    name text NOT NULL,
    is_active boolean NOT NULL DEFAULT true,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),

    CONSTRAINT uq_applications_code
        UNIQUE (code),

    CONSTRAINT chk_applications_code_not_blank
        CHECK (btrim(code) <> ''),

    CONSTRAINT chk_applications_name_not_blank
        CHECK (btrim(name) <> '')
);

CREATE TRIGGER trg_applications_updated_at
    BEFORE UPDATE ON public.applications
    FOR EACH ROW
    EXECUTE FUNCTION public.sso_set_updated_at();


CREATE TABLE public.app_memberships (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    app_user_id uuid NOT NULL,
    application_id uuid NOT NULL,

    role text NOT NULL,
    status text NOT NULL,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,

    CONSTRAINT fk_app_memberships_app_user
        FOREIGN KEY (app_user_id)
        REFERENCES public.app_users(id)
        ON DELETE RESTRICT,

    CONSTRAINT fk_app_memberships_application
        FOREIGN KEY (application_id)
        REFERENCES public.applications(id)
        ON DELETE RESTRICT,

    CONSTRAINT uq_app_memberships_user_application
        UNIQUE (app_user_id, application_id),

    CONSTRAINT chk_app_memberships_role_not_blank
        CHECK (btrim(role) <> ''),

    CONSTRAINT chk_app_memberships_status
        CHECK (
            status IN (
                'pending',
                'approved',
                'rejected',
                'disabled'
            )
        )
);

CREATE INDEX idx_app_memberships_app_user
    ON public.app_memberships (app_user_id);

CREATE INDEX idx_app_memberships_application
    ON public.app_memberships (application_id);

CREATE INDEX idx_app_memberships_application_status
    ON public.app_memberships (application_id, status)
    WHERE deleted_at IS NULL;

CREATE TRIGGER trg_app_memberships_updated_at
    BEFORE UPDATE ON public.app_memberships
    FOR EACH ROW
    EXECUTE FUNCTION public.sso_set_updated_at();


-- Registered applications.
INSERT INTO public.applications (code, name)
VALUES
    ('silapet', 'SILAPET'),
    ('klinik_pkp', 'Klinik PKP'),
    ('arsiparis', 'Arsiparis');


-- Backfill legacy SILAPET memberships.
--
-- Current production evidence shows that existing central identities linked
-- to klinikpkp_user are identities created through the Klinik migration path.
-- The Klinik migration refuses to reuse an existing app_users identity, so
-- these linked identities are excluded from the legacy SILAPET backfill.
INSERT INTO public.app_memberships (
    app_user_id,
    application_id,
    role,
    status
)
SELECT
    au.id,
    app.id,
    au.role,
    au.status
FROM public.app_users au
CROSS JOIN public.applications app
WHERE app.code = 'silapet'
  AND au.deleted_at IS NULL
  AND NOT EXISTS (
      SELECT 1
      FROM public.klinikpkp_user ku
      WHERE ku.app_user_id = au.id
  );


-- Backfill Klinik PKP memberships.
INSERT INTO public.app_memberships (
    app_user_id,
    application_id,
    role,
    status
)
SELECT
    au.id,
    app.id,
    COALESCE(NULLIF(btrim(ku.role), ''), 'user'),
    CASE
        WHEN COALESCE(ku.is_active, false) = true
             AND ku.deleted_at IS NULL
            THEN 'approved'
        ELSE 'disabled'
    END
FROM public.klinikpkp_user ku
JOIN public.app_users au
    ON au.id = ku.app_user_id
CROSS JOIN public.applications app
WHERE app.code = 'klinik_pkp'
  AND ku.app_user_id IS NOT NULL
  AND au.deleted_at IS NULL;
