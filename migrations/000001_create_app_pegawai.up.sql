CREATE TABLE IF NOT EXISTS public.app_pegawai (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),

    app_user_id uuid NOT NULL,

    nip text,
    nik text,

    alamat text,
    gelar_depan text,
    gelar_belakang text,

    created_at timestamptz NOT NULL DEFAULT now(),
    updated_at timestamptz NOT NULL DEFAULT now(),
    deleted_at timestamptz,

    CONSTRAINT uq_app_pegawai_app_user
        UNIQUE (app_user_id),

    CONSTRAINT uq_app_pegawai_nip
        UNIQUE (nip),

    CONSTRAINT uq_app_pegawai_nik
        UNIQUE (nik),

    CONSTRAINT fk_app_pegawai_app_user
        FOREIGN KEY (app_user_id)
        REFERENCES public.app_users(id)
        ON DELETE RESTRICT
);

CREATE OR REPLACE FUNCTION public.sso_set_updated_at()
RETURNS TRIGGER AS $$
BEGIN
    NEW.updated_at = now();
    RETURN NEW;
END;
$$ LANGUAGE plpgsql;

DROP TRIGGER IF EXISTS trg_app_pegawai_updated_at
ON public.app_pegawai;

CREATE TRIGGER trg_app_pegawai_updated_at
    BEFORE UPDATE ON public.app_pegawai
    FOR EACH ROW
    EXECUTE FUNCTION public.sso_set_updated_at();