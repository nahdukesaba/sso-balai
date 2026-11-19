ALTER TABLE public.applications
    ADD COLUMN IF NOT EXISTS port integer,
    ADD COLUMN IF NOT EXISTS backend_port integer;

DO $$
BEGIN
    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_applications_port_range'
    ) THEN
        ALTER TABLE public.applications
            ADD CONSTRAINT chk_applications_port_range
            CHECK (port IS NULL OR (port > 0 AND port <= 65535));
    END IF;

    IF NOT EXISTS (
        SELECT 1 FROM pg_constraint WHERE conname = 'chk_applications_backend_port_range'
    ) THEN
        ALTER TABLE public.applications
            ADD CONSTRAINT chk_applications_backend_port_range
            CHECK (backend_port IS NULL OR (backend_port > 0 AND backend_port <= 65535));
    END IF;
END $$;

COMMENT ON COLUMN public.applications.port IS 'Frontend / Web UI port for local development (e.g. 3000, 3001, 3002, 3003)';
COMMENT ON COLUMN public.applications.backend_port IS 'Backend API service port for local development (e.g. 8080, 8081, 8083)';

-- Populate ports according to local development configuration:
-- BE Klinik PKP: 8080, FE Klinik: 3000
UPDATE public.applications
SET
    port = 3000,
    backend_port = 8080
WHERE code = 'klinik_pkp';

-- BE Silapet: 8081, FE Silapet: 3001
UPDATE public.applications
SET
    port = 3001,
    backend_port = 8081
WHERE code = 'silapet';

-- BE Kompu: 8083, FE Kompu: 3003
UPDATE public.applications
SET
    port = 3003,
    backend_port = 8083
WHERE code = 'kompu';

-- Sijabu: 3002 (Landing)
UPDATE public.applications
SET
    port = 3002,
    backend_port = NULL
WHERE code = 'sijabu';

-- BE Arsiparis: 8084, FE Arsiparis: 3004
UPDATE public.applications
SET
    port = 3004,
    backend_port = 8084
WHERE code = 'arsiparis';
