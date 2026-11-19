ALTER TABLE public.applications
    DROP CONSTRAINT IF EXISTS chk_applications_port_range,
    DROP CONSTRAINT IF EXISTS chk_applications_backend_port_range;

ALTER TABLE public.applications
    DROP COLUMN IF EXISTS backend_port,
    DROP COLUMN IF EXISTS port;
