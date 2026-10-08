DROP TRIGGER IF EXISTS trg_app_pegawai_updated_at
ON public.app_pegawai;

DROP TABLE IF EXISTS public.app_pegawai;

DROP FUNCTION IF EXISTS public.sso_set_updated_at();