DROP TRIGGER IF EXISTS trg_app_memberships_updated_at
ON public.app_memberships;

DROP TABLE IF EXISTS public.app_memberships;


DROP TRIGGER IF EXISTS trg_applications_updated_at
ON public.applications;

DROP TABLE IF EXISTS public.applications;
