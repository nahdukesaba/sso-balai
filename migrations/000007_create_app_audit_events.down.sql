BEGIN;

DROP TRIGGER IF EXISTS trg_app_audit_events_no_truncate ON public.app_audit_events;
DROP TRIGGER IF EXISTS trg_app_audit_events_no_update_delete ON public.app_audit_events;
DROP FUNCTION IF EXISTS public.app_audit_events_reject_mutation();
DROP TABLE IF EXISTS public.app_audit_events;

COMMIT;
