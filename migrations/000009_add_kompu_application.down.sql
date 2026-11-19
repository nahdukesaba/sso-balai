-- Fails on purpose (FK ON DELETE RESTRICT) while memberships or audit events
-- still reference Kompu, so a rollback never drops user access silently.
DELETE FROM public.applications
WHERE code = 'kompu';
