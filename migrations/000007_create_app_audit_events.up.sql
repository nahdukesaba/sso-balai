BEGIN;

CREATE TABLE public.app_audit_events (
    id uuid PRIMARY KEY DEFAULT gen_random_uuid(),
    occurred_at timestamptz NOT NULL DEFAULT now(),
    actor_app_user_id uuid NOT NULL,
    source_application text NOT NULL,
    action text NOT NULL,
    entity_kind text NOT NULL,
    entity_id uuid NOT NULL,
    subject_app_user_id uuid NOT NULL,
    changed_fields text[] NOT NULL,
    before_data jsonb NOT NULL,
    after_data jsonb NOT NULL,

    CONSTRAINT fk_app_audit_events_actor
        FOREIGN KEY (actor_app_user_id)
        REFERENCES public.app_users(id)
        ON DELETE RESTRICT,
    CONSTRAINT fk_app_audit_events_source_application
        FOREIGN KEY (source_application)
        REFERENCES public.applications(code)
        ON UPDATE RESTRICT
        ON DELETE RESTRICT,
    CONSTRAINT fk_app_audit_events_subject
        FOREIGN KEY (subject_app_user_id)
        REFERENCES public.app_users(id)
        ON DELETE RESTRICT,
    CONSTRAINT chk_app_audit_events_action
        CHECK (action = 'update'),
    CONSTRAINT chk_app_audit_events_entity_kind
        CHECK (entity_kind IN ('profile', 'membership')),
    CONSTRAINT chk_app_audit_events_changed_fields
        CHECK (cardinality(changed_fields) > 0),
    CONSTRAINT chk_app_audit_events_before_object
        CHECK (jsonb_typeof(before_data) = 'object'),
    CONSTRAINT chk_app_audit_events_after_object
        CHECK (jsonb_typeof(after_data) = 'object')
);

CREATE INDEX idx_app_audit_events_subject_history
    ON public.app_audit_events (subject_app_user_id, occurred_at DESC, id DESC);

CREATE INDEX idx_app_audit_events_entity_history
    ON public.app_audit_events (entity_kind, entity_id, occurred_at DESC, id DESC);

CREATE OR REPLACE FUNCTION public.app_audit_events_reject_mutation()
RETURNS trigger
LANGUAGE plpgsql
AS $$
BEGIN
    RAISE EXCEPTION 'app_audit_events is append-only: % is prohibited', TG_OP
        USING ERRCODE = '55000';
END;
$$;

CREATE TRIGGER trg_app_audit_events_no_update_delete
    BEFORE UPDATE OR DELETE ON public.app_audit_events
    FOR EACH ROW
    EXECUTE FUNCTION public.app_audit_events_reject_mutation();

CREATE TRIGGER trg_app_audit_events_no_truncate
    BEFORE TRUNCATE ON public.app_audit_events
    FOR EACH STATEMENT
    EXECUTE FUNCTION public.app_audit_events_reject_mutation();

REVOKE UPDATE, DELETE, TRUNCATE ON public.app_audit_events FROM PUBLIC;

COMMIT;
