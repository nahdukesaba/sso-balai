-- Register Kompu so its portal card and enrollment work.
-- client_id stays NULL: the Kompu SSO client comes from SSO_KOMPU_* env vars,
-- and the dynamic loader in cmd/api skips rows without a client_id.
INSERT INTO public.applications (code, name, description)
VALUES (
    'kompu',
    'Kompu',
    'Aplikasi Kompu BP3KP Sumatera II'
)
ON CONFLICT (code) DO NOTHING;
