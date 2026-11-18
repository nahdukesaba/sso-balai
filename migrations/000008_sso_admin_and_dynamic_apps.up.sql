ALTER TABLE public.app_users
    ADD COLUMN IF NOT EXISTS is_sso_admin boolean NOT NULL DEFAULT false;

ALTER TABLE public.applications
    ADD COLUMN IF NOT EXISTS client_id text,
    ADD COLUMN IF NOT EXISTS access_policy text NOT NULL DEFAULT 'AUTO_USER',
    ADD COLUMN IF NOT EXISTS redirect_uris text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS post_logout_redirect_uris text[] NOT NULL DEFAULT '{}',
    ADD COLUMN IF NOT EXISTS launch_url text NOT NULL DEFAULT '',
    ADD COLUMN IF NOT EXISTS description text NOT NULL DEFAULT '';

CREATE UNIQUE INDEX IF NOT EXISTS uq_applications_client_id
    ON public.applications (client_id)
    WHERE client_id IS NOT NULL AND btrim(client_id) <> '';

UPDATE public.applications
SET
    client_id = COALESCE(NULLIF(client_id, ''), 'silapet-web'),
    access_policy = 'AUTO_USER',
    redirect_uris = CASE WHEN array_length(redirect_uris, 1) IS NULL THEN ARRAY['https://silapet.bp3kpsumatera2.com/auth/sso/callback'] ELSE redirect_uris END,
    post_logout_redirect_uris = CASE WHEN array_length(post_logout_redirect_uris, 1) IS NULL THEN ARRAY['https://silapet.bp3kpsumatera2.com/'] ELSE post_logout_redirect_uris END,
    launch_url = CASE WHEN launch_url = '' THEN 'https://silapet.bp3kpsumatera2.com/' ELSE launch_url END,
    description = CASE WHEN description = '' THEN 'Portal layanan peminjaman fasilitas sarana, prasarana, serta kendaraan operasional resmi BP3KP Sumatera II' ELSE description END
WHERE code = 'silapet';

UPDATE public.applications
SET
    client_id = COALESCE(NULLIF(client_id, ''), 'klinik-pkp-web'),
    access_policy = 'AUTO_USER',
    redirect_uris = CASE WHEN array_length(redirect_uris, 1) IS NULL THEN ARRAY['https://klinikpkp.bp3kpsumatera2.com/auth/sso/callback'] ELSE redirect_uris END,
    post_logout_redirect_uris = CASE WHEN array_length(post_logout_redirect_uris, 1) IS NULL THEN ARRAY['https://klinikpkp.bp3kpsumatera2.com/'] ELSE post_logout_redirect_uris END,
    launch_url = CASE WHEN launch_url = '' THEN 'https://klinikpkp.bp3kpsumatera2.com/' ELSE launch_url END,
    description = CASE WHEN description = '' THEN 'Portal layanan informasi, konsultasi, dan pendampingan teknis perumahan serta permukiman BP3KP Sumatera II' ELSE description END
WHERE code = 'klinik_pkp';

UPDATE public.applications
SET
    client_id = COALESCE(NULLIF(client_id, ''), 'sijabu-landing-web'),
    access_policy = 'AUTO_USER',
    redirect_uris = CASE WHEN array_length(redirect_uris, 1) IS NULL THEN ARRAY['https://bp3kpsumatera2.com/auth/sso/callback','https://www.bp3kpsumatera2.com/auth/sso/callback','http://localhost:8080/auth/sso/callback'] ELSE redirect_uris END,
    post_logout_redirect_uris = CASE WHEN array_length(post_logout_redirect_uris, 1) IS NULL THEN ARRAY['https://bp3kpsumatera2.com/','https://www.bp3kpsumatera2.com/','http://localhost:8080/'] ELSE post_logout_redirect_uris END,
    launch_url = CASE WHEN launch_url = '' THEN 'https://bp3kpsumatera2.com/' ELSE launch_url END,
    description = CASE WHEN description = '' THEN 'Portal layanan informasi perumahan, pengaduan masyarakat, dan akses pegawai BP3KP Sumatera II' ELSE description END
WHERE code = 'sijabu';
