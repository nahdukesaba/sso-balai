# SSO Balai

Central SSO untuk akun pegawai BP3KP Sumatera II. Service ini menangani autentikasi Supabase, portal akun, pemulihan password, undangan pengguna, Browser SSO, dan otorisasi aplikasi seperti Klinik PKP dan SILAPET.

## Komponen

- Go dan Fiber sebagai API serta server halaman akun.
- PostgreSQL/Supabase sebagai database identitas dan membership aplikasi.
- Supabase Auth sebagai penyedia autentikasi dan pengirim email.
- Browser SSO berbasis authorization code, PKCE, dan cookie `HttpOnly`.

## Menjalankan di lokal

### 1. Prasyarat

Siapkan:

- Git.
- Go sesuai versi pada `go.mod`.
- Akses ke project Supabase non-production untuk pengujian.
- Connection string PostgreSQL project tersebut.
- PowerShell jika menggunakan Windows.
- Node.js/npm jika Klinik PKP dan frontend SILAPET ikut dijalankan.

Jangan menjalankan migrasi atau seed terhadap database production untuk pengujian lokal.

### 2. Ambil source terbaru

```powershell
git clone git@github.com:nahdukesaba/sso-balai.git
Set-Location sso-balai
git switch main
git pull --ff-only origin main
go mod download
```

Semua perintah berikut dijalankan dari root repository `sso-balai` karena aplikasi membaca `.env` dan folder `migrations` dari working directory tersebut.

### 3. Buat konfigurasi lokal

```powershell
Copy-Item .env.example .env
```

Isi nilai berikut di `.env` menggunakan project Supabase yang sama untuk Auth dan PostgreSQL:

```dotenv
APP_HOST=127.0.0.1
APP_PORT=18082

DATABASE_URL=postgres://...
SUPABASE_URL=https://PROJECT_REF.supabase.co
SUPABASE_PUBLISHABLE_KEY=...
SUPABASE_SECRET_KEY=...

PASSWORD_RECOVERY_REDIRECT_URL=http://127.0.0.1:18082/reset-password
SUPABASE_INVITE_REDIRECT_URL=http://127.0.0.1:18082/accept-invite

SSO_BROWSER_ENABLED=true
SSO_BROWSER_SESSION_KEY=BASE64_32_BYTE_KEY
SSO_BROWSER_COOKIE_SECURE=false
SSO_BROWSER_COOKIE_SAME_SITE=Lax

# Input untuk `go run ./cmd/sso-client`, tidak dibaca API.
SSO_SILAPET_INTROSPECTION_SECRET=MINIMUM_32_CHARACTER_SECRET
SSO_KLINIK_INTROSPECTION_SECRET=MINIMUM_32_CHARACTER_SECRET
```

Keterangan penting:

- Gunakan `SUPABASE_PUBLISHABLE_KEY` dan `SUPABASE_SECRET_KEY` yang direkomendasikan Supabase. Variabel key lama pada `.env.example` hanya fallback.
- `SUPABASE_SECRET_KEY` adalah secret server dan tidak boleh masuk frontend atau Git.
- `SSO_BROWSER_COOKIE_SECURE=false` hanya untuk pengembangan melalui HTTP lokal. Production harus menggunakan `true`.
- Kedua introspection secret harus berbeda, minimal 32 karakter, dan harus sama persis dengan secret pada backend aplikasi pasangannya.
- Jangan commit file `.env`.

Untuk membuat secret base64 32 byte di PowerShell:

```powershell
$bytes = New-Object byte[] 32
$rng = [System.Security.Cryptography.RandomNumberGenerator]::Create()
$rng.GetBytes($bytes)
[Convert]::ToBase64String($bytes)
$rng.Dispose()
```

Jalankan ulang perintah tersebut untuk setiap secret yang berbeda.

### 4. Konfigurasi URL dan email Supabase

Pada Supabase Dashboard untuk project yang digunakan:

1. Buka **Authentication > URL Configuration**.
2. Tambahkan redirect URL lokal berikut:
   - `http://127.0.0.1:18082/reset-password`
   - `http://127.0.0.1:18082/accept-invite`
3. Buka **Authentication > Email Templates**.
4. Pastikan template **Invite user** tetap menggunakan `{{ .ConfirmationURL }}`.
5. Pastikan template **Reset password** membentuk link menuju `{{ .RedirectTo }}` dengan `token_hash` dan `type=recovery`.
6. Konfigurasikan SMTP project jika email undangan/reset perlu benar-benar diterima saat pengujian.

Nilai redirect pada Dashboard dan `.env` harus sama. Jika menggunakan domain `sso-balai.test` untuk link email, daftarkan dan gunakan domain tersebut secara konsisten sebagai pengganti `127.0.0.1`.

### 5. Jalankan migrasi database

Cek versi lalu terapkan seluruh migrasi:

```powershell
go run ./cmd/migrate version
go run ./cmd/migrate up
go run ./cmd/migrate version
```

Migrasi membuat tabel identitas, membership aplikasi, Browser SSO, serta fungsi `public.custom_access_token_hook`.

Setelah migrasi selesai, buka **Authentication > Hooks** pada Supabase Dashboard dan aktifkan **Custom Access Token** menggunakan Postgres function:

```text
public.custom_access_token_hook
```

Jangan menjalankan `go run ./cmd/migrate down` kecuali memang ingin membatalkan satu migrasi dan sudah memahami dampak penghapusan skemanya.

#### Daftarkan aplikasi Browser SSO

Daftar aplikasi SSO disimpan di tabel `public.sso_clients`, bukan di `.env`. Jika `SSO_BROWSER_ENABLED=true`, API menolak start bila tabel ini kosong. Daftarkan aplikasi yang sudah ada:

```powershell
go run ./cmd/sso-client `
  -client-id silapet-web -app silapet -access-policy AUTO_USER `
  -redirect-uris http://silapet.test:8080/auth/sso/callback `
  -post-logout-uris http://silapet.test:8080/login `
  -launch-url http://silapet.test:8081/api/auth/sso/start `
  -description "Portal layanan peminjaman fasilitas sarana, prasarana, serta kendaraan operasional resmi BP3KP Sumatera II" `
  -secret-env SSO_SILAPET_INTROSPECTION_SECRET
```

```powershell
go run ./cmd/sso-client `
  -client-id klinik-pkp-web -app klinik_pkp -access-policy AUTO_USER `
  -redirect-uris http://klinik-pkp.test:3000/auth/sso/callback `
  -post-logout-uris http://klinik-pkp.test:3000/login `
  -launch-url http://klinik-pkp.test:3000/api/auth/sso/start `
  -description "Portal layanan informasi, konsultasi, dan pendampingan teknis perumahan serta permukiman BP3KP Sumatera II" `
  -secret-env SSO_KLINIK_INTROSPECTION_SECRET
```

Menambah sistem baru tidak perlu mengubah kode. Simpan secret-nya di `.env` (misalnya `SSO_EOFFICE_INTROSPECTION_SECRET=...`, minimal 32 karakter), lalu jalankan perintah yang sama dengan `-name` agar baris `applications` ikut dibuat:

```powershell
go run ./cmd/sso-client `
  -client-id eoffice-web -app eoffice -name "E-Office" -access-policy AUTO_USER `
  -redirect-uris https://eoffice.example/auth/sso/callback `
  -post-logout-uris https://eoffice.example/login `
  -launch-url https://eoffice.example/api/auth/sso/start `
  -secret-env SSO_EOFFICE_INTROSPECTION_SECRET
```

Perintah dengan `-client-id` yang sudah ada akan memperbarui datanya. Hanya hash SHA-256 secret yang disimpan. Restart API setelah mendaftarkan atau mengubah aplikasi. `AUTO_USER`: pengguna boleh mendaftar atau meminta akses sendiri, lalu status `pending` sampai admin menyetujui. `RESTRICTED`: tidak ada pendaftaran mandiri; akses hanya lewat undangan/provisioning admin.

#### Aktifkan OpenID Connect (opsional, disarankan untuk aplikasi baru)

Dengan OIDC, aplikasi baru cukup memakai library "Generic OpenID Connect" (Auth.js, Laravel Socialite, Spring Security, `coreos/go-oidc`, dan lain-lain), sama seperti memasang "Login with Google". Buat kunci tanda tangan RSA sekali (Git Bash menyediakan `openssl`):

```bash
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out oidc-signing-key.pem
```

Lalu isi `.env`:

```dotenv
SSO_OIDC_ISSUER=http://sso-balai.test:18082
SSO_OIDC_SIGNING_KEY_FILE=oidc-signing-key.pem
```

`*.pem` sudah diabaikan Git. Jangan pernah membagikan file ini; aplikasi hanya membutuhkan kunci publik yang tersedia di `/.well-known/jwks.json`. Mengganti kunci membuat token lama tidak bisa diverifikasi, jadi lakukan hanya saat perlu.

### 6. Buat akun bootstrap bila diperlukan

Untuk database baru, isi sementara bagian berikut pada `.env`:

```dotenv
BOOTSTRAP_USER_EMAIL=admin@example.com
BOOTSTRAP_USER_PASSWORD=PASSWORD_YANG_KUAT
BOOTSTRAP_USER_NAME=Administrator
BOOTSTRAP_USER_ROLE=admin
```

Kemudian jalankan:

```powershell
go run ./cmd/seed
```

Seed membuat atau mencocokkan akun Supabase Auth dengan profil Central. Proses akan berhenti jika menemukan identitas yang konflik dan tidak akan menaikkan role akun lama secara diam-diam. Setelah selesai, hapus nilai password bootstrap dari `.env` jika tidak lagi diperlukan.

### 7. Tambahkan domain lokal

Jalankan editor sebagai Administrator dan tambahkan baris berikut ke `C:\Windows\System32\drivers\etc\hosts`:

```text
127.0.0.1 sso-balai.test
127.0.0.1 klinik-pkp.test
127.0.0.1 silapet.test
```

`sso-balai.test` digunakan untuk portal yang mudah dibaca. Domain Klinik dan SILAPET diperlukan hanya jika integrasi aplikasi tersebut ikut diuji.

### 8. Jalankan Central SSO

Verifikasi kode terlebih dahulu:

```powershell
go test -count=1 ./...
go build ./...
```

Kemudian hidupkan service:

```powershell
go run ./cmd/api
```

Endpoint lokal:

- Health check: `http://127.0.0.1:18082/health`
- Portal akun: `http://sso-balai.test:18082/`
- Lupa password: `http://sso-balai.test:18082/forgot-password`
- Aktivasi undangan: `/accept-invite` melalui link email Supabase.
- Reset password: `/reset-password` melalui link email Supabase.

Cek health dari PowerShell:

```powershell
Invoke-RestMethod http://127.0.0.1:18082/health
```

Respons yang diharapkan:

```json
{
  "status": "ok",
  "service": "sso-balai",
  "database": "connected"
}
```

## Integrasi Klinik PKP dan SILAPET

Bagian ini opsional jika hanya ingin memeriksa Central SSO. Untuk menguji tombol **Buka Aplikasi**, login SSO, dan coordinated logout, hidupkan aplikasi pasangan juga.

Pastikan repository `sso-balai`, `klinik-pkp`, `office-craft-api`, dan `office-craft` sudah tersedia sebagai folder sejajar, serta masing-masing berada pada branch yang memang akan diuji.

### Nilai yang harus cocok

| Central SSO | Aplikasi pasangan |
| --- | --- |
| `-client-id` saat registrasi `cmd/sso-client` | Aplikasi `SSO_CLIENT_ID` |
| Secret yang ditunjuk `-secret-env` | Aplikasi `SSO_INTROSPECTION_SECRET` |
| Central berjalan di `http://127.0.0.1:18082` | `SSO_BASE_URL=http://127.0.0.1:18082` |

Aturan penting:

- `-redirect-uris` harus sama persis dengan redirect URI yang dikirim aplikasi.
- `-post-logout-uris` harus sama persis dengan post-logout URI aplikasi.
- `-launch-url` menunjuk endpoint start SSO milik aplikasi, bukan langsung ke halaman dashboard.
- Setelah mendaftarkan ulang aplikasi atau mengubah `.env`, restart service terkait.

Contoh URL lokal sudah tersedia pada `.env.example`. Sesuaikan port jika aplikasi mentor berjalan pada port berbeda, tetapi ubah kedua sisi secara bersamaan.

### Menghubungkan aplikasi baru lewat OIDC

1. Daftarkan aplikasi dengan `go run ./cmd/sso-client` (lihat bagian registrasi di atas).
2. Di aplikasi, buat provider OIDC generik dengan nilai berikut:

| Pengaturan di aplikasi | Nilai |
| --- | --- |
| Issuer / discovery URL | `SSO_OIDC_ISSUER` (discovery: `<issuer>/.well-known/openid-configuration`) |
| Client ID | `-client-id` yang didaftarkan |
| Client secret | Secret yang ditunjuk `-secret-env` |
| Redirect URI | Salah satu `-redirect-uris` |
| Scope | `openid email profile` |
| PKCE | Wajib, metode `S256` |
| Autentikasi client | `client_secret_basic` atau `client_secret_post` |

`id_token` berisi `sub` (ID pengguna Central), `email`, `name`, `sid` (sesi Central), dan `app_role` (role pengguna di aplikasi tersebut). Untuk logout, arahkan ke `end_session_endpoint` (`/logout`) dengan `post_logout_redirect_uri` dan `id_token_hint` atau `client_id`. Untuk mengecek apakah sesi Central masih aktif, panggil `userinfo_endpoint` dengan access token; logout Central langsung membuatnya ditolak.

### Pendaftaran dan persetujuan akses

sso-balai adalah satu-satunya tempat login dan daftar. Aplikasi tidak lagi punya form password sendiri.

1. Tombol **Masuk** di aplikasi mengarah ke `/authorize` seperti biasa.
2. Tombol **Daftar** di aplikasi mengarah ke `/authorize` yang sama ditambah `prompt=create`. sso-balai langsung membuka form daftar (`/account/register`). Form login juga menampilkan tautan "Belum punya akun? Daftar".
3. Pendaftaran membuat Akun Balai dan permintaan akses `pending` untuk aplikasi itu, lalu kembali ke aplikasi dengan `status=pending`. Aplikasi cukup menampilkan "Menunggu persetujuan admin".
4. Admin membuka `/admin` (tombol **Kelola Akses** di portal) untuk menyetujui, menolak, mengganti role (`user`/`admin`), atau menonaktifkan akses. Setiap perubahan dicatat di `app_audit_events`.
5. Setelah disetujui, login berikutnya langsung masuk ke aplikasi.

Siapa yang bisa membuka `/admin`:

- Admin Central (`app_users.role = 'admin'`, misalnya akun bootstrap) mengelola semua aplikasi.
- Admin aplikasi (membership `role = admin` dan `approved`) hanya mengelola aplikasinya sendiri.
- Tidak ada admin yang bisa mengubah akses miliknya sendiri.

Pendaftaran hanya tersedia untuk aplikasi dengan `-access-policy AUTO_USER`. Akun yang mendaftar sendiri belum memverifikasi kepemilikan email, jadi admin perlu memastikan pemohon sebelum menyetujui.

### Urutan menjalankan seluruh stack

Gunakan terminal terpisah untuk setiap service:

1. Central SSO:

   ```powershell
   Set-Location sso-balai
   go run ./cmd/api
   ```

2. SILAPET API:

   ```powershell
   Set-Location office-craft-api
   go run ./cmd/server
   ```

3. SILAPET frontend:

   ```powershell
   Set-Location office-craft
   npm install
   npm run dev -- --port 8081
   ```

4. Klinik PKP:

   ```powershell
   Set-Location klinik-pkp
   npm install
   npm run dev
   ```

Urutan paling aman adalah database/Supabase, Central SSO, backend aplikasi, lalu frontend aplikasi.

## Checklist pengujian lokal

- `/health` mengembalikan status `ok`.
- Portal Central dapat dibuka dan login menggunakan akun bootstrap/test.
- Reload tetap mempertahankan sesi Central.
- Forgot password mengirim email dan kembali ke `/reset-password` lokal.
- Invite user mengirim email dan kembali ke `/accept-invite` lokal.
- Aplikasi dengan membership `approved` memiliki tombol **Buka Aplikasi**.
- Membership `pending`, `rejected`, `disabled`, atau tidak tersedia tidak dapat diluncurkan.
- Login SSO Klinik dan SILAPET kembali ke callback yang benar.
- Logout SSO membatalkan sesi Central; tombol batal tidak menghapus sesi.
- Login langsung pada aplikasi tidak ikut keluar karena logout Central.

## Troubleshooting singkat

- `DATABASE_URL is required`: `.env` tidak ditemukan atau connection string belum diisi.
- Browser SSO gagal saat startup: periksa session key dan pastikan migrasi `000008` sudah jalan serta `public.sso_clients` berisi aplikasi aktif (`go run ./cmd/sso-client`).
- Cookie login tidak tersimpan di lokal: pastikan `SSO_BROWSER_COOKIE_SECURE=false` selama menggunakan HTTP.
- Email menuju URL yang salah: samakan `.env`, Supabase URL Configuration, dan email template.
- Tombol **Buka Aplikasi** tidak muncul: membership harus `approved` dan launch URL harus valid.
- `Access is denied` pada Go cache Windows: gunakan cache lokal sementara:

  ```powershell
  $env:GOCACHE = "$PWD\.gocache-local"
  go test -count=1 ./...
  go build ./...
  ```

Dokumentasi alur Browser SSO yang lebih teknis tersedia di [docs/BROWSER_SSO.md](docs/BROWSER_SSO.md).
