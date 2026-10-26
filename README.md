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
| `SSO_KLINIK_CLIENT_ID` | Klinik `SSO_CLIENT_ID` |
| `SSO_KLINIK_INTROSPECTION_SECRET` | Klinik `SSO_INTROSPECTION_SECRET` |
| `SSO_SILAPET_CLIENT_ID` | SILAPET API `SSO_CLIENT_ID` |
| `SSO_SILAPET_INTROSPECTION_SECRET` | SILAPET API `SSO_INTROSPECTION_SECRET` |
| Central berjalan di `http://127.0.0.1:18082` | `SSO_BASE_URL=http://127.0.0.1:18082` |

Aturan penting:

- `SSO_*_REDIRECT_URIS` di Central harus sama persis dengan redirect URI yang dikirim aplikasi.
- `SSO_*_POST_LOGOUT_REDIRECT_URIS` harus sama persis dengan post-logout URI aplikasi.
- `PORTAL_*_LAUNCH_URL` menunjuk endpoint start SSO milik aplikasi, bukan langsung ke halaman dashboard.
- Setelah mengubah `.env`, restart service terkait.

Contoh URL lokal sudah tersedia pada `.env.example`. Sesuaikan port jika aplikasi mentor berjalan pada port berbeda, tetapi ubah kedua sisi secara bersamaan.

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
- Browser SSO gagal saat startup: periksa session key, kedua introspection secret, redirect URI, post-logout URI, dan launch URL.
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
