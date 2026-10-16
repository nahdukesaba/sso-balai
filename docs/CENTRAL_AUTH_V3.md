# Central Auth V3

## 1. Authority

Central SSO adalah authority untuk:

- global identity
- credentials/password
- authentication
- sessions
- password lifecycle
- application membership
- application authorization

Supabase Auth bukan authentication authority permanen.

Supabase/PostgreSQL masih boleh digunakan sebagai database infrastructure.

---

## 2. Identity

`app_users` adalah global identity.

Satu `app_users.id` dapat mempunyai banyak `app_memberships`.

Contoh:

- SILAPET -> user
- Klinik PKP -> admin
- Arsiparis -> operator

Satu identity menggunakan satu global password.

Role dan status akses tetap application-scoped melalui `app_memberships`.

---

## 3. Credentials

Credential disimpan di:

`auth_credentials`

Password plaintext tidak pernah disimpan.

Initial password hashing:

`bcrypt`

Password policy awal:

- minimum 8 karakter
- maksimum 128 karakter

`password_algorithm` disimpan agar migration algoritma di masa depan tetap memungkinkan.

---

## 4. Sessions

Central SSO membuat dan mengelola session.

Session awal bersifat application-scoped.

`auth_sessions` menyimpan:

- user
- application
- hash refresh token
- expiry
- revoked status
- last use

Refresh token asli tidak disimpan di database.

Database hanya menyimpan hash refresh token.

---

## 5. Access Token

Central SSO mengeluarkan access token.

Minimum claims:

- sub = app_user UUID
- aud = application code
- sid = auth session UUID
- role = role dari app_memberships
- iat
- exp

Backend aplikasi wajib memastikan token ditujukan untuk aplikasinya.

Role tidak boleh berasal dari global `app_users.role`.

Authorization role berasal dari `app_memberships`.

---

## 6. Login

Endpoint:

POST /api/v1/auth/login

Request fields:

- email
- password
- application

Flow:

1. resolve app_user berdasarkan email
2. verify central credential
3. resolve application
4. verify approved membership
5. create auth_session
6. issue access token
7. issue refresh token

Response sebisa mungkin tetap kompatibel dengan client Klinik/SILAPET yang ada.

---

## 7. Registration

Endpoint:

POST /api/v1/auth/register

Request fields:

- email
- password
- fullName
- phone optional
- application

Untuk identity baru:

1. create app_user
2. create auth_credentials
3. create app_membership

Untuk identity yang sudah ada:

- jangan membuat global identity baru
- proses hanya membership aplikasi sesuai aturan aplikasi

Registration pada satu aplikasi tidak otomatis memberikan akses ke aplikasi lain.

---

## 8. Refresh Session

Endpoint:

POST /api/v1/auth/refresh

Request:

- refreshToken

Flow:

1. hash refresh token
2. resolve auth_session
3. reject expired/revoked session
4. rotate refresh token
5. issue new access token
6. update session metadata

---

## 9. Logout

Endpoint:

POST /api/v1/auth/logout

Authorization:

Bearer access token

Flow:

1. validate access token
2. resolve session
3. set revoked_at

---

## 10. Change Password

Endpoint:

PUT /api/v1/auth/password

Authorization:

Bearer access token

Request fields:

- oldPassword
- newPassword

Flow:

1. authenticate user/session
2. verify old password
3. validate new password
4. ensure password differs
5. generate new password hash
6. update auth_credentials
7. update password_changed_at
8. revoke other active sessions

Change Password membutuhkan password lama.

---

## 11. Forgot Password

Endpoint:

POST /api/v1/auth/forgot-password

Request:

- email

Tidak membutuhkan application.

Response harus anti-enumeration.

Success response tetap generik:

"Jika email terdaftar, instruksi reset password akan dikirim."

Flow jika account ditemukan:

1. generate cryptographically secure random token
2. simpan SHA-256 hash token di password_reset_tokens
3. default expiry 30 menit
4. invalidate token reset lama yang belum dipakai
5. kirim reset URL melalui SMTP

Reset URL tunggal:

SSO_PUBLIC_URL/reset-password?token=<raw-token>

Tidak ada application-specific recovery URL.

---

## 12. Reset Password

Endpoint:

POST /api/v1/auth/reset-password

Request fields:

- token
- password

Flow:

1. SHA-256 token input
2. resolve password_reset_tokens
3. reject token tidak ditemukan
4. reject expired token
5. reject token yang sudah digunakan
6. update password hash
7. mark token used
8. invalidate reset token lain
9. revoke existing sessions

Password lama tidak dibutuhkan.

---

## 13. SMTP

Central SSO memiliki SMTP client sendiri.

Configuration target:

- SMTP_HOST
- SMTP_PORT
- SMTP_USERNAME
- SMTP_PASSWORD
- SMTP_FROM_NAME
- SMTP_FROM_EMAIL

Central SSO tidak memanggil SILAPET untuk mengirim email.

SMTP hanya transport email dan tidak mempunyai authority atas reset-password.

---

## 14. Central SSO Frontend

Target public URL:

SSO_PUBLIC_URL

Target pages:

- /login
- /register
- /forgot-password
- /reset-password
- /account
- /account/password

Aplikasi tetap boleh mempunyai login UI masing-masing.

Credential validation tetap dilakukan oleh Central SSO.

---

## 15. Legacy Credential Migration

Existing user yang belum memiliki `auth_credentials` dapat menggunakan temporary legacy verifier selama masa migrasi.

Setelah password lama berhasil diverifikasi:

1. hash password yang baru saja diberikan user
2. create auth_credentials
3. login berikutnya menggunakan Central SSO credential

Legacy verifier hanya mekanisme transisi.

Target akhirnya adalah menghapus dependency credential terhadap Supabase Auth maupun local application credential.

---

## 16. Seamless SSO

Seamless browser SSO dikerjakan setelah central authentication stabil.

Target berikutnya dapat menggunakan:

- central browser session
- /authorize
- one-time authorization code
- application callback
- code exchange

Aplikasi tidak mengambil access token secara manual dari storage Central SSO.

Tahap ini bukan dependency untuk implementasi Central Auth V3 awal.
