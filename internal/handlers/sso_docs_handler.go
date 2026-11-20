package handlers

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
)

// AdminSSODownloadDocsMD serves the complete SSO & App Launcher integration guide as a downloadable .md file.
func (h *BrowserSSOHandler) AdminSSODownloadDocsMD(c *fiber.Ctx) error {
	_, _, ok := h.requireSSOAdmin(c)
	if !ok {
		return nil
	}
	md := buildSSOIntegrationMarkdown(requestOrigin(c))
	c.Set(fiber.HeaderContentType, "text/markdown; charset=utf-8")
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="SSO_BP3KP_INTEGRATION_GUIDE.md"`)
	return c.SendString(md)
}

func buildSSOIntegrationMarkdown(ssoOrigin string) string {
	origin := strings.TrimRight(strings.TrimSpace(ssoOrigin), "/")
	if origin == "" {
		origin = "https://sso.bp3kpsumatera2.com"
	}
	return fmt.Sprintf(`# Panduan Integrasi Central SSO & Universal App Launcher — BP3KP Sumatera II

> **INSTRUKSI UNTUK AI CODING ASSISTANT (Cursor / Antigravity / Claude / ChatGPT / Copilot):**
> Dokumen ini adalah spesifikasi resmi dan lengkap untuk mengintegrasikan website internal BP3KP Sumatera II dengan **Central SSO Balai** (%s).
> Jika pengguna meminta Anda memasang SSO atau App Launcher pada proyek website ini:
> 1. Ikuti seluruh endpoint, parameter PKCE (S256), struktur payload JSON, dan Web Component di bawah ini **tanpa mengubah nama field atau path endpoint SSO**.
> 2. Semua pengguna yang terdaftar di SSO **otomatis memiliki akses role `+"`user`"+`** ke seluruh aplikasi aktif tanpa perlu approval manual. Role `+"`admin`"+` diatur terpusat di Admin Pusat SSO dan dikirim melalui array `+"`applications`"+` saat token exchange.
> 3. Pasang juga **Universal App Switcher (`+"`<bp3kp-app-switcher>`"+`)** di navbar/header agar pengguna dapat berpindah antar-aplikasi BP3KP secara konsisten.

---

## 1. Pendaftaran Website di Admin Pusat SSO

Sebelum mulai coding di website target, daftarkan aplikasi di **%s/admin/sso?tab=apps** (**+ Tambah / Perbarui Aplikasi SSO**):

| Field di Admin SSO | Contoh Nilai | Keterangan |
| :--- | :--- | :--- |
| **Code** | `+"`arsiparis`"+` | Kode unik aplikasi (huruf kecil). Dipakai untuk mencocokkan role di array `+"`applications`"+` & atribut `+"`current-app`"+` di widget. |
| **Nama Aplikasi** | `+"`Arsiparis`"+` | Nama tampilan di Portal SSO & App Switcher. |
| **Client ID** | `+"`arsiparis-web`"+` | Identifier OAuth/SSO client yang dikirim ke `+"`/authorize`"+` dan `+"`/api/v1/auth/sso/exchange`"+`. |
| **Port FE / Port BE** | `+"`3004`"+` / `+"`8084`"+` | Opsional, dokumentasi port internal server. |
| **Launch URL** | `+"`https://arsip.bp3kpsumatera2.com/`"+` | URL utama ketika aplikasi dibuka dari Portal SSO atau App Switcher. |
| **Redirect URIs** | `+"`https://arsip.bp3kpsumatera2.com/auth/sso/callback, http://localhost:3004/auth/sso/callback`"+` | **Wajib sama persis** dengan URL callback di website target (pisahkan dengan koma jika lebih dari satu). |
| **Post-Logout Redirect URIs** | `+"`https://arsip.bp3kpsumatera2.com/`"+` | URL tujuan setelah proses Single Logout selesai. |
| **Logo** | Upload PNG/SVG/WebP atau URL | Jika dikosongkan, otomatis menggunakan Logo resmi BP3KP Sumatera II. |

---

## 2. Konfigurasi Environment Variables (`+"`.env`"+`) di Website Target

Tambahkan variabel berikut pada `+"`.env`"+` website target (sesuaikan prefix framework seperti `+"`VITE_`"+` atau `+"`NEXT_PUBLIC_`"+` bila diakses dari frontend):

`+"```env"+`
SSO_BASE_URL=%s
SSO_APP_CODE=arsiparis
SSO_CLIENT_ID=arsiparis-web
SSO_REDIRECT_URI=https://arsip.bp3kpsumatera2.com/auth/sso/callback
SSO_POST_LOGOUT_REDIRECT_URI=https://arsip.bp3kpsumatera2.com/
`+"```"+`

---

## 3. Alur Login SSO (OAuth 2.0 Authorization Code + PKCE S256)

Central SSO Balai **wajib** menggunakan **PKCE (`+"`code_challenge_method=S256`"+`)** dan **tidak membutuhkan client secret** saat menukar authorization code.

### Langkah 3.1 — Mulai Login (Redirect ke `+"`/authorize`"+`)
Saat user menekan tombol **"Masuk dengan Akun Balai"**:
1. Buat `+"`state`"+` acak (minimal 16 byte hex/base64url).
2. Buat `+"`code_verifier`"+` acak (43–128 karakter URL-safe: `+"`A-Z`"+`, `+"`a-z`"+`, `+"`0-9`"+`, `+"`-._~`"+`).
3. Hitung `+"`code_challenge = BASE64URL_NO_PADDING(SHA256(code_verifier))`"+`.
4. Simpan `+"`state`"+` dan `+"`code_verifier`"+` di `+"`sessionStorage`"+` (untuk SPA) atau cookie `+"`HttpOnly`"+` singkat (untuk SSR/Backend).
5. Redirect browser ke:

`+"```text"+`
GET %s/authorize
  ?client_id={SSO_CLIENT_ID}
  &redirect_uri={ encodeURIComponent(SSO_REDIRECT_URI) }
  &response_type=code
  &state={state}
  &code_challenge={code_challenge}
  &code_challenge_method=S256
`+"```"+`

#### Contoh Helper PKCE (TypeScript / JavaScript Browser & Node 18+)
`+"```ts"+`
function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const b of bytes) binary += String.fromCharCode(b);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

export function randomUrlSafe(byteLength = 32): string {
  const bytes = new Uint8Array(byteLength);
  crypto.getRandomValues(bytes);
  return toBase64Url(bytes);
}

export async function createPkceChallenge(verifier: string): Promise<string> {
  const data = new TextEncoder().encode(verifier);
  const digest = await crypto.subtle.digest("SHA-256", data);
  return toBase64Url(new Uint8Array(digest));
}

export async function startSsoLogin(config: {
  ssoBaseUrl: string;
  clientId: string;
  redirectUri: string;
}) {
  const state = randomUrlSafe(24);
  const codeVerifier = randomUrlSafe(32);
  const codeChallenge = await createPkceChallenge(codeVerifier);

  sessionStorage.setItem("bp3kp_sso_state", state);
  sessionStorage.setItem("bp3kp_sso_verifier", codeVerifier);

  const url = new URL("/authorize", config.ssoBaseUrl);
  url.searchParams.set("client_id", config.clientId);
  url.searchParams.set("redirect_uri", config.redirectUri);
  url.searchParams.set("response_type", "code");
  url.searchParams.set("state", state);
  url.searchParams.set("code_challenge", codeChallenge);
  url.searchParams.set("code_challenge_method", "S256");

  window.location.assign(url.toString());
}
`+"```"+`

---

## 4. Implementasi Route Callback & Token Exchange

Buat halaman atau endpoint callback sesuai `+"`SSO_REDIRECT_URI`"+` (contoh: `+"`/auth/sso/callback`"+`).

### Parameter Query yang Diterima di Callback
- **Sukses**: `+"`?code=<authorization_code>&state=<state>`"+`
- **Gagal / Belum Disetujui**: `+"`?status=pending|denied&state=<state>`"+`

### Langkah 4.1 — Validasi `+"`state`"+` & Tukar `+"`code`"+` ke `+"`/api/v1/auth/sso/exchange`"+`
1. Pastikan `+"`state`"+` dari query URL **sama persis** dengan `+"`bp3kp_sso_state`"+` yang disimpan sebelumnya.
2. Ambil `+"`codeVerifier`"+` (`+"`bp3kp_sso_verifier`"+`), lalu hapus `+"`state`"+` dan `+"`codeVerifier`"+` dari storage.
3. Kirim HTTP `+"`POST`"+` ke **%s/api/v1/auth/sso/exchange**:

#### Request
`+"```http"+`
POST %s/api/v1/auth/sso/exchange
Content-Type: application/json

{
  "code": "<code_dari_query_url>",
  "clientId": "<SSO_CLIENT_ID>",
  "redirectUri": "<SSO_REDIRECT_URI>",
  "codeVerifier": "<code_verifier_pkce>"
}
`+"```"+`

#### Response Sukses (`+"`200 OK`"+`)
`+"```json"+`
{
  "accessToken": "eyJhbGciOi...",
  "refreshToken": "...",
  "tokenType": "bearer",
  "expiresIn": 3600,
  "expiresAt": 1763612345,
  "sid": "d8f9e0a1-...",
  "user": {
    "id": "8f14e45f-...",
    "authUserId": "c2a1b3d4-...",
    "email": "pegawai@bp3kpsumatera2.com",
    "fullName": "Budi Santoso",
    "phone": "08123456789",
    "isActive": true
  },
  "applications": [
    {
      "code": "arsiparis",
      "name": "Arsiparis",
      "description": "Portal pengelolaan arsip...",
      "statusLabel": "Akses Aktif",
      "statusClass": "status-active",
      "roleLabel": "Admin",
      "launchUrl": "/portal/launch?app=arsiparis",
      "launchable": true
    }
  ]
}
`+"```"+`

### Langkah 4.2 — Menentukan Role User (`+"`user`"+` vs `+"`admin`"+`) di Website Target
Semua pengguna SSO otomatis mendapat akses ke setiap aplikasi sebagai `+"`user`"+`. Untuk mengecek apakah user yang login adalah **`+"`admin`"+`** di website Anda:
`+"```ts"+`
const myApp = data.applications?.find(
  (app: { code: string; roleLabel?: string }) =>
    app.code.toLowerCase() === SSO_APP_CODE.toLowerCase()
);

// roleLabel bernilai "Admin" jika di-set sebagai Admin di SSO, atau "Pengguna" untuk role user biasa
const isAdmin = myApp?.roleLabel?.toLowerCase() === "admin";
const role: "admin" | "user" = isAdmin ? "admin" : "user";
`+"```"+`

> **Alternatif via Endpoint Terautentikasi:**
> Dengan `+"`accessToken`"+` dari response exchange, backend/frontend juga bisa memanggil:
> `+"`GET %s/api/v1/auth/application-context?app={SSO_APP_CODE}`"+` dengan header `+"`Authorization: Bearer <accessToken>`"+` untuk mendapatkan `+"`{ \"application\": \"arsiparis\", \"role\": \"admin\" | \"user\", \"status\": \"approved\" }`"+`.

---

## 5. Single Logout (Keluar Terpusat)

Saat user menekan tombol **Keluar / Logout** di website target:
1. Bersihkan session / cookie / `+"`localStorage`"+` lokal website target.
2. Arahkan browser ke endpoint logout SSO agar sesi SSO pusat juga diakhiri:

`+"```text"+`
GET %s/logout
  ?client_id={SSO_CLIENT_ID}
  &post_logout_redirect_uri={ encodeURIComponent(SSO_POST_LOGOUT_REDIRECT_URI) }
`+"```"+`

---

## 6. Pemasangan Universal App Switcher / Launcher (`+"`<bp3kp-app-switcher>`"+`)

Agar tampilan menu pindah aplikasi (ikon 9-titik) **100%% seragam di semua website BP3KP** dan otomatis ter-update saat ada aplikasi/logo baru di Admin Pusat SSO, gunakan Web Component resmi dari `+"`sso-balai`"+`.

Widget ini menggunakan **Shadow DOM**, sehingga CSS-nya tidak akan bentrok dengan Tailwind, Bootstrap, atau CSS lokal website Anda.

### Opsi A — HTML Biasa / Laravel Blade / PHP / Vue
Pasang di dalam navbar/header:
`+"```html"+`
<bp3kp-app-switcher
  sso-url="%s"
  current-app="arsiparis"
></bp3kp-app-switcher>
<script src="%s/widget/app-switcher.js" defer></script>
`+"```"+`

### Opsi B — React / Next.js / TanStack Start (TypeScript-Safe)
Buat komponen `+"`AppLauncher.tsx`"+`:
`+"```tsx"+`
import { createElement, useEffect } from "react";

const SCRIPT_ID = "bp3kp-app-switcher-script";

export function AppLauncher({
  ssoBaseUrl = "%s",
  currentApp = "arsiparis",
  className,
}: {
  ssoBaseUrl?: string;
  currentApp?: string;
  className?: string;
}) {
  const cleanBase = ssoBaseUrl.replace(/\/+$/, "");

  useEffect(() => {
    if (typeof window === "undefined" || !window.customElements) return;
    if (window.customElements.get("bp3kp-app-switcher")) return;
    if (document.getElementById(SCRIPT_ID)) return;

    const script = document.createElement("script");
    script.id = SCRIPT_ID;
    script.src = `+"`${cleanBase}/widget/app-switcher.js`"+`;
    script.defer = true;
    document.head.appendChild(script);
  }, [cleanBase]);

  return createElement("bp3kp-app-switcher", {
    "sso-url": cleanBase,
    "current-app": currentApp,
    class: className,
  });
}
`+"```"+`

### Atribut yang Didukung `+"`<bp3kp-app-switcher>`"+`
| Atribut | Wajib? | Contoh | Fungsi |
| :--- | :--- | :--- | :--- |
| `+"`sso-url`"+` | Opsional | `+"`%s`"+` | Base URL server SSO (otomatis terdeteksi dari `+"`src`"+` script jika tidak diisi). |
| `+"`current-app`"+` | Disarankan | `+"`arsiparis`"+` | Menandai aplikasi yang sedang aktif dengan highlight biru lembut di dalam daftar. |
| `+"`label`"+` | Opsional | `+"`Aplikasi`"+` | Menampilkan teks di sebelah kanan ikon 9-titik pada tombol trigger. |
| `+"`align`"+` | Opsional | `+"`right`"+` (default) / `+"`left`"+` | Mengatur arah bukaan popover (`+"`right`"+` cocok jika tombol berada di kanan navbar). |

---

## 7. Checklist Verifikasi Integrasi (Definition of Done)

Pastikan seluruh poin berikut terpenuhi sebelum menyatakan integrasi selesai:
- [ ] Aplikasi sudah terdaftar dan berstatus **Aktif** di `+"`%s/admin/sso?tab=apps`"+`.
- [ ] `+"`Redirect URIs`"+` di Admin Pusat SSO sudah memuat URL callback production dan local development secara presisi.
- [ ] Klik tombol Login SSO di website target mengarahkan ke `+"`%s/authorize`"+` dengan parameter `+"`code_challenge_method=S256`"+`.
- [ ] Route callback memvalidasi `+"`state`"+`, memanggil `+"`POST %s/api/v1/auth/sso/exchange`"+`, menyimpan sesi user beserta role (`+"`user`"+` atau `+"`admin`"+`), lalu mengarahkan ke halaman utama/dashboard.
- [ ] Widget `+"`<bp3kp-app-switcher>`"+` tampil di header/navbar dan menampilkan daftar aplikasi terbaru beserta logonya dari `+"`%s/api/v1/public/apps`"+`.
`, origin, origin, origin, origin, origin, origin, origin, origin, origin, origin, origin, origin, origin, origin, origin, origin)
}
