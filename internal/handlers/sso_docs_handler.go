package handlers

import (
	"strings"

	"github.com/gofiber/fiber/v2"
)

// AdminSSODownloadDocsMD serves the complete SSO & App Launcher Master Prompt as a downloadable .md file.
func (h *BrowserSSOHandler) AdminSSODownloadDocsMD(c *fiber.Ctx) error {
	_, _, ok := h.requireSSOAdmin(c)
	if !ok {
		return nil
	}

	appCode := strings.ToLower(strings.TrimSpace(c.Query("app")))
	appName := "Arsiparis"
	clientID := "arsiparis-web"
	launchURL := "https://arsip.bp3kpsumatera2.com/"
	redirectURI := "https://arsip.bp3kpsumatera2.com/auth/sso/callback"
	logoutURI := "https://arsip.bp3kpsumatera2.com/"

	if appCode != "" && h.adminRepo != nil {
		if apps, err := h.adminRepo.ListApplications(c.UserContext()); err == nil {
			for _, a := range apps {
				if strings.EqualFold(a.Code, appCode) {
					appCode = a.Code
					if strings.TrimSpace(a.Name) != "" {
						appName = a.Name
					}
					if strings.TrimSpace(a.ClientID) != "" {
						clientID = a.ClientID
					} else {
						clientID = a.Code + "-web"
					}
					if strings.TrimSpace(a.LaunchURL) != "" {
						launchURL = a.LaunchURL
					} else {
						launchURL = "https://" + a.Code + ".bp3kpsumatera2.com/"
					}
					if len(a.RedirectURIs) > 0 && strings.TrimSpace(a.RedirectURIs[0]) != "" {
						redirectURI = strings.TrimSpace(a.RedirectURIs[0])
					} else {
						redirectURI = strings.TrimRight(launchURL, "/") + "/auth/sso/callback"
					}
					if len(a.PostLogoutRedirectURIs) > 0 && strings.TrimSpace(a.PostLogoutRedirectURIs[0]) != "" {
						logoutURI = strings.TrimSpace(a.PostLogoutRedirectURIs[0])
					} else {
						logoutURI = launchURL
					}
					break
				}
			}
		}
	}
	if appCode == "" {
		appCode = "arsiparis"
	}

	md := fillMasterPromptTokens(
		buildSSOIntegrationMarkdownTemplate(requestOrigin(c)),
		appCode, appName, clientID, launchURL, redirectURI, logoutURI,
	)
	filename := "SSO_BP3KP_MASTER_PROMPT_" + strings.ToUpper(appCode) + ".md"
	c.Set(fiber.HeaderContentType, "text/markdown; charset=utf-8")
	c.Set(fiber.HeaderContentDisposition, `attachment; filename="`+filename+`"`)
	return c.SendString(md)
}

func buildSSOIntegrationMarkdown(ssoOrigin string) string {
	return fillMasterPromptTokens(
		buildSSOIntegrationMarkdownTemplate(ssoOrigin),
		"arsiparis",
		"Arsiparis",
		"arsiparis-web",
		"https://arsip.bp3kpsumatera2.com/",
		"https://arsip.bp3kpsumatera2.com/auth/sso/callback",
		"https://arsip.bp3kpsumatera2.com/",
	)
}

func fillMasterPromptTokens(tpl, code, name, clientID, launchURL, redirectURI, logoutURI string) string {
	r := strings.NewReplacer(
		"__APP_CODE__", code,
		"__APP_NAME__", name,
		"__CLIENT_ID__", clientID,
		"__LAUNCH_URL__", launchURL,
		"__REDIRECT_URI__", redirectURI,
		"__LOGOUT_URI__", logoutURI,
	)
	return r.Replace(tpl)
}

func buildSSOIntegrationMarkdownTemplate(ssoOrigin string) string {
	origin := strings.TrimRight(strings.TrimSpace(ssoOrigin), "/")
	if origin == "" {
		origin = "https://sso.bp3kpsumatera2.com"
	}
	return strings.ReplaceAll(masterPromptMarkdownRaw, "__SSO_ORIGIN__", origin)
}

const masterPromptMarkdownRaw = `# Master Prompt: Integrasi Central SSO & Universal App Launcher — __APP_NAME__ (BP3KP Sumatera II)

> **INSTRUKSI UNTUK AI CODING ASSISTANT (Cursor / Antigravity / Claude / ChatGPT / Copilot):**
> Dokumen ini adalah **Master Prompt** & spesifikasi resmi untuk mengintegrasikan website **__APP_NAME__** (` + "`__APP_CODE__`" + `) dengan **Central SSO Balai** (__SSO_ORIGIN__).
> Kerjakan integrasi SSO dan pemasangan App Launcher pada project website ini sampai 100% berjalan dengan mengikuti aturan wajib berikut:
> 1. Gunakan konfigurasi aplikasi yang sudah terdaftar di SSO berikut ini:
>    - **Application Code (` + "`SSO_APP_CODE`" + `)**: ` + "`__APP_CODE__`" + `
>    - **Nama Aplikasi**: ` + "`__APP_NAME__`" + `
>    - **Client ID (` + "`SSO_CLIENT_ID`" + `)**: ` + "`__CLIENT_ID__`" + `
>    - **SSO Base URL (` + "`SSO_BASE_URL`" + `)**: ` + "`__SSO_ORIGIN__`" + `
>    - **Launch URL**: ` + "`__LAUNCH_URL__`" + `
>    - **Redirect URI (` + "`SSO_REDIRECT_URI`" + `)**: ` + "`__REDIRECT_URI__`" + `
>    - **Post-Logout Redirect URI (` + "`SSO_POST_LOGOUT_REDIRECT_URI`" + `)**: ` + "`__LOGOUT_URI__`" + `
> 2. Ikuti seluruh endpoint, parameter PKCE (S256), struktur payload JSON, dan Web Component di bawah ini **tanpa mengubah nama field atau path endpoint SSO**.
> 3. Semua pengguna yang terdaftar di SSO **otomatis memiliki akses role ` + "`user`" + `** ke seluruh aplikasi aktif tanpa perlu approval manual. Role ` + "`admin`" + ` diatur terpusat di Admin Pusat SSO dan dikirim melalui array ` + "`applications`" + ` saat token exchange.
> 4. Pasang **Universal App Switcher (` + "`<bp3kp-app-switcher>`" + `)** di navbar/header agar pengguna dapat berpindah antar-aplikasi BP3KP secara konsisten.

---

## 1. Konfigurasi Environment Variables (` + "`.env`" + `) di Website Target

Tambahkan variabel berikut pada ` + "`.env`" + ` website target (sesuaikan prefix framework seperti ` + "`VITE_`" + ` atau ` + "`NEXT_PUBLIC_`" + ` bila diakses dari frontend):

` + "```env" + `
SSO_BASE_URL=__SSO_ORIGIN__
SSO_APP_CODE=__APP_CODE__
SSO_CLIENT_ID=__CLIENT_ID__
SSO_REDIRECT_URI=__REDIRECT_URI__
SSO_POST_LOGOUT_REDIRECT_URI=__LOGOUT_URI__
` + "```" + `

---

## 2. Alur Login SSO (OAuth 2.0 Authorization Code + PKCE S256)

Central SSO Balai **wajib** menggunakan **PKCE (` + "`code_challenge_method=S256`" + `)** dan **tidak membutuhkan client secret** saat menukar authorization code.

### Langkah 2.1 — Mulai Login (Redirect ke ` + "`/authorize`" + `)
Saat user menekan tombol **"Masuk dengan Akun Balai"**:
1. Buat ` + "`state`" + ` acak (minimal 16 byte hex/base64url).
2. Buat ` + "`code_verifier`" + ` acak (43–128 karakter URL-safe: ` + "`A-Z`" + `, ` + "`a-z`" + `, ` + "`0-9`" + `, ` + "`-._~`" + `).
3. Hitung ` + "`code_challenge = BASE64URL_NO_PADDING(SHA256(code_verifier))`" + `.
4. Simpan ` + "`state`" + ` dan ` + "`code_verifier`" + ` di ` + "`sessionStorage`" + ` (untuk SPA) atau cookie ` + "`HttpOnly`" + ` singkat (untuk SSR/Backend).
5. Redirect browser ke:

` + "```text" + `
GET __SSO_ORIGIN__/authorize
  ?client_id=__CLIENT_ID__
  &redirect_uri={ encodeURIComponent("__REDIRECT_URI__") }
  &response_type=code
  &state={state}
  &code_challenge={code_challenge}
  &code_challenge_method=S256
` + "```" + `

#### Contoh Helper PKCE (TypeScript / JavaScript Browser & Node 18+)
` + "```ts" + `
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

export async function startSsoLogin(config = {
  ssoBaseUrl: "__SSO_ORIGIN__",
  clientId: "__CLIENT_ID__",
  redirectUri: "__REDIRECT_URI__",
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
` + "```" + `

---

## 3. Implementasi Route Callback & Token Exchange

Buat halaman atau endpoint callback sesuai ` + "`SSO_REDIRECT_URI`" + ` (` + "`__REDIRECT_URI__`" + `).

### Parameter Query yang Diterima di Callback
- **Sukses**: ` + "`?code=<authorization_code>&state=<state>`" + `
- **Gagal / Ditolak (opsional fallback)**: ` + "`?status=pending|denied&state=<state>`" + `

> **Penting — Penanganan Akses Ditolak / Private App (` + "`status`" + ` atau ` + "`code`" + ` kosong):**
> - Secara default, jika user belum diundang ke aplikasi Private (` + "`RESTRICTED`" + `) atau aksesnya ditolak, Central SSO (` + "`__SSO_ORIGIN__`" + `) akan langsung menampilkan halaman **"Belum Mendapat Izin Akses / Akses Ditolak"** yang seragam.
> - Namun sebagai penjagaan di route callback website target: **JANGAN memanggil ` + "`/api/v1/auth/sso/exchange`" + ` apabila ` + "`status=pending`" + `, ` + "`status=denied`" + `, atau ` + "`code`" + ` kosong**. Tampilkan pesan yang ramah sesuai tema website (*"Akun Anda belum memiliki izin untuk mengakses aplikasi ini. Silakan hubungi Admin Pusat SSO."*) beserta tombol kembali ke Beranda / Portal SSO (` + "`__SSO_ORIGIN__/`" + `).

### Langkah 3.1 — Validasi ` + "`state`" + ` & Tukar ` + "`code`" + ` ke ` + "`/api/v1/auth/sso/exchange`" + `
1. Pastikan ` + "`state`" + ` dari query URL **sama persis** dengan ` + "`bp3kp_sso_state`" + ` yang disimpan sebelumnya.
2. Ambil ` + "`codeVerifier`" + ` (` + "`bp3kp_sso_verifier`" + `), lalu hapus ` + "`state`" + ` dan ` + "`codeVerifier`" + ` dari storage.
3. Kirim HTTP ` + "`POST`" + ` ke **__SSO_ORIGIN__/api/v1/auth/sso/exchange**:

#### Request
` + "```http" + `
POST __SSO_ORIGIN__/api/v1/auth/sso/exchange
Content-Type: application/json

{
  "code": "<code_dari_query_url>",
  "clientId": "__CLIENT_ID__",
  "redirectUri": "__REDIRECT_URI__",
  "codeVerifier": "<code_verifier_pkce>"
}
` + "```" + `

#### Response Sukses (` + "`200 OK`" + `)
` + "```json" + `
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
      "code": "__APP_CODE__",
      "name": "__APP_NAME__",
      "statusLabel": "Akses Aktif",
      "statusClass": "status-active",
      "roleLabel": "Admin",
      "launchUrl": "/portal/launch?app=__APP_CODE__",
      "launchable": true
    }
  ]
}
` + "```" + `

### Langkah 3.2 — Menentukan Role User (` + "`user`" + ` vs ` + "`admin`" + `) di Website Target
Semua pengguna SSO otomatis mendapat akses ke setiap aplikasi sebagai ` + "`user`" + `. Untuk mengecek apakah user yang login adalah **` + "`admin`" + `** di **__APP_NAME__** (` + "`__APP_CODE__`" + `):
` + "```ts" + `
const myApp = data.applications?.find(
  (app: { code: string; roleLabel?: string }) =>
    app.code.toLowerCase() === "__APP_CODE__"
);

// roleLabel bernilai "Admin" jika di-set sebagai Admin di SSO, atau "Pengguna" untuk role user biasa
const isAdmin = myApp?.roleLabel?.toLowerCase() === "admin";
const role: "admin" | "user" = isAdmin ? "admin" : "user";
` + "```" + `

> **Alternatif via Endpoint Terautentikasi:**
> Dengan ` + "`accessToken`" + ` dari response exchange, backend/frontend juga bisa memanggil:
> ` + "`GET __SSO_ORIGIN__/api/v1/auth/application-context?app=__APP_CODE__`" + ` dengan header ` + "`Authorization: Bearer <accessToken>`" + ` untuk mendapatkan ` + "`{ \"application\": \"__APP_CODE__\", \"role\": \"admin\" | \"user\", \"status\": \"approved\" }`" + `.

---

## 4. Single Logout (Keluar Terpusat)

Saat user menekan tombol **Keluar / Logout** di website target:
1. Bersihkan session / cookie / ` + "`localStorage`" + ` lokal website target.
2. Arahkan browser ke endpoint logout SSO agar sesi SSO pusat juga diakhiri:

` + "```text" + `
GET __SSO_ORIGIN__/logout
  ?client_id=__CLIENT_ID__
  &post_logout_redirect_uri={ encodeURIComponent("__LOGOUT_URI__") }
` + "```" + `

---

## 5. Pemasangan Universal App Switcher / Launcher (` + "`<bp3kp-app-switcher>`" + `)

Agar tampilan menu pindah aplikasi (ikon 9-titik) **100% seragam di semua website BP3KP** dan otomatis ter-update saat ada aplikasi/logo baru di Admin Pusat SSO, gunakan Web Component resmi dari ` + "`sso-balai`" + `.

Widget ini menggunakan **Shadow DOM**, sehingga CSS-nya tidak akan bentrok dengan Tailwind, Bootstrap, atau CSS lokal website Anda.

### Opsi A — HTML Biasa / Laravel Blade / PHP / Vue
Pasang di dalam navbar/header:
` + "```html" + `
<bp3kp-app-switcher
  sso-url="__SSO_ORIGIN__"
  current-app="__APP_CODE__"
></bp3kp-app-switcher>
<script src="__SSO_ORIGIN__/widget/app-switcher.js" defer></script>
` + "```" + `

### Opsi B — React / Next.js / TanStack Start (TypeScript-Safe)
Buat komponen ` + "`AppLauncher.tsx`" + `:
` + "```tsx" + `
import { createElement, useEffect } from "react";

const SCRIPT_ID = "bp3kp-app-switcher-script";

export function AppLauncher({
  ssoBaseUrl = "__SSO_ORIGIN__",
  currentApp = "__APP_CODE__",
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
    script.src = ` + "`${cleanBase}/widget/app-switcher.js`" + `;
    script.defer = true;
    document.head.appendChild(script);
  }, [cleanBase]);

  return createElement("bp3kp-app-switcher", {
    "sso-url": cleanBase,
    "current-app": currentApp,
    class: className,
  });
}
` + "```" + `

---

## 6. Checklist Verifikasi Integrasi (Definition of Done)

Pastikan seluruh poin berikut terpenuhi sebelum menyatakan integrasi selesai:
- [ ] ` + "`Client ID`" + ` menggunakan ` + "`__CLIENT_ID__`" + ` dan ` + "`Redirect URI`" + ` menggunakan ` + "`__REDIRECT_URI__`" + `.
- [ ] Klik tombol Login SSO di website target mengarahkan ke ` + "`__SSO_ORIGIN__/authorize`" + ` dengan parameter ` + "`code_challenge_method=S256`" + `.
- [ ] Route callback memvalidasi ` + "`state`" + `, memanggil ` + "`POST __SSO_ORIGIN__/api/v1/auth/sso/exchange`" + `, menyimpan sesi user beserta role (` + "`user`" + ` atau ` + "`admin`" + ` untuk ` + "`__APP_CODE__`" + `), lalu mengarahkan ke halaman utama/dashboard.
- [ ] Widget ` + "`<bp3kp-app-switcher current-app=\"__APP_CODE__\">`" + ` tampil di header/navbar dan menampilkan daftar aplikasi terbaru beserta logonya dari ` + "`__SSO_ORIGIN__/api/v1/public/apps`" + `.
`
