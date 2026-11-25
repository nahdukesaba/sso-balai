package handlers

import "github.com/gofiber/fiber/v2"

const recoveryExtraStyles = `
button[type="submit"]{display:inline-flex;align-items:center;justify-content:center;gap:.45rem;width:100%;min-height:2.6rem;margin-top:1.35rem;padding:.6rem 1.05rem;border:0;border-radius:.6rem;background:var(--accent);color:#fff;font:inherit;font-size:.88rem;font-weight:600;cursor:pointer;transition:background .15s ease,transform .15s ease}
button[type="submit"]:hover:not(:disabled){background:var(--accent-hover)}
button[type="submit"]:disabled{cursor:not-allowed;opacity:.6}
.eyebrow{margin:0;color:var(--muted);font-size:.78rem;font-weight:600;letter-spacing:.01em}
#message{margin:1rem 0 0;padding:.75rem .9rem;border-radius:.6rem;border:1px solid #bae6fd;background:#f0f9ff;color:var(--accent);font-size:.85rem;font-weight:500;line-height:1.5}
#message:empty{display:none}
#message.is-error{border-color:#fecaca;background:#fef2f2;color:#b42318}
#message.is-success{border-color:#a7f3d0;background:#ecfdf5;color:#047857}
[hidden]{display:none!important}
`

var forgotPasswordPageHTML = `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lupa password - Akun Balai Pegawai</title>` + accountPortalFavicon + `
  <style>` + accountPortalStyles + recoveryExtraStyles + `</style>
</head>
<body>` + accountPortalBrandHeader + `</div></header>
  <div class="auth-wrap">
    <section class="auth-card">
      <div class="auth-head">
        <img class="brand-logo" src="` + accountPortalLogoDataURI + `" alt="" aria-hidden="true">
        <p class="eyebrow">BP3KP Sumatera II · Akun Balai Pegawai</p>
        <h1>Lupa Password</h1>
        <p class="lead">Kami akan mengirimkan tautan pengaturan ulang password ke email terdaftar Anda.</p>
      </div>
      <form id="forgot-form">
        <label for="email">Email</label>
        <input id="email" name="email" type="email" autocomplete="email" placeholder="nama@bp3kpsumatera2.com" required>
        <button id="submit" type="submit">Kirim</button>
      </form>
      <p id="message" role="status" aria-live="polite"></p>
      <div class="form-foot">
        <span class="muted" style="font-size:.84rem;margin:0">Sudah ingat password?</span>
        <a class="footer-link" href="/account/login">Login</a>
      </div>
    </section>
  </div>
  <footer class="portal-foot" style="margin-top:1rem;margin-bottom:2rem">Kementerian Perumahan dan Kawasan Permukiman · BP3KP Sumatera II</footer>
  <script>
    (() => {
      const form = document.getElementById('forgot-form');
      const submit = document.getElementById('submit');
      const message = document.getElementById('message');
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        submit.disabled = true;
        message.className = '';
        message.textContent = 'Mengirim...';
        try {
          const response = await fetch('/api/v1/auth/forgot-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: document.getElementById('email').value })
          });
          const result = await response.json().catch(() => ({}));
          if (!response.ok) {
            throw new Error(result.message || 'Permintaan Tidak Dapat Diproses !');
          }
          form.reset();
          form.hidden = true;
          message.className = 'is-success';
          message.textContent = result.message || 'Jika email terdaftar, instruksi reset password akan dikirim';
        } catch (error) {
          message.className = 'is-error';
          message.textContent = error.message || 'Permintaan Tidak Dapat Diproses !';
          submit.disabled = false;
        }
      });
    })();
  </script>
</body>
</html>`

func (h *AuthHandler) ForgotPasswordPage(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set("Referrer-Policy", "no-referrer")
	c.Set(
		"Content-Security-Policy",
		"default-src 'self'; img-src 'self' data:; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
	)
	c.Type("html", "utf-8")

	return c.SendString(forgotPasswordPageHTML)
}
