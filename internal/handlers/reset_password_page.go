package handlers

import "github.com/gofiber/fiber/v2"

var resetPasswordPageHTML = `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reset password - Akun Balai</title>` + accountPortalFavicon + `
  <style>` + accountPortalStyles + recoveryExtraStyles + `</style>
</head>
<body>` + accountPortalBrandHeader + `</div></header>
  <div class="auth-wrap">
    <section class="auth-card">
      <div class="auth-head">
        <img class="brand-logo" src="` + accountPortalLogoDataURI + `" alt="" aria-hidden="true">
        <p class="eyebrow">BP3KP Sumatera II · Akun Balai</p>
        <h1>Reset password</h1>
        <p class="lead">Masukkan password baru untuk mengamankan Akun Balai Anda.</p>
      </div>
      <form id="reset-form">
        <label for="password">Password baru</label>
        <input id="password" name="password" type="password" minlength="8" maxlength="128" autocomplete="new-password" placeholder="Minimal 8 karakter" required>
        <label for="confirmation">Konfirmasi password baru</label>
        <input id="confirmation" name="confirmation" type="password" minlength="8" maxlength="128" autocomplete="new-password" placeholder="Ulangi password baru" required>
        <button id="submit" type="submit">Perbarui password</button>
      </form>
      <p id="message" role="status" aria-live="polite"></p>
      <a id="login-cta" class="button" href="/account/login" style="width:100%;margin-top:1.25rem" hidden>Masuk ke Akun Balai</a>
      <div class="form-foot">
        <a class="footer-link" href="/forgot-password">Minta tautan baru</a>
        <a class="footer-link" href="/account/login">Kembali ke Login</a>
      </div>
    </section>
  </div>
  <footer class="portal-foot" style="margin-top:1rem;margin-bottom:2rem">Kementerian Perumahan dan Kawasan Permukiman · BP3KP Sumatera II</footer>
  <script>
    (() => {
      const searchParams = new URLSearchParams(window.location.search);
      const hashParams = new URLSearchParams(window.location.hash.replace(/^#/, ''));
      const tokenHash = searchParams.get('token_hash') || hashParams.get('token_hash') || '';
      const form = document.getElementById('reset-form');
      const submit = document.getElementById('submit');
      const message = document.getElementById('message');
      const loginCta = document.getElementById('login-cta');

      if (tokenHash) {
        window.history.replaceState({}, document.title, window.location.pathname);
      } else {
        submit.disabled = true;
        message.className = 'is-error';
        message.textContent = 'Tautan reset password tidak valid atau sudah kedaluwarsa.';
      }

      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const password = document.getElementById('password').value;
        const confirmation = document.getElementById('confirmation').value;

        if (password !== confirmation) {
          message.className = 'is-error';
          message.textContent = 'Konfirmasi password tidak sama.';
          return;
        }

        submit.disabled = true;
        message.className = '';
        message.textContent = 'Memperbarui password...';

        try {
          const response = await fetch('/api/v1/auth/reset-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ tokenHash, password })
          });
          const result = await response.json().catch(() => ({}));

          if (!response.ok) {
            throw new Error(result.message || 'Password tidak dapat diperbarui.');
          }

          form.reset();
          form.hidden = true;
          message.className = 'is-success';
          message.textContent = result.message || 'Password berhasil diperbarui.';
          if (loginCta) loginCta.hidden = false;
        } catch (error) {
          message.className = 'is-error';
          message.textContent = error.message || 'Password tidak dapat diperbarui.';
          submit.disabled = false;
        }
      });
    })();
  </script>
</body>
</html>`

func (h *AuthHandler) ResetPasswordPage(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set("Referrer-Policy", "no-referrer")
	c.Set(
		"Content-Security-Policy",
		"default-src 'self'; img-src 'self' data:; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
	)
	c.Type("html", "utf-8")

	return c.SendString(resetPasswordPageHTML)
}
