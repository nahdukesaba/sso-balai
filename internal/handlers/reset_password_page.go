package handlers

import "github.com/gofiber/fiber/v2"

const resetPasswordPageHTML = `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Reset password - Akun Balai</title>
  <style>
    :root { color-scheme: light; font-family: system-ui, sans-serif; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: #f4f6f8; color: #17212b; }
    main { width: min(28rem, calc(100% - 2rem)); padding: 2rem; border-radius: .75rem; background: white; box-shadow: 0 .5rem 2rem #1f29371a; }
    h1 { margin-top: 0; font-size: 1.5rem; }
    label { display: block; margin-top: 1rem; font-weight: 600; }
    input, button { box-sizing: border-box; width: 100%; margin-top: .4rem; padding: .75rem; font: inherit; }
    button { margin-top: 1.25rem; border: 0; border-radius: .4rem; background: #075985; color: white; cursor: pointer; }
    button:disabled { cursor: not-allowed; opacity: .6; }
    #message { min-height: 1.5rem; margin-top: 1rem; }
  </style>
</head>
<body>
  <main>
    <p>BP3KP Sumatera II · Akun Balai</p>
    <h1>Reset password</h1>
    <form id="reset-form">
      <label for="password">Password baru</label>
      <input id="password" name="password" type="password" minlength="8" maxlength="128" autocomplete="new-password" required>
      <label for="confirmation">Konfirmasi password baru</label>
      <input id="confirmation" name="confirmation" type="password" minlength="8" maxlength="128" autocomplete="new-password" required>
      <button id="submit" type="submit">Perbarui password</button>
    </form>
    <p id="message" role="status" aria-live="polite"></p>
  </main>
  <script>
    (() => {
      const tokenHash = new URLSearchParams(window.location.search).get('token_hash') || '';
      const form = document.getElementById('reset-form');
      const submit = document.getElementById('submit');
      const message = document.getElementById('message');

      if (tokenHash) {
        window.history.replaceState({}, document.title, window.location.pathname);
      } else {
        submit.disabled = true;
        message.textContent = 'Tautan reset password tidak valid atau sudah kedaluwarsa.';
      }

      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const password = document.getElementById('password').value;
        const confirmation = document.getElementById('confirmation').value;

        if (password !== confirmation) {
          message.textContent = 'Konfirmasi password tidak sama.';
          return;
        }

        submit.disabled = true;
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
          message.textContent = result.message || 'Password berhasil diperbarui.';
        } catch (error) {
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
		"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'",
	)
	c.Type("html", "utf-8")

	return c.SendString(resetPasswordPageHTML)
}
