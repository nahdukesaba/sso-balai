package handlers

import "github.com/gofiber/fiber/v2"

const acceptInvitePageHTML = `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Aktivasi Akun Balai</title>
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
    #login-link { display: inline-block; margin-top: .75rem; color: #075985; }
  </style>
</head>
<body>
  <main>
    <p>BP3KP Sumatera II &middot; Akun Balai</p>
    <h1>Aktivasi Akun Balai</h1>
    <form id="activation-form">
      <label for="password">Password Baru</label>
      <input id="password" name="password" type="password" minlength="8" maxlength="128" autocomplete="new-password" required>
      <label for="confirmation">Konfirmasi Password</label>
      <input id="confirmation" name="confirmation" type="password" minlength="8" maxlength="128" autocomplete="new-password" required>
      <button id="submit" type="submit">Aktifkan Akun</button>
    </form>
    <p id="message" role="status" aria-live="polite"></p>
    <a id="login-link" href="/login" hidden>Masuk dengan Akun Balai</a>
  </main>
  <script>
    (() => {
      const fragment = new URLSearchParams(window.location.hash.slice(1));
      const inviteType = fragment.get('type') || '';
      let inviteAccessToken = fragment.get('access_token') || '';
      window.history.replaceState({}, document.title, window.location.pathname);

      const form = document.getElementById('activation-form');
      const submit = document.getElementById('submit');
      const message = document.getElementById('message');
      const loginLink = document.getElementById('login-link');

      if (inviteType !== 'invite' || !inviteAccessToken) {
        inviteAccessToken = '';
        submit.disabled = true;
        message.textContent = 'Tautan aktivasi tidak valid atau sudah kedaluwarsa.';
      }

      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        const passwordInput = document.getElementById('password');
        const confirmationInput = document.getElementById('confirmation');
        const password = passwordInput.value;

        if (password.length < 8 || password.length > 128) {
          message.textContent = 'Password harus terdiri dari 8 sampai 128 karakter.';
          return;
        }
        if (password !== confirmationInput.value) {
          message.textContent = 'Konfirmasi password tidak sama.';
          return;
        }

        submit.disabled = true;
        message.textContent = 'Mengaktifkan akun...';

        try {
          const response = await fetch('/api/v1/auth/accept-invite', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ accessToken: inviteAccessToken, password })
          });
          const result = await response.json().catch(() => ({}));

          if (!response.ok) {
            throw new Error(result.message || 'Akun tidak dapat diaktifkan.');
          }

          inviteAccessToken = '';
          form.reset();
          form.hidden = true;
          message.textContent = result.message || 'Password berhasil dibuat. Silakan masuk menggunakan Akun Balai.';
          loginLink.hidden = false;
        } catch (error) {
          message.textContent = error.message || 'Akun tidak dapat diaktifkan.';
          submit.disabled = false;
        } finally {
          passwordInput.value = '';
          confirmationInput.value = '';
        }
      });
    })();
  </script>
</body>
</html>`

func (h *AuthHandler) AcceptInvitePage(c *fiber.Ctx) error {
	c.Set(fiber.HeaderCacheControl, "no-store")
	c.Set("Referrer-Policy", "no-referrer")
	c.Set(
		"Content-Security-Policy",
		"default-src 'none'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'",
	)
	c.Type("html", "utf-8")

	return c.SendString(acceptInvitePageHTML)
}
