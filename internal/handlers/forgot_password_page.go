package handlers

import "github.com/gofiber/fiber/v2"

const forgotPasswordPageHTML = `<!doctype html>
<html lang="id">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>Lupa password - Akun Balai</title>
  <style>
    :root { color-scheme: light; font-family: system-ui, sans-serif; color: #17212b; background: #eef3f7; }
    * { box-sizing: border-box; }
    body { margin: 0; min-height: 100vh; display: grid; place-items: center; background: linear-gradient(145deg,#eef5f8,#f8fafc 55%,#e7eff3); }
    main { width: min(30rem, calc(100% - 2rem)); padding: 2rem; border: 1px solid #d9e3e9; border-radius: 1rem; background: white; box-shadow: 0 1.25rem 3rem #29455714; }
    h1 { margin-top: 0; }
    p { color: #526574; line-height: 1.6; }
    label { display: block; margin-top: 1rem; font-weight: 700; }
    input, button { width: 100%; margin-top: .4rem; padding: .75rem; border-radius: .5rem; font: inherit; }
    input { border: 1px solid #b9c8d2; }
    button { margin-top: 1.25rem; border: 0; background: #075985; color: white; font-weight: 700; cursor: pointer; }
    button:disabled { cursor: not-allowed; opacity: .6; }
    a { color: #075985; }
    #message { min-height: 1.5rem; }
  </style>
</head>
<body>
  <main>
    <p>BP3KP Sumatera II · Akun Balai</p>
    <h1>Lupa password</h1>
    <p>Masukkan email Akun Balai. Jika email terdaftar, instruksi reset password akan dikirim.</p>
    <form id="forgot-form">
      <label for="email">Email</label>
      <input id="email" name="email" type="email" autocomplete="email" required>
      <button id="submit" type="submit">Kirim instruksi</button>
    </form>
    <p id="message" role="status" aria-live="polite"></p>
    <a href="/">Kembali ke Akun Balai</a>
  </main>
  <script>
    (() => {
      const form = document.getElementById('forgot-form');
      const submit = document.getElementById('submit');
      const message = document.getElementById('message');
      form.addEventListener('submit', async (event) => {
        event.preventDefault();
        submit.disabled = true;
        message.textContent = 'Mengirim instruksi...';
        try {
          const response = await fetch('/api/v1/auth/forgot-password', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ email: document.getElementById('email').value })
          });
          const result = await response.json().catch(() => ({}));
          if (!response.ok) {
            throw new Error(result.message || 'Permintaan tidak dapat diproses.');
          }
          form.reset();
          form.hidden = true;
          message.textContent = result.message || 'Jika email terdaftar, instruksi reset password akan dikirim.';
        } catch (error) {
          message.textContent = error.message || 'Permintaan tidak dapat diproses.';
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
		"default-src 'self'; script-src 'unsafe-inline'; style-src 'unsafe-inline'; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'",
	)
	c.Type("html", "utf-8")

	return c.SendString(forgotPasswordPageHTML)
}
