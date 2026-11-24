package handlers

import (
	"fmt"
	"strings"

	"github.com/gofiber/fiber/v2"
)

type publicAppItem struct {
	Code      string `json:"code"`
	Name      string `json:"name"`
	LaunchURL string `json:"launchUrl"`
	LogoURL   string `json:"logoUrl"`
}

func requestOrigin(c *fiber.Ctx) string {
	scheme := c.Protocol()
	if xfProto := strings.TrimSpace(c.Get("X-Forwarded-Proto")); xfProto != "" {
		scheme = strings.Split(xfProto, ",")[0]
	}
	return fmt.Sprintf("%s://%s", scheme, c.Hostname())
}

// DefaultLogoPNG serves the default BP3KP logo for applications without a custom logo.
func (h *BrowserSSOHandler) DefaultLogoPNG(c *fiber.Ctx) error {
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set(fiber.HeaderCacheControl, "public, max-age=86400")
	c.Set(fiber.HeaderContentType, "image/png")
	return c.Send(accountPortalLogoPNG)
}

// PublicApps returns active applications with launch URLs and logos for the universal app-switcher widget.
// Applications with RESTRICTED access_policy are only returned to authenticated users who hold an approved membership.
func (h *BrowserSSOHandler) PublicApps(c *fiber.Ctx) error {
	if origin := strings.TrimSpace(c.Get("Origin")); origin != "" {
		c.Set("Access-Control-Allow-Origin", origin)
		c.Set("Access-Control-Allow-Credentials", "true")
		c.Set("Vary", "Origin")
	} else {
		c.Set("Access-Control-Allow-Origin", "*")
	}
	c.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Set(fiber.HeaderCacheControl, "private, no-store")
	if c.Method() == fiber.MethodOptions {
		return c.SendStatus(fiber.StatusNoContent)
	}

	allowedRestricted := make(map[string]bool)
	if h != nil && h.service != nil && h.portalService != nil {
		if browserToken := strings.TrimSpace(c.Cookies(browserSSOSessionCookie)); browserToken != "" {
			if identity, err := h.service.ResolveBrowserIdentity(c.UserContext(), browserToken); err == nil && identity != nil && identity.User != nil {
				for _, card := range h.portalService.UserApplications(c.UserContext(), identity.User.ID) {
					if card.Launchable {
						allowedRestricted[strings.ToLower(strings.TrimSpace(card.Code))] = true
					}
				}
			}
		}
	}

	defaultLogo := requestOrigin(c) + "/widget/default-logo.png"
	var items []publicAppItem
	if h != nil && h.adminRepo != nil {
		apps, err := h.adminRepo.ListApplications(c.UserContext())
		if err == nil {
			for _, a := range apps {
				if !a.IsActive || strings.TrimSpace(a.LaunchURL) == "" {
					continue
				}
				policy := strings.ToUpper(strings.TrimSpace(a.AccessPolicy))
				if policy == "RESTRICTED" && !allowedRestricted[strings.ToLower(strings.TrimSpace(a.Code))] {
					continue
				}
				logo := strings.TrimSpace(a.LogoURL)
				if logo == "" {
					logo = defaultLogo
				}
				items = append(items, publicAppItem{
					Code:      a.Code,
					Name:      a.Name,
					LaunchURL: a.LaunchURL,
					LogoURL:   logo,
				})
			}
		}
	}
	if items == nil {
		items = []publicAppItem{}
	}
	return c.JSON(fiber.Map{
		"defaultLogoUrl": defaultLogo,
		"apps":           items,
	})
}

// AppSwitcherWidgetJS serves the universal <bp3kp-app-switcher> Web Component.
func (h *BrowserSSOHandler) AppSwitcherWidgetJS(c *fiber.Ctx) error {
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set(fiber.HeaderCacheControl, "public, max-age=300")
	c.Set(fiber.HeaderContentType, "application/javascript; charset=utf-8")
	return c.SendString(strings.ReplaceAll(appSwitcherWidgetScript, "__DEFAULT_SSO_ORIGIN__", requestOrigin(c)))
}

const appSwitcherWidgetScript = `(function(){
  if (typeof window === 'undefined' || !window.customElements || customElements.get('bp3kp-app-switcher')) return;

  var scriptEl = document.currentScript;
  var detectedOrigin = '__DEFAULT_SSO_ORIGIN__';
  if (scriptEl && scriptEl.src) {
    try { detectedOrigin = new URL(scriptEl.src).origin; } catch (_) {}
  }

  function esc(s) {
    return String(s || '').replace(/&/g,'&amp;').replace(/</g,'&lt;').replace(/>/g,'&gt;').replace(/"/g,'&quot;');
  }

  class Bp3kpAppSwitcher extends HTMLElement {
    constructor() {
      super();
      this.attachShadow({ mode: 'open' });
      this._open = false;
      this._apps = null;
      this._defaultLogo = null;
      this._onDocClick = this._handleDocClick.bind(this);
      this._onKeyDown = this._handleKeyDown.bind(this);
    }

    connectedCallback() {
      this._render();
      document.addEventListener('click', this._onDocClick);
      document.addEventListener('keydown', this._onKeyDown);
    }

    disconnectedCallback() {
      document.removeEventListener('click', this._onDocClick);
      document.removeEventListener('keydown', this._onKeyDown);
    }

    _ssoBase() {
      return (this.getAttribute('sso-url') || detectedOrigin).replace(/\/+$/, '');
    }

    _handleDocClick(e) {
      if (!this._open) return;
      if (e.composedPath && e.composedPath().indexOf(this) !== -1) return;
      this._open = false;
      this._syncPanel();
    }

    _handleKeyDown(e) {
      if (this._open && e.key === 'Escape') {
        this._open = false;
        this._syncPanel();
      }
    }

    _toggle() {
      this._open = !this._open;
      this._syncPanel();
      if (this._open && !this._apps) this._loadApps();
    }

    _syncPanel() {
      var panel = this.shadowRoot.getElementById('panel');
      var btn = this.shadowRoot.getElementById('trigger');
      if (panel) panel.hidden = !this._open;
      if (btn) btn.setAttribute('aria-expanded', this._open ? 'true' : 'false');
    }

    _loadApps() {
      var self = this;
      var grid = this.shadowRoot.getElementById('grid');
      if (grid) grid.innerHTML = '<div class="loading">Memuat aplikasi...</div>';
      fetch(this._ssoBase() + '/api/v1/public/apps', { credentials: 'include' })
        .then(function(r){ return r.json(); })
        .then(function(data){
          self._apps = Array.isArray(data.apps) ? data.apps : [];
          self._defaultLogo = data.defaultLogoUrl || (self._ssoBase() + '/widget/default-logo.png');
          self._renderGrid();
        })
        .catch(function(){
          if (grid) grid.innerHTML = '<div class="loading">Gagal memuat daftar aplikasi.</div>';
        });
    }

    _renderGrid() {
      var grid = this.shadowRoot.getElementById('grid');
      if (!grid) return;
      var current = (this.getAttribute('current-app') || '').toLowerCase();
      var base = this._ssoBase();
      var fallbackLogo = this._defaultLogo || (base + '/widget/default-logo.png');
      var html = '';
      var apps = this._apps || [];
      for (var i = 0; i < apps.length; i++) {
        var a = apps[i];
        var logo = a.logoUrl || fallbackLogo;
        var isCurrent = current && String(a.code || '').toLowerCase() === current;
        html += '<a class="tile' + (isCurrent ? ' current' : '') + '" href="' + esc(a.launchUrl) + '" target="_blank" rel="noopener">'
          + '<span class="logo-box"><img src="' + esc(logo) + '" alt="' + esc(a.name) + '" loading="lazy"></span>'
          + '<span class="tile-label">' + esc(a.name) + '</span>'
          + '</a>';
      }
      html += '<a class="tile" href="' + esc(base + '/') + '" target="_blank" rel="noopener">'
        + '<span class="logo-box"><img src="' + esc(fallbackLogo) + '" alt="Akun SSO" loading="lazy"></span>'
        + '<span class="tile-label">Akun SSO</span>'
        + '</a>';
      grid.innerHTML = html;
      var imgs = grid.querySelectorAll('img');
      for (var j = 0; j < imgs.length; j++) {
        imgs[j].addEventListener('error', function(){
          if (this.src !== fallbackLogo) this.src = fallbackLogo;
        });
      }
    }

    _render() {
      var label = this.getAttribute('label') || '';
      var align = this.getAttribute('align') === 'left' ? 'left:0' : 'right:0';
      var base = this._ssoBase();
      this.shadowRoot.innerHTML = '<style>'
        + ':host{position:relative;display:inline-block;font-family:system-ui,-apple-system,"Segoe UI",Roboto,Inter,sans-serif}'
        + '.trigger{display:inline-flex;align-items:center;gap:.45rem;padding:.45rem .65rem;border-radius:.65rem;border:1px solid #cbd5e1;background:#ffffff;color:#0f172a;font:inherit;font-size:.84rem;font-weight:600;cursor:pointer;box-shadow:0 1px 2px rgba(15,23,42,.06);transition:background .15s,border-color .15s}'
        + '.trigger:hover{background:#f1f5f9;border-color:#94a3b8}'
        + '.trigger svg{width:1.1rem;height:1.1rem;flex-shrink:0;color:#0b5d78}'
        + '.panel{position:absolute;top:calc(100% + .55rem);' + align + ';width:min(22.5rem,calc(100vw - 1.5rem));background:#ffffff;border:1px solid #e2e8f0;border-radius:1rem;padding:1rem;box-shadow:0 20px 45px rgba(15,23,42,.15);z-index:9999;color:#0f172a}'
        + '.panel[hidden]{display:none}'
        + '.head{display:flex;align-items:center;justify-content:space-between;padding:0 .15rem .75rem;border-bottom:1px solid #f1f5f9;margin-bottom:.75rem}'
        + '.title{font-size:.74rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#64748b}'
        + '.portal-link{font-size:.8rem;font-weight:600;color:#0b5d78;text-decoration:none}'
        + '.portal-link:hover{text-decoration:underline}'
        + '.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.55rem}'
        + '.tile{display:flex;flex-direction:column;align-items:center;gap:.42rem;text-decoration:none;color:#0f172a;padding:.6rem .35rem;border-radius:.75rem;border:1px solid transparent;transition:background .15s,border-color .15s,transform .12s}'
        + '.tile:hover{background:#f8fafc;border-color:#e2e8f0;transform:translateY(-1px)}'
        + '.tile.current{background:#e0f2fe;border-color:#bae6fd}'
        + '.logo-box{width:2.9rem;height:2.9rem;border-radius:.75rem;background:#f8fafc;border:1px solid #e2e8f0;display:grid;place-items:center;padding:.35rem;overflow:hidden}'
        + '.logo-box img{width:100%;height:100%;object-fit:contain;display:block}'
        + '.tile-label{font-size:.77rem;font-weight:600;line-height:1.2;text-align:center;word-break:break-word;color:#1e293b}'
        + '.loading{grid-column:1/-1;text-align:center;font-size:.82rem;color:#64748b;padding:1.25rem 0}'
        + '</style>'
        + '<button id="trigger" class="trigger" type="button" aria-haspopup="true" aria-expanded="false" title="Aplikasi BP3KP">'
        + '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="5" cy="5" r="2"/><circle cx="12" cy="5" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="12" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="19" cy="12" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="12" cy="19" r="2"/><circle cx="19" cy="19" r="2"/></svg>'
        + (label ? '<span>' + esc(label) + '</span>' : '')
        + '</button>'
        + '<div id="panel" class="panel" hidden>'
        + '<div class="head"><span class="title">Aplikasi BP3KP</span><a class="portal-link" href="' + esc(base + '/') + '" target="_blank" rel="noopener">Portal SSO &#8599;</a></div>'
        + '<div id="grid" class="grid"></div>'
        + '</div>';
      var self = this;
      this.shadowRoot.getElementById('trigger').addEventListener('click', function(e){
        e.stopPropagation();
        self._toggle();
      });
    }
  }

  customElements.define('bp3kp-app-switcher', Bp3kpAppSwitcher);
})();
`
