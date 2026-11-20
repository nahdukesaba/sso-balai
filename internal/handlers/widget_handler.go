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
}

// PublicApps returns active applications with launch URLs for the universal app-switcher widget.
func (h *BrowserSSOHandler) PublicApps(c *fiber.Ctx) error {
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set("Access-Control-Allow-Methods", "GET, OPTIONS")
	c.Set(fiber.HeaderCacheControl, "public, max-age=60")
	if c.Method() == fiber.MethodOptions {
		return c.SendStatus(fiber.StatusNoContent)
	}

	var items []publicAppItem
	if h != nil && h.adminRepo != nil {
		apps, err := h.adminRepo.ListApplications(c.UserContext())
		if err == nil {
			for _, a := range apps {
				if !a.IsActive || strings.TrimSpace(a.LaunchURL) == "" {
					continue
				}
				items = append(items, publicAppItem{
					Code:      a.Code,
					Name:      a.Name,
					LaunchURL: a.LaunchURL,
				})
			}
		}
	}
	if items == nil {
		items = []publicAppItem{}
	}
	return c.JSON(fiber.Map{
		"apps": items,
	})
}

// AppSwitcherWidgetJS serves the universal <bp3kp-app-switcher> Web Component.
func (h *BrowserSSOHandler) AppSwitcherWidgetJS(c *fiber.Ctx) error {
	c.Set("Access-Control-Allow-Origin", "*")
	c.Set(fiber.HeaderCacheControl, "public, max-age=300")
	c.Type("application/javascript", "utf-8")

	scheme := c.Protocol()
	if xfProto := strings.TrimSpace(c.Get("X-Forwarded-Proto")); xfProto != "" {
		scheme = strings.Split(xfProto, ",")[0]
	}
	defaultOrigin := fmt.Sprintf("%s://%s", scheme, c.Hostname())
	return c.SendString(strings.ReplaceAll(appSwitcherWidgetScript, "__DEFAULT_SSO_ORIGIN__", defaultOrigin))
}

const appSwitcherWidgetScript = `(function(){
  if (typeof window === 'undefined' || !window.customElements || customElements.get('bp3kp-app-switcher')) return;

  var scriptEl = document.currentScript;
  var detectedOrigin = '__DEFAULT_SSO_ORIGIN__';
  if (scriptEl && scriptEl.src) {
    try { detectedOrigin = new URL(scriptEl.src).origin; } catch (_) {}
  }

  var ICONS = {
    silapet: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="3" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="3" width="7" height="7" rx="1.5"/><rect x="14" y="14" width="7" height="7" rx="1.5"/><rect x="3" y="14" width="7" height="7" rx="1.5"/></svg>',
    klinik_pkp: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M4.8 2.3A.3.3 0 1 0 5 2H4a2 2 0 0 0-2 2v5a6 6 0 0 0 6 6v0a6 6 0 0 0 6-6V4a2 2 0 0 0-2-2h-1a.2.2 0 1 0 .3.3"/><path d="M8 15v1a6 6 0 0 0 6 6v0a6 6 0 0 0 6-6v-4"/><circle cx="20" cy="10" r="2"/></svg>',
    arsiparis: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="4" width="20" height="5" rx="1"/><path d="M4 9v9a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2V9"/><path d="M10 13h4"/></svg>',
    kompu: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="2" y="3" width="20" height="14" rx="2"/><path d="M8 21h8"/><path d="M12 17v4"/></svg>',
    sijabu: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M3 9l9-7 9 7v11a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/><polyline points="9 22 9 12 15 12 15 22"/></svg>',
    'realisasi-bsps': '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 20V10"/><path d="M18 20V4"/><path d="M6 20v-4"/></svg>',
    account: '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 22s8-4 8-10V5l-8-3-8 3v7c0 6 8 10 8 10z"/><path d="m9 12 2 2 4-4"/></svg>'
  };

  var PALETTE = {
    silapet: { bg: '#CBE5F3', fg: '#0284C7' },
    klinik_pkp: { bg: '#C6EBDD', fg: '#0F766E' },
    arsiparis: { bg: '#F7DFC2', fg: '#D97706' },
    kompu: { bg: '#E5DAF7', fg: '#7C3AED' },
    sijabu: { bg: '#CCEAE6', fg: '#0B5D78' },
    'realisasi-bsps': { bg: '#F8D7DA', fg: '#E11D48' },
    account: { bg: '#EFE8D2', fg: '#0B5D78' }
  };

  var FALLBACK = [
    { bg: '#CBE5F3', fg: '#0284C7' },
    { bg: '#C6EBDD', fg: '#0F766E' },
    { bg: '#F7DFC2', fg: '#D97706' },
    { bg: '#E5DAF7', fg: '#7C3AED' },
    { bg: '#F8D7DA', fg: '#E11D48' }
  ];

  function colorFor(code, idx) {
    var key = (code || '').toLowerCase();
    return PALETTE[key] || FALLBACK[idx % FALLBACK.length];
  }

  function iconFor(code) {
    var key = (code || '').toLowerCase();
    return ICONS[key] || ICONS.silapet;
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
      fetch(this._ssoBase() + '/api/v1/public/apps')
        .then(function(r){ return r.json(); })
        .then(function(data){
          self._apps = Array.isArray(data.apps) ? data.apps : [];
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
      var html = '';
      var apps = this._apps || [];
      for (var i = 0; i < apps.length; i++) {
        var a = apps[i];
        var c = colorFor(a.code, i);
        var isCurrent = current && String(a.code || '').toLowerCase() === current;
        html += '<a class="tile' + (isCurrent ? ' current' : '') + '" href="' + esc(a.launchUrl) + '" target="_blank" rel="noopener">'
          + '<span class="icon-box" style="background:' + c.bg + ';color:' + c.fg + '">' + iconFor(a.code) + '</span>'
          + '<span class="tile-label">' + esc(a.name) + '</span>'
          + '</a>';
      }
      var acc = PALETTE.account;
      html += '<a class="tile" href="' + esc(base + '/') + '" target="_blank" rel="noopener">'
        + '<span class="icon-box" style="background:' + acc.bg + ';color:' + acc.fg + '">' + ICONS.account + '</span>'
        + '<span class="tile-label">Akun SSO</span>'
        + '</a>';
      grid.innerHTML = html;
    }

    _render() {
      var label = this.getAttribute('label') || '';
      var align = this.getAttribute('align') === 'left' ? 'left:0' : 'right:0';
      var base = this._ssoBase();
      this.shadowRoot.innerHTML = '<style>'
        + ':host{position:relative;display:inline-block;font-family:system-ui,-apple-system,"Segoe UI",Roboto,Inter,sans-serif}'
        + '.trigger{display:inline-flex;align-items:center;gap:.45rem;padding:.45rem .75rem;border-radius:.75rem;border:1px solid rgba(15,23,42,.14);background:#FDFBF4;color:#0B333D;font:inherit;font-size:.85rem;font-weight:600;cursor:pointer;box-shadow:0 1px 2px rgba(15,23,42,.06);transition:background .15s,transform .1s}'
        + '.trigger:hover{background:#F5EEDC}'
        + '.trigger svg{width:1.1rem;height:1.1rem;flex-shrink:0}'
        + '.panel{position:absolute;top:calc(100% + .55rem);' + align + ';width:min(22rem,calc(100vw - 1.5rem));background:#FDFBF4;border:1px solid #E5DEC9;border-radius:1.25rem;padding:1rem;box-shadow:0 20px 45px rgba(15,23,42,.18);z-index:9999;color:#0B333D}'
        + '.panel[hidden]{display:none}'
        + '.head{display:flex;align-items:center;justify-content:space-between;padding:0 .25rem .75rem}'
        + '.title{font-size:.75rem;font-weight:700;letter-spacing:.06em;text-transform:uppercase;color:#64748B}'
        + '.portal-link{font-size:.82rem;font-weight:600;color:#0B5D78;text-decoration:none}'
        + '.portal-link:hover{text-decoration:underline}'
        + '.tray{background:#F5EEDC;border-radius:1rem;padding:1rem .75rem}'
        + '.grid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:.85rem .5rem}'
        + '.tile{display:flex;flex-direction:column;align-items:center;gap:.42rem;text-decoration:none;color:#0B333D;padding:.35rem .25rem;border-radius:.75rem;transition:background .15s,transform .12s}'
        + '.tile:hover{background:rgba(255,255,255,.6);transform:translateY(-1px)}'
        + '.tile.current{background:rgba(11,93,120,.1)}'
        + '.icon-box{width:3rem;height:3rem;border-radius:.95rem;display:grid;place-items:center;box-shadow:0 1px 2px rgba(15,23,42,.05)}'
        + '.icon-box svg{width:1.35rem;height:1.35rem}'
        + '.tile-label{font-size:.78rem;font-weight:600;line-height:1.2;text-align:center;word-break:break-word}'
        + '.loading{grid-column:1/-1;text-align:center;font-size:.82rem;color:#64748B;padding:1rem 0}'
        + '</style>'
        + '<button id="trigger" class="trigger" type="button" aria-haspopup="true" aria-expanded="false" title="Aplikasi BP3KP">'
        + '<svg viewBox="0 0 24 24" fill="currentColor" aria-hidden="true"><circle cx="5" cy="5" r="2"/><circle cx="12" cy="5" r="2"/><circle cx="19" cy="5" r="2"/><circle cx="5" cy="12" r="2"/><circle cx="12" cy="12" r="2"/><circle cx="19" cy="12" r="2"/><circle cx="5" cy="19" r="2"/><circle cx="12" cy="19" r="2"/><circle cx="19" cy="19" r="2"/></svg>'
        + (label ? '<span>' + esc(label) + '</span>' : '')
        + '</button>'
        + '<div id="panel" class="panel" hidden>'
        + '<div class="head"><span class="title">Aplikasi BP3KP</span><a class="portal-link" href="' + esc(base + '/') + '" target="_blank" rel="noopener">Portal SSO &#8599;</a></div>'
        + '<div class="tray"><div id="grid" class="grid"></div></div>'
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
