---
title: Frontend architecture
purpose: Explain how the VEYRS console and the two static sites are built, served, cached and secured, so an engineer can change or deploy them without surprises.
scope: Files, serving model, caching, CSP, libraries and guard tests of the console (frontend/console) and the two site builders; per-screen behaviour is in console.md and the site builders are detailed in sites.md.
version: 0.39.1
verified: 2026-11-17
status: Verified
sources: [frontend/console/index.html, frontend/console/app.js, frontend/console/console.css, infrastructure/nginx-veyrs-console.conf, docker/console.conf, docker/Dockerfile, site/build.py, site/web/build_web.py, tests/test_console_redesign_0370.py, tests/test_phase31_console_wiring.py]
related: [frontend/console.md, frontend/sites.md, DESIGN_SYSTEM.md, DEPLOYMENT.md, ARCHITECTURE.md, SECURITY.md]
---

# Frontend architecture

VEYRS has three browser-facing surfaces. None of them uses a JavaScript framework, a bundler or a package manager.

| Surface | Source | What it is | Rendered by |
|---|---|---|---|
| Console | `frontend/console/` | The single-page management UI operators sign in to | The browser, at run time (vanilla JS) |
| Docs Center | `site/build.py`, `site/static/` | Every Markdown file under `docs/` as static HTML plus a client-side search | Python, at build time |
| Product site | `site/web/build_web.py` | Marketing and install pages (Overview, Capabilities, Architecture, Security, Manual, Download, Install, Docs) | Python, at build time |

The console is the only surface that talks to the API. Both sites are plain HTML that is rebuilt into a document root on each node.

## The console in one page

| File | Lines | Role |
|---|---|---|
| `frontend/console/index.html` | 106 | Login form, application shell (sidebar, top bar, `#view`), toast stack, modal root. No inline script and no inline event handler. |
| `frontend/console/app.js` | 9,559 | The whole application: API client, router, navigation, 27 routes and one redirect, chart renderers, dialogs. One file, `'use strict'`, no modules. |
| `frontend/console/console.css` | 1,304 | Design system: tokens for two themes, shell, components, responsive rules. |
| `frontend/console/fonts/` | 6 woff2 + licences | Inter (400, 500, 600, 700) and JetBrains Mono (400, 500), Latin subsets, served from the console's own origin. |

The stylesheet `veyrs-tokens.css` and every image (`veyrs-favicon.png`, `veyrs-logo-on-dark-gradient.png`, `veyrs-mark-gradient.png`) come from `/static/`, which is **not** part of `frontend/console/`; see [Where `/static/` comes from](#where-static-comes-from).

### No build step, no libraries

- There is nothing to compile. The files in `frontend/console/` are the files nginx serves.
- There are no runtime dependencies. The header of `app.js` states the reason: a vulnerability-management console should not ship a dependency tree that its own SCA would have to flag.
- Charts (`trendChart`, `donut`, `stackBar`, ...) are hand-written SVG/HTML strings; icons are the `ICONS` map of inline SVG paths. Nothing is fetched from another origin.
- The console loads no third-party font, script or style. The self-hosted fonts exist so that `font-src 'self'` holds.

> [!NOTE]
> The product site and the Docs Center copy these same font files at build time (the repository holds one copy). Only a product-site build with `--webfonts google` links Google Fonts, for a host whose CSP does not yet admit `font-src 'self'`. See [sites.md](sites.md#known-differences-between-the-sites).

### Single page, hash routing

`index.html` is the only page. `app.js` registers one handler per top-level route (`route('findings', ...)`) and re-renders `#view` on every `hashchange`. An address such as `#/admin?tab=users` is route `admin`, query `tab=users`; `#/findings/<uuid>` is route `findings` with one extra path part (the detail view). Details are in [console.md](console.md#router).

State lives in three places only: JS module variables (current route, caches), `localStorage` (session and preferences, listed in [console.md](console.md#browser-state)) and the DOM. There is no client-side data store; every view fetches what it shows.

## How it is served

### Host install (native, `install.sh`)

nginx serves a **copy** of `frontend/console/` from `/var/www/veyrs-console` (`infrastructure/nginx-veyrs-console.conf:17`). `git pull` does not update it; the upgrade procedure copies the three files again (`docs/DEPLOYMENT.md` Upgrading, `INSTALL.md` "Console and nginx"):

```bash
# On an application node, as root, from the checkout (default /opt/veyrs)
cd /opt/veyrs
install -m 644 frontend/console/app.js frontend/console/console.css \
        frontend/console/index.html /var/www/veyrs-console/
md5sum frontend/console/app.js /var/www/veyrs-console/app.js     # must match
grep -o 'app.js?v=[0-9]*' /var/www/veyrs-console/index.html
```

> [!WARNING]
> The documented copy command installs `app.js`, `console.css` and `index.html` only. The `fonts/` directory is installed by `install.sh` (CHANGELOG 0.37.0) and is not re-copied by the upgrade snippet, so a node whose `fonts/` was never installed renders in fallback fonts without any error. Check `ls /var/www/veyrs-console/fonts`.

The same nginx server block also:

| Location | Behaviour | Source |
|---|---|---|
| `/` | `try_files $uri $uri/ /index.html; expires -1;` so any unknown path serves the SPA and `index.html` is never cached | `infrastructure/nginx-veyrs-console.conf:38-41` |
| `/fonts/` | `expires 30d` | `:44-46` |
| `/static/` | `alias /var/www/veyrs/static/`; `expires 1h` plus `Cache-Control: public, max-age=3600` | `:56-60` |
| `/api/` | Reverse proxy to the API on `127.0.0.1:8000`, `proxy_read_timeout 300s`, `client_max_body_size 128m` | `:62-70` |
| `= /documentation` | `302` to the Docs Center (the console never links to `/`, which on this host is the console itself) | `:52-54` |
| `/healthz` and `/readyz` (regex location) | Proxied to the API with `Cache-Control: no-store` | `:72-75` |

The API is therefore **same-origin** with the console: the browser never makes a cross-origin authenticated request and no CORS configuration is required for this deployment.

### Container install (Docker Compose)

The `console` image target (`docker/Dockerfile`) is `nginx:1.28-alpine` running as uid 101 on port 8080. It copies `frontend/console/` to `/usr/share/nginx/html/`, copies `frontend/brand/logo/` and `frontend/brand/veyrs-tokens.css` into `/usr/share/nginx/html/static/`, and uses `docker/console.conf`. Differences from the host vhost (all documented in the file): no `Strict-Transport-Security` header (the stack terminates plain HTTP), `/static/` is a real directory instead of an alias, the API upstream is re-resolved through Docker DNS (`resolver 127.0.0.11 valid=10s`), `/docs` and `/redoc` are proxied (they only exist outside production), and `/metrics` is deliberately not proxied (`return 404`).

### Where `/static/` comes from

| Install | `/static/` content | Consequence |
|---|---|---|
| Host | `alias /var/www/veyrs/static/`: the **Docs Center** document root. `site/build.py` does a wholesale `copytree` of `site/static/` into `<out>/static/` | A console on a node whose Docs Center has never been built has no `veyrs-tokens.css`: every colour token resolves to its default and the theme looks broken. Build the Docs Center first. |
| Container | Brand files baked into the console image | No cross-vhost dependency |

## Cache busting

`index.html` names its assets with a version query: `/static/veyrs-tokens.css?v=2`, `/console.css?v=21`, `/app.js?v=47` (`index.html:12-13,104`; 0.39.1). The number is bumped by hand in the same commit that changes the asset. Because `index.html` itself is served with `expires -1` (`Cache-Control: no-cache`), a deploy is visible on the next page load. Before 0.37.0 the page was served with only `Last-Modified`, browsers cached it for days and a bumped `?v=` was invisible; the comment in both vhosts records this. `expires`, not `add_header`, is used on purpose: an `add_header` inside a location drops every server-level security header, the CSP included.

Fonts are not versioned (`expires 30d`, stable file names). `/static/` assets live one hour.

## Content-Security-Policy and what it forces

Both vhosts send the same policy (`infrastructure/nginx-veyrs-console.conf:30`, `docker/console.conf:36`):

```text
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;
font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

along with `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer` and `Permissions-Policy: geolocation=(), microphone=(), camera=()` (plus HSTS on the host vhost only).

Rules that follow for anyone editing the console:

1. **No inline script and no `on*=` attribute.** Clicks are wired by `addEventListener`, by element id after `innerHTML`, or by one delegated listener keyed on `data-act` / `data-*` attributes (the `ACTIONS` table). `grep -c 'onclick="' frontend/console/app.js` is `0`.
2. **Inline `style=` is allowed** (`style-src 'unsafe-inline'`) and is used for small layout values; colours should still come from tokens (`tests/test_console_design_system.py`).
3. **Same origin only.** `connect-src 'self'`: the console can only call `/api/v1`. Any link out (`target="_blank" rel="noopener"`) is a navigation, not a fetch.
4. **Images:** `data:` URIs are allowed, remote images are not.
5. **Escaping.** Every dynamic value goes through `esc()` before being placed in a template string that is assigned to `innerHTML` (181 assignments in `app.js`). The one place that injects server HTML unescaped is the TOTP QR code (`r.qr_svg`, `app.js:7034`), produced by the API.

## Security-relevant behaviour

- The access token, refresh token, permission list and organization slug are kept in `localStorage` (`veyrs.at`, `veyrs.rt`, `veyrs.perms`, `veyrs.org`). That is readable by any script on the origin; the CSP above is the mitigation.
- Authorisation is **never** decided in the browser. `can(perm)` only decides what to *offer*; every API call is checked server-side and a refused call renders "Access denied" (see [console.md](console.md#error-handling)).
- The console clears its session on a `401` that survives a token refresh, then shows the sign-in page.

## Guard tests

| Test | What it keeps true |
|---|---|
| `tests/test_phase31_console_wiring.py` | Every top-level selector wired by `on()` exists in `index.html`; `boot()` is the last statement; no direct top-level `.onclick =` on a possibly missing node |
| `tests/test_console_layout_classes.py` | Every CSS class the JS emits is styled; layout primitives exist |
| `tests/test_console_redesign_0370.py` | `expires -1` and no `add_header` in `location /` of all vhosts; fonts present, declared and installed; no font from another origin |
| `tests/test_console_design_system.py`, `test_console_redesign_0380.py` | Both themes define the full token set; no colour literal outside token blocks; one drawn icon per nav group |
| `tests/test_console_configure_frame.py`, `test_console_nav_pin_bottom.py` | Configure is the only pinned group; every tab a Configure page hides has a menu entry; sidebar and frame share `navShown` |
| `tests/test_console_readability_0391.py` | (0.39.1) dates use no-break spaces; asset criticality never uses a severity class; policy JSON is rendered as text; the export guard admits `.woff2` only under `frontend/console/fonts/` |
| `tests/test_console_dialog_payloads.py` | Each create dialog sends a body the API schema accepts (for example `accept-risk` sends `reason`/`until` in the query string) |
| `tests/test_console_docs_link.py`, `test_console_vhost_names.py` | The Documentation link targets the `/documentation` redirect; the vhost answers to every host name the proxy forwards |
| `tests/test_phase42_console_screens.py` | Asset sources and Import teams are registered, in the sidebar, gated on the right permission family, and call routes that exist |

## Deployed state observed on 2026-11-17

Both application nodes serve `frontend/console` files that are **identical to each other** (`app.js` md5 `518b361b278245175c86711eeb887abc`, `index.html` references `app.js?v=47`, `console.css?v=21`). They are also **identical to the documented source copy**, release 0.39.1 (`ab8103e`): same `app.js` md5, same `?v=` numbers. 0.39.1 added no-break dates, a neutral asset-criticality pill (`critPill`), readable escalation ladders and assignment conditions on the Policies page (`ladderSteps`, `matchChips`) and a collapsible Configure menu rail (`veyrs.cfg.rail`); see [console reference](console.md#changes-in-0391). The 0.39.0 file (md5 `2ed290a9fa3207132a28f0542f126e7d`, `?v=46`, `?v=20`) is no longer deployed.
