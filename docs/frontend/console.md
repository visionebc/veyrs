---
title: Console reference
purpose: Describe every part of the VEYRS operator console (router, navigation, shared components, state, every screen, every API call) so it can be operated, debugged and extended from this page.
scope: The single-page console in frontend/console as of 0.39.1 (app.js 9,559 lines); API contracts are in the generated API reference and the end-user task guides are USER_GUIDE.md and USER_MANUAL.md.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [frontend/console/app.js, frontend/console/index.html, frontend/console/console.css, backend/veyrs/api/v1/ai.py, extract/routes.json]
related: [frontend/README.md, APP_FLOW.md, USER_MANUAL.md, USER_GUIDE.md, ADMIN_GUIDE.md, DESIGN_SYSTEM.md, reference/permissions.md, api/reference/README.md]
---

# Console reference

All line numbers refer to `frontend/console/app.js` unless a path is given. The console is read from source; it was not driven in a browser for this document, so the page status is **Implemented**, not Verified. The server-permission column of the [route matrix](#route-to-api-matrix) was computed by matching every literal API path in `app.js` against `extract/routes.json` (`require(...)` declarations), which is machine evidence.

## Boot sequence

1. `app.js` ends with `boot()` (`app.js:9559`); a guard test keeps it the last statement so a throw in the wiring above it cannot leave a blank page.
2. `boot()` (`:1515`) applies the stored theme (`veyrs.theme`, default `dark`), pre-fills the Organization field from `veyrs.org`, and if the hash starts with `#/sso` finishes an OpenID Connect sign-in (`ssoLanding()`, `:7265`).
3. With no access token it shows `#login` and asks `GET /auth/sso` whether to show the *Sign in with SSO* button (`ssoButton()`, `:7285`).
4. With a token it calls `GET /auth/me`. On any failure it calls `logout()` (clears the session, shows the login form).
5. `enterApp(me)` (`:1532`) hides the login, shows `#shell`, sets the user chip, caches `me.permissions`, reads the tenant switches from `/auth/me` (see below), loads `GET /organization` for the sidebar name, starts the 60-second notification poll and renders the current hash, defaulting to `#/triage`.

Tenant switches read **once** from `GET /auth/me` and held in module variables, because the menu is painted once and a menu that gains and loses entries reads as the console losing pages (`:57-114`):

| Variable | `/auth/me` field | Default when absent | Effect |
|---|---|---|---|
| `activeScanning` | `active_scanning` | `true` | Hides the *Vulnerability scanner* page and its palette entry when `false` |
| `ticketingMode` | `ticketing_mode` | `'internal'` | `internal` shows **Tickets**, `external` shows **Issues**; exactly one |
| `ticketingUsable` | `ticketing_usable` | `true` | Issues page warns when the connector is missing or disabled |
| `riskRegisterOn` | `risk_register_enabled` | `true` | Hides **Risk Register** from menu and palette (entries stay readable by URL) |
| `scope` | `scope` | `{restricted:false}` | Team-scoped identities see a "Team view" banner on aggregate screens |
| `prefs.dashboard_team_id` | `preferences.dashboard_team_id` | `null` | Remembered dashboard scope |

Every failure path leaves a switch at its permissive default: an unreadable answer must show a menu entry rather than hide it.

## Browser state

| Key / variable | Where | Holds | Cleared by |
|---|---|---|---|
| `veyrs.at` | localStorage | Access token (default lifetime 30 min, `VEYRS_ACCESS_TOKEN_MINUTES`) | `logout()` |
| `veyrs.rt` | localStorage | Refresh token (default 14 days, `VEYRS_REFRESH_TOKEN_DAYS`; rotates on use) | `logout()` |
| `veyrs.perms` | localStorage | JSON list of the permissions in the token; used by `can()` | `logout()` |
| `veyrs.org` | localStorage | Organization slug last signed in to (pre-fills the login form) | never |
| `veyrs.theme` | localStorage | `dark` (Midnight) or `light` (Porcelain) | never |
| `veyrs.nav.open.groups` | localStorage | The one sidebar group the operator opened | overwritten on click |
| `veyrs.nav.open.items` | localStorage | The one sidebar item with sub-entries the operator opened | overwritten on click |
| `veyrs.nav.rail` | localStorage | `1` when the sidebar is collapsed to an icon rail | toggled |
| `veyrs.cfg.rail` | localStorage | `1` when the Configure menu is folded to its icon rail (0.39.1, `CFG_RAIL_LS`, `:1390`) | toggled |
| `veyrs.explain.dismissed.v1` | localStorage | Keys of the "?" explainer panels the operator collapsed; the `v1` suffix re-opens rewritten explainers | toggled |
| `teamCache`, `savedViews`, `triage`, `palette` | memory | Team list, saved views, triage buffer, palette state | page reload |
| `window.__radiusChallenge` | memory | RADIUS Access-Challenge id between the password and code steps; single use | cleared on each login attempt |

Preferences that must follow a person across browsers (the dashboard team scope) are **not** kept in `localStorage`: they are written to the profile with `PATCH /auth/me/preferences` and read back from `/auth/me` (`:68-76`, `:1638`).

`store.clear()` removes only `at`, `rt` and `perms`; the slug, theme, nav and Configure-rail state survive sign-out.

## API client

`api(path, opts)` (`:167`) wraps `fetch` for every call to `/api/v1`. Helpers `get`, `post`, `patch`, `put`, `del` (`:200-205`) call it; `post` accepts `FormData` (file uploads) without setting a content type.

| Behaviour | Detail |
|---|---|
| Authorization | `Authorization: Bearer <veyrs.at>` on every call except the auth-entry routes |
| JSON | `Content-Type: application/json` is set whenever there is a body that is not `FormData` |
| 401 handling | One shared `POST /auth/refresh` (a single in-flight promise, so a dashboard firing six requests rotates the refresh token once), then the call is retried once. If it still fails: `logout()` and `ApiError(401, 'Session expired')`, or `'Sign in to continue.'` when there was never a session |
| Auth-entry routes | `/auth/login`, `/auth/refresh`, `/auth/sso`, `/auth/oidc/exchange` never trigger refresh-then-logout: their 401 means *wrong credentials* and surfaces the API's own detail |
| 204 | Returns `null` |
| Errors | Non-2xx throws `ApiError(status, detail)`. `detail` is the string `detail`; for FastAPI validation errors an array is flattened to `field: message; ...`; otherwise the first 300 characters of the JSON |
| Success body | JSON when the response is JSON, else text |
| Downloads | Report exports use `rawFetch` and a blob URL (`<a download>`), because a bare link would carry no bearer token |
| Pagination | The API has two dialects (`page`/`size` and `limit`/`offset`). `listView` sends **both**; the server ignores the one it does not know. `pageOf()` normalises arrays and `{items,total,limit,offset}` |

## Router

`render()` (`:1471`) is the only router; `window.addEventListener('hashchange', render)` (`:8683`) is its only trigger (a palette jump to the hash you are already on calls it directly).

1. Parse `location.hash` (default `#/triage`): `#/<name>/<part>/...?<query>` gives `name`, `parts` and `params` (`URLSearchParams`).
2. Return silently if there is no token or the shell is hidden: no view is ever painted behind the login screen.
3. Store `navCtx`, redraw the sidebar and breadcrumbs, close the mobile drawer, show a `Loading…` placeholder and set `aria-busy`.
4. Look up `routes[name]`. Unknown name renders **Not found: No view is registered for "<name>"**.
5. If the route belongs to the Configure group (or is `configure`), `configureFrame()` draws the left menu and returns the frame body as the render target; otherwise the target is `#view`.
6. Call `fn(target, parts, params)`. On success `enhancePage()` sets the tab title (`<h1> · VEYRS Console`), adds the record's own title as the last breadcrumb for detail views and folds page descriptions longer than 180 characters behind a *More* button.
7. On error: `403` renders an **Access denied** card; anything else renders **Could not load this view** with the error text and a *Retry* button (`data-act="reload"`). Both draw into the same target, so the Configure menu stays on screen.

Routes are registered with `route(name, fn)` (`:1372`). List screens use the `listView()` factory, which returns a route function that renders the list, or the detail function when the hash has a second path part.

`MOVED` (`:1464`) holds old hashes that redirect with `location.replace`: only `workflows` -> `#/automation?tab=workflows`.

### Routes

| Route | Page | Detail hash | Tabs (`?tab=`) |
|---|---|---|---|
| `triage` | Triage queue | none | `?queue=` one of `new`, `critical`, `kev`, `sla`, `mine`; `?view=<saved-view-id>` |
| `guide` | Getting Started | none | none |
| `dashboard` | Dashboards | none | `executive` (default), `technical`, `sla`; `&days=` one of 30, 90, 180, 365; `&team=` an id or `all` |
| `search` | Search | none | `?q=` |
| `notifications` | Notifications | none | `inbox` (default), `preferences`, `digest` |
| `findings` | Findings | `#/findings/<id>` | filters, see below |
| `changes` | Recent changes | none | `?kind=` `closed` or `reopened`; `cause=`; `days=` one of 1, 7, 30, 90; `page=` |
| `tickets` | Tickets | `#/tickets/<id>` | filters |
| `issues` | Issues (external ITSM links) | none | filters |
| `vulnerabilities` | Vulnerabilities | `#/vulnerabilities/<id>` | filters |
| `risks` | Risk Register | `#/risks/<id>` | filters |
| `assets` | Inventory | `#/assets/<id>` | filters |
| `intel` | Threat Intel | `#/intel/cve/<id>`, `#/intel/cwe/<id>` | `cve`, `kev`, `news`, `sources`, `runs`, `schedule`; `&scope=` `exposed`, `estate` or `all` |
| `documents` | Documents & Advisories | `#/documents/<id>` | filters |
| `knowledge` | Knowledge Base | `#/knowledge/<id>` | filters |
| `cvss` | CVSS Calculator | none | `?v=` one of 2.0, 3.0, 3.1, 4.0 |
| `ai` | AI Assistant | none | `ask`, `search`, `policy`, `providers`, `audit` |
| `reports` | Reports | none | `fixed` (default), `builder` |
| `compliance` | Compliance | `#/compliance/<framework-id>` | none |
| `audit` | Audit Log | none | `?action=&object_type=` |
| `configure` | Configure overview | none | none |
| `scanner` | Vulnerability scanner | none | none |
| `integrations` | Data sources | none | `import` (default), `scanners`, `runs`, `connectors`, `docs` |
| `policies` | SLA & Policies | none | `sla` (default), `escalation`, `assignment`, `risk`, `events`, `upgrade` |
| `automation` | Automation | none | `tickets` (default), `workflows`, `runs` |
| `admin` | Administration | none | 18 tabs in three sections, see [Administration](#administration-admin) |
| `account` | My account | none | none |

`#/sso` is not a route: it is the identity-provider landing, consumed by `ssoLanding()` before the shell opens (`#/sso?h=<handoff>` or `#/sso?error=<reason>`); the hash is removed from the address bar with `history.replaceState`.

> [!NOTE]
> `#/integrations?tab=itsm` (linked from the Issues empty state, `:3042`, and the Ticketing tab, `:8239`) is not a tab key. It falls through to the final `else` branch, which renders the ITSM connector list, but no tab button is highlighted. The NAV key for that tab is `connectors`.

## Navigation

### NAV

`NAV` (`:927`) is the single description of the menu. The sidebar, the Configure frame, the breadcrumbs and the command palette are all built from it, so they cannot name a page differently. Item fields:

| Field | Meaning |
|---|---|
| `group`, `key`, `ico` | Group title, key, drawn icon name (`ICONS`, 24-unit grid, 1.75 stroke, `currentColor`) |
| `path`, `label`, `ico` | Route name, menu text, icon |
| `perm` | Permission the **palette** requires before listing the page. The sidebar does **not** filter by permission: a page the role cannot read keeps its entry and answers *Access denied* |
| `children` | Sub-entries. `q` is the query string they apply; `def: true` marks the one active when the query is absent; `sec` prints a small heading above that entry |
| `hidden` | Registered route with no menu entry (`search`, `notifications`) |
| `scan: true` | Shown only while `activeScanning` |
| `reg: true` | Shown only while `riskRegisterOn` |
| `mode` | Shown only while it equals `ticketingMode` (`internal` Tickets, `external` Issues) |
| `pin: 'bottom'` | Group rendered in `#nav-pinned` at the foot of the sidebar |

`navShown(i)` (`:1221`) is the one visibility filter: `!hidden && !(scan && !activeScanning) && !(reg && !riskRegisterOn) && !(mode && mode !== ticketingMode)`. The sidebar and the Configure frame share it, so a switched-off page disappears from both. The palette (`paletteCommands()`, `:9135`) applies the same switches **plus** `perm`.

### Sidebar structure (0.39.0, unchanged in 0.39.1)

| Group | Page (route) | Sub-entries | Palette gate (`perm`) |
|---|---|---|---|
| **Overview** | Triage queue (`triage`) | none | `finding:read` |
| | Getting Started (`guide`) | none | none |
| | Dashboards (`dashboard`) | Executive, Technical, SLA | `report:read` |
| | Search, Notifications | hidden (top-bar search box and bell) | none |
| **Work** | Findings (`findings`) | All findings, Critical, New / untriaged, My teams' queue, No owner at all | `finding:read` |
| | Recent changes (`changes`) | none | `finding:read` |
| | Tickets (`tickets`, internal mode) | All, Remediation, Changes, Incidents | `ticket:read` |
| | Issues (`issues`, external mode) | All, Critical, High, Unlinked | `ticket:read` |
| | Vulnerabilities (`vulnerabilities`) | All, Critical, High | `vulnerability:read` |
| | Risk Register (`risks`, when enabled) | All, Open only, Nobody accountable, Review overdue, Mine | `riskregister:read` |
| **Estate** | Inventory (`assets`) | All assets, Internet-exposed, Not internet-facing, Business-critical, Production, Non-production, No owning team | `asset:read` |
| **Intelligence** | Threat Intel (`intel`) | CVE, CISA KEV, News, then under *Feeds*: Sources, Feed runs, Schedule | `cve:read` |
| | Documents & Advisories (`documents`) | none | `document:read` |
| | Knowledge Base (`knowledge`) | none | `knowledge:read` |
| | CVSS Calculator (`cvss`) | none | none |
| | AI Assistant (`ai`) | Ask, Natural-language search, then under *Configure*: Policy, Providers, AI audit | `ai:read` |
| **Reporting** | Reports (`reports`) | none | `report:read` |
| | Compliance (`compliance`) | none | `compliance:read` |
| | Audit Log (`audit`) | none | `audit:read` |
| **Configure** (pinned) | one sidebar entry, `#/configure` | the five pages below appear in the Configure frame, not in the sidebar | |

There is no *Tools* group any more (CVSS Calculator moved under Intelligence in 0.36.0) and Configure is no longer a tree in the sidebar (0.39.0).

### Configure hub and frame (0.39.0; rail added in 0.39.1)

`NAV` group `configure` has five pages:

| Page (route) | Palette gate | Sub-entries (`?tab=`) |
|---|---|---|
| Vulnerability scanner (`scanner`, `scan: true`) | `agent:read` | none |
| Data sources (`integrations`) | `importer:read` | Scanner import, Scanner connectors, Import runs, ITSM connectors, Documentation |
| SLA & Policies (`policies`) | `sla:read` | SLA policies, Escalation, Assignment rules, Risk profiles, SLA events, Upgrade paths |
| Automation (`automation`) | `workflow:read` | Automatic tickets, Workflows, Workflow runs |
| Administration (`admin`) | `user:read` | *Access*: Users, Teams, Roles, Departments, API keys, Directory, RADIUS, Single sign-on. *Data intake*: Ticketing, Asset sources, Import teams, Scanning. *Platform*: Risk register, Secret storage, Organization, Installed software, Network access, Software update |

- `route('configure')` (`:1444`) renders one card per **shown** page with a one-line blurb (`CONFIGURE_BLURB`) and its sub-entry count.
- `configureFrame(view, name, params)` (`:1393`) wraps every Configure page and the hub in `.cfg`: a left menu (Overview, then each shown page, with the current page's sub-views indented and *Access / Data intake / Platform* sub-headings) and a body the page draws into. On narrow screens (below 900 px) the menu becomes a toggle button (`aria-expanded`). The menu is 216 px wide (`.cfg`, `console.css:803`; 236 px in 0.39.0).
- When the frame lists every tab of a page, the page hides its own tab bar and Administration its section switch: two menus for one choice is noise. `tests/test_console_configure_frame.py` pins that every hidden tab has a menu entry.
- **Rail (0.39.1).** A button at the top of the menu (`.cfg-rail-btn`, `:1420`) folds it to a 52 px icon rail (`.cfg.rail`, `console.css:837-850`, applied above 900 px only). The choice is stored per browser in `veyrs.cfg.rail` (`:1414-1440`). Folded, the page labels and sub-views leave the menu, so the page's own tab bar and Administration's section switch come back (`.cfg.rail .cfg-body[data-subnav] > .tabs`); wide tables get the width. `tests/test_console_configure_frame.py::test_the_menu_folds_to_a_rail_and_the_tabs_come_back` pins it. The button's `title` and `aria-pressed` follow the state, but its `aria-label` stays "Collapse the Configure menu" when folded (`:1420`, `:1435-1438`).
- The Administration section switch (`ADMIN_SECTIONS`, `:7306`) is `Access` (8 tabs), `Data intake` (4), `Platform` (6).

### Sidebar behaviour

- Groups and items start **collapsed**; opening one closes the previous one (`navSelect`, exclusive at both levels, at most one key stored). The group and item holding the current route are forced open at render time and the stored preference is not changed.
- A sub-entry with no `q` is the "All ..." entry and is active only while none of its siblings' filters are in the URL (`navChildActive`).
- `#rail-btn` collapses the sidebar to a 68 px icon rail (`veyrs.nav.rail`); below 900 px the sidebar is an off-canvas drawer toggled by `#menu-btn`.
- `renderNav` scrolls the nav (never the page) to bring the active entry into view (0.36.1).
- The footer holds the user chip (links to `#/account`), the theme toggle, the documentation link (`/documentation`, new tab) and sign-out.

### Breadcrumbs (0.37.0)

`renderCrumbs()` (`:1284`) shows *Group / Page / Sub-view / Record*. The group crumb links to `#/configure` for the pinned group and is plain text otherwise; the record title is added by `enhancePage` from the page's `<h1>` when the hash has an id.

### Command palette and shortcuts

| Key | Where | Action |
|---|---|---|
| `Ctrl+K` / `Cmd+K` | anywhere inside the app | Open the palette (`:9304`) |
| `Esc` | palette, dialogs, chart tooltip | Close the topmost layer |
| `Up` / `Down`, `Enter` | palette | Move, open |
| `T` `A` `F` `R` `S` | Triage queue | Ticket, Assign, False positive, accept Risk, Skip |
| `J` / `K` or arrows | Triage queue | Next / previous finding |
| `Enter` | Triage queue | Open the finding in full |

The palette lists permitted NAV pages and sub-entries, the five triage queues, the operator's saved finding views, *Toggle light / dark theme* and *Sign out*, and as you type adds `GET /search?q=&limit_per_type=5` hits (CVE, vulnerability, finding, asset, ticket, document, knowledge article); a later keystroke never overwrites an earlier slower one (`palette.seq`). Triage shortcuts are ignored when an input, a dialog or a modifier key is active.

## Shared components

| Component | Function | Notes |
|---|---|---|
| List screen | `listView()` `:1830` | Title and blurb, filter toolbar (`select` for fixed options, `input` otherwise), optional saved-view chips, bulk-action bar, pager. Filter values live in the URL. Empty **and** unfiltered renders `notConfigured()` (setup steps); empty **and** filtered renders "No records match these filters" |
| Table | `table(cols, rows, opts)` `:434` | `cols[].cell` returns HTML; optional checkbox column (`data-pick`) wired by `wireSelection()` to the bulk bar |
| Modal | `modal({title, body, actions, wide, dismiss})` `:300` | Returns a promise of the form values (`name` attributes) or `null`. `Esc` closes the topmost dialog only, Tab is trapped, focus returns to the opener. `keepOpen` actions can validate before closing |
| Toast | `toast()` / `ok()` / `err()` `:284` | Stack in a live region; 4 s, errors 7 s |
| Explainer | `explainer(key, {title, what, who, effect, warn, links})` `:378` | The "?" panel on configuration screens: what it decides, who touches it, what changes. Collapse state in `veyrs.explain.dismissed.v1` |
| Team scope banner | `scopeBanner()` `:116` | "Team view" notice when `/auth/me` reports a restricted scope |
| Ownership dialog | `assignDialog()` `:1926` | Team picker with *Leave unchanged* and *Clear the owner*; optional reason. Used for findings and assets |
| Saved views | `loadViews`, `viewChips`, `saveViewDialog`, `deleteViewDialog` `:8729-8812` | Chips for pinned views per entity; applying a view replaces the filters wholesale and goes back through the normal list endpoint, so team scope still applies |
| Page enhancer | `enhancePage()` `:1311` | Tab title, detail crumb, "More" fold |
| Chart tooltip | IIFE `:1342` | One styled tooltip for every chart; marks keep `title` until first hover, then it moves to `data-tip` |
| Helpers | `esc`, `fmtNum`, `fmtPct`, `fmtScore`, `fmtDate`, `fmtDay`, `titleCase`, `sevPill`, `critPill`, `ladderSteps`, `matchChips`, `statePill`, `qs` | `esc` is the HTML-escape applied to every dynamic value; dates are joined with no-break spaces (0.39.1); `critPill` is the neutral asset-criticality pill, never a severity colour |

Global `window` functions exist for the buttons rendered by `listView` actions (`window.newAsset`, `newTicket`, `uploadDoc`, `newArticle`) and are reached through the delegated `data-act` listener (`ACTIONS`, `:8671`); there are no inline handlers.

## Charts

All charts are generated SVG or CSS-bar HTML strings, with the value in text so colour is never the only encoding. `chartData()` adds a *Show data* table behind a disclosure for keyboard and screen-reader users.

| Function | Draws | Used by |
|---|---|---|
| `bars(obj, palette)` `:478` | Horizontal bars with count and share in the tooltip | Technical dashboard lifecycle states |
| `stackBar(obj, order)` `:503` | One 100 % strip of a single total with a legend carrying every number; sub-0.5 % segments still get a 3 px sliver | Severity composition |
| `donut(obj, order)` `:670` | Part-to-whole ring plus legend table (the Executive "Backlog composition") | Executive |
| `kpi(o)` / `delta(n, opts)` / `kpiSpark(vals, label)` `:536-575` | KPI tile with signed window delta (`goodWhen` decides which direction is green; text says improved/worse) and a sparkline listing its values | Executive, SLA |
| `trendChart(points, opts)` `:596` | Line/area chart with snapped y range, gridlines, real gaps for empty buckets, per-bucket hover | Risk trend |
| `smoothPath(pts)` `:645` | Monotone cubic (Fritsch-Carlson) path: smooth and never overshoots | `trendChart`, `flowColumns` |
| `flowColumns(points)` `:779` | Back-to-back columns around a zero baseline: detected up, remediated down | Detected vs remediated |
| `splitBars(left, right, opts)` `:733` | Scanner severity beside VEYRS risk level with signed deltas | Executive |
| `histogram(obj, unit)` `:761` | Ordered numeric bins, one hue | CVSS and EPSS distributions |
| `rankedBars(rows, opts)` `:822` | Ranked list with one hue | Top assets, environments, products, teams |
| `ring(ratio, target)` `:576` | Radial gauge of one ratio against a target | SLA compliance (target 0.9) |
| `meter(ratio)` `:717` | Bar showing where a ratio sits between 0 and 100 % | SLA compliance |
| `opsList(rows)` `:698` | Label, hint and value rows for figures not worth a tile | Executive "Exposure and operations" |
| `sparkline(points)` `:865` | Small uniformly scaled SVG line | Intel and scanner screens |
| `riskBand(score)` `:844` | Maps a 0-100 risk score to critical/high/medium/low; the cut points mirror `LEVEL_BANDS` in `backend/veyrs/engines/risk.py` | Ranked-bar colours |

Colour rules recorded in the code: severity colours mean severity only; the high/medium pair is nearly indistinguishable under deuteranopia, so every mark also carries its label and number.

## Themes

Two themes, selected by `<html data-theme>` (always present; both are scoped to the attribute):

| Value | Name | Default |
|---|---|---|
| `dark` | Midnight: graphite surfaces, midnight sidebar | Yes (0.38.0) |
| `light` | Porcelain: white panels on cool grey, light sidebar | No |

The toggle in the sidebar footer (and the palette action) calls `applyTheme()` first and stores `veyrs.theme` second, so a private window that refuses storage still switches. Tokens come from `/static/veyrs-tokens.css` (brand) and the token blocks of `console.css`; breakpoints are 640, 900 and 1000 px; `prefers-reduced-motion` and `forced-colors` have explicit rules. The login hero is always midnight whatever the theme.

## Error handling

| Situation | What the user sees | Source |
|---|---|---|
| `401` on a normal call | One silent refresh and retry; if that fails the sign-in page, error text **Session expired** | `:167-186` |
| `401` on `/auth/login` | The API's own detail (for example "invalid credentials") in the form's error line | `:154-165`, `:8549` |
| `401 mfa_required` on login | The *Two-factor code* field appears, labelled by method (`totp`, `email`, `telegram`, `radius` with the server's challenge text); for e-mail and Telegram the code has already been sent; `throttled` says to wait `retry_after` seconds | `:8564-8592` |
| `503 mfa_delivery_failed` | "Your sign-in code could not be sent ... Use a recovery code" | `:8593` |
| `403` while rendering a view | **Access denied** card inside the same frame ("VEYRS enforces authorization server-side") | `:1494-1496` |
| `403` on a tab that needs more than a role (Secret storage, Software update) | An explanatory card (estate-wide `settings:admin`; platform administrator) | `:6518`, `:6610` |
| `422` from a create dialog | The flattened `field: message` text in an error toast; dialogs that know a rule check it first (full name 2+ characters, risk-acceptance reason 10+ characters, passwords equal, valid JSON for SLA conditions and risk weights) | `:7366`, `:2664`, `:7077` |
| Any other failure | Error toast (7 s) with the API detail; list/detail views show **Could not load this view** with *Retry* | `:1497-1500` |
| Optional data that fails | Swallowed on purpose: team list, notifications, saved views, fix plan, ITSM links, `/policies/sla/summary`. The page renders without them rather than failing | `:38-44`, `:1564-1570`, `:8729-8742` |

The console never invents a permission failure: it shows what the server said.

## Loading, empty and not-configured states

| State | Rendering |
|---|---|
| Loading | `<div class="loading">Loading…</div>` in `#view` and in tab bodies; `aria-busy` on `#view` while a route runs |
| Empty list, no filters | `notConfigured({title, hint, steps})`: a numbered list of setup links (for example Findings: load the estate, import a scanner export, check the feeds, enable the scanner or configure a connector) |
| Empty list, filters applied | "No records match these filters. The list itself is not empty: clear the filters to see it." |
| Empty table inside a card | `table()` renders an icon, `emptyTitle` and `emptyHint` |
| Scanning off | Scanner page stays registered and explains the mode; the menu entry and palette entry are removed |

## Screens

Every screen below lists its route, who can open it (palette gate; the server still decides), what it does and the API it calls. The consolidated call list is the [matrix](#route-to-api-matrix).

### Sign-in (`#login`)

Fields: **Organization** (slug), **Email or username** (`type=text`, because `type=email` would make a username impossible to type), **Password**, and a hidden **Two-factor code** (`maxlength 20`). Submit sends `POST /auth/login {identifier, password, organization, mfa_code?, radius_challenge?}` (`:8549-8562`); the legacy field `email` is still accepted by the API. On success it stores the tokens and slug, reads `/auth/me` and enters the app. *Sign in with SSO* appears when `GET /auth/sso` reports `available`; it needs the Organization field and calls `GET /auth/oidc/<org>/start`, then navigates to the returned `authorization_url`. The return trip lands on `#/sso?h=...` and `POST /auth/oidc/exchange {handoff}` swaps it for tokens.

### Triage queue (`#/triage`)

One finding at a time with the context needed to decide. Queues: **Never triaged** (`state=new`), **Critical**, **Known exploited** (`kev=true`), **Past its deadline** (`sla_breached=true`), **My teams' queue**; or a saved view (`?view=<id>`). Each queue is a preset query on `GET /findings` ordered by risk (SLA queue by deadline), fetched 50 at a time; the detail of the card is `GET /findings/<id>`. Actions:

| Action | Call | Notes |
|---|---|---|
| Ticket | `POST /findings/<id>/remediation` | Creates (or returns) the remediation ticket, or raises an issue in the external ITSM; idempotent. Needs `ticket:write` (checked before the call) |
| Assign | `POST /findings/bulk-assign {finding_ids, assigned_team_id or clear, reason}` | `Nothing changed` if neither team nor person chosen |
| False positive | `POST /findings/<id>/transition {state:false_positive, note}` | Closes; a re-detection reopens as new |
| Accept risk | `POST /findings/<id>/transition {state:triaged}` if the finding is `new`, then `POST /findings/<id>/accept-risk?reason=&until=` | `reason` 10+ characters; `reason` and `until` travel in the **query string**. Gated in the console on `risk:admin` (the server requires the same) |

After an action the finding leaves the local buffer and the counter ("12 of 149 - 3 disposed this sitting") updates. Saved views of findings can be created from the current queue (`Save this view`) and deleted.

### Getting Started (`#/guide`)

The scan -> risk -> ticket chain with live counts: findings (`GET /findings?size=1`), critical findings, remediation tickets and all tickets (`GET /tickets?size=1&ticket_type=remediation`), and, only while scanning is on, `GET /agents?limit=5` and `GET /agents/jobs/summary`. A chain is flagged broken when findings exist and no remediation ticket does. Every request is optional (`total()` returns null on failure) and the cell shows a dash.

### Dashboards (`#/dashboard`)

Tabs **Executive**, **Technical**, **SLA**. A *Scope* selector (whole estate or one team) is remembered in the profile (`PATCH /auth/me/preferences {dashboard_team_id}`; a URL `team=` wins for that render and is not written back; `team=all` is the explicit estate token). A time-range control (**30 d, 90 d, 6 mo, 1 yr**) sets `days` (default 90, API range 7-730) on Executive and SLA; Technical is a snapshot of what is open now and hides it. The banner under the head is built from the payload's own `scope` block, not the cached token.

| Tab | Calls | Content |
|---|---|---|
| Executive | `GET /dashboard/executive?days=&team_id=` | Five KPI tiles (open findings with net flow and sparkline, critical, known exploited, average VEYRS risk with delta, SLA breached), risk trend, backlog donut, detected vs remediated, severity vs risk, exposure and operations (internet-facing, high EPSS, escalated, asset coverage, MTTR with a reliability flag), top assets by peak risk, risk by environment, top products, risk by team |
| Technical | `GET /dashboard/technical?team_id=` | Scored sample, known exploited, EPSS > 10 %, theoretical only, CVSS and EPSS histograms, top CWE (links to `#/intel/cwe/<id>`), lifecycle states, findings by scanner |
| SLA | `GET /dashboard/sla?days=&team_id=` and `GET /policies/sla/summary` | Under an SLA, due within 3 days, breached and open, escalated, compliance ring and meter (target 90 %), by-severity table |

Dashboards do not render a figure without its denominator ("12 critical of 430 open") and mark MTTR or SLA compliance over a small sample as unreliable.

### Findings (`#/findings`, `#/findings/<id>`)

List filters: `state`, `severity`, `owning_team_id`, `queue` (`my_teams`, `mine`, `unowned`; translated by `mapQuery` into the three boolean API flags) and `q`. Columns: title with port/protocol/path, severity, risk, CVSS, EPSS, KEV, state, age, owner (marks "via asset" when ownership is inherited), SLA. Saved views are enabled. Bulk bar (shown when rows are ticked): **Assign to team...** (`finding:write`) and **Create tickets...** / **Raise issues...** (`ticket:write`; one `GET /findings/<id>` plus `POST /findings/<id>/remediation` per finding, counting successes and failures).

Detail actions: **Transition...** (target state `select` of all 15 states, note; the server refuses illegal edges with 409), **Create ticket / Raise issue**, **Re-score** (`POST /findings/<id>/rescore`), **Accept risk...** (reason 10+ characters, optional review date; triages a `new` finding first), **Explain** and **Remediation** (`POST /ai/findings/<id>/explain|remediation`, labelled AI output). Panels: Risk (VEYRS risk, CVSS, EPSS, technical/exploitability/business/exposure sub-scores, "Why this score" factors), Context (CVE, vulnerability, asset, criticality, exposure, owner, SLA, escalation level), Detail, Recommendation, Fix plan (`GET /findings/<id>/fix-plan`), History, and **Why did this change?** (`GET /findings/<id>/attribution`).

### Recent changes (`#/changes`)

Closed and reopened findings in a window with the recorded cause: `GET /findings/changes?since=&page=&size=50&kind=&cause=`. Filters: kind, cause (options from the payload), window 24 h / 7 d / 30 d / 90 d. Paged by page number.

### Vulnerabilities (`#/vulnerabilities`)

Filters `q`, `severity`. Columns: identifier, title, severity, CVSS with version, EPSS with percentile, KEV, risk, state. Detail: `GET /vulnerabilities/<id>` with risk, CVSS, EPSS, created and description; link to the CVE page.

### Inventory (`#/assets`)

Filters: `q`, `asset_type`, `criticality`, `exposure`, `environment`, `exclude_environment`, `exclude_exposure`, `team_id`, `unowned`. Bulk **Assign to team...** (`asset:write`) -> `POST /assets/bulk-assign {asset_ids, team_id | clear}`. **New asset** dialog (fields below). Detail: identity, business context, installed products, open findings (`GET /findings?asset_id=&size=25`), fix plan (`GET /assets/<id>/fix-plan`), **Re-correlate** (`POST /assets/<id>/rescan`) and **Delete** (confirmation; findings go with it).

### Tickets (`#/tickets`, internal mode) and Issues (`#/issues`, external mode)

Tickets: filters `state`, `ticket_type` (`incident`, `problem`, `change`, `remediation`, `service_request`), `priority`; **New ticket** dialog; detail with description, resolution, team, finding and asset links, change fields (approver, window) for `change` tickets, external links, comments and history. **Transition...** offers only the states in `allowed_transitions` returned by the API (the server owns the ITIL graph; a change cannot close without approval). **Comment...**, **Push to ITSM** (`POST /integrations/connectors/<cid>/push/<ticket>`).

Issues: the relation between a finding and an issue raised in the external ITSM (`GET /integrations/links`). Filters `q`, `severity`, `remote_status`, `is_active`. Row actions **Refresh** (`POST /integrations/links/<id>/refresh`; a recorded remote failure is shown from `last_error` rather than thrown) and **Unlink** (`.../unlink`; the remote issue is not touched). Both need `ticket:write`.

### Risk Register (`#/risks`)

Risks that are not findings, with a RACI. Summary tiles from `GET /risks/summary` (open, critical and high, nobody accountable, review overdue). Filters `status`, `band`, `category`, `treatment`, `open_only`, `review_overdue`, `unassigned`, `mine`, `q`, page size 200. **How a risk is scored** (a modal explaining likelihood x impact bands, `GET /risks/meta`) is shown to every reader; **Add a risk** needs `riskregister:write`. Detail: edit (`PATCH /risks/<id>`), RACI (`PUT /risks/<id>/raci`), links to assets/findings (`POST`/`DELETE /risks/<id>/links`), delete. People pickers use `GET /users?limit=200` (`user:read`).

### Threat Intel (`#/intel`)

A header strip from `GET /intel/health` (counts, freshest feed age, products resolved, an inventory warning when no installation is recorded) and a tick pill and, when the hourly maintenance tick is `never_run`, `stale` or `failing` (`tick` in the same response, 0.41.0), a banner with the last success and the stored detail, and a lens: `scope=exposed` (default: an open finding exists), `estate` (the CVE names a product you run, versions not compared), `all` (the catalogue), carried across tabs in the URL. Tabs: **CVE** (`GET /intel/cve`, search `q`), **CISA KEV** (`GET /intel/kev`), **News** (`GET /intel/news?limit=40`), **Sources** (`GET /intel/sources`, *Add source*: name, kind `rss|cert|vendor_advisory|misp|opencti`, URL; `POST /intel/sources`), **Feed runs** (`GET /intel/feeds/runs?size=40`), **Schedule** (`GET`/`PUT /intel/schedule`, editable with `intel:write`). CVE detail (`GET /intel/cve/<id>` plus `/exposure` and `/epss-history`, *AI analysis* via `POST /ai/cve/<id>/analysis`) and CWE detail (`GET /intel/cwe/<id>`).

### Documents & Advisories (`#/documents`) and Knowledge Base (`#/knowledge`)

Documents: filters `q`, `doc_class`, `status`, `team_id`, `cve_id`; **Upload document** sends a multipart `POST /documents` with the file in the body and `title`, `notes`, `team_id` in the **query string**; detail shows the extraction and allows edit (`PATCH`) and delete (`document:delete`). Vendor names come from `GET /intel/vendors`. Knowledge: list, **New article** (title, tags, body -> `POST /knowledge`), edit (`PATCH`), publish to Confluence (`POST /knowledge/<id>/publish`, with `GET /knowledge/<id>/publications` and `GET /knowledge-publishing`).

### CVSS Calculator (`#/cvss?v=`)

Tabs v2.0, v3.0, v3.1, v4.0. The metric form is built from `GET /cvss/metrics/<v>`; scoring and explanation call `POST /cvss/score`, `/cvss/explain`, `/cvss/validate`. **Analyse a bulletin...** posts text to `POST /cvss/assist` and fills the form with provenance chips. Scores come from the server engine; the page states it is validated against FIRST's reference vectors.

### AI Assistant (`#/ai`)

Tabs: **Ask** (`POST /ai/ask {question}`), **Natural-language search** (`GET /ai/search/grammar`, then `POST /ai/search`), **Policy** (`GET`/`PUT /ai/policy`), **Providers** (`GET /ai/providers`, `POST` to add, `DELETE`), **AI audit** (`GET /ai/audit?limit=50`, `audit:read`). `GET /ai/capabilities` decides what is offered. Writes need `ai:admin`.

> Natural-language search posted `{ "query": ... }` until 0.40.x, which the API refused with 422 (`NlSearchRequest` requires `question`). Since 0.41.0 the tab posts `{ "question": ... }` and shows the API's `error` and `hint` when the question was not understood (`understood: false`). Guarded in `tests/test_console_dialog_payloads.py`.

### Reports (`#/reports`) and Compliance (`#/compliance`) and Audit Log (`#/audit`)

Reports **Fixed reports** lists `GET /reports` (slug, required permission, formats `json`, `csv`, `xlsx`, `pdf`); *Preview* shows `GET /reports/<slug>`; each format downloads `GET /reports/<slug>/export?format=` through `fetch` (file name `veyrs-<slug>.<fmt>`); a few reports ask for extra parameters (window, framework). **Builder** (`report:read`): choose an entity from `GET /report-builder/catalog`, tick columns or choose up to three group-by fields with aggregates (`count`, `count_distinct`, `avg`, `sum`, `min`, `max`), add typed filters (operators per field type; day-count operators take 1-3650), then **Run** (`POST /report-builder/run`), **Export CSV/XLSX** (`POST /report-builder/export?format=`) or **Save** (`POST`/`PATCH /report-builder/queries`, optional *Share with everyone in this organization*, which needs `report:write`). Only the saved spec is stored; whoever runs it sees their own scope. Compliance lists `GET /compliance/frameworks` as cards; a framework page (`/coverage`) shows applicable controls, implemented, partial and coverage, with per-control evidence chains (`GET /compliance/controls/<id>/chain`) and *Refresh signals* (`compliance:write`). Audit Log is a read-only list of `GET /audit` with `action` and `object_type` filters, columns When, Actor, Action, Object, Changes, IP.

### Search (`#/search?q=`) and Notifications (`#/notifications`)

Search runs `GET /search?q=&limit_per_type=10` and `GET /search/semantic?q=&limit=10` in parallel and lists permission-aware hits; types the role cannot read are named under *Not searched*; a semantic fallback is labelled. Notifications: **Inbox** (`GET /notifications?page=1&size=50`, *Mark read* -> `POST /notifications/<id>/read`), **Preferences** (`GET`/`PUT /notifications/preferences`, one checkbox per event and channel; SLA breaches and escalations are listed as *always delivered*), **Digest** (policy `GET`/`PUT /notifications/digest`, preview `POST /notifications/digest/preview`, send `POST /notifications/digest/send`). The bell badge is `GET /notifications?size=1` every 60 seconds (`99+` cap).

### Vulnerability scanner (`#/scanner`)

The VEYRS runner, its queue and jobs: agents (`GET /agents?limit=50`), jobs (`GET /agents/jobs?limit=12`, `/agents/jobs/summary`), the technical dashboard counters, importers and the latest import, and the scanning mode (`GET /scanning`). The route stays registered when scanning is off and the page explains the mode and links to *Administration -> Scanning*.

### Data sources (`#/integrations`)

**Scanner import**: format (or detect), file, and options: *Dry run* (checked by default), *Create assets the scanner reports*, *Close findings this test previously reported and no longer does*, *Also record installed software*, *software read from plugin text output*, minimum severity -> `POST /integrations/imports` (multipart). **Scanner connectors**: drivers `GET /integrations/scanner-drivers`, connectors `GET`/`POST /integrations/scanners`, per-row *Test* (`.../test`), *Choose scans* (`GET .../scans`), *Sync* (`.../sync`), edit and delete; secrets are write-only. **Import runs**: `GET /integrations/imports?limit=50`. **ITSM connectors**: `GET`/`POST /integrations/connectors`, test, edit, delete. **Documentation**: Confluence connectors for one-way publishing (`GET /knowledge-publishing`).

### SLA & Policies (`#/policies`)

A page action **Evaluate SLA now** (`POST /policies/sla/evaluate`). Tabs: **SLA policies** (list, *New SLA policy*), **Escalation** (read-only list), **Assignment rules** (list and *Test a rule set* with a JSON context), **Risk profiles** (list, *New risk profile*, *Simulate*, *Re-score everything*), **SLA events**, **Upgrade paths** (create, edit, delete). Each tab starts with an explainer. Since 0.39.1 the JSON is rendered as text with the exact JSON kept in the cell's tooltip: escalation ladders as steps (`ladderSteps`, `:259`, for example `L1 4 h → Team › L2 8 h → Team Manager`; `ciso`, `cio`, `cto`, `soc`, `it` print in capitals), SLA *Applies when*, assignment *Match* and risk-profile *Weights* as key/value chips (`matchChips`, `:270`; an empty object reads *Matches everything*). The table columns are at `:4074`, `:4107`, `:4114` and `:4132`. In 0.39.0 they were raw JSON.

### Automation (`#/automation`)

**Automatic tickets** (`GET`/`PUT /tickets/automation`; fields `enabled`, `min_risk_score`, severity picker, `require_kev`, `internet_exposed_only`, `require_owner`, `max_per_run`; *Preview* and *Dry run the backfill* before opening for real). **Workflows** (guided editor generated from `GET /workflows/actions`, with an Advanced JSON toggle; `POST /workflows`, `PATCH /workflows/<id>`, *Seed the built-in set* `POST /workflows/seed`). **Workflow runs** (`GET /workflows/runs?size=50`).

### Administration (`#/admin`)

| Section | Tab | Content | Calls |
|---|---|---|---|
| Access | `users` | List with source (Local or Directory), roles, MFA, last login; *Invite user*; *Scope...* (`role:admin`) | `GET /users?limit=100`, `GET /roles`, `POST /users`, `GET /users/<id>`, `PUT /users/<id>/scope {team_ids}` |
| Access | `teams` | Teams with member counts; *New team* (slug derived from the name) | `GET /teams?limit=100`, `POST /teams` |
| Access | `roles` | Roles and the permission catalogue (read-only) | `GET /roles`, `GET /permissions` |
| Access | `departments` | List, *New department* | `GET`/`POST /departments` |
| Access | `apikeys` | List, *Create API key* (secret shown once), *Revoke* | `GET`/`POST /api-keys`, `DELETE /api-keys/<id>` |
| Access | `directory` | LDAP / Active Directory settings and test | `GET`/`PUT /ldap`, `POST /ldap/test` |
| Access | `radius` | RADIUS servers, NAS id, role map, test with a code | `GET`/`PUT /radius`, `POST /radius/test` |
| Access | `sso` | OpenID Connect issuer, client, scopes, claims, group-role map, JIT, test | `GET`/`PUT /oidc`, `POST /oidc/test` |
| Data intake | `ticketing` | Which system owns remediation work (internal queue or an ITSM connector), with a required reason | `GET`/`PUT /ticketing`, `GET /integrations/connectors` |
| Data intake | `sources` | Asset sources (CMDB drivers such as NetBox): connection, field and value mapping, auto-promote; test and sync. Needs `importer:read`, writes `importer:admin` / `importer:write` | `GET /asset-sources`, `/asset-sources/drivers`, `POST`, `PATCH`, `DELETE /asset-sources/<id>`, `POST .../test`, `.../sync` |
| Data intake | `teamimport` | Import teams from NetBox or LDAP (preview, run) and assign assets (dry run) | `GET /teams/import/providers`, `POST /teams/import/preview`, `POST /teams/import`, `POST /teams/import/assign-assets` |
| Data intake | `scanning` | The switch that decides whether VEYRS may probe anything | `GET`/`PUT /scanning` |
| Platform | `riskregister` | Switch for the risk register | `GET`/`PUT /risk-register` |
| Platform | `secrets` | Secret storage mode (local, mirror, vault) and per-column counts, read-only | `GET /secret-storage` |
| Platform | `org` | Organization name, slug, default locale | `GET`/`PATCH /organization` |
| Platform | `software` | Installed software and platform components | `GET /admin/system/software` |
| Platform | `network` | Network access requirements of this installation | `GET /admin/system/network` |
| Platform | `updates` | Check, apply, local-copy upload in chunks, history | `GET /admin/updates`, `POST /admin/updates/apply`, `.../uploads`, `PUT .../uploads/<id>/<name>?offset=&total=`, `.../finish`, `DELETE .../uploads/<version>` |

Platform-admin-only routes (`updates`, `software`, `network`) answer 403 to an organization administrator and the tab explains that. Switching scanning, ticketing mode or the risk register opens a dialog describing exactly what the change does and asks for a **reason** (marked required when turning scanning or the register off); the reason is sent with the `PUT`.

### My account (`#/account`)

**Two-factor sign-in** card: with MFA off, choose `totp`, `email` or `telegram` (unavailable methods are disabled with the reason: no SMTP relay, no bot), *Continue* (`POST /auth/mfa/enroll`; a TOTP enrolment shows the server-generated QR SVG and the key), type the code and *Turn on* (`POST /auth/mfa/activate`), then the ten recovery codes are displayed once. With MFA on: *Send me a code* (`POST /auth/mfa/send-code`), *New recovery codes...* (`POST /auth/mfa/recovery-codes`) and *Turn off...* (`POST /auth/mfa/disable`); the last two ask for the password and a code. **Password** card: current, new (min 12), repeat -> `POST /auth/password {current_password, new_password}`; success shows a toast and signs the browser out after 1.2 s because the server revokes every refresh token.

## Forms and validation

Dialogs return the value of every field with a `name`. The console validates only what would otherwise be a guaranteed 422; everything else is the server's job.

| Form | Fields (`name`) | Console-side checks | Endpoint |
|---|---|---|---|
| Sign in | `organization`, `identifier`, `password`, `mfa_code`, `radius_challenge` | required inputs | `POST /auth/login` |
| New asset | `name`*, `hostname`, `ips` (comma list), `asset_type`, `environment`, `criticality`, `data_classification`, `exposure`, `location`, `tags` | `name` required | `POST /assets` |
| New ticket | `title`*, `ticket_type`, `priority`, `description` | `title` required | `POST /tickets` |
| Transition finding | `state`, `note` | none; server returns 409 for an illegal edge | `POST /findings/<id>/transition` |
| Accept risk | `reason`, `until` (date) | `reason` >= 10 characters; `new` findings are triaged first | `POST /findings/<id>/accept-risk?reason=&until=` |
| Invite user | `email`*, `username` (letters, digits, `.`, `_`, `-`; no `@`), `full_name`* (>= 2), `password`*, `role` | full name length; empty username omitted | `POST /users` with `role_slugs:[role]` |
| New team | `name`*, `email` | slug derived by `slugify` (`^[a-z0-9][a-z0-9-]*$`, 2+ chars) | `POST /teams` |
| New SLA policy | `name`*, `hours`*, `priority`, `conditions` (JSON) | JSON must parse; slug derived | `POST /policies/sla` |
| New risk profile | `name`*, `weights` (JSON: technical, exploitability, business, exposure) | JSON must parse | `POST /risk/profiles` |
| Add intel source | `name`*, `kind`, `url`* | none | `POST /intel/sources` |
| Upload document | file*, `title`, `team_id`, `notes` | a file must be chosen | `POST /documents?title=&notes=&team_id=` (multipart) |
| Risk | `title`*, `description`, `category`, `source`, `status`, `treatment`, `likelihood` (1-5), `impact` (1-5), `review_due_at`, `external_ref`, `treatment_plan`, `closure_note` | server-validated | `POST`/`PATCH /risks` |
| Automatic tickets | `enabled`, `min_risk_score`, severity picker, `require_kev`, `internet_exposed_only`, `require_owner`, `max_per_run` | preview before save | `PUT /tickets/automation` |
| Directory (LDAP) | `host`, `port`, `timeout_seconds`, `use_ssl`, `start_tls`, `verify_certificate`, `bind_dn`, `bind_password` (write-only, `clear_bind_password`), `base_dn`, `user_filter`, `attr_username`, `attr_email`, `attr_full_name`, `attr_member_of`, `group_role_map`, `sync_roles_on_login`, `jit_provisioning`, `default_role_slugs` | none | `PUT /ldap`, `POST /ldap/test` |
| RADIUS | `servers`, `secret` (write-only), `nas_identifier`, `timeout_seconds`, `retries`, `role_attribute`, `value_role_map` | none | `PUT /radius`, `POST /radius/test` |
| Single sign-on | `issuer`, `client_id`, `client_secret`, `redirect_uri`, `scopes`, `email_claim`, `groups_claim`, `group_role_map`, `require_mfa_amr`, `jit_provisioning`, `button_label` | none | `PUT /oidc`, `POST /oidc/test` |
| Scanner / ITSM / Confluence connector | `name`, `slug`, `driver`, `base_url`, credentials (`username`/`password` or `access_key`/`secret_key` or `token`), `verify_tls`, `space_key`, `parent_page_id` | none | `POST /integrations/scanners`, `POST /integrations/connectors` |
| Digest policy | `enabled`, `hour`, `min_severity`, `window_hours`, `ch_in_app`, `ch_email` | none | `PUT /notifications/digest` |
| Saved view | `name`, `description`, `is_shared` | name required | `POST`/`PATCH /saved-views` |
| Change password | `current_password`, `new_password` (min 12), repeat | the two new values must match | `POST /auth/password` |

## Route to API matrix

Server permissions are the union of the `require(...)` permissions of the matched routes in `extract/routes.json`; routes with no permission need only an authenticated token (or are public, for the auth entry routes). Paths are relative to `/api/v1`; `{id}` is a record id. "Console gate" is the NAV `perm`.

| Route | Console gate | Reads (GET) | Writes | Server permissions |
|---|---|---|---|---|
| (all screens) | none | `/auth/me`, `/organization`, `/notifications?size=1`, `/teams`, `/saved-views`, `/search` | `POST /auth/login`, `/auth/logout`, `/auth/refresh`, `/auth/oidc/exchange`, `/notifications/{id}/read`, `/saved-views`; `PATCH`/`DELETE /saved-views/{id}`; `GET /auth/sso`, `/auth/oidc/{org}/start` | `team:read`, `organization:read`; others signed in or public |
| `configure` | none | none of its own | none | none |
| `triage` | `finding:read` | `/findings`, `/findings/{id}` | `POST /findings/bulk-assign`, `/findings/{id}/transition`, `/findings/{id}/accept-risk`, `/findings/{id}/remediation`; saved views | `finding:read`, `finding:write`, `risk:admin`, `ticket:write` |
| `guide` | none | `/findings`, `/tickets`, `/agents`, `/agents/jobs/summary` | none | `finding:read`, `ticket:read`, `agent:read` (each optional) |
| `dashboard` | `report:read` | `/dashboard/executive`, `/dashboard/technical`, `/dashboard/sla`, `/policies/sla/summary`, `/teams` | `PATCH /auth/me/preferences` | `report:read`, `sla:read`, `team:read` |
| `findings` | `finding:read` | `/findings`, `/findings/{id}`, `/findings/{id}/fix-plan`, `/findings/{id}/attribution` | `POST /findings/bulk-assign`, `/findings/{id}/transition`, `/findings/{id}/rescore`, `/findings/{id}/accept-risk`, `/findings/{id}/remediation`, `/ai/findings/{id}/explain`, `/ai/findings/{id}/remediation` | `finding:read`, `finding:write`, `risk:write`, `risk:admin`, `ticket:write`, `risk:read` (explain) |
| `changes` | `finding:read` | `/findings/changes` | none | `finding:read` |
| `tickets` | `ticket:read` | `/tickets`, `/tickets/{id}`, `/integrations/tickets/{id}/links`, `/integrations/connectors` | `POST /tickets`, `/tickets/{id}/transition`, `/tickets/{id}/comments`, `/integrations/connectors/{id}/push/{id}` | `ticket:read`, `ticket:write` |
| `issues` | `ticket:read` | `/integrations/links` | `POST /integrations/links/{id}/refresh`, `/integrations/links/{id}/unlink` | `ticket:read`, `ticket:write` |
| `vulnerabilities` | `vulnerability:read` | `/vulnerabilities`, `/vulnerabilities/{id}` | none | `vulnerability:read` |
| `risks` | `riskregister:read` | `/risks`, `/risks/{id}`, `/risks/meta`, `/risks/summary`, `/users` | `POST /risks`, `PATCH`/`DELETE /risks/{id}`, `PUT /risks/{id}/raci`, `POST /risks/{id}/links`, `DELETE /risks/{id}/links/{id}` | `riskregister:read`, `riskregister:write`, `riskregister:delete`, `user:read` |
| `assets` | `asset:read` | `/assets`, `/assets/{id}`, `/assets/{id}/fix-plan`, `/findings` | `POST /assets`, `/assets/bulk-assign`, `/assets/{id}/rescan`; `DELETE /assets/{id}` | `asset:read`, `asset:write`, `asset:delete`, `finding:read` |
| `intel` | `cve:read` | `/intel/health`, `/intel/cve`, `/intel/cve/{id}`, `/intel/cve/{id}/exposure`, `/intel/cve/{id}/epss-history`, `/intel/cwe/{id}`, `/intel/kev`, `/intel/news`, `/intel/sources`, `/intel/feeds/runs`, `/intel/schedule` | `POST /intel/sources`, `PUT /intel/schedule`, `POST /ai/cve/{id}/analysis` | `cve:read`, `intel:read`, `intel:write`, `finding:read` (exposure) |
| `documents` | `document:read` | `/documents`, `/documents/{id}`, `/intel/vendors` | `POST /documents`, `PATCH`/`DELETE /documents/{id}` | `document:read`, `document:write`, `document:delete`, `cve:read` |
| `knowledge` | `knowledge:read` | `/knowledge`, `/knowledge/{id}`, `/knowledge/{id}/publications`, `/knowledge-publishing` | `POST /knowledge`, `PATCH /knowledge/{id}`, `POST /knowledge/{id}/publish` | `knowledge:read`, `knowledge:write` |
| `cvss` | none | `/cvss/metrics/{version}` | `POST /cvss/score`, `/cvss/explain`, `/cvss/validate`, `/cvss/assist` | `vulnerability:read` |
| `ai` | `ai:read` | `/ai/capabilities`, `/ai/search/grammar`, `/ai/policy`, `/ai/providers`, `/ai/audit` | `POST /ai/ask`, `/ai/search`, `/ai/providers`; `PUT /ai/policy`; `DELETE /ai/providers/{id}` | `ai:read`, `ai:admin`, `audit:read` |
| `reports` | `report:read` | `/reports`, `/reports/{slug}`, `/reports/{slug}/export`, `/report-builder/catalog`, `/report-builder/queries`, `/compliance/frameworks` | `POST /report-builder/run`, `/report-builder/export`, `/report-builder/queries`; `PATCH`/`DELETE /report-builder/queries/{id}` | catalogue and exports: signed in plus each report's own permission; builder `report:read`; `compliance:read` |
| `compliance` | `compliance:read` | `/compliance/frameworks`, `/compliance/frameworks/{id}/coverage`, `/compliance/controls/{id}/chain` | `POST /compliance/frameworks/{id}/refresh-signals` | `compliance:read`, `compliance:write` |
| `audit` | `audit:read` | `/audit` | none | `audit:read` |
| `search` | none | `/search`, `/search/semantic` | none | signed in; each result type needs its own read permission |
| `notifications` | none | `/notifications`, `/notifications/preferences`, `/notifications/digest` | `POST /notifications/{id}/read`, `/notifications/digest/preview`, `/notifications/digest/send`; `PUT /notifications/preferences`, `/notifications/digest` | inbox and preferences: signed in; digest `notification:read` / `notification:admin`; preview `finding:read` |
| `scanner` | `agent:read` | `/agents`, `/agents/jobs`, `/agents/jobs/summary`, `/dashboard/technical`, `/integrations/importers`, `/integrations/imports`, `/scanning` | none | `agent:read`, `report:read`, `importer:read`, `settings:read` |
| `integrations` | `importer:read` | `/integrations/importers`, `/integrations/imports`, `/integrations/scanners`, `/integrations/scanner-drivers`, `/integrations/scanners/{id}/scans`, `/integrations/connectors`, `/knowledge-publishing` | `POST /integrations/imports`; `POST`/`PATCH`/`DELETE /integrations/scanners[/{id}]`, `.../{id}/test`, `.../{id}/sync`; `POST`/`PATCH`/`DELETE /integrations/connectors[/{id}]`, `.../{id}/test` | `importer:read`, `importer:write` (import, sync), `importer:admin` (scanner setup), `ticket:read`, `ticket:admin` (ITSM), `knowledge:read` |
| `policies` | `sla:read` | `/policies/sla`, `/policies/sla/events`, `/policies/escalation`, `/policies/assignment`, `/risk/profiles`, `/upgrade-path-rules` | `POST /policies/sla`, `/policies/sla/evaluate`, `/policies/assignment/test`, `/risk/profiles`, `/risk/simulate`, `/risk/rescore`, `/upgrade-path-rules`; `PATCH`/`DELETE /upgrade-path-rules/{id}` | `sla:read`, `sla:write`, `escalation:read`, `finding:read`, `riskprofile:read`, `riskprofile:write`, `risk:read`, `risk:admin` |
| `automation` | `workflow:read` | `/tickets/automation`, `/workflows`, `/workflows/actions`, `/workflows/runs` | `PUT /tickets/automation`; `POST /tickets/automation/preview`, `/tickets/automation/backfill`, `/workflows`, `/workflows/seed`; `PATCH /workflows/{id}` | `ticket:read`, `ticket:admin`, `workflow:read`, `workflow:write`, `workflow:admin` |
| `admin` (Access) | `user:read` | `/users`, `/users/{id}`, `/roles`, `/permissions`, `/teams`, `/departments`, `/api-keys`, `/ldap`, `/radius`, `/oidc` | `POST /users`, `/teams`, `/departments`, `/api-keys`; `PUT /users/{id}/scope`; `DELETE /api-keys/{id}`; `PUT /ldap`, `/radius`, `/oidc`; `POST /ldap/test`, `/radius/test`, `/oidc/test` | `user:read`, `user:write`, `role:read`, `role:admin` (scope), `team:read`, `team:write`, `apikey:read`, `apikey:write`, `apikey:delete`, `settings:admin` |
| `admin` (Data intake) | `user:read` | `/ticketing`, `/integrations/connectors`, `/asset-sources`, `/asset-sources/drivers`, `/teams/import/providers`, `/scanning` | `PUT /ticketing`, `/scanning`; `POST`/`PATCH`/`DELETE /asset-sources[/{id}]`, `.../{id}/test`, `.../{id}/sync`; `POST /teams/import/preview`, `/teams/import`, `/teams/import/assign-assets` | `settings:read`, `settings:admin`, `ticket:read`, `importer:read`, `importer:admin`, `importer:write`, `team:write` |
| `admin` (Platform) | `user:read` | `/risk-register`, `/secret-storage`, `/organization`, `/admin/system/software`, `/admin/system/network`, `/admin/updates` | `PUT /risk-register`; `PATCH /organization`; `POST /admin/updates/apply`, `/admin/updates/uploads`, `.../uploads/{id}/finish`; `PUT /admin/updates/uploads/{id}/{name}`; `DELETE /admin/updates/uploads/{version}` | `settings:read`, `settings:admin`, `organization:read`, `organization:write`; `/admin/*` routes require platform administrator |
| `account` | none | `/auth/mfa` | `POST /auth/mfa/enroll`, `/auth/mfa/send-code`, `/auth/mfa/activate`, `/auth/mfa/recovery-codes`, `/auth/mfa/disable`, `/auth/password` | signed in |

The Configure frame is the same set of calls as the page it wraps.

### What the console does not call

The API exposes more than the console uses: for example engagements and formal risk acceptances (`/engagements/...`), scan agents' enrolment and job creation, team membership edits (`/teams/{id}/members/...`), user edit/delete, role create/edit, SLA and escalation edit/delete, knowledge revisions, and `/auth/me/scope`. These are API-only today; see the [API reference](../api/reference/README.md) and `../reference/inventory.md`.

## Changes in 0.41.0 (audit fix round)

`index.html` references `app.js?v=48` and `console.css?v=22`. Line numbers elsewhere in this file are those of 0.39.1.

| Change | Where | Guard |
|---|---|---|
| List rows (`tr.clickable`) are focusable; Enter or Space opens the record; visible inset focus ring (TD-13) | `table()`; one delegated key handler; `console.css` `tr.clickable:focus-visible` | `tests/test_console_keyboard_a11y.py::test_clickable_rows_are_focusable_and_keyboard_operable` |
| Natural-language search posts `question` and reports `understood: false` (TD-21) | AI Assistant, search tab | `tests/test_console_dialog_payloads.py` (static and round trip) |
| `--text-muted`, the light semantic tokens, dark informational and dark primary hover raised to 4.5:1 or better; light pill `filter` removed (TD-40) | `console.css` theme blocks | `tests/test_console_contrast.py` |
| The Configure rail button's `aria-label` follows its state; `aria-pressed` dropped (TD-60) | `configureFrame()` | `::test_the_configure_rail_button_names_its_current_action` |
| `.tabs` bars get the tab pattern with arrow-key navigation (`enhanceTabs`, called from `enhancePage`) | `app.js` | `::test_tabs_get_the_tab_pattern_after_every_render` |
| Skip link to `main#view` (focus moved by script: the fragment is the router) | `index.html`, `console.css` | `::test_skip_link_precedes_the_navigation_and_targets_the_view` |
| `st-queued` and `st-cancelled` pills have the neutral style | `console.css` | `::test_job_state_pills_are_styled` |
| Threat Intelligence shows the tick health from `GET /intel/health` (`tick.status`, `minutes_since_success`, `last_detail`) | `route('intel')` | none (no browser harness); the API contract is tested by the SLA workstream |
| Not done: the organization `require_mfa` toggle. The route did not exist on the auth workstream's branch when this was written; wire it once the `PATCH` contract is merged | | |

## Changes in 0.39.1

The source copy documented here is release 0.39.1; its `app.js` is byte-identical to the file both application nodes serve (md5 `518b361b278245175c86711eeb887abc`), and `index.html` references `app.js?v=47` and `console.css?v=21`. What 0.39.1 changed in the console (`docs/CHANGELOG.md`, 0.39.1):

| Change | Where | Guard |
|---|---|---|
| Dates never wrap: `fmtDate`/`fmtDay` replace spaces with no-break spaces (`nbsp`) | `:222-236` | `tests/test_console_readability_0391.py::test_dates_use_no_break_spaces` |
| Asset criticality is a neutral pill with a four-step level mark (`critPill`), not a severity colour; used in the asset list, asset detail, finding detail and the CVE exposure table | `:244-257`; callers `:2597`, `:2886`, `:2922`, `:2943`, `:3726`; styles `console.css:996-1003` | `::test_criticality_never_uses_severity_classes` |
| Policies render JSON as text: ladders (`ladderSteps`) and key/value chips (`matchChips`) | `:259-275`, `:4074-4132`; styles `console.css:1004-1008` | `::test_policy_json_is_rendered_as_text` |
| Configure menu is 216 px and folds to an icon rail remembered in `veyrs.cfg.rail` | `:1390-1440`; `console.css:803-850` | `tests/test_console_configure_frame.py::test_the_menu_folds_to_a_rail_and_the_tabs_come_back` |
