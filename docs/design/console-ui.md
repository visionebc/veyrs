---
title: Console UI reference
purpose: Reference for the console's visual system as shipped in 0.39.1 (Midnight Ops tokens, typography, components, layouts, navigation, states) with line-level evidence.
scope: The vanilla-JS console in frontend/console/ and the shared token file it loads; excludes the documentation portal, the product site and the brand identity rules (see BRAND.md).
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [frontend/console/console.css, frontend/console/app.js, frontend/console/index.html, site/static/veyrs-tokens.css, frontend/console/fonts/README.txt, tests/test_console_design_system.py, tests/test_console_redesign_0380.py, tests/test_console_configure_frame.py]
related: [DESIGN_SYSTEM.md, BRAND.md, design/accessibility.md]
---

# Console UI reference

This is the lookup document for the console's presentation layer. The narrative (why the system looks like this, how to change it, formats, markup rules) is in [Design System](../DESIGN_SYSTEM.md); the identity (palette, logo) is in [Brand](../BRAND.md); accessibility status and measured contrast are in [Accessibility](accessibility.md).

Line references are to the 0.39.1 tree: `console.css` is 1,304 lines, `app.js` 9,559, `index.html` 106 (0.39.0: 1,270 and 9,507; every reference was re-mapped through the 0.39.1 diff). Status words in tables follow the documentation vocabulary; "Verified" means read in code and pinned by a test that was read, not observed in a running browser.

## 1. Files and load order

| Order | File | Role | Evidence |
|---|---|---|---|
| 1 | `/static/veyrs-tokens.css?v=2` | Brand and semantic tokens (65 custom properties), `.sev-*`, `.badge-*`, `.chip`, global `:focus-visible` outline | `index.html:12`, `veyrs-tokens.css:15` |
| 2 | `/console.css?v=22` | Theme blocks, shell, components. Part 1 (lines 9-426) are component layouts that read tokens; Part 2 (428-1304) is the design system and wins where both define a selector | `index.html:13`, `console.css:1-7` |
| 3 | `/app.js?v=48` | Renders every view; `boot()` applies the theme | `index.html:104` |
| fonts | `/fonts/*.woff2` (6 files) | Self-hosted Inter 400/500/600/700 and JetBrains Mono 400/500; two Inter weights are preloaded | `console.css:443-448`, `index.html:10-11` |

`/static/` is served from the site static directory (a mirror of `frontend/brand/`); the token file is byte-identical in both. A console served without it loses `--font-sans`, `--font-mono`, `--veyrs-white`, `--veyrs-ai`, `--veyrs-accepted-risk`, `--veyrs-navy` and the `--space-*` and `--text-*` scales, because `console.css` does not define them.

## 2. Theme mechanism

- Two themes, both scoped to the `data-theme` attribute of `<html>`; neither is an unscoped base (`console.css:469`, `console.css:520`, comment at `app.js:1516-1519`).
  - **Midnight** (dark, default): `:root[data-theme="dark"]`.
  - **Porcelain** (light): `[data-theme="light"]`.
- `index.html:2` ships `data-theme="dark"` so the first paint is correct; `boot()` calls `applyTheme(localStorage.getItem('veyrs.theme') || 'dark')` (`app.js:1519`, `app.js:1573-1576`). Guarded by `test_midnight_is_the_default_theme`.
- Toggle: sidebar button `#theme-toggle` (`app.js:8656-8661`) and the command-palette action "Toggle light / dark theme" (`app.js:9157-9161`). Both apply the theme, then try to store it under `veyrs.theme`; a storage failure is swallowed.
- The operating-system preference is not consulted by the console. The token file has a `prefers-color-scheme: dark` block, but it only matches `:root:not([data-theme="light"])` (`veyrs-tokens.css:135-147`) and the console always sets the attribute.
- Each theme block defines the same 43 custom properties (verified by script: no key in one block is missing from the other). `test_both_themes_are_designed_on_their_own` pins 16 of them, requires the two `--nav-bg` values to differ, and bans the retired warm greys.
- Colour literals are allowed only in the two theme blocks, `:root`, and the login hero rules (`test_colour_literals_live_only_in_the_token_blocks`).

## 3. Token tables

### 3.1 Theme tokens defined by `console.css`

Values are the 0.39.1 values (unchanged from 0.39.0: 0.39.1 added no token). "Role" says what the token is for in the console. Tokens marked * are theme-independent and listed in 3.2.

| Token | Midnight (dark) | Porcelain (light) | Role |
|---|---|---|---|
| `--background` | `#0A0D13` | `#F3F4F7` | Page canvas, translucent top bar base |
| `--surface` | `#0F131B` | `#FFFFFF` | Panels, tables, login form side |
| `--surface-2` | `#151B25` | `#F6F7F9` | Input fill, tracks, wells, hover fills |
| `--surface-raised` | `#19202C` | `#FFFFFF` | Modal, toast, tooltip, `.btn`, active segment |
| `--border` | `#1E2633` | `#E2E5EB` | Hairlines |
| `--border-strong` | `#2B3546` | `#CBD1DA` | Hover borders, overlays, kbd |
| `--text` | `#E7EBF1` | `#0D1524` | Body ink |
| `--text-secondary` | `#98A3B5` | `#556076` | Labels, hints, muted copy |
| `--text-muted` | `#7F899A` | `#666F7E` | Table headers, placeholders, axis labels, page foot |
| `--text-inverse` | `#0A0D13` | `#FFFFFF` | Defined; not read by `console.css` |
| `--primary` | `#3D6FD6` | `#2F5FCC` | Buttons, selected option, focus ring base |
| `--primary-hover` | `#4772CC` | `#2752B3` | Primary button hover |
| `--primary-contrast` | `#FFFFFF` | `#FFFFFF` | Text on `--primary` |
| `--link` | `#86ACF6` | `#2652BD` | Links, "More" button |
| `--focus-ring` | `#86ACF6` | `#2F5FCC` | Outline colour read by the token file's `:focus-visible` rule |
| `--gold` | `#C9A45C` | `#9A7430` | "You are here" marker only: active nav, active tab underline, avatar ring, Configure card icon |
| `--gold-soft` | `rgba(201,164,92,.14)` | `rgba(154,116,48,.12)` | Fill behind gold marks |
| `--nav-bg` | `#080B10` | `#FAFAFB` | Sidebar |
| `--nav-border` | `#151B25` | `#E2E5EB` | Sidebar rules |
| `--nav-text` | `#A3AEC0` | `#3A4558` | Sidebar text |
| `--nav-text-active` | `#F2F4F8` | `#0D1524` | Active and hovered sidebar text |
| `--nav-hover` | `rgba(255,255,255,.04)` | `rgba(13,21,36,.04)` | Sidebar hover fill |
| `--nav-active` | `rgba(255,255,255,.065)` | `#FFFFFF` | Active sidebar row |
| `--band` | `#0C1017` | `#FFFFFF` | Page-head band and tab strip |
| `--row-hover` | `rgba(255,255,255,.025)` | `rgba(13,21,36,.022)` | Table row hover |
| `--veyrs-critical` | `#EF5D68` | `#B52B38` | Severity: critical |
| `--veyrs-high` | `#F08A4B` | `#A34719` | Severity: high |
| `--veyrs-medium` | `#E3B341` | `#815C0E` | Severity: medium |
| `--veyrs-low` | `#6C9BE8` | `#3A62AA` | Severity: low |
| `--veyrs-informational` | `#8B95A5` | `#5A6379` | Severity: informational |
| `--veyrs-remediated` | `#3FB68B` | `#187253` | State: done, good |
| `--veyrs-success` | `#3FB68B` | `#187253` | Success toast edge |
| `--veyrs-warning` | `#E3B341` | `#815C0E` | Warning pill, stat, banner |
| `--veyrs-danger` | `#EF5D68` | `#B52B38` | Errors, destructive button, notification counter |
| `--veyrs-info` | `#6C9BE8` | `#2C5DC9` | In-progress pills |
| `--veyrs-neutral` | `#5E6878` | `#8A93A3` | Fallback series colour for a non-severity key (`app.js:854-857`) |
| `--chart-risk` | `#6F9BF2` | `#2F64D8` | Series: risk score |
| `--chart-in` | `#E3A24B` | `#D08A2E` | Series: risk arriving |
| `--chart-out` | `#3FB68B` | `#1C8460` | Series: risk leaving |
| `--chart-grid` | `#1A212D` | `#EDEFF3` | Chart gridlines |
| `--shadow-sm` | `0 1px 0 rgba(0,0,0,.3)` | `0 1px 2px rgba(13,21,36,.05)` | Triage card |
| `--shadow-md` | `0 10px 30px rgba(0,0,0,.45)` | `0 10px 28px rgba(13,21,36,.09)` | Toast, bulk bar, tooltip |
| `--shadow-lg` | `0 28px 70px rgba(0,0,0,.6)` | `0 28px 64px rgba(13,21,36,.18)` | Modal, palette, mobile drawer |

Source: dark block `console.css:469-514`, light block `console.css:520-565`.

The semantic tokens `--veyrs-info`, `--veyrs-neutral` and `--veyrs-remediated` differ in role from the brand file: the console redefines every severity and status hue per theme; the token file's values are never visible in the console for those names.

### 3.2 Theme-independent tokens (`:root` of `console.css`)

| Token | Value | Role | Line |
|---|---|---|---|
| `--radius-sm` / `--radius` / `--radius-lg` | `4px` / `6px` / `8px` | Radius scale (overrides the token file's 3/5/8) | 452-454 |
| `--ease` | `cubic-bezier(.2,.7,.2,1)` | Easing for every transition | 455 |
| `--dur` | `.16s` | State-change duration | 456 |
| `--sidebar-w` | `236px` | Sidebar column | 457 |
| `--topbar-h` | `48px` | Top bar height; Configure menu offset | 458 |
| `--gutter` | `28px` (16px under 900px) | Horizontal page padding | 459, 1261 |
| `--hero-ink` / `--hero-deep` / `--hero-mid` / `--hero-dim` | `#8FB4F8` / `#05070B` / `#0B1426` / `rgba(255,255,255,.55)` | Login hero (always dark) | 460-463 |
| `--scrim` | `rgba(3,6,12,.62)` | Modal and palette backdrop | 464 |
| `--ring` | `0 0 0 3px color-mix(in srgb, var(--primary) 26%, transparent)` | Form-control focus halo | 465 |

### 3.3 Tokens the console reads from `veyrs-tokens.css`

| Token | Value seen by the console | Used for |
|---|---|---|
| `--font-sans`, `--font-mono` | Inter / JetBrains Mono stacks | `body`, `.mono`, textareas, `kbd` (`veyrs-tokens.css:88-89`) |
| `--space-1`..`--space-6`, `--space-8` | 4, 8, 12, 16, 24, 32, 48 px | Utilities `.mt-*`, `.mb-*`, `.gap-*`, `hr.rule` (`console.css:411-423`, `1303`) |
| `--text-lg`, `--text-xl` | 16px, 20px | `.t-lg`, `.t-xl` (`console.css:424-425`) |
| `--veyrs-white` | `#FFFFFF` | Text on `--primary` and on `.pill-kev`, counter |
| `--veyrs-navy` | `#001030` | Dark `.pill-kev` background mix (`console.css:1010`) |
| `--veyrs-ai` | dark `#A78BFA`, light `#7C3AED` | AI marks only: `.btn-ai`, `.pill-ai`, `.ai-msg.veyrs` |
| `--veyrs-accepted-risk` | dark `#A78BFA`, light `#7C3AED` | Accepted-risk and exception pills |

The remaining token-file properties (brand primitives such as `--veyrs-blue`, `--veyrs-electric`, `--veyrs-steel`, the `-rgb` triplets, the gradient, `--text-xs/sm/base/2xl/3xl`) are not read by `console.css` (verified: every `var(--…)` in the stylesheet resolves to a definition in one of these three groups; none is undefined). The token file's dark block and OS-dark block redefine `--surface` and friends, but `console.css` loads later with higher specificity (`:root[data-theme="dark"]`), so those values never show.

### 3.4 Token rules

1. Structure reads the semantic aliases (`--surface`, `--border`, `--text-secondary`); meaning reads `--veyrs-<severity|status>`. `test_colour_literals_live_only_in_the_token_blocks`.
2. Tints are `color-mix(in srgb, <token> N%, transparent)`: pill fill 13-14 %, pill border 28-32 %, banner 6-9 %, delta 12 %. A new tint follows that pattern so it follows the theme.
3. Border radius never exceeds 8 px except `999px` pills and `50%` dots (`test_radii_stay_on_the_brand_scale`).
4. Gold is a position marker, not a status; blue is interaction; no hue is used for decoration.

## 4. Typography

| Aspect | Value | Evidence |
|---|---|---|
| Families | Inter (sans) and JetBrains Mono (mono), Latin subsets, woff2, `font-display: swap`; CSP `font-src 'self'` | `console.css:443-448`, `fonts/README.txt` |
| Licences | Inter 4.0 under SIL OFL 1.1, JetBrains Mono 2.242 under Apache 2.0, both shipped in `fonts/` | `fonts/README.txt` |
| Body | 13.5 px / 1.5, antialiased, features `cv11`, `calt` | `console.css:570-575` |
| Headings | `h1-h3` weight 600, tracking -0.01 em; page title 22 px (19 px under 640 px; 20 px inside Configure) | `console.css:576`, `763`, `1276`, `854` |
| Mono | 12 px, -0.01 em (`.mono`); textareas 12.5 px mono | `console.css:584`, `602` |
| Captions | 10-11 px uppercase with 0.04-0.12 em tracking (table headers 11 px / .06 em; Configure and nav sub-heads 10.5 px / .08 em; chain steps 10 px / .12 em) | `console.css:197`, `700`, `809`, `955` |
| Numbers | `font-variant-numeric: tabular-nums` on stats, numeric cells, axes | `console.css:922`, `958`, `965` |

Sizes in use (px, count of declarations): 12 (40), 13 (37), 11 (19), 12.5 (12), 11.5 (8), 10.5 (7), 10 (6), 14 (5), 15 (4), 22 (3), 18 (2), 19 (2), 13.5 (2), and one each of 9.5, 16, 20, 26, 30, 34, 52. Weights: 600 (45), 500 (15), 700 (14), 400 (4), 800 (1, the CVSS score). Computed from `console.css` by script on 2026-11-17. Only `.t-lg` and `.t-xl` go through the token scale; every other size is a literal.

The three layers of type most readers meet: 13.5 px body, 13 px controls and table cells, 11-12 px captions and hints. Stat values are 26 px (22 px under 640 px), page titles 22 px.

## 5. Colour roles and severity rules

| Role | Tokens | Rule |
|---|---|---|
| Structure | `--background`, `--surface*`, `--border*` | One step of surface tone plus hairlines; no panel shadows (`console.css:879-881`) |
| Ink | `--text`, `--text-secondary`, `--text-muted` | Muted is for non-essential text only: see [Accessibility](accessibility.md) for its contrast |
| Interaction | `--primary`, `--primary-hover`, `--link`, `--ring` | Buttons, links, selection, focus |
| Position | `--gold`, `--gold-soft` | Active nav, active tab, avatar ring, Configure card icon, login hairline. Nothing else |
| Severity | `--veyrs-critical/high/medium/low/informational` | Classes `.sev-*` (`console.css:983-987`). Used only where the thing is a severity: finding/vulnerability severity, risk-register bands and the 5x5 heat map (cells reuse `.sev-*` so the map cannot disagree with the pills) |
| State | `--veyrs-remediated`, `--veyrs-warning`, `--veyrs-danger`, `--veyrs-info`, `--veyrs-accepted-risk` | Classes `.st-*` (`console.css:988-993`); a state that is not a severity never uses a `.sev-*` class |
| AI | `--veyrs-ai` | Only AI-originated content |
| Series | `--chart-risk`, `--chart-in`, `--chart-out` | One meaning each; risk arriving is never drawn in the leaving colour (`test_chart_series_have_one_meaning_each`) |

Severity colour is never the sole encoding. Severity pills carry the word and a 6 px dot (`console.css:980-981`), donut and split charts carry a label and number per mark, and `sevColour()` falls back to `--veyrs-neutral`, not to blue, for any key that is not a severity (`app.js:854-857`; `test_severity_never_falls_back_to_the_identity_colour`). The comment at `app.js:727-732` records why: high and medium are close under colour-vision deficiency.

`.pill[class*="sev-"]` capitalises the API's lower-case severity word (`console.css:980`).

## 6. Spacing, utilities, density

| Item | Rule | Line |
|---|---|---|
| Scale | 4 px base from the token file: 4, 8, 12, 16, 24, 32, 48 px | `veyrs-tokens.css:85-86` |
| Margin utilities | `.mt-0` (`!important`), `.mt-2`/`-3`/`-4`/`-5` = 8/12/16/24 px; `.mb-2`/`-3` = 8/12 px; `.m-0` | `console.css:411-418` |
| Gap utilities | `.gap-2`, `.gap-3` | 419-420 |
| Layout helpers | `.grow` (flex 1), `.spacer`, `.row` (flex, 8 px gap, wraps), `.stack` (grid, 14 px gap), `.row-between`, `.row-split` (space-between, start-aligned, 16 px gap), `.right`, `.nowrap`, `.sr-only` | 421-423, 585-590, 287 |
| Reading measure | `.measure` 72 ch; page description max 92 ch; form lede and hints 78 ch | 422, 764, 20, 25 |
| Size helpers | `.t-lg` 16 px, `.t-xl` 20 px, `.small` 12 px, `.muted` | 424-425, 583, 582 |
| Rule | `hr.rule`: 16 px vertical margin, 1 px `--border` | 1303 |
| Card | 16 px padding; first-child `h2` becomes a 42 px header strip | 882-891 |
| Table | Header 36 px high, cells 9 px 12 px | 954-958 |
| Page | Max width 1680 px, gutter 28 px, bottom padding 64 px | 749 |
| Grid gaps | `.grid`, `.dash`, `.stack` 14 px; `.grid2`, `.form-grid`, `.cfg-cards` 12 px; Configure column gap 24 px (28 px in 0.39.0) | 899, 907, 904, 291, 858, 803 |

Spacing outside the utilities is written as literal pixels. The 0.36.0 pass replaced 310 inline margins with these classes; 63 `style="` attributes on 61 lines remain in `app.js` (counted 2026-11-17, 0.39.1), mostly computed bar widths and series colours, plus a few banner overrides.

## 7. Component catalogue

"Test" names the guard that pins the component, if any.

### 7.1 Controls

| Component | Classes | Behaviour and spec | Lines | Status |
|---|---|---|---|---|
| Text field, select, textarea | bare `input`, `select`, `textarea` | Full width, 7 px 10 px, 13 px, `--surface-2` fill, `--radius`. Hover darkens border; focus sets border `--primary`, `--ring` halo and fill `--surface`; `outline: none` | 593-602 | Implemented |
| Checkbox, radio | `input[type=checkbox]`, `input[type=radio]` | Native control, `accent-color: var(--primary)` | 603-605 | Implemented |
| Button | `.btn`, `.btn-primary`, `.btn-danger`, `.btn-ai`, `.btn-sm`, `.btn-block`, `.btn-ghost`, `.icon-btn` | 32 px high (28 px `-sm`, 38 px `-block`), 13 px / 500; `:active` shifts 1 px; disabled 45 % opacity. Danger and AI are outline-coloured, not filled. `.icon-btn` is 32 px square | 607-637 | Implemented |
| Key hint | `kbd` | Mono 10.5 px, 2 px bottom border | 638-641 | Implemented |
| Long form | `.formsec`, `.field` (`.lbl`, `.hint`, `.req`), `details.why` | Ruled sections with uppercase 11 px heading; reasoning folded behind a closed `details`; a `.field` inside a grid drops its own bottom margin | 14-47 | Implemented |
| Switch rows | `.switches` | One decision per row, 16 px checkbox column | 50-58 | Implemented |
| Field picker | `.checkgrid`, `.checkgroup`, `.pickbar` | `auto-fill` columns of 215 px; checked label tinted with `:has(input:checked)` | 63-86 | Implemented |
| Key/value editor | `.kv-head`, `.kv-row`, `.vm-row` | Two or three columns plus a 34 px remove column; header hidden under 640 px | 90-105 | Implemented |
| Filters | `.filters`, `.filter-inline`, `.view-chips` + `.chip`/`.chip-on` | 32 px controls; chips are 999 px pills | 304-312, 1013-1016 | Implemented |
| Segmented control | `.seg`, `.seg-sm` | Inline group in a `--surface-2` track; active segment is raised with a 1 px strong border. Time-range control uses `aria-pressed` | 785-796; `app.js:1610-1611` | Implemented |
| Option toggle | `.opt`, `.opt.on` | CVSS metric options; selected fills `--primary` | 124-130 | Implemented |

### 7.2 Containers and metrics

| Component | Classes | Spec | Lines | Test |
|---|---|---|---|---|
| Panel | `.card`, `.card.flush` | Hairline border, `--radius-lg`, 16 px padding, no shadow; `.flush` lets a table run edge to edge | 882-895 | none |
| Metric strip | `.kpis`, `.grid:has(> .card.stat)` | One bordered strip divided by hairlines, never separate tiles; `auto-fit` columns of 190 px, two columns under 640 px | 914-919, 1277 | `test_metric_grids_render_as_strips`, `test_dashboards_open_with_one_metric_strip` |
| Stat | `.stat` (`.label`, `.value`, `.hint`), tone `.crit`/`.warn`/`.ok` | Value 26 px / 600 tabular; tone colours the value and puts a dot before the label | 920-931 | none |
| KPI foot | `.kpi-foot`, `.kpi-spark`, `.delta` (`.good`/`.bad`) | Signed change over the window plus a 112 x 30 sparkline; `delta()` adds screen-reader text "(improved)" / "(worse)" | 932-936; `app.js:554-561` | none |
| Ops list | `.ops`, `.ops-row`, `.ops-l`, `.ops-v` | Compact label/value rows | 937-945 | none |
| SLA ring | `.ring`, `.sla-ring` | 104 px gauge against the 90 % target | 946-948 | none |
| Dashboard grid | `.dash`, `.span-4/5/6/7/8/12` | 12 columns; spans 4/5/7/8 become 6 below 1200 px, everything 12 below 900 px | 907-909, 1257-1259, 1269 | test above |
| Auto grids | `.grid.cols-2/3/4/5`, `.grid2`, `.form-grid` | `auto-fit` / `minmax` columns: 320, 240, 190, 168, 260, 190 px | 899-905, 291 | none |
| Definition list | `dl.kv` | 190 px label column, one column under 640 px | 108-111 | none |
| Page band | `.page-head`, `.page-actions`, `.page-foot` | Full-width band welded to the top bar; `h1` 22 px; description folds to two lines behind "More" when over 180 characters and actually clipped | 757-773; `app.js:1311-1340` | none |
| Explainer | `.explainer` | Collapsible "what is this page for" panel, quiet surface, `aria-expanded` toggle, dismissal kept in `veyrs.explain.dismissed.v1` | 222-259; `app.js:372-415` | none |
| Scope banner | `.scope-banner` | Informational strip: brand-accent tint and left rule, `role="status"`, deliberately not a danger colour | 156-165 | none |
| Bulk bar | `.bulk-bar` | Sticky 14 px above the bottom, z 20, strong border and `--shadow-md` | 170-177 | none |
| Triage card | `.triage-card`, `.triage-facts`, `.tabs.tabs-inline` | Single-record card max 1120 px; queues as inline tabs | 315-344, 1300 | none |

### 7.3 Tables, pills, tabs

| Component | Spec | Lines |
|---|---|---|
| Table | `table()` in `app.js:434-450` always emits `.table-wrap` (horizontal scroll, border, `--radius-lg`) with `thead`/`tbody`. Header 36 px, 11 px uppercase `--text-muted`; cell 9 px 12 px, tabular figures; first data cell weight 500; `.num` right-aligns; `tr.clickable` gets a 2 px inset `--primary` bar on hover; `.cell-bar` is a 64 px inline meter. Headers are not sticky. Selection column: `.pick` with `data-pick` / `data-pick-all` and `aria-label`s | `console.css:951-969` |
| Pager | Right-aligned 12 px row | 970 |
| Pill | 20 px high, 11 px / 600, 1 px border, `--radius-sm`. Colour classes below | 973-977 |
| Severity pills | `.sev-critical/high/medium/low/informational` (14 % tint, 28 % border, text in the severity token), `.sev-none` (neutral) | 983-988 |
| State pills | `.st-remediated/verified/closed/resolved/ok/succeeded` (remediated), `.st-accepted_risk/exception`, `.st-warn`, `.st-failed/expired` (critical hue), `.st-running/leased` (info), `.st-neutral` | 988-993 |
| Special pills | `.pill-kev` (solid critical, white text), `.pill-ai`, `.pill-net` (outline) | 994-995, 1009-1010 |
| Criticality pill (0.39.1) | `critPill()` emits `.pill.crit.crit-<level>`: transparent fill, `--text-secondary` text (`--text` for high and critical, 600 weight for critical), `--border-strong` border, and a four-bar level mark (`.crit-mark`, bars at 25 % opacity unless `.on`). Asset criticality is a business rating, so it never takes a `.sev-*` class; unknown values render `.st-neutral` "—" | 996-1003; `app.js:244-257` |
| Ladder and chips (0.39.1) | `ladderSteps()` emits `.ladder` / `.ladder-step` (level in `--gold`) / `.ladder-sep` (`›`, `aria-hidden`); `matchChips()` emits `.cond` key/value chips (999 px radius, `--border`, key in `.muted`). The exact JSON is in the `title` | 1004-1008; `app.js:259-275` |
| Tabs | `.tabs` row of `button`s (0.41.0: `enhanceTabs()` adds `role="tablist"`/`"tab"`, `aria-selected` and a roving `tabindex`; Left, Right, Home and End move along the bar), 38 px high, 13 px / 500; active has `--text` and a 2 px gold underline; row scrolls horizontally. When it follows `.page-head` it becomes the band's lower edge | 776-784, 768-772 |
| Provenance chip | `.prov-bulletin/-model/-you` on prefilled CVSS fields | 265-269 |

`jobStatePill()` emits `st-queued` and `st-cancelled`; since 0.41.0 both share the neutral pill rule (`.sev-none, .st-neutral, .st-queued, .st-cancelled`), so they have a fill and a border like every other state.

### 7.4 Charts

Hand-built SVG and HTML in `app.js`; no chart library. Series colours are the `--chart-*` tokens; the severity ramp is the severity scale.

| Chart | Helper | Classes | Lines |
|---|---|---|---|
| Risk trend and detected/remediated | `trendChart()`, `flowColumns()` | `.trend`, `.trend-line`, `.line-in`, `.line-out`, `.legend`, `.legend-net` (good/bad) | `console.css:1024-1047` |
| Severity donut | `donut()` | `.donut-wrap`, `.donut`, `.legend-table`, `.lt-row` | 1049-1062 |
| Bars, ranked, split | `bars()`, `rankedBars()`, `splitBars()` | `.bars`, `.bar-row`, `.ranked`, `.split*` | 1064-1091 |
| Histogram | `histogram()` | `.hist`, `.hist-col`, `.hist-bar` | 1093-1106 |
| Legacy flow, composition, meter, sparkline | `meter()`, `sparkline()` | `.flow*`, `.compo`, `.stack-seg`, `.meter`, `.spark`, `.single-point` | `console.css:1108-1130` |
| Risk 5x5 heat map | `.rm-*` | Cells carry `.sev-*`; `.rm-cell` sets border width and style only, never colour, so the severity class decides | 385-405 |
| Data disclosure | `chartData()` | `details.chart-data` "Show data" table: the keyboard and screen-reader route to per-point values | `console.css:1131-1138`, `app.js:707-713` |
| Tooltip | one `.tip` element | Chart marks keep `title` until first hover, then move it to `data-tip`; `role="tooltip"`, mouse-driven, Esc hides | `console.css:1140-1145`, `app.js:1342-1369` |

Line charts draw in over 0.9 s (`stroke-dashoffset` animation, `console.css:1038-1040`); bars grow over 0.5 s. A null bucket is a gap, not a zero (`app.js` trend code; narrative in [Design System](../DESIGN_SYSTEM.md) section 0.4). `test_the_smoothed_curve_never_overshoots_a_measured_value` runs the smoothing function under node.

### 7.5 Overlays and feedback

| Component | Spec | Lines |
|---|---|---|
| Modal | `modal({title, body, actions, wide, dismiss})` returns a promise. Backdrop z 60 with blur; dialog 620 px (940 px `.wide`), `role="dialog"`, `aria-modal`, `aria-labelledby`. Escape closes the topmost dialog only, Tab cycles within it, focus returns to the opener, first field is focused. Header close button has `aria-label="Close"` | `console.css:1175-1191`; `app.js:300-353` |
| Command palette | `#pal-input` combobox over a `listbox`; Ctrl/Cmd+K opens it from anywhere inside the app; arrows, Enter, Esc. Backdrop z 90, 680 px, `role="dialog"` `aria-modal` | `console.css:347-373`; `app.js:9269-9314` |
| Toast | `toast(msg, kind)`, `ok()`, `err()`. Stack bottom-right, max 400 px, z 110, inside `role="status" aria-live="polite"`. Left 3 px edge: primary, success, danger. Auto-removes after 4 s (7 s for errors); no pause on hover, no close button | `console.css:1192-1200`; `app.js:284-292`; `index.html:101` |
| Inline form error | `.form-error`: danger-tinted box | `console.css:1169-1172` |
| Empty | `.empty`: dashed box, masked tray icon, bold title plus hint; inside a table wrap or card it loses border and fill | 1161-1168 |
| Not configured | `.not-configured` with numbered steps: "this module was never set up", distinct from "your filter matched nothing" | 295-301; `app.js:8711-8720` |
| Loading skeleton | `.loading`: shimmering placeholder blocks; the text "Loading..." stays in the DOM (transparent); forced-colours mode shows the text; `aria-busy` is set on `#view` during render | 1148-1160; `app.js:1487-1509` |
| Access denied / failure | `render()` writes a card "Access denied" (403) or "Could not load this view" with a Retry button (`data-act="reload"`) | `app.js:1494-1504` |
| Unknown route | `.empty` "Not found" | `app.js:1486` |

### 7.6 Shell, navigation, breadcrumbs

| Component | Spec | Lines |
|---|---|---|
| Shell | Grid `236px 1fr`; icon rail 60 px at 901 px and wider | `console.css:644`, `1243-1254` |
| Sidebar | Sticky full-height column: brand (56 px), `#nav` (free height, scrolls), `#nav-pinned` (Configure, max 45 vh, top border), foot (user chip, theme, docs, sign-out) | 645-722; `index.html:61-82` |
| Nav group | 32 px button with icon, label and chevron; `aria-expanded` | 665-681; `app.js:1256-1260` |
| Nav item | 30 px link; active has `--nav-active` fill and a 2 px gold marker; the active item in light gets a 1 px ring | 683-706 |
| Sub-menu | Tree line, optional uppercase section heads (`sec`) | 699-703 |
| Top bar | Sticky 48 px, z 30, translucent `--background` 82 % with blur; breadcrumbs left; search and notifications right | 725-747 |
| Breadcrumbs | `<nav aria-label="Breadcrumb">`; group / page / sub-view from `NAV`; current item `aria-current="page"` and not a link; separators `aria-hidden`; hidden under 900 px | 731-735, 1267; `app.js:1284-1309` |
| Search | `role="search"` form, input `aria-label="Search"`, `aria-keyshortcuts` | `index.html:89-93` |
| Notification counter | `.badge`: 16 px danger pill, `99+` cap | `console.css:741-746`; `app.js:1564-1571` |
| Avatar | 28 px circle, gold ring | 715-719 |

### 7.7 Configure frame (0.39.0; rail 0.39.1)

Configure is one pinned sidebar link (`.nav-solo`) that opens its own page: a left menu and a body (`configureFrame()`, `app.js:1393-1442`; hub `route('configure')`, `app.js:1444-1457`).

| Element | Spec | Lines |
|---|---|---|
| `.cfg` | Grid `216px minmax(0,1fr)`, gap 24 px, column width animated (`--ease`, 0.2 s); 236 px and 28 px in 0.39.0 | `console.css:803` |
| `.cfg-nav` | Sticky at `--topbar-h + 16px`, max height viewport minus 32 px and top bar, hairline panel, `--radius-lg` | 804-808 |
| Menu head | `.cfg-head` (title plus the rail button) | 809-810 |
| Menu items | `.cfg-page` (pages with icon), `.cfg-sub` (the current page's sub-views, under a tree line), `.cfg-subhead`, `.cfg-sep`; active has `--surface-2` fill and a gold marker; the page that holds the sub-view is `.here` (bold, no fill) | 811-829 |
| Rail button | `.cfg-rail-btn`: 26 px square, `--text-muted`, hover `--surface-2`; `title` and `aria-label` both follow the state ("Collapse" / "Expand the Configure menu"; 0.41.0, TD-60); it is not also an `aria-pressed` toggle | 831-836; `app.js:1420`, `1434-1439` |
| Rail (0.39.1) | `.cfg.rail`, above 900 px only: 52 px icon column, labels and sub-views hidden, the page holding the view gets a fill and gold marker, and the page's own tab bar / segmented control comes back. State in `localStorage` `veyrs.cfg.rail` | 837-850; `app.js:1390`, `1410-1414` |
| `.cfg-body` | Holds the page. Its `.page-head` loses the band; when the page's sub-views are all in the menu, `data-subnav` hides the page's own tab bar and segmented control | 851-857 |
| `.cfg-cards` | Hub cards, `auto-fill` min 280 px, gold icon tile | 858-867 |
| Mobile | Under 900 px: one column, the menu becomes a collapsible panel opened by `.cfg-menu-btn` (`aria-expanded`, `aria-controls`) | 868-877; `app.js:1416`, `1428-1433` |
| Tests | `test_console_configure_frame.py` (ten tests): five pages, every hidden tab has a menu entry, tab bar hidden only where the menu replaces it, sidebar shows one link, `render()` draws into the frame, hub lists the same pages, shared visibility filter, breadcrumb links back, tokens only, and (0.39.1) the menu folds to a rail and the tabs come back | `tests/test_console_configure_frame.py:37-100` |

Status: Verified (structure, by tests); visual layout not observed in a browser.

### 7.8 Login

Two columns, `1.2fr 1fr`. The left hero is always midnight (`--hero-*`, white lockup `veyrs-logo-on-dark-gradient.png`, a 40 px grid texture, a gold hairline); the right form follows the theme. Under 1000 px it is one column and the "V E Y R S" key descriptions are hidden (`console.css:1202-1240`, `index.html:18-57`). The login form side uses 38 px inputs.

## 8. Layouts and breakpoints

The stylesheet uses six media queries (counted by script):

| Query | Effect | Lines |
|---|---|---|
| `max-width: 1200px` | `.span-4/5/7/8` become 6 columns | 1257-1259 |
| `max-width: 1000px` | Login single column; CVSS calculator stacks | 1234-1240, 115 |
| `max-width: 900px` | Gutter 16 px; sidebar becomes a fixed 260 px off-canvas drawer (z 50, slides in with `.open`); rail button, breadcrumbs hidden; search flexes; `.dash` panels full width; Configure menu collapses; guide chain and explainers stack | 1260-1272, 211, 255, 868 |
| `min-width: 901px` | Icon rail layout (`.shell.rail`, 60 px) | 1243-1254 |
| `max-width: 640px` | KPI strip two columns; filters wrap; key/value editors and `dl.kv` stack; stat value 22 px; search shortcut hidden | 1273-1286, 102-111, 131 |
| `forced-colors: active` | `.loading` shows its text | 1160 |

Stacking order (z-index): chart column 1, bulk bar 20, top bar 30, mobile sidebar 50, modal 60, palette 90, toast stack 110, tooltip 120.

## 9. Navigation and interaction patterns

| Pattern | Behaviour | Evidence |
|---|---|---|
| Routing | Hash routes `#/<name>/<part>?<query>`; `render()` swaps `#view`, calls `renderNav`, `configureFrame` and `enhancePage`; default route is `#/triage`; unknown name shows "Not found" | `app.js:1471-1509` |
| Structure | `NAV` defines six groups: Overview, Work, Estate, Intelligence, Reporting and Configure (pinned to the bottom). The sidebar, breadcrumbs, Configure frame and palette are all built from it | `app.js:927-1047` |
| Accordion | Expansion is exclusive per level; the section holding the current route is always open and the stored preference is not overwritten by it. Persisted in `veyrs.nav.open.groups` and `veyrs.nav.open.items` | `app.js:1158-1197`, `8633-8655` |
| Icon rail | `#rail-btn` toggles `.rail`; stored in `veyrs.nav.rail`; not available under 900 px | `app.js:8613-8627` |
| Mobile drawer | `#menu-btn` toggles `.sidebar.open`; navigating closes it. The menu button has `aria-label` but no `aria-expanded` | `app.js:8607`, `1482` |
| Palette | Ctrl/Cmd+K opens a combobox of screens, saved views, triage queues, actions and live search results | `app.js:9133-9314` |
| Triage keyboard | On `#/triage`, outside inputs and dialogs: `t` ticket, `a` assign, `f` false positive, `r` accept risk, `s` skip, `j`/`ArrowDown` and `k`/`ArrowUp` move, Enter opens | `app.js:9105-9124` |
| Row navigation | `tr.clickable` rows are focusable (`tabindex="0"`, visible inset focus ring) and open the detail view on click, Enter or Space (0.41.0, TD-13; one delegated key handler, only when the row itself has focus) | `app.js` `table()`, `enhanceTabs` block |
| Entry animation | Views rise 4 px and fade over 220 ms | `console.css:750-752` |

Motion budget: 160 ms eases on state change, 220 ms view entry, 0.9 s line draw, 1.4 s skeleton shimmer, modal fade and lift, toast slide. `@media (prefers-reduced-motion: reduce)` disables every transition and animation and shows chart lines fully drawn (`console.css:1295-1298`).

## 10. Interface states

| State | Treatment | Evidence |
|---|---|---|
| Default / hover / active / focus / disabled (buttons) | Hover fills `--surface-2`; active translates 1 px; disabled 45 % opacity and `not-allowed`; focus uses the token file's 2 px `:focus-visible` outline | `console.css:607-629`; `veyrs-tokens.css:191-194` |
| Focus (fields) | Border to `--primary` plus `--ring`; outline removed | `console.css:596-600` |
| Selected | Option `.opt.on`, chip `.chip-on`, segment `.active`, tab `.active`, checked label tint, nav `.active` | see 7.1-7.3 |
| Loading | Skeleton, `aria-busy` | 7.5 |
| Empty | `.empty` or `.not-configured`; list views pick between them on whether a filter is applied | `app.js:1881-1882`, `8700-8720` |
| Error | `.form-error`, error toast (7 s), failure card with Retry, 403 card | 7.5 |
| Partial / scoped | `.scope-banner` (`role="status"`) names a narrowed view | `console.css:156-165` |
| Chart without data | A sentence explaining why, never an empty chart | `app.js` chart helpers |

## 11. Sources

- `frontend/console/console.css` (1,304 lines at 0.39.1): all line references above.
- `frontend/console/app.js` (9,559 lines at 0.39.1): `toast`/`modal` (284-353), `table` (434), chart helpers (554-807), `NAV` (927), nav and breadcrumbs (1158-1340), `configureFrame` (1393), `render` (1471), theme (1573, 8656), palette (9133-9314), `critPill`/`ladderSteps`/`matchChips` (244-275).
- `frontend/console/index.html`, `site/static/veyrs-tokens.css`, `frontend/console/fonts/README.txt`.
- Tests: `tests/test_console_design_system.py`, `tests/test_console_redesign_0380.py`, `tests/test_console_configure_frame.py`, `tests/test_console_layout_classes.py`.
