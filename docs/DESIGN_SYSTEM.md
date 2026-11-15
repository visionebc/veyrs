# Design System

Scope: VEYRS 0.35.1 (`pyproject.toml`). How the console, the documentation site and the product site apply the brand, and the rules for changing them.

[Brand](/BRAND.html) defines the identity: the palette, the severity colours, the logo. This document is the **rulebook** for anyone who writes a view, a stylesheet, a chart or a value formatter: which file owns which style, which tokens exist and what they resolve to in each theme, which components to reuse, how values are formatted, and which deviations are already in the code. Every value here was read from the stylesheets and from `frontend/console/app.js`; where this page and the code disagree, the code wins and this page is wrong.

When a rule here changes, this file changes in the same commit.

---

## 1. Three surfaces, five stylesheets

| Surface | Stylesheets, in load order | Palette actually in use |
|---|---|---|
| Console (single-page app, `frontend/console/`) | `/static/veyrs-tokens.css`, then `/console.css?v=N` | The tokens, overridden by `console.css` in the light theme |
| Documentation site (`site/build.py`) | `/static/veyrs-tokens.css`, then `/static/veyrs.css` The BRAND.md dark palette, restated as variables in `veyrs.css`; the tokens supply only the utility classes and the focus ring |
| Product site (`site/web/build_web.py`) | `assets/web.css?v=<content hash>` (generated from the `CSS` string in `build_web.py`) | Its own variables, copied by hand from the brand values |

### What each file owns

| File | Owns |
|---|---|
| `veyrs-tokens.css` | Every `--veyrs-*` brand and semantic colour, the semantic aliases (`--surface`, `--text`, `--primary`, `--nav-bg`...), shadows, radii, spacing, font stacks, type scale, the dark theme, the `.sev-*` / `.badge-*` / `.chip` / `.ai-mark` utility classes and the global `:focus-visible` outline. |
| `console.css` | All console layout and components. It defines **no new custom property**: it re-declares 16 existing ones inside `[data-theme="light"]` (the 2026-08-23 "Notion-inspired reskin") and otherwise consumes the tokens. |
| `veyrs.css` | The documentation site: dark canvas, three-column layout (sidebar, article, on-this-page rail), rendered Markdown. Defines 16 variables of its own (section 2.7). |
| `web.css` (product site) | The product site: navy hero, light content, cards, notes. Defines 15 variables of its own, duplicating brand hex values. |

### Does the console use the tokens file?

Yes. `index.html` links `/static/veyrs-tokens.css` before `console.css`, and every colour in `console.css` is a `var()` of a token except the literals listed in section 12. The console never reads a `--veyrs-*` brand primitive for structure: it reads the **semantic aliases** (`--surface`, `--text`, `--border`, `--primary`, `--nav-*`) for structure and the `--veyrs-<severity>` / `--veyrs-<status>` tokens for meaning.

Three consequences:

- The tokens file reaches the console through `/static/`, which the host deployment aliases to the documentation site's static directory. The Docker image bakes its own copy instead. A console served without the tokens renders every colour as the browser default.
- The canonical copy of the tokens and the logos is `frontend/brand/`; `site/static/` is a mirror (both copies of `veyrs-tokens.css` are byte-identical at 0.35.1). Change both, or the next site build silently reverts the change.
- The console overrides the brand's light palette. In the light theme the console is warm-grey on white with a light sidebar, not the navy-sidebar light UI described in Brand (section 12).

---

## 2. Tokens

`veyrs-tokens.css` defines **65 distinct custom properties**. `console.css` re-declares 16 of them and defines none of its own. Columns:

- **Tokens default**: the value in `:root` of `veyrs-tokens.css`. This is what the docs and product sites, and any page without `data-theme`, get.
- **Console light**: the value inside the console's `[data-theme="light"]` block; "same" if not overridden.
- **Dark**: the value under `[data-theme="dark"]` (and under `prefers-color-scheme: dark` when no `data-theme="light"` is set); "same" if not re-declared.

### 2.1 Brand primitives

| Token | Tokens default | Console light | Dark | Purpose / where used |
|---|---|---|---|---|
| `--veyrs-blue` | `#0064D8` | same | same | VEYRS Blue. Read through `--primary` |
| `--veyrs-blue-rgb` | `0, 100, 216` | same | same | Triplet for `rgba()`; console `.btn-ghost:hover` (dark) |
| `--veyrs-electric` | `#0080FF` | same | same | Electric Blue. Read through `--primary-hover`, `--focus-ring` |
| `--veyrs-electric-rgb` | `0, 128, 255` | same | same | Triplet; not used anywhere |
| `--veyrs-navy` | `#001030` | same | same | Deep Navy. Read through `--nav-bg` (tokens default only) |
| `--veyrs-navy-security` | `#002060` | same | same | Security Navy; not used anywhere |
| `--veyrs-steel` | `#7080A0` | same | same | Steel; not used by the console |
| `--veyrs-steel-light` | `#A0B0C8` | same | same | Light Steel; not used by the console |
| `--veyrs-white` | `#FFFFFF` | same | same | Feeds `--surface`, `--primary-contrast` |
| `--veyrs-bg` | `#F5F7FA` | same | same | Feeds `--background` |
| `--veyrs-border` | `#D9E0EA` | same | same | Feeds `--border` |
| `--veyrs-text` | `#0B1220` | same | same | Feeds `--text` |
| `--veyrs-text-secondary` | `#526070` | same | same | Feeds `--text-secondary` |
| `--veyrs-gradient` | `linear-gradient(135deg, #001030 0%, #0064D8 55%, #0080FF 100%)` | same | same | Official gradient. Console: the 3 px hairline under the login hero, nothing else |

### 2.2 Severity, status and AI

Severity and status hues are lifted in dark mode "for contrast on dark surfaces while keeping the same hue identity". The console never overrides them.

| Token | Tokens default | Console light | Dark | Purpose |
|---|---|---|---|---|
| `--veyrs-critical` | `#B91C1C` | same | `#EF4444` | Critical severity; `.pill-kev` fill; `.stat.crit`; `.split-delta.up` |
| `--veyrs-high` | `#EA580C` | same | `#F97316` | High severity; also reused for warning-like states (section 7) |
| `--veyrs-medium` | `#D97706` | same | `#F59E0B` | Medium severity |
| `--veyrs-low` | `#2563EB` | same | `#3B82F6` | Low severity |
| `--veyrs-informational` | `#64748B` | same | `#94A3B8` | Informational severity |
| `--veyrs-remediated` | `#15803D` | same | `#22C55E` | Remediated and every "good" state pill |
| `--veyrs-accepted-risk` | `#7C3AED` | same | `#A78BFA` | Accepted risk, exception |
| `--veyrs-success` | `#15803D` | same | `#22C55E` | Success toast border |
| `--veyrs-warning` | `#D97706` | same | `#F59E0B` | Not used by the console (it asks for an undefined `--warning`, section 12) |
| `--veyrs-danger` | `#B91C1C` | same | `#EF4444` | Errors: `.form-error`, `.btn-danger`, error toast, required-field asterisk, notification counter |
| `--veyrs-info` | `#2563EB` | same | `#3B82F6` | Not used by the console |
| `--veyrs-neutral` | `#64748B` | same | same (not lifted) | Not used by the console |
| `--veyrs-ai` | `#7C3AED` | same | `#A78BFA` | AI only: `.btn-ai`, `.pill-ai`, AI answers in the assistant panel |

### 2.3 Semantic aliases (what components read)

| Token | Tokens default | Console light | Dark | Purpose |
|---|---|---|---|---|
| `--background` | `#F5F7FA` | `#FFFFFF` | `#070D18` | Page canvas (`body`, light top bar) |
| `--surface` | `#FFFFFF` | `#FFFFFF` | `#0D1626` | Cards, inputs, tables, modals, toasts |
| `--surface-2` | `#EDF1F7` | `#F7F7F5` | `#111F33` | Wells, table header band (dark), hover rows, chart tracks |
| `--surface-raised` | `#FFFFFF` | same | `#111F33` | Not used by the console |
| `--border` | `#D9E0EA` | `#E9E9E7` | `#24344D` | Card, control and table borders |
| `--border-strong` | `#C2CDDB` | `#D3D1CB` | `#2F4463` | Hover borders, bulk bar, `details.why` rule |
| `--text` | `#0B1220` | `#191919` | `#F1F5F9` | Body text |
| `--text-secondary` | `#526070` | `#787774` | `#94A3B8` | Labels, hints, table headers, muted text (65 uses) |
| `--text-inverse` | `#FFFFFF` | same | `#070D18` | Not used by the console |
| `--primary` | `#0064D8` | same | `#0064D8` | Links, primary buttons, selected options, active tab (dark), chart default series |
| `--primary-hover` | `#0080FF` | same | same | Primary button hover |
| `--primary-contrast` | `#FFFFFF` | same | same | Text on `--primary` (`.btn-primary`, `.opt.on`) |
| `--nav-bg` | `#001030` | `#F7F7F5` | `#070D18` | Sidebar background |
| `--nav-text` | `#C9D6E8` | `#5F5E5B` | `#94A3B8` | Sidebar text |
| `--nav-text-active` | `#FFFFFF` | `#191919` | `#F1F5F9` | Active sidebar entry |
| `--focus-ring` | `#0080FF` | same | same | `:focus-visible` outline colour (2 px, offset 2 px) |

### 2.4 Shadows

The brand forbids glow; shadows are subtle and theme-specific.

| Token | Tokens default | Console light | Dark |
|---|---|---|---|
| `--shadow-sm` | `0 1px 2px rgba(11, 18, 32, 0.06)` | `none` | `0 1px 2px rgba(0, 0, 0, 0.4)` |
| `--shadow-md` | `0 2px 8px rgba(11, 18, 32, 0.08)` | `0 1px 4px rgba(15, 15, 15, .06)` | `0 2px 8px rgba(0, 0, 0, 0.45)` |
| `--shadow-lg` | `0 8px 24px rgba(11, 18, 32, 0.10)` | `0 10px 28px rgba(15, 15, 15, .12)` | `0 8px 24px rgba(0, 0, 0, 0.5)` |

Uses: `--shadow-sm` on `.card`, `--shadow-md` on toasts and the bulk bar, `--shadow-lg` on modals.

### 2.5 Radii

| Token | Tokens default | Console light | Dark | Used for |
|---|---|---|---|---|
| `--radius-sm` | `3px` | `6px` | `3px` | Controls, buttons, pills' square cousins, toasts (19 uses) |
| `--radius` | `5px` | `8px` | `5px` | Cards, table wrapper, explainer, workflow steps |
| `--radius-lg` | `8px` | `12px` | `8px` | Modals |

The two console themes therefore differ in **shape** as well as colour: the light theme is rounder.

### 2.6 Spacing, fonts and type scale

| Token | Value | Console use |
|---|---|---|
| `--space-1` .. `--space-6`, `--space-8` | `4px`, `8px`, `12px`, `16px`, `24px`, `32px`, `48px` | None: the console writes spacing as literal pixels |
| `--font-sans` | `"Inter", "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif` | `body` |
| `--font-mono` | `"JetBrains Mono", "SFMono-Regular", Menlo, Consolas, monospace` | `.mono`, textareas, vectors, `kbd` |
| `--text-xs`, `--text-sm`, `--text-base` | `11px`, `12.5px`, `14px` | None (literal sizes) |
| `--text-lg`, `--text-xl`, `--text-2xl`, `--text-3xl` | `16px`, `20px`, `26px`, `34px` | None (literal sizes) |

### 2.7 Variables outside the tokens file

The documentation site (`veyrs.css`) and the product site (`web.css`) do not read the tokens for their own chrome:

| Site | Variables |
|---|---|
| Docs | The BRAND.md dark-mode values: `--bg #070D18`, `--bg-elev #0D1626`, `--bg-soft #111F33`, `--line #24344D`, `--line-soft #1A2840`, `--fg #F1F5F9`, `--fg-dim #94A3B8`, `--fg-faint #7080A0` (Steel), `--body #CBD5E1`, `--accent #0080FF` (Electric Blue: links, focus), `--accent-2 #0064D8` (VEYRS Blue: card rule, search button), `--ok #15803D`, `--warn #D97706`, `--crit #B91C1C`, `--sidebar-w 260px`, `--toc-w 220px`, `--radius 10px` (shadows the token `--radius` on that site). `tests/test_docs_center.py` fails if the old generic palette comes back. |
| Product | `--blue #0064D8`, `--electric #0080FF`, `--navy #001030`, `--navy2 #002056`, `--steel #7080A0`, `--steel-l #A0B0C8`, `--bg #F5F7FA`, `--border #D9E0EA`, `--text #0B1220`, `--text2 #526070`, `--white #fff`, `--crit #B91C1C`, `--high #EA580C`, `--med #D97706`, `--ok #15803D` |

The product site copies `veyrs-tokens.css` into its assets but never links it.

### 2.8 Rules for tokens

- **Use the semantic alias for structure, the semantic token for meaning.** `var(--surface)`, `var(--text-secondary)`, `var(--border)`; `var(--veyrs-critical)` only when the thing *is* critical.
- **Never use a brand primitive for severity, and never a severity token for decoration.** Blue is interaction; red, orange and amber are claims that something is wrong.
- **Tints are `color-mix()`, not new colours.** Pills use `color-mix(in srgb, <token> 13%, transparent)` for the fill and 30–34 % for the border; banners use 6 %. A new tint follows that pattern so it follows the theme.
- **A fallback inside `var()` must be the current value or absent.** `var(--warning, #C2841A)` is a fallback for a token that does not exist (section 12).
- **A console-only variable is a token, not a literal.** If the console needs a value the tokens do not have, add it to `veyrs-tokens.css` in both `frontend/brand/` and `site/static/`.

---

## 3. Contrast, measured

WCAG 2.1 relative luminance, computed from the hex values; tints composited over the surface they sit on (`p × colour + (1 − p) × surface`). AA is 4.5:1 for normal text and 3:1 for large text (24 px, or 18.66 px bold). Pills are 11 px bold: **normal text**.

### 3.1 Text on surfaces

| Pair | Theme | Ratio | AA normal text |
|---|---|---|---|
| `--text #191919` on `#FFFFFF` | Console light | 17.58:1 | Pass |
| `--text #191919` on `--surface-2 #F7F7F5` | Console light | 16.39:1 | Pass |
| `--text-secondary #787774` on `#FFFFFF` | Console light | 4.48:1 | **Fail** (by 0.02) |
| `--text-secondary #787774` on `#F7F7F5` | Console light | 4.17:1 | **Fail** |
| `--nav-text #5F5E5B` on `--nav-bg #F7F7F5` | Console light | 6.04:1 | Pass |
| `--primary #0064D8` (links) on `#FFFFFF` | Console light | 5.51:1 | Pass |
| White on `--primary #0064D8` (`.btn-primary`, `.chip-on`) | Both | 5.51:1 | Pass |
| White on `--primary-hover #0080FF` | Both | 3.80:1 | **Fail** (hover state only) |
| `--text #F1F5F9` on `--surface #0D1626` | Dark | 16.53:1 | Pass |
| `--text-secondary #94A3B8` on `#0D1626` | Dark | 7.06:1 | Pass |
| `--nav-text #94A3B8` on `--nav-bg #070D18` | Dark | 7.58:1 | Pass |
| `--primary #0064D8` (links) on `#0D1626` | Dark | 3.29:1 | **Fail** |
| `--nav-text-active #F1F5F9` on `--primary` (active nav) | Dark | 5.03:1 | Pass |
| `--text #0B1220` on `--background #F5F7FA` | Tokens default | 17.45:1 | Pass |
| `--text-secondary #526070` on `#FFFFFF` | Tokens default | 6.43:1 | Pass |
| `--nav-text #C9D6E8` on `--nav-bg #001030` | Tokens default | 12.78:1 | Pass |
| White on `#001030` (login hero) | Console | 18.80:1 | Pass |
| `#7FC0FF` (`.login-chain`) on `#001030` | Console | 9.75:1 | Pass |

### 3.2 Severity and status on surfaces

Light: text on white, and text on its own 13 % tint over white (the `.pill` treatment; 14 % for informational and AI).

| Colour | On `#FFFFFF` | On own tint (pill) | White text on it (fill) |
|---|---|---|---|
| Critical `#B91C1C` | 6.47:1 pass | 5.17:1 pass | 6.47:1 pass |
| High `#EA580C` | 3.56:1 **fail** | 3.03:1 **fail** | 3.56:1 **fail** |
| Medium `#D97706` | 3.19:1 **fail** | 2.77:1 **fail** (fails large text too) | 3.19:1 **fail** |
| Low `#2563EB` | 5.17:1 pass | 4.32:1 **fail** | 5.17:1 pass |
| Informational `#64748B` | 4.76:1 pass | 4.01:1 **fail** | 4.76:1 pass |
| Remediated `#15803D` | 5.02:1 pass | 4.20:1 **fail** | 5.02:1 pass |
| Accepted risk / AI `#7C3AED` | 5.70:1 pass | 4.61:1 pass | 5.70:1 pass |

Dark: text on `--surface #0D1626`, and on its own tint over that surface.

| Colour | On `#0D1626` | On own tint (pill) | White text on it (fill) |
|---|---|---|---|
| Critical `#EF4444` | 4.81:1 pass | 4.30:1 **fail** | 3.76:1 **fail** (`.pill-kev`) |
| High `#F97316` | 6.46:1 pass | 5.50:1 pass | 2.80:1 **fail** |
| Medium `#F59E0B` | 8.43:1 pass | 6.84:1 pass | n/a |
| Low `#3B82F6` | 4.92:1 pass | 4.21:1 **fail** | n/a |
| Informational `#94A3B8` | 7.06:1 pass | 5.63:1 pass | n/a |
| Remediated `#22C55E` | 7.95:1 pass | 6.42:1 pass | n/a |
| Accepted risk / AI `#A78BFA` | 6.65:1 pass | 5.39:1 pass | n/a |

Large-text uses that pass at 3:1: `.stat.warn .value` (27 px bold, high, 3.56:1) and `.score-big` (52 px, medium, 3.19:1). Non-text uses (bar fills, toast borders, heat-map borders) need 3:1 against the adjacent colour and are not tabulated.

### 3.3 The other two sites

| Pair | Ratio | AA normal text |
|---|---|---|
| Docs `--fg #F1F5F9` on `--bg #070D18` | 17.75:1 | Pass |
| Docs `--fg-dim #94A3B8` on `#070D18` | 7.58:1 | Pass |
| Docs `--fg-faint #7080A0` (nav titles, TOC links) on `#070D18` | 4.89:1 | Pass |
| Docs `--accent #0080FF` (links) on `#070D18` | 5.12:1 | Pass |
| Product `--text2 #526070` on white | 6.43:1 | Pass |
| Product nav `--steel-l #A0B0C8` on `#001030` | 8.54:1 | Pass |
| Product footer `--steel #7080A0` on `#001030` | 4.73:1 | Pass |

---

## 4. Light and dark theme

- **Selection.** The theme is the `data-theme` attribute on `<html>`. `index.html` ships `data-theme="light"`, and `boot()` calls `applyTheme(localStorage.getItem('veyrs.theme') || 'light')`, which always sets the attribute.
- **The OS preference is ignored by the console.** The tokens' `@media (prefers-color-scheme: dark)` block applies only to `:root:not([data-theme="light"])`. The console always carries an explicit value, so a dark-OS user starts in light until they toggle. A user who chose dark may briefly see the light theme while `app.js` loads, because the stored choice is applied by script.
- **Toggle.** Two entry points, both flip light and dark: the sidebar footer button `#theme-toggle` ("◐ Theme", wired with `on()`), and the command palette action "Toggle light / dark theme" (⌘K / Ctrl-K).
- **Persistence.** `localStorage` key `veyrs.theme` (`light` or `dark`), per browser, not per user profile.
- **What differs between themes.** Light is the console's own reskin (warm greys, light sidebar, active nav entry a quiet grey, tabs underlined in ink, table headers without a band, no card shadow, larger radii). Dark is the tokens' dark set unchanged (navy-black canvas, active nav entry filled VEYRS blue, tabs underlined in blue, tinted table headers, 3/5/8 px radii). Severity hues are lifted in dark.
- **The docs site** has no theme switch: it is always dark (`veyrs.css`). Only the tokens' utility classes respond to the OS preference there.
- **The product site** has no dark theme.

---

## 5. Typography, spacing, radii, shadows, layout

### Type

- **Family.** `--font-sans`, Inter first. The console **does not load Inter**: there is no `@font-face`, and its CSP is `font-src 'self'`. It renders in Inter only where Inter is installed locally, otherwise Segoe UI or the system UI font. The docs and product sites load Inter (and the docs site JetBrains Mono) from Google Fonts, an external origin.
- **Base.** `body` 14 px, line-height 1.5, antialiased.
- **Scale in use (console, literal px).** The common steps: 10 (nav group captions, chain steps), 10.5 (histogram labels), 11 (table headers, pills, stat labels, section captions), 12 (hints, small, form labels), 12.5 (mono, sub-items, check grid), 13 (table cells, nav entries, toasts, modal fields), 14 (body, card titles), 15 (modal titles), 21 (page title `h1`), 22 (login title), 27 (stat value), 30 (single-point value), 34 (triage score), 52 (CVSS score). `console.css` uses 20 distinct sizes in total, none of them through the `--text-*` scale.
- **Weights.** 400, 500 (palette labels), 600 (buttons, labels, active nav), 700 (pills, stat values, captions), 800 (CVSS score only).
- **Captions** are uppercase with 0.07–0.16 em tracking: table headers (.07 em), stat labels (.09 em), nav group captions (.14 em).
- **Numbers** in stats, numeric cells, scores and charts use `font-variant-numeric: tabular-nums`.

### Spacing, radii, shadows

- Spacing is literal pixels; the `--space-*` scale is not used by the console. Common steps: grid gap 14 px, card padding 16 px, page padding 22 px 24 px (16 px 14 px under 900 px), table cell 9 px 12 px, modal body 18 px.
- Radii come from `--radius-sm` / `--radius` / `--radius-lg` (section 2.5) plus literals: 999 px (pills, chips, bar tracks), 14 px (triage card, command palette), 12 px (`.not-configured`), 8 px (inline tabs, filter select, palette rows), 4 px (`kbd`, histogram bar tops), 3 px (`.prov`).
- Shadows come from `--shadow-*` except the command palette (`0 24px 60px rgba(0, 0, 0, .35)`).

### Layout

| Element | Value |
|---|---|
| Shell | Grid, sidebar 248 px + content; icon rail 68 px |
| Top bar | Sticky, `z-index` 20; search field max 560 px |
| Breakpoints | 1000 px (login single column, CVSS calculator stacks), 900 px (sidebar becomes an off-canvas drawer, rail disabled), 760, 700, 640, 620 px (local collapses) |
| Grids | `.grid.cols-2` min 320 px, `.cols-3` min 240 px, `.cols-4` min 190 px, `.grid2` min 260 px, `.form-grid` min 190 px |
| Stacking | Top bar and bulk bar 20, mobile sidebar 40, modal 60, toasts and command palette 90 |

---

## 6. Components

Reuse before writing CSS. `tests/test_console_layout_classes.py` fails if `app.js` uses a class that `console.css` does not define.

| Need | Use | Notes |
|---|---|---|
| Action button | `.btn`, `.btn-primary`, `.btn-danger`, `.btn-ai`, `.btn-sm`, `.btn-block` | 8 px 14 px, weight 600, `--radius-sm`. Disabled: 50 % opacity. `.btn-danger` and `.btn-ai` are outline-coloured, not filled |
| Quiet button | `.btn-ghost`, `.icon-btn` | Sidebar footer, modal close, top bar |
| Text field, select | bare `input` / `select` / `textarea` | Full width, 9 px 11 px, `--surface`, `--border`; focus sets the border to `--primary`. Textareas are monospace 13 px, min 96 px high |
| Long form | `.formsec` (ruled section, uppercase `h3`, `.lede`), `.field` with `.lbl`, `.hint`, `.req`; `details.why` for reasoning on demand | Inside `.grid2` / `.form-grid` a `.field` drops its own bottom margin |
| Toggles | `.switches` (one decision per row), `.checkgrid` + `.checkgroup` + `.pickbar` (field pickers), `label.inline`, `label.check` | |
| Key/value rows | `.kv-head`, `.kv-row`, `.vm-row` | |
| Filters | `.filters`, `.filter-inline`, `.view-chips` with `.chip` / `.chip-on` | `.pager` under a list |
| Table | `table()` helper in `app.js` | See below |
| Panel | `.card` (`.card h2` 14 px) | `--surface`, `--border`, `--radius`, 16 px padding |
| Number tile | `.card.stat` with `.label`, `.value`, `.hint`; `.crit` / `.warn` / `.ok` | Tone only when the value is above zero: `tone()` keeps a zero neutral |
| Page header | `.page-head` (`h1` 21 px + lede), `.page-actions` | |
| Tabs | `.tabs` (buttons), `.tabs.tabs-inline` (links, triage) | |
| Status, severity | `.pill` + one class from section 7 | Built by `sevPill()`, `statePill()`, `jobStatePill()`, `riskBandPill()` |
| Explanation | `explainer(key, {...})` → `.explainer` | Collapsible; dismissal remembered in `veyrs.explain.dismissed.v1` |
| Scope notice | `.scope-banner` (`role="status"`) | Brand-accent tint, deliberately not a danger colour |
| Definition list | `dl.kv` (190 px label column) | |
| Code, identifiers | `.mono`, `kbd`, `.pre-wrap` | |
| AI content | `.ai-msg.veyrs`, `.pill-ai`, `.btn-ai` | AI purple only |

### Tables

- Built by `table(cols, rows, opts)`; always wrapped in **`.table-wrap`** (`overflow-x: auto`, border, `--radius`, `--surface`), so a wide table scrolls horizontally inside its card instead of widening the page. `.tablewrap` (no hyphen) is the **product site's** wrapper, not the console's.
- One density: 13 px cells, 9 px 12 px padding, top-aligned. Headers 11 px uppercase, `--text-secondary`, on `--surface-2` in dark and transparent in light.
- **Headers are not sticky.** No console table pins its header; the sticky elements are the top bar, the sidebar, the bulk-action bar and the CVSS score panel.
- `num: true` on a column right-aligns it with tabular figures.
- `opts.onRow` makes rows `.clickable` (pointer, hover `--surface-2`); `opts.selectable` adds a checkbox column (`data-pick`, `data-pick-all`) and `wireSelection()` drives the sticky `.bulk-bar`.
- Empty: `opts.emptyTitle` / `opts.emptyHint` render `.empty` inside the wrapper ("Nothing here yet" by default).

### Modals and drawers

- `modal({ title, body, actions, wide, dismiss })` returns a promise with the form values. Width 640 px, 940 px with `wide`. Backdrop `rgba(0,16,48,.55)`; a click on it cancels. The first field is focused.
- No Escape-to-close and no focus trap in `modal()`. The command palette (`.pal`) is the only overlay that closes on Escape.
- **There are no drawers.** The only off-canvas element is the sidebar below 900 px.

### Toasts

`toast(msg, kind)`, with `ok()` and `err()` shorthands. Stack bottom-right, max 400 px, 3 px left border: `--primary` (plain), `--veyrs-success` (`ok`), `--veyrs-danger` (`err`). Plain and success toasts last 4 s, errors 7 s. The stack has no `aria-live`.

### Sidebar and navigation

- Defined by the `NAV` array in `app.js`: groups (Overview, Work, Estate, Intelligence, Reporting, Tools, Configure), items with a Unicode glyph icon (`ico`), an optional permission, and optional `children` (filtered sub-entries).
- Groups and items with children collapse; expansion is exclusive at each level. The open sets persist in `veyrs.nav.open.groups` and `veyrs.nav.open.items`; the section holding the current route is always rendered open.
- Icon rail (`#rail-btn`): 68 px column, labels hidden, group captions become hairlines; persisted in `veyrs.nav.rail`; disabled under 900 px.
- Active entry: filled `--primary` in dark, `rgba(15,15,15,.07)` grey in light.

### Empty, loading and error states

| State | Rendering |
|---|---|
| Loading | `.loading` "Loading…" |
| Table with no rows | `.empty` inside `.table-wrap` |
| Module never set up | `notConfigured()` → `.not-configured` (dashed border, numbered steps) — distinct from "your filter matched nothing" |
| Chart with no data | A `p.muted.small` sentence saying why ("Every bucket is empty — nothing to plot.") |
| Unknown route | `.empty` "Not found" |
| 403 | Card "Access denied" |
| Any other failure | Card "Could not load this view" with a Retry button (`data-act="reload"`) |

### CVSS calculator (`#/cvss`)

- Tabs for v2.0, v3.0, v3.1, v4.0; default v3.1. Metric definitions come from `/cvss/metrics/<version>`; scores from `/cvss/score`. The page computes nothing itself.
- `.cvss-layout`: metrics card + 330 px side column (stacks under 1000 px). Each `.metric` is a 210 px name column (`.abbr` in mono) and a row of `.opt` toggle buttons; the selected one is `.opt.on` (filled `--primary`). Optional metrics get a "Not defined" option unless the spec has its own.
- `.score-panel` is sticky (`top: 74px`): `.score-big` 52 px weight 800 coloured by `sevColour(severity)`, a severity pill, the vector in `.score-vector` (mono, breaks anywhere), and a 2×2 `.score-sub` grid (Base, Temporal / Threat, Environmental, Version), each one decimal.
- "Analyse a bulletin…" fills metrics and marks each with a provenance chip: `.prov-bulletin` (green), `.prov-model` (blue); a metric the analyst changes loses its chip.

---

## 7. Severity and status pills

`.pill`: inline, 2 px 8 px, fully rounded, 11 px weight 700, uppercase, 0.03 em tracking, no wrap, 1 px border. A colour class adds a 13 % tint, the colour as text and a 32 % border.

| Class | Colour token | Meaning |
|---|---|---|
| `.sev-critical`, `.sev-high`, `.sev-medium`, `.sev-low`, `.sev-informational` | matching `--veyrs-*` | Severity, and the risk-register bands |
| `.sev-none` | `--surface-2` / `--text-secondary` | Missing or unrecognised severity (label "none") |
| `.st-remediated`, `.st-verified`, `.st-closed`, `.st-resolved`, `.st-succeeded`, `.st-ok` | `--veyrs-remediated` | Done, good, enabled |
| `.st-accepted_risk`, `.st-exception` | `--veyrs-accepted-risk` | Accepted risk |
| `.st-failed`, `.st-expired` | `--veyrs-critical` | Job failed, or nothing is known about whether it ran |
| `.st-running`, `.st-leased`, `.st-warn` | `--veyrs-high` | In progress, attention |
| `.st-neutral` | `--surface-2` / `--text-secondary` | Any other state |
| `.pill-kev` | white on `--veyrs-critical` (filled) | CISA Known Exploited |
| `.pill-ai` | `--veyrs-ai` | AI-originated |
| `.pill-net` | `--veyrs-high` | Internet-exposed asset |

- **Severity order** is `SEV_ORDER`: critical, high, medium, low, informational. Every severity chart and comparison follows it.
- **Labels.** `sevPill()` prints the API value and CSS uppercases it ("CRITICAL"); `statePill()` and `jobStatePill()` title-case the value (`accepted_risk` → "Accepted Risk", then uppercased by `.pill`).
- **Risk bands** for the continuous 0–100 VEYRS risk score (`riskBand()`, mirroring `LEVEL_BANDS` in the backend): ≥ 90 critical, ≥ 70 high, ≥ 40 medium, ≥ 10 low, else informational. `ticketPriorityFor()` uses the same upper cuts and maps everything below 40 to low.
- **Never invent a status colour.** A new state maps to a class above, or gets a class added here and in `console.css` in the same commit.

---

## 8. Charts

There is **no chart library**: every chart is hand-built HTML or inline SVG in `app.js`, styled by `console.css`. Colour is never the only encoding: every mark carries a label and a value, and a hover `title`.

| Helper | Form | Colours |
|---|---|---|
| `bars(obj, palette)` | Horizontal bars on a 10 px rounded track | `palette(key)` or `--primary`; track `--surface-2` |
| `splitBars(left, right, opts)` | Back-to-back bars around a centre column of severity pills, with a signed delta | `sevColour(key)`; delta up `--veyrs-critical`, down `--veyrs-remediated` |
| `histogram(obj, unit)` | Vertical bins (CVSS and EPSS distributions) | One hue, `--primary`; empty bin a 2 px `--surface-2` stub |
| `flowColumns(points)` | Detected above / remediated below a zero baseline | Detected `--veyrs-high`, remediated `--veyrs-remediated`; baseline `--border` |
| `rankedBars(rows, opts)` | Ranked list with a bar per row | `opts.colour(row)` (top assets: `sevColour(riskBand(score))`) or `--primary` |
| `sparkline(points)` | Inline SVG line + area, 720 × 150 viewBox, 2 px non-scaling stroke | `--primary` line, area gradient `--primary` 24 % → 0, axis `--border`, last point ringed with `--surface` |
| Risk heat map (`riskMatrixModal()`) | 5 × 5 grid of `.rm-cell` | The same `.sev-*` classes as the band pills |

- `sevColour()` maps a severity to its token and falls back to `--primary` for anything else (section 12).
- Bar widths and fills are set in `style` attributes (`width:…%;background:var(…)`), permitted by `style-src 'unsafe-inline'`.
- The SVG sets colours through presentation attributes holding `var()` (`stroke="var(--primary)"`, `stop-color="var(--primary)"`). A `style` declaration is the safer form for new drawings.
- One series uses one hue. Severity colours appear only where the categories *are* severities.

---

## 9. Formats

All formatting helpers live at the top of `app.js` (`fmtNum`, `fmtPct`, `fmtScore`, `fmtDate`, `fmtDay`, `fmtShortDate`, `titleCase`) plus `scanDuration` and `scanBytes` in the scanner section. Examples are for an `en-US` browser in its local time zone.

| Value | How it is written | Example | Source |
|---|---|---|---|
| Absent value | Em dash | `—` | All `fmt*` helpers return `—` for `null` / `undefined` |
| Count | Browser-locale grouping, no decimals | `12,408` | `fmtNum()` → `toLocaleString()` |
| Ratio as percent | × 100, one decimal by default, `.` decimal point always | `37.5%` | `fmtPct(n, d = 1)` |
| CVSS score | One decimal | `9.8` | `fmtScore()`; same in the calculator for base, temporal and environmental |
| CVSS vector | Monospace, as returned | `CVSS:3.1/AV:N/AC:L/…` | `.mono`, `.score-vector` |
| VEYRS risk score (0–100) | One decimal, never with a `/100` suffix | `87.4` | `fmtScore()`; labelled "Composite, not CVSS" on the dashboard |
| EPSS probability | `fmtPct()`: one decimal in lists, cards and dashboards; two decimals in EPSS history and the triage card | `12.3%`, `0.04%` | Mixed (section 9.1) |
| EPSS percentile | Integer 0–100 | `percentile 94`, `p94`, `94` | Mixed (section 9.1) |
| Severity | API value, uppercased by `.pill` | `CRITICAL` | `sevPill()` |
| State | Title case, uppercased by `.pill` | `ACCEPTED RISK` | `statePill()` |
| CVE / CWE id | Monospace link to `#/intel/cve/<id>` or `#/intel/cwe/<id>` | `CVE-2024-3400` | Most lists and detail pages |
| Date and time | Locale date and time, no time-zone label | `Nov 01, 2026, 02:05 PM` | `fmtDate()` |
| Date only | Locale date | `Nov 01, 2026` | `fmtDay()` |
| Chart axis date | Month and day | `Nov 1` | `fmtShortDate()` |
| Feed age | Hours, `h ago` | `3 h ago`, `2.5 h ago` | Threat Intel feed pills and stat |
| Mean time to remediate | Hours, one decimal, no space | `12.3h` | Executive dashboard |
| Scan duration | Seconds, or minutes and zero-padded seconds | `42s`, `1m 05s` | `scanDuration()` |
| Refresh interval | Named, or minutes | `Weekly`, `Every 90 min` | Intel schedule |
| File size | 1024-based, one decimal, `B` / `kB` / `MB` | `512 B`, `3.4 kB`, `12.0 MB` | `scanBytes()`; software update shows `MB` inline |
| Sample size | `n=` prefix | `n=14` | MTTR, sparkline tooltip |
| Truncated UUID | First 8 characters | `3f2a9c1d` | Team, agent, finding fallbacks |
| Long text in a cell | Hard cut with `.slice(0, N)`, no ellipsis | — | 60–180 characters depending on the column |
| Never happened | Muted word | `never` | Feed last success, asset source last sync |

Time zone: every `fmt*` date is rendered in the **browser's** time zone with no label. Times sent by the API are ISO 8601.

### 9.1 Format defects

1. **EPSS below 0.05 % reads as `0.0%`.** Lists, cards and dashboards use `fmtPct()` with one decimal; most EPSS scores are below 1 %, so many distinct probabilities print identically as `0.0%`. EPSS history and the triage card use two decimals for the same value.
2. **EPSS percentile is written three ways:** `percentile 94` (finding, vulnerability and CVE cards), `p94` (vulnerability list), bare `94` (EPSS history table).
3. **Mixed locales in one number set.** `fmtNum()` groups with the browser locale, but `fmtPct()`, `fmtScore()` and the duration helpers use `toFixed()`, which always writes `.`. In a German browser a count reads `1.234` and a score `9.8`.
4. **Raw timestamps bypass `fmtDate()`:** Administration › Asset sources "Last sync" (`String(...).slice(0, 16)`, i.e. UTC text beside browser-local times elsewhere), Scanner connectors scan list (`finished_at` printed raw), Risk Register "Review" column (`review_due_at` printed raw).
5. **Risk score printed unformatted** in the external Issues list (`'risk ' + r.risk_score`), where every other view uses `fmtScore()`.
6. **The overdue review date is not highlighted.** The Risk Register wraps it in `class="err"`, which has no rule of its own (only `.toast.err` exists), so overdue and on-time dates look the same. The layout test does not catch it because the class name is interpolated.
7. **Durations have four spellings:** `12.3h`, `3 h ago`, `1m 05s`, `30 s`.
8. **Risk level case differs by place:** the raw API label (lowercase `critical`) under the score in finding and vulnerability lists, `CRITICAL` in pills.
9. **CVE ids are sometimes plain text:** the Issues list and the upgrade-path plan print them without `.mono` or a link.
10. **Truncation is inconsistent:** cut lengths of 60, 80, 90, 100, 110, 120, 150, 160 and 180 characters, with no ellipsis and no `title` carrying the full text. CSS ellipsis is used only in the sidebar, the check grid and ranked-bar labels.
11. **`fmtShortDate(null)` prints the epoch** (`Jan 1`, or `Dec 31` west of UTC) instead of `—`; it lacks the null guard the other two date helpers have.
12. **Job states `queued` and `cancelled` render unstyled.** `jobStatePill()` emits `st-queued` and `st-cancelled`, which `console.css` does not define, so those pills have no fill or border instead of the neutral grey.

---

## 10. Brand assets in the UI

### What the files are

The real logo is the PNG set: one bitmap whose ink measures **1129 × 814 px** (alpha above 25 %; 1129 × 816 counting faint antialiasing). There is no vector master and no larger raster. Measured in `frontend/brand/logo/`:

| File | Canvas | What it contains |
|---|---|---|
| `veyrs-logo.png` | 1240 × 925 | Stacked lockup: folded-ribbon V, navy VEYRS wordmark, descender, rule with a small shield glyph. Light backgrounds |
| `veyrs-logo-on-dark-gradient.png` | 1129 × 816 | Same lockup cropped to ink, gradient V and white wordmark |
| `veyrs-logo-on-dark.png`, `veyrs-logo-white.png` | 1240 × 925 | All-white lockup; the two files are byte-identical |
| `veyrs-logo-on-dark-tight.png` | 1129 × 815 | The white lockup cropped to ink |
| `veyrs-logo-black.png` | 1240 × 925 | All-black lockup |
| `veyrs.png` | 1254 × 1254 | Square master, navy wordmark |
| `veyrs-mark.png` | 852 × 852 | The V alone, padded; 9,289 distinct colours |
| `veyrs-mark-gradient.png` | 706 × 450 | The V alone, cropped to ink |
| `veyrs-wordmark.png` | 1262 × 283 | Wordmark alone |
| `veyrs-favicon.png`, `veyrs-favicon.ico` | 256 × 256 | The V, full colour |

**Not for UI:**

- **Every `.svg`** (`veyrs-logo*.svg`, `veyrs-mark*.svg`, `veyrs-favicon.svg`, `veyrs-wordmark.svg`). They are early placeholders: a geometric shield path with a straight-cut white V, flat fills (`#0064D8`, `#002060`, `#7080A0`, the official gradient) and live-text wordmarks. They do not draw the real mark.
- **`veyrs-mark-white.png`, `veyrs-mark-black.png`, `veyrs-mark-on-dark.png`** (852 × 852, about 29 KB each). Inspected: each holds exactly one colour (white, `#0A0E16` and white respectively) over the same 125,691 opaque pixels as `veyrs-mark.png`, i.e. a flat silhouette of the real V, without the fold and the two-tone shading that make the mark. `mark-white` and `mark-on-dark` are byte-identical. `frontend/brand/logo/README.md` calls them rasterisations of the placeholder SVGs; the pixels show silhouettes of the real outline instead. The rule is unchanged: they are not approved variants. The console sidebar shipped `veyrs-mark-white.png` once, for a day.

### Where each file is used

| Place | File | Size |
|---|---|---|
| Console sidebar (`.brand-mark`) | `/static/veyrs-mark-gradient.png`, `alt=""` beside the "VEYRS" text | `width: 36px; height: auto` → 36 × 23 CSS px, also in rail mode |
| Console login hero (`.login-logo`) | `/static/veyrs-logo-on-dark-gradient.png` | 264 px wide, max 68 % of the hero, subtle drop shadow, on the navy hero gradient `#000B22 → #001030 → #002056` |
| Console favicon | `/static/veyrs-favicon.png` | 256 × 256 PNG |
| Docs site header | `/static/veyrs-mark-gradient.png` (`MARK` in `site/build.py`) | 36 px wide, height auto |
| Docs site favicon | `/static/veyrs-favicon.png` | 256 × 256 PNG |
| Product site nav | `assets/veyrs-mark-gradient.png` | 26 px wide |
| Product site hero | `assets/veyrs-logo-on-dark-gradient.png` | Up to 520 px (`min(520px, 86vw)`) |
| Product site footer | `assets/veyrs-logo-on-dark-gradient.png` | 180 px |
| Product site favicon | `assets/veyrs-favicon.png` | 256 × 256 PNG |
| PDF reports | No logo | Navy title and table header, VEYRS-blue tagline (section 12) |

Rules:

- The resolution ceiling is about 560 CSS px of width on a 2× display; larger looks soft.
- A surface that carries the logo stays navy-dominant (`#000B22 → #002056`). The official gradient's bright end gives white about 3.8:1, so it is a hairline or accent there, never the backdrop.
- A new asset goes into `frontend/brand/logo/` **and** `site/static/`.

---

## 11. Markup rules: CSP, actions, views, cache-busting

### What the Content-Security-Policy does to markup

The console is served with `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` (host vhost and Docker image identical); the API sends a similar policy on its own responses.

- **No inline script and no `on*=` attributes**, including in HTML strings built by `app.js`. They would not fail loudly; the browser would simply not run them.
- `style="…"` attributes are allowed and used (368 in `app.js`, mostly chart geometry), but a class is preferred.
- No web font, script or stylesheet from another origin.
- Images: same origin or `data:` only (the TOTP QR code is inline SVG markup).
- Every interpolated value goes through `esc()`.

### Adding an action

1. For a button that opens a dialog from a list header, write `data-act="<name>"` on it and add `<name>` to the `ACTIONS` map in `app.js`. One document-level listener dispatches every `[data-act]` click.
2. For a behaviour shared across re-renders, add a `data-*` hook and one delegated `document` listener, as `data-explain-toggle`, `data-read`, `data-risk-matrix` and `data-pick` do. The router replaces `#view` on every navigation, so per-element listeners on view content die with it.
3. For controls inside a view, assigning `el.onclick = …` after setting `innerHTML` is acceptable (a property, not an attribute).
4. Elements in `index.html` are wired with `on(selector, event, fn)`, which no-ops when the element is missing; `boot();` stays the last statement of `app.js`.

### Adding a view

1. Register it: `route('<name>', async (view, parts, params) => { … })`. URLs are hash routes, `#/<name>/<part>?<query>`; an unknown name renders "Not found".
2. Add it to `NAV` with `path`, `label`, `ico` and, if gated, `perm`. Filtered sub-entries go in `children` with a `q` object. Optional flags: `hidden`, `scan`, `reg`, `mode`.
3. Build it from the components in section 6 and the formatters in section 9. Every class it uses must exist in `console.css`.
4. A route that moves keeps its old hash working through `MOVED`.

### Cache-busting

- `index.html` loads `/app.js?v=N` and `/console.css?v=N` (37 and 14 at 0.35.1). **Bump the number of every file you change**, in the same commit. `tests/test_phase30_scanner_page.py` checks only that the parameters exist, not that they moved.
- `/static/veyrs-tokens.css` carries **no** version parameter and `/static/` is served with a one-hour cache, so a token change can take up to an hour to reach a browser (section 12).
- The product site appends a content hash to `web.css` automatically; the docs site appends `?v=<hash of veyrs.css + veyrs.js>` to both, computed by `site/build.py`.

---

## 12. Known deviations and debt

### Contradictions with Brand

1. **The console light theme is not the brand's light UI.** Brand specifies canvas `#F5F7FA`, border `#D9E0EA`, text `#0B1220`, secondary `#526070` and a Deep Navy sidebar. The console's light theme uses `#FFFFFF`, `#E9E9E7`, `#191919`, `#787774` and a `#F7F7F5` sidebar. Navy appears only on the login hero, so the "20 % deep navy" usage ratio does not hold in light mode.
2. **Over-rounded surfaces.** Brand avoids over-rounded cards; the tokens comment calls 8 px "deliberately restrained". Console light raises `--radius-lg` to 12 px, and the triage card and the command palette hard-code 14 px.
3. **Brand blue used for severity.** `sevColour()` falls back to `--primary` for any key that is not one of the five severities, so the CVSS calculator paints a `None` (0.0) score in VEYRS blue.
4. **Severity colours reused for non-severity meaning.** `--veyrs-high` marks running jobs, `st-warn`, internet exposure (`.pill-net`), "Nobody accountable", and stale feeds (`sev-high`); `.sev-medium` marks partner exposure and minor upgrades; `st-remediated` marks isolated assets. Brand reserves orange for high.
5. **The `prefers-color-scheme` rule in Brand does not apply to the console** (section 4).
6. **PDF reports carry no severity palette.** `services/reporting.py` uses Deep Navy `#001030` (title, headings, table header), VEYRS Blue `#0064D8` (tagline), `#526070` (metadata), `#D9E0EA` (grid) and `#F5F7FA` (zebra rows), Helvetica. Severities are printed as text.

### Hard-coded colours in `console.css`

| Literal | Where | Should be |
|---|---|---|
| `#000B22`, `#001030`, `#002056`, `rgba(0,128,255,.30)`, `rgba(0,100,216,.22)` | Login hero gradient | Acceptable (logo backdrop per the brand README); `#000B22` and `#002056` are not tokens |
| `#7FC0FF` | `.login-chain` | A token |
| `#fff` (9 times) | Brand name, notification counter, `.pill-kev`, `.explainer-ico`, `.chip-on`, `.pal-row.on`, login hero | `--primary-contrast` or `--text-inverse` |
| `#C2841A`, `rgba(194,132,26,.09)` | `.explainer-warn`, as the fallback of an **undefined** `--warning` | `--veyrs-warning` |
| `#10844A`, `rgba(16,132,74,.14)` | `.prov-bulletin` | `--veyrs-remediated` (`#15803D`); `#10844A` is off-palette and measures 3.95:1 on its tint |
| `rgba(0,128,255,.13)` | `.prov-model` | A `color-mix()` of `--primary` |
| `rgba(0,16,48,.55)` and `rgba(8,13,26,.55)` + blur | Modal backdrop and command-palette backdrop | One token; the second is the docs site's base colour |
| `0 24px 60px rgba(0,0,0,.35)` | Command palette | `--shadow-lg` |
| `rgba(255,255,255,.04–.22)`, `rgba(15,15,15,.045–.07)`, `rgba(127,127,127,.06/.16)` | Nav hover and active tints, sub-item rules, explainer hover, `.prov-you` | Tokens per theme |

In `app.js`: `#fff` behind the TOTP QR code (justified: a QR needs a white quiet zone); `#EA580C` and `#D97706` appear only in a comment. `var(--line)` in an Administration `hr` names the docs site's variable, which the console does not define, so that separator does not render.

### Other defects

1. **Input focus shadow is invalid.** `input:focus { box-shadow: var(--focus-ring) }`, but `--focus-ring` is a colour, so the declaration is dropped; with `outline: none` on inputs, a mouse focus shows only the border colour change. Keyboard focus still gets the tokens' `:focus-visible` outline.
2. **Contrast failures** (section 3): light `--text-secondary` (4.48:1 on white, 4.17:1 on `--surface-2`), high and medium pills and text in light, dark links (3.29:1), dark `.pill-kev` (3.76:1).
3. **Class-name collisions between the tokens file and the console.** `veyrs-tokens.css` defines `.badge` (severity badge), `.chip` (outline chip) and `.sev-*` (coloured text with a square marker); `console.css` reuses all three names for different components (notification counter, saved-view chip, pill colour). Properties the console does not override (uppercase and tracking on `.badge`, weight 600 on `.chip`) leak through.
4. **Unused tokens:** the spacing scale, the type scale, `--surface-raised`, `--text-inverse`, `--veyrs-navy-security`, `--veyrs-electric-rgb`, `--veyrs-info`, `--veyrs-neutral`, `--veyrs-warning` and the steel pair are defined and never read by the console, directly or through an alias. Counting the brand primitives that the console reaches only through an alias, 31 of the 65 tokens are never referenced by name in `console.css` or `app.js`.
5. **The tokens' OS-dark block is incomplete:** it re-declares colours but not shadows, so a page dark by OS preference keeps the light shadows.
6. **`veyrs-tokens.css` is not cache-busted** in the console (section 11).
7. **Modals lack Escape-to-close and a focus trap; toasts lack `aria-live`.**
8. **Sidebar theme toggle writes `localStorage` before applying the theme without a `try`;** where storage throws (some private modes), the click does nothing. The command-palette toggle applies first and guards the write.
9. **SVG colours in presentation attributes** (`stroke="var(--primary)"`) rather than `style`; not verified across browsers in this audit.
10. **Icons are Unicode glyphs** (◆ ⚠ ▦ ✦, plus the emoji 🔔 and 🗎), so their weight and colour depend on the platform font.

### Documentation and product sites

1. **Fixed 2026-11-11:** the docs-site header mark (an inline SVG shield in `#3b82f6 → #8b5cf6`), its placeholder favicon `veyrs-favicon.svg` and its generic slate/blue/violet palette were replaced by `veyrs-mark-gradient.png`, `veyrs-favicon.png` and the BRAND.md dark palette. `tests/test_docs_center.py` guards all three.
2. **External fonts.** The docs site `@import`s Inter and JetBrains Mono from Google Fonts; the product site links Inter from Google Fonts. The console loads no web font at all.
3. **Product site duplicates the palette by hand** instead of linking `veyrs-tokens.css` (which it copies but never references), and uses gradient-filled primary buttons with a blue glow on hover (`0 8px 24px rgba(0,128,255,.32)`), gradient text, and cards that lift on hover — the brand's "excessive gradients" and "glow" list.

---

## 13. Checklist for a UI change

1. Colours are `var(--…)`: semantic aliases for structure, `--veyrs-<severity>` / `--veyrs-<status>` only for meaning, `--veyrs-ai` only for AI. No new hex literal in `console.css` or `app.js`.
2. Statuses are `.pill` + an existing class from section 7; a new state gets a class in `console.css` in the same commit.
3. Text contrast measured at 4.5:1 or better on the surface it sits on, **in both themes**; pills count as normal text.
4. Checked in light **and** dark, since radii, shadows, nav and tab treatments differ between them.
5. Components from section 6; every class used exists in `console.css`; wide tables sit in `.table-wrap`.
6. Values go through the section 9 formatters: `—` for absent, `fmtScore()` for CVSS and risk, `fmtDate()` / `fmtDay()` for times, `fmtNum()` for counts.
7. Charts label every mark; severity colours only for severities; empty data is a sentence, not an empty chart.
8. No `on*=` attribute, no inline script; actions through `data-act` or a delegated `data-*` hook; every interpolated value through `esc()`.
9. `?v=` bumped in `index.html` for each changed file (`app.js`, `console.css`).
10. Logos only from the PNG set in section 10; never an `.svg`, never a `mark-white/-black/-on-dark` PNG; new assets in both brand directories.
11. A token change made in both copies of `veyrs-tokens.css`, and this page and [Brand](/BRAND.html) updated in the same commit.

---

## 14. Where it is enforced

| Test | Holds |
|---|---|
| `tests/test_console_layout_classes.py` | Every literal class `app.js` uses has a rule in `console.css`; modifier classes appear with their base; `st-ok`, `st-warn`, `st-neutral` and the form layout primitives exist |
| `tests/test_phase31_console_wiring.py` | Every top-level selector exists in `index.html`; handlers go through `on()`; `boot()` runs last |
| `tests/test_phase30_scanner_page.py` | `app.js` and `console.css` carry a `?v=` cache-buster |

Nothing tests the contrast of the shipped palette, the use of tokens over literals, or the logo files in use.

Related: [Brand](/BRAND.html) · [Architecture](/ARCHITECTURE.html) · [Security](/SECURITY.html) · [Development](/DEVELOPMENT.html).
