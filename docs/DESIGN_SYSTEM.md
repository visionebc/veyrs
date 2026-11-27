---
title: Design system
purpose: Narrative rulebook for how the console and the sites apply the VEYRS brand: ownership of styles, token rules, component and format conventions, markup rules and the ledger of known deviations.
scope: Console design-system rules at 0.39.1 and the brand token file; the token and component tables are in design/console-ui.md, accessibility in design/accessibility.md, and the documentation portal's own design system lives in site/design-system/.
version: 0.39.1
verified: 2026-11-17
status: Partial
sources: [frontend/console/console.css, frontend/console/app.js, frontend/console/index.html, site/static/veyrs-tokens.css, tests/test_console_design_system.py, tests/test_console_redesign_0380.py, tests/test_console_configure_frame.py, tests/test_docs_center.py]
related: [BRAND.md, design/console-ui.md, design/accessibility.md]
---

# Design System

Scope: VEYRS 0.39.1 (`pyproject.toml`). How the console and the brand token file apply the brand, and the rules for changing them.

[Brand](BRAND.md) defines the identity: the palette, the severity colours, the logo. This document is the **rulebook** for anyone who writes a view, a stylesheet, a chart or a value formatter: which file owns which style, which token rules apply, which components to reuse, how values are formatted, and which deviations are already in the code. The complete token tables per theme, the component catalogue with line references and the layout/breakpoint reference are in [Console UI reference](design/console-ui.md); the measured contrast and the accessibility gaps are in [Accessibility](design/accessibility.md). Every value was read from the stylesheets and from `frontend/console/app.js`; where this page and the code disagree, the code wins and this page is wrong.

**Status of the sections (re-verified 2026-11-17).** Sections 0, 1, 2.1, 2.8, 9, 10, 11 and 13 describe the code as it is. Sections marked *Obsolete* hold pre-0.38.0 values that were superseded and are kept only as history, each with a pointer to where the current value lives. Where a table still lists the sites other than the console, it was not re-verified for the documentation portal, which is being redesigned.

When a rule here changes, this file changes in the same commit.

---

## 0. Console: "Midnight Ops" (0.38.0)

**This section is the current console design.** It replaced the 0.36/0.37 presentation layer; the console-specific values that older sections of this file still carried (palette, chrome, card, stat-tile, pill and chart rules) have been removed or marked *Obsolete* below. The owner rejected two rounds of refinement inside the old rules ("it still looks just as ugly") and asked for a full replacement of the presentation layer: deep navy/midnight, graphite, cool blue accents, a subtle metallic gold, both themes designed separately. 0.39.0 added the Configure frame (section 0.6). The product site is unchanged.

### 0.1 Direction

Three concepts were weighed: *Midnight Ops* (dense, technical, hairline structure), *Ledger* (light, editorial, wide margins) and *Command Deck* (top navigation, full-width observability panels). Midnight Ops was chosen: it is the densest, it suits an operations console, and it carries the requested palette without decoration.

- **Structure over decoration.** Hairline borders and one step of surface tone separate things; there are no drop shadows on panels. Overlays (modal, tooltip, toast, mobile drawer) are the only things that float.
- **Gold means "you are here"**, nothing else: the active nav marker, the active tab underline, the avatar ring. Blue is interaction (buttons, links, focus). Semantic colours are meaning only.
- **Midnight (dark) is the default**; an operator's stored choice is kept. *Porcelain* (light) has its own light sidebar, darker semantic hues for 4.5:1 on tints, and a deeper gold.

### 0.2 Tokens

Both theme blocks sit at the top of Part 2 of `console.css` (`:root[data-theme="dark"]`, lines 469-514, and `[data-theme="light"]`, lines 520-565). Each defines the same 43 custom properties, and they are the only place a colour literal may appear besides `:root` and the login hero (`tests/test_console_design_system.py`); `test_both_themes_are_designed_on_their_own` fails if a pinned key is missing from either. The complete per-theme table, with the role of each token, is in [Console UI reference](design/console-ui.md) section 3. The excerpt below is the part most often needed.

| Token | Midnight | Porcelain | Use |
|---|---|---|---|
| `--background` | `#0A0D13` | `#F3F4F7` | canvas |
| `--surface` / `--surface-2` / `--surface-raised` | `#0F131B` / `#151B25` / `#19202C` | `#FFFFFF` / `#F6F7F9` / `#FFFFFF` | panels / tracks, inputs / overlays |
| `--border` / `--border-strong` | `#1E2633` / `#2B3546` | `#E2E5EB` / `#CBD1DA` | hairlines |
| `--text` / `--text-secondary` / `--text-muted` | `#E7EBF1` / `#98A3B5` / `#6C778A` | `#0D1524` / `#556076` / `#7D879A` | ink |
| `--primary` / `--link` | `#3D6FD6` / `#86ACF6` | `#2F5FCC` / `#2652BD` | buttons / links |
| `--gold` | `#C9A45C` | `#9A7430` | active markers only |
| `--nav-bg` | `#080B10` | `#FAFAFB` | sidebar |
| `--chart-risk` / `--chart-in` / `--chart-out` | `#6F9BF2` / `#E3A24B` / `#3FB68B` | `#2F64D8` / `#D08A2E` / `#1C8460` | risk score / risk arriving / risk leaving |
| `--veyrs-critical` … `--veyrs-informational` | `#EF5D68` `#F08A4B` `#E3B341` `#6C9BE8` `#7D889A` | `#C9303E` `#C9581F` `#A87812` `#3E68B5` `#66708A` | the severity scale |

Radii are 4 / 6 / 8 px (`--radius-sm`, `--radius`, `--radius-lg`, defined in the console's `:root`, which overrides the token file's 3 / 5 / 8). Type: Inter 400–700 and JetBrains Mono 400/500, self-hosted (`frontend/console/fonts/`); body 13.5 px, page title 22 px / 600 / −0.025 em, panel titles 13 px / 600, metrics 26 px tabular.

### 0.3 Shell and page composition

- **Sidebar** (236 px; 60 px icon rail on 901 px and wider): brand and organisation, then six categories as real rows with drawn icons and a rotating chevron (the accordion behaviour of 0.21+ is unchanged and still guarded by `test_phase32_nav_collapsed.py`), a tree line under an open category, and the user, theme, docs and sign-out at the foot. **Configure** lives in its own block, `#nav-pinned`, between the menu and that foot (0.38.2, reworked in 0.38.3): `pin: 'bottom'` in `NAV`; `#nav` takes the free height so the gap sits between Reporting and Configure; open, the block grows upwards to at most 45% of the window and scrolls inside, so it never leaves the bottom.
- **Top bar** (48 px, translucent): breadcrumbs left; search (Ctrl K) and notifications right.
- **Page band:** `.page-head` is a full-width band welded to the top bar; when tabs follow it, they become its lower edge. Long descriptions fold behind *More*.
- **Metric strip:** `.kpis` (and any `.grid` of `.card.stat` anywhere in the console) renders as ONE strip divided by hairlines, never a row of floating tiles. A coloured dot before the label marks tone; the value carries it too.
- **Panels:** `.card` is a hairline panel with a 42 px header strip when its first child is an `h2`. `.card.flush` lets a table run edge to edge under the header.
- **Dashboard grid:** `.dash` is 12 columns; panels take `.span-4/5/6/7/8/12` (6 below 1200 px, 12 below 900 px).
- **Theme:** `data-theme` on `<html>`, dark unless the operator stored a choice under `veyrs.theme` (section 4).

### 0.4 Charts

| Chart | Function | Rule |
|---|---|---|
| Risk trend | `trendChart()` | Monotone cubic line (`smoothPath()`, Fritsch–Carlson: never overshoots a measured value — `test_the_smoothed_curve_never_overshoots_a_measured_value`), gradient area, axis snapped to tens, latest value labelled, null buckets are gaps. |
| Detected vs remediated | `flowColumns()` | Two smooth series over one axis (`niceMax()`), legend with totals and the net, per-bucket tooltip. |
| Backlog composition | `donut()` | Part-to-whole of one total with five ordered parts; the legend carries every number with a bar and a percentage. |
| Distributions | `histogram()` | Gradient columns over quarter gridlines. |
| SLA compliance | `ring()` | One ratio against the 90 % target. |
| KPI sparklines | `kpiSpark()` | Smoothed line with a faint area; only series the API returns. |

Every chart keeps a *Show data* table (keyboard and screen-reader access) and the shared tooltip. Lines draw in once (0.9 s); nothing animates under `prefers-reduced-motion`.

### 0.5 Motion

Entry: views rise 4 px and fade in over 220 ms. State changes: 160 ms ease. Modals fade and lift, toasts slide in, the skeleton shimmers. Reduced motion turns all of it off (`console.css:1295-1298`).

### 0.6 Configure frame (0.39.0; rail 0.39.1)

Everything under Configure (Scanner, Integrations, Policies, Automation, Administration) lives on its own page: a menu of its own on the left listing the pages and the current page's sub-views, the page on the right. The sidebar carries one pinned **Configure** link (`.nav-solo`), lit on the hub and on every page it holds. The frame is built from the `NAV` group (`configureFrame()`, `app.js:1393`), so the frame, the breadcrumbs, the hub cards and the routes cannot disagree; a page whose sub-views are all in the menu hides its own tab bar. Under 900 px the menu collapses behind a button. Since 0.39.1 the menu is 216 px (was 236 px) and, above 900 px, folds to a 52 px icon rail from a button at its top; the choice is remembered per browser (`veyrs.cfg.rail`), and when folded the page's own tab bar comes back so no sub-view is stranded. Details and line references: [Console UI reference](design/console-ui.md) section 7.7; guard: `tests/test_console_configure_frame.py`.

---

## 1. Three surfaces, five stylesheets

| Surface | Stylesheets, in load order | Palette actually in use |
|---|---|---|
| Console (single-page app, `frontend/console/`) | `/static/veyrs-tokens.css?v=2`, then `/console.css?v=21` (`index.html:12-13`) | Two console themes (Midnight, Porcelain) defined in `console.css`; the token file contributes the fonts, the spacing scale, the brand white and navy, the AI and accepted-risk hues |
| Documentation portal (`site/build.py`) | `/static/veyrs.css` only (the token file is not linked: its OS-dark block redefined `--text`/`--border`, names `veyrs.css` shares, and blanked the text, 0.38.3) | Owned by the portal agent; its design system lives in `site/design-system/` (section 15) |
| Product site (`site/web/build_web.py`) | `assets/web.css?v=<content hash>` (generated from the `CSS` string in `build_web.py`) | Its own variables, copied by hand from the brand values |

### What each file owns

| File | Owns |
|---|---|
| `veyrs-tokens.css` | Every `--veyrs-*` brand and semantic colour, the semantic aliases (`--surface`, `--text`, `--primary`, `--nav-bg`...), shadows, radii, spacing, font stacks, type scale, a dark theme, the `.sev-*` / `.badge-*` / `.chip` / `.ai-mark` utility classes and the global `:focus-visible` outline. For the console, most colour aliases are dead values: `console.css` redefines them per theme (section 2). |
| `console.css` | All console layout and components, plus the two theme blocks (43 custom properties each) and 13 theme-independent properties (radii, `--ease`, `--dur`, `--sidebar-w`, `--topbar-h`, `--gutter`, hero colours, `--scrim`, `--ring`). Part 1 (lines 9-426) holds the component layouts that read only tokens; Part 2 (428-1270) holds the design system and wins where both define a selector. |
| `veyrs.css` | The documentation portal. Not described here. |
| `web.css` (product site) | The product site: navy hero, light content, cards, notes. Defines 15 variables of its own, duplicating brand hex values. |

### Does the console use the tokens file?

Yes. `index.html` links `/static/veyrs-tokens.css` before `console.css`, and every colour in `console.css` outside the theme blocks, `:root` and the login hero is a `var()` of a token (`test_colour_literals_live_only_in_the_token_blocks`). The console never reads a `--veyrs-*` brand primitive for structure: it reads the **semantic aliases** (`--surface`, `--text`, `--border`, `--primary`, `--nav-*`) for structure and the `--veyrs-<severity>` / `--veyrs-<status>` tokens for meaning.

Three consequences:

- The tokens file reaches the console through `/static/`, which the host deployment aliases to the documentation site's static directory. The Docker image bakes its own copy instead. A console served without the tokens loses the font stacks, the spacing scale, `--veyrs-white`, `--veyrs-navy`, `--veyrs-ai` and `--veyrs-accepted-risk`; the theme colours survive because `console.css` defines them.
- The canonical copy of the logos is `frontend/brand/logo/`; `site/static/` is a mirror (verified byte-identical for every PNG, the favicon and `veyrs-favicon.svg` on 2026-11-17). Change both, or the next site build silently reverts the change.
- The console overrides the brand's neutral palette in both themes. Its light theme (Porcelain) is cool grey with white panels and a light sidebar, not the navy-sidebar light UI described in [Brand](BRAND.md); its dark theme (Midnight) is graphite, not the brand's navy-black.

---

## 2. Tokens

`veyrs-tokens.css` defines **65 distinct custom properties**. Since 0.38.0 `console.css` defines its own complete palette for both themes (43 properties each, plus 13 theme-independent ones), so most colour values in sections 2.2 to 2.5 below are what the **token file** says, not what the console shows. **The console's values are in [Console UI reference](design/console-ui.md) section 3; the former "Console light" columns of this section held the retired 0.36/0.37 warm-grey values and were removed (Obsolete).** Columns:

- **Tokens default**: the value in `:root` of `veyrs-tokens.css`. This is what a page without `data-theme` gets, and what `.badge-*` and `.sev-*` fall back to.
- **Dark**: the value under `[data-theme="dark"]` in the token file (and under `prefers-color-scheme: dark` when no `data-theme="light"` is set); "same" if not re-declared. In the console, `console.css` loads later and overrides every one of these except `--veyrs-ai` and `--veyrs-accepted-risk`.

### 2.1 Brand primitives

| Token | Tokens default | Dark | Purpose / where used |
|---|---|---|---|
| `--veyrs-blue` | `#0064D8` | same | VEYRS Blue. Read through `--primary` |
| `--veyrs-blue-rgb` | `0, 100, 216` | same | Triplet for `rgba()`; console `.btn-ghost:hover` (dark) |
| `--veyrs-electric` | `#0080FF` | same | Electric Blue. Read through `--primary-hover`, `--focus-ring` |
| `--veyrs-electric-rgb` | `0, 128, 255` | same | Triplet; not used anywhere |
| `--veyrs-navy` | `#001030` | same | Deep Navy. Read through `--nav-bg` (tokens default only) |
| `--veyrs-navy-security` | `#002060` | same | Security Navy; not used anywhere |
| `--veyrs-steel` | `#7080A0` | same | Steel; not used by the console |
| `--veyrs-steel-light` | `#A0B0C8` | same | Light Steel; not used by the console |
| `--veyrs-white` | `#FFFFFF` | same | Feeds `--surface`, `--primary-contrast` |
| `--veyrs-bg` | `#F5F7FA` | same | Feeds `--background` |
| `--veyrs-border` | `#D9E0EA` | same | Feeds `--border` |
| `--veyrs-text` | `#0B1220` | same | Feeds `--text` |
| `--veyrs-text-secondary` | `#526070` | same | Feeds `--text-secondary` |
| `--veyrs-gradient` | `linear-gradient(135deg, #001030 0%, #0064D8 55%, #0080FF 100%)` | same | Official gradient. Console: the 3 px hairline under the login hero, nothing else |

### 2.2 Severity, status and AI

Severity and status hues are lifted in dark mode "for contrast on dark surfaces while keeping the same hue identity". The console overrides every one of them except `--veyrs-ai` and `--veyrs-accepted-risk` (its values are in [Console UI reference](design/console-ui.md) section 3.1); the "Purpose" column describes the roles, which are unchanged.

| Token | Tokens default | Dark | Purpose |
|---|---|---|---|
| `--veyrs-critical` | `#B91C1C` | `#EF4444` | Critical severity; `.pill-kev` fill; `.stat.crit`; `.split-delta.up` |
| `--veyrs-high` | `#EA580C` | `#F97316` | High severity only (warning-like states moved to `--veyrs-warning` in 0.36.0) |
| `--veyrs-medium` | `#D97706` | `#F59E0B` | Medium severity |
| `--veyrs-low` | `#2563EB` | `#3B82F6` | Low severity |
| `--veyrs-informational` | `#64748B` | `#94A3B8` | Informational severity |
| `--veyrs-remediated` | `#15803D` | `#22C55E` | Remediated and every "good" state pill |
| `--veyrs-accepted-risk` | `#7C3AED` | `#A78BFA` | Accepted risk, exception |
| `--veyrs-success` | `#15803D` | `#22C55E` | Success toast border |
| `--veyrs-warning` | `#D97706` | `#F59E0B` | Warning pill, stat and banner tone (console value differs) |
| `--veyrs-danger` | `#B91C1C` | `#EF4444` | Errors: `.form-error`, `.btn-danger`, error toast, required-field asterisk, notification counter |
| `--veyrs-info` | `#2563EB` | `#3B82F6` | In-progress pills (`.st-running`, `.st-leased`) |
| `--veyrs-neutral` | `#64748B` | same (not lifted) | Fallback series colour for a non-severity key (`sevColour()`) |
| `--veyrs-ai` | `#7C3AED` | `#A78BFA` | AI only: `.btn-ai`, `.pill-ai`, AI answers in the assistant panel |

### 2.3 Semantic aliases (what components read)

| Token | Tokens default | Dark | Purpose |
|---|---|---|---|
| `--background` | `#F5F7FA` | `#070D18` | Page canvas |
| `--surface` | `#FFFFFF` | `#0D1626` | Cards, inputs, tables, modals, toasts |
| `--surface-2` | `#EDF1F7` | `#111F33` | Wells, inputs, hover rows, chart tracks |
| `--surface-raised` | `#FFFFFF` | `#111F33` | Overlays and raised controls (the console defines its own) |
| `--border` | `#D9E0EA` | `#24344D` | Card, control and table borders |
| `--border-strong` | `#C2CDDB` | `#2F4463` | Hover borders, overlays, `details.why` rule |
| `--text` | `#0B1220` | `#F1F5F9` | Body text |
| `--text-secondary` | `#526070` | `#94A3B8` | Labels, hints, secondary text |
| `--text-inverse` | `#FFFFFF` | `#070D18` | Not read by `console.css` |
| `--primary` | `#0064D8` | `#0064D8` | Primary buttons, selected options, focus halo (the console redefines it per theme) |
| `--primary-hover` | `#0080FF` | same | Primary button hover |
| `--primary-contrast` | `#FFFFFF` | same | Text on `--primary` (`.btn-primary`, `.opt.on`) |
| `--nav-bg` | `#001030` | `#070D18` | Sidebar background |
| `--nav-text` | `#C9D6E8` | `#94A3B8` | Sidebar text |
| `--nav-text-active` | `#FFFFFF` | `#F1F5F9` | Active sidebar entry |
| `--focus-ring` | `#0080FF` | same | `:focus-visible` outline colour (2 px, offset 2 px) |

### 2.4 Shadows

The brand forbids glow; shadows are subtle and theme-specific.

| Token | Tokens default | Dark |
|---|---|---|
| `--shadow-sm` | `0 1px 2px rgba(11, 18, 32, 0.06)` | `0 1px 2px rgba(0, 0, 0, 0.4)` |
| `--shadow-md` | `0 2px 8px rgba(11, 18, 32, 0.08)` | `0 2px 8px rgba(0, 0, 0, 0.45)` |
| `--shadow-lg` | `0 8px 24px rgba(11, 18, 32, 0.10)` | `0 8px 24px rgba(0, 0, 0, 0.5)` |

Uses in the console (which defines its own three shadows per theme): `--shadow-sm` on the triage card, `--shadow-md` on toasts, the tooltip and the bulk bar, `--shadow-lg` on modals, the palette and the mobile drawer. Panels have no shadow.

### 2.5 Radii

| Token | Tokens default | Dark | Used for |
|---|---|---|---|
| `--radius-sm` | `3px` | `3px` | Segmented buttons, pills, kbd, palette rows (console: 4 px) |
| `--radius` | `5px` | `5px` | Controls, buttons, explainer, workflow steps, segmented control (console: 6 px) |
| `--radius-lg` | `8px` | `8px` | Cards, tables, modals, command palette, triage card, "not configured" panel |

The console redefines the scale as 4 / 6 / 8 px (`console.css:452-454`). Nothing in `console.css` is rounder than 8 px except `999px` chips and `50%` dots (`test_radii_stay_on_the_brand_scale`).

### 2.6 Spacing, fonts and type scale

| Token | Value | Console use |
|---|---|---|
| `--space-1` .. `--space-6`, `--space-8` | `4px`, `8px`, `12px`, `16px`, `24px`, `32px`, `48px` | The utility classes `.mt-*`, `.mb-*`, `.gap-*` and `hr.rule` (`console.css:411-423`, `1303`); everything else is written as literal pixels |
| `--font-sans` | `"Inter", "Segoe UI", system-ui, -apple-system, "Helvetica Neue", Arial, sans-serif` | `body` |
| `--font-mono` | `"JetBrains Mono", "SFMono-Regular", Menlo, Consolas, monospace` | `.mono`, textareas, vectors, `kbd` |
| `--text-xs`, `--text-sm`, `--text-base` | `11px`, `12.5px`, `14px` | None (literal sizes; the console body is 13.5 px) |
| `--text-lg`, `--text-xl`, `--text-2xl`, `--text-3xl` | `16px`, `20px`, `26px`, `34px` | `.t-lg` and `.t-xl` only; the rest are literal sizes |

### 2.7 Variables outside the tokens file

The documentation site (`veyrs.css`) and the product site (`web.css`) do not read the tokens for their own chrome:

| Site | Variables |
|---|---|
| Docs | *Not re-verified for the redesigned portal; its own design system is in `site/design-system/`.* Since 0.38.2 the product site's set, value for value (`--blue`, `--electric`, `--navy`, `--navy2`, `--steel`, `--steel-l`, `--bg`, `--border`, `--text`, `--text2`, `--white`, `--crit`, `--high`, `--med`, `--ok`), plus `--tint #F5F9FF` (active sidebar entry, quotes), `--code-bg #EEF2F7`, and layout: `--wrap 1320px`, `--sidebar-w 248px`, `--toc-w 216px`, `--nav-h 64px`. `tests/test_docs_center.py` compares every product-site variable with the docs one, so changing a colour on one site without the other fails. |
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

The measured contrast of the console's two themes (text, links, buttons, every pill, focus ring, borders) is in [Accessibility](design/accessibility.md) section 2, computed on 2026-11-17 from the 0.39.0 values (0.39.1 changed no token) with a WCAG 2.x relative-luminance function. The 0.36/0.37 tables that used to be in this section (warm-grey light theme, `#191919` text, brand-blue links on dark) described values that no longer ship and were removed (Obsolete).

What remains here are the **brand token colours** (the token file's defaults, used by the product site and by the `.badge-*` and `.sev-*` utility classes) and the two other sites. WCAG 2.1 relative luminance; AA is 4.5:1 for normal text and 3:1 for large text (24 px, or 18.66 px bold).

### 3.1 Brand severity colours (token-file defaults and dark block)

| Colour | On `#FFFFFF` (light default) | White text on it (`.badge-*` fill) | On dark surface `#0D1626` |
|---|---|---|---|
| Critical `#B91C1C` / dark `#EF4444` | 6.47:1 pass | 6.47:1 pass | 4.81:1 pass |
| High `#EA580C` / `#F97316` | 3.56:1 **fail** | 3.56:1 **fail** | 6.46:1 pass |
| Medium `#D97706` / `#F59E0B` | 3.19:1 **fail** | 3.19:1 **fail** | 8.43:1 pass |
| Low `#2563EB` / `#3B82F6` | 5.17:1 pass | 5.17:1 pass | 4.92:1 pass |
| Informational `#64748B` / `#94A3B8` | 4.76:1 pass | 4.76:1 pass | 7.06:1 pass |
| Remediated `#15803D` / `#22C55E` | 5.02:1 pass | 5.02:1 pass | 7.95:1 pass |
| Accepted risk / AI `#7C3AED` / `#A78BFA` | 5.70:1 pass | 5.70:1 pass | 6.65:1 pass |

The console does not use these hues for its pills: it redefines every severity and status colour per theme and tints them (see [Accessibility](design/accessibility.md)). The VEYRS gradient's bright end `#0080FF` gives white text 3.80:1, which is why a surface holding the logo stays navy-dominant (`#0064D8` gives white 5.51:1; `#001030` 18.80:1).

### 3.2 The other two sites

| Pair | Ratio | AA normal text |
|---|---|---|
| Product `--text2 #526070` on white | 6.43:1 | Pass |
| Product nav `--steel-l #A0B0C8` on `#001030` | 8.54:1 | Pass |
| Product footer `--steel #7080A0` on `#001030` | 4.73:1 | Pass |
| Tokens default `--text #0B1220` on `--background #F5F7FA` | 17.45:1 | Pass |
| Tokens default `--text-secondary #526070` on `#FFFFFF` | 6.43:1 | Pass |
| Tokens dark `--text #F1F5F9` on `--surface #0D1626` | 16.53:1 | Pass |

The documentation portal's contrast figures belong to its own design system (`site/design-system/`).

---

## 4. Light and dark theme

- **Selection.** The theme is the `data-theme` attribute on `<html>`. `index.html` ships `data-theme="dark"` (so the first paint is right) and `boot()` calls `applyTheme(localStorage.getItem('veyrs.theme') || 'dark')`, which always sets the attribute (`app.js:1519`, `1573`; pinned by `test_midnight_is_the_default_theme`). Both themes are scoped to the attribute; there is no unscoped base.
- **The OS preference is ignored by the console.** The token file's `@media (prefers-color-scheme: dark)` block applies only to `:root:not([data-theme="light"])`, and the console always carries an explicit value. A user who stored light may briefly see dark while `app.js` loads, because the stored choice is applied by script.
- **Toggle.** Two entry points, both flip dark and light: the sidebar footer button `#theme-toggle` and the command-palette action "Toggle light / dark theme" (Ctrl/Cmd+K). Both apply the theme first and then try to store it.
- **Persistence.** `localStorage` key `veyrs.theme` (`light` or `dark`), per browser, not per user profile.
- **What differs between themes.** The themes are designed separately, not inverted (`console.css:516-519`): *Midnight* (dark) has a graphite canvas and midnight sidebar; *Porcelain* (light) has white panels on a cool grey canvas, a light sidebar with ink type, darker severity and status hues so tinted text holds contrast, and a deeper gold. Radii, spacing, layout and component shapes are identical; one rule differs (the active nav row and active Configure page get a 1 px ring in light, `console.css:690`, `820`).
- **The documentation portal and the product site** have their own palettes; the portal's design system lives in `site/design-system/`.

---

## 5. Typography, spacing, radii, shadows, layout

The full reference (sizes in use with counts, weights, spacing utilities, breakpoints, stacking order) is [Console UI reference](design/console-ui.md) sections 4, 6 and 8. The rules:

### Type

- **Family.** `--font-sans`, Inter first. The console **serves Inter (400/500/600/700) and JetBrains Mono (400/500) from its own origin**: Latin-subset woff2 files in `frontend/console/fonts/` (six files, licences beside them), declared with `@font-face` at the top of Part 2 of `console.css` and two of them preloaded from `index.html`. That keeps the CSP at `font-src 'self'`.
- **Base.** `body` 13.5 px, line-height 1.5, antialiased; controls and table cells 13 px; captions and hints 11-12 px; page title 22 px; stat value 26 px.
- **Weights.** 400, 500, 600 (headings, labels, active nav; the most used), 700, 800 (CVSS score only).
- **Captions** are uppercase with 0.04-0.12 em tracking: table headers (.06 em), section captions (.07-.09 em), chain steps (.12 em).
- **Numbers** in stats, numeric cells, scores and charts use `font-variant-numeric: tabular-nums`.
- Sizes are literal pixels; only `.t-lg` and `.t-xl` use the token scale.

### Spacing, radii, shadows

- Spacing is on a 4 px base; the utility classes `.mt-*`, `.mb-*`, `.gap-*` read `--space-*`, everything else is literal pixels (grid gap 14 px, card padding 16 px, page gutter 28 px or 16 px under 900 px, table cell 9 px 12 px, modal body 18 px).
- Radii: `--radius-sm` 4 px, `--radius` 6 px, `--radius-lg` 8 px, plus `999px` (chips), `50%` (dots), `2-3 px` (small bars and tags).
- Shadows are the theme's three tokens. Panels have none: depth comes from the surface step.

### Layout

| Element | Value |
|---|---|
| Shell | Grid, sidebar 236 px + content; icon rail 60 px at 901 px and wider; off-canvas drawer 260 px at 900 px and below |
| Top bar | Sticky, 48 px, `z-index` 30; search field `clamp(200px, 28vw, 360px)` |
| Page | Max width 1680 px, gutter 28 px (16 px under 900 px) |
| Breakpoints | 1200 px (dashboard spans), 1000 px (login single column, CVSS calculator stacks), 900 px (drawer, Configure menu collapses, rail off), 640 px (KPI strip two columns, key/value editors stack), plus 901 px for the rail |
| Grids | `.grid.cols-2` min 320 px, `.cols-3` min 240 px, `.cols-4` min 190 px, `.cols-5` min 168 px, `.grid2` min 260 px, `.form-grid` min 190 px |
| Stacking | Bulk bar 20, top bar 30, mobile sidebar 50, modal 60, command palette 90, toasts 110, tooltip 120 |

---

## 6. Components

Reuse before writing CSS. `tests/test_console_layout_classes.py` fails if `app.js` uses a class that `console.css` does not define. The catalogue with measurements and line references is [Console UI reference](design/console-ui.md) section 7; this table says which class to reach for.

| Need | Use | Notes |
|---|---|---|
| Action button | `.btn`, `.btn-primary`, `.btn-danger`, `.btn-ai`, `.btn-sm`, `.btn-block` | 32 px high (28 px small), weight 500. `.btn-danger` and `.btn-ai` are outline-coloured, not filled |
| Quiet button | `.btn-ghost`, `.icon-btn` | Sidebar footer, modal close, top bar |
| Text field, select | bare `input` / `select` / `textarea` | Full width, `--surface-2` fill, `--border`; focus sets the border to `--primary` and adds the `--ring` halo. Textareas are monospace, min 96 px high |
| Long form | `.formsec` (ruled section, uppercase `h3`, `.lede`), `.field` with `.lbl`, `.hint`, `.req`; `details.why` for reasoning on demand | Inside `.grid2` / `.form-grid` a `.field` drops its own bottom margin |
| Toggles | `.switches` (one decision per row), `.checkgrid` + `.checkgroup` + `.pickbar` (field pickers), `label.inline`, `label.check` | |
| Key/value rows | `.kv-head`, `.kv-row`, `.vm-row` | |
| Filters | `.filters`, `.filter-inline`, `.view-chips` with `.chip` / `.chip-on` | `.pager` under a list |
| Table | `table()` helper in `app.js` | See below |
| Panel | `.card` | Hairline panel, `--radius-lg`, 16 px padding; an `h2` first child becomes a 42 px header strip |
| Number tile | `.kpis` strip or any grid of `.card.stat`, with `.label`, `.value`, `.hint`; `.crit` / `.warn` / `.ok` | Rendered as one strip. Tone only when the value is above zero: `tone()` keeps a zero neutral |
| Page header | `.page-head` (`h1` 22 px + lede), `.page-actions` | Full-width band |
| Tabs | `.tabs` (buttons), `.tabs.tabs-inline` (links, triage) | Active tab has a gold underline |
| Segmented control | `.seg`, `.seg-sm` | |
| Status, severity | `.pill` + one class from section 7 | Built by `sevPill()`, `statePill()`, `jobStatePill()`, `riskBandPill()` |
| Explanation | `explainer(key, {...})` → `.explainer` | Collapsible; dismissal remembered in `veyrs.explain.dismissed.v1` |
| Scope notice | `.scope-banner` (`role="status"`) | Brand-accent tint, deliberately not a danger colour |
| Definition list | `dl.kv` (190 px label column) | |
| Code, identifiers | `.mono`, `kbd`, `.pre-wrap` | |
| AI content | `.ai-msg.veyrs`, `.pill-ai`, `.btn-ai` | AI purple only |
| Configure page | `configureFrame()`, `.cfg`, `.cfg-nav`, `.cfg-body`, `.cfg-cards` | Section 0.6 |

### Tables

- Built by `table(cols, rows, opts)` (`app.js:434`); always wrapped in **`.table-wrap`** (`overflow-x: auto`, border, `--radius-lg`, `--surface`), so a wide table scrolls horizontally inside its card instead of widening the page. `.tablewrap` (no hyphen) is the **product site's** wrapper, not the console's.
- One density: 13 px cells, 9 px 12 px padding, middle-aligned. Headers are 36 px high, 11 px uppercase, `--text-muted`, on `--surface`.
- **Headers are not sticky.** No console table pins its header; the sticky elements are the top bar, the sidebar, the Configure menu, the bulk-action bar and the CVSS score panel.
- `num: true` on a column right-aligns it with tabular figures.
- `opts.onRow` makes rows `.clickable` (pointer, a 2 px inset `--primary` bar on hover); the row opens its detail on **mouse click only** (`app.js:1901-1903`; see [Accessibility](design/accessibility.md) gap 5). `opts.selectable` adds a checkbox column (`data-pick`, `data-pick-all`) and `wireSelection()` drives the sticky `.bulk-bar`.
- Empty: `opts.emptyTitle` / `opts.emptyHint` render `.empty` inside the wrapper ("Nothing here yet" by default; list views say "No records match these filters" when a filter is applied).

### Modals and drawers

- `modal({ title, body, actions, wide, dismiss })` returns a promise with the form values. Width 620 px, 940 px with `wide`. Backdrop `--scrim` with a 3 px blur; a click on it cancels. The first field is focused.
- **Escape closes the topmost dialog only, Tab cycles inside it and focus returns to the opener** (`app.js:300-353`). The page behind is not made `inert`. The command palette (`.pal`) closes on Escape too.
- **There are no drawers.** The only off-canvas element is the sidebar below 900 px.

### Toasts

`toast(msg, kind)`, with `ok()` and `err()` shorthands. Stack bottom-right, max 400 px, 3 px left edge: `--primary` (plain), `--veyrs-success` (`ok`), `--veyrs-danger` (`err`). Plain and success toasts last 4 s, errors 7 s. The stack is `role="status" aria-live="polite"` (`index.html:101`); toasts cannot be paused or dismissed.

### Sidebar and navigation

- Defined by the `NAV` array in `app.js` (`app.js:927`): groups (Overview, Work, Estate, Intelligence, Reporting, Configure — the last pinned to the foot with `pin: 'bottom'` and shown as one link), items with an icon key (`ico`) into the drawn `ICONS` set, an optional permission, and optional `children` (filtered sub-entries). A child with `sec: '<label>'` opens a labelled block inside a long sub-menu: Threat Intel (Feeds), AI Assistant (Configure) and Administration (Access, Data intake, Platform).
- Icons: one drawn set in `app.js` (`ICONS`, 24-unit grid, 1.75 stroke, `currentColor`), rendered by `icon(name)`; the shell's menu, notification, theme and docs icons in `index.html` are the same drawings inline. No font glyph or emoji is used as an icon.
- A group may hold a single entry only when that entry has a sub-menu (Estate → Inventory).
- Groups and items with children collapse; expansion is exclusive at each level. The open sets persist in `veyrs.nav.open.groups` and `veyrs.nav.open.items`; the section holding the current route is always rendered open.
- Icon rail (`#rail-btn`): 60 px column, labels hidden; persisted in `veyrs.nav.rail`; disabled under 900 px.
- Active entry: `--nav-active` fill, bolder weight and a 2 px gold marker on the left edge; sub-entries take the marker and weight only. Hover: `--nav-hover`.
- Breadcrumbs (`#crumbs`) are derived from `NAV`, so the sidebar and the trail cannot name a page differently.
- Administration page: inside Configure, its section switch is replaced by the Configure menu's sub-views; the sidebar's `sec:` labels and the page's sections must agree, and a test holds them together.

### Empty, loading and error states

| State | Rendering |
|---|---|
| Loading | `.loading` skeleton; the text "Loading…" stays in the DOM and `#view` carries `aria-busy` |
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

`.pill`: inline-flex, 20 px high, 7 px side padding, `--radius-sm`, 11 px weight 600, no wrap, 1 px border. A colour class adds a 13-14 % tint, the colour as text and a 28-32 % border. Severity pills lead with a 6 px dot in the text colour and capitalise the API's lower-case word; state pills carry their own casing (`console.css:973-1010`).

| Class | Colour token | Meaning |
|---|---|---|
| `.sev-critical`, `.sev-high`, `.sev-medium`, `.sev-low`, `.sev-informational` | matching `--veyrs-*` | Severity and the risk-register bands (asset criticality has its own neutral pill since 0.39.1, `.pill.crit`) |
| `.sev-none` | `--surface-2` / `--text-secondary` | Missing or unrecognised severity (label "none") |
| `.st-remediated`, `.st-verified`, `.st-closed`, `.st-resolved`, `.st-succeeded`, `.st-ok` | `--veyrs-remediated` | Done, good, enabled |
| `.st-accepted_risk`, `.st-exception` | `--veyrs-accepted-risk` | Accepted risk |
| `.st-failed`, `.st-expired` | `--veyrs-critical` | Job failed, or nothing is known about whether it ran |
| `.st-running`, `.st-leased` | `--veyrs-info` | In progress |
| `.st-warn` | `--veyrs-warning` | Attention |
| `.st-neutral` | `--surface-2` / `--text-secondary` | Any other state |
| `.pill-kev` | white on `--veyrs-critical` (filled; dark mixes it toward navy) | CISA Known Exploited |
| `.pill-ai` | `--veyrs-ai` | AI-originated |
| `.pill-net` | outline: `--text` on `--border-strong` | Internet-exposed asset |

- **Severity order** is `SEV_ORDER`: critical, high, medium, low, informational (`app.js:493`). Every severity chart and comparison follows it.
- **Severity classes only for severities.** A state that is not a severity never takes a `.sev-*` class; the only non-finding use is the risk-register bands, which are a risk severity on the same five-step scale. Asset criticality is a business rating, not a severity: since 0.39.1 it is a neutral pill with a four-step level mark (`critPill()`, `app.js:244-257`; `.pill.crit`, `console.css:996-1003`), pinned by `tests/test_console_readability_0391.py::test_criticality_never_uses_severity_classes`.
- **Labels.** `sevPill()` prints the API value and CSS capitalises it; `statePill()` and `jobStatePill()` title-case the value (`accepted_risk` → "Accepted Risk").
- **Risk bands** for the continuous 0–100 VEYRS risk score (`riskBand()`, `app.js:844`, mirroring `LEVEL_BANDS` in the backend): ≥ 90 critical, ≥ 70 high, ≥ 40 medium, ≥ 10 low, else informational.
- **Never invent a status colour.** A new state maps to a class above, or gets a class added here and in `console.css` in the same commit. `jobStatePill()` currently emits `st-queued` and `st-cancelled`, which have no rule (section 12).
- Contrast of every pill in both themes: [Accessibility](design/accessibility.md) section 2.2.

---

## 8. Charts

There is **no chart library**: every chart is hand-built HTML or inline SVG in `app.js`, styled by `console.css`. The current chart set (trend, detected vs remediated, donut, histogram, ring, sparklines) is listed in section 0.4; bars, ranked bars, split bars and the risk heat map are the remaining helpers (`bars()` 441, `splitBars()` 696, `rankedBars()` 785, `riskMatrixModal()`). Classes and lines are in [Console UI reference](design/console-ui.md) section 7.4. The former per-helper colour table of this section described the 0.36 charts (`--primary` bars, `--veyrs-high` for detected) and was removed (Obsolete).

- **Colour is never the only encoding:** every mark carries a label and a value, and a hover tip; every chart keeps a "Show data" table.
- **One series, one meaning:** `--chart-risk` is the risk score, `--chart-in` risk arriving, `--chart-out` risk leaving; severity colours appear only where the categories *are* severities.
- `sevColour()` maps a severity to its token and falls back to `--veyrs-neutral`, never to the brand blue (`app.js:854-857`).
- Bar widths and fills are set in `style` attributes (`width:…%;background:var(…)`), permitted by `style-src 'unsafe-inline'`.
- SVG colours are set through presentation attributes holding `var()` in places (`stop-color="var(--chart-risk)"`); a `style` declaration is the safer form for new drawings.
- Empty data is a sentence explaining why, not an empty chart.

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
| Severity | API value, capitalised by `.pill[class*="sev-"]` (`console.css:980`) | `Critical` | `sevPill()` |
| State | Title case (`titleCase()`); `.pill` does not change case (only `.pill-kev` is uppercase) | `Accepted Risk` | `statePill()` |
| Asset criticality (0.39.1) | Title case in a neutral pill with a four-step level mark | `High` | `critPill()` |
| CVE / CWE id | Monospace link to `#/intel/cve/<id>` or `#/intel/cwe/<id>` | `CVE-2024-3400` | Most lists and detail pages |
| Date and time | Locale date and time, no time-zone label; spaces are no-break spaces since 0.39.1, so the value never wraps in a narrow column | `Nov 01, 2026, 02:05 PM` | `fmtDate()` |
| Date only | Locale date, no-break spaces (0.39.1) | `Nov 01, 2026` | `fmtDay()` |
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
8. **Risk level case differs by place:** the raw API label (lowercase `critical`) under the score in finding and vulnerability lists, `Critical` in pills (CSS `capitalize`).
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

- **Every `.svg`** (`veyrs-favicon.svg` and `veyrs-wordmark.svg`; the `veyrs-logo*.svg` and `veyrs-mark*.svg` names that older revisions listed are not in `frontend/brand/logo/`). They are early placeholders: a geometric shield path with a straight-cut white V, flat fills (`#0064D8`, `#002060`, `#7080A0`, the official gradient) and live-text wordmarks. They do not draw the real mark.
- **`veyrs-mark-white.png`, `veyrs-mark-black.png`, `veyrs-mark-on-dark.png`** (852 × 852, about 29 KB each). Inspected: each holds exactly one colour (white, `#0A0E16` and white respectively) over the same 125,691 opaque pixels as `veyrs-mark.png`, i.e. a flat silhouette of the real V, without the fold and the two-tone shading that make the mark. `mark-white` and `mark-on-dark` are byte-identical. `frontend/brand/logo/README.md` calls them rasterisations of the placeholder SVGs; the pixels show silhouettes of the real outline instead. The rule is unchanged: they are not approved variants. The console sidebar shipped `veyrs-mark-white.png` once, for a day. (The pixel counts and colours in this paragraph are from the 0.38 inspection and were not recomputed on 2026-11-17; the byte-identity of `mark-white` and `mark-on-dark` was re-checked by hash.)

### Where each file is used

| Place | File | Size |
|---|---|---|
| Console sidebar (`.brand-mark`) | `/static/veyrs-mark-gradient.png`, `alt=""` beside the "VEYRS" text (`index.html:63`) | `width: 30px; height: auto` (`console.css:650`), also in rail mode |
| Console login hero (`.login-logo`) | `/static/veyrs-logo-on-dark-gradient.png` (`index.html:20`) | 248 px wide, max 70 % of the hero (`console.css:1219`), on the always-dark hero gradient (`--hero-deep` `#05070B` to `--hero-mid` `#0B1426` with a blue glow and a faint grid) and a gold hairline |
| Console favicon | `/static/veyrs-favicon.png` | 256 × 256 PNG |
| Product site nav, hero, footer, favicon | `assets/veyrs-mark-gradient.png`, `assets/veyrs-logo-on-dark-gradient.png` (hero, and 180 px in the footer), `assets/veyrs-favicon.png` / `.ico` | `site/web/build_web.py:115-174` |
| Documentation portal | `veyrs-mark-gradient.png`, `veyrs-logo-on-dark-gradient.png` (footer, 180 px), `veyrs-favicon.png` | `site/build.py:227-284`; the portal's own rules are in `site/design-system/` |
| PDF reports | No logo | Navy title and table header, VEYRS-blue tagline (section 12) |

Rules:

- The resolution ceiling is about 560 CSS px of width on a 2× display; larger looks soft.
- A surface that carries the logo stays navy-dominant. The official gradient's bright end `#0080FF` gives white 3.80:1 (computed 2026-11-17), so it is a hairline or accent there, never the backdrop. The console login hero is graphite-navy, not the brand gradient.
- A new asset goes into `frontend/brand/logo/` **and** `site/static/`.

---

## 11. Markup rules: CSP, actions, views, cache-busting

### What the Content-Security-Policy does to markup

The console is served with `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'` (`docker/console.conf:36`, `infrastructure/nginx-veyrs-console.conf:30` and `install.sh:1288` carry the same string); the API sends a similar policy on its own responses.

- **No inline script and no `on*=` attributes**, including in HTML strings built by `app.js`. They would not fail loudly; the browser would simply not run them.
- `style="…"` attributes are allowed and used (63 on 61 lines of `app.js` at 0.39.1, unchanged from 0.39.0, mostly chart geometry and a few banner overrides), but a class is preferred.
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

- `index.html` loads `/app.js?v=47`, `/console.css?v=21` and `/static/veyrs-tokens.css?v=2` (0.39.1). **Bump the number of every file you change**, in the same commit. `tests/test_phase30_scanner_page.py` checks only that the parameters exist, not that they moved.
- The token file's `?v=` was added after a token change sat behind a one-hour `/static/` cache; it is bumped by hand like the others.
- The product site appends a content hash to `web.css` automatically; the documentation portal handles its own asset versioning.

---

## 12. Known deviations and debt

Status column: *Closed* items are fixed in the code as of 2026-11-17; *Obsolete* items describe a mechanism that no longer exists; *Open* items are real gaps.

### Closed in 0.36.0 (console)

| Former item | What changed | Status |
|---|---|---|
| Light theme was not the brand's light UI | Superseded: since 0.38.0 each theme is a separate palette (section 0); the "navy sidebar in light" rule no longer applies | Obsolete |
| Over-rounded surfaces (12–14 px) | Radii on 4/6/8 px in both themes (`test_radii_stay_on_the_brand_scale`) | Closed |
| Brand blue as a severity fallback | `sevColour()` falls back to `--veyrs-neutral` | Closed |
| Severity colours for non-severity meaning | Running jobs use `--veyrs-info`; `st-warn` uses `--veyrs-warning`; internet exposure is an ink outline; partner exposure, stale feeds, escalation levels and similar use `st-warn`; isolated assets, compensating controls and enabled feeds use `st-ok`. Only real severities and the risk-register bands use `sev-*` | Closed |
| Hard-coded colours in `console.css` | Every literal now lives in the two theme blocks, `:root` and the login hero. The `--chrome-*` tokens named in the 0.36 ledger no longer exist; `--scrim` and `--hero-*` do | Closed (tokens renamed) |
| `var(--line)` separator did not render | `<hr class="rule">` | Closed |
| Input focus shadow invalid | `--ring` (a real box-shadow) | Closed |
| Contrast failures | The 0.36 fixes were replaced by the 0.38.0 palettes; the present measurements, which still show failures, are in [Accessibility](design/accessibility.md) | Obsolete (see Open item 5) |
| `.badge` / `.chip` collisions with the tokens file | The console rules reset the leaking properties | Closed |
| `veyrs-tokens.css` not cache-busted | `?v=` on its link | Closed |
| Modals without Escape or focus trap; toasts without `aria-live` | Escape closes the topmost dialog, Tab cycles inside it, focus returns to the opener; toast stack is `role="status" aria-live="polite"` | Closed |
| Theme toggle wrote storage unguarded | Applies first, stores in a `try` | Closed |
| Unicode glyph icons | Drawn SVG set (section 6) | Closed |
| 310 inline `style="margin…"` attributes on eleven different spacings | Utility classes on the 4 px scale (`.mt-*`, `.mb-*`, `.gap-*`, `.measure`, `.row-split`, `.t-lg/xl`, `.grow`); 61 `style="` attributes remain in `app.js` | Closed |
| Breakpoints at 620/640/700/760/900/1000 | 640 / 900 / 1000 plus 1200 and the 901 rail query | Closed |

### 0.37.0 additions

| Pattern | Where | Rule |
|---|---|---|
| Breadcrumbs | topbar `#crumbs`, `renderCrumbs()` | Group / page / sub-view, read from `NAV` (the sidebar's own source); a detail view appends the record's title. The topbar holds where you are on the left and search on the right. |
| Page description fold | `enhancePage()` | A page-head description over ~180 characters folds to two lines behind **More**, only if the clamp actually clips; focusing a link inside it unfolds it. |
| KPI tile | `kpi()`, `delta()`, `kpiSpark()` | Label (12 px, sentence case), value (26 px, tabular), hint, then a footer with the signed change over the selected window and its shape. Deltas and sparklines come only from series the API returns (`finding_trend`, `risk_trend`); `delta()` states improved/worse in text for assistive tech. |
| Time range | Dashboards, `RANGES` | 30 d / 90 d / 6 mo / 1 yr, sent as `days` (API accepts 7-730). Hidden on Technical, which is a snapshot. Default 90 d. |
| Trend chart | `trendChart()` | y axis snapped to tens around the data (never stretched), gridlines, three date labels, a hover target per bucket. **A null bucket is a gap, never a zero or an interpolation.** "Show data" under the chart lists every bucket as a table. Same disclosure under Detected vs remediated. |
| Ring gauge | `ring()` | SLA compliance only: one ratio against one target (90 %, tick mark). Green at or above target, amber within 20 points, red below. |
| Tooltip | one `.tip` element | Chart marks keep their `title` until first hover, then it moves to `data-tip`. Esc dismisses it. |
| Skeleton loading | `.loading` | The "Loading…" text stays in the DOM (transparent) with `aria-busy` on the view; forced-colours mode shows the text instead of the blocks. |
| Empty state | `.empty::before` | A masked tray icon in `--text-muted`. |
| Pills | `.pill` | 11 px / 600; severity pills lead with a 6 px dot in the series colour (the word is the encoding). |
| `.stack` vs `.compo` | `console.css` | `.stack` is the vertical layout class. The composition strip is `.compo`. 0.36.0 reused `.stack` for the strip and collapsed six layouts; a guard now forbids a second `.stack` definition. |

### 0.38.0 ("Midnight Ops"), 0.39.0 and 0.39.1

The presentation layer was replaced (section 0). Closed by it: the light theme's navy-chrome rule (light now has its own sidebar; the guard requires two complete palettes), floating stat cards (now strips), the bare sparkline (now an axis chart), the plain severity strip on the executive dashboard (now a donut with a legend table). 0.39.0 added the Configure frame (section 0.6). 0.39.1 closed the "criticality painted as severity" inconsistency (neutral `critPill`), rendered policy JSON as text (escalation ladders and key/value chips, `ladderSteps`/`matchChips`), stopped dates wrapping (no-break spaces in `fmtDate`/`fmtDay`) and let the Configure menu fold to a rail.

### Open

| # | Item | Evidence |
|---|---|---|
| 1 | The tokens' OS-dark block re-declares colours but not shadows. Irrelevant to the console (it always sets `data-theme`). | `veyrs-tokens.css:135-147` |
| 2 | SVG colours in presentation attributes (`stop-color="var(--chart-risk)"`) are not verified across browsers; the icon set uses `currentColor` and is unaffected. | `app.js:634-635` |
| 3 | PDF reports carry no severity palette (severities are printed as text); not re-verified in 0.39.0. | `backend/veyrs/services/reporting.py` |
| 4 | `jobStatePill()` emits `st-queued` and `st-cancelled`, which `console.css` does not define: those pills have no fill or border. | `app.js:2112-2116`; `console.css:988-993` |
| 5 | Contrast and accessibility gaps (muted text, light-theme pills, mouse-only table rows, tabs without ARIA roles, no skip link). | [Accessibility](design/accessibility.md) section 3 |
| 6 | The risk-register overdue review date uses `class="err"`, which has no rule (only `.toast.err` exists), so overdue and on-time dates look the same. | `app.js:6209-6210` |

Closed since the 0.37 ledger: **no web font** (Inter and JetBrains Mono are self-hosted, guard `tests/test_console_redesign_0370.py`).

### Documentation and product sites

1. **Fixed 2026-11-11:** the docs-site placeholder header mark, favicon and generic palette were replaced by the real brand assets; `tests/test_docs_center.py` guards the mark and favicon.
2. **Product site duplicates the palette by hand** instead of linking `veyrs-tokens.css` (which it copies but never references), and uses gradient-filled primary buttons with a blue glow on hover, gradient text, and cards that lift on hover — the brand's "excessive gradients" and "glow" list. Not re-verified for 0.39.0.
3. The documentation portal's own deviations are tracked in its design system (section 15).

---

## 13. Checklist for a UI change

1. Colours are `var(--…)`: semantic aliases for structure, `--veyrs-<severity>` / `--veyrs-<status>` only for meaning, `--veyrs-ai` only for AI. No new hex literal in `console.css` or `app.js`.
2. Statuses are `.pill` + an existing class from section 7; a new state gets a class in `console.css` in the same commit.
3. Text contrast measured at 4.5:1 or better on the surface it sits on, **in both themes**; pills count as normal text.
4. Checked in light **and** dark: the palettes are designed separately, and a pair that passes in one can fail in the other (see the pill table in [Accessibility](design/accessibility.md)).
5. Components from section 6; every class used exists in `console.css`; wide tables sit in `.table-wrap`.
6. Values go through the section 9 formatters: `—` for absent, `fmtScore()` for CVSS and risk, `fmtDate()` / `fmtDay()` for times, `fmtNum()` for counts.
7. Charts label every mark; severity colours only for severities; empty data is a sentence, not an empty chart.
8. No `on*=` attribute, no inline script; actions through `data-act` or a delegated `data-*` hook; every interpolated value through `esc()`.
9. `?v=` bumped in `index.html` for each changed file (`app.js`, `console.css`).
10. Logos only from the PNG set in section 10; never an `.svg`, never a `mark-white/-black/-on-dark` PNG; new assets in both brand directories.
11. A token change made in both copies of `veyrs-tokens.css` (and, for a console colour, in both theme blocks of `console.css`), and this page, [Console UI reference](design/console-ui.md) and [Brand](BRAND.md) updated in the same commit.

---

## 14. Where it is enforced

| Test | Holds |
|---|---|
| `tests/test_console_layout_classes.py` | Every literal class `app.js` uses has a rule in `console.css`; modifier classes appear with their base; `st-ok`, `st-warn`, `st-neutral` and the form layout primitives exist |
| `tests/test_phase31_console_wiring.py` | Every top-level selector exists in `index.html`; handlers go through `on()`; `boot()` runs last |
| `tests/test_phase30_scanner_page.py` | `app.js` and `console.css` carry a `?v=` cache-buster |
| `tests/test_console_design_system.py` | No colour literal outside the token blocks; no radius above 8 px; both themes define the same pinned keys and differ in `--nav-bg`, with the retired warm greys banned; `sevColour()` never falls back to `--primary`; every menu icon is drawn; no glyph/emoji icon in the shell; Administration tabs, sections and sidebar agree; no one-entry menu group without a sub-menu |
| `tests/test_console_redesign_0380.py` | Dark is the default theme; dashboards open with one KPI strip and the 12-column grid; metric grids render as strips; chart series keep one meaning; every nav group has a drawn icon; the smoothed curve never overshoots |
| `tests/test_console_configure_frame.py` | The Configure group holds five pages; every hidden tab has a menu entry; the sidebar shows one link; `render()` draws into the frame; the hub lists the same pages; the frame uses tokens only |
| `tests/test_docs_center.py` | The documentation site files BRAND and DESIGN_SYSTEM under "Design & brand", the pages wear the real brand mark, `#0064D8` renders with a swatch |

Nothing tests the measured contrast of the shipped palette, keyboard behaviour or the logo files in use.

## 15. Documentation portal

The documentation portal (`site/build.py`) is being redesigned and **its design system lives in `site/design-system/`**, written by the portal's owner. This file no longer describes the portal's palette, layout or components; where an older section above still mentions the documentation site, it was not re-verified.

Related: [Brand](BRAND.md) · [Console UI reference](design/console-ui.md) · [Accessibility](design/accessibility.md) · [Architecture](ARCHITECTURE.md) · [Security](SECURITY.md) · [Development](DEVELOPMENT.md).
