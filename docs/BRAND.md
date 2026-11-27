---
title: Brand
purpose: Define the VEYRS visual identity: palette, severity colours, logo files and where each is used.
scope: Identity rules and brand assets (frontend/brand/logo, site/static); how the console applies them is in DESIGN_SYSTEM.md and design/console-ui.md, not here.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [site/static/veyrs-tokens.css, frontend/brand/logo/README.md, frontend/brand/logo, site/static, frontend/console/console.css, frontend/console/index.html, backend/veyrs/services/reporting.py, tests/test_docs_center.py]
related: [DESIGN_SYSTEM.md, design/console-ui.md, design/accessibility.md]
---

# Brand

The VEYRS visual identity. Enterprise cybersecurity, not cyberpunk.

See also: [Design System](DESIGN_SYSTEM.md) — how the console applies this identity, the value formats and the known deviations; [Console UI reference](design/console-ui.md) — the console's tokens per theme; [Accessibility](design/accessibility.md) — measured contrast.

## Positioning

The identity must communicate **security, intelligence, visibility, risk and
automation** — and must read as a premium B2B security platform, not as a
hacker-themed product. No neon, no glowing borders, no gaming aesthetics.

## Colour system

### Primary

| Token | Hex | Use |
|---|---|---|
| VEYRS Blue | `#0064D8` | Primary buttons, active nav, links, main icons, charts, brand |
| Electric Blue | `#0080FF` | Hover, highlights, focus, AI indicators, graph emphasis. Sparingly |

### Dark corporate

| Token | Hex | Use |
|---|---|---|
| Deep Navy | `#001030` | Logo, headers, sidebar, dark backgrounds |
| Security Navy | `#002060` | Dark-mode surfaces, cards, gradients |

### Metallic

| Token | Hex | Use |
|---|---|---|
| Steel | `#7080A0` | Secondary icons, borders, metadata |
| Light Steel | `#A0B0C8` | Secondary text, disabled states, subtle borders |

### Light UI

| Token | Hex |
|---|---|
| White | `#FFFFFF` |
| App background | `#F5F7FA` |
| Border | `#D9E0EA` |
| Primary text | `#0B1220` |
| Secondary text | `#526070` |

The console does not use these neutrals for its own surfaces: since 0.38.0 it
defines two separate palettes (graphite *Midnight* and cool-grey *Porcelain*,
with a light sidebar) in `console.css`; see [Design System](DESIGN_SYSTEM.md),
section 0, and [Console UI reference](design/console-ui.md), section 3. The
values on this page remain the brand's own and drive the product site, the
token file's defaults and the PDF exports.

### Dark mode

Dark mode is a first-class experience, not an inverted light theme.

| Token | Hex |
|---|---|
| Background | `#070D18` |
| Surface | `#0D1626` |
| Surface 2 | `#111F33` |
| Primary text | `#F1F5F9` |
| Secondary text | `#94A3B8` |
| Border | `#24344D` |

Premium, secure, professional, technical, calm. No excessive glow.

### Gradient

```css
background: linear-gradient(135deg, #001030 0%, #0064D8 55%, #0080FF 100%);
```

Hero sections, login, selected dashboard elements, marketing. **Not on every
component.** Its bright end is too light to carry white type or the white
lockup (about 3.8:1): a surface that holds the logo stays navy-dominant and
uses the gradient only as an accent or a hairline.

## Console UI palette (0.38.0)

The console's interface palette is *Midnight Ops* (see [Design System](DESIGN_SYSTEM.md), section 0): graphite and midnight surfaces, cool blue for interaction, and a metallic gold (`#C9A45C` dark, `#9A7430` light) used only to mark "you are here": the active navigation entry, the active tab, the avatar ring and the Configure card icons. Its severity and status hues are re-tuned per theme (see [Console UI reference](design/console-ui.md), section 3.1) and differ from the brand values below. It was chosen by the owner on 2026-11-16. The logo files, the severity semantics and the rules below for where each logo goes are unchanged.

## Severity colours

Severity is semantic and must never use the brand blue:

| State | Hex |
|---|---|
| Critical | `#B91C1C` |
| High | `#EA580C` |
| Medium | `#D97706` |
| Low | `#2563EB` |
| Informational | `#64748B` |
| Remediated | `#15803D` |
| Accepted risk | `#7C3AED` |

Status colours: success `#15803D`, warning `#D97706`, danger `#B91C1C`,
info `#2563EB`, neutral `#64748B`. AI accent: `#7C3AED`, used **only** for AI
assistant, insights, recommendations and actions. In dark mode the severity,
status and AI colours are lifted to brighter steps of the same hues. (The console defines its own per-theme steps; the table above is the token file's.)

## The rule

> Brand colours communicate identity.
> Semantic colours communicate meaning.
> Neutral colours communicate structure.

Blue = VEYRS and interaction. Red = critical. Orange = high. Amber = medium.
Green = remediated. Purple = AI and accepted risk. Grey = neutral.

## Usage ratio

60% neutral / background · 20% deep navy · 15% VEYRS blue · 5% accent and
semantic. **Do not build a UI where everything is blue.** Blue must mean
"important" or "interactive"; if it is everywhere, it means nothing.

## Logo

A folded-ribbon V: the left arm runs from VEYRS blue into deep navy at the
fold, the right arm is a steel gradient. The full lockup stacks the V over the
VEYRS wordmark, the "Unified Cybersecurity Risk Management" descender and a
rule carrying a small shield glyph.

The logo is a **PNG set**, all cut from one bitmap with real ink of about
1129 × 814 px. There is no vector master. The canonical files live in
`frontend/brand/logo/` and are mirrored to `site/static/` (verified byte-identical
on 2026-11-17 for every PNG, `veyrs-favicon.ico` and `veyrs-favicon.svg`;
`veyrs-wordmark.svg` and the folder README are not mirrored) and served as `/static/`:

| File | Use |
|---|---|
| `veyrs-logo.png` | Full-colour lockup, light backgrounds only |
| `veyrs-logo-on-dark-gradient.png` | Gradient V + white wordmark, cropped to ink. Preferred on dark: console login, product site |
| `veyrs-logo-on-dark.png` | All-white lockup, dark backgrounds (`veyrs-logo-white.png` is byte-identical) |
| `veyrs-logo-black.png` | All-black lockup (1240 × 925), for one-colour print on light backgrounds. Not used by any surface |
| `veyrs-logo-on-dark-tight.png` | The white lockup cropped to ink, for left-aligned layouts |
| `veyrs-mark-gradient.png` | The V alone, cropped to ink (706 × 450): console sidebar (30 px wide), product site nav and documentation header |
| `veyrs-mark.png` | The V alone, square with padding |
| `veyrs.png` | Square master: app icon, favicon source. Not for dark backgrounds |
| `veyrs-wordmark.png` | Wordmark alone |
| `veyrs-favicon.png` / `.ico` | Favicon: the PNG is 256 × 256; the `.ico` holds six sizes (16 to 256 px). The console and the documentation use the PNG |

**Not the logo — do not use in UI:**

- Both `.svg` files (`veyrs-favicon.svg` and `veyrs-wordmark.svg`). They are
  early placeholders: a geometric shield with a straight-cut white V and a
  live-text wordmark, not the real mark. (An older version of this page named
  `veyrs-logo*.svg` and `veyrs-mark*.svg` too; those files are not in the tree.)
- `veyrs-mark-white.png`, `veyrs-mark-black.png`, `veyrs-mark-on-dark.png`.
  Flat one-colour silhouettes of the V, without the fold and shading that
  make the mark (`mark-white` and `mark-on-dark` are byte-identical); the
  console sidebar shipped one by mistake for a day.

The raster looks soft above roughly 560 CSS px of width on a 2× display; that
is the ceiling of the bitmap, and the fix is a vector redraw, which has not
been done. A new asset goes into `frontend/brand/logo/` **and** `site/static/`.

## Tokens

Every value above is available as a CSS custom property:

```html
<link rel="stylesheet" href="/static/veyrs-tokens.css">
```

```css
color: var(--veyrs-blue);
background: var(--surface);
border-color: var(--veyrs-critical);
```

Both themes are defined; dark mode activates via `[data-theme="dark"]` or
`prefers-color-scheme`. The console always sets `data-theme` explicitly, so it
follows its own theme toggle rather than the operating system, and it loads
`console.css` after the token file, which redefines the colour aliases per
theme. The token file's full list is in [Design System](DESIGN_SYSTEM.md),
section 2; the console's per-theme values are in
[Console UI reference](design/console-ui.md), section 3.

## Visual style

**Prefer:** clean grids, strong typography, clear hierarchy, subtle shadows,
thin borders, dense but readable data tables, consistent spacing, meaningful
colour.

**Avoid:** cyberpunk, hacker imagery, excessive neon or gradients, glowing
borders, gaming aesthetics, over-rounded cards, visual clutter.

## Consistency surface

The identity applies to the web application, mobile and desktop clients, login,
dashboards, reports, **PDF exports**, emails, notifications, documentation, the
marketing site, the favicon and the app icon. PDF exports use Deep Navy for the
title, headings and table headers, VEYRS Blue for the tagline and the light-UI
neutrals for metadata, grid and row banding (`backend/veyrs/services/reporting.py:456-511`);
severities are printed as text, not yet in the severity palette (not re-verified
beyond the palette constants).
