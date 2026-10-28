# Brand

The VEYRS visual identity. Enterprise cybersecurity, not cyberpunk.

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
component.**

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
assistant, insights, recommendations and actions.

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

A shield cut by a V — protection and the wordmark's initial in one mark. Six
variants ship in `/static/`:

| File | Use |
|---|---|
| `veyrs-logo.svg` | Full colour, light backgrounds |
| `veyrs-logo-on-dark.svg` | Full colour, dark backgrounds |
| `veyrs-mark.svg` | Symbol only, full colour |
| `veyrs-mark-white.svg` | Monochrome white |
| `veyrs-favicon.svg` | 16–64 px, simplified |

The symbol remains recognisable without the wordmark, and legible at 16 px. An
earlier draft had a notch in the shield's upper edge: it read as a smudge at
16 px and dirtied the monochrome variants, so it was removed.

## Tokens

Every value above is available as a CSS custom property:

```html
<link rel="stylesheet" href="/static/veyrs-tokens.css">
```

```css
color: var(--veyrs-primary);
background: var(--veyrs-surface);
border-color: var(--veyrs-severity-critical);
```

Both themes are defined; dark mode activates via `[data-theme="dark"]` or
`prefers-color-scheme`.

## Visual style

**Prefer:** clean grids, strong typography, clear hierarchy, subtle shadows,
thin borders, dense but readable data tables, consistent spacing, meaningful
colour.

**Avoid:** cyberpunk, hacker imagery, excessive neon or gradients, glowing
borders, gaming aesthetics, over-rounded cards, visual clutter.

## Consistency surface

The identity applies to the web application, mobile and desktop clients, login,
dashboards, reports, **PDF exports**, emails, notifications, documentation, the
marketing site, the favicon and the app icon. PDF exports already use Deep Navy
headers and this severity palette.
