# Design System Master File — VEYRS product site

> **LOGIC:** When building a page of the product site (`site/web/build_web.py`),
> follow this file. `docs/BRAND.md` wins on colour, type and logo use; this file
> records how the product site applies it. The Docs Center has its own master in
> `site/design-system/veyrs-docs/`.

---

**Project:** VEYRS Web (veyrs-web-a on the LAN, veyrs.example.com in public)
**Decided:** 2026-11-24 (radical redesign; supersedes the 2026-09 single-page style)
**Inputs:** ui-ux-pro-max output for "enterprise cybersecurity risk management SaaS"
(pattern *Trust & Authority + Conversion*, its pre-delivery checklist), overridden by
`docs/BRAND.md` wherever they disagree.
**Dials:** Variance 5/10 (balanced, modern) · Motion 2/10 (hover only) · Density 3/10 (spacious)

---

## 1. Positioning and tone

Enterprise cybersecurity, not cyberpunk. Executive first: the home page must state the
value in one line ("Not a list of vulnerabilities. A list of decisions.") and reach a call
to action without scrolling. Reference feel: Wiz, Tenable, Snyk, Linear-level polish, in
the VEYRS palette. No neon, no glow, no hacker imagery, no glassmorphism except the
subtle blur behind the sticky navigation.

**Proof is verifiable or absent.** The site never shows customers, logos, testimonials,
certifications or numbers that are not in the repository. Counts that can drift are
computed at build time (report formats from the parser registries, pinned packages from
`requirements.txt`, installer gates checked against `veyrs-setup.sh` by a test). The
hero's product panel is illustrative and says so on its face.

## 2. Page pattern (Trust & Authority + Conversion)

Home, top to bottom:

1. Hero (deep navy): eyebrow tagline → H1 → one-paragraph value statement → primary CTA
   "Open the console" + secondary "Explore the platform" → three facts → illustrative
   decision-queue panel → the chain Visibility → Exposure → Risk → Action → Security.
2. Standards strip: CVE, CVSS v2/v3.0/v3.1/v4.0, EPSS, CISA KEV, CWE, CPE; compliance
   mapping NIST CSF 2.0, CIS Controls, ISO/IEC 27001/27002.
3. The problem + severity-vs-risk comparison (9.8 on an isolated host vs 6.5 on the
   internet-facing payment gateway listed in KEV).
4. How it works: five steps, one per link of the chain.
5. Capabilities: six cards linking to the Capabilities page anchors.
6. Principles band (navy): "Every number comes with the number that tells you whether to
   believe it", three pillars.
7. Security and trust grid (six facts, link to Security).
8. Deployment: native, Docker Compose, high availability.
9. Closing CTA panel (navy): console + documentation.

Inner pages: navy page head (breadcrumb eyebrow, H1, lead, optional in-page chips) →
alternating white / `#F5F7FA` sections, each with an icon tile column and a prose column
(max 880 px) → closing CTA panel. Manuals: page head → sticky "On this page" rail
(≥1100 px) or a collapsible list (below) → article.

CTA placement: navigation (every page), hero, closing panel, footer.

## 3. Information architecture

Navigation: **Capabilities · Architecture · Security · Download · Documentation**, language
switcher, "Open the console" button; the logo links home. "Manual", "Install" and "Docs"
are no longer separate entries: the **Documentation** hub (`docs.html`) explains and links
the user manual, installation (Docker Compose manual, native guide, download), architecture
and high availability, security, the API reference and the full documentation (Docs Center
on the LAN, the GitHub `docs/` tree in public), with a "Which document do I need?" table.
Every pre-redesign URL is still a page; none was renamed.

## 4. Colour (from BRAND.md)

| Role | Value | Use |
|---|---|---|
| VEYRS Blue | `#0064D8` | Primary buttons, links, icon tiles, active markers |
| Blue hover | `#0050AD` | Hover of primary buttons and links (white text stays ≥ 4.5:1) |
| Electric Blue | `#0080FF` | Focus ring on light surfaces, gradient hairlines — sparingly |
| Sky (dark-surface accent) | `#8FC2FF` | Eyebrows, the H1 accent line and focus ring on navy |
| Ink / Deep Navy / Security Navy | `#000B22` / `#001030` / `#002060` | Navigation, hero, page heads, principles band, footer |
| Neutrals | `#FFFFFF`, `#F5F7FA`, `#EEF2F7`, `#D9E0EA`, `#E6EBF2` | Content surfaces and borders |
| Text | `#0B1220` primary, `#526070` secondary (6.4:1 on white); on navy `#E8EEF7` / `#B4C2D6` | |
| Severity | `#B91C1C` `#EA580C` `#D97706` `#2563EB`, remediated `#15803D` | Only for severity; pills use a tint with a darker text step (≥ 4.5:1) |

Surfaces that carry the white logo stay navy-dominant (`#000B22 → #001030 → #001A45`); the
brand gradient appears only as a 2 px hairline under the hero and page heads. A faint 56 px
grid (3–3.5 % white) and one soft radial blue are the only textures.

## 5. Typography

Inter (400/500/600/700) for everything; JetBrains Mono (400/500) for eyebrows, chips,
identifiers and code. Both are the console's self-hosted files (`frontend/console/fonts/`),
copied to `assets/fonts/` at build time — never committed twice. Scale: hero H1
`clamp(2.35rem, 1.4rem + 3.5vw, 3.85rem)`, tracking −0.032em, line-height 1.06; section H2
`clamp(1.75rem, 1.2rem + 1.9vw, 2.5rem)`; body 17 px (16 px below 768 px), line-height 1.65;
eyebrows 0.78rem mono uppercase, tracking 0.12em.

## 6. Components

- **Buttons:** 44 px minimum height (50 px large), radius 8 px, weight 600. Primary = blue
  fill, white text; ghost (on navy) = 28 % white border. Hover 180 ms; a 1 px lift only when
  motion is allowed.
- **Cards:** white, 1 px `#D9E0EA` border, radius 14 px, 28 px padding, icon tile 44 px
  (`#EAF2FD` fill, blue stroke). Hover = border and shadow, no layout shift.
- **Icons:** inline SVG, 24 px grid, 1.75 stroke, round joins — the Docs Center set
  (`site/build.py` `ICON`) plus the product-site additions in `build_web.ICONS`. No emoji.
- **Tables:** wrapped in `.tablewrap` (scrolls inside itself on a phone), uppercase 0.8rem
  headers on `#F5F7FA`.
- **Notes:** left rule in blue (info) or orange (warning).
- **Language switcher:** `<details>` disclosure in the navigation (globe, code, chevron);
  entries are endonyms with `hreflang`/`lang`, the current one marked `aria-current`. The
  mobile menu and the footer repeat the list as plain links.

## 7. Internationalisation

English source at the site root; `/es/`, `/de/`, `/fr/`, `/it/` as static directories.
Strings in `site/web/i18n/<lang>.json` (HTML fragments; code spans and placeholders are
never translated; `_identical_ok` lists values legitimately equal to English). Every page:
`<html lang>`, `canonical`, `hreflang` × 5 + `x-default`, translated `<title>`, description
and `og:locale`. The two manuals stay English (`lang="en"` on the article) with a localized
notice. Formal register in every language (usted / Sie / vous / Lei). French avoids the
œ ligature (not in the font subset).

## 8. Constraints

- No JavaScript (the vhost sends `script-src 'none'`); menus are `<details>`.
- No inline `<style>`/`style=`/`on*=`: the CSP forbids them. Bars and meters are SVG
  presentation attributes.
- Zero third-party Python dependencies in the builder.
- `page_title()`: `<Page> — VEYRS`, home `VEYRS — <tagline>`, never "VEYRS — VEYRS".

## 9. Pre-delivery checklist

- [ ] No emoji as icons; one SVG icon style
- [ ] Visible focus on every interactive element (electric on light, sky on navy)
- [ ] Text contrast ≥ 4.5:1 (severity pills use darker text steps)
- [ ] `prefers-reduced-motion` removes transforms and transitions
- [ ] 375 / 768 / 1024 / 1440 px without horizontal scroll (measure `scrollWidth`)
- [ ] Hover transitions 150–300 ms, no layout shift
- [ ] Sticky navigation never hides an anchor target (`scroll-padding-top`)
- [ ] Every locale builds, every relative link and anchor resolves, the public build names
      no LAN host (`tests/test_site_i18n.py`, `tests/test_site_render.py`)
