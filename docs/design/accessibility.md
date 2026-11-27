---
title: Console accessibility status
purpose: State what accessibility support the console implements today, with evidence, the measured contrast of its two themes, and the known gaps against WCAG 2.2 AA.
scope: The console in frontend/console/ at 0.41.0 (gap status updated for that release); it is a code and calculation review, not an audit with assistive technology, and it does not cover the documentation portal or the product site.
version: 0.41.0
verified: 2026-11-17
status: Partial
sources: [frontend/console/console.css, frontend/console/app.js, frontend/console/index.html, site/static/veyrs-tokens.css]
related: [design/console-ui.md, DESIGN_SYSTEM.md, BRAND.md]
---

# Console accessibility status

The console implements a solid keyboard and semantics baseline (dialog focus handling, live regions, reduced motion, text alternatives for charts). 0.41.0 closed the highest-impact gaps: list rows are keyboard-operable, secondary text and every pill reach 4.5:1 in both themes (and a test computes it), tabs carry the tab pattern, there is a skip link, and the Configure rail button names its current action. The remaining gaps are listed in section 3. Nothing here was tested with a screen reader or in a browser; every statement is read from the code or computed. The target is WCAG 2.2 level AA.

## 1. What is implemented

| Area | Implementation | Evidence | Status |
|---|---|---|---|
| Document language and title | `<html lang="en">`; `document.title` becomes "Page title · VEYRS Console" after each render | `index.html:2`; `app.js:1311-1317` | Implemented |
| Landmarks | `aside` sidebar, `nav` "Main" and "Configure", `header` top bar, `nav` "Breadcrumb", `main#view`, search form with `role="search"` | `index.html:61-97` | Implemented |
| Focus indicator, controls | Token file: `:where(a, button, input, select, textarea, [tabindex]):focus-visible` draws a 2 px outline with 2 px offset in `--focus-ring` (8.19:1 dark, 5.79:1 light on `--surface`) | `veyrs-tokens.css:189-194` | Implemented |
| Focus indicator, fields | `outline: none` is set on fields (it beats the zero-specificity `:where` rule) and replaced by a `--primary` border plus a 3 px `--ring` halo on `:focus` | `console.css:596-600` | Implemented |
| Modal dialogs | `role="dialog"`, `aria-modal="true"`, `aria-labelledby`; the first field or action receives focus; Escape closes the topmost dialog only; Tab and Shift+Tab cycle inside it; focus returns to the opener on close | `app.js:300-353` | Implemented |
| Command palette | `role="dialog"` `aria-modal`, input `role="combobox"` with `aria-expanded` and `aria-controls`, results `role="listbox"` / `role="option"` / `aria-selected`; arrows, Enter, Escape | `app.js:9269-9314`, `9229` | Partial (see gaps) |
| Live regions | Toast stack is `role="status" aria-live="polite"`; scope banners and the triage card use `role="status"` / `aria-live="polite"` | `index.html:101`; `app.js:119`, `8864` | Implemented |
| Reduced motion | `prefers-reduced-motion: reduce` removes every transition and animation and shows chart lines fully drawn | `console.css:1295-1298` | Implemented |
| Forced colours | The skeleton shows its text instead of coloured blocks | `console.css:1160` | Partial (only this rule) |
| Colour is not the only signal | Severity and state pills carry the word; severity pills add a dot; donut, split and ranked charts print a label and number per mark; a `delta` adds screen-reader text "(improved)" or "(worse)"; the meter has `role="img"` and an `aria-label` with the percentage | `console.css:980-981`; `app.js:554-561`, `685`, `721` | Implemented |
| Chart alternatives | `chartData()` adds a "Show data" disclosure with every bucket as a table; the donut, sparkline, ring, trend and flow SVGs have `role="img"` and an `aria-label` (8 `role="img"` sites at `app.js:519`, `550`, `583`, `632`, `685`, `721`, `812`, `885`); the risk-trend chart also has a chart note | `app.js:707-713`, `638` | Implemented |
| Disclosures | Explainers, "More" for long descriptions, Configure menu button, nav groups use `aria-expanded` (and `aria-controls` where there is a target); focusing a link inside a folded description unfolds it | `app.js:381`, `1320-1338`, `1416`, `1257` | Implemented |
| Current page | Active nav items and breadcrumb leaf use `aria-current="page"` | `app.js:1231`, `1303`, `1399` | Implemented |
| Pressed state | Time-range segmented control and (0.39.1) the Configure rail button use `aria-pressed` | `app.js:1610-1611`, `1420` | Implemented |
| Names for icon-only controls | Sidebar rail, theme, docs, sign-out, menu, notifications, modal close: `aria-label`; decorative SVGs are `aria-hidden` | `index.html:68-94` | Implemented |
| Table selection | Checkboxes carry `aria-label` ("Select", "Select all on this page") | `app.js:443-445` | Implemented |
| Loading | The text "Loading..." stays in the DOM; `#view` gets `aria-busy` while a route renders | `console.css:1148-1149`; `app.js:1487-1503` | Implemented |
| List rows | `tr.clickable` has `tabindex="0"`; Enter or Space on the focused row opens the record exactly as a click; focus shows a 2 px inset ring (`--focus-ring`) (0.41.0, TD-13) | `app.js` `table()` and the row key handler; `console.css` `tr.clickable:focus-visible` | Implemented |
| Tabs | `.tabs` bars get `role="tablist"`, `role="tab"`, `aria-selected` and a roving `tabindex` with Left/Right/Home/End after every render (0.41.0) | `app.js` `enhanceTabs` | Implemented |
| Skip link | "Skip to main content" is the first tab stop of the shell, visible on focus; it moves focus to `main#view` (`tabindex="-1"`) by script because the fragment is the router (0.41.0) | `index.html`; `console.css` `.skip-link` | Implemented |
| Zoom and reflow | Layout is fluid with `minmax` grids and a single-column layout under 900 px; viewport meta does not disable zoom | `console.css:1260-1286`; `index.html:5` | Implemented |

## 2. Measured contrast

Method: WCAG 2.x relative luminance computed with a short Python function over the hex values in `console.css` (3.1 and 3.2 token tables of [Console UI reference](console-ui.md)). Tinted pills are composited as `p x colour + (1 - p) x surface` with the tint percentages from `console.css:983-993` (13 % or 14 %) over `--surface`. Normal text needs 4.5:1, large text (24 px, or 18.66 px bold) 3:1, non-text user-interface parts 3:1. Computed on 2026-11-17 for 0.39.1 and recomputed for 0.41.0 after the token changes below; values rounded to two decimals. Since 0.41.0 `tests/test_console_contrast.py` recomputes every text token and every tinted pill from the stylesheet and fails below 4.5:1, so this section can be regenerated from that test instead of by hand.

### 2.1 Text and interaction

| Pair | Midnight (dark) | Porcelain (light) | AA normal text |
|---|---|---|---|
| `--text` on `--background` | 16.25 | 16.61 | Pass / Pass |
| `--text` on `--surface` | 15.54 | 18.26 | Pass / Pass |
| `--text` on `--surface-2` | 14.44 | 17.04 | Pass / Pass |
| `--text-secondary` on `--background` | 7.63 | 5.75 | Pass / Pass |
| `--text-secondary` on `--surface` | 7.30 | 6.32 | Pass / Pass |
| `--text-secondary` on `--surface-2` | 6.78 | 5.90 | Pass / Pass |
| `--text-muted` on `--background` | 5.51 | 4.61 | Pass / Pass |
| `--text-muted` on `--surface` | 5.27 | 5.07 | Pass / Pass |
| `--text-muted` on `--surface-2` | 4.89 | 4.73 | Pass / Pass |
| `--link` on `--background` | 8.56 | 6.31 | Pass / Pass |
| `--link` on `--surface` | 8.19 | 6.94 | Pass / Pass |
| `--primary-contrast` (white) on `--primary` (primary button, selected option, chip, palette row) | 4.73 | 5.79 | Pass / Pass |
| White on `--primary-hover` (primary button hover) | 4.62 | 7.13 | Pass / Pass |
| `--nav-text` on `--nav-bg` | 8.80 | 9.27 | Pass / Pass |
| `--nav-text-active` on `--nav-bg` | 17.90 | 17.51 | Pass / Pass |
| `--veyrs-danger` on `--surface` (error text, destructive button) | 5.70 | 6.24 | Pass / Pass |

### 2.2 Pills (11 px, normal text) on `--surface`

Each pill is the severity or state colour as text on its own tint. One theme-specific override remains: in dark the critical, failed and expired text is mixed 78 % with white (`console.css`, after the pill rules). The light-theme `filter: saturate(1.05) brightness(.92)` was removed in 0.41.0: the light semantic tokens are darker instead, so the numbers below are what is drawn. Pills on `--surface-2` are at least 4.58:1 (light) and 4.64:1 (dark).

| Pill | Midnight (dark) | Porcelain (light) | AA |
|---|---|---|---|
| Critical (`.sev-critical`) | 6.25 | 4.98 | Pass / Pass |
| High (`.sev-high`) | 6.08 | 4.92 | Pass / Pass |
| Medium (`.sev-medium`) | 7.42 | 4.96 | Pass / Pass |
| Low (`.sev-low`) | 5.41 | 4.91 | Pass / Pass |
| Informational (`.sev-informational`) | 5.07 | 4.95 | Pass / Pass |
| Remediated and good states (`.st-remediated`...) | 6.03 | 4.89 | Pass / Pass |
| Warning (`.st-warn`) | 7.59 | 5.04 | Pass / Pass |
| Accepted risk (`.st-accepted_risk`) | 5.66 | 4.97 | Pass / Pass |
| Failed, expired (`.st-failed`) | 6.34 | 5.07 | Pass / Pass |
| Running, leased (`.st-running`) | 5.51 | 4.95 | Pass / Pass |
| AI (`.pill-ai`) | 5.56 | 4.98 | Pass / Pass |
| Neutral, queued, cancelled (`--text-secondary` on `--surface-2`) | 6.78 | 5.90 | Pass / Pass |
| Asset criticality (`.pill.crit`, 0.39.1): transparent fill, `--text-secondary` on `--surface` (low, medium) / `--text` on `--surface` (high, critical) | 7.30 / 15.54 | 6.32 / 18.26 | Pass / Pass |
| Known exploited (`.pill-kev`, white on solid critical; dark mixes 72 % critical with navy) | 5.51 | 6.24 | Pass / Pass |

The light theme also overrides `--veyrs-accepted-risk` and `--veyrs-ai` (deeper violet, `#7738E4` / `#7637E1`) in `console.css`; the shared token file keeps its values.

### 2.3 Large text and non-text parts

| Element | Midnight | Porcelain | Requirement | Result |
|---|---|---|---|---|
| Stat value (26 px, 600) in `--veyrs-critical` / `warning` / `remediated` on `--surface` | 5.70 / 9.56 / 7.33 | 6.24 / 6.05 / 5.88 | 3:1 large text | Pass |
| Focus outline `--focus-ring` on `--surface` | 8.19 | 5.79 | 3:1 | Pass |
| `--primary` on `--surface` (selected border, active bar) | 3.93 | 5.79 | 3:1 | Pass |
| `--gold` marker on `--background` | 8.29 | 3.89 | 3:1 | Pass |
| `--border` on `--surface` (hairlines, panel edges) | 1.22 | 1.26 | decorative | n/a |
| `--border` on `--surface-2` (text field boundary at rest) | 1.14 | 1.18 | 3:1 for a control boundary | **Fail** |
| `--border-strong` on `--surface-2` (field hover boundary) | 1.40 | 1.43 | 3:1 | **Fail** |

## 3. Known gaps

Ordered by impact on a user. Gaps 1, 2, 3, 5, 6, 7 and 19 were fixed in 0.41.0 (struck through); the rest are open.

| # | Gap | Evidence | Severity | Success criterion |
|---|---|---|---|---|
| 1 | ~~`--text-muted` is below 4.5:1 in both themes (dark 4.11 on surface, light 3.62) and is used for text that matters: table column headers (11 px), field placeholders, chart axis labels, stat hints, `.page-foot`~~ **Fixed in 0.41.0.** `--text-muted` is now 4.89 to 5.51 (dark) and 4.61 to 5.07 (light) on the page surfaces. | `console.css:601`, `924`, `955`, `773`, `1027` | Fixed | 1.4.3 |
| 2 | ~~Light-theme pills fall short of 4.5:1: critical 4.27, high 3.46, medium 3.23, informational 4.14, remediated 3.93, warning 3.26, failed 4.34, running 4.46. The inline comment claims 4.5:1~~ **Fixed in 0.41.0.** Light semantic tokens darkened; every pill is at least 4.58:1 on `--surface` and `--surface-2`. | `console.css:983-993`, `1288-1290` | Fixed | 1.4.3 |
| 3 | ~~Dark informational pill 4.38 and dark primary-button hover (white on `#4F7FE3`) 3.83~~ **Fixed in 0.41.0.** Dark informational pill 5.07; dark primary hover is `#4772CC` (4.62). | `console.css:987`, `618` | Fixed | 1.4.3 |
| 4 | Text field boundary is 1.14 to 1.43:1 against the field fill; the field is identifiable by position and label but its edge is faint | `console.css:593-599` | Low | 1.4.11 |
| 5 | ~~Clickable table rows work with the mouse only: `tr.clickable` has no `tabindex`, no role and no key handler, so a keyboard user cannot open a record from a list unless the row also holds a link~~ **Fixed in 0.41.0.** Rows are focusable and Enter or Space opens them. | `app.js:1901-1903`; `console.css:962-963` | Fixed | 2.1.1 |
| 6 | ~~Tabs are `button`s in a `div.tabs`; no `role="tablist"`/`tab`, no `aria-selected`; the active tab is shown only by colour and a 2 px underline~~ **Fixed in 0.41.0.** Tablist, tab and `aria-selected` with arrow-key navigation (the active tab is still also drawn with the underline). | `app.js:1621`, `3251`; `console.css:776-784` | Fixed | 4.1.2, 1.4.1 |
| 7 | ~~No skip link before the 6-group sidebar~~ **Fixed in 0.41.0.** Skip link added; it moves focus to the main region. | `index.html:60-98` | Fixed | 2.4.1 |
| 8 | Mobile drawer: the menu button has no `aria-expanded`, Escape does not close the drawer and focus is not moved into or out of it; the page behind a modal is not made `inert` (the focus trap and `aria-modal` stand in for it) | `app.js:8607`; `index.html:86` | Medium | 2.1.2, 4.1.2 |
| 9 | Command palette: the highlighted option is tracked in `aria-selected` only; there is no `aria-activedescendant` on the combobox, so assistive technology is not told which result is active. The palette input removes its focus outline with no replacement | `app.js:9229`, `9276`; `console.css:361` | Medium | 4.1.2, 2.4.7 |
| 10 | Toasts disappear after 4 s (7 s for errors), cannot be paused or dismissed, and error toasts are announced politely (inside `role="status"`), not as alerts | `app.js:284-292`; `index.html:101` | Medium | 2.2.1, 4.1.3 |
| 11 | Chart hover tips are mouse-driven; chart marks are not focusable. The "Show data" table is the keyboard alternative and is present for the trend, flow and distribution charts, but the donut and some small bar charts rely on the legend text only | `app.js:1342-1369`, `707` | Low | 1.4.13, 2.1.1 |
| 12 | Sticky top bar (48 px) and sticky bulk bar can cover a focused element; there is no `scroll-padding` | `console.css:726`, `171` | Low | 2.4.11 |
| 13 | Nav sub-item carets are `role="button"` with `tabindex="-1"`: they cannot be reached by keyboard (the parent link and the accordion button can) | `app.js:1243-1245` | Low | 2.1.1 |
| 14 | Targets are 28 to 32 px high (buttons, icon buttons, nav rows 30 px, footer icons 28 px), below the 44 px guideline but above the 24 px minimum | `console.css:607-637`, `721` | Low | 2.5.8 (met) |
| 15 | Font sizes are px, not rem: browser zoom works, but a "text only" size preference does not scale the interface | `console.css:570` | Low | 1.4.4 |
| 16 | Forced-colours support is limited to the skeleton; pill borders, gold markers and focus halos have no forced-colour rules | `console.css:1160` | Low | 1.4.11 |
| 17 | The OS colour-scheme preference is ignored; the console always starts dark and uses a stored choice | `index.html:2`; `app.js:1519` | Low | (guidance) |
| 18 | The sidebar item for the active page is only distinguished by fill, bold and a gold marker; the gold marker is 2 px wide (3.89:1 in light) | `console.css:689-693` | Low | 1.4.1 |
| 19 | ~~The Configure rail button (0.39.1) keeps `aria-label="Collapse the Configure menu"` when the menu is already folded; only `title` and `aria-pressed` change, so a screen reader announces the wrong action. The criticality level mark's unlit bars are 25 % opacity, but the level is also written as a word, so colour is not the only signal~~ **Fixed in 0.41.0.** The button label now follows the state and is no longer an `aria-pressed` toggle. | `app.js:1420`, `1434-1439`; `console.css:1000`, `1003` | Fixed | 4.1.2 |

## 4. How to keep it from regressing

- `tests/test_console_contrast.py` computes WCAG ratios from the token values (text tokens on every surface, primary button, every tinted pill on `--surface` and `--surface-2`, the known-exploited pill) and fails below 4.5:1. `tests/test_console_keyboard_a11y.py` pins the row, tab, skip-link and rail-button behaviour in the source. Neither runs a browser.
- A colour change is checked by the first test; pills count as normal text. Section 2 can be regenerated from that test.
- New interactive elements need a native control (`button`, `a`) or a role, a key handler and an accessible name. Rows that navigate should contain a real link.
