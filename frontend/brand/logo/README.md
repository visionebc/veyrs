# VEYRS brand assets

Canonical set. `site/static/` is a **mirror** of this directory (plus the docs
CSS/JS); `site/build.py` does a wholesale `copytree` of `site/static` into
`/var/www/veyrs`, so an asset dropped straight into the served directory is
lost on the next build. Add it **here and in `site/static/`**.

## Which files are the real mark

The `.svg` files are early placeholders — a plain geometric shield/V that is
**not** the brand. The real logo is the PNG set. This has already caused a
production bug (the console sidebar shipped `veyrs-mark-white.png`, a raster of
the placeholder SVG, for a day).

| File | Use |
|---|---|
| `veyrs-logo.png` | full-colour lockup — **light backgrounds only** |
| `veyrs-logo-on-dark.png` / `-white.png` | all-white lockup, dark backgrounds |
| `veyrs-logo-on-dark-tight.png` | the white lockup cropped to its ink bbox (originals carry ~4.5% baked padding that breaks left alignment) |
| `veyrs-logo-on-dark-gradient.png` | **the console login hero.** Gradient V + white wordmark, cropped to ink. Prefer this over the flat white lockup on dark surfaces |
| `veyrs.png` | square master (1254×1254), navy wordmark — file master / app icon / favicon source. **Not** for dark backgrounds |
| `veyrs-mark.png` | the mark alone, square with padding |
| `veyrs-mark-gradient.png` | the mark alone, cropped to ink (706×450) — **what the console sidebar uses** |
| `veyrs-favicon.png` / `.ico` | favicons |
| `veyrs-wordmark.png` | wordmark alone |

**Do not use in UI:** `veyrs-mark-white.png`, `veyrs-mark-black.png`,
`veyrs-mark-on-dark.png` (~29 KB each). They are rasterisations of the
placeholder SVGs, not the brand.

## Two constraints that are not negotiable

**Resolution ceiling.** Every brand PNG contains the same bitmap with real ink
of **1129×814 px**; `veyrs-logo.png` and `veyrs.png` differ only in canvas
padding, not detail. There is no SVG master and no larger raster. Above roughly
560 px of CSS width on a 2× display it looks soft — that is the ceiling of the
raster, not the wrong file. The real fix is vectorising the lockup to SVG,
which has not been done.

**Contrast.** The official gradient `--veyrs-gradient`
(`#001030 → #0064D8 → #0080FF`) is too light at its bright end to carry the
white lockup (≈3.8:1). Any surface holding the logo stays navy-dominant
(`#000B22 → #002056`, ≥10:1); the gradient is an accent or a hairline there,
never the backdrop.

All source PNGs already carry an alpha channel — do not key out a background.
