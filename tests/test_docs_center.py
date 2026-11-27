"""The VEYRS Docs Center (`site/build.py`, served as the docs site).

What these guard, each one a way the docs site went wrong before:

* every document is filed in a domain - a new doc used to land in a catch-all
  "Other" group (BRAND.md sat there, so the colours looked undocumented);
  since the 2026-11 documentation reengineering this covers the domain
  folders (architecture/, operations/, api/reference/, ...) too;
* the home page, the sidebar and the search index carry every document;
* the site wears the VEYRS brand: the header mark is the real bitmap, not the
  placeholder shield drawn in a generic blue -> violet gradient;
* colour codes in BRAND/DESIGN_SYSTEM render with a swatch, while the shared
  Markdown renderer (also used by the product site) stays untouched;
* the portal has a light AND a dark theme, each with its own tokens
  (2026-11 owner request; this supersedes the 0.38.2 "product-site palette,
  light only" contract), and still never links veyrs-tokens.css (0.38.3:
  its OS-dark block blanked the text);
* no inline script and no inline event handlers in the chrome.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "site"))
sys.path.insert(0, str(ROOT / "site" / "web"))

import build  # noqa: E402

DOCS = ROOT / "docs"
STATIC = ROOT / "site" / "static"


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    out = tmp_path_factory.mktemp("docs-center")
    build.build(str(out))
    return out


def _keys():
    return build.discover()


def test_every_document_is_filed_in_a_domain():
    grouped = build.file_docs()
    assert "other" not in grouped, f"file these in site/build.py DOMAINS: {grouped.get('other')}"
    filed = [k for ks in grouped.values() for k in ks]
    assert len(filed) == len(set(filed)), "a document is filed in two domains"
    assert set(filed) == set(_keys())


def test_the_four_project_documents_and_the_design_docs_exist():
    for name in ("TECHNICAL_REQUIREMENTS", "APP_FLOW", "TESTING_GUIDE",
                 "IMPLEMENTATION_PLAN", "BRAND", "DESIGN_SYSTEM"):
        assert (DOCS / f"{name}.md").is_file(), name


def test_legacy_urls_keep_working(site):
    """Links from the product site, installers and old bookmarks use these."""
    for p in DOCS.glob("*.md"):
        assert (site / f"{p.stem}.html").is_file(), p.stem
    for p in (DOCS / "ADRs").glob("*.md"):
        assert (site / "adr" / f"{p.stem}.html").is_file(), p.stem


def test_home_shows_every_domain_and_the_sidebar_every_document(site):
    home = (site / "index.html").read_text(encoding="utf-8")
    assert "VEYRS Docs Center" in home
    grouped = build.file_docs()
    for slug, title, _blurb, _k, _d in build.DOMAINS:
        if grouped.get(slug):
            assert f">{title.replace('&', '&amp;')}</h2>" in home, title
    for key in _keys():
        assert f'href="{build.url_of(key)}"' in home, key
    assert ">Other</h2>" not in home


def test_search_index_covers_every_page(site):
    index = json.loads((site / "search-index.json").read_text(encoding="utf-8"))
    urls = {e["u"] for e in index}
    assert {build.url_of(k) for k in _keys()} <= urls
    adrs = {f"/adr/{p.stem}.html" for p in (DOCS / "ADRs").glob("*.md")}
    assert adrs <= urls
    for e in index:
        assert e["t"] and e["c"] and e["x"], e["u"]
        assert len(e["h"]) == len(e["a"]), "every heading carries its anchor"
    assert (site / "search.html").is_file()


def test_summaries_do_not_collide_between_readmes(site):
    """docs/README.md and docs/ADRs/README.md share a stem; the overview once
    showed the ADR index's summary."""
    index = {e["u"]: e for e in json.loads((site / "search-index.json").read_text(encoding="utf-8"))}
    assert index["/README.html"]["s"] != index["/adr/README.html"]["s"]


def test_pages_wear_the_brand_mark_not_the_placeholder_shield(site):
    page = (site / "BRAND.html").read_text(encoding="utf-8")
    assert 'src="/static/veyrs-mark-gradient.png"' in page
    assert "veyrs-favicon.png" in page
    for placeholder in ("#3b82f6", "#8b5cf6"):
        assert placeholder not in page.lower(), placeholder
    # BRAND.md names the placeholder files in its text; the chrome must not use them.
    for asset in ("veyrs-mark-white", "veyrs-mark-on-dark", "veyrs-favicon.svg"):
        assert f'src="/static/{asset}' not in page and f'href="/static/{asset}' not in page, asset


def _theme_block(css, selector):
    m = re.search(re.escape(selector) + r"\s*\{(.*?)\n\}", css, flags=re.S)
    assert m, selector
    return dict(re.findall(r"--([a-z0-9-]+):\s*([^;]+);", m.group(1)))


def test_both_themes_are_designed_with_their_own_tokens():
    css = (STATIC / "veyrs.css").read_text(encoding="utf-8")
    light = _theme_block(css, ':root, :root[data-theme="light"]')
    dark = _theme_block(css, ':root[data-theme="dark"]')
    for token in ("bg", "surface", "text", "text-2", "border", "primary", "code-bg"):
        assert token in light and token in dark, token
        assert light[token].lower() != dark[token].lower(), f"--{token} is the same in both themes"
    assert "color-scheme: light" in css and "color-scheme: dark" in css
    assert light["primary"].upper() == "#0064D8", "light primary is the VEYRS brand blue"
    low = css.lower()
    for generic in ("#3b82f6", "#8b5cf6", "fonts.googleapis", "@import"):
        assert generic not in low, generic


def test_theme_is_set_before_paint_by_an_external_script(site):
    page = (site / "USER_GUIDE.html").read_text(encoding="utf-8")
    head = page.split("</head>", 1)[0]
    assert '<script src="/static/theme.js' in head
    assert head.index("theme.js") < head.index("veyrs.css"), "theme first, or the page flashes"
    js = (STATIC / "theme.js").read_text(encoding="utf-8")
    assert "prefers-color-scheme: dark" in js and "localStorage" in js


def test_docs_pages_do_not_load_the_tokens_stylesheet(site):
    """0.38.3: its OS-dark block redefined --text/--border and blanked the text."""
    for page in ("index.html", "USER_GUIDE.html", "search.html"):
        assert "veyrs-tokens.css" not in (site / page).read_text(encoding="utf-8"), page
    assert (site / "static" / "veyrs-tokens.css").is_file(), "the console still reads it from /static/"


def test_fonts_are_self_hosted(site):
    css = (STATIC / "veyrs.css").read_text(encoding="utf-8")
    for f in re.findall(r'url\("fonts/([^"]+)"\)', css):
        assert (site / "static" / "fonts" / f).is_file(), f
    assert (site / "static" / "fonts" / "LICENSE-Inter.txt").is_file()


def test_chrome_keeps_the_product_site_links_and_the_console(site):
    import build_web
    page = (site / "USER_GUIDE.html").read_text(encoding="utf-8")
    assert '<header class="topbar">' in page and '<footer class="sitefoot">' in page
    for _href, label in build_web.NAV:
        assert f">{label}</a>" in page, label
    assert build.CONSOLE_URL in page and "Console" in page
    assert '<nav class="crumbs" aria-label="Breadcrumb">' in page
    assert '<aside class="toc" aria-label="On this page">' in page
    assert 'aria-current="page"' in page


def test_the_documents_title_moves_into_the_header(site):
    page = (site / "USER_GUIDE.html").read_text(encoding="utf-8")
    head = page.split('<header class="dochead">', 1)[1].split("</header>", 1)[0]
    assert re.search(r"<h1>[^<]+</h1>", head)
    body = page.split('<div class="prose">', 1)[1]
    assert "<h1" not in body.split("</article>", 1)[0], "the title is shown twice"
    schema = (site / "DATABASE_SCHEMA.html").read_text(encoding="utf-8")
    assert "<h1>" in schema.split('<div class="prose">', 1)[0], "every page gets a title"


def test_front_matter_becomes_the_metadata_header_not_text(site):
    page = (site / "DATABASE_SCHEMA.html").read_text(encoding="utf-8")
    assert "purpose:" not in page and "sources: [" not in page
    assert 'class="badge st-verified"' in page
    # the product site's renderer strips it too
    assert "title:" not in build.render("---\ntitle: X\n---\n# X\n")[0]


def test_colour_codes_render_with_a_swatch_on_the_docs_site_only(site):
    brand = (site / "BRAND.html").read_text(encoding="utf-8")
    assert '<span class="swatch" style="background:#0064D8"' in brand
    # The renderer shared with the product site does not add swatches.
    assert "swatch" not in build.render("`#0064D8`")[0]


def test_rich_rendering_is_portal_only():
    md = "> [!WARNING]\n> Careful.\n\n```bash\necho hi # c\n```\n\n| A |\n|---|\n| Verified |\n"
    plain = build.render(md)[0]
    rich = build.render(md, rich=True)[0]
    assert "tk-" not in plain and "badge" not in plain and "tablewrap" not in plain
    assert '<span class="tk-c"># c</span>' in rich
    assert '<span class="badge st-verified">Verified</span>' in rich
    assert 'class="callout callout-warning"' in rich and "Careful." in rich


def test_search_script_is_external_and_reads_the_index():
    js = (STATIC / "veyrs.js").read_text(encoding="utf-8")
    assert "/search-index.json" in js
    chrome = build.WIDE + build.PAGE
    assert "<script>" not in chrome, "no inline script in the page chrome"
    assert not re.search(r"\son[a-z]+\s*=", chrome), "no inline event handlers"
