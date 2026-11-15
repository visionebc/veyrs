"""The VEYRS Docs Center (`site/build.py`, served as the docs site).

What these guard, each one a way the docs site went wrong before:

* every document is filed in a category — a new doc used to land in a catch-all
  "Other" group (BRAND.md sat there, so the colours looked undocumented);
* the home page and the search index carry every document, ADRs included;
* the site wears the VEYRS brand: the header mark is the real bitmap and the
  stylesheet uses the BRAND.md dark palette, not the placeholder shield drawn
  in a generic blue -> violet gradient;
* colour codes in BRAND/DESIGN_SYSTEM render with a swatch, while the shared
  Markdown renderer (also used by the product site) stays untouched.
"""
from __future__ import annotations

import json
import re
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "site"))

import build  # noqa: E402

DOCS = ROOT / "docs"
STATIC = ROOT / "site" / "static"


@pytest.fixture(scope="module")
def site(tmp_path_factory):
    out = tmp_path_factory.mktemp("docs-center")
    build.build(str(out))
    return out


def _doc_names():
    return sorted(p.stem for p in DOCS.glob("*.md"))


def test_every_document_is_filed_in_a_category():
    filed = [k for _title, _blurb, keys in build.NAV for k in keys]
    assert len(filed) == len(set(filed)), "a document is filed in two categories"
    missing = sorted(set(_doc_names()) - set(filed))
    assert not missing, f"file these in site/build.py NAV: {missing}"


def test_the_four_project_documents_and_the_design_docs_exist():
    for name in ("TECHNICAL_REQUIREMENTS", "APP_FLOW", "TESTING_GUIDE",
                 "IMPLEMENTATION_PLAN", "BRAND", "DESIGN_SYSTEM"):
        assert (DOCS / f"{name}.md").is_file(), name


def test_home_links_every_document_and_category(site):
    home = (site / "index.html").read_text(encoding="utf-8")
    assert "VEYRS Docs Center" in home
    for title, _blurb, _keys in build.NAV:
        assert f"<h2>{title.replace('&', '&amp;')}</h2>" in home, title
    for name in _doc_names():
        assert f'href="/{name}.html"' in home, name
    assert "Other</h2>" not in home


def test_search_index_covers_every_page(site):
    index = json.loads((site / "search-index.json").read_text(encoding="utf-8"))
    urls = {e["u"] for e in index}
    assert {f"/{n}.html" for n in _doc_names()} <= urls
    adrs = {f"/adr/{p.stem}.html" for p in (DOCS / "ADRs").glob("*.md")}
    assert adrs <= urls
    for e in index:
        assert e["t"] and e["c"] and e["x"], e["u"]
    assert (site / "search.html").is_file()


def test_summaries_do_not_collide_between_readmes(site):
    """docs/README.md and docs/ADRs/README.md share a stem; the home card for
    the overview once showed the ADR index's summary."""
    home = (site / "index.html").read_text(encoding="utf-8")
    card = re.search(r'<a href="/README.html">Overview</a><span>([^<]*)', home).group(1)
    assert "ADR" not in card


def test_pages_wear_the_brand_mark_not_the_placeholder_shield(site):
    page = (site / "BRAND.html").read_text(encoding="utf-8")
    assert 'src="/static/veyrs-mark-gradient.png"' in page
    assert "veyrs-favicon.png" in page
    for placeholder in ("#3b82f6", "#8b5cf6", "<svg"):
        assert placeholder not in page.lower(), placeholder


def test_stylesheet_uses_the_brand_dark_palette():
    css = (STATIC / "veyrs.css").read_text(encoding="utf-8").lower()
    for generic in ("#080d1a", "#3b82f6", "#8b5cf6", "#a5b4fc", "rgba(59,130,246", "rgba(59, 130, 246", "rgba(139,92,246"):
        assert generic not in css, generic
    for token in ("#070d18", "#0d1626", "#111f33", "#24344d", "#f1f5f9", "#0080ff", "#0064d8"):
        assert token in css, token


def test_colour_codes_render_with_a_swatch_on_the_docs_site_only(site):
    brand = (site / "BRAND.html").read_text(encoding="utf-8")
    assert '<span class="swatch" style="background:#0064D8"' in brand
    # The renderer shared with the product site does not add swatches.
    assert "swatch" not in build.render("`#0064D8`")[0]


def test_search_script_is_external_and_reads_the_index():
    js = (STATIC / "veyrs.js").read_text(encoding="utf-8")
    assert "/search-index.json" in js
    chrome = build.WIDE + build.PAGE
    assert "<script>" not in chrome, "no inline script in the page chrome"
    assert not re.search(r"\son[a-z]+\s*=", chrome), "no inline event handlers"
