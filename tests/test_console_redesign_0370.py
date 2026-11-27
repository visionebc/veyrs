"""Guards for the 0.37.0 console round.

Three defects this round found in production, each pinned so it cannot come
back silently:

* 0.36.0 shipped the severity composition strip as `.stack`, which is also
  the console's vertical layout class; its 12 px height + overflow:hidden
  collapsed six layouts (CVSS score panel, automation, forms) to a sliver.
* index.html went out with no Cache-Control at all, so browsers cached it
  heuristically for days and a deploy that bumped `app.js?v=` was invisible.
* the console named Inter / JetBrains Mono but loaded neither (CSP is
  font-src 'self'), so it rendered in whatever the OS had.

Plus the contracts the new dashboard controls rely on.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "frontend" / "console"
VHOSTS = [
    ROOT / "infrastructure" / "nginx-veyrs-console.conf",
    ROOT / "docker" / "console.conf",
]
FONTS = [
    "inter-regular.woff2", "inter-medium.woff2", "inter-semibold.woff2", "inter-bold.woff2",
    "jetbrains-mono-regular.woff2", "jetbrains-mono-medium.woff2",
]


@pytest.fixture(scope="module")
def css() -> str:
    return re.sub(r"/\*.*?\*/", "", (CONSOLE / "console.css").read_text(encoding="utf-8"), flags=re.DOTALL)


@pytest.fixture(scope="module")
def js() -> str:
    return (CONSOLE / "app.js").read_text(encoding="utf-8")


def _location_root(conf: str) -> str:
    m = re.search(r"location / \{(.*?)\n\s*\}", conf, flags=re.DOTALL)
    assert m, "no `location /` block"
    return m.group(1)


def test_the_layout_stack_class_is_defined_once_and_never_sized(css):
    rules = re.findall(r"(?m)^\.stack\s*\{([^}]*)\}", css)
    assert len(rules) == 1, f".stack is defined {len(rules)} times; a second definition overrides the layout class"
    assert "height" not in rules[0] and "overflow" not in rules[0]


def test_the_composition_strip_has_its_own_class(js, css):
    assert 'class="compo"' in js
    assert 'class="stack" role="img"' not in js
    assert re.search(r"(?m)^\.compo\s*\{", css)


@pytest.mark.parametrize("path", VHOSTS, ids=lambda p: p.name)
def test_index_html_is_revalidated_on_every_load(path):
    block = _location_root(path.read_text(encoding="utf-8"))
    assert re.search(r"\bexpires\s+-1\s*;", block), f"{path.name}: index.html would be cached heuristically"
    # add_header inside a location drops every server-level header, the CSP
    # included. `expires` does not.
    assert "add_header" not in block, f"{path.name}: add_header in `location /` drops the security headers"


def test_the_generated_native_vhost_revalidates_too():
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    block = _location_root(text[text.index("NGEOF"):])
    assert re.search(r"\bexpires\s+-1\s*;", block)
    assert "add_header" not in block


def test_fonts_are_self_hosted_and_installed(css):
    for name in FONTS:
        f = CONSOLE / "fonts" / name
        assert f.is_file() and f.read_bytes()[:4] == b"wOF2", f"{name} missing or not woff2"
        assert f"url(/fonts/{name})" in css, f"{name} has no @font-face"
    assert (CONSOLE / "fonts" / "LICENSE-Inter.txt").is_file()
    assert (CONSOLE / "fonts" / "LICENSE-JetBrainsMono.txt").is_file()
    install = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert 'frontend/console/fonts/*' in install, "native installs would serve the console without its fonts"
    for path in VHOSTS:
        assert "location /fonts/" in path.read_text(encoding="utf-8")


def test_no_font_is_fetched_from_another_origin(css):
    assert not re.search(r"url\(\s*['\"]?https?:", css)
    html = (CONSOLE / "index.html").read_text(encoding="utf-8")
    assert not re.search(r"""(href|src)=["']https?:""", html)


def test_the_dashboard_range_is_one_the_api_accepts(js):
    # backend: days = Query(default=90, ge=7, le=730)
    m = re.search(r"const RANGES = \[(.*?)\];", js)
    assert m
    days = [int(d) for d in re.findall(r"\['(\d+)'", m.group(1))]
    assert days and all(7 <= d <= 730 for d in days)
    assert "'90'" in m.group(1), "the default window must stay 90 days"


def test_trend_gaps_are_never_drawn_as_zero(js):
    body = js[js.index("function segmentsOf("):js.index("function kpiSpark(")]
    # a null bucket ends the segment; it is not coerced with Number() first
    assert "v === null" in body and "segs.push(cur)" in body


def test_every_view_gets_crumbs_title_and_busy_state(js):
    render = js[js.index("async function render()"):js.index("/* ══ Auth flow")]
    assert "enhancePage(view, name, params, parts.slice(1))" in render
    assert "aria-busy" in render
    assert "renderCrumbs(active, p)" in js
