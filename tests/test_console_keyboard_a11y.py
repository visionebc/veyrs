"""TD-13, TD-60 and the small gaps of docs/design/accessibility.md, pinned in the source.

Nothing here runs a browser; it pins the markup and the handlers that make the
console operable without a mouse, so a refactor of the table or the shell
template cannot silently drop them.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

CONSOLE = Path(__file__).resolve().parents[1] / "frontend" / "console"


@pytest.fixture(scope="module")
def js() -> str:
    return (CONSOLE / "app.js").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def html() -> str:
    return (CONSOLE / "index.html").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def css() -> str:
    return (CONSOLE / "console.css").read_text(encoding="utf-8")


def test_clickable_rows_are_focusable_and_keyboard_operable(js, css):
    # focusable
    assert re.search(r"""<tr class="\$\{opts\.onRow \? 'clickable' : ''\}"\$\{opts\.onRow \? ' tabindex="0"' : ''\}""", js), (
        "clickable rows must carry tabindex=0")
    # Enter and Space open the row exactly as a click does, only when the row itself has focus
    m = re.search(r"document\.addEventListener\('keydown', e => \{\s*if \(\(e\.key !== 'Enter' && e\.key !== ' '\)([^\n]*)", js)
    assert m and "tr.clickable" in m.group(1), "no Enter/Space handler for tr.clickable"
    assert "e.target.click()" in js
    # visible focus
    assert re.search(r"tr\.clickable:focus-visible\s*\{[^}]*outline", css)


def test_tabs_get_the_tab_pattern_after_every_render(js):
    body = js[js.index("function enhanceTabs"):js.index("function enhancePage")]
    for needle in ("role', 'tablist'", "role', 'tab'", "aria-selected", "tabIndex", "ArrowRight", "Home"):
        assert needle in body, f"tabs enhancer lost {needle}"
    assert "enhanceTabs(view);" in js[js.index("function enhancePage"):][:200]


def test_skip_link_precedes_the_navigation_and_targets_the_view(html, js):
    assert html.index('class="skip-link"') < html.index('<aside class="sidebar"')
    assert 'id="view" tabindex="-1"' in html
    # the fragment is the router: the link must not be allowed to navigate
    assert "closest('#skip-link')" in js and "v.focus()" in js


def test_the_configure_rail_button_names_its_current_action(js):
    rail = js[js.index("const railBtn = view.querySelector('.cfg-rail-btn')"):][:700]
    assert "setAttribute('aria-label'" in rail, "the label must follow the state (TD-60)"
    tmpl = re.search(r'<button type="button" class="cfg-rail-btn"[^>]*>', js).group(0)
    assert "${rail ? 'Expand' : 'Collapse'}" in tmpl.split("aria-label=")[1], "initial label must reflect the stored state"
    assert "aria-pressed" not in tmpl, "a state-named button must not also be a toggle"


def test_job_state_pills_are_styled(css):
    for state in ("queued", "cancelled"):
        assert re.search(rf"\.st-{state}\b[^{{]*\{{[^}}]*background", css), f"st-{state} has no rule"


def test_cache_busters_follow_the_assets(html):
    """A changed asset must change its ?v= or nginx's `expires -1` page still pulls a cached file."""
    assert re.search(r"console\.css\?v=(\d+)", html) and re.search(r"app\.js\?v=(\d+)", html)
    assert int(re.search(r"console\.css\?v=(\d+)", html).group(1)) >= 22
    assert int(re.search(r"app\.js\?v=(\d+)", html).group(1)) >= 48


def test_the_console_csp_forbids_inline_script_and_foreign_origins():
    """R-16 compensating control: tokens live in localStorage, so script injection must be closed off."""
    conf = (Path(__file__).resolve().parents[1] / "infrastructure" / "nginx-veyrs-console.conf").read_text()
    csp = re.search(r'add_header Content-Security-Policy "([^"]+)"', conf).group(1)
    directives = {d.split()[0]: d.split()[1:] for d in csp.split(";") if d.strip()}
    assert directives["script-src"] == ["'self'"]
    assert directives["connect-src"] == ["'self'"]
    assert directives["default-src"] == ["'self'"]
    assert "'none'" in directives["frame-ancestors"]
    assert not re.search(r"https?://|\*", csp), "the CSP names a foreign origin or a wildcard"
    html = (CONSOLE / "index.html").read_text(encoding="utf-8")
    assert re.findall(r"<script\b[^>]*>", html) == ['<script src="/app.js?v=%s">' % re.search(r"app\.js\?v=(\d+)", html).group(1)]
    js = (CONSOLE / "app.js").read_text(encoding="utf-8")
    assert not re.search(r"\bon(?:click|error|load|submit)=\"", js), "inline event handler attribute (blocked by the CSP)"
