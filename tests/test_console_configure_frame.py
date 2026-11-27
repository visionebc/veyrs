"""Configure has its own page with its own menu (0.39.0, owner request).

The sidebar carries a single Configure link; the pages it used to expand into
(scanner, data sources, SLA & policies, automation, administration) render
inside `configureFrame`: a menu of their own on the left, the page on the
right. A page whose sub-views are all in that menu hides its tab bar, so the
guard that matters most is that no tab can be hidden without a menu entry.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "frontend" / "console" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "frontend" / "console" / "console.css").read_text(encoding="utf-8")

NAV = APP[APP.index("const NAV = ["):APP.index("/* ── Icons")]
CONFIGURE = NAV[NAV.index("{ group: 'Configure'"):]


def _configure_pages() -> list[str]:
    return re.findall(r"^    \{ path: '(\w+)', label:", CONFIGURE, re.M)


def _menu_tabs(page: str) -> set[str]:
    return set(re.findall(r"\{ path: '%s', label: '[^']+',\s*q: \{ tab: '(\w+)' \}" % page, CONFIGURE))


def _route_tabs(page: str) -> set[str] | None:
    start = APP.index(f"route('{page}', async")
    body = APP[start:APP.index("\nroute(", start + 10)]
    m = re.search(r"<div class=\"tabs\">\$\{\[(\[.+?\])\]", body)
    return set(re.findall(r"\['(\w+)', '", m.group(1))) if m else None


def test_the_configure_group_holds_the_five_setup_pages():
    assert _configure_pages() == ["scanner", "integrations", "policies", "automation", "admin"]


def test_every_hidden_tab_has_an_entry_in_the_configure_menu():
    # The frame hides a page's own tab bar whenever the page has sub-views in
    # the menu. A tab missing from NAV would become unreachable.
    for page in _configure_pages():
        tabs = _route_tabs(page)
        menu = _menu_tabs(page)
        if menu:
            assert tabs is not None, f"{page}: menu lists sub-views but the page has no tab bar"
            assert tabs == menu, f"{page}: page tabs {sorted(tabs)} != menu {sorted(menu)}"


def test_the_tab_bar_is_hidden_only_where_the_menu_replaces_it():
    assert "data-subnav" in APP
    assert re.search(r"\.cfg-body\[data-subnav\] > \.tabs, \.cfg-body\[data-subnav\] > \.seg \{ display: none; \}", CSS)
    # Only for direct children: tabs inside a page body (sub-tabs) stay.
    assert ".cfg-body .tabs" not in CSS


def test_the_sidebar_shows_configure_as_one_link():
    m = re.search(r"const navSolo = g => \{(.+?)\n  \};", APP, re.S)
    assert m, "navSolo moved"
    solo = m.group(1)
    assert 'href="#/${esc(g.key)}"' in solo
    assert "nav-sub" not in solo and "children" not in solo


def test_render_draws_configure_pages_into_the_frame():
    assert "const target = configureFrame(view, name, params) || view;" in APP
    assert "await fn(target, parts.slice(1), params);" in APP
    # Errors land in the frame body, so the Configure menu survives a 403.
    assert "target.innerHTML = `<div class=\"card\"><h2>Access denied</h2>" in APP


def test_the_configure_hub_route_exists_and_lists_the_same_pages():
    assert "route('configure', async (view) =>" in APP
    assert "configureGroup().items.filter(navShown)" in APP
    blurbs = APP[APP.index("const CONFIGURE_BLURB = {"):APP.index("const configureGroup")]
    for page in _configure_pages():
        assert re.search(r"^  %s: '" % page, blurbs, re.M), f"no hub blurb for {page}"


def test_sidebar_and_frame_share_one_visibility_filter():
    assert "const navShown = i =>" in APP
    assert "g.items.filter(navShown)" in APP
    # The old inline copy of the filter is gone.
    assert "g.items.filter(i => !i.hidden" not in APP


def test_breadcrumb_links_back_to_configure():
    assert "crumbs.push({ text: g.group, href: g.pin ? '#/' + g.key : '' })" in APP


def test_the_frame_uses_tokens_only():
    block = CSS[CSS.index("/* ── Configure frame (0.39.0)"):]
    block = block[:block.index("\n/* ── ", 10)]
    assert not re.search(r"#[0-9a-fA-F]{3,8}\b", block), "literal colour in the Configure frame"
    assert "rgba(" not in block


def test_the_menu_folds_to_a_rail_and_the_tabs_come_back():
    # 0.39.1: folding the menu must not strand the sub-views it listed.
    assert "const CFG_RAIL_LS = 'veyrs.cfg.rail';" in APP
    assert "classList.toggle('rail')" in APP
    assert ".cfg.rail .cfg-body[data-subnav] > .tabs { display: flex; }" in CSS
    assert ".cfg.rail .cfg-body[data-subnav] > .seg { display: inline-flex; }" in CSS


# 0.42.0 (owner request): no tree in the Configure menu. -------------------

def _frame() -> str:
    start = APP.index("function configureFrame(view, name, params) {")
    return APP[start:APP.index("\n}\n", start)]


def test_the_menu_is_one_level_of_rows_with_icons():
    frame = _frame()
    assert "cfg-sub'" not in frame and "cfg-subs" not in frame, "the indented sub-tree is back"
    assert "cfg-subs" not in CSS
    # Flat items (Administration) give their sections to the menu, every child
    # as a full row with its own icon.
    admin = CONFIGURE[CONFIGURE.index("{ path: 'admin', label: 'Administration'"):]
    assert "flat: true" in admin.splitlines()[0]
    kids = re.findall(r"\{ path: 'admin', label: '([^']+)',\s*q: \{ tab: '\w+' \}([^\n]*)\}", admin)
    assert len(kids) >= 20
    for label, rest in kids:
        assert "ico: '" in rest, f"Administration > {label} has no icon"


def test_only_a_flat_page_hides_its_tab_bar():
    # Pages with ordinary tabs (Data sources, SLA & Policies, Automation) show
    # their own tab bar: the menu no longer lists their sub-views.
    assert "cur && cur.flat ? ' data-subnav' : ''" in APP


def test_every_administration_tab_has_its_own_title_and_description():
    blurbs = APP[APP.index("const ADMIN_BLURB = {"):APP.index("function adminTabLabel")]
    have = set(re.findall(r"^  (\w+): '", blurbs, re.M))
    assert have == _menu_tabs("admin"), sorted(have ^ _menu_tabs("admin"))
    route = APP[APP.index("route('admin', async"):]
    assert "<h1>${esc(adminTabLabel(tab) || 'Administration')}</h1>" in route[:600]


def test_sections_reach_the_hub_and_the_breadcrumb():
    secs = set(re.findall(r"sec: '([^']+)'", CONFIGURE))
    hub = APP[APP.index("const CONFIGURE_SECTION = {"):APP.index("const configureGroup")]
    assert secs == set(re.findall(r"^  '([^']+)': \['", hub, re.M))
    assert "const sec = it && it.flat && kid ? navSections(it)" in APP
