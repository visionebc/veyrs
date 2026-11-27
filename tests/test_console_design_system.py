"""Guards for the 0.36.0 console redesign.

Each test pins a rule from docs/DESIGN_SYSTEM.md that the console had drifted
away from before this round, so the drift cannot come back silently:

* colour comes from tokens, not literals (section 12, "Hard-coded colours");
* radii stay on the brand's 3/5/8 px scale (section 12 item 2);
* the severity palette never falls back to the identity blue (item 3);
* every menu icon comes from the one drawn set, never a font glyph;
* the Administration page and the sidebar agree on which tabs exist and which
  section each belongs to.
"""
from __future__ import annotations

import re
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "frontend" / "console"


@pytest.fixture(scope="module")
def css() -> str:
    return (CONSOLE / "console.css").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def js() -> str:
    return (CONSOLE / "app.js").read_text(encoding="utf-8")


def _strip_comments(css: str) -> str:
    return re.sub(r"/\*.*?\*/", "", css, flags=re.DOTALL)


def _rules_outside(css: str, *selectors: str) -> str:
    """The stylesheet minus the blocks whose selector starts with one of
    `selectors` (the token block and the login hero, which may hold literals)."""
    out, depth, keep = [], 0, True
    for chunk in re.split(r"([{}])", _strip_comments(css)):
        if chunk == "{":
            depth += 1
            if depth == 1:
                head = out.pop() if out else ""
                keep = not any(head.strip().startswith(s) for s in selectors)
                out.append(head if keep else "")
            if keep:
                out.append(chunk)
        elif chunk == "}":
            if keep:
                out.append(chunk)
            depth -= 1
            if depth == 0:
                keep = True
        elif keep:
            out.append(chunk)
    return "".join(out)


def test_colour_literals_live_only_in_the_token_blocks(css):
    body = _rules_outside(
        css, ":root", '[data-theme="light"]', ".login-hero", ".veyrs-key", ".login-logo",
    )
    hexes = re.findall(r"#[0-9A-Fa-f]{3,8}\b", body)
    rgbas = re.findall(r"rgba?\([^)]*\)", body)
    # `rgba(var(--veyrs-blue-rgb), …)` is a token used with an alpha.
    rgbas = [r for r in rgbas if "var(--" not in r]
    assert not hexes and not rgbas, (
        f"colour literals outside the token blocks: {hexes + rgbas}. Name a token "
        "in the :root block at the top of console.css, or use one from veyrs-tokens.css."
    )


def test_radii_stay_on_the_brand_scale(css):
    body = _strip_comments(css)
    big = [m for m in re.findall(r"border-radius:\s*(\d+)px", body) if 8 < int(m) < 999]
    assert not big, (
        f"border-radius values above 8px: {big}. The brand avoids over-rounded "
        "surfaces; use --radius-sm / --radius / --radius-lg."
    )


def test_both_themes_are_designed_on_their_own(css):
    """0.38.0 ("Midnight Ops"): two theme blocks, each a complete palette.
    Light is not dark inverted -- it has its own light sidebar, its own darker
    semantic hues and its own gold. Pinning the keys keeps a future edit from
    leaving one theme half-defined (it would silently inherit the other's)."""
    body = _strip_comments(css)
    dark = re.search(r':root\[data-theme="dark"\] \{(.+?)\}', body, re.DOTALL)
    light = re.search(r'\[data-theme="light"\] \{(.+?)\}', body, re.DOTALL)
    assert dark and light, "a theme block is gone"
    keys = ("--background", "--surface", "--surface-2", "--border", "--text", "--text-secondary",
            "--primary", "--link", "--gold", "--nav-bg", "--nav-text", "--chart-risk",
            "--chart-in", "--chart-out", "--veyrs-critical", "--veyrs-remediated")
    val = lambda block, k: re.search(re.escape(k) + r":\s*([^;]+);", block.group(1))
    for k in keys:
        assert val(dark, k), f"dark theme does not define {k}"
        assert val(light, k), f"light theme does not define {k}"
    assert val(dark, "--nav-bg").group(1) != val(light, "--nav-bg").group(1), "light must not reuse the dark sidebar"
    for old in ("#F7F7F5", "#E9E9E7", "#191919", "#787774"):
        assert old not in css, f"{old} is the retired warm-grey palette"


def test_severity_never_falls_back_to_the_identity_colour(js):
    m = re.search(r"const sevColour = k => \(\{(.+?)\}\[String\(k\)\.toLowerCase\(\)\] \|\| '([^']+)'\);", js, re.DOTALL)
    assert m, "sevColour changed shape; re-pin this test"
    assert m.group(2) != "var(--primary)"


def test_every_menu_icon_is_drawn(js):
    nav = js[js.index("const NAV = ["):js.index("/* ── Icons")]
    used = set(re.findall(r"ico: '([^']*)'", nav))
    icons_block = js[js.index("const ICONS = {"):js.index("const icon = name =>")]
    drawn = set(re.findall(r"^  (\w+): '", icons_block, re.MULTILINE))
    assert used, "no NAV icons found"
    assert used <= drawn, f"NAV icons with no drawing: {sorted(used - drawn)}"


def test_the_shell_uses_no_glyph_or_emoji_icons():
    html = (CONSOLE / "index.html").read_text(encoding="utf-8")
    for glyph in ("☰", "🔔", "◐"):
        assert glyph not in html, f"{glyph!r} is back in the shell markup"


def _admin_page_tabs(js: str) -> list[str]:
    m = re.search(r"<div class=\"tabs\">\$\{(\[\['users', 'Users'\].+?\]\])", js)
    assert m, "the Administration tab list moved; re-pin this test"
    return re.findall(r"\['(\w+)', '", m.group(1))


def _admin_sections(js: str) -> list[tuple[str, list[str]]]:
    block = js[js.index("const ADMIN_SECTIONS = ["):js.index("const adminSection")]
    return [(label, re.findall(r"'(\w+)'", keys))
            for label, keys in re.findall(r"\['([^']+)',\s*\[([^\]]*)\]\]", block)]


def test_every_administration_tab_sits_in_exactly_one_section(js):
    tabs = _admin_page_tabs(js)
    placed = [k for _, keys in _admin_sections(js) for k in keys]
    assert sorted(placed) == sorted(tabs), (
        f"unplaced: {sorted(set(tabs) - set(placed))}, unknown: {sorted(set(placed) - set(tabs))}, "
        f"duplicated: {sorted({k for k in placed if placed.count(k) > 1})}"
    )


def test_the_sidebar_lists_every_administration_tab(js):
    nav = js[js.index("const NAV = ["):js.index("/* ── Icons")]
    in_menu = set(re.findall(r"\{ path: 'admin', label: '[^']+',\s*q: \{ tab: '(\w+)' \}", nav))
    assert in_menu == set(_admin_page_tabs(js)), (
        "the sidebar and the Administration page disagree about which tabs exist: "
        f"menu-only {sorted(in_menu - set(_admin_page_tabs(js)))}, "
        f"page-only {sorted(set(_admin_page_tabs(js)) - in_menu)}"
    )


def test_sidebar_section_labels_match_the_page(js):
    nav = js[js.index("const NAV = ["):js.index("/* ── Icons")]
    admin_secs = re.findall(r"\{ path: 'admin', label: '[^']+',\s*q: \{ tab: '(\w+)' \}[^}]*sec: '([^']+)'", nav)
    starts = {label: keys[0] for label, keys in _admin_sections(js)}
    assert {tab: label for tab, label in admin_secs} == {v: k for k, v in starts.items()}, (
        "each Administration section must open, in the sidebar, at the first tab "
        "the page lists for it"
    )


def test_no_menu_group_holds_a_single_bare_entry(js):
    """A heading over ONE entry with nothing under it is a menu level that
    carries no information (the old "Tools" group). One entry WITH a sub-menu
    is a different thing: Estate -> Inventory is deliberate, see its comment."""
    nav = js[js.index("const NAV = ["):js.index("/* ── Icons")]
    for g in re.split(r"\n  \{ group: ", nav)[1:]:
        name = g.split("'")[1]
        lines = [l for l in re.findall(r"^    \{ path: '\w+'[^\n]*", g, re.MULTILINE) if "hidden: true" not in l]
        if len(lines) == 1:
            assert "children: [" in lines[0], (
                f"menu group {name!r} holds one entry and nothing under it"
            )
