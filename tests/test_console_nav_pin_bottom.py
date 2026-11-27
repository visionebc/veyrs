"""Configure sits at the foot of the console sidebar (0.38.2, 0.38.3).

The group carries `pin: 'bottom'` and renderNav writes it into #nav-pinned, a
block of its own between the scrolling #nav and the account bar. In 0.38.2 it
was pushed down with `margin-top: auto` inside #nav instead, which only held
while the group was closed: on a Configure page the group is forced open, is
taller than the free space, and landed right under Reporting again.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "frontend" / "console" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "frontend" / "console" / "console.css").read_text(encoding="utf-8")
HTML = (ROOT / "frontend" / "console" / "index.html").read_text(encoding="utf-8")


def test_configure_is_the_only_pinned_group():
    lines = re.findall(r"\{ group: '[^']+', key: '[^']+',[^\n]*", APP)
    pinned = [l for l in lines if "pin: 'bottom'" in l]
    assert len(pinned) == 1 and pinned[0].startswith("{ group: 'Configure'"), pinned


def test_the_pinned_block_sits_between_the_menu_and_the_account_bar():
    nav = HTML.index('id="nav"')
    pinned = HTML.index('id="nav-pinned"')
    foot = HTML.index('class="sidebar-foot"')
    assert nav < pinned < foot


def test_render_nav_splits_the_groups():
    assert "$('#nav').innerHTML = NAV.filter(g => !g.pin)" in APP
    # 0.39.0: the pinned group is ONE link to its own page, not a tree.
    assert "pinned.innerHTML = NAV.filter(g => g.pin === 'bottom').map(navSolo)" in APP


def test_both_blocks_answer_clicks():
    assert "on('#nav', 'click', navClick);" in APP
    assert "on('#nav-pinned', 'click', navClick);" in APP


def test_the_pinned_block_does_not_grow_into_the_menu():
    rule = re.search(r"^\.nav\.nav-pinned \{([^}]*)\}", CSS, re.M).group(1)
    assert "flex: none" in rule and "max-height" in rule
    main = re.search(r"^\.nav \{([^}]*)\}", CSS, re.M).group(1)
    assert "flex: 1" in main and "overflow-y: auto" in main
