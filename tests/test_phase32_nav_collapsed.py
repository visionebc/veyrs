"""Phase 32 - the sidebar starts collapsed.

The nav shipped with eight groups expanded on first paint. The state was
persisted as the set of what the operator had CLOSED, so the default was
"everything open" and a group added in a later release arrived expanded on
every browser that had ever loaded the console.

The set is now what is OPEN. Two consequences are load-bearing and are pinned
here because both are invisible until an operator complains:

* **Absent storage means collapsed, not expanded.** `navReadSet` falls back to
  an empty set, and every open test now reads the set positively. A negation
  anywhere in those two expressions silently restores the old default.
* **The storage keys had to change.** The previous keys hold the inverse set;
  reading them as-is would leave each operator with exactly the groups they had
  closed as the only ones open.

The group and item holding the current route are still forced open at render
time without touching the stored set - losing your place is a bug, and
rewriting the preference on navigation would erase what the operator chose.

v0.31.3 narrowed the set to hold AT MOST ONE key at each level: expansion is
exclusive, so opening a section closes the one the operator had open. The
section holding the current route is exempt because it is not in the set at
all, and both click handlers now REFUSE that section rather than flipping its
key - a flip there changed nothing on screen and everything on the next
navigation.
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP_JS = ROOT / "frontend" / "console" / "app.js"


def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


def test_the_inverted_state_object_is_gone():
    assert "navClosed" not in _src(), (
        "navClosed held the set of collapsed groups; keeping the name alongside "
        "navOpen is how one of the two open tests gets left on the old meaning"
    )


def test_storage_keys_were_migrated():
    src = _src()
    m = re.search(r"^const NAV_LS = \{(.+?)\};$", src, re.MULTILINE)
    assert m, "NAV_LS is gone; the keys below are what pin the migration"
    keys = m.group(1)
    assert "'veyrs.nav.open.groups'" in keys and "'veyrs.nav.open.items'" in keys
    assert "'veyrs.nav.groups'" not in keys and "'veyrs.nav.items'" not in keys, (
        "the old keys hold the CLOSED set: reused, they would open exactly the "
        "groups the operator had collapsed"
    )


def test_absent_storage_reads_as_empty():
    m = re.search(r"^const navReadSet = k => \{(.+?)\n\};$", _src(), re.DOTALL | re.MULTILINE)
    assert m, "navReadSet is gone; 'no storage means collapsed' rests on it"
    body = m.group(1)
    assert "|| '[]'" in body and "return new Set()" in body, (
        "both the absent-key and the corrupt-JSON paths must yield an empty "
        "set, which is what makes the default fully collapsed"
    )


def test_group_and_item_open_tests_are_positive():
    src = _src()
    group = "const open = holdsActive || navOpen.groups.has(g.key);"
    item = "const subOpen = kids.length > 0 && (isActive || navOpen.items.has(i.path));"
    assert group in src, (
        "the group open test must read navOpen positively; a leading ! makes "
        "every group expand by default again"
    )
    assert item in src, "same for the sub-item open test"


def test_the_active_route_is_forced_open_without_persisting_it():
    src = _src()
    # holdsActive / isActive widen what is rendered open; neither may write.
    assert "holdsActive" in src and "navSave" in src
    for line in src.splitlines():
        if "holdsActive" in line or "isActive ||" in line:
            assert "navSave" not in line and ".add(" not in line, (
                "rendering the active group open must not mutate the stored "
                "preference: " + line.strip()
            )


def test_both_toggles_route_through_the_exclusive_selector():
    """v0.31.3 - expansion is exclusive, so the set holds at most one key.

    The previous toggle flipped one key and left every other open section
    standing, which is the whole of "nothing ever closes when I open another".
    Both levels must go through navSelect; a bare `.add(` at either call site
    restores the multi-open nav without failing anything else.
    """
    src = _src()
    for level in ("items", "groups"):
        assert f"navSelect(navOpen.{level}, k);" in src, (
            f"the {level} toggle no longer goes through the exclusive selector"
        )
        assert f"navOpen.{level}.add(k)" not in src, (
            f"the {level} toggle adds directly to the set again, which is how "
            f"two sections end up open at once"
        )


def test_the_selector_clears_before_it_opens():
    """Exclusivity lives in one place; without the clear it is an ordinary add."""
    m = re.search(r"^function navSelect\(set, key\) \{(.+?)\n\}$", _src(), re.DOTALL | re.MULTILINE)
    assert m, "navSelect is gone; exclusivity rests entirely on it"
    body = m.group(1)
    assert "set.clear();" in body, (
        "without the clear, opening a section leaves the previous one open"
    )
    assert body.index("const wasOpen") < body.index("set.clear();"), (
        "membership has to be read BEFORE the clear or a second click on the "
        "same section can never collapse it"
    )
    assert "if (!wasOpen) set.add(key);" in body, (
        "clicking an already-open section must collapse it, not reopen it"
    )


def test_neither_toggle_can_act_on_the_section_holding_the_current_page():
    """The operator's second complaint: clicking the section you are IN closed it.

    It never closed on screen - holdsActive/isActive force it open - but the
    click flipped the stored key anyway, so the accordion state after the next
    navigation was decided by a click that appeared to do nothing.
    """
    src = _src()
    assert "if (k === navCtx.name) return;" in src, (
        "the item caret must refuse the active item instead of flipping its key"
    )
    assert "if (navGroupHoldsActive(k)) return;" in src, (
        "the group header must refuse the group holding the current route"
    )
    # Both refusals must sit BEFORE the mutation, or they guard nothing.
    for bail, call in (
        ("if (k === navCtx.name) return;", "navSelect(navOpen.items, k);"),
        ("if (navGroupHoldsActive(k)) return;", "navSelect(navOpen.groups, k);"),
    ):
        assert src.index(bail) < src.index(call), f"{bail} must precede {call}"


def test_the_active_group_is_identified_by_its_items_not_its_key():
    """`holdsActive` asks which group owns the route; the handler must agree.

    Comparing the group key to the route name instead would make the refusal
    fire for no group at all - the keys are group names, the routes are page
    paths - and the guard above would still pass.
    """
    m = re.search(r"const navGroupHoldsActive = key => \{(.+?)\n\};", _src(), re.DOTALL)
    assert m, "navGroupHoldsActive is gone"
    body = m.group(1)
    assert "g.items.some(i => i.path === navCtx.name)" in body, (
        "the handler must resolve the active group the same way renderNav does"
    )
