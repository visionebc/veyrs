"""Phase 31 - a missing element must not blank the console.

The console shipped with CSS and JavaScript for a sidebar rail button whose
markup was never added to `index.html`. The failure was total and silent:
`$('#rail-btn').onclick = ...` ran at module top level, threw
`TypeError: Cannot set properties of null`, and aborted `app.js` **before**
`boot()` was ever called. Both `#login` and `#shell` carry `hidden` in the
markup and only `boot()` removes it, so the operator got a white page - no
login form, no error, no view. nginx logs showed `app.js` served 200 and not a
single API call after it.

What is pinned here:

* **Every id wired at top level exists in the markup.** This is the invariant
  that was violated; asserting it is cheaper than any amount of care.
* **Top level never assigns an `on*` handler directly.** A direct assignment
  needs a non-null element and there is no way to write one defensively without
  repeating the guard; `on()` takes the selector, so a missing element costs a
  no-op instead of the whole application.
* **`boot()` is the last statement.** Wiring that throws after it would leave a
  half-live console; wiring that throws before it leaves nothing at all. The
  ordering is what makes the two rules above load-bearing.
"""
from __future__ import annotations

import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "frontend" / "console"
APP_JS = CONSOLE / "app.js"
INDEX_HTML = CONSOLE / "index.html"

# A top-level statement is one that starts in column 0. Everything inside a
# route handler or a function is indented, so this is an exact filter for the
# statements that run at load time.
TOP_LEVEL_SELECTOR = re.compile(r"^(?:on\(|\$\()'(#[A-Za-z0-9_-]+)'", re.MULTILINE)
DIRECT_HANDLER = re.compile(r"^\$\('(#[A-Za-z0-9_-]+)'\)\.on[a-z]+\s*=", re.MULTILINE)
ID_ATTR = re.compile(r'id="([A-Za-z0-9_-]+)"')


def _markup_ids() -> set[str]:
    return set(ID_ATTR.findall(INDEX_HTML.read_text(encoding="utf-8")))


def test_every_top_level_selector_exists_in_the_markup():
    src = APP_JS.read_text(encoding="utf-8")
    ids = _markup_ids()
    missing = sorted(
        {sel for sel in TOP_LEVEL_SELECTOR.findall(src) if sel.lstrip("#") not in ids}
    )
    assert not missing, (
        "app.js wires these ids at load time but index.html has no such element: "
        + ", ".join(missing)
        + ". A null here aborts the module before boot() and blanks the console."
    )


def test_rail_button_is_present():
    # The regression itself: CSS (#rail-btn) and JS shipped, markup did not.
    assert "rail-btn" in _markup_ids()
    assert "brand-text" in INDEX_HTML.read_text(encoding="utf-8"), (
        "the rail collapses .brand-text; without the class the brand stays "
        "full width inside a 68px column"
    )


def test_no_direct_top_level_handler_assignment():
    src = APP_JS.read_text(encoding="utf-8")
    offenders = sorted(set(DIRECT_HANDLER.findall(src)))
    assert not offenders, (
        "assign top-level handlers through on(selector, event, fn), which "
        "no-ops on a missing element: " + ", ".join(offenders)
    )


def test_on_helper_is_null_safe():
    src = APP_JS.read_text(encoding="utf-8")
    m = re.search(r"^const on = \(sel, ev, fn\) => \{(.+?)\};$", src, re.MULTILINE)
    assert m, "the on() helper is gone; the guarantee above rests on it"
    assert "if (el)" in m.group(1)


def test_boot_is_the_last_statement():
    lines = [l for l in APP_JS.read_text(encoding="utf-8").splitlines() if l.strip()]
    assert lines[-1].strip() == "boot();", (
        "boot() must run last: anything that throws after it leaves a "
        "half-initialised console instead of none at all"
    )
