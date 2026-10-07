"""Every class the console asks for must exist in the stylesheet.

This guard exists because a missing rule is the one front-end defect that
produces no error anywhere. `.grid2` was written into three forms in 0.27.0 and
never added to `console.css`: the browser dropped the unknown class, the forms
rendered as one stacked column, and every test stayed green because the markup
was correct. `.st-ok` and `.st-warn` failed the same way and were worse -- a
status pill with no colour does not look broken, it looks like agreement, so
"Enabled" and "Disabled" were the same grey.

The check is deliberately whole-file rather than a list of the classes we
happen to remember: the next one will be a class nobody has thought of yet.
"""
from __future__ import annotations

import pathlib
import re

import pytest

CONSOLE = pathlib.Path("/opt/veyrs/frontend/console")

#: Classes that are hooks, not appearance. Each is read by JS (`closest()`,
#: `querySelector`) or is a bare block container, and styling it would be
#: inventing a rule to satisfy a test. Anything added here must be justified in
#: the same breath -- the allowlist is where this guard goes to die.
BEHAVIOUR_ONLY = {
    "kv-del",      # delegated click target: remove this mapping row
    "vm-del",      # delegated click target: remove this translation row
    "nav-toggle",  # delegated click target: expand a sidebar group
    "nav-item",    # block container around one sidebar entry
    "nav-items",   # block container around a group's entries
}


@pytest.fixture(scope="module")
def sources() -> tuple[str, str]:
    js, css = CONSOLE / "app.js", CONSOLE / "console.css"
    if not js.exists() or not css.exists():  # pragma: no cover - bare checkout
        pytest.skip("the console is not present")
    return js.read_text(encoding="utf-8"), css.read_text(encoding="utf-8")


#: One level of `${ ... }`, which is all these templates use for a class.
_EXPR = re.compile(r"\$\{[^{}]*(?:\{[^{}]*\}[^{}]*)*\}")


def used_classes(js: str) -> set[str]:
    """Class tokens from `class="..."` literals.

    The interpolated parts are removed first and the static neighbours kept:
    `class="pill ${x ? 'st-ok' : 'st-neutral'}"` contributes `pill`. A literal
    still carrying template syntax after that is dropped whole rather than
    tokenised into JavaScript operators -- reporting `&&` as a missing class is
    how a guard gets muted.
    """
    out: set[str] = set()
    for literal in re.findall(r'class="([^"\n]*)"', js):
        # A sentinel, not a space: `prov-${kind}` is one runtime-built name, and
        # blanking the expression would report the prefix `prov-` as missing.
        stripped = _EXPR.sub("\0", literal)
        if any(c in stripped for c in "${}`"):
            continue
        out.update(t for t in stripped.split() if "\0" not in t)
    return out


def defined_classes(css: str) -> set[str]:
    return set(re.findall(r"\.([A-Za-z][\w-]*)", css))


# ── Classes that only work alongside another one ─────────────────────────
#
# `test_every_class_the_console_uses_is_styled` reads the stylesheet as a bag
# of names, so `.grid.cols-4` makes BOTH `grid` and `cols-4` look defined. The
# register's summary row was written `class="cols-4"`, the guard stayed green,
# and the four stat cards rendered as plain blocks with no gap -- touching.
#
# `cols-4` carries only `grid-template-columns`; without `grid` there is no
# `display: grid` for it to apply to. A modifier is not a layout.

_PSEUDO_FN = re.compile(r"::?[A-Za-z-]+\([^)]*\)")
_PSEUDO = re.compile(r"::?[A-Za-z-]+")
_ATTR = re.compile(r"\[[^\]]*\]")


def _compounds(selector: str):
    """`.a.b > .c:hover` -> `{'a','b'}`, `{'c'}` -- one set per compound."""
    sel = _ATTR.sub("", _PSEUDO_FN.sub("", selector))
    sel = _PSEUDO.sub("", sel)
    for part in re.split(r"[\s>+~]+", sel):
        classes = frozenset(re.findall(r"\.([A-Za-z][\w-]*)", part))
        if classes:
            yield classes


def companion_rules(css: str) -> dict[str, list[frozenset[str]]]:
    """Classes that never appear alone, mapped to the partners they need.

    A class written alone *somewhere* in the stylesheet stands on its own and
    is not reported, however many compounds it also appears in.
    """
    standalone: set[str] = set()
    needs: dict[str, list[frozenset[str]]] = {}
    for chunk in re.findall(r"([^{}]+)\{", css):
        chunk = chunk.strip()
        if chunk.startswith("@"):  # media/supports preludes carry no selector
            continue
        for selector in chunk.split(","):
            for comp in _compounds(selector):
                if len(comp) == 1:
                    standalone.add(next(iter(comp)))
                else:
                    for cls in comp:
                        needs.setdefault(cls, []).append(comp - {cls})
    return {k: v for k, v in needs.items() if k not in standalone}


def class_literals(js: str) -> list[set[str]]:
    """Like `used_classes`, but keeps each literal's tokens together -- the
    partner has to be in the SAME attribute to have any effect."""
    out: list[set[str]] = []
    for literal in re.findall(r'class="([^"\n]*)"', js):
        stripped = _EXPR.sub("\0", literal)
        if any(c in stripped for c in "${}`"):
            continue
        toks = {t for t in stripped.split() if "\0" not in t}
        if toks:
            out.append(toks)
    return out


def test_modifier_classes_are_written_with_the_class_they_modify(sources):
    js, css = sources
    needs = companion_rules(css)
    offenders: set[str] = set()
    for toks in class_literals(js):
        for tok in toks & needs.keys():
            if not any(partners <= toks for partners in needs[tok]):
                wants = " or ".join(sorted(" ".join(sorted(p)) for p in needs[tok]))
                offenders.add(f".{tok} (needs {wants})")
    assert not offenders, (
        "these classes never appear alone in console.css, so on their own they "
        "style nothing -- the element falls back to a plain block: "
        + ", ".join(sorted(offenders))
    )


def test_every_class_the_console_uses_is_styled(sources):
    js, css = sources
    missing = sorted(used_classes(js) - defined_classes(css) - BEHAVIOUR_ONLY)
    assert not missing, (
        "these classes are used by app.js and have no rule in console.css, so "
        "the browser drops them silently: " + ", ".join(missing)
    )


def test_the_layout_primitives_the_forms_depend_on_exist(sources):
    """Named explicitly because these carry the two long configuration forms.
    Losing one turns a two-column form into a stacked list without failing."""
    _, css = sources
    for cls in ("grid2", "formsec", "field", "switches", "checkgrid",
                "checkgroup", "pickbar", "kv-row", "vm-row"):
        assert re.search(rf"\.{re.escape(cls)}\b", css), f".{cls} has no rule"


def test_the_status_pills_the_tables_use_are_distinguishable(sources):
    """`.pill` alone is the neutral treatment. A status class that resolves to
    nothing therefore reads as 'no particular state' rather than as an error."""
    _, css = sources
    for cls in ("st-ok", "st-warn", "st-neutral"):
        assert re.search(rf"\.{re.escape(cls)}\b", css), f".{cls} has no rule"


def test_the_field_picker_covers_every_field_the_api_knows(sources):
    """The picker groups `KNOWN_FIELDS` for reading. A field the console forgets
    to list cannot be ticked, and its absence looks like a deliberate omission
    rather than a gap -- so the grouping must be total by construction."""
    from veyrs.services.cmdb import KNOWN_FIELDS

    js, _ = sources
    block = js[js.index("const FIELD_GROUPS = ["):js.index("const groupedFields")]
    grouped = set(re.findall(r"'([a-z_]+)'", block))
    missed = [f for f in KNOWN_FIELDS if f not in grouped]
    # `Other` catches anything omitted, so this is not a correctness failure --
    # but a field landing there is a sign the grouping was not revisited.
    assert not missed, (
        "these fields fall into the picker's 'Other' bucket and should be "
        "placed deliberately: " + ", ".join(missed)
    )
