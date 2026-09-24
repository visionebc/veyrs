"""Phase 47 -- the dialog that explains the 5x5, and the ladder it must not copy.

A 1-5 picker with no anchors is five numbers, not a scale: one assessor's "4"
is another's "2" and the register stops being comparable, which is the whole
reason the score is computed rather than typed. The dialog is the fix.

What these tests defend is narrower and more important than the copy:

1. the console renders the bands from the map the API publishes (`band_of`),
   never from a second ladder written in JavaScript. Two sets of boundaries is
   two different registers, and the console's copy would go wrong SILENTLY the
   day somebody moves a boundary in `models/risk_register.risk_band` -- the
   heat map would still render, in the wrong colours, agreeing with nothing;
2. `band_of` keeps covering the whole 1..25 product space. It shipped in 0.31.0
   with no consumer at all, and an unused field is the easiest one to drop;
3. the explanation is reachable by people who can only READ the register -- an
   auditor, a board member, the team named in a RACI seat. They are the ones
   most likely to be looking at a 12 they did not assign.
"""
from __future__ import annotations

import pathlib
import re

import pytest

from veyrs.models.risk_register import RISK_BANDS, risk_band

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "frontend/console/app.js"


@pytest.fixture(scope="module")
def js() -> str:
    if not CONSOLE.exists():  # pragma: no cover - bare checkout
        pytest.skip("the console is not present")
    return CONSOLE.read_text(encoding="utf-8")


def matrix_region(js: str) -> str:
    """The source of the dialog, isolated from the rest of the console.

    Scoped deliberately: `>= 15` is an ordinary number elsewhere in a 7000-line
    file, and a whole-file search for the boundaries would be a guard that
    cries wolf until somebody deletes it.
    """
    start = js.index("const RISK_LEVEL_ANCHORS")
    end = js.index("route('risks'", start)
    return js[start:end]


# --- the ladder has ONE home ---------------------------------------------


def test_the_console_renders_the_bands_from_the_api_not_from_a_copy(js):
    region = matrix_region(js)
    assert "band_of" in region, (
        "the dialog must read the 1..25 -> band map from /risks/meta; without it "
        "the console is inventing its own boundaries"
    )
    assert "riskBandRanges" in region, (
        "the Bands table must be DERIVED from that map, so a moved boundary "
        "reflows the table and the heat map together"
    )


def test_the_console_does_not_restate_the_band_thresholds(js):
    """The mutation this kills: `n >= 15 ? 'critical' : ...` written in JS.

    Matched as a boundary in a comparison or a range literal, not as the bare
    number: the dialog legitimately prints 15 and 25 as scores in cells.
    """
    region = matrix_region(js)
    boundaries = sorted({
        n for n in range(2, 26) if risk_band(n) != risk_band(n - 1)
    })
    assert boundaries, "risk_band has no boundaries at all -- read that first"

    offenders = []
    for n in boundaries:
        for hit in re.finditer(rf"[<>]=?\s*{n}\b|\b{n}\s*[<>]=?", region):
            window = region[max(0, hit.start() - 90): hit.end() + 90].lower()
            if any(band in window for band in RISK_BANDS):
                offenders.append((n, hit.group(0).strip()))
    assert not offenders, (
        "the band ladder is restated in the console: "
        f"{offenders}. It has one home -- `risk_band` in the model, published "
        "as `band_of`. A second copy does not fail, it disagrees."
    )


# --- the contract the dialog depends on ----------------------------------


def test_meta_publishes_the_whole_ladder_and_agrees_with_the_model(client, admin_a):
    response = client.get("/api/v1/risks/meta", headers=admin_a)
    assert response.status_code == 200, response.text
    band_of = response.json().get("band_of")

    assert band_of, "band_of is gone -- the heat map would draw 25 blank cells"
    assert {str(n) for n in range(1, 26)} == set(band_of), (
        "band_of must cover every 1..25 product; a gap is a cell the console "
        "cannot colour and renders as a dash"
    )
    mismatched = {k: v for k, v in band_of.items() if v != risk_band(int(k))}
    assert not mismatched, f"the published ladder disagrees with risk_band: {mismatched}"


def test_the_ladder_is_contiguous_so_the_bands_table_reads_as_ranges(client, admin_a):
    """Each band must own one unbroken run of scores.

    Not decoration: `riskBandRanges` collapses the map into ranges, so a band
    that appeared in two disjoint runs would silently print twice.
    """
    band_of = client.get("/api/v1/risks/meta", headers=admin_a).json()["band_of"]
    runs: list[str] = []
    for n in range(1, 26):
        band = band_of[str(n)]
        if not runs or runs[-1] != band:
            runs.append(band)
    assert len(runs) == len(set(runs)), f"a band is split across the scale: {runs}"


# --- who can open it ------------------------------------------------------


def test_the_explanation_is_not_gated_on_the_write_permission(js):
    """The reader who did not assign the score is the one who needs the key."""
    head = js[js.index('<div class="page-actions">', js.index("route('risks'")):]
    head = head[: head.index("</div>")]
    assert "data-risk-matrix" in head, "the Risk Register page must offer the dialog"

    opener = head[: head.index("data-risk-matrix")]
    assert "riskregister:write" not in opener, (
        "the scoring key is gated behind the write permission; an auditor can "
        "read a 12 and has no way to find out what it means"
    )


def test_the_dialog_closes_with_a_word_that_is_not_cancel(js):
    """A reference table has nothing to cancel, and the button must not say so."""
    region = matrix_region(js)
    assert re.search(r"dismiss:\s*'Close'", region), (
        "the explanation modal must pass an explicit dismiss label; the default "
        "'Cancel' reads as discard on a dialog that cannot lose anything"
    )


# --- the trap this screen actually had ------------------------------------


def test_the_heat_map_cell_cannot_override_the_band_colour():
    """`.rm-cell` must not declare background, colour or border-COLOUR.

    The cells carry the same `.sev-*` classes as the band pills, and `.sev-*`
    sits EARLIER in the stylesheet at the same specificity. A shorthand
    `border: 1px solid transparent` here -- the obvious thing to write, and
    what `.pill` itself does -- wins on source order and flattens all 25 cells
    to one colour. The map still renders. It is just wrong, and silently.
    """
    css = (ROOT / "frontend/console/console.css").read_text(encoding="utf-8")
    block = re.search(r"\.rm-cell\s*\{([^}]*)\}", css)
    assert block, ".rm-cell has no rule at all -- the heat map has no layout"

    declared = {
        d.split(":", 1)[0].strip()
        for d in block.group(1).split(";") if ":" in d
    }
    forbidden = declared & {"background", "background-color", "color", "border", "border-color"}
    assert not forbidden, (
        f".rm-cell declares {sorted(forbidden)}, which comes from `.sev-*` and "
        "is defined earlier in this file. Use border-width/border-style only."
    )
