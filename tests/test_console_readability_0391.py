"""0.39.1: readable values in Configure and inventory screens.

* Dates never wrap inside a table cell (no-break spaces, not markup).
* Asset criticality is not painted with severity hues.
* Escalation ladders and assignment conditions render as text, not JSON.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
APP = (ROOT / "frontend" / "console" / "app.js").read_text(encoding="utf-8")
CSS = (ROOT / "frontend" / "console" / "console.css").read_text(encoding="utf-8")
EXPORT = (ROOT / "scripts" / "public-export.sh").read_text(encoding="utf-8")


def _fn(name: str) -> str:
    start = APP.index(f"function {name}(")
    return APP[start:APP.index("\n}\n", start)]


def test_dates_use_no_break_spaces():
    assert "const nbsp = s => s.replace(/ /g, '\\u00a0');" in APP
    assert "nbsp(d.toLocaleString(" in _fn("fmtDate")
    assert "nbsp(d.toLocaleDateString(" in _fn("fmtDay")


def test_criticality_never_uses_severity_classes():
    assert "sev-" not in _fn("critPill")
    assert not re.search(r"sevPill\([^)]*criticality", APP), "criticality rendered with sevPill"
    assert len(re.findall(r"critPill\([^)]*criticality\)", APP)) >= 5


def test_policy_json_is_rendered_as_text():
    assert "JSON.stringify(r.steps" not in APP
    assert "JSON.stringify(r.conditions" not in APP
    assert "JSON.stringify(r.weights" not in APP
    assert "ladderSteps(r.steps || r.levels || [])" in APP
    assert "matchChips(r.conditions || r.match || {})" in APP
    for cls in (".ladder ", ".ladder-step", ".cond ", ".pill.crit ", ".crit-mark "):
        assert cls in CSS, cls


def test_export_allows_console_fonts_only_in_their_directory():
    assert 'font/woff2) [[ "$rel" == frontend/console/fonts/*.woff2 ]]' in EXPORT
