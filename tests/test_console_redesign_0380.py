"""Guards for the 0.38.0 console redesign ("Midnight Ops").

The redesign replaced the presentation layer. These pin the decisions that
would quietly erode: the default theme, metrics as one strip rather than a row
of floating cards, the chart series colours being defined in both themes, the
monotone curve (a smoothed line must never overshoot a measured value), and
the group icons the sidebar now draws.
"""
from __future__ import annotations

import json
import re
import shutil
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "frontend" / "console"


@pytest.fixture(scope="module")
def js() -> str:
    return (CONSOLE / "app.js").read_text(encoding="utf-8")


@pytest.fixture(scope="module")
def css() -> str:
    return re.sub(r"/\*.*?\*/", "", (CONSOLE / "console.css").read_text(encoding="utf-8"), flags=re.DOTALL)


def test_midnight_is_the_default_theme(js):
    html = (CONSOLE / "index.html").read_text(encoding="utf-8")
    assert '<html lang="en" data-theme="dark">' in html, "first paint would flash the other theme"
    assert "applyTheme(localStorage.getItem('veyrs.theme') || 'dark')" in js


@pytest.mark.parametrize("fn", ["execDash", "techDash", "slaDash"])
def test_dashboards_open_with_one_metric_strip(js, fn):
    body = js[js.index(f"function {fn}("):]
    body = body[:body.index("\n}\n")]
    assert '<div class="kpis">' in body, f"{fn} lost its KPI strip"
    assert 'class="card stat' not in body, f"{fn} is back to a row of floating stat cards"
    assert 'class="dash"' in body, f"{fn} lost the 12-column panel grid"


def test_metric_grids_render_as_strips(css):
    assert re.search(r"\.kpis, \.grid:has\(> \.card\.stat\) \{", css)


def test_chart_series_have_one_meaning_each(js):
    for token in ("--chart-risk", "--chart-in", "--chart-out"):
        assert f"var({token})" in js or token in js
    # risk arriving is never drawn in the risk-leaving colour, and vice versa
    flow = js[js.index("function flowColumns("):js.index("/* A ranked list is still a chart")]
    assert "series(inflow, 'line-in'" in flow and "'var(--chart-in)'" in flow
    assert "series(outflow, 'line-out'" in flow and "'var(--chart-out)'" in flow


def test_every_nav_group_has_a_drawn_icon(js):
    icons = set(re.findall(r"^\s{2}([a-z]+): '", js[js.index("const ICONS = {"):js.index("const icon = name")], re.M))
    groups = re.findall(r"\{ group: '([^']+)', key: '[^']+', ico: '([^']+)'", js)
    assert len(groups) == js.count("{ group: '"), "a NAV group has no ico"
    missing = [g for g, i in groups if i not in icons]
    assert not missing, f"groups with an icon name that is not drawn: {missing}"


NODE = shutil.which("node") or "/root/.nvm/versions/node/v20.20.2/bin/node"


@pytest.mark.skipif(not Path(NODE).exists(), reason="node not installed on this host")
def test_the_smoothed_curve_never_overshoots_a_measured_value(js, tmp_path):
    start = js.index("let chartSeq = 0;")
    end = js.index("const niceMax")
    src = js[start:end] + """
const cases = [
  [[0, 50], [10, 90], [20, 10], [30, 60], [40, 60], [50, 0]],
  [[0, 10], [10, 10], [20, 80], [30, 80], [40, 79]],
];
const out = [];
for (const pts of cases) {
  const d = smoothPath(pts);
  const nums = d.replace(/[MC]/g, ' ').trim().split(/[\\s]+/).map(Number);
  const ys = nums.filter((_, i) => i % 2 === 1);
  out.push({ min: Math.min(...ys), max: Math.max(...ys),
             lo: Math.min(...pts.map(p => p[1])), hi: Math.max(...pts.map(p => p[1])) });
}
console.log(JSON.stringify(out));
"""
    f = tmp_path / "smooth.js"
    f.write_text(src, encoding="utf-8")
    res = json.loads(subprocess.run([NODE, str(f)], capture_output=True, text=True, check=True).stdout)
    for r in res:
        # control points of a monotone cubic stay inside the data's range
        assert r["min"] >= r["lo"] - 1e-6 and r["max"] <= r["hi"] + 1e-6, r
