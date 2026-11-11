"""scripts/sync-intel.sh runs the feeds that `veyrs intel-due` says are due.

The defect this pins (v0.21.0 -> 0.32.4): `intel-due --quiet` prints one feed
per LINE, and the script matched them with `case " ${due} " in *" nvd "*`,
which needs SPACES around each name. No feed ever matched. Every tick printed
four `DUE` lines, ran none of them, ran the SLA sweep and exited 0 -- so the
timer stayed green while production's CVE/EPSS/KEV/CWE data stopped ageing
forward for 45 days.

The script is executed for real here, against a stub interpreter that answers
`intel-due` and records every `sync-*` call. No database, no network.
"""

from __future__ import annotations

import os
import shutil
import stat
import subprocess
from pathlib import Path

import pytest

REPO = Path(__file__).resolve().parents[1]
SCRIPT = REPO / "scripts" / "sync-intel.sh"

STUB = r"""#!/usr/bin/env bash
# Stub for "$PY -m veyrs <command> [args]".
shift 2
cmd="$1"; shift || true
case "$cmd" in
    intel-due)
        if [ "${1:-}" = "--quiet" ]; then
            for f in ${STUB_DUE}; do echo "$f"; done   # one per line, like cli.py
        else
            for f in cwe nvd epss kev; do
                case " ${STUB_DUE} " in
                    *" $f "*) echo "DUE  $f   stub" ;;
                    *)        echo "skip $f   stub" ;;
                esac
            done
        fi ;;
    sync-*)
        echo "${cmd#sync-}" >> "${STUB_LOG}"
        [ "${cmd#sync-}" = "${STUB_FAIL:-}" ] && exit 1
        exit 0 ;;
    run-sla)
        echo "run-sla" >> "${STUB_LOG}" ;;
esac
exit 0
"""


@pytest.fixture()
def root(tmp_path: Path) -> Path:
    (tmp_path / "scripts").mkdir()
    (tmp_path / "backend").mkdir()
    (tmp_path / "venv" / "bin").mkdir(parents=True)
    shutil.copy2(SCRIPT, tmp_path / "scripts" / "sync-intel.sh")
    py = tmp_path / "venv" / "bin" / "python"
    py.write_text(STUB)
    py.chmod(py.stat().st_mode | stat.S_IXUSR)
    return tmp_path


def run(root: Path, due: str, *args: str, fail: str = "") -> tuple[int, list[str], str]:
    log = root / "calls.log"
    env = dict(os.environ, STUB_DUE=due, STUB_LOG=str(log), STUB_FAIL=fail)
    p = subprocess.run(
        ["bash", str(root / "scripts" / "sync-intel.sh"), *args],
        env=env, capture_output=True, text=True, timeout=30,
    )
    calls = log.read_text().split() if log.exists() else []
    return p.returncode, calls, p.stdout + p.stderr


def test_every_due_feed_runs_in_the_fixed_order(root: Path) -> None:
    rc, calls, out = run(root, "kev epss nvd cwe")
    assert calls == ["cwe", "nvd", "epss", "kev", "run-sla"], out
    assert rc == 0


@pytest.mark.parametrize("due,expected", [
    ("nvd", ["nvd"]),
    ("cwe", ["cwe"]),          # first in the list
    ("kev", ["kev"]),          # last in the list
    ("epss kev", ["epss", "kev"]),
])
def test_only_the_due_feeds_run(root: Path, due: str, expected: list[str]) -> None:
    rc, calls, out = run(root, due)
    assert calls == expected + ["run-sla"], out
    assert rc == 0


def test_nothing_due_still_runs_the_sla_sweep(root: Path) -> None:
    rc, calls, out = run(root, "")
    assert calls == ["run-sla"], out
    assert rc == 0


def test_full_run_ignores_the_schedule(root: Path) -> None:
    rc, calls, out = run(root, "", "--full-run")
    assert calls == ["cwe", "nvd", "epss", "kev", "run-sla"], out


def test_a_failed_feed_does_not_stop_the_others_and_fails_the_tick(root: Path) -> None:
    rc, calls, out = run(root, "cwe nvd epss kev", fail="nvd")
    assert calls == ["cwe", "nvd", "epss", "kev", "run-sla"], out
    assert rc == 1
    assert "!!! sync-nvd failed" in out


def test_every_due_line_is_followed_by_its_sync(root: Path) -> None:
    """The log invariant an operator reads: a feed printed as DUE has a
    `=== sync-<feed>` header after it. Its absence is exactly what the
    production journal showed for 45 days."""
    _, _, out = run(root, "cwe nvd epss kev")
    for feed in ("cwe", "nvd", "epss", "kev"):
        assert f"DUE  {feed}" in out
        assert f"=== sync-{feed} " in out, out
