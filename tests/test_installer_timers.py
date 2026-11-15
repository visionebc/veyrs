"""0.35.3: a native install refreshes its intelligence.

Until 0.35.3 `install.sh` enabled the API and the updater and only *named*
the timer units, so a host installed with it scored, at full confidence,
against the CVE/EPSS/KEV data it had on install day -- forever. The intel and
digest timers are now installed and enabled by step 7.

The behavioural tests run the real block out of install.sh under bash with
`run`/`systemctl` stubbed and /etc/systemd/system redirected to a temporary
directory: what is asserted is what the script does, not what it says.
"""
from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
INSTALLER = ROOT / "install.sh"
START = "TIMER_UNITS=("
END = 'info "optional units in infrastructure/systemd/'


@pytest.fixture(scope="module")
def block() -> str:
    src = INSTALLER.read_text()
    assert START in src and END in src, "the timer block moved; update this guard"
    return src[src.index(START):src.index(END)]


def _run(block: str, tmp_path: Path, *, dry_run: int = 0, skip: int = 0,
         states: dict[str, str] | None = None) -> tuple[subprocess.CompletedProcess, str]:
    unit_dir = tmp_path / "units"
    unit_dir.mkdir(exist_ok=True)
    log = tmp_path / "run.log"
    log.write_text("")
    for name, state in (states or {}).items():
        (unit_dir / name).write_text("[Timer]\n")
        (unit_dir / f"{name}.state").write_text(state)
    body = block.replace("/etc/systemd/system", str(unit_dir))
    prelude = f"""
set -euo pipefail
DRY_RUN={dry_run}; SKIP_TIMERS={skip}; VEYRS_DIR='/srv/veyrs-x'
LOG='{log}'; UNIT_DIR='{unit_dir}'; REPO='{ROOT}'
run()  {{ echo "RUN $*" >> "$LOG"; }}
warn() {{ echo "WARN $*" >> "$LOG"; }}
ok()   {{ echo "OK $*" >> "$LOG"; }}
info() {{ echo "INFO $*" >> "$LOG"; }}
die()  {{ echo "DIE $*" >> "$LOG"; exit 9; }}
systemctl() {{
    if [[ $1 == is-enabled ]]; then cat "$UNIT_DIR/$2.state" 2>/dev/null || echo not-found; return 0; fi
    echo "SYSTEMCTL $*" >> "$LOG"
}}
"""
    # The block checks the unit sources under $VEYRS_DIR; point the existence
    # test at the repository while keeping VEYRS_DIR for the path rewrite.
    body = body.replace('[[ -f "$VEYRS_DIR/$rel" ]]', '[[ -f "$REPO/$rel" ]]')
    body = body.replace('"$VEYRS_DIR/$rel" >', '"$REPO/$rel" >')
    proc = subprocess.run(["bash", "-c", prelude + body], capture_output=True, text=True)
    return proc, log.read_text()


def test_a_fresh_install_writes_and_enables_both_timers(block, tmp_path):
    proc, log = _run(block, tmp_path)
    assert proc.returncode == 0, proc.stderr + log
    assert "RUN systemctl enable --now veyrs-intel-sync.timer" in log, log
    assert "RUN systemctl enable --now veyrs-digest.timer" in log, log
    units = tmp_path / "units"
    for name in ("veyrs-intel-sync.service", "veyrs-intel-sync.timer",
                 "veyrs-digest.service", "veyrs-digest.timer"):
        assert (units / name).is_file(), f"{name} was not installed"
    service = (units / "veyrs-intel-sync.service").read_text()
    assert "ExecStart=/srv/veyrs-x/scripts/sync-intel.sh" in service, \
        "the unit paths were not rewritten for an install outside /opt/veyrs"


def test_a_rerun_leaves_an_operator_disabled_timer_off(block, tmp_path):
    """The in-product updater re-runs install.sh. On a secondary node the intel
    timer is installed-but-disabled on purpose (it is a singleton); a re-run
    that re-enabled it would have two nodes pulling the same feeds."""
    proc, log = _run(block, tmp_path, states={"veyrs-intel-sync.timer": "disabled"})
    assert proc.returncode == 0, proc.stderr + log
    assert "enable --now veyrs-intel-sync.timer" not in log, log
    assert "RUN systemctl enable --now veyrs-digest.timer" in log, log
    assert "WARN veyrs-intel-sync.timer is disabled" in log, log


def test_a_dry_run_writes_no_unit(block, tmp_path):
    proc, log = _run(block, tmp_path, dry_run=1)
    assert proc.returncode == 0, proc.stderr + log
    assert not list((tmp_path / "units").glob("veyrs-*")), "--dry-run wrote unit files"
    # `run` is the dry-run guard; every state change goes through it
    assert "RUN systemctl enable --now veyrs-intel-sync.timer" in log
    assert "SYSTEMCTL" not in log, "a systemctl call bypassed run()"


def test_skip_timers_installs_nothing_and_says_why(block, tmp_path):
    proc, log = _run(block, tmp_path, skip=1)
    assert proc.returncode == 0, proc.stderr + log
    assert "enable --now" not in log
    assert "will not refresh" in log


def test_the_flag_is_parsed_and_documented():
    src = INSTALLER.read_text()
    assert re.search(r"--skip-timers\)\s+SKIP_TIMERS=1; shift ;;", src)
    assert "  --skip-timers " in src, "--skip-timers is missing from --help"


def test_the_shipped_intel_units_match_what_production_runs():
    """The repo copy was a daily 03:30 timer with no OOMPolicy while the nodes
    ran an hourly tick with OOMPolicy=continue: an install from the repo would
    have reintroduced the three-night KEV outage of August."""
    timer = (ROOT / "integrations/systemd/veyrs-intel-sync.timer").read_text()
    service = (ROOT / "integrations/systemd/veyrs-intel-sync.service").read_text()
    assert re.search(r"(?m)^OnCalendar=hourly$", timer)
    assert re.search(r"(?m)^Persistent=true$", timer)
    assert re.search(r"(?m)^OOMPolicy=continue$", service)
    assert re.search(r"(?m)^ExecStart=/opt/veyrs/scripts/sync-intel.sh$", service)
