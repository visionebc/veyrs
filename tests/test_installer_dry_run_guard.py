"""install.sh: --dry-run must survive a host where nothing is installed yet.

A dry run prints what step 1 WOULD install; it does not install it. Every
later step therefore looks at a host that is missing the very things the plan
would provide, and each one has to say so instead of refusing. Three steps
already did that (nginx's vhost directory, psql in step 2, the secret
generator). Step 1b did not: its guard asked whether a python3 was PRESENT
rather than whether one was USABLE.

That distinction is not academic. A pristine Debian 12 or Ubuntu 24.04 ships
a python3 that is new enough and cannot build a virtualenv, because
python3-venv is a separate package that step 1 installs. The presence test saw
the interpreter, skipped the escape hatch and let resolve_python() refuse, so
`install.sh --dry-run` exited 2 on exactly the hosts a dry run exists for. It
passed on openSUSE only by accident: there is no /usr/bin/python3 there at
all, so a presence test happened to be right for the wrong reason.

These are source-level guards. The behavioural proof is veyrs-dryrun-test.sh,
which rolls a container back to a pristine snapshot and asserts a dry run
exits 0 and leaves the host byte-identical.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parents[1] / "install.sh"


@pytest.fixture(scope="module")
def src() -> str:
    return INSTALLER.read_text()


def _step_1b(src: str) -> str:
    """The step 1b block, from its step() call to the next step()."""
    start = src.index('step "1b. Python interpreter"')
    nxt = src.index('step "2.', start)
    return src[start:nxt]


def test_the_dry_run_escape_hatch_asks_whether_python_is_usable(src: str) -> None:
    block = _step_1b(src)
    assert "dryrun_python_usable" in block, (
        "step 1b's dry-run guard no longer calls dryrun_python_usable(). If it "
        "went back to `have python3`, --dry-run refuses on a pristine "
        "Debian/Ubuntu: the interpreter is there, the venv module is not."
    )
    assert not re.search(r"DRY_RUN -eq 1 \]\] && ! have python3", block), (
        "the presence-based guard is back in step 1b"
    )


def test_the_escape_hatch_does_not_fire_when_there_is_no_step_1(src: str) -> None:
    block = _step_1b(src)
    guard = next(line for line in block.splitlines() if "dryrun_python_usable" in line and line.startswith("if "))
    assert "SKIP_SYSTEM_PACKAGES -eq 0" in guard, (
        "--skip-system-packages means no step 1 will install an interpreter, so "
        "that host IS the final host and an unusable python must still be a "
        "refusal rather than a shrug."
    )


def test_dryrun_python_usable_probes_every_candidate_with_py_ok(src: str) -> None:
    start = src.index("dryrun_python_usable() {")
    body = src[start : src.index("\n}\n", start)]
    assert "PY_CANDIDATES[@]" in body, (
        "the helper must walk PY_CANDIDATES, which is per-family. Hardcoding "
        "python3/python3.11 is what shipped, and SUSE has neither name."
    )
    assert "py_ok" in body, (
        "usability is py_ok's question — version floor AND a stdlib that can "
        "actually reach ensurepip. Testing `command -v` alone re-introduces "
        "the bug this helper exists to fix."
    )
    assert 'if [[ -n "$PY_BIN" ]]' in body, (
        "an explicit --python must be honoured here too, or the helper would "
        "answer about a different interpreter than the one that will be used."
    )


def test_py_ok_still_separates_too_old_from_broken_stdlib(src: str) -> None:
    start = src.index("py_ok() {")
    body = src[start : src.index("\n}\n", start)]
    assert "return 1" in body and "return 2" in body, (
        "py_ok's two failure codes are what let resolve_python() tell "
        "'no Python' from 'a Python whose stdlib is broken'. They send the "
        "operator to different commands."
    )


def test_every_dry_run_escape_hatch_is_still_in_place(src: str) -> None:
    """The other three steps that must not refuse on a not-yet-installed host."""
    for marker, why in (
        ("NGINX_SITE=\"(not decided in a dry run)\"", "nginx vhost directory"),
        ("psql is not installed yet", "step 2's psql probe"),
        ("<a generated %s-byte secret>", "gen_secret without an interpreter"),
    ):
        assert marker in src, f"the dry-run escape hatch for {why} is gone"
