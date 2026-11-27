"""install.sh step 1 on a host with no reachable repositories (0.42.1).

Before 0.42.1 step 1 ran the package manager's refresh first and died when it
failed, so no release could update an offline host, although an update needs
no new package: the previous run installed them all. Now the repositories are
optional when, and only when, every required package is already installed
(read from the package database, never from a repository). A package that is
really missing still stops the run, and the message names it.

These tests run the real shell code from install.sh against fake `rpm` and
`dpkg-query` binaries, so they need neither a distribution nor root.
"""

from __future__ import annotations

import os
import re
import subprocess
from pathlib import Path

import pytest

INSTALLER = Path(__file__).resolve().parents[1] / "install.sh"


@pytest.fixture(scope="module")
def src() -> str:
    return INSTALLER.read_text()


def _function(src: str, name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{.*?^\}}\n", src, re.S | re.M)
    assert m, f"{name}() not found in install.sh"
    return m.group(0)


def _decision(src: str) -> str:
    """The if/elif/else of step 1 that installs or accepts the packages."""
    start = src.index("    if pkg_refresh && pkg_install")
    end = src.index("\n    fi\n", start) + len("\n    fi\n")
    return src[start:end]


def _fake_bin(tmp: Path, installed: set[str]) -> Path:
    b = tmp / "bin"
    b.mkdir()
    listed = " ".join(sorted(installed))
    (b / "rpm").write_text(
        "#!/bin/bash\n"
        '# rpm -q --whatprovides NAME\n'
        f'for p in {listed}; do [ "$p" = "$3" ] && exit 0; done\nexit 1\n'
    )
    (b / "dpkg-query").write_text(
        "#!/bin/bash\n"
        '# dpkg-query -W -f=FMT NAME\n'
        f'for p in {listed}; do [ "$p" = "$3" ] && {{ printf "ii "; exit 0; }}; done\nexit 1\n'
    )
    for f in b.iterdir():
        f.chmod(0o755)
    return b


def _run(src: str, tmp: Path, mgr: str, installed: set[str], pkgs: list[str],
         refresh_ok: bool, install_ok: bool) -> subprocess.CompletedProcess:
    script = "\n".join([
        "set -u",
        f"PKG_MGR={mgr}",
        f"PKGS=({' '.join(pkgs)})",
        f"pkg_refresh() {{ {'return 0' if refresh_ok else 'return 1'}; }}",
        f"pkg_install() {{ {'return 0' if install_ok else 'return 1'}; }}",
        'ok() { echo "OK: $*"; }',
        'warn() { echo "WARN: $*"; }',
        'die() { echo "DIE: $*"; exit 3; }',
        _function(src, "pkgs_missing"),
        _decision(src),
        'echo "REACHED-STEP-2"',
    ])
    env = dict(os.environ, PATH=f"{_fake_bin(tmp, installed)}:{os.environ['PATH']}")
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)


PKGS = ["python311", "python311-pip", "nginx", "redis"]


@pytest.mark.parametrize("mgr", ["zypper", "dnf", "apt-get"])
def test_an_offline_host_with_every_package_continues(src: str, tmp_path: Path, mgr: str) -> None:
    r = _run(src, tmp_path, mgr, set(PKGS), PKGS, refresh_ok=False, install_ok=False)
    assert r.returncode == 0, r.stdout + r.stderr
    assert "REACHED-STEP-2" in r.stdout
    assert "continuing without the repositories" in r.stdout


@pytest.mark.parametrize("mgr", ["zypper", "apt-get"])
def test_an_offline_host_missing_a_package_stops_and_names_it(src: str, tmp_path: Path, mgr: str) -> None:
    r = _run(src, tmp_path, mgr, {"python311", "nginx", "redis"}, PKGS, refresh_ok=False, install_ok=False)
    assert r.returncode == 3, r.stdout + r.stderr
    assert "REACHED-STEP-2" not in r.stdout
    assert "could not install: python311-pip" in r.stdout


def test_a_refresh_that_works_but_an_install_that_fails_is_judged_the_same_way(src: str, tmp_path: Path) -> None:
    # zypper can refresh from a stale cache and then fail to download.
    r = _run(src, tmp_path, "zypper", {"nginx"}, PKGS, refresh_ok=True, install_ok=False)
    assert r.returncode == 3
    assert "python311 python311-pip redis" in r.stdout


def test_an_online_host_installs_as_before(src: str, tmp_path: Path) -> None:
    r = _run(src, tmp_path, "zypper", set(), PKGS, refresh_ok=True, install_ok=True)
    assert r.returncode == 0
    assert "OK: packages installed" in r.stdout
    assert "WARN" not in r.stdout


def test_presence_is_read_from_the_package_database_only(src: str) -> None:
    body = _function(src, "pkgs_missing")
    assert "rpm -q --whatprovides" in body and "dpkg-query -W" in body
    # `apt-get)` is a case label; what must not appear is a package-manager CALL.
    for forbidden in (r"\bzypper\b", r"apt-get\s+(install|update)", r"\bdnf\s", r"\byum\b", r"\bcurl\b"):
        assert not re.search(forbidden, body), f"pkgs_missing() must not touch the network ({forbidden})"
