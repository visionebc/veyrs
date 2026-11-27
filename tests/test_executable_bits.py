"""Scripts operators run as ./name keep their executable bit (0.39.1).

0.37.0 (cfa2566) committed install.sh as 100644. Every documented
`sudo ./install.sh` became "Permission denied", and publish-github.sh refused
the export ("install.sh missing"), which is what had kept the offline publish
harness red since then. The mode lives in git, so this reads the index; outside
a git checkout (a plain copy or tarball) it falls back to the filesystem mode
bits, so the guard never silently skips (TD-64).
"""
from __future__ import annotations

import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
MUST_BE_EXECUTABLE = ["install.sh", "scripts/public-export.sh", "scripts/publish-github.sh",
                      "scripts/test-publish-github.sh", "scripts/test.sh", "scripts/ci.sh",
                      "scripts/publish-sites.sh", "scripts/migrate-service-user.sh",
                      "scripts/backup.sh", "scripts/restore.sh", "scripts/veyrs-updater.sh",
                      "scripts/veyrs-offline-update.sh"]


def _modes() -> dict[str, str]:
    """Map path -> "100755"/"100644": git's index first, os.stat for the rest."""
    modes: dict[str, str] = {}
    try:
        out = subprocess.run(["git", "-C", str(ROOT), "ls-files", "-s", *MUST_BE_EXECUTABLE],
                             capture_output=True, text=True, check=True).stdout
        modes = {line.split()[3]: line.split()[0] for line in out.splitlines()}
    except (OSError, subprocess.CalledProcessError):
        pass
    for rel in MUST_BE_EXECUTABLE:
        p = ROOT / rel
        if rel not in modes and p.is_file():  # plain copy, or not yet added to git
            modes[rel] = "100755" if p.stat().st_mode & stat.S_IXUSR else "100644"
    return modes


@pytest.mark.parametrize("path", MUST_BE_EXECUTABLE)
def test_script_is_executable_in_git(path: str) -> None:
    modes = _modes()
    assert path in modes, f"{path} is not tracked"
    assert modes[path] == "100755", f"{path} is {modes[path]} in git; run git update-index --chmod=+x {path}"
