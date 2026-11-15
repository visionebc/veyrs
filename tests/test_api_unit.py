"""The API unit must be able to start on a git-deployed node.

var/ content is untracked since 0.35.2 (backups hold .env and a full dump).
Under ProtectSystem=strict a non-optional ReadWritePaths entry that does not
exist aborts the start with 226/NAMESPACE -- which happened on veyrs-app-2
when git removed the last tracked file under var/ -- and systemd 252 builds
the namespace even for an `ExecStartPre=+`, so the directory has to come from
the checkout itself: var/.gitkeep is tracked, everything else is ignored.
"""
from __future__ import annotations

import pathlib
import subprocess

ROOT = pathlib.Path(__file__).resolve().parents[1]
UNIT = ROOT / "infrastructure/systemd/veyrs-api.service"


def test_the_writable_path_is_the_tracked_var_directory():
    lines = [l.strip() for l in UNIT.read_text().splitlines() if l.strip() and not l.strip().startswith("#")]
    mandatory = [l.split("=", 1)[1] for l in lines
                 if l.startswith("ReadWritePaths=") and not l.split("=", 1)[1].startswith("-")]
    assert mandatory == ["/opt/veyrs/var"], mandatory
    assert (ROOT / "var/.gitkeep").is_file()


def test_only_the_placeholder_is_tracked_under_var():
    ignore = (ROOT / ".gitignore").read_text().splitlines()
    assert "/var/*" in ignore and "!/var/.gitkeep" in ignore
    if (ROOT / ".git").exists():
        tracked = subprocess.run(["git", "-C", str(ROOT), "ls-files", "var"],
                                 capture_output=True, text=True, check=True).stdout.split()
        assert tracked in ([], ["var/.gitkeep"]), tracked
        probe = subprocess.run(["git", "-C", str(ROOT), "check-ignore", "-q", "var/backups/x/env"])
        assert probe.returncode == 0, "a backup under var/ would not be ignored"
