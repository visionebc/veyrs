"""public-export.sh binary guard on a host whose file(1) predates woff2 (0.42.1).

The guard admits the console's self-hosted fonts by MIME type. file(1) before
5.33 has no woff2 magic and answers application/octet-stream, so on openSUSE
Leap 15 / SLES 15 (file 5.32) -- the image builder -- every font was refused
and no image could be built. The fonts are now also admitted by their own
`wOF2` signature, under the same directory rule; any other octet-stream is
still refused.

The test runs the real guard block from the script against a fake `file`.
"""

from __future__ import annotations

import os
import subprocess
from pathlib import Path

import pytest

EXPORT = Path(__file__).resolve().parents[1] / "scripts" / "public-export.sh"
WOFF2 = b"wOF2" + b"\x00" * 60


@pytest.fixture(scope="module")
def guard() -> str:
    src = EXPORT.read_text()
    start = src.index("bfail=0\n")
    end = src.index("[[ $bfail -eq 0 ]]", start)
    return src[start:end]


def _run(guard: str, tmp: Path, files: dict[str, bytes], mime: str) -> subprocess.CompletedProcess:
    out = tmp / "out"
    for rel, data in files.items():
        f = out / rel
        f.parent.mkdir(parents=True, exist_ok=True)
        f.write_bytes(data)
    b = tmp / "bin"
    b.mkdir()
    fake = b / "file"
    # An old file(1): every binary is octet-stream, whatever it is.
    fake.write_text(f'#!/bin/bash\n[ "$2" = "--mime-type" ] && {{ echo {mime}; exit 0; }}\necho data\n')
    fake.chmod(0o755)
    script = f'OUT="{out}"; C_RED=; C_RESET=\n{guard}\necho "BFAIL=$bfail"\n'
    env = dict(os.environ, PATH=f"{b}:{os.environ['PATH']}")
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env)


def test_fonts_pass_when_file_says_octet_stream(guard: str, tmp_path: Path) -> None:
    r = _run(guard, tmp_path, {"frontend/console/fonts/inter-bold.woff2": WOFF2}, "application/octet-stream")
    assert "BFAIL=0" in r.stdout, r.stdout + r.stderr


def test_an_octet_stream_that_is_not_woff2_is_still_refused(guard: str, tmp_path: Path) -> None:
    r = _run(guard, tmp_path, {"frontend/console/fonts/dump.woff2": b"PGDMP" + b"\x00" * 40}, "application/octet-stream")
    assert "BFAIL=1" in r.stdout
    assert "unexpected binary: frontend/console/fonts/dump.woff2" in r.stdout


def test_a_woff2_outside_the_fonts_directory_is_still_refused(guard: str, tmp_path: Path) -> None:
    r = _run(guard, tmp_path, {"site/static/inter.woff2": WOFF2}, "application/octet-stream")
    assert "BFAIL=1" in r.stdout
    assert "site/static/inter.woff2" in r.stdout


def test_a_modern_file_still_uses_the_font_rule(guard: str, tmp_path: Path) -> None:
    r = _run(guard, tmp_path, {"frontend/console/fonts/inter-bold.woff2": WOFF2}, "font/woff2")
    assert "BFAIL=0" in r.stdout
