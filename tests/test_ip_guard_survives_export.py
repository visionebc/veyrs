"""scripts/ip-guard.sh must keep working after public-export.sh (0.42.1).

The exporter renumbers every private IPv4 literal it finds, the guard's own
source included. Up to 0.42.0 the guard spelled its four block definitions as
literals ("198.19.1.0" with prefix 8, and so on); the export turned them into
198.19.x, so the EXPORTED guard -- the copy publish-images.sh runs on every
image -- refused the definitions it exists to allow, and no image could be
built. The definitions are now compared by octets.
"""

from __future__ import annotations

import ipaddress
import re
import subprocess
from pathlib import Path

import pytest

GUARD = Path(__file__).resolve().parents[1] / "scripts" / "ip-guard.sh"
LITERAL = re.compile(r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d])(?!\.\d)(/\d{1,2})?")
RENUMBERED = [ipaddress.ip_network(n) for n in ("10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10")]


def _guard(tmp: Path, text: str) -> subprocess.CompletedProcess:
    d = tmp / "tree"
    d.mkdir()
    (d / "f.py").write_text(text)
    return subprocess.run(["bash", str(GUARD), str(d)], capture_output=True, text=True)


@pytest.mark.parametrize("definition", ["10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "100.64.0.0/10"])
def test_the_block_definitions_are_allowed(tmp_path: Path, definition: str) -> None:
    r = _guard(tmp_path, f'RANGES = ["{definition}"]\n')
    assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.parametrize("leak", ["198.18.50.31", "198.19.12.4", "198.19.14.10", "198.19.10.1", "198.19.1.0/16", "198.19.9.0/8"])
def test_a_private_address_or_a_wrong_prefix_is_refused(tmp_path: Path, leak: str) -> None:
    r = _guard(tmp_path, f'HOST = "{leak}"\n')
    assert r.returncode == 1, r.stdout + r.stderr
    assert leak in r.stdout


def test_the_guard_has_no_literal_the_export_would_rewrite() -> None:
    """A private literal without its own prefix is renumbered by the export."""
    hits = []
    for n, line in enumerate(GUARD.read_text().splitlines(), 1):
        for m in LITERAL.finditer(line):
            addr = ipaddress.ip_address(m.group(0).split("/")[0])
            if any(addr in net for net in RENUMBERED) and not m.group(1):
                hits.append(f"{n}: {m.group(0)}")
    assert not hits, f"bare private literals in ip-guard.sh (the export rewrites them): {hits}"
