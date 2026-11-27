"""docker/veyrs-docker.sh backup: the dump is listed inside the postgres container (0.42.1).

The command verifies a dump by counting its TABLE DATA entries, because a dump
made as the application role is silently truncated. Up to 0.42.0 it counted
with the HOST's pg_restore and hid its error; a Docker host normally has no
PostgreSQL client, so the count was 0 and every good dump was refused as
"TRUNCATED" (measured on openSUSE Leap 15.6: 89 tables in the container, 0 on
the host). It now lists the dump with the container's pg_restore.
"""

from __future__ import annotations

import re
from pathlib import Path

DRIVER = Path(__file__).resolve().parents[1] / "docker" / "veyrs-docker.sh"


def _cmd_backup() -> str:
    src = DRIVER.read_text()
    m = re.search(r"^cmd_backup\(\) \{.*?^\}\n", src, re.S | re.M)
    assert m, "cmd_backup() not found"
    return m.group(0)


def _code(body: str) -> str:
    return "\n".join(line for line in body.splitlines() if not line.lstrip().startswith("#"))


def test_the_dump_is_listed_by_the_container_pg_restore() -> None:
    code = _code(_cmd_backup())
    assert re.search(r'"\$\{COMPOSE\[@\]\}" exec -T postgres pg_restore --list < "\$out"', code), (
        "cmd_backup must list the dump with the postgres container's pg_restore (stdin), "
        "not with a host pg_restore that a Docker host does not have"
    )


def test_no_host_pg_restore_is_used() -> None:
    code = _code(_cmd_backup())
    for line in code.splitlines():
        if "pg_restore" in line:
            assert "exec -T postgres" in line, f"host pg_restore in cmd_backup: {line.strip()}"


def test_the_truncation_threshold_is_still_enforced() -> None:
    code = _code(_cmd_backup())
    assert re.search(r'tables:-0\}" -lt \d+', code), "the TABLE DATA threshold was removed"
