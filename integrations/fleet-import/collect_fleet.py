#!/usr/bin/env python3
"""Build a VEYRS inventory payload from an existing fleet, over SSH.

Run this on the machine that already has SSH access to the estate; it writes a
JSON file for `veyrs import-inventory` (or `POST /api/v1/assets/inventory/import`,
same shape). Standard library only, so it runs on any box with Python 3.9+ and
no deployment of its own.

Two sources, combined deliberately:

* **A CMDB / project register** gives the *asset*: name, address, business
  context. This is the part a human maintains and a scanner cannot infer.
* **The host's own package manager** gives the *software*, with versions. This
  is the part a human cannot maintain and only the host knows.

An asset register without versions produces exactly zero findings, because
`versions.in_range` refuses to judge an unknown version -- so importing the
register alone looks like a success and changes nothing. That is why this
script goes and asks each host rather than importing a list of names.

It reports only `raw_version`: reducing a distro version to its upstream form
is a rule VEYRS owns (`services.versions.upstream_version`), and a collector
carrying its own copy is a rule that drifts.

Read-only on every host it touches: one `cat /etc/os-release` and one package
query. Hosts that refuse the connection are recorded as skipped, never guessed
at -- an asset with silently empty software would read as "nothing installed".
"""
from __future__ import annotations

import argparse
import json
import re
import sqlite3
import subprocess
import sys
from typing import Any

#: One command, tried in order, so a single round trip covers any distro.
PACKAGE_QUERY = (
    "dpkg-query -W -f='${Package}\\t${Version}\\n' 2>/dev/null"
    " || rpm -qa --qf '%{NAME}\\t%{VERSION}-%{RELEASE}\\n' 2>/dev/null"
    " || apk info -v 2>/dev/null"
)

#: Package names that are pure packaging plumbing. They exist on every Debian
#: host, they are never what an advisory is about, and carrying them multiplies
#: the estate by a few hundred inert rows per host.
NOISE = re.compile(
    r"^(lib.*-(dev|doc|dbg)|.*-(doc|dbgsym|dev)|linux-(headers|image|modules).*|"
    r"fonts-.*|.*-data|locales|tzdata|ca-certificates|debconf.*|dpkg|apt-.*|"
    r"init-system-helpers|install-info|.*-common)$"
)


def ssh(host: str, command: str, *, user: str, timeout: int,
        key: str | None) -> str | None:
    argv = ["ssh", "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=no",
            "-o", f"ConnectTimeout={timeout}", "-o", "LogLevel=ERROR"]
    if key:
        argv += ["-i", key]
    argv += [f"{user}@{host}", command]
    try:
        proc = subprocess.run(argv, capture_output=True, text=True,
                              timeout=timeout + 60)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def parse_packages(output: str, *, keep_noise: bool) -> list[dict[str, str]]:
    items: list[dict[str, str]] = []
    for line in output.splitlines():
        line = line.strip()
        if not line:
            continue
        if "\t" in line:
            name, _, raw = line.partition("\t")
        else:
            # apk's `name-1.2.3-r0`: no delimiter, so this is a heuristic and a
            # package whose name ends version-shaped will be split wrong.
            match = re.match(r"^(?P<name>.+?)-(?P<ver>\d[^-]*(?:-r\d+)?)$", line)
            if not match:
                continue
            name, raw = match.group("name"), match.group("ver")
        name = name.split(":")[0].strip()
        if not name or not raw:
            continue
        if not keep_noise and NOISE.match(name):
            continue
        items.append({"product": name, "raw_version": raw.strip()})
    return items


def os_release(output: str | None) -> tuple[str | None, str | None]:
    if not output:
        return None, None
    values = {}
    for line in output.splitlines():
        key, _, value = line.strip().partition("=")
        if key:
            values[key] = value.strip().strip('"')
    return values.get("NAME") or values.get("ID"), values.get("VERSION_ID")


def read_projects(db_path: str) -> dict[str, dict[str, Any]]:
    """Group the project register by host: an asset is a machine, not a project.

    Several projects share one LXC (three ComfyUI entries on one GPU box). One
    asset per project would triple that host's findings and make remediation
    ambiguous -- which of the three do you patch?
    """
    conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
    conn.row_factory = sqlite3.Row
    rows = conn.execute(
        "SELECT name, server_host, url, category, status, tech_stack, server_path "
        "FROM projects WHERE server_host IS NOT NULL AND TRIM(server_host) != ''"
    ).fetchall()
    conn.close()

    hosts: dict[str, dict[str, Any]] = {}
    for row in rows:
        host = (row["server_host"] or "").strip()
        if not host or host == "local":
            continue
        entry = hosts.setdefault(host, {
            "hostname": host, "ip_addresses": [host], "asset_type": "server",
            "environment": "production", "projects": [], "urls": [],
            "external_id": f"fleet:{host}",
        })
        entry["projects"].append(row["name"])
        if row["url"]:
            entry["urls"].append(row["url"])
    return hosts


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--projects-db", default="/opt/project-index/projects.db")
    parser.add_argument("--out", required=True)
    parser.add_argument("--ssh-user", default="root")
    parser.add_argument("--ssh-key", default=None)
    parser.add_argument("--timeout", type=int, default=10)
    parser.add_argument("--keep-noise", action="store_true",
                        help="keep -dev/-doc/locale packages an advisory never names")
    parser.add_argument("--only", default="", help="comma-separated hosts to include")
    args = parser.parse_args(argv)

    hosts = read_projects(args.projects_db)
    if args.only:
        wanted = {h.strip() for h in args.only.split(",") if h.strip()}
        hosts = {k: v for k, v in hosts.items() if k in wanted}

    payload, skipped = [], []
    for host, entry in sorted(hosts.items()):
        name, version = os_release(
            ssh(host, "cat /etc/os-release", user=args.ssh_user,
                timeout=args.timeout, key=args.ssh_key)
        )
        raw = ssh(host, PACKAGE_QUERY, user=args.ssh_user,
                  timeout=args.timeout, key=args.ssh_key)
        if raw is None:
            skipped.append(host)
            print(f"  {host:16} unreachable - skipped (NOT imported as empty)",
                  file=sys.stderr)
            continue
        items = parse_packages(raw, keep_noise=args.keep_noise)
        projects = entry.pop("projects")
        urls = entry.pop("urls")
        entry.update({
            "name": projects[0] if len(projects) == 1 else f"{host} ({len(projects)} services)",
            "operating_system": name, "os_version": version,
            "exposure": "internet" if any(u.startswith("https://") for u in urls)
                        else "internal",
            "items": items,
        })
        payload.append(entry)
        print(f"  {host:16} {name or '?':22} {len(items):>4} packages "
              f"({', '.join(projects)[:50]})", file=sys.stderr)

    with open(args.out, "w", encoding="utf-8") as handle:
        json.dump({"hosts": payload}, handle, indent=1)
    print(f"\n{len(payload)} hosts written to {args.out}; {len(skipped)} skipped"
          f"{': ' + ', '.join(skipped) if skipped else ''}", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
