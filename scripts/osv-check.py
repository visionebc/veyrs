#!/usr/bin/env python3
"""Check every pinned package against the public OSV database.

Standard library only. Reads exact pins (``name==version``) from a requirements
file (default: requirements.txt next to this script's repository root), sends
them to https://api.osv.dev/v1/querybatch (package name, ecosystem and version
only), fetches each advisory for its summary and fix versions, and prints one
line per advisory.

Exit status: 0 = no advisories, 1 = at least one advisory, 2 = the service
could not be reached or the input is unusable (a check that cannot run must not
pass silently).

    scripts/osv-check.py                      # requirements.txt
    scripts/osv-check.py path/to/lock.txt
    scripts/osv-check.py --json               # machine-readable report
    scripts/osv-check.py --ignore GHSA-xxxx   # accepted advisory (repeatable)
    scripts/osv-check.py pkg==1.2.3 other==4  # ad-hoc pins (what-if upgrade)
"""
from __future__ import annotations

import argparse
import datetime
import json
import re
import sys
import urllib.error
import urllib.request
from pathlib import Path

OSV = "https://api.osv.dev/v1"
PIN = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?==([^\s;\\#]+)")


def parse_pins(text: str) -> list[tuple[str, str]]:
    pins = []
    for line in text.splitlines():
        m = PIN.match(line.strip())
        if m:
            pins.append((m.group(1), m.group(2)))
    return pins


def _post(path: str, body: dict) -> dict:
    req = urllib.request.Request(
        OSV + path, data=json.dumps(body).encode(),
        headers={"Content-Type": "application/json", "User-Agent": "veyrs-osv-check"},
    )
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310 - fixed https host
        return json.load(resp)


def _get(path: str) -> dict:
    req = urllib.request.Request(OSV + path, headers={"User-Agent": "veyrs-osv-check"})
    with urllib.request.urlopen(req, timeout=30) as resp:  # noqa: S310
        return json.load(resp)


def fixed_versions(vuln: dict, name: str) -> list[str]:
    out: list[str] = []
    for aff in vuln.get("affected", []):
        if aff.get("package", {}).get("name", "").lower().replace("_", "-") != name.lower().replace("_", "-"):
            continue
        for rng in aff.get("ranges", []):
            out += [e["fixed"] for e in rng.get("events", []) if "fixed" in e]
    return sorted(set(out))


def check(pins: list[tuple[str, str]], ignore: set[str]) -> list[dict]:
    queries = [{"package": {"name": n, "ecosystem": "PyPI"}, "version": v} for n, v in pins]
    found: list[dict] = []
    for i in range(0, len(queries), 100):  # querybatch accepts large batches; stay modest
        chunk = queries[i:i + 100]
        res = _post("/querybatch", {"queries": chunk})["results"]
        for j, ((name, ver), r) in enumerate(zip(pins[i:i + 100], res)):
            ids = [v["id"] for v in r.get("vulns", [])]
            while r.get("next_page_token"):  # paginated results
                r = _post("/querybatch", {"queries": [dict(chunk[j], page_token=r["next_page_token"])]})["results"][0]
                ids += [v["id"] for v in r.get("vulns", [])]
            for vid in ids:
                if vid in ignore:
                    continue
                vuln = _get("/vulns/" + vid)
                aliases = set(vuln.get("aliases", []))
                if aliases & ignore:
                    continue
                sev = (vuln.get("database_specific") or {}).get("severity", "UNKNOWN")
                found.append({
                    "package": name, "version": ver, "id": vid,
                    "aliases": sorted(aliases), "severity": sev,
                    "summary": vuln.get("summary", ""),
                    "fixed": fixed_versions(vuln, name),
                })
    return found


def main(argv: list[str]) -> int:
    ap = argparse.ArgumentParser(description=__doc__.split("\n")[0])
    ap.add_argument("inputs", nargs="*", help="a requirements file, or name==version pins")
    ap.add_argument("--json", action="store_true", help="print a JSON report")
    ap.add_argument("--ignore", action="append", default=[], metavar="ID",
                    help="accepted advisory id (GHSA/PYSEC/CVE); repeatable")
    args = ap.parse_args(argv)

    root = Path(__file__).resolve().parent.parent
    pins: list[tuple[str, str]] = []
    if not args.inputs:
        pins = parse_pins((root / "requirements.txt").read_text())
    for item in args.inputs:
        if "==" in item:
            pins += parse_pins(item)
        else:
            pins += parse_pins(Path(item).read_text())
    if not pins:
        print("osv-check: no pinned packages found", file=sys.stderr)
        return 2

    try:
        found = check(pins, set(args.ignore))
    except (urllib.error.URLError, OSError, ValueError, KeyError) as exc:
        print(f"osv-check: OSV query failed: {exc}", file=sys.stderr)
        return 2

    today = datetime.date.today().isoformat()
    if args.json:
        print(json.dumps({"date": today, "packages": len(pins), "advisories": found}, indent=2))
    else:
        for f in sorted(found, key=lambda x: (x["package"], x["id"])):
            fix = ",".join(f["fixed"]) or "no fix listed"
            print(f"{f['package']}=={f['version']}  {f['id']}  {f['severity']}  fixed in: {fix}  {f['summary'][:80]}")
        affected = len({f["package"] for f in found})
        print(f"osv-check {today}: {len(pins)} pins, {len(found)} advisories in {affected} packages")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
