#!/usr/bin/env bash
# Software bill of materials (CycloneDX 1.5, JSON) of the Python lock.
#
#   scripts/sbom.sh                        -> JSON on stdout, from requirements.txt
#   scripts/sbom.sh path/to/lock.txt       -> another lock file
#   scripts/sbom.sh -o veyrs-sbom.cdx.json -> write to a file
#
# One component per pinned package: name, exact version, package URL and the
# sha256 of every published file recorded in the lock (the same hashes
# `--require-hashes` verifies). Standard library only, no network access, so it
# is safe to run in CI and in the release job; list the output in SHA256SUMS to
# have it signed with the release. Output is deterministic for a given lock
# unless SBOM_TIMESTAMP is unset (then the current UTC time is used).
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
OUT=""
LOCK="${ROOT}/requirements.txt"
while [ $# -gt 0 ]; do
  case "$1" in
    -o) OUT="${2:?-o needs a file}"; shift 2 ;;
    -h|--help) sed -n '2,13p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
    *) LOCK="$1"; shift ;;
  esac
done
[ -f "$LOCK" ] || { echo "sbom: no lock file at $LOCK" >&2; exit 1; }

run() {
  python3 -I - "$LOCK" "${ROOT}/pyproject.toml" <<'PY'
import datetime, json, os, re, sys, tomllib, uuid

lock, pyproject = sys.argv[1], sys.argv[2]
text = open(lock, encoding="utf-8").read()

components = []
for block in re.split(r"\n(?=[A-Za-z0-9_.-]+==)", text):
    m = re.match(r"([A-Za-z0-9_.-]+)==([^\s\\;]+)", block)
    if not m:
        continue
    name, version = m.groups()
    norm = re.sub(r"[-_.]+", "-", name).lower()
    hashes = sorted(set(re.findall(r"--hash=sha256:([0-9a-f]{64})", block)))
    comp = {
        "type": "library",
        "bom-ref": f"pkg:pypi/{norm}@{version}",
        "name": name,
        "version": version,
        "purl": f"pkg:pypi/{norm}@{version}",
        "hashes": [{"alg": "SHA-256", "content": h} for h in hashes],
    }
    components.append(comp)
components.sort(key=lambda c: c["name"].lower())

proj = tomllib.load(open(pyproject, "rb"))["project"]
stamp = os.environ.get("SBOM_TIMESTAMP") or datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
# Deterministic serial for a given lock and timestamp: re-running does not churn the file.
serial = uuid.uuid5(uuid.NAMESPACE_URL, f"veyrs:{proj['version']}:{stamp}:{len(components)}")
bom = {
    "bomFormat": "CycloneDX",
    "specVersion": "1.5",
    "serialNumber": f"urn:uuid:{serial}",
    "version": 1,
    "metadata": {
        "timestamp": stamp,
        "tools": {"components": [{"type": "application", "name": "veyrs scripts/sbom.sh"}]},
        "component": {
            "type": "application",
            "bom-ref": "veyrs",
            "name": proj["name"],
            "version": proj["version"],
            "description": proj.get("description", ""),
        },
    },
    "components": components,
}
json.dump(bom, sys.stdout, indent=2)
sys.stdout.write("\n")
PY
}

if [ -n "$OUT" ]; then
  run > "$OUT"
  echo "sbom: $(grep -c '"purl"' "$OUT") components -> $OUT" >&2
else
  run
fi
