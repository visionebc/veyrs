#!/usr/bin/env bash
# Regenerate requirements.txt from the venv this node actually runs.
#
# The lock is generated, never hand-edited: a hand-edited lock is a lock that
# lies. Change pyproject.toml, install, run the suite, then run this.
#
# Every pin is written with the sha256 of every file PyPI publishes for that
# exact version (wheels for each platform plus the sdist), so
# `pip install --require-hashes -r requirements.txt` accepts the right file on
# any supported platform and refuses a re-uploaded or substituted one. This
# needs network access to pypi.org. Python side is stdlib only.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${ROOT}/venv/bin/python"
PIP="${ROOT}/venv/bin/pip"

[ -x "$PIP" ] || { echo "no venv at ${ROOT}/venv" >&2; exit 1; }

TMP="$(mktemp)"
FROZEN="$(mktemp)"
trap 'rm -f "$TMP" "$FROZEN"' EXIT

# pip/setuptools/wheel are bootstrap, not dependencies: pinning them makes
# `pip install -r` fight the installer that is running it.
"$PIP" freeze | grep -viE '^(pip|setuptools|wheel)==' | sort -f > "$FROZEN"

{
  echo "# VEYRS dependency lock — the exact set a production node runs."
  echo "#"
  echo "# Regenerate:  ./scripts/freeze-deps.sh   (needs network: it fetches the hashes)"
  echo "# Install:     venv/bin/pip install --require-hashes -r requirements.txt"
  echo "# Audit:       scripts/osv-check.py       SBOM: scripts/sbom.sh"
  echo "#"
  echo "# Direct dependencies and the reasoning behind them live in pyproject.toml."
  echo "# This file is the FULL resolved graph, transitive packages included, so a new"
  echo "# app node (a3, a disaster-recovery rebuild, a laptop) gets byte-identical"
  echo "# software instead of whatever PyPI resolves to that morning. Every pin carries"
  echo "# the sha256 of each published file of that version (--require-hashes)."
  echo "#"
  echo "# Python $("$PY" -V | cut -d' ' -f2)"
  "$PY" - "$FROZEN" <<'PY'
import json, sys, urllib.request

for line in open(sys.argv[1]):
    line = line.strip()
    if not line or line.startswith(("#", "-")):
        continue
    name, _, version = line.partition("==")
    url = f"https://pypi.org/pypi/{name}/{version}/json"
    try:
        with urllib.request.urlopen(url, timeout=30) as resp:
            files = json.load(resp)["urls"]
    except Exception as exc:  # a lock without hashes would be a silent downgrade
        sys.exit(f"freeze-deps: cannot fetch hashes for {name}=={version}: {exc}")
    digests = sorted({f["digests"]["sha256"] for f in files})
    if not digests:
        sys.exit(f"freeze-deps: PyPI lists no files for {name}=={version}")
    print(f"{line} \\")
    print(" \\\n".join(f"    --hash=sha256:{d}" for d in digests))
PY
} > "$TMP"

if [ -f "${ROOT}/requirements.txt" ] && diff -q "$TMP" "${ROOT}/requirements.txt" >/dev/null; then
  echo "requirements.txt already current ($(grep -c '^[A-Za-z]' "$TMP") packages)"
  exit 0
fi

cp "$TMP" "${ROOT}/requirements.txt"
echo "requirements.txt regenerated ($(grep -c '^[A-Za-z]' "${ROOT}/requirements.txt") packages, hashed)"
echo "commit it together with pyproject.toml; then run scripts/osv-check.py."
