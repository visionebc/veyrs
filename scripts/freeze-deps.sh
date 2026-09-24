#!/usr/bin/env bash
# Regenerate requirements.txt from the venv this node actually runs.
#
# The lock is generated, never hand-edited: a hand-edited lock is a lock that
# lies. Change pyproject.toml, install, run the suite, then run this.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
PY="${ROOT}/venv/bin/python"
PIP="${ROOT}/venv/bin/pip"

[ -x "$PIP" ] || { echo "no venv at ${ROOT}/venv" >&2; exit 1; }

TMP="$(mktemp)"
trap 'rm -f "$TMP"' EXIT

{
  echo "# VEYRS dependency lock — the exact set a production node runs."
  echo "#"
  echo "# Regenerate:  ./scripts/freeze-deps.sh"
  echo "# Install:     venv/bin/pip install -r requirements.txt"
  echo "#"
  echo "# Direct dependencies and the reasoning behind them live in pyproject.toml."
  echo "# This file is the FULL resolved graph, transitive packages included, so a new"
  echo "# app node (a3, a disaster-recovery rebuild, a laptop) gets byte-identical"
  echo "# software instead of whatever PyPI resolves to that morning."
  echo "#"
  echo "# Python $("$PY" -V | cut -d' ' -f2)"
  # pip/setuptools/wheel are bootstrap, not dependencies: pinning them makes
  # `pip install -r` fight the installer that is running it.
  "$PIP" freeze | grep -viE '^(pip|setuptools|wheel)==' | sort -f
} > "$TMP"

if [ -f "${ROOT}/requirements.txt" ] && diff -q "$TMP" "${ROOT}/requirements.txt" >/dev/null; then
  echo "requirements.txt already current ($(grep -c '^[^#]' "$TMP") packages)"
  exit 0
fi

cp "$TMP" "${ROOT}/requirements.txt"
echo "requirements.txt regenerated ($(grep -c '^[^#]' "${ROOT}/requirements.txt") packages)"
echo "commit it together with pyproject.toml."
