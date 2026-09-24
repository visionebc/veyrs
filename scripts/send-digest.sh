#!/bin/bash
# VEYRS daily digest — one tick.
#
# Called hourly by veyrs-digest.timer. It does NOT decide when the digest goes
# out: `veyrs digest` asks each organization's own settings whether this is its
# hour and whether one already went out in the last twelve. Putting the hour in
# this file would make the console's setting decorative.
#
# Exit status is deliberately 0 on "nothing was due": a timer unit that lands in
# `failed` every hour it had no work is a timer nobody looks at, and nothing on
# this fleet alerts on a failed unit anyway (that is a known gap, see
# docs/HIGH_AVAILABILITY.md).
set -uo pipefail

# Root and interpreter resolved rather than hard-coded, so the container stack
# runs THIS script instead of a second copy of it. See scripts/sync-intel.sh
# for the full reasoning; the `.env` load was already conditional here.
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"
cd "${ROOT}"

if [ -f .env ]; then
  set -a
  # shellcheck disable=SC1091
  . ./.env
  set +a
fi

export PYTHONPATH="${ROOT}/backend"
PY="${ROOT}/venv/bin/python"
[ -x "${PY}" ] || PY="$(command -v python3)"
[ -n "${PY}" ] || { echo "!!! no python interpreter found" >&2; exit 1; }
exec "${PY}" -m veyrs digest "$@"
