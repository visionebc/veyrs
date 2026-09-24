#!/usr/bin/env bash
# Refresh every intelligence feed, then let the tenants know.
#
# Order is deliberate and not cosmetic:
#   0. CWE   - the dictionary that NAMES what the other three find. Cheap (one
#              2 MB file), and it runs first so the placeholder rows NVD creates
#              tonight are named by tomorrow morning's dashboard rather than
#              waiting a day.
#   1. NVD   - creates/updates the CVE records everything else attaches to, and
#              correlates them against inventory (this is what raises findings).
#   2. EPSS  - skips CVEs it has never seen, so it must run after NVD or a day's
#              new records carry no exploit probability until tomorrow.
#   3. KEV   - last because it is the strongest urgency signal and should be the
#              final word on the day's priority order.
#
# Each feed is independent: one failing must not stop the others, because a
# stale EPSS is a degraded signal while a stale KEV is a missed emergency. The
# exit code is the worst of them so the timer records a real failure.
#
# WHAT RUNS IS NO LONGER DECIDED HERE. The timer ticks hourly and
# `veyrs intel-due` answers which feeds have actually reached their configured
# interval (Threat Intel -> Schedule in the console, stored per tenant in
# `organizations.settings.intel_schedule`). Before this, changing the cadence
# meant editing a systemd unit over SSH, which is a deployment detail rather
# than a product setting.
#
# `--full-run` forces every feed regardless of schedule -- the hand-run escape
# hatch for "I do not care what the interval says, refresh now".
set -uo pipefail

# ---------------------------------------------------------------------------
# The root and the interpreter are RESOLVED, not hard-coded.
#
# The container stack runs THIS script -- not a re-implementation of it -- and
# in a container there is no /opt/veyrs/venv and no .env: the environment is
# injected by compose. A second copy of the feed order living in a compose
# command would be a ladder written twice, and the one that drifts is always
# the copy nobody runs by hand. The order below (CWE names what NVD creates;
# EPSS skips CVEs it has never seen; KEV is the last word) has to have exactly
# one home.
#
# The `.env` load stays CONDITIONAL for the same reason. On the host it is the
# only source of configuration; in a container a file that happened to exist
# would silently override what the orchestrator injected.
# ---------------------------------------------------------------------------
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "${HERE}/.." && pwd)"

cd "${ROOT}/backend" || exit 1
if [ -f "${ROOT}/.env" ]; then
    set -a
    # shellcheck disable=SC1091
    . "${ROOT}/.env"
    set +a
fi
export PYTHONPATH="${ROOT}/backend"
PY="${ROOT}/venv/bin/python"
[ -x "${PY}" ] || PY="$(command -v python3)"
[ -n "${PY}" ] || { echo "!!! no python interpreter found"; exit 1; }

FORCE=0
[ "${1:-}" = "--full-run" ] && FORCE=1

status=0

# The reasons are printed for EVERY feed, due or not: a tick that skips
# everything and prints nothing is indistinguishable from a tick that crashed
# before it started, which is precisely how three nights of `veyrs-intel-sync`
# failures went unseen in August 2026.
echo "=== schedule $(date -Is) ==="
"${PY}" -m veyrs intel-due || echo "!!! could not read the schedule"

if [ "${FORCE}" = "1" ]; then
    echo "=== --full-run: schedule ignored ==="
    due="cwe nvd epss kev"
else
    # Not a pipeline into `while read`: a subshell there would lose `status`.
    due="$("${PY}" -m veyrs intel-due --quiet)" || due=""
fi

# The loop keeps the fixed order (CWE names what NVD creates; EPSS skips CVEs
# it has never seen; KEV is the last word) rather than the order `intel-due`
# happens to print, so a partial night still runs its feeds in a sane sequence.
for feed in cwe nvd epss kev; do
    case " ${due} " in
        *" ${feed} "*) ;;
        *) continue ;;
    esac
    echo "=== sync-${feed} $(date -Is) ==="
    if ! "${PY}" -m veyrs "sync-${feed}"; then
        echo "!!! sync-${feed} failed"
        status=1
    fi
done

# The SLA sweep runs after the feeds so tonight's KEV additions already carry
# their urgency when deadlines are (re)computed. A clock that only advances
# when somebody opens a dashboard is not a clock.
#
# It runs on EVERY tick, including one where no feed was due: SLA deadlines
# elapse with the wall clock, not with the arrival of new intelligence, and a
# breach that waits for the next NVD pull is a breach reported late.
echo "=== run-sla $(date -Is) ==="
if ! "${PY}" -m veyrs run-sla; then
    echo "!!! run-sla failed"
    status=1
fi
echo "=== done $(date -Is), status ${status} ==="
exit "${status}"
