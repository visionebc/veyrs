#!/usr/bin/env bash
# The tick loop that replaces a systemd timer inside a container.
#
#   tick.sh <label> <interval-seconds> <max-jitter-seconds> <command...>
#
# ===========================================================================
# THIS DOES NOT DECIDE WHEN ANYTHING RUNS.
# ===========================================================================
# Both host timers are HOURLY TICKS, not schedules: veyrs-intel-sync.timer and
# veyrs-digest.timer fire every hour and the actual cadence lives in the
# database -- `organizations.settings.intel_schedule` and
# `organizations.settings.digest`, both editable in the console. `veyrs
# intel-due` and `services.digest.due_now` answer whether this tick is the one.
#
# So this loop deliberately carries no notion of "nightly" or "07:00". Putting
# an hour here would make a setting the console displays and the machine
# ignores -- which is the exact defect the host units were written to avoid.
# All it decides is HOW OFTEN THE QUESTION IS ASKED.
# ===========================================================================
set -uo pipefail

LABEL="${1:?tick.sh needs a label}"; shift
INTERVAL="${1:?tick.sh needs an interval in seconds}"; shift
JITTER="${1:?tick.sh needs a maximum jitter in seconds}"; shift
[ "$#" -gt 0 ] || { echo "tick.sh: no command given" >&2; exit 64; }

# --- shutdown -------------------------------------------------------------
# `sleep 3600` in the foreground does not react to a signal until it finishes,
# so `docker compose down` would wait out its whole stop timeout and then
# SIGKILL -- for a container that is doing nothing but waiting. Backgrounding
# the sleep and `wait`ing on it lets the trap run at once.
running=1
child=""
on_term() {
    running=0
    [ -n "$child" ] && kill "$child" 2>/dev/null
}
trap on_term TERM INT

nap() {
    sleep "$1" &
    child=$!
    wait "$child" 2>/dev/null
    child=""
}

jittered() {
    # Not decoration. NVD rate-limits per source address, and a fleet of
    # installations all firing on the hour is how a shared limit is exhausted.
    # The host units carry RandomizedDelaySec for the same reason.
    [ "$JITTER" -gt 0 ] || { echo 0; return; }
    echo $(( RANDOM % (JITTER + 1) ))
}

echo "tick[${LABEL}]: every ${INTERVAL}s (+0..${JITTER}s jitter): $*"

# --- the catch-up tick ----------------------------------------------------
# The host units set Persistent=true, which means "a machine that was off still
# owes the run it missed". The container equivalent is to tick once at startup
# rather than waiting out a full interval -- and it is safe precisely because
# this loop does not decide anything: `intel-due` and `due_now` will refuse a
# run that is not actually due. Without it, a stack restarted at 07:05 would
# skip a digest whose hour had just passed.
first=1

while [ "$running" = "1" ]; do
    if [ "$first" = "1" ]; then
        first=0
        d=$(jittered)
        [ "$d" -gt 0 ] && { echo "tick[${LABEL}]: startup catch-up in ${d}s"; nap "$d"; }
    else
        d=$(( INTERVAL + $(jittered) ))
        echo "tick[${LABEL}]: next in ${d}s"
        nap "$d"
    fi
    [ "$running" = "1" ] || break

    echo "tick[${LABEL}]: running at $(date -Is)"
    # NEVER let a failed run end the loop.
    #
    # With `restart: unless-stopped` a loop that exits on error becomes a
    # restart storm that re-runs the catch-up tick every few seconds -- which
    # for the intel feed means hammering NVD's rate limit with the very
    # requests that failed. The status is reported and the next tick is taken:
    # a stale EPSS is a degraded signal, and the run that fixes it is an hour
    # away, not a crash loop away.
    if "$@"; then
        echo "tick[${LABEL}]: ok at $(date -Is)"
    else
        echo "tick[${LABEL}]: FAILED (exit $?) at $(date -Is) -- retrying on the next tick" >&2
    fi
done

echo "tick[${LABEL}]: stopped"
