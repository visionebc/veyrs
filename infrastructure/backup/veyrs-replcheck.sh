#!/usr/bin/env bash
# Is the hot standby actually replicating?
#
# Replication fails silently. The primary keeps serving, the standby keeps
# running, `systemctl is-active` says active on both, and the only symptom is
# that the standby's data quietly ages. The failure is discovered on the day
# it is needed -- which is the same shape as veyrs-intel-sync failing three
# nights in a row before anyone noticed.
#
# Exits non-zero so the systemd unit goes `failed`, which is at least visible
# in `systemctl --failed` and in the journal.
set -euo pipefail

SLOT="${SLOT:-veyrs_db_a2}"
STANDBY_IP="${STANDBY_IP:-10.50.0.32}"
MAX_LAG_BYTES="${MAX_LAG_BYTES:-134217728}"   # 128 MB of unreplayed WAL
STATE="/var/lib/veyrs-backup/replication-status"

mkdir -p "$(dirname "$STATE")"
log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }

fail() {
    log "REPLICATION UNHEALTHY: $*"
    printf 'status=failed\nat=%s\nreason=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" > "$STATE"
    exit 1
}

q() { (cd /tmp && su postgres -c "psql -tAc \"$1\"") 2>/dev/null; }

# 1. A slot that exists but is inactive means the standby is gone. WAL is being
#    retained for it right now, against max_slot_wal_keep_size.
ACTIVE="$(q "select active from pg_replication_slots where slot_name = '${SLOT}'")"
[ -n "$ACTIVE" ] || fail "replication slot ${SLOT} does not exist"
[ "$ACTIVE" = "t" ] || fail "slot ${SLOT} is inactive — ${STANDBY_IP} is not connected"

# 2. An invalidated slot is worse than a missing one: it looks configured, and
#    the standby can never catch up without a fresh pg_basebackup.
INVALID="$(q "select coalesce(wal_status,'') from pg_replication_slots where slot_name = '${SLOT}'")"
[ "$INVALID" != "lost" ] || fail "slot ${SLOT} is LOST — the standby fell too far behind; rebuild with pg_basebackup"

# 3. Streaming, from the address we expect.
STATE_ROW="$(q "select state from pg_stat_replication where client_addr = '${STANDBY_IP}'")"
[ -n "$STATE_ROW" ] || fail "no walsender for ${STANDBY_IP}"
[ "$STATE_ROW" = "streaming" ] || fail "walsender for ${STANDBY_IP} is '${STATE_ROW}', not streaming"

# 4. Lag in bytes, not seconds: replay_lag reads 0 on an idle primary whether
#    the standby is current or disconnected a moment ago.
LAG="$(q "select coalesce(pg_wal_lsn_diff(pg_current_wal_lsn(), replay_lsn), 0)::bigint from pg_stat_replication where client_addr = '${STANDBY_IP}'")"
[ -n "$LAG" ] || fail "cannot measure lag"
if [ "$LAG" -gt "$MAX_LAG_BYTES" ]; then
    fail "standby is ${LAG} bytes behind (limit ${MAX_LAG_BYTES})"
fi

log "replication healthy: ${STANDBY_IP} streaming, ${LAG} bytes behind"
printf 'status=ok\nat=%s\nstandby=%s\nlag_bytes=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$STANDBY_IP" "$LAG" > "$STATE"
