#!/usr/bin/env bash
# Prove the latest logical dump actually restores.
#
# `pg_restore --list` (which the nightly dump already runs) proves the archive
# parses. It does NOT prove the data comes back: a dump taken under RLS is a
# well-formed archive whose tables are empty, and it lists perfectly. The only
# honest test is to restore it and count rows.
#
# Restores into a scratch database on this node, compares the tenant-scoped
# tables against production, and drops the scratch database again. Reads
# nothing from production except counts.
set -euo pipefail

SRC_DB="${VEYRS_DB:-veyrs}"
SCRATCH="veyrs_restore_check"
LOCAL_DIR="/var/backups/veyrs"
STATE="/var/lib/veyrs-backup/verify-status"
# Tenant-scoped: exactly the tables an RLS-filtered dump would silently empty.
CHECK_TABLES=(assets findings organizations users asset_products import_runs)

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
mkdir -p "$(dirname "$STATE")"

cleanup() {
    (cd /tmp && su postgres -c "dropdb --if-exists --force '${SCRATCH}'") >/dev/null 2>&1 || true
}
trap cleanup EXIT

fail() {
    log "FAILED: $*"
    printf 'status=failed\nat=%s\nreason=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" > "$STATE"
    exit 1
}

DUMP="$(find "$LOCAL_DIR" -name 'veyrs-*.dump' -printf '%T@ %p\n' 2>/dev/null \
        | sort -rn | head -1 | cut -d' ' -f2-)"
[ -n "$DUMP" ] || fail "no dump found in ${LOCAL_DIR}"
log "verifying $(basename "$DUMP")"

# Checksum first: a corrupt file should be named as corrupt, not as a failed restore.
if [ -r "${DUMP}.sha256" ]; then
    [ "$(sha256sum "$DUMP" | awk '{print $1}')" = "$(cat "${DUMP}.sha256")" ] \
        || fail "checksum mismatch: $(basename "$DUMP") is corrupt on disk"
fi

cleanup
# UTF8 from template0, explicitly. Inheriting SQL_ASCII from template1 is the
# documented trap in docs/DEPLOYMENT.md: pg_restore reports zero errors and the
# application then gets bytes instead of str.
(cd /tmp && su postgres -c "createdb -E UTF8 -T template0 --lc-collate=C --lc-ctype=C '${SCRATCH}'") \
    || fail "cannot create the scratch database"

# As postgres, without --no-owner: the dump carries its own OWNER TO, foreign
# keys validate without tripping RLS, and the tables end up owned by veyrs.
# --role=veyrs would submit the restore to the very policies being tested.
if ! (cd /tmp && su postgres -c "pg_restore -d '${SCRATCH}' --exit-on-error '${DUMP}'") 2>/tmp/pgverify.err; then
    fail "pg_restore failed: $(tail -3 /tmp/pgverify.err | tr '\n' ' ')"
fi

MISMATCH=()
SUMMARY=""
for table in "${CHECK_TABLES[@]}"; do
    live="$(cd /tmp && su postgres -c "psql -tAc 'select count(*) from ${table}' ${SRC_DB}" 2>/dev/null || echo missing)"
    back="$(cd /tmp && su postgres -c "psql -tAc 'select count(*) from ${table}' ${SCRATCH}" 2>/dev/null || echo missing)"
    SUMMARY+="${table}=${back}/${live} "
    [ "$live" = "$back" ] || MISMATCH+=("${table}: live=${live} restored=${back}")
done

# Structure too: a restore that loses the RLS policies is a restore that would
# silently serve one tenant's data to another.
POL_LIVE="$(cd /tmp && su postgres -c "psql -tAc 'select count(*) from pg_policies' ${SRC_DB}")"
POL_BACK="$(cd /tmp && su postgres -c "psql -tAc 'select count(*) from pg_policies' ${SCRATCH}")"
[ "$POL_LIVE" = "$POL_BACK" ] || MISMATCH+=("rls policies: live=${POL_LIVE} restored=${POL_BACK}")

TBL_BACK="$(cd /tmp && su postgres -c "psql -tAc \"select count(*) from information_schema.tables where table_schema='public'\" ${SCRATCH}")"

if [ ${#MISMATCH[@]} -gt 0 ]; then
    fail "restored data does not match production — ${MISMATCH[*]}"
fi

log "restore verified: ${SUMMARY}tables=${TBL_BACK} policies=${POL_BACK}"
printf 'status=ok\nat=%s\ndump=%s\ntables=%s\npolicies=%s\ncounts=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$(basename "$DUMP")" "$TBL_BACK" "$POL_BACK" "$SUMMARY" > "$STATE"
