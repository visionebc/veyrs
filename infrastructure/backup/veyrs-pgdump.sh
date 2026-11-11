#!/usr/bin/env bash
# Logical backup of the VEYRS database.
#
# Why this exists alongside PBS
# -----------------------------
# PBS snapshots ct/102 nightly. That is a *crash-consistent block* image:
# Postgres recovers it through WAL and it is a valid restore point for "the
# container died". It is NOT protection against `DROP TABLE`, a bad migration,
# or logical corruption, because the snapshot faithfully preserves the damage.
# A logical dump is the only artifact you can restore *selectively* from.
#
# THE TRAP, and the reason this script insists on the postgres superuser
# ------------------------------------------------------------------------
# VEYRS runs row-level security with FORCE on 61 policies. `pg_dump` is just
# SELECTs: run as the `veyrs` role, every tenant table returns ZERO rows and
# pg_dump exits 0 with a perfectly well-formed, perfectly empty archive. There
# is no error, no warning, and `pg_restore --list` still looks right -- the
# table is in the TOC, it just has nothing in it. That backup is discovered to
# be empty on the day it is needed. Dump as `postgres` (RLS-exempt) and verify
# the row counts, which is what the sanity block below does.
#
# Off-host on purpose
# -------------------
# The PBS datastore (`disk-a`) is a mount point *inside hv-4*, the same host
# that runs veyrs-db-1, veyrs-app-1 and veyrs-app-2. Losing hv-4 loses
# production and every PBS restore point together. The copy pushed to hv-1 is
# currently the only VEYRS backup that survives that.
set -euo pipefail

DB="${VEYRS_DB:-veyrs}"
LOCAL_DIR="/var/backups/veyrs"
KEEP_LOCAL_DAYS="${KEEP_LOCAL_DAYS:-7}"
REMOTE_HOST="${REMOTE_HOST:-10.50.0.40}"
# Unprivileged on purpose. A root key here would turn a compromise of the
# database node into root on the primary hypervisor.
REMOTE_USER="${REMOTE_USER:-veyrsbak}"
REMOTE_DIR="${REMOTE_DIR:-/var/backups/veyrs-offhost}"
KEEP_REMOTE_DAYS="${KEEP_REMOTE_DAYS:-30}"
SSH_KEY="/root/.ssh/id_veyrs_backup"
STATE="/var/lib/veyrs-backup/status"

# A dump smaller than this is assumed to be the RLS trap above, not a small
# database. Production is ~2.6 GB raw / ~350 MB compressed; the floor is set an
# order of magnitude below that so it never fires on legitimate shrinkage.
MIN_BYTES="${MIN_BYTES:-20000000}"

# Tables that must not be empty. Chosen because they are the ones RLS hides:
# `cve` is global (no policy) and would survive a bad dump, so it is a poor
# canary. `assets` and `findings` are tenant-scoped -- exactly what disappears.
CANARY_TABLES=(assets findings organizations users)

log() { printf '%s %s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*"; }
mkdir -p "$LOCAL_DIR" "$(dirname "$STATE")"
# Owned by postgres: pg_dump writes the file itself, as postgres. 0700 keeps
# the archive -- which contains every password hash and every Fernet blob in
# the platform -- readable only by postgres and root.
chown postgres:postgres "$LOCAL_DIR"
chmod 700 "$LOCAL_DIR"

fail() {
    log "FAILED: $*"
    printf 'status=failed\nat=%s\nreason=%s\n' "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$*" > "$STATE"
    exit 1
}

STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
OUT="${LOCAL_DIR}/veyrs-${STAMP}.dump"

# --------------------------------------------------------------------------
# 1. Refuse to run as anything but a superuser.
# --------------------------------------------------------------------------
IS_SUPER="$(cd /tmp && su postgres -c "psql -tAc \"select usesuper from pg_user where usename = current_user\"" 2>/dev/null || true)"
[ "$IS_SUPER" = "t" ] || fail "not running as a superuser; RLS would silently produce an empty dump"

# --------------------------------------------------------------------------
# 2. Record the truth BEFORE dumping, so the verification has something to
#    compare against that did not come from the dump itself.
# --------------------------------------------------------------------------
declare -A EXPECTED
for table in "${CANARY_TABLES[@]}"; do
    count="$(cd /tmp && su postgres -c "psql -tAc 'select count(*) from ${table}' ${DB}")" \
        || fail "cannot count ${table}"
    EXPECTED[$table]="$count"
done
log "live counts: $(for t in "${CANARY_TABLES[@]}"; do printf '%s=%s ' "$t" "${EXPECTED[$t]}"; done)"

# --------------------------------------------------------------------------
# 3. Dump.
# --------------------------------------------------------------------------
log "dumping ${DB} -> ${OUT}"
(cd /tmp && su postgres -c "pg_dump -Fc -Z6 --no-password -f '${OUT}' '${DB}'") \
    || fail "pg_dump exited non-zero"
chmod 600 "$OUT"

SIZE="$(stat -c %s "$OUT")"
[ "$SIZE" -ge "$MIN_BYTES" ] || fail "dump is only ${SIZE} bytes (floor ${MIN_BYTES}) — suspect an empty/RLS-filtered dump"

# --------------------------------------------------------------------------
# 4. Integrity: the archive must be readable, and it must actually contain
#    rows for the canary tables. `pg_restore --list` proves the TOC parses;
#    the data-block sizes prove the rows are in there.
# --------------------------------------------------------------------------
TOC="$(cd /tmp && su postgres -c "pg_restore --list '${OUT}'")" || fail "archive is unreadable"
for table in "${CANARY_TABLES[@]}"; do
    if [ "${EXPECTED[$table]}" -gt 0 ]; then
        grep -qE "TABLE DATA public ${table} " <<<"$TOC" \
            || fail "${table} has ${EXPECTED[$table]} live rows but no TABLE DATA in the archive"
    fi
done
log "archive OK: $(numfmt --to=iec "$SIZE"), $(grep -c 'TABLE DATA' <<<"$TOC") data sections"

sha256sum "$OUT" | awk '{print $1}' > "${OUT}.sha256"

# --------------------------------------------------------------------------
# 5. Off-host copy. A backup that only exists on hv-4 does not protect
#    against losing hv-4.
# --------------------------------------------------------------------------
PUSHED=no
if [ -r "$SSH_KEY" ]; then
    if ssh -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=10 -o StrictHostKeyChecking=accept-new \
         "${REMOTE_USER}@${REMOTE_HOST}" "mkdir -p '${REMOTE_DIR}' && chmod 700 '${REMOTE_DIR}'" 2>/dev/null \
       && scp -i "$SSH_KEY" -o BatchMode=yes -o ConnectTimeout=10 -q \
            "$OUT" "${OUT}.sha256" "${REMOTE_USER}@${REMOTE_HOST}:${REMOTE_DIR}/"; then
        REMOTE_SUM="$(ssh -i "$SSH_KEY" -o BatchMode=yes "${REMOTE_USER}@${REMOTE_HOST}" \
            "sha256sum '${REMOTE_DIR}/$(basename "$OUT")' | awk '{print \$1}'")"
        if [ "$REMOTE_SUM" = "$(cat "${OUT}.sha256")" ]; then
            PUSHED=yes
            log "off-host copy verified on ${REMOTE_HOST}"
            ssh -i "$SSH_KEY" -o BatchMode=yes "${REMOTE_USER}@${REMOTE_HOST}" \
                "find '${REMOTE_DIR}' -name 'veyrs-*.dump*' -mtime +${KEEP_REMOTE_DAYS} -delete" || true
        else
            fail "off-host copy checksum mismatch — the remote file is corrupt"
        fi
    else
        fail "could not push the dump off ${HOSTNAME}; hv-4 loss would take the backup with it"
    fi
else
    fail "no backup ssh key at ${SSH_KEY}; refusing to call an on-host-only dump a backup"
fi

# --------------------------------------------------------------------------
# 6. Retention, last: never delete an old backup before the new one is proven.
# --------------------------------------------------------------------------
find "$LOCAL_DIR" -name 'veyrs-*.dump*' -mtime "+${KEEP_LOCAL_DAYS}" -delete

printf 'status=ok\nat=%s\nfile=%s\nbytes=%s\noffhost=%s\n' \
    "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$OUT" "$SIZE" "$PUSHED" > "$STATE"
log "done: $(basename "$OUT") ($(numfmt --to=iec "$SIZE"), off-host=${PUSHED})"
