#!/bin/bash
# Move an existing native node's API service from root to the `veyrs` account (R-06).
#
# install.sh does this for fresh installs and re-runs. This script is the same
# change for a node that is already running and should not be re-installed:
#
#   1. creates the `veyrs` system account (idempotent);
#   2. .env           -> 0640 root:veyrs      (the service can read, not rewrite)
#      .env.test      -> 0600 root:root       (if present)
#      var/, var/documents, var/update-uploads -> veyrs:veyrs (the only writable tree)
#      var/backups    -> root:root 0700       (.env copies and dumps: not for the API)
#      update spool   -> root:veyrs 0770      (the API drops requests, the root updater acts)
#   3. installs the repository's veyrs-api.service (User=veyrs) over the node's copy,
#      keeping the previous one in the backup directory;
#   4. restarts the API and waits for /healthz; if it does not come back, it ROLLS BACK
#      by itself.
#
# The updater (veyrs-updater.service), the timers and install.sh stay root.
#
# Usage:
#   sudo scripts/migrate-service-user.sh [--dir /opt/veyrs] [--dry-run] [--no-restart]
#   sudo scripts/migrate-service-user.sh --rollback [--from <backup dir>]
#
# ROLLBACK (by hand, if the script itself is unavailable):
#   cp <backup dir>/veyrs-api.service /etc/systemd/system/veyrs-api.service
#   chmod 600 /opt/veyrs/.env; chown root:root /opt/veyrs/.env
#   chown -R root:root /opt/veyrs/var
#   systemctl daemon-reload && systemctl restart veyrs-api
# The `veyrs` account is left in place (harmless); remove it with `userdel veyrs`.
#
# Idempotent: running it twice changes nothing the second time (the backup is only
# taken when the installed unit still says User=root).
set -euo pipefail

VEYRS_DIR="${VEYRS_DIR:-/opt/veyrs}"
SERVICE=veyrs-api
SVC_USER=veyrs
UNIT_DST="/etc/systemd/system/${SERVICE}.service"
SPOOL=/var/lib/veyrs/update-requests
BACKUP_ROOT=/var/lib/veyrs/migrations
DRY=0
RESTART=1
ROLLBACK=0
FROM=""

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)        VEYRS_DIR="$2"; shift 2 ;;
        --dry-run)    DRY=1; shift ;;
        --no-restart) RESTART=0; shift ;;
        --rollback)   ROLLBACK=1; shift ;;
        --from)       FROM="$2"; shift 2 ;;
        -h|--help)    sed -n '2,32p' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
done

[[ $EUID -eq 0 ]] || { echo "must run as root" >&2; exit 1; }
[[ -f "$VEYRS_DIR/.env" ]] || { echo "$VEYRS_DIR/.env not found: not a VEYRS install" >&2; exit 1; }

say() { printf '==> %s\n' "$*"; }
run() { if [[ $DRY -eq 1 ]]; then printf '[dry-run] %s\n' "$*"; else "$@"; fi; }

healthy() {
    local i
    for i in $(seq 1 30); do
        curl -sf http://127.0.0.1:8000/healthz >/dev/null 2>&1 && return 0
        sleep 1
    done
    return 1
}

do_rollback() {
    local dir="${1:?backup dir}"
    [[ -f "$dir/${SERVICE}.service" ]] || { echo "no ${SERVICE}.service in $dir" >&2; return 1; }
    say "rolling back from $dir"
    run cp "$dir/${SERVICE}.service" "$UNIT_DST"
    run chown root:root "$VEYRS_DIR/.env"
    run chmod 600 "$VEYRS_DIR/.env"
    run chown -R root:root "$VEYRS_DIR/var"
    run systemctl daemon-reload
    run systemctl restart "$SERVICE"
    if [[ $DRY -eq 0 ]]; then
        healthy && say "rolled back; the API answers /healthz as root again" \
                || { echo "the API is still unhealthy: systemctl status $SERVICE; journalctl -u $SERVICE -n 50" >&2; return 1; }
    fi
}

if [[ $ROLLBACK -eq 1 ]]; then
    if [[ -z "$FROM" ]]; then
        FROM="$(ls -1dt "$BACKUP_ROOT"/service-user-* 2>/dev/null | head -1 || true)"
    fi
    [[ -n "$FROM" ]] || { echo "no backup found under $BACKUP_ROOT; pass --from <dir>" >&2; exit 1; }
    do_rollback "$FROM"
    exit $?
fi

SRC_UNIT="$VEYRS_DIR/infrastructure/systemd/${SERVICE}.service"
[[ -f "$SRC_UNIT" ]] || { echo "missing $SRC_UNIT: update the checkout first" >&2; exit 1; }
grep -q '^User=veyrs' "$SRC_UNIT" || { echo "$SRC_UNIT does not set User=veyrs: the checkout predates 0.41.0" >&2; exit 1; }

# --- 1. account ---------------------------------------------------------------
if id -u "$SVC_USER" >/dev/null 2>&1; then
    say "account $SVC_USER exists"
else
    say "creating system account $SVC_USER"
    run useradd --system --user-group --no-create-home --home-dir "$VEYRS_DIR/var" \
        --shell "$(command -v nologin || echo /sbin/nologin)" "$SVC_USER"
fi

# Can the account read the code? (a 0750 install root would break the first import)
if [[ $DRY -eq 0 ]] && command -v runuser >/dev/null 2>&1 \
   && ! runuser -u "$SVC_USER" -- test -r "$VEYRS_DIR/backend/veyrs/main.py"; then
    echo "$SVC_USER cannot read $VEYRS_DIR/backend/veyrs/main.py. Make $VEYRS_DIR and its parents" >&2
    echo "world-searchable (chmod o+x) or group-readable by $SVC_USER, then re-run. Nothing changed yet." >&2
    exit 1
fi

# --- backup of what we are about to change ------------------------------------
STAMP="$(date -u +%Y%m%dT%H%M%SZ)"
BACKUP="$BACKUP_ROOT/service-user-$STAMP"
CHANGED=0
if [[ -f "$UNIT_DST" ]] && grep -q '^User=root' "$UNIT_DST"; then
    CHANGED=1
    say "backing up the current unit and ownership to $BACKUP"
    run install -d -m 700 "$BACKUP"
    run cp "$UNIT_DST" "$BACKUP/${SERVICE}.service"
    if [[ $DRY -eq 0 ]]; then
        stat -c '%U:%G %a %n' "$VEYRS_DIR/.env" "$VEYRS_DIR/var" > "$BACKUP/ownership.txt"
    fi
else
    say "the installed unit is not User=root: unit and backup step skipped"
fi

# --- 2. ownership -------------------------------------------------------------
say "ownership: .env 0640 root:$SVC_USER; var/ owned by $SVC_USER; var/backups root-only"
run chown "root:$SVC_USER" "$VEYRS_DIR/.env"
run chmod 640 "$VEYRS_DIR/.env"
if [[ -f "$VEYRS_DIR/.env.test" ]]; then
    run chown root:root "$VEYRS_DIR/.env.test"
    run chmod 600 "$VEYRS_DIR/.env.test"
fi
run install -d -m 750 -o "$SVC_USER" -g "$SVC_USER" "$VEYRS_DIR/var" \
    "$VEYRS_DIR/var/documents" "$VEYRS_DIR/var/update-uploads"
# Existing uploads and documents were written by root: hand them over.
run chown -R "$SVC_USER:$SVC_USER" "$VEYRS_DIR/var/documents" "$VEYRS_DIR/var/update-uploads"
if [[ -d "$VEYRS_DIR/var/backups" ]]; then
    run chown -R root:root "$VEYRS_DIR/var/backups"
    run chmod 700 "$VEYRS_DIR/var/backups"
fi
if [[ -d "$SPOOL" ]]; then
    run chown "root:$SVC_USER" "$SPOOL"
    run chmod 770 "$SPOOL"
fi

# --- 3. unit ------------------------------------------------------------------
if [[ $CHANGED -eq 1 || ! -f "$UNIT_DST" ]]; then
    say "installing $UNIT_DST from the repository unit (User=$SVC_USER)"
    if [[ $DRY -eq 0 ]]; then
        # Same rewrites install.sh applies: install root, and (only when this node's
        # unit already names them) the distribution's redis/postgres unit names.
        sed -e "s#/opt/veyrs#${VEYRS_DIR}#g" "$SRC_UNIT" > "${UNIT_DST}.new"
        for dep in redis-server.service postgresql.service; do
            if ! grep -q "$dep" "$UNIT_DST" 2>/dev/null && grep -q "$dep" "${UNIT_DST}.new"; then
                echo "note: the old unit did not name $dep; the new one does (ordering only)" >&2
            fi
        done
        chmod 644 "${UNIT_DST}.new"
        mv "${UNIT_DST}.new" "$UNIT_DST"
    fi
    if command -v systemd-analyze >/dev/null 2>&1 && [[ $DRY -eq 0 ]]; then
        systemd-analyze verify "$UNIT_DST" 2>&1 | sed 's/^/    verify: /' || true
    fi
    run systemctl daemon-reload
fi

# --- 4. restart + health, auto-rollback ---------------------------------------
if [[ $RESTART -eq 1 ]]; then
    say "restarting $SERVICE"
    run systemctl restart "$SERVICE"
    if [[ $DRY -eq 0 ]]; then
        if healthy; then
            say "healthy. Process owner: $(ps -o user= -p "$(systemctl show -p MainPID --value "$SERVICE")" 2>/dev/null || echo '?')"
        else
            echo "the API did not become healthy as $SVC_USER; rolling back" >&2
            journalctl -u "$SERVICE" -n 15 --no-pager >&2 || true
            if [[ $CHANGED -eq 1 ]]; then do_rollback "$BACKUP"; fi
            exit 1
        fi
    fi
else
    say "--no-restart: run 'systemctl restart $SERVICE' yourself; roll back with: $0 --rollback --from $BACKUP"
fi
say "done. Rollback: $0 --rollback --from $BACKUP"
