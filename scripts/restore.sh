#!/bin/bash
# VEYRS restore. Refuses to run without an explicit confirmation, because it
# DROPS and recreates the schema.
#
#   scripts/restore.sh /opt/veyrs/var/backups/veyrs-20260810-091500 --yes
#
# THE RESTORE RUNS AS A SUPERUSER, NEVER AS THE APPLICATION ROLE.
# Every tenant table is FORCE ROW LEVEL SECURITY, which binds the table OWNER
# too. Restored as the `veyrs` role, the data load is refused table by table
# ("COPY FROM not supported with row-level security" / policy violations) after
# --clean has already dropped what was there. Until 0.35.3 this script did
# exactly that: it connected with VEYRS_DATABASE_URL, the app role. It is the
# mirror image of the trap scripts/backup.sh and veyrs-pgdump avoid.
#
# Two routes, the same two backup.sh offers:
#   * peer authentication as the `postgres` OS user, ONLY when the database in
#     VEYRS_DATABASE_URL is on this host (a node whose database lives
#     elsewhere may carry a local Postgres of its own -- restoring into that
#     would "succeed" against the wrong server);
#   * RESTORE_DSN, a connection string for a SUPERUSER on the database host.
#     Checked before anything is dropped.
# Ownership is preserved (no --no-owner): restored objects stay owned by the
# app role, as the dump recorded them. --no-owner as postgres would leave
# every table owned by postgres and the API without privileges on its data.
set -euo pipefail

SOURCE=${1:-}
CONFIRM=${2:-}
APP_DIR=${APP_DIR:-/opt/veyrs}

if [ -z "$SOURCE" ] || [ ! -d "$SOURCE" ]; then
  echo "usage: $0 <backup-directory> --yes" >&2
  exit 2
fi
if [ "$CONFIRM" != "--yes" ]; then
  echo "This DESTROYS the current VEYRS database and replaces it with:" >&2
  sed -n '1,20p' "$SOURCE/MANIFEST" >&2
  echo >&2
  echo "Re-run with --yes to proceed." >&2
  exit 2
fi

echo "==> verifying checksums"
(cd "$SOURCE" && sha256sum --check --quiet --ignore-missing SHA256SUMS)

# shellcheck disable=SC1091
set -a; . "$APP_DIR/.env"; set +a

DSN=$(sed 's|postgresql+psycopg|postgresql|' <<<"$VEYRS_DATABASE_URL")
DB_NAME=${DSN##*/}
DB_NAME=${DB_NAME%%\?*}
DB_HOST=${DSN#*://}
DB_HOST=${DB_HOST#*@}
DB_HOST=${DB_HOST%%/*}
DB_HOST=${DB_HOST%:*}
DB_IS_LOCAL=0
case "$DB_HOST" in ""|localhost|127.0.0.1|::1|"[::1]") DB_IS_LOCAL=1 ;; esac

# Pick the superuser route BEFORE the API is stopped or anything is dropped.
if [ -n "${RESTORE_DSN:-}" ]; then
  is_super=$(psql "$RESTORE_DSN" -tAXc "select rolsuper from pg_roles where rolname = current_user" 2>/dev/null || true)
  if [ "$is_super" != "t" ]; then
    echo "RESTORE_DSN does not connect as a superuser (got '${is_super:-no answer}')." >&2
    echo "Row-level security would refuse the data load; aborting before anything is dropped." >&2
    exit 1
  fi
  restore() { pg_restore --clean --if-exists --dbname="$RESTORE_DSN" < "$SOURCE/veyrs.dump"; }
  count() { psql "$RESTORE_DSN" -tAXc "$1"; }
elif [ "$DB_IS_LOCAL" = 1 ] && id postgres >/dev/null 2>&1; then
  # The archive is 0600 root: feed it on stdin instead of making postgres read it.
  restore() { su -s /bin/bash postgres -c "pg_restore --clean --if-exists --dbname='$DB_NAME'" < "$SOURCE/veyrs.dump"; }
  count() { (cd /tmp && su -s /bin/bash postgres -c "psql -d '$DB_NAME' -tAXc \"$1\""); }
else
  echo "The database is on '${DB_HOST}', not this host, and RESTORE_DSN is not set." >&2
  echo "Restore must run as a superuser: set RESTORE_DSN to a superuser connection" >&2
  echo "string for that server, or run the restore on the database host." >&2
  exit 1
fi

echo "==> stopping the API so nothing writes mid-restore"
echo "    (other app nodes that share this database must be stopped by hand)"
systemctl stop veyrs-api.service 2>/dev/null || true

echo "==> restoring database '${DB_NAME}' as a superuser"
restore

# A superuser sees every tenant's rows, so an empty organizations table here
# means the data did not load -- not that RLS is hiding it.
orgs=$(count "select count(*) from organizations")
if [ "${orgs:-0}" -lt 1 ]; then
  echo "restore loaded no organizations -- the data did not come back; API left stopped" >&2
  exit 1
fi
echo "    organizations restored: ${orgs}"

if [ -f "$SOURCE/documents.tar.gz" ]; then
  echo "==> restoring documents"
  tar xzf "$SOURCE/documents.tar.gz" -C "$APP_DIR/var"
fi

echo "==> NOT overwriting .env automatically"
echo "    The backup's key material is at $SOURCE/env."
echo "    If VEYRS_ENCRYPTION_KEY differs from the current .env, every stored"
echo "    third-party credential will fail to decrypt. Compare before copying."

echo "==> re-applying schema and RLS policies (idempotent)"
(cd "$APP_DIR" && PYTHONPATH=backend venv/bin/python -m veyrs.cli init-db)

systemctl start veyrs-api.service 2>/dev/null || true
echo "restore complete. Verify: curl -sf http://127.0.0.1:8000/readyz"
