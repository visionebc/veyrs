#!/bin/bash
# VEYRS backup: database + secrets + uploaded documents.
#
# Restore is documented and TESTED in scripts/restore.sh -- a backup that has
# never been restored is a hypothesis, not a backup.
#
# The encryption key is included because without it every stored third-party
# credential (ITSM, AI providers, threat feeds) is unrecoverable ciphertext.
# That makes this archive as sensitive as the database itself: 0600, and it must
# be shipped to storage that is not the same host.
set -euo pipefail

APP_DIR=${APP_DIR:-/opt/veyrs}
BACKUP_DIR=${BACKUP_DIR:-/opt/veyrs/var/backups}
RETAIN_DAYS=${RETAIN_DAYS:-30}
STAMP=$(date -u +%Y%m%d-%H%M%S)
TARGET="$BACKUP_DIR/veyrs-$STAMP"

# shellcheck disable=SC1091
set -a; . "$APP_DIR/.env"; set +a

mkdir -p "$TARGET"
chmod 700 "$BACKUP_DIR" "$TARGET"

echo "==> database"
# The dump MUST run as a role that bypasses RLS.
#
# Every tenant table is FORCE ROW LEVEL SECURITY, which applies to the table
# OWNER too -- so an ordinary `pg_dump` as the veyrs role fails with
# "query would be affected by row-level security policy" partway through, after
# having already written a partial file. That is the worst possible failure mode
# for a backup: it looks like it ran.
#
# Superusers bypass RLS implicitly, so we dump as the postgres OS user over peer
# authentication. If that is unavailable (managed Postgres, remote host), create
# a dedicated role instead:
#     CREATE ROLE veyrs_backup LOGIN BYPASSRLS PASSWORD '...';
#     GRANT pg_read_all_data TO veyrs_backup;
# and set BACKUP_DSN to its connection string.
DSN=$(sed 's|postgresql+psycopg|postgresql|' <<<"$VEYRS_DATABASE_URL")
DB_NAME=${DSN##*/}

if [ -n "${BACKUP_DSN:-}" ]; then
  pg_dump --format=custom --clean --if-exists \
    --dbname="$BACKUP_DSN" --file="$TARGET/veyrs.dump"
elif id postgres >/dev/null 2>&1; then
  su -s /bin/bash postgres -c \
    "pg_dump --format=custom --clean --if-exists --dbname='$DB_NAME'" \
    > "$TARGET/veyrs.dump"
else
  echo "no superuser route to the database: set BACKUP_DSN to a BYPASSRLS role" >&2
  exit 1
fi

# A dump that failed mid-write is worse than no dump. Prove it is readable.
if ! pg_restore --list "$TARGET/veyrs.dump" > "$TARGET/veyrs.toc" 2>/dev/null; then
  echo "the dump is not a readable pg_restore archive -- aborting" >&2
  exit 1
fi
echo "    $(wc -l < "$TARGET/veyrs.toc") objects captured"

echo "==> configuration and key material"
install -m 600 "$APP_DIR/.env" "$TARGET/env"

echo "==> uploaded documents"
if [ -d "$APP_DIR/var/documents" ]; then
  tar czf "$TARGET/documents.tar.gz" -C "$APP_DIR/var" documents
fi

echo "==> manifest"
cat > "$TARGET/MANIFEST" <<MANIFEST
veyrs_backup_version: 1
created_utc: $(date -u +%FT%TZ)
host: $(hostname)
database: $(sed 's|://[^@]*@|://***@|' <<<"$VEYRS_DATABASE_URL")
app_version: $(cd "$APP_DIR" && PYTHONPATH=backend venv/bin/python -c \
  'from veyrs.config import settings; print(settings.version)' 2>/dev/null || echo unknown)
git_commit: $(cd "$APP_DIR" && git rev-parse --short HEAD 2>/dev/null || echo unknown)
contents: veyrs.dump env documents.tar.gz
restore: scripts/restore.sh $TARGET
MANIFEST

sha256sum "$TARGET"/* > "$TARGET/SHA256SUMS"
chmod -R go-rwx "$TARGET"

echo "==> pruning backups older than $RETAIN_DAYS days"
find "$BACKUP_DIR" -maxdepth 1 -type d -name 'veyrs-*' -mtime "+$RETAIN_DAYS" \
  -exec rm -rf {} + 2>/dev/null || true

echo "backup complete: $TARGET"
du -sh "$TARGET"
