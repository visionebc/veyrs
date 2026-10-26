#!/bin/bash
# VEYRS restore. Refuses to run without an explicit confirmation, because it
# DROPS and recreates the schema.
#
#   scripts/restore.sh /opt/veyrs/var/backups/veyrs-20260810-091500 --yes
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

echo "==> stopping the API so nothing writes mid-restore"
systemctl stop veyrs-api.service 2>/dev/null || true

echo "==> restoring database"
pg_restore --clean --if-exists --no-owner \
  --dbname="$(sed 's|postgresql+psycopg|postgresql|' <<<"$VEYRS_DATABASE_URL")" \
  "$SOURCE/veyrs.dump"

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
