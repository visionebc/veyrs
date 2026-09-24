#!/bin/bash
# One-shot initialiser. Runs to completion before the API starts, every `up`.
#
# It must be safe to run on an empty cluster AND on a cluster that has been
# serving for a year. Those are the same command; the difference is entirely in
# the guards below.
set -euo pipefail

say() { printf '[init] %s\n' "$*"; }

# ---------------------------------------------------------------------------
# 1. The data volume.
#
# Named volumes are created EMPTY AND ROOT-OWNED on first `up`, whatever the
# image did to the directory at build time -- Docker populates a volume from
# the image only for the contents, not the ownership of the mount point. The
# API runs as uid 10001, so without this it starts normally and then fails the
# first time it writes an evidence file or a report, which is not at startup.
#
# This service runs as root purely for this step.
# ---------------------------------------------------------------------------
VAR_DIR=/opt/veyrs/var
mkdir -p "$VAR_DIR"
chown -R 10001:10001 "$VAR_DIR"
say "data directory $VAR_DIR owned by uid 10001"

# ---------------------------------------------------------------------------
# 2. Schema.
#
# `init-db` and NOT `sync-schema`: sync-schema reconciles COLUMNS on tables
# that already exist. Pointed at an empty database it prints
# "0 columns, 0 indexes, 0 constraints added" and exits 0 -- a success message
# from a run that created nothing. init-db creates the tables, reconciles
# columns, then binds row level security and seeds the role and compliance
# catalogues.
#
# Idempotent: create_all() skips existing tables, the policy statements are
# DROP-then-CREATE, and both seeders upsert.
# ---------------------------------------------------------------------------
say "applying schema (create tables, reconcile columns, bind RLS, seed)"
python -m veyrs.cli init-db

# ---------------------------------------------------------------------------
# 3. The first administrator -- and the guard that stops this from being a
#    password reset on every restart.
#
# `cli bootstrap` is deliberately idempotent in the wrong direction for us: on
# an existing user it REWRITES the password hash and prints "user exists,
# password reset". Called unconditionally from a service that runs on every
# `up`, that means any operator who changed the admin password has it silently
# reverted to whatever is in .env the next time the stack is restarted --
# including after an unattended reboot.
#
# So the existence check happens FIRST, and it happens as the POSTGRES
# SUPERUSER. `users` is RLS-forced (credential-keyed: permissive only while no
# tenant is bound), and a wrong answer here is not symmetric -- a false "no
# admin" performs exactly the reset this guard exists to prevent, while a false
# "admin exists" only skips a step an operator can run by hand.
# ---------------------------------------------------------------------------
ADMIN_ORG="${VEYRS_ADMIN_ORG:-veyrs}"
ADMIN_EMAIL="${VEYRS_ADMIN_EMAIL:-admin@veyrs.local}"

if [[ "${VEYRS_FORCE_BOOTSTRAP:-0}" == "1" ]]; then
    say "VEYRS_FORCE_BOOTSTRAP=1 -- the admin password WILL be reset"
    exists=0
else
    exists=$(python - <<'PY'
import os, sys
import psycopg

# Keyword arguments, not a "key=value" DSN string: an external database's
# password may contain spaces or quotes, which a DSN string would split.
conninfo = dict(
    host=os.environ["VEYRS_DB_HOST"], port=os.environ.get("VEYRS_DB_PORT", "5432"),
    dbname=os.environ["VEYRS_DB_NAME"], user=os.environ["VEYRS_DB_SUPERUSER"],
    password=os.environ["VEYRS_DB_SUPERUSER_PASSWORD"], connect_timeout=10,
)
org = os.environ.get("VEYRS_ADMIN_ORG", "veyrs")
email = os.environ.get("VEYRS_ADMIN_EMAIL", "admin@veyrs.local").lower()
try:
    with psycopg.connect(**conninfo) as conn, conn.cursor() as cur:
        cur.execute(
            "SELECT 1 FROM users u JOIN organizations o ON o.id = u.organization_id "
            "WHERE o.slug = %s AND lower(u.email) = %s LIMIT 1",
            (org, email),
        )
        print(1 if cur.fetchone() else 0)
except Exception as exc:  # noqa: BLE001
    # Fail CLOSED. An unreadable answer must not be treated as "no admin" --
    # that is the branch that rewrites a password.
    print(f"init: could not determine whether the admin exists: {exc}", file=sys.stderr)
    raise SystemExit(3)
PY
    )
fi

if [[ "$exists" == "1" ]]; then
    say "bootstrap not run: ${ADMIN_EMAIL} already exists in '${ADMIN_ORG}'"
    say "  (set VEYRS_FORCE_BOOTSTRAP=1 to reset that password on purpose)"
else
    if [[ -z "${VEYRS_ADMIN_PASSWORD:-}" ]]; then
        # Refused HERE rather than by the prompt: `cli bootstrap` asks via
        # getpass(), and a service container has no terminal. Left to fail on
        # its own it would block or read EOF after the schema is already built,
        # which reads as a broken initialiser rather than a missing setting.
        echo "[init] VEYRS_ADMIN_PASSWORD is not set and no administrator exists." >&2
        echo "[init] Set it in .env (not on the command line -- an argument is" >&2
        echo "[init] visible in ps(1)) and bring the stack up again." >&2
        exit 78   # EX_CONFIG
    fi
    say "creating organization '${ADMIN_ORG}' and administrator ${ADMIN_EMAIL}"
    # By ENVIRONMENT, never --password. A container has its own PID namespace
    # but its processes are still in the HOST's process table: an argument
    # here is readable by every account on the Docker host in ps(1) for as
    # long as the argon2 hash takes. A prefix assignment is not an argument.
    VEYRS_BOOTSTRAP_PASSWORD="$VEYRS_ADMIN_PASSWORD" python -m veyrs.cli bootstrap \
        --org "$ADMIN_ORG" \
        --email "$ADMIN_EMAIL" \
        ${VEYRS_ADMIN_NAME:+--name "$VEYRS_ADMIN_NAME"} \
        ${VEYRS_ADMIN_FULL_NAME:+--full-name "$VEYRS_ADMIN_FULL_NAME"}
fi

say "done"
