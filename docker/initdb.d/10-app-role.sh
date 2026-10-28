#!/bin/bash
# Create the UNPRIVILEGED application role and its two databases. Runs ONCE,
# during the cluster's first initdb -- the postgres image only executes this
# directory when PGDATA is empty.
#
# ===========================================================================
# WHY THIS FILE EXISTS AT ALL
# ===========================================================================
# The obvious compose stack sets POSTGRES_USER=veyrs and lets the image create
# the role and the database. That role is a SUPERUSER, and a PostgreSQL
# superuser BYPASSES ROW LEVEL SECURITY UNCONDITIONALLY.
#
# 70 of VEYRS' 87 tables carry FORCE ROW LEVEL SECURITY. It is the mechanism
# that keeps one tenant's assets, findings and risk entries from being visible
# to another. Run the application as a superuser and every one of those
# policies silently stops applying: nothing errors, nothing logs, `\d` still
# lists the policies. A cross-tenant leak would be invisible in the container
# stack and fatal on a host install -- and the container stack is the one
# people will evaluate the product on.
#
# So the superuser here is `postgres` and the application role is created
# below with NOSUPERUSER, matching production exactly (rolsuper=false,
# rolcreatedb=false, rolcreaterole=false, rolcanlogin=true; owner of its own
# database and nothing more). tests/test_container_stack.py fails if
# POSTGRES_USER is ever pointed back at the application role, and
# scripts/test-docker-stack.sh proves the isolation on a live stack by reading
# a second tenant's rows and getting none.
#
# FORCE, not plain ENABLE, is what makes this matter: plain RLS already
# exempts the table owner, and the application role owns every table it
# creates. cli.init_db() sets FORCE on each one.
# ===========================================================================
set -euo pipefail

: "${VEYRS_DB_USER:?VEYRS_DB_USER is required}"
: "${VEYRS_DB_PASSWORD:?VEYRS_DB_PASSWORD is required}"
: "${VEYRS_DB_NAME:=veyrs}"

# CREATE DATABASE cannot run inside the transaction block that
# ON_ERROR_STOP + a multi-statement heredoc would otherwise imply, so the role
# and the databases are separate invocations.
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" <<-SQL
	CREATE ROLE "${VEYRS_DB_USER}"
	    LOGIN
	    NOSUPERUSER      -- the entire point of this file; see the header
	    NOCREATEDB
	    NOCREATEROLE
	    NOBYPASSRLS      -- explicit: the attribute a future ALTER might add
	    PASSWORD '${VEYRS_DB_PASSWORD}';
SQL

# Two databases, both OWNED by the application role.
#
# Ownership is required, not cosmetic: cli.init_db() issues ALTER TABLE ...
# ENABLE/FORCE ROW LEVEL SECURITY and CREATE POLICY, which only the owner (or a
# superuser) may do. A role that merely has CONNECT+CREATE on someone else's
# database gets through create_all() and then fails on the first ALTER, leaving
# a schema with tables and no policies -- the exact state this file exists to
# prevent, reached by a different road.
#
# ...._test is created here rather than by the test runner because scripts/
# test.sh refuses any database name that does not end in _test, and conftest
# refuses to run without one. Without it the suite cannot be run against the
# container stack at all.
for db in "${VEYRS_DB_NAME}" "${VEYRS_DB_NAME}_test"; do
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
	    -c "CREATE DATABASE \"${db}\" OWNER \"${VEYRS_DB_USER}\""
	# Revoke the implicit PUBLIC grant. Any role that can log in -- including
	# one added later for reporting or backups -- can otherwise connect to
	# both databases by default.
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
	    -c "REVOKE ALL ON DATABASE \"${db}\" FROM PUBLIC"
	psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
	    -c "GRANT ALL ON DATABASE \"${db}\" TO \"${VEYRS_DB_USER}\""
done

echo "[initdb] role '${VEYRS_DB_USER}' created NOSUPERUSER; databases:" \
     "${VEYRS_DB_NAME}, ${VEYRS_DB_NAME}_test"
