# Disaster Recovery

## Objectives

| | Target | Basis |
|---|---|---|
| RPO | 24 hours | Nightly backup. Lower it by raising backup frequency; the script is idempotent |
| RTO | 1 hour | Restore + verification on comparable hardware |

These are the *design* targets. They become real numbers only after a rehearsal,
and **no rehearsal has been performed against this build**.

## What must be backed up

| Item | Where | Without it |
|---|---|---|
| PostgreSQL database | `scripts/backup.sh` — **not** a hand-run `pg_dump` (see below). Includes uploaded documents (`documents` table: metadata and extracted text; the original bytes are not kept) and compliance evidence | Everything is lost |
| `VEYRS_ENCRYPTION_KEY` | `.env` | Every stored third-party credential is unrecoverable ciphertext |
| `VEYRS_SECRET_KEY` | `.env` | All sessions invalidated (recoverable - users re-login) |
| Application code | GitHub `visionebc/veyrs` releases | Re-downloadable |

The archive therefore contains key material and **is as sensitive as the
database itself**: mode 0600, and it must be shipped off the host.

## Taking a backup

> ### `pg_dump` as the application role produces a truncated backup that looks fine
>
> 72 of the 89 tables carry `FORCE ROW LEVEL SECURITY`, and **forcing it applies
> to the table owner too**. The `veyrs` role owns the database and every table
> in it and is still refused:
>
> ```
> pg_dump: error: query failed: ERROR:  query would be affected by row-level
> security policy for table "agent_job_events"
> ```
>
> `--format=custom` writes as it goes, so what is left behind is a file with
> every appearance of a backup. Measured on production, 2026-09-21:
> **392 KB where the good dump is 509 MB.** Nothing about the filename, the
> extension or the exit path tells you which one you have.
>
> `scripts/backup.sh` already does this correctly — it dumps as the `postgres`
> superuser over peer authentication (or via a `BYPASSRLS` role in `BACKUP_DSN`
> for a managed or remote cluster) and then proves the archive is readable
> (`pg_restore --list`). It does not check the size or row counts — verify by
> listing, below. **Use it.** The equivalent for the container stack is
> `docker/veyrs-docker.sh backup`, which runs `pg_dump -U postgres` inside the
> database container and refuses a dump carrying fewer than 50 tables of data.
>
> If you must do it by hand, verify by **listing**, never by size — half a
> megabyte is entirely plausible for a small installation:
>
> ```bash
> pg_restore --list veyrs.dump | grep -c 'TABLE DATA'   # expect ~87, not ~3
> ```


```bash
/opt/veyrs/scripts/backup.sh
# -> /opt/veyrs/var/backups/veyrs-YYYYMMDD-HHMMSS/
#     veyrs.dump  veyrs.toc  env  documents.tar.gz  MANIFEST  SHA256SUMS
```

`MANIFEST` records the UTC timestamp, host, app version and git commit.
`SHA256SUMS` covers every file. Retention defaults to 30 days (`RETAIN_DAYS=`).
`documents.tar.gz` is a copy of `var/documents/` when that directory exists;
current releases keep uploaded documents in the database, so it is normally
empty.

Schedule it via cron or a systemd timer, then **copy it off the host** - a
backup on the same disk as the database is not a backup.

The repository also ships a database-node backup set in
`infrastructure/backup/` (not installed by `install.sh`): `veyrs-pgdump.timer`
(nightly logical dump as `postgres`, row-count checks, off-host push),
`veyrs-pgverify.timer` (Sundays 04:30: restores the latest dump into a scratch
database and compares row counts and the RLS policy count against production)
and `veyrs-replcheck.timer` (standby health every 15 minutes). See
[High availability](/HIGH_AVAILABILITY.html#logical-backups-2026-08-17).

## Restoring

```bash
/opt/veyrs/scripts/restore.sh /path/to/veyrs-20260810-091500 --yes
```

The script refuses to run without `--yes`, verifies checksums first, stops the
API so nothing writes mid-restore, runs `pg_restore --clean --if-exists`,
checks that organizations came back, restores documents, re-applies schema and
RLS, and restarts.

**It restores as a database superuser, never as the application role.** Every
tenant table is `FORCE ROW LEVEL SECURITY`, which binds the table owner too, so
a restore as `veyrs` has its data load refused after `--clean` has already
dropped the old schema (this is what the script did before 0.35.3). When the
database in `VEYRS_DATABASE_URL` is on the same host, it uses peer
authentication as the `postgres` OS user. When the database is elsewhere, set
`RESTORE_DSN` to a superuser connection string for that server, or run the
restore on the database host; without either, the script stops before it
touches anything:

```bash
RESTORE_DSN='postgresql://postgres:...@db-host:5432/veyrs' \
  /opt/veyrs/scripts/restore.sh /path/to/veyrs-20260810-091500 --yes
```

Stop the API on every other application node that shares the database first;
the script only stops the one it runs on. `scripts/backup.sh` applies the same
rule in the other direction: it refuses peer authentication when the database
is not local, so it cannot dump a different Postgres that happens to run on the
application node.

**It deliberately does not overwrite `.env`.** If the backup's
`VEYRS_ENCRYPTION_KEY` differs from the current one, every stored third-party
credential will fail to decrypt. Compare before copying:

```bash
grep ENCRYPTION_KEY /path/to/backup/env /opt/veyrs/.env
```

## Scenarios

### Database corruption

1. `systemctl stop veyrs-api`
2. Restore the most recent good backup
3. `curl -sf http://127.0.0.1:8000/readyz`
4. Re-run scanner imports since the backup timestamp - findings are
   deduplicated, so re-importing is safe and idempotent.

**Data loss window:** findings and ticket updates since the last backup.
Intelligence (CVE/EPSS/KEV) is re-fetchable in full: `veyrs sync-nvd --full`,
`sync-epss`, `sync-kev`.

### Host loss

1. Provision a comparable container/VM
2. Follow Deployment steps 1-4
3. Restore instead of `init-db`
4. Re-point DNS (or the reverse proxy's upstream) at the new host

### Planned key rotation (the old key is known)

Use this when `VEYRS_ENCRYPTION_KEY` may have been exposed but is still
available. Nothing is lost and nobody re-enters a credential:

1. `veyrs keygen` - put the new key in `VEYRS_ENCRYPTION_KEY` and the old one
   in `VEYRS_ENCRYPTION_KEY_PREVIOUS` (comma-separated if there are several),
   on **every** API node, then restart them. From now on new values are sealed
   with the new key; old ones still open with the previous one.
2. `veyrs secrets rekey` (dry run) - how many local copies are still under an
   old key, and any row no configured key opens.
3. `veyrs secrets rekey --apply` - re-seals every local copy (`v1:` values and
   the local half of `vm1:` mirror values) under the new key. Compare-and-swap
   per row; a second run converts nothing.
4. Remove `VEYRS_ENCRYPTION_KEY_PREVIOUS` everywhere and restart. A value only
   the old key opened would now fail loudly instead of silently.
5. Take a fresh backup: older backups carry the old key in their `env`.

`vault:` values have no local copy and are not touched. Rotating
`VEYRS_SECRET_KEY` is independent (it signs access tokens only): change it on
every node and restart; users sign in again, refresh tokens and API keys are
hashes and keep working.

### Encryption key loss with an intact database

Everything except third-party credentials survives. Recovery:

1. Generate a new key, set `VEYRS_ENCRYPTION_KEY`
2. `NULL` out every encrypted column listed in
   [SECURITY.md §Secrets at rest](/SECURITY.html#secrets-at-rest) (`api_key_enc`,
   `credentials_enc`, `inbound_secret_enc`, `secret_enc`, `users.mfa_secret`,
   the LDAP `bind_password_enc`)
3. Re-enter the credentials through the API; users who had TOTP are reset with
   `veyrs mfa-reset --email USER --reason TEXT` and re-enrol

There is no way around this. That is the point of encryption at rest.

### Accidental tenant deletion

There is no API route or console action that deletes an organization; it
happens only in SQL, and it cascades to every tenant row. There is no
soft-delete for organizations, so restore from backup is the only route. **A tenant deletion should be treated as
a change request, not a click.**

## Rehearsing

A backup that has never been restored is a hypothesis. Quarterly:

1. Restore the latest backup into a scratch database
2. Point a staging instance at it
3. Log in; verify finding counts against the production dashboard
4. Run the test suite against the restored database
5. Record the elapsed time - that is the real RTO

## Continuity of intelligence

If NVD/EPSS/CISA are unreachable, VEYRS keeps working on cached data. Feed
freshness is visible at `GET /api/v1/intel/health`, and the compliance signal
`threat_feeds_active` reports staleness as a control finding rather than letting
it pass unnoticed.
