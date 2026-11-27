---
title: Backup and recovery, data view
purpose: Explain what must be preserved to restore VEYRS data, why a dump taken as the application role is unusable, how to verify a dump, and how the shipped scripts and the standby fit together.
scope: Data-level backup and restore strategy and verification; step-by-step operational procedures and drills stay in DISASTER_RECOVERY.md and HIGH_AVAILABILITY.md.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [scripts/backup.sh, scripts/restore.sh, infrastructure/backup/veyrs-pgdump.sh, infrastructure/backup/veyrs-pgverify.sh, infrastructure/backup/veyrs-replcheck.sh, infrastructure/backup/veyrs-pgdump.timer, infrastructure/backup/veyrs-pgverify.timer, infrastructure/backup/veyrs-replcheck.timer, docker/veyrs-docker.sh, tests/test_restore_as_superuser.py, backend/veyrs/cli.py]
related: [DISASTER_RECOVERY.md, HIGH_AVAILABILITY.md, DOCKER_COMPOSE_MANUAL.md, database/README.md, database/lifecycle.md]
---

# Backup and recovery, data view

This page explains **what** has to be backed up and **how to prove** a backup holds data. For the runbooks (taking a backup on a schedule, restoring, rehearsal, key rotation, host loss) follow [DISASTER_RECOVERY.md](../DISASTER_RECOVERY.md); for the standby and promotion runbook follow [HIGH_AVAILABILITY.md](../HIGH_AVAILABILITY.md); for the container stack see [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md).

## What a restorable backup contains

| Item | Why it is needed | Where it comes from |
|---|---|---|
| The PostgreSQL database (all 90 tables) | All business data, audit trails, credentials ciphertext | `pg_dump --format=custom` as a superuser |
| `VEYRS_ENCRYPTION_KEY` (and any `VEYRS_ENCRYPTION_KEY_PREVIOUS`) | Without it every stored third-party credential and every TOTP seed is unrecoverable ciphertext ([README](README.md#encryption-at-rest-of-columns)) | `.env`, copied into the archive by `scripts/backup.sh` |
| `VEYRS_SECRET_KEY` | Signs access tokens; losing it only forces users to sign in again | `.env` |
| External vault entries, when `VEYRS_SECRET_BACKEND` is `vault` or `mirror` | The database then holds only `vault:` references | the vault's own backup; not covered by VEYRS scripts |
| `var/documents/` | Copied by `backup.sh` when the directory exists; current releases keep extracted text in the database, so it is normally absent | `scripts/backup.sh` |

**Not backed up, by design:** Redis. It holds rate-limit counters, pending MFA codes, OIDC flow state and RADIUS challenges, all short-lived ([README](README.md#what-redis-holds)). After a restore, in-flight sign-ins simply start again.

**Re-fetchable instead of restored:** the intelligence catalogues (`cve`, `epss_*`, `kev_entries`, CPE) can be rebuilt with `sync-nvd --full`, `sync-epss` and `sync-kev`, but a restore is much faster than a full NVD backfill (`DISASTER_RECOVERY.md`, "Database corruption").

> [!IMPORTANT]
> The archive holds every tenant's data, every password hash and the encryption key. Treat it as equal in sensitivity to the live database: mode 0600 or 0700 directories, stored off the database host, and with the key never separated from the dump by the same access path as the data.

## The RLS trap: a dump as the application role is unusable

Every tenant table is `FORCE ROW LEVEL SECURITY`, which applies to the table **owner** as well, and the application role is the owner. The role must therefore never take or restore a dump. Observed and documented behaviours:

| Source | What happens |
|---|---|
| `docs/DISASTER_RECOVERY.md`, `docker/veyrs-docker.sh` (measured on a production node, 2026-09-21) | `pg_dump` as the application role fails with `query would be affected by row-level security policy for table "agent_job_events"` **after** `--format=custom` has already written a partial file: **392 KB where the good dump is 509 MB**. The filename and extension look normal. |
| `infrastructure/backup/veyrs-pgdump.sh` header comment | Describes the failure as a well-formed archive with empty tables and exit code 0. |

The two accounts differ; PostgreSQL documents the first (by default `pg_dump` sets `row_security` off and raises an error when the role cannot bypass it). Either way the file is not a backup, and **neither the exit code nor the file name nor `pg_restore --list` alone proves otherwise**, because the table of contents lists the tables whether or not their data blocks are present. Rules that follow:

1. Dump as a **superuser** (peer authentication as `postgres` on the database host) or as a dedicated role with `BYPASSRLS` and read access:

   ```sql
   -- psql as postgres on the database host
   CREATE ROLE veyrs_backup LOGIN BYPASSRLS PASSWORD 'REPLACE-WITH-A-LONG-RANDOM-VALUE';
   GRANT pg_read_all_data TO veyrs_backup;
   ```

   and point `BACKUP_DSN` at it (for example `postgresql://veyrs_backup@db.example.com:5432/veyrs`).
2. **Restore as a superuser** too, without `--no-owner`: the data load under RLS is refused table by table, and `--no-owner` as `postgres` would leave the tables owned by `postgres` and unusable by the API (`scripts/restore.sh` header; `tests/test_restore_as_superuser.py`).
3. **Verify the content, not the size** (next section).

## Verifying a dump

Run as a superuser, with the archive in a directory the `postgres` OS user can read (not `/root`, where `pg_dump` as `postgres` also cannot write; `/var/tmp` works):

```bash
# on the database host, as root; replace the path
sudo -u postgres pg_restore --list /var/tmp/veyrs.dump | grep -c 'TABLE DATA'
```

The count should equal the number of tables, **90** in 0.41.0 (`infrastructure/backup/veyrs-pgdump.sh` logged 78 data sections when the schema had 78 tables). A truncated dump shows a handful (the DR manual's example is "~3"). The container helper refuses anything under 50 (`docker/veyrs-docker.sh`, `cmd_backup`).

The stronger check, and the one the shipped timers use, compares **live row counts of tenant tables with the restored counts**, because those are exactly the tables an RLS-filtered dump empties. After restoring into a scratch database, as superuser:

```sql
-- psql as postgres, connected to the restored database
SELECT count(*) FROM organizations;                                   -- must be at least 1
SELECT count(*) FROM information_schema.tables WHERE table_schema = 'public';  -- 90 on 0.41.0
SELECT count(*) FROM pg_policies;                                     -- 72 on 0.39.1 (68 strict + 4 pre-auth)
```

A restore that loses policies would serve one tenant's rows to another, so the policy count belongs in every verification (`veyrs-pgverify.sh` compares it with production). A superuser sees every tenant, so an empty `organizations` table after a restore means the data did not load, not that RLS hides it (`scripts/restore.sh`).

## The shipped scripts

### `scripts/backup.sh`

Runs on the application host as root. Environment (all optional): `APP_DIR` (default `/opt/veyrs`), `BACKUP_DIR` (default `$APP_DIR/var/backups`), `RETAIN_DAYS` (default 30), `BACKUP_DSN`.

```bash
# application host, as root
/opt/veyrs/scripts/backup.sh
# remote or managed database: use a BYPASSRLS role
BACKUP_DSN='postgresql://veyrs_backup@db.example.com:5432/veyrs' /opt/veyrs/scripts/backup.sh
```

What it does, in order (`scripts/backup.sh`):

1. Reads `.env`, derives the database name and host from `VEYRS_DATABASE_URL`.
2. Dumps with `pg_dump --format=custom --clean --if-exists`: through `BACKUP_DSN` if set; otherwise as the `postgres` OS user over peer authentication, **only if the database host is this machine** (localhost); otherwise it refuses and tells you to set `BACKUP_DSN`. A local Postgres on an app node whose real database is elsewhere would otherwise produce a valid backup of the wrong server.
3. Checks that `pg_restore --list` can read the archive and writes the listing to `veyrs.toc`.
4. Copies `.env` (0600) as `env`, tars `var/documents` if it exists, writes `MANIFEST` and `SHA256SUMS`, and prunes backup directories older than `RETAIN_DAYS`.

**It does not check that tables contain data.** The readability test passes for a truncated archive. Add the `TABLE DATA` count above, or use the database-node set below, which does check.

### `scripts/restore.sh`

Destructive: it drops and recreates the schema contents of the target database.

> [!CAUTION]
> `restore.sh` stops `veyrs-api.service` on this host and replaces the database. Other application nodes that share the database must be stopped by hand first. Take a fresh backup of the current state before overwriting it.

```bash
# application host, as root; database on this host
/opt/veyrs/scripts/restore.sh /opt/veyrs/var/backups/veyrs-20261101-021500 --yes

# database on another host: RESTORE_DSN must be a superuser
RESTORE_DSN='postgresql://postgres@db.example.com:5432/veyrs' \
  /opt/veyrs/scripts/restore.sh /opt/veyrs/var/backups/veyrs-20261101-021500 --yes
```

Behaviour (`scripts/restore.sh`; the superuser-route, remote-database and empty-restore branches are covered by `tests/test_restore_as_superuser.py`):

- Requires the explicit `--yes`; without it, prints the manifest and exits 2.
- Verifies `SHA256SUMS` first.
- Chooses the superuser route **before** stopping the API or dropping anything: `RESTORE_DSN` (must report `rolsuper = t`, else it aborts before any change) or peer authentication as `postgres` when the database is local. With a remote database and no `RESTORE_DSN` it refuses.
- Runs `pg_restore --clean --if-exists`, then requires at least one row in `organizations`, else leaves the API stopped and exits non-zero.
- Restores `documents.tar.gz` if present.
- **Does not overwrite `.env`.** The key material is in the backup's `env`; compare `VEYRS_ENCRYPTION_KEY` before copying anything, because a different key makes every stored credential fail to decrypt.
- Re-runs `init-db` (idempotent) so a dump from an older release gains new tables, columns and policies, then starts the API. Check it with `curl -sf http://127.0.0.1:8000/readyz`.

A target database must be created `ENCODING 'UTF8'` from `template0`; a `SQL_ASCII` database restores with zero errors and then makes the application fail on `bytes` instead of `str` (`INSTALL.md` in the repository root, section 2; `veyrs-pgverify.sh` creates its scratch database that way).

## The database-node backup set

`infrastructure/backup/` holds three units for the **database node**. They are not installed by `install.sh`. Hostnames and addresses inside the scripts are deployment defaults and must be set for the target site through their environment variables.

| Unit | Schedule | What it does |
|---|---|---|
| `veyrs-pgdump.timer` / `.sh` | daily 02:15 UTC (random delay up to 5 min) | Refuses to run unless it is a superuser; counts live rows of the canary tables `assets`, `findings`, `organizations`, `users` **before** dumping; `pg_dump -Fc -Z6`; fails if the file is under 20 MB (`MIN_BYTES`), unreadable, or lacks a `TABLE DATA` section for a canary that has live rows; SHA-256; pushes to an off-host target as an unprivileged account and verifies the remote checksum; local retention 7 days, off-host 30 days; deletes old dumps only after the new one is proven. Writes `status=ok` or `failed` to a state file. |
| `veyrs-pgverify.timer` / `.sh` | Sundays 04:30 UTC (random delay up to 10 min) | Creates a scratch database `veyrs_restore_check` (UTF8 from `template0`), restores the newest dump there as `postgres`, compares row counts of `assets`, `findings`, `organizations`, `users`, `asset_products`, `import_runs` and the `pg_policies` count with production, drops the scratch database. |
| `veyrs-replcheck.timer` / `.sh` | every 15 minutes after a 5-minute boot delay | Fails the unit if the replication slot is missing, inactive or `lost`, the walsender is not `streaming`, or lag exceeds 128 MiB of WAL. |

> [!NOTE]
> The `failed` state of these units is only visible in `systemctl --failed` and the journal. `docs/HIGH_AVAILABILITY.md` records that nothing alerts on it yet, so a failed nightly backup can go unnoticed. Alerting is a fleet-level task, not part of the scripts.

On the application node inspected on 2026-11-17 none of these timers were present (only `veyrs-digest.timer` and `veyrs-intel-sync.timer` matched), and `/opt/veyrs/var/backups` did not exist there, which is consistent with the set living on the database node. The database node was not reachable from the documentation environment, so whether the three timers are active there is **Unknown**.

## The container stack

`docker/veyrs-docker.sh backup` runs `pg_dump -U postgres -Fc` inside the database container, counts `TABLE DATA` entries and refuses a dump with fewer than 50. With an **external** database (`compose.external-db.yaml`) it refuses to run at all: back up where the database lives, as a superuser or `BYPASSRLS` role. The script has no `restore` command; the restore procedure for the stack is in [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md).

## Standby replication: what it protects

Streaming replication is **not** a backup: it copies a `DROP TABLE` within milliseconds. The documented design (`docs/HIGH_AVAILABILITY.md`, phase 2) is:

- PostgreSQL 15 physical streaming replication with a replication slot, asynchronous, `hot_standby = on`, `hot_standby_feedback = on`.
- The standby mirrors the primary's tuning (`shared_buffers`, `work_mem`, `max_connections`) so promotion does not become a capacity incident.
- The primary bounds retained WAL with `max_slot_wal_keep_size = 20GB`; beyond that the slot is invalidated (`wal_status = 'lost'`) and the standby must be rebuilt with `pg_basebackup`, instead of the primary's disk filling.
- **Promotion is manual.** Two primaries cannot be reconciled; confirm the old primary is truly gone first.
- Redis is not replicated. As documented there it "holds rate-limit counters and cache only"; the code also keeps MFA codes and SSO state in it ([README](README.md#what-redis-holds)), so after a failover e-mail or Telegram codes and in-flight SSO logins restart.
- What the standby protects: loss of the database node. It does not protect against loss of the physical host it runs on, nor against logical damage.

The data-level consequence: the recovery objective for **logical** damage (a bad `DELETE`, a mistaken tenant removal) is the last verified dump, not the standby.

## Data loss window after a restore

Findings, ticket updates and audit rows written since the backup are lost. Scanner imports are idempotent (findings dedupe on `(organization_id, asset_id, dedupe_key)`), so re-running imports since the backup timestamp is safe ([lifecycle.md](lifecycle.md#finding-identity-reopening-and-closure)). A removed organization is recoverable only from a backup ([lifecycle.md](lifecycle.md#cascade-deletes-when-an-organization-is-removed)).

## Sources

- `scripts/backup.sh`, `scripts/restore.sh`, `tests/test_restore_as_superuser.py`
- `infrastructure/backup/veyrs-pgdump.sh`, `veyrs-pgverify.sh`, `veyrs-replcheck.sh` and their timers
- `docker/veyrs-docker.sh` (`cmd_backup`)
- `docs/DISASTER_RECOVERY.md`, `docs/HIGH_AVAILABILITY.md`
