---
title: Backup, restore and disaster recovery
purpose: Give complete, copy-pasteable runbooks to back up, verify, restore and rehearse VEYRS, rotate its keys and recover from the failures that matter.
scope: Native and Docker backups, scheduled logical backups on the database node, restore, drills, key rotation and loss, standby promotion summary; the topology rationale is in HIGH_AVAILABILITY.md and the policy summary in DISASTER_RECOVERY.md.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [scripts/backup.sh, scripts/restore.sh, infrastructure/backup/veyrs-pgdump.sh, infrastructure/backup/veyrs-pgverify.sh, infrastructure/backup/veyrs-replcheck.sh, infrastructure/backup, docker/veyrs-docker.sh, backend/veyrs/cli.py, backend/veyrs/services/secret_storage.py, backend/veyrs/db.py, backend/veyrs/config.py]
related: [DISASTER_RECOVERY.md, HIGH_AVAILABILITY.md, operations/upgrade-rollback.md, operations/monitoring.md, troubleshooting/README.md, SECURITY.md, DATABASE.md]
---

# Backup, restore and disaster recovery

> [!CAUTION]
> **Never take a backup with a bare `pg_dump` as the application role.** 73 of the 89
> tables carry `FORCE ROW LEVEL SECURITY`, which binds the table owner too. `pg_dump`
> as the `veyrs` role is refused partway (`query would be affected by row-level
> security policy for table "..."`) after `--format=custom` has already written a
> plausible file: measured on production on 2026-09-21 as 392 KB where the good dump
> was 509 MB. Use `scripts/backup.sh`, `docker/veyrs-docker.sh backup` or the
> database-node units below, and **verify by listing the archive, never by size**.
> The same applies to a restore: it must run as a superuser.

## What to back up

| Item | Where | Without it | Covered by |
|---|---|---|---|
| PostgreSQL database `veyrs` | database node | everything is lost | `backup.sh`, `veyrs-pgdump`, `veyrs-docker backup` |
| `VEYRS_ENCRYPTION_KEY` (and `VEYRS_ENCRYPTION_KEY_PREVIOUS` during a rotation) | `/opt/veyrs/.env` | every stored third-party credential and every TOTP secret is unrecoverable ciphertext | `backup.sh` copies `.env`; keep a second copy somewhere that is not the database host |
| `VEYRS_SECRET_KEY` | `.env` | all sessions invalidated; users sign in again | same |
| Uploaded documents | rows of the `documents` table in the database. `var/documents` (native) and the `veyrs-var` volume (Docker) exist, but no code in 0.39.1 writes uploaded documents there: the API writes only update uploads under `var/update-uploads` | nothing, in 0.39.1 | the database dump; `backup.sh` archives `var/documents` if the directory exists (normally empty); the Docker `backup` verb does not include the volume |
| Vault configuration | `VEYRS_VAULT_*` in `.env` and the vault's own backups | credentials held only in the vault are lost with the vault | your vault's procedure |
| Code | release assets or git | re-downloadable | n/a |
| Redis | none | only rate-limit windows and short-lived codes | not needed |

The archive contains key material, so it is as sensitive as the database: mode 0600,
and it must leave the host. A backup on the same disk as the database protects you
from mistakes, not from losing the disk.

Targets are design figures: **RPO 24 h** (nightly backup) and **RTO 1 h** on
comparable hardware. They become real numbers only after a rehearsal, and none has
been performed against this build ([Restore drill](#restore-drill)).

## Native backup: `scripts/backup.sh`

Run on the application node that holds `/opt/veyrs/.env`, as root:

```bash
/opt/veyrs/scripts/backup.sh
# -> /opt/veyrs/var/backups/veyrs-YYYYMMDD-HHMMSS/
#    veyrs.dump  veyrs.toc  env  documents.tar.gz  MANIFEST  SHA256SUMS
```

What it does: dumps as the `postgres` OS user over peer authentication
(`pg_dump --format=custom --clean --if-exists`), proves the archive is readable
with `pg_restore --list` (writing `veyrs.toc`) and **refuses a dump that has fewer `TABLE DATA`
entries than tables** (a truncated or RLS-filtered archive still lists cleanly), copies `.env` (0600), archives
`var/documents` if present, writes a `MANIFEST` (time, host, app version, git
commit) and `SHA256SUMS`, sets the directory to 0700, and deletes backups older than
`RETAIN_DAYS` (default 30).

| Variable | Default | Purpose |
|---|---|---|
| `APP_DIR` | `/opt/veyrs` | where `.env` is read |
| `BACKUP_DIR` | `/opt/veyrs/var/backups` | destination |
| `RETAIN_DAYS` | `30` | pruning |
| `BACKUP_DSN` | unset | a connection string for a superuser or `BYPASSRLS` role, **required when the database is on another host**. Keep it in the root-only `/etc/veyrs/backup.env` (loaded by `backup.sh` and by `veyrs-updater.service`) rather than in `.env`, which the API's `veyrs` account can read |
| `BACKUP_ENV` | `/etc/veyrs/backup.env` | optional root-only file sourced after `.env` |

The script refuses peer authentication when the database in `VEYRS_DATABASE_URL` is
not local: a node that carries a local PostgreSQL only for `veyrs_test` would
otherwise produce a well-formed backup of the wrong server. For a remote or managed
database create a dedicated backup role (run as the server's superuser):

```sql
CREATE ROLE veyrs_backup LOGIN BYPASSRLS PASSWORD '<strong>';
GRANT pg_read_all_data TO veyrs_backup;
```

```bash
BACKUP_DSN='postgresql://veyrs_backup:CHANGE_ME@db.example.com:5432/veyrs' /opt/veyrs/scripts/backup.sh
```

Schedule it and ship the result off the host (cron shown; a systemd timer works the
same):

```bash
cat > /etc/cron.d/veyrs-backup <<'EOF'
30 2 * * * root /opt/veyrs/scripts/backup.sh >>/var/log/veyrs-backup.log 2>&1 && rsync -a --chmod=go-rwx /opt/veyrs/var/backups/ backup@192.0.2.50:/srv/veyrs-backups/
EOF
```

### Verify a dump

Size cannot tell a truncated dump from a small database. List it:

```bash
pg_restore --list /path/veyrs.dump | grep -c 'TABLE DATA'    # close to the table count (89 in 0.39.1)
pg_restore --list /path/veyrs.dump | grep 'TABLE DATA' | grep -E ' (assets|findings|organizations|users) '
```

`docker/veyrs-docker.sh backup` refuses a dump with fewer than 50 `TABLE DATA`
entries. A count near 3 means the dump was refused partway by row level security.
`pg_restore` 15 or newer must be on the host that lists the archive.

## Scheduled logical backups

These run on the database node. `infrastructure/backup/` holds three timers. They are **not** installed by
`install.sh`, and they assume PostgreSQL runs locally on the database node under the
OS account `postgres`, database `veyrs`.

| Timer | Does |
|---|---|
| `veyrs-pgdump.timer` (02:15 daily) | records live row counts of `assets`, `findings`, `organizations`, `users`; dumps as `postgres` with `pg_dump -Fc -Z6`; rejects a dump under 20 MB (`MIN_BYTES`) or lacking `TABLE DATA` for any canary with live rows; writes `<dump>.sha256`; pushes the dump and checksum off-host over ssh and compares the remote SHA-256; prunes local copies after 7 days (`KEEP_LOCAL_DAYS`) and remote after 30 (`KEEP_REMOTE_DAYS`) **only after** the new one is proven. Refuses to run unless the connected role is a superuser; refuses to call an on-host-only dump a backup |
| `veyrs-pgverify.timer` (Sunday 04:30) | restores the latest local dump into scratch database `veyrs_restore_check` (UTF8, `template0`) as `postgres` and compares row counts of `assets`, `findings`, `organizations`, `users`, `asset_products`, `import_runs` **and the RLS policy count** with the live database; drops the scratch database |
| `veyrs-replcheck.timer` (every 15 min) | slot active and not `lost`, walsender `streaming`, lag under 128 MB; the unit fails otherwise |

Install and configure, as root on the database node (the units execute
`/usr/local/sbin/veyrs-*.sh`):

```bash
cd /opt/veyrs/infrastructure/backup
install -m 755 veyrs-pgdump.sh veyrs-pgverify.sh veyrs-replcheck.sh /usr/local/sbin/
install -m 644 veyrs-pgdump.service veyrs-pgdump.timer veyrs-pgverify.service veyrs-pgverify.timer \
               veyrs-replcheck.service veyrs-replcheck.timer /etc/systemd/system/

# The off-host target is site specific. Set it for YOUR site (the script defaults name a private address).
systemctl edit veyrs-pgdump.service        # add:
#   [Service]
#   Environment=REMOTE_HOST=backup.example.com REMOTE_USER=veyrsbak REMOTE_DIR=/var/backups/veyrs-offhost
systemctl edit veyrs-replcheck.service     # add: Environment=STANDBY_IP=192.0.2.87 SLOT=veyrs_db_a2

# A dedicated, unprivileged key. A root key on the target would turn a compromise of the
# database node into root on the backup host.
ssh-keygen -t ed25519 -N '' -f /root/.ssh/id_veyrs_backup
#   on the target: create user veyrsbak owning REMOTE_DIR; authorize the key with the 'restrict' option

systemctl daemon-reload
systemctl enable --now veyrs-pgdump.timer veyrs-pgverify.timer veyrs-replcheck.timer
systemctl start veyrs-pgdump.service       # first run now; then read the result:
cat /var/lib/veyrs-backup/status
```

The off-host target must be a **different physical machine** from the database. If it
shares the machine, losing the machine loses every copy. Streaming replication is not a
backup either: it replicates a `DROP TABLE` within milliseconds.

## Docker backup

```bash
docker/veyrs-docker.sh backup                                  # -> ./veyrs-YYYYMMDD-HHMMSS.dump
docker/veyrs-docker.sh backup /var/backups/veyrs/nightly.dump
# the documents/evidence volume is NOT in the dump:
docker run --rm -v veyrs_veyrs-var:/data:ro -v "$PWD":/out postgres:15-bookworm \
  tar -czf /out/veyrs-var-$(date -u +%Y%m%d).tar.gz -C /data .
cp docker/.env /safe/place/veyrs.env        # setup installs: /opt/veyrs-docker/veyrs.env; holds the keys
```

The driver dumps with `pg_dump -U postgres ... -Fc` inside the `postgres` container
and refuses to run against an external database (there is no superuser credential
in the stack): back that up where it lives, as its superuser or a `BYPASSRLS` role. A
refused backup **leaves the file on disk**; delete it before a job mistakes it for a
good one.

## Restore

### Native, with `scripts/restore.sh`

> [!CAUTION]
> This **drops and recreates** the schema of the VEYRS database (`pg_restore --clean
> --if-exists`). Take a fresh backup of the current state first if there is any chance
> you need it.

```bash
/opt/veyrs/scripts/restore.sh /opt/veyrs/var/backups/veyrs-20260810-091500 --yes
```

Without `--yes` it prints the manifest and refuses. In order it: verifies
`SHA256SUMS`; selects a **superuser** route (peer authentication as `postgres` when
the database is on this host, otherwise `RESTORE_DSN`, checked to be a superuser
**before** anything is dropped); stops `veyrs-api`; restores; aborts with the API left
stopped if no `organizations` row came back (a superuser sees every tenant, so an empty
table means the load failed); restores documents; **does not overwrite `.env`**; runs
`init-db`; starts `veyrs-api`.

```bash
# Database on another host:
RESTORE_DSN='postgresql://postgres:CHANGE_ME@db.example.com:5432/veyrs' \
  /opt/veyrs/scripts/restore.sh /path/to/veyrs-20260810-091500 --yes
```

Then, always:

```bash
# Stop veyrs-api on EVERY other application node sharing the database BEFORE the restore (the script stops only its own).
grep ENCRYPTION_KEY /path/to/backup/env /opt/veyrs/.env    # the keys must match
curl -sf http://127.0.0.1:8000/readyz && curl -s http://127.0.0.1:8000/healthz
```

If `VEYRS_ENCRYPTION_KEY` in the backup's `env` differs from the current one, copy
the backup's value over before starting the API, or every stored credential will fail
to decrypt ([Key loss](#encryption-key-loss-with-an-intact-database)). Start the other
nodes only afterwards.

### Native, by hand (database node, or a dump from `veyrs-pgdump`)

Use this when `restore.sh` does not fit (database node, rebuilt host). The dump from
`veyrs-pgdump` has no `--clean`, so restore into an empty database, as `postgres`,
**without** `--no-owner` (the dump assigns tables to the application role; with
`--no-owner` they would belong to `postgres` and `init-db` could not re-apply the
policies):

```bash
systemctl stop veyrs-api                                    # on every application node
su postgres -c "createdb -E UTF8 -T template0 -O veyrs veyrs"   # drop the old one first if it exists; UTF8, never SQL_ASCII
su postgres -c "pg_restore -d veyrs --exit-on-error /var/backups/veyrs/veyrs-<stamp>.dump"
cd /opt/veyrs && PYTHONPATH=backend venv/bin/python -m veyrs init-db   # idempotent: re-applies policies, seeds roles
systemctl start veyrs-api
```

Check as the superuser that structure survived (a restore that loses policies would
serve one tenant's data to another):

```bash
su postgres -c "psql -d veyrs -tAc \"select count(*) from pg_class where relkind='r' and relforcerowsecurity\""   # 72 in 0.39.1
su postgres -c "psql -d veyrs -tAc \"select count(*) from pg_policies\""
su postgres -c "psql -d veyrs -tAc \"select count(*) from organizations\""
```

`createdb -E UTF8 -T template0` is not optional: inheriting `SQL_ASCII` from
`template1` makes psycopg return `bytes`, and `pg_restore` still reports zero errors.

### Docker

```bash
C="docker compose --project-directory docker -f docker/compose.yaml --profile workers --profile agent"
DUMP=/var/backups/veyrs/veyrs-20260101.dump
pg_restore --list "$DUMP" | grep -c 'TABLE DATA'        # verify first
docker/veyrs-docker.sh down
docker volume rm veyrs_veyrs-pgdata                     # DESTRUCTIVE: only with a verified dump in hand
$C up -d --wait postgres                                # initdb.d recreates the application role and empty databases
$C cp "$DUMP" postgres:/var/tmp/veyrs.dump
$C exec -T postgres pg_restore -U postgres -d veyrs /var/tmp/veyrs.dump   # as the superuser, without --no-owner
$C exec -T postgres rm -f /var/tmp/veyrs.dump
docker/veyrs-docker.sh up --with-workers                # init re-applies init-db and finds the administrator
```

Use the `docker/.env` that belongs to this data (same `VEYRS_ENCRYPTION_KEY` and
`VEYRS_DB_USER`). The full procedure with the documents volume is in the
[Docker Compose manual §10](../DOCKER_COMPOSE_MANUAL.md#10-backup-and-restore).

## Restore drill

A backup that has never been restored is a hypothesis. Do this quarterly, and after
any change to the backup procedure. It is also the only way to learn the real RTO.

1. Provision a scratch host or use the database node's spare capacity. Record the start time.
2. Restore the latest backup into a scratch database as in the by-hand procedure, with a different database name.
3. Compare against production as the superuser: `count(*)` of `organizations`, `users`, `assets`, `findings`; `pg_policies` count; `relforcerowsecurity` count.
4. Point a staging API at the scratch database (a separate `.env`, `VEYRS_ENVIRONMENT=development`) and sign in; compare finding counts with the production dashboard.
5. Run `./scripts/test.sh` against the restored data only on a database whose name ends in `_test`; the suite refuses anything else.
6. Record the elapsed time and the problems found. Drop the scratch database.

`veyrs-pgverify` automates steps 2 and 3 weekly for the latest dump; it proves the
data and the policies come back, not that the application works on them.

## Key rotation and key loss

### `VEYRS_ENCRYPTION_KEY`, planned (the old key is known)

Nothing is lost and nobody re-enters a credential. On **every** API node:

```bash
cd /opt/veyrs
veyrs() { PYTHONPATH=backend venv/bin/python -m veyrs "$@"; }
veyrs keygen                                  # prints a new Fernet key
# 1. In .env: VEYRS_ENCRYPTION_KEY=<new>   VEYRS_ENCRYPTION_KEY_PREVIOUS=<old>   (comma-separated if several)
systemctl restart veyrs-api                   # new values are sealed with the new key; old ones still open
veyrs secrets rekey                           # dry run: how many copies are under an old key, any row no key opens
veyrs secrets rekey --apply                   # re-seals every local copy (compare-and-swap per row; a second run converts nothing)
# 2. Remove VEYRS_ENCRYPTION_KEY_PREVIOUS from .env on every node; systemctl restart veyrs-api
```

Then take a fresh backup: older archives carry the old key in their `env`. `vault:`
values have no local copy and are not touched. Production refuses to boot if
`VEYRS_ENCRYPTION_KEY_PREVIOUS` contains the current key. Related commands:
`veyrs secrets status` (backend, vault health, counts per column and mode),
`veyrs secrets migrate --to local|mirror|vault [--apply]`, `veyrs secrets gc [--apply]`
([System manual §3](../SYSTEM_MANUAL.md#3-command-line-reference)).

### `VEYRS_SECRET_KEY`

It signs access tokens only. Change it on **every** node at once and restart: users
sign in again; refresh tokens and API keys are hashes and keep working. Different
values on different nodes (or an empty value, which mints a random key per worker)
reject tokens across nodes.

### Encryption key loss with an intact database

Everything except third-party credentials survives. There is no way around this. As
the database superuser, `NULL` the encrypted values, then re-enter them:

1. Generate a new key (`veyrs keygen`), set `VEYRS_ENCRYPTION_KEY`, restart.
2. Clear the encrypted columns of the registry (`backend/veyrs/services/secret_storage.py`, `COLUMNS`): `ai_providers.api_key_enc`, `itsm_connectors.credentials_enc` and `inbound_secret_enc`, `scanner_connectors.credentials_enc`, `asset_sources.credentials_enc`, `threat_sources.credentials_enc`, `webhook_endpoints.secret_enc`, `users.mfa_secret`.
3. Clear the encrypted fields inside each organization's `settings` JSON: `ldap.bind_password_enc`, `radius.secret_enc` and `oidc.client_secret_enc`. The earlier recovery notes list only the LDAP field; the RADIUS shared secret and the OIDC client secret are also sealed with this key (`services/radius_auth.py`, `services/oidc_auth.py`).
4. Re-enter the credentials in the console; reset people who had TOTP with `veyrs mfa-reset --email USER --reason TEXT` ([Troubleshooting](../troubleshooting/README.md#mfa-reset-lost-phone-and-recovery-codes)) and have them re-enrol.

## Disaster scenarios

### Database corruption or a bad change

1. `systemctl stop veyrs-api` on every application node.
2. Restore the most recent good backup (above).
3. `curl -sf http://127.0.0.1:8000/readyz`.
4. Re-import scanner results since the backup timestamp; findings are deduplicated, so re-importing is idempotent.

Data-loss window: findings and ticket changes since the last backup. Intelligence
(CVE, EPSS, KEV, CWE) is re-fetchable: `veyrs sync-nvd --full`, `sync-epss`, `sync-kev`,
`sync-cwe`.

### Loss of an application node

No data is lost: nodes are stateless ([ADR 0007](../ADRs/0007-stateless-app-nodes.md)).
The proxy sends traffic to the surviving node. If the lost node ran the agent and the
intel timer, enable them on the survivor **after confirming the dead node is not
running them**: `systemctl enable --now veyrs-agent veyrs-intel-sync.timer`. Exactly
one node runs each.

### Loss of the database node

If a streaming standby exists, promotion is **manual and stays manual**: automatic
promotion without fencing produces two primaries and divergent security data. Summary
of [High availability, promotion](../HIGH_AVAILABILITY.md#promotion-is-manual-and-stays-manual):

1. Confirm the primary is really gone; two primaries cannot be reconciled.
2. On the standby: `su postgres -c "/usr/lib/postgresql/15/bin/pg_ctl promote -D /var/lib/postgresql/15/main"`, then `psql -tAc "select pg_is_in_recovery()"` must print `f` (paths are Debian's).
3. Point every application node's `VEYRS_DATABASE_URL` at it and restart `veyrs-api`.
4. Redis is not replicated (rate-limit windows and short-lived codes only): point `VEYRS_REDIS_URL` at a Redis on a surviving node.
5. `pg_hba.conf` on the new primary must list the application nodes by `/32`, not by CIDR.

Without a standby: provision a database host, restore the latest verified dump
(by-hand procedure), re-point the nodes, restart.

### Host loss

Provision a comparable host, install ([Installation](installation.md)) with
`--skip-bootstrap`, restore instead of creating a new schema, restore `.env` from the
backup (**especially** `VEYRS_ENCRYPTION_KEY`), then re-point DNS or the proxy
upstream.

### Accidental tenant deletion

No API route or console action deletes an organization; it happens only in SQL and
cascades to every tenant row. There is no soft delete, so restoring from backup is the
only route. Treat it as a change request, not a click.

## Continuity of intelligence

If NVD, EPSS or CISA are unreachable, VEYRS keeps working on cached data. Freshness is
at `GET /api/v1/intel/health`, and the compliance signal `threat_feeds_active` reports
staleness as a control finding. Each feed has an offline path
(`POST /api/v1/intel/feeds/<feed>`) or an internal mirror through the `VEYRS_*_URL`
settings ([Technical requirements](../TECHNICAL_REQUIREMENTS.md)).

## Sources

- `scripts/backup.sh`, `scripts/restore.sh` (headers and flow), `infrastructure/backup/*`
- `docker/veyrs-docker.sh` (`cmd_backup`), `backend/veyrs/cli.py` (`init_db`)
- `backend/veyrs/services/secret_storage.py`, `services/ldap_auth.py`, `services/radius_auth.py`, `services/oidc_auth.py`
- `docs/DISASTER_RECOVERY.md`, `docs/HIGH_AVAILABILITY.md` (re-verified against the scripts)
