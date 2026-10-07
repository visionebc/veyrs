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
| PostgreSQL database | `scripts/backup.sh` — **not** a hand-run `pg_dump` (see below) | Everything is lost |
| `VEYRS_ENCRYPTION_KEY` | `.env` | Every stored third-party credential is unrecoverable ciphertext |
| `VEYRS_SECRET_KEY` | `.env` | All sessions invalidated (recoverable - users re-login) |
| Uploaded documents | `var/documents/` | Compliance evidence attachments are lost |
| Application code | Gitea `visionebc/veyrs` | Re-clonable |

The archive therefore contains key material and **is as sensitive as the
database itself**: mode 0600, and it must be shipped off the host.

## Taking a backup

> ### `pg_dump` as the application role produces a truncated backup that looks fine
>
> 70 of the 87 tables carry `FORCE ROW LEVEL SECURITY`, and **forcing it applies
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
> for a managed or remote cluster) and then proves the archive is readable and
> substantial. **Use it.** The equivalent for the container stack is
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
#     veyrs.dump  env  documents.tar.gz  MANIFEST  SHA256SUMS
```

`MANIFEST` records the UTC timestamp, host, app version and git commit.
`SHA256SUMS` covers every file. Retention defaults to 30 days (`RETAIN_DAYS=`).

Schedule it via the Power Panel scheduler or a systemd timer, then **copy it off
the host** - a backup on the same disk as the database is not a backup.

## Restoring

```bash
/opt/veyrs/scripts/restore.sh /path/to/veyrs-20260810-091500 --yes
```

The script refuses to run without `--yes`, verifies checksums first, stops the
API so nothing writes mid-restore, runs `pg_restore --clean --if-exists`,
restores documents, re-applies schema and RLS, and restarts.

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
4. Re-point DNS via Power Panel `/dns`, never the resolver directly

### Encryption key loss with an intact database

Everything except third-party credentials survives. Recovery:

1. Generate a new key, set `VEYRS_ENCRYPTION_KEY`
2. `NULL` out `api_key_enc`, `credentials_enc`, `secret_enc`
3. Re-enter the credentials through the API

There is no way around this. That is the point of encryption at rest.

### Accidental tenant deletion

Organization deletion cascades. There is no soft-delete for organizations, so
restore from backup is the only route. **A tenant deletion should be treated as
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
