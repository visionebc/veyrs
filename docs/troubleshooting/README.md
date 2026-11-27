---
title: Troubleshooting manual
purpose: Let an operator go from a symptom to a diagnosis, a fix and a proof that it worked, for the failures VEYRS is known to produce.
scope: Installation and runtime failures of the API, database, Redis, nginx, intelligence sync, scanner agent, AI gateway, sign-in, tests and the release export; application-level business questions and the Docker stack's own table (DOCKER_COMPOSE_MANUAL.md section 12) are not repeated.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [infrastructure/systemd/veyrs-api.service, backend/veyrs/config.py, backend/veyrs/main.py, backend/veyrs/db.py, backend/veyrs/cli.py, backend/veyrs/security/ratelimit.py, backend/veyrs/api/v1/auth.py, backend/veyrs/services/mfa_admin.py, backend/veyrs/services/intel_schedule.py, backend/veyrs/intel/feeds.py, backend/veyrs/services/agents.py, backend/veyrs/services/ai/gateway.py, backend/veyrs/services/ai/providers.py, integrations/veyrs-agent/veyrs_agent.py, scripts/sync-intel.sh, scripts/test.sh, scripts/public-export.sh, scripts/ip-guard.sh, infrastructure/nginx-veyrs-console.conf, tests/test_console_vhost_names.py]
related: [operations/README.md, operations/monitoring.md, operations/services.md, operations/backup-dr.md, operations/upgrade-rollback.md, SYSTEM_MANUAL.md, DOCKER_COMPOSE_MANUAL.md]
---

# Troubleshooting manual

Start with the three commands that answer most questions, on the application node:

```bash
curl -s -w '\n%{http_code}\n' http://127.0.0.1:8000/readyz        # which dependency is down
journalctl -u veyrs-api -n 60 --no-pager                          # JSON lines; quote correlation_id when reporting
cd /opt/veyrs && PYTHONPATH=backend venv/bin/python -m veyrs check   # configuration, database, Redis, engines
```

The `veyrs` shorthand used below is defined in the
[Operations manual](../operations/README.md#conventions-used-in-these-documents).
Docker installs: use `docker/veyrs-docker.sh status`, `logs` and `cli check`; the
stack-specific symptoms (502 through a stale upstream, exit 78 from `init`, `agent`
refusing to start) are in the
[Docker Compose manual, section 12](../DOCKER_COMPOSE_MANUAL.md#12-troubleshooting).

Every entry has the same fields: **Symptom**, **Probable cause**, **Diagnosis**,
**Fix**, **Validation** and **Impact**, then the **Source** it was verified against.

## Symptom index

| Symptom | Go to |
|---|---|
| `veyrs-api` fails at start, status `226/NAMESPACE` | [226/NAMESPACE](#api-does-not-start-226namespace) |
| `veyrs-api` restart-loops or exits right after start | [Unsafe or bad configuration](#api-does-not-start-unsafe-or-bad-configuration) |
| `/readyz` answers 503 | [readyz 503](#readyz-returns-503-database-or-redis) |
| Login works but every list is empty | [Zero rows](#queries-return-zero-rows-tenant-not-bound-rls) |
| Backup file is tiny or restore has empty tables | [Empty pg_dump](#pg_dump-produces-a-tiny-or-empty-backup) |
| New endpoints 500 with `UndefinedTable` after an upgrade | [sync-schema printed 0](#sync-schema-printed-0-added-for-a-new-table) |
| CVE, EPSS, KEV or CWE data is old | [Intelligence sync](#intelligence-sync-silently-failing) |
| Agent never appears, heartbeats fail with 405 | [Agent 405](#agent-heartbeats-fail-with-405) |
| Scans finish with no findings | [Blind scan](#scans-finish-clean-but-nothing-was-tested-zero-template-nuclei) |
| AI answers are generic, "unavailable" or empty | [AI degraded](#ai-answers-are-degraded-or-empty) |
| Whole office gets 429 or the audit shows one address | [Rate limited as proxy](#all-users-are-rate-limited-as-one-client) |
| Users are logged out or get intermittent 401 | [Secret key](#everyone-is-logged-out-or-gets-intermittent-401) |
| Connectors, LDAP, MFA fail with `secret_storage_unavailable` | [Secret storage](#stored-credentials-fail-to-decrypt-or-503-secret_storage_unavailable) |
| Browser shows the previous console after a deploy | [Old console](#browser-shows-the-old-console-after-a-deploy) |
| Console renders without colours or logos | [Unstyled console](#console-is-unstyled-on-a-native-install) |
| A hostname serves documentation instead of the console | [Wrong vhost](#a-hostname-serves-the-documentation-site-instead-of-the-console) |
| Console loads, every call fails in the browser | [CORS](#every-api-call-fails-in-the-browser-cors) |
| nginx answers 502 on `/api/` | [502](#nginx-answers-502-on-api) |
| Sign-in refused although the password is right | [Lockout and 429](#login-lockout-and-429) |
| Someone lost the phone and the recovery codes | [MFA reset](#mfa-reset-lost-phone-and-recovery-codes) |
| `init-db` fails with an ownership error | [init-db ownership](#init-db-fails-with-must-be-owner) |
| Export or publish refuses | [Export guard](#the-public-export-guard-fails) |
| Test run mails real people or aborts at start | [Tests](#tests-reach-a-real-mail-relay-or-refuse-to-start) |

---

## Startup and availability

### API does not start: 226/NAMESPACE

**Symptom.** `systemctl status veyrs-api` shows `Main process exited, code=exited, status=226/NAMESPACE`, and the journal says `Failed at step NAMESPACE spawning /opt/veyrs/venv/bin/uvicorn: No such file or directory`. No VEYRS log line appears at all.

**Probable cause.** The unit sets `ProtectSystem=strict` and `ReadWritePaths=/opt/veyrs/var`. Under `strict`, a `ReadWritePaths` entry that does not exist is fatal, and systemd 252 builds the mount namespace even for an `ExecStartPre=+`, so it cannot be repaired from the unit. `/opt/veyrs/var` is missing: a tarball or copy that dropped empty directories, a `git clean`, or an install root moved without `var/`.

**Diagnosis.**

```bash
systemctl status veyrs-api --no-pager | head -12
journalctl -u veyrs-api -n 20 --no-pager | grep -i namespace
ls -ld /opt/veyrs/var                         # missing = the cause
```

**Fix.**

```bash
install -d -m 750 /opt/veyrs/var /opt/veyrs/var/backups /opt/veyrs/var/documents
systemctl restart veyrs-api
```

If the install root is not `/opt/veyrs`, the unit's paths must have been rewritten
(`install.sh` does this); check `systemctl cat veyrs-api | grep ReadWritePaths`.

**Validation.** `curl -s http://127.0.0.1:8000/healthz` returns the version;
`systemctl is-active veyrs-api` prints `active`.

**Impact.** Full outage of this node until fixed. Other nodes are unaffected.

**Source.** `infrastructure/systemd/veyrs-api.service` (comment above `ReadWritePaths`); `install.sh` step 5.

### API does not start: unsafe or bad configuration

**Symptom.** `veyrs-api` restarts every 5 seconds (`Restart=on-failure`, `RestartSec=5`) or the container `api` restarts; the journal shows a Python traceback ending in one of the messages below, or `veyrs-setup.sh` / `install.sh` reports that the service "did not become healthy within 45s".

| Message | Cause | Fix |
|---|---|---|
| `RuntimeError: unsafe production configuration: debug must be off in production` | `VEYRS_DEBUG=true` with `VEYRS_ENVIRONMENT=production` | set `VEYRS_DEBUG=false` |
| `... database_url still carries the bootstrap password` | `VEYRS_DATABASE_URL` contains `veyrs:veyrs@` | set a real role password (and change it in PostgreSQL) |
| `... public_base_url must be https` | `VEYRS_PUBLIC_BASE_URL` is `http://` in production | use the `https://` address of whatever terminates TLS |
| `... encryption_key must be set explicitly (run: veyrs keygen)` | empty `VEYRS_ENCRYPTION_KEY` | `veyrs keygen`, put the value in `.env`; **never** change it on a database that already holds credentials (see [Key loss](../operations/backup-dr.md#encryption-key-loss-with-an-intact-database)) |
| `... encryption_key_previous must not contain the current encryption_key` | rotation left the same key in both | remove it from `VEYRS_ENCRYPTION_KEY_PREVIOUS` |
| `... secret_backend=vault needs vault_addr` (or another vault item, or a named file that does not exist) | `VEYRS_SECRET_BACKEND` is `mirror` or `vault` with an incomplete `VEYRS_VAULT_*` block | complete the block, or set `VEYRS_SECRET_BACKEND=local` |
| `ValidationError ... VEYRS_SECRET_KEY must be at least 32 characters` | key too short | generate 48 characters: `python3 -c "import secrets; print(secrets.token_urlsafe(48))"` |
| `ValidationError ... Input should be 'development', 'staging' or 'production'` | an enumerated setting with a value outside its list (environment, `secret_backend`, `jwt_algorithm`, `default_locale`, `ai_max_data_classification`) | fix the value |
| `ModuleNotFoundError: No module named 'psycopg2'` | `VEYRS_DATABASE_URL` lacks the driver marker: it must start `postgresql+psycopg://` | add `+psycopg` |

**Probable cause.** `Settings.assert_production_safe()` runs when the app is created
in production and refuses to boot on silent-damage configurations; pydantic validates
types and enumerations at import. A refusal to boot is the intended behaviour.

**Diagnosis.**

```bash
journalctl -u veyrs-api -n 40 --no-pager
cd /opt/veyrs && PYTHONPATH=backend venv/bin/python -c "from veyrs.config import settings; settings.assert_production_safe(); print('config ok')"
cut -d= -f1 /opt/veyrs/.env | grep -v '^#'        # key names only; never print values into a ticket
stat -c '%a %U:%G' /opt/veyrs/.env                 # 640 root:veyrs (600 root:root on a node not yet migrated)
```

**Fix.** Correct the named item in `/opt/veyrs/.env`, then `systemctl restart veyrs-api`
(the environment is fixed when systemd starts the unit). Settings reference:
[Configuration (generated)](../reference/configuration.md).

**Validation.** `/healthz` 200 with the expected version; `veyrs check` ends with `all checks passed`.

**Impact.** The node is down while it loops. No data is affected.

> [!WARNING]
> An **empty** `VEYRS_SECRET_KEY` is *not* refused by `assert_production_safe()`;
> only the container entrypoint refuses it (exit 78). On a native node it boots with a
> random key per worker, see [Logged out](#everyone-is-logged-out-or-gets-intermittent-401).

**Source.** `backend/veyrs/config.py` (`assert_production_safe`, `vault_problems`, `_require_secret`); `backend/veyrs/main.py` (`create_app`); `docker/entrypoint.sh`.

### /readyz returns 503 (database or Redis)

**Symptom.** `/readyz` answers `503 {"status":"degraded","checks":{"database":"error: OperationalError","redis":"ok"}}` while `/healthz` is 200; the load balancer drops the node; the console shows errors.

**Probable cause.** `/readyz` opens a PostgreSQL connection (`SELECT 1`) and pings Redis
with a 2 s timeout. The name of the failing check is in the body. Typical causes:
the database or Redis host is down or unreachable; a firewall or `pg_hba.conf` rule
does not admit this node's address; a password in `VEYRS_DATABASE_URL` or
`VEYRS_REDIS_URL` no longer matches (rotated, or Redis `requirepass` changed); the
database refused the connection with `too many clients` (each API worker can hold 30
connections, four workers per node, against PostgreSQL's default `max_connections` of
100); after a standby promotion the URL still points at the old primary.

**Diagnosis.**

```bash
curl -s http://127.0.0.1:8000/readyz
set -a; . /opt/veyrs/.env; set +a
# database, with the exact URL the app uses (strip the driver marker for psql):
psql "${VEYRS_DATABASE_URL/+psycopg/}" -tAc 'select 1; show max_connections; select count(*) from pg_stat_activity'
# redis:
redis-cli -u "$VEYRS_REDIS_URL" ping
journalctl -u veyrs-api -n 30 --no-pager | grep -iE 'error|refused|authentication|too many'
```

**Fix.** Restore the dependency or correct the URL in `.env` and restart the API.
For `too many clients`, raise `max_connections` on the database before adding workers
or nodes. If PostgreSQL is local, `systemctl status postgresql redis-server`
(`redis@default` on SUSE, `redis` on RHEL).

**Validation.** `/readyz` returns `200` with both checks `ok`; `veyrs check` prints
`database ok` and `redis ok`.

**Impact.** While `/readyz` is 503 the node should receive no traffic; requests that do
arrive fail with 500 if the database is the problem. With Redis down the rate limiter
**fails open** (or, if it was already unreachable at first use, each worker keeps its own
window, roughly N times the limit); two-factor codes by e-mail or Telegram fail closed,
so those users cannot sign in.

**Source.** `backend/veyrs/main.py` (`readyz`); `backend/veyrs/db.py` (pool sizes); `backend/veyrs/security/ratelimit.py`.

### nginx answers 502 on /api/

**Symptom.** The console loads, then every call returns 502; `/var/log/nginx/veyrs-console.error.log` shows `connect() failed (111: Connection refused) while connecting to upstream` or `(13: Permission denied)`.

**Probable cause.** The API is down (see the two entries above); or on an SELinux host in
Enforcing mode, nginx may not open the connection to `127.0.0.1:8000` because
`httpd_can_network_connect` is off. This produces a 502 that neither `nginx -t` nor the
API health check can see.

**Diagnosis.**

```bash
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/healthz        # API itself
curl -s -o /dev/null -w '%{http_code}\n' -H 'Host: veyrs.example.com' http://127.0.0.1/healthz   # through nginx
tail -20 /var/log/nginx/veyrs-console.error.log
getenforce 2>/dev/null; getsebool httpd_can_network_connect 2>/dev/null
```

**Fix.** Start the API; on SELinux `setsebool -P httpd_can_network_connect 1`.

**Validation.** The second `curl` above returns 200.

**Impact.** Total outage of the console path on that node; the proxy retries the other node when there is one.

**Source.** `install.sh` (`selinux_allow_proxy`, step 9 messages).

---

## Data and database

### Queries return zero rows (tenant not bound, RLS)

**Symptom.** Sign-in works and then every list is empty; or a hand-written query or
script as the application role returns `0` for `select count(*) from assets` while
the data is plainly there.

**Probable cause.** 73 of the 89 tables have row level security forced. The policy is
`organization_id::text = NULLIF(current_setting('veyrs.current_org', true), '')`: with no
tenant bound the setting is empty, the comparison is NULL and **no row matches**. The
binding is transaction-local (`set_config(..., true)`), so a pooled connection never
carries one request's tenant into the next; the session also remembers the tenant and
re-applies it on every new transaction (`after_begin` hook). Code that opens a plain
`SessionLocal()` and forgets `set_tenant(session, org_id)`, an `INSERT` with a different
`organization_id` (refused by `WITH CHECK`), or a psql session as the application role,
all see nothing. Four credential-keyed tables (`users`, `refresh_tokens`, `api_keys`,
`exec_agents`) are visible while unbound so that sign-in can find an account.

**Diagnosis.**

```bash
# As the superuser rows are visible (superusers bypass RLS):
su postgres -c "psql -d veyrs -tAc 'select count(*) from assets'"
# As the application role, unbound: 0. Bound: the tenant's rows.
set -a; . /opt/veyrs/.env; set +a
psql "${VEYRS_DATABASE_URL/+psycopg/}" <<'SQL'
select count(*) from assets;                                  -- 0: no tenant bound
select set_config('veyrs.current_org', (select id::text from organizations where slug = 'acme'), false);
select count(*) from assets;                                  -- the tenant's rows
SQL
su postgres -c "psql -d veyrs -tAc \"select count(*) from pg_class where relkind='r' and relforcerowsecurity\""   # 72 in 0.39.1
```

If the superuser also sees nothing the data is genuinely absent (wrong database, an
unfinished restore). If the application role is a **superuser** or has `BYPASSRLS` the
opposite problem applies: every tenant is visible to every other, silently
(`select rolsuper, rolbypassrls from pg_roles where rolname = current_user`; both must be `f`).

**Fix.** In application code, call `set_tenant(session, org_id)` before querying and
after any code path that opens a new session; in operations, bind as shown above or
use `docker/veyrs-docker.sh psql`, which connects as the application role.
If policies are missing after a restore, run `veyrs init-db`.

**Validation.** Counts match between the superuser view and the bound view for the
tenant; `relforcerowsecurity` count is unchanged from before the incident.

**Impact.** Zero rows is a safe failure (nothing leaks). A superuser or `BYPASSRLS`
application role is the dangerous one: **cross-tenant exposure** with no error and no
log, which is why both installers refuse such a role.

**Source.** `backend/veyrs/db.py` (`set_tenant`, `_rebind_tenant`); `backend/veyrs/cli.py` (`STRICT_POLICY`, `PREAUTH_POLICY`, `init_db`); `docker/initdb.d/10-app-role.sh`; `veyrs-setup.sh` (`evaluate_role`).

### pg_dump produces a tiny or empty backup

**Symptom.** A dump is a few hundred kilobytes where hundreds of megabytes are expected;
`pg_dump` printed `query would be affected by row-level security policy for table "..."`;
or a restored database has tables but no rows; or `docker/veyrs-docker.sh backup` says
`TRUNCATED dump`.

**Probable cause.** The dump ran as the application role, which owns every table. `FORCE
ROW LEVEL SECURITY` binds the owner too, and `pg_dump` runs with row security off, so
PostgreSQL refuses the `COPY` of the first protected table. `--format=custom` has already
written a plausible header, so the file looks like a backup: 392 KB against 509 MB was
measured on 2026-09-21. (The `veyrs-pgdump.sh` header describes the same trap as a
well-formed archive with empty tables; the measured failure is the refusal above. Both
mean the same thing: the dump has no data.) The other cause of the same message from
`docker/veyrs-docker.sh backup` is a host `pg_restore` older than 15 or missing: the
count comes back 0 for a good file.

**Diagnosis.**

```bash
pg_restore --list /path/veyrs.dump | grep -c 'TABLE DATA'     # near the table count (89); ~3 = truncated
pg_restore --version                                          # must be 15 or newer
```

**Fix.** Take backups only with `scripts/backup.sh`, `docker/veyrs-docker.sh backup` or
the `veyrs-pgdump` unit, all of which dump as a superuser; for a remote database set
`BACKUP_DSN` to a `BYPASSRLS` role. Delete the bad file: the driver leaves a refused dump
on disk. Take a new backup **now**. Full procedure: [Backup and DR](../operations/backup-dr.md).

**Validation.** `TABLE DATA` count near the table count; `veyrs-pgverify` (or a scratch
restore) reports equal row counts and policy counts.

**Impact.** Any backup taken this way is worthless; if it was the only one, recovery from a
disaster is impossible. This is the most expensive silent failure in the system.

**Source.** `scripts/backup.sh`, `docker/veyrs-docker.sh` (`cmd_backup`), `infrastructure/backup/veyrs-pgdump.sh`, `docs/DISASTER_RECOVERY.md`.

### sync-schema printed 0 added for a new table

**Symptom.** After an upgrade the new endpoints return 500 with `UndefinedTable` (for
example on `/compliance/frameworks` or `/ai/capabilities` historically) while `/healthz`
is green. `veyrs sync-schema` printed `0 columns ... added` and exited 0.

**Probable cause.** `sync-schema` reconciles **columns, indexes and foreign keys of tables
that already exist**; for a table absent from the database it does nothing and says
nothing. Only `init-db` creates tables (`Base.metadata.create_all`) and then binds RLS and
seeds roles.

**Diagnosis.**

```bash
journalctl -u veyrs-api --since '10 min ago' --no-pager | grep -E 'UndefinedTable|UndefinedColumn'
su postgres -c "psql -d veyrs -c '\\dt'" | grep -c table      # compare with 89 (0.39.1)
```

**Fix.** `cd /opt/veyrs && PYTHONPATH=backend venv/bin/python -m veyrs init-db` (idempotent;
safe to run on a live system). It prints `schema: N tables ensured` and the RLS counts.

**Validation.** The failing endpoint returns 200; `init-db` output reports 89 tables and
`row level security: 68 tables strictly isolated, 4 credential-keyed`.

**Impact.** Only the new features fail. A new table that exists without its policy would be
unprotected, which is the second reason to use `init-db`.

**Source.** `backend/veyrs/cli.py` (`sync_columns`, `init_db`); `docs/DEPLOYMENT.md` history note.

### init-db fails with "must be owner"

**Symptom.** `veyrs init-db` or the installer's schema step fails with `must be owner of table ...` while issuing `ALTER TABLE ... FORCE ROW LEVEL SECURITY` or `CREATE POLICY`.

**Probable cause.** Only the table owner (or a superuser) may alter policies. The tables
are owned by someone other than the application role: a restore with `--no-owner` as
`postgres`, or an external database whose application role does not own the database.

**Diagnosis.**

```bash
su postgres -c "psql -d veyrs -tAc \"select tableowner, count(*) from pg_tables where schemaname='public' group by 1\""
```

**Fix.** Make the application role the owner: `ALTER DATABASE veyrs OWNER TO veyrs;` and
for each table `ALTER TABLE ... OWNER TO veyrs` (or restore again **without** `--no-owner`).
Then re-run `init-db`.

**Validation.** `init-db` completes and prints the RLS counts.

**Impact.** Policies cannot be (re)applied until fixed, so a freshly created table stays unprotected.

**Source.** `veyrs-setup.sh` (`evaluate_role`); `docs/DOCKER_COMPOSE_MANUAL.md` section 10.4.

---

## Intelligence, agents and AI

### Intelligence sync silently failing

**Symptom.** CVE, EPSS, KEV or CWE data is days old although `systemctl list-timers` shows
`veyrs-intel-sync.timer` active with a next run; `GET /api/v1/intel/health` says `stale`
or `never_run`; or the CWE dictionary stopped updating while the other feeds work.

**Probable cause.** The timer is only a tick; whether anything runs is decided by the
database. Verified causes, in the order to check them:

1. **Nothing is due or everything is disabled.** `veyrs intel-due` prints `skip ... N min since last success, interval M min`, or `disabled by every tenant`. The tick exits 0 and looks healthy.
2. **The tick ran and a feed failed.** `!!! sync-<feed> failed` in the journal; the script keeps going and exits non-zero. A failed run does not reset the clock, so the feed stays due and retries every hour.
3. **CWE parse failure.** MITRE versions the catalogue's XML namespace with its schema (`cwe-7` up to CWE 4.x, `cwe-8` from CWE 5.0, 2026-10-28) and renamed `<Category>` to `<Grouping>`. A parser pinned to one namespace found zero weaknesses. The current parser accepts any `cwe-<n>` namespace and raises `CWE catalogue parsed to zero weaknesses (root element ...)` or `not valid XML` if the file is unusable.
4. **A feed run hangs.** `TimeoutStartSec=infinity` on purpose (NVD allows 5 requests per 30 s without an API key); `systemctl status veyrs-intel-sync` shows `activating (start)` for many hours.
5. **Killed mid-loop.** An out-of-memory kill of a child once stopped the whole unit and `sync-kev` never ran for three nights; the shipped unit sets `OOMPolicy=continue`. An old unit copy lacks it.
6. **The timer is not on this node.** `--skip-timers`, or the timer is `disabled` here because another node is the singleton; or the sync tick on a Docker stack is the `intel` service of the `workers` profile, which is **off by default**.
7. **Records rejected.** `veyrs sync-nvd` exits 3 and names records the database refused; the watermark moved past them.
8. **Outbound blocked** to the feed hosts or a proxy missing.
9. **Releases 0.21.0 to 0.32.4 only:** with two or more feeds due, the script ran nothing and exited 0 (a newline versus space mismatch in the due list); fixed in 0.32.5.

**Diagnosis.**

```bash
cd /opt/veyrs; veyrs() { PYTHONPATH=backend venv/bin/python -m veyrs "$@"; }
systemctl list-timers 'veyrs-*' --no-pager; systemctl is-enabled veyrs-intel-sync.timer
veyrs intel-due                                           # DUE/skip and why, per feed
journalctl -u veyrs-intel-sync --since '2 days ago' --no-pager | grep -E '===|DUE|skip|!!!|status'
systemctl status veyrs-intel-sync.service --no-pager | head -8      # 'activating' for hours = a hung run
grep OOMPolicy /etc/systemd/system/veyrs-intel-sync.service
TOKEN=<an API token>; curl -s -H "Authorization: Bearer $TOKEN" http://127.0.0.1:8000/api/v1/intel/health
curl -s -H "Authorization: Bearer $TOKEN" 'http://127.0.0.1:8000/api/v1/intel/feeds/runs?limit=10'   # includes CWE
veyrs sync-cwe; echo "exit=$?"                              # run one feed by hand and read its error
```

**Fix.** Per cause: enable a feed or lower its interval in Threat Intel, Schedule (minimum
60 minutes); fix connectivity or set `VEYRS_NVD_API_KEY` (raises the rate limit); for a feed
parse error update VEYRS to a release that handles the new format, and in the meantime load
the file by other means (`POST /api/v1/intel/feeds/<feed>`) or point `VEYRS_CWE_CATALOG_URL`
at a mirror; add `OOMPolicy=continue` and `systemctl daemon-reload` to an old unit; enable the
timer on exactly one node (`systemctl enable --now veyrs-intel-sync.timer`); on Docker use
`docker/veyrs-docker.sh up --with-workers`. Force a refresh now with
`scripts/sync-intel.sh --full-run`.

**Validation.** `veyrs intel-due` shows `skip` with a small minutes figure for every feed;
`/api/v1/intel/health` reports `ok` with a recent `age_hours`; `feeds/runs` has a new row
with `status: succeeded` for each feed including `cwe`; the next tick ends
`=== done ..., status 0`.

**Impact.** Stale intelligence is silently wrong prioritisation: exploit probability and
KEV flags stop updating, findings are not raised for new CVEs, and SLA deadlines are
still evaluated (`run-sla` runs on every tick) against old urgency. A stale KEV is a missed
emergency.

**Source.** `scripts/sync-intel.sh`; `backend/veyrs/services/intel_schedule.py`; `backend/veyrs/intel/feeds.py` (`CWE_NS_PATTERN`, `parse_cwe_catalog`, `run_cli`); `integrations/systemd/veyrs-intel-sync.service`; `docker/tick.sh`.

### Agent heartbeats fail with 405

**Symptom.** The agent starts and logs `POST /agents/self/heartbeat -> 405: ...` (or a
non-JSON body), repeatedly; the agent never appears as connected and queued scan jobs never
start. The API itself is healthy.

**Probable cause.** `VEYRS_URL` names a hostname that answers with a redirect (a retired
alias that returns 301 or 302 to the canonical hostname). The agent uses Python's
`urllib.request` with its default redirect handling, which re-issues a redirected `POST`
as a `GET` and drops the body; the heartbeat route accepts only `POST`, so the
canonical host answers 405. The same happens through any proxy that redirects HTTP to HTTPS:
a `VEYRS_URL` with `http://` pointing at a TLS-only proxy.

**Diagnosis.**

```bash
set -a; . /etc/veyrs-agent/agent.env; set +a
curl -s -o /dev/null -w '%{http_code} -> %{redirect_url}\n' -X POST "$VEYRS_URL/api/v1/agents/self/heartbeat" -H "X-Agent-Token: $VEYRS_AGENT_TOKEN"
# a 301/302 with a redirect_url is the cause; 401 (bad token) or 200 means the URL is fine
journalctl -u veyrs-agent -n 20 --no-pager
```

**Fix.** Set `VEYRS_URL` in `/etc/veyrs-agent/agent.env` to the final canonical
`https://` address (no trailing path), then `systemctl restart veyrs-agent`.

**Validation.** The agent log shows `heartbeat ok; server says status=...` and the agent
shows a recent heartbeat in Settings, Agents.

**Impact.** No scans run from this agent; jobs stay queued. Nothing is lost.

**Source.** `integrations/veyrs-agent/veyrs_agent.py` (`Client._call` uses `urllib.request.urlopen` with no custom redirect handler); the 301-retired alias is described in `docs/HIGH_AVAILABILITY.md` (the retired `-a` name returns 301 at the proxy).

### Scans finish clean but nothing was tested (zero-template nuclei)

**Symptom.** Scan jobs complete with zero findings on assets that should have some; or jobs
fail with `scan coverage refused: ...` or `the scanner completed N% of its checks ... and
then stopped`; the agent log reports no resolver list.

**Probable cause.** A scanner that cannot do its job exits 0 and writes nothing, which is
indistinguishable from a clean target. Three verified ways to get there: nuclei finds no
templates (the unit sets `ProtectHome=yes` locking `/root/nuclei-templates`, or the Docker
template volume is empty); nuclei ignores the system resolver and resolves internal names to
public addresses on a split-horizon network, so 5 % of templates complete instead of 97 %;
or an upgrade replaced the unit with a hardened copy.

**Diagnosis.**

```bash
find /root/nuclei-templates -name '*.yaml' | wc -l          # thousands expected; 0 = blind scanner
systemctl cat veyrs-agent | grep -i ProtectHome             # must not be set
journalctl -u veyrs-agent -n 40 --no-pager | grep -iE 'resolver|template|tools'
cat /etc/veyrs-agent/resolvers.txt
# the job's own evidence: GET /api/v1/agents/jobs/<id> -> meta.scan_stats {requests, errors, percent, templates}
```

**Fix.** Remove `ProtectHome` from the agent unit; `nuclei -update-templates`; create
`/etc/veyrs-agent/resolvers.txt` with your internal resolvers, one address per line (comments
are stripped before nuclei sees the file), and `systemctl restart veyrs-agent`. In Docker the
container refuses to start with fewer than 100 templates (exit 78): give it outbound access to
GitHub or mount an existing template directory.

**Validation.** Run a real scan against a target known to have a finding and read the job's
`scan_stats`: `percent` at least 80 and an error ratio under 50 %. The exit code alone proves
nothing.

**Impact.** The dangerous case: the dashboard goes green and the platform has silently stopped
testing. The server protects reconciliation: a run without coverage evidence cannot close
findings, and an unreachable target or under-80-percent run is refused.

**Source.** `integrations/veyrs-agent/veyrs-agent.service` (comment), `veyrs_agent.py` (`load_resolvers`), `docker/agent-entrypoint.sh`, `backend/veyrs/services/agents.py` (`_coverage`, `MIN_COVERAGE_PERCENT = 80`, `MAX_ERROR_RATE = 0.5`).

### AI answers are degraded or empty

**Symptom.** AI features answer with a deterministic summary labelled degraded ("AI
unavailable"), or an answer arrives empty; `GET /api/v1/ai/audit` shows `decision: degraded`.

**Probable cause.** The gateway never surfaces provider failures: when no endpoint is
eligible or the provider raises, it answers from VEYRS data and records `degraded` with the
reason in `notes`. Verified causes: no provider passes policy, because local AI is off
(`install.sh` writes `VEYRS_AI_ALLOW_LOCAL=false` into `.env`; the code default is `true`),
external providers are off (`VEYRS_AI_ALLOW_EXTERNAL=false` is the default, and a tenant policy
can only narrow it), the data classification exceeds the provider ceiling, or the provider or
model is not on the tenant's allow list; the provider endpoint is down or times out; **a
reasoning model returns its answer only inside a thinking block or in a separate field**,
leaving `message.content` empty (`ollama returned an empty message`), because thinking models
need `think: false` and some builds emit a bare `</think>`. The gateway sends `think: false` to
Ollama and strips reasoning markers from every backend; a model that still produces no answer
text degrades.

**Diagnosis.**

```bash
TOKEN=<an API token>
curl -s -H "Authorization: Bearer $TOKEN" 'http://127.0.0.1:8000/api/v1/ai/audit?limit=5'   # decision + notes (the reason)
grep -E '^VEYRS_AI_' /opt/veyrs/.env
journalctl -u veyrs-api --since '1 hour ago' --no-pager | grep 'ai provider'
# the provider row's last_error is shown on the AI providers page in the console
```

**Fix.** Enable the right scope: `VEYRS_AI_ALLOW_LOCAL=true` (and restart) for a local model,
and the tenant's AI policy (Administration, AI policy); correct the provider base URL, model
name and timeout; for reasoning models use a non-thinking model or one served through
Ollama's native `/api/chat`, and give it enough `max_output_tokens` that it does not spend the
whole budget thinking (probable cause, not verified in code). External providers need both
`VEYRS_AI_ALLOW_EXTERNAL=true` and the organization policy.

**Validation.** A new request produces `decision: allowed`, a `provider` and `model`, and
non-empty text; `last_error` on the provider is cleared.

**Impact.** Degraded answers are less capable but safe: the gateway cannot exceed the caller's
permissions and secrets are stripped before any model. Nothing breaks; quality drops.

**Source.** `backend/veyrs/services/ai/gateway.py` (provider selection, `ProviderError` to `degraded`); `backend/veyrs/services/ai/providers.py` (`_strip_reasoning`, `OllamaProvider`); `backend/veyrs/config.py`; `install.sh` (`.env` template).

---

## Sign-in, keys and secrets

### All users are rate-limited as one client

**Symptom.** Several people get `429 rate_limited` at once; the audit trail and the logs
show a single source address (the proxy) for everybody; one busy user throttles the rest.

**Probable cause.** The application never reads `X-Forwarded-For`; the caller's address is
`request.client.host`, which uvicorn resolves through `--forwarded-allow-ips`. The shipped
unit trusts only `127.0.0.1` (nginx on the same node). With a second proxy in front (a load
balancer or TLS terminator), nginx appends **that proxy's** address, uvicorn does not trust
it as a hop, and every user is recorded and limited as the proxy. The sign-in limiter
(10 per minute per source IP) bites first.

**Diagnosis.**

```bash
journalctl -u veyrs-api --since '15 min ago' --no-pager | grep 'rate limit exceeded' | head -5    # ip= is always the same
grep VEYRS_FORWARDED_ALLOW_IPS /opt/veyrs/.env /etc/systemd/system/veyrs-api.service
tail -3 /var/log/nginx/veyrs-console.access.log                  # remote address = the outer proxy
```

**Fix.** List every hop in front of the API, comma-separated, in `/opt/veyrs/.env`
(systemd lets `EnvironmentFile=` override the unit's `Environment=`), never `*`:

```bash
echo 'VEYRS_FORWARDED_ALLOW_IPS=127.0.0.1,192.0.2.40' >> /opt/veyrs/.env   # 192.0.2.40 = the outer proxy as nginx sees it
systemctl restart veyrs-api
```

Docker: set `VEYRS_FRONT_PROXY_IPS` and recreate `api` with `up`. If your users genuinely
share one NAT address, raise `VEYRS_AUTH_RATE_LIMIT_PER_MINUTE` instead.

**Validation.** Sign-in events in the audit trail (`auth_events.ip_address`) show distinct
client addresses; `rate limit exceeded ... ip=` lines name individual clients.

**Impact.** One abusive or busy client locks out everybody; per-IP audit evidence is useless.
Opening the list to `*` is worse: any caller could claim any source address.

**Source.** `infrastructure/systemd/veyrs-api.service` (comment on `VEYRS_FORWARDED_ALLOW_IPS`); `backend/veyrs/security/ratelimit.py` (`client_ip`, auth limit); `docker/compose.yaml`.

### Everyone is logged out or gets intermittent 401

**Symptom.** Every session ends after a restart; or authenticated requests fail
unpredictably with an invalid-token error that moves when you retry (roughly three requests
of four with four workers); or a user signed in on one node is rejected on the other.

**Probable cause.** `VEYRS_SECRET_KEY` is empty or differs between processes. An empty key
makes `config.py` mint a random one **per process**, so each of the four workers signs with a
different key and each restart invalidates every token. `assert_production_safe()` does not
catch it on a native node. Two nodes with different keys reject each other's tokens.

**Diagnosis.**

```bash
grep -c '^VEYRS_SECRET_KEY=.\{32,\}' /opt/veyrs/.env       # must print 1 on every node
# compare the values between nodes WITHOUT printing them:
sha256sum <(sed -n 's/^VEYRS_SECRET_KEY=//p' /opt/veyrs/.env)
```

**Fix.** Set the same 32-character-or-longer `VEYRS_SECRET_KEY` on every node
(`python3 -c "import secrets; print(secrets.token_urlsafe(48))"`), restart `veyrs-api`
everywhere. Users sign in again once; refresh tokens and API keys are hashes and survive.

**Validation.** 20 consecutive authenticated requests succeed; a token issued on one node works on the other.

**Impact.** Availability and user experience only; no data exposure.

**Source.** `backend/veyrs/config.py` (`_require_secret`); `docker/entrypoint.sh` (exit 78); `docs/SYSTEM_MANUAL.md` section 2.2.

### Stored credentials fail to decrypt or 503 secret_storage_unavailable

**Symptom.** Connectors, LDAP, AI providers or two-factor stop working; the API answers
`503 {"error":"secret_storage_unavailable"}`; the log has `secret storage error
correlation_id=...`.

**Probable cause.** A stored credential cannot be read: `VEYRS_ENCRYPTION_KEY` was replaced
without the rotation procedure (the ciphertext now opens with no configured key), or with
`VEYRS_SECRET_BACKEND=vault` the vault is down, sealed or refusing the AppRole.

**Diagnosis.**

```bash
cd /opt/veyrs; PYTHONPATH=backend venv/bin/python -m veyrs secrets status    # backend, vault health, counts per column; exit 1 if the vault is unusable
PYTHONPATH=backend venv/bin/python -m veyrs secrets rekey                    # dry run: rows no configured key opens
journalctl -u veyrs-api --since '30 min ago' --no-pager | grep -i 'secret storage'
```

**Fix.** Key replaced by mistake: put the **old** key in `VEYRS_ENCRYPTION_KEY_PREVIOUS`, keep the
new one in `VEYRS_ENCRYPTION_KEY`, restart, `veyrs secrets rekey --apply`, then remove the previous
key and restart ([Key rotation](../operations/backup-dr.md#key-rotation-and-key-loss)). Old key lost:
[Key loss](../operations/backup-dr.md#encryption-key-loss-with-an-intact-database). Vault: restore the
vault or switch `VEYRS_SECRET_BACKEND` back after `veyrs secrets migrate --to local`.

**Validation.** `veyrs secrets status` shows every column `local`, `mirror` or `vault` with none
`unknown`; the connector test in the console succeeds.

**Impact.** Integrations and two-factor stop; a user with TOTP cannot sign in if their secret is
unreadable.

**Source.** `backend/veyrs/main.py` (`_secret_handler`); `backend/veyrs/services/secret_storage.py`.

### Login lockout and 429

**Symptom.** A user is refused with `401 invalid credentials` although the password is right; or sign-in returns `429 rate_limited`.

**Probable cause.** Two independent mechanisms. **Lockout** (since 0.41.0, `security/lockout.py`):
after 5 failures from one address, that address waits (30 s doubling to 15 min) before its next
attempt is checked (audit reason `throttled`); failures from several addresses (20 counted) lock
the account for everyone, 1 min doubling to 1 h (audit reason `locked`), except addresses in
`VEYRS_LOCKOUT_EXEMPT_NETWORKS`. Password failures and wrong two-factor codes share the budget
on purpose, and a refused attempt answers the same generic 401 as a wrong password. `veyrs
unlock --email <account> --reason "..."` lifts both. **Rate limit:** more than
`VEYRS_AUTH_RATE_LIMIT_PER_MINUTE` (default 10) requests to the sign-in, refresh, MFA or password
endpoints per source IP per minute return 429 with `Retry-After`.

**Diagnosis.**

```bash
# As the database superuser (it bypasses RLS):
su postgres -c "psql -d veyrs -c \"select email, failed_logins, locked_until from users where email = 'user@example.com'\""
su postgres -c "psql -d veyrs -c \"select created_at, event, success, reason, ip_address from auth_events where email_attempted = 'user@example.com' order by created_at desc limit 10\""
journalctl -u veyrs-api --since '10 min ago' --no-pager | grep 'rate limit exceeded'
```

**Fix.** Wait 15 minutes; the next successful sign-in resets the counter. To unlock at once there is
no console action, API route or CLI command; an operator with the database superuser can clear it,
and should record why:

```sql
-- psql as postgres, database veyrs. One account only.
update users set failed_logins = 0, locked_until = null
 where email = 'user@example.com'
   and organization_id = (select id from organizations where slug = 'acme');
```

For 429, wait for `Retry-After`, find the cause (a script retrying a bad password, a shared NAT: see
[rate limit](#all-users-are-rate-limited-as-one-client)) and raise the limit only for a shared egress address.

**Validation.** The user signs in; `failed_logins` is `0` and `locked_until` is null.

**Impact.** The user is blocked for up to 15 minutes. Repeated lockouts of many accounts indicate
credential stuffing; check `auth_events` for the source.

**Source.** `backend/veyrs/security/lockout.py`; `backend/veyrs/api/v1/auth.py` (`_spend_attempt`, the `lockout.retry_after` branch); `backend/veyrs/security/ratelimit.py`.

### MFA reset: lost phone and recovery codes

**Symptom.** A user cannot sign in because the authenticator, the mailbox or the Telegram chat is gone and no recovery code is left.

**Probable cause.** Second factor lost. The console offers disabling MFA only to someone who is signed in; with no factor
and no recovery code, only an operator on the host can reset it.

**Diagnosis.**

```bash
su postgres -c "psql -d veyrs -c \"select email, mfa_enabled, mfa_method from users where email = 'user@example.com'\""
```

**Fix.** On the application node, as root, after verifying the person's identity out of band:

```bash
cd /opt/veyrs; PYTHONPATH=backend venv/bin/python -m veyrs mfa-reset \
  --email user@example.com --reason "lost phone and recovery codes, identity verified by ticket 1234"
```

It clears the method, secret, last step, Telegram chat id and recovery codes, and writes an audit entry
(`mfa.reset_by_operator`, with the reason). The user signs in with the password alone and must enrol again
(My account). If the account is the only platform administrator, do this before they are needed:
`veyrs platform-admin --email USER` grants a second one.

**Validation.** The user signs in; `select mfa_enabled from users ...` is `f`; the audit entry exists
(`GET /api/v1/audit`, action `mfa.reset_by_operator`). Remind them to enrol and store the ten new codes.

**Impact.** The account is password-only until re-enrolment; treat it as a privileged operation.

**Known limitation.** The command looks the account up by e-mail address alone, and the same e-mail may
exist in two organizations (`users` is unique on organization and e-mail). In that case the lookup is
ambiguous and the command can fail with an error instead of resetting; reset the row with the
superuser in SQL (set `mfa_enabled = false` and null the `mfa_*` columns for that organization's row)
and record it. The e-mail is compared as typed: use the stored lower-case form.

**Source.** `backend/veyrs/services/mfa_admin.py` (`mfa_reset`, `_find`); `backend/veyrs/cli.py` (`platform_admin`).

---

## Web tier

### Browser shows the old console after a deploy

**Symptom.** After a deploy, users still see the previous UI, or new features are missing, or errors appear from new
API fields; a hard reload fixes it. `/healthz` shows the new version.

**Probable cause.** Two different causes. (1) The console copy was not refreshed: nginx serves
`/var/www/veyrs-console`, a copy of `frontend/console/`, and `git pull` does not update it. (2) The browser cached
`index.html`: without `Cache-Control: no-cache` the page goes out with only `Last-Modified`, browsers cache it
heuristically for days, and the cached page still names the old `app.js?v=` value. The shipped vhost sets
`expires -1` on `location /` for this reason; a hand-written vhost may lack it, and an `add_header` in a
`location` silently discards the server-level security headers.

**Diagnosis.**

```bash
for f in index.html app.js console.css; do cmp /opt/veyrs/frontend/console/$f /var/www/veyrs-console/$f && echo "$f same"; done
grep -o 'app.js?v=[0-9]*' /var/www/veyrs-console/index.html
curl -sI -H 'Host: veyrs.example.com' http://127.0.0.1/ | grep -iE 'cache-control|expires|etag|last-modified'   # expect: Cache-Control: no-cache
```

**Fix.** Copy the files (`install -m 644 frontend/console/app.js frontend/console/console.css frontend/console/index.html /var/www/veyrs-console/`
and `fonts/`); make sure `location /` has `expires -1;`, then `nginx -t && systemctl reload nginx`.

**Validation.** Files identical; the response carries `Cache-Control: no-cache`; a normal reload shows the new `app.js?v=`.

**Impact.** The old UI against the new API: broken screens, no health check can see it (every request answers 200).

**Source.** `infrastructure/nginx-veyrs-console.conf` (comment on `location /`); `docs/DEPLOYMENT.md`; `install.sh` step 9 (console files compared).

### Console is unstyled on a native install

**Symptom.** The console loads but has no colours, no logos, browser-default fonts and layout; the browser network tab shows `/static/veyrs-tokens.css` returning HTML.

**Probable cause.** The console page links `/static/veyrs-tokens.css` and its logos. The reference vhost aliases the documentation
site's `static/` tree. Before 0.41.0 the vhost `install.sh` generates had no `/static/` block and the installer did not copy `frontend/brand`, so the request
falls through to `try_files ... /index.html` (TD-09, fixed: the installer now copies the brand files to `<console dir>/static/` on every run and the generated vhost has a
`/static/` location). A node installed or last upgraded with an older installer still has the gap. The container image bakes the files in.

**Diagnosis.** `curl -s -o /dev/null -w '%{content_type}\n' -H 'Host: veyrs.example.com' http://127.0.0.1/static/veyrs-tokens.css` prints `text/html`.

**Fix.** Re-run `install.sh` (or `scripts/publish-sites.sh --only console`), or by hand:

```bash
install -d -m 755 /var/www/veyrs-console/static
install -m 644 /opt/veyrs/frontend/brand/veyrs-tokens.css /opt/veyrs/frontend/brand/logo/* /var/www/veyrs-console/static/
```

**Validation.** The same request now prints `text/css`; a reload shows the styled console.

**Impact.** Cosmetic and usability only. It is a gap in the installer, not in your configuration.

**Source.** `frontend/console/index.html`; `install.sh` (step 8 vhost); `docker/Dockerfile` (console stage).

### A hostname serves the documentation site instead of the console

**Symptom.** `https://<name>/` returns HTTP 200 with documentation pages (or the wrong site) instead of the console, typically through the failover
node or a new alias, while every status-code check passes.

**Probable cause.** The console vhost's `server_name` does not list that name. nginx does not 404: the request falls through to the
`default_server` (`server_name _`), which on these nodes is the documentation vhost.

**Diagnosis.**

```bash
nginx -T 2>/dev/null | grep -E 'server_name|default_server|configuration file'
curl -s -H 'Host: the-missing-name.example.com' http://127.0.0.1/ | grep -c 'app.js'     # 0 = docs, 1 = console
```

**Fix.** Add the name to `server_name` of the console vhost, `nginx -t && systemctl reload nginx`, on **every** node. Keep the console vhost
out of `_` and wildcards.

**Validation.** The `curl` above returns `1`; `tests/test_console_vhost_names.py` passes (it asserts the set of names, not a response).

**Impact.** During a failover operators receive documentation instead of the product; availability tests that check only 200 report success.

**Source.** `infrastructure/nginx-veyrs-console.conf` (comment above `server_name`); `tests/test_console_vhost_names.py`.

### Every API call fails in the browser (CORS)

**Symptom.** The console loads, every call fails in the browser's console with a CORS error, and there is no server-side error.

**Probable cause.** `VEYRS_CORS_ORIGINS` does not list the origin the console is served from (the same-origin nginx proxy makes this irrelevant;
it matters when the console is served from a different host than the API).

**Diagnosis.** `grep VEYRS_CORS_ORIGINS /opt/veyrs/.env`; compare with the page's origin (scheme, host, port).

**Fix.** Set the exact origin(s), comma-separated, never `*` (credentials are allowed), and restart.

**Validation.** `curl -s -i -H 'Origin: https://veyrs.example.com' -X OPTIONS -H 'Access-Control-Request-Method: GET' http://127.0.0.1:8000/api/v1/assets` returns `access-control-allow-origin`.

**Impact.** The console is unusable from that origin.

**Source.** `backend/veyrs/main.py` (CORS middleware); `backend/veyrs/config.py` (`cors_origins`).

---

## Development and release

### The public export guard fails

**Symptom.** `scripts/public-export.sh` or `publish-github.sh` prints `export refused` / `the export is NOT safe to publish`, with a list of hits
under one of the guards.

**Probable cause.** The guard found something that must not leave the building: an internal host name, an IPv4 literal outside the allowlist
(`scripts/ip-guard.sh`), a secret-shaped string, an excluded file that is present, an unexpected binary, a relative documentation link that
points outside the export (often a new document that was never `git add`ed, or a public document linking to a private folder), a Gitea URL
shape under `github.com`, or a missing or non-ELv2 `LICENSE`. The binary guard also refuses a **legitimate**
new file type: it accepts only `image/*`, `text/*`, `application/json`, `application/javascript`, empty
files and, since 0.39.1, `font/woff2` **only under `frontend/console/fonts/`** (`scripts/public-export.sh:509-512`;
a font elsewhere is reported as `font outside frontend/console/fonts/`). On 0.37.0 to 0.39.1 trees the console
fonts were reported as `unexpected binary`. A new type is a guard that must be extended deliberately (add the
MIME type to the `case` list in `scripts/public-export.sh` and re-run the harness), not bypassed.

**Diagnosis.**

```bash
./scripts/public-export.sh --out /tmp/veyrs-public 2>&1 | grep -B1 -A8 '✗'     # which guard, which file:line
./scripts/ip-guard.sh /tmp/veyrs-public; echo "rc=$?"                          # 0 clean, 1 findings, 2 the guard itself broke
git status --short                                                             # untracked documents are invisible to the exporter
```

**Fix.** Edit the **source**: replace a private address with an RFC 5737 documentation address (`192.0.2.0/24`, `198.51.100.0/24`,
`203.0.113.0/24`) and a private name with `example.com`; `git add` new files; move private material under a path listed in `EXCLUDE_GLOBS` and
remove links to it from public documents. Do not weaken a guard or allowlist to get a release out; a guard exit code 2 means the guard itself failed
and must be treated as a failure.

**Validation.** `./scripts/public-export.sh --check-only --out /tmp/veyrs-public` ends `export clean`.

**Impact.** None to users: nothing is published until the guards pass, which is their purpose. Bypassing them would publish internal topology or secrets.

**Source.** `scripts/public-export.sh` (guards); `scripts/ip-guard.sh`; `docs/operations/release.md`.

### Tests reach a real mail relay or refuse to start

**Symptom.** Either (a) a test run sends mail to fixture addresses through the node's relay or posts to a chat bot, or notification tests fail on the
"no relay configured" path; or (b) `pytest` aborts at once with `no test database configured`.

**Probable cause.** (a) The suite was run in a way that kept the node's `.env` channel settings: bare `pytest` instead of `scripts/test.sh`.
`test.sh` blanks `VEYRS_SMTP_HOST` and `VEYRS_TELEGRAM_BOT_TOKEN` so that tests can never reach a live channel, and sets
`VEYRS_ENVIRONMENT=development` and the rate limits. (b) `conftest.py` refuses a database whose name does not end in `_test`, so the suite can
never run against production: bare `pytest` has no test database URL.

**Diagnosis.**

```bash
grep -E '^VEYRS_(SMTP_HOST|TELEGRAM_BOT_TOKEN|TEST_DATABASE_URL)=' /opt/veyrs/.env | sed -E 's/=.*/=<set>/'   # TEST_DATABASE_URL belongs in .env.test, not here (R-22)
ls -l /opt/veyrs/.env.test
sed -n 1,46p /opt/veyrs/scripts/test.sh
```

**Fix.** Always `./scripts/test.sh [pytest args]`. Provide `VEYRS_TEST_DATABASE_URL` in `.env.test` (gitignored, 0600; `test.sh` loads it after `.env`; the application never reads it) pointing at a database named `..._test` (the installer creates
`veyrs_test` and writes `.env.test`); do not point it at the production database host. The suite also deletes the limiter's `veyrs:rl:*` keys, so
`test.sh` gives the app `VEYRS_TEST_REDIS_URL` (default `redis://127.0.0.1:6379/15`) and `conftest.py` aborts on Redis database 0 or on a `VEYRS_REDIS_URL` that is not that URL.

**Validation.** `./scripts/test.sh tests/test_docs_are_current.py` runs; mail logs show no delivery to fixture addresses.

**Impact.** (a) Fixture data and addresses handed to a real relay or bot. (b) None; the guard protected production.

**Source.** `scripts/test.sh`; `tests/conftest.py`; `docs/operations/release.md`.

### The API does not start after moving to the `veyrs` account

**Symptom.** After `install.sh` or `scripts/migrate-service-user.sh`, `systemctl status veyrs-api` shows `217/USER`, `Permission denied` on `.env`, or an import error under `/opt/veyrs`.

**Probable cause.** `217/USER`: the account does not exist. `.env` unreadable: its group is not `veyrs` or its mode is `0600`. Import error: `/opt/veyrs` or a parent directory is not searchable by others. A feature that reads a file outside the tree (a Vault secret-id file, an LDAP CA bundle) fails because that file is readable by root only.

**Diagnosis.** `id veyrs; stat -c '%a %U:%G' /opt/veyrs/.env /opt/veyrs/var; runuser -u veyrs -- test -r /opt/veyrs/backend/veyrs/main.py && echo readable`

**Fix.** Re-run `scripts/migrate-service-user.sh` (idempotent). To go back, `scripts/migrate-service-user.sh --rollback`.

**Source.** `infrastructure/systemd/veyrs-api.service`; `scripts/migrate-service-user.sh`.

---

## Collecting evidence for a bug report

```bash
journalctl -u veyrs-api --since '30 min ago' --no-pager > veyrs-api.log        # JSON; contains no passwords, but check before sharing
curl -s http://127.0.0.1:8000/healthz; curl -s http://127.0.0.1:8000/readyz
cd /opt/veyrs && PYTHONPATH=backend venv/bin/python -m veyrs check
systemctl --failed --no-legend
```

Quote the `correlation_id` from the failing response (`X-Correlation-ID` header, also in the error body). Never paste `.env` values,
tokens or database dumps; list key names with `cut -d= -f1`.
