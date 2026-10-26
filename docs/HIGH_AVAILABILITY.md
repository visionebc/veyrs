# High availability — runbook

Topology decision and rationale: [ADR 0007](ADRs/0007-stateless-app-nodes.md).

## The map

```
                  https://veyrs-app-1.example.com
                  https://veyrs-app-2.example.com   (alias)
                  https://veyrs.example.com    (301 -> a1, retired)
                  https://veyrs-docs.example.com        (docs)
                                 |
                                 v
                 fleet proxy  CT 100 · 10.50.0.10   <-- TLS terminates here
                 upstream veyrs_app { a1 · a2 backup }  (*.example.com wildcard)
                        /                   \
                       v                     v
      veyrs-app-1 CT 101 · 10.50.0.21   veyrs-app-2 CT 103 · 10.50.0.22
        PRIMARY — takes all traffic       SECONDARY — only when a1 is down
        nginx :80                         nginx :80
        veyrs-api  (uvicorn, 4 workers)   veyrs-api  (uvicorn, 4 workers)
        veyrs-agent            <a1 ONLY>  veyrs-agent            (disabled)
        veyrs-intel-sync.timer <a1 ONLY>  veyrs-intel-sync.timer (disabled)
        postgres local = veyrs_test ONLY  postgres local = disabled
                       \                     /
                        v                   v
                 veyrs-db-1  CT 102 · 10.50.0.31
                 PostgreSQL 15 (:5432)  +  Redis (:6379, requirepass)

                 veyrs-db-2  CT 104 · 10.50.0.32   (streaming standby)
```

All four containers are on **hv-4**. That is a known limitation, not an
oversight — see "What this does NOT cover".

## What is protected, and what happens

| Failure | Effect on the user | Intervention |
|---|---|---|
| `veyrs-api` dies on one node | none — the proxy retries on the other | none |
| a whole mag node shuts down | none | none |
| both mag nodes go down | full outage | start one |
| `veyrs-db-1` goes down | full outage | promote the standby (see Phase 2) or restore from PBS |
| `veyrs-agent` stopped (a1 down) | scheduled scans do not run | enable it on a2 (below) |

Verified in production on 2026-08-17, while the upstream was still
active/active (`least_conn`, two equal peers):

- `systemctl stop veyrs-api` on a1 → **20/20 requests returned 200**.
- `pct stop 361` (the whole node) → **25/25 requests returned 200 in 6 s**.
- Split with both alive: 30 concurrent requests → **14 / 16**.

Re-verified on 2026-08-18, after a2 was demoted from peer to `backup` by
operator decision:

- 20 requests in normal operation → **20 to a1, 0 to a2**.
- 15 requests with `nginx` stopped on a1 → **15/15 returned 200, all served by a2**.
- 10 requests immediately after a1 recovered → **still 10 to a2**.
- 10 requests ~15 s later → **10 to a1**.

> **Failback is not instantaneous.** After the primary recovers, nginx keeps
> sending to the backup until `fail_timeout` (10 s) expires. That is correct —
> retrying sooner is how a half-started node gets traffic — but it explains a
> window in which the secondary serves while the primary is already alive.

> `proxy_connect_timeout 3s` is mandatory and is not cosmetic. Without it, the
> *hard* loss of a node (the IP disappears, there is no RST) leaves the
> connection hanging until the 60 s default timeout before retrying: the first
> test with the node powered off scored 19/20 for exactly that reason.

## Runbooks

### Promote a2 to the singleton node (a1 lost for a prolonged period)

```bash
ssh root@10.50.0.22
systemctl enable --now veyrs-agent veyrs-intel-sync.timer
```

**First, confirm a1 is not running them.** Two runners claiming the same jobs
corrupt state. When a1 comes back:

```bash
ssh root@10.50.0.21 && systemctl disable --now veyrs-agent veyrs-intel-sync.timer   # if a2 was promoted
```

Exactly one node, always.

### Take a node out of rotation (planned maintenance)

There is no need to touch the proxy: stopping `nginx` or `veyrs-api` on that
node is enough — the passive health check marks it down after 2 failures /
10 s. To take it out explicitly, comment its line in
`/etc/nginx/conf.d/veyrs-upstream.conf` on 10.50.0.10 and `systemctl reload nginx`.

### Add a third node

1. `pct restore <id> pbs:backup/ct/101/<snapshot> --storage disk-b --hostname veyrs-app-3 --net0 ...`
2. On the node: disable `veyrs-agent`, `veyrs-intel-sync.timer`, `postgresql`, `redis-server`.
3. Point `.env` at `10.50.0.31` (database and Redis) and set `VEYRS_TEST_DATABASE_URL` to `127.0.0.1`.
4. Add its `/32` to `pg_hba.conf` on `veyrs-db-1` and reload.
5. Add it to `upstream veyrs_app`.

Step 4 is deny-by-default on purpose: a new node does not talk to the
vulnerability database until somebody authorises it.

## Constraints that must be respected

- **Do not point `VEYRS_TEST_DATABASE_URL` at `10.50.0.31`.** The suite creates
  and destroys schema; it would compete with production and would defeat the
  physical separation that today backs the guard in `tests/conftest.py`.
- **Do not open `pg_hba.conf` by CIDR.** A `/24` turns any container on the LAN
  into a client of the vulnerability database.
- **The `.env` on both nodes shares the JWT signing secret.** If it is rotated,
  it is rotated on both at once, or tokens issued by one node are rejected by
  the other.
- **`sites-enabled/` on the proxy must be a symlink to `sites-available/`.** The
  VEYRS vhosts were once loose files and already caused a silent no-op edit:
  `nginx -t` passes anyway, because the edited file is not part of the running
  configuration.

## What this does NOT cover

- **Loss of the physical host hv-4.** All four containers live there. This
  covers a dead process and a downed container, not a lost host.
- **`veyrs-db-1` is a single point of failure for writes.** A streaming standby
  exists (Phase 2) but promotion is manual, and since the 2026-08-20 relocation
  the standby is on hv-4 too. Daily PBS snapshots and the nightly logical dump
  to hv-1 are the off-host cover.
- **Batch work during an a1 outage** (scheduled scans, the nightly intelligence
  sync) is paused until an operator promotes a2.

---

## Phase 2 — the database standby (2026-08-17)

Phase 1 made the application nodes disposable. It did not address the fact that
**all of VEYRS lived on one physical host, backups included.**

### What was actually exposed

The PBS datastore is `mp0: disk-a:vm-332-disk-0` — a mount point **inside
hv-4**, the same host running `veyrs-app-1`, `veyrs-app-2` and
`veyrs-db-1`. Losing hv-4 would have taken production and every restore point
with it. "We have nightly backups" was true and irrelevant.

### What exists now

| | |
|---|---|
| Standby | **CT 104 `veyrs-db-2` @ 10.50.0.32, on hv-4** (moved off hv-1 on 2026-08-20 - see *Standby relocation* below) |
| Method | PostgreSQL 15 streaming replication, physical slot `veyrs_db_a2` |
| Mode | Asynchronous, `hot_standby = on`, `hot_standby_feedback = on` |
| Measured lag | ~1 ms / 0 bytes at idle |
| Verification | `veyrs-replcheck.timer`, every 15 minutes |

The standby's `conf.d/veyrs.conf` **mirrors the primary's tuning**
(`shared_buffers`, `work_mem`, `max_connections`). A standby tuned smaller than
its primary becomes a capacity incident the moment it is promoted.

### Standby relocation to hv-4 (2026-08-20)

The standby was moved from hv-1 to hv-4 by operator decision, with its rootfs
on `disk-a` (the mechanical IronWolf). Method: `vzdump` to `pbs`
(`ct/104/2026-08-20T02:13:12Z`) then `pct restore --storage disk-a` - hv-1 and
hv-4 are **not clustered**, so `pct migrate` is not available between them. The
IP is unchanged (10.50.0.32), so the primary's `pg_hba.conf` needed no edit;
replication resumed on its own at 0 bytes of lag.

**State this plainly: the streaming standby no longer protects against the loss
of hv-4.** The primary, both application nodes, the standby and the PBS
datastore (`mp0: disk-a:vm-332-disk-0`, a mount point inside hv-4) are now all
on the same physical host. What remains off-host is the nightly logical dump
pushed to hv-1 - one copy, RPO 24 h, recovered by hand with `pg_restore`, not
by promotion.

Two second-order effects worth knowing:

- **`disk-a` is at 92.65%** (274 GiB free) with both database volumes on it. It
  is thick LVM, so each 100 G volume reserves 100 G regardless of the 5 GB the
  database actually occupies.
- **The standby now shares a spindle with `veyrs-app-1`.** Replay I/O and the
  primary application node contend for the same mechanical disk; any latency
  comparison between a1 and a2 measures the disk, not the code.

### `max_slot_wal_keep_size = 20GB` is not optional

A replication slot with no bound is a space bomb. If the standby is down over a
weekend, the primary faithfully **retains every WAL segment for it** and fills
its own 98 GB disk — the replica takes production down. With the bound, the
slot is invalidated instead (`wal_status = 'lost'`, rebuild with
`pg_basebackup`) and the primary keeps serving.

`veyrs-replcheck.sh` checks for exactly that state, because an invalidated slot
is worse than a missing one: it looks configured, and the standby can never
catch up on its own.

### Promotion is manual, and stays manual

```bash
# 1. Confirm the primary is really gone. Two primaries cannot be reconciled.
ssh root@10.50.0.31 'systemctl status postgresql@15-main'

# 2. Promote.
ssh root@10.50.0.32 'su postgres -c "/usr/lib/postgresql/15/bin/pg_ctl promote -D /var/lib/postgresql/15/main"'
ssh root@10.50.0.32 'su postgres -c "psql -tAc \"select pg_is_in_recovery()\""'   # expect: f

# 3. Point the app nodes at it (both .env files).
for n in 10.50.0.21 10.50.0.22; do
  ssh root@$n "sed -i 's/@10.50.0.31:5432/@10.50.0.32:5432/' /opt/veyrs/.env && systemctl restart veyrs-api"
done

# 4. Redis is NOT replicated. It holds rate-limit counters and cache only —
#    losing it degrades the limiter, it does not lose data. Point the app at a
#    Redis on the surviving node, or stand one up on 10.50.0.32.

# 5. pg_hba on the new primary must list the app nodes (/32, not CIDR).
```

Automatic promotion without fencing produces two primaries, and two primaries
produce divergent security data — findings closed on one side and open on the
other, with no way to tell afterwards which was true.

### What phase 2 still does not cover

- **Redis is not replicated.** Deliberate: it is a cache and a rate limiter, not
  a system of record. Promotion needs one manual step for it.
- **Everything is on hv-4 again - app nodes, primary, standby and PBS.** Since
  the 2026-08-20 standby relocation, losing hv-4 is a full outage *and* the
  streaming standby is lost with it. Recovery is from the nightly logical dump
  on hv-1: one copy, RPO 24 h, restored by hand. The earlier claim that "the
  data survives on hv-1 in two independent forms" is no longer true.
- **`/var/www/veyrs` and `/var/www/veyrs-web` are local state on each app node.**
  They are interchangeable only because both nodes sit on the same commit and
  both run the builders. After any docs change: `git pull` + build on **both**,
  then compare `md5sum`.

---

## Logical backups (2026-08-17)

Streaming replication is not a backup. It replicates a `DROP TABLE` faithfully
and within milliseconds.

| Unit | Schedule | What it does |
|---|---|---|
| `veyrs-pgdump.timer` | 02:15 daily | `pg_dump -Fc`, integrity check, **push to hv-1**, retention |
| `veyrs-pgverify.timer` | Sunday 04:30 | Restores the latest dump into a scratch DB and compares row counts |
| `veyrs-replcheck.timer` | every 15 min | Slot active, not lost, streaming, lag under 128 MB |

Retention: 7 days locally, 30 days off-host. First run: **444 MB, 78 data
sections**, verified byte-for-byte on hv-1 by SHA-256.

### The trap that makes this script look paranoid

**`pg_dump` run as the `veyrs` role produces a perfectly well-formed, perfectly
empty archive.** VEYRS has RLS with FORCE on 61 policies and `pg_dump` is just
SELECTs — every tenant table returns zero rows, the exit code is 0, there is no
warning, and `pg_restore --list` still shows the tables in the TOC. That backup
is discovered to be empty on the day it is needed.

So `veyrs-pgdump.sh`:

1. **refuses to run** unless the connected role is a superuser;
2. counts the tenant-scoped canary tables **before** dumping, so the check has a
   reference that did not come from the dump itself;
3. asserts a size floor (20 MB) and the presence of `TABLE DATA` sections for
   every canary with live rows;
4. only then rotates old backups — a new backup is never trusted before it is
   proven, and an old one is never deleted before the new one is.

Weekly, `veyrs-pgverify.sh` goes further and actually restores, comparing
`assets`, `findings`, `organizations`, `users`, `asset_products`, `import_runs`
**and the RLS policy count** against production. A restore that silently loses
policies is a restore that would serve one tenant's data to another. Verified
2026-08-17: 78 tables, 61 policies, every count equal.

Two details the restore path depends on, both already documented in
DEPLOYMENT.md and both re-learned the hard way:

- `createdb -E UTF8 -T template0` — inheriting `SQL_ASCII` from `template1`
  makes psycopg return `bytes` and the app fail at `_get_server_version_info`,
  while `pg_restore` reports **zero errors**;
- restore as `postgres` and **without** `--no-owner` — `--role=veyrs` submits
  the restore to RLS and foreign-key validation fails with *"query would be
  affected by row-level security policy"*.

### The off-host copy is unprivileged

The dump is pushed to hv-1 as **`veyrsbak`**, a dedicated account whose key is
`restrict`-ed and owns only `/var/backups/veyrs-offhost`. A root key there would
turn a compromise of the database node into root on the primary hypervisor —
which, in a platform whose whole job is knowing where the exposure is, would be
an unusually poor look.

### Still missing

Nothing watches for a `failed` systemd unit on this fleet. `veyrs-intel-sync`
failed three consecutive nights before anyone noticed, and these three new
timers have exactly the same blind spot: they fail loudly into a journal nobody
reads. **The fix is fleet-wide alerting, not another VEYRS-local check.**
