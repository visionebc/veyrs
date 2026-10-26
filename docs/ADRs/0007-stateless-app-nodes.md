# ADR 0007 - Split the state out; make the app nodes disposable

**Status:** Accepted · **Date:** 2026-08-17

## Context

Until today VEYRS was one container. `veyrs-api`, PostgreSQL, Redis, nginx and
the scanner runner (`veyrs-agent`) all lived in CT 101. Losing that container
lost the platform *and* the runner that scans it.

The obvious reading of "add redundancy" is a second full node, kept in step by
copying git and cloning the database. That is the wrong primitive here, and the
reason is in the incident log rather than in theory: the failure that actually
happened three nights running (14, 15 and 16 August) was **a process dying**
(`veyrs-intel-sync` OOM-killed, taking the shell loop with it), not a host being
lost. A cold standby does not cover a dead process, because nothing promotes it.
A streaming replica does not cover it either - a replica does not open itself.

A second consideration decided the shape. VEYRS carries 3.1 GB of PostgreSQL and
3 million rows in `cve_cpe_match`. Any design that keeps a *copy* of that per
node starts diverging the moment it is made, and the divergence is invisible
until someone reads a stale advisory as current.

## Decision

Move the state to its own container and make the application nodes carry none.

| | |
|---|---|
| `veyrs-db-1` (CT 102, 10.50.0.31) | PostgreSQL 15 + Redis. The only stateful component. |
| `veyrs-app-1` (CT 101, 10.50.0.21) | app node. Also the **singleton host**: `veyrs-agent` + `veyrs-intel-sync.timer`. |
| `veyrs-app-2` (CT 103, 10.50.0.22) | app node. Identical, singletons disabled. |
| fleet proxy (CT 100, 10.50.0.10) | `upstream veyrs_app` - `least_conn`, passive health checks, retry to the surviving node. |

Active/active, not active/passive. It is safe because VEYRS keeps **no local
filesystem state**: uploads are read into memory and persisted to the database,
sessions are `refresh_tokens` rows, access tokens are JWTs signed with a secret
both nodes share, and rate limiting is the shared Redis. There is nothing for a
sticky session to protect, so no sticky session is configured.

Failover is therefore **automatic and unattended**, which is the property the
real incident called for. The chosen point of control is the proxy that was
*already* in the path - both public names resolved to 10.50.0.10 before this
change and still do. No DNS change participates in a failover.

## Consequences

**Accepted:** the database container is now a single point of failure for the
whole platform. This is a deliberate trade - it is one small, boring service
instead of a large application, it is covered by the nightly PBS job
(`fleet_backup.sh` enumerates every guest, so CT 102 and 363 were in scope from
the first night without a manifest entry), and `wal_level=replica` /
`max_wal_senders=5` are already set so a streaming standby is an addition rather
than a rebuild. Phase 2 puts that replica on a different physical host.

**Accepted:** `veyrs-agent` and `veyrs-intel-sync` run on **exactly one node**.
Two runners claiming the same jobs is corruption, not redundancy, and two
intelligence syncs is two NVD backfills competing for the same rate limit. If a1
is lost for an extended period, an operator enables them on a2 - the units and
`/etc/veyrs-agent/agent.env` are present and merely disabled. Batch work pausing
during a node outage is the correct trade against corrupting it.

**Rejected - clone-and-reconcile (the SATOM model):** it synchronises *git*, not
data. Applied here it produces a standby whose vulnerability database ages from
the moment it is made.

**Rejected - streaming replica alone:** it addresses host loss, which is not the
failure being observed, and it still needs a human to promote it at 03:40.

## Notes for whoever operates this next

- Test database stays **local to each node** (`VEYRS_TEST_DATABASE_URL` →
  `127.0.0.1`). It must never point at `veyrs-db-1`: the suite would compete
  with production for CPU, and the "never touch production" guard in
  `tests/conftest.py` is now backed by physical separation as well as a name
  check.
- Redis on the shared node is password-protected (`requirepass`). Moving it off
  loopback without that would have been a straight downgrade of the rate limiter.
- `pg_hba.conf` allows `10.50.0.21/32` and `10.50.0.22/32` only. Adding a node
  means adding a line - deliberately, not by CIDR.
