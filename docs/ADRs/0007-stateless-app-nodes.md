---
title: ADR 0007: Split the state out, make the app nodes disposable
purpose: Record why VEYRS separates state from application nodes and runs two interchangeable nodes.
scope: The two-app-node plus database-node topology; checked against the code and a read-only inspection of the reference installation.
version: 0.39.1
verified: 2026-11-17
status: Verified
sources: [backend/veyrs/config.py, backend/veyrs/security/ratelimit.py, infrastructure/systemd/veyrs-api.service, integrations/systemd/veyrs-intel-sync.timer, integrations/veyrs-agent/veyrs-agent.service]
related: [architecture/deployment.md, HIGH_AVAILABILITY.md, ADRs/0008-state-off-host-and-proven-backups.md]
---

# ADR 0007 - Split the state out; make the app nodes disposable

**Status:** Accepted · **Date:** 2026-08-17 · **Checked against code and a live installation:** 0.39.1 · **Routing detail superseded** (see "Check against 0.39.1")

> [!NOTE]
> **Status note (2026-11-17).** The decision below says active/active with `least_conn`. The reference installation routes primary/backup instead: the second application node has been the `backup` server of the proxy upstream since 2026-08-18, so it receives traffic only while the first is down ([High availability](../HIGH_AVAILABILITY.md)). Statelessness, the shared secret key and the shared Redis are unchanged, so either routing mode works; the singleton set is `veyrs-agent`, `veyrs-intel-sync.timer` and also `veyrs-digest.timer`.

## Context

Until this decision VEYRS was one container. `veyrs-api`, PostgreSQL, Redis,
nginx and the scanner runner (`veyrs-agent`) all lived in it. Losing that
container lost the platform *and* the runner that scans it.

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
| database node (example 192.0.2.84) | PostgreSQL 15 + Redis. The only stateful component. |
| app node A (example 192.0.2.83) | app node. Also the **singleton host**: `veyrs-agent` + `veyrs-intel-sync.timer`. |
| app node B (example 192.0.2.86) | app node. Identical, singletons disabled. |
| front proxy (example 192.0.2.40) | an upstream of both app nodes: `least_conn`, passive health checks, retry to the surviving node. |

Active/active, not active/passive. It is safe because VEYRS keeps **no local
filesystem state**: uploads are read into memory and persisted to the database,
sessions are `refresh_tokens` rows, access tokens are JWTs signed with a secret
both nodes share, and rate limiting is the shared Redis. There is nothing for a
sticky session to protect, so no sticky session is configured.

Failover is therefore **automatic and unattended**, which is the property the
real incident called for. The chosen point of control is the proxy that was
*already* in the path - both public names resolved to it before this change
and still do. No DNS change participates in a failover.

## Consequences

**Accepted:** the database container is now a single point of failure for the
whole platform. This is a deliberate trade - it is one small, boring service
instead of a large application, it is covered by the nightly fleet
backup job (which enumerates every guest, so the database node and the second
app node were in scope from the first night without a manifest entry), and `wal_level=replica` /
`max_wal_senders=5` are already set so a streaming standby is an addition rather
than a rebuild. Phase 2 puts that replica on a different physical host.

**Accepted:** `veyrs-agent` and `veyrs-intel-sync` run on **exactly one node**.
Two runners claiming the same jobs is corruption, not redundancy, and two
intelligence syncs is two NVD backfills competing for the same rate limit. If node A
is lost for an extended period, an operator enables them on node B - the units
and `/etc/veyrs-agent/agent.env` are present and merely disabled. Batch work pausing
during a node outage is the correct trade against corrupting it.

**Rejected - clone-and-reconcile (the model used by another system in the same
fleet):** it synchronises *git*, not
data. Applied here it produces a standby whose vulnerability database ages from
the moment it is made.

**Rejected - streaming replica alone:** it addresses host loss, which is not the
failure being observed, and it still needs a human to promote it at 03:40.

## Notes for whoever operates this next

- Test database stays **local to each node** (`VEYRS_TEST_DATABASE_URL` →
  `127.0.0.1`). It must never point at the production database node: the suite would compete
  with production for CPU, and the "never touch production" guard in
  `tests/conftest.py` is now backed by physical separation as well as a name
  check.
- Redis on the shared node is password-protected (`requirepass`). Moving it off
  loopback without that would have been a straight downgrade of the rate limiter.
- `pg_hba.conf` allows `192.0.2.83/32` and `192.0.2.86/32` only. Adding a node
  means adding a line - deliberately, not by CIDR.

## Check against 0.39.1

| Claim | Evidence | Result |
|---|---|---|
| The app holds no local filesystem state | The only backend file writes are the update staging directory and spool (`services/updates.py:338`, `config.py:132-141`). Documents are parsed in memory and their extracted text stored in PostgreSQL; reports are rendered per request | Holds |
| Sessions are `refresh_tokens` rows; JWT secret shared; rate limiting in shared Redis | `api/v1/auth.py`, `security/auth.py`, `security/ratelimit.py` | Holds. An empty `VEYRS_SECRET_KEY` is refused by the container entrypoint because each worker would otherwise sign with a different random key |
| Active/active, `least_conn` | `HIGH_AVAILABILITY.md` records that node B was demoted to `backup` on 2026-08-18 by operator decision, so traffic goes to node A unless it is down | **Superseded detail**: primary/backup, not active/active. The failover property is unchanged |
| Singletons (`veyrs-agent`, `veyrs-intel-sync.timer`) on exactly one node | Observed 2026-11-17: node A runs the agent and both timers; node B runs `veyrs-api` only, agent and intel timer disabled, no digest timer unit installed | Holds. The digest timer also belongs to the singleton set but the ADR does not list it |
| Redis protected by `requirepass` | Taken from the ADR and `HIGH_AVAILABILITY.md`; not inspected | Unknown |

One further behaviour belongs next to the shared-Redis decision: the rate limiter checks Redis once per worker process. If Redis is unreachable on a worker's first request, that worker falls back to in-process windows for its entire lifetime (roughly N times the configured rate across N workers); if Redis fails later, the limiter fails open (`security/ratelimit.py:84-120`). Both are documented in the module and chosen over taking the platform down with the limiter.
