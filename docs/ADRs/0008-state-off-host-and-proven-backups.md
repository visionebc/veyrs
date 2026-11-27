---
title: ADR 0008: The state leaves the app host, and the backup proves itself
purpose: Record why VEYRS keeps a streaming standby and an off-host logical dump, and why every backup must be proven by a restore.
scope: The three-layer backup and standby decision; checked against the shipped backup scripts and the current HA record. Hypervisor names are generalised (H1 original host, H2 second host).
version: 0.39.1
verified: 2026-11-17
status: Partial
sources: [infrastructure/backup/veyrs-pgdump.sh, infrastructure/backup/veyrs-pgverify.sh, infrastructure/backup/veyrs-replcheck.sh, infrastructure/backup/veyrs-pgdump.timer, infrastructure/backup/veyrs-pgverify.timer, infrastructure/backup/veyrs-replcheck.timer, backend/veyrs/cli.py, tests/test_restore_as_superuser.py]
related: [HIGH_AVAILABILITY.md, DISASTER_RECOVERY.md, architecture/deployment.md, ADRs/0007-stateless-app-nodes.md]
---

# ADR 0008 — The state leaves the app host, and the backup proves itself

**Date:** 2026-08-17
**Status:** Accepted
**Supersedes nothing. Extends** [ADR 0007](0007-stateless-app-nodes.md).

> **Status note (2026-11-11).** The decision below is unchanged, but the
> deployment no longer matches layer 1. Per
> [High availability](../HIGH_AVAILABILITY.md) (verified 2026-10-26), all four
> VEYRS containers — both application nodes, the database node and the standby —
> run on **one hypervisor (H2)**, so the standby shares the primary's
> physical host; the off-host dump copy is on H2 too, and the PBS datastore
> is unreachable while its host is off. The deployment currently has no copy on
> another physical machine. Later measurement also showed that the RLS trap
> described below surfaces as a mid-dump *"query would be affected by
> row-level security policy"* error that leaves a truncated archive, not as a
> clean empty one (see [Disaster recovery](../DISASTER_RECOVERY.md)).

## Context

ADR 0007 made the application nodes disposable: two of them behind the fleet
proxy, all state in the database node. That closed the failure that actually kept
happening — a process dying — and it left one that had never been examined.

Auditing the backup chain produced a single fact that reframed the whole
question:

> The backup server's container configuration showed its datastore as a mount
> point on a disk of hypervisor H1.

The Proxmox Backup Server datastore is a **mount point on hypervisor H1**. Every
VEYRS container ran on H1. Losing that host would have destroyed production
*and* every restore point in the same event. The fleet had nightly backups and
no disaster recovery, and the two had been treated as the same thing.

A second fact, found while writing the dump script:

> `pg_dump` executed as the `veyrs` role returns **zero rows** for every tenant
> table, exits 0, emits no warning, and produces an archive whose TOC lists all
> 78 tables.

VEYRS runs row-level security with FORCE on 61 policies, and `pg_dump` is only
SELECTs. An RLS-filtered dump is not a corrupt file that fails to restore — it
is a valid file that restores an empty database. It would have been discovered
on the day it was needed.

## Decision

**Three independent layers, each covering what the others cannot, and each
required to demonstrate that it works.**

1. **A streaming standby on a different physical host.** the standby
   (example 192.0.2.87, on **H2**), physical replication slot, asynchronous,
   `hot_standby_feedback = on`. Tuning mirrors the primary.
2. **A logical dump, pushed off H1.** Nightly `pg_dump -Fc` to H2 under an
   unprivileged account, SHA-256 verified at the destination, 7 days local /
   30 days remote.
3. **Weekly proof of restorability.** The dump is restored into a scratch
   database and its row counts and RLS policy count compared against
   production.

Supporting decisions, each of which is load-bearing:

- **`max_slot_wal_keep_size = 20GB`.** An unbounded replication slot makes the
  standby able to kill the primary: WAL is retained for a consumer that is not
  consuming until the primary's disk fills. Bounded, the slot is invalidated
  instead and production keeps running.
- **The dump script refuses to run as a non-superuser**, counts canary tables
  *before* dumping, asserts a size floor and the presence of `TABLE DATA`
  sections, and rotates old backups only after the new one has passed. The RLS
  trap is not detectable after the fact; it has to be designed out.
- **The off-host account is unprivileged.** `veyrsbak` on H2 owns one
  directory and holds a `restrict`-ed key. A root key would have made a
  compromise of the database node a path to root on the primary hypervisor.
- **Promotion stays manual.** Automatic promotion without fencing produces two
  primaries; two primaries produce security findings that are closed on one side
  and open on the other, with no way to establish afterwards which was true.

## Alternatives considered

**Synchronous replication.** Rejected. It would make every write wait on a link
to another physical host, and — worse — a standby outage would block writes on
the primary. For a platform whose worst realistic loss is a few minutes of
scan ingestion, trading availability for an RPO improvement measured in
milliseconds is the wrong trade.

**Moving PBS off H1.** Correct, and out of scope here: PBS backs up the whole
fleet, so relocating its datastore is a fleet decision with fleet-wide
consequences. It is recorded as an open risk rather than quietly worked around.

**A second application node off H1.** Deferred. It buys nothing until the
data is recoverable, and it is now — the constraint was never CPU.

**Trusting `pg_restore --list` as verification.** Rejected once the RLS trap was
understood: an empty dump lists perfectly. Only a restore that counts rows is
evidence.

## Consequences

**Good.** Losing H1 changes from terminal to recoverable, in two independent
forms. The restore path is exercised weekly rather than believed. The backup
that most people would have called sufficient — the PBS snapshot — is now
documented as the one that does not survive the failure it appears to cover.

**Costs.** One more container to patch. One more Postgres to keep at the same
minor version as the primary (a standby cannot replay WAL from a newer primary).
Roughly 15 GB on H2 for 30 days of dumps. Promotion is four manual steps, one
of which (Redis) is easy to forget under pressure — which is why it is written
down in the runbook rather than left to memory.

**Unresolved, and stated plainly.** Nothing on this fleet alerts on a failed
systemd unit. `veyrs-intel-sync` failed three consecutive nights before it was
noticed, and the three timers added here fail into the same unread journal. The
honest fix is fleet-wide alerting; adding a fourth VEYRS-local check would be
theatre.

## Check against 0.39.1

| Claim | Evidence | Result |
|---|---|---|
| Nightly logical dump, weekly restore proof, replication check | `infrastructure/backup/*.timer`: dump daily 02:15, verify Sunday 04:30, replication check every 15 minutes | Shipped as units and scripts; they belong on the database node, so they are not on the application nodes inspected |
| `pg_dump` as the application role yields a truncated or empty archive | `cli.py` applies `FORCE ROW LEVEL SECURITY`; `tests/test_restore_as_superuser.py` and `tests/test_docs_are_current.py::test_the_recovery_manual_warns_about_the_rls_backup_trap` guard the behaviour and the warning | Holds. Later measurement showed a mid-dump error and a truncated archive rather than a clean empty one (see the status note above) |
| Table and policy counts (78 tables, 61 policies) | Counts at the time of writing. At 0.39.1: 89 tables, 72 with `FORCE ROW LEVEL SECURITY` (68 strict, 4 credential-keyed) | **Historical**; the trap applies to more tables now |
| Layer 1: standby on a **different physical host** | Not currently true per the status note and `HIGH_AVAILABILITY.md` (verified 2026-10-26 by its authors) | **Not met**; the decision stands, the deployment has drifted |
| Promotion stays manual | No promotion automation exists in the repository | Holds |
| "Nothing alerts on a failed systemd unit" | No alerting unit is shipped | Holds; still the largest operational gap |

The database tier was not reachable from the inspection host, so the replication, dump and restore-proof state were not observed.
