# ADR 0008 — The state leaves hv-4, and the backup proves itself

**Date:** 2026-08-17
**Status:** Accepted
**Supersedes nothing. Extends** [ADR 0007](0007-stateless-app-nodes.md).

## Context

ADR 0007 made the application nodes disposable: two of them behind the fleet
proxy, all state in `veyrs-db-1`. That closed the failure that actually kept
happening — a process dying — and it left one that had never been examined.

Auditing the backup chain produced a single fact that reframed the whole
question:

> `pct config 332` → `mp0: disk-a:vm-332-disk-0,mp=/mnt/datastore,size=26078G`

The Proxmox Backup Server datastore is a **mount point inside hv-4**. Every
VEYRS container runs on hv-4. Losing that host would have destroyed production
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

1. **A streaming standby on a different physical host.** `veyrs-db-2`
   (CT 104, 10.50.0.32, **hv-1**), physical replication slot, asynchronous,
   `hot_standby_feedback = on`. Tuning mirrors the primary.
2. **A logical dump, pushed off hv-4.** Nightly `pg_dump -Fc` to hv-1 under an
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
- **The off-host account is unprivileged.** `veyrsbak` on hv-1 owns one
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

**Moving PBS off hv-4.** Correct, and out of scope here: PBS backs up the whole
fleet, so relocating its datastore is a fleet decision with fleet-wide
consequences. It is recorded as an open risk rather than quietly worked around.

**A second application node off hv-4.** Deferred. It buys nothing until the
data is recoverable, and it is now — the constraint was never CPU.

**Trusting `pg_restore --list` as verification.** Rejected once the RLS trap was
understood: an empty dump lists perfectly. Only a restore that counts rows is
evidence.

## Consequences

**Good.** Losing hv-4 changes from terminal to recoverable, in two independent
forms. The restore path is exercised weekly rather than believed. The backup
that most people would have called sufficient — the PBS snapshot — is now
documented as the one that does not survive the failure it appears to cover.

**Costs.** One more container to patch. One more Postgres to keep at the same
minor version as the primary (a standby cannot replay WAL from a newer primary).
Roughly 15 GB on hv-1 for 30 days of dumps. Promotion is four manual steps, one
of which (Redis) is easy to forget under pressure — which is why it is written
down in the runbook rather than left to memory.

**Unresolved, and stated plainly.** Nothing on this fleet alerts on a failed
systemd unit. `veyrs-intel-sync` failed three consecutive nights before it was
noticed, and the three timers added here fail into the same unread journal. The
honest fix is fleet-wide alerting; adding a fourth VEYRS-local check would be
theatre.
