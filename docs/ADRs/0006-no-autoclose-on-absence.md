---
title: ADR 0006: Never close a finding because a scan omitted it
purpose: Record why absence from a scan is not treated as proof of a fix, and how the mechanism has evolved.
scope: The reconciliation policy for findings missing from an import; the principle is current, the original mechanism is partly superseded.
version: 0.39.1
verified: 2026-11-17
status: Superseded
sources: [backend/veyrs/services/engagements.py, backend/veyrs/services/importers/base.py, backend/veyrs/api/v1/integrations.py, backend/veyrs/services/correlation.py, tests/test_phase15_unified_ingest.py]
related: [ADRs/0009-closure-per-covered-asset.md, architecture/data-flows.md, ADRs/README.md]
---

# ADR 0006 - Never close a finding because a scan omitted it

**Status:** Superseded by [ADR 0009](0009-closure-per-covered-asset.md) (mechanism); principle accepted · **Date:** 2026-08-10 · **Checked against code:** 0.39.1

> [!IMPORTANT]
> **Superseded by [ADR 0009](0009-closure-per-covered-asset.md)** (0.41.0), which records the closure semantics the code implements: consecutive absences per engagement type, within the scan test, counted only on assets the run covered, with coverage attestation for agent runs, and never re-closing a finding that already claims a fix. The principle below (absence is evidence, not proof; a false-closed is worse than a false-open; closures are labelled) is carried into ADR 0009 unchanged. The rest of this page is kept as the historical record, checked against 0.39.1.

> **Superseded detail.** The paragraphs below describe the first implementation: absence never closes, `close_missing=true` is the only way. The code now reconciles **per scan test** and closes after a **threshold of consecutive absences by engagement type** (see "Check against 0.39.1" at the end). The principle (absence is evidence, not proof; a false-closed is worse than a false-open; closures are labelled) is unchanged.

> [!NOTE]
> **Status note (2026-11-17).** Current implementation, checked in the 0.39.1 code: a file import is reconciled against the sightings of its own scan test (`services/engagements.py:231-330`). Unless the request says otherwise, the threshold comes from the engagement type, 1 consecutive absence for `ci_cd`, 2 for `scheduled`, 0 (never close) for `interactive` (`DEFAULT_ABSENCE_THRESHOLD`, `services/engagements.py:45-49`), and `close_absent` defaults to "threshold above 0" (`engagements.py:262-266`). An import that names no engagement lands in the default "Continuous scanning" engagement, which is `scheduled` (`engagements.py:123-131`), so by default a finding missing from two consecutive runs of the same test is closed as `remediated` with `evidence: "absence"`. Scanner-console connectors are opt-in: `close_absent` defaults to false and `absence_threshold` to 0 (`api/v1/integrations.py:729-730`), and `close_absent` without an engagement is refused (`services/scanners.py:504-507`). `close_missing` survives only as a deprecated alias for `close_absent` with a threshold of 1 (`services/importers/base.py:276-280,764-772`). Agent results never close unless the run succeeded and coverage was attested (`services/agents.py:974-990`). The decision text below is kept as written; the operator-facing description is in [Scanner integrations](../integrations/scanners.md).

## Context

Most vulnerability management tools auto-close findings absent from the latest
scan. It keeps the queue tidy and the metrics flattering.

It is also wrong. A host that was powered off, unreachable, out of scope for that
scan profile, or missed because credentials expired produces exactly the same
signal as a host that was patched.

The failure is asymmetric. A false-open costs an analyst two minutes of triage. A
false-closed removes a real, exploitable flaw from the queue with a green tick
next to it.

## Decision

Findings absent from an import become `stale_candidates` - counted, reported on
the import run, never closed. `close_missing=true` exists as an explicit opt-in
for operators who know their scan coverage is complete, and the resulting
closures record `"reason": "absent from scanner export"` in the finding event, so
an auditor can distinguish "we fixed it" from "the scanner stopped mentioning
it".

Separately, a finding seen again after `remediated` is **reopened as a
regression** rather than silently duplicated - keyed on the finding *state*, not
on `closed_at`, which `remediated` never sets. That bug meant a failed patch
disappeared from the queue entirely.

## Alternatives rejected

- **Auto-close after N consecutive absences.** Better, still guessing, and the
  operator cannot see the guess.
- **Auto-close silently.** The behaviour this ADR exists to prevent.

## Consequences

- Queues are larger and more honest.
- `stale_candidates` gives operators a real signal about scan coverage, which is
  usually the actual underlying problem.

## Revisit if

Scan coverage becomes machine-verifiable per asset, at which point absence could
be interpreted safely for assets provably in scope.

## Check against 0.39.1

| ADR statement | Code at 0.39.1 | Result |
|---|---|---|
| Absent findings become `stale_candidates`, counted and never closed | `reconcile_test` marks them absent per scan test and **does close** at the threshold for the engagement type: 1 for `ci_cd`, 2 for `scheduled`, 0 (never) for `interactive` (`services/engagements.py:43-48,231-330`). The default "Continuous scanning" engagement is `scheduled`, so an ordinary re-upload that omits a finding twice in a row moves it to `remediated` | **Superseded**: default is not "never close" any more |
| `close_missing=true` is the explicit opt-in | `close_missing` is a deprecated alias for `close_absent` with threshold 1; `close_absent` and `absence_threshold` are the options; `absence_threshold=0` disables closure (`importers/__init__.py`, `api/v1/integrations.py:166-173`) | **Superseded** |
| Closures record `"reason": "absent from scanner export"` | Same string, plus `evidence: "absence"`, `consecutive_absences`, `absence_threshold`, run ids and coverage attestation, so reports can say "not a verified fix" (`engagements.py:296-330`) | Holds and extended |
| Seen again after `remediated` is a regression, keyed on state | `REOPENABLE_STATES = {remediated, verified, closed}` (`services/correlation.py:44`); reopening restarts the SLA clock | Holds |
| Scope | Original text did not scope closure. A scoped design was added because an organization-wide `_close_missing` marked a whole estate remediated from a three-host export; that function was deleted (`importers/base.py:791-797`) | New, and the main reason this ADR needs an update |
| Agent results | Closure is forced off unless the agent's scan statistics attest at least 80 percent coverage or the job succeeded cleanly (`services/agents.py:845-1000`) | New |

> [!NOTE]
> In 0.39.1 the API's self-description at `GET /api/v1/integrations/importers` said absent findings "are NOT closed unless close_absent is set", while the default scheduled engagement closed them after two consecutive absences. The text was corrected in 0.41.0 together with ADR 0009.

Tests read: `tests/test_phase15_unified_ingest.py` (`test_reimport_does_not_close_findings_outside_its_own_scope`, `test_reimport_closes_what_its_own_test_stopped_reporting`, `test_a_single_absence_does_not_close_on_a_scheduled_sweep`, `test_a_reappearing_finding_resets_its_absence_counter`).
