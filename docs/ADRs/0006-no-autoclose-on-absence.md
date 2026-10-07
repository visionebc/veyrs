# ADR 0006 - Never close a finding because a scan omitted it

**Status:** Accepted · **Date:** 2026-08-10

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
