---
title: ADR 0009: Close by absence only on what the run covered
purpose: Record the closure-by-absence semantics VEYRS implements since 0.41.0, superseding the mechanism of ADR 0006.
scope: Reimport reconciliation of findings missing from an import: scope, coverage, consecutive-absence thresholds, coverage attestation and which states may be closed. Deduplication and the correlation engine are out of scope except where they close findings.
version: 0.41.0
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/services/engagements.py, backend/veyrs/services/importers/base.py, backend/veyrs/services/correlation.py, backend/veyrs/services/agents.py, backend/veyrs/models/vulnerability.py, backend/veyrs/api/v1/integrations.py, tests/test_fix_ingest.py, tests/test_phase15_unified_ingest.py, tests/test_phase16_agents.py]
related: [ADRs/0006-no-autoclose-on-absence.md, ADRs/README.md, integrations/scanners.md, integrations/agent.md, database/lifecycle.md]
---

# ADR 0009 - Close by absence only on what the run covered

**Status:** Accepted · **Date:** 2026-11-17 · **Implemented in:** 0.41.0 · **Supersedes:** the mechanism of [ADR 0006](0006-no-autoclose-on-absence.md) (its principle stands)

## Context

[ADR 0006](0006-no-autoclose-on-absence.md) decided that a scan omitting a
finding is evidence, not proof, and that a false-closed finding is worse than a
false-open one. The code then moved past its decision text: by 0.39.1 a finding
was closed after a threshold of consecutive absences within its **scan test**
(engagement plus scanner label), and that threshold defaulted to on.

The scan test turned out to be the wrong unit on its own. It is shared by every
run of its engagement and scanner: every partial export of a scheduled sweep,
and every agent job of an engagement whatever its target. `reconcile_test`
counted an absence for every open sighting of the test that the run did not
see, so:

- a Nessus export covering three hosts counted an absence on every other host
  the test had ever reported, and in the default `scheduled` engagement closed
  them on the second such run (TD-02);
- an agent job against host B closed host A's findings, and with a `ci_cd`
  engagement did so on the first run;
- `GET /integrations/importers` promised that "an import can never close a
  finding on a host it did not look at", which was only true for hosts the test
  had never seen.

Two further defects sat in the same path: findings already `remediated` or in
`verification` are open states, so every later run re-recorded the closure and
reset `remediated_at`; and the correlation engine's `close_missing` set
`remediated` without any transition check (TD-28).

## Decision

A finding is closed by absence only when all of the following hold.

1. **Test scope.** The finding has a sighting in the scan test this import ran
   in. Another engagement's, or another scanner label's, findings are out of
   reach (unchanged from 0.39.1).
2. **Coverage.** The finding's asset was **covered** by this run. A run covers:
   - every asset one of its records resolves to, whatever happens to the record
     afterwards (a record dropped by `min_severity` or for a missing title
     still proves the scanner looked at the host);
   - its `target_asset`, the artefact a host-less report is about;
   - `ImportOptions.covered_targets`, targets a caller asserts it scanned even
     though they produced no record (a clean host);
   - an agent job's target, when, and only when, the job's coverage check
     attested the scan (`coverage_attestation.attested = true`).

   Targets are resolved against existing assets with the importer's matching
   rules. A target that matches nothing covers nothing, and a CIDR is not
   expanded. A run that names no host at all (a header-only CSV, an empty
   upload) covers nothing and closes nothing.
3. **Consecutive absences per engagement type.** The sighting's
   `consecutive_absences` reaches the threshold: an explicit
   `absence_threshold`, else 1 for a `close_missing` caller, else the
   engagement type's default (`ci_cd` 1, `scheduled` 2, `interactive` 0 =
   never). A run that did **not** cover the asset leaves the sighting exactly as
   it was: it is neither an absence nor a sighting. "Consecutive" therefore
   means consecutive runs that covered the asset. A sighting resets to 0 when
   the finding is seen.
4. **Closure is on.** `close_absent` is true (default: threshold above 0). A
   failed or unattested agent run forces it off; a scanner connector must opt in
   and name an engagement (unchanged).
5. **The state allows an observed fix.** The finding is in an open working
   state (`OBSERVED_FIX_FROM` in `models/vulnerability.py`: every open state
   except `remediated` and `verification`). The move goes through
   `correlation.observe_fix`, the single path automation uses to record a fix,
   which the correlation engine's `close_missing` now uses too. It is a declared
   exception to `ALLOWED_TRANSITIONS`, which describes what a person may do:
   evidence may move a `new` finding to `remediated` without inventing the
   triage and assignment steps in between.

The closing event keeps its contract: event `remediated`,
`reason: "absent from scanner export"`, `evidence: "absence"` (not a verified
fix), the test, engagement, consecutive count, threshold, the absent import run
ids and the coverage attestation. A finding that reappears after closure is
reopened as a regression, as before.

## Alternatives rejected

- **One scan test per target.** Fixes agent jobs, not partial exports of a
  sweep, and multiplies tests (and their absence counters) by the number of
  hosts. Coverage is the property that actually decides whether an absence
  means anything.
- **Endpoint-level coverage for web findings.** A finer scope (a nuclei job
  against one URL should not close another URL's finding on the same host)
  but it needs each tool to report which endpoints it exercised, which none of
  the parsers can say today. Asset-level coverage is the boundary the data
  supports; endpoint-scoped findings still close only when the asset was
  covered.
- **Counting an uncovered run as an absence, or as a reset.** Either way an
  unrelated run changes a finding's counter. Neutral is the only honest
  reading of "this run did not look".
- **Expanding a CIDR target to every asset in it.** A network sweep's own
  records already name the hosts it reached; expanding the target would let a
  sweep that reached nothing close everything in the range.

## Consequences

- Partial exports and agent jobs against other targets can no longer close
  findings, so some findings that 0.39.1 would have closed stay open.
  Operators who relied on a host-less upload to close findings (for example a
  header-only CSV) must name the covered hosts (`covered_targets`) or upload a
  report that includes them.
- `stale_candidates` and `findings_marked_absent` now count only absences on
  covered assets, so they fall on partial imports. That is the number they were
  meant to report.
- A finding is closed by absence once; later runs leave it, its event log and
  `remediated_at` alone until it reappears or a person moves it.

## Revisit if

A parser can report the endpoints or checks it actually exercised (endpoint- or
check-level coverage), or VEYRS gains a per-asset record of scan coverage that
is independent of findings (a scanner's host list), at which point a clean host
in a multi-host export could be covered without `covered_targets`.

## Check against 0.41.0

| Statement | Code | Result |
|---|---|---|
| Only sightings of this test on covered assets count | `reconcile_test(covered_asset_ids=...)` joins `test_findings` to `findings` and filters `asset_id IN covered` (`services/engagements.py`) | Holds; `test_an_export_of_host_b_does_not_close_host_a` |
| Coverage sources | `importers/base.py` `ingest` (records before filters, resolved assets) and `ImportOptions.attested_targets()` (`covered_targets`, attested agent target, `target_asset`) | Holds; `test_a_record_filtered_by_severity_still_proves_coverage`, `test_an_empty_run_closes_only_on_an_attested_target` |
| Uncovered runs are neutral; consecutive per engagement type | Sightings outside `covered` are not loaded; `DEFAULT_ABSENCE_THRESHOLD` unchanged | Holds; `test_consecutive_means_consecutive_runs_that_covered_the_asset`, phase 15 threshold tests |
| No re-firing; transition declared | `OBSERVED_FIX_FROM`, `can_observe_fix`, `correlation.observe_fix`; `correlate_cve(close_missing=True)` uses it | Holds; `test_absence_closure_fires_once`, `test_correlation_close_missing_does_not_refire` |
| Agent coverage attestation | `services/agents.submit_result` writes `{"attested", "target", ...}`; `attested_targets()` reads `target` only when `attested is True` | Holds; `tests/test_phase16_agents.py` empty-result closure still passes |
