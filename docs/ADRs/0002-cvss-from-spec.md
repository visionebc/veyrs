---
title: ADR 0002: Implement CVSS from the published algorithms
purpose: Record why VEYRS computes CVSS itself and how it proves correctness.
scope: The CVSS v2, v3.0, v3.1 and v4.0 calculators and their validation corpus, checked against the 0.39.1 code.
version: 0.39.1
verified: 2026-11-17
status: Verified
sources: [backend/veyrs/engines/cvss/common.py, backend/veyrs/engines/cvss/v4.py, backend/veyrs/engines/cvss/v4_tables.py, tests/test_cvss_official.py, tests/fixtures/cvss_official_v4.txt]
related: [architecture/overview.md, architecture/c4.md, ARCHITECTURE.md]
---

# ADR 0002 - Implement CVSS from the published algorithms

**Status:** Accepted · **Date:** 2026-08-10 · **Checked against code:** 0.39.1, in force

## Context

Most tools store a CVSS score they were given. Some approximate the formula.
VEYRS uses CVSS as an *input to risk*, recomputes environmental scores from
tenant context, and shows users a metric breakdown - none of which is possible
with a stored number, and all of which is wrong if the formula is approximate.

## Decision

Implement v2, v3.0, v3.1 and v4.0 as separate modules from FIRST's published
algorithms, and validate against the **complete official vector corpus** from
the reference implementations: 729 v2 + 2,592 v3 + 1,058 v4 = 4,379 vectors.

The v4 MacroVector table (270 equivalence classes) is **converted from FIRST's
published data**, not transcribed by hand.

## Alternatives rejected

- **A third-party library.** Coverage of v4 was immature at build time, and the
  corpus test is the guarantee, not the implementation.
- **Store the NVD score.** Cannot compute environmental scores, cannot explain
  the breakdown, cannot score a vector a scanner produced.
- **Approximate v4.** The spec explicitly forbids it, and rightly: v4 is not a
  formula, it is a lookup with severity-distance interpolation.

## Consequences

- 4,379 assertions run in about 3 seconds and catch any regression instantly.
- **Rounding matters.** Python rounds half-to-even; FIRST specifies half-up. 43
  of 1,058 v4 vectors were wrong by exactly 0.1 until `Decimal` replaced it.
  That single defect is the entire justification for the corpus test.

## Revisit if

FIRST publishes v5, or a library reaches equivalent validated coverage.

## Check against 0.39.1

| Claim | Code | Result |
|---|---|---|
| Separate modules for v2, v3.0/v3.1 and v4.0 | `engines/cvss/v2.py`, `v3.py`, `v4.py`, `common.py` | Holds |
| 729 + 2,592 + 1,058 = 4,379 official vectors | Non-comment line counts of `tests/fixtures/cvss_official_v2.txt`, `_v3.txt`, `_v4.txt` | Holds. The test docstring names the source as the vector corpora of the Red Hat Product Security CVSS reference implementation test suite, described as FIRST-conformant |
| v4 lookup converted from FIRST's data | Lookup in `engines/cvss/v4_tables.py` (`CVSS_LOOKUP`, `MAX_COMPOSED`, `MAX_SEVERITY`) | Present; the conversion script is not in the repository |
| Half-up rounding with `Decimal` | `engines/cvss/common.py:111-115` quantizes with `ROUND_HALF_UP` | Holds |
| Runs in about three seconds | Not measured in this review | Unknown |

Sizes: the three calculators plus tables total six modules under `engines/cvss/`, importing nothing outside the package, which is what allows the corpus test to run without a database.
