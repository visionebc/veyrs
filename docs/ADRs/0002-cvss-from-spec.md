# ADR 0002 - Implement CVSS from the published algorithms

**Status:** Accepted · **Date:** 2026-08-10

## Context

Most tools store a CVSS score they were given. Some approximate the formula.
VEYRS uses CVSS as an *input to risk*, recomputes environmental scores from
tenant context, and shows users a metric breakdown - none of which is possible
with a stored number, and all of which is wrong if the formula is approximate.

## Decision

Implement v2, v3.0, v3.1 and v4.0 as separate modules from FIRST's published
algorithms, and validate against the **complete official vector corpus** from
the reference implementations: 729 v2 + 2,592 v3 + 1,058 v4 = 4,382 vectors.

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

- 4,382 assertions run in about 3 seconds and catch any regression instantly.
- **Rounding matters.** Python rounds half-to-even; FIRST specifies half-up. 43
  of 1,058 v4 vectors were wrong by exactly 0.1 until `Decimal` replaced it.
  That single defect is the entire justification for the corpus test.

## Revisit if

FIRST publishes v5, or a library reaches equivalent validated coverage.
