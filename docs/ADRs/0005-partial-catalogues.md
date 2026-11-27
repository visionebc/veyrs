---
title: ADR 0005: Ship compliance catalogues partial, and say so everywhere
purpose: Record why built-in compliance catalogues carry identifiers only and how partial coverage is made impossible to hide.
scope: The partial-catalogue decision, checked against the 0.39.1 code.
version: 0.39.1
verified: 2026-11-17
status: Verified
sources: [backend/veyrs/models/compliance.py, backend/veyrs/services/compliance.py, backend/veyrs/data/frameworks.py]
related: [architecture/overview.md, reference/glossary.md]
---

# ADR 0005 - Ship compliance catalogues partial, and say so everywhere

**Status:** Accepted · **Date:** 2026-08-10 · **Checked against code:** 0.39.1, in force

## Context

The spec says: *"Never invent regulatory requirements. Use authoritative
sources."*

ISO/IEC 27001 and 27002 are copyrighted; their text cannot be redistributed. CIS
Controls are CC BY-NC-SA. NIST CSF is a US Government work and is free. So a
complete, legal, built-in catalogue is impossible for the standards customers ask
for most.

Three options: ship nothing for ISO; ship a plausible-looking reconstruction; or
ship the identifiers and be explicit about what is missing.

## Decision

Ship control **identifiers and short titles only** - the minimum needed to map to
a control - with mandatory `source_url`, `licence_note` and
`official_control_count`. Mark the framework `is_partial` and surface that flag,
plus a written disclaimer, in every coverage report and every frozen assessment
snapshot.

`is_partial` is **derived** from imported count versus official count. It cannot
be turned off by configuration. Licensed customers import their own copy via CSV,
and the flag clears itself.

VEYRS commentary lives in a column named `veyrs_guidance`, never in
`normative_text`. Crosswalks are labelled editorial and are not endorsed by the
publishers.

## Alternatives rejected

- **Reconstruct the text.** Copyright infringement, and inventing a requirement
  is worse than omitting it.
- **Ship nothing for ISO.** The identifiers are exactly what mapping needs.
- **Let an administrator set `is_partial = false`.** Someone would, and then
  export a "92% compliant" figure from a 24-of-93 catalogue into an audit pack.

## Consequences

- A customer cannot accidentally present partial coverage as full conformance.
- Full catalogues require a licensed import - correct, and a one-command
  operation.

## Revisit if

A publisher grants redistribution rights.

## Check against 0.39.1

| Claim | Code | Result |
|---|---|---|
| Identifiers and short titles only | `data/frameworks.py` defines four built-ins: NIST CSF 2.0, CIS Controls v8, ISO 27001:2022, ISO 27002:2022 (`BUILTIN_FRAMEWORKS`) | Holds |
| `source_url`, `licence_note`, `official_control_count` mandatory | The columns are nullable in the schema (`models/compliance.py:82-90`); the built-in catalogues populate them | Convention, not a database constraint |
| `is_partial` derived from imported versus official count, not configurable | `is_partial` defaults to true; `services/compliance.py:112-171` (`import_controls_csv`) clears it only when the import reaches the official count | Holds |
| Disclaimer in coverage reports and frozen snapshots | `ComplianceFramework.coverage_disclaimer` (`models/compliance.py:101-111`) | Holds |
| Automated signals cannot reach `implemented` | `services/compliance.py` module docstring and `AUTOMATED_SIGNALS` (12 signals) | Holds |
