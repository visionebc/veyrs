---
title: Documentation coverage index
purpose: Measures how much of the system the hand-written documentation covers.
scope: Routes, tags, tables, settings, modules, CLI commands, units and front matter. Each figure states how it was counted.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py]
related: [reference/traceability.md, audit/README.md]
---

# Documentation coverage index

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.
> Documentation-derived: rewritten by every run, not byte-checked by tests.


> [!IMPORTANT]
> The generated references (API, configuration, permissions, schema, inventory) cover 100% of their items **by construction** - they are produced from the code. The percentages below measure the **hand-written** documents only, by text search: a mention is counted, its quality is not. Read them as "where is nothing written", not as a quality score.

| Domain | Measure | Covered | Total | Coverage |
|---|---|---|---|---|
| API | Paths mentioned verbatim in hand-written docs | 277 | 282 | 98% |
| API | Tags named in functional docs / manuals | 19 | 19 | 100% |
| API | Operations in the generated reference | 350 | 350 | 100% (generated) |
| Database | Tables drawn in `database/er-diagrams.md` | 90 | 93 | 97% |
| Database | Tables named anywhere in hand-written docs | 91 | 93 | 98% |
| Database | Tables in the generated schema reference | 93 | 93 | 100% (generated) |
| Configuration | `VEYRS_*` settings named in hand-written docs | 74 | 74 | 100% |
| Backend | Modules mentioned by path or dotted name | 150 | 162 | 93% |
| Backend | Modules referenced by a test file | 119 | 162 | 73% |
| Operations | CLI commands named in hand-written docs | 32 | 32 | 100% |
| Operations | Shipped systemd units named in hand-written docs | 17 | 17 | 100% |
| Quality | Hand-written docs with complete front matter | 106 | 106 | 100% |

## Gaps

- **Tables never named in hand-written docs** (2): `installation_settings`, `web_certificates`
