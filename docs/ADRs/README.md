---
title: Architecture decision records
purpose: Index the decisions that shaped VEYRS and say which are still fully in force.
scope: The nine ADRs and their status against the code (0.39.1; ADR 0009 against 0.41.0); the decisions themselves are in each file.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [docs/ADRs/0001-postgres-rls.md, docs/ADRs/0002-cvss-from-spec.md, docs/ADRs/0003-ai-gateway.md, docs/ADRs/0004-closed-query-grammar.md, docs/ADRs/0005-partial-catalogues.md, docs/ADRs/0006-no-autoclose-on-absence.md, docs/ADRs/0007-stateless-app-nodes.md, docs/ADRs/0008-state-off-host-and-proven-backups.md, docs/ADRs/0009-closure-per-covered-asset.md]
related: [architecture/overview.md, ARCHITECTURE.md]
---

# Architecture Decision Records

Each ADR records a decision that was not obvious, the alternatives that were
rejected, and what would make us revisit it. Every ADR ends with a "Check
against <version>" section that compares its claims with the code: 0.39.1 for 0001 to 0008, 0.41.0 for 0009. The 0.39.1 checks were made on the 0.39.0 backend; the 0.39.1 release changed only the version string in `backend/veyrs/config.py`, console files, `scripts/public-export.sh` and the mode of `install.sh`, so no ADR verdict changed.

| # | Decision | State |
|---|---|---|
| [0001](0001-postgres-rls.md) | PostgreSQL RLS as a second tenant barrier | In force. Four credential-keyed tables, not three; one inaccurate docstring in `db.py` |
| [0002](0002-cvss-from-spec.md) | Implement CVSS from the published algorithms | In force |
| [0003](0003-ai-gateway.md) | One gateway, no provider access anywhere else | In force |
| [0004](0004-closed-query-grammar.md) | AI emits validated JSON, never SQL | In force |
| [0005](0005-partial-catalogues.md) | Ship compliance catalogues partial and say so | In force |
| [0006](0006-no-autoclose-on-absence.md) | Never close a finding because a scan omitted it | Principle in force; mechanism **superseded by ADR 0009** |
| [0007](0007-stateless-app-nodes.md) | Split the state out; make the app nodes disposable | In force; routing is primary/backup rather than active/active |
| [0008](0008-state-off-host-and-proven-backups.md) | Keep the state off the app host; prove every backup by restoring it | Decision in force; the standby is not currently on a separate physical host |
| [0009](0009-closure-per-covered-asset.md) | Close by absence only on what the run covered | In force since 0.41.0; supersedes the mechanism of 0006 |

Hostnames in ADRs 0007 and 0008 were generalised (app node A and B, database
node, hypervisor H1 and H2); the concrete names of the reference installation
are in the internal documentation.
