---
title: Remediation, verification and fix plans
purpose: Explain how VEYRS computes fixed versions and upgrade paths, how remediation is tracked and what "verified" means.
scope: Fix plans, upgrade-path rules and the remediation/verification states; tickets are in ticketing-itsm.md.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/api/v1/fix_plan.py, backend/veyrs/services/fix_plan.py, backend/veyrs/models/upgrade.py, backend/veyrs/services/remediation.py, backend/veyrs/services/engagements.py]
related: [functional/vulnerability-management.md, functional/ticketing-itsm.md, functional/ai.md, api/reference/policies.md]
---

# Remediation, verification and fix plans

## Fix plan

A deterministic computation (no LLM) of the version a product must reach to clear a finding, from CPE version ranges, advisory fixed versions and operator `UpgradePathRule`s (model `backend/veyrs/models/upgrade.py`, table `upgrade_path_rules`; computation `services/fix_plan.py`). It never claims "fixed" on missing data: the status is `no_fix_known` and the plan states "N of M open findings have a known fixed version". Paths are capped at 16 hops with a cycle guard; each step is classified `patch`, `minor`, `major` or `unknown`.

| Feature | Endpoint | Permission | Source | Status |
|---|---|---|---|---|
| Plan for a finding | `GET /findings/{finding_id}/fix-plan` | `finding:read` | `fix_plan.py:51` | Verified |
| Plan for an asset | `GET /assets/{asset_id}/fix-plan` | `asset:read`, `finding:read` | `:62` | Implemented |
| List rules | `GET /upgrade-path-rules` | `finding:read` | `:193` | Implemented |
| Create rule | `POST /upgrade-path-rules` | `sla:write` | `:215` | Implemented |
| Update rule | `PATCH /upgrade-path-rules/{rule_id}` | `sla:write` | `:238` | Implemented |
| Delete rule | `DELETE /upgrade-path-rules/{rule_id}` | `sla:write` | `:267` | Implemented |

Rule writes also require an estate-wide scope (team-scoped principals are refused). Validation 422s include "from range is empty" and "via_version must be newer". Data: `upgrade_path_rules`, `findings`, `vulnerabilities`, installed products. Tests: `test_phase49_fix_plan` (28 tests, name only). A live `GET /findings/{id}/fix-plan` returned 200 with `fix_status: after`.

## Remediation and verification

There is no dedicated verification endpoint. Verification is the state sequence `remediated`, `verification`, `verified`, `closed` driven through `POST /findings/{id}/transition` (see [vulnerability-management.md](vulnerability-management.md)), plus absence-based closure on re-import (`services/engagements.py`), which is explicitly *not* a verified fix. Remediation tickets (`POST /findings/{id}/remediation`) are described in [ticketing-itsm.md](ticketing-itsm.md); AI-drafted remediation text is `POST /ai/findings/{id}/remediation` in [ai.md](ai.md). Status: Partial (no verification workflow beyond states).
