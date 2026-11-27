---
title: Permissions and built-in roles
purpose: The RBAC vocabulary and what each built-in role grants, generated from the code.
scope: Permission strings, wildcard expansion and the role matrix. Team scope (row filtering) is in the security docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/security/permissions.py]
related: [SECURITY.md, api/reference/README.md]
---

# Permissions and built-in roles

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


A permission is `<resource>:<action>`. **30 resources** × **4 actions** = 120 permissions, plus the wildcard `*:*`. Routes declare what they need with `require("resource:action")`; an unknown string raises at import time (`backend/veyrs/security/deps.py`).

## Resources

| Resource | Permissions |
|---|---|
| `organization` | `organization:read`, `organization:write`, `organization:delete`, `organization:admin` |
| `user` | `user:read`, `user:write`, `user:delete`, `user:admin` |
| `team` | `team:read`, `team:write`, `team:delete`, `team:admin` |
| `role` | `role:read`, `role:write`, `role:delete`, `role:admin` |
| `apikey` | `apikey:read`, `apikey:write`, `apikey:delete`, `apikey:admin` |
| `audit` | `audit:read`, `audit:write`, `audit:delete`, `audit:admin` |
| `asset` | `asset:read`, `asset:write`, `asset:delete`, `asset:admin` |
| `product` | `product:read`, `product:write`, `product:delete`, `product:admin` |
| `vulnerability` | `vulnerability:read`, `vulnerability:write`, `vulnerability:delete`, `vulnerability:admin` |
| `finding` | `finding:read`, `finding:write`, `finding:delete`, `finding:admin` |
| `cve` | `cve:read`, `cve:write`, `cve:delete`, `cve:admin` |
| `risk` | `risk:read`, `risk:write`, `risk:delete`, `risk:admin` |
| `riskprofile` | `riskprofile:read`, `riskprofile:write`, `riskprofile:delete`, `riskprofile:admin` |
| `riskregister` | `riskregister:read`, `riskregister:write`, `riskregister:delete`, `riskregister:admin` |
| `ticket` | `ticket:read`, `ticket:write`, `ticket:delete`, `ticket:admin` |
| `sla` | `sla:read`, `sla:write`, `sla:delete`, `sla:admin` |
| `escalation` | `escalation:read`, `escalation:write`, `escalation:delete`, `escalation:admin` |
| `workflow` | `workflow:read`, `workflow:write`, `workflow:delete`, `workflow:admin` |
| `intel` | `intel:read`, `intel:write`, `intel:delete`, `intel:admin` |
| `document` | `document:read`, `document:write`, `document:delete`, `document:admin` |
| `knowledge` | `knowledge:read`, `knowledge:write`, `knowledge:delete`, `knowledge:admin` |
| `compliance` | `compliance:read`, `compliance:write`, `compliance:delete`, `compliance:admin` |
| `evidence` | `evidence:read`, `evidence:write`, `evidence:delete`, `evidence:admin` |
| `report` | `report:read`, `report:write`, `report:delete`, `report:admin` |
| `importer` | `importer:read`, `importer:write`, `importer:delete`, `importer:admin` |
| `notification` | `notification:read`, `notification:write`, `notification:delete`, `notification:admin` |
| `ai` | `ai:read`, `ai:write`, `ai:delete`, `ai:admin` |
| `settings` | `settings:read`, `settings:write`, `settings:delete`, `settings:admin` |
| `agent` | `agent:read`, `agent:write`, `agent:delete`, `agent:admin` |
| `platform` | `platform:read`, `platform:write`, `platform:delete`, `platform:admin` |

## Built-in roles

| Slug | Name | Description | Grants |
|---|---|---|---|
| `org-admin` | Organization Administrator | Full control inside one organization, including RBAC and settings. | all |
| `platform-admin` | Platform Administrator | The installation-wide pages: software update, installed software, network access, trust store, web certificate. Effective only in the organization VEYRS was installed for. | 1 |
| `security-manager` | Security Manager | Owns risk posture: triage, risk profiles, SLA policy, escalation. | 39 |
| `security-engineer` | Security Engineer | Day-to-day triage and remediation work on findings and tickets. | 23 |
| `team-lead` | Team Lead | Accountable for their team's queue and SLA compliance. | 14 |
| `asset-owner` | Asset Owner | Business owner of assets; accepts risk and confirms remediation. | 11 |
| `compliance-officer` | Compliance Officer | Control mapping, evidence collection and audit readiness. | 19 |
| `executive` | Executive / CISO | Read-only executive view plus formal risk acceptance. | 15 |
| `auditor` | Auditor | Immutable read across evidence and audit trail. No writes at all. | 12 |
| `service-account` | Service Account | Machine identity for importers and ITSM webhooks. | 10 |
| `read-only` | Read Only | Baseline visibility with no mutation rights. | 10 |

## Role × permission matrix

`✓` = granted (after wildcard expansion). Columns are the built-in role slugs.

| Permission | `org-admin` | `platform-admin` | `security-manager` | `security-engineer` | `team-lead` | `asset-owner` | `compliance-officer` | `executive` | `auditor` | `service-account` | `read-only` |
|---|---|---|---|---|---|---|---|---|---|---|---|
| `agent:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `agent:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `agent:read` | ✓ |  | ✓ | ✓ |  |  |  |  |  |  |  |
| `agent:write` | ✓ |  | ✓ | ✓ |  |  |  |  |  |  |  |
| `ai:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `ai:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `ai:read` | ✓ |  | ✓ | ✓ |  |  |  |  |  |  |  |
| `ai:write` | ✓ |  | ✓ |  |  |  |  |  |  |  |  |
| `apikey:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `apikey:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `apikey:read` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `apikey:write` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `asset:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `asset:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `asset:read` | ✓ |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `asset:write` | ✓ |  | ✓ | ✓ |  | ✓ |  |  |  | ✓ |  |
| `audit:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `audit:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `audit:read` | ✓ |  | ✓ |  |  |  | ✓ | ✓ | ✓ |  |  |
| `audit:write` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `compliance:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `compliance:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `compliance:read` | ✓ |  | ✓ | ✓ |  |  | ✓ | ✓ | ✓ |  | ✓ |
| `compliance:write` | ✓ |  |  |  |  |  | ✓ |  |  |  |  |
| `cve:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `cve:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `cve:read` | ✓ |  | ✓ | ✓ | ✓ | ✓ |  |  |  | ✓ | ✓ |
| `cve:write` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `document:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `document:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `document:read` | ✓ |  |  | ✓ |  |  | ✓ |  |  |  |  |
| `document:write` | ✓ |  |  | ✓ |  |  | ✓ |  |  |  |  |
| `escalation:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `escalation:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `escalation:read` | ✓ |  | ✓ |  | ✓ |  |  |  |  |  |  |
| `escalation:write` | ✓ |  | ✓ |  |  |  |  |  |  |  |  |
| `evidence:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `evidence:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `evidence:read` | ✓ |  | ✓ |  |  |  | ✓ |  | ✓ |  |  |
| `evidence:write` | ✓ |  |  |  |  |  | ✓ |  |  |  |  |
| `finding:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `finding:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `finding:read` | ✓ |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `finding:write` | ✓ |  | ✓ | ✓ | ✓ |  |  |  |  | ✓ |  |
| `importer:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `importer:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `importer:read` | ✓ |  | ✓ |  |  |  |  |  |  | ✓ |  |
| `importer:write` | ✓ |  | ✓ |  |  |  |  |  |  | ✓ |  |
| `intel:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `intel:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `intel:read` | ✓ |  | ✓ | ✓ |  |  |  | ✓ |  |  |  |
| `intel:write` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `knowledge:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `knowledge:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `knowledge:read` | ✓ |  |  | ✓ |  |  | ✓ |  |  |  |  |
| `knowledge:write` | ✓ |  |  |  |  |  | ✓ |  |  |  |  |
| `notification:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `notification:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `notification:read` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `notification:write` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `organization:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `organization:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `organization:read` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `organization:write` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `platform:admin` | ✓ | ✓ |  |  |  |  |  |  |  |  |  |
| `platform:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `platform:read` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `platform:write` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `product:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `product:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `product:read` | ✓ |  | ✓ | ✓ | ✓ |  |  | ✓ |  | ✓ | ✓ |
| `product:write` | ✓ |  | ✓ |  |  |  |  |  |  |  |  |
| `report:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `report:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `report:read` | ✓ |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  | ✓ |
| `report:write` | ✓ |  | ✓ |  |  |  | ✓ |  |  |  |  |
| `risk:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `risk:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `risk:read` | ✓ |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  | ✓ |
| `risk:write` | ✓ |  | ✓ |  |  |  |  | ✓ |  |  |  |
| `riskprofile:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `riskprofile:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `riskprofile:read` | ✓ |  | ✓ |  |  |  |  | ✓ |  |  |  |
| `riskprofile:write` | ✓ |  | ✓ |  |  |  |  |  |  |  |  |
| `riskregister:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `riskregister:delete` | ✓ |  | ✓ |  |  |  |  |  |  |  |  |
| `riskregister:read` | ✓ |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |  | ✓ |
| `riskregister:write` | ✓ |  | ✓ |  |  |  | ✓ | ✓ |  |  |  |
| `role:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `role:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `role:read` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `role:write` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `settings:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `settings:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `settings:read` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `settings:write` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `sla:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `sla:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `sla:read` | ✓ |  | ✓ | ✓ | ✓ |  | ✓ | ✓ | ✓ |  |  |
| `sla:write` | ✓ |  | ✓ |  |  |  |  |  |  |  |  |
| `team:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `team:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `team:read` | ✓ |  | ✓ | ✓ | ✓ | ✓ |  |  |  |  |  |
| `team:write` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `ticket:admin` | ✓ |  | ✓ |  |  |  |  |  |  |  |  |
| `ticket:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `ticket:read` | ✓ |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `ticket:write` | ✓ |  | ✓ | ✓ | ✓ | ✓ |  |  |  |  |  |
| `user:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `user:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `user:read` | ✓ |  | ✓ |  |  |  |  |  |  |  |  |
| `user:write` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `vulnerability:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `vulnerability:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `vulnerability:read` | ✓ |  | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ | ✓ |
| `vulnerability:write` | ✓ |  | ✓ | ✓ |  |  |  |  |  |  |  |
| `workflow:admin` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `workflow:delete` | ✓ |  |  |  |  |  |  |  |  |  |  |
| `workflow:read` | ✓ |  | ✓ |  |  |  |  |  | ✓ |  |  |
| `workflow:write` | ✓ |  | ✓ |  |  |  |  |  |  |  |  |
