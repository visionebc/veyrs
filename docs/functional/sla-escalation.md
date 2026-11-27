---
title: SLA, escalation and assignment policies
purpose: Document how remediation deadlines, warnings, escalation levels and automatic assignment are defined and evaluated.
scope: The `/policies/*` API and `services/sla.py`; ticketing and notifications are in their own documents.
version: 0.41.0
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/api/v1/policies.py, backend/veyrs/services/sla.py, backend/veyrs/services/tenant_defaults.py, backend/veyrs/models/sla.py, scripts/sync-intel.sh]
related: [functional/vulnerability-management.md, functional/notifications-digest.md, functional/remediation-fix-plans.md, api/reference/policies.md]
---

# SLA, escalation and assignment policies

## How SLA works

- The clock starts at detection. The first enabled policy, ordered by `priority`, whose conditions match wins; otherwise the default policy, or the loosest (`services/sla.py`).
- Built-in policies: 4 h for KEV on an internet-facing asset, then 24 h, 7 d, 30 d, 90 d, 90 d.
- Business-hours mode counts Mon-Fri 09:00-17:00 UTC.
- A warning fires at `warn_at_percent` (default 75).
- **The deadline is counted from detection; escalation is counted from the deadline.** Escalation levels are absolute offsets from `sla_due_at` (defaults 4, 8, 24, 48 h *after the deadline*): level 0 until the deadline passes, level N once the `after_hours` of N have elapsed past it. Before 0.41.0 they were counted from detection, so every finding with a ladder reached level 4 within 48 h of being seen, whatever its deadline. A finding is never escalated while it is on time.
- Each level's `notify` target is resolved to people and notified when the level is first reached (see "Who is notified"). The finding's assigned user is notified by the built-in `escalation-notify` workflow, not twice.
- A tenant gets the built-in SLA policies, the `standard` ladder and the risk profiles when its organization is created by `bootstrap`; for an existing tenant run `veyrs seed-defaults --org <slug> --apply` (adds only what is missing, never edits a row).
- `PATCH /policies/sla/{id}` re-applies deadlines to all open findings unless `reapply=false`.
- The periodic sweep is the CLI command `veyrs run-sla`, called on every hourly tick from `scripts/sync-intel.sh`; it is also reachable via `POST /policies/sla/evaluate`.
- Policy writes are refused for team-scoped principals.
- `triage_within_hours` and `verify_within_hours` are stored and validated but read by no code; only `remediate_within_hours` drives deadlines.

## Who is notified at each escalation level

`notify` on a ladder level is a target name (or a list of names). They resolve from the existing models:

| Target | People |
|---|---|
| `team` | Active members of the finding's assigned team |
| `team_manager` | `Team.manager_id` of the assigned team |
| `security_manager` | Users holding the `security-manager` role |
| `ciso` | Users holding a role with slug `ciso` (define it as a custom role; there is no built-in one) |
| `org_admin` | Users holding `org-admin` |
| `asset_owner`, `assignee` | The asset's owner; the finding's assigned user and team |
| `role:<slug>`, `team:<slug>`, `user:<email>`, a bare e-mail | That role's holders, that team's members, that person or address |

Role grants count only when organization-wide (a grant narrowed to one team does not make someone *the* security manager). `EscalationPolicy.targets` overrides a name with an explicit list of user ids or e-mails (`{"ciso": ["ciso@example.com"]}`).

A target that resolves to nobody falls back to the organization's `org-admin` users and the `escalated` SLA event records `fallback: true` and the unresolved names, so a routing hole is visible in the event log and the service log. Notices are `sla.escalated` notifications (in-app and e-mail, never mutable) through the normal pipeline; the hourly tick dispatches the e-mail.

## Upgrading to 0.41.0: the one-off recompute

The sweep only moves levels up, so findings stored at level 4 under the old rule would never notify at their real breach. After deploying, run once per installation:

```
veyrs recompute-escalation            # dry run: how many levels would change
veyrs recompute-escalation --apply    # set every open finding to the level its deadline gives, silently
```

It writes one `escalation_recomputed` SLA event per finding that moved, sends nothing, and fires no workflow (`--notify` additionally sends the level notice for findings left above level 0). Without it nothing is wrongly notified either: the new rule never gives a higher level than the old one, and the sweep ignores a stored level that is higher than the computed one.

## Endpoints

| Feature | Endpoint | Permission | Source | Status |
|---|---|---|---|---|
| List SLA policies | `GET /policies/sla` | `sla:read` | `policies.py:75` | Verified |
| Create | `POST /policies/sla` | `sla:write` | `:87` | Implemented |
| Update (re-apply) | `PATCH /policies/sla/{policy_id}` | `sla:write` | `:113` | Implemented |
| Delete | `DELETE /policies/sla/{policy_id}` | `sla:admin` | `:148` | Implemented |
| Evaluate now | `POST /policies/sla/evaluate` | `sla:write` | `:283` | Implemented |
| Summary | `GET /policies/sla/summary` | `sla:read` | `:301` | Verified |
| Events | `GET /policies/sla/events` | `sla:read` | `:322` | Verified |
| List escalation policies | `GET /policies/escalation` | `escalation:read` | `:169` | Verified |
| Create escalation policy | `POST /policies/escalation` | `escalation:write` | `:183` | Implemented |
| List assignment rules | `GET /policies/assignment` | `finding:read` | `:216` | Verified |
| Create assignment rule | `POST /policies/assignment` | `finding:write` | `:230` | Implemented |
| Test assignment | `POST /policies/assignment/test` | `finding:read` | `:252` | Implemented |

Upgrade-path rules (`/upgrade-path-rules`) are in [remediation-fix-plans.md](remediation-fix-plans.md).

Data: SLA, escalation and assignment policy tables, SLA events, and `findings` (`sla_due_at`, `sla_breached`, `escalation_level`). Errors: 404 unknown policy; 403 team-scoped principal or missing permission; 422 invalid conditions or thresholds.

## Observed live and debt

On environment A before 0.41.0, 1,529 of 1,972 open findings were SLA-breached and all were at escalation level 4 (the detection-based clock and no resolved recipients). `recompute-escalation` corrects the stored levels. Escalation and assignment rules have create and list routes only (no update or delete). Workflow triggers `sla.warned`, `sla.breached`, `sla.escalated` are emitted from `services/sla.py:470`.
