---
title: Ticketing, automation and workflows
purpose: Document the internal ticket system, external ITSM mode, automatic ticket creation and the workflow engine.
scope: Tickets, ticket automation, ticket metrics and workflows; ITSM connector internals are in integrations.md, notifications in notifications-digest.md.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/api/v1/tickets.py, backend/veyrs/services/ticketing.py, backend/veyrs/services/ticketing_mode.py, backend/veyrs/services/autoticket.py, backend/veyrs/services/workflow.py, backend/veyrs/services/itsm.py]
related: [functional/integrations.md, functional/notifications-digest.md, functional/sla-escalation.md, api/reference/ticketing.md]
---

# Ticketing, automation and workflows

## Tickets

- Types and reference prefixes: INC, PRB, CHG, REQ, REM, EXC (`services/ticketing.py`).
- Each type has its own transition graph. `change` tickets require approval; a requester cannot approve their own change without `ticket:admin` (`api/v1/tickets.py:490`).
- Resolving a remediation (REM) ticket advances its finding to `remediated`.
- **Ticketing mode** (`organizations.settings["ticketing"]`, `services/ticketing_mode.py`): `internal` or `external`. In external mode `POST /tickets` returns 409 and `POST /findings/{id}/remediation` pushes to the configured ITSM connector (502 on `ItsmError`). The mode is switched with `/ticketing` in administration (see [administration-platform.md](administration-platform.md)).

| Feature | Endpoint | Permission | Source | Status |
|---|---|---|---|---|
| Create ticket | `POST /tickets` | `ticket:write` | `tickets.py:136` | Implemented |
| Remediation ticket for a finding | `POST /findings/{finding_id}/remediation` | `ticket:write` | `:204` | Implemented |
| List | `GET /tickets` | `ticket:read` | `:249` | Verified |
| Detail | `GET /tickets/{ticket_id}` | `ticket:read` | `:451` | Implemented |
| Transition | `POST /tickets/{ticket_id}/transition` | `ticket:write` | `:481` | Implemented |
| Comment | `POST /tickets/{ticket_id}/comments` | `ticket:write` | `:518` | Implemented |
| Metrics | `GET /tickets-metrics` | `ticket:read` | `:535` | Verified |

Data: `tickets`, `ticket_comments`, `ticket_counter`, external links (`integration` models). Errors: 404; 409 illegal transition, external mode, or self-approval; 502 connector failure; 422 invalid body.

## Ticket automation

Creates remediation tickets automatically for qualifying findings (`services/autoticket.py`).

| Feature | Endpoint | Permission | Source | Status |
|---|---|---|---|---|
| Read policy | `GET /tickets/automation` | `ticket:read` | `tickets.py:326` | Implemented |
| Update policy | `PUT /tickets/automation` | `ticket:admin` | `:347` | Implemented |
| Preview | `POST /tickets/automation/preview` | `ticket:read` | `:391` | Implemented |
| Backfill | `POST /tickets/automation/backfill` | `ticket:admin` | `:414` | Implemented |

Defaults: off; minimum risk 70; `max_per_run` 50 (ceiling 500) in a 60-minute window; `require_owner` true. A policy with no threshold, severity or KEV requirement is refused (422). Backfill defaults to `dry_run` and is capped at 2,000.

## Workflows

A rule engine: trigger + conditions + ordered steps. Steps have the shape `{"action", "config"}`; there is no free-form code (`services/workflow.py`). Actions: `create_ticket`, `notify`, `transition_finding`, `tag_asset`, `set_priority`, `comment`. Four built-in workflows are installed by `POST /workflows/seed`.

| Feature | Endpoint | Permission | Source | Status |
|---|---|---|---|---|
| List | `GET /workflows` | `workflow:read` | `tickets.py:555` | Verified |
| Action catalogue | `GET /workflows/actions` | `workflow:read` | `:568` | Implemented |
| Create | `POST /workflows` | `workflow:write` | `:578` | Implemented |
| Update | `PATCH /workflows/{workflow_id}` | `workflow:write` | `:603` | Implemented |
| Run history | `GET /workflows/runs` | `workflow:read` | `:625` | Verified |
| Seed built-ins | `POST /workflows/seed` | `workflow:admin` | `:658` | Implemented |

Live: 8,288 workflow runs on environment A.

Known defects:

- Emitters exist only for `finding.created` (`services/correlation.py:606`), `sla.warned`/`sla.breached`/`sla.escalated` (`services/sla.py:470`) and `ticket.created` (`api/v1/tickets.py:198,509`). `finding.state_changed`, `finding.risk_changed`, `intel.kev_added`, `manual` and `schedule` have no emitter, and `ticket.created` is missing from `TriggerType`/`TRIGGER_HELP`; `WorkflowWrite.trigger` is not validated.
- The `transition_finding` action schema offers `pending_verification` and `risk_accepted` (`services/workflow.py:366-367`) while the real states are `verification` and `accepted_risk`; such steps fail at run time.
