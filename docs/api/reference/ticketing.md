---
title: API reference: ticketing
purpose: Every HTTP endpoint tagged `ticketing`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: ticketing

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


26 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `POST` | [`/api/v1/findings/{finding_id}/remediation`](#post-apiv1findingsfinding_idremediation) | Raise the remediation work for a finding | Authenticated | `ticket:write` |
| `GET` | [`/api/v1/notifications`](#get-apiv1notifications) | My in-app notifications | Authenticated | - |
| `GET` | [`/api/v1/notifications/digest`](#get-apiv1notificationsdigest) | The daily digest policy | Authenticated | `notification:read` |
| `PUT` | [`/api/v1/notifications/digest`](#put-apiv1notificationsdigest) | Change the daily digest policy | Authenticated | `notification:admin` |
| `POST` | [`/api/v1/notifications/digest/preview`](#post-apiv1notificationsdigestpreview) | What my digest would say | Authenticated | `finding:read` |
| `POST` | [`/api/v1/notifications/digest/send`](#post-apiv1notificationsdigestsend) | Send the digest now | Authenticated | `notification:admin` |
| `POST` | [`/api/v1/notifications/dispatch`](#post-apiv1notificationsdispatch) | Flush the notification queue | Authenticated | `notification:admin` |
| `GET` | [`/api/v1/notifications/preferences`](#get-apiv1notificationspreferences) | My channel opt-outs | Authenticated | - |
| `PUT` | [`/api/v1/notifications/preferences`](#put-apiv1notificationspreferences) | Mute or unmute one event | Authenticated | - |
| `POST` | [`/api/v1/notifications/{notification_id}/read`](#post-apiv1notificationsnotification_idread) | Mark as read | Authenticated | - |
| `GET` | [`/api/v1/tickets`](#get-apiv1tickets) | List tickets | Authenticated | `ticket:read` |
| `POST` | [`/api/v1/tickets`](#post-apiv1tickets) | Create a ticket | Authenticated | `ticket:write` |
| `GET` | [`/api/v1/tickets-metrics`](#get-apiv1tickets-metrics) | Ticket queue metrics (MTTR, breaches) | Authenticated | `ticket:read` |
| `GET` | [`/api/v1/tickets/automation`](#get-apiv1ticketsautomation) | Automatic ticket creation policy | Authenticated | `ticket:read` |
| `PUT` | [`/api/v1/tickets/automation`](#put-apiv1ticketsautomation) | Change the automatic ticket policy | Authenticated | `ticket:admin` |
| `POST` | [`/api/v1/tickets/automation/backfill`](#post-apiv1ticketsautomationbackfill) | Open tickets for the existing backlog, once | Authenticated | `ticket:admin` |
| `POST` | [`/api/v1/tickets/automation/preview`](#post-apiv1ticketsautomationpreview) | How many tickets this policy would open right now | Authenticated | `ticket:read` |
| `GET` | [`/api/v1/tickets/{ticket_id}`](#get-apiv1ticketsticket_id) | Ticket detail | Authenticated | `ticket:read` |
| `POST` | [`/api/v1/tickets/{ticket_id}/comments`](#post-apiv1ticketsticket_idcomments) | Comment on a ticket | Authenticated | `ticket:write` |
| `POST` | [`/api/v1/tickets/{ticket_id}/transition`](#post-apiv1ticketsticket_idtransition) | Move a ticket through its lifecycle | Authenticated | `ticket:write` |
| `GET` | [`/api/v1/workflows`](#get-apiv1workflows) | List workflows | Authenticated | `workflow:read` |
| `POST` | [`/api/v1/workflows`](#post-apiv1workflows) | Create a workflow | Authenticated | `workflow:write` |
| `GET` | [`/api/v1/workflows/actions`](#get-apiv1workflowsactions) | Available workflow actions | Authenticated | `workflow:read` |
| `GET` | [`/api/v1/workflows/runs`](#get-apiv1workflowsruns) | Workflow run history | Authenticated | `workflow:read` |
| `POST` | [`/api/v1/workflows/seed`](#post-apiv1workflowsseed) | Install the built-in workflow set | Authenticated | `workflow:admin` |
| `PATCH` | [`/api/v1/workflows/{workflow_id}`](#patch-apiv1workflowsworkflow_id) | Update a workflow | Authenticated | `workflow:write` |

## POST /api/v1/findings/{finding_id}/remediation

**Raise the remediation work for a finding**

One route, both modes. THIS is what the console calls.

Before phase 45 the console posted to `/tickets` with a `finding_id`, which hardcoded the internal queue into the front end. Asking the API "arrange for this finding to be fixed" and letting the tenant's own configuration decide where that lands is the difference between a mode and a coat of paint.

The response says which system answered (`kind`), so a caller never has to infer it -- and `created: false` means the work already existed, which is the same idempotence `ticket_for_finding` always had.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/tickets.py:204` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `finding_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/notifications

**My in-app notifications**

Scoped to the caller: there is no "read someone else's inbox" endpoint.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:673` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `unread_only` | query | boolean | no | default `false` |  |
| `page` | query | integer | no | ≥ 1; default `1` |  |
| `size` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/notifications/digest

**The daily digest policy**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `notification:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:834` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PUT /api/v1/notifications/digest

**Change the daily digest policy**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `notification:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:845` |

**Request body** (`application/json`, required): `DigestPolicyWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/notifications/digest/preview

**What my digest would say**

Built by the SAME function that sends it, under the caller's own scope.

A preview assembled separately is a preview that can be right while the message is wrong -- and the operator only finds out by trusting it.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `finding:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:873` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/notifications/digest/send

**Send the digest now**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `notification:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:890` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `dry_run` | query | boolean | no | default `true` | Default TRUE: 'send now' is not a button you press to find out what it does. |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/notifications/dispatch

**Flush the notification queue**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `notification:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:724` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/notifications/preferences

**My channel opt-outs**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:773` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## PUT /api/v1/notifications/preferences

**Mute or unmute one event**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:797` |

**Request body** (`application/json`, required): `PreferenceWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/notifications/{notification_id}/read

**Mark as read**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/tickets.py:710` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `notification_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/tickets

**List tickets**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:249` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `q` | query | string (nullable) | no |  |  |
| `ticket_type` | query | string (nullable) | no |  |  |
| `state` | query | string (nullable) | no |  |  |
| `open_only` | query | boolean | no | default `true` |  |
| `priority` | query | string (nullable) | no |  |  |
| `assigned_team_id` | query | string (uuid) (nullable) | no |  |  |
| `assigned_user_id` | query | string (uuid) (nullable) | no |  |  |
| `finding_id` | query | string (uuid) (nullable) | no |  |  |
| `sla_breached` | query | boolean (nullable) | no |  |  |
| `page` | query | integer | no | ≥ 1; default `1` |  |
| `size` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_TicketOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/tickets

**Create a ticket**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/tickets.py:136` |

**Request body** (`application/json`, required): `TicketCreate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `TicketOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/tickets-metrics

**Ticket queue metrics (MTTR, breaches)**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:535` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/tickets/automation

**Automatic ticket creation policy**

Read-open to anyone who can read tickets.

An operator looking at a queue that grows on its own has to be able to find out why without an administrator; making the answer a privileged secret is how "who opened these?" becomes an afternoon.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:326` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PUT /api/v1/tickets/automation

**Change the automatic ticket policy**

`ticket:admin`, and never a team-scoped grant.

The policy governs the whole estate: a team that could raise the threshold would stop tickets opening for work that is not theirs, and nobody outside that team would see the change. Same refusal SLA policy writes take.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:347` |

**Request body** (`application/json`, required): `AutoTicketPolicyIn`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/tickets/automation/backfill

**Open tickets for the existing backlog, once**

A deliberate one-off catch-up, not a side effect of enabling automation.

It deliberately does NOT require `enabled`: "ticket the backlog now" and "keep ticketing from now on" are different decisions, and coupling them would force anyone who wants the first to live with the second.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:414` |

**Request body** (`application/json`, required): `AutoTicketBackfillIn`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/tickets/automation/preview

**How many tickets this policy would open right now**

Dry-run the policy WITHOUT saving it.

A body lets the console answer "what would happen if I set the threshold to 50?" before anybody commits to it; an empty body previews the policy as stored. Either way it writes nothing.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:391` |

**Request body** (`application/json`, required): `AutoTicketPolicyIn` (nullable)

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/tickets/{ticket_id}

**Ticket detail**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:451` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `ticket_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `TicketDetail` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/tickets/{ticket_id}/comments

**Comment on a ticket**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/tickets.py:518` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `ticket_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `CommentCreate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/tickets/{ticket_id}/transition

**Move a ticket through its lifecycle**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:481` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `ticket_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `TicketTransition`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `TicketOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/workflows

**List workflows**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `workflow:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:555` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `WorkflowOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/workflows

**Create a workflow**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `workflow:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/tickets.py:578` |

**Request body** (`application/json`, required): `WorkflowWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `WorkflowOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/workflows/actions

**Available workflow actions**

The allow-list the visual editor renders. There is no free-form code.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `workflow:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:568` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/workflows/runs

**Workflow run history**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `workflow:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:625` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `definition_id` | query | string (uuid) (nullable) | no |  |  |
| `page` | query | integer | no | ≥ 1; default `1` |  |
| `size` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/workflows/seed

**Install the built-in workflow set**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `workflow:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:658` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/workflows/{workflow_id}

**Update a workflow**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `workflow:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/tickets.py:603` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `workflow_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `WorkflowWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `WorkflowOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## Schemas

Request and response models used on this page.

#### `AutoTicketBackfillIn`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `dry_run` | boolean | no | default `true` |  |
| `limit` | integer | no | ≥ 1.0; ≤ 2000.0; default `200` |  |

#### `AutoTicketPolicyIn`

Every field optional so a client can change one without resetting the rest.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `enabled` | boolean (nullable) | no |  |  |
| `min_risk_score` | number (nullable) | no | ≥ 0.0; ≤ 100.0 |  |
| `severities` | array of string (nullable) | no |  |  |
| `require_kev` | boolean (nullable) | no |  |  |
| `internet_exposed_only` | boolean (nullable) | no |  |  |
| `require_owner` | boolean (nullable) | no |  |  |
| `max_per_run` | integer (nullable) | no | ≥ 1.0; ≤ 500.0 |  |

#### `CommentCreate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `body` | string | yes | min length 1; max length 20000 |  |
| `is_internal` | boolean | no | default `false` |  |

#### `DigestPolicyWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `enabled` | boolean (nullable) | no |  |  |
| `hour` | integer (nullable) | no | ≥ 0.0; ≤ 23.0 |  |
| `window_hours` | integer (nullable) | no | ≥ 1.0; ≤ 168.0 |  |
| `min_severity` | string (nullable) | no |  |  |
| `channels` | array of string (nullable) | no |  |  |
| `include_sla` | boolean (nullable) | no |  |  |
| `include_unassigned` | boolean (nullable) | no |  |  |

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `Page_TicketOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `TicketOut` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `PreferenceWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `event` | string | yes | max length 60 |  |
| `email` | boolean | no | default `true` |  |
| `in_app` | boolean | no | default `true` |  |

#### `TicketCreate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `ticket_type` | string | no | default `"remediation"` |  |
| `title` | string | yes | min length 1; max length 500 |  |
| `description` | string (nullable) | no |  |  |
| `priority` | string | no | default `"medium"` |  |
| `finding_id` | string (uuid) (nullable) | no |  |  |
| `asset_id` | string (uuid) (nullable) | no |  |  |
| `business_service_id` | string (uuid) (nullable) | no |  |  |
| `assigned_team_id` | string (uuid) (nullable) | no |  |  |
| `assigned_user_id` | string (uuid) (nullable) | no |  |  |
| `parent_id` | string (uuid) (nullable) | no |  |  |
| `due_at` | string (date-time) (nullable) | no |  |  |
| `labels` | array of string | no |  |  |
| `change_type` | string (nullable) | no |  |  |
| `implementation_plan` | string (nullable) | no |  |  |
| `rollback_plan` | string (nullable) | no |  |  |
| `scheduled_start` | string (date-time) (nullable) | no |  |  |
| `scheduled_end` | string (date-time) (nullable) | no |  |  |

#### `TicketDetail`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `reference` | string | yes |  |  |
| `ticket_type` | string | yes |  |  |
| `state` | string | yes |  |  |
| `priority` | string | yes |  |  |
| `title` | string | yes |  |  |
| `description` | string (nullable) | yes |  |  |
| `resolution` | string (nullable) | yes |  |  |
| `finding_id` | string (uuid) (nullable) | yes |  |  |
| `vulnerability_id` | string (uuid) (nullable) | yes |  |  |
| `asset_id` | string (uuid) (nullable) | yes |  |  |
| `assigned_team_id` | string (uuid) (nullable) | yes |  |  |
| `assigned_user_id` | string (uuid) (nullable) | yes |  |  |
| `approver_id` | string (uuid) (nullable) | yes |  |  |
| `approved_at` | string (date-time) (nullable) | yes |  |  |
| `change_type` | string (nullable) | yes |  |  |
| `scheduled_start` | string (date-time) (nullable) | yes |  |  |
| `scheduled_end` | string (date-time) (nullable) | yes |  |  |
| `due_at` | string (date-time) (nullable) | yes |  |  |
| `sla_breached` | boolean | yes |  |  |
| `resolved_at` | string (date-time) (nullable) | yes |  |  |
| `closed_at` | string (date-time) (nullable) | yes |  |  |
| `external_system` | string (nullable) | yes |  |  |
| `external_key` | string (nullable) | yes |  |  |
| `labels` | array of string | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |
| `comments` | array of object | no |  |  |
| `events` | array of object | no |  |  |
| `allowed_transitions` | array of string | no |  |  |

#### `TicketOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `reference` | string | yes |  |  |
| `ticket_type` | string | yes |  |  |
| `state` | string | yes |  |  |
| `priority` | string | yes |  |  |
| `title` | string | yes |  |  |
| `description` | string (nullable) | yes |  |  |
| `resolution` | string (nullable) | yes |  |  |
| `finding_id` | string (uuid) (nullable) | yes |  |  |
| `vulnerability_id` | string (uuid) (nullable) | yes |  |  |
| `asset_id` | string (uuid) (nullable) | yes |  |  |
| `assigned_team_id` | string (uuid) (nullable) | yes |  |  |
| `assigned_user_id` | string (uuid) (nullable) | yes |  |  |
| `approver_id` | string (uuid) (nullable) | yes |  |  |
| `approved_at` | string (date-time) (nullable) | yes |  |  |
| `change_type` | string (nullable) | yes |  |  |
| `scheduled_start` | string (date-time) (nullable) | yes |  |  |
| `scheduled_end` | string (date-time) (nullable) | yes |  |  |
| `due_at` | string (date-time) (nullable) | yes |  |  |
| `sla_breached` | boolean | yes |  |  |
| `resolved_at` | string (date-time) (nullable) | yes |  |  |
| `closed_at` | string (date-time) (nullable) | yes |  |  |
| `external_system` | string (nullable) | yes |  |  |
| `external_key` | string (nullable) | yes |  |  |
| `labels` | array of string | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |

#### `TicketTransition`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `state` | string | yes |  |  |
| `note` | string (nullable) | no |  |  |
| `resolution` | string (nullable) | no |  |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |

#### `WorkflowOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `slug` | string | yes | min length 1; max length 80 |  |
| `name` | string | yes | min length 1; max length 200 |  |
| `description` | string (nullable) | no |  |  |
| `is_enabled` | boolean | no | default `true` |  |
| `trigger` | string | yes |  |  |
| `conditions` | object | no |  |  |
| `steps` | array of object | no |  |  |
| `stop_on_error` | boolean | no | default `true` |  |
| `id` | string (uuid) | yes |  |  |
| `run_count` | integer | yes |  |  |
| `last_run_at` | string (date-time) (nullable) | yes |  |  |

#### `WorkflowWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `slug` | string | yes | min length 1; max length 80 |  |
| `name` | string | yes | min length 1; max length 200 |  |
| `description` | string (nullable) | no |  |  |
| `is_enabled` | boolean | no | default `true` |  |
| `trigger` | string | yes |  |  |
| `conditions` | object | no |  |  |
| `steps` | array of object | no |  |  |
| `stop_on_error` | boolean | no | default `true` |  |
