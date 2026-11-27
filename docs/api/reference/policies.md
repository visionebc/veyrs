---
title: API reference: policies
purpose: Every HTTP endpoint tagged `policies`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: policies

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


16 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `GET` | [`/api/v1/policies/assignment`](#get-apiv1policiesassignment) | List assignment rules | Authenticated | `finding:read` |
| `POST` | [`/api/v1/policies/assignment`](#post-apiv1policiesassignment) | Create an assignment rule | Authenticated | `finding:write` |
| `POST` | [`/api/v1/policies/assignment/test`](#post-apiv1policiesassignmenttest) | Dry-run the rule set against a context | Authenticated | `finding:read` |
| `GET` | [`/api/v1/policies/escalation`](#get-apiv1policiesescalation) | List escalation policies | Authenticated | `escalation:read` |
| `POST` | [`/api/v1/policies/escalation`](#post-apiv1policiesescalation) | Create an escalation policy | Authenticated | `escalation:write` |
| `GET` | [`/api/v1/policies/sla`](#get-apiv1policiessla) | List SLA policies | Authenticated | `sla:read` |
| `POST` | [`/api/v1/policies/sla`](#post-apiv1policiessla) | Create an SLA policy | Authenticated | `sla:write` |
| `POST` | [`/api/v1/policies/sla/evaluate`](#post-apiv1policiesslaevaluate) | Run the SLA + escalation sweep now | Authenticated | `sla:write` |
| `GET` | [`/api/v1/policies/sla/events`](#get-apiv1policiesslaevents) | SLA event log | Authenticated | `sla:read` |
| `GET` | [`/api/v1/policies/sla/summary`](#get-apiv1policiesslasummary) | SLA dashboard counters | Authenticated | `sla:read` |
| `DELETE` | [`/api/v1/policies/sla/{policy_id}`](#delete-apiv1policiesslapolicy_id) | Delete an SLA policy | Authenticated | `sla:admin` |
| `PATCH` | [`/api/v1/policies/sla/{policy_id}`](#patch-apiv1policiesslapolicy_id) | Update an SLA policy | Authenticated | `sla:write` |
| `GET` | [`/api/v1/upgrade-path-rules`](#get-apiv1upgrade-path-rules) | List vendor upgrade-path rules | Authenticated | `finding:read` |
| `POST` | [`/api/v1/upgrade-path-rules`](#post-apiv1upgrade-path-rules) | Create an upgrade-path rule | Authenticated | `sla:write` |
| `DELETE` | [`/api/v1/upgrade-path-rules/{rule_id}`](#delete-apiv1upgrade-path-rulesrule_id) | Delete an upgrade-path rule | Authenticated | `sla:write` |
| `PATCH` | [`/api/v1/upgrade-path-rules/{rule_id}`](#patch-apiv1upgrade-path-rulesrule_id) | Update an upgrade-path rule | Authenticated | `sla:write` |

## GET /api/v1/policies/assignment

**List assignment rules**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `finding:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/policies.py:216` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `AssignmentRuleOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/policies/assignment

**Create an assignment rule**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `finding:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/policies.py:230` |

**Request body** (`application/json`, required): `AssignmentRuleWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `AssignmentRuleOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/policies/assignment/test

**Dry-run the rule set against a context**

Explains *why* a rule matched, so operators can debug routing safely.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `finding:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/policies.py:252` |

**Request body** (`application/json`, required): object

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/policies/escalation

**List escalation policies**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `escalation:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/policies.py:169` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `EscalationPolicyOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/policies/escalation

**Create an escalation policy**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `escalation:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/policies.py:183` |

**Request body** (`application/json`, required): `EscalationPolicyWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `EscalationPolicyOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/policies/sla

**List SLA policies**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `sla:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/policies.py:75` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `SlaPolicyOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/policies/sla

**Create an SLA policy**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `sla:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/policies.py:87` |

**Request body** (`application/json`, required): `SlaPolicyWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `SlaPolicyOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/policies/sla/evaluate

**Run the SLA + escalation sweep now**

Sweep the caller's own scope -- deliberately not an arbitrary team.

The sweep writes: it breaches, escalates and notifies. A `?team_id=` here would be a view filter steering a mutation, and "I only meant to look" is the wrong sentence to be able to say about a page-out. Authorization scope is the only thing that narrows it, and the counters returned say so.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `sla:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/policies.py:283` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/policies/sla/events

**SLA event log**

The SLA audit trail, scoped by the finding each event belongs to.

`sla_events` carries no team of its own; it inherits its finding's owner, the same shape as `analytics._scoped_history`. Filtering by a finding outside the scope therefore answers an empty page rather than 404 -- the subquery simply does not contain it, which is the same non-answer the row would get anywhere else.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `sla:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/policies.py:322` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `finding_id` | query | string (uuid) (nullable) | no |  |  |
| `event` | query | string (nullable) | no |  |  |
| `team_id` | query | string (uuid) (nullable) | no |  | Narrow to one owning team |
| `page` | query | integer | no | ≥ 1; default `1` |  |
| `size` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_dict_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/policies/sla/summary

**SLA dashboard counters**

Breach counters, narrowed like every other figure -- and it says which.

Two defects in one route until v0.17.1: a team-restricted identity read the whole estate here, and the console hid the widget under a team filter because the endpoint could not be narrowed. The `scope` block is the same one the dashboards carry, so the console renders one banner from one shape instead of deciding per widget what a number means.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `sla:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/policies.py:301` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `team_id` | query | string (uuid) (nullable) | no |  | Narrow to one owning team |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/policies/sla/{policy_id}

**Delete an SLA policy**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `sla:admin` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/policies.py:148` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `policy_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/policies/sla/{policy_id}

**Update an SLA policy**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `sla:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/policies.py:113` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `policy_id` | path | string (uuid) | yes |  |  |
| `reapply` | query | boolean | no | default `true` | Recompute deadlines on open findings |

**Request body** (`application/json`, required): `SlaPolicyWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `SlaPolicyOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/upgrade-path-rules

**List vendor upgrade-path rules**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `finding:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/fix_plan.py:193` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `vendor` | query | string (nullable) | no |  |  |
| `product` | query | string (nullable) | no |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `UpgradePathRuleOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/upgrade-path-rules

**Create an upgrade-path rule**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `sla:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/fix_plan.py:215` |

**Request body** (`application/json`, required): `UpgradePathRuleWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `UpgradePathRuleOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/upgrade-path-rules/{rule_id}

**Delete an upgrade-path rule**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `sla:write` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/fix_plan.py:267` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `rule_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/upgrade-path-rules/{rule_id}

**Update an upgrade-path rule**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `sla:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/fix_plan.py:238` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `rule_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `UpgradePathRulePatch`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `UpgradePathRuleOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## Schemas

Request and response models used on this page.

#### `AssignmentRuleOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes | min length 1; max length 200 |  |
| `description` | string (nullable) | no |  |  |
| `priority` | integer | no | default `100` |  |
| `is_enabled` | boolean | no | default `true` |  |
| `conditions` | object | no |  |  |
| `team_id` | string (uuid) (nullable) | no |  |  |
| `user_id` | string (uuid) (nullable) | no |  |  |
| `id` | string (uuid) | yes |  |  |
| `match_count` | integer | yes |  |  |
| `last_matched_at` | string (date-time) (nullable) | yes |  |  |

#### `AssignmentRuleWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes | min length 1; max length 200 |  |
| `description` | string (nullable) | no |  |  |
| `priority` | integer | no | default `100` |  |
| `is_enabled` | boolean | no | default `true` |  |
| `conditions` | object | no |  |  |
| `team_id` | string (uuid) (nullable) | no |  |  |
| `user_id` | string (uuid) (nullable) | no |  |  |

#### `EscalationPolicyOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `slug` | string | yes | min length 1; max length 80 |  |
| `name` | string | yes | min length 1; max length 200 |  |
| `description` | string (nullable) | no |  |  |
| `is_enabled` | boolean | no | default `true` |  |
| `is_default` | boolean | no | default `false` |  |
| `levels` | array of object | no |  |  |
| `targets` | object | no |  |  |
| `id` | string (uuid) | yes |  |  |

#### `EscalationPolicyWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `slug` | string | yes | min length 1; max length 80 |  |
| `name` | string | yes | min length 1; max length 200 |  |
| `description` | string (nullable) | no |  |  |
| `is_enabled` | boolean | no | default `true` |  |
| `is_default` | boolean | no | default `false` |  |
| `levels` | array of object | no |  |  |
| `targets` | object | no |  |  |

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `Page_dict_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of object | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `SlaPolicyOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `slug` | string | yes | min length 1; max length 80 |  |
| `name` | string | yes | min length 1; max length 200 |  |
| `description` | string (nullable) | no |  |  |
| `priority` | integer | no | default `100` |  |
| `is_enabled` | boolean | no | default `true` |  |
| `is_default` | boolean | no | default `false` |  |
| `conditions` | object | no |  |  |
| `remediate_within_hours` | integer | yes | ≥ 1.0 |  |
| `triage_within_hours` | integer (nullable) | no | ≥ 1.0 |  |
| `verify_within_hours` | integer (nullable) | no | ≥ 1.0 |  |
| `warn_at_percent` | integer | no | ≥ 1.0; ≤ 100.0; default `75` |  |
| `business_hours_only` | boolean | no | default `false` |  |
| `escalation_policy_id` | string (uuid) (nullable) | no |  |  |
| `id` | string (uuid) | yes |  |  |

#### `SlaPolicyWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `slug` | string | yes | min length 1; max length 80 |  |
| `name` | string | yes | min length 1; max length 200 |  |
| `description` | string (nullable) | no |  |  |
| `priority` | integer | no | default `100` |  |
| `is_enabled` | boolean | no | default `true` |  |
| `is_default` | boolean | no | default `false` |  |
| `conditions` | object | no |  |  |
| `remediate_within_hours` | integer | yes | ≥ 1.0 |  |
| `triage_within_hours` | integer (nullable) | no | ≥ 1.0 |  |
| `verify_within_hours` | integer (nullable) | no | ≥ 1.0 |  |
| `warn_at_percent` | integer | no | ≥ 1.0; ≤ 100.0; default `75` |  |
| `business_hours_only` | boolean | no | default `false` |  |
| `escalation_policy_id` | string (uuid) (nullable) | no |  |  |

#### `UpgradePathRuleOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `vendor` | string | yes | min length 1; max length 200 |  |
| `product` | string | yes | min length 1; max length 300 |  |
| `from_start_including` | string (nullable) | no | max length 120 |  |
| `from_start_excluding` | string (nullable) | no | max length 120 |  |
| `from_end_including` | string (nullable) | no | max length 120 |  |
| `from_end_excluding` | string (nullable) | no | max length 120 |  |
| `via_version` | string (nullable) | no | max length 120 |  |
| `prerequisite` | string (nullable) | no | max length 4000 |  |
| `source_url` | string (nullable) | no | max length 1000 |  |
| `is_enabled` | boolean | no | default `true` |  |
| `id` | string (uuid) | yes |  |  |
| `vendor_key` | string | yes |  |  |
| `product_key` | string | yes |  |  |
| `created_by_id` | string (uuid) (nullable) | no |  |  |
| `created_at` | string (date-time) (nullable) | no |  |  |
| `updated_at` | string (date-time) (nullable) | no |  |  |

#### `UpgradePathRulePatch`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `vendor` | string (nullable) | no | min length 1; max length 200 |  |
| `product` | string (nullable) | no | min length 1; max length 300 |  |
| `from_start_including` | string (nullable) | no | max length 120 |  |
| `from_start_excluding` | string (nullable) | no | max length 120 |  |
| `from_end_including` | string (nullable) | no | max length 120 |  |
| `from_end_excluding` | string (nullable) | no | max length 120 |  |
| `via_version` | string (nullable) | no | max length 120 |  |
| `prerequisite` | string (nullable) | no | max length 4000 |  |
| `source_url` | string (nullable) | no | max length 1000 |  |
| `is_enabled` | boolean (nullable) | no |  |  |

#### `UpgradePathRuleWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `vendor` | string | yes | min length 1; max length 200 |  |
| `product` | string | yes | min length 1; max length 300 |  |
| `from_start_including` | string (nullable) | no | max length 120 |  |
| `from_start_excluding` | string (nullable) | no | max length 120 |  |
| `from_end_including` | string (nullable) | no | max length 120 |  |
| `from_end_excluding` | string (nullable) | no | max length 120 |  |
| `via_version` | string (nullable) | no | max length 120 |  |
| `prerequisite` | string (nullable) | no | max length 4000 |  |
| `source_url` | string (nullable) | no | max length 1000 |  |
| `is_enabled` | boolean | no | default `true` |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |
