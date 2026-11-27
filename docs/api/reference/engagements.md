---
title: API reference: engagements
purpose: Every HTTP endpoint tagged `engagements`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: engagements

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


15 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `GET` | [`/api/v1/engagements`](#get-apiv1engagements) | List Engagements | Authenticated | `importer:read` |
| `POST` | [`/api/v1/engagements`](#post-apiv1engagements) | Create Engagement | Authenticated | `importer:write` |
| `GET` | [`/api/v1/engagements/dedupe-registry`](#get-apiv1engagementsdedupe-registry) | Dedupe Registry | Authenticated | `importer:read` |
| `GET` | [`/api/v1/engagements/endpoints/search`](#get-apiv1engagementsendpointssearch) | Search Endpoints | Authenticated | `asset:read` |
| `GET` | [`/api/v1/engagements/findings/{finding_id}/endpoints`](#get-apiv1engagementsfindingsfinding_idendpoints) | Finding Endpoints | Authenticated | `finding:read` |
| `POST` | [`/api/v1/engagements/findings/{finding_id}/endpoints/mitigate`](#post-apiv1engagementsfindingsfinding_idendpointsmitigate) | Mitigate Endpoints | Authenticated | `asset:write` |
| `POST` | [`/api/v1/engagements/risk-acceptances`](#post-apiv1engagementsrisk-acceptances) | Request Acceptance | Authenticated | `risk:write` |
| `POST` | [`/api/v1/engagements/risk-acceptances/expire`](#post-apiv1engagementsrisk-acceptancesexpire) | Run Expiry | Authenticated | `risk:write` |
| `GET` | [`/api/v1/engagements/risk-acceptances/list`](#get-apiv1engagementsrisk-acceptanceslist) | List Acceptances | Authenticated | `risk:read` |
| `POST` | [`/api/v1/engagements/risk-acceptances/{acceptance_id}/approve`](#post-apiv1engagementsrisk-acceptancesacceptance_idapprove) | Approve Acceptance | Authenticated | `risk:write` |
| `POST` | [`/api/v1/engagements/risk-acceptances/{acceptance_id}/reject`](#post-apiv1engagementsrisk-acceptancesacceptance_idreject) | Reject Acceptance | Authenticated | `risk:write` |
| `POST` | [`/api/v1/engagements/risk-acceptances/{acceptance_id}/revoke`](#post-apiv1engagementsrisk-acceptancesacceptance_idrevoke) | Revoke Acceptance | Authenticated | `risk:write` |
| `GET` | [`/api/v1/engagements/tests/{test_id}`](#get-apiv1engagementsteststest_id) | Read Test | Authenticated | `importer:read` |
| `GET` | [`/api/v1/engagements/{engagement_id}`](#get-apiv1engagementsengagement_id) | Read Engagement | Authenticated | `importer:read` |
| `GET` | [`/api/v1/engagements/{engagement_id}/tests`](#get-apiv1engagementsengagement_idtests) | List Tests | Authenticated | `importer:read` |

## GET /api/v1/engagements

**List Engagements**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/engagements.py:190` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `status` | query | string (nullable) | no |  |  |
| `engagement_type` | query | string (nullable) | no |  |  |
| `limit` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_EngagementOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/engagements

**Create Engagement**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/engagements.py:216` |

**Request body** (`application/json`, required): `EngagementWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `EngagementOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/engagements/dedupe-registry

**Dedupe Registry**

Which deduplication rule each scanner uses, and what the words mean.

Surfaced because a silent identity change is indistinguishable from a scanner behaving differently: when finding counts move, this is the first thing to check.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/engagements.py:237` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/engagements/endpoints/search

**Search Endpoints**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/engagements.py:326` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `host` | query | string (nullable) | no |  |  |
| `asset_id` | query | string (uuid) (nullable) | no |  |  |
| `limit` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_EndpointOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/engagements/findings/{finding_id}/endpoints

**Finding Endpoints**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `finding:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/engagements.py:352` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `finding_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/engagements/findings/{finding_id}/endpoints/mitigate

**Mitigate Endpoints**

Mark endpoints of a finding fixed.

Deliberately does NOT close the finding even when every endpoint is mitigated: closure is a lifecycle transition with its own verification step, and letting a bulk endpoint update slip a finding past verification would be a hole in the state machine.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/engagements.py:384` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `finding_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `MitigateEndpoints`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/engagements/risk-acceptances

**Request Acceptance**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `risk:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/engagements.py:457` |

**Request body** (`application/json`, required): `RiskAcceptanceWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `RiskAcceptanceOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/engagements/risk-acceptances/expire

**Run Expiry**

Expire what is due and warn about what is nearly due.

An endpoint so an operator can run the control on demand and prove it works. Whether a scheduled job also calls `engagements.expire_due` is the scheduler's business, not this route's (0.39.1 had none: TD-17), so this docstring no longer claims one. Idempotent: a second call in the same day expires nothing further.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `risk:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/engagements.py:546` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `warn_days` | query | integer | no | ≥ 0; ≤ 365; default `14` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/engagements/risk-acceptances/list

**List Acceptances**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `risk:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/engagements.py:426` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `state` | query | string (nullable) | no |  |  |
| `expiring_within_days` | query | integer (nullable) | no | ≥ 0; ≤ 365 |  |
| `limit` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_RiskAcceptanceOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/engagements/risk-acceptances/{acceptance_id}/approve

**Approve Acceptance**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `risk:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/engagements.py:480` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `acceptance_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `Decision`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `RiskAcceptanceOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/engagements/risk-acceptances/{acceptance_id}/reject

**Reject Acceptance**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `risk:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/engagements.py:507` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `acceptance_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `Decision`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `RiskAcceptanceOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/engagements/risk-acceptances/{acceptance_id}/revoke

**Revoke Acceptance**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `risk:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/engagements.py:524` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `acceptance_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `Decision`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/engagements/tests/{test_id}

**Read Test**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/engagements.py:295` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `test_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `ScanTestDetail` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/engagements/{engagement_id}

**Read Engagement**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/engagements.py:270` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `engagement_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `EngagementOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/engagements/{engagement_id}/tests

**List Tests**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/engagements.py:279` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `engagement_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `ScanTestOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## Schemas

Request and response models used on this page.

#### `Decision`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `note` | string (nullable) | no | max length 4000 |  |

#### `EndpointOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `asset_id` | string (uuid) (nullable) | yes |  |  |
| `protocol` | string (nullable) | yes |  |  |
| `host` | string | yes |  |  |
| `port` | integer (nullable) | yes |  |  |
| `path` | string (nullable) | yes |  |  |
| `query` | string (nullable) | yes |  |  |
| `fragment` | string (nullable) | yes |  |  |
| `canonical` | string | yes |  |  |

#### `EngagementOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `name` | string | yes |  |  |
| `slug` | string | yes |  |  |
| `description` | string (nullable) | yes |  |  |
| `engagement_type` | string | yes |  |  |
| `status` | string | yes |  |  |
| `business_service_id` | string (uuid) (nullable) | yes |  |  |
| `asset_group_id` | string (uuid) (nullable) | yes |  |  |
| `target_start` | string (date) (nullable) | yes |  |  |
| `target_end` | string (date) (nullable) | yes |  |  |
| `started_at` | string (date-time) (nullable) | yes |  |  |
| `completed_at` | string (date-time) (nullable) | yes |  |  |
| `lead_user_id` | string (uuid) (nullable) | yes |  |  |
| `version` | string (nullable) | yes |  |  |
| `branch_tag` | string (nullable) | yes |  |  |
| `commit_hash` | string (nullable) | yes |  |  |
| `build_id` | string (nullable) | yes |  |  |
| `dedupe_within_engagement` | boolean | yes |  |  |
| `tags` | array of any | yes |  |  |

#### `EngagementWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes | min length 1; max length 200 |  |
| `engagement_type` | string | no | default `"scheduled"` |  |
| `description` | string (nullable) | no |  |  |
| `business_service_id` | string (uuid) (nullable) | no |  |  |
| `asset_group_id` | string (uuid) (nullable) | no |  |  |
| `lead_user_id` | string (uuid) (nullable) | no |  |  |
| `target_start` | string (date) (nullable) | no |  |  |
| `target_end` | string (date) (nullable) | no |  |  |
| `dedupe_within_engagement` | boolean | no | default `false` |  |
| `version` | string (nullable) | no | max length 80 |  |
| `branch_tag` | string (nullable) | no | max length 200 |  |
| `commit_hash` | string (nullable) | no | max length 80 |  |
| `build_id` | string (nullable) | no | max length 120 |  |
| `tags` | array of string | no |  |  |

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `MitigateEndpoints`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `endpoint_ids` | array of string (uuid) | yes | min items 1 |  |

#### `Page_EndpointOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `EndpointOut` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `Page_EngagementOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `EngagementOut` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `Page_RiskAcceptanceOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `RiskAcceptanceOut` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `RiskAcceptanceOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `name` | string | yes |  |  |
| `decision` | string | yes |  |  |
| `state` | string | yes |  |  |
| `reason` | string | yes |  |  |
| `compensating_controls` | string (nullable) | yes |  |  |
| `requested_by_id` | string (uuid) (nullable) | yes |  |  |
| `approved_by_id` | string (uuid) (nullable) | yes |  |  |
| `approved_at` | string (date-time) (nullable) | yes |  |  |
| `decided_note` | string (nullable) | yes |  |  |
| `expires_on` | string (date) (nullable) | yes |  |  |
| `expired_at` | string (date-time) (nullable) | yes |  |  |
| `reactivate_on_expiry` | boolean | yes |  |  |
| `restart_sla_on_expiry` | boolean | yes |  |  |
| `proof_document_id` | string (uuid) (nullable) | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |

#### `RiskAcceptanceWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes | min length 1; max length 300 |  |
| `reason` | string | yes | min length 10; max length 8000 |  |
| `finding_ids` | array of string (uuid) | yes | min items 1 |  |
| `decision` | string | no | default `"accepted"` |  |
| `expires_on` | string (date) (nullable) | no |  |  |
| `compensating_controls` | string (nullable) | no | max length 8000 |  |
| `reactivate_on_expiry` | boolean | no | default `true` |  |
| `restart_sla_on_expiry` | boolean | no | default `false` |  |
| `proof_document_id` | string (uuid) (nullable) | no |  |  |

#### `ScanTestDetail`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `engagement_id` | string (uuid) | yes |  |  |
| `title` | string (nullable) | yes |  |  |
| `scanner` | string | yes |  |  |
| `environment` | string (nullable) | yes |  |  |
| `target_start` | string (date-time) (nullable) | yes |  |  |
| `target_end` | string (date-time) (nullable) | yes |  |  |
| `version` | string (nullable) | yes |  |  |
| `branch_tag` | string (nullable) | yes |  |  |
| `commit_hash` | string (nullable) | yes |  |  |
| `build_id` | string (nullable) | yes |  |  |
| `last_import_run_id` | string (uuid) (nullable) | yes |  |  |
| `reimport_count` | integer | yes |  |  |
| `dedupe_config` | object | yes |  |  |
| `scope_size` | integer | yes |  |  |
| `present` | integer | yes |  |  |
| `absent` | integer | yes |  |  |
| `effective_dedupe` | object | yes |  |  |

#### `ScanTestOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `engagement_id` | string (uuid) | yes |  |  |
| `title` | string (nullable) | yes |  |  |
| `scanner` | string | yes |  |  |
| `environment` | string (nullable) | yes |  |  |
| `target_start` | string (date-time) (nullable) | yes |  |  |
| `target_end` | string (date-time) (nullable) | yes |  |  |
| `version` | string (nullable) | yes |  |  |
| `branch_tag` | string (nullable) | yes |  |  |
| `commit_hash` | string (nullable) | yes |  |  |
| `build_id` | string (nullable) | yes |  |  |
| `last_import_run_id` | string (uuid) (nullable) | yes |  |  |
| `reimport_count` | integer | yes |  |  |
| `dedupe_config` | object | yes |  |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |
