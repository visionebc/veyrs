---
title: API reference: risk register
purpose: Every HTTP endpoint tagged `risk register`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: risk register

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


10 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `GET` | [`/api/v1/risks`](#get-apiv1risks) | The risk register | Authenticated | `riskregister:read` |
| `POST` | [`/api/v1/risks`](#post-apiv1risks) | Add a risk | Authenticated | `riskregister:write` |
| `GET` | [`/api/v1/risks/meta`](#get-apiv1risksmeta) | Vocabularies the register uses | Authenticated | `riskregister:read` |
| `GET` | [`/api/v1/risks/summary`](#get-apiv1riskssummary) | Counts for the register header | Authenticated | `riskregister:read` |
| `DELETE` | [`/api/v1/risks/{risk_id}`](#delete-apiv1risksrisk_id) | Remove a risk from the register | Authenticated | `riskregister:delete` |
| `GET` | [`/api/v1/risks/{risk_id}`](#get-apiv1risksrisk_id) | One risk, with its RACI, links and history | Authenticated | `riskregister:read` |
| `PATCH` | [`/api/v1/risks/{risk_id}`](#patch-apiv1risksrisk_id) | Update a risk | Authenticated | `riskregister:write` |
| `POST` | [`/api/v1/risks/{risk_id}/links`](#post-apiv1risksrisk_idlinks) | Link this risk to an asset, finding, vulnerability or control | Authenticated | `riskregister:write` |
| `DELETE` | [`/api/v1/risks/{risk_id}/links/{link_id}`](#delete-apiv1risksrisk_idlinkslink_id) | Remove a link | Authenticated | `riskregister:write` |
| `PUT` | [`/api/v1/risks/{risk_id}/raci`](#put-apiv1risksrisk_idraci) | Set who is Responsible, Accountable, Consulted, Informed | Authenticated | `riskregister:write` |

## GET /api/v1/risks

**The risk register**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `riskregister:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/risk_register.py:227` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `q` | query | string (nullable) | no |  | substring of code or title |
| `status` | query | string (nullable) | no |  |  |
| `band` | query | string (nullable) | no |  |  |
| `category` | query | string (nullable) | no |  |  |
| `treatment` | query | string (nullable) | no |  |  |
| `tag` | query | string (nullable) | no |  |  |
| `open_only` | query | boolean | no | default `false` |  |
| `review_overdue` | query | boolean | no | default `false` |  |
| `unassigned` | query | boolean | no | default `false` | open risks with no Accountable |
| `mine` | query | boolean | no | default `false` | risks I or my teams hold a seat on |
| `page` | query | integer | no | ≥ 1; default `1` |  |
| `size` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_dict_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/risks

**Add a risk**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `riskregister:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/risk_register.py:312` |

**Request body** (`application/json`, required): `RiskWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/risks/meta

**Vocabularies the register uses**

Served rather than hardcoded in the console.

A picker built from a copy of these tuples goes stale the day one gains a value, and the symptom is an option that exists in the API and cannot be chosen anywhere.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `riskregister:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/risk_register.py:186` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/risks/summary

**Counts for the register header**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `riskregister:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/risk_register.py:214` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/risks/{risk_id}

**Remove a risk from the register**

SOFT delete, like assets and users.

A risk that was on the register and is not any more is itself a fact an auditor asks about; a hard delete makes "was this ever raised?" unanswerable. Closing with a note is the ordinary way to retire a risk -- this is for the duplicate and the typo.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `riskregister:delete` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/risk_register.py:445` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `risk_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/risks/{risk_id}

**One risk, with its RACI, links and history**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `riskregister:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/risk_register.py:299` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `risk_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/risks/{risk_id}

**Update a risk**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `riskregister:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/risk_register.py:338` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `risk_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `RiskPatch`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/risks/{risk_id}/links

**Link this risk to an asset, finding, vulnerability or control**

Optional and additive. A risk with no link at all is the ordinary case -- that is the reason this module exists.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `riskregister:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/risk_register.py:392` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `risk_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `veyrs__api__v1__risk_register__LinkWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/risks/{risk_id}/links/{link_id}

**Remove a link**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `riskregister:write` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/risk_register.py:420` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `risk_id` | path | string (uuid) | yes |  |  |
| `link_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PUT /api/v1/risks/{risk_id}/raci

**Set who is Responsible, Accountable, Consulted, Informed**

Replaces the whole matrix.

One call, because a RACI is read as a single statement: swapping the Accountable through two requests leaves a window in which the register says nobody is accountable, and a failure between them makes that window permanent.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `riskregister:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/risk_register.py:361` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `risk_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `RaciWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## Schemas

Request and response models used on this page.

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

#### `RaciSeat`

One seat. A team, or a person -- optionally a person *inside* a team.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `raci` | string | yes |  | R = Responsible, A = Accountable, C = Consulted, I = Informed |
| `party_type` | string | yes |  | team\|user |
| `team_id` | string (uuid) (nullable) | no |  |  |
| `user_id` | string (uuid) (nullable) | no |  |  |
| `note` | string (nullable) | no | max length 400 |  |

#### `RaciWrite`

The WHOLE matrix, replaced in one call. See `services.risk_register.set_raci`.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `raci` | array of `RaciSeat` | no |  |  |

#### `RiskPatch`

Every field optional, and an unknown one is a 422 rather than a no-op.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `title` | string (nullable) | no | min length 1; max length 300 |  |
| `description` | string (nullable) | no |  |  |
| `category` | string (nullable) | no | max length 60 |  |
| `source` | string (nullable) | no | max length 40 |  |
| `status` | string (nullable) | no |  |  |
| `treatment` | string (nullable) | no |  |  |
| `treatment_plan` | string (nullable) | no |  |  |
| `likelihood` | integer (nullable) | no | ≥ 1.0; ≤ 5.0 |  |
| `impact` | integer (nullable) | no | ≥ 1.0; ≤ 5.0 |  |
| `residual_likelihood` | integer (nullable) | no | ≥ 1.0; ≤ 5.0 |  |
| `residual_impact` | integer (nullable) | no | ≥ 1.0; ≤ 5.0 |  |
| `identified_at` | string (date) (nullable) | no |  |  |
| `review_due_at` | string (date) (nullable) | no |  |  |
| `closure_note` | string (nullable) | no |  |  |
| `tags` | array of string (nullable) | no |  |  |
| `external_ref` | string (nullable) | no | max length 300 |  |

#### `RiskWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `title` | string | yes | min length 1; max length 300 |  |
| `description` | string (nullable) | no |  |  |
| `category` | string (nullable) | no | max length 60 |  |
| `source` | string (nullable) | no | max length 40 |  |
| `status` | string | no | default `"identified"` |  |
| `treatment` | string | no | default `"pending"` |  |
| `treatment_plan` | string (nullable) | no |  |  |
| `likelihood` | integer (nullable) | no | ≥ 1.0; ≤ 5.0 |  |
| `impact` | integer (nullable) | no | ≥ 1.0; ≤ 5.0 |  |
| `residual_likelihood` | integer (nullable) | no | ≥ 1.0; ≤ 5.0 |  |
| `residual_impact` | integer (nullable) | no | ≥ 1.0; ≤ 5.0 |  |
| `identified_at` | string (date) (nullable) | no |  |  |
| `review_due_at` | string (date) (nullable) | no |  |  |
| `closure_note` | string (nullable) | no |  |  |
| `tags` | array of string | no |  |  |
| `external_ref` | string (nullable) | no | max length 300 |  |
| `raci` | array of `RaciSeat` | no |  |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |

#### `veyrs__api__v1__risk_register__LinkWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `object_type` | string | yes |  | asset\|finding\|vulnerability\|control |
| `object_id` | string (uuid) | yes |  |  |
| `note` | string (nullable) | no | max length 400 |  |
