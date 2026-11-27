---
title: API reference: saved views
purpose: Every HTTP endpoint tagged `saved views`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: saved views

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


4 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `GET` | [`/api/v1/saved-views`](#get-apiv1saved-views) | My saved views, plus everything shared here | Authenticated | - |
| `POST` | [`/api/v1/saved-views`](#post-apiv1saved-views) | Save a view | Authenticated | - |
| `DELETE` | [`/api/v1/saved-views/{view_id}`](#delete-apiv1saved-viewsview_id) | Delete a view | Authenticated | - |
| `PATCH` | [`/api/v1/saved-views/{view_id}`](#patch-apiv1saved-viewsview_id) | Rename, re-filter or share a view | Authenticated | - |

## GET /api/v1/saved-views

**My saved views, plus everything shared here**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/views.py:52` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `entity` | query | string (nullable) | no |  |  |
| `seed` | query | boolean | no | default `false` | Install the built-in starter views for this user if they have none at all. Idempotent, and never overwrites. |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/saved-views

**Save a view**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/views.py:82` |

**Request body** (`application/json`, required): `SavedViewWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## DELETE /api/v1/saved-views/{view_id}

**Delete a view**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/views.py:134` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `view_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## PATCH /api/v1/saved-views/{view_id}

**Rename, re-filter or share a view**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/views.py:108` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `view_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `SavedViewPatch`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## Schemas

Request and response models used on this page.

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `SavedViewPatch`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `entity` | string (nullable) | no |  |  |
| `name` | string (nullable) | no | max length 120 |  |
| `description` | string (nullable) | no | max length 400 |  |
| `filters` | object (nullable) | no |  |  |
| `is_shared` | boolean (nullable) | no |  |  |
| `is_pinned` | boolean (nullable) | no |  |  |
| `position` | integer (nullable) | no |  |  |

#### `SavedViewWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `entity` | string | yes |  | one of findings, tickets, assets, vulnerabilities, issues |
| `name` | string | yes | min length 1; max length 120 |  |
| `description` | string (nullable) | no | max length 400 |  |
| `filters` | object | no |  |  |
| `is_shared` | boolean | no | default `false` |  |
| `is_pinned` | boolean | no | default `true` |  |
| `position` | integer | no | default `0` |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |
