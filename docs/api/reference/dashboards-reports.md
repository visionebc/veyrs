---
title: API reference: dashboards & reports
purpose: Every HTTP endpoint tagged `dashboards & reports`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: dashboards & reports

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


17 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `GET` | [`/api/v1/dashboard/executive`](#get-apiv1dashboardexecutive) | Executive Dashboard | Authenticated | `report:read` |
| `GET` | [`/api/v1/dashboard/sla`](#get-apiv1dashboardsla) | Sla Dashboard | Authenticated | `sla:read` |
| `GET` | [`/api/v1/dashboard/technical`](#get-apiv1dashboardtechnical) | Technical Dashboard | Authenticated | `report:read` |
| `GET` | [`/api/v1/dashboard/trends`](#get-apiv1dashboardtrends) | Trends | Authenticated | `report:read` |
| `GET` | [`/api/v1/report-builder/catalog`](#get-apiv1report-buildercatalog) | Entities, fields, operators and limits the builder offers | Authenticated | `report:read` |
| `POST` | [`/api/v1/report-builder/export`](#post-apiv1report-builderexport) | Export an ad-hoc report spec (csv, xlsx, json) | Authenticated | `report:read` |
| `GET` | [`/api/v1/report-builder/queries`](#get-apiv1report-builderqueries) | My saved reports, plus everything shared here | Authenticated | `report:read` |
| `POST` | [`/api/v1/report-builder/queries`](#post-apiv1report-builderqueries) | Save a report | Authenticated | `report:read` |
| `DELETE` | [`/api/v1/report-builder/queries/{query_id}`](#delete-apiv1report-builderqueriesquery_id) | Delete a saved report | Authenticated | `report:read` |
| `GET` | [`/api/v1/report-builder/queries/{query_id}`](#get-apiv1report-builderqueriesquery_id) | One saved report | Authenticated | `report:read` |
| `PATCH` | [`/api/v1/report-builder/queries/{query_id}`](#patch-apiv1report-builderqueriesquery_id) | Rename, re-specify or share a saved report | Authenticated | `report:read` |
| `POST` | [`/api/v1/report-builder/queries/{query_id}/export`](#post-apiv1report-builderqueriesquery_idexport) | Export a saved report | Authenticated | `report:read` |
| `POST` | [`/api/v1/report-builder/queries/{query_id}/run`](#post-apiv1report-builderqueriesquery_idrun) | Run a saved report under MY authorization | Authenticated | `report:read` |
| `POST` | [`/api/v1/report-builder/run`](#post-apiv1report-builderrun) | Run an ad-hoc report spec | Authenticated | `report:read` |
| `GET` | [`/api/v1/reports`](#get-apiv1reports) | List Reports | Authenticated | - |
| `GET` | [`/api/v1/reports/{slug}`](#get-apiv1reportsslug) | Build Report | Authenticated | - |
| `GET` | [`/api/v1/reports/{slug}/export`](#get-apiv1reportsslugexport) | Export Report | Authenticated | - |

## GET /api/v1/dashboard/executive

**Executive Dashboard**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `report:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/reports.py:63` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `days` | query | integer | no | ≥ 7; ≤ 730; default `90` |  |
| `team_id` | query | string (uuid) (nullable) | no |  | Narrow every figure to one owning team |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/dashboard/sla

**Sla Dashboard**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `sla:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/reports.py:84` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `days` | query | integer | no | ≥ 7; ≤ 730; default `90` |  |
| `team_id` | query | string (uuid) (nullable) | no |  | Narrow every figure to one owning team |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/dashboard/technical

**Technical Dashboard**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `report:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/reports.py:74` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `team_id` | query | string (uuid) (nullable) | no |  | Narrow every figure to one owning team |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/dashboard/trends

**Trends**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `report:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/reports.py:95` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `days` | query | integer | no | ≥ 7; ≤ 730; default `90` |  |
| `buckets` | query | integer | no | ≥ 2; ≤ 52; default `12` |  |
| `team_id` | query | string (uuid) (nullable) | no |  | Narrow every figure to one owning team |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/report-builder/catalog

**Entities, fields, operators and limits the builder offers**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `report:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/report_builder.py:118` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/report-builder/export

**Export an ad-hoc report spec (csv, xlsx, json)**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `report:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/report_builder.py:132` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `format` | query | string | no | default `"csv"` |  |

**Request body** (`application/json`, required): object

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/report-builder/queries

**My saved reports, plus everything shared here**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `report:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/report_builder.py:169` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/report-builder/queries

**Save a report**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `report:read` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/report_builder.py:175` |

**Request body** (`application/json`, required): `QueryWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/report-builder/queries/{query_id}

**Delete a saved report**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `report:read` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/report_builder.py:228` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `query_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/report-builder/queries/{query_id}

**One saved report**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `report:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/report_builder.py:196` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `query_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/report-builder/queries/{query_id}

**Rename, re-specify or share a saved report**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `report:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/report_builder.py:202` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `query_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `QueryPatch`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/report-builder/queries/{query_id}/export

**Export a saved report**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `report:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/report_builder.py:251` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `query_id` | path | string (uuid) | yes |  |  |
| `format` | query | string | no | default `"csv"` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/report-builder/queries/{query_id}/run

**Run a saved report under MY authorization**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `report:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/report_builder.py:244` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `query_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/report-builder/run

**Run an ad-hoc report spec**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `report:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/report_builder.py:126` |

**Request body** (`application/json`, required): object

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/reports

**List Reports**

The catalogue, annotated with what THIS caller may actually export.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/reports.py:118` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/reports/{slug}

**Build Report**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/reports.py:132` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `slug` | path | string | yes |  |  |
| `days` | query | integer | no | ≥ 7; ≤ 730; default `90` |  |
| `limit` | query | integer | no | ≥ 1; ≤ 20000; default `1000` |  |
| `framework_id` | query | string (uuid) (nullable) | no |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/reports/{slug}/export

**Export Report**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/reports.py:154` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `slug` | path | string | yes |  |  |
| `format` | query | string | no | default `"json"` |  |
| `days` | query | integer | no | ≥ 7; ≤ 730; default `90` |  |
| `limit` | query | integer | no | ≥ 1; ≤ 20000; default `1000` |  |
| `framework_id` | query | string (uuid) (nullable) | no |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## Schemas

Request and response models used on this page.

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `QueryPatch`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string (nullable) | no | max length 120 |  |
| `description` | string (nullable) | no | max length 400 |  |
| `spec` | object (nullable) | no |  |  |
| `is_shared` | boolean (nullable) | no |  |  |

#### `QueryWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes | min length 1; max length 120 |  |
| `description` | string (nullable) | no | max length 400 |  |
| `spec` | object | yes |  |  |
| `is_shared` | boolean | no | default `false` |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |
