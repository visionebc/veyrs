---
title: API reference: compliance
purpose: Every HTTP endpoint tagged `compliance`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: compliance

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


16 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `GET` | [`/api/v1/compliance/assessments`](#get-apiv1complianceassessments) | List Assessments | Authenticated | `compliance:read` |
| `POST` | [`/api/v1/compliance/assessments`](#post-apiv1complianceassessments) | Create Assessment | Authenticated | `compliance:write` |
| `GET` | [`/api/v1/compliance/assessments/{assessment_id}`](#get-apiv1complianceassessmentsassessment_id) | Read Assessment | Authenticated | `compliance:read` |
| `POST` | [`/api/v1/compliance/assessments/{assessment_id}/complete`](#post-apiv1complianceassessmentsassessment_idcomplete) | Complete Assessment | Authenticated | `compliance:write` |
| `GET` | [`/api/v1/compliance/controls/{control_id}/chain`](#get-apiv1compliancecontrolscontrol_idchain) | Control Chain | Authenticated | `compliance:read` |
| `POST` | [`/api/v1/compliance/controls/{control_id}/evidence`](#post-apiv1compliancecontrolscontrol_idevidence) | Add Evidence | Authenticated | `evidence:write` |
| `PUT` | [`/api/v1/compliance/controls/{control_id}/implementation`](#put-apiv1compliancecontrolscontrol_idimplementation) | Set Implementation | Authenticated | `compliance:write` |
| `POST` | [`/api/v1/compliance/controls/{control_id}/links`](#post-apiv1compliancecontrolscontrol_idlinks) | Link Object | Authenticated | `compliance:write` |
| `GET` | [`/api/v1/compliance/evidence`](#get-apiv1complianceevidence) | List Evidence | Authenticated | `evidence:read` |
| `GET` | [`/api/v1/compliance/frameworks`](#get-apiv1complianceframeworks) | List Frameworks | Authenticated | `compliance:read` |
| `POST` | [`/api/v1/compliance/frameworks`](#post-apiv1complianceframeworks) | Create Framework | Authenticated | `compliance:admin` |
| `GET` | [`/api/v1/compliance/frameworks/{framework_id}/controls`](#get-apiv1complianceframeworksframework_idcontrols) | List Controls | Authenticated | `compliance:read` |
| `POST` | [`/api/v1/compliance/frameworks/{framework_id}/controls:import`](#post-apiv1complianceframeworksframework_idcontrolsimport) | Import Controls | Authenticated | `compliance:admin` |
| `GET` | [`/api/v1/compliance/frameworks/{framework_id}/coverage`](#get-apiv1complianceframeworksframework_idcoverage) | Framework Coverage | Authenticated | `compliance:read` |
| `POST` | [`/api/v1/compliance/frameworks/{framework_id}/refresh-signals`](#post-apiv1complianceframeworksframework_idrefresh-signals) | Refresh Signals | Authenticated | `compliance:write` |
| `GET` | [`/api/v1/compliance/signals`](#get-apiv1compliancesignals) | List Signals | Authenticated | `compliance:read` |

## GET /api/v1/compliance/assessments

**List Assessments**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `compliance:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/compliance.py:484` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `limit` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_dict_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/compliance/assessments

**Create Assessment**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `compliance:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/compliance.py:429` |

**Request body** (`application/json`, required): `AssessmentWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/compliance/assessments/{assessment_id}

**Read Assessment**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `compliance:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/compliance.py:507` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `assessment_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/compliance/assessments/{assessment_id}/complete

**Complete Assessment**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `compliance:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/compliance.py:454` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `assessment_id` | path | string (uuid) | yes |  |  |
| `summary` | query | string (nullable) | no |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/compliance/controls/{control_id}/chain

**Control Chain**

Control -> assets -> findings -> tickets -> evidence, in one call.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `compliance:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/compliance.py:317` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `control_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/compliance/controls/{control_id}/evidence

**Add Evidence**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `evidence:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/compliance.py:360` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `control_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `EvidenceWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PUT /api/v1/compliance/controls/{control_id}/implementation

**Set Implementation**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `compliance:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/compliance.py:279` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `control_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `ImplementationWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/compliance/controls/{control_id}/links

**Link Object**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `compliance:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/compliance.py:330` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `control_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `veyrs__api__v1__compliance__LinkWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/compliance/evidence

**List Evidence**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `evidence:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/compliance.py:395` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `kind` | query | string (nullable) | no |  |  |
| `expired` | query | boolean (nullable) | no |  |  |
| `limit` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_dict_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/compliance/frameworks

**List Frameworks**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `compliance:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/compliance.py:122` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `FrameworkDetail` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/compliance/frameworks

**Create Framework**

Create a CUSTOM framework owned by this organization (spec section 16).

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `compliance:admin` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/compliance.py:145` |

**Request body** (`application/json`, required): `FrameworkCreate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `FrameworkOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/compliance/frameworks/{framework_id}/controls

**List Controls**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `compliance:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/compliance.py:181` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `framework_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `ControlOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/compliance/frameworks/{framework_id}/controls:import

**Import Controls**

Import a catalogue the organization licenses (CSV: ref,title,...).

This is how a partial catalogue becomes complete without VEYRS shipping copyrighted text.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `compliance:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/compliance.py:196` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `framework_id` | path | string (uuid) | yes |  |  |

**Request body** (`multipart/form-data`, required): `Body_import_controls_api_v1_compliance_frameworks__framework_id__controls_import_post`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/compliance/frameworks/{framework_id}/coverage

**Framework Coverage**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `compliance:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/compliance.py:227` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `framework_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/compliance/frameworks/{framework_id}/refresh-signals

**Refresh Signals**

Recompute automated evidence from live VEYRS data.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `compliance:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/compliance.py:239` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `framework_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/compliance/signals

**List Signals**

Evaluate every automated signal right now, with its derivation.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `compliance:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/compliance.py:261` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## Schemas

Request and response models used on this page.

#### `AssessmentWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `framework_id` | string (uuid) | yes |  |  |
| `name` | string | yes | min length 1; max length 240 |  |
| `scope` | string (nullable) | no |  |  |
| `assessor` | string (nullable) | no |  |  |
| `started_on` | string (date) (nullable) | no |  |  |

#### `Body_import_controls_api_v1_compliance_frameworks__framework_id__controls_import_post`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `file` | string | yes |  |  |

#### `ControlOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `ref` | string | yes |  |  |
| `title` | string | yes |  |  |
| `theme` | string (nullable) | yes |  |  |
| `parent_ref` | string (nullable) | yes |  |  |
| `normative_text` | string (nullable) | yes |  |  |
| `veyrs_guidance` | string (nullable) | yes |  |  |
| `crosswalk` | object | yes |  |  |
| `automation_signal` | string (nullable) | yes |  |  |

#### `EvidenceWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `kind` | string | yes |  |  |
| `title` | string | yes | min length 1; max length 300 |  |
| `summary` | string (nullable) | no |  |  |
| `document_id` | string (uuid) (nullable) | no |  |  |
| `ticket_id` | string (uuid) (nullable) | no |  |  |
| `finding_id` | string (uuid) (nullable) | no |  |  |
| `asset_id` | string (uuid) (nullable) | no |  |  |
| `external_url` | string (nullable) | no |  |  |
| `valid_until` | string (date) (nullable) | no |  |  |
| `payload` | object | no |  |  |

#### `FrameworkCreate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `slug` | string | yes | min length 1; max length 60 |  |
| `name` | string | yes | min length 1; max length 200 |  |
| `version` | string | yes | min length 1; max length 40 |  |
| `publisher` | string | yes | min length 1; max length 120 |  |
| `description` | string (nullable) | no |  |  |
| `source_url` | string (nullable) | no |  |  |

#### `FrameworkDetail`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `slug` | string | yes |  |  |
| `name` | string | yes |  |  |
| `version` | string | yes |  |  |
| `publisher` | string | yes |  |  |
| `description` | string (nullable) | yes |  |  |
| `source_url` | string (nullable) | yes |  |  |
| `licence_note` | string (nullable) | yes |  |  |
| `is_partial` | boolean | yes |  |  |
| `official_control_count` | integer (nullable) | yes |  |  |
| `is_builtin` | boolean | yes |  |  |
| `controls_shipped` | integer | no | default `0` |  |
| `disclaimer` | string (nullable) | no |  |  |

#### `FrameworkOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `slug` | string | yes |  |  |
| `name` | string | yes |  |  |
| `version` | string | yes |  |  |
| `publisher` | string | yes |  |  |
| `description` | string (nullable) | yes |  |  |
| `source_url` | string (nullable) | yes |  |  |
| `licence_note` | string (nullable) | yes |  |  |
| `is_partial` | boolean | yes |  |  |
| `official_control_count` | integer (nullable) | yes |  |  |
| `is_builtin` | boolean | yes |  |  |

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `ImplementationWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `status` | string | yes |  |  |
| `statement` | string (nullable) | no |  |  |
| `justification` | string (nullable) | no |  |  |
| `review_period_days` | integer (nullable) | no | ≥ 0.0; ≤ 3650.0 |  |

#### `Page_dict_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of object | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |

#### `veyrs__api__v1__compliance__LinkWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `object_type` | string | yes |  |  |
| `object_id` | string | yes |  |  |
| `rationale` | string (nullable) | no |  |  |
