---
title: API reference: cvss
purpose: Every HTTP endpoint tagged `cvss`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: cvss

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


9 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `POST` | [`/api/v1/cvss/assist`](#post-apiv1cvssassist) | Prefill the calculator from a security bulletin | Authenticated | `vulnerability:read` |
| `POST` | [`/api/v1/cvss/compare`](#post-apiv1cvsscompare) | Score several vectors side by side | Authenticated | `vulnerability:read` |
| `POST` | [`/api/v1/cvss/explain`](#post-apiv1cvssexplain) | Score a vector with a plain-language rationale | Authenticated | `vulnerability:read` |
| `POST` | [`/api/v1/cvss/generate`](#post-apiv1cvssgenerate) | Build a canonical vector from a metric map | Authenticated | `vulnerability:read` |
| `GET` | [`/api/v1/cvss/metrics/{version}`](#get-apiv1cvssmetricsversion) | Metric definitions for a version | Authenticated | `vulnerability:read` |
| `POST` | [`/api/v1/cvss/score`](#post-apiv1cvssscore) | Score a vector | Authenticated | `vulnerability:read` |
| `GET` | [`/api/v1/cvss/severity`](#get-apiv1cvssseverity) | Qualitative rating for a numeric score | Authenticated | `vulnerability:read` |
| `POST` | [`/api/v1/cvss/validate`](#post-apiv1cvssvalidate) | Validate a vector without scoring it | Authenticated | `vulnerability:read` |
| `GET` | [`/api/v1/cvss/versions`](#get-apiv1cvssversions) | Supported CVSS versions | Authenticated | `vulnerability:read` |

## POST /api/v1/cvss/assist

**Prefill the calculator from a security bulletin**

Read a bulletin, cross it against this tenant's inventory, prefill a vector.

The response is a PROPOSAL and says so: `metric_source` names where each value came from (`bulletin` beats `model`, always), `needs_decision` lists what the analyst still has to answer, and the score -- when there is one -- is computed by the same engine that scores everything else, never taken from the model.

`vulnerability:read` and not a new permission: this reads the CVE catalogue and the tenant's own inventory, which is exactly what the calculator's other endpoints already require. The AI leg additionally goes through the gateway, which independently enforces `intel:read` for `advisory_analysis` and returns a *blocked* result rather than raising -- so a caller without it still gets the deterministic half.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `vulnerability:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cvss.py:95` |

**Request body** (`application/json`, required): `CvssAssistRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/cvss/compare

**Score several vectors side by side**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `vulnerability:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cvss.py:67` |

**Request body** (`application/json`, required): `CvssCompareRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/cvss/explain

**Score a vector with a plain-language rationale**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `vulnerability:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cvss.py:44` |

**Request body** (`application/json`, required): `CvssScoreRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/cvss/generate

**Build a canonical vector from a metric map**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `vulnerability:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cvss.py:58` |

**Request body** (`application/json`, required): `CvssGenerateRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/cvss/metrics/{version}

**Metric definitions for a version**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `vulnerability:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cvss.py:29` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `version` | path | string | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/cvss/score

**Score a vector**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `vulnerability:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cvss.py:36` |

**Request body** (`application/json`, required): `CvssScoreRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/cvss/severity

**Qualitative rating for a numeric score**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `vulnerability:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cvss.py:72` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `score` | query | number | yes | ≥ 0.0; ≤ 10.0 |  |
| `version` | query | string | no | default `"3.1"` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/cvss/validate

**Validate a vector without scoring it**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `vulnerability:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cvss.py:52` |

**Request body** (`application/json`, required): `CvssScoreRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/cvss/versions

**Supported CVSS versions**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `vulnerability:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cvss.py:24` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## Schemas

Request and response models used on this page.

#### `CvssAssistRequest`

A pasted advisory, plus which version's vector to fill in.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `text` | string | yes | min length 20; max length 200000 |  |
| `version` | string | no | default `"3.1"` |  |
| `use_ai` | boolean | no | default `true` |  |

#### `CvssCompareRequest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `vectors` | array of string | yes | min items 1; max items 12 |  |

#### `CvssGenerateRequest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `version` | string | yes | pattern ^(2\.0\|3\.0\|3\.1\|4\.0)$ |  |
| `metrics` | object | yes |  |  |

#### `CvssScoreRequest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `vector` | string | yes | min length 3; max length 400 |  |
| `version` | string (nullable) | no | pattern ^(2\.0\|3\.0\|3\.1\|4\.0)$ |  |

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |
