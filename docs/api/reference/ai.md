---
title: API reference: ai
purpose: Every HTTP endpoint tagged `ai`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: ai

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


20 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `POST` | [`/api/v1/ai/ask`](#post-apiv1aiask) | Ask | Authenticated | `ai:read` |
| `GET` | [`/api/v1/ai/audit`](#get-apiv1aiaudit) | Ai Audit | Authenticated | `audit:read` |
| `GET` | [`/api/v1/ai/capabilities`](#get-apiv1aicapabilities) | List Capabilities | Authenticated | `ai:read` |
| `GET` | [`/api/v1/ai/conversations`](#get-apiv1aiconversations) | List Conversations | Authenticated | `ai:read` |
| `GET` | [`/api/v1/ai/conversations/{conversation_id}`](#get-apiv1aiconversationsconversation_id) | Read Conversation | Authenticated | `ai:read` |
| `POST` | [`/api/v1/ai/cve/{cve_id}/analysis`](#post-apiv1aicvecve_idanalysis) | Analyze Cve | Authenticated | `cve:read` |
| `POST` | [`/api/v1/ai/findings/{finding_id}/explain`](#post-apiv1aifindingsfinding_idexplain) | Explain Finding Risk | Authenticated | `risk:read` |
| `POST` | [`/api/v1/ai/findings/{finding_id}/remediation`](#post-apiv1aifindingsfinding_idremediation) | Recommend Remediation | Authenticated | `finding:read` |
| `POST` | [`/api/v1/ai/findings/{finding_id}/suggest-team`](#post-apiv1aifindingsfinding_idsuggest-team) | Suggest Team | Authenticated | `finding:read` |
| `POST` | [`/api/v1/ai/findings/{finding_id}/ticket-draft`](#post-apiv1aifindingsfinding_idticket-draft) | Draft Ticket | Authenticated | `ticket:write` |
| `GET` | [`/api/v1/ai/policy`](#get-apiv1aipolicy) | Read Policy | Authenticated | `ai:read` |
| `PUT` | [`/api/v1/ai/policy`](#put-apiv1aipolicy) | Write Policy | Authenticated | `ai:admin` |
| `GET` | [`/api/v1/ai/providers`](#get-apiv1aiproviders) | List Providers | Authenticated | `ai:read` |
| `POST` | [`/api/v1/ai/providers`](#post-apiv1aiproviders) | Create Provider | Authenticated | `ai:admin` |
| `DELETE` | [`/api/v1/ai/providers/{provider_id}`](#delete-apiv1aiprovidersprovider_id) | Delete Provider | Authenticated | `ai:admin` |
| `POST` | [`/api/v1/ai/providers/{provider_id}/test`](#post-apiv1aiprovidersprovider_idtest) | Test Provider Sign In | Authenticated | `ai:admin` |
| `POST` | [`/api/v1/ai/scan`](#post-apiv1aiscan) | Scan Text | Authenticated | `ai:read` |
| `POST` | [`/api/v1/ai/search`](#post-apiv1aisearch) | Natural Language Search | Authenticated | `ai:read` |
| `GET` | [`/api/v1/ai/search/grammar`](#get-apiv1aisearchgrammar) | Search Grammar | Authenticated | `ai:read` |
| `POST` | [`/api/v1/ai/threat-summary`](#post-apiv1aithreat-summary) | Threat Summary | Authenticated | `intel:read` |

## POST /api/v1/ai/ask

**Ask**

Free-form assistant turn, grounded in permission-aware search results.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ai:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:522` |

**Request body** (`application/json`, required): `AskRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AiAnswer` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/ai/audit

**Ai Audit**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `audit:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:662` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `decision` | query | string (nullable) | no |  |  |
| `limit` | query | integer | no | ≥ 1; ≤ 500; default `100` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_dict_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/ai/capabilities

**List Capabilities**

What this caller can actually use right now, and why not otherwise.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ai:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:353` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/ai/conversations

**List Conversations**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ai:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:611` |

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

## GET /api/v1/ai/conversations/{conversation_id}

**Read Conversation**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ai:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:635` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `conversation_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/ai/cve/{cve_id}/analysis

**Analyze Cve**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `cve:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:387` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `cve_id` | path | string | yes |  |  |
| `locale` | query | string | no | default `"en"` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AiAnswer` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/ai/findings/{finding_id}/explain

**Explain Finding Risk**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `risk:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:403` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `finding_id` | path | string (uuid) | yes |  |  |
| `locale` | query | string | no | default `"en"` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AiAnswer` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/ai/findings/{finding_id}/remediation

**Recommend Remediation**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `finding:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:420` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `finding_id` | path | string (uuid) | yes |  |  |
| `locale` | query | string | no | default `"en"` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AiAnswer` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/ai/findings/{finding_id}/suggest-team

**Suggest Team**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `finding:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:455` |

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

## POST /api/v1/ai/findings/{finding_id}/ticket-draft

**Draft Ticket**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:437` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `finding_id` | path | string (uuid) | yes |  |  |
| `locale` | query | string | no | default `"en"` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/ai/policy

**Read Policy**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ai:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:154` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `PolicyOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PUT /api/v1/ai/policy

**Write Policy**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ai:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:162` |

**Request body** (`application/json`, required): `PolicyWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `PolicyOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/ai/providers

**List Providers**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ai:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:208` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `ProviderDetail` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/ai/providers

**Create Provider**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ai:admin` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/ai.py:226` |

**Request body** (`application/json`, required): `ProviderWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `ProviderOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/ai/providers/{provider_id}

**Delete Provider**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ai:admin` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/ai.py:322` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `provider_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/ai/providers/{provider_id}/test

**Test Provider Sign In**

Sign in with the provider's credentials now and say how long it lasts.

Only for token modes. Answers 200 with ``ok: false`` and the reason when the sign-in fails: a failed test is a result, not a server error. Never returns the token, the password or the client secret.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ai:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:286` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `provider_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/ai/scan

**Scan Text**

Dry-run the guardrails on arbitrary text.

Operators use this to answer "would this document be allowed out?" before enabling an external provider. Returns the report only -- never the redacted text, so the endpoint cannot be used as a redaction oracle to confirm a guessed secret.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ai:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:684` |

**Request body** (`application/json`, required): object

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/ai/search

**Natural Language Search**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ai:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:487` |

**Request body** (`application/json`, required): `NlSearchRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/ai/search/grammar

**Search Grammar**

The closed query grammar, so the UI can offer it and users can verify it.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ai:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:502` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/ai/threat-summary

**Threat Summary**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `intel:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/ai.py:471` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `days` | query | integer | no | ≥ 1; ≤ 90; default `7` |  |
| `locale` | query | string | no | default `"en"` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AiAnswer` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## Schemas

Request and response models used on this page.

#### `AiAnswer`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `text` | string | yes |  |  |
| `decision` | string | yes |  |  |
| `provider` | string | yes |  |  |
| `model` | string | yes |  |  |
| `external` | boolean | yes |  |  |
| `degraded` | boolean | yes |  |  |
| `block_reason` | string (nullable) | no |  |  |
| `citations` | array of object | no |  |  |
| `redactions` | object | no |  |  |
| `facts` | object | no |  |  |

#### `AskRequest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `question` | string | yes | min length 1; max length 4000 |  |
| `conversation_id` | string (uuid) (nullable) | no |  |  |
| `locale` | string | no | default `"en"` |  |

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `NlSearchRequest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `question` | string | yes | min length 1; max length 1000 |  |

#### `Page_dict_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of object | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `PolicyOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `allow_external` | boolean | yes |  |  |
| `allow_local` | boolean | yes |  |  |
| `allowed_providers` | array of string | yes |  |  |
| `allowed_models` | array of string | yes |  |  |
| `max_external_classification` | string | yes |  |  |
| `max_local_classification` | string | yes |  |  |
| `redact_secrets` | boolean | yes |  |  |
| `redact_pii` | boolean | yes |  |  |
| `block_on_injection` | boolean | yes |  |  |
| `disabled_capabilities` | array of string | yes |  |  |
| `max_prompt_chars` | integer | yes |  |  |
| `daily_call_limit` | integer | yes |  |  |

#### `PolicyWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `allow_external` | boolean (nullable) | no |  |  |
| `allow_local` | boolean (nullable) | no |  |  |
| `allowed_providers` | array of string (nullable) | no |  |  |
| `allowed_models` | array of string (nullable) | no |  |  |
| `max_external_classification` | string (nullable) | no |  |  |
| `max_local_classification` | string (nullable) | no |  |  |
| `redact_secrets` | boolean (nullable) | no |  |  |
| `redact_pii` | boolean (nullable) | no |  |  |
| `block_on_injection` | boolean (nullable) | no |  |  |
| `disabled_capabilities` | array of string (nullable) | no |  |  |
| `max_prompt_chars` | integer (nullable) | no | ≥ 500.0; ≤ 200000.0 |  |
| `daily_call_limit` | integer (nullable) | no | ≥ 0.0; ≤ 1000000.0 |  |

#### `ProviderDetail`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `slug` | string | yes |  |  |
| `name` | string | yes |  |  |
| `kind` | string | yes |  |  |
| `base_url` | string (nullable) | yes |  |  |
| `model` | string | yes |  |  |
| `is_external` | boolean | yes |  |  |
| `is_enabled` | boolean | yes |  |  |
| `is_default` | boolean | yes |  |  |
| `capabilities` | array of string | yes |  |  |
| `last_error` | string (nullable) | yes |  |  |
| `last_used_at` | string (date-time) (nullable) | yes |  |  |
| `auth_mode` | string (nullable) | no |  |  |
| `auth_config` | object (nullable) | no |  |  |
| `api_key_masked` | string | no | default `""` |  |

#### `ProviderOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `slug` | string | yes |  |  |
| `name` | string | yes |  |  |
| `kind` | string | yes |  |  |
| `base_url` | string (nullable) | yes |  |  |
| `model` | string | yes |  |  |
| `is_external` | boolean | yes |  |  |
| `is_enabled` | boolean | yes |  |  |
| `is_default` | boolean | yes |  |  |
| `capabilities` | array of string | yes |  |  |
| `last_error` | string (nullable) | yes |  |  |
| `last_used_at` | string (date-time) (nullable) | yes |  |  |
| `auth_mode` | string (nullable) | no |  |  |
| `auth_config` | object (nullable) | no |  |  |

#### `ProviderWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `slug` | string | yes | min length 1; max length 60 |  |
| `name` | string | yes | min length 1; max length 160 |  |
| `kind` | string | yes |  |  |
| `model` | string | yes | min length 1; max length 160 |  |
| `base_url` | string (nullable) | no |  |  |
| `api_key` | string (nullable) | no |  |  |
| `is_external` | boolean | yes |  |  |
| `is_enabled` | boolean | no | default `true` |  |
| `is_default` | boolean | no | default `false` |  |
| `capabilities` | array of string | no |  |  |
| `timeout_seconds` | integer | no | ≥ 1.0; ≤ 600.0; default `60` |  |
| `temperature` | number | no | ≥ 0.0; ≤ 2.0; default `0.1` |  |
| `max_output_tokens` | integer | no | ≥ 64.0; ≤ 32000.0; default `1500` |  |
| `auth_mode` | string | no | default `"api_key"` |  |
| `auth_config` | object | no |  |  |
| `auth_secret` | string (nullable) | no | max length 4000 |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |
