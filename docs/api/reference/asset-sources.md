---
title: API reference: asset sources
purpose: Every HTTP endpoint tagged `asset sources`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: asset sources

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


19 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `GET` | [`/api/v1/asset-sources`](#get-apiv1asset-sources) | List asset sources | Authenticated | `importer:read` |
| `POST` | [`/api/v1/asset-sources`](#post-apiv1asset-sources) | Register an asset source | Authenticated | `importer:admin` |
| `GET` | [`/api/v1/asset-sources/compare`](#get-apiv1asset-sourcescompare) | What two sources say about the same thing | Authenticated | `asset:read` |
| `GET` | [`/api/v1/asset-sources/drivers`](#get-apiv1asset-sourcesdrivers) | What kinds of asset source exist | Authenticated | `importer:read` |
| `POST` | [`/api/v1/asset-sources/promote`](#post-apiv1asset-sourcespromote) | Copy staged records into the asset register | Authenticated | `asset:write` |
| `GET` | [`/api/v1/asset-sources/records`](#get-apiv1asset-sourcesrecords) | Staged records | Authenticated | `asset:read` |
| `PATCH` | [`/api/v1/asset-sources/records/{record_id}`](#patch-apiv1asset-sourcesrecordsrecord_id) | Ignore a record, or link it to an asset by hand | Authenticated | `asset:write` |
| `GET` | [`/api/v1/asset-sources/summary`](#get-apiv1asset-sourcessummary) | What each source holds | Authenticated | `asset:read` |
| `DELETE` | [`/api/v1/asset-sources/{source_id}`](#delete-apiv1asset-sourcessource_id) | Delete a source and its staging rows | Authenticated | `importer:admin` |
| `GET` | [`/api/v1/asset-sources/{source_id}`](#get-apiv1asset-sourcessource_id) | One asset source | Authenticated | `importer:read` |
| `PATCH` | [`/api/v1/asset-sources/{source_id}`](#patch-apiv1asset-sourcessource_id) | Update a source | Authenticated | `importer:admin` |
| `GET` | [`/api/v1/asset-sources/{source_id}/runs`](#get-apiv1asset-sourcessource_idruns) | This source's import history | Authenticated | `importer:read` |
| `POST` | [`/api/v1/asset-sources/{source_id}/sync`](#post-apiv1asset-sourcessource_idsync) | Read the source into staging | Authenticated | `importer:write` |
| `POST` | [`/api/v1/asset-sources/{source_id}/test`](#post-apiv1asset-sourcessource_idtest) | Reach the source, write nothing | Authenticated | `importer:admin` |
| `POST` | [`/api/v1/asset-sources/{source_id}/upload`](#post-apiv1asset-sourcessource_idupload) | Upload a CMDB export into staging | Authenticated | `importer:write` |
| `POST` | [`/api/v1/teams/import`](#post-apiv1teamsimport) | Create the teams this source reports | Authenticated | `team:write` |
| `POST` | [`/api/v1/teams/import/assign-assets`](#post-apiv1teamsimportassign-assets) | Point staged assets at their imported team | Authenticated | `team:write` |
| `POST` | [`/api/v1/teams/import/preview`](#post-apiv1teamsimportpreview) | What an import would do; writes nothing | Authenticated | `team:write` |
| `GET` | [`/api/v1/teams/import/providers`](#get-apiv1teamsimportproviders) | Where teams can be imported from | Authenticated | `team:write` |

## GET /api/v1/asset-sources

**List asset sources**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cmdb.py:317` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `AssetSourceOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/asset-sources

**Register an asset source**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:admin` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/cmdb.py:330` |

**Request body** (`application/json`, required): `AssetSourceWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `AssetSourceOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/asset-sources/compare

**What two sources say about the same thing**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cmdb.py:380` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `source_id` | query | array of string (uuid) (nullable) | no |  |  |
| `mode` | query | string | no | pattern ^(conflicts\|gaps\|all)$; default `"conflicts"` |  |
| `include_absent` | query | boolean | no | default `false` |  |
| `limit` | query | integer | no | ≥ 1; ≤ 500; default `100` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/asset-sources/drivers

**What kinds of asset source exist**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cmdb.py:299` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/asset-sources/promote

**Copy staged records into the asset register**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cmdb.py:474` |

**Request body** (`application/json`, required): `PromoteRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/asset-sources/records

**Staged records**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cmdb.py:396` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `source_id` | query | string (uuid) (nullable) | no |  |  |
| `match_status` | query | string (nullable) | no |  |  |
| `is_absent` | query | boolean (nullable) | no |  |  |
| `promoted` | query | boolean (nullable) | no |  |  |
| `q` | query | string (nullable) | no |  |  |
| `limit` | query | integer | no | ≥ 1; ≤ 500; default `100` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `RecordOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/asset-sources/records/{record_id}

**Ignore a record, or link it to an asset by hand**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cmdb.py:431` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `record_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `RecordPatch`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `RecordOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/asset-sources/summary

**What each source holds**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cmdb.py:372` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/asset-sources/{source_id}

**Delete a source and its staging rows**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:admin` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/cmdb.py:532` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `source_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/asset-sources/{source_id}

**One asset source**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cmdb.py:489` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `source_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AssetSourceOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/asset-sources/{source_id}

**Update a source**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cmdb.py:498` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `source_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `AssetSourcePatch`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AssetSourceOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/asset-sources/{source_id}/runs

**This source's import history**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cmdb.py:616` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `source_id` | path | string (uuid) | yes |  |  |
| `limit` | query | integer | no | ≥ 1; ≤ 200; default `25` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `AssetSourceRunOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/asset-sources/{source_id}/sync

**Read the source into staging**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cmdb.py:565` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `source_id` | path | string (uuid) | yes |  |  |
| `dry_run` | query | boolean | no | default `false` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AssetSourceRunOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/asset-sources/{source_id}/test

**Reach the source, write nothing**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cmdb.py:552` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `source_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/asset-sources/{source_id}/upload

**Upload a CMDB export into staging**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/cmdb.py:589` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `source_id` | path | string (uuid) | yes |  |  |
| `dry_run` | query | boolean | no | default `false` |  |
| `mark_absent` | query | boolean | no | default `false` |  |

**Request body** (`multipart/form-data`, required): `Body_upload_export_api_v1_asset_sources__source_id__upload_post`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AssetSourceRunOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/teams/import

**Create the teams this source reports**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `team:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/team_import.py:97` |

**Request body** (`application/json`, required): `ImportRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/teams/import/assign-assets

**Point staged assets at their imported team**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `team:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/team_import.py:112` |

**Request body** (`application/json`, required): `AssignRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/teams/import/preview

**What an import would do; writes nothing**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `team:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/team_import.py:85` |

**Request body** (`application/json`, required): `ImportRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/teams/import/providers

**Where teams can be imported from**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `team:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/team_import.py:77` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## Schemas

Request and response models used on this page.

#### `AssetSourceOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `slug` | string | yes |  |  |
| `name` | string | yes |  |  |
| `driver` | string | yes |  |  |
| `description` | string (nullable) | yes |  |  |
| `base_url` | string (nullable) | yes |  |  |
| `is_enabled` | boolean | yes |  |  |
| `verify_tls` | boolean | yes |  |  |
| `collections` | array of any | yes |  |  |
| `record_path` | string (nullable) | yes |  |  |
| `field_map` | object | yes |  |  |
| `value_maps` | object | yes |  |  |
| `include_fields` | array of any | yes |  |  |
| `match_order` | array of any | yes |  |  |
| `auto_promote` | boolean | yes |  |  |
| `promote_creates_assets` | boolean | yes |  |  |
| `priority` | integer | yes |  |  |
| `last_sync_at` | object | no |  |  |
| `last_error` | string (nullable) | no |  |  |
| `credentials_set` | boolean | no | default `false` |  |
| `is_inert` | boolean | no | default `false` |  |

#### `AssetSourcePatch`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string (nullable) | no |  |  |
| `description` | string (nullable) | no |  |  |
| `base_url` | string (nullable) | no |  |  |
| `is_enabled` | boolean (nullable) | no |  |  |
| `verify_tls` | boolean (nullable) | no |  |  |
| `collections` | array of string (nullable) | no |  |  |
| `record_path` | string (nullable) | no |  |  |
| `field_map` | object (nullable) | no |  |  |
| `value_maps` | object (nullable) | no |  |  |
| `include_fields` | array of string (nullable) | no |  |  |
| `match_order` | array of string (nullable) | no |  |  |
| `auto_promote` | boolean (nullable) | no |  |  |
| `promote_creates_assets` | boolean (nullable) | no |  |  |
| `priority` | integer (nullable) | no |  |  |
| `credentials` | object (nullable) | no |  |  |

#### `AssetSourceRunOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `source_id` | string (uuid) | yes |  |  |
| `status` | string | yes |  |  |
| `trigger` | string | yes |  |  |
| `dry_run` | boolean | yes |  |  |
| `filename` | string (nullable) | yes |  |  |
| `size_bytes` | integer | yes |  |  |
| `started_at` | object | yes |  |  |
| `finished_at` | object | no |  |  |
| `records_seen` | integer | yes |  |  |
| `records_created` | integer | yes |  |  |
| `records_updated` | integer | yes |  |  |
| `records_unchanged` | integer | yes |  |  |
| `records_rejected` | integer | yes |  |  |
| `assets_matched` | integer | yes |  |  |
| `assets_unmatched` | integer | yes |  |  |
| `assets_promoted` | integer | yes |  |  |
| `assets_created` | integer | yes |  |  |
| `records_absent` | integer | yes |  |  |
| `reject_reasons` | object | yes |  |  |
| `reject_samples` | array of any | yes |  |  |
| `error` | string (nullable) | no |  |  |

#### `AssetSourceWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `slug` | string | yes | min length 1; max length 80 |  |
| `name` | string | yes | min length 1; max length 200 |  |
| `driver` | string | yes |  |  |
| `description` | string (nullable) | no |  |  |
| `base_url` | string | no | default `""` |  |
| `is_enabled` | boolean | no | default `false` |  |
| `verify_tls` | boolean | no | default `true` |  |
| `collections` | array of string | no |  |  |
| `record_path` | string (nullable) | no |  |  |
| `field_map` | object | no |  |  |
| `value_maps` | object | no |  |  |
| `include_fields` | array of string | no |  |  |
| `match_order` | array of string | no |  |  |
| `auto_promote` | boolean | no | default `false` |  |
| `promote_creates_assets` | boolean | no | default `false` |  |
| `priority` | integer | no | default `100` |  |
| `credentials` | object (nullable) | no |  |  |

#### `AssignRequest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `source_id` | string (uuid) | yes |  |  |
| `dry_run` | boolean | no | default `false` |  |
| `overwrite` | boolean | no | default `false` |  |

#### `Body_upload_export_api_v1_asset_sources__source_id__upload_post`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `file` | string | yes |  |  |

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `ImportRequest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `provider` | string | yes |  |  |
| `source_id` | string (uuid) (nullable) | no |  |  |
| `collection` | string (nullable) | no |  |  |
| `import_members` | boolean | no | default `false` |  |
| `update_existing` | boolean | no | default `false` |  |

#### `PromoteRequest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `record_ids` | array of string (uuid) | yes | min items 1 |  |
| `create_assets` | boolean | no | default `false` |  |

#### `RecordOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `source_id` | string (uuid) | yes |  |  |
| `external_key` | string | yes |  |  |
| `identity_key` | string (nullable) | yes |  |  |
| `asset_id` | string (uuid) (nullable) | yes |  |  |
| `match_status` | string | yes |  |  |
| `matched_by` | string (nullable) | yes |  |  |
| `name` | string (nullable) | yes |  |  |
| `hostname` | string (nullable) | yes |  |  |
| `fqdn` | string (nullable) | yes |  |  |
| `serial` | string (nullable) | yes |  |  |
| `asset_type` | string (nullable) | yes |  |  |
| `operating_system` | string (nullable) | yes |  |  |
| `os_version` | string (nullable) | yes |  |  |
| `environment` | string (nullable) | yes |  |  |
| `criticality` | string (nullable) | yes |  |  |
| `exposure` | string (nullable) | yes |  |  |
| `data_classification` | string (nullable) | yes |  |  |
| `location` | string (nullable) | yes |  |  |
| `owner_label` | string (nullable) | yes |  |  |
| `team_label` | string (nullable) | yes |  |  |
| `status_label` | string (nullable) | yes |  |  |
| `ip_addresses` | array of any | yes |  |  |
| `mac_addresses` | array of any | yes |  |  |
| `tags` | array of any | yes |  |  |
| `extra` | object | yes |  |  |
| `is_absent` | boolean | yes |  |  |
| `promoted_at` | object | no |  |  |
| `last_seen_at` | object | no |  |  |

#### `RecordPatch`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `match_status` | string (nullable) | no |  |  |
| `asset_id` | string (uuid) (nullable) | no |  |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |
