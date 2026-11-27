---
title: API reference: assets
purpose: Every HTTP endpoint tagged `assets`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: assets

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


17 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `GET` | [`/api/v1/assets`](#get-apiv1assets) | List/search assets | Authenticated | `asset:read` |
| `POST` | [`/api/v1/assets`](#post-apiv1assets) | Create an asset | Authenticated | `asset:write` |
| `POST` | [`/api/v1/assets/bulk-assign`](#post-apiv1assetsbulk-assign) | Assign ownership to many assets at once | Authenticated | `asset:write` |
| `GET` | [`/api/v1/assets/inventory/aliases`](#get-apiv1assetsinventoryaliases) | Verify the curated CPE aliases | Authenticated | `asset:read` |
| `GET` | [`/api/v1/assets/inventory/coverage`](#get-apiv1assetsinventorycoverage) | Which inventory can never match a CVE | Authenticated | `asset:read` |
| `POST` | [`/api/v1/assets/inventory/import`](#post-apiv1assetsinventoryimport) | Bulk-onboard hosts with their software | Authenticated | `asset:write` |
| `POST` | [`/api/v1/assets/inventory/resolve`](#post-apiv1assetsinventoryresolve) | Dry-run identity resolution | Authenticated | `asset:read` |
| `GET` | [`/api/v1/assets/services`](#get-apiv1assetsservices) | List business services | Authenticated | `asset:read` |
| `POST` | [`/api/v1/assets/services`](#post-apiv1assetsservices) | Create a business service | Authenticated | `asset:write` |
| `DELETE` | [`/api/v1/assets/{asset_id}`](#delete-apiv1assetsasset_id) | Soft-delete an asset | Authenticated | `asset:delete` |
| `GET` | [`/api/v1/assets/{asset_id}`](#get-apiv1assetsasset_id) | Asset detail | Authenticated | `asset:read` |
| `PATCH` | [`/api/v1/assets/{asset_id}`](#patch-apiv1assetsasset_id) | Update an asset | Authenticated | `asset:write` |
| `GET` | [`/api/v1/assets/{asset_id}/fix-plan`](#get-apiv1assetsasset_idfix-plan) | One fix plan per installed product with open findings | Authenticated | `asset:read`, `finding:read` |
| `POST` | [`/api/v1/assets/{asset_id}/products`](#post-apiv1assetsasset_idproducts) | Record installed software on an asset | Authenticated | `asset:write` |
| `POST` | [`/api/v1/assets/{asset_id}/products/bulk`](#post-apiv1assetsasset_idproductsbulk) | Record installed software in bulk | Authenticated | `asset:write` |
| `DELETE` | [`/api/v1/assets/{asset_id}/products/{install_id}`](#delete-apiv1assetsasset_idproductsinstall_id) | Remove installed software | Authenticated | `asset:write` |
| `POST` | [`/api/v1/assets/{asset_id}/rescan`](#post-apiv1assetsasset_idrescan) | Re-correlate this asset against known CVEs | Authenticated | `asset:write` |

## GET /api/v1/assets

**List/search assets**

List the estate.

Negation exists as its own parameter rather than as a magic prefix on the positive one because the two are not opposites in practice: "not production" has to keep meaning "not production" when a sixth environment is added to the enum, and a client that spells out the five it knows about would silently stop covering the estate the day a sixth appears. The columns are NOT NULL with defaults, so a `!=` predicate cannot drop rows through the usual SQL NULL hole -- if that ever changes, these two filters are the first things to revisit.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/assets.py:195` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `q` | query | string (nullable) | no |  |  |
| `asset_type` | query | string (nullable) | no |  |  |
| `criticality` | query | string (nullable) | no |  |  |
| `exposure` | query | string (nullable) | no |  | Comma-separated; `internet,partner` means either. |
| `environment` | query | string (nullable) | no |  | Comma-separated; `staging,test` means either. |
| `exclude_exposure` | query | string (nullable) | no |  | Comma-separated exposures to EXCLUDE. `internet` is how you ask for the estate that is not reachable from the internet without having to enumerate the other three. |
| `exclude_environment` | query | string (nullable) | no |  | Comma-separated environments to EXCLUDE. `production` is how you ask for the non-production estate. |
| `tag` | query | string (nullable) | no |  |  |
| `business_service_id` | query | string (uuid) (nullable) | no |  |  |
| `team_id` | query | string (uuid) (nullable) | no |  |  |
| `owner_id` | query | string (uuid) (nullable) | no |  |  |
| `department_id` | query | string (uuid) (nullable) | no |  |  |
| `unowned` | query | boolean | no | default `false` | Only assets with no owning team. These are invisible to team-scoped users, so they need a way to be found. |
| `is_active` | query | boolean (nullable) | no |  |  |
| `page` | query | integer | no | ≥ 1; default `1` |  |
| `size` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_AssetOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/assets

**Create an asset**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/assets.py:152` |

**Request body** (`application/json`, required): `AssetCreate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `AssetDetail` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/assets/bulk-assign

**Assign ownership to many assets at once**

Set team / owner / department on up to 500 assets.

Ownership is validated ONCE, before the loop: an unknown team is an operator error about the whole request, not a per-row outcome, and half-applying it would leave the estate in a state nobody asked for. Unknown *assets*, by contrast, are reported per id -- same rationale as `findings/bulk-transition`.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/assets.py:288` |

**Request body** (`application/json`, required): `AssetBulkAssign`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/assets/inventory/aliases

**Verify the curated CPE aliases**

A hardcoded alias is a claim about NVD's dictionary; this checks it.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/assets.py:391` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/assets/inventory/coverage

**Which inventory can never match a CVE**

Separate "nothing is vulnerable" from "nothing is matchable".

Both render as an empty findings list everywhere else in the product, and only one of them is good news.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/assets.py:378` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/assets/inventory/import

**Bulk-onboard hosts with their software**

Create/update many assets and their installed software in one call.

Built for the initial load from an existing CMDB. Correlation runs per asset after its software is recorded, so findings appear in the same request rather than at some later unrelated edit.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/assets.py:429` |

**Request body** (`application/json`, required): `InventoryImportIn`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/assets/inventory/resolve

**Dry-run identity resolution**

Resolve identities and roll the transaction back.

Lets an operator see how a CMDB export will be interpreted -- which vendor strings get rewritten, which rows will never match -- before committing the estate to it.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/assets.py:400` |

**Request body** (`application/json`, required): `InventoryBulkIn`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/assets/services

**List business services**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/assets.py:129` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `page` | query | integer | no | ≥ 1; default `1` |  |
| `size` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_BusinessServiceOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/assets/services

**Create a business service**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/assets.py:115` |

**Request body** (`application/json`, required): `BusinessServiceCreate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `BusinessServiceOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/assets/{asset_id}

**Soft-delete an asset**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:delete` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/assets.py:523` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `asset_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/assets/{asset_id}

**Asset detail**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/assets.py:476` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `asset_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AssetDetail` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/assets/{asset_id}

**Update an asset**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/assets.py:485` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `asset_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `AssetUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AssetDetail` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/assets/{asset_id}/fix-plan

**One fix plan per installed product with open findings**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:read`, `finding:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/fix_plan.py:62` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `asset_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/assets/{asset_id}/products

**Record installed software on an asset**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/assets.py:540` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `asset_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): array of `AssetProductIn`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AssetDetail` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/assets/{asset_id}/products/bulk

**Record installed software in bulk**

Like POST /products, but CPE-aware and honest about what it could not match.

The older endpoint takes the operator's vendor string at face value, which is how an inventory ends up pointing at product rows no CVE will ever reference. This one resolves every row against the CPE dictionary and returns the per-row verdict.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/assets.py:572` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `asset_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `InventoryBulkIn`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/assets/{asset_id}/products/{install_id}

**Remove installed software**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:write` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/assets.py:556` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `asset_id` | path | string (uuid) | yes |  |  |
| `install_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/assets/{asset_id}/rescan

**Re-correlate this asset against known CVEs**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `asset:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/assets.py:604` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `asset_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## Schemas

Request and response models used on this page.

#### `AssetBulkAssign`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `clear` | array of string | no |  |  |
| `asset_ids` | array of string (uuid) | yes | min items 1; max items 500 |  |
| `team_id` | string (uuid) (nullable) | no |  |  |
| `owner_id` | string (uuid) (nullable) | no |  |  |
| `department_id` | string (uuid) (nullable) | no |  |  |

#### `AssetCreate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes | min length 1; max length 255 |  |
| `asset_type` | string | no | default `"server"` |  |
| `external_id` | string (nullable) | no |  |  |
| `hostname` | string (nullable) | no |  |  |
| `fqdn` | string (nullable) | no |  |  |
| `ip_addresses` | array of string | no |  |  |
| `mac_addresses` | array of string | no |  |  |
| `operating_system` | string (nullable) | no |  |  |
| `os_version` | string (nullable) | no |  |  |
| `owner_id` | string (uuid) (nullable) | no |  |  |
| `team_id` | string (uuid) (nullable) | no |  |  |
| `department_id` | string (uuid) (nullable) | no |  |  |
| `business_service_id` | string (uuid) (nullable) | no |  |  |
| `criticality` | string | no | default `"medium"` |  |
| `data_classification` | string | no | default `"internal"` |  |
| `exposure` | string | no | default `"internal"` |  |
| `environment` | string | no | default `"production"` |  |
| `location` | string (nullable) | no |  |  |
| `compensating_controls` | array of string | no |  |  |
| `tags` | array of string | no |  |  |
| `attributes` | object | no |  |  |
| `source` | string | no | default `"manual"` |  |
| `products` | array of `AssetProductIn` | no |  |  |

#### `AssetDetail`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `name` | string | yes |  |  |
| `asset_type` | string | yes |  |  |
| `external_id` | string (nullable) | yes |  |  |
| `hostname` | string (nullable) | yes |  |  |
| `fqdn` | string (nullable) | yes |  |  |
| `ip_addresses` | array of string | yes |  |  |
| `operating_system` | string (nullable) | yes |  |  |
| `os_version` | string (nullable) | yes |  |  |
| `owner_id` | string (uuid) (nullable) | yes |  |  |
| `team_id` | string (uuid) (nullable) | yes |  |  |
| `department_id` | string (uuid) (nullable) | yes |  |  |
| `business_service_id` | string (uuid) (nullable) | yes |  |  |
| `criticality` | string | yes |  |  |
| `data_classification` | string | yes |  |  |
| `exposure` | string | yes |  |  |
| `environment` | string | yes |  |  |
| `location` | string (nullable) | yes |  |  |
| `tags` | array of string | yes |  |  |
| `compensating_controls` | array of string | yes |  |  |
| `source` | string | yes |  |  |
| `is_active` | boolean | yes |  |  |
| `first_seen_at` | string (date-time) (nullable) | yes |  |  |
| `last_seen_at` | string (date-time) (nullable) | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |
| `team_name` | string (nullable) | no |  |  |
| `owner_name` | string (nullable) | no |  |  |
| `department_name` | string (nullable) | no |  |  |
| `products` | array of `AssetProductOut` | no |  |  |
| `open_findings` | integer | no | default `0` |  |
| `max_risk_score` | number (nullable) | no |  |  |

#### `AssetOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `name` | string | yes |  |  |
| `asset_type` | string | yes |  |  |
| `external_id` | string (nullable) | yes |  |  |
| `hostname` | string (nullable) | yes |  |  |
| `fqdn` | string (nullable) | yes |  |  |
| `ip_addresses` | array of string | yes |  |  |
| `operating_system` | string (nullable) | yes |  |  |
| `os_version` | string (nullable) | yes |  |  |
| `owner_id` | string (uuid) (nullable) | yes |  |  |
| `team_id` | string (uuid) (nullable) | yes |  |  |
| `department_id` | string (uuid) (nullable) | yes |  |  |
| `business_service_id` | string (uuid) (nullable) | yes |  |  |
| `criticality` | string | yes |  |  |
| `data_classification` | string | yes |  |  |
| `exposure` | string | yes |  |  |
| `environment` | string | yes |  |  |
| `location` | string (nullable) | yes |  |  |
| `tags` | array of string | yes |  |  |
| `compensating_controls` | array of string | yes |  |  |
| `source` | string | yes |  |  |
| `is_active` | boolean | yes |  |  |
| `first_seen_at` | string (date-time) (nullable) | yes |  |  |
| `last_seen_at` | string (date-time) (nullable) | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |
| `team_name` | string (nullable) | no |  |  |
| `owner_name` | string (nullable) | no |  |  |
| `department_name` | string (nullable) | no |  |  |

#### `AssetProductIn`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `vendor` | string | yes | min length 1; max length 200 |  |
| `product` | string | yes | min length 1; max length 300 |  |
| `version` | string (nullable) | no | max length 120 |  |
| `install_path` | string (nullable) | no |  |  |
| `detected_by` | string | no | default `"manual"` |  |

#### `AssetProductOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `product_id` | string (uuid) | yes |  |  |
| `vendor` | string (nullable) | no |  |  |
| `product` | string (nullable) | no |  |  |
| `version` | string (nullable) | yes |  |  |
| `detected_by` | string | yes |  |  |
| `last_seen_at` | string (date-time) (nullable) | no |  |  |

#### `AssetUpdate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string (nullable) | no | min length 1; max length 255 |  |
| `asset_type` | string (nullable) | no |  |  |
| `hostname` | string (nullable) | no |  |  |
| `fqdn` | string (nullable) | no |  |  |
| `ip_addresses` | array of string (nullable) | no |  |  |
| `operating_system` | string (nullable) | no |  |  |
| `os_version` | string (nullable) | no |  |  |
| `owner_id` | string (uuid) (nullable) | no |  |  |
| `team_id` | string (uuid) (nullable) | no |  |  |
| `department_id` | string (uuid) (nullable) | no |  |  |
| `business_service_id` | string (uuid) (nullable) | no |  |  |
| `criticality` | string (nullable) | no |  |  |
| `data_classification` | string (nullable) | no |  |  |
| `exposure` | string (nullable) | no |  |  |
| `environment` | string (nullable) | no |  |  |
| `location` | string (nullable) | no |  |  |
| `compensating_controls` | array of string (nullable) | no |  |  |
| `tags` | array of string (nullable) | no |  |  |
| `attributes` | object (nullable) | no |  |  |
| `is_active` | boolean (nullable) | no |  |  |

#### `BusinessServiceCreate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes | min length 1; max length 200 |  |
| `description` | string (nullable) | no |  |  |
| `criticality` | string | no | default `"medium"` |  |
| `owner_id` | string (uuid) (nullable) | no |  |  |
| `team_id` | string (uuid) (nullable) | no |  |  |
| `revenue_per_hour` | integer (nullable) | no | ≥ 0.0 |  |
| `currency` | string | no | min length 3; max length 3; default `"CHF"` |  |
| `sla_tier` | string (nullable) | no |  |  |

#### `BusinessServiceOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `name` | string | yes |  |  |
| `description` | string (nullable) | yes |  |  |
| `criticality` | string | yes |  |  |
| `revenue_per_hour` | integer (nullable) | yes |  |  |
| `currency` | string | yes |  |  |
| `sla_tier` | string (nullable) | yes |  |  |

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `InventoryBulkIn`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `InventoryItemIn` | yes | min items 1; max items 5000 |  |
| `detected_by` | string | no | max length 60; default `"manual"` |  |
| `replace` | boolean | no | default `false` | Treat this as the complete inventory from `detected_by` and drop what it no longer reports. Only correct for a full sweep. |
| `correlate` | boolean | no | default `true` |  |

#### `InventoryHostIn`

An asset plus its software, for onboarding an existing estate in one call.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string (nullable) | no | max length 255 |  |
| `external_id` | string (nullable) | no | max length 200 |  |
| `hostname` | string (nullable) | no | max length 255 |  |
| `fqdn` | string (nullable) | no | max length 400 |  |
| `ip_addresses` | array of string | no |  |  |
| `mac_addresses` | array of string | no |  |  |
| `asset_type` | string (nullable) | no |  |  |
| `operating_system` | string (nullable) | no |  |  |
| `os_version` | string (nullable) | no |  |  |
| `environment` | string (nullable) | no |  |  |
| `criticality` | string (nullable) | no |  |  |
| `data_classification` | string (nullable) | no |  |  |
| `exposure` | string (nullable) | no |  |  |
| `location` | string (nullable) | no |  |  |
| `items` | array of `InventoryItemIn` | no |  |  |

#### `InventoryImportIn`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `hosts` | array of `InventoryHostIn` | yes | min items 1; max items 2000 |  |
| `detected_by` | string | no | max length 60; default `"cmdb"` |  |
| `replace` | boolean | no | default `false` |  |
| `correlate` | boolean | no | default `true` |  |

#### `InventoryItemIn`

One piece of installed software.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `cpe` | string (nullable) | no | max length 600 | CPE 2.3 string, e.g. cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:* |
| `vendor` | string (nullable) | no | max length 200 |  |
| `product` | string (nullable) | no | max length 300 |  |
| `version` | string (nullable) | no | max length 120 | Upstream version. CVE ranges are expressed in upstream terms only. |
| `raw_version` | string (nullable) | no | max length 200 | What the package manager reported verbatim, e.g. 1:1.24.0-2ubuntu7.1. Kept for the analyst: a distro that backports a fix leaves the upstream version unchanged, so a match on `version` alone can be already-remediated. |
| `install_path` | string (nullable) | no |  |  |
| `detected_by` | string (nullable) | no |  |  |

#### `Page_AssetOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `AssetOut` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `Page_BusinessServiceOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `BusinessServiceOut` | yes |  |  |
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
