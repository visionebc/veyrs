---
title: API reference: threat intelligence
purpose: Every HTTP endpoint tagged `threat intelligence`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: threat intelligence

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


14 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `GET` | [`/api/v1/intel/cve`](#get-apiv1intelcve) | Search CVEs | Authenticated | `cve:read` |
| `GET` | [`/api/v1/intel/cve/{cve_id}`](#get-apiv1intelcvecve_id) | CVE detail with CVSS/EPSS/KEV breakdown | Authenticated | `cve:read` |
| `GET` | [`/api/v1/intel/cve/{cve_id}/epss-history`](#get-apiv1intelcvecve_idepss-history) | EPSS trend | Authenticated | `cve:read` |
| `GET` | [`/api/v1/intel/cve/{cve_id}/exposure`](#get-apiv1intelcvecve_idexposure) | This tenant's exposure to a CVE | Authenticated | `finding:read` |
| `GET` | [`/api/v1/intel/cwe/{cwe_id}`](#get-apiv1intelcwecwe_id) | CWE detail | Authenticated | `cve:read` |
| `POST` | [`/api/v1/intel/feeds/epss`](#post-apiv1intelfeedsepss) | Ingest EPSS scores; runs synchronously, answers 200 | Platform admin | - |
| `POST` | [`/api/v1/intel/feeds/kev`](#post-apiv1intelfeedskev) | Ingest CISA KEV; runs synchronously, answers 200 | Platform admin | - |
| `POST` | [`/api/v1/intel/feeds/nvd`](#post-apiv1intelfeedsnvd) | Ingest NVD 2.0 records (platform administrators); runs synchronously, answers 200 | Platform admin | - |
| `GET` | [`/api/v1/intel/feeds/runs`](#get-apiv1intelfeedsruns) | Feed run history | Authenticated | `intel:read` |
| `GET` | [`/api/v1/intel/health`](#get-apiv1intelhealth) | Freshness of every intelligence feed | Authenticated | `intel:read` |
| `GET` | [`/api/v1/intel/kev`](#get-apiv1intelkev) | CISA KEV catalogue | Authenticated | `cve:read` |
| `GET` | [`/api/v1/intel/schedule`](#get-apiv1intelschedule) | How often each intelligence feed refreshes | Authenticated | `intel:read` |
| `PUT` | [`/api/v1/intel/schedule`](#put-apiv1intelschedule) | Change how often the intelligence feeds refresh | Authenticated | `intel:write` |
| `GET` | [`/api/v1/intel/vendors`](#get-apiv1intelvendors) | Search the shared vendor dictionary | Authenticated | `cve:read` |

## GET /api/v1/intel/cve

**Search CVEs**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `cve:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/intel.py:56` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `q` | query | string (nullable) | no |  | Free text over id/title/description |
| `affects_estate` | query | boolean | no | default `true` | Only CVEs whose applicability names software this organization actually runs. ON by default: the catalogue is the index, not the worklist. Turn it off to research a CVE for software you are considering, or to check a bulletin against the full corpus. |
| `exposed` | query | boolean | no | default `false` | Only CVEs with at least one OPEN finding in this organization. Narrower than affects_estate, which matches the product name and does not compare versions. |
| `kev` | query | boolean (nullable) | no |  |  |
| `min_cvss` | query | number (nullable) | no | ≥ 0.0; ≤ 10.0 |  |
| `min_epss` | query | number (nullable) | no | ≥ 0.0; ≤ 1.0 |  |
| `cwe` | query | string (nullable) | no |  |  |
| `published_after` | query | string (date) (nullable) | no |  |  |
| `order` | query | string | no | pattern ^(risk\|published\|epss\|cvss\|id)$; default `"risk"` |  |
| `page` | query | integer | no | ≥ 1; default `1` |  |
| `size` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_CveSummary_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/intel/cve/{cve_id}

**CVE detail with CVSS/EPSS/KEV breakdown**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `cve:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/intel.py:146` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `cve_id` | path | string | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/intel/cve/{cve_id}/epss-history

**EPSS trend**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `cve:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/intel.py:232` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `cve_id` | path | string | yes |  |  |
| `days` | query | integer | no | ≥ 1; ≤ 3650; default `90` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/intel/cve/{cve_id}/exposure

**This tenant's exposure to a CVE**

The bridge between global intelligence and tenant reality.

`assets` is what the console's "Affected assets" table renders: one row per asset with an OPEN finding, carrying the asset's own name, criticality and exposure. Until 0.35.1 the route returned only `findings` (bare asset ids) while the console read `assets`, so the table said "Not present in your inventory" under a stat card that said 5 -- two claims on one screen, one of them false.

Every vulnerability row for the CVE counts (the unique key is org + cve + internal_ref, so there can be several), and the finding list is narrowed to the caller's team scope like every other finding read.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `finding:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/intel.py:158` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `cve_id` | path | string | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/intel/cwe/{cwe_id}

**CWE detail**

The weakness class, plus how much of it this tenant is carrying.

`name` is null while the row is still the placeholder an NVD identifier created — reporting the id as its own name would make an un-ingested dictionary look like an ingested one.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `cve:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/intel.py:294` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `cwe_id` | path | string | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/intel/feeds/epss

**Ingest EPSS scores; runs synchronously, answers 200**

EPSS changes urgency, never applicability, so this rescores; it does not correlate. See `services.intel_pipeline` for why that distinction matters.

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/intel.py:366` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `correlate` | query | boolean | no | default `true` | Rescore affected findings |

**Request body** (`application/json`, required): `EpssIngestRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/intel/feeds/kev

**Ingest CISA KEV; runs synchronously, answers 200**

Known exploitation is the single biggest urgency signal in the model, so a KEV import rescores every open finding for the CVEs it touched.

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/intel.py:387` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `correlate` | query | boolean | no | default `true` | Rescore affected findings |

**Request body** (`application/json`, required): `KevIngestRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/intel/feeds/nvd

**Ingest NVD 2.0 records (platform administrators); runs synchronously, answers 200**

Ingest CVE records and, by default, tell the tenants they are affected.

Ingestion without correlation was the original behaviour and it was a trap: the CVE landed, no finding was raised, and the estate only discovered it the next time somebody happened to edit an asset.

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/intel.py:338` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `correlate` | query | boolean | no | default `true` | Run the ingested CVEs against every tenant's inventory. Turn off only for a bulk backfill you intend to correlate afterwards in one pass. |

**Request body** (`application/json`, required): `NvdIngestRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/intel/feeds/runs

**Feed run history**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `intel:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/intel.py:406` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `feed` | query | string (nullable) | no |  |  |
| `page` | query | integer | no | ≥ 1; default `1` |  |
| `size` | query | integer | no | ≥ 1; ≤ 200; default `25` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_FeedRunOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/intel/health

**Freshness of every intelligence feed**

Stale intelligence is silently wrong prioritisation, so surface it.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `intel:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/intel.py:556` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/intel/kev

**CISA KEV catalogue**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `cve:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/intel.py:243` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `affects_estate` | query | boolean | no | default `true` | Only KEV entries for software this organization runs. Same lens, same default and same helper as /intel/cve. |
| `exposed` | query | boolean | no | default `false` | Only KEV entries with at least one OPEN finding in this organization. Narrower than affects_estate, which matches the product name and does not compare versions. |
| `due_within_days` | query | integer (nullable) | no | ≥ 0; ≤ 3650 |  |
| `page` | query | integer | no | ≥ 1; default `1` |  |
| `size` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/intel/schedule

**How often each intelligence feed refreshes**

This tenant's requested cadence next to the one actually in force.

Read is open to anyone who can read intelligence: an analyst looking at a two-day-old EPSS score needs to be able to tell "the feed is configured weekly" from "the feed is broken" without asking an administrator.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `intel:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/intel.py:490` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PUT /api/v1/intel/schedule

**Change how often the intelligence feeds refresh**

Set the cadence per feed.

Refused to a team-scoped identity: the corpus is shared by the whole deployment, so this is not a decision that can be narrowed to one team's slice of the estate -- it can only be made for everybody or not at all.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `intel:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/intel.py:504` |

**Request body** (`application/json`, required): `IntelScheduleUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/intel/vendors

**Search the shared vendor dictionary**

The `vendors` table, made reachable.

Worth being blunt about what this is, because the name invites the wrong reading: **this is not third-party risk management.** `vendors` and `products` are the global CPE dictionary that arrives with NVD -- the rows that let "nginx 1.24 on this host" and "this CVE applies to nginx < 1.25" join. They are shared by every tenant and nobody's supplier register.

What IS tenant-specific is `installations`: how many of *your* asset products point at that vendor. Returning both in one row is the whole point -- a dictionary of 30 000 vendors is noise until you can see which twelve of them you actually run.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `cve:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/intel.py:424` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `q` | query | string (nullable) | no |  | Substring of the vendor name. |
| `in_use` | query | boolean | no | default `false` | Only vendors whose products this organization actually runs. |
| `page` | query | integer | no | ≥ 1; default `1` |  |
| `size` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_dict_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## Schemas

Request and response models used on this page.

#### `CveSummary`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `cve_id` | string | yes |  |  |
| `title` | string (nullable) | yes |  |  |
| `severity` | string (nullable) | yes |  |  |
| `cvss_score` | number (nullable) | yes |  |  |
| `cvss_vector` | string (nullable) | yes |  |  |
| `epss_score` | number (nullable) | yes |  |  |
| `epss_percentile` | number (nullable) | yes |  |  |
| `kev` | boolean | yes |  |  |
| `kev_due_date` | string (date) (nullable) | yes |  |  |
| `published_at` | string (date-time) (nullable) | yes |  |  |
| `age_days` | integer (nullable) | yes |  |  |
| `affected_assets` | integer (nullable) | no |  |  |

#### `EpssIngestRequest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `scored_on` | string (date) (nullable) | no |  |  |
| `model_version` | string (nullable) | no |  |  |
| `rows` | array of `EpssRow` | yes |  |  |

#### `EpssRow`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `cve` | string | yes |  |  |
| `epss` | number | yes |  |  |
| `percentile` | number | yes |  |  |

#### `FeedRunOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `feed` | string | yes |  |  |
| `status` | string | yes |  |  |
| `started_at` | string (date-time) | yes |  |  |
| `finished_at` | string (date-time) (nullable) | yes |  |  |
| `records_seen` | integer | yes |  |  |
| `records_created` | integer | yes |  |  |
| `records_updated` | integer | yes |  |  |
| `watermark` | string (nullable) | yes |  |  |
| `error` | string (nullable) | yes |  |  |

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `IntelFeedScheduleIn`

One feed's cadence. Both fields optional so a client can change one.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `enabled` | boolean (nullable) | no |  |  |
| `interval_minutes` | integer (nullable) | no | ≥ 60.0; ≤ 43200.0 |  |

#### `IntelScheduleUpdate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `feeds` | object | no |  |  |

#### `KevIngestRequest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `catalogVersion` | string (nullable) | no |  |  |
| `vulnerabilities` | array of object | no |  |  |

#### `NvdIngestRequest`

NVD 2.0 payload, either the whole envelope or a bare list.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `vulnerabilities` | array of object | no |  |  |

#### `Page_CveSummary_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `CveSummary` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `Page_FeedRunOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `FeedRunOut` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

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
