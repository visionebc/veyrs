---
title: API reference: intelligence & knowledge
purpose: Every HTTP endpoint tagged `intelligence & knowledge`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: intelligence & knowledge

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


20 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `GET` | [`/api/v1/documents`](#get-apiv1documents) | List documents | Authenticated | `document:read` |
| `POST` | [`/api/v1/documents`](#post-apiv1documents) | Upload and analyse a document | Authenticated | `document:write` |
| `DELETE` | [`/api/v1/documents/{document_id}`](#delete-apiv1documentsdocument_id) | Delete a document | Authenticated | `document:delete` |
| `GET` | [`/api/v1/documents/{document_id}`](#get-apiv1documentsdocument_id) | Document detail with extracted entities | Authenticated | `document:read` |
| `PATCH` | [`/api/v1/documents/{document_id}`](#patch-apiv1documentsdocument_id) | Edit a document's title, notes, owner, vendor and CVEs | Authenticated | `document:write` |
| `POST` | [`/api/v1/intel/articles`](#post-apiv1intelarticles) | Ingest feed entries; runs synchronously, answers 200 | Authenticated | `intel:write` |
| `GET` | [`/api/v1/intel/news`](#get-apiv1intelnews) | Relevance-ordered intelligence digest | Authenticated | `intel:read` |
| `GET` | [`/api/v1/intel/sources`](#get-apiv1intelsources) | List feeds | Authenticated | `intel:read` |
| `POST` | [`/api/v1/intel/sources`](#post-apiv1intelsources) | Register a feed | Authenticated | `intel:write` |
| `GET` | [`/api/v1/knowledge`](#get-apiv1knowledge) | List articles | Authenticated | `knowledge:read` |
| `POST` | [`/api/v1/knowledge`](#post-apiv1knowledge) | Create an article | Authenticated | `knowledge:write` |
| `GET` | [`/api/v1/knowledge-publishing`](#get-apiv1knowledge-publishing) | Is wiki publishing configured? | Authenticated | `knowledge:read` |
| `GET` | [`/api/v1/knowledge/{article_id}`](#get-apiv1knowledgearticle_id) | Article detail | Authenticated | `knowledge:read` |
| `PATCH` | [`/api/v1/knowledge/{article_id}`](#patch-apiv1knowledgearticle_id) | Update an article (versioned) | Authenticated | `knowledge:write` |
| `GET` | [`/api/v1/knowledge/{article_id}/publications`](#get-apiv1knowledgearticle_idpublications) | Where this article has been published | Authenticated | `knowledge:read` |
| `POST` | [`/api/v1/knowledge/{article_id}/publish`](#post-apiv1knowledgearticle_idpublish) | Publish an article to the wiki | Authenticated | `knowledge:write` |
| `GET` | [`/api/v1/knowledge/{article_id}/revisions/{version}`](#get-apiv1knowledgearticle_idrevisionsversion) | Read a past revision | Authenticated | `knowledge:read` |
| `POST` | [`/api/v1/knowledge/{article_id}/view`](#post-apiv1knowledgearticle_idview) | Record that the article was opened | Authenticated | `knowledge:read` |
| `GET` | [`/api/v1/search`](#get-apiv1search) | Global search across the graph | Authenticated | - |
| `GET` | [`/api/v1/search/semantic`](#get-apiv1searchsemantic) | Semantic search (falls back to lexical) | Authenticated | - |

## GET /api/v1/documents

**List documents**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `document:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:297` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `doc_class` | query | string (nullable) | no |  |  |
| `status` | query | string (nullable) | no |  |  |
| `team_id` | query | string (uuid) (nullable) | no |  |  |
| `vendor_id` | query | string (uuid) (nullable) | no |  |  |
| `cve_id` | query | string (nullable) | no |  | Documents referencing this CVE, whether the extractor found it or a person attached it. |
| `q` | query | string (nullable) | no |  | Substring of the title or filename. |
| `page` | query | integer | no | ≥ 1; default `1` |  |
| `size` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_DocumentOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/documents

**Upload and analyse a document**

Upload, extract, and optionally file the document in one call.

The metadata is accepted here as well as on `PATCH` because the moment somebody has the advisory in front of them is the moment they know which vendor and which team it belongs to. Forcing a second request is how a library ends up full of untitled, unowned PDFs.

**An upload that DEDUPES does not overwrite existing metadata.** The same bytes uploaded twice return the first row (the content hash is unique per organization); silently replacing a title somebody wrote with whatever the second uploader happened to type would lose work with no trace.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `document:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/knowledge.py:177` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `data_classification` | query | string | no | default `"internal"` |  |
| `correlate` | query | boolean | no | default `true` |  |
| `title` | query | string (nullable) | no | max length 400 |  |
| `notes` | query | string (nullable) | no | max length 20000 |  |
| `team_id` | query | string (uuid) (nullable) | no |  |  |
| `vendor_id` | query | string (uuid) (nullable) | no |  |  |

**Request body** (`multipart/form-data`, required): `Body_upload_document_api_v1_documents_post`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `DocumentDetail` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/documents/{document_id}

**Delete a document**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `document:delete` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/knowledge.py:446` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `document_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/documents/{document_id}

**Document detail with extracted entities**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `document:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:347` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `document_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `DocumentDetail` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/documents/{document_id}

**Edit a document's title, notes, owner, vendor and CVEs**

Edit the operator-owned metadata. Extraction output stays read-only.

Three refusals worth naming, because each is a way this could quietly go wrong:

* **An unknown team or vendor is rejected, not stored.** A dangling id renders as a blank column and looks like the field was never filled in. * **A CVE that is not in the catalogue is rejected.** `documents.py` has always validated extracted CVEs against the `cves` table for exactly this reason -- a document may reference a vulnerability, never invent one -- and a hand-attached identifier is not more trustworthy than a parsed one. A typo would otherwise create a link that can never resolve. * **`filename` is not editable.** It is what the uploader's disk called the bytes the content hash was taken over; `title` is the field for a nicer name.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `document:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:360` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `document_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `DocumentPatch`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `DocumentDetail` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/intel/articles

**Ingest feed entries; runs synchronously, answers 200**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `intel:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:503` |

**Request body** (`application/json`, required): `ArticleIngest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/intel/news

**Relevance-ordered intelligence digest**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `intel:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:527` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `days` | query | integer | no | ≥ 1; ≤ 365; default `7` |  |
| `limit` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/intel/sources

**List feeds**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `intel:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:469` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `ThreatSourceOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/intel/sources

**Register a feed**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `intel:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/knowledge.py:482` |

**Request body** (`application/json`, required): `ThreatSourceWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `ThreatSourceOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/knowledge

**List articles**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `knowledge:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:546` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `kind` | query | string (nullable) | no |  |  |
| `tag` | query | string (nullable) | no |  |  |
| `cve_id` | query | string (nullable) | no |  |  |
| `published_only` | query | boolean | no | default `true` |  |
| `page` | query | integer | no | ≥ 1; default `1` |  |
| `size` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_KnowledgeOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/knowledge

**Create an article**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `knowledge:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/knowledge.py:580` |

**Request body** (`application/json`, required): `KnowledgeWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `KnowledgeDetail` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/knowledge-publishing

**Is wiki publishing configured?**

What the console needs to decide whether to draw a Publish button.

`ready` means a connector exists AND carries a credential AND names a space -- not merely that a row exists. The phase 42 lesson: a source created disabled and with no token reported `ready: true`, and pressing the button surfaced the remote's bare 403, which reads as "the wiki is broken" rather than "you never gave VEYRS a token".

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `knowledge:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:855` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/knowledge/{article_id}

**Article detail**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `knowledge:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:626` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `article_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `KnowledgeDetail` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/knowledge/{article_id}

**Update an article (versioned)**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `knowledge:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:662` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `article_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `KnowledgeUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `KnowledgeDetail` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/knowledge/{article_id}/publications

**Where this article has been published**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `knowledge:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:833` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `article_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/knowledge/{article_id}/publish

**Publish an article to the wiki**

One-way, idempotent, and VEYRS stays the system of record.

Nothing is ever pulled back from Confluence. A wiki page anybody can edit is not a source of truth for a security procedure -- if it were, "who changed the remediation steps for CVE-2023-44487?" would have no answer, which is precisely the question a runbook exists to make answerable. The published page carries a footer saying so, so the first person to edit it there knows they are editing a mirror.

Re-publishing an unchanged article is a no-op by digest: without that, a scheduled publish would put hundreds of empty revisions into the page's history and bury its real edits.

`connector_id` is optional; with one documentation connector configured it is unambiguous, and naming it is only needed for a second space.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `knowledge:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:762` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `article_id` | path | string (uuid) | yes |  |  |
| `connector_id` | query | string (uuid) (nullable) | no |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/knowledge/{article_id}/revisions/{version}

**Read a past revision**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `knowledge:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:683` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `article_id` | path | string (uuid) | yes |  |  |
| `version` | path | integer | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/knowledge/{article_id}/view

**Record that the article was opened**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `knowledge:read` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/knowledge.py:642` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `article_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/search

**Global search across the graph**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:708` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `q` | query | string | yes | min length 1; max length 200 |  |
| `types` | query | string (nullable) | no |  | Comma-separated entity types |
| `limit_per_type` | query | integer | no | ≥ 1; ≤ 50; default `10` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/search/semantic

**Semantic search (falls back to lexical)**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/knowledge.py:724` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `q` | query | string | yes | min length 1; max length 500 |  |
| `limit` | query | integer | no | ≥ 1; ≤ 50; default `10` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## Schemas

Request and response models used on this page.

#### `ArticleIngest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `source_slug` | string (nullable) | no |  |  |
| `entries` | array of object | yes | min items 1; max items 500 |  |

#### `Body_upload_document_api_v1_documents_post`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `file` | string | yes |  |  |

#### `DocumentDetail`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `filename` | string | yes |  |  |
| `title` | string (nullable) | no |  |  |
| `notes` | string (nullable) | no |  |  |
| `content_type` | string | yes |  |  |
| `size_bytes` | integer | yes |  |  |
| `status` | string | yes |  |  |
| `error` | string (nullable) | yes |  |  |
| `doc_class` | string (nullable) | yes |  |  |
| `page_count` | integer (nullable) | yes |  |  |
| `cve_ids` | array of string | yes |  |  |
| `manual_cve_ids` | array of string | no |  |  |
| `team_id` | string (uuid) (nullable) | no |  |  |
| `vendor_id` | string (uuid) (nullable) | no |  |  |
| `data_classification` | string | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |
| `team_name` | string (nullable) | no |  |  |
| `vendor_name` | string (nullable) | no |  |  |
| `all_cve_ids` | array of string | no |  |  |
| `extracted` | object | no |  |  |
| `unknown_cves` | array of string | no |  |  |
| `chunk_count` | integer | no | default `0` |  |
| `text_preview` | string (nullable) | no |  |  |

#### `DocumentOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `filename` | string | yes |  |  |
| `title` | string (nullable) | no |  |  |
| `notes` | string (nullable) | no |  |  |
| `content_type` | string | yes |  |  |
| `size_bytes` | integer | yes |  |  |
| `status` | string | yes |  |  |
| `error` | string (nullable) | yes |  |  |
| `doc_class` | string (nullable) | yes |  |  |
| `page_count` | integer (nullable) | yes |  |  |
| `cve_ids` | array of string | yes |  |  |
| `manual_cve_ids` | array of string | no |  |  |
| `team_id` | string (uuid) (nullable) | no |  |  |
| `vendor_id` | string (uuid) (nullable) | no |  |  |
| `data_classification` | string | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |
| `team_name` | string (nullable) | no |  |  |
| `vendor_name` | string (nullable) | no |  |  |
| `all_cve_ids` | array of string | no |  |  |

#### `DocumentPatch`

Operator-editable metadata. Extraction output is NOT editable here.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `title` | string (nullable) | no | max length 400 |  |
| `notes` | string (nullable) | no | max length 20000 |  |
| `team_id` | string (uuid) (nullable) | no |  |  |
| `vendor_id` | string (uuid) (nullable) | no |  |  |
| `doc_class` | string (nullable) | no | max length 40 |  |
| `data_classification` | string (nullable) | no |  |  |
| `manual_cve_ids` | array of string (nullable) | no |  |  |
| `clear` | array of string | no |  |  |

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `KnowledgeDetail`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `slug` | string | yes |  |  |
| `title` | string | yes |  |  |
| `kind` | string | yes |  |  |
| `summary` | string (nullable) | yes |  |  |
| `locale` | string | yes |  |  |
| `version` | integer | yes |  |  |
| `is_published` | boolean | yes |  |  |
| `tags` | array of string | yes |  |  |
| `cve_ids` | array of string | yes |  |  |
| `required_permissions` | array of string | yes |  |  |
| `view_count` | integer | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |
| `body` | string | yes |  |  |
| `revisions` | array of object | no |  |  |

#### `KnowledgeOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `slug` | string | yes |  |  |
| `title` | string | yes |  |  |
| `kind` | string | yes |  |  |
| `summary` | string (nullable) | yes |  |  |
| `locale` | string | yes |  |  |
| `version` | integer | yes |  |  |
| `is_published` | boolean | yes |  |  |
| `tags` | array of string | yes |  |  |
| `cve_ids` | array of string | yes |  |  |
| `required_permissions` | array of string | yes |  |  |
| `view_count` | integer | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |

#### `KnowledgeUpdate`

Partial update: only the fields the client sent are applied.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `title` | string (nullable) | no | min length 1; max length 400 |  |
| `body` | string (nullable) | no | min length 1 |  |
| `kind` | string (nullable) | no |  |  |
| `summary` | string (nullable) | no |  |  |
| `locale` | string (nullable) | no |  |  |
| `tags` | array of string (nullable) | no |  |  |
| `cve_ids` | array of string (nullable) | no |  |  |
| `product_ids` | array of string (nullable) | no |  |  |
| `cwe_ids` | array of string (nullable) | no |  |  |
| `required_permissions` | array of string (nullable) | no |  |  |
| `is_published` | boolean (nullable) | no |  |  |
| `change_note` | string (nullable) | no |  |  |

#### `KnowledgeWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `title` | string | yes | min length 1; max length 400 |  |
| `body` | string | yes | min length 1 |  |
| `kind` | string | no | default `"guide"` |  |
| `slug` | string (nullable) | no |  |  |
| `summary` | string (nullable) | no |  |  |
| `locale` | string | no | default `"en"` |  |
| `tags` | array of string | no |  |  |
| `cve_ids` | array of string | no |  |  |
| `product_ids` | array of string | no |  |  |
| `cwe_ids` | array of string | no |  |  |
| `required_permissions` | array of string | no |  |  |
| `is_published` | boolean | no | default `false` |  |
| `change_note` | string (nullable) | no |  |  |

#### `Page_DocumentOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `DocumentOut` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `Page_KnowledgeOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `KnowledgeOut` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `ThreatSourceOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `slug` | string | yes | min length 1; max length 80 |  |
| `name` | string | yes | min length 1; max length 200 |  |
| `kind` | string | no | default `"rss"` |  |
| `url` | string (nullable) | no |  |  |
| `is_enabled` | boolean | no | default `true` |  |
| `trust` | number | no | ≥ 0.0; ≤ 1.0; default `0.5` |  |
| `poll_interval_minutes` | integer | no | ≥ 5.0; ≤ 10080.0; default `60` |  |
| `tags` | array of string | no |  |  |
| `id` | string (uuid) | yes |  |  |
| `last_polled_at` | string (date-time) (nullable) | yes |  |  |
| `last_error` | string (nullable) | yes |  |  |

#### `ThreatSourceWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `slug` | string | yes | min length 1; max length 80 |  |
| `name` | string | yes | min length 1; max length 200 |  |
| `kind` | string | no | default `"rss"` |  |
| `url` | string (nullable) | no |  |  |
| `is_enabled` | boolean | no | default `true` |  |
| `trust` | number | no | ≥ 0.0; ≤ 1.0; default `0.5` |  |
| `poll_interval_minutes` | integer | no | ≥ 5.0; ≤ 10080.0; default `60` |  |
| `tags` | array of string | no |  |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |
