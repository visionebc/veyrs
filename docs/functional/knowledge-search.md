---
title: Documents, knowledge base, threat news and search
purpose: Describe how VEYRS stores and analyses uploaded documents, runs the versioned knowledge base, ingests threat news and answers global and semantic searches.
scope: Routes tagged `intelligence & knowledge` (documents, intel sources/articles/news, knowledge, search, wiki publishing) and their services; the AI assistant that retrieves through search is in ai.md.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/api/v1/knowledge.py, backend/veyrs/services/documents.py, backend/veyrs/services/threatintel.py, backend/veyrs/services/search.py, backend/veyrs/services/docs.py]
related: [api/reference/intelligence-knowledge.md, functional/ai.md, functional/threat-intelligence.md, integrations/README.md, database/README.md]
---

# Documents, knowledge base, threat news and search

Reference per endpoint: [../api/reference/intelligence-knowledge.md](../api/reference/intelligence-knowledge.md). Router: `api/v1/knowledge.py` (`tags=["intelligence & knowledge"]`, no prefix). The tag is in `EXEMPT_TAGS` (`security/scope.py:78`): every row here is tenant-scoped by `organization_id` but not narrowed by team.

## Documents

### Upload and analyse

| Item | Detail |
|---|---|
| What | `POST /documents` (multipart `file`) stores a document, extracts text, classifies it, extracts entities and optionally correlates. |
| Why | Vendor advisories and scan reports carry CVE ids, versions and fixes that should link to the estate. |
| How it works | `upload_document` (`api/v1/knowledge.py:160`) reads at most `MAX_UPLOAD_BYTES` = 32 MiB + 1 (`:27`), then `documents.ingest` (`services/documents.py:314`): SHA-256 content hash, **dedupe per organization** (same bytes return the existing row with `created=False` and metadata is not overwritten); `extract_text` (`:80`) handles text/markdown/log, JSON, CSV, HTML (tags stripped textually, scripts removed), XML/`.nessus` (entity resolution disabled via `xmlsafe`), PDF (needs `pypdf`), DOCX; unsupported types set status `unsupported_format`, unexpected failures `failed` (no 500). `classify` (`:205`) picks `vendor_advisory`, `scan_report`, `runbook`, `policy`, `news` or `other` by keyword. `extract_entities` (`:221`) finds CVE, CWE, CVSS vectors/scores, versions, severities, fixed-in versions, products. Only CVE ids present in the `cve` table are stored in `cve_ids`; others are reported as `unknown_cves`. Text is chunked (1 200 chars, 150 overlap) into `document_chunks`. If `correlate` (default true) and CVEs were found, `correlation.correlate_batch` runs. |
| How to use | Console: Intelligence > Documents & Advisories. Query: `data_classification` (default `internal`), `correlate`, `title`, `notes`, `team_id`, `vendor_id`. |
| Permissions | `document:write` |
| Data | `documents`, `document_chunks`, `cve`, `audit_log` |
| Errors | 413 over 32 MiB; 422 `empty upload`, `unknown team` (another tenant's team counts as unknown), `unknown vendor`. |
| Exceptional | Text beyond `MAX_TEXT_CHARS` (4 000 000) is a risk of a dump, not a document; scanned PDFs with no text yield status `needs_ocr` (OCR is not performed: `ocr_used` is always false). The upload is audited as `document.upload`. |
| Status | Implemented (`tests/test_phase10_hardening.py`, `test_write_paths.py` exercise the route) |

### List, read, edit, delete

| Item | Detail |
|---|---|
| What | `GET /documents`, `GET /documents/{document_id}`, `PATCH /documents/{document_id}`, `DELETE /documents/{document_id}`. |
| How it works | `list_documents` (`:280`) filters `doc_class`, `status`, `team_id`, `vendor_id`, `cve_id` (matches extracted **and** hand-attached CVEs), `q` (title or filename ILIKE), `page`, `size` (max 200); team and vendor names are resolved with two batched lookups. `get_document` (`:330`) adds `extracted`, `unknown_cves`, `chunk_count`, 2 000-char `text_preview`. `patch_document` (`:343`) edits only operator metadata: `title`, `notes`, `team_id`, `vendor_id`, `doc_class`, `data_classification`, `manual_cve_ids` (full replacement) and `clear` (names among `team_id,vendor_id,title,notes,doc_class` to null). `filename` is not editable. `delete_document` (`:429`) returns 204. |
| Permissions | `document:read` (GET), `document:write` (PATCH), `document:delete` (DELETE) |
| Errors | 404 `document not found` (also for another tenant's id); PATCH 422 for `cannot clear ...`, `nothing to change`, `unknown team`, `unknown vendor`, `not in the CVE catalogue: ...` (a document may reference a vulnerability but cannot invent one). |
| Status | Implemented |

## Threat news, sources and articles

### Sources, ingest and digest

| Item | Detail |
|---|---|
| What | `GET /intel/sources`, `POST /intel/sources`, `POST /intel/articles`, `GET /intel/news`. |
| Why | Per-tenant news sources (RSS, advisories) ranked by relevance to the tenant's inventory. |
| How it works | `create_source` (`:465`) stores a `ThreatSource` (`slug` unique per tenant, `trust` 0-1, `poll_interval_minutes` 5-10080). `ingest_articles` route (`:486`, up to 500 entries) calls `threatintel.ingest_articles` (`services/threatintel.py:82`): idempotent on (organization, content hash of title+url+body); extracts entities with the document extractor; keeps only known CVE ids; `confidence` = source trust x (1.0 with CVEs, else 0.6); `relevant_asset_count` via `relevance` (`:54`) counting distinct active assets reachable from the article's CVEs or products; `is_relevant` when > 0. `feed_digest` (`:151`) returns the last `days` (1-365, default 7) ordered relevant first, then asset count, then date, capped by `limit` (1-200). |
| Important | VEYRS **stores** what is posted. The routes here do not fetch the feed URL; polling is performed elsewhere (`last_polled_at` is updated only by ingest). Fetching is not implemented in this module. |
| Permissions | `intel:read` (sources, news), `intel:write` (create source, ingest) |
| Errors | `POST /intel/sources` 409 `slug already exists`; `POST /intel/articles` 404 `source not found` when `source_slug` does not exist; 422 body validation (entries 1-500). |
| Status | Implemented |

## Knowledge base

### Articles and revisions

| Item | Detail |
|---|---|
| What | `GET /knowledge`, `POST /knowledge`, `GET /knowledge/{article_id}`, `PATCH /knowledge/{article_id}`, `GET /knowledge/{article_id}/revisions/{version}`. |
| Why | Runbooks and guides linked to CVEs, products and CWEs, with history. |
| How it works | `create_article` (`services/threatintel.py:184`) writes version 1 and a revision labelled `created`; slug defaults to `slugify(title)` and 409 on duplicates. `update_article` (`:220`) increments `version` and writes a revision only when title or body changed. Article-level access: `required_permissions` (any-of); `visible_to` (`:269`) hides articles the caller lacks permission for; the detail route returns **404**, not 403, to hide existence. `list_articles` (`api/v1/knowledge.py:529`) filters kind, tag, `cve_id`, `published_only` (default **true**) and applies the visibility check in Python before paginating so counts match what the caller may open. `get_article` increments `view_count` on every read. |
| How to use | Console: Intelligence > Knowledge Base. |
| Permissions | `knowledge:read`, `knowledge:write` |
| Data | `knowledge_articles`, `knowledge_revisions` |
| Errors | 404 `article not found` / `revision not found`; 409 `slug already exists`; 422 validation (`title` 1-400, `body` required). |
| Exceptional | See "Known defects" below: `PATCH` uses the create schema. |
| Status | Implemented (`tests/test_phase5_intel_docs.py`) |

### Publish to a wiki (Confluence)

| Item | Detail |
|---|---|
| What | `POST /knowledge/{article_id}/publish?connector_id=`, `GET /knowledge/{article_id}/publications`, `GET /knowledge-publishing`. |
| Why | Push runbooks to the team wiki while VEYRS stays the system of record (one-way, nothing is pulled back). |
| How it works | `publish_article` route (`:726`) selects `ItsmConnector` rows whose `system` is in `DOCS_SYSTEMS` (= `{"confluence"}`, `services/docs.py:61`). `docs.publish_article` (`:392`) is idempotent by payload digest, creates or updates the page through `ConfluenceAdapter` and records an `ExternalLink` (`object_type="knowledge"`). Markdown is converted by `markdown_to_storage` (headings, paragraphs, lists, fenced code, inline code, bold, italic, links). `GET /knowledge-publishing` (`:819`) reports `ready` only when a connector has credentials **and** a `space_key`. |
| Permissions | `knowledge:write` (publish), `knowledge:read` (others) |
| Errors | 404 article; 409 `no Confluence connector is configured`, 409 `more than one documentation connector exists; name the one ... ?connector_id=`; 502 remote refusal or unreachable wiki (`last_error` is kept on the connector). |
| Dependencies | Connector configuration: [integrations.md](integrations.md), [../integrations/README.md](../integrations/README.md). |
| Status | Implemented (`tests/test_phase44_confluence.py`; live `GET /knowledge-publishing` returned `ready:false`, no connector) |

## Search

### Global lexical search

| Item | Detail |
|---|---|
| What | `GET /search?q=&types=&limit_per_type=` (q 1-200 chars, limit 1-50). |
| How it works | `search.search` (`services/search.py:53`) runs ILIKE across `cve`, `vulnerability`, `finding`, `asset`, `product`, `ticket`, `document` (filename or text), `knowledge`, `news`. Each entity type is gated by `ENTITY_PERMISSIONS` (`:36`); types the caller may not read appear in `denied_types` so "no results" and "not allowed" differ. Knowledge results also apply `required_permissions`. The AI assistant retrieves through this same function. |
| Permissions | Authenticated only at the route; per-type permission in the service (`cve:read`, `vulnerability:read`, `finding:read`, `asset:read`, `product:read`, `ticket:read`, `document:read`, `knowledge:read`, `intel:read`). Superusers bypass. |
| Exceptional | Despite the docstring, queries use `ILIKE '%term%'`, not `to_tsvector`. Finding search matches only the title. The route does not apply team scope to findings or assets (the tag is exempt): a team-restricted user can see finding and asset titles from other teams through search. |
| Status | Verified (observed live: `q=CVE-2023-44487` returned cve, vulnerability and finding hits) |

### Semantic search

| Item | Detail |
|---|---|
| What | `GET /search/semantic?q=&limit=` (q 1-500). |
| How it works | `semantic_search` (`services/search.py:261`) uses a pluggable `VectorBackend`. The default is `NullVectorBackend` (`available=False`); no concrete backend is registered in the code base (only `search.py` and a model comment mention Qdrant). Without a backend, or if the backend raises, it falls back to lexical search over document and knowledge and returns `mode:"lexical"` with a `note`. |
| Status | Partial: live response was `mode: lexical`, `note: semantic search is not configured`. |

## Known defects and caveats (from code reading)

1. `PATCH /knowledge/{id}` validates against `KnowledgeUpdate` (since 0.41.0): every field is optional and only the fields the client sent are applied, so a partial update can no longer unpublish an article or clear its permissions. An explicit `[]` still clears a list on purpose.
2. `update_article` stores the **new** title and body under the new version number, so revision N is the text of version N (its docstring now says so).
3. `GET /knowledge/{id}` is read-only since 0.41.0; the view counter is incremented by `POST /knowledge/{id}/view` (204, `knowledge:read`).
4. `/intel/articles` answers 200 (it answered 202 before 0.41.0) and processes synchronously.

## Errors summary

| Code | Conditions |
|---|---|
| 401 | Missing or invalid credentials. |
| 403 | Missing the permission listed per feature. |
| 404 | Unknown document, article, revision, source; article hidden by `required_permissions`. |
| 409 | Duplicate slug; connector ambiguity or absence on publish. |
| 413 | Document larger than 32 MiB. |
| 422 | Validation, empty upload, unknown team/vendor/CVE. |
| 502 | Wiki publish failed. |
