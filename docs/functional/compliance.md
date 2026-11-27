---
title: Compliance
purpose: Document how VEYRS models control frameworks, implementation claims, automated evidence, assessments and gaps, and what the engine deliberately refuses to claim.
scope: Backend behaviour of the `compliance` API tag and `services/compliance.py`. The built-in catalogue text lives in backend/veyrs/data/frameworks.py and is not reproduced.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/api/v1/compliance.py, backend/veyrs/services/compliance.py, backend/veyrs/models/compliance.py, backend/veyrs/data/frameworks.py, backend/veyrs/security/scope.py, tests/test_phase7_compliance.py]
related: [functional/README.md, functional/assets-inventory.md, functional/vulnerability-management.md, api/guide.md, DATABASE_SCHEMA.md]
---

# Compliance

Full per-endpoint reference: [`../api/reference/compliance.md`](../api/reference/compliance.md).

## Principles enforced in code

From the module docstring (`services/compliance.py:1-21`):

- VEYRS **never reports "compliant" or "certified"**. It reports measurements and the organization's own claims.
- `not_assessed` is a real state and counts **against** coverage.
- An automated signal can move a control from `not_assessed` to `partial` at most; `implemented` requires a human claim (`refresh_automated_evidence`, `:442-487`).
- Every response that reports coverage carries the framework's `is_partial` flag and a disclaimer (`ComplianceFramework.coverage_disclaimer`, `models/compliance.py:~100`), because exporting "92 % implemented" from a 24-of-93 catalogue to an auditor is a foreseeable misuse (`api/v1/compliance.py:1-8`).

Team scope: tag `compliance` is in `REFUSED_TAGS` (`security/scope.py:98`); team-restricted principals receive 403 on all routes.

## Data model facts that matter

| Table | Notes |
|-------|-------|
| `compliance_frameworks` | **Global** catalogue table (`models/base.py:91` lists it among the non-tenant tables), `organization_id` nullable: null means built-in or shared, set means a custom framework. Since 0.41.0 uniqueness is scoped by two partial unique indexes (schema step `step_api`): `(slug, version)` for built-ins and `(organization_id, slug, version)` for custom frameworks. |
| `compliance_controls` | Global; unique `(framework_id, ref)`; carries `normative_text` (empty for copyrighted catalogues), VEYRS' own `veyrs_guidance`, editorial `crosswalk`, `automation_signal`. |
| `control_implementations` | Tenant-scoped claim per control: `status`, `statement`, `justification`, `review_period_days` (default 365), `last_reviewed_at`, `next_review_at`, `automated_result`. |
| `compliance_evidence` | Tenant-scoped, kinds `document, screenshot, configuration, ticket, scan_result, metric, attestation, automated`; `valid_until`, `content_hash`, `is_automated`. |
| `control_risk_links` | Control to object link (`asset, finding, ticket, vulnerability, document`), unique per control and object. |
| `compliance_assessments`, `assessment_gaps` | Point-in-time audit run and generated gaps. |

Built-in frameworks seeded by `seed_frameworks` (`services/compliance.py:45`, idempotent, safe on every boot): `nist-csf` (2.0), `cis-controls` (v8), `iso-27001` (2022), `iso-27002` (2022) (`data/frameworks.py:270-272`). Statuses: `not_assessed`, `not_applicable`, `planned`, `partial`, `implemented`, `stale` (`models/compliance.py:39-46`).

## Features

### 1. List frameworks

| Item | Detail |
|------|--------|
| What | Built-in frameworks plus this organization's custom ones, each with `controls_shipped` and `disclaimer`. |
| How | `list_frameworks` `api/v1/compliance.py:120`: `organization_id IS NULL OR = caller`, ordered by slug and version; one count query per framework. |
| Use | `GET /api/v1/compliance/frameworks`. Console: Compliance. |
| Permissions | `compliance:read` |
| Status | Verified (observed live: built-in frameworks returned with the licence note and disclaimer) |

### 2. Create a custom framework

| Item | Detail |
|------|--------|
| How | `create_framework` `:143`; sets `is_builtin=false`, `is_partial=false`, the licence note `Custom framework authored by this organization.` |
| Use | `POST /api/v1/compliance/frameworks` with `slug` (max 60), `name`, `version` (max 40), `publisher`, optional `description`, `source_url`. |
| Permissions | `compliance:admin` |
| Errors | 409 `<slug> <version> already exists`. Since 0.41.0 the check covers only the built-ins and the caller's own frameworks, so another tenant's custom framework neither collides nor shows through a 409. |
| Data | `compliance_frameworks`, `audit_log` (`compliance.framework.created`). |
| Status | Implemented (test `test_custom_framework_is_scoped_to_its_creator`) |

### 3. Controls: list and licensed CSV import

| Item | Detail |
|------|--------|
| What | List controls of a framework; import a catalogue the organization licenses so a partial catalogue becomes complete without VEYRS shipping copyrighted text. |
| How | `list_controls` `:173`. `import_controls` `:188` reads the upload (max 8 MiB, `MAX_IMPORT_BYTES`), then `import_controls_csv` (`services/compliance.py:112`): UTF-8 (BOM tolerated) with Latin-1 fallback, required columns `ref` and `title`, optional `normative_text`, `theme`, `parent_ref`. Existing refs are updated (title, normative text); new refs are added with VEYRS crosswalk and guidance if known. When the total reaches `official_control_count`, `is_partial` is cleared: the flag is derived, never hand-set. |
| Use | `GET /api/v1/compliance/frameworks/{framework_id}/controls`, `POST /api/v1/compliance/frameworks/{framework_id}/controls:import` (multipart field `file`). |
| Permissions | `compliance:read`; `compliance:admin` for import. |
| Errors | 404 `framework not found` (also for another organization's custom framework, `_framework` `:521-526`); 413 `file too large`; 422 `CSV is missing required column(s): [...]`. |
| Exceptional | Built-in (null-owner) frameworks are shared by every tenant, so `_framework(..., write=True)` refuses them (403) unless the caller is a platform administrator; a tenant `compliance:admin` can import only into its own custom frameworks (fixed in 0.41.0, TD-03). The upload is read in bounded chunks (413 over 8 MB). Rows without `ref` are skipped silently. |
| Status | Implemented (tests `test_csv_import_adds_controls_and_can_clear_the_partial_flag`, `test_csv_import_rejects_a_file_without_the_required_columns`, `test_partial_import_leaves_the_flag_set`) |

### 4. Automated signals

| Item | Detail |
|------|--------|
| What | A closed registry of 12 computable signals; each returns a measurement and the derivation so an auditor can re-derive it. |
| How | `AUTOMATED_SIGNALS` `services/compliance.py:351-364`: `asset_inventory_coverage`, `product_inventory_coverage`, `asset_criticality_assigned`, `asset_classification_assigned`, `vulnerabilities_recorded`, `risk_scoring_active`, `findings_have_owners`, `remediation_within_sla`, `no_overdue_kev`, `scan_recency`, `internet_asset_scan_recency`, `threat_feeds_active`. A signal passes at ratio >= `SIGNAL_PASS_RATIO` 0.9. A control whose `automation_signal` is not in the registry simply has no automated evidence; there is no dynamic dispatch. |
| Use | `GET /api/v1/compliance/signals` evaluates every signal now (`list_signals` `:255`); `POST /api/v1/compliance/frameworks/{framework_id}/refresh-signals` (`:234`) records each result as `automated` evidence with a SHA-256 content hash and updates `automated_result`; a passing signal lifts a `not_assessed` control to `partial`. Response `{evaluated, promoted_to_partial}`. |
| Permissions | `compliance:read` (signals), `compliance:write` (refresh). |
| Data | `control_implementations`, `compliance_evidence` (one new row per control per refresh, so evidence accumulates), `audit_log`. |
| Status | Verified for `GET /signals` (observed live: ratios such as 101 of 101 assets with hostname, 11 of 101 assets with software). Refresh is Implemented (tests `test_automated_evidence_never_reaches_implemented`, `test_automated_evidence_is_recorded_with_a_hash`). |

### 5. Control implementation claim

| Item | Detail |
|------|--------|
| What | The organization's own statement about a control. |
| How | `set_implementation` `:273` -> `service.set_status` (`:404`): status must be valid; `not_applicable` **requires a justification** (422 otherwise); sets `last_reviewed_at` and `next_review_at = now + review_period_days` (0 means no expiry). |
| Use | `PUT /api/v1/compliance/controls/{control_id}/implementation` with `{status, statement, justification, review_period_days}` (days 0-3650). Response `{control_ref, status, next_review_at}`. |
| Permissions | `compliance:write` |
| Errors | 404 `control not found`; 422 `unknown implementation status` / `not_applicable requires a justification`. |
| Exceptional | `control_id` is looked up with `session.get(ComplianceControl, ...)` and no framework-ownership check, so a caller can create an implementation row (in its own tenant) against a control of another tenant's custom framework if it knows the UUID. |
| Status | Implemented (tests `test_not_applicable_requires_a_justification`, `test_setting_a_status_schedules_the_next_review`, `test_implementation_roundtrip_over_http`) |

### 6. Coverage report and stale marking

| Item | Detail |
|------|--------|
| What | Honest coverage for one framework: counts per status, applicable controls (shipped minus justified not-applicable), `implemented_ratio`, evidenced controls, one row per control. |
| How | `framework_coverage` is read-only since 0.41.0: `coverage` reports an `implemented` control whose `next_review_at` has passed as `stale` without persisting it. The persisting step, `mark_stale_implementations`, runs in `POST .../refresh-signals`. The ratio is over the **shipped** catalogue; for a partial catalogue it is explicitly not a conformance figure. |
| Use | `GET /api/v1/compliance/frameworks/{framework_id}/coverage` |
| Permissions | `compliance:read` |
| Exceptional | A GET performs a status update and commits (`api/v1/compliance.py:~229-231`): it is idempotent but not side-effect free. Coverage runs one evidence count query per control. |
| Status | Implemented (tests `test_coverage_counts_unassessed_against_you`, `test_coverage_excludes_justified_not_applicable_from_the_denominator`, `test_overdue_implementations_become_stale`) |

### 7. Control chain and links

| Item | Detail |
|------|--------|
| What | Control to assets to findings to tickets to evidence in one call, plus manual links. |
| How | `control_chain` `:311` -> `services/compliance.py:612` (up to 50 evidence rows, newest first; tickets are returned as bare ids). `link_object` route `:324` accepts `object_type` in `asset, finding, ticket, vulnerability, document` and is idempotent per control and object. |
| Use | `GET /api/v1/compliance/controls/{control_id}/chain`, `POST /api/v1/compliance/controls/{control_id}/links` with `{object_type, object_id, rationale}` (201). |
| Permissions | `compliance:read`, `compliance:write`. |
| Errors | 404 `control not found`; 422 `object_type must be one of [...]`. |
| Exceptional | `object_id` is not validated to exist or to belong to the organization; `control_chain` parses it with `uuid.UUID(...)`, so a non-UUID `object_id` stored for an `asset` or `finding` link makes the chain endpoint raise an unhandled `ValueError` (500). |
| Status | Implemented (tests `test_control_chain_walks_to_findings_and_evidence`, `test_linking_is_idempotent`, `test_link_rejects_an_unlisted_object_type`) |

### 8. Evidence

| Item | Detail |
|------|--------|
| What | A dated artefact supporting a control claim. |
| How | `add_evidence` `:354` creates the implementation row if absent and stores the evidence with `collected_by_id` and `collected_at`; references `document_id`, `ticket_id`, `finding_id`, `asset_id`, `external_url`, `valid_until`, free `payload`. `list_evidence` `:389` filters `kind` and `expired` (true: `valid_until < today`; false: no expiry or not yet expired) and exposes `is_expired`. |
| Use | `POST /api/v1/compliance/controls/{control_id}/evidence` (201), `GET /api/v1/compliance/evidence?kind=&expired=&limit=&offset=` (limit 1-200). |
| Permissions | `evidence:write`, `evidence:read`. |
| Errors | 404 `control not found`; 422 `kind must be one of [...]`. |
| Status | Implemented (tests `test_evidence_is_listed_with_expiry_state`, `test_evidence_kind_must_be_known`) |

### 9. Assessments and gaps

| Item | Detail |
|------|--------|
| What | A point-in-time audit run against one framework. |
| How | `create_assessment` `:423` (status `in_progress`, `started_on` default today). `complete_assessment` `:448` -> `services/compliance.py:686`: freezes the coverage report into `snapshot` (never recomputed on read), sets `complete` and `completed_on`, and **generates a gap for every control that is neither `implemented` nor `not_applicable`** (severity `high` for `not_assessed`, else `medium`; `stale` counts as a gap and is annotated). Re-running adds no duplicate gaps. `list_assessments` `:478`, `read_assessment` `:501` (snapshot plus gaps). |
| Use | `POST /api/v1/compliance/assessments` (`framework_id`, `name`, `scope`, `assessor`, `started_on`), `POST /api/v1/compliance/assessments/{assessment_id}/complete?summary=`, `GET /api/v1/compliance/assessments`, `GET /api/v1/compliance/assessments/{assessment_id}`. |
| Permissions | `compliance:write` (create, complete), `compliance:read`. |
| Errors | 404 `assessment not found`; 409 `assessment is already complete`; 404 `framework not found`. |
| Exceptional | `list_assessments` returns the real count in `total` (fixed in 0.41.0). Statuses `draft` and `archived` exist in the model but no route sets them. |
| Status | Implemented (tests `test_completed_assessment_freezes_its_snapshot`, `test_completing_an_assessment_raises_gaps_for_every_shortfall`, `test_assessment_lifecycle_over_http`) |

## Errors summary

| Code | Condition |
|------|-----------|
| 401/403 | Auth, missing permission, team-restricted principal. |
| 404 | Framework (including other tenants' custom ones), control, assessment not found. |
| 409 | Duplicate framework slug and version; assessment already complete. |
| 413 | Controls import over 8 MiB. |
| 422 | Invalid status, kind, object type, CSV columns, missing justification. |

## Tests

`tests/test_phase7_compliance.py` has about 40 tests (seed idempotence, no copyrighted normative text shipped, signals, status rules, coverage, chain, assessments, HTTP round trips). Test names were reviewed; bodies were not re-executed.
