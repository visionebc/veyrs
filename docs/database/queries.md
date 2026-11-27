---
title: Relevant and heavy queries
purpose: Catalogue the queries that dominate VEYRS database work (risk recompute, correlation, dashboards, reports, search, feeds), the indexes that serve them, and the performance considerations the code itself shows.
scope: Query shapes read in the code and their declared indexes; no measured execution plans or row counts, because no database access was available for this round.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/services/analytics.py, backend/veyrs/services/report_builder.py, backend/veyrs/services/reporting.py, backend/veyrs/services/search.py, backend/veyrs/services/risk.py, backend/veyrs/engines/risk.py, backend/veyrs/services/correlation.py, backend/veyrs/services/intel_pipeline.py, backend/veyrs/services/intelligence.py, backend/veyrs/services/sla.py, backend/veyrs/api/v1/findings.py, backend/veyrs/api/v1/engagements.py, backend/veyrs/models/views.py, backend/veyrs/models/report_queries.py, extract/schema.json]
related: [database/README.md, database/er-diagrams.md, database/lifecycle.md, DATABASE_SCHEMA.md, api/reference/dashboards-reports.md]
---

# Relevant and heavy queries

Everything here is derived from reading the code and the declared indexes in `extract/schema.json`. **No execution plan, timing or row count was observed**; "serves" means the index exists and matches the predicate, not that the planner chose it. Verify any suspicion with `EXPLAIN (ANALYZE, BUFFERS)` as shown at the end.

## Conventions that shape every query

- **Tenant first.** Every tenant query filters `organization_id` explicitly and RLS adds the same predicate (`organization_id::text = current_setting(...)`). The explicit filter keeps composite indexes that lead with `organization_id` usable; the policy's `::text` cast on the column is evaluated against the row, and the indexes are on the `uuid` column, so the explicit filter is what gives the planner an index condition. Whether the policy predicate also uses the index was not tested.
- **Open work is a state set.** "Open" means `state IN OPEN_STATES` (`new`, `triaged`, `risk_assessed`, `assigned`, `in_progress`, `mitigation`, `remediated`, `verification`, `deferred`; `models/vulnerability.py:67`). The index for it is `ix_findings_org_state (organization_id, state)`.
- **Team scope.** Restricted principals get an extra clause from `security/scope.py` (`finding_clause`, `asset_clause`, `ticket_clause`). Analytics routes every predicate through `_scoped*` helpers (`services/analytics.py:57-91`), enforced by `tests/test_phase26_scope.py`.
- **Timeouts.** Connections default to `statement_timeout = 30s` and `idle_in_transaction_session_timeout = 60s` (`db.py`); the report builder lowers the statement timeout to 20 s per run.
- **Pagination.** List endpoints use `LIMIT/OFFSET` plus a separate `count(*)` over the same filtered statement (for example `api/v1/findings.py:226-232`, `api/v1/engagements.py:338-342`). Deep pages cost proportionally to the offset.

## Query catalogue

| Query | Where | Indexes available | Considerations |
|---|---|---|---|
| **Risk recompute, full** (`python -m veyrs recompute-risk [--org SLUG]`) | `engines/risk.py:542`, `services/risk.py:115` | `ix_findings_org_state` | Loads **every open finding of an organization into memory** (`.scalars().all()`), then for each finding does `session.get` of its asset, vulnerability, CVE and business service (`services/risk.py:57-70`). The identity map caches by primary key, so repeated assets cost nothing, but each distinct row is its own round trip (N+1 on first touch). Writes one `UPDATE` per changed finding and one `risk_score_history` row when the score is new or moves by at least 0.1. One commit per organization. |
| **Risk rescore after EPSS or KEV feed** | `services/intel_pipeline.py:98-146` | `ix_findings_org_state`, `ix_vulnerabilities_cve_id`, `findings.vulnerability_id` index | Joins `findings` to `vulnerabilities` with `cve_id IN (...)`; ids are **windowed to 5,000 per statement** because the EPSS id list is the whole corpus (hundreds of thousands) and a statement with that many bind parameters is expensive to render and plan (`RESCORE_ID_WINDOW`, line 108). Runs per organization with the tenant re-bound each time. |
| **CVE correlation** (new NVD records, new inventory) | `services/correlation.py:108-148`, `612-730` | `ix_cve_cpe_cve`, `ix_cve_cpe_product`, `ix_asset_products_product`, `ix_asset_products_product_id` | Loop shape is **per CVE, per organization**: `session.get(Cve)`, one query on `cve_cpe_match` by `cve_id`, one on `asset_products` joined to `assets` with `product_id IN (...)`, then version-range matching in Python (`match_covers`). Cost scales with CVEs times tenants. The `vulnerable = true` filter has no index of its own; `cve_id` narrows first. |
| **Asset resolution during scanner import** | `services/importers/base.py` `AssetIndex`, built once per `ingest` and once per `ingest_inventory` | `ix_assets_organization_id` | Since 0.41.0 the tenant's live assets are read **once per run** (`SELECT * FROM assets WHERE organization_id = :org AND deleted_at IS NULL`) and indexed in memory by FQDN, hostname rules and IP; each record is then a dictionary lookup. Until 0.41.0 that query ran for every record and matched in Python, records times assets rows transferred. Memory is one ORM object per live asset for the duration of the run. |
| **Finding upsert** (importers, correlation) | `services/dedupe.py` `find_existing`, `correlation.py:445` | unique `uq_findings_organization_id (organization_id, asset_id, dedupe_key)`, `ix_findings_unique_id (organization_id, unique_id_from_tool)` | The importer upsert path. The unique key is also what stops duplicate findings under concurrency. |
| **EPSS ingest** | `services/intelligence.py:515-640` | primary key `epss_scores.cve_id`, unique `(cve_id, scored_on)` | Set-based `INSERT ... ON CONFLICT DO UPDATE` in batches, no ORM instances loaded: the earlier ORM version OOM-killed the nightly job three nights running. Each scored day is about 370,000 rows in `epss_history`; each batch commits so no transaction outlives the 60 s idle limit. |
| **EPSS prune** | `services/intelligence.py:660-710` | `ix_epss_history_cve_date (cve_id, scored_on)` | The delete is `WHERE scored_on = :day`, one day per transaction. The only index leads with `cve_id`, so a `scored_on`-only predicate cannot use it as a prefix; the code does not show an index on `scored_on` alone. Not measured. |
| **CVE child replace** | `services/intelligence.py:350-358` | `ix_cve_references_cve`, `ix_cve_cpe_cve` | Deletes and re-inserts all `cve_references` and `cve_cpe_match` rows of a CVE on every NVD revision. Churn grows with NVD revisions, and `cve_cpe_match` is the largest per-CVE child table. |
| **Executive dashboard** | `services/analytics.py:133-217` | `ix_findings_org_state`, `ix_findings_asset`, `ix_assets_org_exposure` | About twenty sequential statements per call (twelve headline counts and groupings, then the sub-reports), each a `count`/`group by` or row fetch over the organization's open findings: by severity, by risk level, KEV, EPSS at least 0.5, SLA breached, escalated, distinct assets, average risk, plus joins to `assets` for internet-exposed counts. The sub-reports are `mttr`, `risk_trend`, `finding_trend` (two statements), `top_products`, `top_assets`, `top_teams` and `by_environment`. Cost is linear in open findings. No caching layer exists in the code. |
| **Trend and MTTR** | `services/analytics.py:220-297` | none on `detected_at` or `remediated_at` | `mttr` and `finding_trend` fetch the **rows** (`detected_at`, `remediated_at`) for the window into Python and bucket there. `schema.json` lists no index on `findings.detected_at` or `findings.remediated_at`, so these filter on the organization and read the rows. `risk_trend` reads `risk_score_history` filtered on `organization_id` and `created_at`; the only indexes are `ix_risk_score_history_organization_id` and `ix_risk_history_finding (finding_id, created_at)`, which does not lead with the organization. A team-restricted caller adds an `IN (SELECT id FROM findings ...)` subquery. |
| **Top lists** | `services/analytics.py:316-396` | `ix_findings_org_state`, `ix_asset_products_*` | Join `findings` to `asset_products`, `products`, `vendors`, or to `assets`/`teams`, `GROUP BY` and `LIMIT`. Top assets orders by `max(risk_score) DESC NULLS LAST`. |
| **CWE rollup** | `services/analytics.py:470-498` | none useful | Groups open findings by the `cve.cwe_ids` JSONB array **as a whole** (no GIN index, no unnesting), then tallies per CWE in Python. Distinct arrays are grouped separately. |
| **Findings list** | `api/v1/findings.py:166-239` | `ix_findings_org_risk`, `ix_findings_org_state`, `ix_findings_team (organization_id, assigned_team_id, state)`, `ix_findings_due (organization_id, sla_due_at)` | Default order is `risk_score DESC NULLS LAST`. `ix_findings_org_risk` is declared with default (ascending) ordering and no `NULLS` option, which does not match `DESC NULLS LAST` directly; whether the planner can use it for the sort is a question for `EXPLAIN`. The free-text filter is `title ILIKE '%q%'` (see Search). `exposure` joins `assets`. Count and page are two statements. |
| **Exposure lookups** | `analytics.py:155-170`, `findings.py:204` | `ix_assets_org_exposure (organization_id, exposure)`, `ix_findings_asset` | "Internet-facing open" and "KEV and internet-facing" are joins from `findings` to `assets` on `asset_id` filtered by `assets.exposure = 'internet'`. `findings.kev` and `findings.epss_score` have no index (only `ix_findings_risk_score` exists on score), so KEV and EPSS filters are applied while scanning the organization's open findings. |
| **KEV overdue queue** | `api/v1/intel.py:260-271` | `ix_kev_entries_due_date`, `ix_kev_entries_date_added` | Global table, small; range on `due_date`. |
| **SLA sweep** (`python -m veyrs run-sla`) | `services/sla.py:337-373`, `511-540` | `ix_findings_org_state`, `ix_findings_due` | Loads all open findings of each active organization into memory and evaluates them in Python; flips breach flags and writes `sla_events` and notifications. One commit per organization. |
| **Ticket reference counter** | `services/ticketing.py:61-78` | unique `(organization_id, ticket_type)` | `SELECT ... FOR UPDATE` on the counter row serialises ticket creation per organization and type. |
| **Report builder** | `services/report_builder.py:824-966` | whichever the entity's own list route uses | Specifications are compiled to SQLAlchemy expressions against a curated catalog, never to client SQL. Joins are `LEFT OUTER` and many-to-one only, so counts cannot multiply. Limits: 25 columns, 20 filters, 3 group-bys, 6 aggregates, 3 sorts, 100 `IN` values, `RUN_LIMIT` 5,000 rows on screen, `EXPORT_LIMIT` 50,000 in a file, `statement_timeout` 20 s, a canceled query is reported as a 422 (`sqlstate 57014`). Saved specifications live in `report_queries.spec` (JSONB) and are re-validated on every run. |
| **Fixed reports** | `services/reporting.py` | as the dashboards | Executive, technical, SLA, vulnerability register, asset register, team performance, compliance and ticket reports reuse the analytics functions, so they inherit their cost. |
| **Search** | `services/search.py:53-203` | none | See below. |
| **Endpoint search** | `api/v1/engagements.py:326-346` | unique `(organization_id, canonical)`, `ix_endpoints_org_host` | `host ILIKE '%x%'`, which cannot use a B-tree index (leading wildcard). |
| **Saved views** | `models/views.py`, `services/views.py` | `ix_saved_views_org_entity`, unique `(organization_id, owner_id, entity, name)` | Stores a filter set that is replayed as query parameters against the list routes, so it adds no query of its own. |

## Search

`GET /api/v1/search` (`services/search.py`) runs up to nine independent `ILIKE '%term%'` queries, one per entity type (CVE, vulnerability, finding, asset, product, ticket, document, knowledge, news), each with `LIMIT 10`, filtered by tenant and by the caller's permission for that entity. There is **no full-text index, no trigram index and no extension** in the schema, so every one of these is a scan of the tenant's rows (or of the whole `cve` table for CVE search, which matches `id`, `title` and `description`). The `document` search scans `documents.text_content`, the largest text column in the schema. `semantic_search` uses a pluggable vector backend and falls back to the same lexical search when none is configured (`NullVectorBackend`); the schema stores `document_chunks.vector_id` as a reference to an external vector store and has no vector column.

## Indexes that matter, and what the schema does not provide

Declared and confirmed in `extract/schema.json`:

| Index | Serves |
|---|---|
| `ix_findings_org_state`, `ix_findings_org_risk`, `ix_findings_team`, `ix_findings_due`, `ix_findings_unique_id`, `ix_findings_asset`, `ix_findings_vulnerability_id`, `ix_findings_risk_score` | findings list, dashboards, SLA sweep, importer lookup, correlation |
| `uq_findings_organization_id (organization_id, asset_id, dedupe_key)` | importer upsert and duplicate protection |
| `ix_vulns_org_state`, `ix_vulns_org_risk`, `ix_vulnerabilities_cve_id` | vulnerability register, feed rescoring |
| `ix_assets_hostname`, `ix_assets_org_type`, `ix_assets_org_criticality`, `ix_assets_org_exposure`, `ix_assets_team_id`, `ix_assets_owner_id` | asset lists and exposure |
| `ix_asset_products_product (product_id, version_key)`, `ix_asset_products_asset_id` | correlation from CVE to installations, and from asset to CVEs |
| `ix_cve_cpe_cve`, `ix_cve_cpe_product` | CPE matching |
| `ix_cve_cvss3`, `ix_cve_cvss4`, `ix_cve_epss_score`, `ix_cve_kev`, `ix_cve_published` | CVE catalogue filters |
| `ix_epss_scores_score`, `ix_epss_history_cve_date`, `ix_kev_entries_due_date` | EPSS above X, EPSS trend per CVE, KEV queue |
| `ix_audit_org_time`, `ix_audit_object`, `ix_ai_audit_org_time` | audit paging |
| `ix_risk_history_finding (finding_id, created_at)` | per-finding score history |

Not provided by the schema, and implied by queries above: indexes on `findings.detected_at`, `findings.remediated_at`, `findings.kev`, `findings.epss_score`; any index serving `ILIKE '%x%'`; an index on `epss_history.scored_on` alone; a GIN index over JSONB arrays such as `cve.cwe_ids`. Adding one is a hand-written `CREATE INDEX CONCURRENTLY` plus a model change; `sync-schema` creates only indexes declared in the models (`cli.py:174-184`).

## Row growth that affects query cost

`epss_history` (about 370,000 rows per scored day; pruned by `VEYRS_EPSS_HISTORY_DAYS`), `cve_cpe_match`, `cpe`, `audit_log`, `finding_events`, `risk_score_history`, `agent_job_events` and `notifications` only ever grow (see [lifecycle.md](lifecycle.md)). Production size on one node was quoted in the repository as about 2.6 GB raw, 350 MB compressed (`infrastructure/backup/veyrs-pgdump.sh` header comment); that number is from a comment, not measured here.

## Investigating a slow query

Run as the application role (so RLS applies exactly as in production), on any host with `psql` access to the database. `EXPLAIN ANALYZE` executes the statement; use a `SELECT` and roll back.

```sql
BEGIN;
SELECT set_config('veyrs.current_org', '00000000-0000-0000-0000-000000000000', true);  -- replace with the organization uuid
EXPLAIN (ANALYZE, BUFFERS)
SELECT id, title, risk_score
FROM findings
WHERE organization_id = '00000000-0000-0000-0000-000000000000'  -- same uuid
  AND state IN ('new','triaged','assigned','in_progress')
ORDER BY risk_score DESC NULLS LAST
LIMIT 50;
ROLLBACK;
```

Look for `Seq Scan` on `findings` (no usable index), a `Sort` node above an index scan (the ordering mismatch described above), and large differences between estimated and actual rows. The repository ships no `pg_stat_statements` or slow-query logging configuration; enabling `shared_preload_libraries = 'pg_stat_statements'` and `log_min_duration_statement` is a database-node decision outside VEYRS.

## Sources

- `backend/veyrs/services/analytics.py`, `report_builder.py`, `reporting.py`, `search.py`, `risk.py`, `correlation.py`, `intel_pipeline.py`, `intelligence.py`, `sla.py`
- `backend/veyrs/engines/risk.py`, `backend/veyrs/api/v1/findings.py`, `backend/veyrs/api/v1/engagements.py`, `backend/veyrs/api/v1/intel.py`
- `extract/schema.json` (indexes), `backend/veyrs/models/views.py`, `backend/veyrs/models/report_queries.py`
