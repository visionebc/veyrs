---
title: Dashboards, reports, report builder and saved views
purpose: Explain how VEYRS computes dashboards, produces fixed and ad-hoc reports in four formats, and stores operators' saved filters, including the authorization and team-scope rules each surface applies.
scope: Routes tagged `dashboards & reports` and `saved views`, and services analytics, reporting, report_builder and views; per-endpoint parameters are in the generated reference.
version: 0.39.1
verified: 2026-11-17
status: Verified
sources: [backend/veyrs/api/v1/reports.py, backend/veyrs/api/v1/report_builder.py, backend/veyrs/api/v1/views.py, backend/veyrs/services/analytics.py, backend/veyrs/services/reporting.py, backend/veyrs/services/report_builder.py, backend/veyrs/services/views.py]
related: [api/reference/dashboards-reports.md, api/reference/saved-views.md, functional/sla-escalation.md, functional/vulnerability-management.md, security/security-architecture.md]
---

# Dashboards, reports, report builder and saved views

References: [../api/reference/dashboards-reports.md](../api/reference/dashboards-reports.md), [../api/reference/saved-views.md](../api/reference/saved-views.md).

## Team scope rules at a glance

The three surfaces treat a team-scoped principal differently on purpose.

| Surface | Tag class (`security/scope.py`) | Team-scoped caller gets |
|---|---|---|
| Dashboards (`/dashboard/*`) | scoped (`dashboards & reports`, `:53`) | Their own slice, with a `scope` block saying so |
| Fixed reports (`/reports/{slug}`, `/export`) | scoped tag, but the handlers call `_refuse_if_scoped` (`api/v1/reports.py:21`) | **403** `report exports cover the whole estate ...` |
| Report builder | scoped | Their slice, labelled in provenance `scope` |
| Saved views | exempt (`:87`) | The stored query only; applying it goes through the entity's own scoped list route |

Rationale in code: an exported PDF outlives its on-screen context, so a one-team file under an estate title is refused (`reports.py:21-35`).

## Dashboards

### Executive, technical, SLA and trend dashboards

| Item | Detail |
|---|---|
| What | `GET /dashboard/executive`, `GET /dashboard/technical`, `GET /dashboard/sla`, `GET /dashboard/trends`. |
| Why | Live posture views for managers and engineers; the console Dashboard page. |
| How it works | `api/v1/reports.py:63-105` call `services/analytics.py`. **Executive** (`executive_dashboard`, `:133`): open findings, assets, coverage ratio, `by_severity`, `by_risk_level`, exploitation (KEV open, EPSS >= 0.5 open, internet-facing open, KEV and internet-facing), SLA (breached, escalated, breach ratio), average risk score, `mttr`, trends, top products/assets/teams, by environment. **Technical** (`:428`): CVSS and EPSS distributions (`CVSS_BANDS`, `EPSS_BANDS`), KEV counts, top CWE, exploitability, state and scanner breakdowns. **SLA** (`sla_report`, `:543`): findings with an SLA, breached, open and breached, due within 3 days, compliance ratio, per-severity; `reliable` is false below `MIN_MEANINGFUL_SAMPLE` = 10. **Trends**: `risk_trend` (average `RiskScoreHistory` per bucket) and `finding_trend` (detected vs remediated per bucket), `buckets` 2-52. `mttr` (`:220`) measures detected to remediated for findings remediated in the window, mean and median, per severity. |
| How to use | Console: Dashboard (`route('dashboard')`). Query: `days` 7-730 (default 90), `team_id` to narrow to one team. |
| Team filter | `?team_id=` is resolved by `security.scope.resolve_view` (`:172`); an unknown or other-tenant team is 404 `team not found`; the response `scope.team_filter` names the team so a filtered figure cannot pass as the estate figure. |
| Permissions | `report:read` (executive, technical, trends); `sla:read` (sla) |
| Data | `findings`, `assets`, `tickets`, `risk_score_history`, `cwe`/`cve` for top CWE |
| Errors | 422 `days` or `buckets` outside bounds; 404 unknown team. |
| Exceptional | Every dashboard carries a `scope` block (`restricted`, `teams`, `team_ids`, `includes_unowned`) so a partial view never reads as total. |
| Status | Verified (`/dashboard/sla` observed live: 1 972 findings with an SLA, 1 529 breached; `tests/test_phase9_reporting.py`, `test_phase27_team_dashboard.py`, `test_phase26_scope.py`) |

## Fixed reports

### Catalogue, build and export

| Item | Detail |
|---|---|
| What | `GET /reports` (catalogue), `GET /reports/{slug}` (JSON), `GET /reports/{slug}/export?format=`. |
| Why | Documents to hand to someone who was not in the room. |
| How it works | `REPORTS` (`services/reporting.py:275`) registers eight specs: `executive`, `technical`, `sla` (all `report:read`), `vulnerability-register` (`finding:read`), `asset-register` (`asset:read`), `team-performance` (`report:read`), `compliance` (`compliance:read`, optional `framework_id`), `tickets` (`ticket:read`). Each has a builder and a `tabulate` function. `build` returns `{provenance, data}`; provenance records organization, timestamp, VEYRS version, parameters and a staleness note. `render` supports `json`, `csv`, `xlsx`, `pdf` (`FORMATS`); filename `veyrs-<slug>-<UTC stamp>.<fmt>` sent as `Content-Disposition: attachment`. CSV/XLSX cells starting with `= + - @ TAB CR` get a leading apostrophe against formula injection (`FORMULA_PREFIXES`, `:388`). `xlsx` and `pdf` need optional libraries; a missing one is a 422 naming the package. Export is audited as `report.exported` with format and byte size. |
| How to use | Console: Reporting > Reports. Query: `days` 7-730, `limit` 1-20 000 (default 1 000), `framework_id`, `format`. |
| Permissions | `GET /reports` needs only authentication and marks each entry `available` per caller; the report's own permission is enforced in the handler (`principal.require(spec.permission)`), **not** a blanket `report:read`. |
| Errors | 404 `unknown report '<slug>'; known: [...]` (observed live); 403 missing the report's permission, or team-scoped caller; 422 unknown format or missing renderer library. |
| Status | Verified (`tests/test_phase9_reporting.py`; catalogue observed live) |

## Report builder

### Catalogue, run, export

| Item | Detail |
|---|---|
| What | `GET /report-builder/catalog`, `POST /report-builder/run`, `POST /report-builder/export?format=csv\|xlsx\|json`. |
| Why | Ad-hoc questions ("open critical findings per business service and team, with average age") answered inside VEYRS, under its authorization, instead of via an export and a pivot table. |
| How it works | The client posts a JSON **spec** (`entity, columns, filters, group_by, aggregates, sort, limit`), never SQL. `builder.validate` (`services/report_builder.py:677`) checks every name against `CATALOG`; unknown keys are rejected with a message naming them. Entities: `findings` (`finding:read`), `assets` (`asset:read`), `vulnerabilities` (`vulnerability:read`), `tickets` (`ticket:read`), `risks` (`riskregister:read`). Operators by field type: string, number (`eq ne gt gte lt lte between in is_null not_null`), date (adds `last_days older_than_days next_days`), bool, enum (`eq ne in not_in ...`). Aggregates: `count`, `count_distinct`, `avg`, `sum`, `min`, `max`. Limits: 25 columns, 20 filters, 3 group-bys, 6 aggregates, 3 sort keys, 100 `in` values, 200-char strings; rows 5 000 on screen (`RUN_LIMIT`), 50 000 in a file (`EXPORT_LIMIT`). A grouped report must have empty `columns`. Joins are many-to-one LEFT OUTER only. `compile` binds values as parameters, escapes `LIKE` wildcards, and applies the entity's own team-scope predicate plus the tenant predicate; `run` (`:927`) sets `statement_timeout` to 20 s with `set_config(..., true)` (transaction-local) and converts a cancelled query into a 422 asking to narrow it. Provenance carries `scope` (`whole estate` or the team restriction text), `row_count`, `truncated`. |
| Permissions | Every route `report:read`; run/export additionally need the **entity's** read permission (`_entity_permission`, `api/v1/report_builder.py:66`). |
| Errors | 422 spec problems (`ReportBuilderError`), unknown export format, statement timeout; 403 missing entity permission. |
| Audit | Exports record `report.exported` with the spec, row count and truncation. |
| Status | Verified (`tests/test_phase50_report_builder.py`; catalogue observed live) |

### Saved reports

| Item | Detail |
|---|---|
| What | `GET /report-builder/queries`, `POST /report-builder/queries`, `GET /report-builder/queries/{query_id}`, `PATCH /report-builder/queries/{query_id}`, `DELETE /report-builder/queries/{query_id}`, `POST /report-builder/queries/{query_id}/run`, `POST /report-builder/queries/{query_id}/export`. |
| How it works | A saved report is a validated spec in `report_queries`. Visible: own plus shared in the organization (`visible_queries`, `:989`). Only the owner edits or deletes; anyone else gets 404 (not 403). Sharing (`is_shared`) requires `report:write`. Saved specs are re-validated on every run, so a field removed from the catalog yields a 422 telling the user to edit and re-save. A shared report runs under the **reader's** permissions and scope. Limits: 100 per user, unique name per owner. |
| Permissions | `report:read`; `report:write` to share; an API key cannot create one (403 `saved reports belong to a user`). |
| Errors | 404 `no such saved report`; 403 API key; 422 spec/name clash/limit. |
| Status | Verified (`tests/test_phase50_report_builder.py`) |

## Saved views

| Item | Detail |
|---|---|
| What | `GET /saved-views`, `POST /saved-views`, `PATCH /saved-views/{view_id}`, `DELETE /saved-views/{view_id}`. |
| Why | An operator's own queues (named filter sets for the findings, tickets, assets, vulnerabilities and issues lists). |
| How it works | `services/views.py` stores filters as a string-valued allow-list per entity (`ALLOWED_FILTERS`, `:47`); unknown keys are rejected; paging parameters are excluded on purpose; max 20 filters, value length 200, 100 views per user, unique `(owner, entity, name)`. `entity` is immutable (PATCH with a different entity is a 422). `GET ?seed=true` installs three starter views (`Critical, internet-facing`; `Known exploited (KEV)`; `Past its SLA`) only when the user owns none. `is_mine` is a rendering hint; authorization is `get_owned`. |
| How to use | Console: pinned views in list pages (`app.js:8732-8804`). |
| Permissions | Authentication only. The view grants nothing; applying it hits the entity list route which enforces permission and team scope. Sharing a view needs no extra permission (unlike shared reports). |
| Errors | 422 unknown entity/filter, name clash, limit; 403 `saved views belong to a user; an API key cannot own one`; 404 `no such saved view` (also for someone else's view). |
| Status | Verified (`tests/test_phase36_disposition.py`; live list returned the starter views) |

## Errors summary

| Code | Conditions |
|---|---|
| 401 | Missing or invalid credentials. |
| 403 | Missing permission (`report:read`, `sla:read`, report-specific, entity read); team-scoped caller on a fixed report or export; API key creating saved views/reports. |
| 404 | Unknown report slug, team, saved view or saved report. |
| 422 | Parameter bounds, spec validation, unknown format, missing renderer library, statement timeout. |
