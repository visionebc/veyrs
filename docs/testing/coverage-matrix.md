---
title: Test coverage matrix
purpose: Show, per API tag and per backend module, which tests reference it and how many test functions the suite holds, with a measurable API test-reference ratio.
scope: Static, text-based reference coverage of routes, services and test files; it is not line or branch coverage and does not say a referenced route is well tested.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [tests/, extract/routes.json, backend/veyrs/services/, backend/veyrs/security/, backend/veyrs/engines/]
related: [testing/strategy.md, testing/critical-flows.md, testing/known-issues.md, api/reference/administration.md, reference/inventory.md]
---

# Test coverage matrix

> [!IMPORTANT]
> This is **reference coverage**, not execution coverage. No coverage tool is configured in the repository (`pytest.ini`, `scripts/test.sh`) and the suite was not run for this document. A route counts as "referenced" when a test contains its path as a string; that shows a test *mentions* it, not that every branch is exercised.

## Method

1. **Test functions.** `ast.parse` over every `tests/*.py`; every function (module level or inside a class) whose name starts with `test_` is counted. "Expanded" multiplies by the length of a literal list/tuple passed to `@pytest.mark.parametrize` (a variable argument counts once; see [strategy](strategy.md#dynamic-parametrization)). Result at 0.39.1: **94 modules, 1,643 functions, 1,831 expanded** (0.39.0: 90, 1,629, 1,817). The four new modules (`test_console_readability_0391.py`, `test_executable_bits.py`, `test_docs_diagrams.py`, `test_docs_reference_is_current.py`) and the grown `test_console_configure_frame.py` and `test_docs_center.py` contain no API path literal, so the route ratios below are unchanged from the 0.39.0 measurement.
2. **Route reference.** All 336 routes from `extract/routes.json` (method + path + tag). Every string literal and f-string in `tests/*.py` is extracted, each `{expression}` and each `{param}` is normalised to `{}`, and a route is *referenced* if its path (without the `/api/v1` prefix) occurs in some literal, ending at the end of the literal or before `?`/`#`. The match is **by path only, not by HTTP method**: a test that only `GET`s a collection also marks its `POST` as referenced.
3. **Weak reference.** For routes with no strict match, a literal containing `/<last static segment>` (for example `/rescore`). This catches paths built by concatenation (`QUERIES + "/x"`) but also false positives.
4. **No reference.** Neither strict nor weak.

Limits: a path assembled from variables is invisible to step 2, so the strict ratio is a *lower bound*; the weak pass is an *upper bound*. Service-level tests (calling `veyrs.services.*` directly, as the agent and AI-gateway tests do) are invisible to the route measure by construction.

## API test-reference ratio

Total **336 routes**: **259 strictly referenced (77.1%)**, 41 weakly referenced (12.2%), **36 with no reference of any kind (10.7%)**. Bounds: 77.1% (lower) to 89.3% (upper). Every route additionally passes through `test_phase10_hardening.py::test_every_route_is_protected` (authorization walk over the live route table) and `test_phase2_core.py::test_openapi_documents_every_route`, which are not path-literal references.

| Tag | Routes | Strictly referenced | Ratio | Weak only | No reference | Main test modules (by routes matched) |
|---|---|---|---|---|---|---|
| (untagged) | 4 | 4 | 100% | 0 | 0 | `phase10_hardening`, `phase2_core` |
| [administration](../api/reference/administration.md) | 47 | 44 | 94% | 1 | 2 | `phase2_core`, `phase10_hardening`, `phase46_risk_register` |
| [agents](../api/reference/agents.md) | 22 | 15 | 68% | 3 | 4 | `phase16_agents`, `phase30_scanner_page`, `phase34_inventory_and_scanning` |
| [ai](../api/reference/ai.md) | 19 | 12 | 63% | 3 | 4 | `phase6_ai`, `phase10_hardening` |
| [asset sources](../api/reference/asset-sources.md) | 19 | 14 | 74% | 3 | 2 | `phase40_asset_sources`, `phase42_netbox_and_team_import` |
| [assets](../api/reference/assets.md) | 17 | 9 | 53% | 3 | 5 | `phase10_hardening`, `phase26_scope`, `phase26_team_ownership` |
| [authentication](../api/reference/authentication.md) | 18 | 17 | 94% | 0 | 1 | `phase10_hardening`, `phase54_mfa_methods`, `phase2_core` |
| [compliance](../api/reference/compliance.md) | 16 | 12 | 75% | 1 | 3 | `phase7_compliance`, `phase10_hardening` |
| [cvss](../api/reference/cvss.md) | 9 | 6 | 67% | 1 | 2 | `phase2_core`, `phase35_operability` |
| [dashboards & reports](../api/reference/dashboards-reports.md) | 17 | 10 | 59% | 6 | 1 | `phase50_report_builder`, `phase26_scope`, `phase9_reporting` |
| [engagements](../api/reference/engagements.md) | 15 | 14 | 93% | 0 | 1 | `phase15_api` |
| [integrations](../api/reference/integrations.md) | 25 | 17 | 68% | 6 | 2 | `phase33_scanner_connectors`, `phase8_integrations`, `phase10_hardening` |
| [intelligence & knowledge](../api/reference/intelligence-knowledge.md) | 19 | 11 | 58% | 3 | 5 | `write_paths`, `phase10_hardening`, `phase35_operability` |
| [operations](../api/reference/operations.md) | 3 | 3 | 100% | 0 | 0 | `phase10_hardening`, `phase18_hardening`, `phase52_updates` |
| [policies](../api/reference/policies.md) | 16 | 15 | 94% | 1 | 0 | `phase28_sla_scope`, `phase10_hardening`, `write_paths` |
| [risk register](../api/reference/risk-register.md) | 10 | 10 | 100% | 0 | 0 | `phase46_risk_register`, `phase47_risk_matrix` |
| [saved views](../api/reference/saved-views.md) | 4 | 4 | 100% | 0 | 0 | `phase36_disposition` |
| [threat intelligence](../api/reference/threat-intelligence.md) | 14 | 8 | 57% | 4 | 2 | `phase59_cve_exposure`, `phase10_hardening`, `phase37_estate_lens` |
| [ticketing](../api/reference/ticketing.md) | 26 | 21 | 81% | 4 | 1 | `phase10_hardening`, `write_paths`, `phase36_disposition` |
| [vulnerability management](../api/reference/vulnerability-management.md) | 16 | 13 | 81% | 2 | 1 | `phase26_scope`, `phase10_hardening`, `console_dialog_payloads` |

Rows sum to 336 (each route has at most one tag). Tag names link to the generated API reference.

### Routes with no test reference of any kind (36)

These are the strongest gap candidates. Some are exercised indirectly (for example through a service-level test or a path built from a variable that the method above cannot see); each needs a human check before being called untested.

- **administration** (2): `GET /api/v1/organization`; `PATCH /api/v1/organization`
- **agents** (4): `POST /api/v1/agents/self/jobs/{job_id}/lease`; `POST /api/v1/agents/self/jobs/{job_id}/fail`; `POST /api/v1/agents/maintenance/reap`; `POST /api/v1/agents/{agent_id}/rotate-token`
- **ai** (4): `POST /api/v1/ai/cve/{cve_id}/analysis`; `POST /api/v1/ai/findings/{finding_id}/ticket-draft`; `POST /api/v1/ai/findings/{finding_id}/suggest-team`; `POST /api/v1/ai/threat-summary`
- **asset sources** (2): `POST /api/v1/teams/import/assign-assets`; `GET /api/v1/asset-sources/compare`
- **assets** (5): `GET /api/v1/assets/inventory/aliases`; `POST /api/v1/assets/{asset_id}/products`; `DELETE /api/v1/assets/{asset_id}/products/{install_id}`; `POST /api/v1/assets/{asset_id}/products/bulk`; `POST /api/v1/assets/{asset_id}/rescan`
- **authentication** (1): `POST /api/v1/auth/mfa/send-code`
- **compliance** (3): `POST /api/v1/compliance/frameworks/{framework_id}/controls:import`; `POST /api/v1/compliance/frameworks/{framework_id}/refresh-signals`; `GET /api/v1/compliance/controls/{control_id}/chain`
- **cvss** (2): `POST /api/v1/cvss/compare`; `GET /api/v1/cvss/severity`
- **dashboards & reports** (1): `GET /api/v1/dashboard/trends`
- **engagements** (1): `POST /api/v1/engagements/risk-acceptances/{acceptance_id}/revoke`
- **integrations** (2): `POST /api/v1/integrations/connectors/{connector_id}/push/{ticket_id}`; `GET /api/v1/integrations/scanners/{connector_id}/scans`
- **intelligence & knowledge** (5): `POST /api/v1/intel/articles`; `GET /api/v1/intel/news`; `GET /api/v1/knowledge/{article_id}/revisions/{version}`; `GET /api/v1/search/semantic`; `GET /api/v1/knowledge/{article_id}/publications`
- **threat intelligence** (2): `GET /api/v1/intel/cve/{cve_id}/epss-history`; `POST /api/v1/intel/feeds/epss`
- **ticketing** (1): `GET /api/v1/workflows/actions`
- **vulnerability management** (1): `POST /api/v1/risk/simulate`

### Routes with only a weak reference (41)

The last path segment appears in a test, but not the full path. Likely exercised, not proven.

- **administration** (1): `DELETE /api/v1/admin/updates/uploads/{version}`
- **agents** (3): `POST /api/v1/agents/self/inventory`; `GET /api/v1/agents/{agent_id}/tools`; `PATCH /api/v1/agents/{agent_id}/tools/{tool_name}`
- **ai** (3): `DELETE /api/v1/ai/providers/{provider_id}`; `POST /api/v1/ai/findings/{finding_id}/explain`; `POST /api/v1/ai/findings/{finding_id}/remediation`
- **asset sources** (3): `POST /api/v1/teams/import`; `POST /api/v1/asset-sources/{source_id}/test`; `GET /api/v1/asset-sources/{source_id}/runs`
- **assets** (3): `GET /api/v1/assets/inventory/coverage`; `POST /api/v1/assets/inventory/resolve`; `POST /api/v1/assets/inventory/import`
- **compliance** (1): `GET /api/v1/compliance/assessments/{assessment_id}`
- **cvss** (1): `GET /api/v1/cvss/metrics/{version}`
- **dashboards & reports** (6): `GET /api/v1/reports/{slug}`; `GET /api/v1/report-builder/queries/{query_id}`; `PATCH /api/v1/report-builder/queries/{query_id}`; `DELETE /api/v1/report-builder/queries/{query_id}`; `POST /api/v1/report-builder/queries/{query_id}/run`; `POST /api/v1/report-builder/queries/{query_id}/export`
- **integrations** (6): `GET /api/v1/integrations/imports/{run_id}`; `GET /api/v1/integrations/tickets/{ticket_id}/links`; `POST /api/v1/integrations/scanners/{connector_id}/test`; `GET /api/v1/integrations/links`; `POST /api/v1/integrations/links/{link_id}/refresh`; `POST /api/v1/integrations/links/{link_id}/unlink`
- **intelligence & knowledge** (3): `GET /api/v1/knowledge/{article_id}`; `PATCH /api/v1/knowledge/{article_id}`; `GET /api/v1/search`
- **policies** (1): `POST /api/v1/policies/assignment/test`
- **threat intelligence** (4): `GET /api/v1/intel/cve/{cve_id}`; `GET /api/v1/intel/cwe/{cwe_id}`; `POST /api/v1/intel/feeds/nvd`; `POST /api/v1/intel/feeds/kev`
- **ticketing** (4): `POST /api/v1/findings/{finding_id}/remediation`; `PATCH /api/v1/workflows/{workflow_id}`; `POST /api/v1/notifications/{notification_id}/read`; `POST /api/v1/notifications/digest/preview`
- **vulnerability management** (2): `GET /api/v1/findings/{finding_id}`; `POST /api/v1/findings/{finding_id}/rescore`

## Backend modules

Method: for each module under `backend/veyrs/{services,engines,security,intel}` and the top-level modules, the `ast` import map of each test file (`from veyrs.services import x as y`, `from veyrs.services.x import f`, `import veyrs.x as y`) gives **files importing the module**; **functions using it** counts `test_*` functions whose body uses the imported alias or a name imported from it. Imports made inside a test body are included; a module reached only through the HTTP API is **not** counted (so `0` does not mean untested: see the notes below the table).

| Module | Test files importing | Test functions using |
|---|---|---|
| `veyrs.__main__` | 0 | 0 |
| `veyrs.cli` | 9 | 12 |
| `veyrs.config` | 8 | 19 |
| `veyrs.db` | 53 | 372 |
| `veyrs.engines.cvss` | 2 | 5 |
| `veyrs.engines.risk` | 1 | 24 |
| `veyrs.intel.feeds` | 4 | 17 |
| `veyrs.main` | 5 | 4 |
| `veyrs.observability` | 2 | 6 |
| `veyrs.security.agent_auth` | 0 | 0 |
| `veyrs.security.auth` | 7 | 2 |
| `veyrs.security.deps` | 1 | 2 |
| `veyrs.security.mfa` | 2 | 12 |
| `veyrs.security.mfa_delivery` | 3 | 7 |
| `veyrs.security.permissions` | 2 | 2 |
| `veyrs.security.ratelimit` | 2 | 3 |
| `veyrs.security.scope` | 6 | 11 |
| `veyrs.security.secret_vault` | 1 | 3 |
| `veyrs.security.secrets` | 7 | 39 |
| `veyrs.services.agents` | 6 | 40 |
| `veyrs.services.ai` | 1 | 38 |
| `veyrs.services.analytics` | 2 | 15 |
| `veyrs.services.attribution` | 1 | 0 |
| `veyrs.services.audit` | 1 | 2 |
| `veyrs.services.autoticket` | 2 | 7 |
| `veyrs.services.cmdb` | 3 | 50 |
| `veyrs.services.compliance` | 1 | 24 |
| `veyrs.services.correlation` | 10 | 16 |
| `veyrs.services.cvss_assist` | 1 | 6 |
| `veyrs.services.dedupe` | 2 | 11 |
| `veyrs.services.digest` | 1 | 13 |
| `veyrs.services.docs` | 1 | 20 |
| `veyrs.services.documents` | 2 | 15 |
| `veyrs.services.endpoints` | 1 | 7 |
| `veyrs.services.engagements` | 5 | 20 |
| `veyrs.services.fix_plan` | 1 | 5 |
| `veyrs.services.importers` | 7 | 48 |
| `veyrs.services.intel_pipeline` | 1 | 4 |
| `veyrs.services.intel_schedule` | 1 | 4 |
| `veyrs.services.intelligence` | 16 | 18 |
| `veyrs.services.inventory` | 3 | 19 |
| `veyrs.services.itsm` | 4 | 31 |
| `veyrs.services.itsm_inbound` | 2 | 5 |
| `veyrs.services.ldap_auth` | 3 | 20 |
| `veyrs.services.mfa_admin` | 1 | 1 |
| `veyrs.services.network_requirements` | 1 | 6 |
| `veyrs.services.notifications` | 3 | 9 |
| `veyrs.services.oidc_auth` | 1 | 1 |
| `veyrs.services.radius_auth` | 1 | 7 |
| `veyrs.services.remediation` | 1 | 0 |
| `veyrs.services.report_builder` | 1 | 8 |
| `veyrs.services.reporting` | 2 | 14 |
| `veyrs.services.risk` | 11 | 0 |
| `veyrs.services.risk_register` | 0 | 0 |
| `veyrs.services.risk_register_mode` | 0 | 0 |
| `veyrs.services.scanners` | 1 | 13 |
| `veyrs.services.scanning` | 1 | 5 |
| `veyrs.services.search` | 1 | 5 |
| `veyrs.services.secret_storage` | 2 | 14 |
| `veyrs.services.sla` | 11 | 5 |
| `veyrs.services.software_inventory` | 1 | 10 |
| `veyrs.services.team_import` | 1 | 8 |
| `veyrs.services.teams` | 0 | 0 |
| `veyrs.services.threatintel` | 1 | 10 |
| `veyrs.services.ticketing` | 5 | 11 |
| `veyrs.services.ticketing_mode` | 1 | 0 |
| `veyrs.services.updates` | 2 | 18 |
| `veyrs.services.versions` | 5 | 22 |
| `veyrs.services.views` | 1 | 9 |
| `veyrs.services.workflow` | 3 | 6 |
| `veyrs.services.xmlsafe` | 1 | 2 |

Notes on the zeros and the surprises (checked by grepping the module name across `tests/`):

- `veyrs.security.agent_auth` — no test names the module, but its behaviour (agent token is not a principal, tenant isolation of jobs) is exercised through `/agents/self/*` in `tests/test_phase16_agents.py::test_agent_token_is_not_a_principal` and `::test_enrol_queue_claim_and_submit_over_http`.
- `veyrs.services.risk_register` and `risk_register_mode` — covered over HTTP by `tests/test_phase46_risk_register.py` and `tests/test_phase47_risk_matrix.py` (no direct import).
- `veyrs.services.teams` — covered over HTTP (`test_phase26_team_ownership.py`, `test_phase26_scope.py`).
- `veyrs.services.risk` shows files but `0` functions: tests alias it as `risk_service` and call it through helpers, not from the `test_*` body.
- `veyrs.db` appears in 53 files because it supplies `SessionLocal` and `set_tenant`; it is a dependency, not a coverage signal.
- The pure scoring engine `veyrs.engines.risk` is used by 24 functions in one file (`tests/test_phase3_risk.py`); `veyrs.engines.cvss` is validated against 4,379 official vectors in `tests/test_cvss_official.py`.

## Test files

All 94 modules (0.39.1). "Fn" is the AST function count, "Exp." the count with literal parametrize expanded; the last column is the first sentence of the module docstring.

| File | Fn | Exp. | Module docstring |
|---|---|---|---|
| `test_api_unit.py` | 2 | 2 | The API unit must be able to start on a git-deployed node. |
| `test_audit_rls.py` | 6 | 6 | The audit trails are tenant-isolated, and nothing that writes them breaks. |
| `test_client_address.py` | 8 | 8 | One rule for "what is the caller's IP address". |
| `test_console_configure_frame.py` | 10 | 10 | Configure has its own page with its own menu (0.39.0, owner request); 0.39.1 adds the folding rail. |
| `test_console_design_system.py` | 10 | 10 | Guards for the 0.36.0 console redesign. |
| `test_console_dialog_payloads.py` | 6 | 6 | 0.35.3: the console's create dialogs must send what the API accepts. |
| `test_console_docs_link.py` | 5 | 5 | The console Documentation link must leave the console (0.38.1). |
| `test_console_layout_classes.py` | 5 | 5 | Every class the console asks for must exist in the stylesheet. |
| `test_console_nav_pin_bottom.py` | 5 | 5 | Configure sits at the foot of the console sidebar (0.38.2, 0.38.3). |
| `test_console_readability_0391.py` | 4 | 4 | 0.39.1: readable values in Configure and inventory screens. |
| `test_console_redesign_0370.py` | 9 | 9 | Guards for the 0.37.0 console round. |
| `test_console_redesign_0380.py` | 6 | 8 | Guards for the 0.38.0 console redesign ("Midnight Ops"). |
| `test_console_vhost_names.py` | 5 | 5 | The console vhost must answer to every hostname that reaches the nodes. |
| `test_container_images.py` | 19 | 19 | Guards for the PUBLISHED images and the privileges the stack runs with. |
| `test_container_stack.py` | 27 | 27 | Guards for the container stack (docker/). |
| `test_cvss_official.py` | 6 | 6 | Validate the VEYRS CVSS_ENGINE against official / reference expected scores. |
| `test_distro_version_normalisation.py` | 12 | 23 | A distro package string must never be compared as an upstream version. |
| `test_docs_are_current.py` | 12 | 26 | The documentation guards. |
| `test_docs_center.py` | 17 | 17 | The VEYRS Docs Center (`site/build.py`, served as the docs site). |
| `test_docs_diagrams.py` | 2 | 2 | Every Mermaid diagram in docs/ has its pre-rendered SVG. |
| `test_docs_reference_is_current.py` | 1 | 1 | The generated reference must describe the code it was generated from. |
| `test_docs_worked_example.py` | 4 | 4 | The worked example in DOCKER_COMPOSE_MANUAL.md §5.D stays true to the files. |
| `test_epss_retention.py` | 8 | 8 | EPSS history retention (0.33.2). |
| `test_executable_bits.py` | 1 | 1 | Scripts operators run as ./name keep their executable bit (0.39.1). Parametrized over a variable list of 5 scripts; skips outside a git checkout. |
| `test_installer_dry_run_guard.py` | 5 | 5 | install.sh: --dry-run must survive a host where nothing is installed yet. |
| `test_installer_timers.py` | 6 | 6 | 0.35.3: a native install refreshes its intelligence. |
| `test_login_error_message.py` | 7 | 7 | A failed sign-in stops presenting itself as an expired session. |
| `test_nvd_rejects.py` | 5 | 5 | One record the database refuses must not stop the NVD feed (0.32.5). |
| `test_phase10_hardening.py` | 26 | 31 | Phase 10: production hardening. |
| `test_phase15_api.py` | 19 | 19 | Phase 15: the REST surface for engagements, endpoints and risk acceptance. |
| `test_phase15_parsers.py` | 24 | 36 | Phase 15: the modern parser catalogue. |
| `test_phase15_unified_ingest.py` | 35 | 41 | Phase 15: the unified ingestion core. |
| `test_phase16_agents.py` | 30 | 33 | Phase 16: execution agents. |
| `test_phase16_runner.py` | 7 | 15 | Phase 16: the reference agent runner's safety-critical logic. |
| `test_phase17_itsm_inbound.py` | 20 | 22 | Phase 17: inbound ITSM events (the return leg of the sync). |
| `test_phase18_hardening.py` | 18 | 18 | Phase 18: four defects found by running VEYRS against itself. |
| `test_phase19_coverage.py` | 12 | 16 | Phase 19 - a scan that saw nothing is not a scan that found nothing. |
| `test_phase20_artifact_identity.py` | 12 | 12 | Phase 20: a container image reference is not a host:port. |
| `test_phase21_inventory_correlation.py` | 28 | 34 | Phase 21: intelligence that arrives on its own, and inventory it can match. |
| `test_phase24_dependencies.py` | 9 | 9 | Phase 24 - the dependency set is declared, and the declaration is true. |
| `test_phase24_mfa.py` | 19 | 19 | Phase 24 - MFA is a control, not a checkbox. |
| `test_phase25_cwe_catalog.py` | 22 | 22 | Phase 25: the dashboard's Name column, and the XML guard that never ran. |
| `test_phase26_scope.py` | 23 | 23 | Phase 26b - team segregation: a scoped identity sees its teams and no more. |
| `test_phase26_team_ownership.py` | 14 | 14 | Phase 26 - assets and findings divide by team, and the division is usable. |
| `test_phase27_team_dashboard.py` | 11 | 11 | Phase 27 - the dashboards can be read one team at a time. |
| `test_phase28_sla_scope.py` | 23 | 23 | Phase 28 - the SLA endpoints stop answering with the estate. |
| `test_phase2_core.py` | 28 | 28 | Phase 2 - core platform: auth, RBAC, tenancy, audit. |
| `test_phase30_scanner_page.py` | 17 | 17 | Phase 30 - the scanner stops being invisible, and its version stops being line noise. |
| `test_phase31_console_wiring.py` | 5 | 5 | Phase 31 - a missing element must not blank the console. |
| `test_phase32_nav_collapsed.py` | 9 | 9 | Phase 32 - the sidebar starts collapsed. |
| `test_phase33_scanner_connectors.py` | 23 | 23 | Phase 33 - pulling from a scanner instead of waiting to be uploaded to. |
| `test_phase34_inventory_and_scanning.py` | 24 | 26 | Phase 34 - the estate's inventory arrives with the scan, and scanning can stop. |
| `test_phase35_operability.py` | 47 | 47 | Phase 35 - the console stops being a data model, and three things stop lying. |
| `test_phase36_disposition.py` | 43 | 47 | Phase 36 - the disposition half: triage, saved views, digest, palette. |
| `test_phase37_estate_lens.py` | 15 | 15 | Phase 37: intelligence browsing scoped to the software this estate runs. |
| `test_phase38_dashboard_preference.py` | 19 | 19 | Phase 38 - the dashboard scope stops being a per-tab accident. |
| `test_phase39_scanning_nav.py` | 17 | 17 | Phase 39 - an ingest-only deployment stops advertising a scanner. |
| `test_phase3_intel.py` | 26 | 35 | Phase 3 (part 2): version matching, intelligence ingestion, correlation, SLA. |
| `test_phase3_risk.py` | 24 | 24 | Phase 3 - the risk engine. |
| `test_phase40_asset_sources.py` | 51 | 51 | Phase 40 -- external asset sources: CMDB export, generic JSON API, NetBox. |
| `test_phase41_directory_auth.py` | 54 | 64 | Phase 41 - a second login identifier, and a directory to check it against. |
| `test_phase42_console_screens.py` | 7 | 7 | Source-level guardrails for the two new Administration screens. |
| `test_phase42_netbox_and_team_import.py` | 37 | 37 | Phase 42 -- NetBox that a tenant can shape, and teams that come from somewhere. |
| `test_phase43_jira.py` | 29 | 29 | Phase 43 -- the Jira connector nobody could configure, and its missing monitoring leg. |
| `test_phase44_confluence.py` | 25 | 25 | Phase 44 -- publishing VEYRS runbooks into Confluence. |
| `test_phase45_ticketing_mode.py` | 20 | 20 | Phase 45 -- internal queue or external ITSM, and the relation that replaces the Tickets se |
| `test_phase46_risk_register.py` | 24 | 30 | Phase 46 -- the risk register, its RACI, and the switch that removes it. |
| `test_phase47_risk_matrix.py` | 7 | 7 | Phase 47 -- the dialog that explains the 5x5, and the ladder it must not copy. |
| `test_phase48_secret_vault.py` | 45 | 46 | Phase 48 - stored credentials in an external vault (HashiCorp Vault / OpenBao KV v2). |
| `test_phase49_fix_plan.py` | 28 | 43 | Phase 49 - the fix plan: which version fixes this, and how hard is getting there. |
| `test_phase4_itsm.py` | 22 | 22 | Phase 4: ticketing, ITIL lifecycle, workflow engine, notifications. |
| `test_phase50_report_builder.py` | 37 | 57 | Phase 50 - the report builder: ad-hoc reports that cannot escape authorization. |
| `test_phase51_attribution.py` | 20 | 20 | Phase 51 - "why did this finding change?": attribution of closes and reopens. |
| `test_phase52_release_signing.py` | 24 | 24 | Phase 52 -- signed releases. |
| `test_phase52_updates.py` | 25 | 29 | Phase 52 -- the in-product update check and the privileged self-update. |
| `test_phase53_system_inventory.py` | 17 | 17 | Phase 53 -- Installed software and Network access (Administration). |
| `test_phase54_mfa_methods.py` | 17 | 17 | Phase 54 -- two-factor by e-mail, by Telegram, and recovery codes. |
| `test_phase55_local_update.py` | 15 | 15 | Phase 55 -- software update from a LOCAL copy (upload or a mounted directory). |
| `test_phase56_platform_admin.py` | 4 | 4 | Phase 56 (0.34.1) -- somebody can open the installation-wide pages. |
| `test_phase57_radius.py` | 15 | 15 | Phase 57 -- RADIUS sign-in (AAA) with the server's own second factor. |
| `test_phase58_oidc.py` | 7 | 12 | Phase 58 -- single sign-on (OpenID Connect), configurable and off by default. |
| `test_phase59_cve_exposure.py` | 8 | 8 | 0.35.1: the "Affecting you" lens and the CVE page's affected-assets table. |
| `test_phase5_intel_docs.py` | 25 | 29 | Phase 5: document intelligence, threat feeds, knowledge base, search. |
| `test_phase6_ai.py` | 52 | 67 | Phase 6: AI gateway, guardrails, NL search. |
| `test_phase7_compliance.py` | 38 | 38 | Phase 7: compliance engine. |
| `test_phase8_integrations.py` | 43 | 47 | Phase 8: scanner importers and ITSM connectors. |
| `test_phase9_reporting.py` | 34 | 37 | Phase 9: analytics, dashboards and report exports. |
| `test_restore_as_superuser.py` | 6 | 6 | 0.35.3: scripts/restore.sh restores as a superuser, never as the app role. |
| `test_schema_reconcile.py` | 4 | 4 | The reconciler must be able to build every invariant the models declare. |
| `test_secret_rekey.py` | 10 | 10 | Rotating VEYRS_ENCRYPTION_KEY without stranding a stored credential. |
| `test_site_render.py` | 17 | 17 | The site renderer and the product site's manual pages. |
| `test_sync_intel_script.py` | 6 | 9 | scripts/sync-intel.sh runs the feeds that `veyrs intel-due` says are due. |
| `test_widen_columns.py` | 2 | 12 | `sync_columns` may widen a VARCHAR and must not retype anything else. |
| `test_write_paths.py` | 6 | 6 | Every audited write path, exercised over HTTP. |

## Reading the matrix

- **Strong**: Authentication (17/18), Administration (44/47), Engagements (14/15), Policies (15/16), Risk register, Saved views, Operations — every route referenced, usually with dedicated phase files.
- **Thin**: Assets (9/17: the product-install, inventory alias, resolve/import and rescan routes), Threat intelligence (8/14: EPSS history, feed trigger routes), Intelligence & knowledge (11/19: article creation, news, semantic search, revisions), AI (12/19: `explain`, `remediation`, `ticket-draft`, `suggest-team`, `threat-summary` are tested at gateway level but not over HTTP), CVSS (6/9: `compare`, `severity`, `metrics/{version}`).
- The three CVSS version corpora make `veyrs.engines.cvss` the best-verified code in the repository; the HTTP layer over it is the thinnest.
