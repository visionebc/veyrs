---
title: Traceability matrix
purpose: Links every code component to the documents that describe it and the tests that exercise it.
scope: Backend modules, console files, scripts, infrastructure and site builders. Measured by text search, so it shows mentions, not quality.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py]
related: [reference/coverage.md, reference/inventory.md]
---

# Traceability matrix

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.
> Documentation-derived: rewritten by every run, not byte-checked by tests (it would fail on any doc edit).


**Method.** *Documentation* = hand-written docs (generated references excluded) that mention the module's repo path, its path under `backend/veyrs/`, or its dotted name. *Tested* = a test file mentions the dotted module name or imports it (`from veyrs.x import module`). A module exercised only indirectly (through the HTTP API) shows as not tested even when it is: treat *Neither* as "look here first", not as "untested".

## Backend modules

162 modules: 150 mentioned in documentation, 119 referenced by tests.

| Module | Lines | Responsibility | Depends on (veyrs.*) | Documentation | State |
|---|---|---|---|---|---|
| `__init__.py` | 5 | VEYRS - Unified Cybersecurity Risk Management. | config | [ADMIN_GUIDE.md](../ADMIN_GUIDE.md), [0001-postgres-rls.md](../ADRs/0001-postgres-rls.md), [0002-cvss-from-spec.md](../ADRs/0002-cvss-from-spec.md), [0003-ai-gateway.md](../ADRs/0003-ai-gateway.md) +97 | Tested + documented |
| `__main__.py` | 3 |  | cli | [overview.md](../architecture/overview.md), [coverage-matrix.md](../testing/coverage-matrix.md) | Documented |
| `api/__init__.py` | 1 | HTTP layer. Versioned; v1 is the only stable contract. |  | - | Tested |
| `api/v1/__init__.py` | 47 | v1 API router assembly. |  | [API.md](../API.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [guide.md](../api/guide.md), [c4.md](../architecture/c4.md) +2 | Tested + documented |
| `api/v1/admin.py` | 1186 | Tenant administration: organizations, users, teams, departments, roles, API keys and the audit trail. | api.v1.schemas, models.audit, models.tenancy, security, security.auth, security.deps, security.platform, services | [README.md](../audit/README.md), [risks-and-debt.md](../audit/risks-and-debt.md), [lifecycle.md](../database/lifecycle.md), [administration-platform.md](../functional/administration-platform.md) +6 | Tested + documented |
| `api/v1/agents.py` | 733 | Execution agents: control plane and agent data plane (spec section 33). | api.v1.schemas, models, security.agent_auth, security.deps, services | [guide.md](../api/guide.md), [sequences.md](../architecture/sequences.md), [README.md](../audit/README.md), [risks-and-debt.md](../audit/risks-and-debt.md) +6 | Documented |
| `api/v1/ai.py` | 712 | AI gateway, assistant and natural-language search endpoints (spec 19/20). | api.v1.schemas, models, models.audit, security.deps, security.secrets, services, services.ai, services.ai.providers | [0004-closed-query-grammar.md](../ADRs/0004-closed-query-grammar.md), [AI_SECURITY.md](../AI_SECURITY.md), [ARCHITECTURE.md](../ARCHITECTURE.md), [README.md](../audit/README.md) +8 | Tested + documented |
| `api/v1/assets.py` | 613 | Asset inventory API (spec sections 7 and 8). | api.v1.schemas, api.v1.vuln_schemas, models, security, security.deps, services, services.versions | [README.md](../audit/README.md), [risks-and-debt.md](../audit/risks-and-debt.md), [undocumented-features.md](../audit/undocumented-features.md), [lifecycle.md](../database/lifecycle.md) +1 | Tested + documented |
| `api/v1/attribution.py` | 70 | Why did this finding change? (see services/attribution.py) | api.v1.findings, security.deps, services | [README.md](../audit/README.md), [undocumented-features.md](../audit/undocumented-features.md), [vulnerability-management.md](../functional/vulnerability-management.md) | Documented |
| `api/v1/auth.py` | 1293 | Authentication endpoints: login, refresh, logout, me, password change. | api.v1.schemas, config, db, models.tenancy, security, security.auth, security.deps, services | [0007-stateless-app-nodes.md](../ADRs/0007-stateless-app-nodes.md), [APP_FLOW.md](../APP_FLOW.md), [SECURITY.md](../SECURITY.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md) +19 | Tested + documented |
| `api/v1/cmdb.py` | 631 | Asset sources: importing an external inventory and comparing two of them. | api.v1.uploads, models, models.cmdb, security.deps, security.secrets, services | [risks-and-debt.md](../audit/risks-and-debt.md), [undocumented-features.md](../audit/undocumented-features.md), [lifecycle.md](../database/lifecycle.md), [cmdb-asset-sources.md](../functional/cmdb-asset-sources.md) +2 | Documented |
| `api/v1/compliance.py` | 550 | Compliance endpoints (spec sections 16 and 27). | api.v1.schemas, api.v1.updates, api.v1.uploads, models, security.deps, services | [DATABASE.md](../DATABASE.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [guide.md](../api/guide.md), [README.md](../audit/README.md) +4 | Documented |
| `api/v1/cvss.py` | 132 | Interactive CVSS calculator endpoints. | api.v1.schemas, engines, security.deps, services | [cvss.md](../functional/cvss.md) | Documented |
| `api/v1/engagements.py` | 587 | Engagements, scan tests, endpoints and risk acceptance (spec section 32). | api.v1.schemas, models, security.deps, services | [inconsistencies.md](../audit/inconsistencies.md), [undocumented-features.md](../audit/undocumented-features.md), [queries.md](../database/queries.md), [engagements-scan-import.md](../functional/engagements-scan-import.md) +1 | Documented |
| `api/v1/findings.py` | 584 | Vulnerability and finding API: the operator's daily work queue. | api.v1.schemas, api.v1.vuln_schemas, engines, models, security, security.deps, services | [USER_GUIDE.md](../USER_GUIDE.md), [USER_MANUAL.md](../USER_MANUAL.md), [guide.md](../api/guide.md), [README.md](../audit/README.md) +5 | Tested + documented |
| `api/v1/fix_plan.py` | 283 | Fix plan API, and the operator's vendor upgrade-path rules it applies. | api.v1.assets, api.v1.findings, models.upgrade, security, security.deps, services, services.versions | [undocumented-features.md](../audit/undocumented-features.md), [remediation-fix-plans.md](../functional/remediation-fix-plans.md) | Documented |
| `api/v1/integrations.py` | 1189 | Scanner imports and ITSM connectors (spec sections 14 and 31). | api.v1.schemas, api.v1.uploads, db, models, models.integration, security.deps, security.secrets, services … | [0006-no-autoclose-on-absence.md](../ADRs/0006-no-autoclose-on-absence.md), [0009-closure-per-covered-asset.md](../ADRs/0009-closure-per-covered-asset.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [guide.md](../api/guide.md) +9 | Tested + documented |
| `api/v1/intel.py` | 601 | Threat-intelligence API: CVE, CWE, CPE, EPSS, CISA KEV and feed ingestion. | api.v1.schemas, api.v1.updates, api.v1.vuln_schemas, db, models, security, security.deps, services | [guide.md](../api/guide.md), [inconsistencies.md](../audit/inconsistencies.md), [risks-and-debt.md](../audit/risks-and-debt.md), [queries.md](../database/queries.md) +4 | Tested + documented |
| `api/v1/knowledge.py` | 889 | Documents, threat intelligence feeds, knowledge base and global search. | api.v1.schemas, config, models, models.integration, security.deps, services | [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [guide.md](../api/guide.md), [README.md](../audit/README.md), [risks-and-debt.md](../audit/risks-and-debt.md) +5 | Documented |
| `api/v1/policies.py` | 361 | Policy administration: SLA, escalation and assignment rules. | api.v1.schemas, api.v1.vuln_schemas, models, security, security.deps, services | [undocumented-features.md](../audit/undocumented-features.md), [sla-escalation.md](../functional/sla-escalation.md), [automation.md](../integrations/automation.md) | Documented |
| `api/v1/report_builder.py` | 256 | Report builder API: ad-hoc reports from a curated catalog, plus saved reports. | security.deps, services | [guide.md](../api/guide.md), [undocumented-features.md](../audit/undocumented-features.md), [dashboards-reports.md](../functional/dashboards-reports.md) | Tested + documented |
| `api/v1/reports.py` | 197 | Dashboards and report exports (spec sections 27 and 29). | security, security.deps, services | [README.md](../audit/README.md), [dashboards-reports.md](../functional/dashboards-reports.md), [authorization.md](../security/authorization.md) | Documented |
| `api/v1/risk_register.py` | 470 | Risk register API: risks that are not findings, and who answers for them. | api.v1.schemas, models.risk_register, models.tenancy, security, security.deps, services | [README.md](../audit/README.md), [undocumented-features.md](../audit/undocumented-features.md), [lifecycle.md](../database/lifecycle.md), [risk-register.md](../functional/risk-register.md) | Documented |
| `api/v1/schemas.py` | 704 | Request/response models for the v1 API. | config | [API.md](../API.md), [guide.md](../api/guide.md), [dependencies.md](../architecture/dependencies.md), [README.md](../audit/README.md) +4 | Tested + documented |
| `api/v1/system.py` | 38 | Installed software and network requirements of this installation. | api.v1.updates, security.deps, services | [undocumented-features.md](../audit/undocumented-features.md), [updates.md](../functional/updates.md), [authorization.md](../security/authorization.md) | Documented |
| `api/v1/team_import.py` | 125 | Bringing teams in from NetBox or from the directory. | models.cmdb, security.deps, services | [undocumented-features.md](../audit/undocumented-features.md), [authentication-accounts.md](../functional/authentication-accounts.md), [itsm-and-webhooks.md](../integrations/itsm-and-webhooks.md) | Documented |
| `api/v1/tickets.py` | 911 | Ticketing, workflow and notification API (spec sections 13, 14, 15, 30). | api.v1.schemas, models, security, security.deps, services | [ARCHITECTURE.md](../ARCHITECTURE.md), [guide.md](../api/guide.md), [README.md](../audit/README.md), [inconsistencies.md](../audit/inconsistencies.md) +7 | Tested + documented |
| `api/v1/trust_store.py` | 149 | TLS trust store: the CAs this installation accepts when it connects out. | api.v1.updates, models.trust, security.deps, services | [trust-store.md](../functional/trust-store.md) | Documented |
| `api/v1/updates.py` | 184 | Software update: the installation's version, the latest release, and a request for the root updater to apply it. | api.v1.admin, security, security.deps, services | [README.md](../audit/README.md), [undocumented-features.md](../audit/undocumented-features.md), [updates.md](../functional/updates.md), [upgrade-rollback.md](../operations/upgrade-rollback.md) +2 | Documented |
| `api/v1/uploads.py` | 24 | Bounded upload reading shared by the routes that accept files. |  | - | Tested |
| `api/v1/views.py` | 148 | Saved views: an operator's own queues. | models, security.deps, services | [undocumented-features.md](../audit/undocumented-features.md), [README.md](../database/README.md), [dashboards-reports.md](../functional/dashboards-reports.md) | Tested + documented |
| `api/v1/vuln_schemas.py` | 590 | Request/response models for assets, intelligence, vulnerabilities and SLA. | models.assets, models.vulnerability | [assets-inventory.md](../functional/assets-inventory.md), [threat-intelligence.md](../functional/threat-intelligence.md), [vulnerability-management.md](../functional/vulnerability-management.md) | Tested + documented |
| `api/v1/web_tls.py` | 233 | The certificate VEYRS serves: request (CSR), attach the signed certificate, install it on every app node, roll back. | api.v1.updates, security.deps, services | [web-certificate.md](../functional/web-certificate.md) | Documented |
| `cli.py` | 941 | VEYRS operational CLI. | config, db, engines, intel, models, schema_steps, security, security.auth … | [ADMIN_GUIDE.md](../ADMIN_GUIDE.md), [0001-postgres-rls.md](../ADRs/0001-postgres-rls.md), [0008-state-off-host-and-proven-backups.md](../ADRs/0008-state-off-host-and-proven-backups.md), [DATABASE.md](../DATABASE.md) +39 | Tested + documented |
| `config.py` | 313 | VEYRS runtime configuration. |  | [ADMIN_GUIDE.md](../ADMIN_GUIDE.md), [0007-stateless-app-nodes.md](../ADRs/0007-stateless-app-nodes.md), [README.md](../ADRs/README.md), [AI_SECURITY.md](../AI_SECURITY.md) +36 | Tested + documented |
| `data/__init__.py` | 1 | Static reference data shipped with VEYRS (framework catalogues, lookup tables). |  | - | Neither |
| `data/frameworks.py` | 322 | Built-in compliance catalogues. |  | [0005-partial-catalogues.md](../ADRs/0005-partial-catalogues.md), [CONTRIBUTING.md](../CONTRIBUTING.md), [c4.md](../architecture/c4.md), [overview.md](../executive/overview.md) +1 | Documented |
| `db.py` | 102 | Database engine, session factory and the tenant-scoped session helper. | config | [0001-postgres-rls.md](../ADRs/0001-postgres-rls.md), [README.md](../ADRs/README.md), [DATABASE.md](../DATABASE.md), [DEPLOYMENT.md](../DEPLOYMENT.md) +31 | Tested + documented |
| `engines/__init__.py` | 4 | VEYRS decision engines: CVSS, EPSS, KEV, risk, SLA, escalation, workflow. |  | - | Tested |
| `engines/cvss/__init__.py` | 200 | VEYRS CVSS_ENGINE - one façade over the versioned calculators. | engines.cvss.common | [cvss.md](../functional/cvss.md) | Tested + documented |
| `engines/cvss/common.py` | 176 | Shared helpers for the VEYRS CVSS engine. |  | [0002-cvss-from-spec.md](../ADRs/0002-cvss-from-spec.md), [TESTING_GUIDE.md](../TESTING_GUIDE.md) | Documented |
| `engines/cvss/v2.py` | 159 | CVSS v2.0 scoring, per the FIRST "A Complete Guide to the CVSS Version 2.0". | engines.cvss.common | [0002-cvss-from-spec.md](../ADRs/0002-cvss-from-spec.md), [cvss.md](../functional/cvss.md) | Documented |
| `engines/cvss/v3.py` | 217 | CVSS v3.0 and v3.1 scoring, per the FIRST specification documents. | engines.cvss.common | [cvss.md](../functional/cvss.md) | Documented |
| `engines/cvss/v4.py` | 372 | CVSS v4.0 scoring - faithful port of the FIRST.org reference implementation. | engines.cvss.common, engines.cvss.v4_tables | [0002-cvss-from-spec.md](../ADRs/0002-cvss-from-spec.md), [cvss.md](../functional/cvss.md) | Documented |
| `engines/cvss/v4_tables.py` | 396 | CVSS v4.0 official scoring tables. |  | [0002-cvss-from-spec.md](../ADRs/0002-cvss-from-spec.md) | Documented |
| `engines/risk.py` | 572 | VEYRS Risk Engine. | db, models, models.assets, services | [ARCHITECTURE.md](../ARCHITECTURE.md), [README.md](../README.md), [c4.md](../architecture/c4.md), [dependencies.md](../architecture/dependencies.md) +11 | Tested + documented |
| `intel/__init__.py` | 11 | Outbound collection for VEYRS's intelligence feeds. |  | - | Tested |
| `intel/feeds.py` | 559 | Fetch NVD 2.0, EPSS and CISA KEV, hand them to the ingest layer, correlate. | config, db, services | [INTEGRATIONS.md](../INTEGRATIONS.md), [c4.md](../architecture/c4.md), [data-flows.md](../architecture/data-flows.md), [dependencies.md](../architecture/dependencies.md) +12 | Tested + documented |
| `main.py` | 219 | VEYRS ASGI application. | api.v1, config, db, observability, security.ratelimit, security.secrets, security.tenant_guard | [API.md](../API.md), [ARCHITECTURE.md](../ARCHITECTURE.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [README.md](../README.md) +27 | Tested + documented |
| `models/__init__.py` | 131 | SQLAlchemy models. Importing this package registers every table on Base.metadata. | models.agent, models.ai, models.assets, models.audit, models.base, models.cmdb, models.compliance, models.engagement … | - | Tested |
| `models/agent.py` | 334 | Execution agents: remote workers that RUN scanners (spec section 33). | models.base | [data-flows.md](../architecture/data-flows.md), [er-diagrams.md](../database/er-diagrams.md), [agents.md](../functional/agents.md), [agent.md](../integrations/agent.md) | Tested + documented |
| `models/ai.py` | 215 | AI gateway configuration and conversation state (spec sections 19 and 20). | models.assets, models.base | [0003-ai-gateway.md](../ADRs/0003-ai-gateway.md), [README.md](../audit/README.md), [undocumented-features.md](../audit/undocumented-features.md), [er-diagrams.md](../database/er-diagrams.md) +2 | Tested + documented |
| `models/assets.py` | 220 | Tenant asset inventory, business services and asset<->product installation. | models.base | [ARCHITECTURE.md](../ARCHITECTURE.md), [overview.md](../architecture/overview.md), [er-diagrams.md](../database/er-diagrams.md), [overview.md](../executive/overview.md) +1 | Documented |
| `models/audit.py` | 116 | Append-only audit trail. | models.base | [THREAT_MODEL.md](../THREAT_MODEL.md), [inconsistencies.md](../audit/inconsistencies.md), [undocumented-features.md](../audit/undocumented-features.md), [README.md](../database/README.md) +4 | Tested + documented |
| `models/base.py` | 99 | Declarative base plus the mixins every VEYRS table is built from. |  | [0001-postgres-rls.md](../ADRs/0001-postgres-rls.md), [DATABASE.md](../DATABASE.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [README.md](../audit/README.md) +3 | Tested + documented |
| `models/cmdb.py` | 378 | External asset sources: a CMDB export, an arbitrary JSON API, or NetBox. | models.base | [er-diagrams.md](../database/er-diagrams.md), [cmdb-asset-sources.md](../functional/cmdb-asset-sources.md) | Tested + documented |
| `models/compliance.py` | 348 | Compliance framework, control, evidence and assessment model (spec 16/27). | models.base | [0005-partial-catalogues.md](../ADRs/0005-partial-catalogues.md), [README.md](../database/README.md), [er-diagrams.md](../database/er-diagrams.md), [compliance.md](../functional/compliance.md) | Documented |
| `models/engagement.py` | 414 | Engagement / test scoping, endpoints and risk acceptance (spec section 32). | models.base | [README.md](../audit/README.md), [er-diagrams.md](../database/er-diagrams.md), [engagements-scan-import.md](../functional/engagements-scan-import.md) | Documented |
| `models/integration.py` | 277 | Importer runs and external-system links (spec sections 14 and 31). | models.base | [er-diagrams.md](../database/er-diagrams.md) | Tested + documented |
| `models/intelligence.py` | 323 | Global security intelligence: CVE, CWE, CPE, EPSS, CISA KEV, vendor/product. | models.base | [er-diagrams.md](../database/er-diagrams.md) | Tested + documented |
| `models/knowledge.py` | 265 | Threat intelligence feeds, document intelligence and the knowledge base. | models.base | [inconsistencies.md](../audit/inconsistencies.md), [risks-and-debt.md](../audit/risks-and-debt.md), [undocumented-features.md](../audit/undocumented-features.md), [README.md](../database/README.md) +1 | Tested + documented |
| `models/report_queries.py` | 48 | Saved report-builder queries: a question an operator asks more than once. | models.base | [undocumented-features.md](../audit/undocumented-features.md), [queries.md](../database/queries.md) | Documented |
| `models/risk_register.py` | 318 | The risk register: risks that are not findings, and the RACI that owns them. | models.base | [er-diagrams.md](../database/er-diagrams.md), [risk-register.md](../functional/risk-register.md) | Tested + documented |
| `models/sla.py` | 103 | SLA and escalation policies (spec sections 11 and 12). | models.base | [README.md](../audit/README.md), [undocumented-features.md](../audit/undocumented-features.md), [er-diagrams.md](../database/er-diagrams.md), [sla-escalation.md](../functional/sla-escalation.md) | Documented |
| `models/tenancy.py` | 319 | Organizations, users, teams, departments, roles and permissions. | models.base | [er-diagrams.md](../database/er-diagrams.md), [authentication-accounts.md](../functional/authentication-accounts.md) | Tested + documented |
| `models/ticketing.py` | 295 | Ticketing and ITIL record types (spec sections 14 and 15). | models.base | [er-diagrams.md](../database/er-diagrams.md) | Tested + documented |
| `models/trust.py` | 68 | TLS trust store: the certificate authorities this installation ACCEPTS when it connects out (CMDB, scanners, ITSM, direc | models.base | [trust-store.md](../functional/trust-store.md) | Documented |
| `models/upgrade.py` | 60 | Operator-maintained vendor upgrade-path rules, read by the fix plan. | models.base | [README.md](../audit/README.md), [undocumented-features.md](../audit/undocumented-features.md), [remediation-fix-plans.md](../functional/remediation-fix-plans.md) | Tested + documented |
| `models/views.py` | 69 | Saved views: the filter set an operator opens every morning. | models.base | [queries.md](../database/queries.md) | Documented |
| `models/vulnerability.py` | 390 | Tenant-side vulnerability management: findings, their lifecycle, risk scores and the configurable risk profiles that pro | models.base | [0009-closure-per-covered-asset.md](../ADRs/0009-closure-per-covered-asset.md), [APP_FLOW.md](../APP_FLOW.md), [USER_GUIDE.md](../USER_GUIDE.md), [data-flows.md](../architecture/data-flows.md) +7 | Tested + documented |
| `models/web_tls.py` | 114 | The certificate VEYRS PRESENTS to browsers (the mirror image of the trust store, which holds the CAs it ACCEPTS when it | models.base | [web-certificate.md](../functional/web-certificate.md) | Tested + documented |
| `models/workflow.py` | 186 | Workflow and notification models (spec sections 13 and 30). | models.base | [ARCHITECTURE.md](../ARCHITECTURE.md), [README.md](../audit/README.md), [risks-and-debt.md](../audit/risks-and-debt.md), [undocumented-features.md](../audit/undocumented-features.md) +3 | Tested + documented |
| `observability.py` | 276 | Structured logging, correlation IDs, security headers and Prometheus metrics. | config | [SECURITY.md](../SECURITY.md), [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [THREAT_MODEL.md](../THREAT_MODEL.md) +13 | Tested + documented |
| `schema_steps/__init__.py` | 42 | Idempotent DDL that `create_all` and `sync-schema` cannot express. |  | - | Tested |
| `schema_steps/step_api.py` | 30 | Schema steps owned by the API workstream. |  | [README.md](../database/README.md) | Documented |
| `schema_steps/step_auth.py` | 119 | Audit trails append-only in the database; `auth_events` tenant policies (R-05). |  | [0001-postgres-rls.md](../ADRs/0001-postgres-rls.md), [DATABASE.md](../DATABASE.md), [README.md](../database/README.md), [lifecycle.md](../database/lifecycle.md) +3 | Documented |
| `schema_steps/step_ingest.py` | 63 | Ingest workstream DDL: unique keys whose NULLs must not be distinct (TD-33). |  | [risks-and-debt.md](../audit/risks-and-debt.md), [lifecycle.md](../database/lifecycle.md) | Tested + documented |
| `schema_steps/step_search.py` | 40 | Trigram indexes for the lexical search (TD-54, 0.41.0). |  | [risks-and-debt.md](../audit/risks-and-debt.md) | Documented |
| `security/__init__.py` | 4 | Authentication, authorization and hardening primitives. |  | - | Tested |
| `security/agent_auth.py` | 107 | Authentication for execution agents (spec section 33). | db, models, services | [data-flows.md](../architecture/data-flows.md), [dependencies.md](../architecture/dependencies.md), [overview.md](../architecture/overview.md), [sequences.md](../architecture/sequences.md) +7 | Tested + documented |
| `security/auth.py` | 204 | Password hashing, token issuance and API-key handling. | config, models.tenancy | [0007-stateless-app-nodes.md](../ADRs/0007-stateless-app-nodes.md), [SECURITY.md](../SECURITY.md), [THREAT_MODEL.md](../THREAT_MODEL.md), [guide.md](../api/guide.md) +14 | Tested + documented |
| `security/deps.py` | 272 | FastAPI authorization dependencies. | config, db, models.tenancy, security.auth | [0001-postgres-rls.md](../ADRs/0001-postgres-rls.md), [API.md](../API.md), [SECURITY.md](../SECURITY.md), [THREAT_MODEL.md](../THREAT_MODEL.md) +18 | Tested + documented |
| `security/lockout.py` | 178 | Failed-credential accounting: who may try a credential again, and when. | config, models.tenancy | [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [authentication-accounts.md](../functional/authentication-accounts.md), [monitoring.md](../operations/monitoring.md) +4 | Tested + documented |
| `security/mfa.py` | 155 | Time-based one-time passwords (RFC 6238) for local password logins. |  | [SECURITY.md](../SECURITY.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [dependencies.md](../architecture/dependencies.md), [overview.md](../executive/overview.md) +4 | Tested + documented |
| `security/mfa_delivery.py` | 368 | Second factors delivered to the person: a code by e-mail or by Telegram. | config, services | [HIGH_AVAILABILITY.md](../HIGH_AVAILABILITY.md), [SECURITY.md](../SECURITY.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [c4.md](../architecture/c4.md) +14 | Tested + documented |
| `security/permissions.py` | 191 | The single source of truth for VEYRS permissions and built-in roles. |  | [ADMIN_GUIDE.md](../ADMIN_GUIDE.md), [APP_FLOW.md](../APP_FLOW.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [SECURITY.md](../SECURITY.md) +7 | Tested + documented |
| `security/platform.py` | 72 | Who may open the installation-wide pages (platform administration). | db, models.tenancy | - | Tested |
| `security/ratelimit.py` | 250 | Rate limiting (spec section 24, threat model T-API-ABUSE). | config, security.auth | [0007-stateless-app-nodes.md](../ADRs/0007-stateless-app-nodes.md), [API.md](../API.md), [SECURITY.md](../SECURITY.md), [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md) +18 | Tested + documented |
| `security/scope.py` | 368 | Team-level visibility: the ABAC seam `tenancy.py` promised and never enforced. | models, models.tenancy, services.teams | [AI_SECURITY.md](../AI_SECURITY.md), [THREAT_MODEL.md](../THREAT_MODEL.md), [guide.md](../api/guide.md), [c4.md](../architecture/c4.md) +24 | Tested + documented |
| `security/secret_vault.py` | 385 | Client for an external secret store: HashiCorp Vault or OpenBao, KV version 2. | config, security.secrets, services | [SECURITY.md](../SECURITY.md), [c4.md](../architecture/c4.md), [dependencies.md](../architecture/dependencies.md), [overview.md](../architecture/overview.md) +5 | Tested + documented |
| `security/secrets.py` | 307 | Envelope encryption for secrets stored in the database (spec section 24). | config, security.secret_vault | [DATABASE.md](../DATABASE.md), [SECURITY.md](../SECURITY.md), [data-flows.md](../architecture/data-flows.md), [dependencies.md](../architecture/dependencies.md) +12 | Tested + documented |
| `security/tenant_guard.py` | 119 | Tenant isolation guards that do not depend on remembering a filter (R-23). | cli, config, db, models | [0001-postgres-rls.md](../ADRs/0001-postgres-rls.md), [SECURITY.md](../SECURITY.md), [THREAT_MODEL.md](../THREAT_MODEL.md), [README.md](../database/README.md) +2 | Tested + documented |
| `services/__init__.py` | 1 | Business services - the layer routes call into. No HTTP objects here. |  | - | Tested |
| `services/agents.py` | 1272 | Execution-agent lifecycle, dispatch and result intake (spec section 33). | models, security.auth, services.engagements, services.importers | [0006-no-autoclose-on-absence.md](../ADRs/0006-no-autoclose-on-absence.md), [0009-closure-per-covered-asset.md](../ADRs/0009-closure-per-covered-asset.md), [INTEGRATIONS.md](../INTEGRATIONS.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md) +14 | Tested + documented |
| `services/ai/__init__.py` | 18 | VEYRS AI subsystem. | services.ai.gateway, services.ai.guardrails | - | Tested |
| `services/ai/capabilities.py` | 590 | The AI features themselves (spec section 19), all grounded in VEYRS data. | models, models.ai, services.ai.gateway, services.ai.providers | [0003-ai-gateway.md](../ADRs/0003-ai-gateway.md), [0004-closed-query-grammar.md](../ADRs/0004-closed-query-grammar.md), [AI_SECURITY.md](../AI_SECURITY.md), [README.md](../audit/README.md) +2 | Tested + documented |
| `services/ai/gateway.py` | 411 | The AI gateway: the single door between VEYRS and any model (spec 19/20). | config, models.ai, models.audit, security.secrets, services.ai.providers, services.audit | [0003-ai-gateway.md](../ADRs/0003-ai-gateway.md), [AI_SECURITY.md](../AI_SECURITY.md), [README.md](../README.md), [c4.md](../architecture/c4.md) +10 | Tested + documented |
| `services/ai/guardrails.py` | 331 | Input/output guardrails for every AI call (spec section 20). |  | [AI_SECURITY.md](../AI_SECURITY.md), [ai.md](../functional/ai.md) | Tested + documented |
| `services/ai/nlquery.py` | 448 | Natural-language -> structured query translation (spec section 19). | models | [0004-closed-query-grammar.md](../ADRs/0004-closed-query-grammar.md), [AI_SECURITY.md](../AI_SECURITY.md), [ai.md](../functional/ai.md) | Tested + documented |
| `services/ai/providers.py` | 454 | Provider abstraction layer (spec section 19). |  | [0003-ai-gateway.md](../ADRs/0003-ai-gateway.md), [AI_SECURITY.md](../AI_SECURITY.md), [INTEGRATIONS.md](../INTEGRATIONS.md), [c4.md](../architecture/c4.md) +11 | Tested + documented |
| `services/ai/token_auth.py` | 331 | Sign-in for model gateways whose bearer token expires. | services.ai.providers | [ai.md](../functional/ai.md) | Tested + documented |
| `services/analytics.py` | 592 | Dashboard and analytics queries (spec section 27). | models, security | [queries.md](../database/queries.md), [dashboards-reports.md](../functional/dashboards-reports.md), [coverage-matrix.md](../testing/coverage-matrix.md), [known-issues.md](../testing/known-issues.md) | Tested + documented |
| `services/attribution.py` | 715 | Why did this finding change? Attribution of closes and reopens. | models, security | [README.md](../audit/README.md), [undocumented-features.md](../audit/undocumented-features.md), [engagements-scan-import.md](../functional/engagements-scan-import.md), [vulnerability-management.md](../functional/vulnerability-management.md) +1 | Documented |
| `services/audit.py` | 154 | Audit-trail writer. | models.audit | [DATABASE.md](../DATABASE.md), [SECURITY.md](../SECURITY.md), [THREAT_MODEL.md](../THREAT_MODEL.md), [inconsistencies.md](../audit/inconsistencies.md) +9 | Tested + documented |
| `services/autoticket.py` | 524 | Open remediation tickets without a human clicking, and refuse to do it badly. | models, models.integration, models.tenancy | [data-flows.md](../architecture/data-flows.md), [ticketing-itsm.md](../functional/ticketing-itsm.md), [automation.md](../integrations/automation.md), [coverage-matrix.md](../testing/coverage-matrix.md) | Tested + documented |
| `services/cmdb.py` | 1410 | Reading somebody else's asset inventory, and telling two of them apart. | models, models.assets, models.cmdb, security.secrets | [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [guide.md](../api/guide.md), [c4.md](../architecture/c4.md), [dependencies.md](../architecture/dependencies.md) +12 | Tested + documented |
| `services/compliance.py` | 735 | Compliance engine (spec sections 16 and 27). | data.frameworks, models, models.compliance | [0005-partial-catalogues.md](../ADRs/0005-partial-catalogues.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [README.md](../README.md), [c4.md](../architecture/c4.md) +5 | Tested + documented |
| `services/correlation.py` | 808 | CVE -> product -> asset correlation, and the finding lifecycle it produces. | models, models.vulnerability, services.intelligence, services.versions | [0006-no-autoclose-on-absence.md](../ADRs/0006-no-autoclose-on-absence.md), [0009-closure-per-covered-asset.md](../ADRs/0009-closure-per-covered-asset.md), [ARCHITECTURE.md](../ARCHITECTURE.md), [c4.md](../architecture/c4.md) +15 | Tested + documented |
| `services/cvss_assist.py` | 457 | Turn a pasted security bulletin into a filled-in CVSS calculator. | engines, models, security, services.ai.gateway, services.versions | [cvss.md](../functional/cvss.md), [coverage-matrix.md](../testing/coverage-matrix.md) | Tested + documented |
| `services/dedupe.py` | 539 | Configurable finding deduplication (the DefectDojo model, reimplemented). | models, models.integration | [DATABASE.md](../DATABASE.md), [c4.md](../architecture/c4.md), [data-flows.md](../architecture/data-flows.md), [overview.md](../architecture/overview.md) +11 | Tested + documented |
| `services/digest.py` | 454 | The daily digest: VEYRS goes out and finds the operator. | config, db, models, security, security.deps | [DEPLOYMENT.md](../DEPLOYMENT.md), [README.md](../audit/README.md), [inconsistencies.md](../audit/inconsistencies.md), [risks-and-debt.md](../audit/risks-and-debt.md) +7 | Tested + documented |
| `services/docs.py` | 498 | Confluence: publishing VEYRS runbooks into the wiki the organisation reads. | models.integration, models.knowledge, models.ticketing, services.itsm | [c4.md](../architecture/c4.md), [undocumented-features.md](../audit/undocumented-features.md), [integrations.md](../functional/integrations.md), [knowledge-search.md](../functional/knowledge-search.md) +4 | Tested + documented |
| `services/documents.py` | 402 | Document intelligence (spec section 18). | models, services.versions | [dependencies.md](../architecture/dependencies.md), [README.md](../audit/README.md), [undocumented-features.md](../audit/undocumented-features.md), [lifecycle.md](../database/lifecycle.md) +4 | Tested + documented |
| `services/endpoints.py` | 420 | Endpoint parsing, canonicalisation and finding attachment. | models | [lifecycle.md](../database/lifecycle.md), [engagements-scan-import.md](../functional/engagements-scan-import.md), [coverage-matrix.md](../testing/coverage-matrix.md) | Tested + documented |
| `services/engagements.py` | 615 | Engagement/test lifecycle, scoped reimport and risk acceptance. | models, models.integration, models.vulnerability | [0006-no-autoclose-on-absence.md](../ADRs/0006-no-autoclose-on-absence.md), [0009-closure-per-covered-asset.md](../ADRs/0009-closure-per-covered-asset.md), [README.md](../README.md), [USER_GUIDE.md](../USER_GUIDE.md) +13 | Tested + documented |
| `services/fix_plan.py` | 628 | Fix plan: which version fixes everything open on a product, and how far away it is. | models, models.upgrade, security, services.correlation, services.versions | [undocumented-features.md](../audit/undocumented-features.md), [remediation-fix-plans.md](../functional/remediation-fix-plans.md), [coverage-matrix.md](../testing/coverage-matrix.md) | Tested + documented |
| `services/importers/__init__.py` | 169 | Scanner import framework (spec section 31). | models.integration, services.importers.base, services.importers.parsers | [data-flows.md](../architecture/data-flows.md), [sequences.md](../architecture/sequences.md), [engagements-scan-import.md](../functional/engagements-scan-import.md), [integrations.md](../functional/integrations.md) +1 | Tested + documented |
| `services/importers/base.py` | 1058 | Canonical scanner record and the normalizer every importer feeds (spec 31). | models, models.integration | [0006-no-autoclose-on-absence.md](../ADRs/0006-no-autoclose-on-absence.md), [0009-closure-per-covered-asset.md](../ADRs/0009-closure-per-covered-asset.md), [DATABASE.md](../DATABASE.md), [c4.md](../architecture/c4.md) +8 | Tested + documented |
| `services/importers/parsers.py` | 727 | Vendor export parsers (spec section 31). | services.importers.base, services.importers.parsers_modern, services.versions | [DEVELOPMENT.md](../DEVELOPMENT.md), [data-flows.md](../architecture/data-flows.md), [README.md](../audit/README.md), [overview.md](../executive/overview.md) +2 | Tested + documented |
| `services/importers/parsers_modern.py` | 957 | Parsers for the modern toolchain: SAST, SCA, DAST, IaC and cloud posture. | services.importers.base | [extending.md](../integrations/extending.md), [scanners.md](../integrations/scanners.md) | Tested + documented |
| `services/ingest_admin.py` | 249 | `veyrs dedupe ...` -- one-off data migrations of the ingest pipeline. | db, models, models.integration, models.risk_register | - | Neither |
| `services/intel_pipeline.py` | 176 | Turns freshly ingested intelligence into tenant findings. | db, models | [data-flows.md](../architecture/data-flows.md), [overview.md](../architecture/overview.md), [sequences.md](../architecture/sequences.md), [README.md](../database/README.md) +4 | Tested + documented |
| `services/intel_schedule.py` | 277 | How often each intelligence feed refreshes, and who gets to decide. | models, models.tenancy | [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [data-flows.md](../architecture/data-flows.md), [overview.md](../architecture/overview.md), [README.md](../audit/README.md) +8 | Tested + documented |
| `services/intelligence.py` | 1086 | Ingestion of global threat intelligence: NVD/CVE, EPSS, CISA KEV. | models, services.versions | [ARCHITECTURE.md](../ARCHITECTURE.md), [c4.md](../architecture/c4.md), [data-flows.md](../architecture/data-flows.md), [overview.md](../architecture/overview.md) +6 | Tested + documented |
| `services/inventory.py` | 601 | Software inventory: turning what an operator calls something into CPE identity. | models, services.versions | [data-flows.md](../architecture/data-flows.md), [risks-and-debt.md](../audit/risks-and-debt.md), [lifecycle.md](../database/lifecycle.md), [overview.md](../executive/overview.md) +2 | Tested + documented |
| `services/itsm.py` | 755 | ITSM connectors: ServiceNow, Jira Service Management, generic webhook. | models, models.assets, models.integration, models.tenancy, models.vulnerability, security.secrets | [INTEGRATIONS.md](../INTEGRATIONS.md), [guide.md](../api/guide.md), [c4.md](../architecture/c4.md), [dependencies.md](../architecture/dependencies.md) +9 | Tested + documented |
| `services/itsm_inbound.py` | 344 | Inbound ITSM events: the return leg of the sync (spec section 34). | models, security.secrets | [INTEGRATIONS.md](../INTEGRATIONS.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [c4.md](../architecture/c4.md), [data-flows.md](../architecture/data-flows.md) +7 | Tested + documented |
| `services/ldap_auth.py` | 816 | Directory authentication: LDAP and Active Directory. | models.tenancy, security | [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [c4.md](../architecture/c4.md), [dependencies.md](../architecture/dependencies.md), [overview.md](../executive/overview.md) +8 | Tested + documented |
| `services/mfa_admin.py` | 209 | Operator commands for two-factor sign-in, run on the host. | db, models, security, security.auth | [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md), [overview.md](../architecture/overview.md), [README.md](../audit/README.md), [risks-and-debt.md](../audit/risks-and-debt.md) +5 | Tested + documented |
| `services/mfa_policy.py` | 73 | Organization policy: a second factor is required to use VEYRS (R-07). | models.tenancy | [authentication.md](../security/authentication.md), [security-architecture.md](../security/security-architecture.md) | Documented |
| `services/net_guard.py` | 135 | Outbound-URL guard shared by every connector that calls a configured URL. | config | [SECURITY.md](../SECURITY.md), [risk-register.md](../security/risk-register.md), [security-architecture.md](../security/security-architecture.md) | Tested + documented |
| `services/network_requirements.py` | 406 | Every network destination VEYRS needs -- Administration > Network access. | config, models.ai, models.cmdb, models.integration, models.ticketing | [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [dependencies.md](../architecture/dependencies.md), [updates.md](../functional/updates.md) +1 | Tested + documented |
| `services/notifications.py` | 376 | Notification dispatch: in-app, email, webhook (spec section 30). | config, models | [ARCHITECTURE.md](../ARCHITECTURE.md), [INTEGRATIONS.md](../INTEGRATIONS.md), [c4.md](../architecture/c4.md), [dependencies.md](../architecture/dependencies.md) +13 | Tested + documented |
| `services/oidc_auth.py` | 429 | Single sign-on through the organization's identity provider (OpenID Connect). | models.tenancy, security | [DISASTER_RECOVERY.md](../DISASTER_RECOVERY.md), [HIGH_AVAILABILITY.md](../HIGH_AVAILABILITY.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [guide.md](../api/guide.md) +13 | Tested + documented |
| `services/radius_auth.py` | 449 | RADIUS authentication (AAA) for one organization, with the server's own second factor. | models.tenancy, security | [DISASTER_RECOVERY.md](../DISASTER_RECOVERY.md), [HIGH_AVAILABILITY.md](../HIGH_AVAILABILITY.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [c4.md](../architecture/c4.md) +8 | Tested + documented |
| `services/remediation.py` | 200 | One entry point for "somebody must fix this finding", whichever queue owns it. | models.integration, models.ticketing, models.vulnerability | [dependencies.md](../architecture/dependencies.md), [remediation-fix-plans.md](../functional/remediation-fix-plans.md), [coverage-matrix.md](../testing/coverage-matrix.md) | Tested + documented |
| `services/report_builder.py` | 1118 | Report builder: ad-hoc tabular reports from a curated catalog, never from SQL. | models, models.assets, models.risk_register, models.ticketing, models.vulnerability, security | [USER_GUIDE.md](../USER_GUIDE.md), [README.md](../database/README.md), [queries.md](../database/queries.md), [dashboards-reports.md](../functional/dashboards-reports.md) +1 | Tested + documented |
| `services/reporting.py` | 530 | Report generation and export (spec section 29). | config, models | [BRAND.md](../BRAND.md), [DESIGN_SYSTEM.md](../DESIGN_SYSTEM.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [USER_GUIDE.md](../USER_GUIDE.md) +9 | Tested + documented |
| `services/retention.py` | 199 | Data retention: `veyrs prune`. | config, db, models | [automation.md](../integrations/automation.md) | Documented |
| `services/risk.py` | 195 | Persistence side of the risk engine: profile resolution and bulk re-scoring. | engines, models | [c4.md](../architecture/c4.md), [risks-and-debt.md](../audit/risks-and-debt.md), [README.md](../database/README.md), [lifecycle.md](../database/lifecycle.md) +7 | Tested + documented |
| `services/risk_register.py` | 659 | Domain service for the risk register. Every write goes through here. | models.assets, models.compliance, models.risk_register, models.tenancy, models.ticketing, models.vulnerability | [USER_MANUAL.md](../USER_MANUAL.md), [undocumented-features.md](../audit/undocumented-features.md), [lifecycle.md](../database/lifecycle.md), [overview.md](../executive/overview.md) +2 | Documented |
| `services/risk_register_mode.py` | 171 | The switch that decides whether this tenant keeps a risk register at all. | models.risk_register, models.tenancy | [undocumented-features.md](../audit/undocumented-features.md), [administration-platform.md](../functional/administration-platform.md), [risk-register.md](../functional/risk-register.md), [coverage-matrix.md](../testing/coverage-matrix.md) | Documented |
| `services/scanners.py` | 601 | Pulling scan results from a scanner's own API (spec section 31, phase 33). | models, models.integration, security.secrets, services.importers | [0006-no-autoclose-on-absence.md](../ADRs/0006-no-autoclose-on-absence.md), [INTEGRATIONS.md](../INTEGRATIONS.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [c4.md](../architecture/c4.md) +9 | Tested + documented |
| `services/scanning.py` | 186 | Active scanning: the switch that decides whether VEYRS probes anything. | models.agent, models.tenancy | [administration-platform.md](../functional/administration-platform.md), [agents.md](../functional/agents.md), [integrations.md](../functional/integrations.md), [agent.md](../integrations/agent.md) +1 | Tested + documented |
| `services/search.py` | 317 | Global and semantic search (spec section 28). | models, security | [ARCHITECTURE.md](../ARCHITECTURE.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [USER_GUIDE.md](../USER_GUIDE.md), [dependencies.md](../architecture/dependencies.md) +10 | Tested + documented |
| `services/secret_storage.py` | 591 | Where stored credentials live, and moving them between local and an external vault. | db, models, security | [DATABASE.md](../DATABASE.md), [DISASTER_RECOVERY.md](../DISASTER_RECOVERY.md), [undocumented-features.md](../audit/undocumented-features.md), [README.md](../database/README.md) +4 | Tested + documented |
| `services/sla.py` | 881 | SLA and escalation engines (spec sections 11 and 12). | db, models, security | [ADMIN_GUIDE.md](../ADMIN_GUIDE.md), [ARCHITECTURE.md](../ARCHITECTURE.md), [USER_GUIDE.md](../USER_GUIDE.md), [USER_MANUAL.md](../USER_MANUAL.md) +14 | Tested + documented |
| `services/software_inventory.py` | 469 | Installed software on this node -- Administration > Installed software. | config, db, models.agent | [dependencies.md](../architecture/dependencies.md), [updates.md](../functional/updates.md), [coverage-matrix.md](../testing/coverage-matrix.md) | Tested + documented |
| `services/team_import.py` | 509 | Teams that already exist somewhere else, brought in rather than retyped. | models, models.cmdb, services.cmdb | [undocumented-features.md](../audit/undocumented-features.md), [authentication-accounts.md](../functional/authentication-accounts.md), [extending.md](../integrations/extending.md), [itsm-and-webhooks.md](../integrations/itsm-and-webhooks.md) +1 | Tested + documented |
| `services/teams.py` | 159 | Team ownership: name resolution, membership, and the ownership expression. | models, models.tenancy | [assets-inventory.md](../functional/assets-inventory.md), [coverage-matrix.md](../testing/coverage-matrix.md) | Documented |
| `services/tenant_defaults.py` | 69 | Built-in defaults every tenant needs on day one. | db, models | [sla-escalation.md](../functional/sla-escalation.md) | Documented |
| `services/threatintel.py` | 280 | Threat-intelligence feeds and the knowledge base (spec sections 17 and 21). | models, services.documents, services.versions | [inconsistencies.md](../audit/inconsistencies.md), [risks-and-debt.md](../audit/risks-and-debt.md), [overview.md](../executive/overview.md), [knowledge-search.md](../functional/knowledge-search.md) +2 | Tested + documented |
| `services/tick.py` | 203 | The hourly tick: what it does besides the feeds, and proof that it ran. | config, db, models | [inconsistencies.md](../audit/inconsistencies.md), [automation.md](../integrations/automation.md), [coverage-matrix.md](../testing/coverage-matrix.md) | Documented |
| `services/ticketing.py` | 371 | Ticket lifecycle and ITIL mapping (spec sections 14 and 15). | models | [data-flows.md](../architecture/data-flows.md), [README.md](../audit/README.md), [inconsistencies.md](../audit/inconsistencies.md), [risks-and-debt.md](../audit/risks-and-debt.md) +5 | Tested + documented |
| `services/ticketing_mode.py` | 265 | Which ticketing system is the authority: VEYRS' own queue, or an external one. | models.tenancy, models.ticketing | [administration-platform.md](../functional/administration-platform.md), [ticketing-itsm.md](../functional/ticketing-itsm.md), [automation.md](../integrations/automation.md), [itsm-and-webhooks.md](../integrations/itsm-and-webhooks.md) +1 | Tested + documented |
| `services/trust_store.py` | 559 | TLS trust store: import CAs, build the verification context every outbound client uses, and diagnose a server's certific | db, models.trust | [trust-store.md](../functional/trust-store.md) | Tested + documented |
| `services/updates.py` | 621 | Software update check, and the UNPRIVILEGED half of self-update. | config | [ADMIN_GUIDE.md](../ADMIN_GUIDE.md), [0007-stateless-app-nodes.md](../ADRs/0007-stateless-app-nodes.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [guide.md](../api/guide.md) +7 | Tested + documented |
| `services/versions.py` | 315 | Version and name normalisation used by CPE/product correlation. |  | [assets-inventory.md](../functional/assets-inventory.md), [updates.md](../functional/updates.md), [coverage-matrix.md](../testing/coverage-matrix.md) | Tested + documented |
| `services/views.py` | 269 | Saved views: store a query, replay it, never widen it. | models | [queries.md](../database/queries.md), [dashboards-reports.md](../functional/dashboards-reports.md), [coverage-matrix.md](../testing/coverage-matrix.md) | Tested + documented |
| `services/web_tls.py` | 926 | The certificate VEYRS serves: request it here, have it signed anywhere, install it on every app node. | db, models.trust, models.web_tls, security | [web-certificate.md](../functional/web-certificate.md) | Tested + documented |
| `services/workflow.py` | 633 | The workflow engine (spec section 13). | models, models.workflow, services.sla | [ADMIN_GUIDE.md](../ADMIN_GUIDE.md), [ARCHITECTURE.md](../ARCHITECTURE.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [USER_MANUAL.md](../USER_MANUAL.md) +11 | Tested + documented |
| `services/xmlsafe.py` | 62 | One implementation of "parse this XML without letting it own us". |  | [USER_MANUAL.md](../USER_MANUAL.md), [data-flows.md](../architecture/data-flows.md), [dependencies.md](../architecture/dependencies.md), [scanners.md](../integrations/scanners.md) +2 | Tested + documented |

## Console, scripts, infrastructure and builders

| Component | Documentation | State |
|---|---|---|
| `docker/Dockerfile` | [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [dependencies.md](../architecture/dependencies.md), [deployment.md](../architecture/deployment.md) +8 | Tested + documented |
| `docker/README.md` | [0006-no-autoclose-on-absence.md](../ADRs/0006-no-autoclose-on-absence.md), [0009-closure-per-covered-asset.md](../ADRs/0009-closure-per-covered-asset.md), [API.md](../API.md), [BRAND.md](../BRAND.md) +50 | Tested + documented |
| `docker/agent-entrypoint.sh` | [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md), [README.md](../troubleshooting/README.md) | Tested + documented |
| `docker/compose.external-db.yaml` | [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [deployment.md](../architecture/deployment.md), [inconsistencies.md](../audit/inconsistencies.md), [backup-recovery.md](../database/backup-recovery.md) +2 | Documented |
| `docker/compose.yaml` | [ARCHITECTURE.md](../ARCHITECTURE.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md) +21 | Tested + documented |
| `docker/console.conf` | [DEPLOYMENT.md](../DEPLOYMENT.md), [DESIGN_SYSTEM.md](../DESIGN_SYSTEM.md), [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [HIGH_AVAILABILITY.md](../HIGH_AVAILABILITY.md) +15 | Tested + documented |
| `docker/entrypoint.sh` | [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md), [c4.md](../architecture/c4.md) +7 | Tested + documented |
| `docker/env.example` | [DEPLOYMENT.md](../DEPLOYMENT.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md) +5 | Tested + documented |
| `docker/init.sh` | [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [dependencies.md](../architecture/dependencies.md), [deployment.md](../architecture/deployment.md), [installation.md](../operations/installation.md) +2 | Tested + documented |
| `docker/tick.sh` | [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md), [c4.md](../architecture/c4.md), [deployment.md](../architecture/deployment.md) +6 | Tested + documented |
| `docker/veyrs-docker.sh` | [ARCHITECTURE.md](../ARCHITECTURE.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [DISASTER_RECOVERY.md](../DISASTER_RECOVERY.md) +16 | Tested + documented |
| `frontend/console/app.js` | [ADMIN_GUIDE.md](../ADMIN_GUIDE.md), [APP_FLOW.md](../APP_FLOW.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [DESIGN_SYSTEM.md](../DESIGN_SYSTEM.md) +28 | Tested + documented |
| `frontend/console/console.css` | [BRAND.md](../BRAND.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [DESIGN_SYSTEM.md](../DESIGN_SYSTEM.md), [DEVELOPMENT.md](../DEVELOPMENT.md) +14 | Tested + documented |
| `frontend/console/index.html` | [BRAND.md](../BRAND.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [DESIGN_SYSTEM.md](../DESIGN_SYSTEM.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md) +14 | Tested + documented |
| `infrastructure/README.md` | [0006-no-autoclose-on-absence.md](../ADRs/0006-no-autoclose-on-absence.md), [0009-closure-per-covered-asset.md](../ADRs/0009-closure-per-covered-asset.md), [API.md](../API.md), [BRAND.md](../BRAND.md) +50 | Tested + documented |
| `infrastructure/backup/veyrs-alert.sh` | [services.md](../operations/services.md) | Documented |
| `infrastructure/backup/veyrs-alert@.service` | [services.md](../operations/services.md) | Tested + documented |
| `infrastructure/backup/veyrs-pgdump.service` | [automation.md](../integrations/automation.md), [backup-dr.md](../operations/backup-dr.md) | Documented |
| `infrastructure/backup/veyrs-pgdump.sh` | [0008-state-off-host-and-proven-backups.md](../ADRs/0008-state-off-host-and-proven-backups.md), [DISASTER_RECOVERY.md](../DISASTER_RECOVERY.md), [HIGH_AVAILABILITY.md](../HIGH_AVAILABILITY.md), [deployment.md](../architecture/deployment.md) +9 | Documented |
| `infrastructure/backup/veyrs-pgdump.timer` | [0008-state-off-host-and-proven-backups.md](../ADRs/0008-state-off-host-and-proven-backups.md), [DISASTER_RECOVERY.md](../DISASTER_RECOVERY.md), [HIGH_AVAILABILITY.md](../HIGH_AVAILABILITY.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md) +7 | Documented |
| `infrastructure/backup/veyrs-pgverify.service` | [automation.md](../integrations/automation.md), [backup-dr.md](../operations/backup-dr.md) | Documented |
| `infrastructure/backup/veyrs-pgverify.sh` | [0008-state-off-host-and-proven-backups.md](../ADRs/0008-state-off-host-and-proven-backups.md), [HIGH_AVAILABILITY.md](../HIGH_AVAILABILITY.md), [backup-recovery.md](../database/backup-recovery.md), [backup-dr.md](../operations/backup-dr.md) +2 | Documented |
| `infrastructure/backup/veyrs-pgverify.timer` | [0008-state-off-host-and-proven-backups.md](../ADRs/0008-state-off-host-and-proven-backups.md), [DISASTER_RECOVERY.md](../DISASTER_RECOVERY.md), [HIGH_AVAILABILITY.md](../HIGH_AVAILABILITY.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md) +5 | Documented |
| `infrastructure/backup/veyrs-replcheck.service` | [automation.md](../integrations/automation.md), [backup-dr.md](../operations/backup-dr.md) | Documented |
| `infrastructure/backup/veyrs-replcheck.sh` | [0008-state-off-host-and-proven-backups.md](../ADRs/0008-state-off-host-and-proven-backups.md), [HIGH_AVAILABILITY.md](../HIGH_AVAILABILITY.md), [risks-and-debt.md](../audit/risks-and-debt.md), [backup-recovery.md](../database/backup-recovery.md) +3 | Documented |
| `infrastructure/backup/veyrs-replcheck.timer` | [0008-state-off-host-and-proven-backups.md](../ADRs/0008-state-off-host-and-proven-backups.md), [DISASTER_RECOVERY.md](../DISASTER_RECOVERY.md), [HIGH_AVAILABILITY.md](../HIGH_AVAILABILITY.md), [TECHNICAL_REQUIREMENTS.md](../TECHNICAL_REQUIREMENTS.md) +6 | Documented |
| `infrastructure/nginx-veyrs-console.conf` | [DEPLOYMENT.md](../DEPLOYMENT.md), [DESIGN_SYSTEM.md](../DESIGN_SYSTEM.md), [HIGH_AVAILABILITY.md](../HIGH_AVAILABILITY.md), [SECURITY.md](../SECURITY.md) +14 | Tested + documented |
| `infrastructure/nginx-veyrs-docs.conf` | [sites.md](../frontend/sites.md), [web-certificate.md](../functional/web-certificate.md), [services.md](../operations/services.md) | Tested + documented |
| `infrastructure/nginx-veyrs-web.conf` | [sites.md](../frontend/sites.md), [web-certificate.md](../functional/web-certificate.md), [services.md](../operations/services.md) | Tested + documented |
| `infrastructure/systemd/veyrs-api.service` | [0007-stateless-app-nodes.md](../ADRs/0007-stateless-app-nodes.md), [ARCHITECTURE.md](../ARCHITECTURE.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md) +21 | Tested + documented |
| `infrastructure/systemd/veyrs-digest.service` | [DEPLOYMENT.md](../DEPLOYMENT.md), [automation.md](../integrations/automation.md), [notifications.md](../integrations/notifications.md), [services.md](../operations/services.md) | Tested + documented |
| `infrastructure/systemd/veyrs-digest.timer` | [0007-stateless-app-nodes.md](../ADRs/0007-stateless-app-nodes.md), [ARCHITECTURE.md](../ARCHITECTURE.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md) +12 | Tested + documented |
| `infrastructure/systemd/veyrs-tls-sync.service` | [web-certificate.md](../functional/web-certificate.md) | Tested + documented |
| `infrastructure/systemd/veyrs-tls-sync.timer` | [web-certificate.md](../functional/web-certificate.md) | Tested + documented |
| `infrastructure/systemd/veyrs-updater.path` | [ARCHITECTURE.md](../ARCHITECTURE.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [SECURITY.md](../SECURITY.md), [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md) +9 | Documented |
| `infrastructure/systemd/veyrs-updater.service` | [ARCHITECTURE.md](../ARCHITECTURE.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [SECURITY.md](../SECURITY.md), [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md) +6 | Tested + documented |
| `install.sh` | [README.md](../ADRs/README.md), [ARCHITECTURE.md](../ARCHITECTURE.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [DESIGN_SYSTEM.md](../DESIGN_SYSTEM.md) +39 | Tested + documented |
| `integrations/fleet-import/collect_fleet.py` | [data-flows.md](../architecture/data-flows.md), [itsm-and-webhooks.md](../integrations/itsm-and-webhooks.md) | Documented |
| `integrations/veyrs-agent/veyrs_agent.py` | [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [c4.md](../architecture/c4.md), [data-flows.md](../architecture/data-flows.md), [sequences.md](../architecture/sequences.md) +10 | Tested + documented |
| `scripts/README.md` | [0006-no-autoclose-on-absence.md](../ADRs/0006-no-autoclose-on-absence.md), [0009-closure-per-covered-asset.md](../ADRs/0009-closure-per-covered-asset.md), [API.md](../API.md), [BRAND.md](../BRAND.md) +50 | Tested + documented |
| `scripts/backup.sh` | [DATABASE.md](../DATABASE.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [DISASTER_RECOVERY.md](../DISASTER_RECOVERY.md) +13 | Tested + documented |
| `scripts/check-docs-links.py` | [README.md](../audit/README.md), [risks-and-debt.md](../audit/risks-and-debt.md), [undocumented-features.md](../audit/undocumented-features.md), [strategy.md](../testing/strategy.md) | Documented |
| `scripts/check-docs-refs.py` | [risks-and-debt.md](../audit/risks-and-debt.md) | Tested + documented |
| `scripts/ci.sh` | [risks-and-debt.md](../audit/risks-and-debt.md) | Tested + documented |
| `scripts/freeze-deps.sh` | [SECURITY.md](../SECURITY.md), [dependencies.md](../architecture/dependencies.md), [release.md](../operations/release.md), [risk-register.md](../security/risk-register.md) | Tested + documented |
| `scripts/gen-reference-docs.py` | [TESTING_GUIDE.md](../TESTING_GUIDE.md), [README.md](../audit/README.md), [undocumented-features.md](../audit/undocumented-features.md), [strategy.md](../testing/strategy.md) | Tested + documented |
| `scripts/gen-schema-doc.py` | [DATABASE.md](../DATABASE.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md), [TESTING_GUIDE.md](../TESTING_GUIDE.md) +4 | Tested + documented |
| `scripts/ip-guard.sh` | [inconsistencies.md](../audit/inconsistencies.md), [release.md](../operations/release.md), [README.md](../troubleshooting/README.md) | Tested + documented |
| `scripts/migrate-service-user.sh` | [services.md](../operations/services.md), [risk-register.md](../security/risk-register.md), [README.md](../troubleshooting/README.md) | Tested + documented |
| `scripts/osv-check.py` | [dependencies.md](../architecture/dependencies.md), [risk-register.md](../security/risk-register.md) | Tested + documented |
| `scripts/public-export.sh` | [README.md](../ADRs/README.md), [README.md](../audit/README.md), [inconsistencies.md](../audit/inconsistencies.md), [risks-and-debt.md](../audit/risks-and-debt.md) +5 | Tested + documented |
| `scripts/publish-github.sh` | [SECURITY.md](../SECURITY.md), [TESTING_GUIDE.md](../TESTING_GUIDE.md), [release.md](../operations/release.md), [risk-register.md](../security/risk-register.md) +3 | Tested + documented |
| `scripts/publish-images.sh` | [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [SECURITY.md](../SECURITY.md), [release.md](../operations/release.md) | Tested + documented |
| `scripts/publish-sites.sh` | [risks-and-debt.md](../audit/risks-and-debt.md), [services.md](../operations/services.md), [upgrade-rollback.md](../operations/upgrade-rollback.md), [README.md](../troubleshooting/README.md) | Tested + documented |
| `scripts/render-diagrams.py` | [TESTING_GUIDE.md](../TESTING_GUIDE.md), [README.md](../audit/README.md), [undocumented-features.md](../audit/undocumented-features.md), [strategy.md](../testing/strategy.md) | Tested + documented |
| `scripts/restore.sh` | [DATABASE.md](../DATABASE.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [DISASTER_RECOVERY.md](../DISASTER_RECOVERY.md) +8 | Tested + documented |
| `scripts/sbom.sh` | [dependencies.md](../architecture/dependencies.md), [risk-register.md](../security/risk-register.md) | Tested + documented |
| `scripts/send-digest.sh` | [ARCHITECTURE.md](../ARCHITECTURE.md), [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md), [deployment.md](../architecture/deployment.md) +5 | Tested + documented |
| `scripts/sync-intel.sh` | [ARCHITECTURE.md](../ARCHITECTURE.md), [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md), [c4.md](../architecture/c4.md) +18 | Tested + documented |
| `scripts/test-docker-stack.sh` | [DEPLOYMENT.md](../DEPLOYMENT.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [release.md](../operations/release.md) | Tested + documented |
| `scripts/test-publish-github.sh` | [TESTING_GUIDE.md](../TESTING_GUIDE.md), [release.md](../operations/release.md), [known-issues.md](../testing/known-issues.md), [strategy.md](../testing/strategy.md) | Tested + documented |
| `scripts/test-setup-docker.sh` | [release.md](../operations/release.md) | Documented |
| `scripts/test.sh` | [CONTRIBUTING.md](../CONTRIBUTING.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [SECURITY.md](../SECURITY.md) +14 | Tested + documented |
| `scripts/verify-release.sh` | [CONTRIBUTING.md](../CONTRIBUTING.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [SECURITY.md](../SECURITY.md), [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md) +10 | Tested + documented |
| `scripts/veyrs-offline-update.sh` | - | Tested |
| `scripts/veyrs-updater.sh` | [DEPLOYMENT.md](../DEPLOYMENT.md), [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md), [c4.md](../architecture/c4.md), [undocumented-features.md](../audit/undocumented-features.md) +4 | Tested + documented |
| `site/atomic_swap.py` | [services.md](../operations/services.md) | Tested + documented |
| `site/build.py` | [ARCHITECTURE.md](../ARCHITECTURE.md), [DESIGN_SYSTEM.md](../DESIGN_SYSTEM.md), [DEVELOPMENT.md](../DEVELOPMENT.md), [README.md](../README.md) +13 | Tested + documented |
| `site/web/build_web.py` | [ARCHITECTURE.md](../ARCHITECTURE.md), [DESIGN_SYSTEM.md](../DESIGN_SYSTEM.md), [TESTING_GUIDE.md](../TESTING_GUIDE.md), [c4.md](../architecture/c4.md) +5 | Tested + documented |
| `veyrs-setup.sh` | [ADMIN_GUIDE.md](../ADMIN_GUIDE.md), [DEPLOYMENT.md](../DEPLOYMENT.md), [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md), [SECURITY.md](../SECURITY.md) +19 | Tested + documented |

## Test files

114 files, 1968 test functions (parametrised cases count once).

| Test file | Tests |
|---|---|
| `tests/test_ai_token_auth.py` | 24 |
| `tests/test_api_unit.py` | 2 |
| `tests/test_audit_rls.py` | 6 |
| `tests/test_client_address.py` | 8 |
| `tests/test_console_configure_frame.py` | 14 |
| `tests/test_console_contrast.py` | 6 |
| `tests/test_console_design_system.py` | 10 |
| `tests/test_console_dialog_payloads.py` | 7 |
| `tests/test_console_docs_link.py` | 5 |
| `tests/test_console_keyboard_a11y.py` | 7 |
| `tests/test_console_layout_classes.py` | 5 |
| `tests/test_console_mfa_policy.py` | 4 |
| `tests/test_console_nav_pin_bottom.py` | 5 |
| `tests/test_console_readability_0391.py` | 4 |
| `tests/test_console_redesign_0370.py` | 9 |
| `tests/test_console_redesign_0380.py` | 6 |
| `tests/test_console_vhost_names.py` | 5 |
| `tests/test_container_images.py` | 19 |
| `tests/test_container_stack.py` | 27 |
| `tests/test_cvss_official.py` | 6 |
| `tests/test_distro_version_normalisation.py` | 12 |
| `tests/test_docker_backup_verify.py` | 3 |
| `tests/test_docs_are_current.py` | 12 |
| `tests/test_docs_center.py` | 17 |
| `tests/test_docs_diagrams.py` | 2 |
| `tests/test_docs_reference_is_current.py` | 1 |
| `tests/test_docs_worked_example.py` | 4 |
| `tests/test_epss_retention.py` | 8 |
| `tests/test_executable_bits.py` | 1 |
| `tests/test_export_binary_guard.py` | 4 |
| `tests/test_fix_api.py` | 34 |
| `tests/test_fix_auth.py` | 42 |
| `tests/test_fix_deploy.py` | 28 |
| `tests/test_fix_deps.py` | 7 |
| `tests/test_fix_ingest.py` | 27 |
| `tests/test_fix_sla.py` | 42 |
| `tests/test_installer_dry_run_guard.py` | 5 |
| `tests/test_installer_offline_packages.py` | 5 |
| `tests/test_installer_timers.py` | 6 |
| `tests/test_ip_guard_survives_export.py` | 3 |
| `tests/test_login_error_message.py` | 7 |
| `tests/test_nvd_rejects.py` | 5 |
| `tests/test_phase10_hardening.py` | 26 |
| `tests/test_phase15_api.py` | 19 |
| `tests/test_phase15_parsers.py` | 24 |
| `tests/test_phase15_unified_ingest.py` | 35 |
| `tests/test_phase16_agents.py` | 30 |
| `tests/test_phase16_runner.py` | 7 |
| `tests/test_phase17_itsm_inbound.py` | 20 |
| `tests/test_phase18_hardening.py` | 18 |
| `tests/test_phase19_coverage.py` | 12 |
| `tests/test_phase20_artifact_identity.py` | 12 |
| `tests/test_phase21_inventory_correlation.py` | 28 |
| `tests/test_phase24_dependencies.py` | 12 |
| `tests/test_phase24_mfa.py` | 19 |
| `tests/test_phase25_cwe_catalog.py` | 22 |
| `tests/test_phase26_scope.py` | 23 |
| `tests/test_phase26_team_ownership.py` | 14 |
| `tests/test_phase27_team_dashboard.py` | 11 |
| `tests/test_phase28_sla_scope.py` | 23 |
| `tests/test_phase2_core.py` | 28 |
| `tests/test_phase30_scanner_page.py` | 17 |
| `tests/test_phase31_console_wiring.py` | 5 |
| `tests/test_phase32_nav_collapsed.py` | 9 |
| `tests/test_phase33_scanner_connectors.py` | 23 |
| `tests/test_phase34_inventory_and_scanning.py` | 24 |
| `tests/test_phase35_operability.py` | 47 |
| `tests/test_phase36_disposition.py` | 43 |
| `tests/test_phase37_estate_lens.py` | 15 |
| `tests/test_phase38_dashboard_preference.py` | 19 |
| `tests/test_phase39_scanning_nav.py` | 17 |
| `tests/test_phase3_intel.py` | 26 |
| `tests/test_phase3_risk.py` | 24 |
| `tests/test_phase40_asset_sources.py` | 51 |
| `tests/test_phase41_directory_auth.py` | 54 |
| `tests/test_phase42_console_screens.py` | 7 |
| `tests/test_phase42_netbox_and_team_import.py` | 37 |
| `tests/test_phase43_jira.py` | 29 |
| `tests/test_phase44_confluence.py` | 25 |
| `tests/test_phase45_ticketing_mode.py` | 20 |
| `tests/test_phase46_risk_register.py` | 24 |
| `tests/test_phase47_risk_matrix.py` | 7 |
| `tests/test_phase48_secret_vault.py` | 45 |
| `tests/test_phase49_fix_plan.py` | 28 |
| `tests/test_phase4_itsm.py` | 22 |
| `tests/test_phase50_report_builder.py` | 37 |
| `tests/test_phase51_attribution.py` | 20 |
| `tests/test_phase52_release_signing.py` | 24 |
| `tests/test_phase52_updates.py` | 36 |
| `tests/test_phase53_system_inventory.py` | 17 |
| `tests/test_phase54_mfa_methods.py` | 17 |
| `tests/test_phase55_local_update.py` | 15 |
| `tests/test_phase56_platform_admin.py` | 4 |
| `tests/test_phase57_radius.py` | 15 |
| `tests/test_phase58_oidc.py` | 7 |
| `tests/test_phase59_cve_exposure.py` | 8 |
| `tests/test_phase5_intel_docs.py` | 25 |
| `tests/test_phase6_ai.py` | 52 |
| `tests/test_phase7_compliance.py` | 38 |
| `tests/test_phase8_integrations.py` | 43 |
| `tests/test_phase9_reporting.py` | 34 |
| `tests/test_platform_admin_role.py` | 8 |
| `tests/test_restore_as_superuser.py` | 6 |
| `tests/test_schema_reconcile.py` | 4 |
| `tests/test_schema_steps.py` | 4 |
| `tests/test_secret_rekey.py` | 10 |
| `tests/test_setup_docker_env_upgrade.py` | 4 |
| `tests/test_site_i18n.py` | 16 |
| `tests/test_site_render.py` | 17 |
| `tests/test_sync_intel_script.py` | 6 |
| `tests/test_trust_store.py` | 15 |
| `tests/test_web_tls.py` | 23 |
| `tests/test_widen_columns.py` | 2 |
| `tests/test_write_paths.py` | 6 |
