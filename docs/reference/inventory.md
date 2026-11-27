---
title: Component inventory
purpose: Every file in the repository (outside docs/) and what it is, generated from the checkout.
scope: Files, directories, CLI commands, shipped units, route and table counts. Sizes, test counts and documentation links are in the traceability matrix.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, git ls-files]
related: [reference/traceability.md, reference/coverage.md, ARCHITECTURE.md]
---

# Component inventory

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.
> Documentation files are not listed: the portal navigation is their index.


## Totals

| Item | Count |
|---|---|
| Files (outside docs/) | 431 |
| Directories | 42 |
| HTTP operations (documented in OpenAPI) | 350 |
| OpenAPI tags | 19 |
| Database tables | 93 |
| Shipped systemd units | 17 |

## CLI commands

`python -m veyrs <command>` (with the venv and `.env` loaded). Source: `backend/veyrs/cli.py`, `backend/veyrs/services/mfa_admin.py`.

| Command | Purpose |
|---|---|
| `bootstrap` | create the first organization + administrator |
| `check` | self-test configuration, storage and engines |
| `dedupe merge-duplicates` | resolve rows that block the NULLS NOT DISTINCT unique keys on vulnerabilities and risk_register_raci |
| `dedupe rehash` | re-key SCA findings stored before 0.41.0, whose key ignored the CVE |
| `digest` | queue and deliver the daily digest for every organization whose configured hour this is |
| `import-inventory` | load assets and their installed software from a JSON file |
| `init-db` | create schema, RLS policies and built-in roles |
| `intel-due` | print which intelligence feeds are due to run right now |
| `keygen` | print a fresh VEYRS_ENCRYPTION_KEY |
| `maintenance` | the tick's housekeeping: dispatch notifications, reap agent leases, expire risk acceptances, prune by retention |
| `mfa-reset` | turn two-factor OFF for an account that lost every factor |
| `mfa-setup` | turn on e-mail or Telegram two-factor FOR an account |
| `mfa-test` | send one test message by e-mail or Telegram (no account changes) |
| `platform-admin` | grant or revoke platform administration (installation-wide pages) |
| `prune` | delete rows past their retention (the retention_*_days settings); dry run unless --apply |
| `prune-epss-history` | delete EPSS snapshots older than the retention (VEYRS_EPSS_HISTORY_DAYS) |
| `recompute-escalation` | one-off after upgrading to 0.41.0: re-derive escalation levels from the SLA deadline (dry run unless --apply; silent unless --notify) |
| `recompute-risk` | re-run the risk engine |
| `run-sla` | evaluate SLA state and fire escalations |
| `secrets gc` | list (or with --apply delete) vault entries no row references |
| `secrets migrate` | re-store every credential as local, mirror or vault (dry run by default) |
| `secrets rekey` | re-seal every local copy under the current VEYRS_ENCRYPTION_KEY (key rotation; dry run by default) |
| `secrets status` | mode, vault health and counts per column, all tenants |
| `seed-defaults` | add the built-in SLA policies, escalation ladder and risk profiles a tenant is missing (never overwrites; dry run unless --apply) |
| `sync-cwe` | refresh the MITRE CWE weakness dictionary |
| `sync-epss` | refresh EPSS scores |
| `sync-kev` | refresh the CISA KEV catalogue |
| `sync-nvd` | incrementally pull CVE records from NVD |
| `sync-schema` | add columns/indexes/FKs present in the models but missing from the DB |
| `tick` | record the start/finish of an hourly tick |
| `tls-sync` | install the active web certificate on THIS node (root; run by veyrs-tls-sync.timer) |
| `unlock` | lift the sign-in lockout of an account (account lock and every source's back-off) |

## Routes per tag

| Tag | Operations |
|---|---|
| [administration](../api/reference/administration.md) | 65 |
| [agents](../api/reference/agents.md) | 22 |
| [ai](../api/reference/ai.md) | 20 |
| [asset sources](../api/reference/asset-sources.md) | 19 |
| [assets](../api/reference/assets.md) | 17 |
| [authentication](../api/reference/authentication.md) | 17 |
| [compliance](../api/reference/compliance.md) | 16 |
| [cvss](../api/reference/cvss.md) | 9 |
| [dashboards & reports](../api/reference/dashboards-reports.md) | 17 |
| [engagements](../api/reference/engagements.md) | 15 |
| [integrations](../api/reference/integrations.md) | 25 |
| [intelligence & knowledge](../api/reference/intelligence-knowledge.md) | 20 |
| [operations](../api/reference/operations.md) | 2 |
| [policies](../api/reference/policies.md) | 16 |
| [risk register](../api/reference/risk-register.md) | 10 |
| [saved views](../api/reference/saved-views.md) | 4 |
| [threat intelligence](../api/reference/threat-intelligence.md) | 14 |
| [ticketing](../api/reference/ticketing.md) | 26 |
| [vulnerability management](../api/reference/vulnerability-management.md) | 16 |

## Shipped systemd units

| Unit file | Description |
|---|---|
| `infrastructure/backup/veyrs-alert@.service` | VEYRS alert: %i failed |
| `infrastructure/backup/veyrs-pgdump.service` | VEYRS logical database backup (pg_dump + off-host copy) |
| `infrastructure/backup/veyrs-pgdump.timer` | Nightly VEYRS logical database backup |
| `infrastructure/backup/veyrs-pgverify.service` | VEYRS backup restore verification (restores the latest dump and counts rows) |
| `infrastructure/backup/veyrs-pgverify.timer` | Weekly proof that the VEYRS backup actually restores |
| `infrastructure/backup/veyrs-replcheck.service` | VEYRS streaming replication health check |
| `infrastructure/backup/veyrs-replcheck.timer` | Check every 15 minutes that veyrs-db-2 is really replicating |
| `infrastructure/systemd/veyrs-api.service` | VEYRS API (FastAPI/uvicorn) |
| `infrastructure/systemd/veyrs-digest.service` | VEYRS daily digest tick |
| `infrastructure/systemd/veyrs-digest.timer` | VEYRS daily digest tick |
| `infrastructure/systemd/veyrs-tls-sync.service` | VEYRS web certificate installer (applies the certificate chosen in the console to this node's nginx) |
| `infrastructure/systemd/veyrs-tls-sync.timer` | VEYRS web certificate installer, every 30 seconds |
| `infrastructure/systemd/veyrs-updater.path` | VEYRS update requests (starts the root updater when the console queues one) |
| `infrastructure/systemd/veyrs-updater.service` | VEYRS self-update (applies one queued request: verify, back up, install, health-check) |
| `integrations/systemd/veyrs-intel-sync.service` | VEYRS intelligence feed sync (NVD + EPSS + KEV + CWE) |
| `integrations/systemd/veyrs-intel-sync.timer` | VEYRS intelligence refresh tick |
| `integrations/veyrs-agent/veyrs-agent.service` | VEYRS execution agent (scanner runner) |

## Files by area

### API routers

31 files.

| File | Purpose |
|---|---|
| `backend/veyrs/api/__init__.py` | HTTP layer. Versioned; v1 is the only stable contract. |
| `backend/veyrs/api/v1/__init__.py` | v1 API router assembly. |
| `backend/veyrs/api/v1/admin.py` | Tenant administration: organizations, users, teams, departments, roles, API keys and the audit trail. |
| `backend/veyrs/api/v1/agents.py` | Execution agents: control plane and agent data plane (spec section 33). |
| `backend/veyrs/api/v1/ai.py` | AI gateway, assistant and natural-language search endpoints (spec 19/20). |
| `backend/veyrs/api/v1/assets.py` | Asset inventory API (spec sections 7 and 8). |
| `backend/veyrs/api/v1/attribution.py` | Why did this finding change? (see services/attribution.py) |
| `backend/veyrs/api/v1/auth.py` | Authentication endpoints: login, refresh, logout, me, password change. |
| `backend/veyrs/api/v1/cmdb.py` | Asset sources: importing an external inventory and comparing two of them. |
| `backend/veyrs/api/v1/compliance.py` | Compliance endpoints (spec sections 16 and 27). |
| `backend/veyrs/api/v1/cvss.py` | Interactive CVSS calculator endpoints. |
| `backend/veyrs/api/v1/engagements.py` | Engagements, scan tests, endpoints and risk acceptance (spec section 32). |
| `backend/veyrs/api/v1/findings.py` | Vulnerability and finding API: the operator's daily work queue. |
| `backend/veyrs/api/v1/fix_plan.py` | Fix plan API, and the operator's vendor upgrade-path rules it applies. |
| `backend/veyrs/api/v1/integrations.py` | Scanner imports and ITSM connectors (spec sections 14 and 31). |
| `backend/veyrs/api/v1/intel.py` | Threat-intelligence API: CVE, CWE, CPE, EPSS, CISA KEV and feed ingestion. |
| `backend/veyrs/api/v1/knowledge.py` | Documents, threat intelligence feeds, knowledge base and global search. |
| `backend/veyrs/api/v1/policies.py` | Policy administration: SLA, escalation and assignment rules. |
| `backend/veyrs/api/v1/report_builder.py` | Report builder API: ad-hoc reports from a curated catalog, plus saved reports. |
| `backend/veyrs/api/v1/reports.py` | Dashboards and report exports (spec sections 27 and 29). |
| `backend/veyrs/api/v1/risk_register.py` | Risk register API: risks that are not findings, and who answers for them. |
| `backend/veyrs/api/v1/schemas.py` | Request/response models for the v1 API. |
| `backend/veyrs/api/v1/system.py` | Installed software and network requirements of this installation. |
| `backend/veyrs/api/v1/team_import.py` | Bringing teams in from NetBox or from the directory. |
| `backend/veyrs/api/v1/tickets.py` | Ticketing, workflow and notification API (spec sections 13, 14, 15, 30). |
| `backend/veyrs/api/v1/trust_store.py` | TLS trust store: the CAs this installation accepts when it connects out. |
| `backend/veyrs/api/v1/updates.py` | Software update: the installation's version, the latest release, and a request for the root updater to apply it. |
| `backend/veyrs/api/v1/uploads.py` | Bounded upload reading shared by the routes that accept files. |
| `backend/veyrs/api/v1/views.py` | Saved views: an operator's own queues. |
| `backend/veyrs/api/v1/vuln_schemas.py` | Request/response models for assets, intelligence, vulnerabilities and SLA. |
| `backend/veyrs/api/v1/web_tls.py` | The certificate VEYRS serves: request (CSR), attach the signed certificate, install it on every app node, roll back. |

### Services (business logic)

70 files.

| File | Purpose |
|---|---|
| `backend/veyrs/services/__init__.py` | Business services - the layer routes call into. No HTTP objects here. |
| `backend/veyrs/services/agents.py` | Execution-agent lifecycle, dispatch and result intake (spec section 33). |
| `backend/veyrs/services/ai/__init__.py` | VEYRS AI subsystem. |
| `backend/veyrs/services/ai/capabilities.py` | The AI features themselves (spec section 19), all grounded in VEYRS data. |
| `backend/veyrs/services/ai/gateway.py` | The AI gateway: the single door between VEYRS and any model (spec 19/20). |
| `backend/veyrs/services/ai/guardrails.py` | Input/output guardrails for every AI call (spec section 20). |
| `backend/veyrs/services/ai/nlquery.py` | Natural-language -> structured query translation (spec section 19). |
| `backend/veyrs/services/ai/providers.py` | Provider abstraction layer (spec section 19). |
| `backend/veyrs/services/ai/token_auth.py` | Sign-in for model gateways whose bearer token expires. |
| `backend/veyrs/services/analytics.py` | Dashboard and analytics queries (spec section 27). |
| `backend/veyrs/services/attribution.py` | Why did this finding change? Attribution of closes and reopens. |
| `backend/veyrs/services/audit.py` | Audit-trail writer. |
| `backend/veyrs/services/autoticket.py` | Open remediation tickets without a human clicking, and refuse to do it badly. |
| `backend/veyrs/services/cmdb.py` | Reading somebody else's asset inventory, and telling two of them apart. |
| `backend/veyrs/services/compliance.py` | Compliance engine (spec sections 16 and 27). |
| `backend/veyrs/services/correlation.py` | CVE -> product -> asset correlation, and the finding lifecycle it produces. |
| `backend/veyrs/services/cvss_assist.py` | Turn a pasted security bulletin into a filled-in CVSS calculator. |
| `backend/veyrs/services/dedupe.py` | Configurable finding deduplication (the DefectDojo model, reimplemented). |
| `backend/veyrs/services/digest.py` | The daily digest: VEYRS goes out and finds the operator. |
| `backend/veyrs/services/docs.py` | Confluence: publishing VEYRS runbooks into the wiki the organisation reads. |
| `backend/veyrs/services/documents.py` | Document intelligence (spec section 18). |
| `backend/veyrs/services/endpoints.py` | Endpoint parsing, canonicalisation and finding attachment. |
| `backend/veyrs/services/engagements.py` | Engagement/test lifecycle, scoped reimport and risk acceptance. |
| `backend/veyrs/services/fix_plan.py` | Fix plan: which version fixes everything open on a product, and how far away it is. |
| `backend/veyrs/services/importers/__init__.py` | Scanner import framework (spec section 31). |
| `backend/veyrs/services/importers/base.py` | Canonical scanner record and the normalizer every importer feeds (spec 31). |
| `backend/veyrs/services/importers/parsers.py` | Vendor export parsers (spec section 31). |
| `backend/veyrs/services/importers/parsers_modern.py` | Parsers for the modern toolchain: SAST, SCA, DAST, IaC and cloud posture. |
| `backend/veyrs/services/ingest_admin.py` | `veyrs dedupe ...` -- one-off data migrations of the ingest pipeline. |
| `backend/veyrs/services/intel_pipeline.py` | Turns freshly ingested intelligence into tenant findings. |
| `backend/veyrs/services/intel_schedule.py` | How often each intelligence feed refreshes, and who gets to decide. |
| `backend/veyrs/services/intelligence.py` | Ingestion of global threat intelligence: NVD/CVE, EPSS, CISA KEV. |
| `backend/veyrs/services/inventory.py` | Software inventory: turning what an operator calls something into CPE identity. |
| `backend/veyrs/services/itsm.py` | ITSM connectors: ServiceNow, Jira Service Management, generic webhook. |
| `backend/veyrs/services/itsm_inbound.py` | Inbound ITSM events: the return leg of the sync (spec section 34). |
| `backend/veyrs/services/ldap_auth.py` | Directory authentication: LDAP and Active Directory. |
| `backend/veyrs/services/mfa_admin.py` | Operator commands for two-factor sign-in, run on the host. |
| `backend/veyrs/services/mfa_policy.py` | Organization policy: a second factor is required to use VEYRS (R-07). |
| `backend/veyrs/services/net_guard.py` | Outbound-URL guard shared by every connector that calls a configured URL. |
| `backend/veyrs/services/network_requirements.py` | Every network destination VEYRS needs -- Administration > Network access. |
| `backend/veyrs/services/notifications.py` | Notification dispatch: in-app, email, webhook (spec section 30). |
| `backend/veyrs/services/oidc_auth.py` | Single sign-on through the organization's identity provider (OpenID Connect). |
| `backend/veyrs/services/radius_auth.py` | RADIUS authentication (AAA) for one organization, with the server's own second factor. |
| `backend/veyrs/services/remediation.py` | One entry point for "somebody must fix this finding", whichever queue owns it. |
| `backend/veyrs/services/report_builder.py` | Report builder: ad-hoc tabular reports from a curated catalog, never from SQL. |
| `backend/veyrs/services/reporting.py` | Report generation and export (spec section 29). |
| `backend/veyrs/services/retention.py` | Data retention: `veyrs prune`. |
| `backend/veyrs/services/risk.py` | Persistence side of the risk engine: profile resolution and bulk re-scoring. |
| `backend/veyrs/services/risk_register.py` | Domain service for the risk register. Every write goes through here. |
| `backend/veyrs/services/risk_register_mode.py` | The switch that decides whether this tenant keeps a risk register at all. |
| `backend/veyrs/services/scanners.py` | Pulling scan results from a scanner's own API (spec section 31, phase 33). |
| `backend/veyrs/services/scanning.py` | Active scanning: the switch that decides whether VEYRS probes anything. |
| `backend/veyrs/services/search.py` | Global and semantic search (spec section 28). |
| `backend/veyrs/services/secret_storage.py` | Where stored credentials live, and moving them between local and an external vault. |
| `backend/veyrs/services/sla.py` | SLA and escalation engines (spec sections 11 and 12). |
| `backend/veyrs/services/software_inventory.py` | Installed software on this node -- Administration > Installed software. |
| `backend/veyrs/services/team_import.py` | Teams that already exist somewhere else, brought in rather than retyped. |
| `backend/veyrs/services/teams.py` | Team ownership: name resolution, membership, and the ownership expression. |
| `backend/veyrs/services/tenant_defaults.py` | Built-in defaults every tenant needs on day one. |
| `backend/veyrs/services/threatintel.py` | Threat-intelligence feeds and the knowledge base (spec sections 17 and 21). |
| `backend/veyrs/services/tick.py` | The hourly tick: what it does besides the feeds, and proof that it ran. |
| `backend/veyrs/services/ticketing.py` | Ticket lifecycle and ITIL mapping (spec sections 14 and 15). |
| `backend/veyrs/services/ticketing_mode.py` | Which ticketing system is the authority: VEYRS' own queue, or an external one. |
| `backend/veyrs/services/trust_store.py` | TLS trust store: import CAs, build the verification context every outbound client uses, and diagnose a server's certificate in terms an operator can act on. |
| `backend/veyrs/services/updates.py` | Software update check, and the UNPRIVILEGED half of self-update. |
| `backend/veyrs/services/versions.py` | Version and name normalisation used by CPE/product correlation. |
| `backend/veyrs/services/views.py` | Saved views: store a query, replay it, never widen it. |
| `backend/veyrs/services/web_tls.py` | The certificate VEYRS serves: request it here, have it signed anywhere, install it on every app node. |
| `backend/veyrs/services/workflow.py` | The workflow engine (spec section 13). |
| `backend/veyrs/services/xmlsafe.py` | One implementation of "parse this XML without letting it own us". |

### Models (schema)

23 files.

| File | Purpose |
|---|---|
| `backend/veyrs/models/__init__.py` | SQLAlchemy models. Importing this package registers every table on Base.metadata. |
| `backend/veyrs/models/agent.py` | Execution agents: remote workers that RUN scanners (spec section 33). |
| `backend/veyrs/models/ai.py` | AI gateway configuration and conversation state (spec sections 19 and 20). |
| `backend/veyrs/models/assets.py` | Tenant asset inventory, business services and asset<->product installation. |
| `backend/veyrs/models/audit.py` | Append-only audit trail. |
| `backend/veyrs/models/base.py` | Declarative base plus the mixins every VEYRS table is built from. |
| `backend/veyrs/models/cmdb.py` | External asset sources: a CMDB export, an arbitrary JSON API, or NetBox. |
| `backend/veyrs/models/compliance.py` | Compliance framework, control, evidence and assessment model (spec 16/27). |
| `backend/veyrs/models/engagement.py` | Engagement / test scoping, endpoints and risk acceptance (spec section 32). |
| `backend/veyrs/models/integration.py` | Importer runs and external-system links (spec sections 14 and 31). |
| `backend/veyrs/models/intelligence.py` | Global security intelligence: CVE, CWE, CPE, EPSS, CISA KEV, vendor/product. |
| `backend/veyrs/models/knowledge.py` | Threat intelligence feeds, document intelligence and the knowledge base. |
| `backend/veyrs/models/report_queries.py` | Saved report-builder queries: a question an operator asks more than once. |
| `backend/veyrs/models/risk_register.py` | The risk register: risks that are not findings, and the RACI that owns them. |
| `backend/veyrs/models/sla.py` | SLA and escalation policies (spec sections 11 and 12). |
| `backend/veyrs/models/tenancy.py` | Organizations, users, teams, departments, roles and permissions. |
| `backend/veyrs/models/ticketing.py` | Ticketing and ITIL record types (spec sections 14 and 15). |
| `backend/veyrs/models/trust.py` | TLS trust store: the certificate authorities this installation ACCEPTS when it connects out (CMDB, scanners, ITSM, directory, single sign-on, SMTP, AI endpoints, vault, intelligence feeds). |
| `backend/veyrs/models/upgrade.py` | Operator-maintained vendor upgrade-path rules, read by the fix plan. |
| `backend/veyrs/models/views.py` | Saved views: the filter set an operator opens every morning. |
| `backend/veyrs/models/vulnerability.py` | Tenant-side vulnerability management: findings, their lifecycle, risk scores and the configurable risk profiles that produce them. |
| `backend/veyrs/models/web_tls.py` | The certificate VEYRS PRESENTS to browsers (the mirror image of the trust store, which holds the CAs it ACCEPTS when it connects out). |
| `backend/veyrs/models/workflow.py` | Workflow and notification models (spec sections 13 and 30). |

### Security

14 files.

| File | Purpose |
|---|---|
| `backend/veyrs/security/__init__.py` | Authentication, authorization and hardening primitives. |
| `backend/veyrs/security/agent_auth.py` | Authentication for execution agents (spec section 33). |
| `backend/veyrs/security/auth.py` | Password hashing, token issuance and API-key handling. |
| `backend/veyrs/security/deps.py` | FastAPI authorization dependencies. |
| `backend/veyrs/security/lockout.py` | Failed-credential accounting: who may try a credential again, and when. |
| `backend/veyrs/security/mfa.py` | Time-based one-time passwords (RFC 6238) for local password logins. |
| `backend/veyrs/security/mfa_delivery.py` | Second factors delivered to the person: a code by e-mail or by Telegram. |
| `backend/veyrs/security/permissions.py` | The single source of truth for VEYRS permissions and built-in roles. |
| `backend/veyrs/security/platform.py` | Who may open the installation-wide pages (platform administration). |
| `backend/veyrs/security/ratelimit.py` | Rate limiting (spec section 24, threat model T-API-ABUSE). |
| `backend/veyrs/security/scope.py` | Team-level visibility: the ABAC seam `tenancy.py` promised and never enforced. |
| `backend/veyrs/security/secret_vault.py` | Client for an external secret store: HashiCorp Vault or OpenBao, KV version 2. |
| `backend/veyrs/security/secrets.py` | Envelope encryption for secrets stored in the database (spec section 24). |
| `backend/veyrs/security/tenant_guard.py` | Tenant isolation guards that do not depend on remembering a filter (R-23). |

### Engines

8 files.

| File | Purpose |
|---|---|
| `backend/veyrs/engines/__init__.py` | VEYRS decision engines: CVSS, EPSS, KEV, risk, SLA, escalation, workflow. |
| `backend/veyrs/engines/cvss/__init__.py` | VEYRS CVSS_ENGINE - one façade over the versioned calculators. |
| `backend/veyrs/engines/cvss/common.py` | Shared helpers for the VEYRS CVSS engine. |
| `backend/veyrs/engines/cvss/v2.py` | CVSS v2.0 scoring, per the FIRST "A Complete Guide to the CVSS Version 2.0". |
| `backend/veyrs/engines/cvss/v3.py` | CVSS v3.0 and v3.1 scoring, per the FIRST specification documents. |
| `backend/veyrs/engines/cvss/v4.py` | CVSS v4.0 scoring - faithful port of the FIRST.org reference implementation. |
| `backend/veyrs/engines/cvss/v4_tables.py` | CVSS v4.0 official scoring tables. |
| `backend/veyrs/engines/risk.py` | VEYRS Risk Engine. |

### Intelligence feeds

2 files.

| File | Purpose |
|---|---|
| `backend/veyrs/intel/__init__.py` | Outbound collection for VEYRS's intelligence feeds. |
| `backend/veyrs/intel/feeds.py` | Fetch NVD 2.0, EPSS and CISA KEV, hand them to the ingest layer, correlate. |

### Backend core

14 files.

| File | Purpose |
|---|---|
| `backend/veyrs/__init__.py` | VEYRS - Unified Cybersecurity Risk Management. |
| `backend/veyrs/__main__.py` |  |
| `backend/veyrs/cli.py` | VEYRS operational CLI. |
| `backend/veyrs/config.py` | VEYRS runtime configuration. |
| `backend/veyrs/data/__init__.py` | Static reference data shipped with VEYRS (framework catalogues, lookup tables). |
| `backend/veyrs/data/frameworks.py` | Built-in compliance catalogues. |
| `backend/veyrs/db.py` | Database engine, session factory and the tenant-scoped session helper. |
| `backend/veyrs/main.py` | VEYRS ASGI application. |
| `backend/veyrs/observability.py` | Structured logging, correlation IDs, security headers and Prometheus metrics. |
| `backend/veyrs/schema_steps/__init__.py` | Idempotent DDL that `create_all` and `sync-schema` cannot express. |
| `backend/veyrs/schema_steps/step_api.py` | Schema steps owned by the API workstream. |
| `backend/veyrs/schema_steps/step_auth.py` | Audit trails append-only in the database; `auth_events` tenant policies (R-05). |
| `backend/veyrs/schema_steps/step_ingest.py` | Ingest workstream DDL: unique keys whose NULLs must not be distinct (TD-33). |
| `backend/veyrs/schema_steps/step_search.py` | Trigram indexes for the lexical search (TD-54, 0.41.0). |

### Backend other

1 files.

| File | Purpose |
|---|---|
| `backend/README.md` | backend |

### Console (web UI)

12 files.

| File | Purpose |
|---|---|
| `frontend/console/app.js` |  |
| `frontend/console/console.css` |  |
| `frontend/console/fonts/LICENSE-Inter.txt` |  |
| `frontend/console/fonts/LICENSE-JetBrainsMono.txt` |  |
| `frontend/console/fonts/README.txt` |  |
| `frontend/console/fonts/inter-bold.woff2` |  |
| `frontend/console/fonts/inter-medium.woff2` |  |
| `frontend/console/fonts/inter-regular.woff2` |  |
| `frontend/console/fonts/inter-semibold.woff2` |  |
| `frontend/console/fonts/jetbrains-mono-medium.woff2` |  |
| `frontend/console/fonts/jetbrains-mono-regular.woff2` |  |
| `frontend/console/index.html` |  |

### Frontend other

20 files.

| File | Purpose |
|---|---|
| `frontend/README.md` | frontend |
| `frontend/brand/logo/README.md` | VEYRS brand assets |
| `frontend/brand/logo/veyrs-favicon.ico` |  |
| `frontend/brand/logo/veyrs-favicon.png` |  |
| `frontend/brand/logo/veyrs-favicon.svg` |  |
| `frontend/brand/logo/veyrs-logo-black.png` |  |
| `frontend/brand/logo/veyrs-logo-on-dark-gradient.png` |  |
| `frontend/brand/logo/veyrs-logo-on-dark-tight.png` |  |
| `frontend/brand/logo/veyrs-logo-on-dark.png` |  |
| `frontend/brand/logo/veyrs-logo-white.png` |  |
| `frontend/brand/logo/veyrs-logo.png` |  |
| `frontend/brand/logo/veyrs-mark-black.png` |  |
| `frontend/brand/logo/veyrs-mark-gradient.png` |  |
| `frontend/brand/logo/veyrs-mark-on-dark.png` |  |
| `frontend/brand/logo/veyrs-mark-white.png` |  |
| `frontend/brand/logo/veyrs-mark.png` |  |
| `frontend/brand/logo/veyrs-wordmark.png` |  |
| `frontend/brand/logo/veyrs-wordmark.svg` |  |
| `frontend/brand/logo/veyrs.png` |  |
| `frontend/brand/veyrs-tokens.css` |  |

### Integrations and agent

7 files.

| File | Purpose |
|---|---|
| `integrations/README.md` | integrations |
| `integrations/fleet-import/collect_fleet.py` | Build a VEYRS inventory payload from an existing fleet, over SSH. |
| `integrations/systemd/veyrs-intel-sync.service` | VEYRS intelligence feed sync (NVD + EPSS + KEV + CWE) |
| `integrations/systemd/veyrs-intel-sync.timer` | VEYRS intelligence refresh tick |
| `integrations/veyrs-agent/README.md` | VEYRS execution agent |
| `integrations/veyrs-agent/veyrs-agent.service` | VEYRS execution agent (scanner runner) |
| `integrations/veyrs-agent/veyrs_agent.py` | VEYRS execution agent - the reference runner. |

### Infrastructure (systemd, nginx, backup)

22 files.

| File | Purpose |
|---|---|
| `infrastructure/README.md` | infrastructure |
| `infrastructure/backup/veyrs-alert.sh` | Tell a human that a VEYRS backup unit failed. |
| `infrastructure/backup/veyrs-alert@.service` | VEYRS alert: %i failed |
| `infrastructure/backup/veyrs-pgdump.service` | VEYRS logical database backup (pg_dump + off-host copy) |
| `infrastructure/backup/veyrs-pgdump.sh` | Logical backup of the VEYRS database. |
| `infrastructure/backup/veyrs-pgdump.timer` | Nightly VEYRS logical database backup |
| `infrastructure/backup/veyrs-pgverify.service` | VEYRS backup restore verification (restores the latest dump and counts rows) |
| `infrastructure/backup/veyrs-pgverify.sh` | Prove the latest logical dump actually restores. |
| `infrastructure/backup/veyrs-pgverify.timer` | Weekly proof that the VEYRS backup actually restores |
| `infrastructure/backup/veyrs-replcheck.service` | VEYRS streaming replication health check |
| `infrastructure/backup/veyrs-replcheck.sh` | Is the hot standby actually replicating? |
| `infrastructure/backup/veyrs-replcheck.timer` | Check every 15 minutes that veyrs-db-2 is really replicating |
| `infrastructure/nginx-veyrs-console.conf` | VEYRS management console. |
| `infrastructure/nginx-veyrs-docs.conf` | VEYRS Docs Center (documentation site), the default server on the nodes. |
| `infrastructure/nginx-veyrs-web.conf` | VEYRS product site (veyrs-web.example.com). |
| `infrastructure/systemd/veyrs-api.service` | VEYRS API (FastAPI/uvicorn) |
| `infrastructure/systemd/veyrs-digest.service` | VEYRS daily digest tick |
| `infrastructure/systemd/veyrs-digest.timer` | VEYRS daily digest tick |
| `infrastructure/systemd/veyrs-tls-sync.service` | VEYRS web certificate installer (applies the certificate chosen in the console to this node's nginx) |
| `infrastructure/systemd/veyrs-tls-sync.timer` | VEYRS web certificate installer, every 30 seconds |
| `infrastructure/systemd/veyrs-updater.path` | VEYRS update requests (starts the root updater when the console queues one) |
| `infrastructure/systemd/veyrs-updater.service` | VEYRS self-update (applies one queued request: verify, back up, install, health-check) |

### Container deployment

12 files.

| File | Purpose |
|---|---|
| `docker/Dockerfile` | VEYRS container images. Build context is the REPOSITORY ROOT, not this |
| `docker/README.md` | VEYRS — container stack |
| `docker/agent-entrypoint.sh` | Scanner-agent entrypoint. |
| `docker/compose.external-db.yaml` | VEYRS — overlay: PostgreSQL OUTSIDE this stack. |
| `docker/compose.yaml` | VEYRS — single-node evaluation stack. |
| `docker/console.conf` | VEYRS console + same-origin API proxy. |
| `docker/entrypoint.sh` | API entrypoint. Mirrors the ExecStart of veyrs-api.service, with the two |
| `docker/env.example` |  |
| `docker/init.sh` | One-shot initialiser. Runs to completion before the API starts, every `up`. |
| `docker/initdb.d/10-app-role.sh` | Create the UNPRIVILEGED application role and its two databases. Runs ONCE, |
| `docker/tick.sh` | The tick loop that replaces a systemd timer inside a container. |
| `docker/veyrs-docker.sh` | VEYRS container stack driver. |

### Scripts

27 files.

| File | Purpose |
|---|---|
| `scripts/README.md` | scripts |
| `scripts/backup.sh` | VEYRS backup: database + secrets (+ var/documents when that directory exists). |
| `scripts/check-docs-links.py` | Check every internal link of a built Docs Center. |
| `scripts/check-docs-refs.py` | Check the `path:line` references in the hand-written documentation (TD-58). |
| `scripts/ci.sh` | Release gate: the fast, targeted guard set. Run it before tagging a release |
| `scripts/freeze-deps.sh` | Regenerate requirements.txt from the venv this node actually runs. |
| `scripts/gen-reference-docs.py` | Generate the machine-derived reference documentation from the code. |
| `scripts/gen-schema-doc.py` | Generate docs/DATABASE_SCHEMA.md from the SQLAlchemy models. |
| `scripts/ip-guard.sh` | VEYRS — deny-by-default IPv4 sweep for anything that leaves the building |
| `scripts/migrate-service-user.sh` | Move an existing native node's API service from root to the `veyrs` account (R-06). |
| `scripts/osv-check.py` | Check every pinned package against the public OSV database. |
| `scripts/public-export.sh` | VEYRS — build the sanitised tree for the PUBLIC repository. |
| `scripts/publish-github.sh` | Publishes the sanitised VEYRS tree to GitHub as a repository with ONE derived |
| `scripts/publish-images.sh` | Build, verify and publish the VEYRS container images, and write the offline |
| `scripts/publish-sites.sh` | Publish the console, the Docs Center and the product site on THIS node (TD-43, TD-44). |
| `scripts/render-diagrams.py` | Pre-render every Mermaid diagram in docs/ to SVG for the Docs Center. |
| `scripts/restore.sh` | VEYRS restore. Refuses to run without an explicit confirmation, because it |
| `scripts/sbom.sh` | Software bill of materials (CycloneDX 1.5, JSON) of the Python lock. |
| `scripts/send-digest.sh` | VEYRS daily digest — one tick. |
| `scripts/sync-intel.sh` | Refresh every intelligence feed, then let the tenants know. |
| `scripts/test-docker-stack.sh` | Assertions against a RUNNING VEYRS container stack. |
| `scripts/test-publish-github.sh` | Test harness for publish-github.sh: --update, --publish and the release, on |
| `scripts/test-setup-docker.sh` | End-to-end test of veyrs-setup.sh in Docker mode, run ON the target host. |
| `scripts/test.sh` | Canonical VEYRS test entrypoint. |
| `scripts/verify-release.sh` | verify-release.sh — prove that a directory of VEYRS release assets is what the |
| `scripts/veyrs-offline-update.sh` | VEYRS offline update (shipped as update.sh in veyrs-<version>-update.tar). |
| `scripts/veyrs-updater.sh` | veyrs-updater.sh — the PRIVILEGED half of the in-product update (native installs). |

### Site builders

33 files.

| File | Purpose |
|---|---|
| `site/atomic_swap.py` | Publish a freshly built site directory over the live one without a gap (TD-43). |
| `site/build.py` | VEYRS documentation portal generator (the "Docs Center"). |
| `site/design-system/veyrs-docs/MASTER.md` | Design System Master File |
| `site/design-system/veyrs-docs/pages/portal.md` | Docs Center portal — overrides to MASTER.md |
| `site/design-system/veyrs-web/MASTER.md` | Design System Master File — VEYRS product site |
| `site/static/theme.js` |  |
| `site/static/veyrs-favicon.ico` |  |
| `site/static/veyrs-favicon.png` |  |
| `site/static/veyrs-favicon.svg` |  |
| `site/static/veyrs-logo-black.png` |  |
| `site/static/veyrs-logo-on-dark-gradient.png` |  |
| `site/static/veyrs-logo-on-dark-tight.png` |  |
| `site/static/veyrs-logo-on-dark.png` |  |
| `site/static/veyrs-logo-white.png` |  |
| `site/static/veyrs-logo.png` |  |
| `site/static/veyrs-mark-black.png` |  |
| `site/static/veyrs-mark-gradient.png` |  |
| `site/static/veyrs-mark-on-dark.png` |  |
| `site/static/veyrs-mark-white.png` |  |
| `site/static/veyrs-mark.png` |  |
| `site/static/veyrs-tokens.css` |  |
| `site/static/veyrs-wordmark.png` |  |
| `site/static/veyrs.css` |  |
| `site/static/veyrs.js` |  |
| `site/static/veyrs.png` |  |
| `site/web/assets/fonts.css` |  |
| `site/web/assets/web.css` |  |
| `site/web/build_web.py` | VEYRS product site generator (veyrs-web.example.com, veyrs.example.com). |
| `site/web/i18n/de.json` |  |
| `site/web/i18n/en.json` |  |
| `site/web/i18n/es.json` |  |
| `site/web/i18n/fr.json` |  |
| `site/web/i18n/it.json` |  |

### Tests

120 files.

| File | Purpose |
|---|---|
| `tests/README.md` | tests |
| `tests/conftest.py` | Shared test fixtures. |
| `tests/docs_refs_baseline.txt` |  |
| `tests/fixtures/cvss_official_v2.txt` |  |
| `tests/fixtures/cvss_official_v3.txt` |  |
| `tests/fixtures/cvss_official_v4.txt` |  |
| `tests/test_ai_token_auth.py` | AI providers that sign in and renew their token (session / OAuth 2.0). |
| `tests/test_api_unit.py` | The API unit must be able to start on a git-deployed node. |
| `tests/test_audit_rls.py` | The audit trails are tenant-isolated, and nothing that writes them breaks. |
| `tests/test_client_address.py` | One rule for "what is the caller's IP address". |
| `tests/test_console_configure_frame.py` | Configure has its own page with its own menu (0.39.0, owner request). |
| `tests/test_console_contrast.py` | TD-40: the console's two themes must keep WCAG AA contrast (4.5:1 for text). |
| `tests/test_console_design_system.py` | Guards for the 0.36.0 console redesign. |
| `tests/test_console_dialog_payloads.py` | 0.35.3: the console's create dialogs must send what the API accepts. |
| `tests/test_console_docs_link.py` | The console Documentation link must leave the console (0.38.1). |
| `tests/test_console_keyboard_a11y.py` | TD-13, TD-60 and the small gaps of docs/design/accessibility.md, pinned in the source. |
| `tests/test_console_layout_classes.py` | Every class the console asks for must exist in the stylesheet. |
| `tests/test_console_mfa_policy.py` | R-07 in the console (0.41.0): the organization two-factor policy and the policy-forced enrolment. Text guards, like the other console tests. |
| `tests/test_console_nav_pin_bottom.py` | Configure sits at the foot of the console sidebar (0.38.2, 0.38.3). |
| `tests/test_console_readability_0391.py` | 0.39.1: readable values in Configure and inventory screens. |
| `tests/test_console_redesign_0370.py` | Guards for the 0.37.0 console round. |
| `tests/test_console_redesign_0380.py` | Guards for the 0.38.0 console redesign ("Midnight Ops"). |
| `tests/test_console_vhost_names.py` | The console vhost must answer to every hostname that reaches the nodes. |
| `tests/test_container_images.py` | Guards for the PUBLISHED images and the privileges the stack runs with. |
| `tests/test_container_stack.py` | Guards for the container stack (docker/). |
| `tests/test_cvss_official.py` | Validate the VEYRS CVSS_ENGINE against official / reference expected scores. |
| `tests/test_distro_version_normalisation.py` | A distro package string must never be compared as an upstream version. |
| `tests/test_docker_backup_verify.py` | docker/veyrs-docker.sh backup: the dump is listed inside the postgres container (0.42.1). |
| `tests/test_docs_are_current.py` | The documentation guards. |
| `tests/test_docs_center.py` | The VEYRS Docs Center (`site/build.py`, served as the docs site). |
| `tests/test_docs_diagrams.py` | Every Mermaid diagram in docs/ has its pre-rendered SVG. |
| `tests/test_docs_reference_is_current.py` | The generated reference must describe the code it was generated from. |
| `tests/test_docs_worked_example.py` | The worked example in DOCKER_COMPOSE_MANUAL.md §5.D stays true to the files. |
| `tests/test_epss_retention.py` | EPSS history retention (0.33.2). |
| `tests/test_executable_bits.py` | Scripts operators run as ./name keep their executable bit (0.39.1). |
| `tests/test_export_binary_guard.py` | public-export.sh binary guard on a host whose file(1) predates woff2 (0.42.1). |
| `tests/test_fix_api.py` | Regression tests for the api audit-fix round (TD-03/04/06/20/22/23/24/30/47/48/50/51/53/56/62/63, R-03/04/09/17). |
| `tests/test_fix_auth.py` | 0.41.0 audit fix round, workstream `auth`: one regression test per item. |
| `tests/test_fix_deploy.py` | Guards for the deployment fixes of the 0.41.0 audit round. |
| `tests/test_fix_deps.py` | R-01: python-jose was replaced by PyJWT; the verification rules must not have loosened. |
| `tests/test_fix_ingest.py` | 0.41.0 ingest fix round: regression tests, one block per audit item. |
| `tests/test_fix_sla.py` | Audit fix round 0.41.0, workstream `sla`: escalation, notifications, tick, retention. |
| `tests/test_installer_dry_run_guard.py` | install.sh: --dry-run must survive a host where nothing is installed yet. |
| `tests/test_installer_offline_packages.py` | install.sh step 1 on a host with no reachable repositories (0.42.1). |
| `tests/test_installer_timers.py` | 0.35.3: a native install refreshes its intelligence. |
| `tests/test_ip_guard_survives_export.py` | scripts/ip-guard.sh must keep working after public-export.sh (0.42.1). |
| `tests/test_login_error_message.py` | A failed sign-in stops presenting itself as an expired session. |
| `tests/test_nvd_rejects.py` | One record the database refuses must not stop the NVD feed (0.32.5). |
| `tests/test_phase10_hardening.py` | Phase 10: production hardening. |
| `tests/test_phase15_api.py` | Phase 15: the REST surface for engagements, endpoints and risk acceptance. |
| `tests/test_phase15_parsers.py` | Phase 15: the modern parser catalogue. |
| `tests/test_phase15_unified_ingest.py` | Phase 15: the unified ingestion core. |
| `tests/test_phase16_agents.py` | Phase 16: execution agents. |
| `tests/test_phase16_runner.py` | Phase 16: the reference agent runner's safety-critical logic. |
| `tests/test_phase17_itsm_inbound.py` | Phase 17: inbound ITSM events (the return leg of the sync). |
| `tests/test_phase18_hardening.py` | Phase 18: four defects found by running VEYRS against itself. |
| `tests/test_phase19_coverage.py` | Phase 19 - a scan that saw nothing is not a scan that found nothing. |
| `tests/test_phase20_artifact_identity.py` | Phase 20: a container image reference is not a host:port. |
| `tests/test_phase21_inventory_correlation.py` | Phase 21: intelligence that arrives on its own, and inventory it can match. |
| `tests/test_phase24_dependencies.py` | Phase 24 - the dependency set is declared, and the declaration is true. |
| `tests/test_phase24_mfa.py` | Phase 24 - MFA is a control, not a checkbox. |
| `tests/test_phase25_cwe_catalog.py` | Phase 25: the dashboard's Name column, and the XML guard that never ran. |
| `tests/test_phase26_scope.py` | Phase 26b - team segregation: a scoped identity sees its teams and no more. |
| `tests/test_phase26_team_ownership.py` | Phase 26 - assets and findings divide by team, and the division is usable. |
| `tests/test_phase27_team_dashboard.py` | Phase 27 - the dashboards can be read one team at a time. |
| `tests/test_phase28_sla_scope.py` | Phase 28 - the SLA endpoints stop answering with the estate. |
| `tests/test_phase2_core.py` | Phase 2 - core platform: auth, RBAC, tenancy, audit. |
| `tests/test_phase30_scanner_page.py` | Phase 30 - the scanner stops being invisible, and its version stops being line noise. |
| `tests/test_phase31_console_wiring.py` | Phase 31 - a missing element must not blank the console. |
| `tests/test_phase32_nav_collapsed.py` | Phase 32 - the sidebar starts collapsed. |
| `tests/test_phase33_scanner_connectors.py` | Phase 33 - pulling from a scanner instead of waiting to be uploaded to. |
| `tests/test_phase34_inventory_and_scanning.py` | Phase 34 - the estate's inventory arrives with the scan, and scanning can stop. |
| `tests/test_phase35_operability.py` | Phase 35 - the console stops being a data model, and three things stop lying. |
| `tests/test_phase36_disposition.py` | Phase 36 - the disposition half: triage, saved views, digest, palette. |
| `tests/test_phase37_estate_lens.py` | Phase 37: intelligence browsing scoped to the software this estate runs. |
| `tests/test_phase38_dashboard_preference.py` | Phase 38 - the dashboard scope stops being a per-tab accident. |
| `tests/test_phase39_scanning_nav.py` | Phase 39 - an ingest-only deployment stops advertising a scanner. |
| `tests/test_phase3_intel.py` | Phase 3 (part 2): version matching, intelligence ingestion, correlation, SLA. |
| `tests/test_phase3_risk.py` | Phase 3 - the risk engine. |
| `tests/test_phase40_asset_sources.py` | Phase 40 -- external asset sources: CMDB export, generic JSON API, NetBox. |
| `tests/test_phase41_directory_auth.py` | Phase 41 - a second login identifier, and a directory to check it against. |
| `tests/test_phase42_console_screens.py` | Source-level guardrails for the two new Administration screens. |
| `tests/test_phase42_netbox_and_team_import.py` | Phase 42 -- NetBox that a tenant can shape, and teams that come from somewhere. |
| `tests/test_phase43_jira.py` | Phase 43 -- the Jira connector nobody could configure, and its missing monitoring leg. |
| `tests/test_phase44_confluence.py` | Phase 44 -- publishing VEYRS runbooks into Confluence. |
| `tests/test_phase45_ticketing_mode.py` | Phase 45 -- internal queue or external ITSM, and the relation that replaces the Tickets section. |
| `tests/test_phase46_risk_register.py` | Phase 46 -- the risk register, its RACI, and the switch that removes it. |
| `tests/test_phase47_risk_matrix.py` | Phase 47 -- the dialog that explains the 5x5, and the ladder it must not copy. |
| `tests/test_phase48_secret_vault.py` | Phase 48 - stored credentials in an external vault (HashiCorp Vault / OpenBao KV v2). |
| `tests/test_phase49_fix_plan.py` | Phase 49 - the fix plan: which version fixes this, and how hard is getting there. |
| `tests/test_phase4_itsm.py` | Phase 4: ticketing, ITIL lifecycle, workflow engine, notifications. |
| `tests/test_phase50_report_builder.py` | Phase 50 - the report builder: ad-hoc reports that cannot escape authorization. |
| `tests/test_phase51_attribution.py` | Phase 51 - "why did this finding change?": attribution of closes and reopens. |
| `tests/test_phase52_release_signing.py` | Phase 52 -- signed releases. |
| `tests/test_phase52_updates.py` | Phase 52 -- the in-product update check and the privileged self-update. |
| `tests/test_phase53_system_inventory.py` | Phase 53 -- Installed software and Network access (Administration). |
| `tests/test_phase54_mfa_methods.py` | Phase 54 -- two-factor by e-mail, by Telegram, and recovery codes. |
| `tests/test_phase55_local_update.py` | Phase 55 -- software update from a LOCAL copy (upload or a mounted directory). |
| `tests/test_phase56_platform_admin.py` | Phase 56 (0.34.1) -- somebody can open the installation-wide pages. |
| `tests/test_phase57_radius.py` | Phase 57 -- RADIUS sign-in (AAA) with the server's own second factor. |
| `tests/test_phase58_oidc.py` | Phase 58 -- single sign-on (OpenID Connect), configurable and off by default. |
| `tests/test_phase59_cve_exposure.py` | 0.35.1: the "Affecting you" lens and the CVE page's affected-assets table. |
| `tests/test_phase5_intel_docs.py` | Phase 5: document intelligence, threat feeds, knowledge base, search. |
| `tests/test_phase6_ai.py` | Phase 6: AI gateway, guardrails, NL search. |
| `tests/test_phase7_compliance.py` | Phase 7: compliance engine. |
| `tests/test_phase8_integrations.py` | Phase 8: scanner importers and ITSM connectors. |
| `tests/test_phase9_reporting.py` | Phase 9: analytics, dashboards and report exports. |
| `tests/test_platform_admin_role.py` | 0.42.2 -- platform administration is a role, not a host-only flag. |
| `tests/test_restore_as_superuser.py` | 0.35.3: scripts/restore.sh restores as a superuser, never as the app role. |
| `tests/test_schema_reconcile.py` | The reconciler must be able to build every invariant the models declare. |
| `tests/test_schema_steps.py` | Every schema step is idempotent: init-db runs all of them on every call. |
| `tests/test_secret_rekey.py` | Rotating VEYRS_ENCRYPTION_KEY without stranding a stored credential. |
| `tests/test_setup_docker_env_upgrade.py` | veyrs-setup.sh: updating a Docker install whose veyrs.env predates a secret (0.42.1). |
| `tests/test_site_i18n.py` | The product site in five languages, and the links between its pages. |
| `tests/test_site_render.py` | The site renderer and the product site's manual pages. |
| `tests/test_sync_intel_script.py` | scripts/sync-intel.sh runs the feeds that `veyrs intel-due` says are due. |
| `tests/test_trust_store.py` | 0.40.0 -- TLS trust store: the CAs this installation accepts when it connects out. |
| `tests/test_web_tls.py` | 0.42.0 -- the certificate VEYRS serves: request, sign elsewhere, attach, install. |
| `tests/test_widen_columns.py` | `sync_columns` may widen a VARCHAR and must not retype anything else. |
| `tests/test_write_paths.py` | Every audited write path, exercised over HTTP. |

### Migrations placeholder

1 files.

| File | Purpose |
|---|---|
| `migrations/README.md` | migrations |

### Release signing

1 files.

| File | Purpose |
|---|---|
| `release/allowed_signers` |  |

### Runtime directory

1 files.

| File | Purpose |
|---|---|
| `var/.gitkeep` |  |

### Repository root

12 files.

| File | Purpose |
|---|---|
| `.coveragerc` |  |
| `.dockerignore` |  |
| `.env.example` |  |
| `.gitignore` |  |
| `INSTALL.md` | Installing VEYRS |
| `LICENSE` |  |
| `README.md` | VEYRS |
| `install.sh` | VEYRS — full installation script. |
| `pyproject.toml` | Direct dependencies ONLY. Everything here is imported by VEYRS's own code, or |
| `pytest.ini` | The backend package lives in backend/, tests at the repo root. Declaring the |
| `requirements.txt` |  |
| `veyrs-setup.sh` | veyrs-setup.sh — guided installer for VEYRS (native or Docker). |
