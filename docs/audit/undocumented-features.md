---
title: Undocumented, incomplete and obsolete features
purpose: List the features found in the code that had no documentation before the 0.39.x documentation work and where they are documented now, and every feature that is incomplete, unwired, dead or obsolete.
scope: Backend, console, scripts and units of release 0.39.1; defects of working features are in risks-and-debt.md and statement conflicts in inconsistencies.md.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/models/workflow.py, backend/veyrs/services/workflow.py, backend/veyrs/services/notifications.py, backend/veyrs/services/search.py, backend/veyrs/services/sla.py, backend/veyrs/api/v1/agents.py, backend/veyrs/services/engagements.py, backend/veyrs/models/ai.py, backend/veyrs/cli.py]
related: [audit/README.md, audit/inconsistencies.md, audit/risks-and-debt.md, functional/README.md, integrations/README.md]
---

# Undocumented, incomplete and obsolete features

"Before" means the legacy documents as they stood at 0.35.1 to 0.39.0: `API.md`, `ARCHITECTURE.md`, `INTEGRATIONS.md`, the manuals and the guides. A feature counts as undocumented if none of them described it; this is taken from the domain agents' coverage checks. The Status column uses the documentation vocabulary.

## 1. Features that had no documentation before this work

| Feature | Code | Status | Documented now in |
|---|---|---|---|
| Execution agents: enrolment, token rotation, tool policy, job queue, data plane (claim, lease, events, result, fail, inventory), maintenance reap (22 routes) | `api/v1/agents.py`, `services/agents.py`, `integrations/veyrs-agent/veyrs_agent.py` | Implemented | [functional/agents.md](../functional/agents.md), [integrations/agent.md](../integrations/agent.md), [architecture/sequences.md](../architecture/sequences.md) |
| Asset sources (CMDB): drivers `file`, `http_json` and `netbox`; records, compare, promote, runs | `api/v1/cmdb.py`, `services/cmdb.py` | Implemented | [functional/cmdb-asset-sources.md](../functional/cmdb-asset-sources.md), [integrations/itsm-and-webhooks.md](../integrations/itsm-and-webhooks.md) |
| Engagements, scan tests, endpoints, dedupe registry, formal risk acceptances (approve, reject, revoke, expire) | `api/v1/engagements.py`, `services/engagements.py`, `services/dedupe.py` | Implemented | [functional/engagements-scan-import.md](../functional/engagements-scan-import.md), [integrations/scanners.md](../integrations/scanners.md) |
| Risk register: risks that are not findings, RACI, links, events, the on/off switch | `api/v1/risk_register.py`, `services/risk_register.py`, `services/risk_register_mode.py` | Implemented | [functional/risk-register.md](../functional/risk-register.md) |
| Report builder (catalogue, ad-hoc run and export, saved queries) and saved views | `api/v1/report_builder.py`, `api/v1/views.py`, `models/report_queries.py` | Implemented | [functional/dashboards-reports.md](../functional/dashboards-reports.md) |
| Workflows: triggers, conditions, six actions, built-in seeds | `services/workflow.py`, `models/workflow.py` | Partial (see section 2) | [integrations/automation.md](../integrations/automation.md), [functional/ticketing-itsm.md](../functional/ticketing-itsm.md) |
| Notification routes and digest settings | `api/v1/tickets.py`, `services/notifications.py`, `services/digest.py` | Implemented | [functional/notifications-digest.md](../functional/notifications-digest.md), [integrations/notifications.md](../integrations/notifications.md) |
| Intelligence refresh schedule (`/intel/schedule`), `veyrs intel-due`, the hourly tick design, CWE dictionary (`sync-cwe`) | `services/intel_schedule.py`, `cli.py:600,705-710`, `scripts/sync-intel.sh` | Implemented | [integrations/threat-intel.md](../integrations/threat-intel.md), [functional/threat-intelligence.md](../functional/threat-intelligence.md) |
| AI guardrail dry run (`POST /ai/scan`), team-scope refusal for AI routes, AI audit trail | `api/v1/ai.py`, `security/scope.py:98` | Implemented | [functional/ai.md](../functional/ai.md), [AI_SECURITY.md](../AI_SECURITY.md) |
| Knowledge publishing to Confluence | `api/v1/knowledge.py`, `services/docs.py` | Implemented | [functional/knowledge-search.md](../functional/knowledge-search.md) |
| "Why did this finding change?" attribution | `api/v1/attribution.py`, `services/attribution.py` | Implemented | [functional/vulnerability-management.md](../functional/vulnerability-management.md), [API.md](../API.md) |
| Fix plans and operator upgrade-path rules | `api/v1/fix_plan.py`, `services/fix_plan.py`, `models/upgrade.py` | Implemented | [functional/remediation-fix-plans.md](../functional/remediation-fix-plans.md) (the model file was named only during this audit) |
| Team import from NetBox or the directory | `api/v1/team_import.py`, `services/team_import.py` | Implemented | [functional/authentication-accounts.md](../functional/authentication-accounts.md) |
| `GET /auth/me/scope`; the `X-Agent-Token` credential; the OIDC `require_mfa_amr` option; the platform-admin dependency; inline `principal.require` in reports | `api/v1/auth.py`, `security/agent_auth.py`, `services/oidc_auth.py`, `api/v1/updates.py:26-34` | Implemented | [security/authentication.md](../security/authentication.md), [security/authorization.md](../security/authorization.md) |
| Operator commands `platform-admin`, `mfa-setup`, `mfa-reset`, `mfa-test`, `prune-epss-history`, `secrets status/migrate/rekey/gc` | `cli.py`, `services/mfa_admin.py` | Implemented | [SYSTEM_MANUAL.md](../SYSTEM_MANUAL.md), [operations/README.md](../operations/README.md), [database/README.md](../database/README.md) |
| Encryption-key rotation (`VEYRS_ENCRYPTION_KEY_PREVIOUS`, `secrets rekey`) and vault-backed secret storage | `security/secrets.py`, `security/secret_vault.py`, `services/secret_storage.py` | Implemented | [database/README.md](../database/README.md), [operations/backup-dr.md](../operations/backup-dr.md), [DOCKER_COMPOSE_MANUAL.md](../DOCKER_COMPOSE_MANUAL.md) |
| Software update: install from a local copy (chunked upload), installed-software inventory, network checklist | `services/updates.py:440-457`, `api/v1/system.py` | Implemented | [functional/updates.md](../functional/updates.md), [ADMIN_GUIDE.md](../ADMIN_GUIDE.md) |
| API operations the console never calls (engagements, formal acceptances, user edit and delete, role edit, SLA and escalation edit, knowledge revisions, connector pull and inbound secret, AI ticket draft and team suggestion) | `frontend/console/app.js` against `extract/routes.json` | Implemented (API only) | [frontend/console.md](../frontend/console.md) |
| Configure frame (0.39.0) and its icon rail, readable policy chips and ladders, the neutral criticality pill (0.39.1) | `app.js:248-290,1390-1440,4074-4132` | Implemented | [frontend/console.md](../frontend/console.md), [design/console-ui.md](../design/console-ui.md), [USER_MANUAL.md](../USER_MANUAL.md) |
| Documentation tooling: `scripts/gen-reference-docs.py`, `scripts/render-diagrams.py`, `scripts/check-docs-links.py` and their guards `tests/test_docs_reference_is_current.py`, `tests/test_docs_diagrams.py` | `scripts/` | Implemented | [testing/strategy.md](../testing/strategy.md) (added during this audit) |

## 2. Incomplete, unwired, dead or obsolete features

| Feature | Evidence | Status | What is missing |
|---|---|---|---|
| Five workflow triggers: `finding.state_changed`, `finding.risk_changed`, `intel.kev_added`, `schedule`, `manual` | Declared in `models/workflow.py:25-34` and explained to users in `TRIGGER_HELP` (`services/workflow.py:293-307`); no caller. Only `finding.created` (`correlation.py:606`), the SLA events (`sla.py:470`) and the ticket events (`api/v1/tickets.py:198,509`) fire | Partial | Emitters. Also, `ticket.created` is fired but is not an enum value, so it cannot be chosen in the builder |
| Agent lease reaping and marking silent agents offline | `reap_expired_leases` / `mark_stale_agents_offline` are called only from `POST /agents/maintenance/reap` (`api/v1/agents.py:548`) | Partial | A scheduler, timer or CLI command. Expired leases are never requeued automatically |
| Risk-acceptance expiry | `expire_due` is called only from `POST /engagements/risk-acceptances/expire` | Partial | A scheduler; acceptances never expire on their own |
| Outbound webhooks | `WebhookEndpoint` model (`models/workflow.py:152`), `sign_webhook` and `webhook_targets` (`services/notifications.py:311-330`); no route, no writer, no transport | Partial | Management API and a sender |
| `webhook` and `slack` notification channels | Offered in `ACTION_SCHEMA["notify"]` (`services/workflow.py:347-348`); `TRANSPORTS` has neither (`notifications.py:255-273`) | Planned | Transports |
| Threat sources of kind `rss`, `atom`, `json`, `misp`, `opencti` | Stored in a registry; `poll_interval_minutes` is never read; articles arrive only through `POST /intel/articles` | Partial | A poller |
| Semantic (vector) search | `VectorBackend` / `NullVectorBackend` (`services/search.py:221-259`); `DocumentChunk.embedded` is never set by a pipeline; live calls return mode `lexical` | Planned | An embedding pipeline and a vector backend |
| OCR for scanned documents | `needs_ocr` status exists; `ocr_used` is always False (`services/documents.py:361`) | Partial | OCR |
| Original document storage | `Document.storage_key` (`models/knowledge.py:136`) is never written; the uploaded bytes are discarded after text extraction | Partial | Object storage; evidence cannot be reproduced in its original form |
| Escalation ladder `notify` targets (`team`, `team_manager`, `security_manager`, `ciso`) | Recorded in `SlaEvent.details` (`services/sla.py:445-470`); no reader of `EscalationPolicy.targets` | Partial | Recipient resolution; the shipped workflow notifies the assignee only |
| SLA `triage_within_hours`, `verify_within_hours` | Columns in `models/sla.py`, read nowhere | Obsolete (dead fields) | Either wire or drop |
| Default SLA policies and risk profiles for a new tenant | `sla.seed_policies` and `risk.seed_profiles` are called only from tests; `bootstrap` and `init-db` do not call them | Partial | Seeding on organization creation. A fresh tenant has no SLA deadlines or escalation until an admin creates policies |
| Tables with no writer: `asset_groups`, `webhook_endpoints`, `notification_templates` | grep over `api/`, `services/`, `cli.py` | Partial | Management routes (tenant notification-template overrides cannot be set) |
| Per-test dedupe configuration | `ScanTest.dedupe_config` is read by the importer, but no API sets it; `ImportOptions.dedupe_config` and `allow_empty` are not form fields of `POST /integrations/imports` | Partial | API fields |
| Identical re-upload warning | `importers.previous_run_with_hash` is defined and never called | Obsolete (unused helper) | A caller |
| `agent.last_seen_at` | Assigned at `services/agents.py:1126`; not a mapped column | Obsolete (dead assignment) | Map or remove |
| AI capabilities `document_analysis`, `article_draft`, `classify_vulnerability`, `classify_product` | `AiCapability` enum (`models/ai.py:48-60`) with permissions mapped; no caller in `backend/veyrs` | Planned | Implementations |
| JWT claims `perms` and `su` | Issued; ignored for decisions (`security/deps.py`) | Obsolete | Drop, or document as informational |
| `veyrs dedupe rehash` | Referenced in `services/dedupe.py:23`; absent from `cli.py` | Planned | The command |
| `infrastructure/rls.sql` | Referenced in `models/audit.py:8-11`; absent | Obsolete reference | Remove the reference, or ship the GRANTs (risk R-05) |
| `auth_events` | Written by `audit.record_auth` (`services/audit.py:122`); no API or page reads it | Partial | A read API; sign-in failures are visible only in the database |
| Unlocking a locked account | Only a successful sign-in clears the lock (`api/v1/auth.py:549,1111`) | Partial | API, console or CLI unlock; the documented workaround is SQL |
| Removing or deactivating an organization | `organizations.deleted_at` / `is_active` exist; no route, console action or CLI | Partial | A lifecycle operation |
| Update and delete for engagements, business services, escalation policies and assignment rules; assessment statuses `draft` and `archived` | `api/v1/engagements.py`, `api/v1/assets.py`, `api/v1/policies.py`, `api/v1/compliance.py` | Partial | The missing verbs |
| Scheduled scanner-connector sync, CMDB source sync, ITSM status pull, notification dispatch | Route-triggered only; e-mail dispatch runs from the digest tick | Partial | Schedulers (risk TD-08) |
| Retention for audit, auth, AI audit, finding events, risk history, SLA events, notifications, workflow and feed runs, import and agent events, threat articles, refresh tokens | Only `epss_history` has a prune (`cli.py` `prune-epss-history`) | Partial | A retention policy (risk TD-27) |
| Self-update (`veyrs-updater.path/.service`, `scripts/veyrs-updater.sh`) | Native installs only; not installed on either reference node, which are git checkouts | Implemented, not deployed | Exercise on a release install |
| Backup timers (`veyrs-pgdump`, `veyrs-pgverify`, `veyrs-replcheck`) and the agent unit | Shipped under `infrastructure/backup/` and `integrations/veyrs-agent/`; not installed by `install.sh` | Partial | Installer support |
| `/metrics` scrape path | Not proxied by the generated vhost or the container | Implemented | A documented scrape route (direct to the API is documented) |
| `integration` pytest marker | Declared in `pytest.ini`, never used | Obsolete | Use or drop |
| Mutation testing and headless-browser console verification | Manual procedures; no script in the repository | Partial | Scripts |
| Console pills `st-queued`, `st-cancelled` and class `err` | Emitted (`app.js:2112-2116,6210`); no CSS rule | Partial | Styles |
| `veyrs-logo-black.png` and the token file's brand primitives (`--veyrs-blue`, `--veyrs-electric`, the type-scale steps) | Not used by any surface | Obsolete (unused assets) | Remove or use |
| `#/integrations?tab=itsm` | Linked twice from the console; not a tab key (falls through to `connectors`) | Partial | Correct the link |
| `MemoryStore` in `security/mfa_delivery.py` | Used by tests only | Implemented (test helper) | Nothing |
