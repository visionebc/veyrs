---
title: Glossary
purpose: Define every domain and technical term VEYRS uses, as VEYRS uses it, and say which model or module implements it.
scope: Terms that appear across the documentation and the console; it does not list every column or endpoint (see the generated schema and API references).
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/models/vulnerability.py, backend/veyrs/models/assets.py, backend/veyrs/models/tenancy.py, backend/veyrs/engines/risk.py, backend/veyrs/services/dedupe.py, backend/veyrs/services/engagements.py, backend/veyrs/security/deps.py, backend/veyrs/services/ai/gateway.py]
related: [architecture/overview.md, executive/overview.md, DATABASE_SCHEMA.md, reference/permissions.md]
---

# Glossary

Each entry says what the word means **in VEYRS**, which can be narrower than the industry meaning. The "Maps to" column names the SQLAlchemy model (table in parentheses) or the module that owns the concept. Table and column detail is in [DATABASE_SCHEMA.md](../DATABASE_SCHEMA.md); permissions are in [permissions](permissions.md).

## Tenancy and identity

| Term | Meaning in VEYRS | Maps to |
|---|---|---|
| Organization (tenant) | The unit of data ownership. Every customer-owned row carries `organization_id`. Called "tenant" in code comments and "organization" in the API. | `Organization` (`organizations`), `TenantMixin` in `models/base.py` |
| RLS (row level security) | The PostgreSQL feature VEYRS uses as the second tenant barrier. 72 of 89 tables are `FORCE`d with policy `veyrs_tenant_isolation`, bound to the session variable `veyrs.current_org`. | `cli.init_db`, `db.set_tenant`; [ADR 0001](../ADRs/0001-postgres-rls.md) |
| Global table | A table shared by all tenants and not under RLS: CVE, CWE, CPE, EPSS, KEV, vendor/product catalogue, compliance framework library. | `GLOBAL_TABLES` in `models/base.py` |
| Credential-keyed table | A table that authentication must read before a tenant is known (`users`, `refresh_tokens`, `api_keys`, `exec_agents`). Its policy is permissive only while no tenant is bound. | `RLS_TABLES_PREAUTH` in `cli.py` |
| Tenant binding | Setting `veyrs.current_org` for a database session so RLS filters apply. Transaction-local, re-applied on every new transaction. | `db.set_tenant`, `db._rebind_tenant` |
| Principal | The authenticated caller of a user-facing request: user id, organization id, expanded permission set, `kind` (`user` or `apikey`), and team scope. Never an agent. | `security.deps.Principal` |
| Permission | A `resource:action` string such as `finding:read`. 116 exist; wildcards in a role are expanded at request time. | `security/permissions.py` |
| Role | A named set of permissions. Ten built-in roles (`org-admin`, `security-manager`, `security-engineer`, `team-lead`, `asset-owner`, `compliance-officer`, `executive`, `auditor`, `service-account`, `read-only`) plus tenant-defined ones. | `Role` (`roles`), `UserRole` (`user_roles`) |
| Platform administrator | A user with `is_superuser` true. Reaches installation-wide pages and any tenant's data through the API. Granted only from the host with `veyrs platform-admin`. | `User.is_superuser`, `cli.platform_admin` |
| Team | A group that owns assets and findings ("whose queue is this"). Membership alone never widens visibility. | `Team`, `TeamMember` |
| Team scope | The narrowing of a principal to the teams named in its role grants. A grant with no team means estate-wide. Unowned rows are invisible to a scoped principal unless the organization opts in. | `security/scope.py` |
| API key | A long-lived credential `veyrs_<prefix>_<secret>` sent in `X-API-Key`. Only the Argon2 hash of the secret is stored. Permissions are the key's `scopes`. Never team-scoped. | `ApiKey` (`api_keys`), `security/auth.py` |
| Access token | A short-lived HS256 JWT (default 30 minutes) carrying subject, organization and audience `veyrs:access`. Permissions are re-read from the database on every request. | `security.auth.create_access_token` |
| Refresh token | An opaque, rotating token (default 14 days). Reuse of a rotated token revokes its whole family. | `RefreshToken` (`refresh_tokens`) |
| MFA | Second factor at login: TOTP (RFC 6238, implemented on the standard library), a code by e-mail or Telegram, or a RADIUS challenge. Recovery codes exist for TOTP. | `security/mfa.py`, `security/mfa_delivery.py`, `services/radius_auth.py` |
| Directory / SSO | Optional external authentication per organization: LDAP/Active Directory, RADIUS, OpenID Connect. | `services/ldap_auth.py`, `radius_auth.py`, `oidc_auth.py` |
| Correlation ID | A UUID attached to each request (`X-Correlation-ID`), echoed in the response, logs and audit rows. | `observability.RequestContextMiddleware` |
| Audit log | Append-only record of changes (`audit_log`), sign-in events (`auth_events`) and AI calls (`ai_audit_log`). | `models/audit.py`, `services/audit.py` |

## Agents and scanning

| Term | Meaning in VEYRS | Maps to |
|---|---|---|
| Execution agent | A remote runner that polls VEYRS, runs a locally allow-listed scanner, and returns the output. It has its own credential type and can call only `/agents/self/*`. It is **not** a principal. | `ExecAgent` (`exec_agents`), `security/agent_auth.py`, `integrations/veyrs-agent/veyrs_agent.py` |
| Agent token | `veyrsagent_<prefix>_<secret>` sent in `X-Agent-Token`. A distinct scheme so it is never accepted where a user credential is expected. | `security.auth.new_agent_token` |
| Job | One unit of scan work (`tool`, `target`, `profile`, `params`). States: `queued`, `leased`, `running`, `succeeded`, `failed`, `cancelled`, `expired`. The queue is a table, claimed with `FOR UPDATE SKIP LOCKED`. | `AgentJob` (`agent_jobs`), `services/agents.py` |
| Lease | The time-limited right of one agent to write to one job, proven by a random `lease_token` returned once at claim. An expired lease is requeued or, out of attempts, marked `expired` (not `failed`). | `services.agents.claim_next`, `reap_expired_leases` |
| Allowlist | The set of targets an agent may scan. Empty means nothing is scannable. Enforced on the server and again by the agent. | `ExecAgent.allowed_targets`, `services.agents.authorise_target` |
| Active scanning | The per-organization switch that decides whether VEYRS may originate any probe. | `services/scanning.py` |
| Scanner connector | A stored configuration for pulling results from a scanner's own API (Nessus, Tenable.io, Tenable.sc). | `ScannerConnector`, `services/scanners.py` |

## Vulnerability intelligence

| Term | Meaning in VEYRS | Maps to |
|---|---|---|
| CVE | A published vulnerability record from NVD. Global, shared by all tenants. | `Cve` (`cve`) |
| CWE | A weakness class from the MITRE catalogue, used to name what CVEs have in common. | `Cwe` (`cwe`) |
| CPE | A platform identifier string (`cpe:2.3:...`) used to match a CVE to installed software. | `Cpe`, `CveCpeMatch` (`cve_cpe_match`) |
| Vendor, product, product version | The software catalogue that connects a CPE to what an asset has installed. | `Vendor`, `Product`, `ProductVersion` |
| CVSS | Common Vulnerability Scoring System: a severity score computed from a vector string. VEYRS computes v2, v3.0, v3.1 and v4.0 itself and shows the metric breakdown. | `engines/cvss/` |
| CVSS v2 / v3 / v4 | Three incompatible generations. v3.0 and v3.1 differ in rounding and are implemented separately. v4.0 uses a MacroVector lookup with severity-distance interpolation and half-up rounding. | `engines/cvss/v2.py`, `v3.py`, `v4.py` |
| MacroVector | In CVSS v4, one of the equivalence classes a vector maps to before interpolation. | `engines/cvss/v4_tables.py` |
| EPSS | Exploit Prediction Scoring System: the daily probability (0 to 1) that a CVE is exploited. Enters the risk score as likelihood, never as severity. | `EpssScore`, `EpssHistory`, `services/intelligence.ingest_epss` |
| KEV | CISA Known Exploited Vulnerabilities catalogue. Membership applies a floor to the risk score; it is not averaged in. | `KevEntry` (`kev_entries`) |
| Feed run | One execution of an intelligence feed (`nvd`, `epss`, `kev`, `cwe`) with its watermark and result. Freshness is derived from successful runs. | `FeedRun` (`feed_runs`), `intel/feeds.py` |
| Watermark | The last NVD `lastModified` boundary VEYRS asked for. Incremental pulls resume from it. | `services.intelligence.feed_run` |
| Tick | An hourly invocation whose only job is to ask "what is due?". The cadence lives in `organizations.settings.intel_schedule` and `.digest`, not in a unit file. | `veyrs-intel-sync.timer`, `veyrs-digest.timer`, `services/intel_schedule.py` |
| Exposure (of a CVE) | A CVE is *exposed* when it affects software installed on an asset of the tenant. Not the same as asset exposure below. | `services.intelligence.exposed_cve_ids` |

## Assets and context

| Term | Meaning in VEYRS | Maps to |
|---|---|---|
| Asset | Anything that can be vulnerable: server, VM, container, application, website, API, cloud resource, device, and so on (18 types). | `Asset` (`assets`), `AssetType` |
| Installation | One piece of software on one asset, with its version. The unit CVE correlation matches against. | `AssetProduct` (`asset_products`) |
| Inventory | The set of installations. Loaded from a scanner export, an agent sweep, a CMDB source or `veyrs import-inventory`. | `services/inventory.py`, `services/software_inventory.py`, `services/cmdb.py` |
| Criticality | How much the business depends on an asset: `critical`, `high`, `medium`, `low` (weights 1.0 to 0.25). | `Criticality`, `CRITICALITY_WEIGHT` |
| Data classification | What the asset holds: `restricted`, `confidential`, `internal`, `public`. Also the vocabulary of the AI classification ceiling. | `DataClassification` |
| Exposure (of an asset) | How reachable the asset is: `internet`, `partner`, `internal`, `isolated`. | `Exposure`, `EXPOSURE_WEIGHT` |
| Environment | `production`, `dr`, `staging`, `test`, `development`. | `Environment` |
| Business service | A named service with a criticality and optional revenue per hour that assets support. | `BusinessService` (`business_services`) |
| Compensating control | A documented mitigation on an asset (`waf`, `ips`, `edr`, `network_segmentation`, `mfa`, `not_reachable`, `vendor_mitigation_applied`, `config_workaround`). Reduces Exposure Risk only. | `CONTROL_CREDIT` in `engines/risk.py` |
| Asset source | An external system of record for assets (for example a CMDB or NetBox) that VEYRS reads and compares. | `AssetSource`, `services/cmdb.py` |

## Findings and risk

| Term | Meaning in VEYRS | Maps to |
|---|---|---|
| Vulnerability (tenant) | A tenant's record of a weakness, optionally backed by a CVE. Distinct from the global `Cve`. | `Vulnerability` (`vulnerabilities`) |
| Finding | One vulnerability on one asset (plus port, protocol, path where relevant). The unit of work, scoring, SLA and ticketing. | `Finding` (`findings`) |
| Finding state | `new`, `triaged`, `risk_assessed`, `assigned`, `in_progress`, `mitigation`, `remediated`, `verification`, `verified`, `closed`, plus `false_positive`, `duplicate`, `accepted_risk`, `exception`, `deferred`. Transitions are data, not `if` chains. | `FindingState`, `ALLOWED_TRANSITIONS` in `models/vulnerability.py` |
| Dedupe key | A 64-character identity for a finding, so a rescan updates instead of duplicating. Computed by one of four algorithms per scanner. | `Finding.dedupe_key`, `services/dedupe.py` |
| Dedupe algorithm | `legacy` (hash of org, asset, vuln reference, port, protocol, path; default for existing scanners), `unique_id_from_tool`, `hash_code` (configurable field list), `unique_id_or_hash_code`. | `services.dedupe.ALGORITHMS` |
| Regression | A finding seen again after `remediated`, `verified` or `closed`. It is reopened, not duplicated, and its SLA clock restarts. | `services.correlation.REOPENABLE_STATES` |
| Correlation | Matching CVEs to installations and producing or updating findings; also the post-ingest pipeline score, assign, SLA, auto-ticket, workflows. | `services/correlation.py` |
| Risk score | VEYRS's 0 to 100 priority number for a finding: four sub-scores, a weighted mean, then policy adjustments. Stored with an explanation of every factor. | `engines/risk.py`, `Finding.risk_score`, `risk_explanation` |
| Sub-scores | Technical (how bad is the flaw), Exploitability (how likely to be used), Business (what it threatens), Exposure (how reachable). | `technical_risk`, `exploitability_risk`, `business_risk`, `exposure_risk` |
| Risk level | `critical` (>= 90), `high` (>= 70), `medium` (>= 40), `low` (>= 10), `informational`. | `LEVEL_BANDS` |
| Risk profile | A weight vector plus options stored as a row. Built in: `balanced` (default), `technical-security`, `executive-risk`, `internet-exposure`, `compliance`. Tenants add their own. | `RiskProfile`, `BUILTIN_PROFILES` |
| Floor | A minimum score: `kev_floor` for KEV, `internet_kev_floor` for KEV on an internet-facing asset, `active_exploitation_floor`. | `DEFAULT_OPTIONS` in `engines/risk.py` |
| Age penalty | Points added to an open finding per full 30 days since detection, doubled once past its SLA, capped. | `age_penalty_per_30d`, `age_penalty_cap` |
| Risk acceptance | An approved, expiring decision to live with a finding. Expiry returns it to the queue. | `RiskAcceptance`, `services/engagements.py` |
| Risk register | An organization-level register of risks with RACI seats and links, separate from findings. Can be switched off per tenant. | `RiskEntry` (`risk_register`), `services/risk_register.py` |
| Fix plan | For a product, the version that fixes everything open on it and how far away that is. | `services/fix_plan.py`, `UpgradePathRule` |

## Imports, engagements and reconciliation

| Term | Meaning in VEYRS | Maps to |
|---|---|---|
| Import run | One ingestion of a scanner export, with counts and reject reasons, whether it succeeded or failed. | `ImportRun` (`import_runs`), `services/importers/__init__.py` |
| Parser | Turns a vendor export into canonical `ScanRecord` objects. Network scanners (Nessus, Greenbone/OpenVAS, Qualys), CSV, generic JSON, and modern SAST/SCA/DAST/IaC/cloud formats (SARIF, Trivy, Grype, Semgrep, Bandit, Gitleaks, Checkov, Nuclei, ZAP, npm audit, pip-audit, Dependabot, Prowler). | `services/importers/parsers.py`, `parsers_modern.py` |
| Engagement | A scoped body of testing work of type `ci_cd`, `interactive` or `scheduled` (the DefectDojo model). Every import belongs to one. | `Engagement` (`engagements`) |
| Scan test | One scanner's participation in an engagement. The boundary that makes reconciliation sound. | `ScanTest` (`scan_tests`) |
| Sighting | A record that a given test reported a given finding, with `status` `present` or `absent` and a `consecutive_absences` counter. | `TestFinding` (`test_findings`) |
| Stale candidate | A finding that the test used to report and did not this time. Counted and reported, closed only past the threshold. | `ImportRun.stale_candidates` |
| Absence threshold | Consecutive runs a finding may be missing before it is moved to `remediated`: 1 for `ci_cd`, 2 for `scheduled`, 0 (never) for `interactive`. Closure by absence is recorded as evidence `absence`, not as a verified fix. | `DEFAULT_ABSENCE_THRESHOLD` in `services/engagements.py` |
| Endpoint | A parsed network or URL location a finding can attach to. | `Endpoint`, `services/endpoints.py` |
| Coverage attestation | Evidence from an agent that a scan actually covered its target, required before an empty result may close findings. | `services.agents._coverage` |

## Workflow, SLA and tickets

| Term | Meaning in VEYRS | Maps to |
|---|---|---|
| SLA policy | Conditions (severity, CVSS, EPSS, KEV, criticality, exposure) mapped to a duration. Evaluated in `priority` order; the first match wins; otherwise the default, otherwise the loosest. | `SlaPolicy`, `services.sla.resolve_policy` |
| SLA event | `warned`, `breached` or `escalated`, recorded per finding. | `SlaEvent` (`sla_events`) |
| Escalation policy | An ordered list of (hours, target) steps. `sla.breached`, `sla.escalated` and `finding.kev_detected` notifications cannot be muted by users. | `EscalationPolicy`, `UNMUTABLE_EVENTS` |
| Ticket | Remediation or ITIL work item (`incident`, `problem`, `change`, `service_request`, `remediation`, `exception`) with its own state graph. | `Ticket` (`tickets`), `services/ticketing.py` |
| Ticketing mode | Which system is authoritative for remediation work: VEYRS's own queue or an external ITSM. | `services/ticketing_mode.py`, `services/remediation.py` |
| ITSM connector | A configured link to ServiceNow, Jira Service Management or a generic webhook; inbound events are applied idempotently. | `ItsmConnector`, `services/itsm.py`, `itsm_inbound.py` |
| Auto-ticket | A policy that opens remediation tickets without a human, with a per-run budget. | `services/autoticket.py` |
| Workflow | A definition: trigger, conditions and an ordered list of steps. Each step names an action from a closed registry (`create_ticket`, `notify`, `transition_finding`, `tag_asset`, `set_priority`, `comment`). No expression language. | `WorkflowDefinition`, `WorkflowRun`, `services/workflow.py` |
| Digest | A daily summary per recipient (channels `in_app` and `email` by default), delivered when the organization's configured hour comes up; off by default. | `services/digest.py` |

## AI

| Term | Meaning in VEYRS | Maps to |
|---|---|---|
| AI gateway | The single function (`invoke`) through which any model is reached. Applies policy, sanitises, selects a provider, calls or degrades, scans the output, audits. | `services/ai/gateway.py`; [ADR 0003](../ADRs/0003-ai-gateway.md) |
| Capability | A named AI feature (13 exist) bound to the permission the caller must already hold. | `AiCapability`, `CAPABILITY_PERMISSION` in `models/ai.py` |
| Provider | A configured model endpoint, flagged internal or external by an administrator. Kinds: OpenAI-compatible, Anthropic, Gemini, Ollama, deterministic. | `AiProvider`, `services/ai/providers.py` |
| AI policy | Per-organization switches, allow-lists, classification ceilings (external default `public`), redaction flags, prompt-size and daily call limits. Absent row means the restrictive defaults. | `AiPolicy` (`ai_policies`) |
| Degraded | A result produced by the deterministic provider because no model was eligible or the call failed. Always labelled. | `AiResult.degraded` |
| Guardrails | Secret, PII, infrastructure-address and prompt-injection detection on input, and a secret scan on output. | `services/ai/guardrails.py` |
| Closed query grammar | The fixed field, operator and value set a model's structured query is validated against before VEYRS compiles it. Published at `GET /api/v1/ai/search/grammar`. | `services/ai/nlquery.py`; [ADR 0004](../ADRs/0004-closed-query-grammar.md) |

## Compliance

| Term | Meaning in VEYRS | Maps to |
|---|---|---|
| Framework / control | Global reference data (NIST CSF 2.0, CIS Controls v8, ISO 27001:2022, ISO 27002:2022 as identifiers and short titles). | `ComplianceFramework`, `ComplianceControl`, `data/frameworks.py` |
| Implementation | A tenant's claimed status for a control. | `ControlImplementation` |
| Automation signal | A computed measure (12 exist) that can lift a control to `partial` at most. Reaching `implemented` needs a human claim. | `AUTOMATED_SIGNALS` in `services/compliance.py` |
| Evidence, assessment | Stored proof and a frozen snapshot of coverage at a point in time. | `Evidence`, `ComplianceAssessment` |
| `is_partial` | A framework flag derived from imported versus official control count. It cannot be switched off by configuration. | [ADR 0005](../ADRs/0005-partial-catalogues.md) |
| Crosswalk | An editorial mapping between frameworks, labelled as VEYRS's own. | `CROSSWALK` in `data/frameworks.py` |

## Platform and operations

| Term | Meaning in VEYRS | Maps to |
|---|---|---|
| Console | The operator web UI: static HTML, one JavaScript file with hash routing, no build step. | `frontend/console/` |
| Docs Center | The static documentation site generated from `docs/` by a standard-library script. | `site/build.py` |
| Product site | The static public product site and user manual. | `site/web/build_web.py` |
| Singleton host | The one application node that runs the agent and the intel timer, so work is not done twice. | [ADR 0007](../ADRs/0007-stateless-app-nodes.md) |
| Saved view | A stored query that is replayed through the entity's own scoped list endpoint, never widened. | `SavedView`, `services/views.py` |
| Report builder | Ad-hoc tabular reports from a curated catalogue, never from SQL. | `ReportQuery`, `services/report_builder.py` |
| Secret backend | Where stored third-party credentials live: `local` (Fernet in the database), `mirror` (both) or `vault` (external HashiCorp Vault or OpenBao KV v2 only). | `VEYRS_SECRET_BACKEND`, `security/secret_vault.py` |
| Fernet | The symmetric envelope (cryptography library) used to encrypt secrets at rest under `VEYRS_ENCRYPTION_KEY`. | `security/secrets.py` |
| `sync-schema` | The additive schema reconciler: adds columns, indexes and foreign keys the models have and the database lacks; widens VARCHAR/TEXT; never drops or narrows. VEYRS has no Alembic migrations. | `cli.sync_columns` |
