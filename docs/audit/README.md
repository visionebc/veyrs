---
title: Documentation audit report
purpose: Record how the VEYRS documentation set was audited against the 0.39.1 code, what was found and fixed, what coverage was measured, and what could not be verified.
scope: Every hand-written document under docs/ (100 files) and the 60 Mermaid diagrams; the generated references are audited only for coverage, and the code itself was not changed.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs, frontend/console/app.js, frontend/console/console.css, scripts/gen-reference-docs.py, scripts/public-export.sh, install.sh, tests]
related: [audit/inconsistencies.md, audit/undocumented-features.md, audit/risks-and-debt.md, reference/coverage.md, reference/traceability.md, security/risk-register.md, testing/known-issues.md]
---

# Documentation audit report

## 0.41.0 fix round (2026-11-17)

The registers produced by this audit were worked through in one fix round on top of 0.40.0. Status of every row is in the registers themselves; the totals are:

| Register | Fixed | Partially fixed | Accepted | Not a bug | Open |
|---|---|---|---|---|---|
| [Risks and debt](risks-and-debt.md) (TD-01 to TD-64) | 53 | 5 | 1 | 0 | 5 |
| [Security risk register](../security/risk-register.md) (R-01 to R-28) | 22 | 4 | 1 | 1 | 0 |
| **Both** | **75** | **9** | **2** | **1** | **5** |

- Open items are owner decisions: TD-11, TD-12, TD-39, TD-59, TD-61.
- The code-comment inconsistencies (IC-C01 to IC-C34 in [inconsistencies](inconsistencies.md)) are corrected or closed except IC-C23 (open: link shape of notification URLs) and IC-C29 (partial: deployment-specific names, TD-31).
- What changed and what an operator must run on upgrade: [CHANGELOG](../CHANGELOG.md), entry 0.41.0.
- Tests were run per workstream only (targeted); the full suite had not been run when this section was written.

## 1. Summary

Nine domain agents rewrote and extended the VEYRS documentation against release 0.39.0 (`d2ae6f3`). Meanwhile `release/0.27.0` moved to **0.39.1** (`ab8103e`), so this audit re-based the whole set on 0.39.1 and then checked it against the code.

| Measure | Result |
|---|---|
| Hand-written documents audited | 100 (generated references excluded) |
| Concrete technical claims checked against the code | **204** in 14 folders plus the legacy manuals |
| Claims found wrong or incomplete | **48** (24 %) |
| Wrong claims fixed in the documents | **46**. The other 2 are one code defect (`POST /risk/simulate`); the documents now warn about it |
| Claims left unverifiable | 0 of the sampled prose claims; 1 of 60 diagrams (database tier not reachable) |
| Mermaid diagrams checked | **60**: 42 correct, 17 wrong and fixed (2 of them only in the legend), 1 unverifiable |
| Inconsistencies recorded | **101**: 51 document against code, 12 document against document, 34 code against its own comments, 4 owner decisions ([register](inconsistencies.md)) |
| Risk and debt items | **64** in the [register](risks-and-debt.md) (13 High, 33 Medium, 18 Low), plus the 28 security risks (R-01 to R-28) of the [security register](../security/risk-register.md) |
| Completeness gaps filled during the audit | 6 API paths named only in shorthand, `models/upgrade.py`, 3 documentation-tooling scripts, 10 broken `related:` front-matter paths, missing front matter on `IMPLEMENTATION_PLAN.md` |

**Overall judgement.** The reference material is complete by construction because it is generated from the code. The hand-written set now names every route, table, setting, CLI command, unit, script and console route.

Sampling showed that statements written from code reading are reliable: the architecture, database and security folders had 3 wrong claims out of 38. Statements inherited from older manuals, and line citations, are much less reliable. The legacy manuals and the console line references accounted for most of the 48 errors.

Several features are documented as they work, which is not always as they were meant to work. The [risk register](risks-and-debt.md) lists 13 High items that need code changes, including wrong de-duplication for SCA scanners, closure scoped wider than the scan, a cross-tenant write path and three broken endpoints.

## 2. What was analysed and how

**Inputs:**

- the source tree at 0.39.1 (`/root/veyrs-docs/src`; the 0.39.0 copy was used to re-map line numbers);
- the machine extracts (`openapi.json` with 266 paths and 330 operations, `routes.json` with 336 routes, `schema.json` with 89 tables, `settings.json` with 60 settings, `permissions.json` with 116 permissions and 10 roles);
- the nine findings files of the domain agents;
- the generated references (`reference/coverage.md`, `traceability.md`, `inventory.md`);
- the built portal (static HTML; its link check had already reported 0 broken links).

**Method:**

1. **Re-base on 0.39.1.** The changelog entry and the changed files were read: `config.py`, `frontend/console/{app.js,console.css,index.html}`, `scripts/public-export.sh`, the `install.sh` mode, and the new and changed console tests. `app.js` grew from 9,507 to 9,559 lines and `console.css` from 1,270 to 1,304. Every `app.js` and `console.css` line citation in the frontend, design and functional documents was re-mapped through the diff. The front matter of all 100 hand-written documents now says `version: 0.39.1`. Body text that states the documented version was updated; historical "since 0.39.0" markers were kept.
2. **Completeness.** The generated traceability and inventory were compared with the hand-written text. Separately, every OpenAPI path was searched verbatim in the hand-written documents.
3. **Accuracy spot-check.** At least 5 claims per folder and at least 10 per group of legacy manuals were checked, preferring numbers, defaults, permissions, routes, `path:line` citations and behaviour. Each claim was checked at the cited line; when that line was wrong, the real line was found.
4. **Contradictions.** Known contested topics were compared across documents: closure by absence, token lifetimes, Redis contents, table, RLS and test counts, CLI counts, roles, ports and singleton units. Each was resolved by the code.
5. **Diagrams.** All 60 Mermaid blocks were checked against the code they depict. The ER diagrams were checked by script against `schema.json`. Import graphs were re-derived with `ast`. Sequences were read against the handlers. Every edited diagram was rendered with `mmdc` to confirm it still parses.
6. **Unsupported claims.** Searches for webhook, Slack, SBOM, CI, Qdrant/vector/semantic, RSS/Atom/MISP/OpenCTI, HMAC, Celery, Alembic, SAML, OCR and poller. Each hit was labelled `Planned`, `Partial` or `Obsolete`, or removed, according to the code.
7. **Hygiene.** Front matter completeness and `related:` paths were checked by script. Internal addresses and host names were searched with the pattern in the brief; the Spanish-word sweep and the TODO/TBD sweep were also run.

The work was split between the auditor and four sub-passes of the same audit: architecture, database, security and operations; functional, integrations and the user manuals; diagrams; and the 0.39.1 frontend, design and testing changes. The tables below merge their evidence.

## 3. Results per domain

| Domain (folder) | Claims checked | Wrong | Fixed | Main corrections |
|---|---|---|---|---|
| Architecture (`architecture/`, `ARCHITECTURE.md`) | 11 | 0 | 0 | Prose correct; 7 of 17 diagrams in the folder were wrong (middleware order, Redis, import cycle, agent poll, job transitions, digest unit) |
| Database (`database/`, `DATABASE.md`) | 11 | 1 | 1 | RADIUS challenge TTL; the CLI-to-Redis diagram edge; the absence-closure diagram |
| Security (`security/`, `SECURITY.md`, `THREAT_MODEL.md`, `AI_SECURITY.md`) | 16 | 2 | 2 | "RSS articles"; the install-time 60-minute token lifetime added everywhere; trust-boundary diagram order |
| Operations (`operations/`, `DEPLOYMENT.md`, `HIGH_AVAILABILITY.md`, `DISASTER_RECOVERY.md`, `DOCKER_COMPOSE_MANUAL.md`, `SYSTEM_MANUAL.md`) | 17 | 4 | 4 | woff2 export (fixed in 0.39.1), digest timer singleton, Redis contents in the HA guide |
| Troubleshooting | 6 | 1 | 1 | woff2 export entry |
| ADRs | 7 | 0 | 0 | Status notes added (0006, 0007); "Check against" sections now say 0.39.1 |
| Functional (`functional/`) | 36 | 4 | 4 | Template locales; closure line numbers; console line numbers after 0.39.1 |
| Integrations (`integrations/`, `INTEGRATIONS.md`) | 14 | 0 | 0 | Scanner closure text aligned with ADR 0006's status note |
| API guide (`api/guide.md`, `API.md`) | 12 | 4 | 4 | Line citations (`LoginRequest`, `TokenPair`, `_principal_from_jwt`, `set_tenant`) |
| Executive (`executive/`) | 11 | 3 | 3 | Test-file count, notification channels, "full-text" search |
| Glossary (`reference/glossary.md`) | 6 | 1 | 1 | Digest definition |
| User and admin manuals (`USER_GUIDE`, `USER_MANUAL`, `ADMIN_GUIDE`, `APP_FLOW`) | 18 | 8 | 6 | Qdrant, closure, escalation timing and recipient, importer holders, ladder seeding; `/risk/simulate` (not fixable in the docs) |
| Developer docs (`DEVELOPMENT`, `CONTRIBUTING`, `IMPLEMENTATION_PLAN`, `README`, `TECHNICAL_REQUIREMENTS`) | 9 | 4 | 4 | Qdrant; the register written for 0.35.1; status version |
| Frontend (`frontend/`) | 11 | 6 | 6 | 0.39.1 changes (rail, chips, `?v=`, identical deployed files), site builder state |
| Design (`design/`, `DESIGN_SYSTEM.md`, `BRAND.md`) | 12 | 5 | 5 | Pill case, inline-style count, logo files, criticality pill |
| Testing (`testing/`, `TESTING_GUIDE.md`) | 7 | 5 | 5 | Counts (94 files, 1,643 functions), `test.sh`, `conftest.py` and `test_audit_rls.py` lines |
| **Total** | **204** | **48** | **46** | |

The architecture, database and security documents were written from the code during this programme, and the sample found them almost free of errors. The legacy manuals and every file that cites `app.js` lines carried most of the errors.

## 4. Diagrams

60 diagrams were checked. All have a legend, and none uses HTML or `<br>`. The 17 that were wrong were fixed in the Markdown source; their SVGs must be re-rendered.

| File | Diagram | What was wrong | Fix |
|---|---|---|---|
| `HIGH_AVAILABILITY.md` | HA topology | The digest timer was missing from the singleton units | Added; the legend names the three singletons |
| `architecture/c4.md` | Context | The agent "runs scans against scanners"; Telegram was shown as a notification channel | Added a scan-target node; the mail edge now carries notifications and MFA codes only |
| `architecture/c4.md` | Container | "Redis: rate limits, cache" | Rate limits, MFA codes and SSO state |
| `architecture/data-flows.md` | Agent job state | `leased → failed` on a failed result was missing | Added |
| `architecture/dependencies.md` | Layer imports | The engines → core (`db`) edge was missing | Added |
| `architecture/dependencies.md` | Service cycle | 5 edge kinds were wrong and 5 edges missing | Re-derived with `ast` |
| `architecture/deployment.md` | Native single node | The digest edge and the Docs Center | `scripts/send-digest.sh`; Docs Center marked optional |
| `architecture/sequences.md` | Agent claim | "poll default 5 s" | The code default is 15 s; the shipped unit passes `--poll 5` |
| `database/README.md` | Engines | The CLI wrote MFA data to Redis | The CLI only pings Redis (`veyrs check`) |
| `database/lifecycle.md` | Absence closure | `close_absent` was drawn as opt-in | On by default when the threshold is above 0; thresholds in the legend |
| `functional/README.md` | Request layers | Middleware order | CORS → request context → rate limit (`main.py:72-86`) |
| `functional/agents.md` | Job state | Result, fail-with-requeue and fail-without-requeue edges missing | Added; the legend says expiry happens only on reap |
| `functional/updates.md` | Updater sequence | Status written to the spool | A separate status directory, read by `recent_status` |
| `functional/vulnerability-management.md` | Finding state | `new → accepted_risk` is illegal; `closed → new` was missing | `triaged → accepted_risk`; re-detection edge added |
| `security/security-architecture.md` | Trust boundaries | Rate limit drawn before request context | Request context → rate limit |
| `security/security-architecture.md` | Request decisions | Legend cited the non-existent `deps.py:280-378` | `deps.py:87-209` (legend only) |
| `security/authentication.md` | Login decisions | Legend shape wording | Legend only |

The ER diagrams (10) were checked by script against `schema.json` (entities, columns, keys, nullability, edge targets) and have no mismatches. The split-HA diagram in `architecture/deployment.md` is **Unverifiable**: the database and standby nodes cannot be reached from the inspection host.

## 5. Spot-check table

Verdicts: **Correct**; **Wrong (fixed)**, where the document was corrected; **Wrong (not fixed)**, with the reason. "Line" means the citation was off but the value was right. All sources are under `backend/veyrs/` unless they start with another top-level folder.

### 5.1 Architecture, database, security, operations, troubleshooting, ADRs, operations manuals

| # | Document | Claim | Source | Verdict |
|---|---|---|---|---|
| 1 | architecture/overview.md | Middleware order: CORS, request context, rate limit | `main.py:72-86` | Correct |
| 2 | architecture/overview.md | Auth paths 10/min keyed by IP, others 240/min, probes exempt | `security/ratelimit.py:38-43,178-184`, `config.py:68,73` | Correct |
| 3 | architecture/overview.md | Pool 10 + 20; statement timeout 30 s, idle-in-transaction 60 s | `db.py:27-28,41-42` | Correct |
| 4 | architecture/overview.md | `VEYRS_WORKERS` defaults to 4 | `docker/entrypoint.sh:17` | Correct |
| 5 | architecture/overview.md | 140 modules, 54,810 lines | `find backend/veyrs -name '*.py'` | Correct |
| 6 | architecture/overview.md | 20 top-level CLI commands | `cli.py:675-798`, `services/mfa_admin.py:134` | Correct |
| 7 | architecture/data-flows.md | AI defaults: public ceiling, redaction, 24,000 chars, 2,000 calls | `services/ai/gateway.py:112-119` | Correct |
| 8 | architecture/data-flows.md | Agent closure needs 80 % coverage | `services/agents.py:845,990` | Correct |
| 9 | architecture/sequences.md | A missing user still costs an Argon2 check | `api/v1/auth.py:410-411` | Correct |
| 10 | architecture/dependencies.md | Qdrant is not a dependency | `requirements.txt` | Correct |
| 11 | ARCHITECTURE.md | Workflow trigger callers | `services/correlation.py:606`, `services/sla.py:470`, `api/v1/tickets.py:198,509` | Correct |
| 12 | database/README.md | Rate-limit key `veyrs:rl:<id>:<window>` | `security/ratelimit.py:108` | Correct |
| 13 | database/README.md | MFA sends throttled at 30 s and 6 per 15 min | `security/mfa_delivery.py:52-54,273-282` | Correct |
| 14 | database/README.md | OIDC flow state 600 s, hand-off 60 s | `services/oidc_auth.py:54-55` | Correct |
| 15 | database/README.md | RADIUS challenge TTL "short" | `services/radius_auth.py:77` (180 s) | Wrong (fixed) |
| 16 | database/README.md | RLS classes 68/4/15/2 = 89; 72 forced | `cli.py:33-56` | Correct |
| 17 | database/README.md | 216 foreign keys | `extract/schema.json` | Correct |
| 18 | database/queries.md | Nine `ILIKE` queries with `LIMIT 10` | `services/search.py:61,84-167` | Correct |
| 19 | database/backup-recovery.md | The container helper refuses fewer than 50 tables | `docker/veyrs-docker.sh:325-326` | Correct |
| 20 | database/lifecycle.md | No writer for `asset_groups`, `webhook_endpoints`, `notification_templates` | search for constructors outside `models/` | Correct |
| 21 | database/lifecycle.md | EPSS history kept 365 days by default | `config.py:91` | Correct |
| 22 | DATABASE.md | Ticket reference `VEYRS-INC-000001` | `services/ticketing.py:77-78` | Correct |
| 23 | SECURITY.md | Access 30 min, refresh 14 days | `config.py:56-57`; `install.sh:1015` writes 60 | Wrong (fixed): incomplete |
| 24 | security/security-architecture.md | Refresh token is 48 random bytes, stored as SHA-256 | `security/auth.py:112-120` | Correct |
| 25 | security/security-architecture.md | JWT HS256/384/512 | `config.py:58` | Correct |
| 26 | security/authorization.md | 29 resources, 116 permissions, 10 roles | `extract/permissions.json` | Correct |
| 27 | security/authorization.md | 46 routes without a permission; 8 platform-admin routes | `extract/routes.json` | Correct |
| 28 | security/authorization.md | `platform_admin` requires kind `user` | `api/v1/updates.py:28-34` | Correct |
| 29 | security/authentication.md | `MAX_FAILED = 10`, `LOCK_MINUTES = 15` | `api/v1/auth.py:58-59,112-113` | Correct |
| 30 | security/authentication.md | MFA code TTL 300 s (60-900), 5 tries | `config.py:120`, `security/mfa_delivery.py:51,310` | Correct |
| 31 | security/authentication.md | `family_id = user.id` | `api/v1/auth.py:88` | Correct |
| 32 | security/authentication.md | Password-change and logout handlers | `api/v1/auth.py:619-620,771-772` | Correct |
| 33 | security/risk-register.md | No CI; pip install without hashes | no CI folder; `docker/Dockerfile:55` | Correct |
| 34 | security/security-architecture.md | Inbound webhook 5-minute window | `services/itsm_inbound.py:57,114` | Correct |
| 35 | AI_SECURITY.md | Rolling 24 h call ceiling; hosted vendors | `services/ai/gateway.py:188-196`, `providers.py:382` | Correct |
| 36 | THREAT_MODEL.md | "RSS articles" enter the system | no poller; `POST /intel/articles` only | Wrong (fixed) |
| 37 | SECURITY.md | Upload limits 128/32/128/64/8/1 MB | `api/v1/knowledge.py:27`, `integrations.py:31`, `cmdb.py:65`, `agents.py:57`, `compliance.py:32`, `services/itsm_inbound.py:58` | Correct |
| 38 | SECURITY.md | A real release signing key is committed | `release/allowed_signers:13` | Correct |
| 39 | operations/release.md | The export fails on woff2 | `scripts/public-export.sh:509-512` (allowed since 0.39.1) | Wrong (fixed) |
| 40 | operations/services.md | Unit schedules, jitter, users | the `.timer` and `.service` files | Correct |
| 41 | operations/services.md | replcheck every 15 min | `infrastructure/backup/veyrs-replcheck.timer` | Correct |
| 42 | operations/services.md | pgdump 02:15 plus 300 s; 20 MB floor | `veyrs-pgdump.timer`, `veyrs-pgdump.sh:47` | Correct |
| 43 | operations/services.md | Agent `--poll 5 --job-timeout 1800`, runs as root | `integrations/veyrs-agent/veyrs-agent.service:9,15` | Correct |
| 44 | operations/services.md | Container uid 10001 | `docker/Dockerfile:82-87` | Correct |
| 45 | operations/services.md | `install.sh` enables `veyrs-updater.path` | `install.sh:1152-1165` | Correct |
| 46 | operations/services.md | Singletons are the agent and the intel timer | `services/digest.py` `due_now` (the digest is one too) | Wrong (fixed) |
| 47 | operations/monitoring.md | Metric names, 5,000-sample window, 256-series cap, 404 without a token | `observability.py:93,130,154-190`, `main.py:129-138` | Correct |
| 48 | operations/README.md | Ports 80/8000/8080/5432/6379 | `veyrs-api.service:23`, `compose.yaml:63-64,400`, nginx conf `:8` | Correct |
| 49 | operations/README.md | `MIN_PY_MINOR=11` | `install.sh:98` | Correct |
| 50 | operations/installation.md | `ssh-keygen -Y verify` with namespace `veyrs-release` | `scripts/verify-release.sh:19,38` | Correct |
| 51 | troubleshooting/README.md | woff2 is "unexpected binary" | `scripts/public-export.sh:509-512` | Wrong (fixed) |
| 52 | troubleshooting/README.md | `/readyz` body; Redis ping with a 2 s timeout | `main.py:95-113` | Correct |
| 53 | troubleshooting/README.md | Empty secret key gives a per-process key that the production check misses | `config.py:152-159,214-230` | Correct |
| 54 | troubleshooting/README.md | The container entrypoint exits 78 | `docker/entrypoint.sh:39` | Correct |
| 55 | troubleshooting/README.md | The native vhost has no `/static/` block | `install.sh:1264-1335`, `index.html:9-20` | Correct |
| 56 | troubleshooting/README.md | `sync-schema` skips tables that do not exist | `cli.py:100-103` | Correct |
| 57 | ADRs/0006 | Thresholds 1/2/0 per engagement type | `services/engagements.py:43-48` | Correct |
| 58 | ADRs/0006 | `close_missing` is a deprecated alias | `api/v1/integrations.py:173`, `services/importers/base.py:764-772` | Correct |
| 59 | ADRs/0006 | Closure reason and evidence strings | `services/engagements.py:314,323` | Correct |
| 60 | ADRs/0006 | `REOPENABLE_STATES` | `services/correlation.py:44` | Correct |
| 61 | ADRs/0007 | Update spool and status directories | `config.py:132-141`, `services/updates.py:338` | Correct |
| 62 | ADRs/0007 | Redis availability checked once per process | `security/ratelimit.py:81-100` | Correct |
| 63 | ADRs/0001 | 17 tables are not under RLS | `cli.py:33-56` | Correct |
| 64 | HIGH_AVAILABILITY.md | Redis holds rate limits and cache only | `security/mfa_delivery.py:280`, `services/oidc_auth.py:226,302`, `services/radius_auth.py:379` | Wrong (fixed) |
| 65 | DEPLOYMENT.md | Singleton list | `services/digest.py` `due_now` | Wrong (fixed) |
| 66 | DISASTER_RECOVERY.md | RADIUS and OIDC secrets are sealed with the same key | `services/radius_auth.py:67,337`, `services/oidc_auth.py:53,147` | Correct |
| 67 | DOCKER_COMPOSE_MANUAL.md | CLI subcommand list | `cli.py:796-798`, `services/mfa_admin.py:134` | Correct |
| 68 | SYSTEM_MANUAL.md | `sync-epss` trims history | `intel/feeds.py:220` | Correct |
| 69 | TECHNICAL_REQUIREMENTS.md | RADIUS challenge 180 s | `services/radius_auth.py:77` | Correct |
| 70 | TECHNICAL_REQUIREMENTS.md | Access-token lifetime | `config.py:56`, `install.sh:1015` | Wrong (fixed): incomplete |

### 5.2 Functional, integrations, API guide, executive, glossary, user and developer manuals

| # | Document | Claim | Source | Verdict |
|---|---|---|---|---|
| 71 | functional/authentication-accounts.md | 10 failures lock for 15 min | `api/v1/auth.py:58-59` | Correct |
| 72 | functional/authentication-accounts.md | Access token 30 min by default | `config.py:56` | Correct (install note added) |
| 73 | functional/authentication-accounts.md | Refresh token 14 days | `config.py:57` | Correct |
| 74 | functional/authentication-accounts.md | Auth rate limit 10/min | `config.py:73` | Correct |
| 75 | functional/authentication-accounts.md | MFA: 5 tries, 30 s resend gap, 6 per 15 min, TTL 300 s | `security/mfa_delivery.py:51-55`, `config.py:120` | Correct |
| 76 | functional/authentication-accounts.md | API key expiry default 365, range 1-3650 days | `api/v1/schemas.py:616` | Correct |
| 77 | functional/authentication-accounts.md | Built-in roles cannot be edited (422) | `api/v1/admin.py:920-972` | Correct |
| 78 | functional/agents.md | Result limit 64 MiB; coverage 80 %; error rate 50 % | `services/agents.py:57,845,848` | Correct |
| 79 | functional/agents.md | Reap `offline_after` default 180, range 30-86400 | `api/v1/agents.py:552` | Correct |
| 80 | functional/ai.md | 24,000 prompt characters, 2,000 calls a day | `models/ai.py:119-120` | Correct |
| 81 | functional/risk-engine.md | Floors 75/90/80; age penalty 3 per 30 days, capped at 15 | `engines/risk.py:67-72` | Correct |
| 82 | functional/risk-engine.md | `/risk/simulate` raises `TypeError` | `api/v1/findings.py:539-540`, `engines/risk.py:143-178` | Correct (re-verified by the auditor) |
| 83 | functional/sla-escalation.md | SLA warning at 75 % | `models/sla.py:48` | Correct |
| 84 | functional/notifications-digest.md | Templates in five locales | `services/notifications.py:46` (one event only) | Wrong (fixed) |
| 85 | functional/notifications-digest.md | 5 delivery retries; events that cannot be muted | `services/notifications.py:41,267` | Correct |
| 86 | functional/notifications-digest.md | Digest off by default, 07 UTC, 24 h window, high severity, 12 h guard | `services/digest.py:54-61,396` | Correct |
| 87 | functional/integrations.md | Import limit 128 MiB; `absence_threshold` 0-30 | `api/v1/integrations.py:31,223` | Correct |
| 88 | functional/integrations.md | Export timeout 120 s, poll 3 s, HTTP 60 s | `services/scanners.py:60-62` | Correct (line) |
| 89 | functional/integrations.md | Inbound webhook: 300 s replay window, 1 MiB body | `services/itsm_inbound.py:57-58` | Correct |
| 90 | functional/knowledge-search.md | Upload 32 MiB; chunks of 1,200 characters with 150 overlap | `api/v1/knowledge.py:27`, `services/documents.py:282` | Correct |
| 91 | functional/knowledge-search.md | Source poll interval 5-10,080 min | `api/v1/knowledge.py:99` | Correct |
| 92 | functional/cmdb-asset-sources.md | Upload limit 64 MiB | `services/cmdb.py:65` | Correct |
| 93 | functional/compliance.md | Control-import limit 8 MiB | `api/v1/compliance.py:32` | Correct |
| 94 | functional/threat-intelligence.md | NVD window 120 days; delays 7 s / 1 s | `intel/feeds.py:47,58-59` | Correct |
| 95 | functional/threat-intelligence.md | Schedule 60-43,200 min, default 1,440 | `services/intel_schedule.py:65-72` | Correct |
| 96 | functional/dashboards-reports.md | `days` 7-730, default 90 | `api/v1/reports.py:67` | Correct |
| 97 | functional/assets-inventory.md | Page size 1-200, default 50 | `api/v1/assets.py:135` | Correct |
| 98 | functional/engagements-scan-import.md | Risk-acceptance `warn_days` 14 | `services/engagements.py:487` | Correct |
| 99 | functional/engagements-scan-import.md | `DEFAULT_ABSENCE_THRESHOLD` at `:46-50` | `services/engagements.py:43-47` | Wrong (fixed): line |
| 100 | functional/engagements-scan-import.md | Closure reason at `:288` | `services/engagements.py:314` | Wrong (fixed): line |
| 101 | functional/engagements-scan-import.md | The two closure test names | `tests/test_phase8_integrations.py:346,370` | Correct |
| 102 | functional/risk-register.md | `PUT /risks/{id}/raci` at `:361` | `api/v1/risk_register.py:361` | Correct |
| 103 | functional/ticketing-itsm.md | `transition_finding` offers non-existent states | `services/workflow.py:360-370` | Correct |
| 104 | functional/vulnerability-management.md | The open-states set | `models/vulnerability.py:67-68` | Correct |
| 105 | functional/updates.md | `platform_admin` requires a superuser user | `api/v1/updates.py:26-33` | Correct |
| 106 | functional/* (six files) | `app.js` line references | `frontend/console/app.js` at 0.39.1 | Wrong (fixed): shifted by 0.39.1 |
| 107 | integrations/scanners.md | Absence thresholds and their resolution | `services/engagements.py:43-47,258-262`, `services/importers/base.py:767-772` | Correct |
| 108 | integrations/scanners.md | Relation to ADR 0006 | `services/engagements.py:108-131` | Correct (clarified) |
| 109 | integrations/automation.md | Standard ladder 4/8/24/48 h, counted from detection | `services/sla.py:85-91,397,446-449` | Correct |
| 110 | integrations/automation.md | Where workflow triggers fire | `services/sla.py:470`, `services/correlation.py:606`, `api/v1/tickets.py:198,509` | Correct |
| 111 | integrations/threat-intel.md | `intel_due` and `prune_epss_history` lines | `cli.py:600,458` | Correct |
| 112 | integrations/notifications.md | `sign_webhook`; `WebhookEndpoint` | `services/notifications.py:311`, `models/workflow.py:152` | Correct |
| 113 | integrations/notifications.md | 6 provider kinds, 3 always external | `services/ai/providers.py:370-382` | Correct |
| 114 | integrations/notifications.md | Webhook and Slack have no transport | `services/notifications.py:255-259`, `services/workflow.py:347-348` | Correct |
| 115 | integrations/agent.md | Lease 900 s, range 60-86,400 | `api/v1/agents.py:99` | Correct |
| 116 | integrations/agent.md | `max_concurrency` 1-32 | `api/v1/agents.py:98` | Correct |
| 117 | integrations/agent.md | Runner defaults: poll 15 s, timeout 3,600 s, inventory 21,600 s, heartbeat 60 s, extend 120 s, batch 25 | `integrations/veyrs-agent/veyrs_agent.py:67-83,608,734,764` | Correct |
| 118 | integrations/agent.md | Nuclei parameter clamps | `veyrs_agent.py:133-134` | Correct |
| 119 | INTEGRATIONS.md | Feed order, then `run-sla` | `scripts/sync-intel.sh:53,91` | Correct |
| 120 | INTEGRATIONS.md | AI provider endpoints | `services/ai/providers.py:216,252` | Correct |
| 121 | api/guide.md | `LoginRequest` at `schemas.py:119` | `api/v1/schemas.py:117` | Wrong (fixed): line |
| 122 | api/guide.md | `TokenPair` at `:176` | `api/v1/schemas.py:175` | Wrong (fixed): line |
| 123 | api/guide.md | Access token 30 min by default | `config.py:56`, `install.sh:1015` | Correct (install note added) |
| 124 | api/guide.md | `_principal_from_jwt` at 106-140 | `security/deps.py:110` | Wrong (fixed): line |
| 125 | api/guide.md | `require` returns 403 | `security/deps.py:62-67` | Correct |
| 126 | api/guide.md | `set_tenant` at `deps.py:158-160` | `security/deps.py:182,216` | Wrong (fixed) |
| 127 | api/guide.md | `enforce_route_policy`, `refuse_if_restricted` | `security/scope.py:228,247` | Correct |
| 128 | api/guide.md | General limit 240/min | `config.py:68` | Correct |
| 129 | api/guide.md | The rate limiter runs inside request context | `main.py:72-76` | Correct |
| 130 | api/guide.md | Correlation-ID and response-time headers | `observability.py:199,226-227` | Correct |
| 131 | API.md | Changes window 30 days; 5,000-event cap | `api/v1/attribution.py:50`, `services/attribution.py:90` | Correct |
| 132 | API.md | Update apply returns 202, or 409 | `api/v1/updates.py:55,69` | Correct |
| 133 | executive/overview.md | 93 test files | `ls tests/test_*.py` = 94 | Wrong (fixed) |
| 134 | executive/overview.md | 20 CLI commands | `cli.py:675-790` | Correct (23 with `secrets` subcommands added) |
| 135 | executive/overview.md | Notifications by webhook and Telegram | `services/notifications.py:255-259` | Wrong (fixed) |
| 136 | executive/overview.md | PostgreSQL full-text search | `services/search.py:84-134` (`ILIKE`) | Wrong (fixed) |
| 137 | executive/overview.md | 15 finding states | `models/vulnerability.py:27-43` | Correct |
| 138 | executive/overview.md | 6 network-scanner plus 14 other formats | `services/importers/parsers.py:417`, `parsers_modern.py:887` | Correct |
| 139 | executive/overview.md | 13 AI capabilities | `models/ai.py:48-60` | Correct |
| 140 | executive/overview.md | 12 automated compliance signals | `services/compliance.py:351-364` | Correct |
| 141 | executive/overview.md | 5 built-in risk profiles | `engines/risk.py:93-135` | Correct |
| 142 | executive/overview.md | RLS on 72 of 89 tables | `cli.py:33-62,314-330` | Correct |
| 143 | executive/overview.md | 6 workflow actions; 5 of 10 triggers fired | `services/workflow.py:266-273` | Correct |
| 144 | reference/glossary.md | 116 permissions, 10 roles | `extract/permissions.json` | Correct |
| 145 | reference/glossary.md | Risk level bands | `engines/risk.py:42-48` | Correct |
| 146 | reference/glossary.md | Sighting status present or absent | `models/engagement.py:57` | Correct |
| 147 | reference/glossary.md | A lease out of attempts expires, it does not fail | `services/agents.py:1197-1226` | Correct |
| 148 | reference/glossary.md | Dedupe key is 64 characters | `models/vulnerability.py:156` | Correct |
| 149 | reference/glossary.md | The digest is a daily e-mail | `services/digest.py:54-62` | Wrong (fixed) |
| 150 | USER_GUIDE.md | Semantic search through Qdrant | `services/search.py` (null backend) | Wrong (fixed) |
| 151 | USER_GUIDE.md | A finding missing from one scan is not closed | `services/engagements.py:43-47` (`ci_cd` closes after 1) | Wrong (fixed) |
| 152 | USER_MANUAL.md | Escalation fires N hours past the deadline and notifies the manager | `services/sla.py:397,446-464`, `services/workflow.py:578-584` | Wrong (fixed) |
| 153 | USER_MANUAL.md | Business sub-score formula | `engines/risk.py:277-299` | Correct |
| 154 | USER_MANUAL.md | Eight reports | `services/reporting.py:275-298` | Correct |
| 155 | USER_MANUAL.md | Access token 30 min | `config.py:56` | Correct (install note added) |
| 156 | USER_MANUAL.md | 10 failures lock for 15 min | `api/v1/auth.py:58-59` | Correct |
| 157 | USER_MANUAL.md | Hourly tick with up to 10 min jitter | `integrations/systemd/veyrs-intel-sync.timer:15-16` | Correct |
| 158 | USER_MANUAL.md | Feed order CWE, NVD, EPSS, KEV | `scripts/sync-intel.sh:91` | Correct |
| 159 | USER_MANUAL.md | Example network in the private `10.x` range | public-documentation rule | Wrong (fixed) |
| 160 | ADMIN_GUIDE.md | Only security-manager holds importer read and write | `extract/permissions.json` (also service-account) | Wrong (fixed) |
| 161 | ADMIN_GUIDE.md | Accept-risk needs `risk:admin`, held only by org-admin | `api/v1/findings.py:411-418` | Correct |
| 162 | ADMIN_GUIDE.md | The built-in ladder starts at 10 | `services/sla.py:56-79`; `seed_policies` is called only by tests | Wrong (fixed) |
| 163 | ADMIN_GUIDE.md | Risk-profile options list | `engines/risk.py:66-75` | Correct |
| 164 | ADMIN_GUIDE.md | Risk-profile *Simulate* works | `api/v1/findings.py:539-540` | Wrong (not fixed): code defect TD-06; warning added |
| 165 | ADMIN_GUIDE.md | Rights in the role table | `extract/permissions.json` | Correct |
| 166 | APP_FLOW.md | *Simulate* scores the inputs | same as #164 | Wrong (not fixed): code defect TD-06; note added |
| 167 | APP_FLOW.md | Natural-language search posts `query`; the API needs `question` | `frontend/console/app.js:5843`, `api/v1/ai.py:111-112` | Correct (re-verified at 0.39.1) |
| 168 | CONTRIBUTING.md | The version guard test | `tests/test_phase24_dependencies.py:143` | Correct |
| 169 | CONTRIBUTING.md | No CI configuration | repository tree | Correct |
| 170 | DEVELOPMENT.md | Python 3.11 or newer | `pyproject.toml:5` | Correct |
| 171 | DEVELOPMENT.md | Search degrades when Qdrant is down | `services/search.py` | Wrong (fixed) |
| 172 | DEVELOPMENT.md | `GLOBAL_TABLES` in `models/base.py` | `models/base.py:89` | Correct |
| 173 | IMPLEMENTATION_PLAN.md | "VEYRS 0.35.1 … at HEAD" | `pyproject.toml:3` | Wrong (fixed) |
| 174 | README.md | "Status: 0.39.0" | `pyproject.toml:3` | Wrong (fixed): version |

### 5.3 Frontend, design, testing (0.39.1)

| # | Document | Claim | Source | Verdict |
|---|---|---|---|---|
| 175 | frontend/console.md | `boot()` is the last statement, at `app.js:9507` | `app.js:9559` | Wrong (fixed): 0.39.1 |
| 176 | frontend/console.md | `store.clear()` removes only the token and permission keys | `app.js:26` | Correct |
| 177 | frontend/console.md | 27 `route()` registrations | `app.js` | Correct |
| 178 | frontend/console.md | Policies tables show raw JSON | `app.js:4074-4132` | Wrong (fixed): chips and ladder in 0.39.1 |
| 179 | frontend/console.md | Natural-language search posts `{query}` | `app.js:5843` | Correct (defect still present) |
| 180 | frontend/console.md | `veyrs.nav.rail` key exists | `app.js:1165` | Correct |
| 181 | frontend/console.md | `tab=itsm` link | `app.js:8239` | Correct |
| 182 | frontend/README.md | `?v=20` / `?v=46` | `index.html:13,104` | Wrong (fixed): 21/47 |
| 183 | frontend/README.md | Deployed files differ from the source | md5 `518b361b…` on both | Wrong (fixed): identical |
| 184 | frontend/sites.md | `site_nav` at `build.py:291` | `site/build.py:604` | Wrong (fixed) |
| 185 | frontend/sites.md | The builder has no front-matter support | `site/build.py:123` | Wrong (fixed) |
| 186 | DESIGN_SYSTEM.md | Severity pills are uppercase (`CRITICAL`) | `console.css:980` (`capitalize`) | Wrong (fixed) |
| 187 | DESIGN_SYSTEM.md | State pills are uppercase | `app.js:276-281` | Wrong (fixed) |
| 188 | DESIGN_SYSTEM.md, design/console-ui.md | 61 `style="` attributes | 63 on 61 lines | Wrong (fixed) |
| 189 | DESIGN_SYSTEM.md | `veyrs-logo*.svg` and `veyrs-mark*.svg` exist | `frontend/brand/logo/` | Wrong (fixed) |
| 190 | design/console-ui.md, DESIGN_SYSTEM.md | Asset criticality uses `.sev-*` | `app.js:244-257` (`critPill`) | Wrong (fixed): 0.39.1 |
| 191 | design/console-ui.md | `--sidebar-w` 236 px | `console.css:457` | Correct |
| 192 | design/console-ui.md | `st-queued` and `st-cancelled` have no CSS rule | `app.js:2112-2116`, `console.css` | Correct |
| 193 | DESIGN_SYSTEM.md | `class="err"` has no rule | `app.js:6210`, `console.css:1198` | Correct |
| 194 | DESIGN_SYSTEM.md | `fmtShortDate(null)` prints the epoch | `app.js:218-221` | Correct |
| 195 | DESIGN_SYSTEM.md | Login logo 248 px / 70 % | `console.css:1219` | Correct |
| 196 | BRAND.md | The gradient mark is 706×450 and shown at 30 px in the sidebar | PNG header, `console.css:650` | Correct |
| 197 | design/accessibility.md | 8 `role="img"` sites; `text-secondary` 7.30/6.32 on surface | `app.js`; recomputed | Correct |
| 198 | testing/strategy.md | `test.sh:55`, `:25-31`, `:33-46` | `scripts/test.sh:46,24-30,31-44` | Wrong (fixed): lines |
| 199 | testing/strategy.md | `conftest.py:21-35`, `:38-58` | `tests/conftest.py:19-33,35-59` | Wrong (fixed): lines |
| 200 | testing/strategy.md | `test_audit_rls.py:15` | `tests/test_audit_rls.py:39` | Wrong (fixed): line |
| 201 | testing/*, TESTING_GUIDE.md | 90 files, 1,629 functions, 1,817 expanded | AST count: 94, 1,643, 1,831 | Wrong (fixed): 0.39.1 |
| 202 | testing/strategy.md, known-issues.md | `LIST_ENDPOINTS`, `WRITE_PROBES`, the write-path skip at `:93`, the version test at `:143`, the unused `integration` marker, the six `/opt/veyrs` paths | `tests/` at the cited lines | Correct |
| 203 | testing/known-issues.md | The docs builder does not strip front matter | `site/build.py:123` | Wrong (fixed) |
| 204 | testing/known-issues.md | The stray-markup test globs the top level only | `tests/test_site_render.py:76` | Correct |

Also re-verified by the auditor directly in the code, without a document correction: the SCA dedupe defect (`services/dedupe.py:149-152,195-198,293-297`), the threat-summary column (`services/ai/capabilities.py:386,392`), escalation counted from detection (`services/sla.py:397,446-449`), and that `seed_policies` / `seed_profiles` have no non-test caller.

## 6. Coverage

The generated [coverage index](../reference/coverage.md) measures the hand-written set by text search. It counts a mention, not its quality. Its own note explains that the generated references (API per tag, configuration, permissions, schema, inventory) cover 100 % of their items **by construction**: they are produced from the code and prove nothing about the hand-written text.

| Measure | Before this audit (generated index) | After this audit | How it is measured |
|---|---|---|---|
| API paths named verbatim in hand-written docs | 260 / 266 (98 %) | 266 / 266 | Measured: verbatim search of each OpenAPI path. The 6 were risk-acceptance approve/reject and five connector routes written in shorthand; now written in full in `functional/engagements-scan-import.md` and `functional/integrations.md` |
| OpenAPI tags named in functional docs and manuals | 19 / 19 | 19 / 19 | Measured |
| Operations in the API reference | 330 / 330 | 330 / 330 | By construction |
| Tables in the ER diagrams | 89 / 89 | 89 / 89 | Measured (script against `schema.json`) |
| `VEYRS_*` settings named | 60 / 60 | 60 / 60 | Measured |
| Backend modules named by path or dotted name | 131 / 140 (94 %) | 132 / 140 | Measured. `models/upgrade.py` added. The remaining 8 are package `__init__.py` files with no behaviour (`api`, `data`, `engines`, `intel`, `models`, `security`, `services`, `services/ai`) |
| Backend modules referenced by a test file | 105 / 140 (75 %) | unchanged | Measured by import or dotted name. Modules exercised only over HTTP count as untested, so this is a lower bound |
| Routes referenced by a test path literal | 259 / 336 (77 %) | unchanged | Measured by the QA agent at 0.39.0 (path literals; lower bound). 0.39.1 added no route tests |
| CLI commands named | 23 / 23 | 23 / 23 | Measured |
| Shipped systemd units named | 14 / 14 | 14 / 14 | Measured |
| Scripts named | 17 / 20 | 20 / 20 | Measured. `check-docs-links.py`, `gen-reference-docs.py` and `render-diagrams.py` are now in `testing/strategy.md` |
| Console routes documented | 27 + 1 redirect | 27 + 1 redirect | Measured (`route(` registrations against `frontend/console.md`) |
| Hand-written docs with complete front matter | 98 / 99 | 100 / 100 | Measured by script (the audit folder added 4 documents) |
| `related:` front-matter paths that exist | not measured | 100 % (10 fixed) | Measured by script |

> [!NOTE]
> The "after" figures were measured by the auditor's own scripts. `reference/coverage.md` and `reference/traceability.md` are generated and still show the "before" figures until `python3 scripts/gen-reference-docs.py` is re-run.

None of these percentages measures correctness. The only correctness measure is the spot check in section 5. 24 % of the sampled claims were wrong, and the sample was biased towards numbers and citations, which are where errors cluster. Sampled prose is now correct, except for one code defect. Unsampled prose in the legacy manuals, about 5,000 lines of `USER_MANUAL.md`, `DOCKER_COMPOSE_MANUAL.md` and `ADMIN_GUIDE.md`, should be presumed to contain errors at a similar rate.

## 7. Hygiene

| Check | Result |
|---|---|
| Front matter with all eight keys and `version: 0.39.1` | 100 / 100 hand-written documents (`IMPLEMENTATION_PLAN.md` was added). `CHANGELOG.md` is treated as generated and historical, so it has none |
| `status` uses the vocabulary | 100 / 100 |
| First line after the front matter is the `#` title | 100 / 100 |
| Internal addresses and host names outside `docs/internal/` | 3 example networks in the `10.x` range replaced with RFC 5737 ranges. Remaining hits are owner decisions OD-01 (public GitHub organisation name, about 40 lines) and OD-02 (the shipped Docker defaults of `VEYRS_SUBNET` and `VEYRS_CONSOLE_IP`), plus the generated `reference/configuration.md` and `reference/inventory.md`, which print code defaults (TD-31) |
| Secrets | none found |
| Spanish words (sweep from the brief) | 0 files |
| TODO, TBD, FIXME | 0 |

## 8. Limitations and what could not be verified

- **Nothing was executed against the application.** The test suite was not run (operator rule). No POST, PUT, PATCH or DELETE was sent to a live node. Every statement about write paths, including the defects in the risk register, comes from reading the code. The SCA dedupe defect was reproduced by calling the key function in isolation.
- **The database tier, the standby, the front proxy and the backup host were not reachable.** Replication, backup timers on the database node, actual RLS policies, row counts and query plans are taken from the code and from `HIGH_AVAILABILITY.md`. The split-HA diagram is Unverifiable for the same reason.
- **No browser session.** Console behaviour, focus order and rendering are read from code; contrast is computed, not measured on screen.
- **External systems.** ITSM, scanner consoles, Confluence, NetBox, LDAP, RADIUS, OIDC, vault, SMTP and Telegram were not exercised. None is configured on the observed node except one NetBox source.
- **Sampling.** 204 of the several thousand factual statements were checked. The sub-passes that checked them ran on the same model as the auditor, so the review is not independent of the authors' reasoning style. A human spot-check of a further sample is advisable.
- **Line numbers** are at 0.39.1 and will drift with the next release (TD-58).
- **Generated files were not edited.** `reference/coverage.md` and `reference/traceability.md` must be regenerated to reflect this audit. The 17 changed diagrams must be re-rendered to SVG. Neither was done here.
- **The public export** was not re-run. The claim that 0.39.1 unblocks it rests on reading `scripts/public-export.sh:509-512` and the changelog.
