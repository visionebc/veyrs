---
title: Architecture
purpose: Single-document narrative of how VEYRS is structured, why, and how it is deployed; the entry point to the detailed architecture set.
scope: Product architecture, bounded contexts, engines, AI, compliance and both deployment shapes at 0.39.1; diagrams, import graph, data flows and sequences are in the architecture/ folder.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/main.py, backend/veyrs/engines/risk.py, backend/veyrs/services/sla.py, backend/veyrs/services/workflow.py, backend/veyrs/services/search.py, scripts/sync-intel.sh, docker/compose.yaml, install.sh]
related: [architecture/overview.md, architecture/c4.md, architecture/dependencies.md, architecture/data-flows.md, architecture/sequences.md, architecture/deployment.md, executive/overview.md, reference/glossary.md]
---

# Architecture

VEYRS — Unified Cybersecurity Risk Management. Version 0.39.1.

> [!NOTE]
> This page is the narrative. The detailed set is in `architecture/`: [overview](architecture/overview.md) (layers, processes, patterns), [C4](architecture/c4.md), [dependencies](architecture/dependencies.md), [data flows](architecture/data-flows.md), [sequences](architecture/sequences.md) and [deployment](architecture/deployment.md). Terms: [glossary](reference/glossary.md). Corrections made at 0.39.0 are listed at the end of this page.

## 1. Executive architecture

VEYRS answers one question that no single tool in a normal security stack
answers: **which of the thousands of things wrong with our estate actually
matter this week, who owns them, and can we prove we acted?**

A scanner tells you what is broken. A CMDB tells you what you own. A ticketing
system tells you what someone is working on. A GRC tool tells you what you
claimed at audit time. None of them share a spine, so the join is done by hand,
in spreadsheets, monthly. VEYRS *is* that spine:

```
CVE → Product → Version → Asset → Criticality → Exposure → EPSS → CVSS v4 →
KEV → Threat Intel → VEYRS Risk → Team → Ticket → SLA → Escalation → Change →
Remediation → Verification → Compliance Evidence → Audit
```

Everything else in this document exists to make that chain traversable in both
directions, in one query, per tenant.

**What VEYRS replaces:** the spreadsheet that reconciles scanner output against
the asset register; the manual triage meeting; the quarterly evidence hunt
before an audit.

**What VEYRS does not replace:** the scanner itself, the CMDB of record, or the
enterprise ITSM. It integrates with all three.

## 2. Product architecture — bounded contexts

| Context | Owns | Talks to |
|---|---|---|
| Identity & tenancy | organizations, users, teams, roles, API keys | everything |
| Global intelligence | CVE, CWE, CPE, EPSS, KEV, vendor/product catalogue | correlation |
| Asset management | assets, installed products, business services | correlation, risk |
| Vulnerability management | vulnerabilities, findings, lifecycle | risk, ITSM, compliance |
| Risk | scoring engine, profiles, score history | findings, reporting |
| ITSM | tickets, ITIL type graphs, external links | findings, SLA |
| SLA & escalation | policies, due dates, ladders | findings, notifications |
| Workflow | definitions, runs, allow-listed actions | everything (as triggers) |
| Threat & document intelligence | sources, articles, documents, chunks | correlation, AI |
| Knowledge | versioned articles, revisions | search, AI |
| AI | policy, providers, capabilities, conversations | search (retrieval only) |
| Compliance | frameworks, controls, implementations, evidence, assessments | findings, assets |
| Integrations | importers, ITSM connectors | findings, tickets |
| Reporting | report specs, renderers | all read paths |

Global intelligence is **shared** across tenants — CVE-2021-44228 is the same
document for everyone. Every other context is tenant-owned.

## 3. Component architecture

```
                    nginx (:80, /api → :8000, static console)
                              │
                    ┌─────────▼──────────┐
                    │  veyrs-api         │  uvicorn × 4 workers
                    │  FastAPI           │  127.0.0.1:8000
                    └───┬────────────┬───┘
                        │            │
        ┌───────────────▼──┐    ┌────▼───────────┐
        │ PostgreSQL ≥ 15  │    │ Redis          │
        │ 93 tables,       │    │ rate-limit     │
        │ 73 FORCE RLS     │    │ windows, cache │
        └──────────────────┘    └────────────────┘
        ┌──────────────────────┐  ┌────────────────┐
        │ veyrs-intel-sync     │  │ AI providers   │
        │ veyrs-digest         │  │ Ollama (local) │
        │ systemd timer ticks  │  │ or external    │
        ├──────────────────────┤  └────────────────┘
        │ veyrs-agent          │
        │ scanner runner       │
        └──────────────────────┘
```

**There is no Celery and no message broker.** Earlier revisions of this
document drew a `veyrs-worker` running Celery for feed sync, SLA sweeps and
escalation; it never existed — `celery` is not in `requirements.txt`, nothing
in `backend/` imports it, and no such unit is installed. Background work is
done by **systemd timer ticks** (`veyrs-intel-sync.timer` and
`veyrs-digest.timer`, both hourly) calling the CLI, and the decision of *what is actually
due* is a database setting rather than a schedule in a unit file. Redis carries
rate-limit windows and cache, nothing queued.
`tests/test_docs_are_current.py` now fails if this claim comes back.

Layering rule, enforced by review and by import direction:

```
api/v1/*        HTTP, authorization decorators, schemas
  services/*    business logic, one module per context
    engines/*   scoring: CVSS calculators, risk formula
      models/*  SQLAlchemy declarative
```

`services/` never imports `api/`, and nothing in `models/` imports another
layer. The CVSS calculators (`engines/cvss/`) import only each other, which is
what lets them be validated against 4,379 official vectors with no database in
the loop. Two deviations from the picture above are real and are measured in
[architecture/overview.md](architecture/overview.md#11-real-import-direction):
`engines/risk.py` imports weight constants from `models/assets.py` and its
command-line wrapper `run_cli()` lazily imports `db`, `models` and
`services.risk` (the scoring function `evaluate()` itself is database-free);
and `security/` imports two services (`services.teams`, `services.agents`).

## 4. CVSS_ENGINE

`backend/veyrs/engines/cvss/` — `v2.py`, `v3.py`, `v4.py`, `common.py`.

Each version provides: `parse(vector)`, `score(metrics)`, `validate(vector)`,
`generate(metrics)`, `explain(vector)`. Not a lookup table, not an
approximation — the published algorithms.

- **v2** — base, temporal, environmental per the FIRST v2.0 guide.
- **v3.0 / v3.1** — base, temporal, environmental; the two revisions differ in
  the scope-changed roundup, and both are implemented separately.
- **v4.0** — the MacroVector approach: the vector maps to one of 270
  equivalence classes, the class carries a published score, and the final score
  interpolates by severity distance. The macrovector table is **converted from
  FIRST's published data**, not transcribed by hand.

**Rounding:** v4 uses half-up rounding to one decimal (`Decimal`), not Python's
default banker's rounding. This is not pedantry — it moved 43 of 1,058 official
vectors by exactly 0.1.

Validation: `tests/test_cvss_official.py` runs the full published vector corpus:
729 v2 + 2,592 v3 + 1,058 v4 = **4,379 vectors, all passing**.

## 5. EPSS_ENGINE

`services/intelligence.py` ingests the daily EPSS CSV into `epss_scores`
(current) and `epss_history` (daily snapshots, so the trend the spec asks for is
real data rather than a redrawn line). Ingestion is idempotent and watermarked
through `feed_runs`.

EPSS enters risk as *likelihood*, never as severity. A 9.8 CVSS with EPSS 0.001
and a 6.5 with EPSS 0.94 are different problems, and the engine says so.

## 6. CISA KEV

`kev_entries` carries the catalogue including `date_added`, `due_date`,
`required_action` and `known_ransomware`. KEV is not a scoring input that gets
averaged away — it applies a **floor** in the risk engine. Known exploitation is
a fact, not a probability. (The `intel.kev_added` workflow trigger is declared
but nothing fires it in 0.39.1; see §9.)

## 7. Risk engine

`engines/risk.py`. Four sub-scores (0–100), then a weighted overall, then policy
adjustments.

| Sub-score | Answers | Principal inputs |
|---|---|---|
| Technical | how bad is the flaw | CVSS (newest revision wins) |
| Exploitability | how likely is it to be used | EPSS, KEV, exploit maturity, exposure duration |
| Business | what does it threaten | asset criticality, data classification, business service, environment |
| Exposure | how reachable is it | internet exposure, attack vector, privileges/UI required, compensating controls |

Policy adjustments, all configurable without touching code:

- `kev_floor` — a KEV vulnerability can never score below this (default 75).
- `internet_kev_floor` — internet-facing **and** KEV: a higher floor still (default 90).
- `active_exploitation_floor` — a floor for findings with evidence of active exploitation (default 80).
- `age_penalty` — an open finding accrues risk: `age_penalty_per_30d` points
  (default 3) per full 30 days since detection, doubled once its SLA has
  passed, capped at `age_penalty_cap` (default 15). Ignoring something does not
  make it safer.
- `control_credit` — documented compensating controls reduce **Exposure Risk
  only**. A WAF does not unpatch a bug.

Every score carries an `explanation` listing each factor with its raw value,
weight and points, so "why is this critical?" is answered from stored data
rather than re-derived by the UI.

## 8. Risk profiles

Built-in: `balanced` (the default), `technical-security`, `executive-risk`,
`internet-exposure`, `compliance`. Each is a
weight vector plus options, stored as rows. Organizations create their own; no
deployment is needed to change how risk is calculated.

## 9. Workflow engine

`services/workflow.py`. A definition is an ordered list of steps; a step is a
named action plus a JSON config. **Every action a workflow can take is an entry
in the `ACTIONS` registry** (six: `create_ticket`, `notify`,
`transition_finding`, `tag_asset`, `set_priority`, `comment`), reviewed like any
other code. There is no `eval`, no expression language, no tenant-supplied
code. A rules engine that can run arbitrary logic inside a multi-tenant
security product is an attack surface, not a feature.

Ten triggers are declared (`models/workflow.py`). In 0.39.1 the code fires
five: `finding.created` (`services/correlation.py`), `sla.warned`,
`sla.breached`, `sla.escalated` (`services/sla.py`) and `ticket.state_changed`
(`api/v1/tickets.py`); `api/v1/tickets.py` also fires `ticket.created`, which
is not in the enum. `finding.state_changed`, `finding.risk_changed`,
`intel.kev_added`, `schedule` and `manual` are declared and documented in the
console but have no caller, so a workflow bound to one of them never runs.

## 10. SLA and escalation

Policies are data: severity/CVSS/EPSS/KEV/criticality/exposure conditions map to
a duration. Policies are evaluated in `priority` order (then creation time) and
the first match wins; if none matches, the policy flagged default applies, else
the loosest. "Most specific first" is therefore something an administrator
expresses through `priority`, not something the engine infers
(`services/sla.py:191`). Escalation ladders are per-policy lists of
`(hours, target)` pairs. `sla.breached`, `sla.escalated` and
`finding.kev_detected` notifications cannot be muted by user preference — that
is the point of them (`services/notifications.py:41`). The SLA sweep itself
(`veyrs run-sla`) runs on every intelligence tick, not on a timer of its own.

## 11. AI architecture

See [AI Security](AI_SECURITY.md) for the guarantees. Structurally:

```
api/v1/ai.py          HTTP + authorization
  capabilities.py     grounded features (facts computed by VEYRS, prose by model)
    gateway.py        THE single door: policy, sanitize, select, degrade, audit
      providers.py    OpenAI-compatible | Anthropic | Gemini | Ollama | deterministic
      guardrails.py   secret / PII / prompt-injection detection
    nlquery.py        natural language → validated structured query
```

The deterministic provider is a first-class degraded mode, not a mock: with no
model reachable, capabilities still answer from VEYRS data and label themselves
degraded.

## 12. Threat and document intelligence

Sources → articles → extracted entities → correlation → findings. Articles are
ranked by relevance to *your* inventory, weighted by source trust, so a vendor
PSIRT and a random blog are not treated alike.

Documents (PDF, DOCX, HTML, XML, CSV, JSON) are extracted, classified, mined for
entities and correlated. **Entity extraction is deterministic parser work, not a
model task** — "which CVEs does this advisory mention" must be reproducible and
complete, not probabilistic.

## 13. Compliance

Frameworks and controls are global reference data; implementations, evidence and
assessments are tenant-owned. Twelve automated signals compute evidence from live
data and report their own derivation. A passing signal lifts a control to
`partial` at most — never to `implemented`. See [Admin Guide](ADMIN_GUIDE.md).

## 14. Deployment architecture

The API is stateless, all state is in Postgres/Redis/the evidence volume,
configuration is environment-driven, and probes are separated into liveness
(`/healthz`, answers 200 from a process that has lost its database) and
readiness (`/readyz`, answers 503 when Postgres or Redis is down). Those three
properties are what make both shapes below the same system.

There are two supported shapes, and they are not interchangeable.

### 14.1 Host install — `install.sh`

One script, three distribution families (Debian/Ubuntu, openSUSE/SLES,
RHEL/Rocky/Alma), measured on five images. systemd owns the processes. The
installer sets up `veyrs-api.service`, the `veyrs-updater.path` /
`veyrs-updater.service` pair, `veyrs-intel-sync.timer` (hourly,
`integrations/systemd/`) and `veyrs-digest.timer` (`infrastructure/systemd/`);
`veyrs-agent.service` (`integrations/veyrs-agent/`) ships as a file and is
installed by hand (`install.sh` does not install it). nginx
serves the console and proxies on port 80; TLS is added to that vhost or
terminated on a reverse proxy in front of it.
Postgres and Redis may be local or remote — **in production they are remote**:
the application runs on one node and the database on another so that the
standby pair means something. See `INSTALL.md` in the repository root.

### 14.2 Container stack — `docker/compose.yaml`

Single node, one compose project, intended for **evaluation and development**.
It is not a smaller production: collapsing the application and the database
into one project is exactly the coupling the production topology exists to
avoid.

```
                    ┌─────────────────────────────────────────────┐
  operator ────────▶│ console : nginx  (the ONLY published port,   │
  127.0.0.1:8080    │           default 127.0.0.1:8080)           │
                    │  /        the console SPA + /static tokens   │
                    │  /api/    same-origin reverse proxy ────┐    │
                    └────────────────────────────────────────│────┘
                        pinned address (VEYRS_CONSOLE_IP),   │
                        because uvicorn is told to believe   │
                        X-Forwarded-For from exactly it      │
                                                             ▼
   ┌──────────────┐  service_completed_successfully  ┌──────────────────┐
   │ init         │─────────────────────────────────▶│ api : uvicorn    │
   │ one-shot     │                                  │  4 workers, 8000 │
   │ init-db +    │                                  │  NO published    │
   │ bootstrap    │                                  │  port  ◀── the   │
   │ (idempotent) │                                  │  reason XFF is   │
   │              │                                  │  trustworthy     │
   │ ONLY holder  │                                  └────────┬─────────┘
   │ of the PG    │                                           │
   │ superuser    │                    ┌──────────────────────┤
   │ credentials  │                    │                      │
   └──────┬───────┘                    ▼                      ▼
          │                    ┌───────────────┐      ┌──────────────┐
          └───────────────────▶│ postgres : 15 │      │ redis : 7    │
                               │  superuser =  │      │  no volume — │
                               │  `postgres`   │      │  rate-limit  │
                               │  app role =   │      │  windows are │
                               │  NOSUPERUSER  │      │  derivable   │
                               │  NOBYPASSRLS  │      └──────────────┘
                               │  no published port   │
                               └───────────────┘
  ── profile `workers` ─────────────────────────────────────────────────
   ┌─────────────────────────┐   ┌──────────────────────────┐
   │ intel   tick 3600s±600  │   │ digest  tick 3600s±300   │
   │ runs scripts/           │   │ runs scripts/            │
   │   sync-intel.sh         │   │   send-digest.sh         │
   │ = veyrs-intel-sync.timer│   │ = veyrs-digest.timer     │
   └─────────────────────────┘   └──────────────────────────┘
  ── profile `agent` ───────────────────────────────────────────────────
   ┌──────────────────────────────────────────────────────────────────┐
   │ agent   nuclei 3.11.1 (pinned + sha256) · corpus in a volume     │
   │ = veyrs-agent.service · deny-by-default allowlist · no NET_RAW   │
   └──────────────────────────────────────────────────────────────────┘

  volumes:  veyrs-pgdata (the installation) · veyrs-var (update staging; the
            backend writes no evidence or reports to disk) ·
            veyrs-agent-home (nuclei config + ~84 MB template corpus)
```

Five decisions in that diagram are load-bearing:

1. **The application role is not a PostgreSQL superuser.** `POSTGRES_USER=veyrs`
   — the obvious thing — makes it one, and a superuser **bypasses row level
   security unconditionally**. 73 of the 93 tables carry `FORCE ROW LEVEL
   SECURITY`; under a superuser every policy silently stops applying. Nothing
   errors, nothing logs, `\d` still lists them. The superuser is `postgres` and
   `initdb.d/10-app-role.sh` creates the application role `NOSUPERUSER
   NOCREATEDB NOCREATEROLE NOBYPASSRLS`, owner of its own databases.
2. **Only `console` publishes a port.** That is what makes
   `VEYRS_FORWARDED_ALLOW_IPS` (the console's address) meaningful: with the API
   port open, any caller could claim any source address and mint a fresh
   rate-limit identity per request, turning the credential-stuffing limit on
   `/auth/*` into decoration. The application reads only `request.client.host`,
   never `X-Forwarded-For`.
3. **The superuser credentials reach `init` and nothing else.** A long-lived,
   network-reachable process holding the credentials that bypass tenant
   isolation is the worst thing this stack could hand an attacker who finds an
   SSRF.
4. **The background services share the host's scripts, not a copy of them.**
   `intel` runs `scripts/sync-intel.sh` itself. The feed order (CWE names what
   NVD creates; EPSS skips CVEs it has never seen; KEV is the last word) has
   exactly one home.
5. **A tick is not a schedule.** Both loops, and both host timers, ask hourly;
   the cadence lives in
   `organizations.settings.intel_schedule` and `.digest`, and the console edits
   it. An hour written into a unit file or a compose command would make a
   setting the console displays and the machine ignores.

### 14.3 What the container stack does not do

`workers` and `agent` are **off by default**, and the trade is explicit:

| Absent | Consequence |
|---|---|
| `intel` | CVE/EPSS/KEV data never refreshes and SLA deadlines stop elapsing. The platform keeps scoring, with full confidence, against intelligence frozen on install day. Nothing in the console shows this. |
| `digest` | Notification rows are still written; nobody is mailed. |
| `agent` | No scans originate here. Jobs queue and their leases are reaped. |

`veyrs-docker.sh status` prints that table from the machine itself, filled in
from what is actually running — an operator should not have to recall which
flags they passed to `up` three weeks ago.

### 14.4 Kubernetes

Designed for it, not shipped for it. The API is stateless and probe-separated;
what is missing is a chart, a secret story beyond a 0600 `.env`, and an answer
for the evidence volume. See §"Kubernetes readiness" in
[Deployment](DEPLOYMENT.md).

See [Deployment](DEPLOYMENT.md), and `INSTALL.md` in the repository root.

## 15. Technology choices

| Layer | Choice | Why |
|---|---|---|
| API | FastAPI + Pydantic v2 | Schema-first, OpenAPI for free, and validation at the boundary |
| ORM | SQLAlchemy 2.0 | Postgres RLS integration, explicit sessions |
| Database | PostgreSQL ≥ 15 | JSONB, UUID, and **Row Level Security** — the second tenant barrier |
| Cache | Redis | Rate-limit windows and short-lived cache. **Not a queue** — nothing is brokered |
| Background work | systemd timers (host) / tick loops (containers) | Feed sync, SLA sweeps, escalation, digest. A CLI invocation on a tick, not a worker pool: the cadence is a tenant setting, so the thing that fires has no schedule of its own |
| Containers | Compose profiles | The scanner and the feed sync are opt-in, because one sends unsolicited traffic and the other starts a multi-hour NVD pull |
| Search | PostgreSQL FTS | Lexical search must never depend on a second cluster being up |
| Vector | None shipped | `services/search.py` defines a `VectorBackend` interface with a null default; no Qdrant client exists in the code, so search is lexical only. Qdrant was the intended optional backend |
| Docs site | ~500-line stdlib generator (`site/build.py`) | A security product's docs host should not pull an npm dependency tree |

**Deviations from the requested stack, and why:** the console is a static
single-page bundle (`frontend/console/`, plain JavaScript, no build step)
served by nginx, not a framework application. There is no OpenSearch, and no
vector index ships, because an on-premise install must not lose search when a
second cluster is down.

## Related

- [Database](DATABASE.md) · [API](API.md) · [Security](SECURITY.md)
- [Threat Model](THREAT_MODEL.md) · [AI Security](AI_SECURITY.md)


## Public surfaces

A typical installation exposes four names, all resolving to the front reverse
proxy, which terminates TLS with a wildcard certificate (`*.example.com`) and
chooses a backend:

| Role | Serves | Backed by |
|---|---|---|
| Console and API (one name per application node) | Management console + API | the upstream containing both application nodes |
| Product site | Product site and user manual (static) | the same upstream |
| Docs Center | Technical documentation (static, generated from `docs/`) | application node, local files |
| Retired alias | A permanent redirect to the current console name | proxy |

**Failover never touches DNS**, so no bookmark and no TTL is ever in the path of
a recovery. The product site is served from **both application nodes** rather
than a dedicated container: a handful of static HTML files do not justify a
machine to patch, a certificate to track and a new single point of failure.
Served from the existing upstream, the site inherits the nodes' failover for
free. (Verified on the reference installation in August 2026: 15 of 15
requests answered with one node stopped; concrete host names are in the
internal documentation, not here.)

`site/build.py` renders the documentation site from `docs/*.md`;
`site/web/build_web.py` renders the product site and imports the former's
Markdown renderer instead of copying it, so the two cannot drift into
rendering the same file differently.

## Corrections made at 0.39.0

| Earlier text | Code says | Fixed |
|---|---|---|
| `engines/` never imports `services/`; engines are "pure functions, no database" | `engines/risk.py` imports `models.assets` and its `run_cli()` imports `db`, `models`, `services.risk`; `evaluate()` is pure | yes (§3) |
| Policies "most specific first" | Evaluated by `priority`, then creation time | yes (§10) |
| Qdrant optional vector search | No vector backend in code | yes (§15) |
| `veyrs-var` holds "evidence, reports" | Only update staging is written to disk | yes (§14.2) |
| Host intel timer fires "only once a day" | `OnCalendar=hourly` | yes (§14.2) |
| Static address of the console shown as a literal | It is the default of `VEYRS_CONSOLE_IP`; literal removed | yes (§14.2) |
| Version 0.35.1 | 0.39.1 | yes |
| Workflow triggers implied to all be live | Five of ten declared triggers have no caller | documented (§9), not a doc defect |
