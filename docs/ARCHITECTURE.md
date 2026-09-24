# Architecture

VEYRS — Unified Cybersecurity Risk Management. Version 0.9.0.

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
                    nginx (TLS, /api → :8000, static docs)
                              │
                    ┌─────────▼──────────┐
                    │  veyrs-api         │  uvicorn × 4 workers
                    │  FastAPI           │  127.0.0.1:8000
                    └───┬────────────┬───┘
                        │            │
        ┌───────────────▼──┐    ┌────▼───────────┐
        │ PostgreSQL 15    │    │ Redis          │
        │ 87 tables,       │    │ rate-limit     │
        │ 70 FORCE RLS     │    │ windows, cache │
        └──────────────────┘    └────────────────┘
        ┌──────────────────────┐  ┌────────────────┐
        │ veyrs-intel-sync     │  │ AI providers   │
        │ veyrs-digest         │  │ Ollama (local) │
        │ hourly systemd ticks │  │ or external    │
        ├──────────────────────┤  └────────────────┘
        │ veyrs-agent          │
        │ scanner runner       │
        └──────────────────────┘
```

**There is no Celery and no message broker.** Earlier revisions of this
document drew a `veyrs-worker` running Celery for feed sync, SLA sweeps and
escalation; it never existed — `celery` is not in `requirements.txt`, nothing
in `backend/` imports it, and no such unit is installed. Background work is
done by **hourly systemd ticks** (`veyrs-intel-sync.timer`,
`veyrs-digest.timer`) calling the CLI, and the decision of *what is actually
due* is a database setting rather than a schedule in a unit file. Redis carries
rate-limit windows and cache, nothing queued.
`tests/test_docs_are_current.py` now fails if this claim comes back.

Layering rule, enforced by review and by import direction:

```
api/v1/*        HTTP, authorization decorators, schemas
  services/*    business logic, one module per context
    engines/*   pure functions: CVSS, risk. No database, no I/O.
      models/*  SQLAlchemy declarative
```

`engines/` never imports `services/`; `services/` never imports `api/`. That is
what lets the CVSS engine be validated against 4,382 official vectors with no
database in the loop.

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
729 v2 + 2,592 v3 + 1,058 v4 = **4,382 vectors, all passing**.

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
a fact, not a probability.

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

- `kev_floor` — a KEV vulnerability can never score below this.
- `internet_kev_floor` — internet-facing **and** KEV: a higher floor still.
- `age_penalty` — a finding open past its SLA accrues risk; ignoring something
  does not make it safer.
- `control_credit` — documented compensating controls reduce **Exposure Risk
  only**. A WAF does not unpatch a bug.

Every score carries an `explanation` listing each factor with its raw value,
weight and points, so "why is this critical?" is answered from stored data
rather than re-derived by the UI.

## 8. Risk profiles

Built-in: `technical`, `executive`, `internet-exposure`, `compliance`. Each is a
weight vector plus options, stored as rows. Organizations create their own; no
deployment is needed to change how risk is calculated.

## 9. Workflow engine

`services/workflow.py`. A definition is an ordered list of steps; a step is a
named action plus a JSON config. **Every action a workflow can take is an entry
in the `ACTIONS` registry**, reviewed like any other code. There is no `eval`,
no expression language, no tenant-supplied code. A rules engine that can run
arbitrary logic inside a multi-tenant security product is an attack surface, not
a feature.

## 10. SLA and escalation

Policies are data: severity/CVSS/EPSS/KEV/criticality/exposure conditions map to
a duration. The first matching policy wins, most specific first. Escalation
ladders are per-policy lists of `(hours, target)` pairs. Escalation
notifications cannot be muted by user preference — that is the point of them.

## 11. AI architecture

See [AI Security](/AI_SECURITY.html) for the guarantees. Structurally:

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
`partial` at most — never to `implemented`. See [Admin Guide](/ADMIN_GUIDE.html).

## 14. Deployment architecture

The API is stateless, all state is in Postgres/Redis/the evidence volume,
configuration is environment-driven, and probes are separated into liveness
(`/healthz`, answers 200 from a process that has lost its database) and
readiness (`/readyz`, answers 503 when Postgres or Redis is down). Those three
properties are what make both shapes below the same system.

There are two supported shapes, and they are not interchangeable.

### 14.1 Host install — `install.sh`

One script, three distribution families (Debian/Ubuntu, openSUSE/SLES,
RHEL/Rocky/Alma), measured on five images. systemd owns the processes:
`veyrs-api.service`, `veyrs-agent.service`, and the two hourly ticks
`veyrs-intel-sync.timer` and `veyrs-digest.timer`. nginx terminates and proxies.
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
                        static IP 172.29.0.10 — pinned,      │
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

  volumes:  veyrs-pgdata (the installation) · veyrs-var (evidence, reports)
            veyrs-agent-home (nuclei config + ~84 MB template corpus)
```

Five decisions in that diagram are load-bearing:

1. **The application role is not a PostgreSQL superuser.** `POSTGRES_USER=veyrs`
   — the obvious thing — makes it one, and a superuser **bypasses row level
   security unconditionally**. 70 of the 87 tables carry `FORCE ROW LEVEL
   SECURITY`; under a superuser every policy silently stops applying. Nothing
   errors, nothing logs, `\d` still lists them. The superuser is `postgres` and
   `initdb.d/10-app-role.sh` creates the application role `NOSUPERUSER
   NOCREATEDB NOCREATEROLE NOBYPASSRLS`, owner of its own databases.
2. **Only `console` publishes a port.** That is what makes
   `VEYRS_TRUST_PROXY_HEADERS=true` safe: with the API port open, any caller
   could set `X-Forwarded-For` and mint a fresh rate-limit identity per
   request, turning the credential-stuffing limit on `/auth/*` into decoration.
3. **The superuser credentials reach `init` and nothing else.** A long-lived,
   network-reachable process holding the credentials that bypass tenant
   isolation is the worst thing this stack could hand an attacker who finds an
   SSRF.
4. **The background services share the host's scripts, not a copy of them.**
   `intel` runs `scripts/sync-intel.sh` itself. The feed order (CWE names what
   NVD creates; EPSS skips CVEs it has never seen; KEV is the last word) has
   exactly one home.
5. **A tick is not a schedule.** Both loops ask hourly; the cadence lives in
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
[Deployment](/DEPLOYMENT.html).

See [Deployment](/DEPLOYMENT.html), and `INSTALL.md` in the repository root.

## 15. Technology choices

| Layer | Choice | Why |
|---|---|---|
| API | FastAPI + Pydantic v2 | Schema-first, OpenAPI for free, and validation at the boundary |
| ORM | SQLAlchemy 2.0 | Postgres RLS integration, explicit sessions |
| Database | PostgreSQL 15 | JSONB, UUID, and **Row Level Security** — the second tenant barrier |
| Cache | Redis | Rate-limit windows and short-lived cache. **Not a queue** — nothing is brokered |
| Background work | systemd timers (host) / tick loops (containers) | Feed sync, SLA sweeps, escalation, digest. A CLI invocation on a tick, not a worker pool: the cadence is a tenant setting, so the thing that fires has no schedule of its own |
| Containers | Compose profiles | The scanner and the feed sync are opt-in, because one sends unsolicited traffic and the other starts a multi-hour NVD pull |
| Search | PostgreSQL FTS, OpenSearch optional | Lexical search must never depend on a second cluster being up |
| Vector | Qdrant (optional) | Semantic search degrades to lexical if unavailable |
| Docs site | 250-line stdlib generator | A security product's docs host should not pull an npm dependency tree |

**Deviations from the requested stack, and why:** the frontend is not yet built;
the API and its OpenAPI schema are the current interface. OpenSearch and Qdrant
are optional rather than required, because an on-premise install must not lose
search when a second cluster is down.

## Related

- [Database](/DATABASE.html) · [API](/API.html) · [Security](/SECURITY.html)
- [Threat Model](/THREAT_MODEL.html) · [AI Security](/AI_SECURITY.html)


## Public surfaces (2026-08-17)

| Name | Serves | Backed by |
|---|---|---|
| `veyrs-app-1` / `-a2` | Management console + API | `upstream veyrs_app` (both app nodes) |
| `veyrs-web-a` | Product site and user manual (static) | the same upstream |
| `veyrs-a` | Technical documentation (static, generated from `docs/`) | app node local |
| `veyrs-app` | **Retired.** 301 to `veyrs-app-1`. | - |

All four resolve to the fleet proxy at 10.50.0.10, which terminates TLS with the
`*.example.com` wildcard and chooses a backend. **Failover never touches
DNS**, so no bookmark and no TTL is ever in the path of a recovery.

The product site is served from **both application nodes** rather than a
dedicated container. Six static HTML files do not justify a machine to patch, a
certificate to track and a new single point of failure; served from the existing
upstream, the site inherits the nodes' failover for free (verified: 15 of 15
requests answered with one node stopped).

`site/build.py` renders the documentation site from `docs/*.md`;
`site/web/build_web.py` renders the product site and imports the former's
Markdown renderer rather than copying it, so the two cannot drift into
rendering the same file differently.
