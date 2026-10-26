# API

Base URL: `https://veyrs-docs.example.com/api/v1`
OpenAPI: `GET /api/v1/openapi.json` · Interactive: `/docs` (non-production only)

127 routes. Every one authorizes server-side.

## Authentication

Two credentials, same authorization model.

```bash
# 1. Bearer token (humans)
curl -X POST https://veyrs-docs.example.com/api/v1/auth/login \
  -H 'Content-Type: application/json' \
  -d '{"email":"you@example.com","password":"...","organization":"acme"}'
# → {"access_token":"...","refresh_token":"...","expires_in":1800}

curl https://veyrs-docs.example.com/api/v1/findings \
  -H "Authorization: Bearer $TOKEN"

# 2. API key (machines)
curl https://veyrs-docs.example.com/api/v1/findings \
  -H "X-API-Key: veyrs_<prefix>_<secret>"
```

`organization` is required only when the email exists in more than one tenant.
Access tokens live 30 minutes; refresh tokens rotate on use.

**Permissions are re-read from the database on every request**, not trusted from
the token, so a revoked role takes effect immediately rather than at expiry.

## Authorization

`resource:action` where action ∈ `read | write | delete | admin`. Resources:
`organization, user, team, role, apikey, audit, asset, product, vulnerability,
finding, cve, risk, riskprofile, ticket, sla, escalation, workflow, intel,
document, knowledge, compliance, evidence, report, importer, notification, ai,
settings`. Wildcards `*:*` and `resource:*` are accepted in role definitions.

Ten built-in roles: `org-admin, security-manager, security-engineer, team-lead,
asset-owner, compliance-officer, executive, auditor, service-account, read-only`.

A permission string not in the registry raises at **import time**, so a typo in a
route decorator can never silently authorize everyone.

## Conventions

**Pagination.** Collections accept `?page=` (1-based) and `?size=`, and return:

```json
{"items": [...], "total": 412, "limit": 50, "offset": 0, "page": 1, "size": 50}
```

Both representations are returned so clients need not convert.

**Errors.**

```json
{"error": "validation_error", "detail": [...], "correlation_id": "..."}
```

Validation errors echo the field and the message but **never the submitted
value** — request bodies here routinely carry credentials and vulnerability
detail.

**Correlation.** Send `X-Correlation-ID` and it is echoed on the response and
attached to every log line for that request. Absent, one is generated.

**Rate limits.** `X-RateLimit-Limit` / `X-RateLimit-Remaining` on every
response; `429` with `Retry-After` when exceeded. `/auth/*` has a separate,
much stricter per-IP budget.

**Cross-tenant reads return `404`, not `403`** — existence itself is not
disclosed.

## Route map

### Authentication — `/auth`
`POST /login` · `POST /refresh` · `POST /logout` · `GET /me` ·
`POST /password` · MFA enrolment

### Administration
`/users` · `/teams` · `/departments` · `/roles` · `/permissions` ·
`/api-keys` · `/organization` · `/audit`

`GET /secret-storage` (`settings:admin`, refused to team-scoped identities) —
where stored credentials live: `mode` (`local` | `mirror` | `vault`), vault
`addr`/`mount`/`auth_method`, `reachable` / `sealed` / `auth_ok`, this
organization's counts per column by storage kind, `on_host`, `next_step` and the
CLI `commands`. Never a token, secret-id or value. Read-only by design: there is
no write method; migration is `veyrs secrets migrate` on the host.

`GET /admin/updates` (installed vs latest release, signed, install mode,
`can_apply` + reason, updater history; `?refresh=true` skips the one-hour cache) ·
`POST /admin/updates/apply` (`202`: queues the latest signed release for the
root updater; native installs only, `409` with the reason otherwise). Both are
**platform administrator** only (`is_superuser`), never an API key; the apply is
audited as `software.update.requested`.

### CVSS — `/cvss`
`POST /score` (any version, auto-detected from the vector) ·
`POST /explain` · `POST /compare` · `GET /versions` · `GET /severity`

```bash
curl -X POST .../api/v1/cvss/score -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' \
  -d '{"vector":"CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N"}'
# → {"version":"4.0","base_score":9.3,"base_severity":"Critical",...}
```

### Intelligence — `/intel`
`GET /cve` · `GET /cve/{id}` · `GET /kev` · `GET /news` · `GET /sources` ·
`GET /feeds/runs` · `GET /health` · `POST /sync/{feed}`

### Assets — `/assets`
`GET|POST /assets` · `GET|PATCH|DELETE /assets/{id}` · `/assets/services` ·
`POST /assets/{id}/products`

### Vulnerabilities & findings
`/vulnerabilities` · `/findings` · `POST /findings/{id}/transition` ·
`POST /findings/{id}/accept-risk` · `GET /findings/{id}/events` ·
`GET /findings/{id}/fix-plan` · `GET /assets/{id}/fix-plan`

**Fix plan.** Deterministic, computed per request, stored nowhere. For the
installed product behind a finding (or every installed product on an asset
with open findings) it returns the installed version, per-finding fix
information (`fix_status`: `known` / `after` / `unknown`), every candidate
version newer than the installed one with the findings it fixes,
`best_single_target` (the lowest version fixing all findings with a known fix,
or `null` with `best_single_target_reason`), `nearest_on_branch`, the step
class (`patch` / `minor` / `major` / `unknown`), the upgrade path with hops and
prerequisites from the tenant's upgrade-path rules, `no_fix_known`, a
`coverage` block and `computed_at`. Requires `finding:read` (plus `asset:read`
on the asset route); team scope applies to the row (out of scope answers 404,
like the detail routes) **and** to the findings the plan lists. A finding with
no installed product answers `{"available": false, "reason": ...}`.

```bash
curl .../api/v1/findings/$FID/fix-plan -H "Authorization: Bearer $T"
# → {"installed_version":"1.2.3","best_single_target":{"version":"2.0.1","step":"major",
#    "fixes":[...],"path":{"hops":[...],"path_required":true}}, "coverage":{"statement":
#    "2 of 3 open findings have a known fixed version; computed from 3 CPE ranges and 0 advisories"},...}
```

`GET /findings/{id}/attribution` · `GET /findings/changes`

**Attribution** (`finding:read`, tenant- and team-scoped like the finding
detail; 404 when the finding is not visible). `GET /findings/{id}/attribution`
returns every state transition, oldest first:

```json
{"finding_id": "…", "state": "new", "detail_recorded_since": "0.33.0",
 "transitions": [
   {"at": "…", "from": "new", "to": "remediated", "kind": "closed",
    "cause": "reimport_absence", "cause_label": "Absent from re-import",
    "actor": {"kind": "system", "label": "importer", "component": "re-import reconciliation"},
    "evidence": {"sentence": "Closed after 2 consecutive runs of scan test 'Weekly external' (nessus) did not report it (import runs 1a2b3c4d, 5e6f7a8b); …",
                 "ids": {"scan_test_id": "…", "import_run_ids": ["…", "…"]}},
    "missing": []},
   {"at": "…", "from": "remediated", "to": "new", "kind": "reopened",
    "cause": "rescan_seen_again", "…": "…",
    "regression": {"closed_at": "…", "seconds_after_closure": 172800,
                   "seen_again_by": {"scanner": "nessus", "import_run_id": "…"},
                   "inventory_changes": [{"product": "…", "old_version": "1.2.3", "new_version": "1.2.4", "detected_by": "agent:probe-1"}],
                   "sentence": "…"}}],
 "last_closed": {…}, "last_reopened": {…}}
```

`kind` is `closed` (entered remediated / verification / a closed state),
`reopened` (left it) or `progressed`. `cause` is one of `operator`,
`verification_passed`, `verification_failed`, `reimport_absence`,
`rescan_seen_again`, `ticket_resolved`, `ticket_closed_external`,
`ticket_reopened_external`, `workflow_rule`, `acceptance_approved`,
`acceptance_expired`, `acceptance_revoked`, `inventory_version_changed`,
`correlation_rescan`, `sla_policy`, `assignment_rule`, `unknown`.
`ticket_reopened_external` and `sla_policy` are reserved: no code path
produces those transitions today. `unknown` always comes with `missing`
naming the fact that was not recorded. Nothing is inferred and no AI is used.

`GET /findings/changes?since=<ISO>&kind=closed|reopened&cause=<cause>&page=&size=`
lists closes and reopens across the caller's visible estate, newest first
(default window: 30 days). Each item carries the finding, asset, from/to,
`cause`, `actor` and the evidence sentence. The cause filter is applied after
classification over at most 5,000 events per request; `truncated: true` says
the window held more. An unknown `cause` is a 422.

### Risk & policy — `/risk`, `/policies`
`GET /risk/profiles` · `POST /risk/simulate` ·
`/policies/sla` · `/policies/escalation` · `/policies/assignment` ·
`/policies/sla/summary` · `GET|POST /upgrade-path-rules` ·
`PATCH|DELETE /upgrade-path-rules/{id}`

Upgrade-path rules are operator-maintained vendor requirements the fix plan
applies (`vendor`, `product`, `from_start_including|excluding`,
`from_end_including|excluding`, `via_version`, `prerequisite`, `source_url`,
`is_enabled`). Reads need `finding:read`; writes need `sla:write` and an
estate-wide grant (a team-scoped identity gets 403) and are audited as
`upgrade_path_rule.create|update|delete`. Versions and ranges are validated
with the same comparator the plan uses: an empty range, two start (or two end)
bounds, a non-version, a via version at or below the range start, a rule with
neither via version nor prerequisite, or a non-http(s) source URL is a 422.

### Tickets — `/tickets`
`GET|POST /tickets` · `POST /tickets/{id}/transition` · `/tickets/{id}/comments` ·
`GET /tickets-metrics`

### Knowledge & search
`/documents` (upload, extract, correlate) · `/knowledge` · `/search` ·
`/search/semantic`

### AI — `/ai`
`GET|PUT /policy` · `/providers` · `GET /capabilities` ·
`POST /cve/{id}/analysis` · `POST /findings/{id}/explain` ·
`POST /findings/{id}/remediation` · `POST /findings/{id}/ticket-draft` ·
`POST /findings/{id}/suggest-team` · `POST /threat-summary` ·
`POST /search` (natural language) · `GET /search/grammar` · `POST /ask` ·
`/conversations` · `GET /audit` · `POST /scan`

### Compliance — `/compliance`
`GET|POST /frameworks` · `GET /frameworks/{id}/controls` ·
`POST /frameworks/{id}/controls:import` · `GET /frameworks/{id}/coverage` ·
`POST /frameworks/{id}/refresh-signals` · `GET /signals` ·
`PUT /controls/{id}/implementation` · `GET /controls/{id}/chain` ·
`/controls/{id}/links` · `/controls/{id}/evidence` · `/evidence` ·
`/assessments` · `POST /assessments/{id}/complete`

### Integrations — `/integrations`
**Push (upload):** `GET /importers` · `POST /imports` (multipart) ·
`GET /imports[/{id}]`
**Pull (scanner connectors):** `GET /scanner-drivers` · `/scanners` ·
`PATCH|DELETE /scanners/{id}` · `GET /scanners/{id}/scans` ·
`POST /scanners/{id}/test` · `POST /scanners/{id}/sync`
**ITSM:** `/connectors` · `POST /connectors/{id}/push/{ticket_id}` ·
`GET /tickets/{id}/links`

```bash
curl -X POST .../api/v1/integrations/imports -H "Authorization: Bearer $T" \
  -F file=@scan.nessus -F source=nessus -F create_assets=false
```

A pulled export goes through the **same parser** as an uploaded one, so a
connector cannot introduce a second deduplication rule. Connectors are created
**disabled**, and an empty `allowed_scans` means **inert**, not "every scan" —
a sync names the scans it may pull or it does nothing. A `scan_ids` argument
outside that list is rejected, never filtered. `close_absent` requires an
`engagement_id`: absence-based closure outside a scope marks hosts the scan
never looked at as remediated. Credentials are Fernet-encrypted and no response
schema carries them; `credentials_set` reports only that they exist.

```bash
curl -X POST .../api/v1/integrations/scanners -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' -d '{
    "slug":"nessus-lab", "name":"Nessus (lab)", "driver":"nessus",
    "base_url":"https://nessus.example:8834",
    "credentials":{"access_key":"...","secret_key":"..."}}'
curl -X POST .../api/v1/integrations/scanners/$ID/sync -H "Authorization: Bearer $T" \
  -H 'Content-Type: application/json' -d '{"dry_run":true}'
```

### Dashboards & reports
`GET /dashboard/executive|technical|sla|trends` · `GET /reports` ·
`GET /reports/{slug}` · `GET /reports/{slug}/export?format=json|csv|xlsx|pdf`

CSV and XLSX exports neutralise any cell that starts with `=`, `+`, `-`, `@`,
tab or carriage return by prefixing an apostrophe (formula injection,
CWE-1236). Scanner-supplied titles reach these files, so the guard sits in the
shared renderer and covers every export.

### Report builder
Ad-hoc tabular reports. The client sends a **JSON spec**, never SQL; the server
compiles it from a curated catalog, and any entity, field, operator, aggregate
or key the catalog does not offer is a `422` naming it.

| Method | Path | Notes |
|---|---|---|
| `GET` | `/report-builder/catalog` | entities, typed fields (enum values included), operators per type, aggregates, limits; `available` per entity for this caller; `can_share` |
| `POST` | `/report-builder/run` | body: spec. Returns `columns`, `rows`, `row_count`, `truncated`, `limit`, `provenance` |
| `POST` | `/report-builder/export?format=csv\|xlsx\|json` | body: spec. Same renderer and provenance header as the fixed reports; audited as `report.exported` |
| `GET` | `/report-builder/queries` | my saved reports plus the shared ones; each carries `valid` / `problem` against today's catalog |
| `POST` | `/report-builder/queries` | `{name, description?, spec, is_shared?}` |
| `GET` / `PATCH` / `DELETE` | `/report-builder/queries/{id}` | read: own or shared. Write: owner only (`404` otherwise) |
| `POST` | `/report-builder/queries/{id}/run` · `/export?format=` | re-validates the stored spec; a field removed since it was saved is a `422`, not a `500` |

```json
{
  "entity": "findings",
  "filters": [
    {"field": "is_open", "op": "eq", "value": true},
    {"field": "severity", "op": "eq", "value": "critical"}
  ],
  "group_by": ["asset.business_service", "owning_team.name"],
  "aggregates": [{"fn": "count"}, {"fn": "avg", "field": "age_days"}],
  "sort": [{"field": "count", "dir": "desc"}],
  "limit": 200
}
```

* **Entities**: `findings`, `assets`, `vulnerabilities` (the tenant view),
  `tickets`, `risks` (the risk register). Related fields use a dotted key
  (`asset.criticality`, `owning_team.name`, `vulnerability.cve_id`). Joins are
  many-to-one only, so a related field never multiplies rows.
* **Operators** by type: string `eq ne in not_in contains not_contains
  starts_with`; number `eq ne gt gte lt lte between in`; date `gt gte lt lte
  between last_days older_than_days next_days`; bool `eq`; enum `eq ne in
  not_in`; every type also `is_null not_null`. `contains` is a case-insensitive
  match with `%` and `_` escaped, so a value matches itself literally.
* **Grouped reports**: up to 3 `group_by` fields and up to 6 aggregates
  (`count`, `count_distinct`, `avg`, `sum`, `min`, `max`); `columns` must then
  be empty and `sort` names a group-by field or an aggregate key (`count`,
  `avg:age_days`). Date and derived count fields are not groupable.
* **Limits**: 25 columns, 20 filters, 100 values per `in`, 3 sort keys; at most
  5 000 rows on `run` and 50 000 on `export` (`truncated` says when the cap
  bit); each statement runs under `SET LOCAL statement_timeout = 20s` and a
  report that hits it is a `422` asking for narrower filters.
* **Authorization**: every route needs `report:read`; running or exporting an
  entity also needs that entity's own read permission (`finding:read`,
  `asset:read`, `vulnerability:read`, `ticket:read`, `riskregister:read`).
  Team scope is **applied**, as on the list routes: a restricted operator's
  rows, group counts and files cover their slice, and the provenance `scope`
  line says so. Saving a private report needs `report:read`; sharing it with
  the organization needs `report:write`. API keys may run and export but not
  save.

### Operations (unauthenticated)
`GET /healthz` (liveness) · `GET /readyz` (readiness: DB + Redis) ·
`GET /metrics` (Prometheus; LAN-restricted at the proxy)

## Natural-language search

`POST /ai/search` translates a question into a **validated structured query**
against a closed grammar — never SQL. `GET /ai/search/grammar` returns the
complete allowed field set, so the interpretation is inspectable and editable.

```json
{"question": "critical KEV findings on internet-facing systems with EPSS above 0.5"}
```

returns the rows **and** the query it ran, with a plain-English restatement.
