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
`POST /findings/{id}/accept-risk` · `GET /findings/{id}/events`

### Risk & policy — `/risk`, `/policies`
`GET /risk/profiles` · `POST /risk/simulate` ·
`/policies/sla` · `/policies/escalation` · `/policies/assignment` ·
`/policies/sla/summary`

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
