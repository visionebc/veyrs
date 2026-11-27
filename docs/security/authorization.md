---
title: Authorization
purpose: Explain how VEYRS decides what an authenticated caller may do, how tenants and teams are isolated, and which routes are public or authenticated-without-a-permission.
scope: RBAC model, permission evaluation, built-in roles summary, row level security as a control, team scope, platform administrators, public and permissionless routes; the full role by permission matrix is generated in reference/permissions.md.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/security/permissions.py, backend/veyrs/security/deps.py, backend/veyrs/security/scope.py, backend/veyrs/db.py, backend/veyrs/cli.py, backend/veyrs/api/v1/admin.py, backend/veyrs/api/v1/updates.py, backend/veyrs/services/search.py, tests/test_phase10_hardening.py, extract/routes.json]
related: [reference/permissions.md, security/authentication.md, security/security-architecture.md, security/risk-register.md, DATABASE.md]
---

# Authorization

> [!NOTE]
> The full role by permission matrix and the permission list per route are generated from the code in [the permissions reference](../reference/permissions.md). This page explains the *model* and judges the exceptions.

## 1. Model

A **permission** is the string `resource:action`.

- **29 resources**: `organization`, `user`, `team`, `role`, `apikey`, `audit`, `asset`, `product`, `vulnerability`, `finding`, `cve`, `risk`, `riskprofile`, `riskregister`, `ticket`, `sla`, `escalation`, `workflow`, `intel`, `document`, `knowledge`, `compliance`, `evidence`, `report`, `importer`, `notification`, `ai`, `settings`, `agent` (`backend/veyrs/security/permissions.py:9-16`).
- **4 actions**: `read`, `write`, `delete`, `admin` (`permissions.py:17`). Actions are independent: `write` does not imply `read`, and `admin` does not imply `write`. The built-in roles grant `read` alongside `write` through the `_write` helper (`permissions.py:50-51`), but a custom role can contain either alone.
- **116 concrete permissions** (29 x 4), plus the wildcards `resource:*` (all four actions on one resource) and `*:*` (everything) (`permissions.py:18-23`).

A **role** is a named list of permission strings. A user holds zero or more roles through `user_roles` rows; each row may carry a `team_id` (see [section 5](#5-team-scope)) and an `origin` (`manual` or `directory`). Built-in roles have `organization_id = NULL` and are shared by all tenants; custom roles belong to one organization and are managed through `/api/v1/admin/roles` (`backend/veyrs/api/v1/admin.py:936-981`).

## 2. How a request is authorized

1. `get_principal` authenticates the credential ([authentication.md](authentication.md)) and builds a frozen `Principal` (`backend/veyrs/security/deps.py:210-236,339-357`).
2. For a user, `effective_permissions` takes the **union** of `Role.permissions` over every role granted to the user and expands wildcards with `permissions.expand` (`deps.py:257-277`, `permissions.py:32-43`). For an API key, the key's `scopes` are expanded instead (`deps.py:332`).
3. The tenant is bound for the request (`set_tenant`), then the team scope is checked against the route's OpenAPI tag (`deps.py:352-356`, `scope.py:228-244`).
4. The route's dependency `require("resource:action", ...)` returns 403 `missing permission: ...` unless **all** listed permissions are held (`deps.py:363-378`). `Principal.can()` returns true for any permission when `is_superuser` is set (`deps.py:228-229`).

Properties worth knowing:

- **Typos fail at import, not at request time.** `require()` raises `ValueError` for an unknown permission string, and the built-in roles are validated when the module loads (`deps.py:369-371`, `permissions.py:171-179`).
- **The JWT is not the source of truth.** The `perms` claim is ignored; permissions are re-read per request, so a revoked role takes effect on the next call (`deps.py:301-313`).
- **Only valid permissions count.** `expand()` silently drops strings that are not valid permissions, so a malformed entry in a custom role grants nothing (`permissions.py:38-43`).
- **No deny rules.** The model is purely additive. There is no way to subtract a permission that another role grants.
- **Cross-tenant objects look absent.** Lookups run on a tenant-bound session, so another tenant's object answers 404, not 403 (for example `admin.py:964-965`).

### Privilege-escalation guards

| Action | Guard | Source |
|---|---|---|
| Assign roles to a user | A caller who is not a platform administrator and lacks `role:admin` cannot grant a role containing permissions they do not hold | `backend/veyrs/api/v1/admin.py:636-646` |
| Create or edit a custom role | Requires `role:admin`; permission strings validated; built-in roles are immutable | `admin.py:936-981` |
| Issue an API key | Scopes must be a subset of the creator's permissions unless the creator is a platform administrator | `admin.py:1005-1011` |
| Directory-derived roles | Reconciled at login; manual grants are never removed by a directory sync | `backend/veyrs/api/v1/auth.py:117-158` |

`role:admin` can therefore create a custom role containing `*:*` and assign it. Treat `role:admin` as equivalent to organization administrator.

## 3. Built-in roles

Ten roles are seeded by `init-db` from `BUILTIN_ROLES` (`permissions.py:57-168`; seeding in `backend/veyrs/cli.py`). They map to operational personas rather than generic admin/editor/viewer tiers. Counts are concrete permissions after expansion, taken from the generated `extract/permissions.json`.

| Role slug | Concrete permissions | Intended persona | Notable grants and omissions |
|---|---|---|---|
| `org-admin` | all 116 (`*:*`) | Organization administrator | The only role holding `user:write`, `apikey:*`, `role:*`, `settings:*`, `organization:*`, `agent:admin` |
| `security-manager` | 39 | Owns risk posture | read/write on assets, findings, risk, SLA, escalation, workflow, importers, agents; `riskregister:delete`; `ticket:admin`; `ai:read`, `ai:write`; read-only on users, teams, audit |
| `security-engineer` | 24 | Daily triage | read/write on findings, vulnerabilities, tickets, assets, documents; `agent:read`, `agent:write` but not `agent:admin`; `ai:read` |
| `team-lead` | 14 | Team queue and SLA | read/write on tickets and findings; read on assets, risk, SLA, escalation, reports |
| `asset-owner` | 11 | Business owner | read/write on assets and tickets; read on vulnerabilities, findings, risk |
| `compliance-officer` | 19 | Controls and evidence | read/write on compliance, evidence, documents, knowledge, reports, risk register; read on audit |
| `executive` | 15 | CISO view | read across the estate, `risk:write`, `riskregister:write` (accepting a risk) but not delete |
| `auditor` | 12 | Immutable read | read only, including `audit:read`, `evidence:read`, `workflow:read` |
| `service-account` | 10 | Importers, ITSM | read/write on findings, assets, importers; read on products, CVEs, vulnerabilities, tickets |
| `read-only` | 10 | Baseline visibility | read on assets, products, vulnerabilities, findings, risk, risk register, tickets, reports, CVEs, compliance |

Only `org-admin` holds the `delete` action broadly, and only `org-admin` can manage users, roles, API keys and settings. Custom roles can be created per organization for anything else.

## 4. Tenant isolation as a security control

Tenant isolation exists in two layers, with an important caveat about the first:

1. **Application layer.** Handlers filter by `organization_id` explicitly (for example `admin.py:964`, `search.py:96`). This is a coding convention, and the `db.py` docstring now says so: nothing refuses a statement without the filter; `TenantSession` is a session with the tenant bound. Since 0.41.0 (R-23) `backend/veyrs/security/tenant_guard.py` adds two guards around RLS, the real control: the production API refuses to start under a role that bypasses RLS (superuser or `BYPASSRLS`), and an ORM hook flags any statement on a strictly isolated table run with **no tenant bound** (logged with `VEYRS_DEBUG`; `tests/test_fix_auth.py` walks every GET route with it and fails on any). It does not check that a bound query also filters correctly within the tenant, nor raw `text()` SQL.
2. **Database layer (PostgreSQL RLS).** `init-db` enables **and forces** row level security and creates the policy `veyrs_tenant_isolation` on every table with an `organization_id` column except a skip list (`backend/veyrs/cli.py:30-62,303-340`). The policy compares `organization_id` with `current_setting('veyrs.current_org', true)`, and `set_tenant` sets that variable transaction-locally and re-applies it on every new transaction of the session (`backend/veyrs/db.py:49-79`).

From the generated schema: 89 tables, of which 14 have no tenant column (global reference data such as `cve`, `cwe`, `kev_entries`, `compliance_controls`, plus `feed_runs` and `organizations`), and 72 receive an RLS policy by `init-db` (computed from `extract/schema.json` and the skip lists; this count was not read back from a live database). The exceptions inside the 75 tenant-scoped tables:

| Class | Tables | Why |
|---|---|---|
| Skipped by `init-db` | `roles`, `compliance_frameworks` (tenant column present, deliberately not RLS) | Built-in roles and frameworks are shared (`cli.py:30-39`) |
| Own policies (`schema_steps/step_auth.py`, since 0.41.0) | `auth_events` | Written before a tenant is known, often with none: any session may INSERT; a session READS only its bound organization's rows; rows with no organization are readable only with `veyrs.auth_events_unattributed = 'on'` (the API sets it for platform administrators who ask) |
| Permissive while the tenant is unbound | `users`, `refresh_tokens`, `api_keys`, `exec_agents` | Login looks up users by e-mail, refresh by token hash, API keys by prefix, agents by prefix, all before the tenant is known. With no tenant bound the row is visible; once bound, the strict predicate applies (`cli.py:44-62`) |
| Strict, nullable tenant column | `audit_log`, `ai_audit_log` | Isolated like the rest (`cli.py:56`) |

Consequences for operators:

- **The application database role must not be a superuser and must not have `BYPASSRLS`.** A PostgreSQL superuser bypasses every policy silently. The container stack creates the role correctly (`docker/initdb.d/10-app-role.sh`); on a native install verify it with the command in [hardening.md](hardening.md).
- **Backups must use a role that can read RLS tables**, otherwise a dump is silently empty. See the recovery manual.
- A code path that forgets to call `set_tenant` before touching a credential-keyed table sees every tenant's rows in that table. The authentication code binds explicitly after identifying the user (for example `auth.py:216,306,360`).

## 5. Team scope

Team scope narrows **which assets, findings and tickets** a principal sees inside its tenant (`backend/veyrs/security/scope.py`). It is not a second tenant boundary.

**How a principal becomes restricted.** From its role grants, not from team membership (`scope.py:197-225`):

- Superuser: unrestricted.
- No grants at all: restricted to nothing (empty result rather than the estate).
- Any grant with `team_id IS NULL`: unrestricted. Every pre-existing grant is of this kind, so nothing changes until an administrator scopes a grant on purpose.
- Otherwise: restricted to the union of the teams named in the grants. Assets with no owning team are invisible unless the organization sets `settings.team_scope.unowned_visible = true`.
- **Joining a team does not widen visibility.** `TeamMember` answers "whose queue is this"; authorization comes from grants only.
- **API keys are never narrowed** (`deps.py:221-225`).

**Route policy** (`scope.py:52-98,228-244`). When the principal is restricted, `get_principal` looks at the route's OpenAPI tag:

| Tag set | Tags | Effect for a restricted principal |
|---|---|---|
| `SCOPED_TAGS` | assets, vulnerability management, ticketing, dashboards & reports, policies, cvss, risk register | Served, filtered by team |
| `EXEMPT_TAGS` | authentication, intelligence & knowledge, threat intelligence, operations, administration, saved views | Served unfiltered (no per-asset tenant data, or filtered downstream) |
| `REFUSED_TAGS` | agents, ai, compliance, engagements, integrations, asset sources | 403: "reports on the whole estate and cannot be narrowed to a team" |
| any other tag | | 403 "not team-scope aware; refused rather than served unfiltered" |

A route with **no tag** is not checked by this policy (`scope.py:240` requires `tags` to be non-empty). The eight platform-administrator routes are untagged, but they are superuser-only.

> [!WARNING]
> `GET /api/v1/search` and `GET /api/v1/search/semantic` belong to the exempt tag `intelligence & knowledge`, so the router policy lets team-restricted principals through; since 0.41.0 `services/search.py` receives `principal.scope` and narrows vulnerabilities, findings, assets and tickets like the list endpoints do (risk R-03, fixed). Documents, knowledge articles and news are not team-owned and are not narrowed.

## 6. Platform administrators

`users.is_superuser` marks a platform administrator ("superuser" in the code). It has three effects:

1. `Principal.can()` is true for every permission (`deps.py:228-229`).
2. Team scope is unrestricted (`scope.py:205-206`).
3. It unlocks the installation-wide routes guarded by the `platform_admin` dependency, which also requires `kind == "user"` so an API key can never use them (`backend/veyrs/api/v1/updates.py:28-34`): software update status and apply, update uploads (6 routes in `updates.py`) and system information (`/api/v1/admin/system/software`, `/api/v1/admin/system/network`, `backend/veyrs/api/v1/system.py:21,33`).

A platform administrator is **not** a cross-tenant super-user at the database: the session is still bound to the administrator's own organization, so RLS applies (`deps.py:352`). Other properties: the flag is never delegated to LDAP or SSO and such accounts cannot sign in through SSO (`auth.py:256-257,1089`); it can only be granted or revoked with `python -m veyrs platform-admin --email <address> [--revoke]` on the host, which refuses to remove the last one and audits the change (`backend/veyrs/cli.py:629-675`).

## 7. Public and permissionless routes

The generated route table has 336 routes. 46 have no `require(...)` permission and are not platform-admin routes. They fall into four groups.

### 7.1 Public (no credential)

The authoritative list is `PUBLIC_PATHS` in `tests/test_phase10_hardening.py:195-212`, enforced by `test_every_route_is_protected` (line 229), which probes every other route anonymously and accepts only 401, 403 or 405.

| Route | Why it is public | Judgement |
|---|---|---|
| `POST /api/v1/auth/login` | Entry point | Acceptable. Per-IP limit, generic errors, lockout. |
| `POST /api/v1/auth/refresh` | The access token is expired; the refresh token is the credential | Acceptable. Reuse detection; same limit tier as login. |
| `GET /api/v1/auth/sso` | Console needs to know whether to show an SSO button | Acceptable. Boolean only; does not list organizations. |
| `GET /api/v1/auth/oidc/{org_slug}/start` | Browser redirect to the IdP | Acceptable. Same 404 for unknown and unconfigured organization. Starts a flow; costs one discovery request (cached 1 h). |
| `GET /api/v1/auth/oidc/callback` | IdP redirect target | Acceptable. Requires a single-use `state` and the binder cookie set by `start` in the same browser (R-11, fixed in 0.41.0). Hidden from the OpenAPI schema. |
| `POST /api/v1/auth/oidc/exchange` | Browser swaps a one-time handoff for tokens | Acceptable. Handoff is random, single-use, 60 s. |
| `GET /healthz`, `GET /readyz` | Liveness and readiness probes, exempt from rate limiting (`ratelimit.py:38`) | Acceptable. `/healthz` discloses app name and version; `/readyz` discloses which dependency is down by exception class name. Keep them off the public internet where possible. |
| `GET /metrics` | Prometheus | Acceptable. Requires `Authorization: Bearer <VEYRS_METRICS_TOKEN>` (constant-time compare), 404 otherwise, always 404 in production if no token is set (`main.py:115-139`). Not proxied by the shipped nginx configs. Exempt from rate limiting, so a leaked token allows unthrottled scraping. |
| `GET /api/v1/openapi.json` | FastAPI default | Off in production unless `VEYRS_EXPOSE_OPENAPI=true` (R-17, fixed in 0.41.0); served in development. |
| `GET /docs`, `/redoc`, `/docs/oauth2-redirect` | Swagger UI | Acceptable. Not mounted when `VEYRS_ENVIRONMENT=production` (`main.py:66-67`; observed 404 live). Available in `development` and `staging`, and in the container stack's default `development` mode. |

### 7.2 Authenticated by something other than a principal

| Route | Credential | Judgement |
|---|---|---|
| `POST /api/v1/integrations/itsm/{organization_slug}/{connector_slug}/inbound` | HMAC-SHA256 signature over `timestamp.body` with a per-connector secret, 5-minute replay window | Acceptable. Tenant comes from the path, not the body; identical 404 for unknown org, unknown connector and disabled inbound; body capped at 1 MB by the application (and 128 MB by nginx), so the body is read before the cap applies. |
| `POST /api/v1/agents/self/heartbeat`, `/jobs/claim`, `/jobs/{job_id}/events`, `/lease`, `/result`, `/fail`, `/inventory` (7 routes) | `X-Agent-Token` | Acceptable. Separate credential type, no principal. Every route resolves the agent first; they answer 401 anonymously (covered by the route walk). |

### 7.3 Authenticated, no permission needed (self-service)

These require a valid principal but no `resource:action`, because they concern the caller's own data. Each is judged by whether it can leak or alter data beyond the caller.

| Route | Judgement |
|---|---|
| `POST /auth/logout`, `GET /auth/me`, `GET /auth/me/scope`, `GET`/`PATCH /auth/me/preferences`, `POST /auth/password` | Self only. `/auth/me/scope` reports the caller's own team scope. `/auth/password` requires the current password and charges a wrong one to the lockout budget. An enrolment-only token (organization `require_mfa`) reaches only `/auth/me`, `/auth/mfa*` and `/auth/logout`. |
| `GET /auth/mfa`, `POST /auth/mfa/enroll`, `/send-code`, `/activate`, `/recovery-codes`, `/disable` | Self only; disabling and regenerating need password and a valid code. |
| `GET /notifications`, `POST /notifications/{id}/read`, `GET`/`PUT /notifications/preferences` | Filtered by `recipient_user_id = principal.user_id`; another user's notification answers 404 (`backend/veyrs/api/v1/tickets.py:673-720`). Acceptable. |
| `GET /search`, `GET /search/semantic` | Permission-filtered per entity type, tenant-filtered, but not team-scoped (see warning in section 5). Needs attention. |
| `GET /reports` | Returns the catalogue annotated with what the caller may export. Acceptable. |
| `GET /reports/{slug}`, `GET /reports/{slug}/export` | The decorator has no `require`, but the handler calls `principal.require(spec.permission)` and refuses team-restricted callers; exports are audited as egress (`backend/veyrs/api/v1/reports.py:118-172`). Acceptable, but invisible to the route table: a reviewer reading `routes.json` alone sees them as open. |
| `GET`, `POST /saved-views`, `PATCH`, `DELETE /saved-views/{id}` | Stores a query, never a row; edits only by the owner, 404 for other users' views; API keys cannot own views. Shared views are visible to the whole organization. Acceptable. |

### 7.4 What the route table cannot show

`routes.json` records permissions declared through `require(...)`. Handlers that call `principal.require(...)` or `principal.can(...)` inline (reports, parts of `ai.py`, `admin.py`) are not in that column. Treat the generated reference as a lower bound and read the handler when auditing a route.
