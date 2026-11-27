---
title: Administration and platform settings
purpose: Document the organization-level switches and settings (scanning, ticketing mode, risk register, directory, SSO, RADIUS, secret storage) and the organization record, feature by feature.
scope: The organization and settings routes of api/v1/admin.py and the services behind them. Users, teams, roles, API keys and audit are in authentication-accounts.md; software update and platform-admin pages are in updates.md.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/api/v1/admin.py, backend/veyrs/services/scanning.py, backend/veyrs/services/ticketing_mode.py, backend/veyrs/services/risk_register_mode.py, backend/veyrs/services/ldap_auth.py, backend/veyrs/services/oidc_auth.py, backend/veyrs/services/radius_auth.py, backend/veyrs/services/secret_storage.py, backend/veyrs/security/scope.py]
related: [functional/authentication-accounts.md, functional/updates.md, reference/configuration.md, api/reference/administration.md, security/security-architecture.md, api/guide.md]
---

# Administration and platform settings

All routes here are in the router tagged `administration` (`backend/veyrs/api/v1/admin.py:48`). The tag is exempt from team scoping (`security/scope.py:78`), so every settings handler calls `team_scope.refuse_if_restricted` itself: a team-scoped identity cannot change or read estate-wide settings (403 with an explanatory detail).

Per-organization settings live in the JSONB column `organizations.settings`, one block per key: `scanning`, `ticketing`, `risk_register`, `ldap`, `oidc`, `radius`, `team_scope`. Every service writes by **reassigning** the dictionary (`settings = dict(...); organization.settings = settings`) because SQLAlchemy does not track in-place changes of a plain dict inside JSONB.

All three mode switches (scanning, ticketing, risk register) share a pattern: `GET` is open to anyone with `settings:read` because the console reads it on every page load to decide which menu entries to paint; `PUT` needs `settings:admin` and an estate-wide grant; each change records `reason`, the previous state and is written to `audit_log`; nothing is ever deleted or migrated by flipping a switch.

Console: Configure, in three menu groups (since 0.42.0 each tab is a menu entry of its own, with its own title): **Access** (users, teams, roles, departments, API keys, directory, RADIUS, single sign-on), **Data intake** (ticketing, asset sources, import teams, scanning) and **Platform** (risk register, secret storage, organization, installed software, network access, trust store, web certificate, software update). The route is still `#/admin?tab=...` (`NAV` in `frontend/console/app.js`, item `admin` with `flat: true`).

## Feature: organization record

- **What**: `GET /organization`, `PATCH /organization` (`api/v1/admin.py:60-90`).
- **Why**: name, invoicing code, default locale and timezone of the caller's own tenant. The tenant is always taken from the principal, never from the request.
- **How it works**: PATCH applies every field in `OrganizationUpdate` that was sent (`name`, `invoicing_code`, `default_locale` in `en|es|de|fr|it`, `timezone`) with `setattr` and audits `organization.update` with a diff.
- **Permissions**: `organization:read` / `organization:write`.
- **Data**: `organizations`.
- **Errors**: 404 `organization not found`; 422 validation.
- **Exceptional**: since 0.41.0 `OrganizationUpdate` rejects unknown fields, so a body carrying `settings` or `is_active` answers 422. Settings blocks are changed only through their own guarded routes (`settings:admin`); `is_active` is not a tenant decision (TD-23, fixed).
- **Status**: Implemented.

## Feature: active scanning switch

- **What**: `GET /scanning`, `PUT /scanning` (`api/v1/admin.py:92-155`, service `services/scanning.py`). Decides whether this tenant may run scans itself through enrolled agents; ingestion of scanner results is unaffected.
- **Why**: an operator who already owns a scanner wants VEYRS as a vulnerability management and traceability platform, not as a second prober. The switch is enforced where work is created and handed out, not only in the menu (`services/scanning.py:1-48`).
- **How it works**: state `active_scanning_enabled` (default **true**, so upgrades do not change behaviour), `explicit` (was it ever set), `reason`, `changed_at`, `changed_by_id`. `GET` adds `queued_jobs`. `PUT` body: `active_scanning_enabled`, `reason`, `cancel_queued_jobs` (default true; ignored when enabling). Turning it off cancels `queued` agent jobs one by one through `agents.cancel_job` so each cancellation is audited and has its own event; leased/running jobs are left alone (`scanning.py:117-146`). Enforcement points: `queue_job`, `claim_next` and `enroll` refuse when off; `heartbeat`, `submit_result`, `/agents/self/inventory` and imports are allowed (table in `scanning.py:13-31`, details in [agents](agents.md)).
- **Permissions**: `settings:read` (GET), `settings:admin` (PUT), estate-wide grant only.
- **Data**: `organizations.settings["scanning"]`, `agent_jobs`, `agent_job_events`, `audit_log` (`organization.scanning_mode_changed`).
- **Errors**: 403 team-scoped identity; 422 body; refusals elsewhere raise `ScanningDisabled` (mapped by the agent routes, see [agents](agents.md)).
- **Status**: Verified (GET observed live: keys `active_scanning_enabled, changed_at, changed_by_id, reason, explicit, queued_jobs`; PUT not run). Test: `tests/test_phase34_inventory_and_scanning.py`.

## Feature: ticketing mode (internal queue or external ITSM)

- **What**: `GET /ticketing`, `PUT /ticketing` (`api/v1/admin.py:157-226`, `services/ticketing_mode.py`). Chooses which system owns remediation work: the built-in tickets, or one ITSM connector (Jira, ServiceNow etc., see [integrations](integrations.md)).
- **How it works**: `mode` is `internal` (default) or `external`. External requires a `connector_id` of this organization (`validate`, `:187-206`; `set_mode`, `:209-262`). The connector need not be enabled yet: `state()["usable"]` reports the gap, and a mode with a missing/disabled connector is reported as broken, not silently treated as internal. Nothing is migrated or closed; existing internal tickets stay transitionable. The audit entry records `open_internal_tickets` at the moment of the flip. The service guards ticket creation paths through `require_internal` (`:173`), which raises `TicketingModeError`.
- **Permissions**: `settings:read`, `settings:admin` (estate-wide).
- **Data**: `organizations.settings["ticketing"]`, `itsm_connectors`, `tickets`, `audit_log` (`organization.ticketing_mode_changed`).
- **Errors**: 403 team-scoped; 422 `mode must be one of internal, external`, `external ticketing needs a connector`, `connector not found in this organization`.
- **Status**: Verified for GET (live keys: `mode, connector_id, connector_name, connector_system, connector_enabled, usable, changed_at, changed_by_id, reason, explicit, open_internal_tickets`). Test: `tests/test_phase45_ticketing_mode.py`.

## Feature: risk register switch

- **What**: `GET /risk-register`, `PUT /risk-register` (`api/v1/admin.py:228-292`, `services/risk_register_mode.py`).
- **How it works**: `enabled` defaults to **true**. With it off, `POST/PATCH/DELETE /risks`, RACI and link writes answer 409 (`RiskRegisterDisabled`), while reads of existing entries and `/risks/summary` stay open, so records written earlier remain evidence (table in `risk_register_mode.py:8-33`). The audit entry records `entries` and `open_entries` at the flip. Detail of the register itself is in [risk-register](risk-register.md).
- **Permissions**: `settings:read`, `settings:admin` (estate-wide).
- **Data**: `organizations.settings["risk_register"]`, `risk_entries`, `audit_log` (`organization.risk_register_changed`).
- **Errors**: 403 team-scoped.
- **Status**: Verified for GET (live keys `enabled, changed_at, changed_by_id, reason, explicit, entries, open_entries`).

## Feature: OIDC, LDAP, RADIUS configuration

- **What**: for each method a `GET` (redacted state), a `PUT` (configure) and a `POST .../test`: `/ldap`, `/ldap/test`, `/oidc`, `/oidc/test`, `/radius`, `/radius/test` (`api/v1/admin.py:294-512`). Runtime behaviour is in [authentication-accounts](authentication-accounts.md).
- **Why**: these decide who can sign in. They are therefore **not** read-open: the payload names hosts, the service-account DN and the group-to-role map, which is a map of how to become an administrator (`admin.py:297-303`).
- **How it works**:
  - Updates use `exclude_unset`: an absent key means "leave as is". Secrets (`bind_password`, `client_secret`, `secret`) are optional on update; absent keeps the stored one. LDAP additionally has `clear_bind_password`. Secrets are encrypted with `security/secrets.py` and never returned; the state exposes `*_set` booleans (`client_secret_set`, `secret_set`).
  - `validate` returns all problems at once, joined in a 422. LDAP refuses an unencrypted connection (no LDAPS and no StartTLS) when enabling, requires service-account DN, base DN, `{username}` in the filter, timeout 1-60, at most 100 group mappings (`ldap_auth.py:244-311`). OIDC requires https issuer, a redirect URI that ends in `/api/v1/auth/oidc/callback`, `openid` scope, and a client secret to enable (`oidc_auth.py:110-164`). RADIUS allows at most four servers, timeout 1-120, retries 0-3, `role_attribute` empty/`Class`/`Filter-Id` (`radius_auth.py:290-317`).
  - `test` endpoints diagnose the **saved** configuration, step by step, and never 500 on a bad directory: LDAP steps `library, configuration, bind, search base, user lookup` (`ldap_auth.py:695-778`); OIDC steps `configuration, discovery, signing keys, PKCE S256` (`oidc_auth.py:321-341`); RADIUS performs a real exchange with a test account and optional `code` for a challenge, and audits `organization.radius_tested` (the audit records the user name, never the password) (`admin.py:491-512`).
  - Changes are audited as `organization.directory_configured`, `organization.oidc_configured`, `organization.radius_configured`; diffs are taken over the redacted state so a secret cannot reach the log.
- **Permissions**: `settings:admin`, estate-wide grant only (all GET/PUT/POST).
- **Data**: `organizations.settings["ldap"|"oidc"|"radius"]`, `audit_log`.
- **Dependencies**: `ldap3` package (LDAP), outbound HTTPS to the issuer (OIDC), UDP to RADIUS servers, Redis for OIDC flow state and RADIUS challenges, encryption key or vault (`secret_storage`).
- **Errors**: 403 team-scoped; 422 `validate` problems (semicolon separated).
- **Exceptional**: a platform superuser is never authenticated through LDAP, RADIUS or SSO, so the break-glass account can repair a bad configuration.
- **Status**: Verified for GETs (live: `/ldap`, `/oidc`, `/radius` returned 200 with redacted state; keys include `client_secret_set` and `secret_set`, no secret fields). PUT and test routes: Implemented (`tests/test_phase41_directory_auth.py`, `test_phase57_radius.py`, `test_phase58_oidc.py`).

## Feature: secret storage status

- **What**: `GET /secret-storage` (`api/v1/admin.py:514-535`, `services/secret_storage.py:194`). Read-only page: storage mode (`local`, `mirror`, `vault`), vault health, per-column counts of where this organization's encrypted credentials live, and the next suggested command.
- **Why**: credentials (`*_enc` columns, `users.mfa_secret`, the LDAP bind password) can be kept as local ciphertext or in an external vault. Moving them is a platform operation, so there is deliberately **no PUT**: `web_migration` is always false.
- **How it works**: `status` probes the vault (`secret_vault.probe`) and counts each registered column by kind (`local, mirror, vault, empty, unknown`) with the tenant bound, because the tables are RLS-forced and an unbound read would silently report zero. The registry `COLUMNS` is enforced by a test so a new `*_enc` column cannot be missed. The CLI commands returned in `commands` are `veyrs secrets status`, `migrate --to mirror|vault|local [--apply]`, `gc --apply`, `rekey --apply` (`secret_storage.py:73-81`). Configuration of the backend is through `VEYRS_SECRET_BACKEND` and `VEYRS_VAULT_*` ([configuration reference](../reference/configuration.md)).
- **Permissions**: `settings:admin`, estate-wide.
- **Data**: all `*_enc` columns (read for counts), vault (HTTP).
- **Errors**: 403 team-scoped. Unreadable credentials elsewhere in the API produce the global `503 secret_storage_unavailable` (see [guide](../api/guide.md#error-envelope)).
- **Status**: Verified for GET (live: `mode: local`, 1 local credential, `web_migration: false`). Test: `tests/test_phase48_secret_vault.py`, `tests/test_secret_rekey.py`.

## Feature: team-scope guardrail (settings block)

- **What**: not a route. `organizations.settings["team_scope"]["unowned_visible"]` (default false) makes assets and findings with no owning team visible to team-scoped identities (`security/scope.py:23-30`). It can only be changed through the generic `PATCH /organization` `settings` field or the database, there is no dedicated endpoint.
- **Status**: Implemented; no dedicated UI or endpoint (see findings).

## Route coverage

Covered here: `GET/PATCH /organization`, `GET/PUT /scanning`, `GET/PUT /ticketing`, `GET/PUT /risk-register`, `GET/PUT /ldap`, `POST /ldap/test`, `GET/PUT /oidc`, `POST /oidc/test`, `GET/PUT /radius`, `POST /radius/test`, `GET /secret-storage` (17 routes). `/admin/updates*` and `/admin/system/*` are in [updates](updates.md).
