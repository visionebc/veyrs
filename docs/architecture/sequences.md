---
title: Sequence diagrams
purpose: Show the exact call order, decisions and failure responses of the six interactions that define VEYRS behaviour at runtime.
scope: Password login with MFA and token refresh, API key authentication, tenant session binding, agent job claim and result, scan import, and the AI gateway decision, as implemented in 0.39.1.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/api/v1/auth.py, backend/veyrs/security/auth.py, backend/veyrs/security/deps.py, backend/veyrs/db.py, backend/veyrs/security/agent_auth.py, backend/veyrs/services/agents.py, backend/veyrs/api/v1/agents.py, backend/veyrs/services/importers/__init__.py, backend/veyrs/services/ai/gateway.py, integrations/veyrs-agent/veyrs_agent.py]
related: [architecture/data-flows.md, architecture/overview.md, security/authentication.md]
---

# Sequence diagrams

Participants use the names of the code (`get_principal`, `set_tenant`, `claim_next`). Tests that exercise the same behaviour are named where they exist. Request-independent flows (feeds, SLA sweep) are in [data flows](data-flows.md).

## 1. Password login, MFA and refresh

```mermaid
sequenceDiagram
  autonumber
  participant C as Client
  participant RL as RateLimitMiddleware
  participant A as auth.login
  participant DB as PostgreSQL
  participant X as Directory or RADIUS
  participant M as MFA delivery
  C->>RL: POST /api/v1/auth/login with identifier, password, organization
  RL->>RL: per-IP budget on auth paths, 10 per minute
  RL->>A: pass
  A->>DB: select user by e-mail or username, join organization
  Note over A,DB: users is a credential-keyed table, readable before a tenant is bound
  alt no local user
    A->>X: just-in-time provision if the tenant enables it
  end
  A->>A: locked, inactive or unknown gives the same 401 body
  A->>A: local Argon2 verify first
  opt local check failed and not a platform admin
    A->>X: directory bind or RADIUS Access-Request
  end
  alt password wrong
    A->>DB: failed_logins plus 1, lock 15 min at 10, auth_events row
    A-->>C: 401 generic
  else password right and MFA enabled and no code sent
    A->>M: send code now if method is e-mail or Telegram
    A-->>C: 401 error mfa_required with method, no attempt spent
    C->>A: POST /auth/login again with mfa_code
    A->>A: TOTP with replay guard on mfa_last_step, or recovery code, or delivered code
  end
  alt second factor wrong
    A->>DB: failed_logins plus 1, auth_events bad_mfa
    A-->>C: 401 generic
  else ok
    A->>DB: reset failed_logins, rehash password if parameters changed, last_login_at
    A->>DB: effective_permissions: bind tenant, read roles
    A->>DB: insert refresh_tokens row, family = user id, hash only
    A->>DB: auth_events success row, commit
    A-->>C: 200 access_token JWT, refresh_token, permissions
  end
  C->>A: POST /auth/refresh with refresh_token
  A->>DB: find by SHA-256 of token
  alt unknown token
    A-->>C: 401
  else already revoked
    A->>DB: revoke every token in the family, reuse_detected
    A-->>C: 401
  else expired
    A->>DB: revoke, expired
    A-->>C: 401
  else valid
    A->>DB: revoke old, insert new token in the same family
    A-->>C: 200 new token pair
  end
```

**Legend.** Solid arrows are calls, dashed arrows are responses, `Note` boxes explain the data-access rule. `alt`/`opt` blocks are the branches. Participant `A` is `api/v1/auth.py`. Defaults: access token 30 minutes (`access_token_minutes`), refresh token 14 days (`refresh_token_days`), 10 failed attempts then a 15-minute lock (`MAX_FAILED`, `LOCK_MINUTES`).

Design points visible in the sequence:

- The 401 body is identical for unknown user, wrong password, locked, inactive and disabled organization, and a missing user still burns an Argon2 verification so timing does not reveal existence (`auth.py:410`).
- When the same identifier exists in several tenants and no slug is supplied, VEYRS reveals the candidate slugs only after the password has been proven for more than one of them (HTTP 409 `organization_required`).
- An MFA challenge is not charged to the lockout budget; a wrong code is. Password failures and MFA failures share one counter on purpose (`auth.py:104-114`).
- If the MFA secret cannot be decrypted (key rotated), login fails closed rather than falling back to password only (`auth.py:507-520`).
- A directory login never writes a local password hash (`auth.py:534-546`).
- Permissions are not trusted from the token afterwards: every request re-reads them (see sequence 2).

Tests: `tests/test_phase2_core.py::test_refresh_rotates_and_reuse_kills_the_family`, `tests/test_phase24_mfa.py`, `tests/test_login_error_message.py`. Status: Implemented (code and tests read; not replayed against the live system).

## 2. API key and bearer authentication on a normal request

```mermaid
sequenceDiagram
  autonumber
  participant C as Client
  participant RL as RateLimitMiddleware
  participant GP as get_principal
  participant DB as PostgreSQL
  participant S as scope
  participant R as Route with require
  C->>RL: GET /api/v1/findings with X-API-Key or Authorization Bearer
  RL->>RL: key = apikey prefix or SHA-256 of bearer or client IP, 240 per minute
  RL->>GP: pass
  alt X-API-Key present
    GP->>GP: split veyrs_prefix_secret, malformed gives 401
    GP->>DB: select api_keys where prefix = p
    Note over GP,DB: api_keys is credential-keyed, tenant not yet bound
    GP->>GP: record usable and Argon2 verify of the secret
    GP->>DB: last_used_at = now
    GP->>GP: Principal kind apikey, permissions from scopes, no team narrowing
  else Bearer JWT
    GP->>GP: decode HS256, check audience veyrs:access, subject, org
    GP->>DB: load user, organization, check active and not locked
    GP->>DB: effective_permissions, bind tenant, union of role permissions
    GP->>S: resolve_for_user: team scope from role grants
    GP->>GP: Principal kind user
  end
  GP->>DB: set_tenant(organization_id)
  GP->>S: enforce_route_policy by router tag
  S-->>GP: allowed, or 403 for a restricted principal on an estate-wide router
  GP->>R: Principal
  R->>R: require checks every permission string, else 403
  R-->>C: 200 or error, X-Correlation-ID header
```

**Legend.** Same conventions as above. `GP` is `security/deps.get_principal`. The rate-limit key is derived from the request headers, never from `request.state`, because middleware runs before the dependency that would set it (`security/ratelimit.py:140-163`).

Properties:

- Permissions come from the database on every request, so a revoked role takes effect immediately, not at token expiry (`security/deps.py:131-134`).
- A token minted for another tenant is treated as forgery unless the user is a platform administrator (`security/deps.py:123-125`).
- API keys are never narrowed by team scope: an importer that silently saw a third of the estate would close findings it merely could not observe (`security/deps.py:50-54`).
- An agent token is rejected here: it uses another scheme word (`veyrsagent_`), so `split_api_key` fails on it (`security/auth.py:155-168`).

Tests: `tests/test_phase10_hardening.py::test_a_token_from_one_tenant_cannot_read_another`, `tests/test_phase26_scope.py`. Status: Implemented.

## 3. Tenant session binding (RLS)

```mermaid
sequenceDiagram
  autonumber
  participant R as Request handler
  participant D as deps.get_principal and tenant_session
  participant SA as SQLAlchemy Session
  participant EV as after_begin listener
  participant PG as PostgreSQL with RLS
  R->>D: dependency resolution
  D->>SA: get_session: new Session from pool
  D->>SA: set_tenant(org)
  SA->>SA: session.info veyrs_tenant = org
  SA->>PG: SELECT set_config veyrs.current_org, org, true
  Note over SA,PG: true means transaction-local: dies at COMMIT or ROLLBACK
  R->>SA: SELECT * FROM findings
  SA->>PG: query, no organization filter written
  PG->>PG: policy: organization_id = current_setting veyrs.current_org
  PG-->>R: only this tenant's rows
  R->>SA: commit
  SA->>PG: COMMIT, setting discarded
  R->>SA: next query in the same request
  SA->>EV: new transaction begins
  EV->>PG: set_config again from session.info
  PG-->>R: still only this tenant's rows
  R->>SA: close, connection returns to pool with no tenant
  Note over R,PG: A query on an unbound session matches no rows
```

**Legend.** `D` bundles two dependencies in `security/deps.py`. The policy text is `organization_id::text = NULLIF(current_setting('veyrs.current_org', true), '')` (`cli.py:58`). Four credential-keyed tables (`users`, `refresh_tokens`, `api_keys`, `exec_agents`) use a variant that also matches when no tenant is bound, which is what lets login find a user before knowing the tenant.

Why each step exists:

- **Transaction-local** so a pooled connection cannot carry one request's tenant into another (`db.py:54-56`).
- **`after_begin` re-bind** because a `commit()` ends the transaction; without it, handlers that create a ticket, commit, and then fire a workflow read zero rows (`db.py:57-80`).
- **Fail closed**: no tenant means no rows, not all rows.
- **Not a superuser**: a PostgreSQL superuser or a role with `BYPASSRLS` ignores the policies silently. The installers and `veyrs-setup.sh` refuse such a role; `tests/test_audit_rls.py::test_the_suite_is_not_running_as_a_role_that_bypasses_rls` guards the test suite.
- **Background jobs** bind per tenant in a loop (`services/intel_pipeline.py`) and restore the binding that was in force on entry.

Tests: `tests/test_audit_rls.py`, `tests/test_phase15_unified_ingest.py::test_tenant_isolation_holds_for_the_new_tables`, `tests/test_phase16_agents.py::test_agents_and_jobs_are_invisible_across_tenants`. Status: Verified for the policy and binding code by tests read; the RLS state of the live database was not queried.

## 4. Agent job claim, lease and result

```mermaid
sequenceDiagram
  autonumber
  participant Op as Operator
  participant API as VEYRS API
  participant DB as PostgreSQL
  participant Ag as veyrs-agent
  participant Sc as Scanner binary
  Op->>API: POST /agents/jobs tool, target, optional agent
  API->>API: scanning enabled, target allowed by agent allowlist
  API->>DB: insert agent_jobs state queued
  opt every 60 s
    Ag->>API: POST /agents/self/heartbeat with tools and version
    API->>DB: agent online, tools declared
    API-->>Ag: status, active_scanning flag
  end
  loop every poll interval, 15 s default, 5 s in the shipped unit
    Ag->>API: POST /agents/self/jobs/claim
    Note over API,DB: X-Agent-Token checked, tenant bound to the agent's organization
    API->>DB: select queued jobs FOR UPDATE SKIP LOCKED, priority then age
    API->>API: re-authorise tool and target for this agent
    API->>DB: state leased, lease_token, lease_expires_at, attempts plus 1
    API-->>Ag: 200 job and lease_token, or 204 no work
  end
  Ag->>Ag: re-check own allowlist, build argv locally, no shell
  Ag->>Sc: execute
  loop while scanning
    Ag->>API: POST /jobs/id/events with lease_token
    API->>DB: verify_lease, append events, leased becomes running
    Ag->>API: POST /jobs/id/lease with lease_token
    API->>DB: lease_expires_at = now plus lease_seconds
  end
  Sc-->>Ag: output file
  Ag->>API: POST /jobs/id/result raw body, scanner, exit_code, X-Agent-Scan-Stats
  API->>DB: verify_lease, check size and coverage
  API->>API: run_import as in sequence 5, close_absent only if coverage attested
  API->>DB: job succeeded or failed, lease cleared, audit row
  API-->>Ag: job state, import_run_id, counts
  Note over API,DB: If the agent dies, nothing changes until POST /agents/maintenance/reap runs
```

**Legend.** `Op` can be a person or a script with `agent:write`. The agent holds no user permissions; every self route needs the agent token and, for writes to a job, the lease token returned once at claim.

Failure and edge behaviour:

| Situation | Result | Source |
|---|---|---|
| Disabled agent | 403 (not 401), so the agent can tell "rotate token" from "switched off" | `security/agent_auth.py:55-60` |
| Wrong or stolen lease token | Refused: only the current holder may write; terminal jobs refuse writes | `services/agents.py:720` |
| Lease expires | Requeued while `attempts < max_attempts`, else `expired`; only on a call to the reap endpoint | `services/agents.py:1197` |
| Empty result with no coverage statistics | Refused as a blind scanner; an empty result with attested coverage is accepted and may close findings | `api/v1/agents.py:323-345`, `services/agents.py:845` |
| Non-zero exit with no output | Job `failed`, no import | `services/agents.py:918-1000` |
| Result larger than 64 MB | Refused; split the scan | `services/agents.py:57` |

Tests: `tests/test_phase16_agents.py` (claim, lease, expiry, tenant isolation, end to end over HTTP), `tests/test_phase16_runner.py`. Status: Verified for the agent unit running on the primary node; Implemented for the protocol details above.

## 5. Scan import

```mermaid
sequenceDiagram
  autonumber
  participant C as Client
  participant API as POST /integrations/imports
  participant RI as importers.run_import
  participant P as Parser
  participant IN as base.ingest
  participant CO as correlation
  participant EN as engagements
  participant DB as PostgreSQL
  C->>API: multipart file, source, engagement_id, options
  API->>API: require importer:write, read body into memory
  API->>RI: payload, options, actor
  RI->>DB: insert import_runs status running, content hash
  RI->>P: get_parser(source) or detect_format
  alt unparseable
    P-->>RI: ParserError
    RI->>DB: run status failed with reason
    RI-->>API: failed run, still persisted
  else parsed
    P-->>RI: ScanRecord list
    RI->>IN: records, scanner
    IN->>EN: resolve_scope: engagement and test
    loop each record
      IN->>IN: reject if no title, below min_severity, or asset not resolvable
      IN->>CO: resolve vulnerability, installation
      IN->>IN: dedupe.resolve_identity
      IN->>CO: ensure_finding: create, update or reopen
      IN->>EN: record_sighting
      IN->>CO: process_finding: score, assign, SLA, auto-ticket, workflow
    end
    IN->>EN: reconcile_test: mark absent, close past threshold
    IN-->>RI: ImportResult counters
    RI->>DB: run complete with counts and reject samples
  end
  API->>DB: audit import.run, commit
  API-->>C: 201 ImportRun
```

**Legend.** Conventions as above. All DB writes happen on the tenant-bound session (sequence 3). A dry-run option parses and reports without persisting findings. Parse failures are stored as failed runs so the operator can see later why a file was rejected.

Tests: `tests/test_phase15_parsers.py`, `tests/test_phase15_unified_ingest.py`, `tests/test_phase8_integrations.py`. Status: Implemented.

## 6. AI gateway decision

```mermaid
sequenceDiagram
  autonumber
  participant U as User
  participant API as api/v1/ai
  participant CAP as capabilities
  participant GW as gateway.invoke
  participant G as guardrails
  participant PR as Provider
  participant DB as PostgreSQL
  U->>API: POST /ai/... question
  API->>API: require ai permission
  API->>CAP: build grounded facts from tenant data the user may read
  CAP->>GW: AiRequest capability, prompt, facts, classification
  GW->>DB: load ai_policies, or restrictive defaults
  alt capability disabled, permission missing, over size or daily budget
    GW->>DB: ai_audit_log decision blocked
    GW-->>U: allowed false, block_reason
  else within policy
    GW->>G: sanitize: secrets, PII, injection
    alt injection and block_on_injection
      GW->>DB: ai_audit_log blocked
      GW-->>U: blocked
    else clean
      GW->>DB: select enabled providers, order by default, internal first
      GW->>GW: classification ceiling and allow-lists per provider
      alt none eligible
        GW->>PR: deterministic provider, no network
        GW->>DB: ai_audit_log degraded
      else provider chosen
        opt external provider
          GW->>G: redact internal addresses
        end
        GW->>PR: complete over HTTPS
        alt provider error
          GW->>PR: deterministic fallback
          GW->>DB: audit degraded, provider last_error
        else answer
          GW->>DB: audit allowed with tokens, duration, redactions
        end
      end
      GW->>G: scan_output for leaked secrets
      GW-->>API: AiResult text, decision, provider, redactions
      API-->>U: answer labelled degraded when applicable
    end
  end
```

**Legend.** `alt` branches are mutually exclusive outcomes; every outcome writes one `ai_audit_log` row (the audit write for a clean answer happens in `_finish`). Participant `PR` is any provider class in `services/ai/providers.py`. Facts are assembled by VEYRS before the call: the model supplies wording, not data.

Tests: `tests/test_phase6_ai.py` (default policy forbids external providers, confidential data cannot reach an external provider, degraded mode with no provider, provider failure, injection blocks, daily limit). The test suite never reaches a real provider ([ADR 0003](../ADRs/0003-ai-gateway.md)). Status: Verified by tests read; no live provider is configured in the observed environment.

## Sources

- `backend/veyrs/api/v1/auth.py:364-632`, `security/auth.py`, `security/deps.py`, `security/ratelimit.py`
- `backend/veyrs/db.py`, `cli.py:58-64`
- `backend/veyrs/security/agent_auth.py`, `services/agents.py`, `api/v1/agents.py:239-445`, `integrations/veyrs-agent/veyrs_agent.py`
- `backend/veyrs/services/importers/__init__.py`, `importers/base.py`
- `backend/veyrs/services/ai/gateway.py`
