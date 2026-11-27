---
title: ADR 0001: PostgreSQL RLS as a second tenant barrier
purpose: Record why tenant isolation is enforced twice and what that costs.
scope: The decision to use row level security alongside application filtering, checked against the 0.39.1 code.
version: 0.39.1
verified: 2026-11-17
status: Verified
sources: [backend/veyrs/db.py, backend/veyrs/cli.py, backend/veyrs/models/base.py, backend/veyrs/security/deps.py, tests/test_audit_rls.py]
related: [architecture/overview.md, architecture/sequences.md, DATABASE.md, THREAT_MODEL.md]
---

# ADR 0001 - PostgreSQL Row Level Security as a second tenant barrier

**Status:** Accepted · **Date:** 2026-08-10 · **Checked against code:** 0.39.1, still in force, one detail changed (see below)

## Context

VEYRS holds, per tenant, a list of every unpatched flaw in an estate with
exposure and criticality attached. A cross-tenant leak is not an embarrassment;
it is a target package handed to an attacker.

Application-level filtering (`WHERE organization_id = ?`) is the normal answer.
It fails the same way every time: one query, written under deadline, omits the
predicate, and nothing detects it because the result still looks plausible.

## Decision

Enforce tenancy **twice**, in independent layers. Every tenant-owned table gets
`ENABLE` + `FORCE ROW LEVEL SECURITY` with a policy bound to a session variable
that the request pipeline sets from the authenticated principal.

## Alternatives rejected

- **Database per tenant.** Strongest isolation, but migrations across hundreds
  of databases, and cross-tenant global intelligence (one CVE table) becomes
  painful. Revisit if a customer demands physical separation.
- **Schema per tenant.** Same migration problem, weaker guarantee.
- **Application filtering alone.** One missed predicate is a breach.

## Consequences

- A forgotten `WHERE` clause returns zero rows instead of another tenant's data.
- The tenant must be bound before any query. `set_config` with the local flag is
  transaction-scoped, so a commit silently unbinds it - mitigated with an
  `after_begin` hook (see DATABASE.md).
- Four tables must be readable pre-auth (login by email, refresh by hash, API
  key by prefix, agent token by prefix) and use a permissive-when-unbound
  policy. Documented as T-TENANT-01. (Three when this ADR was written;
  `exec_agents` was added with the execution agents.)

## Revisit if

A customer requires physical database separation, or RLS becomes a measurable
bottleneck at scale.

## Check against 0.39.1

| Claim | Code | Result |
|---|---|---|
| Every tenant table gets `ENABLE` + `FORCE ROW LEVEL SECURITY` with a policy bound to a session variable | `cli.init_db` (`cli.py:314-330`) creates policy `veyrs_tenant_isolation` on every table with a non-null `organization_id`, plus the audit tables | Holds. 72 of 89 tables: 68 strict and 4 credential-keyed |
| The variable is set from the authenticated principal | `security/deps.get_principal` and `tenant_session` call `db.set_tenant`, which runs `set_config('veyrs.current_org', :v, true)` | Holds |
| A commit silently unbinds the tenant; mitigated with an `after_begin` hook | `db._rebind_tenant` (`db.py:74-80`) | Holds |
| Application filtering is the first layer | Handlers query with an explicit `organization_id` filter on a session bound by `tenant_session`. `TenantSession` is a typing alias for a bound `Session` (`security/deps.py`); nothing refuses a statement without the filter. Since 0.41.0 `security/tenant_guard.py` refuses an RLS-bypassing role in production and flags unbound tenant-table statements in debug mode and tests | Holds as a convention; the `db.py` docstring was corrected in 0.41.0 |
| Credential-keyed policy | `RLS_TABLES_PREAUTH = {users, refresh_tokens, api_keys, exec_agents}` | Four, not three |

Not under RLS (16 tables): 13 global reference tables (`GLOBAL_TABLES`), `organizations`, `roles`, `feed_runs`. `auth_events` has its own policies since 0.41.0 (`schema_steps/step_auth.py`).

Operational consequence worth repeating: the application database role must be neither superuser nor `BYPASSRLS`, and `pg_dump` as that role produces a truncated archive. See [deployment](../architecture/deployment.md#22-split-deployment-with-a-standby-ha) and `DISASTER_RECOVERY.md`.

Tests read: `tests/test_audit_rls.py`, `tests/test_phase10_hardening.py::test_a_token_from_one_tenant_cannot_read_another`.
