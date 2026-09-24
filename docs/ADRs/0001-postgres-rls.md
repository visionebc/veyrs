# ADR 0001 - PostgreSQL Row Level Security as a second tenant barrier

**Status:** Accepted · **Date:** 2026-08-10

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
- Three tables must be readable pre-auth (login by email, refresh by hash, API
  key by prefix) and use a permissive-when-unbound policy. Documented as
  T-TENANT-01.

## Revisit if

A customer requires physical database separation, or RLS becomes a measurable
bottleneck at scale.
