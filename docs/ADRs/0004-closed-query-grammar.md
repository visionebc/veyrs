# ADR 0004 - AI emits validated JSON against a closed grammar, never SQL

**Status:** Accepted · **Date:** 2026-08-10

## Context

"Show me all critical vulnerabilities affecting internet-facing FortiWeb
appliances with EPSS above 0.5 and CISA KEV enabled" must become a query. The
obvious implementations - ask the model for SQL, or for an ORM expression - put a
language model inside the trust boundary of a multi-tenant security database.

## Decision

The model emits a JSON object against a **closed grammar**: a fixed field list,
per-field operator sets, and per-field allowed values. VEYRS validates every
field, operator and value, then compiles the query itself and appends the tenant
predicate unconditionally.

The complete grammar is published at `GET /ai/search/grammar`.

## Alternatives rejected

- **Text-to-SQL.** One prompt injection away from arbitrary reads. Even with a
  read-only role, cross-tenant exposure would depend on the model behaving.
- **A sandboxed expression language.** More surface, same class of risk.
- **Free-text search only.** Cannot express "EPSS above 0.5 AND internet-facing".

## Consequences

- A hallucinated field yields a validation error, not a query.
- Adding a queryable field is a code review, not a prompt change.
- A deterministic heuristic parser runs *first* and handles the common shapes
  with no model at all, so the feature works air-gapped and the cheap path is the
  default path.
- The user sees the structured query that ran and can edit it. An opaque
  natural-language search in a security tool is a liability: the operator must be
  able to prove what was actually asked.

## Revisit if

The grammar becomes too limiting - extend it, never bypass it.
