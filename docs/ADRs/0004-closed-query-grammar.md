---
title: ADR 0004: AI emits validated JSON against a closed grammar, never SQL
purpose: Record why natural-language search compiles through a closed grammar instead of model-written queries.
scope: The grammar-based query translation decision, checked against the 0.39.1 code.
version: 0.39.1
verified: 2026-11-17
status: Verified
sources: [backend/veyrs/services/ai/nlquery.py, backend/veyrs/services/ai/capabilities.py, backend/veyrs/api/v1/ai.py]
related: [architecture/data-flows.md, ADRs/0003-ai-gateway.md]
---

# ADR 0004 - AI emits validated JSON against a closed grammar, never SQL

**Status:** Accepted · **Date:** 2026-08-10 · **Checked against code:** 0.39.1, in force

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

## Check against 0.39.1

| Claim | Code | Result |
|---|---|---|
| Fixed fields, per-field operators and values; VEYRS validates and compiles | `nlquery.validate`, `_validate_filter`, `compile_query` (`nlquery.py:133-281`) | Holds |
| Tenant predicate appended unconditionally | `compile_query(query, organization_id)` | Holds |
| Grammar published at `GET /ai/search/grammar` | `api/v1/ai.py:439`, mounted under `/api/v1` | Holds |
| Heuristic parser first, model only when it returns nothing | `capabilities.py:445` calls `heuristic_parse`; the gateway is invoked only if that returns `None` | Holds |
| The user sees and can edit the structured query | The result carries the structured query and an explanation (`nlquery.describe`) | Holds in the API response; console behaviour not checked |
