# ADR 0003 - One AI gateway; no provider access anywhere else

**Status:** Accepted · **Date:** 2026-08-10

## Context

The spec asks for AI across many features and, separately, that AI never bypass
authorization and never leak sensitive data. Those requirements conflict if each
feature calls a provider itself: the policy check becomes a convention, and
conventions erode under delivery pressure.

## Decision

`services/ai/gateway.invoke()` is the only function that may reach a model.
Capability features assemble grounded facts and call it. It performs capability
lookup, permission re-check, budget check, sanitization, provider selection by
data classification, the call (or a deterministic fallback), output scanning and
an audit write - in that order, every time.

## Alternatives rejected

- **A middleware or decorator.** Cannot see the payload's classification, which
  is the input that decides whether an external provider is eligible at all.
- **Per-feature calls with a shared helper.** A helper can be skipped.
- **Provider-native tool calling.** A model that can invoke tools inside a
  multi-tenant security product is an authorization boundary made of prose.

## Consequences

- One place to audit, one place to change policy semantics.
- Policy refusals are *results*, not exceptions - a blocked call is visible to
  the caller and to the auditor.
- The deterministic provider is a first-class degraded mode, which also makes the
  entire test suite hermetic: no test in this repository reaches the network.

## Revisit if

Streaming responses are required, which would need a different return contract.
