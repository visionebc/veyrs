---
title: ADR 0003: One AI gateway, no provider access anywhere else
purpose: Record why every model call goes through one function and what that function guarantees.
scope: The AI gateway decision, checked against the 0.39.1 code.
version: 0.39.1
verified: 2026-11-17
status: Verified
sources: [backend/veyrs/services/ai/gateway.py, backend/veyrs/services/ai/capabilities.py, backend/veyrs/services/ai/providers.py, backend/veyrs/models/ai.py, tests/test_phase6_ai.py]
related: [architecture/data-flows.md, architecture/sequences.md, AI_SECURITY.md]
---

# ADR 0003 - One AI gateway; no provider access anywhere else

**Status:** Accepted · **Date:** 2026-08-10 · **Checked against code:** 0.39.1, in force

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

## Check against 0.39.1

| Claim | Code | Result |
|---|---|---|
| `gateway.invoke()` is the only function that reaches a model | `get_provider` is imported only in `services/ai/gateway.py:42-44`; `capabilities.py` imports `providers` only for `ProviderError` and `parse_json_object` | Holds. Enforced by convention and review; no test asserts the absence of other callers |
| Order: capability lookup, permission re-check, budget, sanitization, provider selection by classification, call or deterministic fallback, output scan, audit | `invoke()` and `_finish()` (`gateway.py:231-392`): capability enabled, permission held, prompt size and daily budget, `guardrails.sanitize`, `select_provider`, infrastructure redaction for external providers, call or `DeterministicProvider`, `scan_output`, `record_ai` | Holds, with one addition: infrastructure addresses are redacted on the way to an external provider |
| Refusals are results | `AiResult(decision="blocked")`, audited in `ai_audit_log` | Holds |
| Deterministic provider as degraded mode, tests hermetic | `DeterministicProvider`; `tests/test_phase6_ai.py` | Holds |

Thirteen capabilities are registered, each bound to a permission (`models/ai.py:66-80`). Provider kinds: OpenAI-compatible, Anthropic, Gemini, Ollama, deterministic.
