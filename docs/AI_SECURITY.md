---
title: AI security
purpose: Explain how VEYRS uses language models without giving them authority, and which guardrails, ceilings and audit records apply.
scope: The AI gateway, guardrails, classification ceilings, grounding, closed query grammar, retrieval and audit at 0.39.1; the choice of models and provider hosting are not covered.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/services/ai/gateway.py, backend/veyrs/services/ai/guardrails.py, backend/veyrs/services/ai/providers.py, backend/veyrs/services/ai/nlquery.py, backend/veyrs/services/ai/capabilities.py, backend/veyrs/api/v1/ai.py, backend/veyrs/config.py, tests/test_phase6_ai.py]
related: [security/security-architecture.md, security/authorization.md, THREAT_MODEL.md, SECURITY.md]
---

# AI Security

How VEYRS uses models without giving them authority. Spec section 20. Source references are to `backend/veyrs/services/ai/` unless stated otherwise; the gateway entry point is `gateway.invoke` (`gateway.py:231`).

## The one rule

**AI is a client of VEYRS, never a privileged path into it.**

Every AI feature can only see what the *asking human* could already see, can
only phrase what VEYRS already computed, and can only recommend — never act.

## The gateway

Nothing calls a provider directly. `services/ai/gateway.invoke()` is the single
door, and it runs eight steps in this order:

1. **Capability check** — is this capability known, and enabled for the tenant?
2. **Authorization check** — does the caller hold the permission the capability
   maps to? `risk_explanation` requires `risk:read`, the same permission a human
   needs to open the risk page.
3. **Budget check** — per-tenant call ceiling over a rolling 24 hours (not a calendar day; default 2000, blocked calls do not count) and a prompt size cap (default 24000 characters) (`gateway.py:272-280`, `gateway.py:186-196`).
4. **Sanitization** — secrets and PII stripped per policy; injection scored.
5. **Provider selection** — the classification of the payload decides whether an
   external endpoint is even eligible.
6. **Call, or degrade** — a provider failure falls back to the deterministic
   backend rather than erroring.
7. **Output guard** — the reply is scanned for secrets before it is returned.
8. **Audit** — written for allowed, degraded **and blocked** calls alike.

Policy refusals are *results*, not exceptions. A blocked call must be visible to
the caller and to the auditor.

Two things are policy switches and one is not. `redact_secrets`, `redact_pii`
and `block_on_injection` are per-tenant policy fields (all on by default); a
tenant administrator with `ai:admin` can turn them off. The output guard in step
7 has no switch (`guardrails.scan_output`). With no provider configured, or none
eligible under policy, the deterministic backend answers and the result is
labelled `degraded`.

## Data classification ceilings

Each tenant sets the highest classification permitted to reach each provider
class:

| Setting | Default | Meaning |
|---|---|---|
| `allow_external` | **false** | Nothing leaves the perimeter at all |
| `allow_local` | true | On-premise models permitted |
| `max_external_classification` | `public` | Ceiling for external providers |
| `max_local_classification` | `internal` | Ceiling for local providers |

Classification is ordered `public < internal < confidential < restricted`, and
it is the *same* enum as asset data classification — one concept, not two copies
that drift.

Risk explanations, remediation advice and ticket drafts are classified
`confidential` (`capabilities.py:253,299,536`); CVE analysis, team suggestion,
threat summaries and natural-language search are `internal`
(`capabilities.py:160,340,411,456`). Under the default policy (external ceiling
`public`) none of them can reach an external provider. Test:
`test_confidential_data_cannot_reach_an_external_provider`
(`tests/test_phase6_ai.py:237`).

**A hosted vendor cannot be relabelled internal.** An administrator may mark a
self-hosted vLLM endpoint internal; marking an `anthropic`, `openai` or `gemini`
endpoint internal has no effect, because that is not a local decision to make
(`providers.py:382`, `INHERENTLY_EXTERNAL`).

The installation-wide defaults come from `VEYRS_AI_ALLOW_EXTERNAL` (false),
`VEYRS_AI_ALLOW_LOCAL` (true) and `VEYRS_AI_MAX_DATA_CLASSIFICATION` (`internal`)
and apply to any tenant without a saved policy (`gateway.py:75-96`,
`backend/veyrs/config.py:94-98`).

## Guardrails

`services/ai/guardrails.py`.

### Secret detection

AWS keys, GitHub/Slack/OpenAI/Anthropic/Google tokens, JWTs, private key blocks,
basic-auth URLs, database connection strings, and `password: ...` assignments.
Ordered most-specific first so the audit record names the precise vendor.

Redaction runs on the way **in**, before provider selection, and again on the way
**out** — a model can echo a secret it saw in context, and there is no policy
switch that makes rendering a live credential into a browser acceptable.

### PII detection

Email, IBAN, credit card, US SSN, Swiss AHV, international phone numbers.

Card numbers pass a **Luhn check** before redaction. Without it, `CVE-2026-0001`
style identifiers and 16-digit build numbers were redacted as card data — the
analyst's own query disappeared from the prompt.

### Infrastructure redaction

RFC1918 addressing is stripped on egress to an external provider even when the
classification ceiling permits the call. Internal topology is not PII, but it is
disclosure.

### Prompt-injection detection

Weighted signals, not a single regex — any one appears in legitimate security
writing ("the exploit instructs the system to…"), but the combination does not:

| Signal | Weight |
|---|---|
| override_instructions ("ignore all previous instructions") | 5 |
| chatml_marker (`<\|im_start\|>`) | 5 |
| exfil_request ("list all customer credentials") | 5 |
| system_prompt_probe | 4 |
| tool_forgery | 4 |
| role_hijack ("you are now…") | 3 |
| fake_role_marker (`### system:`) | 3 |
| encoded_payload | 2 |

Score ≥ 5 blocks under default policy. Injection is **never silently stripped**:
quietly sanitising an attack hides an attack in progress. The attempt is audited
either way.

### Fencing

Ingested third-party content is wrapped in markers the content cannot close —
they are stripped from the body first, so a crafted advisory cannot end the
fence early and have its tail read as instructions. The system prompt declares
fenced text to be data.

## Grounding — the anti-hallucination design

Every capability follows the same shape:

```
gather facts from the database (already tenant- and permission-scoped)
  → render them into a `VEYRS FACTS:` block
    → ask the gateway to narrate/structure them
      → return BOTH the computed facts and the narrative
```

The numbers an analyst acts on — CVSS, EPSS, KEV, risk score, affected asset
count — are **always computed by VEYRS**. The model contributes prose and
prioritisation language.

If no model is reachable, the deterministic provider re-presents the facts
unchanged and the answer is labelled `degraded`. The feature never fabricates and
never disappears.

Prompts explicitly forbid inventing CVE identifiers, CVSS vectors, EPSS values,
affected versions or regulatory requirements.

## Structured output is validated, never trusted

- **Natural-language search** — the model emits JSON against a closed grammar
  (`services/ai/nlquery.FIELDS`). Every field, operator and value is validated;
  an unknown field yields an error, not a query. VEYRS compiles the SQL itself
  and appends the tenant predicate unconditionally. `GET /ai/search/grammar`
  publishes the entire allowed surface so users can verify it.
- **Team suggestion** — the model picks from the tenant's *actual* team list. A
  hallucinated team is rejected with a reason rather than silently ignored.
- **Ticket draft** — returned as a DRAFT. AI never creates the ticket; the
  caller does, through the normal authorized endpoint with the normal audit
  trail.

## Retrieval

The assistant grounds on `services/search.search()` — the **same**
permission-aware function a human uses. There is no second, unfiltered retrieval
path. That is how "AI must never bypass VEYRS authorization" is satisfied
structurally rather than by promise.

Conversations record a snapshot of the asker's permissions and are private to
their author: another user's questions reveal what they were investigating.
Platform administrators can open any conversation of their tenant
(`backend/veyrs/api/v1/ai.py:517,580`).

AI routes are refused outright to team-restricted principals (`ai` is in
`REFUSED_TAGS`, `security/scope.py:98`), because the assistant cannot narrow its
answers to a team. Global search, which the assistant's retrieval is modelled on,
is **not** team-scoped (see [Authorization](security/authorization.md#5-team-scope)).

## No tool calling

VEYRS does not expose provider-native tool calling to tenants. A model that can
invoke tools inside a multi-tenant security product is an authorization boundary
made of prose.

## Audit

`ai_audit_log` records, per call: capability, provider, model, whether it was
external, data classification, decision (`allowed | degraded | blocked`), block
reason, token counts, duration, the redaction report, and a **digest** of the
prompt. The prompt itself is not stored.

`GET /ai/audit` exposes it, filterable by decision, and requires `audit:read`. `POST /ai/scan` lets an
operator dry-run the guardrails on arbitrary text — answering "would this
document be allowed out?" before enabling an external provider. It returns the
report only, never the redacted text, so it cannot be used as an oracle to
confirm a guessed secret.

## Configuration

```bash
PUT /api/v1/ai/policy
{
  "allow_external": false,
  "allow_local": true,
  "allowed_providers": ["local-ollama"],
  "allowed_models": ["qwen3:32b"],
  "max_external_classification": "public",
  "max_local_classification": "confidential",
  "redact_secrets": true,
  "redact_pii": true,
  "block_on_injection": true,
  "disabled_capabilities": ["ticket_draft"],
  "daily_call_limit": 2000
}
```
