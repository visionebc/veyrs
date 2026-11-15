# AI Security

How VEYRS uses models without giving them authority. Spec section 20.

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
3. **Budget check** — per-tenant daily call ceiling and prompt size cap.
4. **Sanitization** — secrets and PII stripped per policy; injection scored.
5. **Provider selection** — the classification of the payload decides whether an
   external endpoint is even eligible.
6. **Call, or degrade** — a provider failure falls back to the deterministic
   backend rather than erroring.
7. **Output guard** — the reply is scanned for secrets before it is returned.
8. **Audit** — written for allowed, degraded **and blocked** calls alike.

Policy refusals are *results*, not exceptions. A blocked call must be visible to
the caller and to the auditor.

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

Risk explanations and remediation advice are classified `confidential`, so under
default policy they can **never** reach an external provider. Test:
`test_confidential_data_cannot_reach_an_external_provider`.

**A hosted vendor cannot be relabelled internal.** An administrator may mark a
self-hosted vLLM endpoint internal; marking an `anthropic` or `openai` endpoint
internal has no effect, because that is not a local decision to make.

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

## No tool calling

VEYRS does not expose provider-native tool calling to tenants. A model that can
invoke tools inside a multi-tenant security product is an authorization boundary
made of prose.

## Audit

`ai_audit_log` records, per call: capability, provider, model, whether it was
external, data classification, decision (`allowed | degraded | blocked`), block
reason, token counts, duration, the redaction report, and a **digest** of the
prompt. The prompt itself is not stored.

`GET /ai/audit` exposes it, filterable by decision. `POST /ai/scan` lets an
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
