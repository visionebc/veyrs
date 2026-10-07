# User Guide

For security engineers, team leads and asset owners working in VEYRS.

## The idea in one paragraph

VEYRS does not show you a list of vulnerabilities. It shows you a list of
**findings** - a specific flaw, on a specific asset, at a specific location -
ranked by what that flaw would actually cost *you*, not by its CVSS score. A 9.8
on an isolated lab box outranked by a 6.5 on your internet-facing payment
gateway is the system working correctly.

## Logging in

```
POST /api/v1/auth/login
{"email": "you@example.com", "password": "...", "organization": "acme"}
```

`organization` is only needed if your email exists in more than one tenant. You
get an access token (30 min) and a refresh token (14 days, rotates on use).

## Your queue

`GET /api/v1/findings?state=new&sort=risk_score&order=desc`

Useful filters: `severity`, `risk_level`, `kev=true`, `epss_min=0.5`,
`sla_breached=true`, `assigned_team_id`, `exposure=internet`.

Or ask in plain language:

```
POST /api/v1/ai/search
{"question": "critical KEV findings on internet-facing systems with EPSS above 0.5"}
```

The response includes the **structured query it actually ran** and a one-sentence
restatement. If the interpretation is wrong, edit the query and re-run it. An
opaque natural-language search in a security tool is a liability - you must be
able to prove what was asked.

## Reading a risk score

Every finding carries five numbers:

| Score | Question |
|---|---|
| Technical | how bad is the flaw itself |
| Exploitability | how likely is it to be used against you |
| Business | what does it threaten |
| Exposure | how reachable is it |
| **VEYRS Risk** | the weighted result, plus policy floors |

`GET /api/v1/findings/{id}` returns `risk_explanation` with every contributing
factor, its raw value, its weight and the points it added - plus any policy
adjustment that fired (`kev_floor`, `age_penalty`, `control_credit`).

For a narrative version:

```
POST /api/v1/ai/findings/{id}/explain
```

The numbers come from VEYRS; only the prose comes from a model. If no model is
available you still get the facts, labelled `degraded`.

## The lifecycle

```
NEW -> TRIAGED -> RISK_ASSESSED -> ASSIGNED -> IN_PROGRESS -> MITIGATION ->
REMEDIATED -> VERIFICATION -> VERIFIED -> CLOSED
```

Side states: `FALSE_POSITIVE`, `DUPLICATE`, `ACCEPTED_RISK`, `EXCEPTION`,
`DEFERRED`.

```
POST /api/v1/findings/{id}/transition   {"to_state": "triaged", "note": "confirmed"}
```

Invalid transitions are refused with the list of legal next states. Every
transition writes a `finding_event` with actor and timestamp.

**A remediated finding that reappears in a later scan is reopened as a
regression**, not silently duplicated - and the SLA clock restarts. A failed
patch does not quietly vanish from the queue.

## Accepting risk

```
POST /api/v1/findings/{id}/accept-risk
{"reason": "compensating WAF rule, vendor fix due Q4", "until": "2026-12-31"}
```

Requires `risk:write`. Acceptance is dated and expires - it reopens on the
`until` date rather than becoming permanent by neglect. Accepted findings are
excluded from MTTR, because closing tickets is not fixing things.

## Tickets

```
POST /api/v1/tickets
{"finding_id": "...", "ticket_type": "remediation", "title": "...", "priority": "critical"}
```

Types follow ITIL: `incident`, `problem`, `change`, `remediation`,
`service_request`. **Change tickets require approval before they can move to
implementation** - the state graph enforces it.

For a starting point:

```
POST /api/v1/ai/findings/{id}/ticket-draft
```

Returns a *draft* with summary, description and acceptance criteria. AI never
creates the ticket; you do, through the normal endpoint with the normal audit
trail.

## SLA

Every finding gets a due date from the first matching SLA policy. Typical:

| Condition | Due |
|---|---|
| Critical + KEV + internet-facing | 4 hours |
| Critical | 24 hours |
| High | 7 days |
| Medium | 30 days |
| Low | 90 days |

Breaches escalate on a ladder (team -> manager -> security manager -> CISO).
**Escalation notifications cannot be muted** - that is the point of them.

`GET /api/v1/dashboard/sla` shows attainment by severity, current breaches and
what is due within three days.

## Uploading an advisory

```
POST /api/v1/documents   (multipart)
```

PDF, DOCX, HTML, XML, CSV, JSON. VEYRS extracts the text, classifies the
document, mines CVEs / products / affected and fixed versions / CVSS vectors, and
correlates against your inventory. Upload a Fortinet PSIRT advisory and you get
back which of your appliances are affected.

Entity extraction is deterministic parsing, not a model - "which CVEs does this
mention" must be complete and reproducible.

## Search

`GET /api/v1/search?q=CVE-2021-44228` searches CVEs, assets, findings, tickets,
documents, knowledge and news - filtered by what you are allowed to see. Exact
identifiers match exactly; `GET /search/semantic` adds vector similarity when
Qdrant is configured, and degrades to lexical when it is not.

## Reports

`GET /api/v1/reports` lists what you can export. Each renders to JSON, CSV, XLSX
or PDF:

```
GET /api/v1/reports/executive/export?format=pdf
```

Every export carries a provenance header: organization, exact moment, VEYRS
version, and a note that figures are a snapshot. Re-generate before relying on
them.

## Things that will surprise you

- **A dashboard number always shows its denominator.** "12 critical" is a
  number; "12 critical of 430 open, on 38 of 512 assets" is information.
- **MTTR over a small sample is flagged unreliable** rather than drawn as a
  confident line.
- **Top assets are ranked by peak risk, not by finding count.** Forty
  informational findings on a lab box do not outrank one KEV on the gateway.
- **Findings missing from a scan are not closed.** They become stale candidates.
  A host that was offline during the scan is not a remediated host.
