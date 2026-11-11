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

`GET /api/v1/findings?state=new&order=risk`

`order` is one of `risk` (default, highest risk first), `sla`, `detected` or
`severity`.

Useful filters: `severity`, `risk_level`, `kev=true`, `min_epss=0.5`,
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
POST /api/v1/findings/{id}/transition   {"state": "triaged", "note": "confirmed"}
```

Invalid transitions are refused with the list of legal next states. Every
transition writes a `finding_event` with actor and timestamp.

**A remediated finding that reappears in a later scan is reopened as a
regression**, not silently duplicated - and the SLA clock restarts. A failed
patch does not quietly vanish from the queue.

**Every close and reopen says why.** The finding's *Why did this change?*
panel (and `GET /api/v1/findings/{id}/attribution`) gives each transition a
cause - re-import absence with the run ids and who vouched for coverage, the
operator, the ticket closed in an external system, the workflow, the expired
acceptance, the installed version that changed - and, for a reopen, which scan
saw it again, how long after closure, and whether the installed version moved
in between. *Work -> Recent changes* lists them across your estate. A cause
that was not recorded is shown as such, naming the missing fact.

## Accepting risk

```
POST /api/v1/findings/{id}/accept-risk?reason=compensating%20WAF%20rule&until=2026-12-31
```

`reason` (at least 10 characters) and the optional `until` date are query
parameters, not a JSON body. Requires `risk:admin`. This direct acceptance
records `until` on the finding but does not reopen it on that date.

For an acceptance that expires on its own, request a formal one with
`POST /api/v1/engagements/risk-acceptances` (`risk:write`); a second named
user approves it, and when its `expires_on` date passes the findings return
to the queue rather than staying accepted by neglect. Accepted findings are
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

### Building your own report

**Reports → Builder** answers the questions the fixed reports do not, such as
"open critical findings per business service and team, with their average
age":

1. **Report on** findings, assets, vulnerabilities, tickets or the risk register.
2. Tick **columns**, or instead pick up to three **group-by** fields and add
   **aggregates** (count, distinct count, average, sum, minimum, maximum).
   *Age (days)* on findings is days since first seen.
3. Add **filters**: field, operator, value. Lists are comma-separated
   (`critical, high`); `last days` takes a number of days.
4. **Run**, then **Export CSV / XLSX** if you need the file.
5. **Save** keeps the report for you. Ticking *Share* shows it to everyone in
   the organization (needs `report:write`); only you can change or delete it.

There is no SQL box, and there will not be: the builder offers a fixed catalog
of fields, and the server rejects anything else. What you see is what your role
and team scope allow. A team-restricted operator gets their own slice, and the
result and every exported file say so on the *Scope* line. A shared report
opened by a colleague shows *their* slice, not yours.

## Things that will surprise you

- **A dashboard number always shows its denominator.** "12 critical" is a
  number; "12 critical of 430 open, on 38 of 512 assets" is information.
- **MTTR over a small sample is flagged unreliable** rather than drawn as a
  confident line.
- **Top assets are ranked by peak risk, not by finding count.** Forty
  informational findings on a lab box do not outrank one KEV on the gateway.
- **A finding missing from one scan is not closed.** It becomes a stale
  candidate; a host that was offline during the scan is not a remediated host.
  Only findings the *same scan test* reported before are counted, and only
  after consecutive misses: 1 for a `ci_cd` engagement, 2 for `scheduled`
  (including the default *Continuous scanning* engagement), never for
  `interactive`. Then the finding moves to `remediated`, not `closed`. The
  import options `close_absent=false` or `absence_threshold` override this.
