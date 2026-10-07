# VEYRS User Manual

For the people who run VEYRS day to day: security engineers triaging findings,
team leads answering for an SLA, asset owners who want to know why their box is
on a list, and the administrator who has to explain all of it to an auditor.

This manual is longer than the [User Guide](USER_GUIDE.md) on purpose. The
guide tells you which endpoint to call; this tells you what the system will do
with the call, and which of its answers you should not trust at face value.

---

## 1. What VEYRS is, and what it refuses to be

VEYRS is a **risk** platform, not a scanner and not a vulnerability list.

The distinction is operational, not marketing. A scanner answers *"what is
wrong with this host?"*. VEYRS answers *"of everything wrong across the
estate, what should this team fix this week, and what happens if they don't?"*
Those are different questions and they sort differently. A CVSS 9.8 on an
isolated lab box ranked below a 6.5 on an internet-facing payment gateway is
the system working correctly, not a bug.

**The concept chain** — it is on the login screen because it is the actual data
flow, not a slogan:

> **Visibility → Exposure → Risk → Action → Security**

- **Visibility** — assets and the software installed on them.
- **Exposure** — where that asset sits: internet-facing, internal, isolated.
- **Risk** — severity combined with exploitability (EPSS), known exploitation
  (CISA KEV), exposure and business impact.
- **Action** — a ticket with an owner and an SLA.
- **Security** — the finding is verified fixed by a subsequent scan, not by
  someone ticking a box.

The name is the same chain: **V**isibility · **E**xposure · **Y**ield · **R**isk
· **S**ecurity.

### Three things VEYRS deliberately will not do

1. **It will not guess which asset a finding belongs to.** A SAST, SCA or cloud
   report with no host of its own is *rejected* unless the import names a
   `target_asset`. Inferring would be convenient and occasionally wrong, and a
   finding filed against the wrong asset is worse than a finding that failed to
   import loudly.
2. **It will not let an external system close a security finding.** ITSM
   webhooks and status pulls are advisory by default. Jira moving a ticket to
   *Done* updates the ticket's remote status in VEYRS and nothing else, unless
   an administrator has explicitly mapped that transition.
3. **It will not treat "the scanner did not crash" as evidence of a fix.** See
   §7 — this is the single most important idea in the product.

### Finding versus vulnerability — the distinction everything else rests on

These are two different tables and two different scales, and mixing them up is
the fastest way to misread every number on this console.

| | **Vulnerability** | **Finding** |
|---|---|---|
| What it is | The problem, at the level of your organization — normally one CVE | That vulnerability **on one asset** |
| Is it the unit of work? | No | **Yes** — it has a state, an owner, an SLA deadline and a ticket |
| Its risk score | The **maximum** of its open findings | Computed for this asset (§9) |

> CVE-2024-21762 on twelve servers is **one vulnerability and twelve findings.**

The rollup takes the maximum rather than the average deliberately: averaging
would hide the single internet-facing server among twenty lab boxes, which is
precisely the one you needed to see.

Practically: work the **Findings** list. Use **Vulnerabilities** when you want
to ask "how many of these do I have, and where", or to hand somebody a single
CVE to eradicate across the estate.

---

## 2. Finding your way around the console

The navigation splits along one axis: **what you do every day**, and **what you
set up once**. Before v0.21.0 it did not, and both halves suffered — an analyst
had to walk past workflow definitions and compliance frameworks to reach their
queue, and a platform decision like the SLA policy sat in the same visual rank
as a list of tickets.

| Group | What lives there | How often you touch it |
|---|---|---|
| **Overview** | **Triage queue**, Getting Started, Dashboards | Every day, all day |
| **Work** | Findings, Tickets, Vulnerabilities | Constantly |
| **Estate** | Inventory | Weekly |
| **Intelligence** | Threat Intel, Documents & Advisories, Knowledge Base, AI Assistant | As needed |
| **Reporting** | Reports, Compliance, Audit Log | Monthly, or when asked |
| **Tools** | CVSS Calculator | When you reach for it |
| **Configure** | Vulnerability scanner*, Data sources, SLA & Policies, Automation, Administration | Rarely, and on purpose |

\* **Vulnerability scanner is only in the menu while this deployment scans.**
With active scanning off (*Administration → Scanning*), VEYRS is an
ingest-only platform: it probes nothing, so the runner, its queue and its
jobs leave the sidebar and the command palette. What does **not** leave is
*Administration → Scanning* itself — hiding the switch with the thing it
controls would be a one-way door — nor *Data sources*, which is how an
ingest-only deployment receives findings at all. The page also stays
reachable at `#/scanner`, so an old bookmark lands on the screen that
explains the mode rather than on a dead hash.

**The console opens on the Triage queue, not on a dashboard.** That changed
in v0.22.0 and it was not a cosmetic decision: production had 408 findings,
149 of which nobody had ever opened, and 5 tickets. Every screen answered
*how bad is it*; none of them was a place to do anything about it. A
dashboard is a report. Anyone who wants the numbers is one click away in the
nav — nobody was one click away from acting on them.

Three moves that may surprise somebody who knew the old layout:

- **The `Governance` group is gone.** It held four unrelated things whose only
  common property was that senior people cared about them. Compliance and
  Reports are *outputs* and moved to Reporting; Integrations and Administration
  are *setup* and moved to Configure.
- **The vulnerability scanner moved to Configure.** It used to sit first under
  `Risk`, on the reasoning that a reader who cannot find what produced the
  findings assumes nothing did. That concern is still right — so the Findings
  page itself now names its three producers and links to each. The scanner page
  is a runner, a queue and a job list: it is configuration, and using its menu
  position as documentation was solving the wrong problem.

Every configuration screen carries a **?** panel answering the same three
questions in the same order: *what this decides*, *who normally touches it*,
and *what changes if you change it*. The third one is the one that used to be
missing. "Escalation policy" tells you what the row is called; "raise a level
here and the CISO starts getting paged at hour 24" tells you whether to touch
it.

---

## 3. Signing in

```
POST /api/v1/auth/login
{"email": "you@example.com", "password": "...", "organization": "acme"}
```

`organization` is only required when your email exists in more than one tenant;
if it does and you omit it, you get a `409` listing the slugs you may choose
from — **but only after your password has already been verified**, so the
endpoint cannot be used to enumerate tenants.

You receive an **access token** (30 minutes) and a **refresh token** (14 days).
The refresh token rotates on every use. Presenting one that has already been
rotated revokes the entire token family, because the only ordinary explanation
for a replayed refresh token is that someone else has a copy.

Failed logins are counted per user, not per IP: **10 failures locks the account
for 15 minutes**, so a distributed attempt does not get a fresh budget from
each source address.

### Two-factor authentication

MFA is time-based one-time passwords (TOTP, RFC 6238) — Google Authenticator,
Aegis, 1Password, anything standard.

Enrolment is deliberately **three steps**, because enabling in one step is how
administrators lock themselves out of the console they administer:

```
POST /api/v1/auth/mfa/enroll     -> {"secret": "...", "provisioning_uri": "otpauth://..."}
POST /api/v1/auth/mfa/activate   {"code": "123456"}
```

`enroll` returns the shared secret **once** and stores it encrypted. Your
account is still password-only at this point. `activate` is where you prove
your authenticator actually generates correct codes; only then is MFA enforced
at login.

After that, login carries the code:

```
POST /api/v1/auth/login
{"email": "...", "password": "...", "mfa_code": "123456"}
```

Omitting it returns `401 {"error": "mfa_required"}` — a challenge, not a
failure, so it does not consume your lockout budget. A **wrong** code does
consume it, and shares the same ten-attempt budget as the password: separate
budgets would let anyone who already has your password make unlimited guesses
at six digits.

Turning MFA off requires **both** factors:

```
POST /api/v1/auth/mfa/disable    {"password": "...", "code": "123456"}
```

A stolen access token on its own cannot strip the second factor off the account
it was stolen from.

**Things that will look like bugs and are not:**

- A code is **single-use**. Re-submitting the same six digits inside the same
  30-second window is refused, because a code read off a proxy log or over your
  shoulder should be worth nothing.
- Codes from the previous and next 30-second step are accepted (clock skew).
  Two steps out is refused; that is the standard tolerance and it is a constant,
  not a setting, because widening it multiplies the guess space.
- If your account says MFA is enabled but the stored secret is unreadable, you
  cannot log in at all. That is intentional: silently falling back to
  password-only would downgrade exactly the account that asked for more. An
  administrator has to clear the flag.

---

## 4. Your queue

### The triage queue (`#/triage`)

The console's landing screen, and the only one where work leaves the queue. It
hands you one open finding at a time with everything needed to judge it — the
asset and how exposed it is, the CVE, EPSS, KEV, the deadline, the risk factors
and the recommended fix — and four verbs.

| Key | What it does | What it commits you to |
|---|---|---|
| `T` | **Create ticket** | Opens remediation work with an SLA and an owner. A finding that already has an open remediation ticket keeps it — the server returns the existing one rather than doubling it. |
| `A` | **Assign to team** | Changes whose queue it is in. It does **not** change the finding's state. |
| `F` | **False positive** | Closes it. If the same scan reports it again it comes back as `new` — VEYRS does not remember a verdict across detections, so write down *why* or the next person repeats your work. |
| `R` | **Accept risk** | A formal, audited business decision. Needs `risk:admin`, not `finding:write`. |
| `S` | **Skip** | Leaves it in the queue. Use it; a decision you are not ready to make is not a decision. |
| `J` / `K` | Move down / up | |
| `↵` | Open the full finding | |

Two behaviours worth knowing:

- **Accepting a risk on a finding in `new` moves it to `triaged` first**, and
  the dialog says so. The lifecycle has no edge straight from `new` to
  `accepted_risk`, and 149 of production's 408 findings are in `new` — an
  Accept button that did not know this would fail on the most common case on
  the screen.
- **A disposed finding leaves the queue immediately** and the counter drops.
  The buffer refills from the next page before the queue is declared clear, so
  "12 of 149" always counts work still to do.

The keyboard is inert while you are typing in a field or while a dialog is
open. A keystroke that fired mid-sentence would dispose of the finding you were
explaining.

### Saved views

The queue tabs cover the five questions the product anticipated. Everything
else — *critical, internet-facing, my team, not yet ticketed* — is a filter set
you would otherwise rebuild every morning, which is a filter set you stop using
by Thursday.

**Save this view** stores it. Saved views appear as chips on the triage queue
and on the Findings, Tickets, Assets and Vulnerabilities lists, and in the
command palette. Three starters are seeded on your first visit; delete them and
they stay deleted.

A view stores **the question, not the answer**. Applying it goes back through
the normal list endpoint, so what you see is whatever your permissions and team
scope allow at that moment. Sharing a view makes it *visible* to your
organization — only you can rename or delete it, and a colleague opening your
estate-wide view still sees only their own slice.

### The command palette

`⌘K` (macOS) or `Ctrl-K` searches the navigation, the triage queues, your saved
views and — through the same permission-aware endpoint as the Search page —
CVEs, findings, assets, vulnerabilities, tickets, documents and articles. It
never offers a screen your role cannot open, and never returns a row you are
not entitled to.

### The API behind it

```
GET /api/v1/findings?state=new&order=risk&page=1&size=50
```

Useful filters: `severity`, `risk_level`, `min_risk`, `kev=true`,
`min_epss=0.5`, `sla_breached=true`, `exposure=internet`, and for ownership
**`owning_team_id`** rather than `assigned_team_id` — most findings are
never explicitly assigned and inherit the team that owns their asset, so
filtering on the raw column answers *"this team has no work"* for a fully
owned estate. `my_teams=true`, `mine=true` and `unowned=true` are the
shorthands for the three queues that matter.

Paging is `page`/`size`, as on every list route except users, audit, agents,
teams and imports, which take `limit`/`offset`.

Plain language works too:

```
POST /api/v1/ai/search
{"question": "critical KEV findings on internet-facing systems with EPSS above 0.5"}
```

The response includes **the structured query it actually ran**, plus a one
sentence restatement of how it understood you. Read it. If the interpretation
is wrong, edit the structured query and re-run. An opaque natural-language
search in a security tool is a liability: you must be able to prove to an
auditor what was asked, not just what came back.

### What the ranking actually means

`risk_score` is not CVSS. It combines:

| Input | Source | Why it moves the number |
|---|---|---|
| Severity | CVSS v2/v3/v4 from the advisory | How bad the flaw is in the abstract |
| **EPSS** | FIRST, refreshed nightly | Probability of exploitation in the next 30 days |
| **KEV** | CISA, refreshed nightly | Someone *is* exploiting this, right now |
| Exposure | Your asset register | Internet-facing beats isolated |
| Business impact | Your asset criticality | A payment gateway beats a lab box |

KEV is the input that should change your day. EPSS is a probability; KEV is an
observation.

### States, and what they commit you to

`new → triaged → risk_assessed → assigned → in_progress → mitigation →
remediated → verification → verified → closed`, with `false_positive`,
`duplicate`, `accepted_risk` and `exception` as terminal side exits.
(Earlier editions of this manual named states — `confirmed`, `resolved`,
`risk_accepted` — that the platform has never had. The list above is the
`FindingState` enum.)

**`remediated` is a claim; `verified` is evidence.** Only a subsequent scan
that does *not* see the finding moves it through `verification` to verified. If you find yourself with a
large `resolved` population that never becomes `verified`, the scan that would
confirm it is not running against those assets — that is the finding.

`accepted_risk` records the accepting party and a reason of at least ten
characters. **The expiry is optional and should not be**: an acceptance with
no end date outlives the facts it was made under. The triage dialog asks for
one and the platform does not yet refuse an acceptance without it — treat
that as a gap in the product, not as permission.

---

## 5. Assets and inventory — the part that silently fails

An **asset** is a machine, a service, a container image or a cloud account. It
carries the exposure and criticality that the risk score depends on, so an
asset register that is wrong makes every number downstream wrong in a way that
looks perfectly plausible.

### The identity trap

This is the most important paragraph in the manual for anyone loading
inventory.

NVD builds its product dictionary from CPE tokens. In that dictionary nginx is
**`f5:nginx`**. If your inventory says `vendor="Nginx"`, VEYRS used to create a
*second* product row, the CPE match never joined, and your tenant read as
**unaffected — silently and completely**. No error, no warning, just a clean
report.

VEYRS now resolves identity most-authoritative-first: explicit CPE → dictionary
hit → product token disambiguated by which candidate CVEs actually cite it →
curated aliases → recorded but unmatched. What you must understand is that the
last state exists and is *normal*: some software will not match, and VEYRS says
so rather than pretending.

Two different questions, and you must not confuse them:

```
GET /api/v1/assets/inventory/coverage
```

- **anchored** — the identity is pinned to a real dictionary entry.
- **matched** — advisories actually reference it.

"Nothing is vulnerable" and "nothing is matchable" look **identical** in every
other view in the product. Only one of them is good news. Check coverage before
you report a clean estate.

### Versions

`AssetProduct.raw_version` stores what the collector actually saw
(`1:1.24.0-2ubuntu7.1`). Matching uses the upstream version (`1.24.0`) because
otherwise it never fires. But distributions backport fixes *without* moving the
upstream version, so a match against `1.24.0` may describe something your
distro already patched. The verbatim string is what lets an analyst tell the
difference — that is why both are kept.

Collectors send `raw_version` **only**. The normalisation rule lives on the
server, because a collector carrying its own copy of that rule is a rule that
drifts.

### Loading inventory

```
POST /api/v1/assets/{id}/products/bulk
POST /api/v1/assets/inventory/import
POST /api/v1/assets/inventory/resolve      # dry run: shows what would match, rolls back
GET  /api/v1/assets/inventory/coverage
GET  /api/v1/assets/inventory/aliases
```

Use `resolve` before `import` on anything unfamiliar. It tells you what the
identity resolver will do without writing a row.

### Appliance firmware

Network appliance inventory (FortiWeb, FortiADC, FortiAnalyzer…) is pulled
**from SATOM**, which already owns those devices' credentials. VEYRS carries a
read token, not ten admin passwords: a second copy of every appliance
credential inside the vulnerability platform would make VEYRS the most valuable
target on the network.

Authority runs one way. SATOM owns device identity; VEYRS never writes back to
SATOM except to *ask* for a re-read. Two rules follow from that:

- Firmware strings arrive **verbatim** (`FortiWeb-KVM 7.6.8,build1128(GA.M),260602`).
  Normalisation is a matching rule and belongs to whoever owns the dictionary.
- `firmware_checked_at == null` means **nobody ever confirmed that version
  against the live device**. VEYRS imports it but does not correlate it. An
  unattested version is not evidence.

---

## 6. Getting scan results in

### The imports themselves

Twenty parsers ship in the box (Nessus, Qualys, Greenbone, Trivy, Grype,
Nuclei, ZAP, Semgrep, Prowler, Dependabot, generic CSV/JSON, …). Every import
is scoped to an **engagement**; imports that name none land in the tenant's
auto-created *"Continuous scanning"* engagement.

**After every import, read two fields:**

```
GET /api/v1/engagements/imports/{run_id}
-> records_rejected, reject_reasons
```

An import run reporting *"succeeded, 12 updated"* while discarding 45% of the
scanner's output is a real thing that has happened here. `succeeded` means the
file parsed, not that the findings landed.

### Pulling from a scanner instead of uploading to it

*Integrations → Scanner connectors.* Three drivers: **Nessus Professional /
Manager**, **Tenable Vulnerability Management** (cloud) and **Tenable Security
Center**.

A connector downloads the same `.nessus` file you would have exported by hand
and feeds it to the **same parser**. Nothing about deduplication, engagement
scoping, rejection counting or absence handling changes because the bytes
arrived over the network — which is the point. If you know how an upload
behaves, you know how a pull behaves.

**The three refusals you will meet, in the order you will meet them:**

1. **A new connector is disabled.** Enrol it, press *Test* to prove the
   credentials work, then enable it. Nothing reaches out until you do.
2. **A connector with no allowed scans is inert.** Press *Scans*, tick the
   scans it may pull, save. An empty list does not mean "all of them" — it
   means the connector refuses every sync. The list you tick is the blast
   radius of every future sync, so it is a decision, not a filter.
3. **`close_absent` needs an engagement.** A pull covering three hosts cannot
   answer for the rest of the estate; without a scope, closing what is absent
   would mark hosts the scan never looked at as remediated.

**Dry run first.** The sync dialog defaults to it. A dry run parses, reports and
writes nothing — including writing nothing to the connector's memory of what it
has already imported, so the real sync afterwards is not skipped.

**A scan whose export is byte-identical to the last one imported is skipped**,
and says so. That is not an error: it is the connector declining to re-ingest
an unchanged file and inflate your *updated* counts. Tick *force* if you
genuinely want it re-imported.

**Each scan becomes its own import run.** If you sync four scans and one
rejects half its records, you will see which one. Read `records_rejected` on
each run, exactly as with an upload.

**Where it runs.** A sync is triggered by an operator and executes on the node
that served the request. Enrolling a connector is an estate-wide action, so a
team-scoped identity is refused rather than shown a narrowed list.

### Deduplication

Dedup is **per scanner** and configurable — four algorithms, inspectable live:

```
GET /api/v1/engagements/dedupe-registry
```

Do not change a scanner's algorithm casually. Re-keying a finding creates a
duplicate rather than updating the original, so the estate appears to double
overnight and every trend line breaks.

Scanner granularity is respected rather than normalised: ZAP emits one alert
with N endpoints (one finding); Nuclei emits one match per URL (N findings).
Their dedup configurations differ accordingly. This is intentional — flattening
them would misrepresent what each tool actually observed.

### Closing findings on reimport

Reimport closure is scoped to **the sightings of a specific scan test**, never
to a whole scanner. A scanner-wide scope was a real defect once: a three-host
export closed the entire estate.

Closure also requires *consecutive* absences, by scan type:

| Scan type | Absences required to close |
|---|---|
| `ci_cd` | 1 |
| `scheduled` | 2 |
| `interactive` | never |

---

## 7. Running scanners — and why a green scan can be a lie

VEYRS runs scanners as well as ingesting them, through **agents**: small
runners you place on a jump host.

### What nuclei is, and what VEYRS does with it

The scanner VEYRS drives is [nuclei](https://github.com/projectdiscovery/nuclei),
from ProjectDiscovery. Two sentences of theory, because the design of
everything below follows from them:

**Nuclei is a template engine, not a reasoning engine.** Every check is a YAML
file describing a request to send and a condition that means "hit" — a banner
substring, a path that should not exist, a response header, a status code. It
does no inference: it pattern-matches against real responses. That is why it is
fast, why it is safe to point at production, and why it finds *exposures and
misconfigurations* far better than it finds logic flaws.

**VEYRS does not embed it.** The agent shells out to the binary and parses its
JSONL output. The command it builds:

```
nuclei -target <target> -jsonl -output <file> -silent
       -rate-limit 150 -timeout 10
       [-severity critical,high]          # profile: quick
       [-tags cves|exposures|misconfiguration]
       -resolvers <sanitised copy of the internal resolver>
       -stats -stats-json -stats-interval 10
```

Three details in there are load-bearing:

- **Template selection is a closed enum**, never a path. `quick` (critical and
  high only) and `full` (everything) are choices, and the tag list is fixed. A
  free-form template path arriving from the server would be remote code
  execution wearing a configuration field.
- **`-resolvers` is not optional.** Nuclei's dialer carries public resolvers
  compiled in and ignores the system resolver entirely. On a split-horizon
  network that means it resolves an internal name to its public address, cannot
  route there, and exits 0 having scanned nothing. See the coverage table below
  — this is not hypothetical, it is where the 5% figure came from.
- **`-stats-json` is the only thing** that distinguishes an aborted scan from a
  clean one. Without it, both produce an empty file and a zero exit code.

Results are then normalised into findings exactly like an imported report: same
parser contract, same dedupe key, same correlation. A scan that runs here and a
report you upload by hand converge on the same rows.

> **The internal runner has been dead since 17 August 2026, and this is
> deliberate.** `veyrs-agent.service` is `active (running)`, the agent row says
> `busy`, and its log is an endless `POST /agents/self/heartbeat -> 405`. The
> cause is `VEYRS_URL` in `/etc/veyrs-agent/agent.env` still pointing at
> `veyrs.example.com`, a name retired behind a **301** — the HTTP
> client follows the redirect, downgrades POST to GET, and there is no GET
> handler. It has not been repaired because repairing it would *revive* the
> scanner, and this deployment was deliberately switched to ingest-only
> (*Administration → Scanning*). Two general lessons worth keeping: **an
> `active` systemd unit is not evidence a service is working**, and **retiring
> a hostname behind a 301 breaks every non-browser POST client pointed at it.**

### Enrolment grants nothing

An enrolled agent is inert until **two** switches are on:

1. `AgentTool.enabled` — an operator decision, default false. A *declared* tool
   is not an *authorised* tool.
2. A non-empty `allowed_targets` — deny by default, so an agent enrolled and
   forgotten cannot scan anything.

If a job is refused, check those two before anything else.

### Target rules that look like bugs and are not

- **A hostname target never matches a CIDR rule.** That is a DNS-rebinding
  guard: allow `*.acme.com`, not `10.0.0.0/8`, for named hosts.
- **Loopback, link-local and multicast** (including `169.254.169.254`, the
  cloud metadata address) need an **exact literal** entry. A CIDR that merely
  contains them is refused.
- `require_asset_match` (default true) also demands the host exist in your
  asset register.
- Targets are authorised **twice**: at queue time, and again against the
  claiming agent's own policy. An unpinned job silently skipping an agent is
  that second check doing its job.

### The lesson: coverage, not output size

Two scans of two similar hosts. Both exited 0. Both wrote **zero bytes**. One
was a clean host; the other never reached its target at all.

The cause: **the scanner does not use the system resolver.** Nuclei's dialer
carries public resolvers compiled in, so on a split-horizon network it resolved
an internal name to the public address and could not route there. `dig` and
`getent` from the same machine answered correctly — checking the OS resolver
proves nothing about what the scanner will do.

| | requests completed | errors |
|---|---|---|
| default resolvers | **5%** | 703 |
| explicit internal resolver | **97%** | 108 |

Zero bytes was legitimate for one of them. **Payload size cannot distinguish a
blind scan from a clean one. Coverage can.** So:

- Agents report scan statistics plus a reachability probe taken with the
  *system* resolver. **When the probe and the scanner disagree, that is the
  diagnosis.**
- Server policy: below **80% coverage** or above a **50% error rate**, the job
  is marked **failed**, whatever its exit code.
- **An empty result closes findings only with a positive attestation.** An
  unattested result is still imported — what it saw is real — but it closes
  nothing. An empty *unattested* result is refused outright.
- A **crashed** scan never closes a finding, and a crashed scan with no output
  is not imported at all.

If a job failed and you want to know why, `job.error` carries the tail of the
runner's own output. `no templates provided for scan` is much more useful than
`exit code 1`, and that is why it is there.

---

## 8. Where the intelligence comes from, and how often

Nothing here is discovered by scanning. **CVEs arrive by feed**; what a scanner
or an import contributes is *which software you have*. The join between the two
is what produces a finding.

Four feeds, in this order, and the order is not cosmetic:

| # | Feed | Source | What it does |
|---|---|---|---|
| 0 | **CWE** | `cwe.mitre.org/data/xml/cwec_latest.xml.zip` | Names the weakness classes. Creates nothing. |
| 1 | **NVD** | `services.nvd.nist.gov/rest/json/cves/2.0` | Creates and updates the CVE records, and **correlates them against your inventory — this is what raises findings.** |
| 2 | **EPSS** | `epss.empiricalsecurity.com/epss_scores-current.csv.gz` | Probability the CVE will be exploited in the next 30 days. **Rescores only.** |
| 3 | **KEV** | CISA Known Exploited Vulnerabilities catalogue | Confirmed exploitation in the wild. **Rescores only.** |

Why that order:

- **CWE first** because it is cheap (one 2 MB file) and it *names* the
  placeholder rows NVD is about to create. Run last, every new weakness would
  show as a bare number under a column headed "Name" until the following day.
- **EPSS after NVD** because EPSS skips CVEs it has never seen. Run first, a
  day's new records carry no exploit probability for twenty-four hours.
- **KEV last** because it is the strongest urgency signal and should be the
  final word on the day's priority order.

**EPSS and KEV never create findings.** A probability or an exploitation flag
does not change *what software is affected*, so correlating over them would
mean a quarter of a million inventory queries every night to learn nothing.

### The cadence is a setting, not a timer

*Threat Intel → Schedule*, or `GET`/`PUT /api/v1/intel/schedule`.

Before v0.21.0 the schedule lived in a systemd unit on the primary node: the
only way to make KEV hourly during an active exploitation event was to SSH in
and edit `veyrs-intel-sync.timer`. That is a deployment detail wearing a
setting's clothes.

Now the timer **ticks hourly** and asks the database what is actually due. Each
feed carries its own interval, between 1 hour and 30 days, plus an on/off
switch. The defaults reproduce exactly what a deployment did before — all four
enabled, all four daily — because an upgrade must not change what a system
does.

Two properties worth understanding before you read the screen:

1. **"Due" is measured from the last *successful* run.** A failure does not
   reset the clock. If NVD errors at 03:30, the feed is still as stale as it
   was and still reports itself as due — treating the failure as a refresh is
   how an outage becomes a week of quietly old data.
2. **The corpus is shared, so the effective cadence may be tighter than
   yours.** `cves`, `epss_scores`, `kev_entries` and `cwe` have no
   `organization_id`: CVE-2024-3094 is the same row for every tenant. So your
   setting is a *demand*, and what actually runs is the **tightest demand
   across every active organization**. If you ask for daily and the screen says
   hourly is in force, another tenant asked for hourly. That is not a bug, and
   it is why both numbers are shown side by side. Averaging them would give
   everybody a cadence nobody chose; taking the loosest would let one tenant's
   monthly setting starve another's hourly one, silently, in the direction of
   stale intelligence.

Changing the schedule needs `intel:write` and an estate-wide grant: a
team-scoped identity is refused, because this is not a decision that can be
narrowed to one team's slice of an estate.

From the command line, `python -m veyrs intel-due` prints what the next tick
would run **and why each feed was skipped**. A tick that skips everything and
prints nothing is indistinguishable from one that crashed before it started —
which is precisely how three consecutive nights of feed failures went unseen in
August 2026.

There is no NVD API key configured, so the rate limit is 5 requests per 30
seconds. A **full backfill takes hours, not minutes.**

### The estate lens: why the catalogue is huge and your lists are not

*Threat Intel → CVE* and *Threat Intel → CISA KEV* show, **by default, only the
records whose applicability names software this organization actually runs.**
On a typical deployment that is a few thousand CVEs out of ~360 000, and single
digits out of the ~1 700 KEV entries. A **Whole catalogue** button next to each
list widens it, and the row counts are printed on both buttons so you can always
see what you are not looking at.

The most common question about this screen is why VEYRS stores the other 99 %
at all — if we do not run a particular database engine, why is its CVE in the
system? The answer is that **correlation is computed *from* the catalogue.**
`cve`, `vendors`, `products` and `cve_cpe_match` are a shared dictionary with no
tenant column; a finding exists because a row in *your* inventory joins to a row
in *that* dictionary. A CVE that was never ingested cannot fail to match an
asset — it is simply absent, and absence renders on screen as *not affected*.
Downloading "only what affects us" is circular: you need the record present
before you can decide whether it applies. It also breaks the two cases the
catalogue is for — *"a bulletin just landed, does it touch us?"* and *"we are
considering this component, what is its history?"* — neither of which can be
answered from a list that only contains what already affects you.

> **The cost of the lens, stated plainly: under it, your inventory becomes the
> boundary of what you can see.** A package that never resolved to a CPE has no
> product id, so its CVEs are not shown as *unmatched* — they are outside the
> filter entirely. This is why the counters always print both numbers
> (*"2 578 of 359 353"*), why *Products resolved* sits beside them, and why an
> unresolved inventory raises a banner on the screen. **An empty filtered list
> and a clean estate look identical; only one of them is good news.** If the
> estate count drops sharply, suspect the inventory before you celebrate.

The lens is product-level, not finding-level, and that is deliberate: a CVE for
nginx 1.20 while you run 1.28 stays in your list. It is yours the day somebody
rolls a host back. The narrower question — *which assets have an open finding* —
is the **Your assets** column on the same table, and the Findings page.

---

## 9. How the risk score is computed

Every finding carries a **VEYRS risk score** from 0 to 100. It is not CVSS.
CVSS says how bad the flaw is in the abstract; the risk score says how much
this instance of it should worry *you*, and it is the number the queue sorts by.

```
score = 0.30 · Technical  +  0.30 · Exploitability
      + 0.25 · Business   +  0.15 · Exposure
```

The four weights are editable per profile (*SLA & Policies → Risk profiles*).
The shipped default is `balanced`; `technical-security`, `executive-risk`,
`internet-exposure` and `compliance` ship alongside it.

### The four sub-scores

| Sub-score | How it is built |
|---|---|
| **Technical** | `CVSS × 10`. **A finding with no CVSS scores 40, not 0** — unknown is not the same as harmless, and defaulting it to zero would bury every unscored finding. |
| **Exploitability** | `√EPSS × 60`, plus `+30` if the CVE is in CISA KEV, plus `+15` for observed active exploitation / `+10` for a known exploit / `+5` for a public PoC. The square root is deliberate: EPSS is heavily skewed towards zero, and a linear term would flatten the entire distribution into the bottom of the range. |
| **Business** | `criticality × 55 + data classification × 25 + environment × 10`, plus a bonus when the business service is more critical than the asset itself, plus a revenue band bonus (100k/10k/1k/100 per hour of outage → 10/7/4/2 points). |
| **Exposure** | `exposure weight × 60` (internet 1.0, partner 0.7, internal 0.4, isolated 0.1) `+` attack vector (N 25, A 15, L 8, P 2) `+ 15` when the CVSS vector says `PR:N` and `UI:N`, **minus** credit for compensating controls (WAF 20%, segmentation 25%, not reachable 40%, …, capped at 50%). |

### Then three floors and one penalty

- KEV ⇒ at least **75**
- Internet-facing **and** KEV ⇒ at least **90**
- Actively exploited ⇒ at least **80**
- **+3 points per 30 days past its SLA deadline**, capped at +15. Age is a risk
  factor because an overdue finding is one somebody has already decided not to
  fix.

Bands: **≥90 critical · ≥70 high · ≥40 medium · ≥10 low**. Those thresholds are
the same ones automatic ticketing and the ticket priority mapping use, which is
why re-weighting a profile is not a cosmetic change — see §11.

### Every score explains itself

Each finding stores a `risk_explanation`: factor, value, and points
contributed. That is the auditable answer to *"why is this a 92?"*, and it is
what the *Explain* button on a finding renders. If a number ever looks wrong,
read the explanation before the code — it will usually name the asset attribute
that is missing.

**Re-weighting changes nothing until you re-score.** Existing findings keep the
number they were given. *Risk profiles → Re-score everything* rewrites them and
writes the change to each finding's history.

---

## 10. Tickets: opened by hand, and opened for you

A **remediation ticket** is the unit of work handed to whoever will do the
fixing. It keeps a hard link to its finding, so the ITIL chain is a set of
joins rather than a convention:

> Vulnerability → Risk → Incident → Change → Remediation → Verification → Closure

### What happens when a ticket is created

Whether a person clicks *Create ticket* or the automation does it, the same
code runs:

- **Type is `remediation`.** It is the only type that de-duplicates per
  finding, carries the `REM` prefix, and advances its finding on resolution.
  The API accepts any string and will silently create a dead-end type — this
  bit the console for two releases.
- **Priority comes from the risk score**: **≥90 critical · ≥70 high · ≥40
  medium**, falling back to the finding's severity when there is no score.
- **Asset, vulnerability and SLA deadline are filled in from the finding.** The
  due date is the finding's own `sla_due_at`, not a new clock.
- **One open remediation ticket per finding, always.** A second attempt returns
  the existing one. Duplicated tickets are the classic way a vulnerability
  programme loses the plot.
- **Resolving it moves the finding to `remediated`, not to `closed`.**
  Verification is a separate step and, ideally, a separate person.

### Automatic creation

*Automation → Automatic tickets*, or `GET`/`PUT /api/v1/tickets/automation`.

**It is off by default and stays off until somebody turns it on.** Enabling it
also changes **nothing** about findings that already exist. Both of those are
deliberate: an estate with several hundred open findings would otherwise
produce several hundred tickets — each with a reference number, an SLA deadline
and whatever notifications your workflows send — from a single click, and
undoing that is manual.

A finding earns a ticket when it clears **all** of the conditions you set:

| Condition | Default | Notes |
|---|---|---|
| Minimum risk score | **70** | The floor of the `high` band. Empty means "no threshold" and is only accepted alongside a severity list or a KEV requirement. |
| Severities | *(none)* | An empty list means **do not filter by severity**, not "match nothing". |
| CISA KEV only | off | |
| Internet-facing assets only | off | |
| Has an owner | **on** | A ticket with no assignee lands in a queue nobody reads. |
| Cap | **50 per hour** | |

Four things it will not do:

1. **It never ticket-bombs.** The cap is enforced from the database, not from a
   per-process counter — the API runs several workers and an in-memory counter
   would give each one a full budget. When the cap is hit, work is **skipped
   and logged**, never queued for later.
2. **It never duplicates.** Same dedupe as the manual path.
3. **It never ticks a closed or remediated finding.** A ticket for work already
   done is an inbox item whose only possible outcome is being closed again.
4. **It cannot be changed by a team-scoped identity.** Raising the threshold
   would stop tickets opening for work that is not yours, invisibly to everyone
   else.

**Preview before you commit.** *Preview these settings* runs the automation's
own predicate — not a similar-looking one — against your real estate and tells
you how many tickets it would open, broken down by severity, writing nothing. A
preview computed from an approximation is worse than no preview.

**The backlog is a separate, deliberate action.** *Dry run the backfill* counts;
*Open them for real* creates, with a limit you choose, and reports honestly when
it hit that limit (`capped`, plus how many are left). A clean count over
silently dropped work is how a backfill gets believed and then re-run forever.

**The case worth having automation for** is not new findings. It is a finding
you have lived with for months whose risk *rises* past your threshold overnight
because CISA added its CVE to KEV — the ticket is waiting when you arrive.

### ITSM connectors push out, they do not pull in

Outbound connectors (Jira, ServiceNow) mirror a VEYRS ticket into the system
your organization actually works from. The ticket still lives here.

Inbound webhooks are authenticated by **HMAC only**:

```
X-VEYRS-Signature: sha256=<hmac of "<timestamp>." + raw body>
X-VEYRS-Timestamp: <unix seconds, inside a 300s window>
```

Mint the secret with `POST /api/v1/integrations/connectors/{id}/inbound-secret`
— it is shown once.

**Inbound events are advisory by default.** They update `remote_status`,
`remote_key`, the URL and comments. They move nothing in VEYRS unless the
connector carries an explicit `inbound_transitions` map such as
`{"Done": "resolved"}`. An external system does not close a security finding
unless someone has decided, in writing, that it may.

Unknown organisation, unknown connector, and `inbound_enabled=false` all return
the same `404`, on purpose.

---

## 11. SLA & Policies, tab by tab

Five tabs, five unrelated decisions that happen to share a screen. Reading them
as one thing is why this page has a reputation.

### SLA policies — *how long may this stay open?*

The **first** policy whose conditions match a finding wins, and **lower
priority numbers are checked first**. A narrow rule ("critical + KEV +
internet-facing: 4 hours") must therefore carry a *lower* number than a broad
one, or the broad one will swallow it.

Changing a policy recomputes the deadline for **every open finding in the
organization**, not just new ones — findings whose new deadline is already in
the past become breached immediately.

> **A finding that matches no policy has no deadline at all.** It never turns
> red, never escalates, and never appears in a breach count. It simply sits
> there. Keep one broad catch-all policy with a high priority number.

### Escalation — *who else finds out?*

A ladder is a list of steps:
`{"level": 2, "after_hours": 8, "notify": "team_manager"}` means eight hours
past the deadline, the manager is notified.

A finding only ever moves **up** a level, and only when the sweep runs.
Lowering a threshold does not re-notify people about levels already passed.

> A breached SLA with no escalation policy notifies nobody beyond the owning
> team — and if the finding is unowned, nobody at all.

### Assignment rules — *who owns the work?*

Rules are tried in priority order; the first match wins. If none match, the
finding inherits the team that owns its **asset**.

Applies to new and re-scored findings only; existing assignments are not
rewritten. Use *Assign to team…* on the findings list for those.

Writing an assignment rule requires an estate-wide grant. A team that could
write its own routing rule would be choosing its own queue.

### Risk profiles — *how is the number built?*

See §9.

### SLA events — *what actually fired*

Read-only. Every warning, breach and escalation the sweep has produced: the
evidence trail behind a breach number, not a queue of work.

---

## 12. Vendors and products are a dictionary, not a supplier register

This one is worth stating plainly because the name invites exactly the wrong
reading.

`vendors` and `products` are the **global CPE dictionary** that arrives with
NVD. They are the rows that let *"nginx 1.24 is installed on this host"* and
*"this CVE applies to nginx below 1.25"* join to each other. They are **shared
by every tenant** and they are **nobody's third-party risk register**. VEYRS
does not do TPRM, and nothing on this screen is about your suppliers'
security posture.

What *is* tenant-specific is `asset_products` — which of those dictionary
entries your estate actually contains. That is why *Threat Intel → Vendors*
shows an **installations** count next to each name and sorts by it: a
dictionary of 37 000 vendors is noise until you can see which two hundred of
them describe your estate.

One consequence to know about: **the same software can occupy two rows
depending on how it arrived.** A CPE tag from a Nessus report resolves to
`nginx:nginx`; a product token from the execution agent resolves to `f5:nginx`.
Both are real NVD entries with real applicability. Collapsing them would need a
product aliasing layer, and changing how the agent path resolves identity would
be a larger and riskier change than the duplication is worth.

Vendors are also what a **document** is filed under (§13), so "every Fortinet
advisory we have" and "every Fortinet product we run" are answerable from one
identifier rather than from a free-text field that drifts one spelling per
upload.

---

## 13. Documents and advisories

*Documents & Advisories* is where a vendor advisory, a pentest report, a scan
report or a customer security questionnaire goes. VEYRS extracts CVEs,
products, versions and remediation text from it and correlates them against
your inventory.

Everything beyond the file itself is metadata a **person** owns, and it is
worth filling in:

| Field | Why |
|---|---|
| **Title** | The filename is what somebody's disk called the bytes. A library of `advisory_final_v3.pdf` is a library nobody searches. |
| **Notes** | Why this was uploaded, and what was decided. |
| **Owning team** | Ownership, not authorization: documents stay visible organization-wide. Making a team's advisories private is how the same CVE gets triaged twice. |
| **Vendor** | Points at the same `vendors` row the CPE dictionary uses (§12). |
| **Linked CVEs** | CVEs *you* attach, kept separately from the ones the extractor found. |

Four refusals:

1. **The filename is not editable.** It is evidence — the content hash was
   taken over those exact bytes.
2. **Extracted and hand-linked CVEs live in different columns.** They have
   different lifetimes and different authority: re-running extraction may
   legitimately rewrite what the text said, and it must never discard a
   judgement somebody made. Searching by CVE covers both.
3. **A CVE that is not in the catalogue is rejected**, hand-attached or not. A
   document may *reference* a vulnerability; it cannot invent one. A typo would
   otherwise create a link that can never resolve.
4. **An upload that de-duplicates does not overwrite existing metadata.** The
   same bytes uploaded twice return the first row; silently replacing a title
   somebody wrote would lose work with no trace.

XML is parsed through `services/xmlsafe.py`, which rejects entity
**declarations** in the prologue only — a security report that quotes
`<!ENTITY` in the text of its own findings must still import, or the guardrail
causes the outage it exists to prevent.

---

## 14. The CVSS calculator, and the bulletin assistant

The calculator scores vectors with the VEYRS engine, validated against FIRST's
official reference corpora — 729 v2, 2592 v3 and 1058 v4 vectors, every
release. Nothing on it is an approximation.

### *Analyse a bulletin…*

The calculator asks eight questions in a vocabulary (AV, AC, PR, UI, S, C, I,
A) that a bulletin answers in prose, in a different order, usually without
naming a single metric. Somebody who has read the advisory still has to
translate it, and the translation is where the vector goes wrong — almost
always in the optimistic direction, because "authenticated" reads as `PR:H`
when the account in question is a default one.

Paste the advisory text and VEYRS does three separate things, with very
different trust levels:

1. **Extraction (deterministic).** CVE identifiers and any CVSS vector the
   bulletin *prints* are pulled out by pattern. An advisory that already
   carries `CVSS:3.1/AV:N/…` has told us the answer.
2. **Inventory (deterministic).** Those CVEs are looked up in your own
   findings, and the product names against your own `asset_products`. This is
   the half that answers *"does this apply to me"*, and it is a database query.
3. **Proposal (model).** Only for the metrics nothing above could settle. The
   model proposes values **with a per-metric rationale** you can read.

Three refusals make this a helper rather than a liar:

- **The score is never the model's.** Whatever vector comes out is scored by
  the same engine everything else uses. A model that says "9.8" over a vector
  that computes to 7.5 is a number an analyst would have put in a report.
- **A printed vector beats a proposed one, always.** Each metric carries a chip
  saying which it came from, so a reviewer can see which half they are actually
  reviewing. Touch a metric yourself and the chip goes away — provenance that
  survives being overruled is a lie.
- **Nothing is applied.** It fills the form; you confirm it. Metrics the
  bulletin genuinely does not settle are listed under *Still yours to decide*
  rather than guessed.

The bulletin is third-party text and is fenced as untrusted before it reaches
any model — an advisory containing "ignore previous instructions" is exactly
the input this feature is designed to accept. Untick *Ask the AI model* to run
the deterministic half alone; the answer says which provider was used, whether
it was external, and what it rejected as not valid CVSS.

---

## 15. Reporting

```
POST /api/v1/reports/generate
{"template": "executive_summary", "format": "pdf", "scope": {...}}
```

Templates cover executive summary, technical detail, compliance posture, SLA
performance and remediation trend. PDF and XLSX.

Before sending a "clean estate" report to anyone who will act on it, check
these three things:

1. `records_rejected` on the imports feeding it (§6).
2. `inventory/coverage` — matched versus anchored (§5).
3. Agent job coverage statistics on the scans behind it (§7).

Each of the three can turn a clean report into a blind one without producing a
single error message. That is the whole reason they exist as separate,
visible numbers.

### Reading a dashboard one team at a time

The *Scope* selector in the dashboard head narrows every figure on the screen
to one owning team — `?team_id=` on `/dashboard/executive`, `/technical`,
`/sla` and `/trends`. Ownership is the **effective** one: a finding's explicit
assignment if it has one, otherwise the owning team of its asset.

Three things about it that are deliberate and will otherwise look wrong:

- **A team dashboard excludes work nobody owns.** If your estate has unowned
  assets, the three team dashboards will not add up to the estate dashboard,
  and the difference is exactly the unowned residue. `GET /assets?unowned=true`
  lists it; `GET /auth/me/scope` counts it.
- **The banner distinguishes filtered from restricted.** *Filtered* is a choice
  you just made and can undo from the same selector. *Restricted* means your
  role grants do not reach the whole estate and there is nothing to undo. A
  zero means something different under each.
- **Exports are never narrowed.** Report exports refuse a team scope on
  purpose: a dashboard is read in context, a PDF gets attached to an audit six
  months later under the title "asset register". If you need a per-team
  document, say so in the document, not in the filter.

**The selector remembers.** Your last choice is stored on your account, not in
the browser, so it comes back on the next sign-in from any machine — `GET` and
`PATCH /auth/me/preferences`, and it also rides along on `GET /auth/me` so the
first screen already paints under the right scope. Three rules govern which
scope you get:

1. a link carrying `?team=` wins for that page view and is **not** saved — a
   colleague's screenshot link cannot repoint your own dashboard;
2. otherwise your remembered choice applies;
3. otherwise the whole estate.

Picking *Whole estate* is itself a choice and is saved as one. It is a
**default, not a permission**: the scope of what you may read is recomputed on
every request from your role grants, so a remembered team can never show you
more than your role allows, and a team deleted after you saved it quietly falls
back to the estate view rather than breaking the page.

### SLA under a team scope

The SLA counters at `/policies/sla/summary` take the same `?team_id=` as the
dashboards and are narrowed by your own scope as well, so the widget and the
SLA dashboard beside it now count the same set. Until 0.17.1 they did not: the
summary answered with the whole estate for everyone, and the console hid it
under a filter rather than show an estate total next to filtered figures.

The SLA event log (`/policies/sla/events`) is scoped by the finding each event
belongs to. Asking for the events of a finding you cannot see returns an empty
page, not an error — there is nothing there to tell you about.

`POST /policies/sla/evaluate` — the sweep — accepts **no** team filter. It is
not a read: it breaches, escalates and sends notifications. It runs over your
authorization scope and nothing else, and the counters it returns say which
scope that was. If you are estate-wide, it sweeps the estate.

### Why you cannot edit an SLA policy from a team scope

Reading policy is open to everyone; **writing it needs an estate-wide grant**
(403 otherwise). This applies to SLA policies, escalation ladders and
assignment rules.

It is not an oversight. Saving an SLA policy re-applies the changed deadline to
**every open finding in the organisation** — that is what makes a policy change
mean anything. Applying it to only your team would leave everyone else governed
by a deadline nobody recomputed, so the policy and the findings would quietly
disagree. Assignment rules are the same problem from the other end: a rule
decides which team work is routed to, so a team that can write one is choosing
its own queue.

An operator must always be able to *read* the SLA they are being judged
against. That is why only the writes are refused.

---

## 16. Multi-tenancy and what you can see

Every tenant table is protected by PostgreSQL row-level security with **FORCE**
enabled — the isolation is in the database, not in application `WHERE` clauses,
so a bug in a query cannot leak across tenants.

Roles are `<resource>:<action>` permissions (`asset:write`, `finding:read`,
`agent:admin`, …) granted through roles, optionally scoped to a team.

If you are looking at production data through a script and every table comes
back empty, **you have not set the tenant**, and the data is fine. This has
cost real hours. Empty is the correct, safe answer to an unscoped query.

Every state change is written to an immutable audit log, with passwords, key
hashes and MFA secrets redacted at the recording layer rather than at display
time.

---

## 17. Availability — what happens when something breaks

VEYRS runs as **two interchangeable application nodes** behind the fleet proxy,
plus **one database node** that holds all the state, plus a **hot standby** of
that database on a different physical host.

| Failure | What you see | Action needed |
|---|---|---|
| One app node's API dies | Nothing. Verified 20/20 requests served. | None |
| A whole app node stops | Nothing. Verified 25/25 in 6 s. | None |
| Batch jobs pause | Scheduled scans and the nightly sync stop | Operator enables the units on the surviving node |
| Database node lost | Full outage | Promote the standby (manual, deliberate) |
| The physical host lost | Full outage | Restore from the off-host logical backup |

Two consequences you should know about as a user:

- **Scheduled scans and the nightly intelligence sync run on exactly one node.**
  Two runners claiming the same jobs is corruption, not redundancy. If node a1
  is down, batch work is paused until an operator promotes a2 — the console
  keeps working throughout.
- **Failover does not happen in DNS.** All public names resolve to the fleet
  proxy, which chooses a backend. Your bookmark never needs to change.

Promotion of the database standby is **manual on purpose**. Automatic promotion
without a fencing mechanism produces two primaries, and two primaries produce
divergent security data that cannot be reconciled afterwards.

---

## 17b. Being told, instead of remembering to look

VEYRS generated 74 notifications before v0.22.0 and delivered none of them
anywhere except the bell icon. Two things changed.

### Your own preferences — Notifications → Preferences

Per event, per channel, for you alone. **SLA breaches and escalations ignore
this screen entirely**: a product whose alerts can be silently switched off is
worse than one with no alerts, and the API answers 422 rather than writing a
row that would be ignored.

### The daily digest — Notifications → Digest

One message a day per person: what arrived, what is late, what is being
exploited, what nobody has looked at, and how many tickets are open.

- **Off by default**, and enabling it is an organization-wide decision
  (`notification:admin`). From the next scheduled hour every user whose role can
  read findings starts receiving it.
- **Each recipient's digest is built under their own scope.** Not one estate
  digest mailed to a list — an email carries no scope banner, so a restricted
  operator's message counts only their teams and says so.
- **Recipients come from permissions, not from team membership.** Joining a team
  does not subscribe you to its estate.
- **Nobody with nothing to report is sent anything.** A daily "no news" trains
  its reader to delete it unread, and then the one that matters goes too.
- Email needs SMTP configured on the API host (`VEYRS_SMTP_HOST`). With no
  transport the messages queue, stay visible in-app and retry — they are not
  lost, but they do not arrive either.

The hour lives in the setting, not in the timer: `veyrs-digest.timer` fires
hourly and `veyrs digest` asks each organization whether this is its hour, so
changing it in the console is enough.

---

## 18. Quick reference

| I want to… | Do this |
|---|---|
| See my queue | `GET /findings?state=new&sort=risk_score&order=desc` |
| Ask in English | `POST /ai/search` — then read the query it ran |
| Know if a clean report is real | `inventory/coverage`, `records_rejected`, job coverage |
| Import a scan | `POST /engagements/{id}/imports` (+ `target_asset` for SAST/SCA/cloud) |
| Find out why an import lost rows | `reject_reasons` on the import run |
| Find out why an agent job was refused | `AgentTool.enabled`, then `allowed_targets` |
| Find out why a job "failed" on exit 0 | `job.meta.scan_stats` — coverage below 80% |
| Turn on MFA | `mfa/enroll` → scan QR → `mfa/activate` |
| Accept a risk | Set `risk_accepted` with an expiry and an accepting party |
| Prove a fix | Re-scan. `verified` is the only state a machine assigns. |
| Understand why a finding scored what it did | Its `risk_explanation`, or *Explain* on the finding |
| Change how often intelligence refreshes | *Threat Intel → Schedule*; `python -m veyrs intel-due` to see what is due |
| Open tickets automatically | *Automation → Automatic tickets*, and **preview before you save** |
| Ticket the existing backlog | *Automation → Automatic tickets → Dry run the backfill*, then open for real |
| Build a workflow without writing JSON | *Automation → Workflows → New workflow* |
| Fill a CVSS vector from an advisory | *CVSS Calculator → Analyse a bulletin…* |
| List the estate that is **not** production | *Inventory → Non-production*, or `?exclude_environment=production` |
| List the estate that is **not** internet-facing | *Inventory → Not internet-facing*, or `?exclude_exposure=internet` |
| See which vendors you actually run | *Threat Intel → Vendors*, or `GET /intel/vendors?in_use=true` |
| Stop VEYRS scanning anything itself | *Administration → Scanning* — the scanner screens leave the menu with it |
| Get the scanner back in the menu | *Administration → Scanning* → turn it back on; the menu updates on the same click |

---

## 19. If you remember one thing

Every number in VEYRS has a matching number that tells you whether to believe
it. A finding count means nothing without a rejected-records count. A clean
estate means nothing without inventory coverage. A successful scan means
nothing without coverage statistics. A resolved finding means nothing until
a scan verifies it.

Those pairs are not defensive engineering. They are the product.
