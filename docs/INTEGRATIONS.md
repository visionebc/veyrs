# Integrations

## Scanner importers

| Format | Parser | Notes |
|---|---|---|
| Nessus (`.nessus` v2) | `parse_nessus` | Host properties, plugin id/name, CVSS v3 preferred, plugin output kept as evidence |
| Qualys VM (XML) | `parse_qualys` | 1-5 severity scale mapped; QID retained |
| Greenbone / OpenVAS (GMP) | `parse_greenbone` | NVT refs, `cvss_base_vector` mined from tags, QoD retained |
| Generic CSV | `parse_csv` | Header aliases; delimiter sniffed |
| Generic JSON | `parse_json` | Bare list, or `{findings|results|vulnerabilities|items|data: [...]}` |

```bash
curl -X POST https://<host>/api/v1/integrations/imports \
  -H "Authorization: Bearer $TOKEN" \
  -F file=@scan.nessus -F source=nessus \
  -F create_assets=false -F min_severity=low
```

Omit `source` and the format is sniffed. Explicit beats implicit.

### The two rules the importer will not bend

**Never invent an asset identity.** Match order is FQDN, then hostname, then IP
- IP last because it is the least stable identity in a DHCP estate. If nothing
matches and `create_assets=false`, the record is rejected with a reason. A
finding on the wrong asset is worse than a finding you know you dropped.

**Never auto-close on absence.** A finding missing from today's export becomes a
`stale_candidate`. Set `close_missing=true` only if your scan coverage is
genuinely complete; the resulting closures record `"reason": "absent from
scanner export"` so an auditor can distinguish "we fixed it" from "the scanner
stopped mentioning it".

### Reading an import run

```json
{
  "status": "complete", "records_seen": 4120,
  "findings_created": 380, "findings_updated": 3610, "assets_created": 0,
  "records_rejected": 130,
  "reject_reasons": {"unknown asset (create_assets is off)": 130},
  "reject_samples": [{"reason": "...", "asset_key": "web-07", "plugin_id": "12345"}],
  "stale_candidates": 42
}
```

**Read `reject_reasons` after every import.** A renamed column silently dropping
4,000 rows is how a vulnerability programme develops a blind spot.

The payload hash detects re-imports of an identical file, which answers "why did
my counts change?".

### Adding a format

Write `bytes -> Iterator[ScanRecord]` in `services/importers/parsers.py` and add
it to `PARSERS`. The normalizer, deduplication, scoring, assignment and SLA all
come for free. XML parsers must use `_parse_xml` - entity declarations are
refused because a scanner export is attacker-influenced input.

## Scanner connectors (pull)

The section above receives a file. This one goes and fetches it.

| Driver | Console | Credentials | Transport |
|---|---|---|---|
| `nessus` | Nessus Professional / Manager | `access_key` + `secret_key` | `X-ApiKeys`, `/scans/{id}/export` → poll → download |
| `tenable_io` | Tenable Vulnerability Management (cloud) | `access_key` + `secret_key` | same API, `https://cloud.tenable.com` by default |
| `tenable_sc` | Tenable Security Center | `username` + `password` | session token **and** cookie, `/rest/scanResult`, download returns a **zip** |

```bash
POST   /api/v1/integrations/scanners                 # enrol   (importer:admin)
PATCH  /api/v1/integrations/scanners/{id}            # edit    (importer:admin)
POST   /api/v1/integrations/scanners/{id}/test       # prove credentials, import nothing
GET    /api/v1/integrations/scanners/{id}/scans      # what the remote holds (importer:read)
POST   /api/v1/integrations/scanners/{id}/sync       # pull + ingest (importer:write)
GET    /api/v1/integrations/scanner-drivers          # driver catalogue
```

**A pulled export goes through `run_import`, and therefore through the same
parser an upload uses.** A driver's entire job is to end up holding the bytes an
operator would have downloaded by hand. A second ingestion route would mean a
second deduplication rule, two sets of reject counters and two answers to "why
did my findings double".

### The four refusals

1. **Created disabled.** A connector that starts polling when it is saved is an
   outbound connection nobody decided to make. Same discipline as `ExecAgent`.
2. **Empty `allowed_scans` means INERT, not "every scan".** The blast radius of
   a sync is the set of scans it pulls; defaulting that to the whole remote
   console is how wiring up one test import ingests a neighbouring estate.
3. **A `scan_ids` argument outside the allow-list is rejected, not filtered.**
   Silently narrowing a request reports success on work that never happened.
4. **`close_absent` requires an `engagement_id`** — validated on create, on
   patch against the *resulting* row, and again in `sync()`. Absence-based
   closure outside a scope is the over-closing defect that removed
   `_close_missing()`.

### Behaviour worth knowing

- **One `ImportRun` per scan.** A single run covering three scans could not
  report which of them rejected 400 records, and reconciliation is per test.
- **A byte-identical export is skipped.** `sync_state` holds a sha256 per scan,
  so a sync run twice in an hour does not inflate `findings_updated`. `force`
  overrides.
- **A dry run writes no `sync_state`** — otherwise the next real sync would skip
  a scan it never imported.
- **Credentials** use the same Fernet envelope as ITSM connectors. No response
  schema carries the ciphertext; `credentials_set` reports only that it exists.
  An undecryptable credential **fails closed** rather than going out
  unauthenticated.
- **Permissions reuse `importer:*`.** Pulling an export *is* an import. The
  router is in `security.scope.REFUSED_TAGS`, so a team-scoped identity is
  refused rather than served a narrowed view.

### Adding a driver

Implement `list_scans(spec)` and `fetch_report(spec, scan_id) -> bytes` and
register it in `services/scanners.DRIVERS`. Drivers speak HTTP and return bytes:
they take no `Session`, and `tests/test_phase33_scanner_connectors.py` asserts
that over the source. `parser_format` must name a parser that exists in
`importers.PARSERS` — a typo there fails after the credentials worked and the
export was built.

## ITSM

| System | Endpoint used | Field mapping keys |
|---|---|---|
| ServiceNow | Table API `/api/now/table/{table}` | `table`, `category`, `extra_fields` |
| Jira | `/rest/api/3/issue` | `project_key`, `issue_type`, `priority_field`, `extra_fields` |
| Webhook | your URL | `headers`, plus anything your receiver needs |

```bash
POST /api/v1/integrations/connectors
{"slug": "snow", "system": "servicenow",
 "base_url": "https://acme.service-now.com",
 "credentials": {"username": "svc", "password": "..."},
 "ticket_types": ["remediation"],
 "field_mapping": {"table": "incident"}}

POST /api/v1/integrations/connectors/{id}/push/{ticket_id}
```

**Push is idempotent.** A digest of the payload is stored; an unchanged ticket is
not re-sent, because a queue full of no-op updates is how integrations get muted.

**Pull is advisory.** `pull_status` refreshes the remote status and nothing else.
A ServiceNow closure means the change ticket is done - which is *evidence* for
remediation, not proof of it. Verification stays a VEYRS decision.

One VEYRS ticket can be mirrored into several systems (a change record in
ServiceNow, an engineering task in Jira) because links live in their own table
rather than as a column on the ticket.

## Intelligence feeds

| Feed | Source | Cadence |
|---|---|---|
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0` | daily, watermarked |
| EPSS | `epss.empiricalsecurity.com` daily CSV | daily |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | daily |
| RSS / Atom | per-tenant configured sources | per-source interval |

```bash
veyrs sync-nvd [--full]
veyrs sync-epss
veyrs sync-kev
```

All idempotent and watermarked through `feed_runs`. Set `VEYRS_NVD_API_KEY` to
raise the NVD rate limit.

MISP and OpenCTI are modelled as source kinds; their pull adapters are not yet
implemented. Stated rather than implied.

## AI providers

| Kind | Endpoint | Treated as |
|---|---|---|
| `openai`, `openai_compatible` | `/v1/chat/completions` | external (hosted) / configurable |
| `anthropic` | `/v1/messages` | external, always |
| `gemini` | `:generateContent` | external, always |
| `ollama` | `/api/chat` with `think:false` | internal by default |
| `deterministic` | none | internal; answers from VEYRS data only |

Hosted vendors cannot be relabelled internal. A self-hosted OpenAI-compatible
gateway can. See [AI Security](/AI_SECURITY.html).

## Webhooks and notifications

Outbound webhooks carry an HMAC signature using the connector secret. Email is
SMTP with STARTTLS. Notification templates exist in five languages (en, es, de,
fr, it); escalation notifications ignore user mute preferences.


## Execution agents

VEYRS can now *run* scanners, not only import what somebody else ran. An agent
is a long-lived worker inside a network segment: it asks for work, executes a
scanner, streams the output and submits the result, which lands in the normal
ingestion core (engagement → test → dedupe → scoped reconciliation).

The reference runner is one standard-library file:
[`integrations/veyrs-agent/`](https://github.com/visionebc/veyrs/tree/main/integrations/veyrs-agent).

### The trust model

The server does **not** decide what gets executed. It sends
`{tool, target, profile, params}`; the agent builds the argv itself.

| Rule | Enforced by |
|---|---|
| No command line, no shell | job carries structured params; runner uses `subprocess(argv, shell=False)` |
| A declared tool is not an authorised tool | `AgentTool.enabled` defaults false; an operator with `agent:admin` flips it |
| A target must be in scope | `services/agents.authorise_target()` — agent allowlist, deny rules, then the asset register |
| Reserved ranges refused | loopback / link-local / multicast need an exact literal allow. `169.254.169.254` is the reason |
| Names are never resolved to match a CIDR | DNS rebinding would otherwise turn "you may scan app.acme" into "you may scan 10.0.0.1" |
| Authorised twice | queue time (pinned jobs) **and** claim time (the claimant's own policy always decides) |
| Every dispatch is audited | `agent.job_queued` records who, what, where and the mandatory `reason` |

An agent enrolled with an empty `allowed_targets` can run nothing. The
allowlist is deny-by-default: a half-finished enrolment is inert, not permissive.

### Permissions

| Permission | Covers |
|---|---|
| `agent:admin` | enrol, rotate a token, delete, change execution policy, enable a tool — everything that widens what may run where |
| `agent:write` | queue and cancel jobs inside the policy an admin set |
| `agent:read` | see agents, jobs and their streamed output |

### The loop

```bash
# 1. enrol (agent:admin). The token is returned exactly once.
curl -X POST https://<host>/api/v1/agents -H "Authorization: Bearer $TOKEN" \
  -d '{"name":"dmz-runner","allowed_targets":["10.44.0.0/24","*.example.com"]}'

# 2. the agent checks in and declares what it has (X-Agent-Token)
POST /api/v1/agents/self/heartbeat

# 3. an operator authorises one tool
PATCH /api/v1/agents/{id}/tools/nuclei   {"enabled": true}

# 4. queue work. `reason` is mandatory and lands in the audit trail.
POST /api/v1/agents/jobs
  {"tool":"nuclei","target":"app.example.com","agent_id":"...","reason":"weekly sweep"}

# 5. the agent claims, streams and submits
POST /api/v1/agents/self/jobs/claim            -> job + lease_token
POST /api/v1/agents/self/jobs/{id}/events      -> streamed stdout/progress
POST /api/v1/agents/self/jobs/{id}/result      -> raw scanner output, ingested
```

An agent token is **not** a principal: it reaches `/agents/self/*` and nothing
else, and a user token does not work on the data plane. Only the agent holding
a job's lease may write to that job.

### A clean scan is a result

A completed scan with no output submits an empty payload, and VEYRS treats it
as a scan of the job's scope that found nothing — which is what closes findings
that were actually fixed. It is the only remediation signal the platform gets,
so it is accepted deliberately rather than rejected as an empty file
(`ImportOptions.allow_empty`; off for human uploads, where a 0-byte export is a
mistake).

### Housekeeping

`POST /api/v1/agents/maintenance/reap` requeues jobs whose lease expired and
marks silent agents offline. Idempotent — run it from cron as often as you like.
A job that runs out of attempts becomes `expired`, not `failed`: nothing is
known about whether the scan ran, and "failed" invites reading it as "we looked
and found nothing".

## ITSM inbound (the return leg)

`push_ticket` sends a ticket out; `pull_status` polls it back. Polling answers
"did the engineer close this?" minutes late and costs a request per link per
cycle. The inbound webhook is the push-back.

```bash
# mint the shared secret (ticket:admin). Shown once.
POST /api/v1/integrations/connectors/{id}/inbound-secret
# -> {"secret": "...", "webhook_url": ".../itsm/<org>/<connector>/inbound", ...}
```

The remote system signs each delivery:

```
X-VEYRS-Timestamp: 1786500000
X-VEYRS-Signature: sha256=<hex hmac-sha256 of "<timestamp>." + raw body>
```

The timestamp must be within 300 seconds — a signature alone would make every
captured request replayable forever. Jira, ServiceNow (flat and `{"result":…}`
shapes) and a generic canonical shape are parsed.

### An external system still cannot close a security finding

That policy predates this feature and survives it intact:

- By default an inbound event is **advisory**: it updates `remote_status`,
  `remote_key`, `remote_url` and imports comments. Nothing in VEYRS moves, and
  an unmapped status is recorded as a `remote_status_changed` event so the
  operator can see the mapping they meant to configure.
- State changes require an explicit per-connector opt-in
  (`inbound_transitions: {"Done": "resolved"}`), and even then the transition
  goes through the ticket state machine, which refuses illegal edges and
  records the refusal.

Unknown org, unknown connector and inbound-disabled connector all answer the
same `404 unknown webhook endpoint`, so the URL cannot be used to enumerate
tenants. VEYRS never creates a link from an inbound event: it only tracks twins
it pushed itself.

## Harvesting the estate's inventory from the same scan

A scan report answers two questions. What is **wrong** with each host — that is
the finding — and what each host **has**. VEYRS read only the first until
0.20.0, which meant the platform asked its operators to maintain an asset
inventory by hand while a perfectly good one arrived in every Nessus export.

The second read is what the correlation engine joins CVEs against. Without it,
`affected_installations` returns nothing and the platform reports an estate as
unaffected — silently, and completely.

### Turning it on

| Where | Option | Default |
|---|---|---|
| Scanner connector | *Harvest the host inventory from every export it pulls* | **on** |
| Integrations → Scanner import | *Also record what each host has installed* | off |
| API (`ImportOptions`) | `import_inventory` | `False` |
| Connector (`ScannerConnector`) | `import_inventory` | `True` |

The asymmetry is deliberate. A person uploading one export is triaging a file
and has not asked to have their asset register rewritten. A connector exists to
keep VEYRS fed from a scanner it does not control, and the software list is
already sitting in the bytes it downloads.

### Where the identity comes from

In order of authority:

1. **`HostProperties` CPE tags** (`cpe`, `cpe-0`, `cpe-1`, …). This is the
   scanner naming the dictionary entry itself — no inference at all. Nessus
   emits **CPE 2.2 URIs** with a human gloss appended
   (`cpe:/a:openbsd:openssh:9.2p1 -> OpenBSD OpenSSH 9.2p1`);
   `versions.cpe22_to_cpe23` converts them, because `parse_cpe23` returns
   `None` for a 2.2 URI and a `None` here does not raise — it quietly demotes
   the row to a guess.
2. **Software-enumeration plugin output** (Nessus **20811** on Windows,
   **22869** over SSH). **Off by default, and that is a refusal.** A CPE tag is
   a dictionary reference; a line of plugin output is prose being guessed at.
   Lines that do not match a known rpm / dpkg / `[version …]` shape are skipped
   rather than approximated — `libfoo` with no version becomes nothing, not a
   product called `libfoo`.

### What it will not do

- **It never prunes.** A scan of three hosts is not a statement about the
  estate, and an unauthenticated scan is barely a statement about the three.
  Rows are added and refreshed, never deleted, so a credentialled scan followed
  by an unauthenticated one does not erase what the first one learned.
- **It never invents an asset on its own terms.** Inventory attaches to hosts
  VEYRS already knows unless `create_assets` is on.
- **A dry run writes nothing.**
- **Its rejects are its own.** `records_rejected` counts findings. A host that
  is not in the register shows up in `inventory_hosts` minus `inventory_added`,
  not as vulnerability data that was dropped.

### Reading the result

`Integrations → Import runs` carries **Inv. hosts**, **Inv. added** and
**Inv. unmatched**. The last one is the number that matters for quality: an
unmatched install is a **name to fix**, not a host that is safe. It is recorded
anyway — losing inventory is worse than holding it unmatched — and
`GET /assets/inventory/coverage` lists the offenders with suggestions.

**A known consequence, stated rather than hidden.** NVD's dictionary sometimes
carries two entries for one product (`nginx:nginx` and `f5:nginx` both exist
and both have applicability data). A scanner that supplies a CPE resolves to
the entry it named; the token-based path used by the agent resolves by
evidence. The same software reported through both channels can therefore
occupy two `AssetProduct` rows. Both are real dictionary entries and neither is
wrong, but an estate count can read high. `detected_by` tells you which channel
produced which row.
