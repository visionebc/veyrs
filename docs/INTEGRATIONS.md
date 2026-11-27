---
title: Integrations
purpose: Overview of everything VEYRS connects to, with the rules each integration obeys and pointers to the detailed reference for each.
scope: Summary level only. Parsers, feeds, ITSM, agent, notifications and automation each have a full document under integrations/; this file keeps the principles and the corrected quick facts.
version: 0.39.1
verified: 2026-11-17
status: Verified
sources: [backend/veyrs/services/importers/, backend/veyrs/services/scanners.py, backend/veyrs/services/itsm.py, backend/veyrs/services/itsm_inbound.py, backend/veyrs/intel/feeds.py, backend/veyrs/services/agents.py, backend/veyrs/services/notifications.py, backend/veyrs/services/ai/providers.py, integrations/]
related: [integrations/README.md, integrations/scanners.md, integrations/threat-intel.md, integrations/itsm-and-webhooks.md, integrations/agent.md, integrations/notifications.md, integrations/automation.md, integrations/extending.md, AI_SECURITY.md]
---

# Integrations

This page is the overview. The full references are:

| Topic | Document |
|---|---|
| Integration map and status table | [integrations/README.md](integrations/README.md) |
| Scanner parsers, deduplication, closure on reimport, pull connectors, host inventory | [integrations/scanners.md](integrations/scanners.md) |
| NVD, EPSS, KEV, CWE, the hourly tick and the schedule | [integrations/threat-intel.md](integrations/threat-intel.md) |
| ITSM connectors, inbound webhook, external ticketing mode, Confluence, CMDB sources | [integrations/itsm-and-webhooks.md](integrations/itsm-and-webhooks.md) |
| Execution agent | [integrations/agent.md](integrations/agent.md) |
| Notifications, digest, locales, AI providers | [integrations/notifications.md](integrations/notifications.md) |
| Timers, CLI, SLA, escalation, auto-ticketing, workflows | [integrations/automation.md](integrations/automation.md) |
| How to add a parser, connector, feed or tool | [integrations/extending.md](integrations/extending.md) |

## Scanner importers

Twenty parser names are registered (`importers.PARSERS`):

| Group | Names |
|---|---|
| Network scanners | `nessus` (`.nessus` v2), `qualys` (VM XML), `greenbone` and `openvas` (GMP XML), `csv`, `json` |
| Code, dependency and secrets | `sarif`, `codeql`, `semgrep`, `bandit`, `gitleaks`, `checkov`, `trivy`, `grype`, `npm_audit`, `pip_audit`, `dependabot` |
| Web and cloud | `nuclei`, `zap`, `prowler` |

```bash
# Prerequisite: a bearer token with importer:write.
curl -X POST https://veyrs.example.com/api/v1/integrations/imports \
  -H "Authorization: Bearer $TOKEN" \
  -F file=@scan.nessus -F source=nessus \
  -F create_assets=false -F min_severity=low
```

Omit `source` and the format is sniffed. Explicit beats implicit. A parse failure is stored as a `failed` import run (the HTTP status is still `201`); always read `status`, `error` and `reject_reasons`.

### The two rules the importer will not bend

**Never invent an asset identity.** Match order is FQDN, then hostname, then IP, because IP is the least stable identity on a DHCP estate. If nothing matches and `create_assets=false`, the record is rejected with a reason. Reports with no host (SAST, SCA) need `target_asset`.

**Never close on unbounded absence.** A finding missing from today's export becomes a stale candidate; only findings the **same test** (engagement plus scanner) reported before are considered, and only after a number of **consecutive** absences: 1 for a `ci_cd` engagement, 2 for `scheduled` (including the default `Continuous scanning`), never for `interactive`. `absence_threshold=0` or `close_absent=false` disables closure; `close_missing=true` is a deprecated alias with threshold 1. Closures move the finding to `remediated` with `reason: "absent from scanner export"` and `evidence: "absence"`, so an auditor can tell "we fixed it" from "the scanner stopped mentioning it". The scope caveat for partial exports is in [Scanners](integrations/scanners.md#reimport-closure). ADR: [0006](ADRs/0006-no-autoclose-on-absence.md).

### Reading an import run

`records_seen`, `findings_created`, `findings_updated`, `assets_created`, `records_rejected`, `reject_reasons`, `reject_samples`, `stale_candidates`, `findings_marked_absent`, `findings_closed_absent`, `dedupe_algorithm`. **Read `reject_reasons` after every import**: a renamed column silently dropping 4,000 rows is how a vulnerability programme develops a blind spot.

### Adding a format

See [Extending](integrations/extending.md#add-a-scanner-parser). In short: write `bytes -> Iterator[ScanRecord]`, register it, add detection markers, and **register its deduplication config** in `services/dedupe.SCANNER_REGISTRY`.

## Scanner connectors (pull)

Three drivers (`nessus`, `tenable_io`, `tenable_sc`) fetch a `.nessus` export and feed it to the same `run_import` an upload uses, so a pull cannot introduce a second deduplication rule. Connectors are created disabled; an empty `allowed_scans` makes them inert; `close_absent` requires an engagement; a byte-identical export is skipped. There is no scheduler: sync runs only when called. Detail: [Scanners](integrations/scanners.md#scanner-connectors-pull).

## ITSM

| System | Endpoint | `field_mapping` keys |
|---|---|---|
| ServiceNow | Table API `/api/now/table/{table}` | `table`, `category`, `extra_fields` |
| Jira Cloud and Data Center | `/rest/api/3/issue` or `/rest/api/2/issue` | `api_version`, `project_key`, `issue_type`, `priority_field`, `extra_fields` |
| Webhook | your URL, bearer token optional | `headers` |
| Confluence (documentation) | wiki content API | `space_key`, `parent_page_id`, `deployment` |

**Push is idempotent** (a payload digest is stored; an unchanged ticket is not re-sent). **Pull is advisory** (`POST /integrations/connectors/{id}/pull` refreshes the remote status and nothing else; it has no scheduler). An external system **cannot close a security finding**: the signed inbound webhook is advisory unless the connector has an explicit `inbound_transitions` mapping, and then it goes through the ticket state machine. Unknown organization, unknown connector and an inbound-disabled connector all answer the same `404`. Detail: [ITSM and webhooks](integrations/itsm-and-webhooks.md).

## Intelligence feeds

| Feed | Source | Command |
|---|---|---|
| NVD | `services.nvd.nist.gov/rest/json/cves/2.0`, incremental by `lastModified`, watermarked | `veyrs sync-nvd [--full]` |
| EPSS | `epss.empiricalsecurity.com` daily CSV (gzip) | `veyrs sync-epss` |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | `veyrs sync-kev` |
| MITRE CWE | `cwe.mitre.org/data/xml/cwec_latest.xml.zip` | `veyrs sync-cwe` |

The hourly timer asks `veyrs intel-due` which feeds have reached their interval (default 24 h; per-organization, tightest demand wins) and runs those in the order CWE, NVD, EPSS, KEV, then `run-sla`. `VEYRS_NVD_API_KEY` raises the NVD rate limit. RSS, Atom, MISP and OpenCTI are **source kinds only**: there is no puller; articles are pushed to `POST /intel/articles`. Detail: [Threat intelligence](integrations/threat-intel.md).

## AI providers

| Kind | Endpoint | Treated as |
|---|---|---|
| `openai` | `/v1/chat/completions` | external, always |
| `openai_compatible` | `/v1/chat/completions` | external or internal, the operator's declaration |
| `anthropic` | `/v1/messages` | external, always |
| `gemini` | `:generateContent` | external, always |
| `ollama` | `/api/chat` with `think:false` | internal by default (operator's declaration) |
| `deterministic` | none; answers from VEYRS data only | internal; the fallback for every failure |

Hosted vendors cannot be relabelled internal. See [AI Security](AI_SECURITY.md) and [Notifications and AI](integrations/notifications.md#ai-providers).

## Notifications

In-app and e-mail (SMTP with optional STARTTLS) are the only working channels. A notification is a database row before any transport is tried; escalation and SLA-breach notices ignore per-user mute preferences. The daily digest is off by default. Five locales exist (`en`, `es`, `de`, `fr`, `it`), but built-in templates cover all five only for `finding.created`; other events have `en` and `es` and fall back to English. **Outbound HMAC-signed webhooks and Slack are not implemented**: the signing helper and an endpoint table exist, but nothing sends. Only the inbound ITSM webhook is signed (HMAC-SHA256, 300 s replay window). Detail: [Notifications](integrations/notifications.md).

## Execution agents

An agent is a worker inside a network segment that polls for work, runs a scanner and submits the result into the normal ingestion pipeline. The reference runner is one standard-library file, `integrations/veyrs-agent/` in the repository.

| Rule | Enforced by |
|---|---|
| No command line, no shell | Structured job params; the runner uses `subprocess` with `shell=False` |
| A declared tool is not an authorised tool | `AgentTool.enabled` defaults false; `agent:admin` flips it |
| A target must be in scope | `services/agents.authorise_target()`: deny rules, agent allowlist, then the asset register |
| Reserved ranges refused | Loopback, link-local and multicast need an exact literal allow |
| Names are never resolved to match a CIDR | Prevents DNS-rebinding |
| Authorised twice | At queue time (pinned jobs) and again at claim time |
| Every dispatch is audited | `agent.job_queued` records who, what, where and the mandatory `reason` |

An agent enrolled with an empty `allowed_targets` can run nothing. An agent token reaches `/agents/self/*` only. A clean scan is a result (an empty payload from a scan that covered its target is how fixed findings close), but a scan that did not cover its target (below 80 % complete, unreachable, error rate above 50 %) is refused and cannot close anything. Lease expiry is collected by `POST /agents/maintenance/reap`, which **nothing schedules**. Detail, job state diagram and the sequence of calls: [Agent](integrations/agent.md).

```bash
# Enrol (agent:admin). The response contains the token exactly once.
curl -X POST https://veyrs.example.com/api/v1/agents -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"name":"dmz-runner","allowed_targets":["198.51.100.0/24","*.example.com"]}'
```

## ITSM inbound, host inventory, CMDB

- **Inbound ITSM** (the return leg): `POST /integrations/itsm/{org}/{connector}/inbound`, headers `X-VEYRS-Timestamp` and `X-VEYRS-Signature: sha256=<hmac over "<timestamp>." + body>`. See [ITSM and webhooks](integrations/itsm-and-webhooks.md#inbound-webhook).
- **Host inventory from a scan report** (since 0.20.0): a second read of a Nessus export records what each host has installed, from CPE tags (authoritative) and optionally from plugin output. It never prunes, never invents an asset, and is on by default for connectors and off for uploads. See [Scanners](integrations/scanners.md#host-inventory-from-a-scan-report).
- **CMDB sources** (`file`, `http_json`, `netbox`) stage records without writing assets; promotion is explicit. See [ITSM and webhooks](integrations/itsm-and-webhooks.md#cmdb-and-asset-sources).
