---
title: Threat intelligence feeds
purpose: Explain what each intelligence feed fetches, from where, how often, how the schedule is decided, what happens after a feed lands, and how each feed fails.
scope: Covers CWE, NVD, EPSS and KEV synchronisation, the hourly tick, the per-tenant schedule, the health endpoint and the article and source registry. Risk scoring formulas are not covered.
version: 0.39.1
verified: 2026-11-17
status: Verified
sources: [backend/veyrs/intel/feeds.py, backend/veyrs/services/intel_schedule.py, backend/veyrs/services/intel_pipeline.py, backend/veyrs/services/intelligence.py, backend/veyrs/api/v1/intel.py, backend/veyrs/cli.py, backend/veyrs/config.py, scripts/sync-intel.sh, integrations/systemd/veyrs-intel-sync.timer, integrations/systemd/veyrs-intel-sync.service, docker/tick.sh, backend/veyrs/services/threatintel.py]
related: [integrations/README.md, integrations/automation.md, integrations/notifications.md, reference/configuration.md, INTEGRATIONS.md]
---

# Threat intelligence feeds

Four public feeds make up the global intelligence corpus. The corpus is **shared by every organization** in the deployment: `cves`, `kev_entries`, `epss_scores` and `cwe` have no `organization_id`, because a CVE is the same row for everyone. What differs per organization is what the corpus is correlated against (its own inventory).

## The feeds

| Feed | CLI | Source (setting, default) | What it provides | Default cadence |
|---|---|---|---|---|
| `cwe` | `veyrs sync-cwe` | `VEYRS_CWE_CATALOG_URL`, `https://cwe.mitre.org/data/xml/cwec_latest.xml.zip` | Names and descriptions of weaknesses, categories (and CWE 5.0 groupings) and views | 1440 min |
| `nvd` | `veyrs sync-nvd [--full]` | `VEYRS_NVD_API_URL`, `https://services.nvd.nist.gov/rest/json/cves/2.0` | CVE records, CVSS, CPE applicability | 1440 min |
| `epss` | `veyrs sync-epss` | `VEYRS_EPSS_CSV_URL`, `https://epss.empiricalsecurity.com/epss_scores-current.csv.gz` | Exploit probability per CVE, daily snapshot kept in `epss_history` | 1440 min |
| `kev` | `veyrs sync-kev` | `VEYRS_KEV_JSON_URL`, CISA `known_exploited_vulnerabilities.json` | Known-exploited flag and dates | 1440 min |

All four accept `--no-correlate` (ingest only; do not raise or rescore tenant findings, for a bulk backfill you correlate afterwards) and `--full` (ignore watermarks). `--full` is meaningful for NVD only. Other settings: `VEYRS_NVD_API_KEY` (optional, raises the rate limit), `VEYRS_FEED_HTTP_TIMEOUT` (default 60 s), `VEYRS_EPSS_HISTORY_DAYS` (default 365). See [Configuration reference](../reference/configuration.md).

Observed on the verified node: NVD run of 1,397 records in 15 s, EPSS 406,741 rows, KEV 1,781 entries, CWE 1,477 entries at catalogue version 5.0, `cve` table 417,419 rows.

### How each feed behaves

**NVD** is incremental by `lastModified`, never by publication date, so a CVE re-scored yesterday comes back. The watermark is the **end** of the window last requested. NVD refuses ranges over 120 days, so a backfill is walked in 120-day windows; a first run with no watermark reaches back 90 days; `--full` starts at 2002-01-01. Pages are 2,000 records. The client enforces NVD's per-address rate limit by sleeping 7 s between requests (1 s with an API key), because NVD answers a rate limit with `403`. Each page is committed before the next is fetched, and each record is written in its own savepoint: a record the database refuses is rolled back alone and named in `feed_runs.details`, while the rest is stored and the watermark moves on. The command then exits **3**, not 0.

**EPSS** downloads a gzip file (handled whether FIRST serves it as a gzip body or as `Content-Encoding`). The `#` metadata line carries `model_version` and `score_date`; the history table is keyed on `score_date`. Unknown CVEs are skipped, so EPSS must run after NVD. After ingest it prunes `epss_history` to `VEYRS_EPSS_HISTORY_DAYS` (0 keeps everything). The same pruning runs on demand:

```bash
# On an app node, as root, from /opt/veyrs/backend with the venv and .env loaded.
cd /opt/veyrs/backend && set -a && . ../.env && set +a
PYTHONPATH=. ../venv/bin/python -m veyrs prune-epss-history --dry-run
```

**KEV** ingests the whole catalogue each run; an empty `vulnerabilities` array is a `FeedError`, not a success. A KEV entry for a CVE NVD has not delivered yet creates a stub CVE row (`tests/test_phase3_intel.py::test_ingest_kev_creates_stub_for_unknown_cve`).

**CWE** unpacks MITRE's zip (member size capped at 128 MiB as a zip-bomb guard), refuses XML that declares entities, and streams it with `iterparse`. MITRE versions the XML namespace with the schema (`cwe-7`, then `cwe-8` from CWE 5.0), so the namespace is matched as a family. Categories, groupings and views are ingested alongside weaknesses because CVE records cite their ids.

### What happens after a feed lands

`services/intel_pipeline.refresh_after_feed` is the only code that walks every tenant:

- **NVD** new or revised CVEs are run against every active organization's inventory (`correlate_new_cves`): this is what raises findings.
- **EPSS and KEV** change urgency, not applicability, so only the open findings for the touched CVEs are re-scored (`rescore_for_cves`), five thousand ids at a time.
- **CWE** triggers nothing: it is vocabulary.

Each tenant is processed under its own row-level-security binding and committed separately; the caller's tenant binding is restored afterwards.

## The hourly tick and the schedule

The timer does not decide *what* runs; it asks.

```text
veyrs-intel-sync.timer  (OnCalendar=hourly, RandomizedDelaySec=600, Persistent=true)
  -> veyrs-intel-sync.service  (oneshot, TimeoutStartSec=infinity, OOMPolicy=continue)
    -> scripts/sync-intel.sh
         1. veyrs intel-due            prints DUE or skip with a reason, for every feed
         2. veyrs intel-due --quiet    one due feed per line
         3. for feed in cwe nvd epss kev: veyrs sync-<feed>   (fixed order, isolated)
         4. veyrs run-sla              every tick, even when no feed was due
```

The fixed order matters: CWE names what NVD creates; EPSS skips CVEs it has never seen; KEV is the last word on urgency. A failing feed sets the script's exit status to 1 but does not stop the others. `scripts/sync-intel.sh --full-run` ignores the schedule and runs all four, which is the hand-run escape hatch:

```bash
# On an app node, as root. Runs every feed now regardless of schedule, then the SLA sweep.
/opt/veyrs/scripts/sync-intel.sh --full-run
```

Container stacks run the same script from `docker/tick.sh intel 3600 600` (service `intel`, compose profile `workers`). `install.sh --skip-timers` skips installing the timers for air-gapped hosts, which then rely on `POST /intel/feeds/*` (see below).

### How "due" is decided

`intel_schedule.due_feeds` compares the time since the **last successful** `feed_runs` row (status `succeeded`; a failed run never resets the clock) with the **effective interval**. Output from the verified node:

```text
skip cwe   548 min since last success, interval 1440 min
skip nvd   188 min since last success, interval 1440 min
```

Each organization stores its demand in `organizations.settings.intel_schedule` (`enabled`, `interval_minutes`, per feed; default enabled, 1440 min). Because the corpus is global, the effective schedule is the **tightest** demand across active organizations: a feed is fetched if any active organization has it enabled, at the smallest interval asked for. An administrator who sets 24 h and observes 1 h is seeing another tenant's setting, not a bug; the API reports `shared: true` and both `interval_minutes` and `effective_interval_minutes`. Intervals are clamped to 60 to 43,200 minutes (one hour to 30 days); the tick is hourly, so 60 is the floor.

`veyrs intel-due` always exits 0, including when nothing is due, so a quiet hour never paints `systemctl --failed` red.

## API

| Route | Permission | Purpose |
|---|---|---|
| `GET /intel/health` | `intel:read` | Per feed: `ok`, `stale` or `never_run`, `age_hours`, `records_seen`, `watermark`; plus corpus counts and estate coverage. Stale thresholds: NVD 48 h, EPSS 48 h, KEV 72 h. CWE is not in this view. |
| `GET /intel/schedule` | `intel:read` | This organization's request next to the effective schedule, `last_success_at`, `next_due_at`, `due_now`. |
| `PUT /intel/schedule` | `intel:write` | Set `feeds: {nvd: {enabled, interval_minutes}}`. An unknown feed name is `422`. Refused for a team-scoped identity. Audited as `organization.intel_schedule_changed`. |
| `GET /intel/feeds/runs` | `intel:read` | `feed_runs` history, filter `feed`. |
| `POST /intel/feeds/nvd`, `/epss`, `/kev` | platform administrator (`is_superuser`) since 0.41.0: the corpus is shared by every tenant | Ingest a payload you fetched yourself (air-gapped path). `correlate=true` by default. |
| `GET /intel/cve`, `/cve/{id}`, `/cve/{id}/exposure`, `/cve/{id}/epss-history`, `/kev`, `/cwe/{id}`, `/vendors` | `cve:read` or `finding:read` | Read the corpus. |

Reference: [threat intelligence API](../api/reference/threat-intelligence.md).

`FeedRun.status` is `running`, `succeeded` or `failed`. A run that fetches nothing is not recorded as succeeded: the freshness shown by `/intel/health` is derived from successful runs only.

## Failure modes

| Symptom | Cause | Where to look |
|---|---|---|
| `intel/health` shows `stale` | Feed failing or timer not firing | `journalctl -u veyrs-intel-sync -n 100`; `systemctl list-timers veyrs-intel-sync.timer` |
| Every tick prints `skip` lines | Intervals not reached; normal | The `reason` text in the journal |
| `nvd: ... answered 403` after four attempts | Rate limit; backoff is 5, 10, 20 s | Set `VEYRS_NVD_API_KEY`; reduce parallel installs sharing an address |
| Unit exits non-zero, `records REJECTED by the database` | `sync-nvd` exit 3: partial result | `feed_runs.details` names the CVE ids and errors |
| `EPSS file parsed to zero rows`, `KEV catalogue came back with no vulnerabilities`, `CWE catalogue parsed to zero weaknesses` | Upstream format change or truncated download | The `FeedError` message; the run is recorded `failed` |
| KEV stops while EPSS runs | Historic: an OOM kill of the wrapper shell mid-loop. `OOMPolicy=continue` in the unit prevents systemd from stopping the rest of the cgroup | The unit file comment |
| Feeds silently never run | Historic (0.21.0 to 0.32.4): `intel-due --quiet` prints one feed per line, which the script's `case` did not match. Fixed by joining lines; pinned by `tests/test_sync_intel_script.py` | Run `/opt/veyrs/scripts/sync-intel.sh` by hand and read the DUE lines |
| First NVD pull takes hours | 7 s per request anonymously, 120-day windows of 2,000 records | `TimeoutStartSec=infinity` is intentional |

## Threat sources and articles

Separate from the four feeds there is a per-organization registry of advisory sources (`threat_sources`: kind `rss`, `atom`, `json`, `misp`, `opencti`, `vendor_advisory`, `cert`, `manual`; `url`, `trust` 0 to 1, `poll_interval_minutes` 5 to 10,080) and a table of articles (`threat_articles`).

**Status: Partial.** There is **no puller** for these sources. Nothing in the code reads a source's URL or honours `poll_interval_minutes`, and `FeedRun` carries `rss` and `misp` only as documented labels. Articles enter through `POST /intel/articles` (an external script or workflow posts entries, optionally naming `source_slug`, which stamps `last_polled_at`). Articles are de-duplicated per organization by a content hash and scored for relevance against the organization's estate; `GET /intel/news` returns the relevance-ordered digest. MISP and OpenCTI exist as source kinds only. Routes: `GET`/`POST /intel/sources`, `POST /intel/articles`, `GET /intel/news` (`intel:read` or `intel:write`).

## Sources

- Feeds: `intel/feeds.py` (constants at lines 40-66), `cli.py:600-627` (`intel_due`), `cli.py:458-478` (`prune_epss_history`).
- Schedule: `services/intel_schedule.py`; defaults `DEFAULT_INTERVAL_MINUTES`, `MIN_INTERVAL_MINUTES=60`, `MAX_INTERVAL_MINUTES=43200`.
- Health: `api/v1/intel.py:548`.
- Live: `GET /api/v1/intel/health`, `/intel/schedule`, `/intel/feeds/runs`; `journalctl -u veyrs-intel-sync` on the verified node.
