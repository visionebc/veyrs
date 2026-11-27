---
title: Extending VEYRS integrations
purpose: Give a developer an exact, step-by-step recipe, derived from how existing ones are wired, for adding a scanner parser, a connector or driver, an intelligence feed, an agent runner tool, a workflow action, a notification transport and an AI provider.
scope: Covers registries, files to touch, invariants and the tests to extend. There is no plugin system; every extension is a code change in this repository. UI work beyond reading registries from the API is not covered.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/services/importers/parsers_modern.py, backend/veyrs/services/importers/parsers.py, backend/veyrs/services/dedupe.py, backend/veyrs/services/scanners.py, backend/veyrs/services/itsm.py, backend/veyrs/services/itsm_inbound.py, backend/veyrs/services/cmdb.py, backend/veyrs/intel/feeds.py, backend/veyrs/services/intel_schedule.py, backend/veyrs/cli.py, integrations/veyrs-agent/veyrs_agent.py, backend/veyrs/services/workflow.py, backend/veyrs/services/notifications.py, backend/veyrs/services/ai/providers.py, tests/test_phase15_parsers.py]
related: [integrations/README.md, integrations/scanners.md, integrations/agent.md, integrations/threat-intel.md, integrations/automation.md, TESTING_GUIDE.md, CONTRIBUTING.md]
---

# Extending VEYRS integrations

**There is no plugin loader.** No entry points, no dynamic import, no directory scanned at start. Each extension point is a Python dictionary or tuple that you add to, plus tests. This is intentional: in a multi-tenant security product a mechanism that loads tenant-authored code is a remote code execution risk, and the workflow engine and the agent are designed around fixed registries for the same reason.

| Extension | Registry | File |
|---|---|---|
| Scanner parser | `MODERN_PARSERS` (or `PARSERS`), `_JSON_MARKERS`, `SCANNER_REGISTRY` | `services/importers/parsers_modern.py`, `parsers.py`, `services/dedupe.py` |
| Scanner pull driver | `DRIVERS`, `DRIVER_LABELS` | `services/scanners.py` |
| ITSM adapter | `ADAPTERS` (and `PARSERS` for inbound) | `services/itsm.py`, `services/itsm_inbound.py` |
| Documentation (wiki) adapter | `DOCS_ADAPTERS`, `DOCS_SYSTEMS` | `services/docs.py` |
| CMDB driver | `ASSET_DRIVERS`, `DRIVER_LABELS` | `services/cmdb.py` |
| Team import provider | `PROVIDERS` | `services/team_import.py` |
| Intelligence feed | `FEEDS`, `_COMMANDS`, CLI parser | `services/intel_schedule.py`, `intel/feeds.py`, `cli.py`, `scripts/sync-intel.sh` |
| Agent tool | `TOOLS` | `integrations/veyrs-agent/veyrs_agent.py` |
| Workflow action | `ACTIONS`, `ACTION_SCHEMA` | `services/workflow.py` |
| Notification transport | `TRANSPORTS`, `BUILTIN_TEMPLATES` | `services/notifications.py` |
| AI provider | `REGISTRY`, `VALID_KINDS` | `services/ai/providers.py`, `api/v1/ai.py` |

Run only the tests around your change (`./scripts/test.sh tests/test_phase15_parsers.py`); the suite needs a PostgreSQL database whose name ends in `_test` and refuses to start without one. See [Testing guide](../TESTING_GUIDE.md).

## Add a scanner parser

A parser is a pure function `bytes -> Iterator[ScanRecord]`: no database, no network, and a file that is not this format must raise `ParserError`, never yield nothing.

1. **Write the parser** in `services/importers/parsers_modern.py` (JSON and code-scanning tools) or `parsers.py` (network scanners; use `_parse_xml` for XML so entity declarations are refused). Rules each existing parser follows:
   - Raise `ParserError` for a wrong format. Check for a format-specific key (`_require(data, "results")`) and, for line-oriented formats, require the tool's marker field when the file is non-empty. An **empty but valid** report must yield zero records (a clean scan), not an error.
   - Fill `title`, `plugin_id`, `severity` (use `severity_from_word` or `severity_from_score`; leave `None` rather than invent one), `description`, `solution`, and the right dimension: `hostname` or `url` for network and web findings, `file_path` and `line` for code, `component_name` and `component_version` for dependencies, `cwe`, `cve_ids`.
   - Set `host_is_artifact=True` when `hostname` carries an image reference, resource id or repository.
   - Set `unique_id` only when the tool has a stable per-instance id; the dedupe algorithm decides whether it is used.
   - Never store a matched secret. Gitleaks and Trivy strip it.
   - Keep `raw` for reject samples, minus bulky or sensitive keys.
2. **Register it**: add `"mytool": parse_mytool` to `MODERN_PARSERS` (it is merged into `PARSERS` by `parsers.py`) or to `PARSERS` directly. The name is the scanner label stamped on findings and the key of the test scope.
3. **Teach detection**: add an entry to `_JSON_MARKERS` in `parsers_modern.py`. Each entry is `(name, alternatives)`; an alternative is a tuple of markers that must all appear in the first 200,000 characters. Put a more specific format **before** one that shares a marker (Prowler before Semgrep, both use `check_id`). Filename hints need no code: a filename starting with the name, or containing `-name` or `_name`, wins. For XML or CSV formats extend `detect_format` in `parsers.py`.
4. **Register deduplication**: add an entry to `SCANNER_REGISTRY` in `services/dedupe.py`. This is **not optional**: an unregistered name silently gets `legacy`, which collapses code and dependency findings. Choose the algorithm by the tool's granularity (see [Scanners](scanners.md#deduplication-in-one-paragraph)). Use only fields from `VALID_FIELDS`, and do not rely on `cve` until the defect in [Scanners](scanners.md#deduplication-in-one-paragraph) is fixed.
5. **Check `target_asset` semantics.** A host-less report needs the operator to supply `target_asset`; say so in the format's section of `scanners.md`.
6. **Tests**, in `tests/test_phase15_parsers.py`:
   - add a minimal payload constant and a `test_<tool>_...` asserting severity, identity fields and that secrets are not stored;
   - add the name and payload to `test_every_format_is_detected_from_its_own_payload`;
   - add the name to **both** parametrised lists `test_every_parser_refuses_garbage...` and `test_every_parser_refuses_a_report_from_a_different_tool`;
   - add it to the `code_and_web` set in `test_every_registered_parser_has_a_dedupe_config`.
   These lists are hand-maintained, which is how `burp`, `nikto`, `snyk` and `aws_security_hub` came to have registry entries without parsers: nothing asserts that the two registries match. Consider adding that test.
7. **Docs**: add a section to [Scanners](scanners.md) and update the count there and in the [map](README.md).

The console lists formats from `GET /integrations/importers`, so no front-end change is needed.

## Add an agent runner tool

Both halves must agree: the tool's `parser` must be a key of `importers.PARSERS`. `tests/test_fix_ingest.py::test_every_agent_tool_names_a_parser_the_server_has` enforces it (until 0.41.0 `nmap` declared a parser that did not exist).

1. Add a parser for the tool's output first (above). The name you declare in the runner **must** be a key of `importers.PARSERS`, or the server drops it at declaration and the job fails at import with `unknown importer`.
2. In `integrations/veyrs-agent/veyrs_agent.py` write `build_<tool>(target, profile, params, out) -> list[str]`: an argv list only. Whitelist and clamp every knob with `_int(...)`; map a free-text param to a fixed choice; never pass a server string through as a flag or path. Write the output to the `out` path the agent gives you.
3. Register: `Tool("mytool", "binary-name", "<parser>", ["profiles", ...], build_mytool, suffix=".json")` in the `TOOLS` dict. If the scanner reports coverage, pass `stats=` a function that turns one output line into `{requests, errors, percent, ...}` (see `stats_nuclei`); without it the run is "not attested" and cannot close findings.
4. A host-less tool's results need an asset: the server uses the job's authorised host as `target_asset` automatically.
5. **Tests**: `tests/test_phase16_runner.py` (flag injection, clamping, temp-file-only output); add the tool to its checks. Add a server-side case to `tests/test_phase16_agents.py` if the tool needs a new parser path.
6. Operators must then enable the tool per agent (`PATCH /agents/{id}/tools/{name}`); it never runs on declaration.

## Add a scanner pull driver (console connector)

1. In `services/scanners.py` implement a class with `credential_fields`, `parser_format` (a key of `importers.PARSERS`), `default_base_url`, `list_scans(spec) -> list[RemoteScan]` and `fetch_report(spec, scan_id) -> bytes`. Drivers speak HTTP and return bytes; they take **no `Session`** and never write rows.
2. Register in `DRIVERS` and `DRIVER_LABELS`. `describe_drivers()` feeds the console form.
3. Tests: `tests/test_phase33_scanner_connectors.py`. `test_every_driver_names_a_parser_that_exists` and `test_only_sync_touches_the_database` (a source-level assertion) already cover the two invariants; add a stub-driver case for the pull and the skip-identical behaviour.

## Add an ITSM or documentation adapter

1. In `services/itsm.py` add a class with `system`, `create(spec, payload) -> RemoteTicket`, `update(spec, remote_id, payload)`, `fetch(spec, remote_id)` and `verify(spec) -> list[step]` (use `_step(name, "ok"|"failed"|"skipped", detail)`; never raise for a remote failure inside `verify`). Use `_request` for HTTP so errors become `ItsmError` without leaking response bodies. Map from the canonical payload (`ticket_payload`, `finding_payload`); do not invent a second payload shape. Raise a named error for unusable credentials instead of sending an empty header.
2. Register in `ADAPTERS`. A wiki-style system goes in `docs.py`'s `DOCS_ADAPTERS` and `DOCS_SYSTEMS` instead.
3. **Inbound** (optional): add `parse_<system>(body) -> InboundEvent` and register it in `itsm_inbound.PARSERS`; unknown systems fall back to the generic parser.
4. Tests: `tests/test_phase43_jira.py` (credential and API-version cases, `verify` steps), `tests/test_phase4_itsm.py` and `tests/test_phase8_integrations.py` (push idempotency, disabled and type filters), `tests/test_phase17_itsm_inbound.py` (signature, replay, advisory-only behaviour). Tests replace an adapter with `monkeypatch.setitem(itsm.ADAPTERS, ...)`.
5. The create route validates `system` against `ADAPTERS` plus `DOCS_ADAPTERS`; no route change is needed.

## Add a CMDB asset driver or team-import provider

- **Driver**: a class with `driver`, `credential_fields`, `needs_field_map`, `default_base_url` and `fetch(spec) -> list[SourceRecord]`, registered in `cmdb.ASSET_DRIVERS` (and `DRIVER_LABELS`). Drivers never touch the session and never create assets; `sync()` is the only writer and `promote()` the only copier into `assets`. Use `_client(spec)` and `_json_body` for HTTP, cap pages with `MAX_PAGES` and `MAX_RECORDS`, and map to `KNOWN_FIELDS`. Tests: `tests/test_phase40_asset_sources.py`, `tests/test_phase42_netbox_and_team_import.py`.
- **Team provider**: add a name to `team_import.PROVIDERS`, a `from_<provider>` function returning `Candidate` list, and a branch in `collect`. It must never delete teams or create users.

## Add an intelligence feed

A feed is five coordinated pieces; the first is easy to forget.

1. **Ingest function** in `services/intelligence.py` wrapped in `feed_run(session, "<feed>")` so the run is recorded `running`, then `succeeded` or `failed`. Never record an empty fetch as success.
2. **Fetch and sync** in `intel/feeds.py`: `fetch_<feed>`, `sync_<feed>` (use `_get` for retries, `http_client()` for the User-Agent and timeout), and add the CLI mapping to `_COMMANDS` and the branch in `run_cli`.
3. **CLI**: add `("sync-<feed>", help)` to the tuple in `cli.py main()` and the name to the tuple that dispatches to `feeds.run_cli`.
4. **Schedule**: add the feed to `FEEDS`, `FEED_LABEL` and `DEFAULT_INTERVAL_MINUTES` in `services/intel_schedule.py`; `due_feeds`, the API and the console follow. Then add it to the **ordered `for feed in cwe nvd epss kev` loop** in `scripts/sync-intel.sh` in the right position (what must exist before it, and what depends on it) and to the `--full-run` list. Both the host timer and the container run this one script.
5. **Reaction**: add the feed to `intel_pipeline.refresh_after_feed` (correlate if it changes applicability, rescore if it only changes urgency, nothing if it is vocabulary); an unknown feed raises.
6. **Health**: add it to the loop and the `limit` map in `intel_health` (`api/v1/intel.py`) if staleness matters.
7. **Settings**: a URL setting in `config.py` (`VEYRS_<NAME>_URL`) which is then documented in the configuration reference.
8. **Tests**: `tests/test_sync_intel_script.py` (script order against a stub interpreter), `tests/test_phase3_intel.py`, `tests/test_phase35_operability.py` (schedule and `intel-due`), and `tests/test_docs_are_current.py` (every CLI command must appear in `SYSTEM_MANUAL.md`: add the new command to its parametrised list **and** to the manual).

## Add a workflow action

1. In `services/workflow.py` write `_action_<name>(session, ctx, config) -> {"status": "ok"|"skipped"|"warning"|"error", "detail": ...}`. Read only from `ctx`; return `skipped` when a required object is absent; raise or return `error` for a failure (the run records it per step).
2. Add it to `ACTIONS` **and** `ACTION_SCHEMA` (label, summary, `requires`, typed `fields`). An `assert` at import fails if the two disagree, and the console builder renders its form from `ACTION_SCHEMA`.
3. Tests: `tests/test_phase4_itsm.py` (run recording, conditions, unknown action rejected at save) and `tests/test_phase35_operability.py` (vocabulary).
4. To add a **trigger**, add it to `TriggerType` and `TRIGGER_HELP`, then call `workflow_service.trigger(...)` where the event happens. Naming a trigger without firing it is how five of the ten listed triggers came to do nothing.

## Add a notification transport or template

- **Transport**: a function `(Notification) -> None` that raises on failure, added to `TRANSPORTS`. Then it is a valid digest and workflow channel automatically (`set_policy` validates against `TRANSPORTS`), and `dispatch` retries it five times. The recipient address field is `recipient_address`; add a field and a migration path (`sync-schema`) if your channel needs another. This is how the outbound-webhook gap in [Notifications](notifications.md#outbound-webhooks-and-slack) would be closed: `WebhookEndpoint`, `webhook_targets` and `sign_webhook` already exist.
- **Template**: add `{"<locale>": {"subject": ..., "body": ...}}` under the event in `BUILTIN_TEMPLATES`. Provide `en`; add the other four of `en, es, de, fr, it` or accept the English fallback. The mute-preference list is built from this dictionary.

## Add an AI provider kind

1. In `services/ai/providers.py` add a class with `complete(spec, system, prompt) -> Completion`; raise `ProviderError` on failure (the gateway then degrades to the deterministic backend). Strip reasoning blocks with `_strip_reasoning`. Do not add provider-native tool calling.
2. Add it to `REGISTRY`; if it is a hosted vendor, add it to `INHERENTLY_EXTERNAL`.
3. Add the kind to `VALID_KINDS` in `api/v1/ai.py` (the create route validates against that tuple, not against `REGISTRY`).
4. Tests: `tests/test_phase6_ai.py`.

## Checklist before opening a change

- Registry entry added and counted in the docs ([map](README.md), the topic page).
- A test that fails without the change, and the hand-maintained parametrised lists updated.
- Docs front matter updated (`verified`, `status`) and any CLI command mentioned in `SYSTEM_MANUAL.md`.
- No secret stored, logged or returned; credentials go through `encrypt()` and a `*_set` flag.
- Nothing runs unprompted: new connectors are created disabled or inert.
