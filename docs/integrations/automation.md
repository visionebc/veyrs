---
title: Automation, scheduled jobs and rules
purpose: List every scheduled task and CLI job, and document how the SLA engine, escalation, auto-ticketing and the workflow engine decide and act, including what is and is not wired.
scope: Covers systemd timers, container ticks, the veyrs CLI, SLA policies and escalation ladders, assignment rules, autoticket and workflow triggers, conditions and actions. Backup timers are listed only; their procedures are in the recovery docs.
version: 0.41.0
verified: 2026-11-17
status: Verified
sources: [backend/veyrs/cli.py, scripts/sync-intel.sh, scripts/send-digest.sh, integrations/systemd/veyrs-intel-sync.timer, infrastructure/systemd/veyrs-digest.timer, infrastructure/systemd/veyrs-updater.path, infrastructure/backup/, docker/tick.sh, docker/compose.yaml, backend/veyrs/services/sla.py, backend/veyrs/services/workflow.py, backend/veyrs/services/autoticket.py, backend/veyrs/services/correlation.py, backend/veyrs/services/ticketing_mode.py, backend/veyrs/api/v1/policies.py, backend/veyrs/api/v1/tickets.py]
related: [integrations/README.md, integrations/threat-intel.md, integrations/notifications.md, integrations/agent.md, SYSTEM_MANUAL.md, DISASTER_RECOVERY.md]
---

# Automation, scheduled jobs and rules

VEYRS has very little scheduled work. Two hourly ticks do almost everything; the rest is event-driven (a finding is created, an import runs) or manual.

## Scheduled tasks

Observed on the verified node with `systemctl list-timers`: exactly two VEYRS timers on an application node, both active.

| Unit | Trigger | Runs | What it does | Where |
|---|---|---|---|---|
| `veyrs-intel-sync.timer` | `OnCalendar=hourly`, `RandomizedDelaySec=600`, `Persistent=true` | `veyrs-intel-sync.service` (oneshot, no timeout) then `scripts/sync-intel.sh` | `intel-due`, then whichever of `sync-cwe`, `sync-nvd`, `sync-epss`, `sync-kev` are due, then **`run-sla` on every tick**, then **`maintenance`** (dispatch queued notifications, reap agent leases, expire risk acceptances, prune by retention), bracketed by `tick start` / `tick finish` that record the result for `GET /intel/health` | `integrations/systemd/`, installed by `install.sh` |
| `veyrs-digest.timer` | `OnCalendar=hourly`, `RandomizedDelaySec=300`, `Persistent=true` | `veyrs-digest.service` (oneshot, 600 s) then `scripts/send-digest.sh` | `veyrs digest`: per organization, only if enabled and this is its hour | `infrastructure/systemd/`, installed by `install.sh` |
| `veyrs-updater.path` | `PathExistsGlob=/var/lib/veyrs/update-requests/*.json` | `veyrs-updater.service` | Starts the root updater when the console queues a software update | `infrastructure/systemd/` |
| `veyrs-pgdump.timer` | daily 02:15, 300 s jitter | `veyrs-pgdump.service` | Nightly logical database backup | `infrastructure/backup/` (not installed by `install.sh`; see the recovery docs) |
| `veyrs-pgverify.timer` | Sundays 04:30, 600 s jitter | `veyrs-pgverify.service` | Weekly proof the backup restores | same |
| `veyrs-replcheck.timer` | boot + 5 min, then every 15 min | `veyrs-replcheck.service` | Checks the standby is replicating | same |

The first two are **ticks, not schedules**: the cadence lives in the database (`organizations.settings.intel_schedule` and `.digest`), so changing it in the console takes effect without editing systemd. `install.sh --skip-timers` leaves both out; `install.sh` leaves a timer that an operator disabled switched off on re-run.

`run-sla` and `maintenance` have no unit of their own. They are the last steps of `sync-intel.sh`, so they run hourly **even when no feed is due**, because SLA deadlines elapse with the wall clock, not with intelligence. If the intel timer is disabled on a node, so is the SLA sweep. On a multi-node install the intel timer is meant to run on **one** node and sit installed-but-disabled on the others (`install.sh` preserves that choice on re-run).

Observed on the verified node: sweep output per tick, for example `checked 1972 · warned 10 · breached 4 · escalated 0`.

### Containers

Container stacks replace each timer with a loop, `docker/tick.sh <label> <interval seconds> <max jitter seconds> <command>`: compose service `intel` (`3600 600`, runs `scripts/sync-intel.sh`) and `digest` (`3600 300`, runs `scripts/send-digest.sh`), both in compose profile `workers`. The loop never exits on a failed run (a restart storm would hammer NVD's rate limit); it logs `FAILED` and takes the next tick. The container runs **the same script** as the host timer; the feed order is defined once.

### Not scheduled

These exist but nothing runs them for you: scanner connector `sync`, CMDB source `sync`, ITSM `pull`, `recompute-risk`, `import-inventory`. (`agents/maintenance/reap`, `notifications/dispatch`, risk-acceptance expiry and retention pruning run from the tick since 0.41.0; the routes remain for on-demand use.) Run them from your own cron when you need them. See the warnings in [Agent](agent.md#job-lifecycle) and [Notifications](notifications.md#how-a-notification-is-produced-and-delivered).

## The `veyrs` CLI

All commands are `python -m veyrs <command>`, run from `backend/` with the environment loaded:

```bash
# On an app node, as root (the same user the units run as).
cd /opt/veyrs/backend && set -a && . ../.env && set +a
PYTHONPATH=. ../venv/bin/python -m veyrs --help
```

| Command | Purpose | Typical use |
|---|---|---|
| `init-db` | Create schema, RLS policies and built-in roles | Install, upgrade |
| `sync-schema` | Add columns, indexes and foreign keys present in the models but missing | Upgrade |
| `check` | Self-test configuration, storage and engines | After install |
| `keygen` | Print a fresh `VEYRS_ENCRYPTION_KEY` | Install |
| `bootstrap --org --email [--name --full-name --password --invoicing-code --locale --superuser]` | First organization and administrator | Install |
| `platform-admin --email [--revoke]` | Grant or revoke installation-wide administration; refuses to revoke the last one | Recovery |
| `sync-kev`, `sync-epss`, `sync-nvd`, `sync-cwe` `[--full] [--no-correlate]` | Refresh a feed ([Threat intelligence](threat-intel.md)) | Timer, manual |
| `intel-due [--quiet]` | Print which feeds are due and why; exit 0 always | Timer, debugging |
| `run-sla` | Sweep open findings for breach and escalation, every active organization | Timer, manual |
| `maintenance` | Dispatch notifications, reap expired agent leases, expire risk acceptances, prune by retention; exit 1 if a step failed | Timer (end of the tick), manual |
| `tick start` / `tick finish --status N` | Record the tick's start and result (`organizations.settings.tick`) | Timer |
| `prune [--apply] [--table T]` | Retention, dry run by default | Timer (`maintenance` applies it), manual |
| `recompute-escalation [--apply] [--notify]` | One-off 0.41.0 migration of escalation levels | Manual |
| `seed-defaults --org <slug> [--apply]` | Add missing built-in SLA policies, ladder and risk profiles | Manual |
| `recompute-risk [--org SLUG]` | Re-score every open finding | After risk-model changes; manual only |
| `digest [--dry-run] [--force]` | Queue and deliver the daily digest | Timer, manual |
| `prune-epss-history [--days N] [--dry-run]` | Delete EPSS snapshots older than retention (also done by `sync-epss`) | Manual |
| `import-inventory --file --org [--source --replace --no-correlate]` | Load assets and installed software from JSON | Initial load |
| `secrets status`, `secrets migrate --to local\|mirror\|vault [--apply]`, `secrets rekey [--apply]`, `secrets gc [--apply]` | Stored credentials: local Fernet or an external vault | Key rotation |
| `mfa-test`, `mfa-setup`, `mfa-reset` | Two-factor operations on the host | Support |
| `dedupe rehash [--org SLUG] [--apply]` | Re-key SCA findings stored before 0.41.0, whose key ignored the CVE ([lifecycle](../database/lifecycle.md#identity)) | Once after upgrading to 0.41.0 |
| `dedupe merge-duplicates [--org SLUG] [--apply]` | Resolve rows that stop `init-db` making the vulnerability and RACI keys NULLS NOT DISTINCT | Only if `init-db` asks for it |

Dry runs are the default for the `secrets` and `dedupe` write commands; they change nothing without `--apply`.

## SLA engine

An SLA policy is data (`sla_policies`), evaluated by `services/sla.py`.

- **The clock starts at detection**, not assignment, so a backlog cannot hide a breach.
- **Policy selection** (`resolve_policy`): enabled policies in ascending `priority`; the first whose `conditions` match wins; a policy with no conditions applies only if it is flagged default; otherwise the loosest (last) policy is used.
- **Conditions** are a flat AND map over this context: `severity, kev, cvss, epss, risk, exposure, asset_criticality, environment, asset_type`. List values match any (case-insensitive), booleans match exactly, `min_<field>` and `max_<field>` are numeric gates where a **missing value does not match** (an unscored finding falls through to a looser policy instead of inheriting a 4-hour deadline).
- **Deadline**: `detected_at + remediate_within_hours`, or only Mon to Fri 09:00 to 17:00 UTC when `business_hours_only` is set (off by default).
- Fields: `triage_within_hours`, `verify_within_hours` (stored; the sweep acts on remediation), `warn_at_percent` (default 75), `escalation_policy_id`.

> [!WARNING]
> **Seeding (0.41.0).** `bootstrap` seeds the built-in policies below, the `standard` ladder and the risk profiles when it creates an organization (or finds one with no SLA policy). For an existing tenant run `veyrs seed-defaults --org <slug> --apply`: it adds only what is missing by slug, never edits a row, and never creates a second default. A tenant that has no SLA policy gets no `sla_due_at` and the sweep skips its findings. The workflow built-ins have their own route (`POST /workflows/seed`) and are not part of `seed-defaults`.

Built-in policies as defined in `BUILTIN_SLA_POLICIES`:

| Slug | Priority | Conditions | Remediate within |
|---|---|---|---|
| `critical-kev-internet` | 10 | `kev` true and `exposure` internet | 4 h (warn at 50 %) |
| `critical` | 20 | severity critical | 24 h |
| `high` | 30 | severity high | 7 days |
| `medium` | 40 | severity medium | 30 days |
| `low` | 50 | severity low | 90 days |
| `default` | 1000 | none, default | 90 days |

Routes (`api/v1/policies.py`): `GET`, `POST /policies/sla` and `PATCH /policies/sla/{id}` (`sla:read`, `sla:write`), `DELETE /policies/sla/{id}` (`sla:admin`), `GET /policies/sla/summary` and `GET /policies/sla/events` (`sla:read`). Reference: [policies API](../api/reference/policies.md).

### The sweep

`evaluate_findings` (run by `run-sla`, and on demand by `POST /policies/sla/evaluate`, `sla:write`, narrowed to the caller's team scope) visits every open finding (`OPEN_STATES`, which includes `remediated` and `verification`, so a finding keeps its clock until it is verified). For each it: applies a policy if none is set; marks **breached** once `now > due` (event `breached`, workflow `sla.breached`); otherwise at `warn_at_percent` records **warned** once (workflow `sla.warned`); then raises the **escalation level**, notifying the level's resolved recipients. `SlaEvent` rows record `set`, `warned`, `breached`, `escalated`, `escalation_recomputed`, `met`. Workflows fire after the whole sweep has settled. The sweep is idempotent.

### Escalation ladders

An escalation policy (`escalation_policies`, API `/policies/escalation`, `escalation:read|write`) is an ordered list of `{level, after_hours, notify}` with **absolute** offsets from the finding's SLA **deadline** (`sla_due_at`; counted from detection before 0.41.0), so level 0 holds until the deadline and a stalled sweep catches up to the right level instead of skipping steps. Built-in `standard`: level 1 after 4 h (`team`), 2 after 8 h (`team_manager`), 3 after 24 h (`security_manager`), 4 after 48 h (`ciso`). Levels must be unique.

> [!WARNING]
> **`notify` targets are resolved (0.41.0).** `team`, `team_manager`, `security_manager`, `ciso`, `org_admin`, `asset_owner`, `assignee`, `role:<slug>`, `team:<slug>`, `user:<email>` and bare e-mail addresses become users from the existing team and role models; the mapping, the `EscalationPolicy.targets` override and the org-admin fallback for an unresolvable target are in [SLA and escalation](../functional/sla-escalation.md#who-is-notified-at-each-escalation-level). The sweep queues the `sla.escalated` notice for them when a level is first reached. The built-in `escalation-notify` workflow still notifies the finding's assignee (who is excluded from the ladder notice so nobody is told twice). Source: `services/sla.py` (`resolve_escalation_recipients`).

## Assignment rules

`POST`/`GET /policies/assignment` (`finding:read`/`finding:write`) define first-match rules (`assignment_rules`, ascending `priority`) that route a new finding to a team or user. Conditions use the same flat grammar as workflows (below); an unknown field never matches. `POST /policies/assignment/test` evaluates a context without saving. Assignment runs inside `process_finding`, before the SLA and ticket policy.

## Auto-ticketing

`services/autoticket.py` opens remediation tickets without a human. **Off by default.** Enabling it changes nothing about findings that already exist; the backlog is a separate, explicit action.

| Setting (`organizations.settings.auto_ticket`) | Default | Meaning |
|---|---|---|
| `enabled` | false | The switch. |
| `min_risk_score` | 70 | Floor (0 to 100). `null` means no threshold, refused unless a severity list or `require_kev` exists, or you send `0`. |
| `severities` | `[]` | Empty means "do not filter", not "match nothing". |
| `require_kev` | false | |
| `internet_exposed_only` | false | |
| `require_owner` | true | Owner means the explicit assignment **or** the asset's owning team. |
| `max_per_run` | 50 (ceiling 500; the verified node uses 25) | A rolling 60-minute budget counted from `ticket_events` (or `external_links` in external mode), not a per-process counter. When exhausted it logs a warning and skips. |

One predicate, `matches()`, serves the live hook, the preview and the backfill. The live hook runs at the end of `process_finding` (after scoring, assignment and SLA). A finding earns a ticket only if it is open, above the thresholds and owned. Type is always `remediation` (the only type that de-duplicates per finding, uses the `REM` prefix and advances the finding when resolved), an existing open ticket is reused, and errors never propagate into correlation.

| Route | Permission |
|---|---|
| `GET /tickets/automation` | `ticket:read` |
| `PUT /tickets/automation` | `ticket:admin` |
| `POST /tickets/automation/preview` | `ticket:read`: how many tickets this would create, with a sample |
| `POST /tickets/automation/backfill` | `ticket:admin`: `dry_run` defaults true, `limit` up to 2,000; reports `capped` and `remaining` |

In external ticketing mode the same code creates issues in the external system ([ITSM](itsm-and-webhooks.md#external-ticketing-mode)). Verified node: enabled, threshold 70, severities critical and high, `max_per_run` 25.

## Workflow engine

A workflow is configuration, not code: a **trigger**, a flat **condition** map and an ordered list of **steps** drawn from a fixed registry. There is no expression evaluator and no tenant-authored code path. Routes (`/workflows`, `workflow:read|write|admin`): list, create, patch, `GET /workflows/actions` (the vocabulary the console builder renders), `GET /workflows/runs`, `POST /workflows/seed`. Steps are validated at save time: an unknown action is refused then, not at 3 a.m.

```json
{"slug": "kev-internet-immediate", "trigger": "finding.created",
 "conditions": {"kev": true, "exposure": ["internet"]},
 "steps": [{"action": "create_ticket", "config": {"ticket_type": "remediation"}},
           {"action": "notify", "config": {"event": "finding.created", "to": ["assignee", "asset_owner"]}}],
 "stop_on_error": true}
```

Step parameters live under `config` (never `params`: an old console example used the wrong key and ran every step with empty configuration).

### Triggers

`trigger` is stored as free text and the console builder offers exactly the triggers below, all of which fire. (A workflow saved with any other string, for example the former `manual` and `schedule`, is accepted and never runs.)

| Trigger | Fired by | Status |
|---|---|---|
| `finding.created` | `correlation.process_finding` for a newly created finding | Implemented, verified live (9 runs each for the two `finding.created` built-ins) |
| `sla.warned`, `sla.breached`, `sla.escalated` | the SLA sweep | Verified live (1,529 and 6,741 runs for the built-ins) |
| `ticket.created` | `POST /tickets` | Implemented (an enum member since 0.41.0, so the builder offers it) |
| `ticket.state_changed` | `POST /tickets/{id}/transition` | Implemented |
| `finding.state_changed` | `correlation.transition`, for every move except those made by a workflow or by automatic assignment (so a rule cannot trigger itself). `extra`: `previous_state`, `state` | Implemented in 0.41.0 |
| `finding.risk_changed` | `risk.score_finding` when a re-score changes the risk **level**; not for a finding's first score. `extra`: `previous_level`, `level`, `previous_score`, `score` | Implemented in 0.41.0 |
| `intel.kev_added` | `risk.score_finding` when an already scored finding's KEV flag turns on. `extra`: `previous_level` | Implemented in 0.41.0 |

`manual` and `schedule` were listed in the builder but nothing ever fired them (there is no run-now route and no per-workflow schedule), so they were **removed from the builder in 0.41.0** rather than half-implemented. Existing rows that carry them are untouched and still never run.

### Conditions

`correlation.rule_matches`: every key must match (AND). A key absent from the context makes the rule **not** match, so a typo cannot silently widen scope. A list value means "any of"; a list in the context (`asset_tags`) intersects; strings compare case-insensitively; booleans compare exactly. Available fields for a finding trigger: `trigger, severity, risk_level, risk_score, kev, epss, cvss, state, sla_breached, escalation_level, exposure, asset_criticality, environment, asset_type, asset_tags`; for a ticket: `ticket_type, ticket_state, ticket_priority`; plus anything in the trigger's `extra` (`overdue_hours`, `percent_used`, `level`, `notify`, `previous_state`, `state`).

### Actions

Registered in `workflow.ACTIONS`; the same file describes them for the builder (`ACTION_SCHEMA`) and asserts the two registries agree at import.

| Action | `config` | Behaviour |
|---|---|---|
| `create_ticket` | `ticket_type` (default `remediation`) | Opens or reuses the remediation ticket; in external mode raises the external issue and leaves the later ticket steps skipped. Only `remediation` de-duplicates and advances the finding. |
| `notify` | `to` (`assignee`, `asset_owner`, `team:<slug>`, an e-mail address; default `["assignee"]`), `channels` (default in_app and email), `event` (template; default the trigger name) | Queues notifications. No recipients resolved is a **warning** step, not silence. Only `in_app` and `email` have transports. |
| `transition_finding` | `state` (required) | Advances the finding through its state machine; an illegal move is a step error, not forced. |
| `tag_asset` | `tags` | Adds tags to the asset; never removes. |
| `set_priority` | `priority` (`critical`, `high`, `medium`, `low`) | On the ticket in context; skipped if none. Put after `create_ticket`. |
| `comment` | `body` (placeholders in braces), `internal` (default true) | Adds a ticket comment. Unknown placeholders render empty. |

Each trigger evaluation fires every enabled matching definition in creation order, each with a fresh context. A run is recorded in `workflow_runs` with per-step results and status `succeeded` or `failed`; `stop_on_error` (default true) halts at the first error. The built-in set (`POST /workflows/seed`, idempotent): `kev-internet-immediate`, `critical-risk-ticket`, `sla-breach-notify`, `escalation-notify`.

### Plugins and extension points

There is no plugin loader: no entry points, no dynamic import. Extension is by adding code to a registry, listed in [Extending](extending.md). Workflow actions in particular are reviewed Python functions on purpose.

## Sources

- Timers: `integrations/systemd/`, `infrastructure/systemd/`, `infrastructure/backup/`, `docker/tick.sh`; live `systemctl list-timers`, `journalctl -u veyrs-intel-sync`.
- CLI: `cli.py:672-835`.
- SLA: `services/sla.py` (`evaluate_findings`, `resolve_escalation_recipients`, `recompute_escalation`); retention `services/retention.py`; tick `services/tick.py`; policies API `api/v1/policies.py`.
- Autoticket: `services/autoticket.py`; workflows `services/workflow.py`; trigger call sites `services/sla.py` (`sla.*`), `services/correlation.py` (`finding.created`, `finding.state_changed`), `services/risk.py` (`finding.risk_changed`, `intel.kev_added`), `api/v1/tickets.py` (`ticket.*`).
