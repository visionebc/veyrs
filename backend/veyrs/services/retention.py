"""Data retention: `veyrs prune`.

Before 0.41.0 only `epss_history` had a retention. Every other append-only table
grew without bound and there was no stated period for audit or personal data.
This module is the single definition of what is kept for how long; the periods
are settings (`retention_*_days`, 0 = keep forever) and the hourly tick
runs it with `--apply`.

Rules that are not negotiable:

* **A row younger than its setting is never deleted.** Every rule is
  `<timestamp> < now - days`; there is no size- or count-based trimming.
* **Audit and authentication trails are the longest-lived** (400 days by
  default: a full audit year plus a quarter of slack for the review cycle).
* **Nothing the product still reads is pruned.** Event/history rows go only with
  findings that are no longer open; agent events only with finished jobs; run
  tables only finished runs; the newest run of every intelligence feed (and the
  newest successful one, which freshness checks read) always stays.
* Dry run is the default. Deletion is batched (one transaction per batch) so a
  first run over a large table never holds one long lock.

`audit_log` / `ai_audit_log` rows with a NULL tenant are invisible under row
level security and are not touched (every writer passes a tenant).
"""
from __future__ import annotations

import datetime as dt
import logging
from dataclasses import dataclass
from typing import Iterable

from sqlalchemy import select, text

from ..config import settings
from ..models import OPEN_STATES, Organization

log = logging.getLogger("veyrs.retention")

BATCH = 5000

_OPEN = ", ".join(f"'{s}'" for s in sorted(OPEN_STATES))
_FINDING_CLOSED = f"finding_id IN (SELECT id FROM findings WHERE state NOT IN ({_OPEN}))"


@dataclass(frozen=True)
class Rule:
    table: str
    setting: str          # attribute of `settings`, days
    tenant: bool          # True: RLS-bound, run once per organization
    where: str            # uses :cutoff
    note: str


RULES: tuple[Rule, ...] = (
    Rule("audit_log", "retention_audit_days", True, "created_at < :cutoff",
         "audit trail"),
    Rule("ai_audit_log", "retention_audit_days", True, "created_at < :cutoff",
         "AI gateway audit trail"),
    Rule("auth_events", "retention_audit_days", False, "created_at < :cutoff",
         "sign-in attempts"),
    Rule("refresh_tokens", "retention_tokens_days", False,
         "(expires_at < :cutoff OR (revoked_at IS NOT NULL AND revoked_at < :cutoff))",
         "expired or revoked refresh tokens"),
    Rule("notifications", "retention_notifications_days", True,
         "(read_at < :cutoff OR (channel <> 'in_app' AND status IN ('sent', 'failed') "
         "AND created_at < :cutoff))",
         "read in-app messages; delivered or given-up e-mail/webhook rows"),
    Rule("workflow_runs", "retention_runs_days", True, "started_at < :cutoff",
         "workflow run log"),
    Rule("import_runs", "retention_runs_days", True,
         "finished_at IS NOT NULL AND started_at < :cutoff", "finished import runs"),
    Rule("asset_source_runs", "retention_runs_days", True,
         "finished_at IS NOT NULL AND started_at < :cutoff", "finished asset-source runs"),
    Rule("agent_job_events", "retention_runs_days", True,
         "created_at < :cutoff AND job_id IN (SELECT id FROM agent_jobs WHERE state "
         "NOT IN ('queued', 'leased', 'running'))", "log lines of finished agent jobs"),
    Rule("feed_runs", "retention_runs_days", False,
         "started_at < :cutoff AND id NOT IN (SELECT DISTINCT ON (feed) id FROM feed_runs "
         "WHERE status = 'succeeded' ORDER BY feed, started_at DESC) "
         "AND id NOT IN (SELECT DISTINCT ON (feed) id FROM feed_runs "
         "ORDER BY feed, started_at DESC)",
         "intelligence feed runs (newest and newest successful per feed are kept)"),
    Rule("finding_events", "retention_events_days", True,
         f"created_at < :cutoff AND {_FINDING_CLOSED}", "history of closed findings"),
    Rule("sla_events", "retention_events_days", True,
         f"created_at < :cutoff AND {_FINDING_CLOSED}", "SLA events of closed findings"),
    Rule("risk_score_history", "retention_events_days", True,
         f"created_at < :cutoff AND {_FINDING_CLOSED}", "score history of closed findings"),
    Rule("threat_articles", "retention_articles_days", True,
         "COALESCE(published_at, created_at) < :cutoff", "threat news articles"),
)

RULES_BY_TABLE = {r.table: r for r in RULES}


def retention_days(rule: Rule) -> int:
    return int(getattr(settings, rule.setting))


def cutoff_for(rule: Rule, now: dt.datetime) -> dt.datetime | None:
    days = retention_days(rule)
    return None if days <= 0 else now - dt.timedelta(days=days)


#: The append-only logs (schema step `step_auth`): their trigger refuses every
#: DELETE unless the transaction set `veyrs.audit_prune = 'on'`, which only
#: this module does.
AUDIT_TABLES = frozenset({"audit_log", "ai_audit_log", "auth_events"})


def _bind(session, rule: Rule, org_id) -> None:
    """Per-transaction settings: both are `set_config(..., true)`, so they are
    gone after every commit and must be re-applied before each batch."""
    from ..db import set_tenant

    set_tenant(session, org_id)
    if rule.table in AUDIT_TABLES:
        session.execute(text("SELECT set_config('veyrs.audit_prune', 'on', true)"))


def _run_rule(session, rule: Rule, cutoff: dt.datetime, *, apply: bool, org_id=None) -> int:
    _bind(session, rule, org_id)
    if not apply:
        return int(session.execute(
            text(f'SELECT count(*) FROM "{rule.table}" WHERE {rule.where}'),
            {"cutoff": cutoff},
        ).scalar_one())
    total = 0
    while True:
        _bind(session, rule, org_id)
        result = session.execute(
            text(f'DELETE FROM "{rule.table}" WHERE id IN '
                 f'(SELECT id FROM "{rule.table}" WHERE {rule.where} LIMIT {BATCH})'),
            {"cutoff": cutoff},
        )
        session.commit()
        total += result.rowcount or 0
        if (result.rowcount or 0) < BATCH:
            return total


def prune(*, apply: bool = False, tables: Iterable[str] | None = None,
          now: dt.datetime | None = None) -> dict[str, dict]:
    """Apply (or, by default, only count) every retention rule.

    Returns `{table: {"days", "cutoff", "rows"}}`; `rows` is what was deleted
    when `apply`, else what would be.
    """
    from ..db import SessionLocal, set_tenant

    now = now or dt.datetime.now(dt.timezone.utc)
    wanted = set(tables) if tables else None
    if wanted:
        unknown = wanted - set(RULES_BY_TABLE)
        if unknown:
            raise ValueError(f"unknown table(s): {sorted(unknown)}")
    out: dict[str, dict] = {}
    with SessionLocal() as session:
        org_ids = [o.id for o in session.execute(select(Organization)).scalars().all()]
        session.rollback()
        for rule in RULES:
            if wanted and rule.table not in wanted:
                continue
            cutoff = cutoff_for(rule, now)
            entry = {"days": retention_days(rule), "cutoff": None, "rows": 0,
                     "note": rule.note}
            out[rule.table] = entry
            if cutoff is None:
                continue
            entry["cutoff"] = cutoff.isoformat()
            if rule.tenant and rule.table not in AUDIT_TABLES:
                for org_id in org_ids:
                    entry["rows"] += _run_rule(session, rule, cutoff, apply=apply, org_id=org_id)
                    session.rollback()
            else:
                # Global tables, and the audit logs: under `veyrs.audit_prune`
                # their prune policies expose every tenant's rows (and the
                # NULL-tenant platform rows a per-tenant loop never sees).
                entry["rows"] += _run_rule(session, rule, cutoff, apply=apply)
                session.rollback()
    return out


def run_cli(*, apply: bool, tables: list[str] | None = None) -> int:
    try:
        result = prune(apply=apply, tables=tables)
    except ValueError as exc:
        print(str(exc))
        return 2
    verb = "deleted" if apply else "would delete"
    for table, entry in result.items():
        if entry["cutoff"] is None:
            print(f"{table}: retention is 0 (keep everything)")
        else:
            print(f"{table}: {verb} {entry['rows']} row(s) older than {entry['days']} "
                  f"day(s) [{entry['note']}]")
    if not apply:
        print("dry run - nothing deleted; re-run with --apply")
    return 0
