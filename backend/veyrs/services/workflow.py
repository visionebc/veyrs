"""The workflow engine (spec section 13).

Configuration, not code: a workflow is a trigger + a condition map + an ordered
list of steps. Each step names an action from the `ACTIONS` registry below, and
actions are ordinary reviewed Python functions -- there is no expression
evaluator, no `eval`, no user-supplied code path. In a multi-tenant security
product, a "flexible" rules engine that executes tenant-authored logic is an
RCE waiting to happen; the spec's requirement is that workflows are configurable
*without code changes*, which this satisfies.

The canonical chain from the spec runs end to end:

    CVE detected -> normalize -> identify product -> identify assets -> CVSS
    -> EPSS -> KEV -> VEYRS risk -> owner -> team -> ticket -> SLA -> notify
    -> monitor -> escalate -> remediation -> verification -> close

Steps 1-9 happen in `services/correlation.correlate_cve`; this module wires the
remaining, org-configurable half (ticket / notify / escalate / tag / webhook).
"""
from __future__ import annotations

import datetime as dt
import logging
import uuid
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Asset, Finding, Team, Ticket, User, WorkflowDefinition, WorkflowRun,
)
from . import correlation, notifications, ticketing
from .sla import sla_status

log = logging.getLogger("veyrs.workflow")

ActionFn = Callable[[Session, "WorkflowContext", dict], dict]


class WorkflowError(RuntimeError):
    pass


class WorkflowContext:
    """Everything a step may read. Deliberately a fixed surface."""

    def __init__(
        self,
        organization_id: uuid.UUID,
        *,
        trigger: str,
        finding: Finding | None = None,
        ticket: Ticket | None = None,
        extra: dict[str, Any] | None = None,
        actor_label: str = "workflow",
    ) -> None:
        self.organization_id = organization_id
        self.trigger = trigger
        self.finding = finding
        self.ticket = ticket
        self.extra = extra or {}
        self.actor_label = actor_label

    def as_conditions(self, session: Session) -> dict[str, Any]:
        """Flat map the shared condition grammar is evaluated against."""
        data: dict[str, Any] = {"trigger": self.trigger, **self.extra}
        if self.finding is not None:
            asset = session.get(Asset, self.finding.asset_id)
            data.update({
                "severity": self.finding.severity,
                "risk_level": self.finding.risk_level,
                "risk_score": self.finding.risk_score,
                "kev": bool(self.finding.kev),
                "epss": self.finding.epss_score,
                "cvss": self.finding.cvss_score,
                "state": self.finding.state,
                "sla_breached": bool(self.finding.sla_breached),
                "escalation_level": self.finding.escalation_level,
                "exposure": asset.exposure if asset else None,
                "asset_criticality": asset.criticality if asset else None,
                "environment": asset.environment if asset else None,
                "asset_type": asset.asset_type if asset else None,
                "asset_tags": list(asset.tags or []) if asset else [],
            })
        if self.ticket is not None:
            data.update({
                "ticket_type": self.ticket.ticket_type,
                "ticket_state": self.ticket.state,
                "ticket_priority": self.ticket.priority,
            })
        return data

    def as_template(self, session: Session) -> dict[str, Any]:
        """Placeholders available to notification templates."""
        data: dict[str, Any] = {"trigger": self.trigger, **self.extra}
        if self.finding is not None:
            asset = session.get(Asset, self.finding.asset_id)
            status = sla_status(self.finding)
            data.update({
                "title": self.finding.title,
                "asset": asset.name if asset else "",
                "risk_score": self.finding.risk_score,
                "risk_level": self.finding.risk_level,
                "severity": self.finding.severity,
                "due_at": status.get("due_at") or "",
                "percent_used": status.get("percent_used") or "",
                "link": f"/findings/{self.finding.id}",
            })
        if self.ticket is not None:
            data.update({
                "reference": self.ticket.reference,
                "title": self.ticket.title,
                "priority": self.ticket.priority,
                "state": self.ticket.state,
                "link": f"/tickets/{self.ticket.id}",
            })
        return data


# --------------------------------------------------------------------------
# Actions
# --------------------------------------------------------------------------


def _action_create_ticket(session: Session, ctx: WorkflowContext, config: dict) -> dict:
    if ctx.finding is None:
        return {"status": "skipped", "detail": "no finding in context"}
    from . import remediation

    record, created = remediation.open_for_finding(
        session, ctx.finding,
        ticket_type=config.get("ticket_type", "remediation"),
        actor_label=ctx.actor_label,
    )
    # `ctx.ticket` stays None in external mode rather than being handed a
    # look-alike: the later steps that use it (comment, transition, approval)
    # operate on a VEYRS ticket and there is no such thing here. A duck-typed
    # stand-in would make those steps fail deep instead of skipping cleanly.
    ctx.ticket = record.ticket
    return {"status": "ok", "detail": {
        "ticket": record.reference, "created": created, "kind": record.kind,
        "url": record.url,
    }}


def _resolve_recipients(session: Session, ctx: WorkflowContext, config: dict):
    """Turn a step's `to` list into concrete users / team ids / addresses."""
    users: list[User] = []
    team_ids: list[uuid.UUID] = []
    addresses: list[str] = []
    for target in config.get("to") or ["assignee"]:
        if target == "assignee" and ctx.finding is not None:
            if ctx.finding.assigned_user_id:
                user = session.get(User, ctx.finding.assigned_user_id)
                if user is not None:
                    users.append(user)
            if ctx.finding.assigned_team_id:
                team_ids.append(ctx.finding.assigned_team_id)
        elif target == "asset_owner" and ctx.finding is not None:
            asset = session.get(Asset, ctx.finding.asset_id)
            if asset is not None and asset.owner_id:
                user = session.get(User, asset.owner_id)
                if user is not None:
                    users.append(user)
        elif isinstance(target, str) and target.startswith("team:"):
            team = session.execute(
                select(Team).where(
                    Team.organization_id == ctx.organization_id,
                    Team.slug == target.split(":", 1)[1],
                )
            ).scalars().first()
            if team is not None:
                team_ids.append(team.id)
        elif isinstance(target, str) and "@" in target:
            addresses.append(target)
    return users, team_ids, addresses


def _action_notify(session: Session, ctx: WorkflowContext, config: dict) -> dict:
    users, team_ids, addresses = _resolve_recipients(session, ctx, config)
    event = config.get("event") or ctx.trigger
    channels = tuple(config.get("channels") or ("in_app", "email"))
    context = ctx.as_template(session)
    created = notifications.queue(
        session, ctx.organization_id, event, context,
        users=users, addresses=addresses, channels=channels,
        finding_id=ctx.finding.id if ctx.finding else None,
        ticket_id=ctx.ticket.id if ctx.ticket else None,
    )
    for team_id in team_ids:
        created += notifications.queue(
            session, ctx.organization_id, event, context,
            team_id=team_id, channels=channels,
            finding_id=ctx.finding.id if ctx.finding else None,
            ticket_id=ctx.ticket.id if ctx.ticket else None,
        )
    if not created:
        # Silence here means somebody configured a workflow that notifies
        # nobody. Report it as a step outcome so it shows up in the run log.
        return {"status": "warning", "detail": "no recipients resolved"}
    return {"status": "ok", "detail": {"queued": len(created), "event": event}}


def _action_transition_finding(session: Session, ctx: WorkflowContext, config: dict) -> dict:
    if ctx.finding is None:
        return {"status": "skipped", "detail": "no finding in context"}
    target = config.get("state")
    if not target:
        raise WorkflowError("transition_finding requires a 'state'")
    try:
        correlation.advance(session, ctx.finding, target,
                            actor_label=ctx.actor_label, note="workflow")
    except correlation.TransitionError as exc:
        return {"status": "error", "detail": str(exc)}
    return {"status": "ok", "detail": {"state": ctx.finding.state}}


def _action_tag_asset(session: Session, ctx: WorkflowContext, config: dict) -> dict:
    if ctx.finding is None:
        return {"status": "skipped", "detail": "no finding in context"}
    asset = session.get(Asset, ctx.finding.asset_id)
    if asset is None:
        return {"status": "skipped", "detail": "asset missing"}
    tags = set(asset.tags or [])
    added = [t for t in (config.get("tags") or []) if t not in tags]
    asset.tags = sorted(tags | set(added))
    session.flush()
    return {"status": "ok", "detail": {"added": added}}


def _action_set_priority(session: Session, ctx: WorkflowContext, config: dict) -> dict:
    if ctx.ticket is None:
        return {"status": "skipped", "detail": "no ticket in context"}
    ctx.ticket.priority = config.get("priority", ctx.ticket.priority)
    session.flush()
    return {"status": "ok", "detail": {"priority": ctx.ticket.priority}}


def _action_comment(session: Session, ctx: WorkflowContext, config: dict) -> dict:
    if ctx.ticket is None:
        return {"status": "skipped", "detail": "no ticket in context"}
    body = str(config.get("body") or "").format_map(
        notifications._SafeDict(ctx.as_template(session))
    )
    ticketing.add_comment(session, ctx.ticket, body or "(empty)",
                          author_label=ctx.actor_label,
                          is_internal=bool(config.get("internal", True)))
    return {"status": "ok", "detail": "comment added"}


ACTIONS: dict[str, ActionFn] = {
    "create_ticket": _action_create_ticket,
    "notify": _action_notify,
    "transition_finding": _action_transition_finding,
    "tag_asset": _action_tag_asset,
    "set_priority": _action_set_priority,
    "comment": _action_comment,
}


# --------------------------------------------------------------------------
# The vocabulary, in words a person can read
#
# This lives NEXT TO the implementations on purpose. The console used to ship
# its own idea of what a step looked like -- and shipped it wrong: its example
# put the parameters under `"params"` while the engine has always read
# `step.get("config")`, so every workflow created from that example ran with an
# empty configuration and reported success. A form built from a description
# that sits in another repository, in another language, is a form that drifts.
#
# `describe()` is what `/workflows/actions` returns, so the guided builder in
# the console renders its fields from the same file that executes them. Adding
# an action without describing it makes it appear in the builder with no
# fields, which is visible; describing one that does not exist raises at
# import.
# --------------------------------------------------------------------------

TRIGGER_HELP: dict[str, str] = {
    "finding.created": "A vulnerability is first seen on one of your assets.",
    "finding.state_changed": "Somebody moves a finding along its lifecycle "
                             "(triaged, assigned, remediated, verified, closed).",
    "finding.risk_changed": "A finding's VEYRS risk score moves -- usually because "
                            "EPSS rose or CISA added the CVE to KEV.",
    "sla.warned": "A deadline is approaching and the finding is still open.",
    "sla.breached": "A deadline has passed with the finding still open.",
    "sla.escalated": "The escalation ladder moved this finding up a level.",
    "intel.kev_added": "CISA added a CVE you are exposed to to the Known "
                       "Exploited Vulnerabilities catalogue.",
    "ticket.state_changed": "A ticket moves between states.",
    "manual": "Nothing fires this on its own; somebody runs it.",
    "schedule": "Runs on a timer rather than in response to an event.",
}

#: Per action: what it does, what it needs in context, and its fields.
#: `type` is one of text | textarea | select | multiselect | tags | number.
ACTION_SCHEMA: dict[str, dict[str, Any]] = {
    "create_ticket": {
        "label": "Open a ticket",
        "summary": "Creates the remediation ticket for the finding that fired the "
                   "workflow. If one is already open, it is reused rather than "
                   "duplicated.",
        "requires": "a finding",
        "fields": [{
            "name": "ticket_type", "label": "Ticket type", "type": "select",
            "default": "remediation",
            "options": [
                {"value": "remediation", "label": "Remediation (recommended)"},
                {"value": "incident", "label": "Incident"},
                {"value": "problem", "label": "Problem"},
                {"value": "change", "label": "Change"},
            ],
            "help": "Only `remediation` de-duplicates per finding and advances the "
                    "finding when the ticket is resolved. The other types are "
                    "dead ends for this purpose.",
        }],
    },
    "notify": {
        "label": "Notify somebody",
        "summary": "Queues a notification. If it resolves to no recipients the step "
                   "reports a warning rather than passing silently.",
        "requires": "nothing (but recipients depend on the finding)",
        "fields": [
            {"name": "to", "label": "Recipients", "type": "tags",
             "default": ["assignee"],
             "help": "`assignee`, `asset_owner`, `team:<slug>` or a plain email "
                     "address. One per entry."},
            {"name": "channels", "label": "Channels", "type": "multiselect",
             "default": ["in_app", "email"],
             "options": [
                 {"value": "in_app", "label": "In-app"},
                 {"value": "email", "label": "Email"},
                 {"value": "webhook", "label": "Webhook"},
                 {"value": "slack", "label": "Slack"},
             ]},
            {"name": "event", "label": "Template", "type": "text",
             "help": "Which notification template to render. Leave empty to use "
                     "the trigger's own name."},
        ],
    },
    "transition_finding": {
        "label": "Move the finding",
        "summary": "Advances the finding to another lifecycle state. An illegal "
                   "transition is reported as a step error, not forced.",
        "requires": "a finding",
        "fields": [{
            "name": "state", "label": "New state", "type": "select",
            "required": True,
            "options": [
                {"value": v, "label": v.replace("_", " ")}
                for v in ("triaged", "risk_assessed", "assigned", "in_progress",
                          "pending_verification", "remediated", "verified",
                          "closed", "risk_accepted", "false_positive")
            ],
        }],
    },
    "tag_asset": {
        "label": "Tag the asset",
        "summary": "Adds tags to the asset the finding is on. Existing tags are "
                   "kept; this never removes one.",
        "requires": "a finding",
        "fields": [{"name": "tags", "label": "Tags to add", "type": "tags",
                    "required": True}],
    },
    "set_priority": {
        "label": "Set ticket priority",
        "summary": "Overrides the priority of the ticket in context.",
        "requires": "a ticket -- put this AFTER an 'Open a ticket' step",
        "fields": [{
            "name": "priority", "label": "Priority", "type": "select",
            "required": True,
            "options": [{"value": v, "label": v} for v in
                        ("critical", "high", "medium", "low")],
        }],
    },
    "comment": {
        "label": "Comment on the ticket",
        "summary": "Adds a comment. `{placeholders}` are filled from the finding "
                   "and ticket; an unknown one is left as-is rather than crashing.",
        "requires": "a ticket -- put this AFTER an 'Open a ticket' step",
        "fields": [
            {"name": "body", "label": "Comment", "type": "textarea", "required": True,
             "help": "Available placeholders include {cve}, {asset}, {severity}, "
                     "{risk_score}, {ticket_reference}."},
            {"name": "internal", "label": "Internal only", "type": "select",
             "default": "true",
             "options": [{"value": "true", "label": "Yes"},
                         {"value": "false", "label": "No"}]},
        ],
    },
}

# An action that executes but cannot be described is an action the builder
# renders as an empty box; one that is described but does not execute is a
# field somebody fills in for nothing. Neither is allowed to ship.
assert set(ACTION_SCHEMA) == set(ACTIONS), (
    f"ACTION_SCHEMA and ACTIONS disagree: "
    f"{set(ACTION_SCHEMA) ^ set(ACTIONS)}"
)


def describe() -> dict[str, Any]:
    """The workflow vocabulary, for the console's guided builder."""
    from ..models.workflow import TriggerType

    return {
        "actions": sorted(ACTIONS),
        "triggers": [t.value for t in TriggerType],
        "trigger_help": dict(TRIGGER_HELP),
        "action_schema": ACTION_SCHEMA,
        # Said explicitly because the console got it wrong for two releases:
        # the engine reads `step["config"]`, never `step["params"]`.
        "step_shape": {"action": "<action name>", "config": {"<field>": "<value>"}},
    }


def validate_steps(steps: list[dict]) -> None:
    """Reject unknown actions at save time, not at 3am when the trigger fires."""
    for index, step in enumerate(steps or []):
        action = (step or {}).get("action")
        if action not in ACTIONS:
            raise WorkflowError(
                f"step {index}: unknown action {action!r}; "
                f"known actions: {sorted(ACTIONS)}"
            )


# --------------------------------------------------------------------------
# Execution
# --------------------------------------------------------------------------


def matching_definitions(
    session: Session, organization_id: uuid.UUID, trigger: str
) -> list[WorkflowDefinition]:
    return session.execute(
        select(WorkflowDefinition).where(
            WorkflowDefinition.organization_id == organization_id,
            WorkflowDefinition.trigger == trigger,
            WorkflowDefinition.is_enabled.is_(True),
        ).order_by(WorkflowDefinition.created_at)
    ).scalars().all()


def run_definition(
    session: Session, definition: WorkflowDefinition, ctx: WorkflowContext
) -> WorkflowRun:
    run = WorkflowRun(
        organization_id=ctx.organization_id, definition_id=definition.id,
        trigger=ctx.trigger,
        finding_id=ctx.finding.id if ctx.finding else None,
        context=ctx.extra,
    )
    session.add(run)
    session.flush()

    results: list[dict] = []
    status = "succeeded"
    for step in definition.steps or []:
        action_name = (step or {}).get("action")
        action = ACTIONS.get(action_name)
        if action is None:
            results.append({"action": action_name, "status": "error",
                            "detail": "unknown action"})
            status = "failed"
            if definition.stop_on_error:
                break
            continue
        try:
            outcome = action(session, ctx, (step or {}).get("config") or {})
        except Exception as exc:  # noqa: BLE001 - recorded per step
            log.exception("workflow %s step %s failed", definition.slug, action_name)
            results.append({"action": action_name, "status": "error",
                            "detail": f"{type(exc).__name__}: {exc}"})
            status = "failed"
            if definition.stop_on_error:
                break
            continue
        results.append({"action": action_name, **outcome})
        if outcome.get("status") == "error":
            status = "failed"
            if definition.stop_on_error:
                break

    run.step_results = results
    run.status = status
    run.finished_at = dt.datetime.now(dt.timezone.utc)
    run.ticket_id = ctx.ticket.id if ctx.ticket else None
    definition.run_count += 1
    definition.last_run_at = run.finished_at
    session.flush()
    return run


def trigger(
    session: Session,
    organization_id: uuid.UUID,
    trigger_name: str,
    *,
    finding: Finding | None = None,
    ticket: Ticket | None = None,
    extra: dict | None = None,
    actor_label: str = "workflow",
) -> list[WorkflowRun]:
    """Fire every enabled workflow whose trigger and conditions match."""
    definitions = matching_definitions(session, organization_id, trigger_name)
    if not definitions:
        return []
    ctx = WorkflowContext(organization_id, trigger=trigger_name, finding=finding,
                          ticket=ticket, extra=extra, actor_label=actor_label)
    conditions = ctx.as_conditions(session)
    runs: list[WorkflowRun] = []
    for definition in definitions:
        if definition.conditions and not correlation.rule_matches(
            definition.conditions, conditions
        ):
            continue
        # Each definition gets a fresh context so one workflow's created ticket
        # does not leak into the next one's condition evaluation.
        step_ctx = WorkflowContext(
            organization_id, trigger=trigger_name, finding=finding, ticket=ticket,
            extra=extra, actor_label=actor_label,
        )
        runs.append(run_definition(session, definition, step_ctx))
    return runs


BUILTIN_WORKFLOWS = [
    {
        "slug": "kev-internet-immediate",
        "name": "KEV on an internet-facing asset: ticket + notify immediately",
        "trigger": "finding.created",
        "conditions": {"kev": True, "exposure": ["internet"]},
        "steps": [
            {"action": "create_ticket", "config": {"ticket_type": "remediation"}},
            {"action": "notify", "config": {"event": "finding.created",
                                            "to": ["assignee", "asset_owner"]}},
            {"action": "tag_asset", "config": {"tags": ["kev-exposed"]}},
        ],
    },
    {
        "slug": "critical-risk-ticket",
        "name": "Critical risk: open a remediation ticket",
        "trigger": "finding.created",
        "conditions": {"risk_level": ["critical"]},
        "steps": [
            {"action": "create_ticket", "config": {}},
            {"action": "notify", "config": {"event": "finding.created"}},
        ],
    },
    {
        "slug": "sla-breach-notify",
        "name": "SLA breach: notify the owner and the security team",
        "trigger": "sla.breached",
        "conditions": {},
        "steps": [
            {"action": "notify", "config": {"event": "sla.breached",
                                            "to": ["assignee", "asset_owner"]}},
        ],
    },
    {
        "slug": "escalation-notify",
        "name": "Escalation: notify the level target",
        "trigger": "sla.escalated",
        "conditions": {},
        "steps": [
            {"action": "notify", "config": {"event": "sla.escalated", "to": ["assignee"]}},
        ],
    },
]


def seed_workflows(session: Session, organization_id: uuid.UUID) -> int:
    existing = {
        d.slug for d in session.execute(
            select(WorkflowDefinition).where(
                WorkflowDefinition.organization_id == organization_id
            )
        ).scalars().all()
    }
    created = 0
    for spec in BUILTIN_WORKFLOWS:
        if spec["slug"] in existing:
            continue
        validate_steps(spec["steps"])
        session.add(WorkflowDefinition(organization_id=organization_id, **spec))
        created += 1
    session.flush()
    return created


__all__ = [
    "ACTIONS", "ACTION_SCHEMA", "TRIGGER_HELP", "describe",
    "WorkflowContext", "WorkflowError", "validate_steps", "trigger",
    "run_definition", "matching_definitions", "seed_workflows", "BUILTIN_WORKFLOWS",
]
