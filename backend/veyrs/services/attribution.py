"""Why did this finding change? Attribution of closes and reopens.

An operator sees a finding flip to `remediated`, or come back as `new`, and
VEYRS used to show the state and not the cause -- even though VEYRS itself
caused the change and had written a row about it. That is the failure this
module exists to prevent: a drift alert that says "if nobody edited it here,
somebody changed the device", when the product had made the change itself and
had the audit row, is a correlation that was available and thrown away.

**This is a reader, not an inference engine.** Every cause comes from facts
written at the moment of the change (`FindingEvent.details`, filled in at the
source since 0.33.0: the import run and scan test, the absence count and who
vouched for coverage, the ticket and external system, the workflow and run,
the risk acceptance, the installed version). Where a fact was not recorded the
answer is `unknown`, and the sentence says WHICH fact is missing. It never
guesses, and it never asks a language model.

**Reopens carry a regression assessment**: who saw it again, how long after
it was closed, and whether the inventory of the same installed product moved
in between (old -> new version, and which run reported it). That is the drift
analogue -- "it came back" next to "and the version had been rolled back two
hours earlier, by the agent sweep".

The inventory half is written here too (`note_inventory_change`), because an
installed-version change is not a finding event anywhere else: it is recorded
on every finding linked to that installation, so the explanation can find it.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    CLOSED_STATES, Asset, AssetProduct, Finding, FindingEvent, ImportRun, Product, ScanTest,
    User,
)

#: Since when the emission points record their cause. Events older than this
#: are explained from what they carry, and the gap is named, not papered over.
DETAIL_SINCE = "0.33.0"

#: Every cause the explainer can return. A closed vocabulary so the console can
#: badge it and the `changes` endpoint can filter on it.
CAUSES: dict[str, str] = {
    "operator": "Operator action",
    "verification_passed": "Verification passed",
    "verification_failed": "Verification failed",
    "reimport_absence": "Absent from re-import",
    "rescan_seen_again": "Seen again by a scan",
    "ticket_resolved": "Ticket resolved in VEYRS",
    "ticket_closed_external": "Ticket closed in external system",
    # No code path reopens a finding from a ticket today (the ticket link only
    # advances a finding on resolution). Kept so an event carrying it would be
    # read correctly rather than reported as unknown.
    "ticket_reopened_external": "Ticket reopened in external system",
    "workflow_rule": "Workflow rule",
    "acceptance_approved": "Risk acceptance approved",
    "acceptance_expired": "Risk acceptance expired",
    "acceptance_revoked": "Risk acceptance revoked",
    "inventory_version_changed": "Installed version changed",
    "correlation_rescan": "Correlation engine",
    # The SLA sweep breaches and escalates but never moves a finding's state.
    # Listed for the same reason as `ticket_reopened_external`.
    "sla_policy": "SLA policy",
    "assignment_rule": "Assignment rule",
    "unknown": "Cause not recorded",
}

#: "Out of the queue": fixed, being verified, or formally closed/accepted.
FIXED_STATES = frozenset(CLOSED_STATES) | {"remediated", "verification"}

#: Events that move `Finding.state`. Anything else is an annotation.
TRANSITION_EVENTS = frozenset({
    "state_changed", "reopened", "remediated", "no_longer_applicable",
    "risk_accepted", "risk_acceptance_ended",
})
INVENTORY_EVENT = "inventory_version_changed"

#: For events written before `to_state` was stored, what the event name implies.
_IMPLIED_TO = {
    "reopened": "new", "remediated": "remediated", "no_longer_applicable": "remediated",
    "risk_accepted": "accepted_risk",
}

#: Upper bound on events one `changes` request scans before filtering by cause.
CHANGES_SCAN_CAP = 5000


# ---------------------------------------------------------------------------
# Writing: installed-version changes
# ---------------------------------------------------------------------------
def note_inventory_change(
    session: Session,
    installation: AssetProduct,
    *,
    old_version: str | None,
    new_version: str | None,
    detected_by: str | None,
    source: dict | None = None,
) -> int:
    """Record an installed-version change on every finding linked to it.

    Called by each path that rewrites `AssetProduct.version` in place
    (`inventory.install`, the asset API, the importer filling an empty
    version). Returns how many findings were annotated. Never changes state.
    """
    if old_version == new_version or installation.id is None:
        return 0
    findings = session.execute(
        select(Finding).where(
            Finding.organization_id == installation.organization_id,
            Finding.asset_product_id == installation.id,
        )
    ).scalars().all()
    if not findings:
        return 0
    product = session.get(Product, installation.product_id)
    for finding in findings:
        session.add(FindingEvent(
            organization_id=finding.organization_id, finding_id=finding.id,
            event=INVENTORY_EVENT, actor_label=(detected_by or "inventory")[:200],
            details={
                "origin": "inventory",
                "asset_product_id": str(installation.id),
                "asset_id": str(installation.asset_id),
                "product": product.name if product is not None else None,
                "old_version": old_version, "new_version": new_version,
                "detected_by": detected_by,
                "source": source or None,
                "finding_state": finding.state,
            },
        ))
    return len(findings)


# ---------------------------------------------------------------------------
# Reading
# ---------------------------------------------------------------------------
def _text(value: Any) -> str | None:
    return value if isinstance(value, str) and value else None


def _short(value: Any) -> str:
    return str(value)[:8] if value else "?"


def _parse_ts(value: Any) -> dt.datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = dt.datetime.fromisoformat(value)
    except ValueError:
        return None
    return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)


def _uuid(value: Any) -> uuid.UUID | None:
    try:
        return uuid.UUID(str(value)) if value else None
    except ValueError:
        return None


def _duration(delta: dt.timedelta) -> str:
    seconds = int(max(delta.total_seconds(), 0))
    days, rest = divmod(seconds, 86400)
    hours, rest = divmod(rest, 3600)
    minutes = rest // 60
    if days:
        return f"{days} day{'s' if days != 1 else ''}" + (
            f" {hours} hour{'s' if hours != 1 else ''}" if hours else "")
    if hours:
        return f"{hours} hour{'s' if hours != 1 else ''}" + (
            f" {minutes} minute{'s' if minutes != 1 else ''}" if minutes else "")
    if minutes:
        return f"{minutes} minute{'s' if minutes != 1 else ''}"
    return "less than a minute"


def states_of(event: FindingEvent) -> tuple[str | None, str | None]:
    """(from, to) of a transition event, from the columns or the details."""
    details = event.details or {}
    frm = event.from_state or _text(details.get("from")) or _text(details.get("previous_state"))
    to = event.to_state or _text(details.get("to")) or _IMPLIED_TO.get(event.event)
    if to is None and event.event == "risk_acceptance_ended":
        to = _text(details.get("restored_state"))
    return frm, to


def kind_of(event_name: str, frm: str | None, to: str | None) -> str:
    """closed | reopened | progressed -- relative to "out of the queue"."""
    if event_name == "reopened":
        return "reopened"
    if to in FIXED_STATES and (frm is None or frm not in FIXED_STATES):
        return "closed"
    if frm in FIXED_STATES and to is not None and to not in FIXED_STATES:
        return "reopened"
    return "progressed"


class _Lookups:
    """Per-request cache of the rows explanations cite."""

    def __init__(self, session: Session) -> None:
        self.session = session
        self._users: dict[uuid.UUID, str | None] = {}
        self._runs: dict[uuid.UUID, ImportRun | None] = {}
        self._tests: dict[uuid.UUID, ScanTest | None] = {}
        self._events: dict[uuid.UUID, list[FindingEvent]] = {}

    def user(self, value: Any) -> str | None:
        key = _uuid(value)
        if key is None:
            return None
        if key not in self._users:
            row = self.session.get(User, key)
            self._users[key] = (row.full_name or row.email) if row is not None else None
        return self._users[key]

    def run(self, value: Any) -> ImportRun | None:
        key = _uuid(value)
        if key is None:
            return None
        if key not in self._runs:
            self._runs[key] = self.session.get(ImportRun, key)
        return self._runs[key]

    def test(self, value: Any) -> ScanTest | None:
        key = _uuid(value)
        if key is None:
            return None
        if key not in self._tests:
            self._tests[key] = self.session.get(ScanTest, key)
        return self._tests[key]

    def events(self, finding_id: uuid.UUID) -> list[FindingEvent]:
        if finding_id not in self._events:
            self._events[finding_id] = list(self.session.execute(
                select(FindingEvent).where(FindingEvent.finding_id == finding_id)
                .order_by(FindingEvent.created_at)
            ).scalars().all())
        return self._events[finding_id]


def _actor(kind: str, label: str | None, **extra: Any) -> dict[str, Any]:
    return {"kind": kind, "label": label, **{k: v for k, v in extra.items() if v is not None}}


def _user_actor(event: FindingEvent) -> dict[str, Any]:
    return _actor("user", event.actor_label, id=str(event.actor_id) if event.actor_id else None)


def _run_phrase(look: _Lookups, run_id: Any) -> str:
    run = look.run(run_id)
    if run is None:
        return f"import run {_short(run_id)}"
    bits = [f"import run {_short(run.id)}"]
    if run.filename:
        bits.append(f"file '{run.filename}'")
    return bits[0] + (f" ({', '.join(bits[1:])})" if len(bits) > 1 else "")


def _coverage_phrase(look: _Lookups, coverage: Any, run_id: Any) -> tuple[str, list[str]]:
    """Who vouched that the closing run observed its scope."""
    if isinstance(coverage, dict) and coverage.get("kind") == "agent":
        if coverage.get("attested"):
            pct = coverage.get("percent")
            return (f"coverage attested by agent '{coverage.get('agent')}' "
                    f"(job {_short(coverage.get('job_id'))}"
                    + (f", scanner completed {pct}%" if isinstance(pct, int) else "")
                    + ")"), []
        return (f"agent '{coverage.get('agent')}' did NOT attest coverage "
                f"(job {_short(coverage.get('job_id'))})"), []
    if isinstance(coverage, dict) and coverage.get("kind") == "connector":
        return (f"pulled by scanner connector '{coverage.get('connector')}', which an "
                "operator opted into closing by absence; a pulled export carries no "
                "coverage measurement"), []
    run = look.run(run_id)
    if run is not None and run.started_by_id:
        who = look.user(run.started_by_id) or _short(run.started_by_id)
        return (f"coverage not machine-attested: the export was imported by {who}"
                + (f" ('{run.filename}')" if run.filename else "")), []
    if run is not None:
        return "coverage not machine-attested: no agent, connector or user vouched for the run", []
    return "", ["coverage attestation"]


def _inventory_between(
    events: Iterable[FindingEvent], start: dt.datetime | None, end: dt.datetime
) -> list[FindingEvent]:
    return [
        e for e in events
        if e.event == INVENTORY_EVENT and e.created_at <= end
        and (start is None or e.created_at >= start)
    ]


def _inventory_phrase(event: FindingEvent) -> str:
    d = event.details or {}
    src = d.get("source") or {}
    where = []
    if isinstance(src, dict):
        if src.get("import_run_id"):
            where.append(f"import run {_short(src['import_run_id'])}")
        if src.get("agent"):
            where.append(f"agent '{src['agent']}'")
    return (f"{d.get('product') or 'the installed product'} changed from "
            f"{d.get('old_version') or 'no version'} to {d.get('new_version') or 'no version'} "
            f"(reported by {d.get('detected_by') or event.actor_label}"
            + (f", {', '.join(where)}" if where else "")
            + f") at {event.created_at.isoformat(timespec='seconds')}")


def _inventory_ref(event: FindingEvent) -> dict[str, Any]:
    d = event.details or {}
    return {
        "at": event.created_at.isoformat(), "event_id": str(event.id),
        "product": d.get("product"), "old_version": d.get("old_version"),
        "new_version": d.get("new_version"), "detected_by": d.get("detected_by"),
        "asset_product_id": d.get("asset_product_id"), "source": d.get("source"),
    }


def _classify(
    look: _Lookups, finding: Finding, event: FindingEvent, frm: str | None, to: str | None,
    previous_at: dt.datetime | None,
) -> dict[str, Any]:
    """cause, actor, evidence and the facts that were not recorded."""
    d = event.details or {}
    origin = d.get("origin")
    ids: dict[str, Any] = {"event_id": str(event.id)}
    missing: list[str] = []
    legacy_gap = f"not recorded before {DETAIL_SINCE}"
    arrow = f"{frm or '?'} to {to or '?'}"

    # -- re-import absence ---------------------------------------------------
    if origin == "reimport_absence" or (
        event.event == "remediated" and d.get("reason") == "absent from scanner export"
    ):
        test = look.test(d.get("test_id"))
        title = d.get("test_title") or (test.title if test is not None else None)
        runs = [r for r in (d.get("absent_import_run_ids") or []) if r]
        ids.update({"scan_test_id": d.get("test_id"), "engagement_id": d.get("engagement_id"),
                    "import_run_ids": runs, "closing_import_run_id": d.get("import_run_id")})
        count = d.get("consecutive_absences")
        sentence = (f"Closed after {count} consecutive run{'s' if count != 1 else ''} of scan "
                    f"test '{title or _short(d.get('test_id'))}' ({d.get('scanner')}) did not "
                    "report it")
        if runs:
            sentence += f" (import runs {', '.join(_short(r) for r in runs)})"
        else:
            missing.append(f"which import runs missed it ({legacy_gap})")
        if d.get("absence_threshold") is not None:
            sentence += f"; the threshold is {d['absence_threshold']}"
        if origin == "reimport_absence":
            phrase, gap = _coverage_phrase(look, d.get("coverage"), d.get("import_run_id"))
            missing += gap
            if phrase:
                sentence += f"; {phrase}"
        else:
            missing.append(f"coverage attestation ({legacy_gap})")
        sentence += ". Absence is not a verified fix."
        return {"cause": "reimport_absence",
                "actor": _actor("system", "importer", component="re-import reconciliation"),
                "sentence": sentence, "ids": ids, "missing": missing}

    # -- seen again ----------------------------------------------------------
    if event.event == "reopened":
        scanner = d.get("scanner")
        correlation_path = origin == "correlation" or scanner == "veyrs-correlation"
        ids.update({"import_run_id": d.get("import_run_id"),
                    "asset_product_id": d.get("asset_product_id")})
        if correlation_path:
            version = d.get("installed_version")
            sentence = ("The correlation engine matched the CVE again"
                        + (f" against installed version {version}" if version else "")
                        + f", reopening it from {frm or '?'}.")
            if origin is None:
                missing.append(f"the installed version that matched ({legacy_gap})")
            return {"cause": "correlation_rescan",
                    "actor": _actor("system", "veyrs-correlation", component="correlation engine"),
                    "sentence": sentence, "ids": ids, "missing": missing}
        run_id = d.get("import_run_id")
        sentence = f"Seen again by {scanner or 'a scanner'}"
        if run_id:
            run = look.run(run_id)
            sentence += f" in {_run_phrase(look, run_id)}"
            test = look.test(run.test_id) if run is not None and run.test_id else None
            if test is not None:
                ids["scan_test_id"] = str(test.id)
                sentence += f", scan test '{test.title}'"
        else:
            missing.append(f"which import run saw it ({legacy_gap})")
        sentence += f"; it had been {frm or 'closed'}."
        return {"cause": "rescan_seen_again",
                "actor": _actor("system", scanner or "importer", component="importer"),
                "sentence": sentence, "ids": ids, "missing": missing}

    # -- risk acceptance -----------------------------------------------------
    if event.event in ("risk_accepted", "risk_acceptance_ended"):
        name = d.get("name") or _short(d.get("acceptance_id"))
        ids["risk_acceptance_id"] = d.get("acceptance_id")
        if event.event == "risk_accepted":
            approver = look.user(d.get("approved_by")) or _short(d.get("approved_by"))
            sentence = f"Risk acceptance '{name}' was approved by {approver}"
            if d.get("expires_on"):
                sentence += f"; it expires on {d['expires_on']}"
            return {"cause": "acceptance_approved",
                    "actor": _actor("user", approver, id=d.get("approved_by")),
                    "sentence": sentence + ".", "ids": ids, "missing": missing}
        if d.get("reason") == "revoked":
            who = look.user(event.actor_id) or event.actor_label
            return {"cause": "acceptance_revoked", "actor": _user_actor(event) | {"label": who},
                    "sentence": f"Risk acceptance '{name}' was revoked by {who}; the finding "
                                f"went back to {to or '?'}.",
                    "ids": ids, "missing": missing}
        sentence = (f"Risk acceptance '{name}' expired"
                    + (f" on {d['expires_on']}" if d.get("expires_on") else "")
                    + f"; the expiry job put the finding back to {to or '?'}.")
        if origin is None:
            missing.append(f"the expiry date ({legacy_gap})")
        return {"cause": "acceptance_expired",
                "actor": _actor("system", "risk acceptance expiry", component="expire-acceptances job"),
                "sentence": sentence, "ids": ids, "missing": missing}

    # -- correlation engine closed it -----------------------------------------
    if event.event == "no_longer_applicable":
        ids.update({"cve": d.get("cve"), "asset_product_id": d.get("asset_product_id")})
        changes = _inventory_between(look.events(finding.id), previous_at, event.created_at)
        actor = _actor("system", "veyrs-correlation", component="correlation engine")
        if changes:
            ids["inventory_changes"] = [_inventory_ref(c) for c in changes]
            return {"cause": "inventory_version_changed", "actor": actor,
                    "sentence": f"The correlation engine closed it for {d.get('cve') or 'the CVE'} "
                                f"after the inventory moved: {_inventory_phrase(changes[-1])}; "
                                "that version is outside the vulnerable range.",
                    "ids": ids, "missing": missing}
        if origin is None:
            missing.append(f"which CVE and installed version ({legacy_gap})")
            sentence = "The correlation engine closed it as no longer applicable."
        else:
            sentence = (f"The correlation engine closed it for {d.get('cve')}: installed version "
                        f"{d.get('installed_version') or 'unknown'} is outside the vulnerable "
                        "range. No installed-version change was recorded on this finding "
                        "before it.")
        return {"cause": "correlation_rescan", "actor": actor,
                "sentence": sentence, "ids": ids, "missing": missing}

    # -- state_changed: operator, ticket, workflow, assignment ----------------
    # A legacy ticket resolution carries only the free-text note "ticket X
    # resolved". It is quoted in the unknown sentence below, never parsed.
    if origin == "ticket":
        ext = d.get("external_source") if isinstance(d.get("external_source"), dict) else None
        ids.update({"ticket_id": d.get("ticket_id"), "ticket_reference": d.get("ticket_reference")})
        if ext:
            system = (ext.get("system") or "external system").replace("_", " ")
            ids.update({"connector": ext.get("connector"), "remote_id": ext.get("remote_id"),
                        "remote_key": ext.get("remote_key"), "remote_url": ext.get("remote_url")})
            sentence = (f"{system.title()} (connector '{ext.get('connector')}') reported issue "
                        f"{ext.get('remote_key') or ext.get('remote_id')} as "
                        f"'{ext.get('remote_status')}'"
                        + (f" (changed by {ext['remote_actor']})" if ext.get("remote_actor") else "")
                        + f"; the connector's inbound mapping turned that into ticket "
                        f"{d.get('ticket_reference')} -> {d.get('ticket_to')}, which moved the "
                        f"finding from {arrow}.")
            cause = "ticket_closed_external" if to in FIXED_STATES else "ticket_reopened_external"
            return {"cause": cause,
                    "actor": _actor("external", ext.get("remote_actor") or system,
                                    system=ext.get("system"), connector=ext.get("connector")),
                    "sentence": sentence, "ids": ids, "missing": missing}
        who = event.actor_label
        return {"cause": "ticket_resolved", "actor": _user_actor(event) if event.actor_id
                else _actor("system", who),
                "sentence": f"Ticket {d.get('ticket_reference')} was resolved by {who} in VEYRS, "
                            f"which moved the finding from {arrow}.",
                "ids": ids, "missing": missing}

    if origin == "workflow" or (origin is None and d.get("note") == "workflow"
                                and event.actor_id is None):
        ids.update({"workflow_id": d.get("workflow_id"), "workflow_run_id": d.get("workflow_run_id")})
        if d.get("workflow_id"):
            sentence = (f"Workflow '{d.get('workflow_name')}' ({d.get('workflow_slug')}, run "
                        f"{_short(d.get('workflow_run_id'))}) fired on trigger "
                        f"'{d.get('trigger')}' and moved it from {arrow}.")
        else:
            sentence = f"A workflow moved it from {arrow}."
            missing.append(f"which workflow and run ({legacy_gap})")
        return {"cause": "workflow_rule",
                "actor": _actor("system", d.get("workflow_name") or event.actor_label,
                                component="workflow engine"),
                "sentence": sentence, "ids": ids, "missing": missing}

    if origin == "assignment":
        return {"cause": "assignment_rule",
                "actor": _actor("system", event.actor_label, component="assignment"),
                "sentence": f"Automatic assignment ({d.get('reason') or 'no rule named'}) walked "
                            f"it from {arrow}.",
                "ids": ids, "missing": missing}

    if origin == "operator" or (origin is None and event.actor_id is not None):
        who = event.actor_label
        note = _text(d.get("note")) or _text(event.note)
        if frm == "verification" and to == "verified":
            cause, sentence = "verification_passed", f"{who} recorded the verification as passed."
        elif frm == "verification" and to == "in_progress":
            cause, sentence = ("verification_failed",
                               f"{who} recorded a failed verification and sent it back to in_progress.")
        else:
            via = {"api_bulk": " in a bulk change", "accept_risk": " by accepting the risk"}.get(
                d.get("via"), "")
            cause, sentence = "operator", f"{who} moved it from {arrow}{via}."
        if note:
            sentence += f" Note: \"{note}\"."
        if d.get("accepted_until"):
            sentence += f" Accepted until {d['accepted_until']}."
        if origin is None:
            missing.append(f"the route the change came through ({legacy_gap})")
        return {"cause": cause, "actor": _user_actor(event),
                "sentence": sentence, "ids": ids, "missing": missing}

    # -- nothing recorded that says why ----------------------------------------
    note = _text(d.get("note")) or _text(event.note)
    if origin is not None:
        sentence = (f"Recorded as {arrow} with an origin this version does not know "
                    f"('{origin}').")
        missing.append("a recognised origin")
    else:
        sentence = (f"Recorded as {arrow} by '{event.actor_label}'"
                    + (f" with the note \"{note}\"" if note else "")
                    + ", but the event does not say what triggered it: no event detail "
                    f"was recorded before {DETAIL_SINCE}.")
        missing.append(f"what triggered the change ({legacy_gap})")
    return {"cause": "unknown", "actor": _actor("system", event.actor_label),
            "sentence": sentence, "ids": ids, "missing": missing}


def _regression(
    look: _Lookups, finding: Finding, event: FindingEvent, prior_close: dict | None,
) -> dict[str, Any]:
    """For a reopen: seen again by what, how long after closure, and inventory drift."""
    d = event.details or {}
    closed_at = (
        _parse_ts(prior_close["at"]) if prior_close is not None else None
    ) or _parse_ts(d.get("previously_closed_at")) or _parse_ts(d.get("previously_remediated_at"))
    out: dict[str, Any] = {
        "closed_at": closed_at.isoformat() if closed_at else None,
        "closed_by_cause": prior_close["cause"] if prior_close is not None else None,
        "reopened_at": event.created_at.isoformat(),
        "seconds_after_closure": int((event.created_at - closed_at).total_seconds())
        if closed_at else None,
        "seen_again_by": None,
        "inventory_changes": [],
        "inventory_checked": False,
    }
    if event.event == "reopened":
        run = look.run(d.get("import_run_id"))
        out["seen_again_by"] = {
            "scanner": d.get("scanner"), "import_run_id": d.get("import_run_id"),
            "filename": run.filename if run is not None else None,
            "scan_test_id": str(run.test_id) if run is not None and run.test_id else None,
        }
    linked = finding.asset_product_id or _uuid(d.get("asset_product_id"))
    changes = _inventory_between(look.events(finding.id), closed_at, event.created_at)
    out["inventory_changes"] = [_inventory_ref(c) for c in changes]

    parts: list[str] = []
    if event.event == "reopened":
        parts.append(f"Seen again by {d.get('scanner') or 'a scanner'}")
    else:
        parts.append("Reopened")
    if closed_at is not None:
        parts[0] += f" {_duration(event.created_at - closed_at)} after it was closed"
        if prior_close is not None:
            parts[0] += f" ({CAUSES.get(prior_close['cause'], prior_close['cause']).lower()})"
    else:
        parts[0] += "; when it was closed is not recorded"
    if changes:
        out["inventory_checked"] = True
        parts.append("Between closure and reopen the inventory moved: "
                     + "; ".join(_inventory_phrase(c) for c in changes))
    elif linked is not None:
        out["inventory_checked"] = True
        installation = look.session.get(AssetProduct, linked)
        product = look.session.get(Product, installation.product_id) if installation else None
        name = product.name if product is not None else "the linked installed product"
        parts.append(f"No installed-version change on {name} was recorded between closure "
                     "and reopen")
    else:
        parts.append("This finding is not linked to an installed product, so inventory "
                     "drift cannot be checked")
    out["sentence"] = ". ".join(parts) + "."
    return out


def explain(session: Session, finding: Finding) -> dict[str, Any]:
    """Every state transition of one finding, oldest first, with its cause."""
    look = _Lookups(session)
    events = look.events(finding.id)
    transitions: list[dict[str, Any]] = []
    previous_at: dt.datetime | None = None
    last_close: dict[str, Any] | None = None
    for event in events:
        if event.event not in TRANSITION_EVENTS:
            continue
        frm, to = states_of(event)
        kind = kind_of(event.event, frm, to)
        verdict = _classify(look, finding, event, frm, to, previous_at)
        item = {
            "at": event.created_at.isoformat(), "event": event.event,
            "event_id": str(event.id), "from": frm, "to": to, "kind": kind,
            "cause": verdict["cause"], "cause_label": CAUSES[verdict["cause"]],
            "actor": verdict["actor"],
            "evidence": {"sentence": verdict["sentence"], "ids": verdict["ids"]},
            "missing": verdict["missing"],
        }
        if kind == "reopened":
            item["regression"] = _regression(look, finding, event, last_close)
        if kind == "closed":
            last_close = item
        transitions.append(item)
        previous_at = event.created_at
    last_closed = next((t for t in reversed(transitions) if t["kind"] == "closed"), None)
    last_reopened = next((t for t in reversed(transitions) if t["kind"] == "reopened"), None)
    return {
        "finding_id": str(finding.id), "state": finding.state, "title": finding.title,
        "detail_recorded_since": DETAIL_SINCE,
        "transitions": transitions,
        "last_closed": last_closed, "last_reopened": last_reopened,
    }


def recent_changes(
    session: Session,
    organization_id: uuid.UUID,
    scope,
    *,
    since: dt.datetime,
    kinds: frozenset[str] = frozenset({"closed", "reopened"}),
    cause: str | None = None,
    page: int = 1,
    size: int = 50,
) -> dict[str, Any]:
    """Recent closes/reopens across the visible estate, newest first.

    The statement is narrowed by tenant AND team scope before anything is
    read; the cause filter is applied after classification (a cause is a
    reading of recorded facts, not a column), over at most CHANGES_SCAN_CAP
    events -- `truncated` says when that bound was hit.
    """
    from ..security import scope as team_scope

    stmt = (
        select(FindingEvent, Finding)
        .join(Finding, Finding.id == FindingEvent.finding_id)
        .where(
            FindingEvent.organization_id == organization_id,
            Finding.organization_id == organization_id,
            FindingEvent.event.in_(tuple(TRANSITION_EVENTS)),
            FindingEvent.created_at >= since,
        )
    )
    stmt = team_scope.findings(stmt, scope)
    rows = session.execute(
        stmt.order_by(FindingEvent.created_at.desc()).limit(CHANGES_SCAN_CAP + 1)
    ).all()
    truncated = len(rows) > CHANGES_SCAN_CAP
    rows = rows[:CHANGES_SCAN_CAP]

    look = _Lookups(session)
    matched: list[tuple[FindingEvent, Finding, str, str | None, str | None, dict]] = []
    for event, finding in rows:
        frm, to = states_of(event)
        kind = kind_of(event.event, frm, to)
        if kind not in kinds:
            continue
        previous_at = None
        if event.event == "no_longer_applicable":
            earlier = [e for e in look.events(finding.id)
                       if e.event in TRANSITION_EVENTS and e.created_at < event.created_at]
            previous_at = earlier[-1].created_at if earlier else None
        verdict = _classify(look, finding, event, frm, to, previous_at)
        if cause and verdict["cause"] != cause:
            continue
        matched.append((event, finding, kind, frm, to, verdict))

    total = len(matched)
    window = matched[(page - 1) * size: page * size]
    asset_ids = {f.asset_id for _, f, *_ in window}
    names = dict(session.execute(
        select(Asset.id, Asset.name).where(Asset.id.in_(asset_ids or {uuid.uuid4()}))
    ).all())
    items = [{
        "at": event.created_at.isoformat(), "event_id": str(event.id),
        "finding_id": str(finding.id), "finding_title": finding.title,
        "finding_state": finding.state,
        "asset_id": str(finding.asset_id), "asset_name": names.get(finding.asset_id),
        "from": frm, "to": to, "kind": kind,
        "cause": verdict["cause"], "cause_label": CAUSES[verdict["cause"]],
        "actor": verdict["actor"], "evidence": verdict["sentence"],
        "missing": verdict["missing"],
    } for event, finding, kind, frm, to, verdict in window]
    pages = (total + size - 1) // size if size else 0
    return {"items": items, "total": total, "page": page, "size": size, "pages": pages,
            "since": since.isoformat(), "truncated": truncated,
            "causes": CAUSES}


__all__ = [
    "CAUSES", "DETAIL_SINCE", "FIXED_STATES", "TRANSITION_EVENTS", "INVENTORY_EVENT",
    "note_inventory_change", "states_of", "kind_of", "explain", "recent_changes",
]
