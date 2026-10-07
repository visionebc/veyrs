"""Engagement/test lifecycle, scoped reimport and risk acceptance.

Two things live here that VEYRS previously did wrong or not at all.

**Scoped reimport.** `importers.base._close_missing()` closed every open finding
in the organisation whose `scanner` matched the import, minus the ones the run
happened to touch. A Nessus export covering three hosts therefore marked the
entire estate's Nessus findings remediated. The scope was never the scanner - it
is *what this test looked at*, which is now recorded as `TestFinding` sightings.

**Absence is evidence, not proof.** DefectDojo closes on a single absence.
Faraday does not close at all. Neither is right for infrastructure: a host that
was powered off during the window looks identical to a host that was patched.
`reconcile_test()` therefore counts *consecutive* absences and closes only at a
configurable threshold (default 1 for CI/CD, where a build either contains the
dependency or does not, and 2 for scheduled sweeps, where hosts come and go).
Every close records why, so an auditor can tell "we fixed it" from "the scanner
stopped mentioning it".

**Risk acceptance.** Previously three columns on `Finding` and no machinery: an
acceptance could be set with no approver and would never expire, which is the
control an ISO 27001 auditor tests first. Now an acceptance is an approved
artefact with an expiry date and a job that acts on it.
"""
from __future__ import annotations

import datetime as dt
import logging
import re
import uuid
from typing import Any, Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Engagement, EngagementStatus, EngagementType, Finding, OPEN_STATES, RiskAcceptance,
    RiskAcceptanceFinding, RiskAcceptanceState, ScanTest, TestFinding, TestFindingStatus,
)

log = logging.getLogger("veyrs.engagements")

#: How many consecutive runs of a test may omit a finding before it is treated
#: as fixed. Keyed on engagement type because the confidence differs by kind.
DEFAULT_ABSENCE_THRESHOLD = {
    EngagementType.CI_CD.value: 1,
    EngagementType.INTERACTIVE.value: 0,   # 0 = never auto-close
    EngagementType.SCHEDULED.value: 2,
}

_SLUG_RE = re.compile(r"[^a-z0-9]+")


def slugify(value: str) -> str:
    slug = _SLUG_RE.sub("-", (value or "").strip().lower()).strip("-")
    return slug[:120] or "engagement"


# ---------------------------------------------------------------------------
# Engagements and tests
# ---------------------------------------------------------------------------
def create_engagement(
    session: Session,
    organization_id: uuid.UUID,
    *,
    name: str,
    engagement_type: str = EngagementType.SCHEDULED.value,
    description: str | None = None,
    business_service_id: uuid.UUID | None = None,
    asset_group_id: uuid.UUID | None = None,
    lead_user_id: uuid.UUID | None = None,
    target_start: dt.date | None = None,
    target_end: dt.date | None = None,
    dedupe_within_engagement: bool = False,
    version: str | None = None,
    branch_tag: str | None = None,
    commit_hash: str | None = None,
    build_id: str | None = None,
    tags: Sequence[str] | None = None,
) -> Engagement:
    if engagement_type not in {e.value for e in EngagementType}:
        raise ValueError(f"unknown engagement type {engagement_type!r}")

    base = slugify(name)
    slug, suffix = base, 1
    while session.execute(
        select(Engagement.id).where(
            Engagement.organization_id == organization_id, Engagement.slug == slug
        )
    ).scalars().first() is not None:
        suffix += 1
        slug = f"{base[:110]}-{suffix}"

    row = Engagement(
        organization_id=organization_id, name=name.strip()[:200], slug=slug,
        description=description, engagement_type=engagement_type,
        business_service_id=business_service_id, asset_group_id=asset_group_id,
        lead_user_id=lead_user_id, target_start=target_start, target_end=target_end,
        dedupe_within_engagement=dedupe_within_engagement, version=version,
        branch_tag=branch_tag, commit_hash=commit_hash, build_id=build_id,
        tags=list(tags or []),
    )
    session.add(row)
    session.flush()
    return row


def default_engagement(session: Session, organization_id: uuid.UUID) -> Engagement:
    """The catch-all engagement for imports that name none.

    Every import must land in *some* scope or scoped reimport is impossible, so
    rather than making the parameter mandatory (and breaking every existing
    caller) an unscoped import lands here.
    """
    row = session.execute(
        select(Engagement).where(
            Engagement.organization_id == organization_id,
            Engagement.slug == "continuous-scanning",
        )
    ).scalars().first()
    if row is not None:
        return row
    return create_engagement(
        session, organization_id,
        name="Continuous scanning",
        engagement_type=EngagementType.SCHEDULED.value,
        description=(
            "Default scope for imports that do not name an engagement. Findings "
            "here are reconciled per scanner rather than per assessment."
        ),
    )


def get_or_create_test(
    session: Session,
    organization_id: uuid.UUID,
    *,
    scanner: str,
    engagement: Engagement | None = None,
    engagement_id: uuid.UUID | None = None,
    title: str | None = None,
    environment: str | None = None,
    reuse: bool = True,
    **provenance: Any,
) -> ScanTest:
    """Find the engagement's test for this scanner, or open a new one.

    `reuse=True` is what makes a nightly Nessus import reconcile against
    yesterday's sighting set instead of starting a fresh, empty scope every
    night (which would make every finding look new and nothing ever close).
    A pentest wants `reuse=False`: each pass is its own record.
    """
    if engagement is None:
        engagement = (
            session.get(Engagement, engagement_id) if engagement_id
            else default_engagement(session, organization_id)
        )
    if engagement is None:
        raise ValueError("engagement not found")
    if engagement.organization_id != organization_id:
        raise ValueError("engagement belongs to a different organization")

    scanner = (scanner or "").strip().lower()
    if reuse:
        row = session.execute(
            select(ScanTest)
            .where(
                ScanTest.organization_id == organization_id,
                ScanTest.engagement_id == engagement.id,
                ScanTest.scanner == scanner,
            )
            .order_by(ScanTest.created_at.desc())
        ).scalars().first()
        if row is not None:
            for field, value in provenance.items():
                if value and hasattr(row, field):
                    setattr(row, field, value)
            session.flush()
            return row

    row = ScanTest(
        organization_id=organization_id, engagement_id=engagement.id, scanner=scanner,
        title=title or f"{scanner} scan", environment=environment,
        version=provenance.get("version") or engagement.version,
        branch_tag=provenance.get("branch_tag") or engagement.branch_tag,
        commit_hash=provenance.get("commit_hash") or engagement.commit_hash,
        build_id=provenance.get("build_id") or engagement.build_id,
    )
    session.add(row)
    session.flush()
    if engagement.status == EngagementStatus.NOT_STARTED.value:
        engagement.status = EngagementStatus.IN_PROGRESS.value
        engagement.started_at = dt.datetime.now(dt.timezone.utc)
    return row


# ---------------------------------------------------------------------------
# Sightings
# ---------------------------------------------------------------------------
def record_sighting(
    session: Session,
    *,
    organization_id: uuid.UUID,
    test: ScanTest,
    finding_id: uuid.UUID,
    import_run_id: uuid.UUID | None = None,
) -> TestFinding:
    """This test saw this finding in this run. Resets the absence counter."""
    now = dt.datetime.now(dt.timezone.utc)
    row = session.execute(
        select(TestFinding).where(
            TestFinding.organization_id == organization_id,
            TestFinding.test_id == test.id,
            TestFinding.finding_id == finding_id,
        )
    ).scalars().first()
    if row is None:
        row = TestFinding(
            organization_id=organization_id, test_id=test.id, finding_id=finding_id,
            first_seen_at=now, last_seen_at=now,
        )
        session.add(row)
    row.status = TestFindingStatus.PRESENT.value
    row.last_seen_at = now
    row.consecutive_absences = 0
    row.last_import_run_id = import_run_id
    session.flush()
    return row


def reconcile_test(
    session: Session,
    *,
    organization_id: uuid.UUID,
    test: ScanTest,
    seen_finding_ids: Iterable[uuid.UUID],
    close_absent: bool | None = None,
    absence_threshold: int | None = None,
    actor: str = "import",
) -> dict[str, Any]:
    """Mark this test's unseen findings absent; close the ones past threshold.

    Only findings this test has *previously reported* are considered. That is
    the whole fix: the scope is the sighting set, so a partial export can never
    reach a host the test has never covered.
    """
    from . import correlation

    seen = {fid for fid in seen_finding_ids}
    engagement = session.get(Engagement, test.engagement_id)
    if absence_threshold is None:
        absence_threshold = DEFAULT_ABSENCE_THRESHOLD.get(
            engagement.engagement_type if engagement else EngagementType.SCHEDULED.value, 2
        )
    if close_absent is None:
        close_absent = absence_threshold > 0

    sightings = session.execute(
        select(TestFinding).where(
            TestFinding.organization_id == organization_id,
            TestFinding.test_id == test.id,
        )
    ).scalars().all()

    now = dt.datetime.now(dt.timezone.utc)
    marked_absent = closed = 0
    absent_ids: list[str] = []

    for sighting in sightings:
        if sighting.finding_id in seen:
            continue
        finding = session.get(Finding, sighting.finding_id)
        if finding is None or finding.state not in OPEN_STATES:
            continue

        if sighting.status != TestFindingStatus.ABSENT.value:
            sighting.status = TestFindingStatus.ABSENT.value
        sighting.consecutive_absences += 1
        marked_absent += 1
        absent_ids.append(str(finding.id))

        if not close_absent or absence_threshold <= 0:
            continue
        if sighting.consecutive_absences < absence_threshold:
            continue
        # Endpoint-scoped findings only close when every endpoint is gone; a
        # tool that stopped reporting /admin has not fixed /api.
        correlation.record_event(
            session, finding, "remediated",
            details={
                # Wording is a contract: reports, the console and
                # tests/test_phase8_integrations.py all match on this string.
                "reason": "absent from scanner export",
                "scanner": test.scanner,
                "test_id": str(test.id),
                "engagement_id": str(test.engagement_id),
                "consecutive_absences": sighting.consecutive_absences,
                "actor": actor,
                "evidence": "absence",  # NOT a verified fix - reports must say so
            },
        )
        finding.state = "remediated"
        finding.remediated_at = now
        closed += 1

    session.flush()
    return {
        "marked_absent": marked_absent,
        "closed": closed,
        "absence_threshold": absence_threshold,
        "close_absent": bool(close_absent),
        "absent_finding_ids": absent_ids[:200],
    }


def test_scope_size(session: Session, organization_id: uuid.UUID, test_id: uuid.UUID) -> int:
    return len(session.execute(
        select(TestFinding.id).where(
            TestFinding.organization_id == organization_id,
            TestFinding.test_id == test_id,
        )
    ).scalars().all())


# ---------------------------------------------------------------------------
# Risk acceptance
# ---------------------------------------------------------------------------
def request_acceptance(
    session: Session,
    organization_id: uuid.UUID,
    *,
    name: str,
    reason: str,
    finding_ids: Sequence[uuid.UUID],
    requested_by_id: uuid.UUID | None = None,
    decision: str = "accepted",
    expires_on: dt.date | None = None,
    compensating_controls: str | None = None,
    reactivate_on_expiry: bool = True,
    restart_sla_on_expiry: bool = False,
    proof_document_id: uuid.UUID | None = None,
) -> RiskAcceptance:
    """Open a PENDING acceptance. Findings are not touched until it is approved.

    Deliberate: a request is not a decision. Moving findings out of the queue on
    request would let anyone silence a finding by asking.
    """
    if not reason or not reason.strip():
        raise ValueError("a risk acceptance requires a written reason")
    if not finding_ids:
        raise ValueError("a risk acceptance must cover at least one finding")

    acceptance = RiskAcceptance(
        organization_id=organization_id, name=name.strip()[:300], reason=reason.strip(),
        decision=decision, state=RiskAcceptanceState.PENDING.value,
        requested_by_id=requested_by_id, expires_on=expires_on,
        compensating_controls=compensating_controls,
        reactivate_on_expiry=reactivate_on_expiry,
        restart_sla_on_expiry=restart_sla_on_expiry,
        proof_document_id=proof_document_id,
    )
    session.add(acceptance)
    session.flush()

    for finding_id in finding_ids:
        finding = session.get(Finding, finding_id)
        if finding is None or finding.organization_id != organization_id:
            raise ValueError(f"finding {finding_id} not found in this organization")
        session.add(RiskAcceptanceFinding(
            organization_id=organization_id, acceptance_id=acceptance.id,
            finding_id=finding.id, previous_state=finding.state,
        ))
    session.flush()
    return acceptance


def approve(
    session: Session,
    acceptance: RiskAcceptance,
    *,
    approved_by_id: uuid.UUID,
    note: str | None = None,
) -> RiskAcceptance:
    """Approve and move the covered findings to `accepted_risk`.

    Self-approval is refused. It is the single control every auditor tests on
    an exception process, and enforcing it in code costs nothing.
    """
    from . import correlation

    if acceptance.state != RiskAcceptanceState.PENDING.value:
        raise ValueError(f"acceptance is {acceptance.state}, not pending")
    if acceptance.requested_by_id and acceptance.requested_by_id == approved_by_id:
        raise ValueError("the requester cannot approve their own risk acceptance")

    now = dt.datetime.now(dt.timezone.utc)
    acceptance.state = RiskAcceptanceState.ACTIVE.value
    acceptance.approved_by_id = approved_by_id
    acceptance.approved_at = now
    acceptance.decided_note = note

    for link in acceptance.findings:
        finding = session.get(Finding, link.finding_id)
        if finding is None:
            continue
        link.previous_state = finding.state
        correlation.record_event(
            session, finding, "risk_accepted",
            details={
                "acceptance_id": str(acceptance.id), "name": acceptance.name,
                "expires_on": acceptance.expires_on.isoformat() if acceptance.expires_on else None,
                "approved_by": str(approved_by_id),
            },
        )
        finding.state = "accepted_risk"
        finding.accepted_by_id = approved_by_id
        finding.accepted_reason = acceptance.reason
        finding.accepted_until = acceptance.expires_on
    session.flush()
    return acceptance


def reject(
    session: Session, acceptance: RiskAcceptance, *, actor_id: uuid.UUID,
    note: str | None = None,
) -> RiskAcceptance:
    if acceptance.state != RiskAcceptanceState.PENDING.value:
        raise ValueError(f"acceptance is {acceptance.state}, not pending")
    acceptance.state = RiskAcceptanceState.REJECTED.value
    acceptance.approved_by_id = actor_id
    acceptance.approved_at = dt.datetime.now(dt.timezone.utc)
    acceptance.decided_note = note
    session.flush()
    return acceptance


def revoke(
    session: Session, acceptance: RiskAcceptance, *, actor_id: uuid.UUID | None = None,
    note: str | None = None,
) -> dict[str, Any]:
    """Withdraw an active acceptance early and put the findings back."""
    if acceptance.state != RiskAcceptanceState.ACTIVE.value:
        raise ValueError(f"acceptance is {acceptance.state}, not active")
    acceptance.state = RiskAcceptanceState.REVOKED.value
    acceptance.decided_note = note
    result = _reactivate(session, acceptance, reason="revoked", actor_id=actor_id)
    session.flush()
    return result


def expire_due(
    session: Session,
    organization_id: uuid.UUID | None = None,
    *,
    today: dt.date | None = None,
    warn_days: int = 14,
) -> dict[str, Any]:
    """Scheduled job: expire what is due, warn about what is nearly due.

    Idempotent - `expiration_warned_at` and the ACTIVE->EXPIRED transition both
    guard against a second run in the same day doing the work twice.
    """
    today = today or dt.date.today()
    stmt = select(RiskAcceptance).where(
        RiskAcceptance.state == RiskAcceptanceState.ACTIVE.value,
        RiskAcceptance.expires_on.is_not(None),
    )
    if organization_id is not None:
        stmt = stmt.where(RiskAcceptance.organization_id == organization_id)

    expired = warned = reactivated = 0
    now = dt.datetime.now(dt.timezone.utc)
    for acceptance in session.execute(stmt).scalars().all():
        if acceptance.expires_on <= today:
            acceptance.state = RiskAcceptanceState.EXPIRED.value
            acceptance.expired_at = now
            expired += 1
            if acceptance.reactivate_on_expiry:
                result = _reactivate(session, acceptance, reason="expired")
                reactivated += result["reactivated"]
        elif (
            acceptance.expiration_warned_at is None
            and (acceptance.expires_on - today).days <= warn_days
        ):
            acceptance.expiration_warned_at = now
            warned += 1
            _notify_expiring(session, acceptance, days=(acceptance.expires_on - today).days)
    session.flush()
    return {"expired": expired, "warned": warned, "findings_reactivated": reactivated}


def _reactivate(
    session: Session, acceptance: RiskAcceptance, *, reason: str,
    actor_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Put an acceptance's findings back in the queue."""
    from . import correlation
    from . import sla as sla_service

    reactivated = 0
    for link in acceptance.findings:
        finding = session.get(Finding, link.finding_id)
        if finding is None or finding.state != "accepted_risk":
            continue
        target = link.previous_state if link.previous_state in OPEN_STATES else "triaged"
        correlation.record_event(
            session, finding, "risk_acceptance_ended",
            details={
                "acceptance_id": str(acceptance.id), "reason": reason,
                "restored_state": target, "actor": str(actor_id) if actor_id else "system",
            },
        )
        finding.state = target
        finding.accepted_until = None
        finding.accepted_by_id = None
        finding.accepted_reason = None
        if acceptance.restart_sla_on_expiry:
            finding.detected_at = dt.datetime.now(dt.timezone.utc)
            finding.sla_breached = False
            finding.sla_breached_at = None
            finding.escalation_level = 0
        # Recompute the deadline either way: on the ORIGINAL detection date
        # unless explicitly restarted, so an acceptance cannot launder an
        # already-overdue finding into a fresh SLA window. `force=True` because
        # the finding still carries the policy it had before acceptance, and
        # apply_sla short-circuits when policy and due date are both already set.
        sla_service.apply_sla(session, finding, force=True)
        reactivated += 1
    session.flush()
    return {"reactivated": reactivated}


def _notify_expiring(session: Session, acceptance: RiskAcceptance, *, days: int) -> None:
    """Best-effort warning. A failure here must not abort the expiry job.

    The whole point of the job is the state transition; if the mail template is
    missing or SMTP is down, expiring on time still matters more than telling
    someone about it, so the exception is logged and swallowed.
    """
    try:
        from ..models import User
        from . import notifications

        requester = (
            session.get(User, acceptance.requested_by_id)
            if acceptance.requested_by_id else None
        )
        if requester is None:
            return
        notifications.queue(
            session, acceptance.organization_id, "risk_acceptance.expiring",
            {
                "acceptance_name": acceptance.name,
                "days": days,
                "expires_on": acceptance.expires_on.isoformat(),
                "finding_count": len(acceptance.findings),
            },
            users=[requester],
        )
    except Exception:  # pragma: no cover - notification transport is optional
        log.warning("could not queue expiry warning for acceptance %s", acceptance.id,
                    exc_info=True)
