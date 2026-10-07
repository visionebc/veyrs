"""Phase 4: ticketing, ITIL lifecycle, workflow engine, notifications.

The claims under test are the ones that make VEYRS an operations tool rather
than a report generator: a KEV on an internet-facing box automatically produces
an owned, deadlined ticket and tells somebody, and a change cannot be deployed
without an approval that is recorded.
"""
from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    Asset, AssetProduct, Cve, Finding, Notification, Team, TeamMember, Ticket,
    TicketEvent, User, WorkflowDefinition, WorkflowRun,
)
from veyrs.security.auth import hash_password
from veyrs.services import correlation, intelligence, notifications as notify
from veyrs.services import risk as risk_service
from veyrs.services import sla as sla_service, ticketing
from veyrs.services import workflow as workflow_service

from test_phase3_intel import NVD_ITEM  # reuse the FortiWeb advisory fixture


@pytest.fixture()
def shop(org_a):
    """A tenant with inventory, policies, workflows, a team and an owner."""
    org_id, slug, _ = org_a
    with SessionLocal() as session:
        intelligence.ingest_nvd(session, [NVD_ITEM])
        session.commit()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        product = intelligence.upsert_product(session, "fortinet", "fortiweb")

        team = Team(organization_id=org_id, name="Network Security", slug="netsec")
        owner = User(organization_id=org_id, email=f"owner@{slug}.test",
                     full_name="Asset Owner", password_hash=hash_password("x" * 16),
                     locale="es")
        session.add_all([team, owner])
        session.flush()
        session.add(TeamMember(organization_id=org_id, team_id=team.id, user_id=owner.id))

        asset = Asset(
            organization_id=org_id, name="fw-edge-01", asset_type="firewall",
            criticality="critical", exposure="internet", environment="production",
            owner_id=owner.id, team_id=team.id,
        )
        session.add(asset)
        session.flush()
        session.add(AssetProduct(organization_id=org_id, asset_id=asset.id,
                                 product_id=product.id, version="7.2.4"))

        risk_service.seed_profiles(session, org_id)
        sla_service.seed_policies(session, org_id)
        workflow_service.seed_workflows(session, org_id)

        cve = session.get(Cve, "CVE-2026-0001")
        cve.kev = True
        session.commit()
        return {"org_id": org_id, "team_id": team.id, "owner_id": owner.id,
                "asset_id": asset.id}


def _correlate(org_id):
    with SessionLocal() as session:
        set_tenant(session, org_id)
        cve = session.get(Cve, "CVE-2026-0001")
        correlation.correlate_cve(session, org_id, cve)
        session.commit()


# --------------------------------------------------------------------------
# Reference sequence
# --------------------------------------------------------------------------


def test_reference_sequence_is_per_tenant(org_a, org_b):
    with SessionLocal() as session:
        set_tenant(session, org_a[0])
        first = ticketing.next_reference(session, org_a[0], "incident")
        second = ticketing.next_reference(session, org_a[0], "incident")
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_b[0])
        other = ticketing.next_reference(session, org_b[0], "incident")
        session.commit()
    assert first == "VEYRS-INC-000001"
    assert second == "VEYRS-INC-000002"
    # Tenant B starts at 1 too: the counter must not leak A's volume.
    assert other == "VEYRS-INC-000001"


def test_reference_prefix_per_type(org_a):
    with SessionLocal() as session:
        set_tenant(session, org_a[0])
        assert ticketing.next_reference(session, org_a[0], "change").startswith("VEYRS-CHG-")
        assert ticketing.next_reference(session, org_a[0], "remediation").startswith("VEYRS-REM-")
        session.commit()


# --------------------------------------------------------------------------
# Workflow-driven ticket creation
# --------------------------------------------------------------------------


def test_kev_internet_finding_auto_creates_ticket_and_notifies(shop):
    org_id = shop["org_id"]
    _correlate(org_id)

    with SessionLocal() as session:
        set_tenant(session, org_id)
        tickets = session.execute(select(Ticket)).scalars().all()
        assert len(tickets) == 1
        ticket = tickets[0]
        assert ticket.ticket_type == "remediation"
        assert ticket.reference.startswith("VEYRS-REM-")
        assert ticket.priority in ("critical", "high")
        # The ticket inherits the finding's authoritative deadline.
        finding = session.execute(select(Finding)).scalars().one()
        assert ticket.due_at == finding.sla_due_at
        assert ticket.finding_id == finding.id

        queued = session.execute(select(Notification)).scalars().all()
        assert queued, "a KEV on an internet-facing asset must notify somebody"
        assert {n.recipient_user_id for n in queued} == {shop["owner_id"]}


def test_workflow_run_is_recorded_with_step_results(shop):
    org_id = shop["org_id"]
    _correlate(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        runs = session.execute(select(WorkflowRun)).scalars().all()
        assert runs
        kev_run = next(r for r in runs if r.trigger == "finding.created")
        assert kev_run.status == "succeeded"
        actions = [s["action"] for s in kev_run.step_results]
        assert "create_ticket" in actions and "notify" in actions
        assert all(s["status"] in ("ok", "warning") for s in kev_run.step_results)


def test_workflow_tag_asset_step_applied(shop):
    _correlate(shop["org_id"])
    with SessionLocal() as session:
        set_tenant(session, shop["org_id"])
        asset = session.get(Asset, shop["asset_id"])
        assert "kev-exposed" in (asset.tags or [])


def test_correlation_is_idempotent_for_tickets(shop):
    """Re-running correlation must not open a second ticket for one finding."""
    for _ in range(3):
        _correlate(shop["org_id"])
    with SessionLocal() as session:
        set_tenant(session, shop["org_id"])
        assert len(session.execute(select(Ticket)).scalars().all()) == 1


def test_unknown_workflow_action_is_rejected_at_save_time():
    with pytest.raises(workflow_service.WorkflowError):
        workflow_service.validate_steps([{"action": "rm_rf", "config": {}}])


def test_workflow_conditions_gate_execution(shop):
    """A workflow whose conditions do not match must not run."""
    org_id = shop["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        session.add(WorkflowDefinition(
            organization_id=org_id, slug="never", name="Never matches",
            trigger="finding.created", conditions={"exposure": ["isolated"]},
            steps=[{"action": "tag_asset", "config": {"tags": ["should-not-appear"]}}],
        ))
        session.commit()
    _correlate(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        asset = session.get(Asset, shop["asset_id"])
        assert "should-not-appear" not in (asset.tags or [])
        never = session.execute(
            select(WorkflowDefinition).where(WorkflowDefinition.slug == "never")
        ).scalars().one()
        assert never.run_count == 0


# --------------------------------------------------------------------------
# Ticket lifecycle / ITIL
# --------------------------------------------------------------------------


def test_resolving_remediation_ticket_advances_the_finding(shop):
    org_id = shop["org_id"]
    _correlate(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        ticket = session.execute(select(Ticket)).scalars().one()
        ticketing.transition_ticket(session, ticket, "in_progress")
        ticketing.transition_ticket(session, ticket, "resolved",
                                    resolution="Upgraded to 7.2.6")
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.execute(select(Finding)).scalars().one()
        # Remediated, NOT verified: verification is a separate human step.
        assert finding.state == "remediated"
        assert finding.verified_at is None


def test_incident_resolution_does_not_touch_the_finding(shop):
    org_id = shop["org_id"]
    _correlate(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.execute(select(Finding)).scalars().one()
        incident = ticketing.create_ticket(
            session, org_id, ticket_type="incident", title="Suspicious traffic",
            finding_id=finding.id,
        )
        ticketing.transition_ticket(session, incident, "in_progress")
        ticketing.transition_ticket(session, incident, "resolved")
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.execute(select(Finding)).scalars().one()
        assert finding.state != "remediated"


def test_change_ticket_requires_approval_before_scheduling(org_a):
    org_id = org_a[0]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        change = ticketing.create_ticket(
            session, org_id, ticket_type="change", title="Upgrade FortiWeb cluster",
        )
        with pytest.raises(ticketing.TicketError):
            ticketing.transition_ticket(session, change, "scheduled")
        # The legal path is open -> awaiting_approval -> approved -> scheduled
        ticketing.transition_ticket(session, change, "awaiting_approval")
        ticketing.transition_ticket(session, change, "approved", note="CAB 2026-02-10")
        ticketing.transition_ticket(session, change, "scheduled")
        session.commit()
        assert change.state == "scheduled"
        assert change.approved_at is not None


def test_ticket_events_are_appended_not_replaced(shop):
    org_id = shop["org_id"]
    _correlate(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        ticket = session.execute(select(Ticket)).scalars().one()
        ticketing.transition_ticket(session, ticket, "in_progress")
        ticketing.add_comment(session, ticket, "Patch scheduled", author_label="analyst")
        session.commit()
        events = session.execute(
            select(TicketEvent).where(TicketEvent.ticket_id == ticket.id)
            .order_by(TicketEvent.created_at)
        ).scalars().all()
        assert [e.event for e in events] == ["created", "state_changed", "commented"]


def test_ticket_metrics_report_mttr(shop):
    org_id = shop["org_id"]
    _correlate(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        ticket = session.execute(select(Ticket)).scalars().one()
        ticketing.transition_ticket(session, ticket, "in_progress")
        ticketing.transition_ticket(session, ticket, "resolved")
        session.commit()
        stats = ticketing.metrics(session, org_id)
        assert stats["resolved"] == 1
        assert stats["mttr_hours"] is not None and stats["mttr_hours"] >= 0


# --------------------------------------------------------------------------
# SLA sweep -> workflow -> notification
# --------------------------------------------------------------------------


def test_sla_breach_fires_workflow_and_queues_notification(shop):
    org_id = shop["org_id"]
    _correlate(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        before = len(session.execute(select(Notification)).scalars().all())

    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=30)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        stats = sla_service.evaluate_findings(session, org_id, now=later)
        session.commit()
    assert stats["breached"] == 1

    with SessionLocal() as session:
        set_tenant(session, org_id)
        rows = session.execute(select(Notification)).scalars().all()
        assert len(rows) > before
        assert any(n.event == "sla.breached" for n in rows)


# --------------------------------------------------------------------------
# Notifications
# --------------------------------------------------------------------------


def test_template_renders_in_the_recipient_locale(shop):
    """The owner's locale is es; the message must not arrive in English."""
    _correlate(shop["org_id"])
    with SessionLocal() as session:
        set_tenant(session, shop["org_id"])
        rows = session.execute(
            select(Notification).where(Notification.event == "finding.created")
        ).scalars().all()
        assert rows
        assert all(n.locale == "es" for n in rows)
        assert any("hallazgo" in n.body.lower() for n in rows)


def test_missing_placeholder_does_not_break_delivery():
    subject, body = notify.render("finding.created", "en", {"title": "x"})
    assert "x" in subject
    assert "{risk_level}" not in subject  # rendered empty, not left literal


def test_unknown_event_still_produces_a_message():
    subject, body = notify.render("some.new.event", "en", {"a": 1})
    assert "some.new.event" in subject
    assert "\"a\": 1" in body


def test_escalation_notices_cannot_be_muted(shop):
    org_id = shop["org_id"]
    from veyrs.models import NotificationPreference

    with SessionLocal() as session:
        set_tenant(session, org_id)
        session.add(NotificationPreference(
            organization_id=org_id, user_id=shop["owner_id"],
            event="sla.escalated", email=False, in_app=False,
        ))
        session.add(NotificationPreference(
            organization_id=org_id, user_id=shop["owner_id"],
            event="finding.created", email=False, in_app=False,
        ))
        session.commit()

    _correlate(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        owner = session.get(User, shop["owner_id"])
        # Routine traffic honours the opt-out...
        assert notify._muted(session, owner, "finding.created", "email") is True
        # ...escalation does not.
        assert notify._muted(session, owner, "sla.escalated", "email") is False


def test_dispatch_marks_in_app_sent_and_retries_email(shop, monkeypatch):
    org_id = shop["org_id"]
    _correlate(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        stats = notify.dispatch(session, org_id)
        session.commit()
    # in_app always succeeds; email fails because no SMTP host is configured in
    # tests, and a failure must be recorded rather than swallowed.
    assert stats["sent"] >= 1
    with SessionLocal() as session:
        set_tenant(session, org_id)
        rows = session.execute(select(Notification)).scalars().all()
        in_app = [n for n in rows if n.channel == "in_app"]
        email = [n for n in rows if n.channel == "email"]
        assert all(n.status == "sent" for n in in_app)
        assert all(n.status == "pending" and n.error for n in email)
        assert all(n.attempts == 1 for n in email)


def test_email_gives_up_only_after_max_attempts(shop):
    org_id = shop["org_id"]
    _correlate(org_id)
    for _ in range(5):
        with SessionLocal() as session:
            set_tenant(session, org_id)
            notify.dispatch(session, org_id)
            session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        email = session.execute(
            select(Notification).where(Notification.channel == "email")
        ).scalars().all()
        assert all(n.status == "failed" and n.attempts == 5 for n in email)


def test_webhook_signature_is_stable_and_replay_scoped():
    body = b'{"event":"sla.breached"}'
    first = notify.sign_webhook("s3cret", body, "1770000000")
    second = notify.sign_webhook("s3cret", body, "1770000000")
    other_time = notify.sign_webhook("s3cret", body, "1770000060")
    assert first == second
    assert first != other_time  # timestamp is inside the MAC, so replays differ


def test_notifications_are_deduplicated_per_user(shop):
    """A user on the notified team AND the assignee gets one message per channel."""
    org_id = shop["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        owner = session.get(User, shop["owner_id"])
        rows = notify.queue(
            session, org_id, "finding.created", {"title": "t"},
            users=[owner, owner], team_id=shop["team_id"], channels=("in_app",),
        )
        session.commit()
    assert len(rows) == 1
