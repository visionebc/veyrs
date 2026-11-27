"""Audit fix round 0.41.0, workstream `sla`: escalation, notifications, tick, retention.

TD-07  escalation ladder targets resolve to people and are notified
TD-14  escalation is counted from the SLA deadline (+ the one-off recompute)
TD-08  queued notifications are dispatched by the tick, never twice
TD-16/17  lease reaping and risk-acceptance expiry run from the tick
TD-18/29  workflow triggers that fire; transition states derived from FindingState
TD-19  built-in SLA policies / risk profiles seeded, additive
TD-27  retention (`veyrs prune`)
TD-37  tick state in /intel/health
TD-55  digest advisory lock
"""
from __future__ import annotations

import datetime as dt
import os
import shutil
import stat
import subprocess
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from veyrs.config import settings
from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    Asset, AuditLog, Cve, EscalationPolicy, Finding, FindingEvent, FindingState,
    Notification, Organization, RefreshToken, RiskProfile, Role, SlaEvent, SlaPolicy, Team,
    TeamMember, User, UserRole, Vulnerability, WorkflowDefinition, WorkflowRun,
)
from veyrs.services import (
    correlation, digest, notifications, retention, sla as sla_service, tenant_defaults, tick,
    workflow as workflow_service,
)
from veyrs.services import risk as risk_service

REPO = Path(__file__).resolve().parents[1]
NOW = dt.datetime.now(dt.timezone.utc)


def _user(session, org_id, label, *, role=None, role_org=False):
    user = User(organization_id=org_id, email=f"{label}-{uuid.uuid4().hex[:6]}@example.com",
                full_name=label.title(), password_hash="x")
    session.add(user)
    session.flush()
    if role:
        row = session.execute(select(Role).where(
            Role.slug == role,
            (Role.organization_id.is_(None)) | (Role.organization_id == org_id),
        )).scalars().first()
        if row is None:
            row = Role(organization_id=org_id, name=role, slug=role, permissions=[])
            session.add(row)
            session.flush()
        session.add(UserRole(organization_id=org_id, user_id=user.id, role_id=row.id))
        session.flush()
    return user


@pytest.fixture()
def world(org_a):
    """Team (2 members + manager), a security manager, a CISO, one KEV/internet finding."""
    org_id, slug, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        risk_service.seed_profiles(session, org_id)
        sla_service.seed_policies(session, org_id)
        manager = _user(session, org_id, "manager")
        m1, m2 = _user(session, org_id, "m1"), _user(session, org_id, "m2")
        secmgr = _user(session, org_id, "secmgr", role="security-manager")
        ciso = _user(session, org_id, "ciso", role="ciso")
        team = Team(organization_id=org_id, name="Edge", slug=f"edge-{uuid.uuid4().hex[:6]}",
                    manager_id=manager.id)
        session.add(team)
        session.flush()
        for member in (m1, m2):
            session.add(TeamMember(organization_id=org_id, team_id=team.id, user_id=member.id))
        cve_id = f"CVE-2026-{uuid.uuid4().int % 90000 + 9000}"
        session.merge(Cve(id=cve_id, source="test", title="t"))
        asset = Asset(organization_id=org_id, name=f"a-{uuid.uuid4().hex[:6]}",
                      exposure="internet", criticality="critical")
        vuln = Vulnerability(organization_id=org_id, cve_id=cve_id, title="v",
                             severity="critical")
        session.add_all([asset, vuln])
        session.flush()
        finding = Finding(
            organization_id=org_id, asset_id=asset.id, vulnerability_id=vuln.id,
            state="new", dedupe_key=uuid.uuid4().hex, title="Edge RCE", severity="critical",
            kev=True, risk_score=95.0, risk_level="critical",
            detected_at=NOW - dt.timedelta(hours=10), assigned_team_id=team.id,
            assigned_user_id=m1.id,
        )
        session.add(finding)
        session.flush()
        sla_service.apply_sla(session, finding)     # kev + internet -> 4 h policy
        session.commit()
        return {"org_id": org_id, "slug": slug, "team": team.id, "finding": finding.id,
                "manager": manager.id, "m1": m1.id, "m2": m2.id, "secmgr": secmgr.id,
                "ciso": ciso.id, "asset": asset.id, "cve": cve_id}


def _sweep(org_id, now):
    with SessionLocal() as session:
        set_tenant(session, org_id)
        stats = sla_service.evaluate_findings(session, org_id, now=now)
        session.commit()
    return stats


def _escalation_notes(org_id):
    with SessionLocal() as session:
        set_tenant(session, org_id)
        return session.execute(
            select(Notification).where(Notification.event == "sla.escalated")
        ).scalars().all()


# --------------------------------------------------------------------------- TD-14
def test_td14_escalation_is_counted_from_the_deadline_not_detection(world):
    """Detected 10 h ago with a 4 h deadline: the deadline passed 6 h ago, so the
    4 h level fires and the 8 h level does not. Counted from detection (10 h) it
    would already be level 2."""
    _sweep(world["org_id"], NOW)
    with SessionLocal() as session:
        set_tenant(session, world["org_id"])
        finding = session.get(Finding, world["finding"])
        assert finding.sla_breached is True
        assert finding.escalation_level == 1


def test_td14_nothing_escalates_before_the_deadline(world):
    with SessionLocal() as session:
        set_tenant(session, world["org_id"])
        finding = session.get(Finding, world["finding"])
        # same age, but a 90-day deadline
        finding.sla_due_at = finding.detected_at + dt.timedelta(days=90)
        session.commit()
    stats = _sweep(world["org_id"], NOW)
    assert stats["escalated"] == 0
    with SessionLocal() as session:
        set_tenant(session, world["org_id"])
        assert session.get(Finding, world["finding"]).escalation_level == 0


def test_td14_recompute_lowers_stale_levels_silently(world):
    org_id = world["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.get(Finding, world["finding"])
        finding.sla_due_at = NOW + dt.timedelta(days=30)     # not breached at all
        finding.escalation_level = 4                          # the old regime's answer
        session.commit()

    with SessionLocal() as session:                           # dry run changes nothing
        set_tenant(session, org_id)
        dry = sla_service.recompute_escalation(session, org_id, apply=False, now=NOW)
        session.rollback()
    assert dry["lowered"] == 1 and dry["applied"] is False
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert session.get(Finding, world["finding"]).escalation_level == 4

    with SessionLocal() as session:
        set_tenant(session, org_id)
        done = sla_service.recompute_escalation(session, org_id, apply=True, now=NOW)
        session.commit()
    assert done["lowered"] == 1
    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.get(Finding, world["finding"])
        assert finding.escalation_level == 0
        events = session.execute(select(SlaEvent).where(
            SlaEvent.finding_id == finding.id, SlaEvent.event == "escalation_recomputed"
        )).scalars().all()
        assert len(events) == 1 and events[0].details["from"] == 4
    assert _escalation_notes(org_id) == []                    # no storm

    # ...and the finding now escalates for real once it breaches
    _sweep(org_id, NOW + dt.timedelta(days=31))
    assert _escalation_notes(org_id)


def test_td14_the_first_sweep_after_the_change_does_not_notify_stale_levels(world):
    """A finding stored at level 4 under the old rule and not yet recomputed:
    the sweep only moves levels UP, so it stays silent."""
    org_id = world["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.get(Finding, world["finding"])
        finding.escalation_level = 4
        session.commit()
    assert _sweep(org_id, NOW)["escalated"] == 0
    assert _escalation_notes(org_id) == []


# --------------------------------------------------------------------------- TD-07
def test_td07_each_target_resolves_to_people(world):
    with SessionLocal() as session:
        set_tenant(session, world["org_id"])
        finding = session.get(Finding, world["finding"])
        ids = lambda notify: {u.id for u in sla_service.resolve_escalation_recipients(  # noqa: E731
            session, finding, notify).users}
        assert ids("team") == {world["m1"], world["m2"]}
        assert ids("team_manager") == {world["manager"]}
        assert ids("security_manager") == {world["secmgr"]}
        assert ids("ciso") == {world["ciso"]}
        assert ids(["team_manager", "ciso"]) == {world["manager"], world["ciso"]}


def test_td07_an_unresolvable_target_falls_back_to_org_admins_loudly(world):
    with SessionLocal() as session:
        set_tenant(session, world["org_id"])
        finding = session.get(Finding, world["finding"])
        got = sla_service.resolve_escalation_recipients(session, finding, "role:nobody-has-this")
        assert got.fallback is True and got.unresolved == ["role:nobody-has-this"]
        assert got.users, "the org-admin created by the fixture must receive it"


def test_td07_ladder_override_wins(world):
    with SessionLocal() as session:
        set_tenant(session, world["org_id"])
        finding = session.get(Finding, world["finding"])
        ladder = session.execute(select(EscalationPolicy).where(
            EscalationPolicy.organization_id == world["org_id"])).scalars().first()
        ladder.targets = {"ciso": [str(world["secmgr"]), "audit@example.com"]}
        got = sla_service.resolve_escalation_recipients(session, finding, "ciso", ladder)
        assert {u.id for u in got.users} == {world["secmgr"]}
        assert got.addresses == ["audit@example.com"]


def test_td07_the_sweep_notifies_the_level_target_but_not_the_assignee_twice(world):
    org_id = world["org_id"]
    # 30 h past the deadline: level 3 -> `security_manager`
    _sweep(org_id, NOW + dt.timedelta(hours=26))
    notes = _escalation_notes(org_id)
    assert {n.recipient_user_id for n in notes} == {world["secmgr"]}
    assert {n.channel for n in notes} == {"in_app", "email"}
    with SessionLocal() as session:
        set_tenant(session, org_id)
        event = session.execute(select(SlaEvent).where(
            SlaEvent.finding_id == world["finding"], SlaEvent.event == "escalated"
        )).scalars().one()
        assert event.details["notify"] == "security_manager"
        assert event.details["recipients"] == 1 and event.details["fallback"] is False
    # re-running changes nothing: levels only notify when they increase
    before = len(_escalation_notes(org_id))
    _sweep(org_id, NOW + dt.timedelta(hours=26))
    assert len(_escalation_notes(org_id)) == before


def test_td07_team_level_never_includes_the_assignee_a_second_time(world):
    _sweep(world["org_id"], NOW)          # level 1 -> `team` (m1 is the assignee)
    notes = _escalation_notes(world["org_id"])
    assert {n.recipient_user_id for n in notes} == {world["m2"]}


# --------------------------------------------------------------------------- TD-08
def _pending(org_id, channel="in_app", user_id=None):
    with SessionLocal() as session:
        set_tenant(session, org_id)
        row = Notification(organization_id=org_id, channel=channel, event="x",
                           subject="s", body="b", recipient_user_id=user_id,
                           recipient_address="a@example.com" if channel == "email" else None)
        session.add(row)
        session.commit()
        return row.id


def test_td08_overlapping_dispatchers_never_pick_the_same_row(org_a):
    org_id = org_a[0]
    nid = _pending(org_id)
    one, two = SessionLocal(), SessionLocal()
    try:
        set_tenant(one, org_id)
        set_tenant(two, org_id)
        first = notifications.dispatch(one, org_id)            # holds the row lock
        second = notifications.dispatch(two, org_id)           # SKIP LOCKED: sees nothing
        assert first["sent"] == 1 and second["attempted"] == 0
        one.commit()
        two.rollback()
    finally:
        one.close()
        two.close()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert session.get(Notification, nid).status == "sent"


def test_td08_the_tick_dispatches_and_holds_email_without_smtp(org_a, monkeypatch):
    org_id = org_a[0]
    monkeypatch.setattr(settings, "smtp_host", "")
    monkeypatch.setattr(settings, "notify_email_enabled", True)
    in_app, email = _pending(org_id), _pending(org_id, "email")
    with SessionLocal() as session:
        set_tenant(session, org_id)
        org = session.get(Organization, org_id)
        message = tick._step_dispatch(session, org)
        session.commit()
    assert "e-mail held" in message
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert session.get(Notification, in_app).status == "sent"
        held = session.get(Notification, email)
        assert held.status == "pending" and held.attempts == 0      # not burned


def test_td08_the_tick_sends_email_when_smtp_is_configured(org_a, monkeypatch):
    org_id = org_a[0]
    sent = []
    monkeypatch.setattr(settings, "smtp_host", "relay.example.com")
    monkeypatch.setitem(notifications.TRANSPORTS, "email", lambda n: sent.append(n.id))
    email = _pending(org_id, "email")
    with SessionLocal() as session:
        set_tenant(session, org_id)
        tick._step_dispatch(session, session.get(Organization, org_id))
        session.commit()
    assert sent == [email]


def test_td08_email_stays_held_when_the_operator_disabled_it(org_a, monkeypatch):
    org_id = org_a[0]
    monkeypatch.setattr(settings, "smtp_host", "relay.example.com")
    monkeypatch.setattr(settings, "notify_email_enabled", False)
    sent = []
    monkeypatch.setitem(notifications.TRANSPORTS, "email", lambda n: sent.append(n.id))
    _pending(org_id, "email")
    with SessionLocal() as session:
        set_tenant(session, org_id)
        tick._step_dispatch(session, session.get(Organization, org_id))
        session.commit()
    assert sent == []


# ------------------------------------------------------------------ TD-16 / TD-17
def test_td16_td17_the_tick_reaps_leases_and_expires_acceptances(org_a, monkeypatch):
    from veyrs.services import agents, engagements

    org_id = org_a[0]
    calls = []
    monkeypatch.setattr(agents, "reap_expired_leases",
                        lambda s, o=None, **k: calls.append(("reap", o)) or {"requeued": 0, "expired": 0})
    monkeypatch.setattr(agents, "mark_stale_agents_offline",
                        lambda s, o=None, **k: calls.append(("offline", o)) or 0)
    monkeypatch.setattr(engagements, "expire_due",
                        lambda s, o=None, **k: calls.append(("expire", o)) or {})
    monkeypatch.setattr(retention, "prune", lambda **k: {})
    assert tick.run_maintenance() == 0
    assert {("reap", org_id), ("offline", org_id), ("expire", org_id)} <= set(calls)


def test_a_failing_step_does_not_skip_the_rest_and_fails_the_tick(org_a, monkeypatch):
    from veyrs.services import agents, engagements

    calls = []

    def boom(*a, **k):
        raise RuntimeError("boom")

    monkeypatch.setattr(agents, "reap_expired_leases", boom)
    monkeypatch.setattr(agents, "mark_stale_agents_offline", lambda *a, **k: 0)
    monkeypatch.setattr(engagements, "expire_due", lambda s, o=None, **k: calls.append(o) or {})
    monkeypatch.setattr(retention, "prune", lambda **k: calls.append("prune") or {})
    assert tick.run_maintenance() == 1
    assert org_a[0] in calls and "prune" in calls


# ------------------------------------------------------------------------- TD-37
def test_td37_tick_state_is_recorded_and_reported(org_a, client, admin_a):
    org_id = org_a[0]
    with SessionLocal() as session:
        assert tick.health(session, org_id)["status"] == "never_run"
    tick.mark_start()
    tick.mark_finish(True, "exit status 0")
    with SessionLocal() as session:
        h = tick.health(session, org_id)
    assert h["status"] == "ok" and h["last_result"] == "ok"
    assert h["minutes_since_success"] is not None and h["minutes_since_success"] < 5
    body = client.get("/api/v1/intel/health", headers=admin_a).json()
    assert body.get("tick", {}).get("status") == "ok", body

    tick.mark_start()
    tick.mark_finish(False, "exit status 1")
    with SessionLocal() as session:
        assert tick.health(session, org_id)["status"] == "failing"
        later = NOW + dt.timedelta(minutes=settings.tick_stale_minutes + 5)
        assert tick.health(session, org_id, now=later)["status"] == "stale"


def test_td37_mark_start_reports_minutes_since_the_last_success(org_a):
    org_id, slug, _ = org_a
    tick.mark_finish(True)
    gaps = tick.mark_start(now=NOW + dt.timedelta(minutes=95))
    assert 90 <= gaps[slug] <= 100


STUB = r"""#!/usr/bin/env bash
shift 2
cmd="$1"; shift || true
case "$cmd" in
    intel-due) [ "${1:-}" = "--quiet" ] && true ;;
    tick) echo "tick-$1${2:+ $2 $3}" >> "${STUB_LOG}" ;;
    sync-*|run-sla|maintenance) echo "${cmd}" >> "${STUB_LOG}";
        [ "${cmd}" = "${STUB_FAIL:-}" ] && exit 1; exit 0 ;;
esac
exit 0
"""


def _script(tmp_path, fail=""):
    (tmp_path / "scripts").mkdir()
    (tmp_path / "backend").mkdir()
    (tmp_path / "venv" / "bin").mkdir(parents=True)
    shutil.copy2(REPO / "scripts" / "sync-intel.sh", tmp_path / "scripts" / "sync-intel.sh")
    py = tmp_path / "venv" / "bin" / "python"
    py.write_text(STUB)
    py.chmod(py.stat().st_mode | stat.S_IXUSR)
    log = tmp_path / "calls.log"
    p = subprocess.run(["bash", str(tmp_path / "scripts" / "sync-intel.sh")],
                       env=dict(os.environ, STUB_LOG=str(log), STUB_FAIL=fail),
                       capture_output=True, text=True, timeout=30)
    return p, log.read_text().splitlines() if log.exists() else []


def test_the_tick_script_records_start_runs_maintenance_last_and_records_the_result(tmp_path):
    p, calls = _script(tmp_path)
    assert calls == ["tick-start", "run-sla", "maintenance", "tick-finish --status 0"], p.stdout
    assert p.returncode == 0


def test_a_failed_maintenance_fails_the_tick_and_is_recorded(tmp_path):
    p, calls = _script(tmp_path, fail="maintenance")
    assert calls[-1] == "tick-finish --status 1"
    assert p.returncode == 1


# ------------------------------------------------------------------------- TD-55
def test_td55_the_digest_lock_is_exclusive_across_sessions(org_a):
    org_id = org_a[0]
    one, two = SessionLocal(), SessionLocal()
    try:
        assert digest.claim_org(one, org_id) is True
        assert digest.claim_org(two, org_id) is False          # the other node is sending
        one.rollback()
        two.rollback()
        assert digest.claim_org(two, org_id) is True           # released with the txn
        two.rollback()
    finally:
        one.close()
        two.close()


def test_td55_a_digest_run_that_lost_the_race_sends_nothing(org_a, monkeypatch, capsys):
    org_id = org_a[0]
    holder = SessionLocal()
    try:
        assert digest.claim_org(holder, org_id) is True
        with SessionLocal() as session:
            set_tenant(session, org_id)
            digest.set_policy(session, org_id, {"enabled": True})
            session.commit()
        ran = []
        monkeypatch.setattr(digest, "run", lambda s, o, **k: ran.append(o) or {
            "queued": 0, "recipients": 0, "skipped_empty": 0})
        digest.run_cli(force=True)
        assert org_id not in ran                                # other orgs may still run
        assert f"{org_a[1]}: another digest run holds the lock" in capsys.readouterr().out
    finally:
        holder.rollback()
        holder.close()


# -------------------------------------------------------------------- TD-18 / TD-29
def test_td29_transition_options_come_from_the_finding_states():
    options = {o["value"] for o in
               workflow_service.ACTION_SCHEMA["transition_finding"]["fields"][0]["options"]}
    assert options == {s.value for s in FindingState}
    assert "pending_verification" not in options and "risk_accepted" not in options


def test_td29_save_time_validation_refuses_a_state_that_does_not_exist():
    with pytest.raises(workflow_service.WorkflowError):
        workflow_service.validate_steps(
            [{"action": "transition_finding", "config": {"state": "pending_verification"}}])
    workflow_service.validate_steps(
        [{"action": "transition_finding", "config": {"state": "verification"}}])


def test_td18_the_builder_offers_only_triggers_that_fire():
    triggers = set(workflow_service.describe()["triggers"])
    assert triggers == {
        "finding.created", "finding.state_changed", "finding.risk_changed", "sla.warned",
        "sla.breached", "sla.escalated", "intel.kev_added", "ticket.created",
        "ticket.state_changed",
    }
    assert "manual" not in triggers and "schedule" not in triggers


def _workflow(org_id, trigger):
    with SessionLocal() as session:
        set_tenant(session, org_id)
        session.add(WorkflowDefinition(
            organization_id=org_id, slug=f"w-{uuid.uuid4().hex[:6]}", name=trigger,
            trigger=trigger, steps=[{"action": "tag_asset", "config": {"tags": ["seen"]}}]))
        session.commit()


def _runs(org_id, trigger):
    with SessionLocal() as session:
        set_tenant(session, org_id)
        return session.execute(select(WorkflowRun).where(WorkflowRun.trigger == trigger)
                               ).scalars().all()


def test_td18_state_changed_fires_for_an_operator_move_but_not_for_a_workflow_move(world):
    org_id = world["org_id"]
    _workflow(org_id, "finding.state_changed")
    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.get(Finding, world["finding"])
        correlation.transition(session, finding, "triaged",
                               details={"origin": "operator", "via": "api"})
        session.commit()
    assert len(_runs(org_id, "finding.state_changed")) == 1
    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.get(Finding, world["finding"])
        correlation.transition(session, finding, "risk_assessed",
                               details={"origin": "workflow"})
        correlation.transition(session, finding, "assigned",
                               details={"origin": "assignment"})
        session.commit()
    assert len(_runs(org_id, "finding.state_changed")) == 1


def test_td18_a_state_changed_workflow_that_moves_the_finding_does_not_loop(world):
    org_id = world["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        session.add(WorkflowDefinition(
            organization_id=org_id, slug=f"loop-{uuid.uuid4().hex[:6]}", name="loop",
            trigger="finding.state_changed",
            steps=[{"action": "transition_finding", "config": {"state": "assigned"}}]))
        finding = session.get(Finding, world["finding"])
        correlation.transition(session, finding, "triaged", details={"origin": "operator"})
        session.commit()
    assert len(_runs(org_id, "finding.state_changed")) == 1        # not an endless chain


def test_td18_risk_changed_and_kev_added_fire_on_a_rescore(world):
    org_id = world["org_id"]
    _workflow(org_id, "finding.risk_changed")
    _workflow(org_id, "intel.kev_added")
    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.get(Finding, world["finding"])
        finding.kev = False
        finding.risk_level = "low"
        finding.risk_score = 10.0
        session.get(Cve, world["cve"]).kev = True
        vuln = session.get(Vulnerability, finding.vulnerability_id)
        vuln.kev = True
        session.flush()
        risk_service.score_finding(session, finding, profile=risk_service.resolve_profile(
            session, org_id))
        session.commit()
    assert len(_runs(org_id, "intel.kev_added")) == 1
    assert len(_runs(org_id, "finding.risk_changed")) == 1


def test_td18_the_first_score_of_a_finding_fires_neither(world):
    org_id = world["org_id"]
    _workflow(org_id, "finding.risk_changed")
    _workflow(org_id, "intel.kev_added")
    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.get(Finding, world["finding"])
        finding.risk_score = None
        finding.risk_level = None
        finding.kev = False
        session.get(Vulnerability, finding.vulnerability_id).kev = True
        session.flush()
        risk_service.score_finding(session, finding)
        session.commit()
    assert _runs(org_id, "finding.risk_changed") == []
    assert _runs(org_id, "intel.kev_added") == []


# ------------------------------------------------------------------------- TD-19
def test_td19_seed_defaults_adds_only_what_is_missing(org_a, capsys):
    org_id, slug, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert len(tenant_defaults.missing(session, org_id)["sla_policies"]) == 6
    assert tenant_defaults.run_cli(slug, apply=False) == 0          # dry run
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert session.execute(select(SlaPolicy)).scalars().all() == []
    assert tenant_defaults.run_cli(slug, apply=True) == 0
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert len(session.execute(select(SlaPolicy)).scalars().all()) == 6
        assert session.execute(select(RiskProfile)).scalars().all()
        assert sum(p.is_default for p in session.execute(select(SlaPolicy)).scalars()) == 1
    assert "nothing to add" not in capsys.readouterr().out
    assert tenant_defaults.run_cli(slug, apply=True) == 0
    assert "nothing to add" in capsys.readouterr().out


def test_td19_seeding_never_overwrites_or_adds_a_second_default(org_a):
    org_id, slug, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        session.add(SlaPolicy(organization_id=org_id, name="Mine", slug="mine",
                              remediate_within_hours=1, is_default=True))
        session.add(SlaPolicy(organization_id=org_id, name="Edited", slug="critical",
                              remediate_within_hours=2))
        session.commit()
    tenant_defaults.run_cli(slug, apply=True)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        rows = {p.slug: p for p in session.execute(select(SlaPolicy)).scalars()}
        assert rows["critical"].remediate_within_hours == 2 and rows["critical"].name == "Edited"
        assert [p.slug for p in rows.values() if p.is_default] == ["mine"]


def test_td19_bootstrap_seeds_a_new_organization(monkeypatch):
    import argparse

    from veyrs import cli

    slug = f"boot-{uuid.uuid4().hex[:8]}"
    args = argparse.Namespace(org=slug, name=None, email=f"a@{slug}.test", full_name=None,
                              password="Bootstrap-Password-12345!", invoicing_code=None,
                              locale="en", superuser=False)
    assert cli.bootstrap(args) == 0
    with SessionLocal() as session:
        org = session.execute(select(Organization).where(Organization.slug == slug)).scalar_one()
        set_tenant(session, org.id)
        assert len(session.execute(select(SlaPolicy)).scalars().all()) == 6
        assert session.execute(select(RiskProfile)).scalars().all()
    # a second bootstrap (password reset) must not re-add a policy the tenant deleted
    with SessionLocal() as session:
        set_tenant(session, org.id)
        session.delete(session.execute(select(SlaPolicy).where(SlaPolicy.slug == "low")).scalar_one())
        session.commit()
    assert cli.bootstrap(args) == 0
    with SessionLocal() as session:
        set_tenant(session, org.id)
        assert len(session.execute(select(SlaPolicy)).scalars().all()) == 5


# ------------------------------------------------------------------------- TD-27
def _audit(org_id, age_days):
    with SessionLocal() as session:
        set_tenant(session, org_id)
        row = AuditLog(organization_id=org_id, action="t.x", object_type="t",
                       created_at=NOW - dt.timedelta(days=age_days))
        session.add(row)
        session.commit()
        return row.id


def _exists(org_id, model, pk):
    with SessionLocal() as session:
        set_tenant(session, org_id)
        return session.get(model, pk) is not None


def test_td27_audit_rows_younger_than_the_setting_are_never_pruned(org_a, monkeypatch):
    org_id = org_a[0]
    monkeypatch.setattr(settings, "retention_audit_days", 400)
    young, edge, old = _audit(org_id, 10), _audit(org_id, 399), _audit(org_id, 401)
    dry = retention.prune(apply=False, tables=["audit_log"])
    assert dry["audit_log"]["rows"] >= 1
    assert _exists(org_id, AuditLog, old)                        # dry run deleted nothing
    retention.prune(apply=True, tables=["audit_log"])
    assert _exists(org_id, AuditLog, young) and _exists(org_id, AuditLog, edge)
    assert not _exists(org_id, AuditLog, old)


def test_td27_zero_keeps_everything(org_a, monkeypatch):
    org_id = org_a[0]
    monkeypatch.setattr(settings, "retention_audit_days", 0)
    old = _audit(org_id, 5000)
    out = retention.prune(apply=True, tables=["audit_log"])
    assert out["audit_log"]["cutoff"] is None and _exists(org_id, AuditLog, old)


def test_td27_notifications_read_or_delivered_go_unread_inapp_stays(org_a, monkeypatch):
    org_id = org_a[0]
    monkeypatch.setattr(settings, "retention_notifications_days", 90)
    old = NOW - dt.timedelta(days=200)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        rows = {
            "read": Notification(organization_id=org_id, channel="in_app", event="e",
                                 subject="s", body="b", status="sent", read_at=old),
            "unread": Notification(organization_id=org_id, channel="in_app", event="e",
                                   subject="s", body="b", status="sent", created_at=old),
            "mail_sent": Notification(organization_id=org_id, channel="email", event="e",
                                      subject="s", body="b", status="sent", created_at=old),
            "mail_pending": Notification(organization_id=org_id, channel="email", event="e",
                                         subject="s", body="b", status="pending",
                                         created_at=old),
            "recent_read": Notification(organization_id=org_id, channel="in_app", event="e",
                                        subject="s", body="b", status="sent",
                                        read_at=NOW - dt.timedelta(days=1)),
        }
        session.add_all(rows.values())
        session.commit()
        ids = {k: v.id for k, v in rows.items()}
    retention.prune(apply=True, tables=["notifications"])
    kept = {k for k, v in ids.items() if _exists(org_id, Notification, v)}
    assert kept == {"unread", "mail_pending", "recent_read"}


def test_td27_expired_refresh_tokens_after_the_grace_period(org_a, monkeypatch):
    org_id = org_a[0]
    monkeypatch.setattr(settings, "retention_tokens_days", 30)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        user = _user(session, org_id, "tok")
        mk = lambda exp, rev=None: RefreshToken(  # noqa: E731
            organization_id=org_id, user_id=user.id, token_hash=uuid.uuid4().hex,
            family_id=uuid.uuid4(), expires_at=exp, revoked_at=rev)
        rows = {"old": mk(NOW - dt.timedelta(days=40)),
                "recent": mk(NOW - dt.timedelta(days=5)),
                "live": mk(NOW + dt.timedelta(days=5)),
                "revoked_old": mk(NOW + dt.timedelta(days=5), NOW - dt.timedelta(days=40))}
        session.add_all(rows.values())
        session.commit()
        ids = {k: v.id for k, v in rows.items()}
    retention.prune(apply=True, tables=["refresh_tokens"])
    kept = {k for k, v in ids.items() if _exists(org_id, RefreshToken, v)}
    assert kept == {"recent", "live"}


def test_td27_history_goes_only_with_closed_findings(world, monkeypatch):
    org_id = world["org_id"]
    monkeypatch.setattr(settings, "retention_events_days", 730)
    old = NOW - dt.timedelta(days=1000)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        open_event = FindingEvent(organization_id=org_id, finding_id=world["finding"],
                                  event="x", created_at=old)
        finding = session.get(Finding, world["finding"])
        closed = Finding(
            organization_id=org_id, asset_id=finding.asset_id,
            vulnerability_id=finding.vulnerability_id, state="closed",
            dedupe_key=uuid.uuid4().hex, title="c")
        session.add_all([open_event, closed])
        session.flush()
        closed_event = FindingEvent(organization_id=org_id, finding_id=closed.id,
                                    event="x", created_at=old)
        session.add(closed_event)
        session.commit()
        ids = (open_event.id, closed_event.id)
    retention.prune(apply=True, tables=["finding_events"])
    assert _exists(org_id, FindingEvent, ids[0]) and not _exists(org_id, FindingEvent, ids[1])


def test_td27_the_newest_run_of_every_feed_survives():
    from veyrs.models import FeedRun

    feed = f"t{uuid.uuid4().hex[:6]}"
    with SessionLocal() as session:
        rows = [FeedRun(feed=feed, status="succeeded",
                        started_at=NOW - dt.timedelta(days=d)) for d in (900, 800, 700)]
        session.add_all(rows)
        session.commit()
        ids = [r.id for r in rows]
    retention.prune(apply=True, tables=["feed_runs"])
    with SessionLocal() as session:
        kept = [i for i in ids if session.get(FeedRun, i) is not None]
    assert kept == [ids[2]]                                      # the newest only


def test_td27_unknown_table_is_refused():
    with pytest.raises(ValueError):
        retention.prune(tables=["users"])


def test_td27_every_rule_names_a_real_setting_and_table():
    from veyrs.models import Base

    for rule in retention.RULES:
        assert rule.table in Base.metadata.tables
        assert hasattr(settings, rule.setting)


def test_td27_prune_survives_its_own_commits(org_a, monkeypatch):
    """Integration of TD-27 with R-05: the tenant binding and the audit-prune
    flag are transaction-local, and the prune commits after every batch. Each
    batch must re-bind both, or the second batch sees zero rows (RLS) or is
    refused (append-only trigger)."""
    org_id = org_a[0]
    monkeypatch.setattr(settings, "retention_audit_days", 400)
    monkeypatch.setattr(retention, "BATCH", 2)
    old = [_audit(org_id, 500) for _ in range(5)]
    out = retention.prune(apply=True, tables=["audit_log"])
    assert out["audit_log"]["rows"] >= 5
    assert not any(_exists(org_id, AuditLog, pk) for pk in old)


def _age(org_id, nid, hours):
    with SessionLocal() as session:
        set_tenant(session, org_id)
        row = session.get(Notification, nid)
        row.created_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(hours=hours)
        session.commit()


def test_td08_a_stale_email_backlog_expires_instead_of_going_out(org_a, monkeypatch):
    """0.41.0 starts dispatching from the tick. A queue that nothing drained for
    weeks must not reach people in one burst: e-mail older than
    VEYRS_NOTIFY_EMAIL_MAX_AGE_HOURS is expired, fresh e-mail is sent, in-app
    rows are never expired."""
    org_id = org_a[0]
    monkeypatch.setattr(settings, "notify_email_enabled", True)
    monkeypatch.setattr(settings, "notify_email_max_age_hours", 48)
    sent = []
    monkeypatch.setitem(notifications.TRANSPORTS, "email", lambda n: sent.append(n.id))
    old_mail, new_mail, old_inapp = _pending(org_id, "email"), _pending(org_id, "email"), _pending(org_id)
    _age(org_id, old_mail, 72)
    _age(org_id, old_inapp, 72)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        stats = notifications.dispatch(session, org_id)
        session.commit()
    assert stats["expired"] >= 1
    assert new_mail in sent and old_mail not in sent
    with SessionLocal() as session:
        set_tenant(session, org_id)
        old = session.get(Notification, old_mail)
        assert old.status == "expired" and "48 h" in old.error
        assert session.get(Notification, old_inapp).status == "sent"


def test_td08_max_age_zero_sends_everything(org_a, monkeypatch):
    org_id = org_a[0]
    monkeypatch.setattr(settings, "notify_email_enabled", True)
    monkeypatch.setattr(settings, "notify_email_max_age_hours", 0)
    sent = []
    monkeypatch.setitem(notifications.TRANSPORTS, "email", lambda n: sent.append(n.id))
    old_mail = _pending(org_id, "email")
    _age(org_id, old_mail, 24 * 30)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        notifications.dispatch(session, org_id)
        session.commit()
    assert old_mail in sent
