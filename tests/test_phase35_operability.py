"""Phase 35 - the console stops being a data model, and three things stop lying.

This round came from a list of twelve questions and change requests, and the
useful way to read it is that most of them were the same complaint: VEYRS
exposed everything it knows to everybody, in the vocabulary of its own schema,
with no way to tell configuration from daily work and no way to change the
things that *were* configuration.

What is pinned here is, as ever, the set of ways each piece can be quietly
wrong -- a screen that renders perfectly over a control that does nothing:

* **Negation filters.** `exclude_environment=production` has to keep meaning
  "not production" when a sixth environment is added. A client that enumerates
  the five it knows about stops covering the estate the day somebody adds
  `sandbox`, and nothing raises: the list still returns rows.
* **The intel schedule.** The first draft matched `FeedRun.status == "success"`
  and the column holds `"succeeded"`, so every feed reported "never completed"
  and the scheduler would have run all four on every tick -- a setting that
  silently does the opposite of what it says. `last_run` now delegates to
  `intelligence.last_successful_run`, and this file asserts there is no second
  copy of that predicate.
* **Automatic ticketing.** The dangerous direction is volume: a switch that
  ticketed the existing backlog on flip would produce hundreds of tickets and
  hundreds of notifications from one click. So: off by default, preview from
  the SAME predicate the automation uses, backlog behind an explicit call, and
  a budget that is enforced from the database rather than from a per-process
  counter that each worker would get its own copy of.
* **The CVSS assistant.** A model that proposes `AV:Q` must never reach a
  stored vector, a vector the bulletin PRINTS must beat anything a model says,
  and the score must always come from `engines.cvss`. Those three are the
  difference between a helper and a number an analyst puts in a report.
* **Team scope.** `/cvss/assist` reads the tenant's own findings and
  installations, so the `cvss` tag had to leave `EXEMPT_TAGS` -- the same
  reclassification `policies` needed in phase 28, for the same reason: a tag
  is a claim about every route beneath it.
* **The workflow vocabulary.** The console's example put step parameters under
  `"params"` while the engine reads `"config"`, so workflows built from it ran
  with an empty configuration and reported success. The description now lives
  next to the implementations and a source-level assert keeps the two sets
  equal.
"""
from __future__ import annotations

import datetime as dt
import pathlib
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.engines import cvss
from veyrs.models import (
    Asset, Cve, Document, Finding, FeedRun, Ticket, TicketEvent, Vulnerability,
)
from veyrs.models.tenancy import Organization
from veyrs.security import scope as team_scope
from veyrs.services import autoticket, cvss_assist, intel_schedule, ticketing
from veyrs.services import workflow as workflow_service

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCHEDULE_PY = ROOT / "backend" / "veyrs" / "services" / "intel_schedule.py"


# ---------------------------------------------------------------------------
# helpers
#
# `feed_runs` and `cves` have no `organization_id`: they are the shared
# intelligence corpus. That makes them the one place in this suite where a test
# can be polluted by an EARLIER test rather than by a fixture, and the symptom
# is a pass or a fail that depends on execution order. Both helpers below exist
# to make these tests hermetic against that, and neither should be replaced by
# "just insert a row".
# ---------------------------------------------------------------------------


def _only_feed_runs(session, feed: str, runs: list[tuple[str, dt.timedelta]]) -> None:
    """Make `feed` have exactly these runs, and nothing an earlier test left."""
    for row in session.execute(select(FeedRun).where(FeedRun.feed == feed)).scalars().all():
        session.delete(row)
    session.flush()
    now = dt.datetime.now(dt.timezone.utc)
    for status, ago in runs:
        session.add(FeedRun(feed=feed, status=status,
                            started_at=now - ago, finished_at=now - ago))
    session.commit()


def _a_cve(session) -> str:
    """A CVE identifier nothing else in the suite can collide with."""
    cve_id = f"CVE-2099-{uuid.uuid4().int % 900000 + 100000}"
    session.add(Cve(id=cve_id, description="phase-35 fixture"))
    session.flush()
    return cve_id


def _asset(session, organization_id, **kw):
    asset = Asset(
        organization_id=organization_id,
        name=kw.pop("name", f"host-{uuid.uuid4().hex[:6]}"),
        asset_type="server",
        **kw,
    )
    session.add(asset)
    session.flush()
    return asset


def _finding(session, organization_id, asset, *, risk=None, severity="high",
             state="new", kev=False, team_id=None):
    vulnerability = Vulnerability(
        organization_id=organization_id,
        title=f"vuln-{uuid.uuid4().hex[:6]}",
        severity=severity,
    )
    session.add(vulnerability)
    session.flush()
    finding = Finding(
        organization_id=organization_id,
        vulnerability_id=vulnerability.id,
        asset_id=asset.id,
        title=f"finding-{uuid.uuid4().hex[:6]}",
        severity=severity,
        state=state,
        risk_score=risk,
        kev=kev,
        assigned_team_id=team_id,
        dedupe_key=uuid.uuid4().hex,
    )
    session.add(finding)
    session.flush()
    return finding


# ---------------------------------------------------------------------------
# 1. Estate filters: negation, and why it is its own parameter
# ---------------------------------------------------------------------------


def test_exclude_environment_returns_everything_that_is_not_that(client, org_a, admin_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        _asset(session, org_id, name="prod-1", environment="production", exposure="internet")
        _asset(session, org_id, name="stg-1", environment="staging", exposure="internal")
        _asset(session, org_id, name="dev-1", environment="development", exposure="isolated")
        session.commit()

    r = client.get("/api/v1/assets?exclude_environment=production", headers=admin_a)
    assert r.status_code == 200
    names = {i["name"] for i in r.json()["items"]}
    assert names == {"stg-1", "dev-1"}


def test_exclude_survives_a_new_enum_member(client, org_a, admin_a):
    """The whole reason negation is a parameter and not four positive options.

    An asset in an environment this test invents is still "not production", and
    a client that had enumerated staging/test/development/dr would have missed
    it while continuing to return rows -- a silent under-count, in the direction
    of "you have less to worry about than you do".
    """
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        _asset(session, org_id, name="prod-2", environment="production")
        _asset(session, org_id, name="sandbox-1", environment="sandbox")
        session.commit()

    r = client.get("/api/v1/assets?exclude_environment=production", headers=admin_a)
    assert {i["name"] for i in r.json()["items"]} == {"sandbox-1"}


def test_positive_filter_accepts_several_values(client, org_a, admin_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        _asset(session, org_id, name="net-1", exposure="internet")
        _asset(session, org_id, name="ptr-1", exposure="partner")
        _asset(session, org_id, name="int-1", exposure="internal")
        session.commit()

    r = client.get("/api/v1/assets?exposure=internet,partner", headers=admin_a)
    assert {i["name"] for i in r.json()["items"]} == {"net-1", "ptr-1"}


def test_exclude_exposure_and_positive_filter_are_consistent(client, org_a, admin_a):
    """`exposure=X` and `exclude_exposure=X` must partition the estate exactly.

    If they ever overlap or leave a gap, one of the two is dropping rows and
    the estate silently stops adding up -- the failure mode that makes a
    per-team dashboard disagree with the whole-estate one.
    """
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        for i, exposure in enumerate(("internet", "internet", "partner", "isolated")):
            _asset(session, org_id, name=f"part-{i}", exposure=exposure)
        session.commit()

    inside = client.get("/api/v1/assets?exposure=internet", headers=admin_a).json()
    outside = client.get("/api/v1/assets?exclude_exposure=internet", headers=admin_a).json()
    everything = client.get("/api/v1/assets", headers=admin_a).json()
    assert inside["total"] + outside["total"] == everything["total"]
    assert not ({i["id"] for i in inside["items"]} & {i["id"] for i in outside["items"]})


def test_blank_members_are_dropped_not_matched(client, org_a, admin_a):
    """A stray comma must not become a filter for the empty string."""
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        _asset(session, org_id, name="comma-1", exposure="internet")
        session.commit()

    r = client.get("/api/v1/assets?exposure=internet,", headers=admin_a)
    assert {i["name"] for i in r.json()["items"]} == {"comma-1"}


# ---------------------------------------------------------------------------
# 2. Intelligence refresh schedule
# ---------------------------------------------------------------------------


def test_schedule_defaults_reproduce_the_previous_behaviour(client, org_a, admin_a):
    """An upgrade must not change what a deployment does."""
    r = client.get("/api/v1/intel/schedule", headers=admin_a)
    assert r.status_code == 200
    body = r.json()
    assert body["explicit"] is False
    assert {f["feed"] for f in body["feeds"]} == set(intel_schedule.FEEDS)
    for feed in body["feeds"]:
        assert feed["enabled"] is True
        assert feed["interval_minutes"] == 1440


def test_due_is_measured_from_a_SUCCEEDED_run(org_a):
    """The bug this file exists to prevent recurring.

    `feed_runs.status` holds `"succeeded"`. A predicate written against
    `"success"` matches nothing, every feed reads as "never completed
    successfully", and the scheduler runs all four on every hourly tick -- a
    cadence setting that silently does the opposite of what it says.
    """
    with SessionLocal() as session:
        _only_feed_runs(session, "kev", [("succeeded", dt.timedelta(minutes=10))])
        decisions = {d["feed"]: d for d in intel_schedule.due_feeds(session)}
        assert decisions["kev"]["due"] is False, decisions["kev"]["reason"]


def test_a_failed_run_does_not_reset_the_clock(org_a):
    """A broken feed must keep reporting itself as due, not as fresh."""
    with SessionLocal() as session:
        _only_feed_runs(session, "epss", [
            ("succeeded", dt.timedelta(days=3)),
            ("failed", dt.timedelta(seconds=1)),
        ])
        decisions = {d["feed"]: d for d in intel_schedule.due_feeds(session)}
        assert decisions["epss"]["due"] is True


def test_schedule_has_no_second_copy_of_the_success_predicate():
    """Source-level guardrail, in the line of phases 26 and 28.

    There is one definition of "a feed run that worked". A module that spells
    it again is a module that can spell it differently, and the symptom is
    invisible.
    """
    import ast as _ast

    source = SCHEDULE_PY.read_text()
    assert "last_successful_run" in source

    # Docstrings are stripped before the check: this module EXPLAINS the bug at
    # length, and a naive substring search over the file would fail on the
    # comment that exists to stop the bug coming back.
    tree = _ast.parse(source)
    literals = {
        node.value for node in _ast.walk(tree)
        if isinstance(node, _ast.Constant) and isinstance(node.value, str)
    }
    docstrings = set()
    for node in _ast.walk(tree):
        if isinstance(node, (_ast.Module, _ast.FunctionDef, _ast.AsyncFunctionDef,
                             _ast.ClassDef)):
            doc = _ast.get_docstring(node, clean=False)
            if doc is not None:
                docstrings.add(doc)
    for literal in literals - docstrings:
        assert "succeed" not in literal and literal != "success", (
            "the terminal state of a feed run is defined once, in "
            "services/intelligence.last_successful_run; a second copy here is "
            "a second copy that can be spelled differently"
        )


def test_tightening_the_cadence_makes_an_old_run_due(client, org_a, admin_a):
    """Only the TIGHTENING direction is assertable, and that is not a weak test.

    The first version of this also checked the other half -- "daily, and a
    three-hour-old run is not due" -- and it failed, for a reason worth keeping
    written down rather than working around: `due_now` is computed from the
    EFFECTIVE schedule, which is the tightest demand across every active
    organization, because the CVE corpus is shared and has no tenant column.
    Any other tenant asking for hourly makes this feed hourly for everybody,
    so "my setting is daily therefore this is not due" is not a property this
    system has, and a test asserting it was asserting the absence of other
    tenants rather than anything about the scheduler.

    What IS true in every deployment: a tenant asking for a tighter interval
    can never be served a looser one. That is the guarantee, and it is the one
    pinned here. Its counterpart -- both numbers being reported so an operator
    can see the difference -- is
    `test_effective_schedule_takes_the_tightest_demand`.
    """
    org_id, _, _ = org_a
    with SessionLocal() as session:
        _only_feed_runs(session, "cwe", [("succeeded", dt.timedelta(hours=3))])

    r = client.put("/api/v1/intel/schedule",
                   json={"feeds": {"cwe": {"interval_minutes": 60}}}, headers=admin_a)
    assert r.status_code == 200
    cwe = next(f for f in r.json()["feeds"] if f["feed"] == "cwe")
    assert cwe["interval_minutes"] == 60
    assert cwe["effective_interval_minutes"] <= 60
    assert cwe["due_now"] is True

    # And the demand round-trips even when somebody else's is tighter.
    r = client.put("/api/v1/intel/schedule",
                   json={"feeds": {"cwe": {"interval_minutes": 10080}}}, headers=admin_a)
    cwe = next(f for f in r.json()["feeds"] if f["feed"] == "cwe")
    assert cwe["interval_minutes"] == 10080
    assert cwe["effective_interval_minutes"] <= 10080


def test_changing_one_field_does_not_reset_the_other(client, org_a, admin_a):
    """`exclude_unset` is what makes a partial update partial."""
    client.put("/api/v1/intel/schedule",
               json={"feeds": {"nvd": {"interval_minutes": 360}}}, headers=admin_a)
    r = client.put("/api/v1/intel/schedule",
                   json={"feeds": {"nvd": {"enabled": False}}}, headers=admin_a)
    nvd = next(f for f in r.json()["feeds"] if f["feed"] == "nvd")
    assert nvd["enabled"] is False
    assert nvd["interval_minutes"] == 360


def test_unknown_feed_is_refused_not_ignored(client, org_a, admin_a):
    """A typo that returns 200 is a change the operator believes they made."""
    r = client.put("/api/v1/intel/schedule",
                   json={"feeds": {"nvd2": {"enabled": True}}}, headers=admin_a)
    assert r.status_code == 422
    assert "nvd2" in r.json()["detail"]


def test_interval_outside_the_range_is_refused(client, org_a, admin_a):
    """The floor is the tick itself: a control that cannot be honoured is a lie."""
    r = client.put("/api/v1/intel/schedule",
                   json={"feeds": {"kev": {"interval_minutes": 5}}}, headers=admin_a)
    assert r.status_code == 422


def test_effective_schedule_takes_the_tightest_demand(org_a, org_b):
    """The corpus is shared, so the effective cadence cannot be per tenant.

    Taking the loosest would let one tenant's weekly setting starve another's
    hourly one, silently and in the direction of stale intelligence.
    """
    org_a_id, _, _ = org_a
    org_b_id, _, _ = org_b
    with SessionLocal() as session:
        intel_schedule.set_schedule(session, org_a_id, {"kev": {"interval_minutes": 1440}})
        intel_schedule.set_schedule(session, org_b_id, {"kev": {"interval_minutes": 60}})
        session.commit()
        assert intel_schedule.effective_schedule(session)["kev"]["interval_minutes"] == 60

        state = intel_schedule.state(session, org_a_id)
        kev = next(f for f in state["feeds"] if f["feed"] == "kev")
        # Both numbers are reported, so an administrator who set 24h and
        # observes 1h is not looking at a bug.
        assert kev["interval_minutes"] == 1440
        assert kev["effective_interval_minutes"] == 60
        assert state["shared"] is True


# ---------------------------------------------------------------------------
# 3. Automatic ticket creation
# ---------------------------------------------------------------------------


def test_automation_is_off_by_default(client, org_a, admin_a):
    body = client.get("/api/v1/tickets/automation", headers=admin_a).json()
    assert body["enabled"] is False
    assert body["explicit"] is False
    assert body["require_owner"] is True


def test_correlation_creates_no_ticket_while_the_switch_is_off(org_a):
    from veyrs.services import correlation

    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        asset = _asset(session, org_id, exposure="internet")
        finding = _finding(session, org_id, asset, risk=99.0, team_id=None)
        correlation.process_finding(session, finding, fire_workflows=False)
        session.commit()
        assert ticketing.open_ticket_for_finding(session, finding.id) is None


def test_preview_uses_the_same_predicate_as_the_automation(client, org_a, admin_a):
    """A preview computed from a similar-looking rule is worse than none.

    The number an operator sees before flipping the switch has to be the number
    they get afterwards, so `preview()` and `consider()` share `matches()`.
    """
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        team = _team(session, org_id)
        asset = _asset(session, org_id)
        wanted = [_finding(session, org_id, asset, risk=95.0, team_id=team) for _ in range(3)]
        _finding(session, org_id, asset, risk=10.0, team_id=team)      # below threshold
        _finding(session, org_id, asset, risk=95.0, team_id=None)      # unowned
        session.commit()
        wanted_ids = {str(f.id) for f in wanted}

    body = client.post("/api/v1/tickets/automation/preview", json={}, headers=admin_a).json()
    assert body["would_create"] == 3
    assert {s["finding_id"] for s in body["sample"]} == wanted_ids


def test_preview_writes_nothing(client, org_a, admin_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        team = _team(session, org_id)
        asset = _asset(session, org_id)
        _finding(session, org_id, asset, risk=95.0, team_id=team)
        session.commit()

    client.post("/api/v1/tickets/automation/preview", json={}, headers=admin_a)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert session.execute(
            select(Ticket).where(Ticket.organization_id == org_id)
        ).scalars().all() == []


def test_empty_severity_list_means_do_not_filter(org_a):
    """An omitted optional and a deliberate empty set are the same JSON.

    Reading it as an exclusion would make a policy that names only a risk
    threshold ticket nothing at all -- and look like it was working.
    """
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        team = _team(session, org_id)
        asset = _asset(session, org_id)
        finding = _finding(session, org_id, asset, risk=95.0, severity="high", team_id=team)
        policy = dict(autoticket.state(session, org_id), enabled=True, severities=[])
        assert autoticket.matches(finding, policy, asset=asset) is True


def test_a_policy_with_no_condition_at_all_is_refused(org_a):
    """It would ticket every open finding, and that is unrecoverable at volume."""
    org_id, _, _ = org_a
    with SessionLocal() as session:
        with pytest.raises(autoticket.AutoTicketError):
            autoticket.set_policy(session, org_id, {"min_risk_score": None})
        # Explicit zero IS allowed: somebody who means it can say so.
        state = autoticket.set_policy(session, org_id, {"min_risk_score": 0})
        assert state["min_risk_score"] == 0.0


def test_enabling_does_not_touch_the_existing_backlog(client, org_a, admin_a):
    """The single most dangerous thing this feature could do on one click."""
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        team = _team(session, org_id)
        asset = _asset(session, org_id)
        for _ in range(5):
            _finding(session, org_id, asset, risk=95.0, team_id=team)
        session.commit()

    r = client.put("/api/v1/tickets/automation", json={"enabled": True}, headers=admin_a)
    assert r.status_code == 200
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert session.execute(
            select(Ticket).where(Ticket.organization_id == org_id)
        ).scalars().all() == []


def test_backfill_defaults_to_a_dry_run(client, org_a, admin_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        team = _team(session, org_id)
        asset = _asset(session, org_id)
        for _ in range(4):
            _finding(session, org_id, asset, risk=95.0, team_id=team)
        session.commit()

    body = client.post("/api/v1/tickets/automation/backfill", json={}, headers=admin_a).json()
    assert body["dry_run"] is True and body["created"] == 4
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert session.execute(
            select(Ticket).where(Ticket.organization_id == org_id)
        ).scalars().all() == []


def test_backfill_reports_the_cap_instead_of_silently_truncating(client, org_a, admin_a):
    """A clean count over dropped work is how a backfill gets believed."""
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        team = _team(session, org_id)
        asset = _asset(session, org_id)
        for _ in range(6):
            _finding(session, org_id, asset, risk=95.0, team_id=team)
        session.commit()

    body = client.post("/api/v1/tickets/automation/backfill",
                       json={"dry_run": False, "limit": 2}, headers=admin_a).json()
    assert body["created"] == 2
    assert body["capped"] is True
    assert body["remaining"] == 4


def test_backfill_never_duplicates_an_open_ticket(client, org_a, admin_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        team = _team(session, org_id)
        asset = _asset(session, org_id)
        finding = _finding(session, org_id, asset, risk=95.0, team_id=team)
        session.commit()

    first = client.post("/api/v1/tickets/automation/backfill",
                        json={"dry_run": False}, headers=admin_a).json()
    second = client.post("/api/v1/tickets/automation/backfill",
                         json={"dry_run": False}, headers=admin_a).json()
    assert first["created"] == 1
    assert second["created"] == 0 and second["skipped_existing"] == 1


def test_the_budget_is_counted_from_the_database(org_a):
    """Not from a process-local variable.

    The API runs several workers and a correlation batch can span more than one
    of them; an in-memory counter would give each worker a full budget and the
    real cap would be `max_per_run x workers`.
    """
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        team = _team(session, org_id)
        asset = _asset(session, org_id)
        finding = _finding(session, org_id, asset, risk=95.0, team_id=team)
        ticket, _ = ticketing.ticket_for_finding(
            session, finding, actor_label=autoticket.ACTOR_LABEL)
        session.commit()

        assert autoticket.recent_auto_created(session, org_id) == 1
        # A ticket somebody opened by hand does not spend the automation's budget.
        other = _finding(session, org_id, asset, risk=95.0, team_id=team)
        ticketing.ticket_for_finding(session, other, actor_label="alice@example.test")
        session.commit()
        assert autoticket.recent_auto_created(session, org_id) == 1


def test_consider_stops_when_the_budget_is_spent(org_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        team = _team(session, org_id)
        asset = _asset(session, org_id)
        autoticket.set_policy(session, org_id, {"enabled": True, "max_per_run": 2})
        session.commit()

        created = []
        for _ in range(4):
            finding = _finding(session, org_id, asset, risk=95.0, team_id=team)
            ticket = autoticket.consider(session, finding)
            session.commit()
            if ticket is not None:
                created.append(ticket)
        assert len(created) == 2


def test_a_team_scoped_identity_cannot_change_the_policy(client, org_a, admin_a):
    """403, not a narrowed version: a team raising the threshold would stop
    tickets opening for work that is not theirs, invisibly to everybody else."""
    from veyrs.api.v1 import tickets as tickets_api

    org_id, _, _ = org_a
    restricted = team_scope.TeamScope(restricted=True, team_ids=frozenset({uuid.uuid4()}))
    with pytest.raises(Exception) as excinfo:
        team_scope.refuse_if_restricted(restricted, "test")
    assert getattr(excinfo.value, "status_code", None) == 403


def test_only_remediation_tickets_are_opened(org_a):
    """The backend accepts any string and silently creates a dead-end type.

    `remediation` is the only one that de-duplicates per finding, carries the
    REM prefix and advances its finding on resolution.
    """
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        team = _team(session, org_id)
        asset = _asset(session, org_id)
        autoticket.set_policy(session, org_id, {"enabled": True})
        finding = _finding(session, org_id, asset, risk=95.0, team_id=team)
        ticket = autoticket.consider(session, finding)
        session.commit()
        assert ticket is not None
        assert ticket.ticket_type == "remediation"
        assert ticket.reference.startswith("VEYRS-REM-") or "REM" in ticket.reference


# ---------------------------------------------------------------------------
# 4. CVSS bulletin assistant
# ---------------------------------------------------------------------------


BULLETIN = """
Vendor Security Advisory ACME-2026-0001.

A stack-based buffer overflow in the ACME gateway allows a remote
unauthenticated attacker to execute arbitrary code. CVE-2021-44228 has been
assigned. CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H
"""


def test_a_printed_vector_is_taken_verbatim_and_scored_by_the_engine(org_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        result = cvss_assist.assist(
            session, organization_id=org_id, text=BULLETIN, version="3.1", use_ai=False)

    assert result["vector"] == "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert result["score"]["score"] == 9.8
    # Provenance travels with every metric so a reviewer can see which half
    # they are actually reviewing.
    assert set(result["metric_source"].values()) == {"bulletin"}
    assert result["ai"]["used"] is False


def test_cve_identifiers_are_extracted_and_deduplicated(org_a):
    org_id, _, _ = org_a
    text = "CVE-2021-44228 and cve-2021-44228 and CVE-2024-3094."
    with SessionLocal() as session:
        set_tenant(session, org_id)
        result = cvss_assist.assist(
            session, organization_id=org_id, text=text + " " * 20,
            version="3.1", use_ai=False)
    assert result["cve_ids"] == ["CVE-2021-44228", "CVE-2024-3094"]


def test_a_metric_the_specification_does_not_define_is_dropped_and_reported():
    """A model that answers `AV:Q` must not reach a form that then 422s at the
    user, and must certainly not reach a stored vector."""
    kept, rejected = cvss_assist.sanitize_metrics(
        {"AV": "N", "AC": "Q", "XX": "N", "C": "H"}, "3.1")
    assert kept == {"AV": "N", "C": "H"}
    assert any("AC" in r for r in rejected)
    assert any("XX" in r for r in rejected)


def test_an_incomplete_bulletin_produces_a_half_filled_form_not_an_error(org_a):
    """The normal outcome, not a failure. A bulletin that never says whether
    privileges are required leaves PR unset, and the honest response is the
    list of what the analyst still has to decide."""
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        result = cvss_assist.assist(
            session, organization_id=org_id,
            text="A remote attacker over the network can read files. " * 3,
            version="3.1", use_ai=False)
    assert result["vector"] is None
    assert result["needs_decision"]
    assert any("AV" in item for item in result["needs_decision"])


def test_an_invalid_printed_vector_is_reported_rather_than_swallowed(org_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        result = cvss_assist.assist(
            session, organization_id=org_id,
            text="Advisory. CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H is the score.",
            version="3.1", use_ai=False)
    printed = result["printed_vectors"]
    assert printed and printed[0]["valid"] is False
    assert printed[0]["error"]


def test_product_matching_uses_whole_tokens(org_a):
    """A substring test reports the estate's `nginx` as named by a bulletin
    that only ever says `nginx-plus`, and the analyst acts on the wrong host."""
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        hits = cvss_assist.matched_products(
            session, org_id, "An issue in nginxplus 1.0 was found.")
        assert all(h["product"].lower() != "nginx" for h in hits)


def test_the_assist_route_reads_tenant_rows_so_cvss_is_scope_aware():
    """The phase-28 lesson, applied before it could bite.

    `EXEMPT_TAGS` asserts its routes carry no asset- or finding-level rows.
    `/cvss/assist` reads both, so the tag had to move.
    """
    assert "cvss" in team_scope.SCOPED_TAGS
    assert "cvss" not in team_scope.EXEMPT_TAGS


def test_assist_refuses_an_empty_bulletin(client, org_a, admin_a):
    r = client.post("/api/v1/cvss/assist",
                    json={"text": " " * 40, "version": "3.1", "use_ai": False},
                    headers=admin_a)
    assert r.status_code == 422


# ---------------------------------------------------------------------------
# 5. Documents: what a person owns, next to what the extractor found
# ---------------------------------------------------------------------------


def test_manual_cves_live_in_their_own_column(client, org_a, admin_a):
    """Machine-derived and human-decided have different lifetimes.

    Appending a hand-attached CVE to `cve_ids` would let the next re-extraction
    silently discard somebody's judgement.
    """
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        cve_id = _a_cve(session)
        document = Document(organization_id=org_id, filename="a.txt",
                            content_hash=uuid.uuid4().hex, cve_ids=["CVE-2021-44228"])
        session.add(document)
        session.commit()
        document_id = document.id

    # Lower-cased on the way in: an identifier is case-insensitive to a human
    # and exact to a database, and only one of those can be right.
    r = client.patch(f"/api/v1/documents/{document_id}",
                     json={"manual_cve_ids": [cve_id.lower()]}, headers=admin_a)
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["cve_ids"] == ["CVE-2021-44228"]
    assert body["manual_cve_ids"] == [cve_id]
    assert body["all_cve_ids"] == ["CVE-2021-44228", cve_id]


def test_a_cve_outside_the_catalogue_is_refused(client, org_a, admin_a):
    """A document may reference a vulnerability; it cannot invent one."""
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        document = Document(organization_id=org_id, filename="b.txt",
                            content_hash=uuid.uuid4().hex)
        session.add(document)
        session.commit()
        document_id = document.id

    r = client.patch(f"/api/v1/documents/{document_id}",
                     json={"manual_cve_ids": ["CVE-1999-99999"]}, headers=admin_a)
    assert r.status_code == 422


def test_filename_is_not_editable(client, org_a, admin_a):
    """It is evidence: the content hash was taken over those bytes."""
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        document = Document(organization_id=org_id, filename="evidence.pdf",
                            content_hash=uuid.uuid4().hex)
        session.add(document)
        session.commit()
        document_id = document.id

    client.patch(f"/api/v1/documents/{document_id}",
                 json={"title": "Q3 advisory", "filename": "nicer.pdf"}, headers=admin_a)
    r = client.get(f"/api/v1/documents/{document_id}", headers=admin_a).json()
    assert r["filename"] == "evidence.pdf"
    assert r["title"] == "Q3 advisory"


def test_clear_is_required_to_remove_an_owner(client, org_a, admin_a):
    """An omitted optional and an explicit null are the same JSON."""
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        team = _team(session, org_id)
        document = Document(organization_id=org_id, filename="c.txt",
                            content_hash=uuid.uuid4().hex, team_id=team)
        session.add(document)
        session.commit()
        document_id = document.id

    r = client.patch(f"/api/v1/documents/{document_id}", json={"title": "x"},
                     headers=admin_a)
    assert r.status_code == 200, r.text
    assert client.get(f"/api/v1/documents/{document_id}",
                      headers=admin_a).json()["team_id"] is not None

    client.patch(f"/api/v1/documents/{document_id}",
                 json={"clear": ["team_id"]}, headers=admin_a)
    assert client.get(f"/api/v1/documents/{document_id}",
                      headers=admin_a).json()["team_id"] is None


def test_searching_by_cve_covers_both_columns(client, org_a, admin_a):
    """Searching only the extracted list would answer "no documents" for the
    link somebody made precisely because the text did not say it."""
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        cve_id = _a_cve(session)
        session.add(Document(organization_id=org_id, filename="d.txt",
                             content_hash=uuid.uuid4().hex,
                             manual_cve_ids=[cve_id]))
        session.commit()

    r = client.get(f"/api/v1/documents?cve_id={cve_id}", headers=admin_a)
    assert r.json()["total"] == 1


# ---------------------------------------------------------------------------
# 6. The workflow vocabulary the console renders from
# ---------------------------------------------------------------------------


def test_every_action_is_described_and_every_description_executes():
    """The guardrail behind the guided builder.

    An action that executes but is not described renders as an empty box; one
    that is described but does not execute is a field somebody fills in for
    nothing.
    """
    assert set(workflow_service.ACTION_SCHEMA) == set(workflow_service.ACTIONS)


def test_the_described_step_shape_is_the_one_the_engine_reads():
    """The console shipped an example using `params` for two releases.

    The engine reads `step.get("config")`, so every workflow built from that
    example ran with an empty configuration and reported success.
    """
    described = workflow_service.describe()
    assert "config" in described["step_shape"]
    assert "params" not in described["step_shape"]
    engine_source = (ROOT / "backend" / "veyrs" / "services" / "workflow.py").read_text()
    assert 'config.get(' in engine_source or 'step.get("config")' in engine_source


def test_every_trigger_carries_a_plain_language_explanation():
    """A dropdown of `finding.state_changed` is a dropdown only its author can use."""
    described = workflow_service.describe()
    for trigger in described["triggers"]:
        assert described["trigger_help"].get(trigger), trigger


def test_action_fields_declare_a_renderable_type():
    known = {"text", "textarea", "select", "multiselect", "tags", "number"}
    for name, spec in workflow_service.ACTION_SCHEMA.items():
        assert spec.get("summary"), name
        for field in spec.get("fields", []):
            assert field["type"] in known, (name, field)
            if field["type"] in ("select", "multiselect"):
                assert field.get("options"), (name, field)


# ---------------------------------------------------------------------------
# 7. The vendor dictionary, made reachable
# ---------------------------------------------------------------------------


def test_vendors_are_ranked_by_what_this_tenant_actually_runs(client, org_a, admin_a):
    """Sorting a page after paginating it produces a list that looks ranked and
    is not: the first attempt returned the alphabetically-first 50 of 37 000
    vendors, all with zero installations, tidily sorted among themselves."""
    r = client.get("/api/v1/intel/vendors?size=25", headers=admin_a)
    assert r.status_code == 200
    counts = [item["installations"] for item in r.json()["items"]]
    assert counts == sorted(counts, reverse=True)


def test_in_use_returns_only_vendors_with_installations(client, org_a, admin_a):
    r = client.get("/api/v1/intel/vendors?in_use=true", headers=admin_a)
    assert all(item["installations"] > 0 for item in r.json()["items"])


def _team(session, organization_id):
    from veyrs.models import Team

    team = Team(organization_id=organization_id,
                name=f"team-{uuid.uuid4().hex[:6]}",
                slug=f"team-{uuid.uuid4().hex[:6]}")
    session.add(team)
    session.flush()
    return team.id
