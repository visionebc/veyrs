"""Phase 28 - the SLA endpoints stop answering with the estate.

Phase 26 built the authorization boundary and phase 27 gave the dashboards a
team filter. Both left one hole open and *known*: `/policies/sla/summary` took
no scope at all, and the `policies` tag sat in `EXEMPT_TAGS`, whose comment
claims its routes carry "no asset- or finding-level tenant rows". Three of them
do. The console worked around it by hiding the SLA widget whenever a team
filter was on, which hid the symptom and kept the leak.

What is pinned here:

* the counters, the event log and the sweep are all narrowed by the caller's
  scope -- a router is not exempt because most of its routes are;
* the **sweep narrows what it touches**, not merely what it counts. It
  breaches, escalates and notifies; a restricted operator must not be able to
  page a team they cannot read;
* `?team_id=` on the summary behaves exactly like the dashboards': it only
  intersects, 404s on a team outside scope, and keeps `filtered` apart from
  `restricted`;
* the two SLA surfaces **agree**. `/dashboard/sla` was scoped and
  `/policies/sla/summary` was not, so the same screen showed one team's
  findings beside the estate's breach count;
* organization configuration stays estate-wide. Over-restricting the policy
  tables would be the opposite failure and just as wrong;
* one implementation of the view filter, asserted on the source. Two copies of
  "look up the team, 404 on another tenant's, name it" is how one of the three
  goes missing.
"""
from __future__ import annotations

import pathlib
import uuid

import pytest

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Finding, SlaEvent

from test_phase26_scope import PASSWORD, estate  # noqa: F401  (fixture import)

BACKEND = pathlib.Path(__file__).resolve().parents[1] / "backend" / "veyrs"


@pytest.fixture()
def sla_events(estate):  # noqa: F811
    """One SLA event per finding, so the log has something to segregate."""
    with SessionLocal() as session:
        set_tenant(session, estate["org_id"])
        for label in ("net", "app", "orphan"):
            session.add(SlaEvent(
                organization_id=estate["org_id"], finding_id=estate[label]["finding"],
                event="breached", details={"label": label},
            ))
        session.commit()
    return estate


def _summary(client, headers, team_id=None):
    query = f"?team_id={team_id}" if team_id else ""
    response = client.get(f"/api/v1/policies/sla/summary{query}", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# 1. the counters
# ---------------------------------------------------------------------------
def test_the_summary_counts_only_what_the_caller_may_see(client, admin_a, estate):
    """The hole itself: this route answered with the estate for everyone."""
    scoped = _summary(client, estate["scoped"])
    estate_wide = _summary(client, admin_a)
    assert scoped["open"] == 1
    # netops' finding, the appsec one, and the orphan nobody owns.
    assert estate_wide["open"] >= 3
    assert scoped["open"] < estate_wide["open"]


def test_the_summary_states_the_scope_it_counted(client, admin_a, estate):
    """A number under the wrong heading is the failure mode, not a missing number."""
    assert _summary(client, estate["scoped"])["scope"]["restricted"] is True
    assert _summary(client, admin_a)["scope"]["restricted"] is False


def test_the_summary_takes_the_same_team_filter_as_the_dashboards(client, admin_a, estate):
    payload = _summary(client, admin_a, estate["netops"])
    assert payload["open"] == 1
    assert payload["scope"]["team_filter"]["team_name"] == "Redes"


def test_a_filtered_summary_is_not_an_authorization_limit(client, admin_a, estate):
    """An administrator who filters is not a restricted administrator."""
    block = _summary(client, admin_a, estate["netops"])["scope"]
    assert block["restricted"] is False
    assert block["team_filter"] is not None


def test_the_filter_can_only_intersect(client, estate):
    """404, not 403: a 403 confirms the other team exists."""
    response = client.get(f"/api/v1/policies/sla/summary?team_id={estate['appsec']}",
                          headers=estate["scoped"])
    assert response.status_code == 404


def test_an_unknown_team_is_also_404(client, admin_a):
    response = client.get(f"/api/v1/policies/sla/summary?team_id={uuid.uuid4()}",
                          headers=admin_a)
    assert response.status_code == 404


def test_the_two_sla_surfaces_agree_under_the_same_filter(client, admin_a, estate):
    """`/dashboard/sla` was scoped and this one was not -- on the same screen."""
    dashboard = client.get(f"/api/v1/dashboard/sla?team_id={estate['netops']}",
                           headers=admin_a).json()
    summary = _summary(client, admin_a, estate["netops"])
    assert dashboard["scope"]["team_filter"] == summary["scope"]["team_filter"]

    scoped_dash = client.get("/api/v1/dashboard/sla", headers=estate["scoped"]).json()
    assert scoped_dash["scope"]["team_ids"] == summary["scope"]["team_ids"]


# ---------------------------------------------------------------------------
# 2. the event log
# ---------------------------------------------------------------------------
def test_sla_events_are_scoped_by_the_finding_they_belong_to(client, sla_events):
    """`sla_events` has no team of its own; it inherits its finding's owner."""
    body = client.get("/api/v1/policies/sla/events",
                      headers=sla_events["scoped"]).json()
    assert {item["finding_id"] for item in body["items"]} == {
        str(sla_events["net"]["finding"])
    }


def test_asking_for_an_invisible_findings_events_returns_nothing(client, sla_events):
    """Not 404: the subquery simply does not contain it, same as anywhere else."""
    body = client.get(
        f"/api/v1/policies/sla/events?finding_id={sla_events['app']['finding']}",
        headers=sla_events["scoped"],
    ).json()
    assert body["items"] == [] and body["total"] == 0


def test_the_event_log_estate_wide_still_sees_every_event(client, admin_a, sla_events):
    body = client.get("/api/v1/policies/sla/events", headers=admin_a).json()
    findings = {item["finding_id"] for item in body["items"]}
    assert findings >= {str(sla_events[label]["finding"]) for label in ("net", "app", "orphan")}


# ---------------------------------------------------------------------------
# 3. the sweep -- the one that writes
# ---------------------------------------------------------------------------
def test_the_sweep_touches_only_the_scoped_findings(client, estate):
    """It breaches, escalates and notifies. Unscoped, it pages other teams."""
    response = client.post("/api/v1/policies/sla/evaluate", headers=estate["scoped"])
    assert response.status_code == 200, response.text
    assert response.json()["checked"] == 1


def test_the_sweep_reports_the_scope_it_ran_under(client, estate):
    body = client.post("/api/v1/policies/sla/evaluate", headers=estate["scoped"]).json()
    assert body["scope"]["restricted"] is True


def test_the_sweep_leaves_an_invisible_finding_untouched(client, estate):
    """A side effect on a row the caller cannot read is still a leak."""
    client.post("/api/v1/policies/sla/evaluate", headers=estate["scoped"])
    with SessionLocal() as session:
        set_tenant(session, estate["org_id"])
        outside = session.get(Finding, estate["app"]["finding"])
        assert outside.sla_breached is False
        assert outside.escalation_level == 0
        events = session.query(SlaEvent).filter(
            SlaEvent.finding_id == estate["app"]["finding"]
        ).count()
        assert events == 0


def test_an_estate_wide_sweep_still_covers_everything(client, admin_a, estate):
    body = client.post("/api/v1/policies/sla/evaluate", headers=admin_a).json()
    assert body["checked"] >= 3
    assert body["scope"]["restricted"] is False


# ---------------------------------------------------------------------------
# 3b. estate-wide policy writes -- found by the guardrail below, not by hand
# ---------------------------------------------------------------------------
def test_a_scoped_identity_cannot_edit_the_estate_wide_sla_policy(client, admin_a, estate):
    """`PATCH ?reapply=true` recomputes deadlines on EVERY open finding.

    The worst of the four defects this round: a write reaching rows the caller
    cannot list. Narrowing the re-apply would leave the rest of the estate on a
    deadline nobody recomputed, so the action is refused instead.
    """
    policy = client.post("/api/v1/policies/sla", headers=admin_a, json={
        "name": "estate", "slug": f"estate-{uuid.uuid4().hex[:6]}",
        "remediate_within_hours": 24,
    }).json()
    body = {k: v for k, v in policy.items() if k != "id"}
    body["remediate_within_hours"] = 1
    response = client.patch(f"/api/v1/policies/sla/{policy['id']}",
                            headers=estate["scoped"], json=body)
    assert response.status_code == 403, response.text
    assert "estate-wide" in response.json()["detail"]
    # The same body from an unrestricted identity still works, so the refusal is
    # about the scope rather than a route this change broke.
    assert client.patch(f"/api/v1/policies/sla/{policy['id']}",
                        headers=admin_a, json=body).status_code == 200


def test_a_scoped_identity_cannot_create_policy_or_routing(client, estate):
    """An assignment rule is the same defect from the other end: it routes work
    *to* teams, so a team that can write one decides its own queue."""
    created = client.post("/api/v1/policies/sla", headers=estate["scoped"], json={
        "name": "mine", "slug": f"mine-{uuid.uuid4().hex[:6]}",
        "remediate_within_hours": 1,
    })
    assert created.status_code == 403, created.text
    rule = client.post("/api/v1/policies/assignment", headers=estate["scoped"], json={
        "name": "everything to me", "team_id": str(estate["netops"]), "conditions": {},
    })
    assert rule.status_code == 403, rule.text


def test_an_estate_wide_identity_still_creates_policy(client, admin_a, estate):
    created = client.post("/api/v1/policies/sla", headers=admin_a, json={
        "name": "ours", "slug": f"ours-{uuid.uuid4().hex[:6]}",
        "remediate_within_hours": 72,
    })
    assert created.status_code == 201, created.text


# ---------------------------------------------------------------------------
# 4. what must NOT have been narrowed
# ---------------------------------------------------------------------------
def test_policy_configuration_stays_estate_wide(client, estate):
    """SLA policies are organization config and have no owning team.

    Over-restricting them would be the mirror-image bug: a triage identity that
    cannot read the deadline it is being held to.
    """
    for path in ("/api/v1/policies/sla", "/api/v1/policies/escalation",
                 "/api/v1/policies/assignment"):
        response = client.get(path, headers=estate["scoped"])
        assert response.status_code == 200, f"{path}: {response.text}"


def test_the_router_is_still_reachable_at_all(client, estate):
    """`policies` left EXEMPT_TAGS; landing outside both sets would 403 the lot."""
    assert client.get("/api/v1/policies/sla", headers=estate["scoped"]).status_code == 200


# ---------------------------------------------------------------------------
# 5. guardrails on the source -- the class of defect, not this instance
# ---------------------------------------------------------------------------
def test_policies_is_declared_scope_aware_not_exempt():
    from veyrs.security.scope import EXEMPT_TAGS, SCOPED_TAGS

    assert "policies" in SCOPED_TAGS
    assert "policies" not in EXEMPT_TAGS


def test_no_route_in_the_policies_router_reads_findings_without_a_scope():
    """The defect was one route forgetting; this fails on the source, not on a leak.

    Phase 26 pinned the same property over `services/analytics.py`. A route
    added tomorrow that selects findings and never mentions a scope trips here
    rather than shipping an estate figure to a team-scoped console.
    """
    source = (BACKEND / "api" / "v1" / "policies.py").read_text()
    handlers = source.split("\n@router.")[1:]
    assert handlers, "router blocks not found -- has the file been restructured?"
    for block in handlers:
        name = block.split("def ", 1)[1].split("(", 1)[0]
        touches_findings = any(token in block for token in
                               ("Finding", "SlaEvent", "breach_summary", "evaluate_findings"))
        if touches_findings:
            # Two acceptable answers, and no third one. Either the route narrows
            # what it reads, or it declares the action estate-wide and refuses a
            # scoped caller outright. Silently serving the estate is the defect.
            narrowed = "scope" in block
            refused = "_estate_only(" in block
            assert narrowed or refused, (
                f"route {name}() touches finding-level rows without narrowing them "
                f"or declaring itself estate-wide"
            )


def test_the_view_filter_has_exactly_one_implementation():
    """`reports.py` must delegate, not keep a second copy of the lookup."""
    reports = (BACKEND / "api" / "v1" / "reports.py").read_text()
    assert "resolve_view" in reports
    assert "session.get(Team" not in reports


def test_the_console_no_longer_hides_the_widget_under_a_filter():
    """The workaround is gone with the defect; leaving it would be a silent gap."""
    console = BACKEND.parents[1] / "frontend" / "console" / "app.js"
    text = console.read_text()
    assert "get('/policies/sla/summary' + q)" in text
    assert "teamId ? Promise.resolve({})" not in text
