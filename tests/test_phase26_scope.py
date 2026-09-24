"""Phase 26b - team segregation: a scoped identity sees its teams and no more.

The properties here are the feature. Each of them is a way the segregation
could look like it works while leaking, or look like it leaks while working:

* out of scope answers **404, never 403** -- a 403 confirms the row exists;
* a finding is scoped by its **effective** owner (assignment, else the asset's
  team), not by `assigned_team_id`, which is NULL on most rows;
* **any** estate-wide grant wins. Scoping is opt-in per grant, so nothing that
  exists today changes behaviour;
* unowned rows are invisible by default, and that blind spot is **counted**
  rather than assumed away;
* a router that does not understand the scope is **refused**, not served
  unfiltered. Phase 25 shipped a security guard that never executed; the
  lesson taken was that coverage has to be enforced, not intended;
* every dashboard states its scope, because "0 critical" and "0 critical that
  you can see" are different sentences under the same heading.
"""
from __future__ import annotations

import pathlib
import re
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Asset, Cve, Finding, Vulnerability
from veyrs.models.tenancy import Organization, Team

from conftest import login

PASSWORD = "Str0ng-Passw0rd!x"


def _headers(client, email, slug):
    return {"Authorization": f"Bearer {login(client, email, slug, PASSWORD)['access_token']}"}


@pytest.fixture()
def estate(client, admin_a, org_a):
    """Two teams, one asset+finding each, one owned by nobody."""
    org_id, slug, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        netops = Team(organization_id=org_id, name="Redes", slug=f"redes-{uuid.uuid4().hex[:6]}")
        appsec = Team(organization_id=org_id, name="Apps", slug=f"apps-{uuid.uuid4().hex[:6]}")
        session.add_all([netops, appsec])
        session.flush()
        made = {}
        for label, team in (("net", netops), ("app", appsec), ("orphan", None)):
            cve_id = f"CVE-2026-{uuid.uuid4().int % 90000 + 9000}"
            session.merge(Cve(id=cve_id, source="test", title=label))
            asset = Asset(organization_id=org_id, name=f"{label}-{uuid.uuid4().hex[:8]}",
                          team_id=team.id if team else None, exposure="internet")
            vulnerability = Vulnerability(organization_id=org_id, cve_id=cve_id,
                                          title=f"{label} vulnerability", severity="critical")
            session.add_all([asset, vulnerability])
            session.flush()
            finding = Finding(organization_id=org_id, asset_id=asset.id,
                              vulnerability_id=vulnerability.id, state="new",
                              dedupe_key=uuid.uuid4().hex, title=f"{label} finding",
                              severity="critical", risk_score=90.0, risk_level="critical")
            session.add(finding)
            session.flush()
            made[label] = {"asset": asset.id, "finding": finding.id,
                           "vulnerability": vulnerability.id}
        session.commit()

    email = f"netops-{uuid.uuid4().hex[:8]}@{slug}.test"
    created = client.post("/api/v1/users", headers=admin_a, json={
        "email": email, "full_name": "Redes Analyst", "password": PASSWORD,
        "role_slugs": ["security-manager"],
        "team_ids": [str(netops.id)], "scope_team_ids": [str(netops.id)],
    })
    assert created.status_code == 201, created.text
    return {"org_id": org_id, "slug": slug, "netops": netops.id, "appsec": appsec.id,
            "scoped": _headers(client, email, slug), "scoped_email": email,
            "scoped_id": created.json()["id"], **made}


# ---------------------------------------------------------------------------
# 1. the scope itself
# ---------------------------------------------------------------------------
def test_a_scoped_identity_reports_its_own_scope(client, estate):
    me = client.get("/api/v1/auth/me", headers=estate["scoped"]).json()
    assert me["scope"]["restricted"] is True
    assert me["scope"]["team_ids"] == [str(estate["netops"])]


def test_an_estate_wide_grant_stays_estate_wide(client, admin_a):
    """Nothing regresses: every grant that exists today has team_id NULL."""
    me = client.get("/api/v1/auth/me", headers=admin_a).json()
    assert me["scope"]["restricted"] is False


def test_one_unscoped_grant_anywhere_wins(client, admin_a, estate):
    """Mixed grants are estate-wide. A partial narrowing is not a narrowing."""
    email = f"mixed-{uuid.uuid4().hex[:8]}@{estate['slug']}.test"
    client.post("/api/v1/users", headers=admin_a, json={
        "email": email, "full_name": "Mixed", "password": PASSWORD,
        "role_slugs": ["security-manager"], "scope_team_ids": [str(estate["netops"])],
    })
    # a second, unscoped grant of another role
    client.post("/api/v1/users", headers=admin_a, json={
        "email": f"x{email}", "full_name": "Estate", "password": PASSWORD,
        "role_slugs": ["security-manager"],
    })
    assert client.get("/api/v1/auth/me",
                      headers=_headers(client, f"x{email}", estate["slug"])
                      ).json()["scope"]["restricted"] is False


# ---------------------------------------------------------------------------
# 2. assets and findings
# ---------------------------------------------------------------------------
def test_assets_outside_the_scope_are_not_listed(client, estate):
    body = client.get("/api/v1/assets", headers=estate["scoped"]).json()
    ids = {item["id"] for item in body["items"]}
    assert ids == {str(estate["net"]["asset"])}


def test_an_asset_outside_the_scope_answers_404_not_403(client, estate):
    """403 would confirm the row exists -- the one fact segregation must hide."""
    response = client.get(f"/api/v1/assets/{estate['app']['asset']}", headers=estate["scoped"])
    assert response.status_code == 404


def test_findings_are_scoped_by_their_effective_owner(client, estate):
    """No finding here was ever explicitly assigned; ownership comes from the asset."""
    body = client.get("/api/v1/findings", headers=estate["scoped"]).json()
    assert {item["id"] for item in body["items"]} == {str(estate["net"]["finding"])}


def test_a_finding_outside_the_scope_cannot_be_transitioned(client, estate):
    response = client.post(
        f"/api/v1/findings/{estate['app']['finding']}/transition",
        headers=estate["scoped"], json={"state": "triaged"},
    )
    assert response.status_code == 404


def test_bulk_transition_silently_skips_what_it_cannot_see(client, estate):
    response = client.post("/api/v1/findings/bulk-transition", headers=estate["scoped"], json={
        "finding_ids": [str(estate["net"]["finding"]), str(estate["app"]["finding"])],
        "state": "triaged",
    })
    body = response.json()
    assert body["changed"] == [str(estate["net"]["finding"])]
    assert body["rejected"] == [str(estate["app"]["finding"])]


def test_a_vulnerability_with_no_visible_finding_is_not_listed(client, estate):
    body = client.get("/api/v1/vulnerabilities", headers=estate["scoped"]).json()
    ids = {item["id"] for item in body["items"]}
    assert str(estate["net"]["vulnerability"]) in ids
    assert str(estate["app"]["vulnerability"]) not in ids


def test_a_vulnerability_roll_up_outside_the_scope_answers_404(client, estate):
    response = client.get(f"/api/v1/vulnerabilities/{estate['app']['vulnerability']}",
                          headers=estate["scoped"])
    assert response.status_code == 404


# ---------------------------------------------------------------------------
# 3. the unowned blind spot -- measured, not assumed away
# ---------------------------------------------------------------------------
def test_unowned_rows_are_invisible_by_default(client, estate):
    body = client.get("/api/v1/assets", headers=estate["scoped"]).json()
    assert str(estate["orphan"]["asset"]) not in {item["id"] for item in body["items"]}


def test_the_blind_spot_is_counted_rather_than_hidden(client, estate):
    body = client.get("/api/v1/auth/me/scope", headers=estate["scoped"]).json()
    assert body["unowned"]["assets"]["unowned"] >= 1
    assert body["warning"] is not None


def test_an_organization_may_choose_to_share_the_unowned_bucket(client, estate):
    with SessionLocal() as session:
        set_tenant(session, estate["org_id"])
        org = session.get(Organization, estate["org_id"])
        org.settings = {**(org.settings or {}), "team_scope": {"unowned_visible": True}}
        session.commit()
    headers = _headers(client, estate["scoped_email"], estate["slug"])  # scope is re-read per token
    ids = {item["id"] for item in client.get("/api/v1/assets", headers=headers).json()["items"]}
    assert {str(estate["net"]["asset"]), str(estate["orphan"]["asset"])} <= ids


# ---------------------------------------------------------------------------
# 4. ownership cannot be used to escape the scope
# ---------------------------------------------------------------------------
def test_a_scoped_identity_cannot_hand_an_asset_to_a_team_it_cannot_see(client, estate):
    """Otherwise segregation is a one-way door you can walk yourself through."""
    response = client.post("/api/v1/assets/bulk-assign", headers=estate["scoped"], json={
        "asset_ids": [str(estate["net"]["asset"])], "team_id": str(estate["appsec"]),
    })
    assert response.status_code == 403


def test_a_scoped_identity_cannot_route_work_out_of_its_scope(client, estate):
    response = client.post("/api/v1/findings/bulk-assign", headers=estate["scoped"], json={
        "finding_ids": [str(estate["net"]["finding"])],
        "assigned_team_id": str(estate["appsec"]),
    })
    assert response.status_code == 403


def test_an_administrator_cannot_scope_themselves(client, admin_a, estate):
    me = client.get("/api/v1/auth/me", headers=admin_a).json()
    response = client.put(f"/api/v1/users/{me['id']}/scope", headers=admin_a,
                          json={"team_ids": [str(estate["netops"])]})
    assert response.status_code == 422


def test_scope_can_be_restored_estate_wide(client, admin_a, estate):
    response = client.put(f"/api/v1/users/{estate['scoped_id']}/scope",
                          headers=admin_a, json={"team_ids": []})
    assert response.status_code == 200 and response.json()["restricted"] is False
    headers = _headers(client, estate["scoped_email"], estate["slug"])
    assert client.get("/api/v1/auth/me", headers=headers).json()["scope"]["restricted"] is False


# ---------------------------------------------------------------------------
# 5. routers that do not understand the scope are refused, not served
# ---------------------------------------------------------------------------
def test_an_estate_wide_router_is_refused_rather_than_served_unfiltered(client, estate):
    response = client.get("/api/v1/agents", headers=estate["scoped"])
    assert response.status_code == 403
    assert "whole estate" in response.json()["detail"]


def test_report_exports_are_refused_for_a_scoped_identity(client, estate):
    catalogue = client.get("/api/v1/reports", headers=estate["scoped"]).json()
    slug = next(r["slug"] for r in catalogue["reports"] if r["available"])
    response = client.get(f"/api/v1/reports/{slug}/export?format=json", headers=estate["scoped"])
    assert response.status_code == 403
    assert "whole estate" in response.json()["detail"]


# ---------------------------------------------------------------------------
# 6. dashboards say what they are showing
# ---------------------------------------------------------------------------
def test_the_executive_dashboard_is_narrowed_and_says_so(client, admin_a, estate):
    whole = client.get("/api/v1/dashboard/executive", headers=admin_a).json()
    narrow = client.get("/api/v1/dashboard/executive", headers=estate["scoped"]).json()
    assert whole["scope"]["restricted"] is False
    assert narrow["scope"] == {"restricted": True, "teams": 1,
                               "team_ids": [str(estate["netops"])],
                               "includes_unowned": False}
    assert narrow["totals"]["open_findings"] < whole["totals"]["open_findings"]
    assert narrow["totals"]["assets"] == 1


def test_the_sla_dashboard_carries_the_same_marker(client, estate):
    body = client.get("/api/v1/dashboard/sla", headers=estate["scoped"]).json()
    assert body["scope"]["restricted"] is True


def test_the_scope_survives_a_query_that_already_joins_assets(client, estate):
    """Regression: `?exposure=` joins Asset, and the ownership subquery used to
    auto-correlate it away -- "no FROM clauses due to auto-correlation", a 500
    on exactly the queries a scoped user runs most. See `teams.owning_team()`.
    """
    response = client.get("/api/v1/findings?exposure=internet", headers=estate["scoped"])
    assert response.status_code == 200
    assert {item["id"] for item in response.json()["items"]} == {str(estate["net"]["finding"])}


# ---------------------------------------------------------------------------
# 7. the structural guard
# ---------------------------------------------------------------------------
def test_no_analytics_query_bypasses_the_scope_helpers():
    """A new unscoped query in analytics.py fails here, not in production.

    Threading a scope through fifteen functions works exactly until someone adds
    the sixteenth. This asserts on the source, because the alternative is
    noticing the day a dashboard quietly reports someone else's estate.
    """
    source = pathlib.Path(
        "/opt/veyrs/backend/veyrs/services/analytics.py"
    ).read_text()
    body = source.split("def _scope_block(", 1)[1]
    offenders = re.findall(
        r"(?:Finding|Asset|Ticket|RiskScoreHistory)\.organization_id\s*==\s*org_id", body
    )
    assert offenders == [], (
        f"{len(offenders)} analytics query/queries filter on organization_id directly; "
        "use _scoped()/_scoped_asset()/_scoped_ticket()/_scoped_history()"
    )
