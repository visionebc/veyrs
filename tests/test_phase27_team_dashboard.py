"""Phase 27 - the dashboards can be read one team at a time.

Phase 26 gave the estate an ownership dimension and an authorization boundary.
This adds the third thing an operator actually asked for: the same dashboards,
narrowed to one team on demand. It is a **view filter**, and the tests here pin
the ways a view filter can quietly become something worse:

* it may only ever **intersect** an authorization scope, never widen it -- a
  restricted principal asking for someone else's team gets 404, the same answer
  the rest of the platform gives for a row it may not see (403 would confirm
  the team exists);
* the payload must keep "filtered" and "restricted" **apart**. Telling an
  administrator their visibility is capped is false; saying nothing at all lets
  one team's figure be read as the estate's. They are two different sentences;
* the filter runs through `TeamScope`, so it reaches every predicate in
  `analytics` -- including the ones added after this was written. A per-endpoint
  `team_id` argument would be correct only where somebody remembered it;
* **unowned rows stay out.** "The platform team's dashboard" must not fold in
  every asset nobody owns; that work is real and is triaged from the estate
  view, which counts it.
"""
from __future__ import annotations

import uuid

from veyrs.db import SessionLocal, set_tenant
from veyrs.models.tenancy import Organization, Team

from test_phase26_scope import PASSWORD, estate  # noqa: F401  (fixture import)

DASHBOARDS = ("executive", "technical", "sla", "trends")


def _get(client, headers, name, team_id=None):
    query = f"?team_id={team_id}" if team_id else ""
    response = client.get(f"/api/v1/dashboard/{name}{query}", headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


# ---------------------------------------------------------------------------
# 1. the filter narrows, and says so
# ---------------------------------------------------------------------------
def test_every_dashboard_accepts_a_team_and_names_it(client, admin_a, estate):
    for name in DASHBOARDS:
        payload = _get(client, admin_a, name, estate["netops"])
        block = payload["scope"]
        assert block["team_filter"]["team_id"] == str(estate["netops"])
        # Named, not a bare UUID: a dashboard headed by an id is how a filtered
        # screenshot ends up filed as an estate figure.
        assert block["team_filter"]["team_name"] == "Redes"


def test_an_unfiltered_dashboard_carries_no_team_filter(client, admin_a, estate):
    for name in DASHBOARDS:
        block = _get(client, admin_a, name)["scope"]
        assert "team_filter" not in block
        assert block["restricted"] is False


def test_the_filter_is_not_reported_as_an_authorization_limit(client, admin_a, estate):
    """An administrator who filters is not a restricted administrator."""
    block = _get(client, admin_a, "executive", estate["netops"])["scope"]
    assert block["restricted"] is False        # their grants still reach the estate
    assert block["team_filter"] is not None    # but this screen shows one team


def test_the_numbers_actually_change(client, admin_a, estate):
    estate_total = _get(client, admin_a, "executive")["totals"]["open_findings"]
    net = _get(client, admin_a, "executive", estate["netops"])["totals"]["open_findings"]
    app = _get(client, admin_a, "executive", estate["appsec"])["totals"]["open_findings"]
    assert net == 1 and app == 1
    # The orphan finding is in the estate figure and in neither team's.
    assert estate_total >= net + app + 1


def test_a_team_filter_excludes_unowned_work(client, admin_a, estate, org_a):
    """Even with `unowned_visible`, one team's dashboard is one team's."""
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        org = session.get(Organization, org_id)
        org.settings = {**(org.settings or {}), "team_scope": {"unowned_visible": True}}
        session.commit()
    try:
        payload = _get(client, admin_a, "executive", estate["netops"])
        assert payload["scope"]["includes_unowned"] is False
        assert payload["totals"]["open_findings"] == 1
    finally:
        with SessionLocal() as session:
            set_tenant(session, org_id)
            org = session.get(Organization, org_id)
            org.settings = {**(org.settings or {}), "team_scope": {}}
            session.commit()


# ---------------------------------------------------------------------------
# 2. it can only ever intersect an authorization scope
# ---------------------------------------------------------------------------
def test_a_scoped_identity_cannot_filter_to_a_team_it_may_not_see(client, estate):
    for name in DASHBOARDS:
        response = client.get(f"/api/v1/dashboard/{name}?team_id={estate['appsec']}",
                              headers=estate["scoped"])
        # 404, never 403: the second confirms the team exists.
        assert response.status_code == 404, (name, response.text)


def test_a_scoped_identity_may_filter_within_its_own_scope(client, estate):
    block = _get(client, estate["scoped"], "executive", estate["netops"])["scope"]
    assert block["restricted"] is True          # still capped by their grants
    assert block["team_filter"]["team_id"] == str(estate["netops"])


def test_an_unknown_team_is_not_found(client, admin_a, estate):
    response = client.get(f"/api/v1/dashboard/executive?team_id={uuid.uuid4()}",
                          headers=admin_a)
    assert response.status_code == 404


def test_another_tenants_team_is_not_found(client, admin_a, org_b):
    org_id, _, _ = org_b
    with SessionLocal() as session:
        set_tenant(session, org_id)
        other = Team(organization_id=org_id, name="Otro",
                     slug=f"otro-{uuid.uuid4().hex[:6]}")
        session.add(other)
        session.commit()
        team_id = other.id
    response = client.get(f"/api/v1/dashboard/executive?team_id={team_id}",
                          headers=admin_a)
    assert response.status_code == 404


def test_a_malformed_team_id_is_rejected(client, admin_a):
    assert client.get("/api/v1/dashboard/executive?team_id=not-a-uuid",
                      headers=admin_a).status_code == 422


# ---------------------------------------------------------------------------
# 3. what the filter must NOT reach
# ---------------------------------------------------------------------------
def test_report_exports_are_still_estate_wide(client, admin_a, estate):
    """Exports outlive the context that would explain their scope, so they take
    no team. A stray `team_id` must be ignored, not honoured silently."""
    filtered = client.get(f"/api/v1/reports/asset-register?team_id={estate['netops']}",
                          headers=admin_a)
    plain = client.get("/api/v1/reports/asset-register", headers=admin_a)
    assert filtered.status_code == 200 and plain.status_code == 200
    assert "team_filter" not in filtered.text
    # An unknown query parameter must not silently shrink the register.
    assert len(filtered.json().get("rows", [])) == len(plain.json().get("rows", []))
