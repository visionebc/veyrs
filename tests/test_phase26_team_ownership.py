"""Phase 26 - assets and findings divide by team, and the division is usable.

The gap this closes: every ownership column already existed in the schema
(`Asset.team_id`, `Finding.assigned_team_id`, `AssignmentRule`) and none of it
could be *reached*. `GET /assets` had no team filter, list responses returned
raw UUIDs, and there was no way to move more than one row at a time.

Two behaviours here are load-bearing and would look like bugs if changed:

* a finding with no explicit assignment is still owned -- by the team that owns
  its asset. Filtering on `assigned_team_id` alone answers "this team has no
  work" for an estate that is fully owned;
* `my_teams` for an identity with no memberships returns NOTHING, not
  everything. Failing open on a scoping filter is the failure mode the whole
  feature exists to prevent.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Asset, Cve, Finding, FindingEvent, Vulnerability
from veyrs.models.tenancy import Team

from conftest import login


# ---------------------------------------------------------------------------
# fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def estate(org_a):
    """Two teams, three assets (two owned, one orphan) and one finding each."""
    org_id, slug, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        netops = Team(organization_id=org_id, name="Redes", slug=f"redes-{uuid.uuid4().hex[:6]}")
        appsec = Team(organization_id=org_id, name="Aplicaciones",
                      slug=f"apps-{uuid.uuid4().hex[:6]}")
        session.add_all([netops, appsec])
        session.flush()

        made = {}
        for label, team in (("net", netops), ("app", appsec), ("orphan", None)):
            cve_id = f"CVE-2026-{uuid.uuid4().int % 90000 + 9000}"
            session.merge(Cve(id=cve_id, source="test", title=f"{label} fixture"))
            asset = Asset(organization_id=org_id, name=f"{label}-{uuid.uuid4().hex[:8]}",
                          team_id=team.id if team else None)
            vulnerability = Vulnerability(organization_id=org_id, cve_id=cve_id,
                                          title=f"{label} vulnerability")
            session.add_all([asset, vulnerability])
            session.flush()
            finding = Finding(organization_id=org_id, asset_id=asset.id,
                              vulnerability_id=vulnerability.id, state="new",
                              dedupe_key=uuid.uuid4().hex, title=f"{label} finding")
            session.add(finding)
            session.flush()
            made[label] = {"asset": asset.id, "finding": finding.id}
        session.commit()
        yield {"org_id": org_id, "slug": slug, "netops": netops.id,
               "appsec": appsec.id, **made}


# ---------------------------------------------------------------------------
# 1. assets divide by team
# ---------------------------------------------------------------------------
def test_assets_filter_by_team(client, admin_a, estate):
    body = client.get(f"/api/v1/assets?team_id={estate['netops']}",
                      headers=admin_a).json()
    assert [item["id"] for item in body["items"]] == [str(estate["net"]["asset"])]


def test_assets_can_list_the_ones_nobody_owns(client, admin_a, estate):
    """The orphan bucket is the antidote to scoping: unowned means invisible."""
    body = client.get("/api/v1/assets?unowned=true", headers=admin_a).json()
    ids = {item["id"] for item in body["items"]}
    assert str(estate["orphan"]["asset"]) in ids
    assert str(estate["net"]["asset"]) not in ids


def test_asset_list_carries_the_team_name_not_only_its_uuid(client, admin_a, estate):
    body = client.get(f"/api/v1/assets?team_id={estate['netops']}", headers=admin_a).json()
    assert body["items"][0]["team_name"] == "Redes"


def test_asset_detail_also_carries_the_label(client, admin_a, estate):
    body = client.get(f"/api/v1/assets/{estate['net']['asset']}", headers=admin_a).json()
    assert body["team_name"] == "Redes" and body["department_name"] is None


# ---------------------------------------------------------------------------
# 2. bulk ownership
# ---------------------------------------------------------------------------
def test_bulk_assign_moves_many_assets_at_once(client, admin_a, estate):
    response = client.post("/api/v1/assets/bulk-assign", headers=admin_a, json={
        "asset_ids": [str(estate["net"]["asset"]), str(estate["orphan"]["asset"])],
        "team_id": str(estate["appsec"]),
    })
    assert response.status_code == 200 and response.json()["changed_count"] == 2
    body = client.get(f"/api/v1/assets?team_id={estate['appsec']}", headers=admin_a).json()
    assert body["total"] == 3


def test_clearing_ownership_needs_the_explicit_clear_list(client, admin_a, estate):
    """`team_id: null` is indistinguishable from an omitted field, so it is a no-op."""
    silent = client.post("/api/v1/assets/bulk-assign", headers=admin_a, json={
        "asset_ids": [str(estate["net"]["asset"])], "team_id": None,
    })
    assert silent.status_code == 422          # nothing to assign, rather than a silent orphan

    explicit = client.post("/api/v1/assets/bulk-assign", headers=admin_a, json={
        "asset_ids": [str(estate["net"]["asset"])], "clear": ["team_id"],
    })
    assert explicit.status_code == 200
    body = client.get(f"/api/v1/assets/{estate['net']['asset']}", headers=admin_a).json()
    assert body["team_id"] is None


def test_a_team_from_another_tenant_is_refused_before_anything_is_written(
    client, admin_a, admin_b, estate
):
    foreign = client.post("/api/v1/teams", headers=admin_b,
                          json={"name": "Otro", "slug": f"otro-{uuid.uuid4().hex[:6]}"}).json()
    response = client.post("/api/v1/assets/bulk-assign", headers=admin_a, json={
        "asset_ids": [str(estate["net"]["asset"])], "team_id": foreign["id"],
    })
    assert response.status_code == 422
    still = client.get(f"/api/v1/assets/{estate['net']['asset']}", headers=admin_a).json()
    assert still["team_id"] == str(estate["netops"])


def test_unknown_assets_are_reported_per_id_not_as_a_failed_batch(client, admin_a, estate):
    response = client.post("/api/v1/assets/bulk-assign", headers=admin_a, json={
        "asset_ids": [str(estate["net"]["asset"]), str(uuid.uuid4())],
        "team_id": str(estate["appsec"]),
    })
    body = response.json()
    assert body["changed_count"] == 1 and body["rejected_count"] == 1


# ---------------------------------------------------------------------------
# 3. findings inherit ownership from their asset
# ---------------------------------------------------------------------------
def test_the_team_queue_finds_work_that_was_never_explicitly_assigned(
    client, admin_a, estate
):
    """The defect this prevents: `assigned_team_id` is NULL on most findings."""
    assigned = client.get(f"/api/v1/findings?assigned_team_id={estate['netops']}",
                          headers=admin_a).json()
    assert assigned["total"] == 0                       # nothing was ever assigned

    owned = client.get(f"/api/v1/findings?owning_team_id={estate['netops']}",
                       headers=admin_a).json()
    assert [item["id"] for item in owned["items"]] == [str(estate["net"]["finding"])]
    assert owned["items"][0]["owning_team_name"] == "Redes"


def test_findings_with_no_owner_anywhere_can_be_listed(client, admin_a, estate):
    body = client.get("/api/v1/findings?unowned=true", headers=admin_a).json()
    assert str(estate["orphan"]["finding"]) in {item["id"] for item in body["items"]}


def test_my_teams_fails_closed_for_an_identity_with_no_memberships(
    client, admin_a, estate
):
    """Returning the whole estate here would be the bug, not the convenience."""
    body = client.get("/api/v1/findings?my_teams=true", headers=admin_a).json()
    assert body["total"] == 0


def test_my_teams_answers_with_the_members_queue(client, admin_a, estate):
    member_email = f"lead-{uuid.uuid4().hex[:8]}@{estate['slug']}.test"
    created = client.post("/api/v1/users", headers=admin_a, json={
        "email": member_email, "full_name": "Team Lead", "password": "Str0ng-Passw0rd!x",
        "role_slugs": ["security-manager"], "team_ids": [str(estate["netops"])],
    })
    assert created.status_code == 201, created.text
    token = login(client, member_email, estate["slug"], "Str0ng-Passw0rd!x")["access_token"]
    headers = {"Authorization": f"Bearer {token}"}
    body = client.get("/api/v1/findings?my_teams=true", headers=headers).json()
    assert [item["id"] for item in body["items"]] == [str(estate["net"]["finding"])]


# ---------------------------------------------------------------------------
# 4. assignment is auditable on the finding itself
# ---------------------------------------------------------------------------
def test_bulk_assign_writes_the_findings_own_history(client, admin_a, estate):
    response = client.post("/api/v1/findings/bulk-assign", headers=admin_a, json={
        "finding_ids": [str(estate["orphan"]["finding"])],
        "assigned_team_id": str(estate["appsec"]),
        "reason": "owner confirmed during triage",
    })
    assert response.status_code == 200 and response.json()["changed_count"] == 1

    with SessionLocal() as session:
        set_tenant(session, estate["org_id"])
        events = session.execute(
            select(FindingEvent).where(
                FindingEvent.finding_id == estate["orphan"]["finding"],
                FindingEvent.event == "assigned",
            )
        ).scalars().all()
        assert len(events) == 1
        assert events[0].details["to"]["assigned_team_id"] == str(estate["appsec"])
        finding = session.get(Finding, estate["orphan"]["finding"])
        assert finding.assignment_reason == "owner confirmed during triage"


def test_an_explicit_assignment_overrides_the_assets_team(client, admin_a, estate):
    client.post("/api/v1/findings/bulk-assign", headers=admin_a, json={
        "finding_ids": [str(estate["net"]["finding"])],
        "assigned_team_id": str(estate["appsec"]),
    })
    netops = client.get(f"/api/v1/findings?owning_team_id={estate['netops']}",
                        headers=admin_a).json()
    assert netops["total"] == 0
    appsec = client.get(f"/api/v1/findings?owning_team_id={estate['appsec']}",
                        headers=admin_a).json()
    assert str(estate["net"]["finding"]) in {item["id"] for item in appsec["items"]}
