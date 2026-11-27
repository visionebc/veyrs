"""Phase 46 -- the risk register, its RACI, and the switch that removes it.

What these tests are actually defending, in the order the defects would appear:

1. the switch is enforced where work is CREATED, not only where it is drawn;
2. there is exactly one Accountable, and it is a person;
3. a person named under a team is really in that team;
4. scores are derived, never accepted;
5. a risk cannot leave the register without a sentence saying why;
6. one tenant's register is invisible to another, reference numbers included.
"""
from __future__ import annotations

import ast
import pathlib
import uuid

import pytest
from sqlalchemy import text

from veyrs.db import SessionLocal, set_tenant
from veyrs.security import permissions as perms
from veyrs.security import scope as team_scope

ROOT = pathlib.Path(__file__).resolve().parents[1]
ROUTER = ROOT / "backend/veyrs/api/v1/risk_register.py"
CONSOLE = ROOT / "frontend/console/app.js"


# --- helpers --------------------------------------------------------------


def make_risk(client, headers, **over):
    payload = {"title": "Single supplier for the payment gateway",
               "category": "third-party", "likelihood": 4, "impact": 5}
    payload.update(over)
    response = client.post("/api/v1/risks", json=payload, headers=headers)
    assert response.status_code == 201, response.text
    return response.json()


def make_user(client, headers, name="Ana Ruiz"):
    response = client.post("/api/v1/users", headers=headers, json={
        "email": f"{uuid.uuid4().hex[:10]}@tenant.test",
        "full_name": name,
        "password": "a-sufficiently-long-password",
    })
    assert response.status_code == 201, response.text
    return response.json()


def make_team(client, headers, name="Platform"):
    response = client.post("/api/v1/teams", headers=headers, json={
        "name": name, "slug": f"{name.lower()}-{uuid.uuid4().hex[:6]}",
    })
    assert response.status_code == 201, response.text
    return response.json()


# --- the switch -----------------------------------------------------------


def test_the_register_is_on_by_default_and_says_so_explicitly(client, admin_a):
    state = client.get("/api/v1/risk-register", headers=admin_a).json()
    assert state["enabled"] is True
    # `explicit` False means nobody chose this -- it is the shipped default.
    # An operator reading "on" is owed that distinction.
    assert state["explicit"] is False
    assert state["entries"] == 0


def test_auth_me_carries_the_flag_so_the_nav_is_painted_once(client, admin_a):
    me = client.get("/api/v1/auth/me", headers=admin_a).json()
    assert me["risk_register_enabled"] is True


def test_turning_it_off_refuses_writes_and_keeps_reads(client, admin_a):
    risk = make_risk(client, admin_a)

    off = client.put("/api/v1/risk-register", headers=admin_a, json={
        "risk_register_enabled": False, "reason": "our risks live in the GRC tool",
    })
    assert off.status_code == 200, off.text
    assert off.json()["enabled"] is False
    # The count is reported BEFORE the section disappears: an operator turning
    # the register off is owed the number they are about to hide.
    assert off.json()["entries"] == 1

    # Every creation path refuses -- and with 409, not 403: the caller holds the
    # permission; the tenant is in a state where the request does not apply.
    assert client.post("/api/v1/risks", headers=admin_a,
                       json={"title": "another"}).status_code == 409
    assert client.patch(f"/api/v1/risks/{risk['id']}", headers=admin_a,
                        json={"title": "renamed"}).status_code == 409
    assert client.put(f"/api/v1/risks/{risk['id']}/raci", headers=admin_a,
                      json={"raci": []}).status_code == 409
    assert client.post(f"/api/v1/risks/{risk['id']}/links", headers=admin_a,
                       json={"object_type": "asset",
                             "object_id": str(uuid.uuid4())}).status_code == 409
    # Deletion too. Turning the module off must not become a quiet way to erase
    # risk records.
    assert client.delete(f"/api/v1/risks/{risk['id']}",
                         headers=admin_a).status_code == 409

    # ... and everything written before the flip is still readable. Entries are
    # evidence; hiding them to tidy a menu is what this assertion forbids.
    assert client.get("/api/v1/risks", headers=admin_a).json()["total"] == 1
    assert client.get(f"/api/v1/risks/{risk['id']}",
                      headers=admin_a).status_code == 200
    assert client.get("/api/v1/risks/summary", headers=admin_a).json()["total"] == 1

    back = client.put("/api/v1/risk-register", headers=admin_a,
                      json={"risk_register_enabled": True})
    assert back.json() == {**back.json(), "enabled": True, "explicit": True}
    assert client.post("/api/v1/risks", headers=admin_a,
                       json={"title": "again"}).status_code == 201


def test_the_flip_is_audited_with_the_counts_at_that_moment(client, admin_a):
    make_risk(client, admin_a)
    client.put("/api/v1/risk-register", headers=admin_a,
               json={"risk_register_enabled": False, "reason": "migrating to Archer"})
    entries = client.get(
        "/api/v1/audit?action=organization.risk_register_changed",
        headers=admin_a,
    ).json()["items"]
    row = entries[0]
    assert row["changes"]["risk_register_enabled"] == [True, False]
    assert row["changes"]["reason"] == "migrating to Archer"
    assert row["changes"]["entries"] == 1


def test_no_write_route_can_reach_the_database_without_the_guard():
    """AST, not grep: a call inside a comment or a renamed import passes grep.

    Every route that mutates must go through `_guard_write`, which is where both
    the switch and the team-scope refusal live. A fourth write route added later
    without it would turn the switch into decoration for that one path, and
    nothing on screen would look different.
    """
    tree = ast.parse(ROUTER.read_text())
    mutating = []
    for node in tree.body:
        if not isinstance(node, ast.FunctionDef):
            continue
        for dec in node.decorator_list:
            func = dec.func if isinstance(dec, ast.Call) else dec
            if isinstance(func, ast.Attribute) and func.attr in {"post", "patch",
                                                                 "put", "delete"}:
                mutating.append(node)
    assert len(mutating) >= 5, "expected the five write routes"
    for node in mutating:
        calls = {
            n.func.id for n in ast.walk(node)
            if isinstance(n, ast.Call) and isinstance(n.func, ast.Name)
        }
        assert "_guard_write" in calls, f"{node.name} does not call _guard_write"


def test_the_router_tag_is_classified_in_the_scope_policy():
    """An unclassified tag is refused outright for a restricted identity.

    `enforce_route_policy` fails closed, so forgetting to classify a new router
    does not leak -- it 403s every team-scoped user with a message about the
    endpoint not being scope aware, which reads as a bug in the wrong place.
    """
    assert "risk register" in team_scope.SCOPED_TAGS
    assert "risk register" not in team_scope.EXEMPT_TAGS
    assert "risk register" not in team_scope.REFUSED_TAGS


# --- RACI: the invariants the module exists for ---------------------------


def test_a_person_inside_a_team_is_the_normal_case(client, admin_a):
    risk = make_risk(client, admin_a)
    team = make_team(client, admin_a)
    user = make_user(client, admin_a)
    assert client.post(f"/api/v1/teams/{team['id']}/members/{user['id']}",
                       headers=admin_a).status_code == 204

    response = client.put(f"/api/v1/risks/{risk['id']}/raci", headers=admin_a, json={
        "raci": [
            {"raci": "A", "party_type": "user", "user_id": user["id"],
             "team_id": team["id"], "note": "signs off the exit plan"},
            {"raci": "R", "party_type": "team", "team_id": team["id"]},
        ]
    })
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["accountable"] == "Ana Ruiz"
    assert body["responsible"] == [team["name"]]
    seat = next(s for s in body["raci"] if s["raci"] == "A")
    assert seat["team_name"] == team["name"] and seat["user_name"] == "Ana Ruiz"
    assert seat["raci_label"] == "Accountable"


def test_a_person_cannot_be_seated_under_a_team_they_are_not_in(client, admin_a):
    risk = make_risk(client, admin_a)
    team = make_team(client, admin_a, "Network")
    user = make_user(client, admin_a, "Bea Soto")
    # Deliberately NOT a member.
    response = client.put(f"/api/v1/risks/{risk['id']}/raci", headers=admin_a, json={
        "raci": [{"raci": "A", "party_type": "user", "user_id": user["id"],
                  "team_id": team["id"]}]
    })
    assert response.status_code == 422
    assert "not a member" in response.json()["detail"]


def test_accountable_is_one_named_person_never_a_team(client, admin_a):
    risk = make_risk(client, admin_a)
    team = make_team(client, admin_a, "SecOps")
    response = client.put(f"/api/v1/risks/{risk['id']}/raci", headers=admin_a, json={
        "raci": [{"raci": "A", "party_type": "team", "team_id": team["id"]}]
    })
    assert response.status_code == 422
    assert "one named person" in response.json()["detail"]
    # ... and the same team is perfectly acceptable as Responsible.
    ok = client.put(f"/api/v1/risks/{risk['id']}/raci", headers=admin_a, json={
        "raci": [{"raci": "R", "party_type": "team", "team_id": team["id"]}]
    })
    assert ok.status_code == 200


def test_two_accountables_are_refused(client, admin_a):
    risk = make_risk(client, admin_a)
    one, two = make_user(client, admin_a, "Uno"), make_user(client, admin_a, "Dos")
    response = client.put(f"/api/v1/risks/{risk['id']}/raci", headers=admin_a, json={
        "raci": [{"raci": "A", "party_type": "user", "user_id": one["id"]},
                 {"raci": "A", "party_type": "user", "user_id": two["id"]}]
    })
    assert response.status_code == 422
    assert "exactly one Accountable" in response.json()["detail"]


def test_one_accountable_is_enforced_by_the_database_too():
    """The service is not the only writer in this schema's future.

    An import, a script, or a workflow action bypassing the service would be
    able to create the committee the whole module refuses -- unless the database
    itself says no. This asserts the partial unique index exists and covers
    exactly `raci = 'A'`.
    """
    with SessionLocal() as session:
        definition = session.execute(text(
            "select indexdef from pg_indexes "
            "where indexname = 'uq_risk_register_one_accountable'"
        )).scalar_one_or_none()
    assert definition, "the one-Accountable index is missing"
    assert "UNIQUE" in definition
    assert "risk_id" in definition
    assert "'A'" in definition


def test_the_same_party_cannot_hold_the_same_seat_twice(client, admin_a):
    risk = make_risk(client, admin_a)
    team = make_team(client, admin_a, "Dup")
    response = client.put(f"/api/v1/risks/{risk['id']}/raci", headers=admin_a, json={
        "raci": [{"raci": "C", "party_type": "team", "team_id": team["id"]},
                 {"raci": "C", "party_type": "team", "team_id": team["id"]}]
    })
    assert response.status_code == 422
    assert "twice" in response.json()["detail"]


def test_the_matrix_is_replaced_whole_and_the_change_is_in_the_history(client, admin_a):
    risk = make_risk(client, admin_a)
    first = make_user(client, admin_a, "Primera")
    second = make_user(client, admin_a, "Segunda")
    client.put(f"/api/v1/risks/{risk['id']}/raci", headers=admin_a, json={
        "raci": [{"raci": "A", "party_type": "user", "user_id": first["id"]}]})
    body = client.put(f"/api/v1/risks/{risk['id']}/raci", headers=admin_a, json={
        "raci": [{"raci": "A", "party_type": "user", "user_id": second["id"]}]}).json()
    assert body["accountable"] == "Segunda"
    assert len(body["raci"]) == 1
    assert any(e["event"] == "raci_changed" for e in body["events"])


def test_a_party_from_another_tenant_is_not_found(client, admin_a, admin_b):
    risk = make_risk(client, admin_a)
    stranger = make_user(client, admin_b, "Otro Inquilino")
    response = client.put(f"/api/v1/risks/{risk['id']}/raci", headers=admin_a, json={
        "raci": [{"raci": "R", "party_type": "user", "user_id": stranger["id"]}]})
    assert response.status_code == 422
    assert "not found in this organization" in response.json()["detail"]


# --- scoring, status, references -----------------------------------------


def test_the_score_is_derived_and_cannot_be_sent(client, admin_a):
    risk = make_risk(client, admin_a, likelihood=4, impact=5)
    assert risk["score"] == 20 and risk["band"] == "critical"
    # Residual stays empty rather than copying the inherent values: "we have not
    # looked yet" and "the controls changed nothing" must not render alike.
    assert risk["residual_score"] is None and risk["residual_band"] is None

    refused = client.patch(f"/api/v1/risks/{risk['id']}", headers=admin_a,
                           json={"score": 3})
    assert refused.status_code == 422, "a derived field must not be silently dropped"

    lowered = client.patch(f"/api/v1/risks/{risk['id']}", headers=admin_a,
                           json={"residual_likelihood": 2, "residual_impact": 2}).json()
    assert lowered["residual_score"] == 4 and lowered["residual_band"] == "low"
    assert lowered["score"] == 20, "treating a risk must not rewrite its inherent score"


def test_closing_needs_a_reason(client, admin_a):
    risk = make_risk(client, admin_a)
    refused = client.patch(f"/api/v1/risks/{risk['id']}", headers=admin_a,
                           json={"status": "closed"})
    assert refused.status_code == 422
    assert "closure note" in refused.json()["detail"]

    closed = client.patch(f"/api/v1/risks/{risk['id']}", headers=admin_a, json={
        "status": "closed", "closure_note": "supplier replaced, contract signed",
    }).json()
    assert closed["closed_at"] and closed["is_open"] is False

    reopened = client.patch(f"/api/v1/risks/{risk['id']}", headers=admin_a,
                            json={"status": "monitoring"}).json()
    # Open and closed at the same time is a state no report can render.
    assert reopened["closed_at"] is None and reopened["is_open"] is True


def test_reference_numbers_are_per_tenant(client, admin_a, admin_b):
    assert make_risk(client, admin_a)["code"] == "RISK-000001"
    assert make_risk(client, admin_a)["code"] == "RISK-000002"
    # A shared sequence would leak how many risks the other tenant records.
    assert make_risk(client, admin_b)["code"] == "RISK-000001"


def test_one_tenant_cannot_read_anothers_register(client, admin_a, admin_b):
    risk = make_risk(client, admin_a)
    assert client.get(f"/api/v1/risks/{risk['id']}",
                      headers=admin_b).status_code == 404
    assert client.get("/api/v1/risks", headers=admin_b).json()["total"] == 0


# --- links: optional, additive, and validated ----------------------------


def test_a_risk_needs_no_asset_at_all(client, admin_a):
    """The entire reason this module exists, asserted rather than assumed."""
    risk = client.get(f"/api/v1/risks/{make_risk(client, admin_a)['id']}",
                      headers=admin_a).json()
    assert risk["links"] == []
    assert risk["status"] == "identified" and risk["score"] == 20


def test_linking_validates_the_target_and_snapshots_its_name(client, admin_a):
    risk = make_risk(client, admin_a)
    asset = client.post("/api/v1/assets", headers=admin_a, json={
        "name": "pay-gw-01", "asset_type": "server"}).json()

    missing = client.post(f"/api/v1/risks/{risk['id']}/links", headers=admin_a,
                          json={"object_type": "asset", "object_id": str(uuid.uuid4())})
    assert missing.status_code == 422

    body = client.post(f"/api/v1/risks/{risk['id']}/links", headers=admin_a, json={
        "object_type": "asset", "object_id": asset["id"]}).json()
    link = body["links"][0]
    # The label is a snapshot: the register still reads as a sentence after the
    # asset is decommissioned.
    assert link["label"] == "pay-gw-01" and link["object_type"] == "asset"

    # Idempotent: a double-click is not an error worth teaching anybody about.
    again = client.post(f"/api/v1/risks/{risk['id']}/links", headers=admin_a, json={
        "object_type": "asset", "object_id": asset["id"]}).json()
    assert len(again["links"]) == 1

    assert client.delete(f"/api/v1/risks/{risk['id']}/links/{link['id']}",
                         headers=admin_a).status_code == 204


# --- the numbers an operator opens this screen for ------------------------


def test_the_summary_counts_open_risks_with_nobody_accountable(client, admin_a):
    orphan = make_risk(client, admin_a, title="Nobody owns this")
    owned = make_risk(client, admin_a, title="Somebody owns this")
    user = make_user(client, admin_a, "Dueña")
    client.put(f"/api/v1/risks/{owned['id']}/raci", headers=admin_a, json={
        "raci": [{"raci": "A", "party_type": "user", "user_id": user["id"]}]})

    summary = client.get("/api/v1/risks/summary", headers=admin_a).json()
    assert summary["total"] == 2 and summary["open"] == 2
    assert summary["unassigned"] == 1
    assert summary["by_band"]["critical"] == 2

    # ... and a closed risk stops counting as unassigned, because nobody needs
    # chasing for it any more.
    client.patch(f"/api/v1/risks/{orphan['id']}", headers=admin_a,
                 json={"status": "closed", "closure_note": "duplicate"})
    assert client.get("/api/v1/risks/summary",
                      headers=admin_a).json()["unassigned"] == 0


def test_mine_returns_what_i_and_my_teams_are_named_on(client, admin_a, org_a):
    _, slug, email = org_a
    mine = make_risk(client, admin_a, title="Mine")
    make_risk(client, admin_a, title="Somebody else's")
    me = client.get("/api/v1/auth/me", headers=admin_a).json()
    client.put(f"/api/v1/risks/{mine['id']}/raci", headers=admin_a, json={
        "raci": [{"raci": "R", "party_type": "user", "user_id": me["id"]}]})

    listed = client.get("/api/v1/risks?mine=true", headers=admin_a).json()
    assert [i["title"] for i in listed["items"]] == ["Mine"]


def test_deleting_is_soft_so_the_history_survives(client, admin_a, org_a):
    org_id, _, _ = org_a
    risk = make_risk(client, admin_a)
    assert client.delete(f"/api/v1/risks/{risk['id']}",
                         headers=admin_a).status_code == 204
    assert client.get(f"/api/v1/risks/{risk['id']}",
                      headers=admin_a).status_code == 404
    with SessionLocal() as session:
        # `risk_register` is RLS-FORCED: without binding the tenant this query
        # returns ZERO ROWS AND NO ERROR, which reads exactly like a hard
        # delete. Measuring RLS before believing the data is the lesson from
        # the ai_providers pass that "proved" environment A had none.
        set_tenant(session, org_id)
        still_there = session.execute(text(
            "select deleted_at is not null from risk_register where id = :i"
        ), {"i": risk["id"]}).scalar_one()
    assert still_there is True


# --- who may do any of this ----------------------------------------------


@pytest.mark.parametrize("slug,expected", [
    ("security-manager", {"read", "write", "delete"}),
    ("compliance-officer", {"read", "write"}),
    ("executive", {"read", "write"}),
    ("security-engineer", {"read"}),
    ("auditor", {"read"}),
    ("read-only", {"read"}),
    ("service-account", set()),
])
def test_the_register_is_granted_to_the_personas_that_own_it(slug, expected):
    """A new resource, NOT a reuse of `risk:*`.

    `risk:read` means the CVE-derived score on an asset and is held by seven
    built-in roles. Folding the register into it would mean that changing who
    may edit the organisation's risk register silently changes who may see asset
    risk scores, and the reverse -- which is exactly the kind of coupling nobody
    discovers until an auditor asks why a contractor can read the board's risk
    list.
    """
    granted = perms.expand(perms.BUILTIN_ROLES[slug]["permissions"])
    actual = {p.split(":")[1] for p in granted if p.startswith("riskregister:")}
    assert actual == expected
