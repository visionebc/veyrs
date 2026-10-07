"""Phase 36 - the disposition half: triage, saved views, digest, palette.

The measurement this round started from, taken read-only against production:
408 findings (149 never touched, exactly 1 remediated), 5 tickets, 0 risk
acceptances, 0 webhooks, 74 notifications generated and nothing that ever left
the console. The ingestion half works. What did not exist was anywhere to make
a decision, any way to keep the query you make it from, and any reason to come
back tomorrow.

What is pinned here is, as always, the set of ways each piece can be quietly
wrong -- a control that renders perfectly and does nothing:

* **A saved view must not become a second way to ask a question.** It stores a
  query and is replayed as query parameters; an unvalidated blob is a place to
  park a parameter and wait for a future release to start honouring it. So the
  allow-list is asserted against the ACTUAL signatures of the list routes: a
  renamed parameter breaks this file rather than silently producing views that
  filter nothing.
* **The `saved views` tag claims to carry no finding rows.** `policies` made
  that claim falsely until v0.17.1 and `cvss` until v0.21.0. This file reads
  the router's source and asserts it.
* **A digest built once for the estate and fanned out is a leak.** Email
  carries no scope banner, so each recipient's message is built under their own
  scope, and recipients come from PERMISSIONS rather than from team membership.
* **A preview that is assembled separately from the send is a preview that can
  be right while the message is wrong.** One function, both paths -- the same
  discipline `autoticket.matches()` was written with.
* **Nothing is sent to somebody with nothing to say.** A daily "no news" trains
  its reader to delete it unread, and then the one that matters goes too.
"""
from __future__ import annotations

import datetime as dt
import inspect
import pathlib
import re
import uuid

import pytest
from sqlalchemy import select

from veyrs.api.v1 import assets as assets_api, findings as findings_api, tickets as tickets_api
from veyrs.api.v1 import integrations as integrations_api
from veyrs.api.v1 import views as views_api
from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    Asset, Finding, Notification, NotificationPreference, Organization, SavedView,
    Vulnerability, VIEW_ENTITIES,
)
from veyrs.models.tenancy import User
from veyrs.security import scope as team_scope
from veyrs.services import digest, notifications as notify_service, views as view_service

ROOT = pathlib.Path(__file__).resolve().parents[1]
VIEWS_ROUTER = ROOT / "backend" / "veyrs" / "api" / "v1" / "views.py"
APP_JS = ROOT / "frontend" / "console" / "app.js"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------


def _finding(session, org_id, *, severity="critical", state="new", risk=91.0,
             kev=False, breached=False, detected=None, title=None):
    asset = Asset(organization_id=org_id, name=f"host-{uuid.uuid4().hex[:8]}",
                  asset_type="server", criticality="high", exposure="internet",
                  environment="production")
    session.add(asset)
    session.flush()
    vuln = Vulnerability(organization_id=org_id, title="v", severity=severity,
                         internal_ref=f"INT-{uuid.uuid4().hex[:8]}")
    session.add(vuln)
    session.flush()
    row = Finding(
        organization_id=org_id, asset_id=asset.id, vulnerability_id=vuln.id,
        title=title or f"finding-{uuid.uuid4().hex[:6]}", severity=severity, state=state,
        dedupe_key=uuid.uuid4().hex,
        risk_score=risk, kev=kev, sla_breached=breached,
        detected_at=detected or dt.datetime.now(dt.timezone.utc),
    )
    session.add(row)
    session.flush()
    return row


def _query_params(fn) -> set[str]:
    """The names a FastAPI route actually accepts, minus its dependencies."""
    skip = {"session", "principal", "request", "payload", "response", "_"}
    return {name for name in inspect.signature(fn).parameters if name not in skip}


# ---------------------------------------------------------------------------
# 1. the allow-list is a claim about real routes
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("entity, route", [
    ("findings", findings_api.list_findings),
    ("vulnerabilities", findings_api.list_vulnerabilities),
    ("tickets", tickets_api.list_tickets),
    ("assets", assets_api.list_assets),
    ("issues", integrations_api.list_links),
])
def test_every_allowed_filter_is_a_real_query_parameter(entity, route):
    """A view that filters on a parameter the route ignores filters nothing.

    It also returns 200 and a full list, so the operator reads it as "no
    matches were excluded" rather than as a broken view.
    """
    accepted = _query_params(route)
    unknown = view_service.ALLOWED_FILTERS[entity] - accepted
    assert not unknown, f"{entity} view allows {sorted(unknown)}, which {route.__name__} ignores"


def test_paging_is_not_saveable():
    """A view pinned to page 3 shows nothing the day the queue gets shorter."""
    for entity, allowed in view_service.ALLOWED_FILTERS.items():
        assert not ({"page", "size", "limit", "offset"} & allowed), entity


def test_every_entity_has_an_allow_list():
    assert set(view_service.ALLOWED_FILTERS) == set(VIEW_ENTITIES)


# ---------------------------------------------------------------------------
# 2. normalisation refuses rather than drops
# ---------------------------------------------------------------------------


def test_unknown_filter_is_rejected_not_silently_dropped():
    with pytest.raises(view_service.SavedViewError) as exc:
        view_service.normalise_filters("findings", {"severity": "critical", "sql": "1=1"})
    assert "sql" in str(exc.value)


def test_booleans_become_url_text_and_empties_disappear():
    out = view_service.normalise_filters(
        "findings", {"kev": True, "sla_breached": False, "q": "", "severity": None})
    assert out == {"kev": "true", "sla_breached": "false"}


def test_a_filter_cannot_be_a_nested_object():
    with pytest.raises(view_service.SavedViewError):
        view_service.normalise_filters("findings", {"severity": {"$ne": "low"}})


def test_entity_must_be_known():
    with pytest.raises(view_service.SavedViewError):
        view_service.normalise_filters("payroll", {})


# ---------------------------------------------------------------------------
# 3. the API
# ---------------------------------------------------------------------------


def test_saved_view_crud(client, admin_a):
    made = client.post("/api/v1/saved-views", headers=admin_a, json={
        "entity": "findings", "name": "Critical + internet",
        "filters": {"severity": "critical", "exposure": "internet"},
    })
    assert made.status_code == 201, made.text
    row = made.json()
    assert row["filters"] == {"severity": "critical", "exposure": "internet"}
    assert row["is_mine"] is True

    listed = client.get("/api/v1/saved-views?entity=findings", headers=admin_a).json()
    assert any(v["id"] == row["id"] for v in listed["items"])

    renamed = client.patch(f"/api/v1/saved-views/{row['id']}", headers=admin_a,
                           json={"name": "Renamed"})
    assert renamed.status_code == 200 and renamed.json()["name"] == "Renamed"

    assert client.delete(f"/api/v1/saved-views/{row['id']}", headers=admin_a).status_code == 204
    after = client.get("/api/v1/saved-views", headers=admin_a).json()
    assert not any(v["id"] == row["id"] for v in after["items"])


def test_a_bad_filter_is_a_422_at_write_time(client, admin_a):
    r = client.post("/api/v1/saved-views", headers=admin_a, json={
        "entity": "findings", "name": "bad", "filters": {"drop_table": "x"}})
    assert r.status_code == 422
    assert "drop_table" in r.text


def test_a_view_cannot_change_entity(client, admin_a):
    row = client.post("/api/v1/saved-views", headers=admin_a, json={
        "entity": "findings", "name": "n", "filters": {"kev": True}}).json()
    r = client.patch(f"/api/v1/saved-views/{row['id']}", headers=admin_a,
                     json={"entity": "assets"})
    assert r.status_code == 422


def test_another_tenant_cannot_see_or_edit_a_view(client, admin_a, admin_b):
    row = client.post("/api/v1/saved-views", headers=admin_a, json={
        "entity": "findings", "name": "mine", "filters": {"kev": True},
        "is_shared": True}).json()
    other = client.get("/api/v1/saved-views", headers=admin_b).json()
    assert not any(v["id"] == row["id"] for v in other["items"])
    # 404, not 403: confirming the id exists is the leak.
    assert client.patch(f"/api/v1/saved-views/{row['id']}", headers=admin_b,
                        json={"name": "hijacked"}).status_code == 404


def test_seed_only_fires_for_a_user_with_nothing(client, admin_a):
    first = client.get("/api/v1/saved-views?seed=true", headers=admin_a).json()
    assert len(first["items"]) == 3, "the three starter queues"
    names = {v["name"] for v in first["items"]}
    client.delete(f"/api/v1/saved-views/{first['items'][0]['id']}", headers=admin_a)
    again = client.get("/api/v1/saved-views?seed=true", headers=admin_a).json()
    # Re-seeding somebody who deleted a starter would be the console arguing
    # with them once a day.
    assert len(again["items"]) == 2
    assert {v["name"] for v in again["items"]} < names


def test_the_starter_views_are_replayable(client, admin_a):
    """Every seeded filter has to survive its own allow-list."""
    items = client.get("/api/v1/saved-views?seed=true", headers=admin_a).json()["items"]
    for v in items:
        assert view_service.normalise_filters(v["entity"], v["filters"]) == v["filters"]


# ---------------------------------------------------------------------------
# 4. the scope classification is a claim about every route
# ---------------------------------------------------------------------------


def test_saved_views_is_exempt_from_team_scope():
    assert "saved views" in team_scope.EXEMPT_TAGS
    assert views_api.router.tags == ["saved views"]


def test_no_route_in_the_views_router_touches_a_finding_or_asset_row():
    """The exemption's whole justification, asserted rather than described.

    `policies` carried this same claim falsely for four releases because
    somebody classified a router by what most of it did.
    """
    source = VIEWS_ROUTER.read_text()
    code = "\n".join(line for line in source.splitlines()
                     if not line.lstrip().startswith("#"))
    for forbidden in ("Finding", "Asset", "Ticket(", "Vulnerability"):
        assert forbidden not in code, (
            f"{forbidden} appears in the saved-views router; the tag is exempt "
            "from team scope on the promise that it never reads tenant rows"
        )


# ---------------------------------------------------------------------------
# 5. the digest
# ---------------------------------------------------------------------------


def test_digest_is_off_by_default(client, admin_a):
    policy = client.get("/api/v1/notifications/digest", headers=admin_a).json()
    assert policy["enabled"] is False
    assert digest.DEFAULT_ENABLED is False


def test_a_disabled_digest_sends_nothing(org_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        result = digest.run(session, org_id)
        assert result["queued"] == 0
        assert "disabled" in result["reason"]


def test_an_empty_digest_is_not_sent(org_a):
    """"Nothing happened" every morning is how the one that matters gets deleted."""
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        digest.set_policy(session, org_id, {"enabled": True})
        session.commit()
        result = digest.run(session, org_id)
        assert result["queued"] == 0
        assert result["skipped_empty"] == result["recipients"] >= 1


def test_a_digest_with_news_reaches_the_admin(org_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        _finding(session, org_id, severity="critical")
        digest.set_policy(session, org_id, {"enabled": True})
        session.commit()
        result = digest.run(session, org_id)
        assert result["queued"] >= 1
        session.commit()
        rows = session.execute(
            select(Notification).where(Notification.organization_id == org_id,
                                       Notification.event == digest.EVENT)
        ).scalars().all()
        assert rows, "the digest must exist as a Notification row, not be fire-and-forget"
        assert "1" in rows[0].subject or "new" in rows[0].body.lower()


def test_preview_and_send_are_the_same_function():
    """Two implementations is how a preview promises 12 and the send makes 300."""
    send_src = inspect.getsource(digest.run)
    assert "build(" in send_src
    preview_src = inspect.getsource(tickets_api.digest_preview)
    assert "digest_service.build(" in preview_src


def test_recipients_come_from_permissions_not_from_membership():
    source = inspect.getsource(digest.recipients)
    assert "effective_permissions" in source
    assert "finding:read" in source
    assert "TeamMember" not in source, (
        "membership answers whose queue this is; grants answer what may be read. "
        "A digest sent on membership mails somebody the estate they just joined."
    )


def test_each_recipient_is_scoped_individually():
    source = inspect.getsource(digest.run)
    assert "resolve_for_user" in source, (
        "one estate digest fanned out to a list is a leak: an email carries no "
        "scope banner to qualify the number in it"
    )


def test_a_restricted_scope_narrows_the_digest(org_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        _finding(session, org_id)
        session.commit()
        wide = digest.build(session, org_id)
        narrow = digest.build(
            session, org_id,
            scope=team_scope.TeamScope(restricted=True, team_ids=frozenset()),
        )
        assert wide["counts"]["new_findings"] >= 1
        assert narrow["counts"]["new_findings"] == 0
        assert narrow["scope"]["restricted"] is True


def test_a_channel_with_no_transport_is_refused(org_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        with pytest.raises(digest.DigestError):
            digest.set_policy(session, org_id, {"channels": ["carrier_pigeon"]})
        with pytest.raises(digest.DigestError):
            digest.set_policy(session, org_id, {"channels": []})


def test_hour_is_validated(org_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        with pytest.raises(digest.DigestError):
            digest.set_policy(session, org_id, {"hour": 25})


def test_due_now_needs_the_hour_and_a_gap():
    now = dt.datetime(2026, 8, 23, 7, 30, tzinfo=dt.timezone.utc)
    policy = {"enabled": True, "hour": 7}
    assert digest.due_now(policy, now=now) is True
    assert digest.due_now({**policy, "hour": 8}, now=now) is False
    assert digest.due_now({**policy, "enabled": False}, now=now) is False
    # A restart inside the same hour must not send it twice.
    just_ran = {**policy, "last_run_at": (now - dt.timedelta(minutes=20)).isoformat()}
    assert digest.due_now(just_ran, now=now) is False
    yesterday = {**policy, "last_run_at": (now - dt.timedelta(days=1)).isoformat()}
    assert digest.due_now(yesterday, now=now) is True


def test_send_now_defaults_to_a_dry_run(client, admin_a):
    r = client.post("/api/v1/notifications/digest/send", headers=admin_a)
    assert r.status_code == 200, r.text
    assert r.json()["dry_run"] is True, (
        "'send now' is not a button you press to find out what it does"
    )


def test_the_digest_policy_is_audited(client, admin_a, org_a):
    org_id, _, _ = org_a
    assert client.put("/api/v1/notifications/digest", headers=admin_a,
                      json={"enabled": True, "hour": 6}).status_code == 200
    from veyrs.models.audit import AuditLog

    with SessionLocal() as session:
        set_tenant(session, org_id)
        rows = session.execute(
            select(AuditLog).where(AuditLog.organization_id == org_id,
                                   AuditLog.action == "digest.policy")
        ).scalars().all()
        assert rows and rows[-1].changes.get("enabled") == {"from": False, "to": True}


# ---------------------------------------------------------------------------
# 6. notification preferences
# ---------------------------------------------------------------------------


def test_preferences_list_every_mutable_event_and_name_the_rest(client, admin_a):
    body = client.get("/api/v1/notifications/preferences", headers=admin_a).json()
    events = {e["event"] for e in body["events"]}
    assert digest.EVENT in events
    assert set(body["unmutable"]) == set(notify_service.UNMUTABLE_EVENTS)
    assert not (events & set(body["unmutable"]))


def test_an_unmutable_event_is_refused_rather_than_written(client, admin_a, org_a):
    org_id, _, _ = org_a
    r = client.put("/api/v1/notifications/preferences", headers=admin_a,
                   json={"event": "sla.breached", "email": False, "in_app": False})
    assert r.status_code == 422
    with SessionLocal() as session:
        set_tenant(session, org_id)
        rows = session.execute(
            select(NotificationPreference).where(
                NotificationPreference.organization_id == org_id,
                NotificationPreference.event == "sla.breached")
        ).scalars().all()
        assert not rows, (
            "a preference row that `_muted` ignores is a switch that stays on: "
            "a control that does nothing is worse than no control"
        )


def test_muting_the_digest_actually_stops_it(org_a, client, admin_a):
    org_id, _, _ = org_a
    assert client.put("/api/v1/notifications/preferences", headers=admin_a,
                      json={"event": digest.EVENT, "email": False,
                            "in_app": False}).status_code == 200
    with SessionLocal() as session:
        set_tenant(session, org_id)
        _finding(session, org_id)
        digest.set_policy(session, org_id, {"enabled": True})
        session.commit()
        # force=True bypasses the enabled flag and the empty check, and MUST NOT
        # bypass a mute: an administrator pressing "send now" is not new
        # information about what this user asked for.
        result = digest.run(session, org_id, force=True)
        assert result["queued"] == 0


# ---------------------------------------------------------------------------
# 7. the console contracts the API actually has
# ---------------------------------------------------------------------------


def _console() -> str:
    return APP_JS.read_text()


def test_the_notifications_list_reads_the_fields_the_api_returns():
    """It read `created_at`/`kind`/`message`; the route returns `at`/`event`/`subject`.

    Three blank columns on every row since the page existed, and a "Mark read"
    button that was never wired. Same family as the Integrations page in
    v0.19.0: renders perfectly, is wrong, never changes a status code.
    """
    src = _console()
    inbox = src[src.index("async function notifInbox"):]
    inbox = inbox[:inbox.index("async function notifPreferences")]
    for field in ("r.at", "r.event", "r.subject", "r.body"):
        assert field in inbox, field
    for stale in ("r.created_at", "r.kind", "r.message"):
        assert stale not in inbox, stale


def test_search_is_flattened_from_results_not_read_as_items():
    """`GET /search` returns `{results: {type: [...]}}` and has never had `items`.

    `pageOf()` on that envelope yields an empty list, so the Search page printed
    "No matches" for searches that matched.
    """
    src = _console()
    assert "function flattenSearch" in src
    page = src[src.index("route('search'"):]
    page = page[:page.index("/* ══ Notifications")]
    assert "flattenSearch(" in page
    assert "pageOf(" not in page


def test_the_triage_assign_maps_the_dialog_onto_the_api():
    """`assignDialog` returns `{team,user,reason}`; the route reads
    `assigned_team_id`. Passing it through unmapped is a 200 that assigns
    nothing."""
    src = _console()
    fn = src[src.index("async function triageAct"):]
    fn = fn[:fn.index("route('triage'")]
    assert "assigned_team_id" in fn
    assert "clear" in fn and "'assigned_team_id'" in fn


def test_accepting_a_risk_from_new_triages_first():
    """`ALLOWED_TRANSITIONS['new']` has no edge to `accepted_risk`.

    149 of production's 408 findings are in `new`, so an Accept button that
    did not know this would 409 on the most common case on the screen.
    """
    from veyrs.models import ALLOWED_TRANSITIONS

    assert "accepted_risk" not in ALLOWED_TRANSITIONS["new"]
    assert "accepted_risk" in ALLOWED_TRANSITIONS["triaged"]
    src = _console()
    fn = src[src.index("async function triageAct"):]
    fn = fn[:fn.index("route('triage'")]
    assert "state: 'triaged'" in fn


def test_the_console_lands_on_the_queue_not_a_dashboard():
    src = _console()
    assert "location.hash = '#/triage'" in src
    assert "'#/dashboard'" not in src.split("async function boot")[1].split("async function enterApp")[0]


def test_the_palette_is_bound_and_permission_filtered():
    src = _console()
    assert "function paletteOpen" in src
    assert "e.key.toLowerCase() === 'k'" in src
    cmds = src[src.index("function paletteCommands"):]
    cmds = cmds[:cmds.index("function flattenSearch")]
    assert "can(item.perm)" in cmds, (
        "the palette must not offer a screen the caller's role cannot open"
    )


def test_the_empty_list_distinguishes_unconfigured_from_over_filtered():
    src = _console()
    assert "function notConfigured" in src
    assert "data.total === 0 && !filtered" in src
    assert "clear the filters" in src


def test_triage_keyboard_yields_to_inputs_and_dialogs():
    """A keystroke that fires while a reason is being typed disposes of the
    finding the operator was explaining."""
    src = _console()
    block = src[src.index("if (navCtx.name !== 'triage') return;"):]
    block = block[:block.index("/* ══ Command palette")]
    assert "TEXTAREA" in block and "INPUT" in block
    assert ".modal-backdrop" in block


def test_no_route_is_registered_twice():
    """Two `route('search')` calls where the second silently wins is a trap."""
    src = _console()
    for name in ("search", "notifications", "triage", "findings", "tickets"):
        assert len(re.findall(rf"route\('{name}'", src)) == 1, name


# ---------------------------------------------------------------------------
# 8. ownership
# ---------------------------------------------------------------------------


def test_a_shared_view_is_visible_to_others_but_only_its_owner_may_edit(org_a, client):
    from tests.conftest import ADMIN_PASSWORD, auth_headers  # noqa: PLC0415

    org_id, slug, email = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        owner = session.execute(
            select(User).where(User.organization_id == org_id)).scalars().first()
        other = User(organization_id=org_id, email=f"second@{slug}.test",
                     full_name="Second", password_hash=owner.password_hash)
        session.add(other)
        session.flush()
        from veyrs.models.tenancy import Role, UserRole

        role = session.execute(
            select(Role).where(Role.slug == "org-admin",
                               Role.organization_id.is_(None))).scalar_one()
        session.add(UserRole(organization_id=org_id, user_id=other.id, role_id=role.id))
        shared = view_service.create(session, org_id, owner.id, entity="findings",
                                     name="Shared", filters={"kev": True}, is_shared=True)
        shared_id = shared.id
        session.commit()

    second = auth_headers(client, f"second@{slug}.test", slug)
    listed = client.get("/api/v1/saved-views", headers=second).json()["items"]
    mine = [v for v in listed if v["id"] == str(shared_id)]
    assert mine and mine[0]["is_mine"] is False
    assert client.delete(f"/api/v1/saved-views/{shared_id}", headers=second).status_code == 404


# ---------------------------------------------------------------------------
# 9. automatic ticketing: require_owner read the wrong column
# ---------------------------------------------------------------------------


def test_require_owner_accepts_the_asset_s_team(org_a):
    """The phase-26 defect in its most expensive form.

    Ownership is an explicit assignment OR the team owning the asset --
    `services.teams.owning_team()` is the whole reason that distinction exists,
    and every queue filters on it. `matches()` read `assigned_team_id` alone,
    and almost nothing carries one: production had 408 findings over 14 fully
    owned assets, and `require_owner` (ON by default) rejected all of them.
    Automatic ticketing could be enabled, report success and create nothing,
    forever, on a completely owned estate.
    """
    from veyrs.models.tenancy import Team
    from veyrs.services import autoticket

    org_id, _, _ = org_a
    policy = {"enabled": True, "min_risk_score": 70.0, "require_owner": True}
    with SessionLocal() as session:
        set_tenant(session, org_id)
        team = Team(organization_id=org_id, slug="platform", name="Platform")
        session.add(team)
        session.flush()
        finding = _finding(session, org_id, risk=95.0)
        asset = session.get(Asset, finding.asset_id)

        assert finding.assigned_team_id is None
        assert autoticket.matches(finding, policy, asset=asset) is False, (
            "an asset with no team is genuinely unowned"
        )

        asset.team_id = team.id
        session.flush()
        assert autoticket.matches(finding, policy, asset=asset) is True

        # An explicit assignment still wins on its own, with no asset loaded.
        asset.team_id = None
        finding.assigned_team_id = team.id
        session.flush()
        assert autoticket.matches(finding, policy, asset=asset) is True
        session.rollback()


def test_the_owner_check_has_exactly_one_implementation():
    """Preview, backfill and the live hook must not disagree about ownership."""
    import inspect as _inspect

    from veyrs.services import autoticket

    source = _inspect.getsource(autoticket)
    body = "\n".join(line for line in source.splitlines()
                     if not line.lstrip().startswith("#") and '"""' not in line)
    assert body.count("assigned_team_id or finding.assigned_user_id") == 1, (
        "the ownership predicate belongs in _has_owner() and nowhere else"
    )
