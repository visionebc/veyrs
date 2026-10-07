"""Phase 38 - the dashboard scope stops being a per-tab accident.

The filter itself shipped in phase 27: `?team_id=` narrows every dashboard,
and the console has offered a picker since. What it never did was *remember*.
Every reload, every fresh browser and every link from an email put the operator
back on the whole estate, so somebody who runs one team re-picked it several
times a day and, on the occasions they forgot, read an estate figure as theirs.

Storing the answer is easy. The ways it goes wrong are not, and this file pins
them:

* a preference is a **default, not an authorization**. Saving a team must not
  widen anything, and reading a dashboard must resolve the scope from scratch
  every time -- so a role change mid-session is obeyed, not overridden by a
  value written before it;
* **`None` is an answer.** "Whole estate" and "never chose" both render the
  same screen, but only the first may overwrite a stored team. `exclude_unset`
  is what keeps them apart, and without it the picker cannot be undone;
* **a stored id can rot.** A team deleted after the preference was saved must
  degrade to the estate view, not 404 the dashboard on every load for the one
  person who happened to have it selected;
* the store is **whitelisted**. A JSONB column reachable by anyone holding a
  session is a blob store unless the keys are fixed;
* it belongs to the **user**, not the browser. Two sessions of the same person
  agree; two people never see each other's.
"""
from __future__ import annotations

import inspect
import uuid

from veyrs.api.v1 import auth as auth_router
from veyrs.db import SessionLocal, set_tenant
from veyrs.models.tenancy import Team, User

from conftest import auth_headers
from test_phase26_scope import estate  # noqa: F401  (fixture import)

PREFS = "/api/v1/auth/me/preferences"


def _get(client, headers):
    response = client.get(PREFS, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def _set(client, headers, body, expect=200):
    response = client.patch(PREFS, headers=headers, json=body)
    assert response.status_code == expect, response.text
    return response.json()


# ---------------------------------------------------------------------------
# 1. it stores, and it comes back where the console reads it
# ---------------------------------------------------------------------------
def test_a_fresh_identity_has_no_remembered_scope(client, admin_a):
    """The estate is the default, and the default is not a stored value."""
    assert _get(client, admin_a) == {"dashboard_team_id": None}


def test_the_choice_survives_a_new_session(client, admin_a, estate, org_a):
    """The point of the profile: another browser, same answer.

    A second *login*, not a second request on the same token -- a value that
    only survives inside one session is what localStorage already did.
    """
    _set(client, admin_a, {"dashboard_team_id": str(estate["appsec"])})
    _org_id, slug, email = org_a
    fresh = auth_headers(client, email, slug)
    assert _get(client, fresh)["dashboard_team_id"] == str(estate["appsec"])


def test_the_identity_payload_carries_it(client, admin_a, estate):
    """`/auth/me` ships it, so the console has it before the first render.

    A second call at boot would let the first dashboard paint under the estate
    scope and then jump -- half a second of figures the operator did not ask
    for, which is the misread this whole screen exists to avoid.
    """
    _set(client, admin_a, {"dashboard_team_id": str(estate["netops"])})
    me = client.get("/api/v1/auth/me", headers=admin_a).json()
    assert me["preferences"]["dashboard_team_id"] == str(estate["netops"])


def test_it_is_a_string_on_the_way_out(client, admin_a, estate):
    """JSONB has no UUID type, and the console compares against `team.id`.

    Returning a value that is a string on read but was a UUID on write is how
    `rows.some(t => t.id === saved)` silently stops matching.
    """
    saved = _set(client, admin_a, {"dashboard_team_id": str(estate["netops"])})
    assert isinstance(saved["dashboard_team_id"], str)
    assert saved["dashboard_team_id"] == str(estate["netops"])


# ---------------------------------------------------------------------------
# 2. "whole estate" is an answer, and it must be sayable
# ---------------------------------------------------------------------------
def test_null_clears_the_remembered_team(client, admin_a, estate):
    _set(client, admin_a, {"dashboard_team_id": str(estate["netops"])})
    assert _set(client, admin_a, {"dashboard_team_id": None}) == {"dashboard_team_id": None}


def test_an_empty_patch_changes_nothing(client, admin_a, estate):
    """The distinction the whole merge rests on.

    `{}` means "I did not mention this key" and must leave it alone;
    `{"dashboard_team_id": null}` means "whole estate" and must clear it. Fold
    the two together and the picker becomes a one-way door.
    """
    _set(client, admin_a, {"dashboard_team_id": str(estate["appsec"])})
    assert _set(client, admin_a, {})["dashboard_team_id"] == str(estate["appsec"])


# ---------------------------------------------------------------------------
# 3. what may not be stored
# ---------------------------------------------------------------------------
def test_an_unknown_team_is_refused(client, admin_a):
    _set(client, admin_a, {"dashboard_team_id": str(uuid.uuid4())}, expect=404)


def test_another_tenants_team_is_not_found(client, admin_a, admin_b, org_b, estate):
    """404, not 403: the second confirms the team exists."""
    org_b_id, _slug, _email = org_b
    with SessionLocal() as session:
        set_tenant(session, org_b_id)
        theirs = Team(organization_id=org_b_id, name="Theirs",
                      slug=f"theirs-{uuid.uuid4().hex[:6]}")
        session.add(theirs)
        session.commit()
        theirs_id = theirs.id
    _set(client, admin_a, {"dashboard_team_id": str(theirs_id)}, expect=404)


def test_an_unknown_key_is_rejected_rather_than_stored(client, admin_a):
    """The column is not a blob store for anyone holding a session."""
    _set(client, admin_a, {"favourite_colour": "blue"}, expect=422)


def test_only_whitelisted_keys_are_ever_served(client, admin_a, estate, org_a):
    """A row that already holds junk does not leak it back through the API."""
    org_id, _slug, email = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        user = session.query(User).filter(User.email == email).one()
        user.preferences = {"dashboard_team_id": str(estate["netops"]),
                            "left_over_from_v9": {"big": "payload"}}
        session.commit()
    served = _get(client, admin_a)
    assert served == {"dashboard_team_id": str(estate["netops"])}


# ---------------------------------------------------------------------------
# 4. a preference is not an authorization
# ---------------------------------------------------------------------------
def test_a_remembered_team_does_not_widen_a_restricted_identity(client, estate):
    """Saving somebody else's team buys nothing.

    It is accepted -- a view filter can only ever intersect the caller's own
    scope, and refusing here would make this route a second, weaker copy of the
    scope check that would then have to be kept in step. What it must not do is
    change a single figure.
    """
    scoped = estate["scoped"]
    _set(client, scoped, {"dashboard_team_id": str(estate["appsec"])})
    payload = client.get(f"/api/v1/dashboard/executive?team_id={estate['appsec']}",
                         headers=scoped)
    # Their grants do not reach appsec, so the filter resolves to a scope that
    # intersects to nothing rather than to somebody else's estate.
    assert payload.status_code in (200, 404), payload.text
    if payload.status_code == 200:
        assert payload.json()["scope"]["restricted"] is True


def test_the_dashboard_still_resolves_scope_per_read(client, admin_a, estate):
    """The stored value is a console default; the API is unchanged.

    Nothing server-side reads the preference to decide a scope. If it ever
    does, a role narrowed at 09:00 would still be answering with a scope
    written at 08:00, and the audit trail would show a read nobody made.
    """
    _set(client, admin_a, {"dashboard_team_id": str(estate["netops"])})
    unfiltered = client.get("/api/v1/dashboard/executive", headers=admin_a).json()
    assert "team_filter" not in unfiltered["scope"]


def test_the_preference_is_per_user_not_per_organization(client, admin_a, estate):
    """Two people in one tenant do not share a dashboard scope."""
    _set(client, admin_a, {"dashboard_team_id": str(estate["netops"])})
    assert _get(client, estate["scoped"])["dashboard_team_id"] is None


# ---------------------------------------------------------------------------
# 5. the console's own guards, read from its source
# ---------------------------------------------------------------------------
def _console() -> str:
    import pathlib
    return (pathlib.Path(__file__).resolve().parents[1]
            / "frontend" / "console" / "app.js").read_text()


def test_the_console_validates_a_saved_team_before_using_it():
    """A team deleted after the save must degrade, not 404 every load.

    The server refuses a dangling id on write, which does not help the row that
    was valid when it was written. Only the console can notice, because only it
    holds the current list.
    """
    source = _console()
    assert "const asked = params.get('team') || prefs.dashboard_team_id || '';" in source
    assert "const teamId = rows.some(t => t.id === asked) ? asked : '';" in source


def test_the_estate_choice_is_explicit_in_the_url():
    """`team=all`, not an absent parameter.

    With no token for "estate", choosing Whole estate produces a URL with no
    `team=`, which the next render reads as "use the preference" -- and the
    picker springs back to the team just left. The bug is invisible until the
    preference is non-empty, which is exactly when this feature is in use.
    """
    assert "encodeURIComponent(team || 'all')" in _console()


def test_a_followed_link_does_not_rewrite_the_profile():
    """Only the picker persists. A colleague's link is for one reading."""
    source = _console()
    picker = source.split("sel.onchange")[1][:600]
    assert "patch('/auth/me/preferences'" in picker
    assert source.count("patch('/auth/me/preferences'") == 1


def test_the_view_survives_a_failed_save():
    """A profile write that fails must not block the scope change."""
    source = _console()
    picker = source.split("sel.onchange")[1][:600]
    assert picker.index("location.hash = href(") < picker.index("patch('/auth/me/preferences'")
    assert "Scope applied, but not saved to your profile" in source


# ---------------------------------------------------------------------------
# 6. the classification claim
# ---------------------------------------------------------------------------
def test_the_routes_stay_on_the_identity_tag():
    """`authentication` is EXEMPT from team scope, and that must stay true.

    A tag is a claim about every route beneath it (the lesson `policies` taught
    in v0.17.1 and `cvss` repeated in v0.21.0). These two routes read and write
    one column of the caller's own user row and touch no asset or finding, so
    the claim holds -- but the moment something here reads tenant data, the tag
    is wrong and this test is the reminder.
    """
    source = inspect.getsource(auth_router)
    body = source.split("PREFERENCE_KEYS")[1]
    for forbidden in ("Finding", "Asset", "analytics."):
        assert forbidden not in body, f"{forbidden} appeared under an EXEMPT tag"


def test_the_whitelist_is_the_only_definition_of_a_preference():
    """One list. A second copy is how a key gets served but never accepted."""
    assert auth_router.PREFERENCE_KEYS == ("dashboard_team_id",)
    fields = set(
        __import__("veyrs.api.v1.schemas", fromlist=["x"]).UserPreferencesPatch.model_fields
    )
    assert fields == set(auth_router.PREFERENCE_KEYS)
