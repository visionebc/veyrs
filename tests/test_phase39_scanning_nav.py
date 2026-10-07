"""Phase 39 - an ingest-only deployment stops advertising a scanner.

Phase 34 shipped the switch and deliberately left the nav alone: the
Vulnerability scanner page got a *banner* rather than being hidden, on the
reasoning that an operator at an empty queue must be able to tell "nothing is
scheduled" from "this deployment does not scan". That reasoning was right about
the question and wrong about who has to answer it. The operator of an
ingest-only platform does not want a page explaining that a capability is off;
they want a console that describes the product they actually run.

So the entry leaves the menu. What that cannot be allowed to take with it is
pinned here, because each one is a door that only closes once:

* **`Administration -> Scanning` stays.** It is the switch. Hiding it with the
  thing it controls means whoever turned scanning off has no menu path back.
* **`Data sources` stays.** Ingestion *is* the mode. A menu with no import
  screen would be perfectly consistent and the product would be dead.
* **`route('scanner')` stays registered.** A bookmark or a runbook link must
  not land on "No view is registered", and the page already carries the banner
  naming the mode.
* **The palette is filtered too.** Otherwise the hidden page sits one Ctrl-K
  away and the menu is merely lying rather than tidy.

And one fact decided where the flag lives: `GET /scanning` requires
`settings:read`, which of the ten built-in roles only the wildcard `org-admin`
carries. A console driving its menu from that route would clean the nav for
exactly the persona that did not need it cleaned, and 403 for everyone else.
The flag therefore rides on `/auth/me` -- tenant state, not a permission, read
once at boot alongside `preferences`.
"""
from __future__ import annotations

import pathlib
import uuid

from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Role, User, UserRole
from veyrs.security.auth import hash_password
from veyrs.security.permissions import BUILTIN_ROLES, expand

from conftest import ADMIN_PASSWORD, auth_headers

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP_JS = ROOT / "frontend" / "console" / "app.js"

ME = "/api/v1/auth/me"
SCANNING = "/api/v1/scanning"


def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _flip(client, headers, enabled: bool, **extra):
    body = {"active_scanning_enabled": enabled, "reason": "phase 39 test"}
    body.update(extra)
    response = client.put(SCANNING, headers=headers, json=body)
    assert response.status_code == 200, response.text
    return response.json()


def _me(client, headers) -> dict:
    response = client.get(ME, headers=headers)
    assert response.status_code == 200, response.text
    return response.json()


def _user_with_role(client, org, slug: str) -> dict[str, str]:
    """A second identity in the same tenant, holding one built-in role."""
    org_id, org_slug, _ = org
    email = f"{slug}-{uuid.uuid4().hex[:6]}@{org_slug}.test"
    with SessionLocal() as session:
        set_tenant(session, org_id)
        user = User(organization_id=org_id, email=email, full_name=slug.title(),
                    password_hash=hash_password(ADMIN_PASSWORD))
        session.add(user)
        session.flush()
        role = session.execute(
            select(Role).where(Role.slug == slug, Role.organization_id.is_(None))
        ).scalar_one()
        session.add(UserRole(organization_id=org_id, user_id=user.id, role_id=role.id))
        session.commit()
    return auth_headers(client, email, org_slug)


# ── the flag on the identity ──────────────────────────────────────────────


def test_the_identity_carries_the_scanning_mode(client, admin_a):
    assert _me(client, admin_a)["active_scanning"] is True


def test_the_flag_follows_the_switch_both_ways(client, admin_a):
    _flip(client, admin_a, False, cancel_queued_jobs=True)
    assert _me(client, admin_a)["active_scanning"] is False
    _flip(client, admin_a, True)
    assert _me(client, admin_a)["active_scanning"] is True


def test_a_tenant_is_not_told_about_another_tenants_switch(client, admin_a, admin_b):
    _flip(client, admin_a, False, cancel_queued_jobs=True)
    assert _me(client, admin_a)["active_scanning"] is False
    assert _me(client, admin_b)["active_scanning"] is True


def test_the_route_it_could_not_have_used(client, org_a):
    """The whole reason the flag is on `/auth/me` and not behind `GET /scanning`.

    A security engineer is the person this feature is FOR -- they work the
    queue all day and will never touch the switch. They are also refused the
    route that reports it.
    """
    engineer = _user_with_role(client, org_a, "security-engineer")
    assert client.get(SCANNING, headers=engineer).status_code == 403
    assert _me(client, engineer)["active_scanning"] is True


def test_only_the_wildcard_role_can_read_the_scanning_route():
    holders = [slug for slug, spec in BUILTIN_ROLES.items()
               if "settings:read" in expand(spec["permissions"])]
    assert holders == ["org-admin"], (
        "if another built-in role gains settings:read this test should be "
        "updated, not deleted -- but the console must keep reading the mode "
        "from /auth/me, because a nav that depends on a permission hides "
        "pages for a reason the operator cannot see"
    )


def test_the_engineer_sees_the_mode_change_too(client, org_a, admin_a):
    engineer = _user_with_role(client, org_a, "security-engineer")
    _flip(client, admin_a, False, cancel_queued_jobs=True)
    assert _me(client, engineer)["active_scanning"] is False


def test_the_default_is_on_so_an_unset_tenant_keeps_its_menu():
    from veyrs.api.v1.schemas import MeResponse
    assert MeResponse.model_fields["active_scanning"].default is True, (
        "the failure mode of this field must be a visible menu: a hidden "
        "entry is indistinguishable from a page that was removed"
    )


# ── the console reads it, and hides exactly one thing ─────────────────────


def test_the_scanner_entry_is_the_only_flagged_nav_item():
    src = _src()
    nav = src[src.index("const NAV = ["):src.index("/* ── Sidebar state")]
    # `, scan: true }` rather than the bare token: the flag is documented in
    # a comment directly above the entry, and matching prose would make this
    # test fail on an edit to the explanation rather than to the behaviour.
    flagged = [line for line in nav.splitlines() if ", scan: true }" in line]
    assert len(flagged) == 1, flagged
    assert "'scanner'" in flagged[0]


def test_the_switch_itself_is_never_hidden():
    """The one-way door. Hiding the switch with what it controls strands the
    tenant in ingest-only mode with no menu path back."""
    src = _src()
    nav = src[src.index("const NAV = ["):src.index("/* ── Sidebar state")]
    for line in nav.splitlines():
        if "'Scanning'" in line or "tab: 'scanning'" in line:
            assert "scan: true" not in line, line


def test_ingestion_is_never_hidden():
    """Ingestion IS the mode. A menu without it would be consistent and dead."""
    src = _src()
    nav = src[src.index("const NAV = ["):src.index("/* ── Sidebar state")]
    for line in nav.splitlines():
        if "'integrations'" in line:
            assert "scan: true" not in line, line


def test_the_nav_filters_on_the_flag():
    assert "!i.hidden && !(i.scan && !activeScanning)" in _src()


def test_the_palette_filters_on_the_flag():
    """A hidden page one Ctrl-K away is worse than a visible one."""
    src = _src()
    body = src[src.index("function paletteCommands()"):]
    body = body[:body.index("\n}")]
    assert "item.scan && !activeScanning" in body


def test_the_route_stays_registered_unconditionally():
    src = _src()
    assert "\nroute('scanner', async (view) => {" in src, (
        "the view must not be registered conditionally: a bookmark landing on "
        "'No view is registered' teaches people the console is unreliable"
    )


def test_an_api_that_omits_the_field_leaves_the_menu_alone():
    src = _src()
    assert "let activeScanning = true;" in src
    assert "activeScanning = me.active_scanning !== false;" in src, (
        "a truthiness test would read a missing field as 'hide the scanner', "
        "so an older API would silently amputate the console"
    )


def test_flipping_the_switch_moves_the_menu_in_the_same_click():
    src = _src()
    window = src[src.index("await put('/scanning', {"):]
    window = window[:window.index("} catch (e)")]
    assert "activeScanning = !on;" in window
    assert window.index("activeScanning = !on;") < window.index("render();"), (
        "re-rendering before updating the flag leaves the operator looking at "
        "a menu that still offers the page they just switched off"
    )


def test_the_lazy_blurb_is_what_makes_the_copy_follow_the_mode():
    """`listView` is called at module load, before login. A plain string would
    freeze the scanner into the findings page for the life of the tab."""
    src = _src()
    assert "const lazy = v => (typeof v === 'function' ? v() : v);" in src
    assert "${lazy(blurb)}" in src
    assert "steps: lazy(setup)" in src


def test_no_link_points_at_the_route_that_does_not_exist():
    """`#/agents` was never registered; the intelligence page has been sending
    operators to 'No view is registered' since the estate lens shipped."""
    assert "#/agents" not in _src()
