"""Phase 41 - a second login identifier, and a directory to check it against.

Two changes that arrived as one request: sign in with a username as well as an
email address, and delegate the credential check to LDAP / Active Directory.

What is pinned here is mostly the set of doors that only close once:

* **A directory login must never write a local password.** `needs_rehash("")`
  is True, so the pre-existing rehash branch would have fired on every
  directory login and stored `hash_password(the domain password)` on a row
  whose entire purpose is having none. The estate would have silently acquired
  a frozen local copy of every domain password typed into it -- each one
  surviving revocation upstream forever, which is the exact failure delegating
  authentication is meant to remove.
* **A platform superuser is never delegated.** Every failure mode this feature
  has is *a bad directory configuration*. If the one account that can open
  Administration -> Directory and repair it also depends on the directory, the
  deployment locks its own operator out of the repair.
* **`@` is refused in a username.** The lookup is `email == x OR username == x`
  over one tenant; a username shaped like an address lets its owner sit in
  front of somebody else's account, and the collision is not resolvable once
  both rows exist.
* **Directory role grants carry `origin`.** Without provenance there are only
  two behaviours and both are wrong: replace every grant and an administrator's
  hand-made exception dies at the next login, or only ever add and somebody
  removed from a group keeps the role forever.
* **`GET /ldap` needs `settings:admin`, not `settings:read`.** Unlike the
  scanning switch, this payload is a map of how to become an administrator:
  the host, the service-account DN, the search base and the group-to-role
  mapping.

The defect fixed on the way: the console has always posted
`organization_slug` while `LoginRequest` declared `organization`, so pydantic
dropped it and the Organization box on the sign-in page had never once done
anything. Latent with one tenant; the moment an address exists in two, the
backend answers `409 organization_required` and the console cannot satisfy it.
"""
from __future__ import annotations

import pathlib
import re
import uuid

import pytest
from sqlalchemy import select

from veyrs.api.v1.schemas import USERNAME_RE, LoginRequest
from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Organization, User, UserRole
from veyrs.security.auth import hash_password
from veyrs.services import ldap_auth

from conftest import ADMIN_PASSWORD, auth_headers

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "frontend" / "console"


# --- the request schema ---------------------------------------------------


class TestLoginRequest:
    def test_a_username_is_accepted_as_the_identifier(self):
        payload = LoginRequest(identifier="jsmith", password="x")
        assert payload.login_identifier == "jsmith"

    def test_the_legacy_email_field_still_works(self):
        """Every client that predates this release sends `email`.

        Replacing it outright would have been a silent breaking change on the
        one endpoint whose failure mode is "nobody can sign in".
        """
        payload = LoginRequest(email="Admin@Corp.Test", password="x")
        assert payload.login_identifier == "admin@corp.test"

    def test_the_legacy_field_is_no_longer_syntax_checked_as_an_address(self):
        """An old client posting `email: "jsmith"` must get an answer, not a 422.

        It is now one of two ways to name an account, so refusing it on address
        syntax would make usernames unreachable for exactly the clients that
        have not been updated yet.
        """
        assert LoginRequest(email="jsmith", password="x").login_identifier == "jsmith"

    def test_identifier_wins_over_email(self):
        """A client sending both is mid-migration; take the new field."""
        payload = LoginRequest(identifier="jsmith", email="other@corp.test", password="x")
        assert payload.login_identifier == "jsmith"

    def test_neither_is_refused(self):
        with pytest.raises(ValueError):
            LoginRequest(password="x")

    def test_the_identifier_is_folded_to_lowercase(self):
        assert LoginRequest(identifier="JSmith", password="x").login_identifier == "jsmith"

    def test_organization_slug_is_finally_accepted(self):
        """The console has sent this spelling since the login page was written.

        pydantic dropped it as an unknown key, which is why the Organization
        box has never done anything. Both spellings are accepted rather than
        picking a winner and breaking whichever clients use the other.
        """
        assert LoginRequest(identifier="a", password="x",
                            organization_slug="visionebc").organization == "visionebc"
        assert LoginRequest(identifier="a", password="x",
                            organization="visionebc").organization == "visionebc"


class TestUsernameRule:
    @pytest.mark.parametrize("good", ["jsmith", "j.smith", "j_smith", "j-smith", "user2", "ab"])
    def test_accepted(self, good):
        assert re.match(USERNAME_RE, good)

    @pytest.mark.parametrize("bad", [
        "bob@corp.com",   # the whole point: ambiguous with an address
        "a",              # too short to be anybody's account name
        ".hidden",        # must not read as a flag or a relative path
        "-x",
        "has space",
        "sue;drop",
    ])
    def test_refused(self, bad):
        assert not re.match(USERNAME_RE, bad)

    def test_at_sign_is_refused_and_that_is_load_bearing(self):
        """`email == x OR username == x` is only safe because of this.

        Allow one person to take `bob@corp.com` as a username and they can sit
        in front of the account that owns that address.
        """
        assert not re.match(USERNAME_RE, "bob@corp.com")


# --- the service, without a directory to talk to --------------------------


class TestLdapValidation:
    BASE = {
        "enabled": True, "host": "dc01.corp.local", "port": 636, "use_ssl": True,
        "start_tls": False, "bind_dn": "CN=veyrs,DC=corp,DC=local",
        "base_dn": "DC=corp,DC=local", "user_filter": ldap_auth.DEFAULT_USER_FILTER,
        "timeout_seconds": 8,
    }

    def test_a_complete_configuration_has_no_complaints(self):
        assert ldap_auth.validate(dict(self.BASE)) == []

    def test_an_unencrypted_bind_is_refused(self):
        """A simple bind sends the password in cleartext."""
        cfg = dict(self.BASE, use_ssl=False, start_tls=False)
        assert any("cleartext" in p for p in ldap_auth.validate(cfg))

    def test_ssl_and_starttls_together_are_refused(self):
        cfg = dict(self.BASE, use_ssl=True, start_tls=True)
        assert any("not both" in p for p in ldap_auth.validate(cfg))

    def test_a_filter_without_the_placeholder_is_refused(self):
        """Without `{username}` the filter matches everybody, forever."""
        cfg = dict(self.BASE, user_filter="(objectClass=user)")
        assert any(ldap_auth.FILTER_PLACEHOLDER in p for p in ldap_auth.validate(cfg))

    def test_a_service_account_is_required_to_enable(self):
        cfg = dict(self.BASE, bind_dn="")
        assert any("service-account" in p for p in ldap_auth.validate(cfg))

    def test_jit_without_enabled_is_refused(self):
        cfg = dict(self.BASE, enabled=False, jit_provisioning=True)
        assert any("just-in-time" in p for p in ldap_auth.validate(cfg))

    def test_every_problem_is_returned_at_once(self):
        """An operator fixing a directory one 422 at a time gives up on the fourth."""
        cfg = dict(self.BASE, host="", base_dn="", user_filter="(x=y)", bind_dn="")
        assert len(ldap_auth.validate(cfg)) >= 4

    def test_the_shipped_filter_excludes_computer_accounts(self):
        """`objectClass=user` alone matches every workstation in the domain.

        A workstation that can bind is an account that can log in.
        """
        assert "objectCategory=person" in ldap_auth.DEFAULT_USER_FILTER


class TestGroupMapping:
    def test_a_bare_cn_matches_a_full_dn(self):
        """An operator reads `SOC Analysts` off a screen and types that.

        Matching only the full DN makes a correct-looking mapping do nothing,
        and the symptom is a person who signs in with no roles at all.
        """
        cfg = {"group_role_map": {"soc analysts": "security-analyst"}, "default_role_slugs": []}
        identity = ldap_auth.LdapIdentity(
            dn="CN=J,DC=corp", username="j",
            groups=["CN=SOC Analysts,OU=Groups,DC=corp,DC=local"],
        )
        assert ldap_auth.roles_for(cfg, identity) == ["security-analyst"]

    def test_a_full_dn_also_matches(self):
        dn = "cn=soc analysts,ou=groups,dc=corp,dc=local"
        cfg = {"group_role_map": {dn: "security-analyst"}, "default_role_slugs": []}
        identity = ldap_auth.LdapIdentity(
            dn="CN=J,DC=corp", username="j",
            groups=["CN=SOC Analysts,OU=Groups,DC=corp,DC=local"],
        )
        assert ldap_auth.roles_for(cfg, identity) == ["security-analyst"]

    def test_an_unmapped_group_grants_nothing(self):
        """No fallback that grants a role because a group's NAME resembles it.

        An accidental match on something like `org-admin` is not a mistake
        anybody would catch by reading the screen afterwards.
        """
        cfg = {"group_role_map": {}, "default_role_slugs": []}
        identity = ldap_auth.LdapIdentity(
            dn="CN=J,DC=corp", username="j", groups=["CN=org-admin,DC=corp"])
        assert ldap_auth.roles_for(cfg, identity) == []

    def test_defaults_apply_with_no_groups(self):
        cfg = {"group_role_map": {}, "default_role_slugs": ["viewer"]}
        identity = ldap_auth.LdapIdentity(dn="CN=J,DC=corp", username="j", groups=[])
        assert ldap_auth.roles_for(cfg, identity) == ["viewer"]


class TestDefaults:
    def test_directory_authentication_ships_off(self):
        """A platform does not start delegating authentication on upgrade."""
        assert ldap_auth.DEFAULT_ENABLED is False
        assert ldap_auth.DEFAULTS["enabled"] is False

    def test_provisioning_ships_off(self):
        """On, everybody the directory will bind reaches this estate's findings."""
        assert ldap_auth.DEFAULTS["jit_provisioning"] is False

    def test_new_accounts_get_no_roles_by_default(self):
        assert ldap_auth.DEFAULTS["default_role_slugs"] == []

    def test_certificate_verification_is_on_by_default(self):
        assert ldap_auth.DEFAULTS["verify_certificate"] is True


class TestLazyImport:
    def test_the_module_imports_without_ldap3(self):
        """Configuration, redaction and validation are pure Python.

        An upgrade that lands this code before the dependency is installed must
        still boot and serve every other route, reporting one clear error on
        the Directory page -- not fail at import and take the API with it.

        Asserted over the AST rather than by grepping the text: every `import
        ldap3` in this module is legitimate *because* it sits inside a function
        body, so a substring search cannot tell the safe ones from the one that
        would break the API. What matters is that none is at module level.
        """
        import ast

        tree = ast.parse((ROOT / "backend" / "veyrs" / "services" / "ldap_auth.py").read_text())
        for node in tree.body:
            if isinstance(node, ast.Import):
                assert not any(a.name.split(".")[0] == "ldap3" for a in node.names)
            if isinstance(node, ast.ImportFrom):
                assert (node.module or "").split(".")[0] != "ldap3"

    def test_ldap3_is_imported_somewhere(self):
        """Guards the test above from passing on a module that never uses it."""
        source = (ROOT / "backend" / "veyrs" / "services" / "ldap_auth.py").read_text()
        assert "ldap3" in source


# --- the API --------------------------------------------------------------


class TestLoginWithUsername:
    def test_a_username_signs_in(self, client, org_a):
        _org_id, slug, email = org_a
        with SessionLocal() as session:
            org = session.execute(
                select(Organization).where(Organization.slug == slug)).scalars().one()
            set_tenant(session, org.id)
            user = session.execute(
                select(User).where(User.email == email)).scalars().one()
            user.username = "adm.one"
            session.commit()
        r = client.post("/api/v1/auth/login", json={
            "identifier": "adm.one", "password": ADMIN_PASSWORD, "organization": slug})
        assert r.status_code == 200, r.text

    def test_the_email_still_signs_in(self, client, org_a):
        _org_id, slug, email = org_a
        r = client.post("/api/v1/auth/login", json={
            "email": email, "password": ADMIN_PASSWORD, "organization": slug})
        assert r.status_code == 200, r.text

    def test_a_username_is_case_insensitive(self, client, org_a):
        _org_id, slug, email = org_a
        with SessionLocal() as session:
            org = session.execute(
                select(Organization).where(Organization.slug == slug)).scalars().one()
            set_tenant(session, org.id)
            session.execute(select(User).where(User.email == email)).scalars().one().username = "casetest"
            session.commit()
        r = client.post("/api/v1/auth/login", json={
            "identifier": "CaseTest", "password": ADMIN_PASSWORD, "organization": slug})
        assert r.status_code == 200, r.text

    def test_a_wrong_username_is_the_same_401_as_a_wrong_password(self, client, org_a):
        """Account enumeration through this endpoint stays impossible."""
        _org_id, slug, email = org_a
        unknown = client.post("/api/v1/auth/login", json={
            "identifier": "nobody", "password": ADMIN_PASSWORD, "organization": slug})
        wrong = client.post("/api/v1/auth/login", json={
            "email": email, "password": "not-the-password", "organization": slug})
        assert unknown.status_code == wrong.status_code == 401
        assert unknown.json() == wrong.json()

    def test_me_carries_the_username(self, client, org_a):
        _org_id, slug, email = org_a
        with SessionLocal() as session:
            org = session.execute(
                select(Organization).where(Organization.slug == slug)).scalars().one()
            set_tenant(session, org.id)
            session.execute(select(User).where(User.email == email)).scalars().one().username = "meuser"
            session.commit()
        r = client.get("/api/v1/auth/me", headers=auth_headers(client, email, slug))
        assert r.json()["username"] == "meuser"


class TestUserAdministration:
    def test_a_username_can_be_set_on_create(self, client, org_a):
        _org_id, slug, email = org_a
        h = auth_headers(client, email, slug)
        r = client.post("/api/v1/users", headers=h, json={
            "email": f"u{uuid.uuid4().hex[:8]}@corp.test", "username": "newperson",
            "full_name": "New Person", "password": "a-long-enough-password"})
        assert r.status_code in (200, 201), r.text
        assert r.json()["username"] == "newperson"

    def test_an_at_sign_is_refused_with_422(self, client, org_a):
        _org_id, slug, email = org_a
        r = client.post("/api/v1/users", headers=auth_headers(client, email, slug), json={
            "email": f"u{uuid.uuid4().hex[:8]}@corp.test", "username": "bob@corp.com",
            "full_name": "Bob", "password": "a-long-enough-password"})
        assert r.status_code == 422

    def test_a_duplicate_username_is_409_not_500(self, client, org_a):
        """Two unique constraints reach the same handler now.

        Naming only the email would send an administrator to check an address
        that is perfectly free.
        """
        _org_id, slug, email = org_a
        h = auth_headers(client, email, slug)
        name = f"dup{uuid.uuid4().hex[:6]}"
        first = client.post("/api/v1/users", headers=h, json={
            "email": f"a{uuid.uuid4().hex[:8]}@corp.test", "username": name,
            "full_name": "Ana Uno", "password": "a-long-enough-password"})
        assert first.status_code in (200, 201), first.text
        second = client.post("/api/v1/users", headers=h, json={
            "email": f"b{uuid.uuid4().hex[:8]}@corp.test", "username": name,
            "full_name": "Beto Dos", "password": "a-long-enough-password"})
        assert second.status_code == 409
        assert "username" in second.json()["detail"]

    def test_the_same_username_is_free_in_another_tenant(self, client, org_a, org_b):
        """`jsmith` in two organizations is two different people.

        A global constraint would let the first tenant to claim a common name
        deny it to every other one.
        """
        name = f"shared{uuid.uuid4().hex[:6]}"
        for org in (org_a, org_b):
            _org_id, slug, email = org
            r = client.post("/api/v1/users", headers=auth_headers(client, email, slug), json={
                "email": f"x{uuid.uuid4().hex[:8]}@corp.test", "username": name,
                "full_name": "Shared Name", "password": "a-long-enough-password"})
            assert r.status_code in (200, 201), r.text


class TestDirectoryRoutes:
    def test_reading_needs_settings_admin(self, client, org_a):
        """NOT read-open like `/scanning`.

        That payload answers "does this deployment scan". This one names the
        host, the service account, the search base and the group-to-role
        mapping: a map of how to become an administrator here.
        """
        import inspect

        from veyrs.api.v1 import admin

        source = inspect.getsource(admin.get_ldap)
        assert 'require("settings:admin")' in source
        assert 'require("settings:read")' not in source

    def test_it_is_off_and_unconfigured_by_default(self, client, org_a):
        _org_id, slug, email = org_a
        r = client.get("/api/v1/ldap", headers=auth_headers(client, email, slug))
        assert r.status_code == 200, r.text
        assert r.json()["enabled"] is False

    def test_the_bind_password_is_never_returned(self, client, org_a):
        """Not even as ciphertext.

        Echoing it would hand anyone with read access something to replay into
        the PUT. `bind_password_set` answers the only question the UI has.
        """
        _org_id, slug, email = org_a
        h = auth_headers(client, email, slug)
        saved = client.put("/api/v1/ldap", headers=h, json={
            "host": "dc01.corp.local", "port": 636, "use_ssl": True,
            "bind_dn": "CN=veyrs,DC=corp,DC=local", "base_dn": "DC=corp,DC=local",
            "bind_password": "sup3r-s3cret"})
        assert saved.status_code == 200, saved.text
        body = saved.json()
        assert "bind_password" not in body
        assert "bind_password_enc" not in body
        assert body["bind_password_set"] is True
        assert "sup3r-s3cret" not in saved.text

    def test_an_absent_password_keeps_the_stored_one(self, client, org_a):
        """A form that re-sends it every time eventually saves the placeholder."""
        _org_id, slug, email = org_a
        h = auth_headers(client, email, slug)
        client.put("/api/v1/ldap", headers=h, json={
            "host": "dc01.corp.local", "use_ssl": True,
            "bind_dn": "CN=veyrs,DC=corp,DC=local", "base_dn": "DC=corp,DC=local",
            "bind_password": "keep-me"})
        again = client.put("/api/v1/ldap", headers=h, json={"timeout_seconds": 12})
        assert again.json()["bind_password_set"] is True
        assert again.json()["timeout_seconds"] == 12

    def test_an_unencrypted_configuration_is_refused_with_422(self, client, org_a):
        _org_id, slug, email = org_a
        r = client.put("/api/v1/ldap", headers=auth_headers(client, email, slug), json={
            "enabled": True, "host": "dc01.corp.local", "port": 389,
            "use_ssl": False, "start_tls": False,
            "bind_dn": "CN=veyrs,DC=corp,DC=local", "base_dn": "DC=corp,DC=local"})
        assert r.status_code == 422
        assert "cleartext" in r.text

    def test_the_test_route_never_500s_on_an_unreachable_directory(self, client, org_a):
        """Five distinct causes needing five different fixes, so five steps."""
        _org_id, slug, email = org_a
        h = auth_headers(client, email, slug)
        client.put("/api/v1/ldap", headers=h, json={
            "host": "192.0.2.1", "port": 636, "use_ssl": True, "timeout_seconds": 1,
            "bind_dn": "CN=veyrs,DC=corp,DC=local", "base_dn": "DC=corp,DC=local",
            "bind_password": "x"})
        r = client.post("/api/v1/ldap/test", headers=h, json={})
        assert r.status_code == 200, r.text
        assert r.json()["ok"] is False
        assert [s for s in r.json()["steps"] if not s["ok"]]


class TestRehashGuard:
    def test_a_directory_login_cannot_write_a_local_password(self):
        """The single most dangerous line in this change.

        `needs_rehash("")` is True, so without the `method == "local"` guard
        every directory login would store `hash_password(the domain password)`
        on a row whose whole point is having none -- and that frozen copy would
        keep working after the password was revoked upstream, forever.
        """
        import inspect

        from veyrs.api.v1 import auth as auth_module

        source = inspect.getsource(auth_module.login)
        assert 'method == "local" and needs_rehash' in source

    @staticmethod
    def _statement_lines(name: str) -> dict[str, int]:
        """Line of the first EXECUTABLE mention of each token, docstring excluded.

        Matching the raw source would compare prose: `_check_credential`'s own
        docstring names `services/ldap_auth.py` several lines above any code,
        so a substring search "proves" the directory is consulted first when
        the opposite is true. Ordering claims have to be read off the AST.
        """
        import ast
        import inspect
        import textwrap

        from veyrs.api.v1 import auth as auth_module

        tree = ast.parse(textwrap.dedent(inspect.getsource(getattr(auth_module, name))))
        body = tree.body[0].body
        if (body and isinstance(body[0], ast.Expr)
                and isinstance(body[0].value, ast.Constant)):
            body = body[1:]  # drop the docstring
        found: dict[str, int] = {}
        for node in body:
            for sub in ast.walk(node):
                token = None
                if isinstance(sub, ast.Attribute):
                    token = sub.attr
                elif isinstance(sub, ast.Name):
                    token = sub.id
                if token and token not in found:
                    found[token] = getattr(sub, "lineno", 0)
        return found

    def test_a_superuser_is_never_checked_against_the_directory(self):
        """The account that repairs a bad directory must not depend on it."""
        lines = self._statement_lines("_check_credential")
        assert "is_superuser" in lines and "ldap_auth" in lines
        assert lines["is_superuser"] < lines["ldap_auth"], \
            "the superuser guard must come before any directory call"

    def test_local_is_checked_before_the_directory(self):
        """Otherwise every login carries a network round trip.

        Including the break-glass one an operator makes precisely because the
        network is what broke.
        """
        lines = self._statement_lines("_check_credential")
        assert lines["verify_password"] < lines["ldap_auth"]


class TestRoleProvenance:
    def test_user_role_has_an_origin_column(self):
        assert hasattr(UserRole, "origin")

    def test_it_defaults_to_manual(self):
        """Every grant that predates the column is a human decision.

        A sync must never touch one.
        """
        assert UserRole.__table__.c.origin.default.arg == "manual"

    def test_a_manual_role_edit_leaves_directory_grants_alone(self):
        """Relabelling them `manual` would make removal from a group stop working.

        Forever, and silently -- which is the offboarding failure a directory is
        adopted to fix.
        """
        import inspect

        from veyrs.api.v1 import admin

        source = inspect.getsource(admin.update_user)
        assert 'UserRole.origin != "directory"' in source


# --- the console ----------------------------------------------------------


class TestConsole:
    def test_the_login_field_is_not_type_email(self):
        """The browser would refuse `jsmith` before the form is submitted.

        No backend change can rescue a field the browser will not let you fill.
        """
        html = (CONSOLE / "index.html").read_text()
        field = [ln for ln in html.splitlines() if 'id="l-email"' in ln][0]
        assert 'type="text"' in field
        assert 'type="email"' not in field

    def test_the_login_posts_identifier_and_organization(self):
        app = (CONSOLE / "app.js").read_text()
        assert "identifier: $('#l-email').value.trim()" in app
        assert "organization_slug: org" not in app

    def test_the_directory_tab_exists_and_is_in_the_menu(self):
        app = (CONSOLE / "app.js").read_text()
        assert "['directory', 'Directory']" in app
        assert "tab: 'directory'" in app

    def test_the_directory_entry_is_not_hidden_by_the_scanning_mode(self):
        """How people sign in is on in an ingest-only deployment too."""
        app = (CONSOLE / "app.js").read_text()
        line = [ln for ln in app.splitlines() if "label: 'Directory'" in ln][0]
        assert ", scan: true }" not in line

    def test_the_users_table_says_where_a_password_is_checked(self):
        """The first question asked when somebody's password stops working."""
        app = (CONSOLE / "app.js").read_text()
        assert "r.ldap_dn" in app
