"""Phase 56 (0.34.1) -- somebody can open the installation-wide pages.

The published 0.34.0 SUSE bundle installed a Docker stack whose only account
got 403 on Software update, Installed software and Network access: the Docker
initialiser bootstrapped without --superuser, the native installer with it.
"""
from __future__ import annotations

import re
from pathlib import Path

from sqlalchemy import select

from tests.conftest import auth_headers
from veyrs import cli
from veyrs.db import SessionLocal, set_tenant
from veyrs.models import User

ROOT = Path(__file__).resolve().parents[1]


def _is_superuser(email: str) -> bool:
    with SessionLocal() as s:
        u = s.execute(select(User).where(User.email == email)).scalar_one()
        set_tenant(s, u.organization_id)
        return s.get(User, u.id).is_superuser


def test_both_installers_bootstrap_a_platform_administrator():
    init = (ROOT / "docker" / "init.sh").read_text()
    call = init[init.index("python -m veyrs.cli bootstrap"):]
    call = call[:call.index("\nfi")]
    assert "--superuser" in call, "docker/init.sh must bootstrap the first admin with --superuser"
    install = (ROOT / "install.sh").read_text()
    assert re.search(r"BOOT_ARGS.*--superuser|--superuser.*BOOT_ARGS", install, re.S), \
        "install.sh must keep bootstrapping with --superuser"


def test_grant_then_the_pages_open(client, org_a):
    _, slug, email = org_a
    headers = auth_headers(client, email, slug)
    r = client.get("/api/v1/admin/system/network", headers=headers)
    assert r.status_code == 403 and "veyrs platform-admin" in r.json()["detail"]
    assert cli.main(["platform-admin", "--email", email]) == 0
    assert _is_superuser(email)
    headers = auth_headers(client, email, slug)       # takes effect at the next sign-in
    assert client.get("/api/v1/admin/system/network", headers=headers).status_code == 200
    assert cli.main(["platform-admin", "--email", email]) == 0   # idempotent


def test_revoke_refuses_the_last_platform_administrator(org_a, org_b):
    _, _, a = org_a
    _, _, b = org_b
    assert cli.main(["platform-admin", "--email", a]) == 0
    with SessionLocal() as s:
        others = s.execute(select(User).where(User.is_superuser.is_(True), User.email != a)).scalars().all()
    if not others:
        assert cli.main(["platform-admin", "--email", a, "--revoke"]) == 2
        assert _is_superuser(a)
    assert cli.main(["platform-admin", "--email", b]) == 0
    assert cli.main(["platform-admin", "--email", a, "--revoke"]) == 0
    assert not _is_superuser(a) and _is_superuser(b)


def test_unknown_account(capsys):
    assert cli.main(["platform-admin", "--email", "nobody@nowhere.invalid"]) == 2
