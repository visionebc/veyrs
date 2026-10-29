"""Phase 53 -- Installed software and Network access (Administration).

* `services/software_inventory.py`: never invents a version, flags drift
  against the lock, and is platform-admin only through the API.
* `services/network_requirements.py`: resolved against the live settings, and
  GUARDED -- every host literal in the shipped code must be in REGISTRY or in
  DOCUMENTATION_ONLY, and every registry host must be on the product site's
  Download page. A new outbound call cannot ship without its row.
* The console loads nothing from the internet.
"""
from __future__ import annotations

import re
from pathlib import Path
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from tests.conftest import auth_headers
from veyrs.db import SessionLocal, set_tenant
from veyrs.models import User
from veyrs.services import network_requirements as net
from veyrs.services import software_inventory as inv

ROOT = Path(__file__).resolve().parents[1]

#: The shipped code that runs on a customer's host (or installs it). The
#: maintainer-side publish scripts and the tests are not part of an install.
SCANNED = [
    *sorted((ROOT / "backend" / "veyrs").rglob("*.py")),
    *sorted((ROOT / "integrations" / "veyrs-agent").glob("*.py")),
    ROOT / "scripts" / "veyrs-updater.sh",
    ROOT / "scripts" / "sync-intel.sh",
    ROOT / "scripts" / "verify-release.sh",
    ROOT / "install.sh",
    ROOT / "veyrs-setup.sh",
    ROOT / "docker" / "Dockerfile",
]
URL_RE = re.compile(r"https?://([A-Za-z0-9.-]+\.[A-Za-z]{2,})")
#: RFC 2606 / 6761 reserved names: never real destinations.
IGNORED = re.compile(r"(^|\.)(example(\.(com|org|net))?|invalid|local|localhost|test)$")


@pytest.fixture(autouse=True)
def _fresh():
    inv.clear_cache()
    yield
    inv.clear_cache()


# ------------------------------------------------------- inventory ---
def test_parse_version_never_guesses():
    assert inv.parse_version("nginx version: nginx/1.22.1") == "1.22.1"
    assert inv.parse_version("OpenSSH_9.2p1 Debian-2+deb12u7, OpenSSL 3.0.17", r"OpenSSH_([0-9][0-9A-Za-z.]*)") == "9.2p1"
    assert inv.parse_version("\x1b[34mINF\x1b[0m] Nuclei Engine Version: v3.11.1",
                             r"Engine Version:\s*v?([0-9][0-9.]*)") == "3.11.1"
    assert inv.parse_version("command not found") == ""
    assert inv.parse_version("") == ""
    assert inv.parse_version("[INF] Nuclei Engine Version: v3.11.1") == "3.11.1"


def test_a_missing_binary_is_not_found_not_a_version(monkeypatch):
    monkeypatch.setattr(inv.shutil, "which", lambda *a, **k: None)
    row = inv.probe({"key": "x", "name": "X", "argv": ["no-such-binary", "--version"],
                     "deb": ["x"], "rpm": ["x"], "used_by": "test"}, {}, "dpkg")
    assert row["state"] == "not_found" and row["version"] is None and row["path"] is None


def test_package_globs_take_the_first_installed_match():
    installed = {"postgresql-client-15": "15.14-0+deb12u1", "nginx": "1.22.1-9+deb12u3"}
    assert inv.match_package(["postgresql-client-*"], installed) == ("postgresql-client-15", "15.14-0+deb12u1")
    assert inv.match_package(["nginx-core", "nginx"], installed) == ("nginx", "1.22.1-9+deb12u3")
    assert inv.match_package(["curl"], installed) == ("", "")


def test_the_package_with_the_running_major_wins():
    # openSUSE Leap 15.6, measured: a meta package at 18, the real server at 16.
    installed = {"postgresql-server": "18-150600.17.9.1", "postgresql16-server": "16.13-150600.16.1",
                 "openssh-clients": "9.6p1-150600.6.34.1"}
    assert inv.match_package(["postgresql*-server"], installed, prefer="16.13")[0] == "postgresql16-server"
    assert inv.match_package(["postgresql*-server"], installed)[0] == "postgresql-server"
    deb = {"openssh-client": "1:9.2p1-2+deb12u7"}
    assert inv.match_package(["openssh-client"], deb, prefer="9.2p1") == ("openssh-client", "1:9.2p1-2+deb12u7")


def _dist(name, version, summary="s"):
    meta = {"Name": name, "Summary": summary}

    class M(dict):
        def get_all(self, _k):
            return []
    return SimpleNamespace(metadata=M(meta), version=version)


def test_drift_against_the_lock_is_flagged():
    rows = inv.python_packages(
        declared={"fastapi", "httpx"},
        locked={"fastapi": "0.115.6", "httpx": "0.28.1", "anyio": "4.14.2", "redis": "5.2.1"},
        distributions=[_dist("fastapi", "0.115.6"), _dist("httpx", "0.27.0"), _dist("anyio", "4.14.2"),
                       _dist("pytest", "8.3.4"), _dist("pip", "24.0"), _dist("Py_Thing", "1.0"),
                       _dist("veyrs", "0.25.2")],
    )
    by = {r["name"].lower(): r for r in rows}
    assert by["fastapi"]["state"] == "ok" and by["fastapi"]["direct"] is True
    assert by["httpx"]["state"] == "differs" and by["httpx"]["locked"] == "0.28.1"
    assert by["anyio"]["state"] == "ok" and by["anyio"]["direct"] is False
    assert by["pytest"]["state"] == "not_in_lock"
    assert by["pip"]["state"] == "tooling"
    assert by["veyrs"]["state"] == "application"   # the app itself is not drift
    assert by["redis"]["state"] == "missing" and by["redis"]["version"] is None
    # direct packages first
    assert [r["direct"] for r in rows][:2] == [True, True]


def test_the_lock_and_pyproject_are_read_as_written():
    locked = inv.locked_versions()
    declared = inv.declared_dependencies()
    assert locked.get("fastapi") and locked.get("sqlalchemy")
    assert {"fastapi", "uvicorn", "sqlalchemy", "psycopg", "python-jose"} <= declared
    # every declared dependency is pinned in the lock
    assert declared <= set(locked), declared - set(locked)


def test_no_probe_executes_a_scanner_inside_the_api_sandbox():
    # nuclei aborts under MemoryDenyWriteExecute; scanner versions come from the agents.
    assert not {c["argv"][0] for c in inv.COMPONENTS} & {"nuclei", "zap.sh", "zap-baseline.py", "nmap"}


def test_inventory_shape_and_cache(monkeypatch):
    monkeypatch.setattr(inv, "components", lambda: [{"key": "nginx", "state": "ok"}])
    first = inv.inventory(now=1000.0)
    assert first["cached"] is False and first["node"]["python"]
    assert first["summary"]["python_packages"] > 10
    assert inv.inventory(now=1030.0)["cached"] is True
    assert inv.inventory(now=1100.0)["cached"] is False
    assert inv.inventory(refresh=True, now=1101.0)["cached"] is False


def test_service_dsn_hosts_never_carry_credentials():
    assert inv._url_host("postgresql+psycopg://veyrs:s3cret@10.1.2.3:5432/veyrs") == "10.1.2.3:5432"
    assert inv._url_host("redis://:pw@cache.internal:6379/0") == "cache.internal:6379"
    assert "s3cret" not in str(net._host_port("postgresql+psycopg://veyrs:s3cret@db:5432/veyrs"))


# --------------------------------------------------------- network ---
def test_registry_is_resolved_against_settings(monkeypatch):
    monkeypatch.setattr(net.settings, "update_url", "")
    monkeypatch.setattr(net.settings, "nvd_api_url", "https://nvd-mirror.corp.internal/rest/json/cves/2.0")
    monkeypatch.setattr(net.settings, "ai_allow_external", False)
    rows = {r["key"]: r for r in net.registry()}
    assert rows["update-check"]["disabled"] is True
    assert rows["nvd"]["hosts"] == ["nvd-mirror.corp.internal"] and rows["nvd"]["moved"] is True
    assert rows["kev"]["hosts"] == ["www.cisa.gov"] and not rows["kev"]["disabled"]
    assert all(rows[k]["disabled"] for k in ("ai-openai", "ai-anthropic", "ai-gemini"))


def test_every_registry_row_says_what_to_do_without_it():
    groups = {k for k, _ in net.GROUPS}
    for d in net.REGISTRY:
        assert d.group in groups, d.key
        assert d.need in ("required", "recommended", "optional"), d.key
        assert d.offline.strip() and d.purpose.strip() and d.used_by.strip(), d.key
    assert len({d.key for d in net.REGISTRY}) == len(net.REGISTRY)


def test_every_host_in_the_code_is_accounted_for():
    known = {h for d in net.REGISTRY for h in d.hosts} | net.DOCUMENTATION_ONLY
    unknown: dict[str, list[str]] = {}
    for path in SCANNED:
        text = path.read_text(encoding="utf-8", errors="replace")
        for host in URL_RE.findall(text):
            host = host.lower().rstrip(".")
            if IGNORED.search(host) or re.match(r"^\d+\.\d+\.\d+\.\d+$", host):
                continue
            if host not in known:
                unknown.setdefault(host, []).append(str(path.relative_to(ROOT)))
    assert not unknown, ("hosts in the code with no row in services/network_requirements.py "
                         f"(REGISTRY, or DOCUMENTATION_ONLY if never contacted): {unknown}")


def test_the_settings_defaults_are_the_registry_defaults():
    from veyrs.config import Settings

    defaults = Settings.model_fields
    for d in net.REGISTRY:
        if d.attr:
            assert defaults[d.attr].default == d.default_url, d.key


def test_the_download_page_names_every_internet_host():
    page = (ROOT / "site" / "web" / "build_web.py").read_text(encoding="utf-8")
    missing = sorted({h for d in net.REGISTRY if d.group in ("intelligence", "updates", "install", "ai", "mfa")
                      for h in d.hosts if " " not in h and h not in page})
    assert not missing, f"Download page (site/web/build_web.py) does not name: {missing}"


def test_the_console_loads_nothing_from_the_internet():
    console = ROOT / "frontend" / "console"
    for name in ("index.html", "console.css"):
        text = (console / name).read_text(encoding="utf-8")
        assert not re.search(r"""(src|href)\s*=\s*["']?(https?:)?//""", text), name
        assert not re.search(r"url\(\s*['\"]?(https?:)?//", text), name
        assert "@import" not in text or not re.search(r"@import\s+url\(\s*['\"]?https?:", text), name


# ------------------------------------------------------------- API ---
def _make_platform_admin(org) -> None:
    org_id, _slug, email = org
    with SessionLocal() as session:
        set_tenant(session, org_id)
        user = session.execute(select(User).where(User.email == email)).scalar_one()
        user.is_superuser = True
        session.commit()


def test_both_endpoints_are_platform_admin_only(client, org_a):
    _, slug, email = org_a
    headers = auth_headers(client, email, slug)   # org-admin, NOT platform admin
    for path in ("/api/v1/admin/system/software", "/api/v1/admin/system/network"):
        assert client.get(path, headers=headers).status_code == 403, path
        assert client.get(path).status_code == 401, path


def test_platform_admin_reads_both(client, org_a, monkeypatch):
    monkeypatch.setattr(inv, "components", lambda: [])
    _make_platform_admin(org_a)
    _, slug, email = org_a
    headers = auth_headers(client, email, slug)
    sw = client.get("/api/v1/admin/system/software", headers=headers)
    assert sw.status_code == 200, sw.text
    body = sw.json()
    assert body["node"]["veyrs_version"] and any(p["name"].lower() == "fastapi" for p in body["python_packages"])
    assert isinstance(body["agents"], list)
    nw = client.get("/api/v1/admin/system/network", headers=headers)
    assert nw.status_code == 200, nw.text
    data = nw.json()
    assert {d["key"] for d in data["destinations"]} >= {"nvd", "epss", "kev", "cwe", "update-check"}
    assert any(p["key"] == "database" for p in data["platform"])
    assert isinstance(data["configured"], list)
    # never a credential from a DSN
    assert "@" not in str(data["platform"])
