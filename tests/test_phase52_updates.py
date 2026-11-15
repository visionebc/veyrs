"""Phase 52 -- the in-product update check and the privileged self-update.

Three layers, each tested where it lives:

* `services/updates.py` (inside the API): install-mode detection, the release
  check (cached, never raising, off when VEYRS_UPDATE_URL is empty) and the
  spool request -- one file, no secrets.
* `/api/v1/admin/updates`: platform administrators only, the apply is audited
  and refused wherever the root updater would refuse.
* `scripts/veyrs-updater.sh` (root): driven against a LOCAL fake release over
  file://, with a throwaway signing key. It must refuse unsigned releases, bad
  hashes, bad signatures, the placeholder key and git checkouts before touching
  anything, and write its steps for the console.
"""
from __future__ import annotations

import http.server
import json
import os
import shutil
import subprocess
import threading
import uuid
from pathlib import Path

import pytest
from sqlalchemy import select

from tests.conftest import auth_headers
from tests.test_phase52_release_signing import PLACEHOLDER_LINE, make_key, make_release, sign
from veyrs.db import SessionLocal, set_tenant
from veyrs.models import User
from veyrs.models.audit import AuditLog
from veyrs.services import updates

ROOT = Path(__file__).resolve().parents[1]
UPDATER = ROOT / "scripts" / "veyrs-updater.sh"


@pytest.fixture(autouse=True)
def _fresh_cache():
    updates.clear_cache()
    yield
    updates.clear_cache()


def _release_info(version: str = "0.33.0", signed: bool = True) -> dict:
    assets = ["veyrs-setup.sh", f"veyrs-{version}-src.tar.gz", "SHA256SUMS"]
    if signed:
        assets.append("SHA256SUMS.sig")
    return updates.parse_release({
        "tag_name": f"v{version}", "published_at": "2026-10-20T10:00:00Z",
        "html_url": f"https://github.com/visionebc/veyrs/releases/tag/v{version}",
        "assets": [{"name": n} for n in assets],
    })


@pytest.fixture()
def native(monkeypatch, tmp_path):
    """A native install that may apply: newer signed release, backup arranged, spool writable."""
    spool = tmp_path / "spool"
    spool.mkdir()
    status_dir = tmp_path / "status"
    status_dir.mkdir()
    monkeypatch.setattr(updates.settings, "version", "0.32.5")
    monkeypatch.setattr(updates.settings, "update_url", "https://example.invalid/releases/latest")
    monkeypatch.setattr(updates.settings, "update_spool", str(spool))
    monkeypatch.setattr(updates.settings, "update_status_dir", str(status_dir))
    monkeypatch.setattr(updates.settings, "update_skip_backup", True)
    monkeypatch.setattr(updates.settings, "update_pre_hook", "")
    monkeypatch.setattr(updates, "detect_mode", lambda root=None, **_: "native")
    calls = []

    def fetch(url, timeout):
        calls.append(url)
        return _release_info()

    monkeypatch.setattr(updates, "_fetch_latest", fetch)
    return {"spool": spool, "status": status_dir, "calls": calls}


# -------------------------------------------------------------- mode -------
def test_a_git_checkout_is_git_even_if_configured_otherwise(tmp_path):
    (tmp_path / ".git").mkdir()
    (tmp_path / "install.sh").write_text("#!/bin/sh\n")
    assert updates.detect_mode(tmp_path, configured="native") == "git"
    assert updates.detect_mode(tmp_path, configured="docker") == "git"


def test_docker_marker_and_native_tree(tmp_path):
    assert updates.detect_mode(tmp_path, configured="docker") == "docker"
    (tmp_path / "install.sh").write_text("#!/bin/sh\n")
    if not Path("/.dockerenv").exists():
        assert updates.detect_mode(tmp_path, configured="") == "native"
        assert updates.detect_mode(tmp_path / "nothing-here", configured="") == "unknown"


def test_the_image_sets_the_docker_marker():
    dockerfile = (ROOT / "docker" / "Dockerfile").read_text()
    assert "VEYRS_INSTALL_MODE=docker" in dockerfile


def test_git_mode_refuses_with_managed_by_git_deploy(native, monkeypatch):
    monkeypatch.setattr(updates, "detect_mode", lambda root=None, **_: "git")
    st = updates.status()
    assert st["can_apply"] is False and "managed by git deploy" in st["reason"]


def test_docker_mode_cannot_apply_and_gets_the_host_command(native, monkeypatch):
    monkeypatch.setattr(updates, "detect_mode", lambda root=None, **_: "docker")
    st = updates.status()
    assert st["can_apply"] is False
    assert st["command"] and "veyrs-setup.sh --version 0.33.0" in st["command"]


# ------------------------------------------------------- release check -----
@pytest.mark.parametrize("latest,current,available", [
    ("0.33.0", "0.32.5", True),
    ("0.32.5", "0.32.5", False),
    ("0.32.4", "0.32.5", False),
    ("0.10.0", "0.9.9", True),     # numeric, not lexical
    ("1.0.0", "0.99.99", True),
])
def test_version_comparison(native, monkeypatch, latest, current, available):
    monkeypatch.setattr(updates.settings, "version", current)
    monkeypatch.setattr(updates, "_fetch_latest", lambda url, timeout: _release_info(latest))
    st = updates.status()
    assert st["update_available"] is available
    assert st["can_apply"] is available, st["reason"]


def test_an_empty_update_url_makes_no_network_call(native, monkeypatch):
    import httpx

    def boom(*a, **k):
        raise AssertionError("network used although VEYRS_UPDATE_URL is empty")

    monkeypatch.setattr(httpx, "get", boom)
    monkeypatch.setattr(updates, "_fetch_latest", boom)
    monkeypatch.setattr(updates.settings, "update_url", "")
    st = updates.status()
    assert st["check"]["disabled"] is True and st["latest"] is None
    assert st["can_apply"] is False and "disabled" in st["reason"]


#: services/updates._fetch_latest as shipped (the `native` fixture replaces it).
_ORIGINAL_FETCH = updates._fetch_latest


def test_a_network_failure_is_reported_not_raised(native, monkeypatch):
    """The shipped fetcher, with the transport failing underneath it."""
    import httpx

    def refuse(*a, **k):
        raise httpx.ConnectError("connection refused")

    monkeypatch.setattr(httpx, "get", refuse)
    monkeypatch.setattr(updates, "_fetch_latest", _ORIGINAL_FETCH)
    st = updates.status()
    assert st["check"]["checked"] is False
    assert "ConnectError" in st["check"]["error"]
    assert st["can_apply"] is False and "could not be determined" in st["reason"]
    # ...and a 200 with junk in it is a reported failure too, not a crash.
    class Junk:
        def raise_for_status(self):
            return None

        def json(self):
            return {"tag_name": "nightly"}

    updates.clear_cache()
    monkeypatch.setattr(httpx, "get", lambda *a, **k: Junk())
    st = updates.status()
    assert st["check"]["checked"] is False and "unexpected release tag" in st["check"]["error"]


def test_the_check_is_cached_for_an_hour(native):
    updates.latest_release()
    updates.latest_release()
    assert len(native["calls"]) == 1
    updates.latest_release(force=True)
    assert len(native["calls"]) == 2
    later = __import__("time").time() + updates.CACHE_TTL_SECONDS + 5
    updates.latest_release(now=later)
    assert len(native["calls"]) == 3


def test_parse_release_validates_what_it_hands_on():
    with pytest.raises(ValueError):
        updates.parse_release({"tag_name": "latest; rm -rf /"})
    info = updates.parse_release({"tag_name": "v0.33.0", "html_url": "javascript:alert(1)",
                                  "assets": [{"name": "SHA256SUMS"}]})
    assert info["notes_url"] is None and info["signed"] is False and info["version"] == "0.33.0"


def test_unsigned_release_or_no_backup_cannot_be_applied(native, monkeypatch):
    monkeypatch.setattr(updates, "_fetch_latest", lambda url, t: _release_info(signed=False))
    st = updates.status()
    assert st["can_apply"] is False and "SHA256SUMS.sig" in st["reason"]
    updates.clear_cache()
    monkeypatch.setattr(updates, "_fetch_latest", lambda url, t: _release_info())
    monkeypatch.setattr(updates.settings, "update_skip_backup", False)
    st = updates.status()
    assert st["can_apply"] is False and "VEYRS_UPDATE_PRE_HOOK" in st["reason"]


# ------------------------------------------------------------- spool -------
def test_request_apply_writes_exactly_one_file_with_no_secrets(native):
    req = updates.request_apply(target_version="0.33.0", requested_by="admin@example.com")
    files = list(native["spool"].iterdir())
    assert [f.name for f in files] == [req["file"]], "exactly one file, and no temp file left behind"
    data = json.loads(files[0].read_text())
    assert set(data) == set(updates.REQUEST_KEYS)
    assert data["target_version"] == "0.33.0" and data["requested_by"] == "admin@example.com"
    text = files[0].read_text().lower()
    for word in ("token", "password", "secret", "key"):
        assert word not in text
    assert updates.settings.secret_key not in files[0].read_text()
    assert oct(files[0].stat().st_mode & 0o777) == "0o600"
    with pytest.raises(updates.UpdateRefused):
        updates.request_apply(target_version="0.33.0", requested_by="again@example.com")
    assert len(list(native["spool"].iterdir())) == 1
    with pytest.raises(updates.UpdateRefused):
        updates.request_apply(target_version="../../x", requested_by="x", spool=native["spool"])


# --------------------------------------------------------------- API -------
def _make_platform_admin(org) -> None:
    org_id, _slug, email = org
    with SessionLocal() as session:
        set_tenant(session, org_id)
        user = session.execute(select(User).where(User.email == email)).scalar_one()
        user.is_superuser = True
        session.commit()


def test_the_api_is_platform_admin_only(client, org_a, native):
    _, slug, email = org_a
    headers = auth_headers(client, email, slug)   # org-admin (wildcard), NOT platform admin
    assert client.get("/api/v1/admin/updates", headers=headers).status_code == 403
    r = client.post("/api/v1/admin/updates/apply", headers=headers, json={})
    assert r.status_code == 403
    assert list(native["spool"].iterdir()) == []
    assert client.get("/api/v1/admin/updates").status_code == 401


def test_apply_queues_one_request_and_is_audited(client, org_a, native):
    _make_platform_admin(org_a)
    org_id, slug, email = org_a
    headers = auth_headers(client, email, slug)
    st = client.get("/api/v1/admin/updates", headers=headers)
    assert st.status_code == 200, st.text
    body = st.json()
    assert body["current"] == "0.32.5" and body["latest"] == "0.33.0" and body["signed"] is True
    assert body["mode"] == "native" and body["can_apply"] is True, body["reason"]

    r = client.post("/api/v1/admin/updates/apply", headers=headers, json={"version": "0.33.0"})
    assert r.status_code == 202, r.text
    files = list(native["spool"].glob("*.json"))
    assert len(files) == 1
    assert json.loads(files[0].read_text())["requested_by"] == email

    with SessionLocal() as session:
        set_tenant(session, org_id)
        rows = session.execute(select(AuditLog).where(
            AuditLog.organization_id == org_id,
            AuditLog.action == "software.update.requested")).scalars().all()
    assert len(rows) == 1 and rows[0].object_label == "0.32.5 -> 0.33.0"

    again = client.post("/api/v1/admin/updates/apply", headers=headers, json={})
    assert again.status_code == 409 and "already queued" in again.json()["detail"]
    assert len(list(native["spool"].glob("*.json"))) == 1


def test_apply_is_refused_where_the_updater_would_refuse(client, org_a, native, monkeypatch):
    _make_platform_admin(org_a)
    _, slug, email = org_a
    headers = auth_headers(client, email, slug)
    monkeypatch.setattr(updates, "detect_mode", lambda root=None, **_: "git")
    r = client.post("/api/v1/admin/updates/apply", headers=headers, json={})
    assert r.status_code == 409 and "managed by git deploy" in r.json()["detail"]
    monkeypatch.setattr(updates, "detect_mode", lambda root=None, **_: "native")
    r = client.post("/api/v1/admin/updates/apply", headers=headers, json={"version": "9.9.9"})
    assert r.status_code == 409 and "reload the page" in r.json()["detail"]
    assert list(native["spool"].iterdir()) == []


def test_get_returns_the_recent_status_files(client, org_a, native):
    _make_platform_admin(org_a)
    _, slug, email = org_a
    (native["status"] / "20261026T000000Z-x.json").write_text(json.dumps({
        "id": "x", "state": "refused", "ok": False, "target_version": "0.33.0",
        "steps": [{"name": "verify", "ok": False, "detail": "BAD SIGNATURE", "at": "2026-10-26T00:00:00Z"}],
    }))
    (native["status"] / "broken.json").write_text("{not json")
    body = client.get("/api/v1/admin/updates", headers=auth_headers(client, email, slug)).json()
    names = {h["file"]: h for h in body["history"]}
    assert names["20261026T000000Z-x.json"]["steps"][0]["detail"] == "BAD SIGNATURE"
    assert "unreadable" in names["broken.json"]["error"]


# ------------------------------------------------------- the root updater --
needs_tools = pytest.mark.skipif(
    any(shutil.which(t) is None for t in ("ssh-keygen", "curl", "bash", "tar", "sha256sum")),
    reason="the updater test needs ssh-keygen, curl, bash, tar and sha256sum",
)


class _Health(http.server.BaseHTTPRequestHandler):
    version = "0.33.0"

    def do_GET(self):  # noqa: N802
        if self.path == "/healthz":
            payload = json.dumps({"status": "ok", "version": self.version}).encode()
            self.send_response(200)
        elif self.path == "/readyz":
            payload = b'{"status":"ready"}'
            self.send_response(200)
        else:
            payload = b"{}"
            self.send_response(404)
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(payload)

    def log_message(self, *args):
        pass


@pytest.fixture()
def bench(tmp_path):
    """A fake native install, a fake signed release over file://, a spool."""
    keys = tmp_path / "keys"
    key, signers = make_key(keys, "release")
    impostor, _ = make_key(keys, "impostor")
    app = tmp_path / "app"
    (app / "scripts").mkdir(parents=True)
    (app / "release").mkdir()
    shutil.copy(ROOT / "scripts" / "verify-release.sh", app / "scripts" / "verify-release.sh")
    shutil.copy(signers, app / "release" / "allowed_signers")
    (app / "install.sh").write_text("#!/bin/sh\nexit 0\n")
    (app / "pyproject.toml").write_text('[project]\nname = "veyrs"\nversion = "0.32.5"\n')
    marker = tmp_path / "setup-ran.txt"
    setup = ('#!/usr/bin/env bash\n'
             f'printf "%s\\n" "$*" "SETUP_EXISTING=$SETUP_EXISTING" "SETUP_MODE=$SETUP_MODE" > "{marker}"\n')
    rel = tmp_path / "rel" / "v0.33.0"
    make_release(rel, key, setup_body=setup)
    spool = tmp_path / "spool"
    spool.mkdir()
    status_dir = tmp_path / "status"
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Health)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = {
        "PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp_path),
        "VEYRS_UPDATER_APP_DIR": str(app), "VEYRS_UPDATE_SPOOL": str(spool),
        "VEYRS_UPDATE_STATUS_DIR": str(status_dir),
        "VEYRS_UPDATE_DOWNLOAD_BASE": f"file://{tmp_path / 'rel'}",
        "VEYRS_UPDATE_SKIP_BACKUP": "1",
        "VEYRS_UPDATER_HEALTH_URL": f"http://127.0.0.1:{server.server_address[1]}",
        "VEYRS_UPDATER_HEALTH_TIMEOUT": "10",
    }
    yield {"app": app, "rel": rel, "spool": spool, "status": status_dir, "env": env,
           "key": key, "impostor": impostor, "marker": marker, "tmp": tmp_path}
    server.shutdown()


def _request(bench, version="0.33.0", who="admin@example.com") -> Path:
    req = bench["spool"] / f"request-{uuid.uuid4().hex[:8]}.json"
    req.write_text(json.dumps({"target_version": version, "from_version": "0.32.5",
                               "requested_by": who, "requested_at": "2026-10-26T00:00:00Z"}, indent=2))
    return req


def _run(bench, **env_extra) -> tuple[subprocess.CompletedProcess, dict]:
    r = subprocess.run(["bash", str(UPDATER)], capture_output=True, text=True, timeout=120,
                       env={**bench["env"], **env_extra})
    files = sorted(bench["status"].glob("*.json"))
    assert len(files) == 1, f"one status file per run, got {files}\n{r.stdout}\n{r.stderr}"
    return r, json.loads(files[0].read_text())


def _steps(status: dict) -> list[str]:
    return [s["name"] for s in status["steps"]]


@needs_tools
def test_updater_happy_path_writes_every_step(bench):
    req = _request(bench)
    r, st = _run(bench)
    assert r.returncode == 0, r.stdout + r.stderr
    assert st["state"] == "succeeded" and st["ok"] is True
    assert _steps(st) == ["request", "preflight", "download", "verify", "backup", "install", "health"]
    assert all(s["ok"] and s["at"] for s in st["steps"])
    assert st["requested_by"] == "admin@example.com" and st["from_version"] == "0.32.5"
    ran = bench["marker"].read_text().splitlines()
    assert ran[0].startswith("--yes --version 0.33.0 --source ") and ran[0].endswith("veyrs-0.33.0-src.tar.gz")
    assert "SETUP_EXISTING=update" in ran and "SETUP_MODE=native" in ran
    assert not req.exists(), "the request must be removed"
    # The console reads it through the service.
    hist = updates.recent_status(status_dir=bench["status"])
    assert hist[0]["ok"] is True and len(hist[0]["steps"]) == 7


@needs_tools
def test_updater_refuses_an_unsigned_release(bench):
    (bench["rel"] / "SHA256SUMS.sig").unlink()
    req = _request(bench)
    r, st = _run(bench)
    assert r.returncode == 1 and st["state"] == "refused"
    assert st["steps"][-1]["name"] == "download" and "UNSIGNED" in st["steps"][-1]["detail"]
    assert not bench["marker"].exists(), "nothing may be installed"
    assert not req.exists()


@needs_tools
def test_updater_refuses_a_bad_hash(bench):
    with open(bench["rel"] / "veyrs-0.33.0-src.tar.gz", "ab") as fh:
        fh.write(b"tampered")
    _request(bench)
    r, st = _run(bench)
    assert r.returncode == 1 and st["state"] == "refused"
    assert st["steps"][-1]["name"] == "verify" and "HASH MISMATCH" in st["steps"][-1]["detail"]
    assert not bench["marker"].exists()


@needs_tools
def test_updater_refuses_a_signature_by_another_key(bench):
    sign(bench["rel"], bench["impostor"])
    _request(bench)
    r, st = _run(bench)
    assert st["state"] == "refused" and "BAD SIGNATURE" in st["steps"][-1]["detail"]
    assert not bench["marker"].exists()


@needs_tools
def test_updater_with_the_placeholder_key_cannot_verify(bench):
    (bench["app"] / "release" / "allowed_signers").write_text(PLACEHOLDER_LINE)
    _request(bench)
    r, st = _run(bench)
    assert st["state"] == "refused" and "CANNOT VERIFY" in st["steps"][-1]["detail"]
    assert not bench["marker"].exists()


@needs_tools
def test_updater_refuses_a_git_checkout_before_downloading(bench):
    (bench["app"] / ".git").mkdir()
    _request(bench)
    r, st = _run(bench)
    assert st["state"] == "refused" and _steps(st) == ["request", "preflight"]
    assert "managed by git deploy" in st["steps"][-1]["detail"]


@needs_tools
def test_updater_refuses_without_a_backup_arrangement(bench):
    env = dict(bench["env"])
    env.pop("VEYRS_UPDATE_SKIP_BACKUP")
    bench["env"] = env
    _request(bench)
    r, st = _run(bench)
    assert st["state"] == "refused" and "VEYRS_UPDATE_PRE_HOOK" in st["steps"][-1]["detail"]


@needs_tools
def test_updater_refuses_a_target_that_is_not_newer_and_a_malformed_request(bench):
    _request(bench, version="0.32.5")
    r, st = _run(bench)
    assert st["state"] == "refused" and "not newer" in st["steps"][-1]["detail"]
    for f in bench["status"].glob("*"):
        f.unlink()
    (bench["spool"] / "request-bad.json").write_text('{"target_version": "1.0; reboot"}')
    r, st = _run(bench)
    assert st["state"] == "refused" and _steps(st) == ["request"]
    assert list(bench["spool"].glob("*.json")) == []


@needs_tools
@pytest.mark.skipif(os.geteuid() != 0, reason="the hook ownership check needs root to set up")
def test_updater_runs_a_safe_pre_hook_and_refuses_an_unsafe_one(bench):
    marker = bench["tmp"] / "hook-ran"
    hook = bench["tmp"] / "hook.sh"
    hook.write_text(f'#!/bin/sh\necho "$VEYRS_UPDATE_FROM->$VEYRS_UPDATE_TARGET" > "{marker}"\n')
    hook.chmod(0o775)   # group-writable: refused
    _request(bench)
    r, st = _run(bench, VEYRS_UPDATE_PRE_HOOK=str(hook))
    assert st["state"] == "refused" and "writable by group/other" in st["steps"][-1]["detail"]
    assert not marker.exists()
    for f in bench["status"].glob("*"):
        f.unlink()
    hook.chmod(0o755)
    _request(bench)
    r, st = _run(bench, VEYRS_UPDATE_PRE_HOOK=str(hook))
    assert st["state"] == "succeeded", st
    assert marker.read_text().strip() == "0.32.5->0.33.0"
