"""Phase 55 -- software update from a LOCAL copy (upload or a mounted directory).

* The service finds a release in the uploads or in VEYRS_UPDATE_LOCAL_DIR and
  says, before anybody clicks, whether its signature verifies.
* The console uploads in chunks: names are allowlisted, offsets must follow.
* The request carries a KEYWORD (release / upload / local), never a path.
* The root updater copies local files into its own work dir, refuses links,
  unsigned or incomplete copies, and hands the wheelhouse to the installer.
"""
from __future__ import annotations

import hashlib
import io
import json
import os
import shutil
import subprocess
import tarfile
import uuid
from pathlib import Path

import pytest

from tests.conftest import auth_headers
from tests.test_phase52_release_signing import make_key, make_release, sign, write_sums
from tests.test_phase52_updates import _Health, _make_platform_admin, needs_tools  # noqa: F401
from veyrs.services import updates

ROOT = Path(__file__).resolve().parents[1]
UPDATER = ROOT / "scripts" / "veyrs-updater.sh"


def add_wheels(rel: Path, key: Path, version: str = "0.34.0") -> str:
    """A fake wheelhouse asset, listed in SHA256SUMS and re-signed."""
    name = f"veyrs-{version}-wheels-x86_64.tar.gz"
    with tarfile.open(rel / name, "w:gz") as tar:
        data = b"not really a wheel"
        info = tarfile.TarInfo("wheels/demo-1.0-py3-none-any.whl")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))
    digest = hashlib.sha256((rel / name).read_bytes()).hexdigest()
    (rel / f"{name}.sha256").write_text(f"{digest}  {name}\n")
    tgz = f"veyrs-{version}-src.tar.gz"
    write_sums(rel, ["veyrs-setup.sh", "veyrs-setup.sh.sha256", tgz, f"{tgz}.sha256", name, f"{name}.sha256"])
    sign(rel, key)
    return name


@pytest.fixture()
def fake_root(tmp_path, monkeypatch):
    """An install root whose trusted key is a throwaway one; a local dir; uploads."""
    key, signers = make_key(tmp_path / "keys", "release")
    root = tmp_path / "app"
    (root / "scripts").mkdir(parents=True)
    (root / "release").mkdir()
    shutil.copy(ROOT / "scripts" / "verify-release.sh", root / "scripts" / "verify-release.sh")
    shutil.copy(signers, root / "release" / "allowed_signers")
    spool = tmp_path / "spool"
    spool.mkdir()
    local = tmp_path / "usb"
    local.mkdir()
    monkeypatch.setattr(updates, "INSTALL_ROOT", root)
    monkeypatch.setattr(updates.settings, "version", "0.33.2")
    monkeypatch.setattr(updates.settings, "update_url", "")
    monkeypatch.setattr(updates.settings, "update_spool", str(spool))
    monkeypatch.setattr(updates.settings, "update_status_dir", str(tmp_path / "status"))
    monkeypatch.setattr(updates.settings, "update_skip_backup", True)
    monkeypatch.setattr(updates.settings, "update_local_dir", str(local))
    monkeypatch.setattr(updates.settings, "update_upload_dir", str(tmp_path / "uploads"))
    monkeypatch.setattr(updates, "detect_mode", lambda root=None, **_: "native")
    updates.clear_cache()
    updates._verify_cache.clear()
    return {"key": key, "local": local, "spool": spool, "tmp": tmp_path}


# ------------------------------------------------------------- service ---
@needs_tools
def test_a_signed_copy_in_the_local_dir_is_found_and_applicable(fake_root):
    rel = fake_root["local"] / "v0.34.0"
    make_release(rel, fake_root["key"], version="0.34.0")
    add_wheels(rel, fake_root["key"])
    st = updates.status()
    [item] = [i for i in st["local"] if i["version"] == "0.34.0"]
    assert item["origin"] == "local" and item["verification"] == "signed" and item["has_wheels"]
    assert item["can_apply"] is True, item["reason"]


@needs_tools
def test_flat_layout_unsigned_and_tampered_copies_are_not_applicable(fake_root, tmp_path):
    flat = fake_root["local"]
    make_release(flat, None, version="0.34.0")                 # unsigned, files directly in the dir
    item = next(i for i in updates.local_releases() if i["path"] == str(flat))
    assert item["verification"] in ("unsigned", "incomplete") and not item.get("can_apply")

    other = fake_root["local"] / "veyrs-0.35.0"
    make_release(other, fake_root["key"], version="0.35.0")
    with open(other / "veyrs-0.35.0-src.tar.gz", "ab") as fh:
        fh.write(b"x")
    updates._verify_cache.clear()
    item = next(i for i in updates.local_releases() if i["version"] == "0.35.0")
    assert item["verification"] == "hash_mismatch"
    st = updates.status()
    assert not next(i for i in st["local"] if i["version"] == "0.35.0")["can_apply"]


@needs_tools
def test_an_older_or_equal_copy_is_not_applicable(fake_root):
    make_release(fake_root["local"] / "v0.33.2", fake_root["key"], version="0.33.2")
    item = next(i for i in updates.status()["local"] if i["version"] == "0.33.2")
    assert item["can_apply"] is False and "not newer" in item["reason"]


def test_the_request_carries_a_keyword_never_a_path(fake_root):
    q = updates.request_apply(target_version="0.34.0", requested_by="a@b", source="local")
    data = json.loads(next(fake_root["spool"].glob("*.json")).read_text())
    assert data["source"] == "local" and set(data) <= set(updates.REQUEST_KEYS)
    assert "/" not in json.dumps({k: v for k, v in data.items() if k != "requested_at"})
    with pytest.raises(updates.UpdateRefused):
        updates.request_apply(target_version="0.34.0", requested_by="a@b", source="/etc")


# ------------------------------------------------------------- uploads ---
def test_upload_names_offsets_and_versions_are_checked(fake_root):
    uid = updates.upload_start()
    with pytest.raises(updates.UploadError):
        updates.upload_chunk(uid, "../../etc/passwd", 0, 10, b"x")
    with pytest.raises(updates.UploadError):
        updates.upload_chunk(uid, "evil.sh", 0, 10, b"x")
    updates.upload_chunk(uid, "veyrs-setup.sh", 0, 4, b"ab")
    with pytest.raises(updates.UploadError):
        updates.upload_chunk(uid, "veyrs-setup.sh", 0, 4, b"cd")     # offset must follow
    updates.upload_chunk(uid, "veyrs-setup.sh", 2, 4, b"cd")
    with pytest.raises(updates.UploadError):
        updates.upload_finish(uid)                                    # no src tarball
    with pytest.raises(updates.UploadError):
        updates.upload_chunk("not-an-id", "SHA256SUMS", 0, 1, b"x")


@needs_tools
def test_upload_through_the_api_then_apply(client, org_a, fake_root):
    _make_platform_admin(org_a)
    _, slug, email = org_a
    h = auth_headers(client, email, slug)
    src = fake_root["tmp"] / "dl"
    make_release(src, fake_root["key"], version="0.34.0")
    add_wheels(src, fake_root["key"])
    uid = client.post("/api/v1/admin/updates/uploads", headers=h).json()["upload_id"]
    for f in sorted(src.iterdir()):
        data = f.read_bytes()
        for off in range(0, len(data), 7):          # tiny chunks: exercises the offsets
            r = client.put(f"/api/v1/admin/updates/uploads/{uid}/{f.name}?offset={off}&total={len(data)}",
                           headers=h, content=data[off:off + 7])
            assert r.status_code == 200, r.text
    fin = client.post(f"/api/v1/admin/updates/uploads/{uid}/finish", headers=h)
    assert fin.status_code == 200, fin.text
    assert fin.json()["version"] == "0.34.0" and fin.json()["verification"] == "signed"

    st = client.get("/api/v1/admin/updates", headers=h).json()
    item = next(i for i in st["local"] if i["origin"] == "upload")
    assert item["can_apply"], item["reason"]
    r = client.post("/api/v1/admin/updates/apply", headers=h, json={"version": "0.34.0", "source": "upload"})
    assert r.status_code == 202, r.text
    assert json.loads(next(fake_root["spool"].glob("*.json")).read_text())["source"] == "upload"

    assert client.delete("/api/v1/admin/updates/uploads/0.34.0", headers=h).status_code == 204
    assert client.delete("/api/v1/admin/updates/uploads/0.34.0", headers=h).status_code == 404


def test_uploads_are_platform_admin_only(client, org_a, fake_root):
    _, slug, email = org_a
    h = auth_headers(client, email, slug)
    assert client.post("/api/v1/admin/updates/uploads", headers=h).status_code == 403
    assert client.put("/api/v1/admin/updates/uploads/abc/SHA256SUMS?offset=0&total=1",
                      headers=h, content=b"x").status_code == 403


def test_apply_from_an_unknown_local_copy_is_refused(client, org_a, fake_root):
    _make_platform_admin(org_a)
    _, slug, email = org_a
    h = auth_headers(client, email, slug)
    r = client.post("/api/v1/admin/updates/apply", headers=h, json={"version": "9.9.9", "source": "local"})
    assert r.status_code == 404


# ------------------------------------------------------ the root updater ---
@pytest.fixture()
def bench(tmp_path):
    keys = tmp_path / "keys"
    key, signers = make_key(keys, "release")
    app = tmp_path / "app"
    (app / "scripts").mkdir(parents=True)
    (app / "release").mkdir()
    shutil.copy(ROOT / "scripts" / "verify-release.sh", app / "scripts" / "verify-release.sh")
    shutil.copy(signers, app / "release" / "allowed_signers")
    (app / "install.sh").write_text("#!/bin/sh\nexit 0\n")
    (app / "pyproject.toml").write_text('[project]\nname = "veyrs"\nversion = "0.33.2"\n')
    marker = tmp_path / "setup-ran.txt"
    setup = f'#!/usr/bin/env bash\nprintf "%s\\n" "$*" > "{marker}"\n'
    spool = tmp_path / "spool"
    spool.mkdir()
    import http.server
    import threading

    _Health.version = "0.34.0"
    server = http.server.ThreadingHTTPServer(("127.0.0.1", 0), _Health)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(tmp_path),
           "VEYRS_UPDATER_APP_DIR": str(app), "VEYRS_UPDATE_SPOOL": str(spool),
           "VEYRS_UPDATE_STATUS_DIR": str(tmp_path / "status"),
           "VEYRS_UPDATE_DOWNLOAD_BASE": "file:///nonexistent",
           "VEYRS_UPDATE_LOCAL_DIR": str(tmp_path / "usb"), "VEYRS_UPDATE_SKIP_BACKUP": "1",
           "VEYRS_UPDATER_HEALTH_URL": f"http://127.0.0.1:{server.server_address[1]}",
           "VEYRS_UPDATER_HEALTH_TIMEOUT": "10"}
    yield {"app": app, "key": key, "setup": setup, "spool": spool, "env": env, "marker": marker, "tmp": tmp_path}
    server.shutdown()
    _Health.version = "0.33.0"


def _request(bench, source, version="0.34.0"):
    (bench["spool"] / f"request-{uuid.uuid4().hex[:8]}.json").write_text(json.dumps(
        {"target_version": version, "from_version": "0.33.2", "requested_by": "admin@example.com",
         "requested_at": "2026-10-28T00:00:00Z", "source": source}))


def _run(bench):
    r = subprocess.run(["bash", str(UPDATER)], capture_output=True, text=True, timeout=120, env=bench["env"])
    st = json.loads(next((bench["tmp"] / "status").glob("*.json")).read_text())
    return r, st


@needs_tools
def test_updater_local_dir_with_wheels(bench):
    rel = bench["tmp"] / "usb" / "v0.34.0"
    make_release(rel, bench["key"], version="0.34.0", setup_body=bench["setup"])
    whl = add_wheels(rel, bench["key"])
    _request(bench, "local")
    r, st = _run(bench)
    assert r.returncode == 0 and st["state"] == "succeeded", r.stdout + r.stderr
    download = next(s for s in st["steps"] if s["name"] == "download")
    assert str(rel) in download["detail"] and whl in download["detail"]
    ran = bench["marker"].read_text()
    assert "--source " in ran and f"--wheels " in ran and ran.strip().endswith(whl)
    assert "/var/tmp/veyrs-update." in ran, "the installer must read the root-only copy, not the USB"


@needs_tools
def test_updater_upload_source(bench):
    rel = bench["app"] / "var" / "update-uploads" / "v0.34.0"
    make_release(rel, bench["key"], version="0.34.0", setup_body=bench["setup"])
    _request(bench, "upload")
    r, st = _run(bench)
    assert st["state"] == "succeeded", r.stdout + r.stderr
    assert "--wheels" not in bench["marker"].read_text()


@needs_tools
def test_updater_refuses_a_symlink_in_a_local_copy(bench):
    rel = bench["tmp"] / "usb" / "v0.34.0"
    make_release(rel, bench["key"], version="0.34.0", setup_body=bench["setup"])
    os.replace(rel / "veyrs-setup.sh", bench["tmp"] / "real-setup.sh")
    os.symlink(bench["tmp"] / "real-setup.sh", rel / "veyrs-setup.sh")
    _request(bench, "local")
    r, st = _run(bench)
    assert st["state"] == "refused" and "not a regular file" in st["steps"][-1]["detail"]
    assert not bench["marker"].exists()


@needs_tools
def test_updater_refuses_an_unsigned_or_incomplete_local_copy(bench):
    rel = bench["tmp"] / "usb" / "v0.34.0"
    make_release(rel, bench["key"], version="0.34.0", setup_body=bench["setup"])
    add_wheels(rel, bench["key"])
    (rel / "veyrs-0.34.0-wheels-x86_64.tar.gz").unlink()
    _request(bench, "local")
    r, st = _run(bench)
    assert st["state"] == "refused" and "lists" in st["steps"][-1]["detail"]
    shutil.rmtree(bench["tmp"] / "status")
    make_release(rel, None, version="0.34.0", setup_body=bench["setup"])
    (rel / "SHA256SUMS.sig").unlink(missing_ok=True)
    _request(bench, "local")
    r, st = _run(bench)
    assert st["state"] == "refused" and "UNSIGNED" in st["steps"][-1]["detail"]
    assert not bench["marker"].exists()


@needs_tools
def test_updater_refuses_an_unknown_source(bench):
    _request(bench, "/etc/shadow")
    r, st = _run(bench)
    assert st["state"] == "refused" and st["steps"][-1]["name"] == "request"


@needs_tools
def test_updater_local_without_a_configured_dir(bench):
    bench["env"]["VEYRS_UPDATE_LOCAL_DIR"] = ""
    _request(bench, "local")
    r, st = _run(bench)
    assert st["state"] == "refused" and "VEYRS_UPDATE_LOCAL_DIR" in st["steps"][-1]["detail"]


# ------------------------------------------------------- static guards ---
def test_installer_chain_passes_the_wheelhouse():
    setup = (ROOT / "veyrs-setup.sh").read_text()
    install = (ROOT / "install.sh").read_text()
    assert 'VEYRS_PIP_WHEELHOUSE="$WHEELHOUSE"' in setup and "--wheels)" in setup
    assert '--no-index --find-links "$VEYRS_PIP_WHEELHOUSE"' in install
    publish = (ROOT / "scripts" / "publish-github.sh").read_text()
    assert "asset_wheels" in publish and "verify_wheelhouse" in publish
