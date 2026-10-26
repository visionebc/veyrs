"""Software update check, and the UNPRIVILEGED half of self-update.

Two halves, in two processes, on purpose:

* This module runs inside the API. It answers "what is installed, what is the
  latest release, is it signed, can THIS installation apply it?" and -- when a
  platform administrator asks -- writes one small request file into a spool
  directory. That is all it can do.
* `scripts/veyrs-updater.sh`, run as root by `veyrs-updater.service` when that
  file appears (`veyrs-updater.path`), downloads the release, verifies its
  signature against the trusted key of the INSTALLED tree, runs the pre-update
  backup hook, installs, checks `/healthz` and `/readyz`, and leaves a status
  JSON with its steps for `recent_status()` to show.

The API never updates itself: a process cannot verify, replace and restart its
own code without trusting the very code it is replacing, and the API runs
sandboxed (`ProtectSystem=strict`) precisely so that it cannot write its tree.

Install modes:

* ``git``    -- a `.git` directory in the install root. That is how the
  operator's own environment is deployed; the git deploy owns it, and
  self-update refuses there, always.
* ``docker`` -- the image sets ``VEYRS_INSTALL_MODE=docker``. A container is
  replaced, not patched: the answer is the host command that re-runs the
  installer.
* ``native`` -- an `install.sh` tree. The only mode the root updater applies.
"""
from __future__ import annotations

import datetime as dt
import json
import logging
import os
import re
import secrets
import threading
import time
from pathlib import Path
from typing import Any, Callable

from ..config import settings
from . import versions

log = logging.getLogger("veyrs.updates")

#: backend/veyrs/services/updates.py -> the install root (where install.sh lives).
INSTALL_ROOT = Path(__file__).resolve().parents[3]
CACHE_TTL_SECONDS = 3600
#: A failed check is retried sooner, but not on every page load.
FAILURE_TTL_SECONDS = 300
SIGNATURE_ASSET = "SHA256SUMS.sig"
VERSION_RE = re.compile(r"^\d+\.\d+\.\d+$")
MODES = ("git", "docker", "native")
#: Keys a request file may carry. Nothing else is ever written into the spool:
#: the root process reads it, so it holds a version string and who asked.
REQUEST_KEYS = ("target_version", "from_version", "requested_by", "requested_at")
_STATUS_MAX_BYTES = 256 * 1024

_cache: dict[str, tuple[float, dict]] = {}
_lock = threading.Lock()


class UpdateRefused(Exception):
    """A request the spool cannot take (already pending, no spool, bad version)."""


def _now_iso() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="seconds")


def clear_cache() -> None:
    with _lock:
        _cache.clear()


# --------------------------------------------------------------- mode ---
def detect_mode(root: Path | str | None = None, *, configured: str | None = None) -> str:
    """`git` | `docker` | `native` | `unknown` for the tree at `root`."""
    root = Path(root) if root is not None else INSTALL_ROOT
    # First, and not overridable: a git checkout is managed by its git deploy.
    # A VEYRS_INSTALL_MODE=native left in its .env must not talk the console
    # into overwriting a working copy.
    if (root / ".git").exists():
        return "git"
    mode = (settings.install_mode if configured is None else configured or "").strip().lower()
    if mode in MODES:
        return mode
    if Path("/.dockerenv").exists():
        return "docker"
    if (root / "install.sh").is_file():
        return "native"
    return "unknown"


# ------------------------------------------------------- latest release ---
def _safe_url(value: Any) -> str | None:
    """Only an https URL is handed to the console as a link."""
    text = str(value or "")
    return text if text.startswith("https://") and len(text) < 500 else None


def _fetch_latest(url: str, timeout: float) -> dict:
    import httpx  # local: `import veyrs` stays free of network clients

    response = httpx.get(
        url,
        timeout=timeout,
        follow_redirects=True,
        headers={"Accept": "application/vnd.github+json",
                 "User-Agent": f"veyrs/{settings.version} update-check"},
    )
    response.raise_for_status()
    return parse_release(response.json())


def parse_release(data: Any) -> dict:
    """The fields of a GitHub "release" object this module uses, validated."""
    if not isinstance(data, dict):
        raise ValueError("the release answer is not a JSON object")
    tag = str(data.get("tag_name") or "")
    version = tag[1:] if tag[:1] in ("v", "V") else tag
    if not VERSION_RE.match(version):
        raise ValueError(f"unexpected release tag {tag[:40]!r}")
    names = [str(a.get("name")) for a in (data.get("assets") or []) if isinstance(a, dict)]
    return {
        "version": version,
        "published_at": str(data.get("published_at") or "") or None,
        "notes_url": _safe_url(data.get("html_url")),
        "signed": SIGNATURE_ASSET in names,
        "assets": names[:50],
    }


def latest_release(
    *,
    force: bool = False,
    url: str | None = None,
    fetcher: Callable[[str, float], dict] | None = None,
    now: float | None = None,
) -> dict:
    """The latest published release, cached for an hour. Never raises.

    An empty `VEYRS_UPDATE_URL` disables the check without touching the
    network. A network or parsing failure is REPORTED in the result (and
    cached for five minutes), never raised: a console page must not 500
    because GitHub is unreachable from an air-gapped host.
    """
    url = settings.update_url if url is None else url
    if not (url or "").strip():
        return {"checked": False, "disabled": True, "error": None, "cached": False,
                "reason": "update checks are disabled (VEYRS_UPDATE_URL is empty)"}
    now = time.time() if now is None else now
    with _lock:
        hit = _cache.get(url)
    if hit and not force and hit[0] > now:
        return dict(hit[1], cached=True)
    try:
        info = (fetcher or _fetch_latest)(url, 10.0)
        result = {"checked": True, "disabled": False, "error": None,
                  "checked_at": _now_iso(), **info}
        ttl = CACHE_TTL_SECONDS
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        log.warning("update check against %s failed: %s", url, exc)
        result = {"checked": False, "disabled": False, "checked_at": _now_iso(),
                  "error": f"{type(exc).__name__}: {str(exc)[:200]}"}
        ttl = FAILURE_TTL_SECONDS
    with _lock:
        _cache[url] = (now + ttl, result)
    return dict(result, cached=False)


# ------------------------------------------------------------- spool ---
def _spool(spool: Path | str | None) -> Path:
    return Path(spool or settings.update_spool)


def pending_requests(spool: Path | str | None = None) -> list[str]:
    d = _spool(spool)
    try:
        return sorted(p.name for p in d.glob("*.json") if p.is_file())
    except OSError:
        return []


def backup_configured() -> bool:
    return bool((settings.update_pre_hook or "").strip()) or bool(settings.update_skip_backup)


def docker_command(version: str | None) -> str:
    """What a Docker host runs instead: the installer, which knows the stack."""
    v = version if version and VERSION_RE.match(version) else "<X.Y.Z>"
    base = (settings.update_download_base or "").rstrip("/") or \
        "https://github.com/visionebc/veyrs/releases/download"
    return (f"curl -fsSLO {base}/v{v}/veyrs-setup.sh && "
            f"sudo bash veyrs-setup.sh --version {v}")


def _can_apply(mode: str, latest: dict, update_available: bool,
               pending: list[str], spool: Path) -> tuple[bool, str]:
    target = latest.get("version")
    if mode == "git":
        return False, ("managed by git deploy: this installation is a git checkout and is "
                       "updated by its git deploy, never from the console")
    if mode == "docker":
        return False, ("a Docker installation is updated on the host by re-running the "
                       "installer (see the command below); a container is replaced, not patched")
    if mode != "native":
        return False, "the install mode could not be determined (no install.sh in the install root)"
    if latest.get("disabled"):
        return False, latest.get("reason") or "update checks are disabled"
    if not latest.get("checked"):
        return False, f"the latest release could not be determined: {latest.get('error') or 'unknown error'}"
    if not update_available:
        return False, "this installation already runs the latest release"
    if not latest.get("signed"):
        return False, (f"release {target} carries no {SIGNATURE_ASSET}: the updater only "
                       "installs releases whose signature it can verify")
    if not backup_configured():
        return False, ("no pre-update backup is configured: set VEYRS_UPDATE_PRE_HOOK (for example "
                       "/opt/veyrs/scripts/backup.sh) or, deliberately, VEYRS_UPDATE_SKIP_BACKUP=1 "
                       "in .env -- the updater refuses otherwise")
    if pending:
        return False, "an update request is already queued for the updater"
    if not spool.is_dir() or not os.access(spool, os.W_OK):
        return False, (f"the update spool {spool} does not exist or is not writable by the API: "
                       "the veyrs-updater units are not installed (re-run install.sh)")
    return True, f"release {target} can be applied by the root updater"


def status(*, force: bool = False, root: Path | str | None = None,
           spool: Path | str | None = None, mode: str | None = None) -> dict:
    """Everything the console's Software update tab shows, in one answer."""
    current = settings.version
    mode = mode or detect_mode(root)
    latest = latest_release(force=force)
    target = latest.get("version")
    update_available = bool(target) and versions.compare(target, current) > 0
    spool_path = _spool(spool)
    pending = pending_requests(spool_path)
    can_apply, reason = _can_apply(mode, latest, update_available, pending, spool_path)
    return {
        "current": current,
        "latest": target,
        "published_at": latest.get("published_at"),
        "notes_url": latest.get("notes_url"),
        "signed": bool(latest.get("signed")),
        "update_available": update_available,
        "mode": mode,
        "can_apply": can_apply,
        "reason": reason,
        "command": docker_command(target) if mode == "docker" else None,
        "pending": pending,
        "check": {k: latest.get(k) for k in ("checked", "disabled", "error", "checked_at", "cached")},
    }


def request_apply(*, target_version: str, requested_by: str, from_version: str | None = None,
                  spool: Path | str | None = None) -> dict:
    """Write exactly ONE request file into the spool, atomically.

    The file holds the target version and who asked -- nothing secret, because
    a root process reads it and a status page echoes it. It is written under a
    dot-name and renamed into place, so `veyrs-updater.path` (PathExistsGlob
    `*.json`) never sees half a file.
    """
    if not VERSION_RE.match(target_version or ""):
        raise UpdateRefused(f"not a release version: {target_version!r}")
    d = _spool(spool)
    if not d.is_dir():
        raise UpdateRefused(f"the update spool {d} does not exist (the updater units are not installed)")
    if pending_requests(d):
        raise UpdateRefused("an update request is already queued")
    payload = {
        "target_version": target_version,
        "from_version": from_version or settings.version,
        "requested_by": (requested_by or "unknown")[:200],
        "requested_at": _now_iso(),
    }
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    name = f"request-{stamp}-{secrets.token_hex(4)}.json"
    tmp = d / f".{name}.part"
    try:
        fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
        with os.fdopen(fd, "w", encoding="utf-8") as fh:
            json.dump(payload, fh, indent=2)
            fh.write("\n")
            fh.flush()
            os.fsync(fh.fileno())
        os.replace(tmp, d / name)
    except OSError as exc:
        try:
            tmp.unlink()
        except OSError:
            pass
        raise UpdateRefused(f"could not write the request into {d}: {exc.strerror or exc}") from exc
    return {"file": name, **payload}


def recent_status(limit: int = 10, status_dir: Path | str | None = None) -> list[dict]:
    """The updater's last runs, newest first. Unreadable files are reported, not fatal."""
    d = Path(status_dir or settings.update_status_dir)
    try:
        files = [p for p in d.glob("*.json") if p.is_file()]
    except OSError:
        return []
    files.sort(key=lambda p: p.stat().st_mtime, reverse=True)
    out: list[dict] = []
    for path in files[: max(1, limit)]:
        try:
            if path.stat().st_size > _STATUS_MAX_BYTES:
                raise ValueError("too large")
            data = json.loads(path.read_text(encoding="utf-8"))
            if not isinstance(data, dict):
                raise ValueError("not an object")
        except (OSError, ValueError) as exc:
            out.append({"file": path.name, "ok": False, "error": f"unreadable status file: {exc}",
                        "steps": []})
            continue
        steps = data.get("steps") if isinstance(data.get("steps"), list) else []
        out.append({
            "file": path.name,
            "id": data.get("id"),
            "ok": bool(data.get("ok")),
            "state": data.get("state"),
            "target_version": data.get("target_version"),
            "from_version": data.get("from_version"),
            "requested_by": data.get("requested_by"),
            "started_at": data.get("started_at"),
            "finished_at": data.get("finished_at"),
            "steps": [
                {"name": str(s.get("name", "")), "ok": bool(s.get("ok")),
                 "detail": str(s.get("detail", ""))[:2000], "at": s.get("at")}
                for s in steps if isinstance(s, dict)
            ][:50],
        })
    return out
