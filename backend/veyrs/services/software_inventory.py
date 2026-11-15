"""Installed software on this node -- Administration > Installed software.

Answers one question for an operator or an auditor: "what does this VEYRS run
on, and which version of each piece is installed?" Two lists:

* Platform components -- the operating system, the interpreter, the database
  and cache servers, and the binaries VEYRS or its installer call (nginx,
  pg_dump, ssh-keygen for release signatures, curl for the root updater, git
  for a git deploy). Each row carries the version
  the BINARY reports and, separately, the version the distro PACKAGE MANAGER
  has on record: the first is what runs, the second is what a security
  advisory names (``1.22.1`` vs ``1.22.1-9+deb12u9``).
* Python packages -- every distribution in the interpreter that runs the API
  (the venv), not a curated subset. ``direct`` marks what pyproject.toml asks
  for; ``locked`` is the pin in requirements.txt (the full resolved graph a
  node must run); a package whose installed version differs from its pin, or
  that the lock does not list at all, is flagged -- that is drift, and drift
  between two app nodes is how a failover serves different code.

Read-only by construction: fixed argv, no shell, short timeouts, and a binary
that cannot be found or does not answer is reported as "not found" -- this
module never invents a version. The answer describes the node that served the
request; behind the proxy that is the primary unless it is down.

Versions of everything installed are reconnaissance data, so the route that
serves this is for platform administrators only.
"""
from __future__ import annotations

import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import threading
import time
import tomllib
from importlib import metadata as _meta
from pathlib import Path
from typing import Any

from ..config import settings

#: backend/veyrs/services/software_inventory.py -> the install root.
ROOT = Path(__file__).resolve().parents[3]
PYPROJECT = ROOT / "pyproject.toml"
REQUIREMENTS = ROOT / "requirements.txt"

# nginx & co. live in sbin, which is not on every service user's PATH.
_SEARCH_PATH = os.pathsep.join([os.environ.get("PATH", ""), "/usr/local/sbin",
                                "/usr/local/bin", "/usr/sbin", "/usr/bin", "/sbin", "/bin"])
_PROBE_TIMEOUT = 4
_CACHE_TTL = 60.0
_VERSION_RE = re.compile(r"(\d+(?:\.\d+)+(?:[a-z]\d*)?)")
_ANSI_RE = re.compile(r"\x1b\[[0-9;]*m")

#: key -> how to measure it. ``argv`` runs with ``argv[0]`` resolved on the
#: search path; ``version_re`` overrides the generic dotted-number match;
#: ``deb`` / ``rpm`` are package-name globs, first installed match wins.
#: ``used_by`` is what in VEYRS needs it -- the reason the row exists.
COMPONENTS: tuple[dict, ...] = (
    {"key": "nginx", "name": "nginx", "argv": ["nginx", "-v"],
     "deb": ["nginx", "nginx-core", "nginx-light", "nginx-full"], "rpm": ["nginx"],
     "used_by": "serves the console, the documentation and the product site; proxies the API"},
    {"key": "pg_dump", "name": "PostgreSQL client (pg_dump)", "argv": ["pg_dump", "--version"],
     "deb": ["postgresql-client-*"], "rpm": ["postgresql*-server", "postgresql*"],
     "used_by": "backups (scripts/backup.sh, veyrs-pgdump) and the restore drill"},
    {"key": "openssl", "name": "OpenSSL", "argv": ["openssl", "version"],
     "deb": ["openssl"], "rpm": ["openssl"],
     "used_by": "TLS for every outbound connection; installer secret generation"},
    {"key": "openssh", "name": "OpenSSH (ssh-keygen)", "argv": ["ssh", "-V"],
     "version_re": r"OpenSSH_([0-9][0-9A-Za-z.]*)",
     "deb": ["openssh-client"], "rpm": ["openssh-clients", "openssh"],
     "used_by": "ssh-keygen -Y verify: the signature check of every release before it is installed"},
    {"key": "curl", "name": "curl", "argv": ["curl", "--version"],
     "deb": ["curl"], "rpm": ["curl"],
     "used_by": "the root updater (veyrs-updater.sh) and the installer download releases with it"},
    {"key": "git", "name": "git", "argv": ["git", "--version"],
     "deb": ["git"], "rpm": ["git", "git-core"],
     "used_by": "a git-deployed node (install mode git) updates through it"},
    # No scanner binaries here. nuclei aborts at start-up under the API's
    # MemoryDenyWriteExecute (a dependency generates machine code at run
    # time), and loosening the API sandbox to read a version string is the
    # wrong trade. Each agent reports its own tool versions instead:
    # see agent_tools().
)


class _Cache:
    def __init__(self) -> None:
        self.lock = threading.Lock()
        self.at = 0.0
        self.value: dict | None = None


_cache = _Cache()


def clear_cache() -> None:
    with _cache.lock:
        _cache.at, _cache.value = 0.0, None


# ------------------------------------------------------------- probing ---
def parse_version(text: str, pattern: str | None = None) -> str:
    """The version in a tool's output, or "" -- never a guess."""
    text = _ANSI_RE.sub("", text or "")
    if pattern:
        m = re.search(pattern, text)
        return m.group(1).rstrip(".") if m else ""
    m = _VERSION_RE.search(text)
    return m.group(1) if m else ""


def _run(argv: list[str]) -> tuple[str, str]:
    """(resolved path, combined output) of a fixed argv; ("", "") if absent."""
    path = shutil.which(argv[0], path=_SEARCH_PATH)
    if not path:
        return "", ""
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [path, *argv[1:]], capture_output=True, text=True,
            timeout=_PROBE_TIMEOUT, env={"PATH": _SEARCH_PATH, "LC_ALL": "C", "HOME": "/tmp"},
            stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return path, ""
    return path, (proc.stdout or "") + "\n" + (proc.stderr or "")


def package_manager() -> str:
    if shutil.which("dpkg-query", path=_SEARCH_PATH):
        return "dpkg"
    if shutil.which("rpm", path=_SEARCH_PATH):
        return "rpm"
    return ""


def installed_os_packages(family: str) -> dict[str, str]:
    """name -> version of every installed OS package, or {} when unknown."""
    if family == "dpkg":
        argv = ["dpkg-query", "-W", "-f", "${Package}\t${Version}\t${db:Status-Abbrev}\n"]
    elif family == "rpm":
        argv = ["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\tii\n"]
    else:
        return {}
    path = shutil.which(argv[0], path=_SEARCH_PATH)
    if not path:
        return {}
    try:
        proc = subprocess.run(  # noqa: S603 - fixed argv, no shell
            [path, *argv[1:]], capture_output=True, text=True, timeout=15,
            env={"PATH": _SEARCH_PATH, "LC_ALL": "C"}, stdin=subprocess.DEVNULL,
        )
    except (OSError, subprocess.SubprocessError):
        return {}
    out: dict[str, str] = {}
    for line in proc.stdout.splitlines():
        parts = line.split("\t")
        # dpkg lists removed-but-configured packages too ("rc"): only "ii" is installed.
        if len(parts) >= 3 and parts[2].strip().startswith("ii"):
            out[parts[0].split(":")[0]] = parts[1]
    return out


def match_package(globs: list[str], installed: dict[str, str],
                  prefer: str | None = None) -> tuple[str, str]:
    """First pattern with a hit wins. Among its hits, the package whose version
    has the binary's major version: on SUSE `postgresql-server` is a meta
    package at 18 while `postgresql16-server` holds the 16.13 that runs
    (measured on the 0.34.0 bench), and the first name alphabetically was the
    meta one."""
    import fnmatch

    for pattern in globs:
        hits = [name for name in sorted(installed) if fnmatch.fnmatchcase(name, pattern)]
        if not hits:
            continue
        if prefer:
            major = prefer.split(".")[0]
            for name in hits:
                upstream = installed[name].split(":")[-1]   # drop a Debian epoch
                if upstream.split(".")[0].split("-")[0] == major:
                    return name, installed[name]
        return hits[0], installed[hits[0]]
    return "", ""


def probe(comp: dict, installed: dict[str, str], family: str) -> dict:
    path, output = _run(comp["argv"])
    version = parse_version(output, comp.get("version_re")) if path else ""
    globs = comp.get("deb" if family == "dpkg" else "rpm", []) if family else []
    pkg, pkg_version = match_package(globs, installed, prefer=version or None) if globs else ("", "")
    if version:
        state = "ok"
    elif path:
        state = "no_version"   # the binary exists but did not say which it is
    else:
        state = "not_found"
    return {"key": comp["key"], "name": comp["name"], "used_by": comp["used_by"],
            "version": version or None, "path": path or None, "state": state,
            "package": pkg or None, "package_version": pkg_version or None}


def _os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    try:
        for line in Path("/etc/os-release").read_text(encoding="utf-8").splitlines():
            key, _, value = line.partition("=")
            if key:
                data[key.strip()] = value.strip().strip('"')
    except OSError:
        pass
    return data


def _service_versions() -> list[dict]:
    """PostgreSQL and Redis as the SERVERS report themselves -- they may be on another host."""
    rows: list[dict] = []
    pg: dict[str, Any] = {"key": "postgresql", "name": "PostgreSQL server",
                          "used_by": "every piece of state: findings, assets, intelligence, audit",
                          "path": None, "package": None, "package_version": None}
    try:
        from sqlalchemy import text

        from ..db import engine

        with engine.connect() as conn:
            pg["version"] = parse_version(str(conn.execute(text("SHOW server_version")).scalar() or "")) or None
        pg["state"] = "ok" if pg["version"] else "no_version"
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        pg.update(version=None, state="unreachable", error=type(exc).__name__)
    pg["host"] = _url_host(settings.database_url)
    rows.append(pg)

    rd: dict[str, Any] = {"key": "redis", "name": "Redis server",
                          "used_by": "rate limiting, caches and job coordination",
                          "path": None, "package": None, "package_version": None}
    try:
        import redis

        info = redis.Redis.from_url(settings.redis_url, socket_timeout=2).info("server")
        rd["version"] = str(info.get("redis_version") or "") or None
        rd["state"] = "ok" if rd["version"] else "no_version"
    except Exception as exc:  # noqa: BLE001 - reported, never raised
        rd.update(version=None, state="unreachable", error=type(exc).__name__)
    rd["host"] = _url_host(settings.redis_url)
    rows.append(rd)
    return rows


def _url_host(url: str) -> str | None:
    """host[:port] of a DSN -- never the credentials in it."""
    from urllib.parse import urlsplit

    try:
        parts = urlsplit((url or "").replace("+psycopg", ""))
        if not parts.hostname:
            return None
        return f"{parts.hostname}:{parts.port}" if parts.port else parts.hostname
    except ValueError:
        return None


def components() -> list[dict]:
    family = package_manager()
    installed = installed_os_packages(family)
    rows = _service_versions()
    for comp in COMPONENTS:
        rows.append(probe(comp, installed, family))
    return rows


# ------------------------------------------------------ python packages ---
def norm(name: str) -> str:
    """PEP 503 normalised name: `Python_Jose` == `python-jose`."""
    return re.sub(r"[-_.]+", "-", name or "").lower()


def _req_name_version(spec: str) -> tuple[str, str]:
    spec = spec.split("#", 1)[0].split(";", 1)[0].strip()
    m = re.match(r"^([A-Za-z0-9][A-Za-z0-9._-]*)(?:\[[^\]]*\])?\s*(?:==\s*([^\s,]+))?", spec)
    if not m:
        return "", ""
    return norm(m.group(1)), (m.group(2) or "")


def declared_dependencies(path: Path = PYPROJECT) -> set[str]:
    """Names pyproject.toml asks for directly; empty when it cannot be read."""
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, tomllib.TOMLDecodeError):
        return set()
    out = set()
    for spec in (data.get("project") or {}).get("dependencies") or []:
        name, _ = _req_name_version(str(spec))
        if name:
            out.add(name)
    return out


def locked_versions(path: Path = REQUIREMENTS) -> dict[str, str]:
    """name -> pinned version from the lock; {} when there is no lock."""
    out: dict[str, str] = {}
    try:
        lines = path.read_text(encoding="utf-8").splitlines()
    except OSError:
        return out
    for line in lines:
        if not line.strip() or line.lstrip().startswith(("#", "-")):
            continue
        name, version = _req_name_version(line)
        if name:
            out[name] = version
    return out


def _license(dist: Any) -> str | None:
    meta = dist.metadata
    for key in ("License-Expression",):
        if meta.get(key):
            return str(meta.get(key))[:60]
    classifiers = [c.split("::")[-1].strip() for c in (meta.get_all("Classifier") or [])
                   if c.startswith("License ::")]
    if classifiers:
        return ", ".join(dict.fromkeys(classifiers))[:60]
    lic = str(meta.get("License") or "").strip()
    # Some packages paste the whole licence text here: a first line is enough.
    return (lic.splitlines()[0][:60] if lic and lic.upper() != "UNKNOWN" else None)


def python_packages(*, declared: set[str] | None = None,
                    locked: dict[str, str] | None = None,
                    distributions: Any = None) -> list[dict]:
    declared = declared_dependencies() if declared is None else declared
    locked = locked_versions() if locked is None else locked
    seen: dict[str, dict] = {}
    for dist in (distributions if distributions is not None else _meta.distributions()):
        name = str(dist.metadata.get("Name") or "")
        if not name:
            continue
        key = norm(name)
        if key in seen:        # a stray second copy on sys.path: the first one wins at import
            continue
        version = str(dist.version or "")
        pin = locked.get(key)
        if key == "veyrs":
            # The application's own distribution metadata (an editable install
            # leaves it at the version it was installed with). Not a dependency.
            state = "application"
        elif not locked:
            state = "no_lock"
        elif pin is None:
            # pip/setuptools/wheel are the venv's own tooling, not the application.
            state = "tooling" if key in ("pip", "setuptools", "wheel") else "not_in_lock"
        elif pin and pin != version:
            state = "differs"
        else:
            state = "ok"
        seen[key] = {"name": name, "version": version, "direct": key in declared,
                     "locked": pin or None, "state": state,
                     "summary": str(dist.metadata.get("Summary") or "")[:160] or None,
                     "license": _license(dist)}
    rows = sorted(seen.values(), key=lambda r: (not r["direct"], r["name"].lower()))
    # A pin with nothing installed is the worst drift of all: the import fails at runtime.
    for key, pin in sorted(locked.items()):
        if key not in seen:
            rows.append({"name": key, "version": None, "direct": key in declared, "locked": pin or None,
                         "state": "missing", "summary": None, "license": None})
    return rows


# -------------------------------------------------------- scan agents ---
def agent_tools(session: Any, organization_id: Any) -> list[dict]:
    """What each registered agent of ONE organization reports about itself.

    The scan tools run on the agent's host, not here: their versions are the
    ones the agent declared at its last registration, stamped with when that
    was. The session must be bound to the organization (RLS).
    """
    from sqlalchemy import select

    from ..models.agent import AgentTool, ExecAgent

    agents = session.scalars(select(ExecAgent).where(ExecAgent.organization_id == organization_id)
                             .order_by(ExecAgent.name)).all()
    tools = session.scalars(select(AgentTool).where(AgentTool.organization_id == organization_id)).all()
    by_agent: dict[Any, list[dict]] = {}
    for t in tools:
        by_agent.setdefault(t.agent_id, []).append({
            # Agents store the first line of `<tool> --version` as printed
            # ("[INF] Nuclei Engine Version: v3.11.1"): show the number.
            "name": t.name, "version": parse_version(t.tool_version or "") or t.tool_version,
            "enabled": bool(t.enabled),
            "declared_at": t.declared_at.isoformat() if t.declared_at else None})
    return [{
        "name": a.name, "hostname": a.hostname, "platform": a.platform,
        "agent_version": a.agent_version, "status": a.status,
        "last_heartbeat_at": a.last_heartbeat_at.isoformat() if a.last_heartbeat_at else None,
        "disabled": a.disabled_at is not None,
        "tools": sorted(by_agent.get(a.id, []), key=lambda r: r["name"]),
    } for a in agents]


# ---------------------------------------------------------------- whole ---
def _install_mode() -> str:
    from . import updates

    return updates.detect_mode()


def _revision() -> str | None:
    """The commit a git deploy runs, read from the files -- no git subprocess."""
    git = ROOT / ".git"
    try:
        head = (git / "HEAD").read_text(encoding="utf-8").strip()
        if head.startswith("ref: "):
            ref = head[5:]
            ref_file = git / ref
            if ref_file.is_file():
                return ref_file.read_text(encoding="utf-8").strip()[:12]
            packed = git / "packed-refs"
            if packed.is_file():
                for line in packed.read_text(encoding="utf-8").splitlines():
                    if line.endswith(" " + ref):
                        return line.split()[0][:12]
            return None
        return head[:12]
    except OSError:
        return None


def inventory(refresh: bool = False, now: float | None = None) -> dict:
    now = time.time() if now is None else now
    with _cache.lock:
        if not refresh and _cache.value is not None and now - _cache.at < _CACHE_TTL:
            return dict(_cache.value, cached=True)
    osr = _os_release()
    pkgs = python_packages()
    comps = components()
    data = {
        "node": {
            "hostname": socket.gethostname(),
            "veyrs_version": settings.version,
            "install_mode": _install_mode(),
            "revision": _revision(),
            "os": osr.get("PRETTY_NAME") or platform.platform(),
            "os_id": osr.get("ID"),
            "kernel": platform.release(),
            "architecture": platform.machine(),
            "python": platform.python_version(),
            "python_executable": sys.executable,
            "package_manager": package_manager() or None,
        },
        "components": comps,
        "python_packages": pkgs,
        "summary": {
            "python_packages": sum(1 for p in pkgs if p["version"]),
            "direct": sum(1 for p in pkgs if p["direct"] and p["version"]),
            "drift": sum(1 for p in pkgs if p["state"] in ("differs", "not_in_lock", "missing")),
            "components_found": sum(1 for c in comps if c["state"] == "ok"),
        },
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(now)),
    }
    with _cache.lock:
        _cache.at, _cache.value = now, data
    return dict(data, cached=False)
