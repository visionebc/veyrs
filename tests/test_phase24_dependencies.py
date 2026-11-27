"""Phase 24 - the dependency set is declared, and the declaration is true.

VEYRS ran in production for months with no `requirements.txt` and no
`pyproject.toml`. The venv was whatever had been `pip install`-ed by hand, which
meant (a) a new node could not be reproduced, and (b) dead weight accumulated
invisibly: alembic with no migrations, a whole Celery stack with no worker,
feedparser/bs4/lxml/pyotp with zero imports between them.

These tests are the guard against that drifting back. They are deliberately
cheap and read only files in the repo plus the running interpreter.
"""
from __future__ import annotations

import importlib
import importlib.metadata as md
import pathlib
import re
import tomllib

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
PYPROJECT = ROOT / "pyproject.toml"
LOCK = ROOT / "requirements.txt"

# distribution name -> module you actually import
IMPORT_NAME = {
    "PyJWT": "jwt",
    "pillow": "PIL",
    "python-docx": "docx",
    "python-multipart": None,   # runtime dep of FastAPI, never imported by us
    "argon2-cffi": "argon2",
    "email-validator": "email_validator",
    "psycopg": "psycopg",
    "SQLAlchemy": "sqlalchemy",
    "uvicorn": "uvicorn",
    "pydantic-settings": "pydantic_settings",
}


def _requirement_name(spec: str) -> str:
    return re.split(r"[\[=<>!~;]", spec, maxsplit=1)[0].strip()


@pytest.fixture(scope="module")
def pyproject() -> dict:
    assert PYPROJECT.is_file(), "pyproject.toml is the declaration; it must exist"
    return tomllib.loads(PYPROJECT.read_text())


@pytest.fixture(scope="module")
def lock_names() -> dict[str, str]:
    assert LOCK.is_file(), "requirements.txt is the lock; it must exist"
    out = {}
    for line in LOCK.read_text().splitlines():
        line = line.strip()
        if not line or line.startswith(("#", "--")):
            continue
        name, _, version = line.rstrip("\\").strip().partition("==")
        out[name.strip().lower().replace("_", "-")] = version.strip()
    return out


def test_every_declared_dependency_is_pinned(pyproject):
    """A floating dependency is an unreviewed change to a security platform."""
    deps = pyproject["project"]["dependencies"]
    assert deps, "the dependency list must not be empty"
    for spec in deps:
        assert "==" in spec, f"{spec} is not pinned"


def test_every_declared_dependency_is_in_the_lock(pyproject, lock_names):
    """The lock must be a superset of the declaration, or it locks the wrong thing."""
    missing = [
        _requirement_name(spec)
        for spec in pyproject["project"]["dependencies"]
        if _requirement_name(spec).lower().replace("_", "-") not in lock_names
    ]
    assert not missing, f"declared but absent from requirements.txt: {missing}"


def test_declared_versions_match_the_lock(pyproject, lock_names):
    for spec in pyproject["project"]["dependencies"]:
        name = _requirement_name(spec)
        declared = spec.split("==", 1)[1].split(";")[0].strip()
        locked = lock_names[name.lower().replace("_", "-")]
        assert declared == locked, f"{name}: pyproject says {declared}, lock says {locked}"


def test_every_declared_dependency_is_installed(pyproject):
    for spec in pyproject["project"]["dependencies"]:
        name = _requirement_name(spec)
        md.distribution(name)  # raises PackageNotFoundError if absent


def test_every_declared_dependency_is_importable(pyproject):
    """Catches a dependency that is declared but whose module was never wired."""
    for spec in pyproject["project"]["dependencies"]:
        name = _requirement_name(spec)
        module = IMPORT_NAME.get(name, name.replace("-", "_"))
        if module is None:
            continue
        importlib.import_module(module)


def test_the_removed_packages_stay_removed():
    """Each of these was installed, imported nowhere, and is now gone.

    If one comes back, either something legitimately started using it -- in
    which case declare it in pyproject.toml and delete the entry here -- or the
    venv drifted by hand again, which is the thing this phase fixed.
    """
    banished = [
        "alembic",       # no migrations exist; schema evolves via `veyrs sync-schema`
        "celery",        # never imported; only ever named in one stale docstring
        "kombu",
        "billiard",
        "feedparser",
        "beautifulsoup4",
        "pyotp",         # TOTP is stdlib in veyrs/security/mfa.py
        "defusedxml",    # XXE defence is hand-rolled on expat in importers/parsers.py
        "python-jose",   # unmaintained, unfixed advisory; replaced by PyJWT (R-01)
        "ecdsa",         # only ever pulled in by python-jose
    ]
    present = []
    for name in banished:
        try:
            md.distribution(name)
        except md.PackageNotFoundError:
            continue
        present.append(name)
    assert not present, f"dead dependencies reinstalled: {present}"


def test_multipart_is_present_even_though_nothing_imports_it():
    """FastAPI needs it to parse the scanner uploads; its absence 500s at request time."""
    md.distribution("python-multipart")


def test_freeze_script_exists_and_is_executable():
    script = ROOT / "scripts" / "freeze-deps.sh"
    assert script.is_file(), "the lock must be regenerable, not hand-edited"
    assert script.stat().st_mode & 0o111, f"{script} is not executable"


def _lock_blocks() -> list[str]:
    blocks = re.split(r"\n(?=[A-Za-z0-9_.-]+==)", LOCK.read_text())
    return [b for b in blocks if re.match(r"[A-Za-z0-9_.-]+==", b)]


def test_every_lock_entry_is_hashed():
    """R-21: an install with `--require-hashes` needs a sha256 on every pin, transitive ones too."""
    pins = _lock_blocks()
    assert len(pins) > 40
    unhashed = [b.split("==")[0] for b in pins if not re.search(r"--hash=sha256:[0-9a-f]{64}", b)]
    assert not unhashed, f"pins without a hash: {unhashed}"


def test_installers_require_hashes():
    """The lock is only a control if the installers refuse an unhashed install."""
    for rel in ("install.sh", "docker/Dockerfile"):
        lines = [
            l for l in (ROOT / rel).read_text().splitlines()
            if "-r requirements.txt" in l and "pip" in l and not l.lstrip().startswith(("#", "info"))
        ]
        assert lines and all("--require-hashes" in l for l in lines), f"{rel}: {lines}"


def test_supply_chain_scripts_parse_the_lock():
    """scripts/sbom.sh emits CycloneDX with hashes; scripts/osv-check.py reads the same pins."""
    import importlib.util
    import json
    import subprocess

    for name in ("sbom.sh", "osv-check.py"):
        script = ROOT / "scripts" / name
        assert script.is_file() and script.stat().st_mode & 0o111, f"{name} missing or not executable"
    out = subprocess.run([str(ROOT / "scripts" / "sbom.sh"), str(LOCK)],
                         capture_output=True, text=True, check=True).stdout
    bom = json.loads(out)
    assert bom["bomFormat"] == "CycloneDX" and bom["specVersion"] == "1.5"
    comps = {c["name"].lower(): c for c in bom["components"]}
    assert {"fastapi", "pyjwt", "starlette"} <= set(comps)
    assert comps["pyjwt"]["purl"].startswith("pkg:pypi/pyjwt@")
    assert comps["pyjwt"]["hashes"][0]["alg"] == "SHA-256"
    assert len(comps) == len(_lock_blocks())
    spec = importlib.util.spec_from_file_location("osv_check", ROOT / "scripts" / "osv-check.py")
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    pins = mod.parse_pins(LOCK.read_text())
    assert len(pins) == len(_lock_blocks()) and any(n.lower() == "pyjwt" for n, _ in pins)


def test_the_running_version_matches_the_declared_one(pyproject):
    """`pyproject.toml` and `settings.version` must not drift apart.

    The version lives in two places: the packaging declaration and
    `config.Settings.version`, which is what `/healthz` reports and therefore
    what every deploy is verified against. 0.27.0 shipped with only the first
    one bumped, so a correctly deployed node reported the PREVIOUS release --
    a health check that answers 200 with a stale truth is worse than one that
    fails, because it is used as the proof that the deploy landed.
    """
    from veyrs.config import settings

    assert settings.version == pyproject["project"]["version"], (
        "pyproject.toml says %s but settings.version says %s -- /healthz reports "
        "the second one, so the deploy would be verified against the wrong number"
        % (pyproject["project"]["version"], settings.version)
    )
