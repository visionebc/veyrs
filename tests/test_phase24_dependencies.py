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
    "python-jose": "jose",
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
        if not line or line.startswith("#"):
            continue
        name, _, version = line.partition("==")
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
