"""The documentation guards.

Two documents in `docs/` describe the shape of the system rather than its
behaviour, and both of them drifted silently before these tests existed:

* `DATABASE.md` claimed **67 tables** for six weeks while the models carried 87,
  and claimed schema changes were managed by **Alembic** while `migrations/` was
  an empty placeholder.
* No document listed the environment variables the process actually reads, so
  an operator's only complete reference was `config.py`.

A wrong number in a manual does not fail anything. That is the whole problem:
these tests make it fail.
"""
from __future__ import annotations

import re
import subprocess
import sys
from pathlib import Path

import pytest

from veyrs.config import Settings
from veyrs.models import Base

ROOT = Path(__file__).resolve().parent.parent
DOCS = ROOT / "docs"


def test_the_generated_schema_reference_matches_the_models():
    """`scripts/gen-schema-doc.py --check` is the contract; this runs it."""
    result = subprocess.run(
        [sys.executable, str(ROOT / "scripts" / "gen-schema-doc.py"), "--check"],
        capture_output=True,
        text=True,
    )
    assert result.returncode == 0, (
        "docs/DATABASE_SCHEMA.md no longer describes the models.\n"
        "Regenerate it: python3 scripts/gen-schema-doc.py\n"
        f"{result.stdout}{result.stderr}"
    )


def test_the_database_manual_states_the_real_table_count():
    """A count in prose is a claim, and this one was wrong for six weeks."""
    text = (DOCS / "DATABASE.md").read_text(encoding="utf-8")
    real = len(Base.metadata.tables)
    assert f"**{real} tables.**" in text, (
        f"docs/DATABASE.md must state the real table count ({real}). "
        "Update the summary line and the table in section 8."
    )


def test_the_database_manual_does_not_promise_a_migration_tool_that_is_absent():
    """It promised Alembic. `migrations/` holds a placeholder README and nothing else."""
    versions = ROOT / "migrations" / "versions"
    has_migrations = versions.is_dir() and any(versions.glob("*.py"))
    text = (DOCS / "DATABASE.md").read_text(encoding="utf-8").lower()
    claims_alembic = "alembic, in" in text or "managed by alembic" in text
    assert claims_alembic == has_migrations, (
        "docs/DATABASE.md and the repository disagree about Alembic: "
        f"doc claims it={claims_alembic}, migration files present={has_migrations}"
    )


def _documented_env_vars() -> set[str]:
    text = (DOCS / "SYSTEM_MANUAL.md").read_text(encoding="utf-8")
    return set(re.findall(r"\bVEYRS_[A-Z0-9_]+\b", text))


def test_every_setting_the_process_reads_is_documented():
    """`config.Settings` is the only complete list; the manual has to carry it.

    A setting nobody documents is a setting nobody sets — and several of these
    (metrics_token, trust_proxy_headers, auth_rate_limit_per_minute) are the
    difference between a hardened deployment and an open one.
    """
    expected = {f"VEYRS_{name.upper()}" for name in Settings.model_fields}
    missing = sorted(expected - _documented_env_vars())
    assert not missing, (
        "docs/SYSTEM_MANUAL.md does not document these settings: "
        + ", ".join(missing)
    )


def _orchestration_plane() -> set[str]:
    """Variables that are real but are NOT read by `config.Settings`.

    Two planes, and conflating them is how this guard nearly forbade
    documenting half of a supported deployment:

    * the CONFIGURATION plane — `config.Settings`, read by the process itself;
    * the ORCHESTRATION plane — read by compose, install.sh, the entrypoints
      and the agent (`VEYRS_ADMIN_PASSWORD`, `VEYRS_HTTP_BIND`,
      `VEYRS_AGENT_TOKEN`, …). An operator sets both in the same file, so the
      manual is the right place for both.

    DERIVED from the files that actually read them, never a hand-kept list. A
    fixed allowlist would turn this test from "the manual invents nothing" into
    "the manual invents nothing except whatever somebody added to the list" —
    which is the failure it exists to prevent.
    """
    found: set[str] = set()
    for rel in (
        "docker/compose.yaml", "docker/env.example", "docker/entrypoint.sh",
        "docker/init.sh", "docker/agent-entrypoint.sh", "docker/tick.sh",
        "docker/veyrs-docker.sh", "install.sh",
        "integrations/veyrs-agent/veyrs_agent.py",
    ):
        path = ROOT / rel
        if path.exists():
            found |= set(re.findall(r"\bVEYRS_[A-Z0-9_]+\b", path.read_text(encoding="utf-8")))
    return found


def test_the_manual_does_not_invent_settings():
    """The mirror of the test above: a documented variable the code ignores.

    This is the worse direction. An operator who sets VEYRS_SESSION_TIMEOUT
    because the manual lists it gets no error and no effect, and believes the
    deployment is configured.
    """
    real = {f"VEYRS_{name.upper()}" for name in Settings.model_fields}
    invented = sorted(_documented_env_vars() - real - _orchestration_plane())
    assert not invented, (
        "docs/SYSTEM_MANUAL.md documents settings that config.Settings does not read: "
        + ", ".join(invented)
    )


@pytest.mark.parametrize(
    "command",
    [
        "init-db", "sync-schema", "check", "keygen", "bootstrap", "sync-kev",
        "sync-epss", "sync-nvd", "sync-cwe", "recompute-risk", "run-sla",
        "digest", "intel-due", "import-inventory",
    ],
)
def test_every_cli_command_appears_in_the_manual(command):
    """A command that exists and is undocumented is a command nobody runs."""
    text = (DOCS / "SYSTEM_MANUAL.md").read_text(encoding="utf-8")
    assert f"`{command}`" in text or f"veyrs {command}" in text, (
        f"CLI command '{command}' is not documented in docs/SYSTEM_MANUAL.md"
    )


# ---------------------------------------------------------------------------
# The architecture document describes shape, and shape drifts silently.
#
# It claimed a `veyrs-worker` running Celery for feed sync, SLA sweeps and
# escalation. There is no such unit, `celery` is not in requirements.txt, and
# nothing under backend/ imports it — the work is done by hourly systemd ticks
# calling the CLI. It also drew "67 tables" against 87 real ones, the same
# defect DATABASE.md carried for six weeks.
#
# A wrong architecture diagram is worse than a wrong number in a manual: it is
# what a new operator reads to decide where to look when something breaks, and
# it sent them looking for a queue that was never there.
# ---------------------------------------------------------------------------
ARCHITECTURE = DOCS / "ARCHITECTURE.md"


def test_every_shipped_unit_can_actually_start():
    """A unit whose ExecStart does not exist is worse than a missing unit.

    `infrastructure/systemd/veyrs-worker.service` ran
    `/opt/veyrs/venv/bin/celery -A veyrs.worker worker` for months after Celery
    was removed from the dependency set in 0.14.1. It was never installed here,
    but install.sh and INSTALL.md both RECOMMENDED it — so an operator who took
    the advice got a unit restart-looping every ten seconds on a missing
    binary, and, worse, a reason to believe that feeds, SLA and escalation were
    handled by a worker rather than by the two timers that actually do it.

    Reads the units rather than the prose: the prose is what was wrong.
    """
    units = sorted((ROOT / "infrastructure" / "systemd").glob("*.service"))
    assert units, "no systemd units in the repository"
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    broken = []
    for unit in units:
        text = unit.read_text(encoding="utf-8")
        m = re.search(r"^ExecStart=(\S+)", text, re.M)
        if not m:
            broken.append(f"{unit.name}: no ExecStart")
            continue
        exe = m.group(1)
        if "/venv/bin/" in exe:
            tool = exe.rsplit("/", 1)[-1]
            # python and uvicorn are installed by definition; anything else has
            # to be a declared dependency or it will not be in the venv.
            if tool not in ("python", "python3", "uvicorn") and tool not in requirements:
                broken.append(
                    f"{unit.name}: ExecStart runs {tool!r}, which is not in "
                    "requirements.txt and will therefore not exist in the venv"
                )
        elif exe.startswith("/opt/veyrs/"):
            rel = exe[len("/opt/veyrs/"):]
            if not (ROOT / rel).exists():
                broken.append(f"{unit.name}: ExecStart={exe} is not in the repository")
    assert not broken, "units that cannot start:\n  " + "\n  ".join(broken)


def test_no_live_document_presents_a_task_queue_as_a_component():
    """It was in three places: two docs and the installer's own advice.

    CHANGELOG.md is excluded deliberately — it is a historical record and its
    entry recording the removal must keep saying so. ARCHITECTURE.md's prose
    explaining that there is no Celery is excluded by looking only at table
    rows and at the installer, not at sentences.
    """
    requirements = (ROOT / "requirements.txt").read_text(encoding="utf-8").lower()
    installed = "celery" in requirements

    claims = []
    targets = [d for d in sorted(DOCS.glob("*.md")) if d.name != "CHANGELOG.md"]
    targets += [ROOT / "README.md", ROOT / "INSTALL.md", ROOT / "install.sh"]
    for doc in targets:
        for n, line in enumerate(doc.read_text(encoding="utf-8").splitlines(), 1):
            low = line.lower()
            # A table row, or a named unit — a claim that the thing is part of
            # the system. Prose about its absence is not.
            if line.lstrip().startswith("|") and "celery" in low:
                claims.append(f"{doc.name}:{n}: {line.strip()}")
            elif "veyrs-worker.service" in low and "no worker unit" not in low:
                claims.append(f"{doc.name}:{n}: {line.strip()}")

    assert bool(claims) == installed, (
        "the documentation and requirements.txt disagree about a task queue: "
        f"presented as a component={bool(claims)}, installed={installed}.\n"
        + "\n".join(claims)
    )


def test_the_architecture_states_the_real_table_count():
    text = ARCHITECTURE.read_text(encoding="utf-8")
    real = len(Base.metadata.tables)
    stale = re.findall(r"\b(\d{2,3}) tables\b", text)
    wrong = sorted({n for n in stale if int(n) != real})
    assert not wrong, (
        f"docs/ARCHITECTURE.md says {', '.join(wrong)} tables; there are {real}."
    )


# ---------------------------------------------------------------------------
# The container stack has to be described where an operator looks for
# deployment shapes, not only in docker/README.md. A supported deployment that
# the architecture document does not mention is a deployment nobody audits.
# ---------------------------------------------------------------------------
def test_the_architecture_describes_both_deployment_shapes():
    text = ARCHITECTURE.read_text(encoding="utf-8")
    for needle, why in [
        ("install.sh", "the host installer"),
        ("docker/compose.yaml", "the container stack"),
        ("NOBYPASSRLS", "the decision that keeps tenant isolation working in containers"),
        ("profile", "that the scanner and the feed sync are opt-in"),
    ]:
        assert needle in text, (
            f"docs/ARCHITECTURE.md never mentions {needle!r} — {why} is undocumented"
        )


def test_the_deployment_manual_documents_the_container_stack():
    text = (DOCS / "DEPLOYMENT.md").read_text(encoding="utf-8")
    assert "veyrs-docker.sh" in text, (
        "docs/DEPLOYMENT.md does not mention the container stack driver. An "
        "operator reading the deployment manual would not know it exists."
    )
    # And it must carry the consequence of running without the workers, which
    # is the one thing about a container node that is invisible in the console.
    assert re.search(r"does not (refresh|age forward)", text), (
        "docs/DEPLOYMENT.md describes the container stack without saying that "
        "a node without the intel worker stops refreshing its data"
    )


def test_the_recovery_manual_warns_about_the_rls_backup_trap():
    """The most expensive silent failure this system has: a backup that looks fine.

    `pg_dump` as the application role is refused partway through by FORCE ROW
    LEVEL SECURITY — which applies to the table OWNER too — and `--format=custom`
    has already written a plausible file. Measured on production 2026-09-21:
    392 KB where the good dump is 509 MB. scripts/backup.sh gets this right; a
    recovery manual that documents a bare `pg_dump` teaches an operator to do it
    by hand and lose the data they were protecting.
    """
    text = (DOCS / "DISASTER_RECOVERY.md").read_text(encoding="utf-8")
    assert "row-level security" in text.lower() or "row level security" in text.lower(), (
        "docs/DISASTER_RECOVERY.md does not warn that pg_dump as the application "
        "role produces a truncated backup"
    )
    assert "pg_restore --list" in text, (
        "the recovery manual does not say how to VERIFY a dump. Size alone "
        "cannot tell a truncated dump from a small database."
    )
