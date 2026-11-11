"""0.35.3: scripts/restore.sh restores as a superuser, never as the app role.

Every tenant table is FORCE ROW LEVEL SECURITY, which binds the table owner
too. restore.sh used to connect with VEYRS_DATABASE_URL -- the `veyrs` app
role -- so `pg_restore --clean` dropped the schema and then had its data load
refused table by table. The same RLS trap backup.sh and veyrs-pgdump were
written around, on the way back in.

These run the real scripts with `pg_restore`, `pg_dump`, `psql`, `su` and
`systemctl` replaced by stubs on PATH that only log their arguments. No
database is touched, and the assertions are about which commands ran, with
which connection, in which order.
"""
from __future__ import annotations

import hashlib
import os
import stat
import subprocess
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
RESTORE = ROOT / "scripts" / "restore.sh"
BACKUP = ROOT / "scripts" / "backup.sh"

REMOTE_DSN = "postgresql+psycopg://veyrs:apppw@10.9.9.9:5432/veyrs"
LOCAL_DSN = "postgresql+psycopg://veyrs:apppw@127.0.0.1:5432/veyrs"
SUPER_DSN = "postgresql://postgres:superpw@10.9.9.9:5432/veyrs"


def _stub(bindir: Path, name: str, body: str) -> None:
    path = bindir / name
    path.write_text("#!/bin/bash\n" + body + "\n")
    path.chmod(path.stat().st_mode | stat.S_IXUSR | stat.S_IXGRP | stat.S_IXOTH)


@pytest.fixture()
def bench(tmp_path):
    log = tmp_path / "calls.log"
    log.write_text("")
    bindir = tmp_path / "bin"
    bindir.mkdir()
    app = tmp_path / "app"
    (app / "venv" / "bin").mkdir(parents=True)
    (app / "var").mkdir()
    source = tmp_path / "backup"
    source.mkdir()
    dump = source / "veyrs.dump"
    dump.write_bytes(b"PGDMP fake archive")
    (source / "MANIFEST").write_text("veyrs_backup_version: 1\n")
    digest = hashlib.sha256(dump.read_bytes()).hexdigest()
    (source / "SHA256SUMS").write_text(f"{digest}  veyrs.dump\n")

    for name in ("pg_restore", "pg_dump", "systemctl"):
        _stub(bindir, name, f'echo "{name} $*" >> "{log}"')
    # psql answers the superuser probe from $FAKE_SUPER and the row count from $FAKE_ORGS
    _stub(bindir, "psql", f'''echo "psql $*" >> "{log}"
case "$*" in *rolsuper*) echo "${{FAKE_SUPER:-t}}";; *organizations*) echo "${{FAKE_ORGS:-3}}";; esac''')
    # su postgres -c "<cmd>": log it, then run <cmd> so the inner stub logs too
    _stub(bindir, "su", f'''echo "su $*" >> "{log}"
while [ $# -gt 0 ]; do [ "$1" = -c ] && {{ shift; eval "$1"; exit $?; }}; shift; done''')
    _stub(bindir, "id", 'exit 0')
    _stub(app / "venv" / "bin", "python", f'echo "init-db $*" >> "{log}"')

    def run(script: Path, dsn: str, *args: str, **env: str):
        (app / ".env").write_text(f"VEYRS_DATABASE_URL={dsn}\n")
        environ = {**os.environ, "PATH": f"{bindir}:{os.environ['PATH']}",
                   "APP_DIR": str(app), "BACKUP_DIR": str(tmp_path / "backups"), **env}
        for inherited in ("RESTORE_DSN", "BACKUP_DSN"):
            if inherited not in env:
                environ.pop(inherited, None)
        proc = subprocess.run(["bash", str(script), *args], capture_output=True,
                              text=True, env=environ)
        return proc, log.read_text()

    return run, source


def test_a_remote_database_without_a_superuser_dsn_is_refused_before_anything_stops(bench):
    run, source = bench
    proc, log = run(RESTORE, REMOTE_DSN, str(source), "--yes")
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "superuser" in proc.stderr
    assert "pg_restore" not in log, "restore ran without a superuser route"
    assert "systemctl stop" not in log, "the API was stopped for a restore that could not run"


def test_the_app_role_dsn_is_never_handed_to_pg_restore(bench):
    run, source = bench
    proc, log = run(RESTORE, REMOTE_DSN, str(source), "--yes", RESTORE_DSN=SUPER_DSN)
    assert proc.returncode == 0, proc.stdout + proc.stderr + log
    restores = [line for line in log.splitlines() if line.startswith("pg_restore")]
    assert restores and all(f"--dbname={SUPER_DSN}" in line for line in restores), log
    assert "apppw" not in "\n".join(restores), "pg_restore was given the application role"
    assert all("--no-owner" not in line for line in restores), (
        "--no-owner as a superuser leaves every table owned by postgres and the "
        "API without privileges on its own data"
    )
    order = [line.split()[0] + " " + line.split()[1] for line in log.splitlines()
             if line.startswith(("systemctl", "pg_restore"))]
    assert order[0] == "systemctl stop" and order[-1] == "systemctl start", order
    assert "init-db" in log


def test_a_restore_dsn_that_is_not_a_superuser_is_refused(bench):
    run, source = bench
    proc, log = run(RESTORE, REMOTE_DSN, str(source), "--yes",
                    RESTORE_DSN="postgresql://veyrs:apppw@10.9.9.9/veyrs", FAKE_SUPER="f")
    assert proc.returncode == 1
    assert "pg_restore" not in log and "systemctl stop" not in log


def test_a_local_database_is_restored_as_postgres_over_peer_auth(bench):
    run, source = bench
    proc, log = run(RESTORE, LOCAL_DSN, str(source), "--yes")
    assert proc.returncode == 0, proc.stdout + proc.stderr + log
    assert "su -s /bin/bash postgres -c pg_restore --clean --if-exists --dbname='veyrs'" in log, log
    assert "apppw" not in "".join(l for l in log.splitlines() if l.startswith(("su", "pg_restore")))


def test_an_empty_restore_fails_loudly_and_leaves_the_api_stopped(bench):
    run, source = bench
    proc, log = run(RESTORE, REMOTE_DSN, str(source), "--yes",
                    RESTORE_DSN=SUPER_DSN, FAKE_ORGS="0")
    assert proc.returncode == 1
    assert "no organizations" in proc.stderr
    assert "systemctl start" not in log


def test_backup_refuses_peer_auth_against_a_remote_database(bench):
    """An app node can carry a local Postgres of its own (environment A's a1
    has a local `veyrs` database that is NOT production). Peer auth reaches
    that one, so backup.sh used to dump the wrong server and call it done."""
    run, _ = bench
    proc, log = run(BACKUP, REMOTE_DSN)
    assert proc.returncode == 1, proc.stdout + proc.stderr
    assert "not this host" in proc.stderr
    assert "pg_dump" not in log
