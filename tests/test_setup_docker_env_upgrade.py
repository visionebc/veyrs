"""veyrs-setup.sh: updating a Docker install whose veyrs.env predates a secret (0.42.1).

0.41.0 gave Redis a password and compose.yaml requires VEYRS_REDIS_PASSWORD.
The update path reused the existing veyrs.env as it was, so every Docker
install made before 0.41.0 stopped at "validate compose configuration"
(measured: 0.35.6 -> 0.42.1 on openSUSE Leap 15.6). The reuse branch now adds
the Redis password when it is missing, and nothing else: database and signing
secrets are never invented, because the data was written with the old ones.

The test runs the real secret block of write_docker_env() on a file shaped
like a 0.35.6 one.
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path

import pytest

SETUP = Path(__file__).resolve().parents[1] / "veyrs-setup.sh"

OLD_ENV = """POSTGRES_PASSWORD=pgsecret
VEYRS_DB_PASSWORD=dbsecret
VEYRS_SECRET_KEY=signsecret
VEYRS_ENCRYPTION_KEY=enckey
VEYRS_HTTP_BIND=127.0.0.1:8080
"""


@pytest.fixture(scope="module")
def src() -> str:
    return SETUP.read_text()


def _fn(src: str, name: str) -> str:
    m = re.search(rf"^{name}\(\) \{{.*?^\}}\n", src, re.S | re.M) or re.search(rf"^{name}\(\) \{{.*?\}}\n", src, re.M)
    assert m, f"{name}() not found"
    return m.group(0)


def _secret_block(src: str) -> str:
    body = _fn(src, "write_docker_env")
    start = body.index('    if [ ! -f "$DOCKER_ENV" ]; then')
    end = body.index("\n    fi\n", start) + len("\n    fi\n")
    return body[start:end]


def _run(src: str, tmp: Path, content: str) -> tuple[str, str]:
    env = tmp / "veyrs.env"
    env.write_text(content)
    script = "\n".join([
        f'DOCKER_HOME="{tmp}"; DOCKER_ENV="{env}"; D=/nonexistent',
        'ok() { echo "OK: $*"; }',
        _fn(src, "rand_hex"),
        _fn(src, "env_get"),
        _fn(src, "env_set"),
        _secret_block(src),
    ])
    r = subprocess.run(["bash", "-c", script], capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    return env.read_text(), r.stdout


def test_an_old_env_gets_a_redis_password(src: str, tmp_path: Path) -> None:
    after, out = _run(src, tmp_path, OLD_ENV)
    m = re.search(r"^VEYRS_REDIS_PASSWORD=([0-9a-f]{48})$", after, re.M)
    assert m, after
    assert "VEYRS_REDIS_PASSWORD added" in out


def test_the_existing_secrets_are_left_exactly_as_they_were(src: str, tmp_path: Path) -> None:
    after, _ = _run(src, tmp_path, OLD_ENV)
    for line in OLD_ENV.splitlines():
        assert line in after.splitlines(), f"{line} changed"


def test_an_existing_redis_password_is_never_replaced(src: str, tmp_path: Path) -> None:
    after, out = _run(src, tmp_path, OLD_ENV + "VEYRS_REDIS_PASSWORD=keepme\n")
    assert "VEYRS_REDIS_PASSWORD=keepme" in after.splitlines()
    assert after.count("VEYRS_REDIS_PASSWORD=") == 1
    assert "added" not in out


def test_no_database_or_signing_secret_is_ever_generated_on_reuse(src: str, tmp_path: Path) -> None:
    after, _ = _run(src, tmp_path, "VEYRS_HTTP_BIND=127.0.0.1:8080\n")
    for key in ("POSTGRES_PASSWORD", "VEYRS_DB_PASSWORD", "VEYRS_SECRET_KEY", "VEYRS_ENCRYPTION_KEY"):
        assert f"{key}=" not in after, f"{key} was invented for an existing install"
