"""Guards for the PUBLISHED images and the privileges the stack runs with.

0.32.4 made the container images a release artefact (ghcr.io/visionebc/veyrs,
veyrs-console, veyrs-agent and an offline bundle) and dropped every privilege
the stack did not need. These pin both decisions so that neither can be
undone by an edit that still "works": an unpinned base image, a root console
or a capability added back all start, pass health checks and serve pages.

Like test_container_stack.py, parsed as TEXT -- no YAML library, no Docker.
Matches are anchored to whole lines with comments removed: three earlier
guards in this repository passed against a COMMENT that named the thing they
were looking for, or against a neighbouring key that contained it as a
substring.

The live half -- CapEff of PID 1 is zero, no console process is uid 0, init
logs "running as uid 10001" -- is section 9 of scripts/test-docker-stack.sh.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = (ROOT / "docker" / "compose.yaml").read_text()
DOCKERFILE = (ROOT / "docker" / "Dockerfile").read_text()
CONSOLE_CONF = (ROOT / "docker" / "console.conf").read_text()
INIT = (ROOT / "docker" / "init.sh").read_text()
DRIVER = (ROOT / "docker" / "veyrs-docker.sh").read_text()
PUBLISH = (ROOT / "scripts" / "publish-images.sh").read_text()
SETUP = (ROOT / "veyrs-setup.sh").read_text()

DIGEST = r"@sha256:[0-9a-f]{64}"


def _code(text: str) -> str:
    """Text with full-line comments removed (shell, YAML, Dockerfile, nginx)."""
    return "\n".join(l for l in text.splitlines() if not l.lstrip().startswith("#"))


def _service(name: str) -> str:
    m = re.search(rf"^  {name}:$", COMPOSE, re.M)
    assert m, f"no service '{name}' in docker/compose.yaml"
    rest = COMPOSE[m.end():]
    nxt = re.search(r"^  \w[\w-]*:$|^\w[\w-]*:$", rest, re.M)
    return _code(rest[: nxt.start()] if nxt else rest)


def _stage(name: str) -> str:
    """The Dockerfile text of one build stage, comments removed."""
    code = _code(DOCKERFILE)
    m = re.search(rf"^FROM \S+ AS {name}$", code, re.M)
    assert m, f"no stage '{name}' in docker/Dockerfile"
    rest = code[m.start():]
    nxt = re.search(r"^FROM ", rest[1:], re.M)
    return rest[: nxt.start() + 1] if nxt else rest


# ---------------------------------------------------------------------------
# Reproducible inputs
# ---------------------------------------------------------------------------
def test_every_external_base_image_is_pinned_by_digest():
    froms = re.findall(r"^FROM (\S+)", _code(DOCKERFILE), re.M)
    external = [f for f in froms if f not in ("api",)]
    assert external, "no FROM lines found"
    loose = [f for f in external if not re.search(DIGEST + "$", f)]
    assert not loose, (
        f"base images not pinned by digest: {loose}. A tag is a pointer the "
        "registry moves; python:3.11-slim moved from Debian 12 to 13 under this "
        "file without a line of it changing.")


def test_the_console_base_is_not_the_end_of_life_nginx_branch():
    base = re.search(r"^FROM (\S+) AS console$", _code(DOCKERFILE), re.M).group(1)
    assert not base.startswith("nginx:1.27"), \
        "nginx 1.27 was a mainline branch that ended in April 2025 and gets no fixes"


def test_postgres_and_redis_defaults_are_pinned_by_digest():
    for svc, var in (("postgres", "VEYRS_POSTGRES_IMAGE"), ("redis", "VEYRS_REDIS_IMAGE")):
        m = re.search(rf"^    image: \$\{{{var}:-(\S+)\}}$", _service(svc), re.M)
        assert m, f"{svc}: image is not ${{{var}:-<pinned default>}}"
        assert re.search(DIGEST + "$", m.group(1)), f"{svc} default {m.group(1)} is not pinned by digest"


def test_the_bundled_postgres_stays_on_the_debian_it_was_initialised_with():
    # glibc collation changed between bookworm and trixie: a data volume moved
    # across leaves text indexes mis-ordered until REINDEX.
    m = re.search(r"VEYRS_POSTGRES_IMAGE:-(postgres:[^@]+)@", _service("postgres"))
    assert m and m.group(1).endswith("-bookworm"), \
        f"postgres image {m and m.group(1)} changes the distribution under existing volumes"


def test_images_carry_provenance_labels():
    for stage in ("api", "console"):
        body = _stage(stage)
        for key in ("source", "version", "revision", "licenses"):
            assert re.search(rf"org\.opencontainers\.image\.{key}=", body), \
                f"stage {stage} has no org.opencontainers.image.{key} label"


# ---------------------------------------------------------------------------
# Nothing runs as root that does not have to
# ---------------------------------------------------------------------------
def test_the_console_stage_runs_unprivileged():
    users = re.findall(r"^USER\s+(\S+)", _stage("console"), re.M)
    assert users, "the console stage sets no USER: nginx's master process runs as root"
    assert users[-1].split(":")[0] not in ("0", "root"), f"console USER is {users[-1]}"


def test_the_console_listens_on_an_unprivileged_port_everywhere():
    listens = re.findall(r"^\s*listen\s+(\d+)", _code(CONSOLE_CONF), re.M)
    assert listens and all(int(p) >= 1024 for p in listens), \
        f"console.conf listens on {listens}; uid 101 cannot bind below 1024"
    ports = re.findall(r'^\s*- "\$\{VEYRS_HTTP_BIND:-[^}]+\}:(\d+)"$', _service("console"), re.M)
    assert ports == listens[:1], \
        f"compose maps the console to container port {ports}, nginx listens on {listens}"
    assert re.search(r"127\.0\.0\.1:(\d+)/", _code(_stage("console"))).group(1) == listens[0], \
        "the console HEALTHCHECK probes a port nginx does not listen on"


def test_init_gives_up_root_before_it_touches_the_database():
    code = _code(INIT)
    drop = re.search(r"^\s*exec setpriv --reuid=10001 --regid=10001 --clear-groups", code, re.M)
    first_db = re.search(r"^python -m veyrs\.cli init-db$", code, re.M)
    assert drop, "init.sh no longer re-executes itself as 10001"
    assert first_db and drop.start() < first_db.start(), \
        "init-db runs before init.sh drops root"


# ---------------------------------------------------------------------------
# Capabilities and filesystem
# ---------------------------------------------------------------------------
def _anchor() -> str:
    m = re.search(r"^x-hardening: &hardening\n((?:  .*\n|\s*\n)+)", COMPOSE, re.M)
    assert m, "no x-hardening anchor in compose.yaml"
    return _code(m.group(1))


def test_the_hardening_anchor_drops_everything():
    a = _anchor()
    assert re.search(r'^  security_opt:\n    - "no-new-privileges:true"$', a, re.M), "anchor: no-new-privileges"
    assert re.search(r"^  cap_drop:\n    - ALL$", a, re.M), "anchor: cap_drop ALL"
    assert re.search(r"^  read_only: true$", a, re.M), "anchor: read_only"


def test_every_veyrs_service_uses_the_hardening_anchor():
    for svc in ("api", "console", "intel", "digest", "agent"):
        assert re.search(r"^    <<: \*hardening$", _service(svc), re.M), \
            f"service {svc} does not merge the hardening anchor"
        assert not re.search(r"^    cap_add:", _service(svc), re.M), f"service {svc} adds capabilities back"
        assert not re.search(r"^    privileged:", _service(svc), re.M), f"service {svc} is privileged"


def test_init_gets_only_the_capabilities_its_chown_and_setpriv_need():
    body = _service("init")
    assert re.search(r"^    cap_drop:\n      - ALL$", body, re.M), "init does not drop ALL first"
    m = re.search(r"^    cap_add:\n((?:      - \w+\n)+)", body + "\n", re.M)
    added = set(re.findall(r"- (\w+)", m.group(1))) if m else set()
    allowed = {"CHOWN", "DAC_OVERRIDE", "FOWNER", "SETUID", "SETGID"}
    assert added and added <= allowed, f"init adds {sorted(added - allowed)} beyond {sorted(allowed)}"
    assert re.search(r'^    security_opt:\n      - "no-new-privileges:true"$', body, re.M), "init: no-new-privileges"


def test_postgres_and_redis_cannot_gain_privileges():
    for svc in ("postgres", "redis"):
        assert re.search(r'^    security_opt:\n      - "no-new-privileges:true"$', _service(svc), re.M), \
            f"{svc}: no-new-privileges missing"


def test_the_api_tmp_holds_the_largest_upload_the_console_accepts():
    body = _service("api")
    m = re.search(r"^      - /tmp:size=(\d+)m", body, re.M)
    limit = re.search(r"client_max_body_size (\d+)m;", CONSOLE_CONF)
    assert m and limit, "api has no sized /tmp tmpfs, or console.conf no body limit"
    assert int(m.group(1)) > int(limit.group(1)), (
        f"api /tmp is {m.group(1)}m but uploads of {limit.group(1)}m are accepted: "
        "Starlette spools uploads to /tmp, and a full tmpfs is ENOSPC")


# ---------------------------------------------------------------------------
# Where images come from
# ---------------------------------------------------------------------------
def test_up_never_falls_back_to_building_on_its_own():
    code = _code(DRIVER)
    assert re.search(r'up -d --no-build --pull never$', code, re.M), \
        "`up` without --no-build/--pull never quietly builds a missing image"


def test_an_offline_bundle_is_only_loaded_after_its_checksum_matches():
    code = _code(DRIVER)
    load = code[code.index("cmd_load() {"):]
    i_check = load.index('[[ -n "$want" && "$want" == "$got" ]]')
    i_load = load.index("docker load -i")
    assert i_check < i_load, "docker load runs before the bundle checksum is compared"
    assert re.search(r'\[\[ -f "\$file\.sha256" \]\] \|\| die', load), "a bundle without .sha256 is accepted"
    assert re.search(r'IMAGES_ARG\.sha256" \] \|\| die', _code(SETUP)), "veyrs-setup.sh --images accepts a bundle with no .sha256"


def test_the_publish_script_never_puts_the_token_on_a_command_line():
    code = _code(PUBLISH)
    assert "--password-stdin" in code, "docker login must read the token from stdin"
    assert not re.search(r'(-p|--password)[ =]"?\$\{?GH_TOKEN', code), "the token is passed as an argument"
    assert not re.search(r"curl[^\n]*Authorization: [^\n]*\$\{?GH_TOKEN", code), "the token is on curl's argv"


def test_the_publish_script_proves_anonymous_access_and_digest_equality():
    code = _code(PUBLISH)
    assert re.search(r'export DOCKER_CONFIG="\$WORK/anon-config"', code), "no anonymous re-read after push"
    assert re.search(r'\[\[ "\$remote" == "\$\{PUSHED\[\$t\]\}" \]\]', code), "pushed and served digests are not compared"


def test_the_publish_script_checks_who_each_image_runs_as():
    code = _code(PUBLISH)
    assert re.search(r'\[\[ "\$\(uid "\$CON_IMG"\)" == 101 \]\]', code), "console uid not verified"
    assert re.search(r'\[\[ "\$\(uid "\$API_IMG"\)" == 10001 \]\]', code), "api uid not verified"


def test_a_refused_anonymous_read_reaches_its_explanation():
    # set -e + pipefail turn a failed read inside $(...) into a silent exit
    # before the "make the package public" message. Happened on 0.32.4.
    code = _code(PUBLISH)
    m = re.search(r'^\s*remote="\$\(docker buildx imagetools inspect .*\)"$', code, re.M)
    assert m and m.group(0).rstrip('"').rstrip(")").endswith("|| true"), \
        "the anonymous read can end the script before it explains the failure"

