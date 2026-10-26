"""Guards for the container stack (docker/).

These run in the ordinary suite, with no Docker daemon: they are the half of
the contract that can be checked by reading. The half that needs a running
stack -- tenant isolation actually isolating, the admin password surviving a
re-run -- lives in scripts/test-docker-stack.sh.

Parsed as TEXT rather than with a YAML library on purpose: PyYAML is not in
requirements.txt, and adding a dependency so that a guard can run is how a
guard ends up deleted the next time the lock file is regenerated.
"""
from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = (ROOT / "docker" / "compose.yaml").read_text()
DOCKERFILE = (ROOT / "docker" / "Dockerfile").read_text()
INITDB = (ROOT / "docker" / "initdb.d" / "10-app-role.sh").read_text()
DRIVER = (ROOT / "docker" / "veyrs-docker.sh").read_text()
IGNORE = (ROOT / ".dockerignore").read_text()


def _service(name: str) -> str:
    """The text of one service block, from its key to the next same-level key."""
    m = re.search(rf"^  {name}:$", COMPOSE, re.M)
    assert m, f"no service '{name}' in docker/compose.yaml"
    rest = COMPOSE[m.end():]
    nxt = re.search(r"^  \w[\w-]*:$|^\w[\w-]*:$", rest, re.M)
    return rest[: nxt.start()] if nxt else rest


def _uncommented(block: str) -> str:
    return "\n".join(l for l in block.splitlines() if not l.lstrip().startswith("#"))


# ---------------------------------------------------------------------------
# The application role must not be a PostgreSQL superuser.
#
# This is the single load-bearing decision in the stack. A superuser bypasses
# row level security unconditionally, and 70 of 87 tables carry FORCE ROW
# LEVEL SECURITY. Under a superuser every policy silently stops applying:
# nothing errors, nothing logs, \d still lists them. scripts/
# test-docker-stack.sh proves the consequence on a live stack; these two make
# the regression impossible to merge.
# ---------------------------------------------------------------------------
def test_the_postgres_superuser_is_not_the_application_role():
    pg = _uncommented(_service("postgres"))
    m = re.search(r"POSTGRES_USER:\s*(\S+)", pg)
    assert m, "postgres service declares no POSTGRES_USER"
    assert m.group(1) == "postgres", (
        f"POSTGRES_USER is {m.group(1)!r}. The image creates that role as a "
        "SUPERUSER, and a superuser bypasses row level security entirely -- "
        "VEYRS' tenant isolation would silently stop applying."
    )


def test_the_application_role_is_created_without_privileges():
    body = _uncommented(INITDB)
    assert "NOSUPERUSER" in body, "initdb.d must create the app role NOSUPERUSER"
    assert "NOBYPASSRLS" in body, "initdb.d must create the app role NOBYPASSRLS"
    assert "SUPERUSER" not in body.replace("NOSUPERUSER", ""), \
        "initdb.d grants SUPERUSER to the application role"
    assert re.search(r"CREATE DATABASE .*OWNER", body), (
        "the app role must OWN its databases: cli.init_db issues ALTER TABLE "
        "... FORCE ROW LEVEL SECURITY, which only the owner may do"
    )


# ---------------------------------------------------------------------------
# Trusting X-Forwarded-For and publishing the API port are each defensible
# alone and unsafe together, so they are asserted together.
# ---------------------------------------------------------------------------
def test_the_api_publishes_no_host_port():
    api = _uncommented(_service("api"))
    assert "ports:" not in api, (
        "the api service publishes a host port. It runs with "
        "VEYRS_TRUST_PROXY_HEADERS=true, so a directly reachable port lets any "
        "caller set X-Forwarded-For and mint a fresh rate-limit identity per "
        "request -- which turns the /auth/* credential-stuffing limit into "
        "decoration."
    )
    assert 'VEYRS_TRUST_PROXY_HEADERS: "true"' in COMPOSE, (
        "X-Forwarded-For is not trusted, so ratelimit.py falls back to "
        "request.client.host -- always the console's address in a container, "
        "so every caller shares one rate-limit bucket"
    )


def test_the_database_publishes_no_host_port():
    assert "ports:" not in _uncommented(_service("postgres")), \
        "the database must be reachable only on the stack network"
    assert "ports:" not in _uncommented(_service("redis"))


def test_only_the_console_publishes_and_it_defaults_to_loopback():
    console = _uncommented(_service("console"))
    assert "ports:" in console
    assert "VEYRS_HTTP_BIND:-127.0.0.1:" in console, (
        "the console must default to loopback. It is an operator surface with "
        "a login form; arriving bound to every interface publishes it to the "
        "local network on behalf of someone who only meant to try it."
    )


# ---------------------------------------------------------------------------
# Secrets
# ---------------------------------------------------------------------------
def test_the_signing_and_encryption_keys_are_refused_not_defaulted():
    for var in ("VEYRS_SECRET_KEY", "VEYRS_ENCRYPTION_KEY",
                "POSTGRES_PASSWORD", "VEYRS_DB_PASSWORD"):
        assert re.search(rf"\$\{{{var}:\?", COMPOSE), (
            f"{var} must use ${{{var}:?...}} so compose refuses to start "
            "without it. An empty VEYRS_SECRET_KEY makes config.py mint a "
            "RANDOM key per process: with 4 workers, tokens signed by one are "
            "rejected by the other three and authentication fails "
            "intermittently rather than loudly."
        )


def test_the_superuser_password_never_reaches_the_api_service():
    api = _uncommented(_service("api"))
    assert "POSTGRES_PASSWORD" not in api, (
        "the api service receives the PostgreSQL superuser password. A "
        "long-lived, network-reachable process holding the credential that "
        "bypasses tenant isolation is the worst thing this stack could hand "
        "an attacker who finds an SSRF."
    )
    assert "POSTGRES_PASSWORD" in _uncommented(_service("init")), \
        "the init service does need it, to read the RLS-forced users table"


def test_the_image_is_built_from_named_copies_not_the_whole_tree():
    body = "\n".join(l for l in DOCKERFILE.splitlines() if not l.startswith("#"))
    assert not re.search(r"^COPY \.\s+\.", body, re.M), (
        "COPY . . bakes .env, .bootstrap-credentials and var/backups/ -- the "
        "live signing key, the live Fernet key and a production dump -- into "
        "an image layer, where a later RUN rm cannot remove them."
    )


def test_dockerignore_covers_nested_secret_files():
    # The `**/` is the whole point. A bare `.env` matches only the context
    # root, and docker/.env -- which veyrs-docker.sh writes, carrying the
    # signing key, the Fernet key and the admin password -- sits one directory
    # down, where that pattern never looks.
    #
    # Matched LINE-ANCHORED, not as a substring. `"**/.env" in IGNORE` is
    # satisfied by the neighbouring `**/.env.*` line, so the guard stayed green
    # with the protection removed -- caught by mutating the file it guards.
    for pattern in (r"\*\*/\.env", r"\*\*/\.bootstrap-credentials", r"var/"):
        assert re.search(rf"^{pattern}$", IGNORE, re.M), (
            f"'{pattern}' must appear on its own line in .dockerignore. The "
            "`**/` is the point: a bare `.env` matches only the context root, "
            "and docker/.env -- carrying the signing key, the Fernet key and "
            "the admin password -- sits one directory down."
        )


# ---------------------------------------------------------------------------
# Operability
# ---------------------------------------------------------------------------
def test_the_init_service_has_its_healthcheck_disabled():
    init = _service("init")
    assert "disable: true" in init, (
        "the image HEALTHCHECK probes :8000 and this service does not listen, "
        "so it would settle on 'unhealthy' forever. A permanently red health "
        "column teaches the operator to ignore the column meant to carry the "
        "alarm."
    )


def test_the_console_address_is_static_and_matches_what_uvicorn_trusts():
    # uvicorn is told to believe X-Forwarded-For from exactly one address. If
    # the console's address were dynamic it would stop matching after any
    # recreate that reorders startup -- and it fails quietly: every user lands
    # in one rate-limit bucket and every audit entry records the proxy.
    console = _uncommented(_service("console"))
    m_ip = re.search(r"ipv4_address:\s*\$\{VEYRS_CONSOLE_IP:-([\d.]+)\}", console)
    assert m_ip, "the console must have a static ipv4_address"
    m_allow = re.search(
        r"VEYRS_FORWARDED_ALLOW_IPS:\s*\$\{VEYRS_CONSOLE_IP:-([\d.]+)\}",
        _uncommented(_service("api")))
    assert m_allow, "the api must pin VEYRS_FORWARDED_ALLOW_IPS"
    assert m_ip.group(1) == m_allow.group(1), (
        f"the console is at {m_ip.group(1)} but the api trusts "
        f"{m_allow.group(1)}"
    )


def test_postgres_health_is_a_real_login_not_pg_isready():
    # _uncommented, not _service: the comment above the healthcheck explains
    # why pg_isready is insufficient, and matching on that made the guard fail
    # against a correct file. A guard that fires on its own documentation gets
    # deleted rather than fixed.
    pg = _uncommented(_service("postgres"))
    assert "pg_isready" not in pg, (
        "pg_isready answers 'accepting connections' as soon as the postmaster "
        "listens, which on a first start is BEFORE initdb.d has created the "
        "application role. init then fails authentication and the error reads "
        "like a wrong password rather than a race."
    )
    assert "psql" in pg and "SELECT 1" in pg


def test_the_backup_command_runs_as_the_superuser_and_verifies_the_result():
    # pg_dump as the application role produces a TRUNCATED dump that looks
    # fine: FORCE ROW LEVEL SECURITY applies to the table owner too, -Fc writes
    # as it goes, and what is left is 392 KB where the good one is 509 MB.
    # Measured on production, 2026-09-21.
    m = re.search(r"cmd_backup\(\)\s*\{.*?\n\}", DRIVER, re.S)
    assert m, "veyrs-docker.sh has no cmd_backup"
    body = m.group(0)
    assert "pg_dump -U postgres" in body, \
        "the backup must run as the superuser, not as the application role"
    assert "pg_restore --list" in body, (
        "the backup must be verified by listing its contents. Size alone does "
        "not tell a truncated dump from a small database."
    )


def test_the_stack_says_out_loud_what_is_not_running():
    # A container node quietly missing intel-sync stops learning about new
    # CVEs while continuing to score confidently. Absence has to be stated
    # where an operator will read it, not only in a comment -- and it has to
    # name the HOST UNIT it corresponds to, because that is the vocabulary
    # every other VEYRS document uses.
    for unit in ("veyrs-agent", "veyrs-intel-sync", "veyrs-digest"):
        assert unit in DRIVER, f"veyrs-docker.sh status must name {unit}"
        assert unit in COMPOSE, f"compose.yaml must account for {unit}"
    # And it must state the CONSEQUENCE, not just the fact. "intel: not
    # running" is a status line; "the data does not refresh and SLA deadlines
    # do not elapse" is the reason anyone would act on it.
    status = re.search(r"cmd_status\(\)\s*\{.*?\n\}", DRIVER, re.S)
    assert status, "veyrs-docker.sh has no cmd_status"

    # STRUCTURE, not a phrase, and read from the UNCOMMENTED body.
    #
    # The first version of this asserted that the words "does not refresh" or
    # "stopped learning" appeared somewhere in cmd_status -- and a mutation
    # that gutted the printed consequence survived, because the explanatory
    # COMMENT above it still contained one of the phrases. A guard that reads
    # prose measures the documentation, not what the operator sees on screen.
    # Third time this exact shape has bitten in this repository.
    calls = re.findall(
        r'_report_worker\s+"\$up"\s+(\w+)\s+"([^"]*)"\s+"([^"]*)"\s*\\?\s*"([^"]*)"',
        _uncommented(status.group(0)),
    )
    reported = {c[0]: c for c in calls}
    for svc, unit in (("intel", "veyrs-intel-sync"), ("digest", "veyrs-digest"),
                      ("agent", "veyrs-agent")):
        assert svc in reported, f"cmd_status does not report on '{svc}'"
        _, host_unit, flag, consequence = reported[svc]
        assert unit in host_unit, (
            f"'{svc}' is not mapped to its host unit ({unit}); that mapping is "
            "the vocabulary every other VEYRS document uses"
        )
        assert flag.startswith("--with-"), \
            f"'{svc}' is reported without telling the operator how to enable it"
        assert len(consequence) >= 60, (
            f"'{svc}' is reported with no real consequence ({consequence!r}). "
            "\"not running\" is a status line; what it costs is the reason "
            "anyone would act on it."
        )


# ---------------------------------------------------------------------------
# The optional services: present, but never by default.
# ---------------------------------------------------------------------------
def test_the_workers_and_the_agent_are_behind_profiles():
    # A profile is what keeps `up` from starting an NVD pull -- hours against
    # a rate-limited feed -- on a stack somebody is merely trying out, and it
    # is what keeps a scanner from existing before its operator has decided
    # what it may touch.
    for svc, profile in (("intel", "workers"), ("digest", "workers"),
                         ("agent", "agent")):
        body = _uncommented(_service(svc))
        # ANCHORED to the start of a line. `re.search("profiles:")` also
        # matches `x-was-profiles:`, `old-profiles:` and anything else ending
        # in that word -- the same substring trap that let a guard pass with
        # `**/.env` removed from .dockerignore, because the neighbouring line
        # `**/.env.*` contained it.
        m = re.search(r"^\s*profiles:\s*\[([^\]]*)\]", body, re.M)
        assert m, f"service '{svc}' has no profiles: key -- it would start with a bare `up`"
        assert profile in m.group(1), f"service '{svc}' is not in profile '{profile}'"


def test_the_base_services_are_not_behind_a_profile():
    # The mirror. A profile accidentally added to `api` would make `up` bring
    # up a console with no backend and report success.
    for svc in ("postgres", "redis", "init", "api", "console"):
        assert "profiles:" not in _uncommented(_service(svc)), (
            f"service '{svc}' is behind a profile; the base stack would not start"
        )


def test_the_agent_token_is_not_a_required_variable_marker():
    # `${VEYRS_AGENT_TOKEN:?...}` would look like the right level of rigour
    # and would break the whole file: compose interpolates every service when
    # it LOADS the file, profiles or not, so `up`, `ps`, `logs` and `down` of
    # the base stack would all fail over a service nobody asked to run. The
    # real guard is in veyrs_agent.py, which refuses to start without it.
    body = _uncommented(_service("agent"))
    for var in ("VEYRS_AGENT_TOKEN", "VEYRS_AGENT_ALLOW"):
        assert f"${{{var}:?" not in body, (
            f"{var} uses a required-variable marker. Compose interpolates the "
            "whole file regardless of profiles, so this breaks every command "
            "on the base stack."
        )
        assert f"${{{var}:-" in body, f"{var} should be declared with an empty default"


def test_the_agent_is_not_granted_net_raw():
    # NET_RAW is what nmap needs for SYN scanning and also what lets a process
    # forge packets on the stack network. Connect-scan works without it. If it
    # is ever granted it must be a deliberate, reviewed edit -- not something
    # that arrived with a profile flag.
    body = _uncommented(_service("agent"))
    assert "NET_RAW" not in body, (
        "the agent service grants NET_RAW. It must stay commented out: a "
        "container with NET_RAW is not meaningfully confined."
    )
    assert "NET_RAW" in _service("agent"), (
        "the commented explanation of why NET_RAW is withheld was removed"
    )


def test_the_agent_stops_with_sigint_like_the_host_unit():
    # veyrs_agent.py exits 0 on KeyboardInterrupt, so SIGINT is its graceful
    # stop where SIGTERM is not. veyrs-agent.service sets KillSignal=SIGINT
    # for exactly this reason.
    body = _uncommented(_service("agent"))
    assert re.search(r"stop_signal:\s*SIGINT", body), (
        "the agent service must stop with SIGINT, matching KillSignal in "
        "veyrs-agent.service"
    )


# ---------------------------------------------------------------------------
# One home for the feed order.
# ---------------------------------------------------------------------------
def test_the_intel_worker_runs_the_repository_script():
    # The feed order (CWE names what NVD creates, EPSS skips CVEs it has never
    # seen, KEV is the last word), the per-feed isolation and the SLA sweep
    # that must run even on an empty tick all live in scripts/sync-intel.sh.
    # Re-spelling any of that as a compose `command` is the same ladder
    # written twice, and the copy nobody runs by hand is the one that drifts.
    body = _uncommented(_service("intel"))
    assert "scripts/sync-intel.sh" in body, \
        "the intel worker must run scripts/sync-intel.sh, not its own feed list"
    for feed in ("sync-nvd", "sync-epss", "sync-kev", "sync-cwe", "run-sla"):
        assert feed not in body, (
            f"compose.yaml names '{feed}' directly -- that is a second copy of "
            "the feed order. It belongs only in scripts/sync-intel.sh."
        )
    assert "scripts/send-digest.sh" in _uncommented(_service("digest"))


def test_the_shared_scripts_resolve_their_root_instead_of_hard_coding_it():
    # They are run by systemd on a host (venv + .env) and by a container
    # (neither). A hard-coded /opt/veyrs/venv/bin/python is what would force a
    # second implementation to exist.
    for name in ("sync-intel.sh", "send-digest.sh"):
        body = (ROOT / "scripts" / name).read_text()
        assert "/opt/veyrs/venv/bin/python" not in body, (
            f"scripts/{name} hard-codes the venv interpreter, so the container "
            "cannot run it and the logic would have to be duplicated"
        )
        assert 'BASH_SOURCE[0]' in body, f"scripts/{name} does not resolve its own root"


def test_the_tick_loop_carries_no_schedule_of_its_own():
    # Both host timers are hourly TICKS; the cadence lives in
    # organizations.settings and the console edits it. An hour written into
    # the loop would make a setting the console displays and the machine
    # ignores -- the exact defect the host units were written to avoid.
    # UNCOMMENTED. The comments name `intel-due` and `due_now` on purpose --
    # they are what explains where the decision does live -- and a guard that
    # reads prose measures the documentation instead of the code. The same
    # mistake made a `pg_isready` assertion fail against its own explanation.
    tick = _uncommented((ROOT / "docker" / "tick.sh").read_text())
    body = _uncommented(_service("intel")) + _uncommented(_service("digest"))
    assert "intel-due" not in tick and "due_now" not in tick, \
        "tick.sh decides what is due; that belongs to the database"
    assert re.search(r"OnCalendar|\b0[0-9]:00\b", tick) is None, \
        "tick.sh carries a wall-clock schedule"
    # An interval, yes -- that is how often the question is asked.
    assert '"3600"' in body, "the workers should tick hourly, like the host timers"


# ---------------------------------------------------------------------------
# The agent image.
# ---------------------------------------------------------------------------
def test_the_scanner_binary_is_pinned_and_checksummed():
    # A scanner fetched at build time with no verification is a supply-chain
    # hole in the one component whose entire job is to be pointed at things
    # and believed about what it finds.
    assert re.search(r"ARG NUCLEI_VERSION=\d+\.\d+\.\d+", DOCKERFILE), \
        "the nuclei version is not pinned"
    assert re.search(r"ARG NUCLEI_SHA256_\w+=[0-9a-f]{64}", DOCKERFILE), \
        "the nuclei download is not checksummed"
    assert "sha256sum -c -" in DOCKERFILE, \
        "the checksum is declared but never verified"


def test_the_agent_refuses_to_start_without_templates():
    # THE failure mode of this component. nuclei with no templates does not
    # error: it runs every job, finds nothing, and reports a clean scan for
    # assets that were never tested -- worse than being down, because a down
    # agent is visible. It is why veyrs-agent.service omits ProtectHome, and
    # in a container the same hole arrives through an empty named volume.
    entry = (ROOT / "docker" / "agent-entrypoint.sh").read_text()
    assert "exit 78" in entry, \
        "agent-entrypoint.sh does not refuse to start on an empty template corpus"
    assert "-update-templates" in entry, \
        "agent-entrypoint.sh never seeds the template corpus"


def test_the_agent_image_does_not_run_as_root():
    m = re.search(r"FROM api AS agent\b(.*)", DOCKERFILE, re.S)
    assert m, "no agent target in the Dockerfile"
    users = re.findall(r"^USER\s+(\S+)", m.group(1), re.M)
    assert users, "the agent stage sets no USER"
    assert users[-1].startswith("10001"), (
        f"the agent stage ends as {users[-1]!r}; it must drop back to uid 10001 "
        "after the package install"
    )


# ---------------------------------------------------------------------------
# Teardown has to see the whole stack.
# ---------------------------------------------------------------------------
def test_teardown_and_inspection_cover_every_profile():
    # `docker compose down` WITHOUT the profiles that started a container does
    # not stop it, prints no warning and exits 0. An operator who ran
    # `up --with-agent` and then `down` would be left with a scanner still
    # running on a stack they believe is off.
    assert "COMPOSE_ALL=(" in DRIVER, "veyrs-docker.sh defines no all-profiles invocation"
    block = re.search(r"COMPOSE_ALL=\((.*?)\)", DRIVER, re.S).group(1)
    for profile in ("workers", "agent"):
        assert f"--profile {profile}" in block, \
            f"COMPOSE_ALL does not include the '{profile}' profile"
    for verb in ("down", "restart", "ps", "logs"):
        m = re.search(rf"^\s*{verb}\)\s*shift;.*$", DRIVER, re.M)
        assert m, f"veyrs-docker.sh has no '{verb}' command"
        assert "COMPOSE_ALL" in m.group(0), (
            f"'{verb}' uses the base invocation, so it would silently skip "
            "containers started under a profile"
        )


def test_nginx_re_resolves_the_api_address_instead_of_caching_it_forever():
    """The console outliving the address it proxies to.

    nginx resolves a literal name in `proxy_pass` ONCE, at configuration load,
    and caches it for the life of the worker. Measured 2026-09-22:
    `up --with-workers` on a running stack recreated `api` on a new address,
    left `console` untouched, and every request through the console returned
    502 -- `connect() failed (111: Connection refused) ... upstream:
    "http://172.29.0.4:8000/readyz"` -- while `docker compose ps` reported BOTH
    containers healthy. console's probe fetches its own static index; api's
    probe runs inside api. Green on both sides, dead in between.

    Pinning api to a static address was the first fix and is the reason this
    test also asserts the NEGATIVE: `docker compose run` creates a second
    container of that service and cannot reuse a fixed address ("Address
    already in use"), which takes out `veyrs-docker.sh cli` and the
    tenant-isolation assertions in scripts/test-docker-stack.sh.
    """
    conf = (ROOT / "docker" / "console.conf").read_text()

    assert re.search(r"^\s*resolver\s+127\.0\.0\.11\b", conf, re.M), (
        "console.conf declares no resolver. Without one, nginx cannot look an "
        "upstream up again after startup."
    )

    passes = re.findall(r"proxy_pass\s+(\S+?);", conf)
    assert passes, "console.conf proxies nothing"
    for target in passes:
        assert "$" in target, (
            f"proxy_pass {target} uses a literal name. A resolver does NOT make "
            "a literal re-resolve -- only a variable defers the lookup to "
            "request time. This is the exact regression that served 502s."
        )
        assert "/" not in target.split("://", 1)[-1], (
            f"proxy_pass {target} carries a URI part. With a variable AND a URI, "
            "nginx replaces the request URI instead of forwarding it, which "
            "changes what the API receives."
        )

    # And api must NOT be pinned: that fix broke `docker compose run`.
    api = _uncommented(_service("api"))
    assert "ipv4_address" not in api, (
        "the api service pins an address. `docker compose run` creates a second "
        "container of the service and fails with 'Address already in use', "
        "which breaks `veyrs-docker.sh cli` and the isolation assertions."
    )
