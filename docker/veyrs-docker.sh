#!/usr/bin/env bash
# VEYRS container stack driver.
#
# Exists so that the things which are easy to get wrong and quiet when wrong
# are not left to memory:
#
#   * the build context is the repository root, not docker/
#   * there are TWO images (api, console) from one Dockerfile
#   * secrets must be generated once and kept, not regenerated per `up`
#   * pg_dump run as the application role produces a TRUNCATED backup that
#     looks fine (see `backup` below)
#
#   ./veyrs-docker.sh init      write docker/.env with real secrets (once)
#   ./veyrs-docker.sh up        get the images, start, wait until /readyz answers
#       --with-workers            + intel (NVD/EPSS/KEV/SLA) and digest
#       --with-agent              + the scanner runner (READ docker/README.md)
#       --all                     both
#   ./veyrs-docker.sh down      stop (keeps the data; add --volumes to destroy)
#   ./veyrs-docker.sh ps|logs   inspect
#   ./veyrs-docker.sh psql      a shell on the database, as the app role
#   ./veyrs-docker.sh backup    a COMPLETE dump (as the superuser) + verify
#   ./veyrs-docker.sh cli ...   run backend/veyrs/cli.py in the stack
#   ./veyrs-docker.sh status    version, health and what is NOT running here
#   ./veyrs-docker.sh load FILE load an offline image bundle (no registry needed)
#
# Where the images come from is VEYRS_IMAGE_SOURCE in .env:
#
#   registry  pull the published images (ghcr.io/visionebc/veyrs*:<version>).
#             What `init` writes. No compiler, no PyPI, ~1 minute.
#   build     build them from THIS tree (docker/Dockerfile). For a modified
#             tree, or a version that was never published.
#   local     use images that are already on this machine -- normally from
#             `load FILE` on a host without internet. Never pulls, never builds.
#
# A .env written before 0.32.4 has no VEYRS_IMAGE_SOURCE and keeps building,
# which is what it did when it was written.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
ENV_FILE="$HERE/.env"

# ===========================================================================
# Overlays, named in .env rather than on every command line.
#
#   VEYRS_COMPOSE_OVERLAYS=compose.external-db.yaml
#
# A file given with -f to `up` and forgotten on `down`, `ps` or `backup` is
# the same trap as a forgotten profile (see COMPOSE_ALL below): the commands
# then describe a different stack from the one running. Read from .env, every
# verb sees the same set. Names only, resolved inside docker/ -- a path would
# let .env pull in a compose file from anywhere on the host.
# ===========================================================================
OVERLAYS=()
if [[ -f "$ENV_FILE" ]]; then
    for ov in $(sed -n 's/^VEYRS_COMPOSE_OVERLAYS=//p' "$ENV_FILE" | tail -1 | tr -d "'\"," ); do
        [[ "$ov" != */* && -f "$HERE/$ov" ]] || {
            printf '\033[31merror:\033[0m VEYRS_COMPOSE_OVERLAYS names %s, which is not a file in %s\n' "$ov" "$HERE" >&2
            exit 1; }
        OVERLAYS+=(-f "$HERE/$ov")
    done
fi
EXTERNAL_DB=0
[[ " ${OVERLAYS[*]-} " == *"/compose.external-db.yaml "* ]] && EXTERNAL_DB=1

COMPOSE=(docker compose --project-directory "$HERE" -f "$HERE/compose.yaml"
         ${OVERLAYS[@]+"${OVERLAYS[@]}"})

# ===========================================================================
# EVERY profile, for the commands that must see the whole stack.
#
# `docker compose down` run WITHOUT the profiles that started a container does
# not stop that container. It stops the base services, prints no warning, and
# exits 0 -- so an operator who ran `up --with-agent` and then `down` is left
# with a scanner still running and still holding leases, on a stack they
# believe is off. Same for `ps` and `logs`: the containers are simply absent
# from the output, which reads as "not running".
#
# So inspection and teardown always use this, and only `up` and `build` take
# the operator's chosen profiles. There is a test.
# ===========================================================================
COMPOSE_ALL=(docker compose --project-directory "$HERE" -f "$HERE/compose.yaml"
             ${OVERLAYS[@]+"${OVERLAYS[@]}"}
             --profile workers --profile agent)

die()  { printf '\033[31merror:\033[0m %s\n' "$*" >&2; exit 1; }
info() { printf '\033[36m==>\033[0m %s\n' "$*"; }
warn() { printf '\033[33mwarning:\033[0m %s\n' "$*" >&2; }

need_docker() {
    command -v docker >/dev/null 2>&1 || die "docker is not installed"
    docker compose version >/dev/null 2>&1 \
        || die "the docker compose plugin is missing (this is not docker-compose v1)"
}

# A url-safe base64 encoding of 32 random bytes -- exactly what
# cryptography.fernet.Fernet.generate_key() produces. Generated with openssl
# rather than by running the image, because `init` has to work BEFORE anything
# is built; a chicken-and-egg there is how people end up pasting a key from a
# tutorial.
fernet_key() { openssl rand -base64 32 | tr '+/' '-_'; }
secret_key() { openssl rand -base64 48 | tr -d '\n=' | tr '+/' '-_'; }

REGISTRY="ghcr.io/visionebc"
tree_version() { sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$ROOT/pyproject.toml" | head -1; }

env_get() { [[ -f "$ENV_FILE" ]] && sed -n "s/^$1=//p" "$ENV_FILE" | tail -1 | sed "s/^['\"]\(.*\)['\"]\$/\1/" || true; }
# Replace KEY in place or append it. Written THROUGH the file (`cat >`), not by
# renaming over it: under veyrs-setup.sh docker/.env is a symlink to
# /opt/veyrs-docker/veyrs.env, and a rename would replace the link with a copy
# that the next install no longer sees. The mode stays 0600.
env_set() {
    local k="$1" v="$2" tmp
    tmp="$(mktemp)"; chmod 600 "$tmp"
    V="$v" awk -v k="$k" 'BEGIN { done = 0 }
        $0 ~ "^" k "=" { if (!done) { print k "=" ENVIRON["V"]; done = 1 }; next }
        { print } END { if (!done) print k "=" ENVIRON["V"] }' "$ENV_FILE" >"$tmp"
    cat "$tmp" >"$ENV_FILE"; rm -f "$tmp"
}

image_source() {
    local s; s="$(env_get VEYRS_IMAGE_SOURCE)"
    case "${s:-build}" in
        registry|build|local) printf '%s' "${s:-build}" ;;
        *) die "VEYRS_IMAGE_SOURCE=$s in $ENV_FILE (expected registry, build or local)" ;;
    esac
}

require_env() {
    [[ -f "$ENV_FILE" ]] || die "no $ENV_FILE -- run: $0 init"
    # Refuse placeholders rather than letting compose fail four services deep
    # with an error that names a variable and not a remedy.
    local missing=()
    for key in POSTGRES_PASSWORD VEYRS_DB_PASSWORD VEYRS_SECRET_KEY VEYRS_ENCRYPTION_KEY; do
        grep -qE "^${key}=.+" "$ENV_FILE" || missing+=("$key")
    done
    ((${#missing[@]} == 0)) || die "empty in $ENV_FILE: ${missing[*]} -- run: $0 init"

    # The one cross-value check compose cannot make. VEYRS_FORWARDED_ALLOW_IPS
    # is set to VEYRS_CONSOLE_IP, and the console is pinned to that address on
    # the stack network; if the operator moves the subnet without moving the
    # console address, docker refuses to allocate it and the failure names
    # neither variable.
    local subnet console
    subnet=$(grep -E '^VEYRS_SUBNET=' "$ENV_FILE" | cut -d= -f2- || true)
    console=$(grep -E '^VEYRS_CONSOLE_IP=' "$ENV_FILE" | cut -d= -f2- || true)
    if [[ -n "$subnet" && -n "$console" ]]; then
        # Compare the network part only as far as the prefix is written; this
        # is a sanity check, not an IPAM implementation.
        local net="${subnet%%/*}"; net="${net%.*.*}"
        [[ "$console" == "$net".* ]] \
            || die "VEYRS_CONSOLE_IP ($console) is not inside VEYRS_SUBNET ($subnet)"
    fi

    # An evaluation stack that has been told it is production, over plain
    # HTTP. config.assert_production_safe() refuses a non-https
    # public_base_url; catching it here says which file to edit.
    if grep -qE '^VEYRS_ENVIRONMENT=production' "$ENV_FILE" \
       && ! grep -qE '^VEYRS_PUBLIC_BASE_URL=https://' "$ENV_FILE"; then
        die "VEYRS_ENVIRONMENT=production with a non-https VEYRS_PUBLIC_BASE_URL.
This stack terminates plain HTTP. Put a TLS terminator in front of it and set
VEYRS_PUBLIC_BASE_URL to its https address, or leave the environment at
development."
    fi
}

cmd_init() {
    if [[ -f "$ENV_FILE" ]]; then
        # Never silently. Rewriting VEYRS_ENCRYPTION_KEY makes every stored
        # credential in an existing database permanently unreadable.
        die "$ENV_FILE already exists.
Delete it deliberately if you mean to start over -- regenerating
VEYRS_ENCRYPTION_KEY against an existing database makes every stored
credential unrecoverable."
    fi
    command -v openssl >/dev/null 2>&1 || die "openssl is required to generate secrets"

    local admin_pw="${VEYRS_ADMIN_PASSWORD:-$(openssl rand -base64 18 | tr -d '\n=' | tr '+/' '-_')}"

    umask 077
    sed \
        -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(openssl rand -hex 24)|" \
        -e "s|^VEYRS_DB_PASSWORD=.*|VEYRS_DB_PASSWORD=$(openssl rand -hex 24)|" \
        -e "s|^VEYRS_SECRET_KEY=.*|VEYRS_SECRET_KEY=$(secret_key)|" \
        -e "s|^VEYRS_ENCRYPTION_KEY=.*|VEYRS_ENCRYPTION_KEY=$(fernet_key)|" \
        -e "s|^VEYRS_ADMIN_PASSWORD=.*|VEYRS_ADMIN_PASSWORD=${admin_pw}|" \
        "$HERE/env.example" > "$ENV_FILE"
    chmod 600 "$ENV_FILE"

    # The published images of THIS tree's version. A tree whose version was
    # never published fails at `up` with a message that names the switch.
    local ver; ver="$(tree_version)"
    env_set VEYRS_IMAGE_SOURCE registry
    env_set VEYRS_IMAGE "$REGISTRY/veyrs:$ver"
    env_set VEYRS_CONSOLE_IMAGE "$REGISTRY/veyrs-console:$ver"
    env_set VEYRS_AGENT_IMAGE "$REGISTRY/veyrs-agent:$ver"

    info "wrote $ENV_FILE (0600) -- images: $REGISTRY/veyrs*:$ver"
    printf '\n    console   http://%s\n' "$(grep -E '^VEYRS_HTTP_BIND=' "$ENV_FILE" | cut -d= -f2-)"
    printf '    login     %s / %s\n' \
        "$(grep -E '^VEYRS_ADMIN_EMAIL=' "$ENV_FILE" | cut -d= -f2-)" "$admin_pw"
    printf '    org       %s\n\n' "$(grep -E '^VEYRS_ADMIN_ORG=' "$ENV_FILE" | cut -d= -f2-)"
    warn "this is the only time the admin password is printed; it is in $ENV_FILE"
}

cmd_up() {
    require_env
    local profiles=() want_agent=0
    while [ "$#" -gt 0 ]; do
        case "$1" in
            --with-workers) profiles+=(--profile workers); shift ;;
            --with-agent)   profiles+=(--profile agent); want_agent=1; shift ;;
            --all)          profiles+=(--profile workers --profile agent); want_agent=1; shift ;;
            *) break ;;
        esac
    done

    # Fail here rather than in a restart loop.
    #
    # veyrs_agent.py is the authority and already refuses to start on an empty
    # allowlist -- this does not re-implement that decision, it just surfaces
    # it before `restart: unless-stopped` turns a one-line configuration
    # mistake into a container that dies every ten seconds with the reason
    # buried in `logs`.
    if [ "$want_agent" = "1" ] && ! grep -qE '^VEYRS_AGENT_ALLOW=..*' "$ENV_FILE"; then
        die "--with-agent needs VEYRS_AGENT_ALLOW in $ENV_FILE.

An empty allowlist means the agent may scan NOTHING, not everything -- it is
deny-by-default on purpose, so that the machine's own operator decides what it
may be pointed at, rather than whatever the server hands it.

  VEYRS_AGENT_ALLOW=example.com,*.internal.example,10.10.0.0/24
  VEYRS_AGENT_TOKEN=<mint one in the console: Settings -> Agents>"
    fi

    local src; src="$(image_source)"
    case "$src" in
        registry)
            info "pulling the published images ($(env_get VEYRS_IMAGE))"
            "${COMPOSE[@]}" "${profiles[@]+"${profiles[@]}"}" pull --quiet \
                || die "could not pull the images.
Either this version was never published, or this host cannot reach the registry.
  - offline host:     $0 load veyrs-images-<version>-amd64.tar.gz
  - modified tree:    set VEYRS_IMAGE_SOURCE=build in $ENV_FILE" ;;
        build)
            info "building images (context: $ROOT)"
            VEYRS_BUILD_VERSION="$(tree_version)"
            VEYRS_BUILD_REVISION="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)"
            export VEYRS_BUILD_VERSION VEYRS_BUILD_REVISION
            "${COMPOSE[@]}" "${profiles[@]+"${profiles[@]}"}" build "$@"
            # postgres and redis are never built; `up --pull never` below would
            # otherwise refuse them on a host that has not pulled them yet.
            "${COMPOSE[@]}" pull --quiet postgres redis ;;
        local)
            info "using the images already on this host (VEYRS_IMAGE_SOURCE=local)"
            # Checked here, all at once, by name. Otherwise `up --pull never`
            # stops at the first absent image with "No such image" and a digest,
            # which names neither the cause nor the remedy.
            local img missing=()
            while read -r img; do
                [[ -z "$img" ]] || docker image inspect "$img" >/dev/null 2>&1 || missing+=("$img")
            done < <("${COMPOSE[@]}" "${profiles[@]+"${profiles[@]}"}" config --images 2>/dev/null | sort -u)
            ((${#missing[@]} == 0)) || die "VEYRS_IMAGE_SOURCE=local, but these images are not on this host:
$(printf '    %s\n' "${missing[@]}")
Load the offline bundle ($0 load FILE), or set VEYRS_IMAGE_SOURCE=registry or build." ;;
    esac
    info "starting"
    # --no-build and --pull never: the images were settled above. Without them
    # compose falls back to BUILDING a missing image on its own, and a host
    # that was meant to run published images quietly compiles its own instead.
    "${COMPOSE[@]}" "${profiles[@]+"${profiles[@]}"}" up -d --no-build --pull never

    # A bounded poll, never a bare sleep: a sleep either wastes time or
    # reports success against a stack that never came up.
    local bind; bind=$(grep -E '^VEYRS_HTTP_BIND=' "$ENV_FILE" | cut -d= -f2-)
    info "waiting for http://${bind}/readyz"
    if timeout 180 bash -c "until curl -sfo /dev/null 'http://${bind}/readyz'; do sleep 2; done"; then
        info "ready -- console on http://${bind}"
        curl -s "http://${bind}/healthz" && echo
    else
        warn "the stack did not become ready in 180s"
        "${COMPOSE_ALL[@]}" ps
        # console too: when the wait fails because nginx is proxying to an
        # address nothing is listening on, the 502 and the stale upstream
        # address appear ONLY in its log -- `ps` shows everything healthy.
        "${COMPOSE_ALL[@]}" logs --tail 40 init api console
        return 1
    fi
}

cmd_backup() {
    require_env
    # With an EXTERNAL database there is no cluster in this stack and no
    # superuser credential on this host: the `postgres` service is only a
    # probe. A pg_dump as the application role is the truncated dump described
    # below, so refuse rather than produce one.
    if [[ $EXTERNAL_DB -eq 1 ]]; then
        die "this stack uses an EXTERNAL PostgreSQL (compose.external-db.yaml).
Back it up where it lives, as a role that bypasses row level security (its
superuser): an application-role pg_dump is refused by FORCE RLS or truncated."
    fi
    local out="${1:-veyrs-$(date -u +%Y%m%d-%H%M%S).dump}"
    # ======================================================================
    # AS THE SUPERUSER, NOT AS THE APPLICATION ROLE.
    #
    # 70 of the 87 tables carry FORCE ROW LEVEL SECURITY, and forcing it
    # applies to the TABLE OWNER TOO. The application role owns every table
    # and is still refused:
    #
    #   pg_dump: error: query failed: ERROR: query would be affected by
    #   row-level security policy for table "agent_job_events"
    #
    # -Fc writes as it goes, so what is left behind is a file that looks like
    # a backup. Measured on production, 2026-09-21: 392 KB where the good one
    # is 509 MB. Nothing about the filename, the exit path or the extension
    # says which one you have -- which is why this verifies by listing the
    # contents rather than by trusting the size.
    # ======================================================================
    info "dumping as the postgres superuser"
    "${COMPOSE[@]}" exec -T postgres \
        pg_dump -U postgres -d "$(grep -E '^VEYRS_DB_NAME=' "$ENV_FILE" | cut -d= -f2-)" -Fc \
        > "$out"

    local tables
    tables=$(pg_restore --list "$out" 2>/dev/null | grep -c 'TABLE DATA' || true)
    if [[ "${tables:-0}" -lt 50 ]]; then
        die "$out lists only ${tables} tables with data -- that is a TRUNCATED dump, not a backup.
Check that the dump ran as the superuser and not as the application role."
    fi
    info "$out — $(du -h "$out" | cut -f1), ${tables} tables with data"
}

# load FILE -- an offline bundle made by scripts/publish-images.sh: the api,
# console, postgres and redis images in one `docker save` archive, plus a
# FILE.sha256 next to it. The checksum is REQUIRED: on a host with no registry
# to compare against, it is the only thing that says these are the published
# images and not something else with the same name.
cmd_load() {
    local file="${1:-}"
    [[ -f "$file" ]] || die "usage: $0 load veyrs-images-<version>-amd64.tar.gz (with its .sha256 beside it)"
    [[ -f "$file.sha256" ]] || die "no $file.sha256 -- refusing to load an image bundle that cannot be verified"
    local want got
    want="$(awk '{print $1; exit}' "$file.sha256")"
    got="$(sha256sum "$file" | awk '{print $1}')"
    [[ -n "$want" && "$want" == "$got" ]] || die "$file does not match $file.sha256 (expected $want, got $got)"
    info "checksum ok ($got)"

    local out; out="$(docker load -i "$file")" || die "docker load failed"
    printf '%s\n' "$out"
    local api console pg redis ref
    while read -r ref; do
        case "$ref" in
            */veyrs:*)          api="$ref" ;;
            */veyrs-console:*)  console="$ref" ;;
            */veyrs-agent:*)    env_set VEYRS_AGENT_IMAGE "$ref" ;;
            postgres:*)         pg="$ref" ;;
            redis:*)            redis="$ref" ;;
        esac
    done < <(sed -n 's/^Loaded image: //p' <<<"$out")
    [[ -n "${api:-}" && -n "${console:-}" ]] || die "the bundle holds no veyrs and veyrs-console images"

    [[ -f "$ENV_FILE" ]] || die "loaded, but there is no $ENV_FILE yet -- run: $0 init, then load again"
    env_set VEYRS_IMAGE_SOURCE local
    env_set VEYRS_IMAGE "$api"
    env_set VEYRS_CONSOLE_IMAGE "$console"
    # By TAG, as loaded. A digest reference is not reliably matched by an
    # image that arrived through `docker save | docker load` (the classic image
    # store does not keep the registry digest), and `up --pull never` would then
    # refuse an image that is sitting right there. The bundle's checksum above
    # is what vouches for these.
    [[ -n "${pg:-}" ]]    && env_set VEYRS_POSTGRES_IMAGE "$pg"
    [[ -n "${redis:-}" ]] && env_set VEYRS_REDIS_IMAGE "$redis"
    info "VEYRS_IMAGE_SOURCE=local -- next: $0 up"
}

cmd_status() {
    require_env
    "${COMPOSE_ALL[@]}" ps
    echo
    printf 'Images (VEYRS_IMAGE_SOURCE=%s):\n' "$(image_source)"
    local img
    for img in "$(env_get VEYRS_IMAGE)" "$(env_get VEYRS_CONSOLE_IMAGE)"; do
        [[ -n "$img" ]] || continue
        printf '  %-52s %s\n' "$img" "$(docker image inspect -f \
            '{{index .Config.Labels "org.opencontainers.image.version"}} @ {{index .Config.Labels "org.opencontainers.image.revision"}}' \
            "$img" 2>/dev/null || echo 'not on this host')"
    done
    local bind; bind=$(grep -E '^VEYRS_HTTP_BIND=' "$ENV_FILE" | cut -d= -f2-)
    echo
    curl -s "http://${bind}/healthz" 2>/dev/null && echo || warn "no answer on http://${bind}"

    # ======================================================================
    # WHAT IS NOT RUNNING, SAID FROM THE MACHINE ITSELF.
    #
    # The three optional services are the difference between a node that is
    # merely smaller than production and a node that is quietly WRONG. A stack
    # without `intel` keeps scoring with full confidence against CVE, EPSS and
    # KEV data that stopped refreshing on the day it was installed, and its SLA
    # clocks stop advancing -- neither of which shows up anywhere in the
    # console. An operator should not have to remember which flags they passed
    # to `up` three weeks ago to find that out.
    #
    # Printed dynamically rather than as a fixed paragraph: a list that says
    # "not running" about something that IS running teaches people to ignore
    # the list.
    # ======================================================================
    local up; up=$("${COMPOSE_ALL[@]}" ps --services --filter status=running 2>/dev/null)
    echo
    echo "Background work (host equivalent -> this stack):"
    _report_worker "$up" intel  "veyrs-intel-sync.timer" "--with-workers" \
        "CVE/EPSS/KEV data does not refresh and SLA deadlines do not elapse;
     the platform keeps scoring confidently against intelligence that has
     stopped learning"
    _report_worker "$up" digest "veyrs-digest.timer"     "--with-workers" \
        "no daily digest mail goes out; the notification rows are still
     written, so nothing is lost -- nobody is told"
    _report_worker "$up" agent  "veyrs-agent.service"    "--with-agent" \
        "no scans run from this node; scan jobs queue and their leases are
     reaped"
}

_report_worker() {
    local running="$1" svc="$2" unit="$3" flag="$4" consequence="$5"
    if grep -qx "$svc" <<<"$running"; then
        printf '  \033[32m%-7s\033[0m running   (%s)\n' "$svc" "$unit"
    else
        printf '  \033[33m%-7s\033[0m NOT running (%s) -- enable with `up %s`\n' \
            "$svc" "$unit" "$flag"
        printf '     %s\n' "$consequence"
    fi
}

need_docker
case "${1:-}" in
    init)    shift; cmd_init "$@" ;;
    up)      shift; cmd_up "$@" ;;
    # down/restart/ps/logs use COMPOSE_ALL: without the profiles that started
    # them, compose neither stops nor lists the optional containers, and says
    # nothing about it. See the comment on COMPOSE_ALL.
    down)    shift; require_env; "${COMPOSE_ALL[@]}" down "$@" ;;
    restart) shift; require_env; "${COMPOSE_ALL[@]}" restart "$@" ;;
    ps)      shift; require_env; "${COMPOSE_ALL[@]}" ps "$@" ;;
    logs)    shift; require_env; "${COMPOSE_ALL[@]}" logs "$@" ;;
    build)   shift; require_env
             VEYRS_BUILD_VERSION="$(tree_version)" \
             VEYRS_BUILD_REVISION="$(git -C "$ROOT" rev-parse HEAD 2>/dev/null || echo unknown)" \
             "${COMPOSE_ALL[@]}" build "$@" ;;
    status)  shift; cmd_status "$@" ;;
    backup)  shift; cmd_backup "$@" ;;
    load)    shift; cmd_load "$@" ;;
    psql)    shift; require_env
             # As the APPLICATION role: an operator poking at the data should
             # see what the application sees, RLS included. `backup` is the
             # documented exception.
             # VEYRS_EXT_DB_* exist only in the external-database probe; unset,
             # this is the bundled cluster on loopback.
             "${COMPOSE[@]}" exec postgres sh -lc \
                 'PGPASSWORD=$VEYRS_DB_PASSWORD psql -h "${VEYRS_EXT_DB_HOST:-127.0.0.1}" -p "${VEYRS_EXT_DB_PORT:-5432}" -U "$VEYRS_DB_USER" -d "$VEYRS_DB_NAME"' ;;
    cli)     shift; require_env
             "${COMPOSE[@]}" run --rm --no-deps api python -m veyrs.cli "$@" ;;
    ""|-h|--help|help)
             # Reads the header comment to its end rather than a pinned line
             # range: `sed -n '2,30p'` silently started printing shell code the
             # first time a usage line was added above it.
             awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next }
                  NR>1 { exit }' "${BASH_SOURCE[0]}" ;;
    *)       die "unknown command: $1 (try: $0 --help)" ;;
esac
