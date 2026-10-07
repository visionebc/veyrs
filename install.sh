#!/usr/bin/env bash
#
# VEYRS — full installation script.
#
# Automates docs/../INSTALL.md end to end on a clean host: system packages,
# PostgreSQL role and UTF8 databases, Redis, the pinned Python dependency set,
# secrets, schema, the first administrator, the systemd unit, the nginx vhost
# and the console files.
#
# Supported families. An image marked (measured) was installed from a pristine
# snapshot and asserted end to end, twice — once clean and once re-run. The
# others share that family's package manager, unit names and paths but were
# NOT run, and the distinction is the point: "supported" and "tested" are not
# the same claim.
#
#   debian   apt-get   Debian 12 (measured) · Ubuntu 24.04 LTS (measured)
#                      Ubuntu 22.04 — same family, not run
#   suse     zypper    openSUSE Leap 15.6 (measured)
#                      SLES 15 SP6 — the same code base as Leap 15.6, not run:
#                      its repositories need a subscription
#   rhel     dnf       Rocky 9 (measured) · AlmaLinux 9 (measured)
#                      RHEL 9 — same family, not run
#
#   sudo ./install.sh                     # interactive, asks for what it cannot invent
#   sudo ./install.sh --unattended        # every answer comes from a flag or an env var
#   sudo ./install.sh --dry-run           # print the plan, change nothing
#
# Design rules this script follows, because each one is a failure mode that
# cost somebody hours:
#
#   * Idempotent. Re-running it on a working install changes nothing and
#     exits 0. Every create is guarded by an existence check.
#   * It never writes a secret it did not generate, and it never overwrites
#     an existing .env. An installer that silently rotates the Fernet key
#     makes every stored credential in the database undecryptable.
#   * It verifies UTF8 instead of assuming it. A SQL_ASCII cluster produces
#     databases that look fine for weeks.
#   * It waits on a health endpoint with a bounded poll, never on `sleep N`.
#     A bare sleep either wastes time or reports success on a dead service.
#   * It never widens the host's attack surface without being asked. The
#     firewall is only touched with --open-firewall.
#   * Nothing is derived from the distribution NAME when it can be measured
#     from the host instead. The nginx vhost directory is read out of
#     nginx.conf; the Python interpreter is chosen by asking candidates for
#     their version and then importing what pip actually needs.
#   * Failures are loud and name the step. `set -euo pipefail` plus a trap.
#
# Exit codes: 0 ok · 1 usage/precondition · 2 a step failed.

set -euo pipefail

# ---------------------------------------------------------------- defaults ---

VEYRS_DIR="${VEYRS_DIR:-/opt/veyrs}"
CONSOLE_DIR="${CONSOLE_DIR:-/var/www/veyrs-console}"
SERVICE_NAME="veyrs-api"

DB_HOST="${DB_HOST:-127.0.0.1}"
DB_PORT="${DB_PORT:-5432}"
DB_NAME="${DB_NAME:-veyrs}"
DB_TEST_NAME="${DB_TEST_NAME:-veyrs_test}"
DB_USER="${DB_USER:-veyrs}"
DB_PASSWORD="${DB_PASSWORD:-}"          # generated when empty

REDIS_HOST="${REDIS_HOST:-127.0.0.1}"
REDIS_PORT="${REDIS_PORT:-6379}"
REDIS_PASSWORD="${REDIS_PASSWORD:-}"    # generated when empty and Redis is local

SERVER_NAME="${SERVER_NAME:-}"          # nginx server_name, e.g. veyrs.example.com
PUBLIC_BASE_URL="${PUBLIC_BASE_URL:-}"  # e.g. https://veyrs.example.com
ENVIRONMENT="${ENVIRONMENT:-production}"

ORG_SLUG="${ORG_SLUG:-}"
ORG_NAME="${ORG_NAME:-}"
ADMIN_EMAIL="${ADMIN_EMAIL:-}"
ADMIN_PASSWORD="${ADMIN_PASSWORD:-}"    # env is preferred; the flag lands in ps(1)

API_BIND="127.0.0.1"
API_PORT="8000"

DISTRO_FAMILY="${DISTRO_FAMILY:-}"      # debian|suse|rhel — autodetected when empty
PG_MAJOR="${PG_MAJOR:-16}"              # only used where the major is selectable
PY_BIN="${PY_BIN:-}"                    # resolved in step 1b

SKIP_SYSTEM_PACKAGES=0
SKIP_POSTGRES=0
SKIP_REDIS=0
SKIP_NGINX=0
SKIP_BOOTSTRAP=0
FORCE_BOOTSTRAP=0
OPEN_FIREWALL=0
UNATTENDED=0
DRY_RUN=0

MIN_PY_MAJOR=3
MIN_PY_MINOR=11
MIN_PG_MAJOR=15

# ----------------------------------------------------------------- output ---

if [[ -t 1 ]]; then
    C_RESET=$'\033[0m'; C_BOLD=$'\033[1m'; C_RED=$'\033[31m'
    C_GREEN=$'\033[32m'; C_YELLOW=$'\033[33m'; C_BLUE=$'\033[34m'
else
    C_RESET=; C_BOLD=; C_RED=; C_GREEN=; C_YELLOW=; C_BLUE=
fi

STEP=""
step()  { STEP="$1"; printf '\n%s==> %s%s\n' "$C_BOLD$C_BLUE" "$1" "$C_RESET"; }
info()  { printf '    %s\n' "$*"; }
ok()    { printf '    %s✓%s %s\n' "$C_GREEN" "$C_RESET" "$*"; }
warn()  { printf '    %s!%s %s\n' "$C_YELLOW" "$C_RESET" "$*"; }
die()   { printf '\n%sinstall failed%s during: %s\n    %s\n' \
                 "$C_BOLD$C_RED" "$C_RESET" "${STEP:-startup}" "$*" >&2; exit 2; }
usage_die() { printf '%s\n' "$*" >&2; printf 'Run with --help for options.\n' >&2; exit 1; }

trap 'rc=$?; [[ $rc -ne 0 && $rc -ne 1 && $rc -ne 2 ]] && \
      printf "\n%sinstall aborted%s (exit %d) during: %s\n" \
             "$C_BOLD$C_RED" "$C_RESET" "$rc" "${STEP:-startup}" >&2; exit $rc' ERR

run() {
    if [[ $DRY_RUN -eq 1 ]]; then printf '    [dry-run] %s\n' "$*"; return 0; fi
    "$@"
}

# ------------------------------------------------------------------- usage ---

show_usage() {
    cat <<'USAGE'
VEYRS installer

Usage: sudo ./install.sh [options]

Location
  --dir PATH                 install root (default /opt/veyrs, must be this repo)
  --console-dir PATH         nginx document root (default /var/www/veyrs-console)

Identity — asked interactively when omitted
  --server-name NAME         nginx server_name, e.g. veyrs.example.com
  --public-url URL           VEYRS_PUBLIC_BASE_URL; must be https:// in production
  --org SLUG                 first organization slug
  --org-name "NAME"          first organization display name
  --admin-email EMAIL        first administrator (prompts for the password)
  --admin-password PASS      required by --unattended unless --skip-bootstrap.
                             Prefer the ADMIN_PASSWORD environment variable:
                             a flag is visible in ps(1) to every local account.

Database / cache
  --db-host HOST             default 127.0.0.1
  --db-port PORT             default 5432
  --db-name NAME             default veyrs
  --db-user USER             default veyrs
  --db-password PASS         default: generated
  --redis-host HOST          default 127.0.0.1
  --redis-port PORT          default 6379
  --redis-password PASS      default: generated when Redis is local

Platform — autodetected; override only when detection is wrong
  --distro-family FAM        debian | suse | rhel
  --pg-major N               PostgreSQL major to install where selectable
                             (default 16; ignored on Debian, which ships one)
  --python PATH              interpreter to build the virtualenv with

Skips — for split deployments and re-runs
  --skip-system-packages     packages are managed elsewhere
  --skip-postgres            the database lives on another host
  --skip-redis               Redis lives on another host
  --skip-nginx               a different front end serves the console
  --skip-bootstrap           an organization already exists
  --force-bootstrap          run the bootstrap even when the administrator
                             already exists. This RESETS that account's
                             password; without it, a re-run leaves it alone.

Modes
  --environment ENV          production (default) | development
  --open-firewall            open HTTP in firewalld/ufw (off: the installer
                             never widens the attack surface unasked)
  --unattended               never prompt; missing required answers are an error
  --dry-run                  print what would run, change nothing
  -h, --help                 this text

Every option also reads an environment variable of the same name in upper
snake case (DB_PASSWORD, SERVER_NAME, ADMIN_EMAIL, PG_MAJOR, ...).
USAGE
}

while [[ $# -gt 0 ]]; do
    case "$1" in
        --dir)                VEYRS_DIR="${2:?--dir needs a path}"; shift 2 ;;
        --console-dir)        CONSOLE_DIR="${2:?}"; shift 2 ;;
        --server-name)        SERVER_NAME="${2:?}"; shift 2 ;;
        --public-url)         PUBLIC_BASE_URL="${2:?}"; shift 2 ;;
        --org)                ORG_SLUG="${2:?}"; shift 2 ;;
        --org-name)           ORG_NAME="${2:?}"; shift 2 ;;
        --admin-email)        ADMIN_EMAIL="${2:?}"; shift 2 ;;
        --admin-password)     ADMIN_PASSWORD="${2:?}"; ADMIN_PW_FROM_ARGV=1; shift 2 ;;
        --db-host)            DB_HOST="${2:?}"; shift 2 ;;
        --db-port)            DB_PORT="${2:?}"; shift 2 ;;
        --db-name)            DB_NAME="${2:?}"; shift 2 ;;
        --db-user)            DB_USER="${2:?}"; shift 2 ;;
        --db-password)        DB_PASSWORD="${2:?}"; shift 2 ;;
        --redis-host)         REDIS_HOST="${2:?}"; shift 2 ;;
        --redis-port)         REDIS_PORT="${2:?}"; shift 2 ;;
        --redis-password)     REDIS_PASSWORD="${2:?}"; shift 2 ;;
        --distro-family)      DISTRO_FAMILY="${2:?}"; shift 2 ;;
        --pg-major)           PG_MAJOR="${2:?}"; shift 2 ;;
        --python)             PY_BIN="${2:?}"; shift 2 ;;
        --environment)        ENVIRONMENT="${2:?}"; shift 2 ;;
        --skip-system-packages) SKIP_SYSTEM_PACKAGES=1; shift ;;
        --skip-postgres)      SKIP_POSTGRES=1; shift ;;
        --skip-redis)         SKIP_REDIS=1; shift ;;
        --skip-nginx)         SKIP_NGINX=1; shift ;;
        --skip-bootstrap)     SKIP_BOOTSTRAP=1; shift ;;
        --force-bootstrap)    FORCE_BOOTSTRAP=1; shift ;;
        --open-firewall)      OPEN_FIREWALL=1; shift ;;
        --unattended)         UNATTENDED=1; shift ;;
        --dry-run)            DRY_RUN=1; shift ;;
        -h|--help)            show_usage; exit 0 ;;
        *)                    usage_die "unknown option: $1" ;;
    esac
done

# --------------------------------------------------------------- helpers ----

have() { command -v "$1" >/dev/null 2>&1; }

gen_secret() {   # url-safe, no shell metacharacters, safe inside a URL
    # A dry run on a host that has not been installed yet has no interpreter
    # to generate with — on SUSE there is no /usr/bin/python3 at all. Returning
    # a placeholder keeps --dry-run usable where it is actually needed: before
    # the first install. Nothing consumes this value when DRY_RUN=1.
    if [[ $DRY_RUN -eq 1 ]] && ! have "${PY_BIN:-python3}"; then
        printf '<a generated %s-byte secret>\n' "$1"; return 0
    fi
    "${PY_BIN:-python3}" - "$1" <<'PY'
import secrets, sys
print(secrets.token_urlsafe(int(sys.argv[1])))
PY
}

ask() {          # ask VAR "prompt" "default"
    local __var="$1" __prompt="$2" __default="${3:-}" __reply=""
    if [[ -n "${!__var}" ]]; then return 0; fi
    if [[ $UNATTENDED -eq 1 ]]; then
        [[ -n "$__default" ]] && { printf -v "$__var" '%s' "$__default"; return 0; }
        die "--unattended and no value for ${__var}. Pass it as a flag or an env var."
    fi
    if [[ -n "$__default" ]]; then
        read -r -p "    ${__prompt} [${__default}]: " __reply || true
        printf -v "$__var" '%s' "${__reply:-$__default}"
    else
        while [[ -z "$__reply" ]]; do
            read -r -p "    ${__prompt}: " __reply || die "no input for ${__var}"
        done
        printf -v "$__var" '%s' "$__reply"
    fi
}

# Bounded wait. Never `sleep N` and hope: a bare sleep either wastes time or
# reports success on a service that never came up.
wait_for() {     # wait_for <seconds> <description> <command...>
    local timeout="$1" what="$2"; shift 2
    local deadline=$(( SECONDS + timeout ))
    while (( SECONDS < deadline )); do
        if "$@" >/dev/null 2>&1; then ok "$what is up"; return 0; fi
        sleep 1
    done
    return 1
}

psql_super() { su - postgres -c "psql -tAc \"$1\""; }

# Does the first administrator already exist? Queried as the SUPERUSER on
# purpose: users and organizations are RLS-FORCEd, so the application role
# sees zero rows until a tenant is bound — and a false "no such user" here
# would permit exactly the password reset this check exists to prevent.
# Returns 1 (unknown, assume absent) when the database is not local.
bootstrap_admin_exists() {
    [[ $SKIP_POSTGRES -eq 0 ]] || return 1
    local n
    n="$(su - postgres -c "psql -d '${DB_NAME}' -tAc \"select count(*) from users u join organizations o on o.id = u.organization_id where o.slug = '${ORG_SLUG}' and u.email = lower('${ADMIN_EMAIL}')\"" 2>/dev/null | tr -d '[:space:]')"
    [[ "$n" == "1" ]]
}

nginx_probe_200() {
    [[ "$(curl -so /dev/null -w '%{http_code}' -H "Host: ${SERVER_NAME:-localhost}" \
          "http://127.0.0.1/healthz" 2>/dev/null || true)" == "200" ]]
}

pg_can_login() {
    PGPASSWORD="$DB_PASSWORD" psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" \
        -d "$DB_NAME" -tAc 'select 1' >/dev/null 2>&1
}

# Debian permits password authentication over loopback out of the box. SUSE
# and RHEL ship `ident` for 127.0.0.1, which refuses a password login for a
# role with no matching system user — so the install dies at init-db with
#     FATAL: Ident authentication failed for user "veyrs"
# AFTER the role and both databases already exist, which reads like a VEYRS
# bug and is not one. Measured on Leap 15.6: `host all all 127.0.0.1/32 ident`.
pg_ensure_password_auth() {
    local hba tmp
    # Measure before changing. On Debian this returns immediately and the
    # host's pg_hba.conf is never touched.
    if pg_can_login; then
        ok "password authentication over ${DB_HOST} already works"
        return 0
    fi

    hba="$(psql_super 'show hba_file' | tr -d '[:space:]')"
    [[ -n "$hba" && -f "$hba" ]] \
        || die "the server rejected a password login and its hba_file ('${hba:-unset}') is not readable.
    Allow the role by hand, then re-run:
      host  ${DB_NAME},${DB_TEST_NAME}  ${DB_USER}  127.0.0.1/32  scram-sha-256"

    if grep -q 'BEGIN VEYRS' "$hba"; then
        warn "$hba already carries the VEYRS block, yet the login still fails"
    else
        info "adding a scram-sha-256 rule for ${DB_USER} to $(basename "$hba")"
        tmp="$(mktemp)"
        {
            cat <<HBAEOF
# BEGIN VEYRS (managed by install.sh) — do not edit between these markers.
# pg_hba.conf is first-match-wins, so this must precede the distribution's
# generic ident/peer lines. Scoped to one role and its two databases rather
# than relaxing authentication for "all" — this file is a firewall.
host    ${DB_NAME},${DB_TEST_NAME}    ${DB_USER}    127.0.0.1/32    scram-sha-256
host    ${DB_NAME},${DB_TEST_NAME}    ${DB_USER}    ::1/128         scram-sha-256
# END VEYRS
HBAEOF
            cat "$hba"
        } > "$tmp"
        # Keep the file's own owner and mode; do not assume postgres:postgres 600.
        chown --reference="$hba" "$tmp" && chmod --reference="$hba" "$tmp" \
            || die "could not match the ownership/mode of $hba"
        mv -f "$tmp" "$hba" || die "could not write $hba"
        systemctl reload "$SVC_PG" 2>/dev/null || systemctl restart "$SVC_PG" \
            || die "PostgreSQL would not reload after editing $hba"
    fi

    wait_for 20 "password authentication for ${DB_USER}" pg_can_login \
        || die "role ${DB_USER} still cannot log in with a password over ${DB_HOST}:${DB_PORT}.
    Read the rules:  grep -v '^#' ${hba}
    The role exists and its password is stored with $(psql_super 'show password_encryption' | tr -d '[:space:]').
    If this host authenticates through LDAP/GSSAPI, install with an explicit
    --db-host that reaches PostgreSQL over a path that accepts a password."
}

# ==================================================== platform detection =====
#
# The family decides package names, service names and config paths. Everything
# that can be measured on the host instead of inferred from the family IS
# measured — see nginx_resolve_site() and resolve_python().

detect_family() {
    [[ -n "$DISTRO_FAMILY" ]] && return 0
    [[ -r /etc/os-release ]] || die "no /etc/os-release. Pass --distro-family debian|suse|rhel."
    local id id_like
    id="$(. /etc/os-release; printf '%s' "${ID:-}")"
    id_like="$(. /etc/os-release; printf '%s' "${ID_LIKE:-}")"
    case " $id $id_like " in
        *debian*|*ubuntu*)                 DISTRO_FAMILY=debian ;;
        *suse*|*sles*|*opensuse*)          DISTRO_FAMILY=suse ;;
        *rhel*|*fedora*|*centos*)          DISTRO_FAMILY=rhel ;;
        *)
            die "unsupported distribution: ID=${id} ID_LIKE=${id_like}
    Supported: debian (apt) · suse (zypper) · rhel (dnf).
    If this host is a derivative of one of them, force it:
      sudo ./install.sh --distro-family suse
    Otherwise install the packages yourself and re-run with
      --skip-system-packages" ;;
    esac
}

# Package names, service names and config paths per family. A single table,
# so a fifth family is one block and not a grep across the whole script.
platform_tables() {
    case "$DISTRO_FAMILY" in
    debian)
        PKG_MGR=apt-get
        PKGS_BASE=(python3 python3-venv python3-pip git ca-certificates)
        PKGS_NGINX=(nginx)
        # Debian ships exactly one PostgreSQL major per release; PG_MAJOR is
        # not selectable here and pretending otherwise would install nothing.
        PKGS_PG=(postgresql postgresql-client)
        PKGS_REDIS=(redis-server)
        PY_CANDIDATES=(python3.13 python3.12 python3.11 python3)
        SVC_PG=postgresql
        SVC_REDIS=redis-server
        REDIS_CONF=/etc/redis/redis.conf
        REDIS_CONF_SEED=""
        PG_NEEDS_INITDB=0
        BUILD_DEPS_HINT="apt-get install -y build-essential python3-dev libpq-dev libffi-dev libxml2-dev libxslt1-dev"
        ;;
    suse)
        PKG_MGR=zypper
        # libexpat1 is NOT decoration. On a stock Leap 15.6 / SLES 15 SP6
        # image the python311 from the update channel ships a pyexpat built
        # against a newer libexpat than the base image carries, and the
        # interpreter then dies inside ensurepip with
        #   undefined symbol: XML_SetAllocTrackerActivationThreshold
        # so `python3 -m venv` produces a virtualenv with no pip at all.
        # Naming it here makes zypper resolve the pair together.
        PKGS_BASE=(python311 python311-pip libexpat1 git-core ca-certificates)
        PKGS_NGINX=(nginx)
        PKGS_PG=("postgresql${PG_MAJOR}-server" "postgresql${PG_MAJOR}")
        PKGS_REDIS=(redis)
        # There is no /usr/bin/python3 on SUSE even after installing python311.
        PY_CANDIDATES=(python3.13 python3.12 python3.11)
        SVC_PG=postgresql
        # No redis.service on SUSE — only the redis@.service template plus a
        # redis.target. The instance name IS the config file's basename.
        SVC_REDIS=redis@default
        REDIS_CONF=/etc/redis/default.conf
        REDIS_CONF_SEED=/etc/redis/default.conf.example
        PG_NEEDS_INITDB=0
        BUILD_DEPS_HINT="zypper install -y gcc python311-devel postgresql${PG_MAJOR}-devel libffi-devel libxml2-devel libxslt-devel"
        ;;
    rhel)
        PKG_MGR=dnf; have dnf || PKG_MGR=yum
        PKGS_BASE=(python3.11 python3.11-pip git ca-certificates)
        PKGS_NGINX=(nginx)
        PKGS_PG=(postgresql-server postgresql)
        PKGS_REDIS=(redis)
        PY_CANDIDATES=(python3.12 python3.11 python3)
        SVC_PG=postgresql
        SVC_REDIS=redis
        REDIS_CONF=/etc/redis/redis.conf
        REDIS_CONF_SEED=""
        # RHEL does not initialise the cluster on first start the way Debian
        # and SUSE do; postgresql.service fails until postgresql-setup ran.
        PG_NEEDS_INITDB=1
        BUILD_DEPS_HINT="dnf install -y gcc python3.11-devel libpq-devel libffi-devel libxml2-devel libxslt-devel"
        ;;
    *)  die "unknown --distro-family '$DISTRO_FAMILY' (expected debian, suse or rhel)" ;;
    esac

    # The installer needs the curl BINARY, not the curl package. RHEL minimal
    # images ship curl-minimal, which provides /usr/bin/curl and CONFLICTS
    # with the curl package: `dnf install curl` then fails outright, taking
    # the whole package step down on a host that already has a working curl.
    have curl || PKGS_BASE+=(curl)
}

pkg_refresh() {
    case "$PKG_MGR" in
        apt-get) run env DEBIAN_FRONTEND=noninteractive apt-get update -qq ;;
        zypper)  run zypper --non-interactive --gpg-auto-import-keys refresh ;;
        dnf|yum) run "$PKG_MGR" -y makecache ;;
    esac
}

pkg_install() {  # pkg_install pkg...
    [[ $# -eq 0 ]] && return 0
    case "$PKG_MGR" in
        apt-get) run env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" ;;
        zypper)  run zypper --non-interactive --gpg-auto-import-keys install -y "$@" ;;
        dnf|yum) run "$PKG_MGR" -y install "$@" ;;
    esac
}

# RHEL 9 base repositories carry PostgreSQL 13, which is below the minimum.
# The usable major lives behind a module stream. Best-effort: if modules are
# not a thing on this host the plain install runs and the version gate in
# step 2 reports the truth instead of this function guessing.
rhel_enable_pg_module() {
    [[ "$DISTRO_FAMILY" == "rhel" ]] || return 0
    have dnf || return 0
    dnf -y module list postgresql >/dev/null 2>&1 || { info "no postgresql module stream on this host"; return 0; }
    if dnf module list --enabled postgresql 2>/dev/null | grep -q "\[e\]"; then
        ok "a postgresql module stream is already enabled"
        return 0
    fi
    info "enabling module stream postgresql:${PG_MAJOR}"
    run dnf -y module reset postgresql >/dev/null 2>&1 || true
    if ! run dnf -y module enable "postgresql:${PG_MAJOR}" >/dev/null 2>&1; then
        warn "could not enable postgresql:${PG_MAJOR} — falling back to the base repo.
      If step 2 then reports a PostgreSQL older than ${MIN_PG_MAJOR}, add PGDG:
        dnf install -y https://download.postgresql.org/pub/repos/yum/reporpms/EL-9-x86_64/pgdg-redhat-repo-latest.noarch.rpm"
    fi
}

# SELinux turns a working nginx config into a 502 with nothing in the nginx
# error log that names the cause. Enforcing hosts need the boolean, and the
# console files need a context nginx is allowed to read.
selinux_allow_proxy() {
    have getenforce || return 0
    [[ "$(getenforce 2>/dev/null)" == "Enforcing" ]] || return 0
    info "SELinux is Enforcing"
    if have setsebool; then
        run setsebool -P httpd_can_network_connect 1 \
            || warn "setsebool httpd_can_network_connect failed — nginx will 502 on /api/"
        ok "httpd_can_network_connect on (nginx may reach ${API_BIND}:${API_PORT})"
    fi
    have restorecon && run restorecon -R "$CONSOLE_DIR" >/dev/null 2>&1 || true
}

firewall_note() {
    local fw=""
    have firewall-cmd && systemctl is-active --quiet firewalld 2>/dev/null && fw=firewalld
    [[ -z "$fw" ]] && have ufw && ufw status 2>/dev/null | grep -q "^Status: active" && fw=ufw
    [[ -z "$fw" ]] && return 0
    if [[ $OPEN_FIREWALL -eq 0 ]]; then
        warn "${fw} is active and HTTP was NOT opened. The installer does not widen
      the attack surface unasked. Re-run with --open-firewall, or open it yourself."
        return 0
    fi
    case "$fw" in
        firewalld) run firewall-cmd --permanent --add-service=http >/dev/null \
                   && run firewall-cmd --reload >/dev/null && ok "firewalld: http opened" ;;
        ufw)       run ufw allow http >/dev/null && ok "ufw: http opened" ;;
    esac
}

# Choose the interpreter by ASKING candidates, not by trusting a name. Then
# import what the install actually needs: a python3.11 that cannot import
# xml.parsers.expat looks perfectly healthy until pip runs.
PY_STDLIB_PROBE='import xml.parsers.expat, ssl, ctypes, sqlite3, venv, ensurepip, zlib, hashlib, lzma'

py_ok() {        # py_ok <path> — version high enough AND stdlib usable
    local p="$1"
    "$p" -c "import sys; sys.exit(0 if sys.version_info[:2] >= ($MIN_PY_MAJOR,$MIN_PY_MINOR) else 1)" \
        >/dev/null 2>&1 || return 1
    "$p" -c "$PY_STDLIB_PROBE" >/dev/null 2>&1 || return 2
}

resolve_python() {
    local cand path rc broken=""
    if [[ -n "$PY_BIN" ]]; then
        have "$PY_BIN" || die "--python '$PY_BIN' is not executable"
        py_ok "$PY_BIN"; rc=$?
        [[ $rc -eq 0 ]] || die "--python '$PY_BIN' is unusable (code $rc): needs >= ${MIN_PY_MAJOR}.${MIN_PY_MINOR} and a working stdlib."
        return 0
    fi
    for cand in "${PY_CANDIDATES[@]}"; do
        path="$(command -v "$cand" 2>/dev/null || true)"
        [[ -n "$path" ]] || continue
        # Capture py_ok's own status. `$?` read after an `if` compound is the
        # status of the `if`, not of its condition — it is always 0 there, so
        # the "stdlib is broken" case would never be reported.
        rc=0; py_ok "$path" || rc=$?
        if [[ $rc -eq 0 ]]; then PY_BIN="$path"; return 0; fi
        if [[ $rc -eq 2 ]]; then broken="${broken}${broken:+, }${path}"; fi
    done

    # Name the distinction. "No Python" and "a Python whose stdlib is broken"
    # send the operator to two different places, and the second one is the
    # case that actually happens on a stock SUSE image.
    if [[ -n "$broken" ]]; then
        die "found Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ at: ${broken}
    but its standard library is incomplete, so building a virtualenv would
    produce one with no pip. Reproduce it:
      ${broken%%,*} -c '${PY_STDLIB_PROBE}'
    On SUSE this is almost always libexpat: the interpreter from the update
    channel needs a newer libexpat than a stock image carries.
      zypper install -y libexpat1
    On Debian/Ubuntu install the venv module:  apt-get install -y python3-venv"
    fi
    die "no Python ${MIN_PY_MAJOR}.${MIN_PY_MINOR}+ found (tried: ${PY_CANDIDATES[*]}).
    Step 1 was skipped or the package is named differently on this host.
    Install it and pass it explicitly:  --python /usr/bin/python3.11"
}

# Is an interpreter ALREADY usable on this host, right now? Only a dry run
# asks this. It differs from resolve_python() in that it answers instead of
# refusing, and it asks about usability rather than presence -- the two are
# not the same question on a pristine Debian or Ubuntu, where python3 is new
# enough and still cannot build a virtualenv because python3-venv has not
# been installed yet.
dryrun_python_usable() {
    local cand path
    if [[ -n "$PY_BIN" ]]; then
        have "$PY_BIN" && py_ok "$PY_BIN"
        return $?
    fi
    for cand in "${PY_CANDIDATES[@]}"; do
        path="$(command -v "$cand" 2>/dev/null || true)"
        [[ -n "$path" ]] || continue
        py_ok "$path" && return 0
    done
    return 1
}

# Read the vhost directory out of nginx.conf. Debian's layout and the
# conf.d/vhosts.d layout are not distinguishable from the distro name alone:
# Debian nginx includes BOTH sites-enabled and conf.d, and a file dropped in
# a directory nginx does not include is a config that silently does nothing.
nginx_resolve_site() {
    local conf=/etc/nginx/nginx.conf inc
    if [[ ! -r "$conf" ]] && [[ $DRY_RUN -eq 1 ]]; then
        # The layout is a property of the installed nginx, so on a host where
        # step 1 has not run there is nothing to read. Saying so beats naming
        # a directory this run cannot actually confirm.
        NGINX_STYLE="read from nginx.conf at install time"
        NGINX_SITE="(not decided in a dry run)"
        NGINX_LINK=""
        warn "$conf does not exist yet — the vhost directory is chosen from it"
        return 0
    fi
    [[ -r "$conf" ]] || die "nginx is installed but $conf is unreadable"
    inc="$(grep -E '^[[:space:]]*include' "$conf" || true)"

    if [[ "$inc" == *sites-enabled* ]] && [[ -d /etc/nginx/sites-available ]]; then
        NGINX_STYLE=symlink
        NGINX_SITE=/etc/nginx/sites-available/veyrs
        NGINX_LINK=/etc/nginx/sites-enabled/veyrs
    elif [[ "$inc" == *vhosts.d* ]] && [[ -d /etc/nginx/vhosts.d ]]; then
        NGINX_STYLE=direct
        NGINX_SITE=/etc/nginx/vhosts.d/veyrs.conf
        NGINX_LINK=""
    elif [[ "$inc" == *conf.d* ]] && [[ -d /etc/nginx/conf.d ]]; then
        NGINX_STYLE=direct
        NGINX_SITE=/etc/nginx/conf.d/veyrs.conf
        NGINX_LINK=""
    else
        die "nginx.conf includes no directory this installer can drop a vhost into.
    Looked for sites-enabled/, vhosts.d/ and conf.d/ in the include lines of
    $conf. Add one, or re-run with --skip-nginx and serve
    ${VEYRS_DIR}/frontend/console/ yourself."
    fi
}

# ============================================================== preflight ====

step "Preflight"

[[ $DRY_RUN -eq 1 ]] && warn "dry-run: nothing will be changed"

if [[ $EUID -ne 0 && $DRY_RUN -eq 0 ]]; then
    die "run as root (sudo ./install.sh). It installs packages and systemd units."
fi

[[ -f "$VEYRS_DIR/requirements.txt" && -d "$VEYRS_DIR/backend/veyrs" ]] \
    || die "$VEYRS_DIR is not a VEYRS checkout (no requirements.txt + backend/veyrs).
    Clone first:  git clone <repo> $VEYRS_DIR && cd $VEYRS_DIR && sudo ./install.sh"
ok "repository at $VEYRS_DIR"

if [[ -r /etc/os-release ]]; then
    info "host: $(. /etc/os-release; printf '%s' "${PRETTY_NAME:-unknown}")"
fi
detect_family
platform_tables
have "$PKG_MGR" || [[ $SKIP_SYSTEM_PACKAGES -eq 1 ]] \
    || die "family '${DISTRO_FAMILY}' was detected but '${PKG_MGR}' is not on PATH.
    Either the detection is wrong (--distro-family) or packages are managed
    elsewhere (--skip-system-packages)."
ok "family: ${DISTRO_FAMILY} · packages: ${PKG_MGR} · redis unit: ${SVC_REDIS}"

# The Python check deliberately does NOT run here. On SUSE there is no
# /usr/bin/python3 at all on a pristine image, so a preflight gate on it
# aborts the installer before the step that would install it. It runs in
# step 1b, after packages.

case "$ENVIRONMENT" in
    production|development) ok "environment: $ENVIRONMENT" ;;
    *) die "--environment must be production or development, got '$ENVIRONMENT'" ;;
esac

# Fail fast, here, rather than at step 6. veyrs.cli bootstrap reads the
# administrator password with getpass(), which needs a terminal: --unattended
# with no password is not an unattended install, it is a five-minute install
# that stops at the very last prompt with the database already created.
if [[ $UNATTENDED -eq 1 && $SKIP_BOOTSTRAP -eq 0 && $DRY_RUN -eq 0 && -z "$ADMIN_PASSWORD" ]]; then
    die "--unattended cannot create the first administrator without a password.
    Pass it in the environment (preferred, not visible in ps):
      ADMIN_PASSWORD='...' sudo -E ./install.sh --unattended ...
    or skip that step and run the bootstrap by hand afterwards:
      --skip-bootstrap"
fi
[[ ${ADMIN_PW_FROM_ARGV:-0} -eq 1 ]] && \
    warn "--admin-password is visible in ps(1) to every local account; prefer ADMIN_PASSWORD"

# ========================================================= 1. packages =======

step "1. System packages"

if [[ $SKIP_SYSTEM_PACKAGES -eq 1 ]]; then
    info "skipped (--skip-system-packages)"
else
    PKGS=("${PKGS_BASE[@]}")
    [[ $SKIP_NGINX    -eq 0 ]] && PKGS+=("${PKGS_NGINX[@]}")
    [[ $SKIP_REDIS    -eq 0 ]] && PKGS+=("${PKGS_REDIS[@]}")
    if [[ $SKIP_POSTGRES -eq 0 ]]; then
        rhel_enable_pg_module
        PKGS+=("${PKGS_PG[@]}")
    fi

    info "${PKG_MGR} install: ${PKGS[*]}"
    pkg_refresh || die "${PKG_MGR} refresh/update failed — is this host online and are its repositories configured?"
    pkg_install "${PKGS[@]}" || die "${PKG_MGR} install failed. Re-read the output above: the usual
    causes are an unregistered SLES host (no repositories), a missing
    AppStream/CRB repository on RHEL, or a package named differently on this
    release. You can install them by hand and re-run with --skip-system-packages."
    ok "packages installed"
fi

# No compiler is installed on purpose. On x86-64 / CPython 3.11 every pinned
# dependency ships a manylinux wheel, including psycopg[binary], cryptography
# and argon2-cffi-bindings. The fallback is detected in step 4 and named
# there, rather than pre-installing a toolchain nobody needs.

# ==================================================== 1b. python runtime =====

step "1b. Python interpreter"

# In a dry run, step 1 above only PRINTED its install command, so the only
# interpreter this probe can see is the one the host had BEFORE the plan ran.
# The guard therefore keys on USABLE, not on present. Keying on presence is
# what shipped, and it made --dry-run exit 2 on a pristine Debian or Ubuntu --
# exactly the host it exists to be run on -- because those images carry a
# python3 that is new enough and still has no venv module until step 1
# installs python3-venv. It passed on SUSE only by accident: there is no
# /usr/bin/python3 there at all, so the presence test happened to be right for
# the wrong reason. Same reasoning as nginx_resolve_site() and the psql branch
# in step 2: on a host where step 1 has not run, say so instead of refusing.
#
# --skip-system-packages means there is no step 1 to fix it, so the refusal
# stands: that host IS the final host.
if [[ $DRY_RUN -eq 1 && $SKIP_SYSTEM_PACKAGES -eq 0 ]] && ! dryrun_python_usable; then
    PY_BIN="python3"
    info "[dry-run] no usable interpreter yet — step 1 installs ${PKGS_BASE[*]}"
else
    resolve_python
    PY_VER="$("$PY_BIN" -c 'import sys; print("%d.%d.%d"%sys.version_info[:3])')"
    ok "$PY_BIN — Python $PY_VER (stdlib probe passed)"
fi

# ========================================================= 2. database =======

step "2. PostgreSQL role and databases"

if [[ $SKIP_POSTGRES -eq 1 ]]; then
    info "skipped (--skip-postgres) — expecting $DB_NAME on $DB_HOST:$DB_PORT"
    [[ -n "$DB_PASSWORD" ]] || ask DB_PASSWORD "password for role ${DB_USER} on ${DB_HOST}"
else
    # In a dry run the binary legitimately does not exist yet: step 1 is what
    # would have installed it. Dying here made --dry-run succeed only on a
    # host that was already installed.
    if ! have psql; then
        if [[ $DRY_RUN -eq 1 ]]; then
            warn "psql is not installed yet — step 1 would have installed ${PKGS_PG[*]}"
        else
            die "psql not found and --skip-postgres was not given"
        fi
    fi

    if [[ $DRY_RUN -eq 0 ]]; then
        # Debian and SUSE initialise the cluster on first start. RHEL does
        # not: postgresql.service exits non-zero until this has run once.
        if [[ $PG_NEEDS_INITDB -eq 1 ]] && [[ ! -s /var/lib/pgsql/data/PG_VERSION ]]; then
            have postgresql-setup \
                || die "this family needs an explicit initdb but postgresql-setup is missing"
            run postgresql-setup --initdb \
                || die "postgresql-setup --initdb failed"
            ok "cluster initialised (/var/lib/pgsql/data)"
        fi

        systemctl is-active --quiet "$SVC_PG" || run systemctl enable --now "$SVC_PG" \
            || die "could not start ${SVC_PG}. Check: systemctl status ${SVC_PG}"
        wait_for 45 "PostgreSQL" su - postgres -c 'psql -tAc "select 1"' \
            || die "PostgreSQL did not accept connections within 45s.
    Check: systemctl status ${SVC_PG}; journalctl -u ${SVC_PG} -n 30"

        PG_VER="$(psql_super 'show server_version' | cut -d. -f1)"
        [[ "${PG_VER:-0}" -ge $MIN_PG_MAJOR ]] \
            || die "PostgreSQL $PG_VER is too old. VEYRS needs >= $MIN_PG_MAJOR (row-level security is FORCEd).
    On RHEL the base repository carries 13; enable a newer stream or add PGDG:
      dnf -y module reset postgresql && dnf -y module enable postgresql:${PG_MAJOR}
    then remove the old cluster and re-run. On SUSE pass --pg-major 16."
        ok "PostgreSQL $PG_VER"
    fi

    if [[ -z "$DB_PASSWORD" ]]; then
        DB_PASSWORD="$(gen_secret 24)"
        ok "generated a database password"
    fi

    if [[ $DRY_RUN -eq 0 ]] && [[ "$(psql_super "select 1 from pg_roles where rolname='${DB_USER}'")" == "1" ]]; then
        # Do NOT silently rotate an existing role's password: a second node
        # pointing at the same database would start failing authentication.
        warn "role ${DB_USER} already exists — password left untouched"
        if [[ -f "$VEYRS_DIR/.env" ]]; then
            EXISTING_PW="$(sed -n 's#^VEYRS_DATABASE_URL=.*://[^:]*:\([^@]*\)@.*#\1#p' "$VEYRS_DIR/.env" | head -1)"
            [[ -n "$EXISTING_PW" ]] && { DB_PASSWORD="$EXISTING_PW"; info "reusing the password already in .env"; }
        fi
    else
        run su - postgres -c "psql -v ON_ERROR_STOP=1 -c \"CREATE ROLE ${DB_USER} LOGIN PASSWORD '${DB_PASSWORD}';\"" \
            || die "could not create role ${DB_USER}"
        ok "role ${DB_USER} created"
    fi

    # TEMPLATE template0 is what makes ENCODING 'UTF8' legal when the cluster
    # default is not UTF-8. Dropping it is how installs end up SQL_ASCII.
    for db in "$DB_NAME" "$DB_TEST_NAME"; do
        if [[ $DRY_RUN -eq 0 ]] && [[ "$(psql_super "select 1 from pg_database where datname='${db}'")" == "1" ]]; then
            ok "database ${db} already exists"
        else
            run su - postgres -c "psql -v ON_ERROR_STOP=1 -c \"CREATE DATABASE ${db} OWNER ${DB_USER} ENCODING 'UTF8' TEMPLATE template0;\"" \
                || die "could not create database ${db}"
            ok "database ${db} created"
        fi
    done

    # Verify, do not assume. A SQL_ASCII database accepts every write and
    # surfaces weeks later as a decoding traceback on one advisory.
    if [[ $DRY_RUN -eq 0 ]]; then
        for db in "$DB_NAME" "$DB_TEST_NAME"; do
            enc="$(psql_super "select pg_encoding_to_char(encoding) from pg_database where datname='${db}'")"
            [[ "$enc" == "UTF8" ]] \
                || die "database ${db} is ${enc}, not UTF8.
    VEYRS stores advisories in five languages; ${enc} corrupts them silently.
    Fix: drop it and re-create with ENCODING 'UTF8' TEMPLATE template0, or
    re-initialise the cluster with a UTF-8 locale."
        done
        ok "both databases are UTF8"

        # Last, because it needs the role AND the databases to exist: prove
        # the application's own connection string actually authenticates.
        # Every later step assumes it does.
        pg_ensure_password_auth
    fi
fi

# =========================================================== 3. redis ========

step "3. Redis"

if [[ $SKIP_REDIS -eq 1 ]]; then
    info "skipped (--skip-redis) — expecting Redis on $REDIS_HOST:$REDIS_PORT"
else
    # SUSE ships only <conf>.example and a redis@<instance> template unit, so
    # there is no config file until one is created — and redis@default refuses
    # to start without /etc/redis/default.conf.
    if [[ -n "$REDIS_CONF_SEED" ]] && [[ ! -f "$REDIS_CONF" ]] && [[ -f "$REDIS_CONF_SEED" ]]; then
        run install -o root -g redis -m 640 "$REDIS_CONF_SEED" "$REDIS_CONF" \
            || die "could not seed $REDIS_CONF from $REDIS_CONF_SEED"
        ok "seeded $(basename "$REDIS_CONF") from the shipped example"
    fi

    if [[ -z "$REDIS_PASSWORD" ]] && [[ -f "$REDIS_CONF" ]]; then
        EXISTING_RPW="$(sed -n 's/^requirepass[[:space:]]\+\(.*\)$/\1/p' "$REDIS_CONF" | head -1)"
        if [[ -n "$EXISTING_RPW" ]]; then
            REDIS_PASSWORD="$EXISTING_RPW"
            ok "Redis already has requirepass — reusing it"
        else
            REDIS_PASSWORD="$(gen_secret 24)"
            run sed -i "s/^# *requirepass .*/requirepass ${REDIS_PASSWORD}/" "$REDIS_CONF"
            grep -q "^requirepass " "$REDIS_CONF" 2>/dev/null \
                || run bash -c "printf 'requirepass %s\n' '${REDIS_PASSWORD}' >> '${REDIS_CONF}'"
            ok "set requirepass"
        fi
    elif [[ ! -f "$REDIS_CONF" ]]; then
        warn "no $REDIS_CONF on this host — leaving Redis authentication as it is"
    fi

    run systemctl enable "$SVC_REDIS" >/dev/null 2>&1 || true
    run systemctl restart "$SVC_REDIS" \
        || die "could not start ${SVC_REDIS}. Check: systemctl status ${SVC_REDIS}; journalctl -u ${SVC_REDIS} -n 30"
    if [[ $DRY_RUN -eq 0 ]]; then
        RCLI=(redis-cli -h "$REDIS_HOST" -p "$REDIS_PORT")
        [[ -n "$REDIS_PASSWORD" ]] && RCLI+=(-a "$REDIS_PASSWORD")
        wait_for 20 "Redis" "${RCLI[@]}" ping \
            || die "Redis did not answer PING within 20s. Check: journalctl -u ${SVC_REDIS} -n 30"
    fi
fi

# ==================================================== 4. python packages =====

step "4. Python dependencies"

cd "$VEYRS_DIR"

if [[ ! -x venv/bin/python ]]; then
    run "$PY_BIN" -m venv venv \
        || die "could not create the virtualenv with ${PY_BIN}.
    A venv that fails here but whose interpreter passed step 1b almost always
    means ensurepip cannot run. Reproduce:  ${PY_BIN} -m ensurepip --version
    Debian/Ubuntu: apt-get install -y python3-venv
    SUSE:          zypper install -y python311-pip libexpat1"
    ok "virtualenv created with $PY_BIN"
else
    ok "virtualenv already present"
fi

# A venv whose pip is missing is the exact shape of the SUSE ensurepip
# failure, and every later step would blame the wrong thing.
if [[ $DRY_RUN -eq 0 ]]; then
    [[ -x venv/bin/pip ]] \
        || die "venv/bin/pip does not exist — the virtualenv was created without pip.
    Delete it and re-run:  rm -rf ${VEYRS_DIR}/venv
    If it happens again, ${PY_BIN} -m ensurepip is broken on this host (see step 1b)."
fi

run venv/bin/pip install --quiet --upgrade pip || die "pip self-upgrade failed"

# Install from requirements.txt — the full resolved graph, every version
# pinned. pyproject.toml lists only the direct dependencies and is for
# reading, not for installing.
PIP_LOG="$(mktemp -t veyrs-pip-XXXXXX.log)"
if [[ $DRY_RUN -eq 0 ]]; then
    if ! venv/bin/pip install -r requirements.txt >"$PIP_LOG" 2>&1; then
        if grep -qiE "Building wheel for|error: command .*(gcc|cc1)" "$PIP_LOG"; then
            printf '%s\n' "$(tail -30 "$PIP_LOG")" >&2
            die "pip tried to COMPILE instead of downloading wheels.
    That happens on ARM, on musl/Alpine, or on a Python newer than the pinned
    wheels. Install the build toolchain and re-run:
      ${BUILD_DEPS_HINT}
    Full log: $PIP_LOG"
        fi
        printf '%s\n' "$(tail -30 "$PIP_LOG")" >&2
        die "pip install failed. Full log: $PIP_LOG"
    fi
    if grep -q "Building wheel for" "$PIP_LOG"; then
        warn "some packages were compiled from source (expected: all wheels). Log: $PIP_LOG"
    fi
    rm -f "$PIP_LOG"
else
    info "[dry-run] venv/bin/pip install -r requirements.txt"
fi
ok "$(wc -l < requirements.txt) pinned lines installed"

if [[ $DRY_RUN -eq 0 ]]; then
    venv/bin/pip check >/dev/null 2>&1 || warn "pip check reports broken requirements — run: venv/bin/pip check"
    venv/bin/python -c "import fastapi, sqlalchemy, psycopg, redis" \
        || die "the core imports fail inside the virtualenv"
    ok "fastapi · sqlalchemy · psycopg · redis import cleanly"
fi

# ======================================================== 5. configure =======

step "5. Configuration and secrets"

run mkdir -p "$VEYRS_DIR/var/backups" "$VEYRS_DIR/var/documents"
run chmod 750 "$VEYRS_DIR/var" "$VEYRS_DIR/var/backups" "$VEYRS_DIR/var/documents"
ok "writable directories under var/"

if [[ -f "$VEYRS_DIR/.env" ]]; then
    # Never rewrite an existing .env. Rotating VEYRS_ENCRYPTION_KEY makes every
    # credential already stored in the database permanently undecryptable, and
    # nothing would report an error until the first integration is used.
    ok ".env already exists — left untouched"
    warn "delete it yourself if you intend to reconfigure from scratch"
else
    ask SERVER_NAME     "public hostname for this console (e.g. veyrs.example.com)"
    if [[ -z "$PUBLIC_BASE_URL" ]]; then
        PUBLIC_BASE_URL="https://${SERVER_NAME}"
        ask PUBLIC_BASE_URL "public base URL" "https://${SERVER_NAME}"
    fi
    if [[ "$ENVIRONMENT" == "production" && "$PUBLIC_BASE_URL" != https://* ]]; then
        die "VEYRS_PUBLIC_BASE_URL must be https:// in production.
    assert_production_safe() refuses to boot otherwise — deliberately: session
    cookies and tokens would otherwise cross the network in the clear."
    fi

    SECRET_KEY="$(gen_secret 48)"
    if [[ $DRY_RUN -eq 0 ]]; then
        ENCRYPTION_KEY="$(PYTHONPATH="$VEYRS_DIR/backend" "$VEYRS_DIR/venv/bin/python" -m veyrs.cli keygen | head -1)" \
            || die "veyrs.cli keygen failed — the virtualenv is incomplete"
        [[ -n "$ENCRYPTION_KEY" ]] || die "keygen produced an empty Fernet key"
    else
        ENCRYPTION_KEY="<generated by: veyrs.cli keygen>"
    fi
    ok "generated VEYRS_SECRET_KEY and VEYRS_ENCRYPTION_KEY"

    REDIS_URL="redis://${REDIS_PASSWORD:+:${REDIS_PASSWORD}@}${REDIS_HOST}:${REDIS_PORT}/0"
    DB_URL="postgresql+psycopg://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_NAME}"
    DB_TEST_URL="postgresql+psycopg://${DB_USER}:${DB_PASSWORD}@${DB_HOST}:${DB_PORT}/${DB_TEST_NAME}"

    if [[ $DRY_RUN -eq 0 ]]; then
        umask 077
        cat > "$VEYRS_DIR/.env" <<ENVEOF
# VEYRS runtime configuration — written by install.sh on $(date -u +%Y-%m-%dT%H:%M:%SZ).
# Keys match veyrs.config.Settings (VEYRS_ prefix). Never commit this file.

VEYRS_ENVIRONMENT=${ENVIRONMENT}
VEYRS_DEBUG=false

# Secrets. Rotating VEYRS_ENCRYPTION_KEY makes every stored integration
# credential undecryptable — treat it like the database itself.
VEYRS_SECRET_KEY=${SECRET_KEY}
VEYRS_ENCRYPTION_KEY=${ENCRYPTION_KEY}

VEYRS_DATABASE_URL=${DB_URL}
VEYRS_TEST_DATABASE_URL=${DB_TEST_URL}
VEYRS_REDIS_URL=${REDIS_URL}

VEYRS_PUBLIC_BASE_URL=${PUBLIC_BASE_URL}
VEYRS_CORS_ORIGINS=${PUBLIC_BASE_URL}

VEYRS_ACCESS_TOKEN_MINUTES=60
VEYRS_REFRESH_TOKEN_DAYS=14

# Per credential. Per source IP for the auth limiter — raise it if all your
# users egress behind one NAT address, or sign-in will lock them out.
VEYRS_RATE_LIMIT_PER_MINUTE=240
VEYRS_AUTH_RATE_LIMIT_PER_MINUTE=10

# Enable ONLY behind a reverse proxy you control. Otherwise any caller mints
# a fresh rate-limit identity per request by forging X-Forwarded-For.
VEYRS_TRUST_PROXY_HEADERS=true

# Bearer token for /metrics. A wrong token gets 404, not 401, on purpose.
VEYRS_METRICS_TOKEN=$(gen_secret 24)

VEYRS_DEFAULT_LOCALE=en
VEYRS_AI_ALLOW_EXTERNAL=false
VEYRS_AI_ALLOW_LOCAL=false

# Optional: raises the NVD rate limit. https://nvd.nist.gov/developers/request-an-api-key
VEYRS_NVD_API_KEY=
ENVEOF
        chmod 600 "$VEYRS_DIR/.env"
        ok "wrote .env (0600)"
    else
        info "[dry-run] would write $VEYRS_DIR/.env"
    fi
fi

# ===================================================== 6. schema + admin =====

step "6. Schema, self-check and first administrator"

# init-db creates tables, RLS policies, built-in roles and the compliance
# catalogues, and is idempotent. sync-schema does NOT create tables: on a
# database missing one it prints "0 columns added" and exits 0 — a success
# message for a no-op.
run env PYTHONPATH="$VEYRS_DIR/backend" "$VEYRS_DIR/venv/bin/python" -m veyrs.cli init-db \
    || die "init-db failed. Most often the database URL or the role password is wrong.
    Test it:  psql '${DB_HOST}:${DB_PORT}/${DB_NAME}' as ${DB_USER}"
ok "schema, RLS policies, roles and catalogues in place"

run env PYTHONPATH="$VEYRS_DIR/backend" "$VEYRS_DIR/venv/bin/python" -m veyrs.cli check \
    || die "veyrs.cli check failed — read its output above; it names the subsystem"
ok "configuration / storage / engine self-check passed"

if [[ $SKIP_BOOTSTRAP -eq 1 ]]; then
    info "skipped (--skip-bootstrap)"
elif [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] veyrs.cli bootstrap --org ... --superuser"
else
    ask ORG_SLUG    "first organization slug (lowercase, no spaces)"
    ask ORG_NAME    "organization display name" "$ORG_SLUG"
    ask ADMIN_EMAIL "administrator e-mail"
    [[ -n "$ADMIN_PASSWORD" ]] \
        || info "the next prompt is the administrator password — it is not echoed"
    # veyrs.cli bootstrap is not read-only on an existing account: it calls
    # hash_password() and overwrites the stored hash ("user exists, password
    # reset"). An installer that rotates a live credential on a re-run
    # contradicts its own rule about .env and the database role password, so
    # the account is checked first and left alone unless asked.
    if [[ $FORCE_BOOTSTRAP -eq 0 ]] && bootstrap_admin_exists; then
        ok "administrator ${ADMIN_EMAIL} already exists in '${ORG_SLUG}' — bootstrap not run"
        info "calling it would RESET that password. To do so deliberately:"
        info "  sudo ./install.sh --force-bootstrap ..."
    else
        # An array, not ${VAR:+...}: an unquoted conditional expansion splits
        # an organization name that contains a space into two arguments.
        BOOT_ARGS=(--org "$ORG_SLUG" --name "$ORG_NAME" --email "$ADMIN_EMAIL" --superuser)
        # The password goes to the CLI through its ENVIRONMENT, never as
        # --password: an argument is readable by every local account in ps(1)
        # for as long as the bootstrap runs (argon2 hashing is not instant).
        # A bash prefix assignment is not an argument either -- unlike
        # `env VAR=value cmd`, which would put it straight back into argv.
        BOOT_OUT="$(VEYRS_BOOTSTRAP_PASSWORD="$ADMIN_PASSWORD" \
                    PYTHONPATH="$VEYRS_DIR/backend" "$VEYRS_DIR/venv/bin/python" \
                    -m veyrs.cli bootstrap "${BOOT_ARGS[@]}" 2>&1)" || {
            printf '%s\n' "$BOOT_OUT" >&2
            die "bootstrap failed — its output is above."
        }
        # Report what the CLI actually did. The previous version printed
        # "created" unconditionally, which was a lie on every re-run.
        printf '    %s\n' "$BOOT_OUT"
        if printf '%s' "$BOOT_OUT" | grep -q 'password reset'; then
            warn "an existing administrator's password was RESET by this run"
        else
            ok "organization '$ORG_SLUG' and administrator $ADMIN_EMAIL created"
        fi
    fi
fi

# ======================================================== 7. systemd =========

step "7. systemd unit"

UNIT_SRC="$VEYRS_DIR/infrastructure/systemd/veyrs-api.service"
[[ -f "$UNIT_SRC" ]] || die "missing $UNIT_SRC"

if [[ $DRY_RUN -eq 0 ]]; then
    # Rewrite the paths so an install outside /opt/veyrs still works, AND the
    # ordering dependencies so they name units that exist on THIS host. A
    # stale `After=redis-server.service` on SUSE is not an error systemd
    # reports: an ordering dependency on a unit that does not exist is simply
    # ignored, so the API can start before Redis and fail its first request.
    sed -e "s#/opt/veyrs#${VEYRS_DIR}#g" \
        -e "s#redis-server\.service#${SVC_REDIS}.service#g" \
        -e "s#\bpostgresql\.service#${SVC_PG}.service#g" \
        "$UNIT_SRC" > "/etc/systemd/system/${SERVICE_NAME}.service"
    chmod 644 "/etc/systemd/system/${SERVICE_NAME}.service"
    grep -q "${SVC_REDIS}.service" "/etc/systemd/system/${SERVICE_NAME}.service" \
        || warn "the shipped unit names no redis dependency — nothing to rewrite"
fi
run systemctl daemon-reload
run systemctl enable "${SERVICE_NAME}" >/dev/null 2>&1 || true
run systemctl restart "${SERVICE_NAME}"

if [[ $DRY_RUN -eq 0 ]]; then
    wait_for 45 "${SERVICE_NAME}" curl -sf "http://${API_BIND}:${API_PORT}/healthz" \
        || die "${SERVICE_NAME} did not become healthy within 45s.
$(systemctl status "${SERVICE_NAME}" --no-pager -l 2>&1 | head -20)
    Then read:  journalctl -u ${SERVICE_NAME} -n 40 --no-pager
    In production the usual cause is assert_production_safe(): debug on, the
    bootstrap database password, plain HTTP, or a derived encryption key."
fi

info "optional units in infrastructure/systemd/:"
info "veyrs-digest.{service,timer}, veyrs-maintenance.{service,timer}"

# ========================================================== 8. console =======

step "8. Console and nginx"

if [[ $SKIP_NGINX -eq 1 ]]; then
    info "skipped (--skip-nginx)"
    warn "the console is static files in frontend/console/ — serve them yourself"
else
    if ! have nginx; then
        if [[ $DRY_RUN -eq 1 ]]; then
            warn "nginx is not installed yet — step 1 would have installed it"
        else
            die "nginx not found and --skip-nginx was not given"
        fi
    fi

    run install -d -m 755 "$CONSOLE_DIR"
    run install -m 644 \
        "$VEYRS_DIR/frontend/console/app.js" \
        "$VEYRS_DIR/frontend/console/console.css" \
        "$VEYRS_DIR/frontend/console/index.html" \
        "$CONSOLE_DIR/"
    ok "console copied to $CONSOLE_DIR"

    nginx_resolve_site
    info "vhost layout: ${NGINX_STYLE} → ${NGINX_SITE}"

    # The shipped vhost carries the author's own server_name. Generate one for
    # THIS host instead of asking the operator to remember to edit it.
    [[ -n "$SERVER_NAME" ]] || ask SERVER_NAME "nginx server_name" "_"

    NGINX_SITE_WRITTEN=0
    if [[ -f "$NGINX_SITE" ]]; then
        ok "$NGINX_SITE already exists — left untouched"
    elif [[ $DRY_RUN -eq 0 ]]; then
        NGINX_SITE_WRITTEN=1
        cat > "$NGINX_SITE" <<NGEOF
# VEYRS management console — generated by install.sh.
#
# This block listens on port 80. Terminate TLS either here (add a listen 443
# ssl block with your certificate) or on a reverse proxy in front of it. The
# API is proxied on the SAME origin so the browser never makes a cross-origin
# authenticated request.
server {
    listen 80;
    server_name ${SERVER_NAME};

    root ${CONSOLE_DIR};
    index index.html;

    access_log /var/log/nginx/veyrs-console.access.log;
    error_log  /var/log/nginx/veyrs-console.error.log;

    # The console is an operator surface, not public content.
    add_header X-Frame-Options           "DENY" always;
    add_header X-Content-Type-Options    "nosniff" always;
    add_header Referrer-Policy           "no-referrer" always;
    add_header Permissions-Policy        "geolocation=(), microphone=(), camera=()" always;
    add_header Strict-Transport-Security "max-age=31536000; includeSubDomains" always;
    # No 'unsafe-inline' for scripts: the console carries no inline handlers.
    add_header Content-Security-Policy "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; font-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'" always;

    # Hash routing: any unknown path is still the single page.
    location / {
        try_files \$uri \$uri/ /index.html;
    }

    location /api/ {
        proxy_pass http://${API_BIND}:${API_PORT};
        proxy_set_header Host              \$host;
        proxy_set_header X-Real-IP         \$remote_addr;
        proxy_set_header X-Forwarded-For   \$proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto \$scheme;
        proxy_read_timeout 300s;
        client_max_body_size 128m;   # scanner exports and PDFs
    }

    location ~ ^/(healthz|readyz)\$ {
        proxy_pass http://${API_BIND}:${API_PORT};
        add_header Cache-Control "no-store" always;
    }

    # /metrics is NOT exposed here. It is token-authenticated on the API and
    # an IP allowlist in nginx is not a substitute — see docs/SECURITY.md.
}
NGEOF
        ok "wrote $NGINX_SITE for server_name ${SERVER_NAME}"
    fi

    [[ -n "${NGINX_LINK:-}" ]] && run ln -sf "$NGINX_SITE" "$NGINX_LINK"

    selinux_allow_proxy

    if [[ $DRY_RUN -eq 0 ]]; then
        nginx -t >/dev/null 2>&1 || { nginx -t; die "nginx configuration is invalid"; }
        systemctl is-enabled --quiet nginx 2>/dev/null || run systemctl enable nginx >/dev/null 2>&1 || true
        # A reload on a stopped nginx fails on some families and is a no-op on
        # others. Start it when it is not running, reload when it is.
        if systemctl is-active --quiet nginx; then
            systemctl reload nginx || die "nginx reload failed"
            ok "nginx reloaded"
        else
            systemctl start nginx || die "nginx failed to start. Check: systemctl status nginx"
            ok "nginx started"
        fi
    fi
    firewall_note
fi

# ========================================================== 9. verify ========

step "9. Verify"

if [[ $DRY_RUN -eq 1 ]]; then
    info "[dry-run] skipping verification"
else
    HEALTH="$(curl -sf "http://${API_BIND}:${API_PORT}/healthz" || true)"
    [[ -n "$HEALTH" ]] || die "/healthz did not answer"
    ok "healthz: $HEALTH"

    curl -sf "http://${API_BIND}:${API_PORT}/readyz" >/dev/null \
        || die "/readyz is not 200 — the API is up but PostgreSQL or Redis is not reachable from it.
    Check the URLs in ${VEYRS_DIR}/.env, then: journalctl -u ${SERVICE_NAME} -n 30"
    ok "readyz: database and cache reachable"

    # An unauthenticated API call must be REFUSED, not served. This is the one
    # check that distinguishes "it starts" from "it is safe to expose".
    CODE="$(curl -so /dev/null -w '%{http_code}' "http://${API_BIND}:${API_PORT}/api/v1/assets" || true)"
    if [[ "$CODE" == "401" || "$CODE" == "403" ]]; then
        ok "unauthenticated /api/v1/assets -> $CODE (refused, as it must be)"
    else
        die "unauthenticated /api/v1/assets returned $CODE, expected 401/403. DO NOT EXPOSE THIS HOST."
    fi

    if [[ $SKIP_NGINX -eq 0 ]]; then
        for f in app.js console.css index.html; do
            cmp -s "$VEYRS_DIR/frontend/console/$f" "$CONSOLE_DIR/$f" \
                || die "$CONSOLE_DIR/$f differs from the checkout — the console copy did not take.
    A stale console serves the OLD UI against the NEW API and every surface still answers 200."
        done
        ok "console artefacts match the checkout"

        # Prove the front end actually reaches the API through nginx. This is
        # the check SELinux fails, and it fails as a 502 that neither the
        # nginx test nor the API health endpoint can see.
        # A bounded poll, not one shot. `systemctl reload nginx` returns before
        # the worker processes have picked up the new configuration, so on a
        # host where nginx was ALREADY running the first request still hits
        # the old config and answers 404 from the distribution's default site.
        # Measured on Debian 12, where nginx starts at package install time.
        if wait_for 15 "nginx -> API: /healthz through port 80" nginx_probe_200; then
            NCODE=200
        else
            NCODE="$(curl -so /dev/null -w '%{http_code}' -H "Host: ${SERVER_NAME:-localhost}" \
                     "http://127.0.0.1/healthz" || true)"
        fi
        NGX_MSG="nginx answered $NCODE for /healthz on port 80, expected 200.
    The API is healthy on ${API_BIND}:${API_PORT}, so this is the proxy hop.
    On an SELinux host:  setsebool -P httpd_can_network_connect 1
    Otherwise read:      tail -20 /var/log/nginx/veyrs-console.error.log"
        if [[ "$NCODE" == "200" ]]; then
            : # wait_for already reported it
        elif [[ ${NGINX_SITE_WRITTEN:-0} -eq 1 && "${SERVER_NAME}" != "_" ]]; then
            # Only assertable on a vhost THIS run authored. A pre-existing
            # vhost may listen on 443 only, or answer to a server_name this
            # script never learned (a re-run leaves .env, and with it
            # SERVER_NAME, untouched) — failing there would break the
            # idempotent re-run this installer promises.
            die "$NGX_MSG"
        else
            warn "$NGX_MSG"
            info "not fatal: the vhost was not written by this run, so its"
            info "server_name and listeners are not this installer's to assert."
        fi
    fi
fi

# ============================================================= summary =======

printf '\n%s%s VEYRS installed %s\n\n' "$C_BOLD$C_GREEN" "==>" "$C_RESET"
cat <<SUMMARY
    Platform      ${DISTRO_FAMILY} · ${PKG_MGR} · python ${PY_BIN}
    Root          ${VEYRS_DIR}
    Service       ${SERVICE_NAME}   (systemctl status ${SERVICE_NAME})
    API           http://${API_BIND}:${API_PORT}
    Console       ${CONSOLE_DIR}${SERVER_NAME:+  (server_name ${SERVER_NAME})}
    Database      ${DB_NAME} on ${DB_HOST}:${DB_PORT} as ${DB_USER}
    Redis unit    ${SVC_REDIS}   (config ${REDIS_CONF})
    Secrets       ${VEYRS_DIR}/.env  (mode 0600 — back it up, it is not recoverable)

    Next
      1. Put TLS in front of it. ${ENVIRONMENT} + plain HTTP is refused at boot.
      2. Load threat intelligence — the first sync takes a while:
           cd ${VEYRS_DIR}
           PYTHONPATH=backend venv/bin/python -m veyrs.cli sync-cwe
           PYTHONPATH=backend venv/bin/python -m veyrs.cli sync-kev
           PYTHONPATH=backend venv/bin/python -m veyrs.cli sync-epss
           PYTHONPATH=backend venv/bin/python -m veyrs.cli sync-nvd
      3. Sign in at ${PUBLIC_BASE_URL:-https://${SERVER_NAME:-YOUR-HOST}}/
      4. Run the suite (never bare pytest): ./scripts/test.sh

    Full reference: INSTALL.md · docs/DEPLOYMENT.md · docs/SECURITY.md
SUMMARY
