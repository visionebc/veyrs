#!/usr/bin/env bash
# ============================================================================
# veyrs-setup.sh — guided installer for VEYRS (native or Docker).
#
#   Download:  https://github.com/visionebc/veyrs/releases/latest/download/veyrs-setup.sh
#   Usage:     sudo bash veyrs-setup.sh                  (interactive)
#              sudo bash veyrs-setup.sh --check          (checks only, changes nothing)
#              sudo bash veyrs-setup.sh --yes --answers answers.env
#              sudo bash veyrs-setup.sh --uninstall      (Docker install; keeps the data)
#
# This script DRIVES the installers that ship in the release. It does not
# re-implement them:
#
#   native  install.sh  — packages, PostgreSQL role and UTF8 databases, Redis,
#                         virtualenv, .env, schema, first administrator,
#                         systemd unit, nginx vhost. This script asks every
#                         question up front and hands the answers over by
#                         ENVIRONMENT (never argv: argv is readable by every
#                         local account in ps(1)).
#   docker  docker/veyrs-docker.sh — builds the images and runs the stack.
#                         This script installs Docker if it is missing, writes
#                         docker/.env with the same keys `veyrs-docker.sh init`
#                         would, and chooses the overlays and profiles.
#
# Flow
#   1. Operating system and requirements.
#   2. Existing installation (native or Docker)? -> update / reinstall / abort.
#   3. Source: the tree this script sits in, --source DIR|TARBALL, or the
#      release tarball from GitHub, verified against its .sha256.
#   4. Native or Docker; bundled or EXTERNAL PostgreSQL. An external role is
#      checked through the real network path and REFUSED if it is a superuser
#      or has BYPASSRLS: either one silently switches off tenant isolation.
#   5. Administrator password: asked twice and validated, or generated into
#      a 0600 file. There is never a default password.
#   6. Summary: URL, where the password is, log, how to uninstall.
#
# Re-running is safe: it never rotates the admin password, the database
# password, VEYRS_SECRET_KEY or the Fernet VEYRS_ENCRYPTION_KEY.
#
# Unattended (--yes): each question reads its SETUP_* variable (environment or
# --answers file) or takes its default. The list is in --help.
# ============================================================================
set -Eeuo pipefail

SETUP_SELF_VERSION="1.0.0"
GH_REPO="visionebc/veyrs"
# Overridable for offline mirrors and for the test bench; the defaults are the
# public release.
RELEASE_BASE="${VEYRS_SETUP_RELEASE_BASE:-https://github.com/${GH_REPO}/releases/download}"
API_LATEST="${VEYRS_SETUP_API_LATEST:-https://api.github.com/repos/${GH_REPO}/releases/latest}"

LOG="/var/log/veyrs-setup.log"
NATIVE_DIR="/opt/veyrs"
DOCKER_HOME="/opt/veyrs-docker"
DOCKER_ENV="$DOCKER_HOME/veyrs.env"
STATE_FILE="/etc/veyrs-setup.conf"
PW_FILE="/root/veyrs-admin-password.txt"
WRAPPER="/usr/local/sbin/veyrs-docker"
COMPOSE_PROJECT="veyrs"          # `name:` in docker/compose.yaml
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

c_b=$'\033[1m'; c_g=$'\033[32m'; c_y=$'\033[33m'; c_r=$'\033[31m'; c_d=$'\033[2m'; c_0=$'\033[0m'
[ -t 1 ] || { c_b=; c_g=; c_y=; c_r=; c_d=; c_0=; }

# The log is opened only once we know this run may change things: --check
# promises to write NOTHING, the log included.
LOG_ON=0
log_raw() { [ "$LOG_ON" -eq 1 ] || return 0; printf '%s %s\n' "$(date '+%F %T')" "$*" >>"$LOG" 2>/dev/null || true; }
say()  { echo; echo "${c_b}==> $*${c_0}"; log_raw "==> $*"; }
ok()   { echo "    ${c_g}✓${c_0} $*"; log_raw "OK $*"; }
warn() { echo "    ${c_y}!${c_0} $*"; log_raw "WARN $*"; }
info() { echo "    ${c_d}·${c_0} $*"; log_raw "INFO $*"; }
die()  { echo; echo "${c_r}ERROR:${c_0} $*" >&2; log_raw "ERROR [${CURRENT_STEP}] $*"; exit 1; }

CURRENT_STEP="startup"
on_error() {
    local rc=$?
    echo
    echo "${c_r}Setup stopped during step: ${CURRENT_STEP} (exit code ${rc}).${c_0}" >&2
    [ "$LOG_ON" -eq 1 ] && echo "  Full log: ${LOG}" >&2
    echo "  Re-running this script is safe: it resumes without undoing finished work" >&2
    echo "  and keeps every secret that was already generated." >&2
    log_raw "FAILED in step '${CURRENT_STEP}' rc=${rc}"
    exit "$rc"
}
trap on_error ERR

WORK=""
cleanup() { [ -n "$WORK" ] && [ -d "$WORK" ] && rm -rf "$WORK"; return 0; }
trap cleanup EXIT

usage() {
    cat <<'EOF'
veyrs-setup.sh — guided installer for VEYRS (native or Docker)

Options:
  --check              Only check this machine. Changes nothing, writes nothing.
  --yes                No questions: every answer comes from a SETUP_* variable
                       or its default. Missing required answers are an error.
  --answers FILE       KEY=VALUE file with the SETUP_* answers (use with --yes).
  --version X.Y.Z      VEYRS release to install (default: the latest release).
  --source DIR|TARBALL Install from a local tree or veyrs-<ver>-src.tar.gz
                       (offline). A TARBALL.sha256 next to it is verified.
                       Default: the tree this script sits in, if it is one;
                       otherwise the release tarball from GitHub.
  --dry-run            Print the plan and change nothing. Native mode runs
                       install.sh --dry-run; Docker mode asks the questions,
                       prints the summary and stops (it does not install or
                       start Docker either).
  --force              Continue on an operating system that is not supported.
  --uninstall          Remove the Docker installation. KEEPS the data volumes
                       and the secrets file, so a later install finds its data.
  --purge              With --uninstall: ALSO delete the volumes (database) and
                       the secrets. Irreversible; asks you to type PURGE.
  -h, --help           This help.

Answers for --yes (optional unless marked):
  SETUP_MODE=native|docker               (required with --yes on a fresh host)
  SETUP_EXISTING=update|reinstall|abort  when VEYRS is already installed (default update)
  SETUP_SERVER_NAME     hostname of the console (default: hostname -f)
  SETUP_PUBLIC_URL      public base URL (native default https://<server name>)
  SETUP_ENVIRONMENT     production|development (production requires an https URL)
  SETUP_ORG             first organization slug (default veyrs)
  SETUP_ORG_NAME        its display name (default: the slug)
  SETUP_ADMIN_EMAIL     first administrator (default admin@<server name>)
  SETUP_ADMIN_PASSWORD  empty = generate one into /root/veyrs-admin-password.txt (0600)
  SETUP_DB=bundled|external
  SETUP_DB_HOST, SETUP_DB_PORT (5432), SETUP_DB_NAME (veyrs), SETUP_DB_USER (veyrs),
  SETUP_DB_PASSWORD     external PostgreSQL (role must NOT be superuser/BYPASSRLS,
                        must own the database, database must be UTF8, server >= 15)
  SETUP_FIREWALL=yes|no open the console port in firewalld/ufw (default no)
  Docker only:
  SETUP_HTTP_BIND       where the console is published (default 127.0.0.1:8080)
  SETUP_WORKERS=yes|no  intel + digest workers (default no — read the question)
  SETUP_AGENT=yes|no    scanner agent (default no — read the question)
  SETUP_AGENT_ALLOW     agent allowlist (hosts, wildcards, CIDRs)
  SETUP_AGENT_TOKEN     agent token minted in the console (Settings -> Agents)
  SETUP_INSTALL_DOCKER=yes|no   install Docker if missing (default yes)
EOF
}

# ─────────────────────────────────────────────────────────────────────────────
# Arguments
# ─────────────────────────────────────────────────────────────────────────────
ASSUME_YES=0; CHECK_ONLY=0; FORCE=0; UNINSTALL=0; PURGE=0; DRY_RUN=0
WANT_VERSION=""; SOURCE_ARG=""
while [ $# -gt 0 ]; do
    case "$1" in
        --check) CHECK_ONLY=1 ;;
        --yes|-y) ASSUME_YES=1 ;;
        --answers) shift; [ -f "${1:-}" ] || die "--answers: no such file '${1:-}'"
                   # shellcheck disable=SC1090
                   set -a; . "$1"; set +a ;;
        --version) shift; WANT_VERSION="${1#v}"
                   [[ "$WANT_VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "--version wants X.Y.Z, got '${1:-}'" ;;
        --source) shift; SOURCE_ARG="${1:-}"; [ -e "$SOURCE_ARG" ] || die "--source: no such file or directory '${SOURCE_ARG}'" ;;
        --dry-run) DRY_RUN=1 ;;
        --force) FORCE=1 ;;
        --uninstall) UNINSTALL=1 ;;
        --purge) PURGE=1 ;;
        -h|--help) usage; exit 0 ;;
        *) die "unknown option: $1 (see --help)" ;;
    esac
    shift
done
[ "$PURGE" -eq 0 ] || [ "$UNINSTALL" -eq 1 ] || die "--purge only makes sense with --uninstall"

[ "$(id -u)" -eq 0 ] || die "run as root: sudo bash $0"
if [ "$CHECK_ONLY" -eq 0 ]; then
    mkdir -p "$(dirname "$LOG")"; touch "$LOG"; chmod 600 "$LOG"; LOG_ON=1
    log_raw "===== veyrs-setup ${SETUP_SELF_VERSION} — $(date -u +%FT%TZ) — args: check=${CHECK_ONLY} yes=${ASSUME_YES} dry=${DRY_RUN} uninstall=${UNINSTALL} purge=${PURGE} version=${WANT_VERSION:-latest} source=${SOURCE_ARG:-auto} ====="
fi

# ─────────────────────────────────────────────────────────────────────────────
# Questions. With --yes each one reads its SETUP_* variable, else its default;
# with neither, it stops and names the variable.
# ─────────────────────────────────────────────────────────────────────────────
# ask VAR "question" "default" [PRESET_VAR]
ask() {
    local __var="$1" __q="$2" __def="${3:-}" __pre="${4:-}" __ans=""
    if [ -n "$__pre" ] && [ -n "${!__pre:-}" ]; then
        __ans="${!__pre}"; info "$__q ${__ans} (from ${__pre})"
    elif [ "$ASSUME_YES" -eq 1 ]; then
        [ -n "$__def" ] || die "--yes: no value for ${__pre:-the answer to}: $__q"
        __ans="$__def"; info "$__q ${__ans} (default)"
    else
        read -rp "    ${__q}${__def:+ [${__def}]}: " __ans </dev/tty || die "input closed at: $__q"
        __ans="${__ans:-$__def}"
    fi
    printf -v "$__var" '%s' "$__ans"
    log_raw "Q: $__q -> $__ans"
}
# ask_choice VAR "question" "a|b|c" "default" [PRESET_VAR]
ask_choice() {
    local __var="$1" __q="$2" __opts="$3" __def="$4" __pre="${5:-}" __a
    while :; do
        ask __a "$__q (${__opts//|/\/})" "$__def" "$__pre"
        __a="$(printf '%s' "$__a" | tr '[:upper:]' '[:lower:]')"
        case "|$__opts|" in *"|$__a|"*) printf -v "$__var" '%s' "$__a"; return 0 ;; esac
        if [ "$ASSUME_YES" -eq 1 ] || { [ -n "$__pre" ] && [ -n "${!__pre:-}" ]; }; then
            die "invalid value '$__a' for: $__q (valid: ${__opts//|/, })"
        fi
        warn "valid answers: ${__opts//|/, }"
    done
}
ask_yn() {  # ask_yn "question" y|n [PRESET_VAR] -> rc 0 = yes
    local __a; ask __a "$1 (y/n)" "$2" "${3:-}"
    case "$(printf '%s' "$__a" | tr '[:upper:]' '[:lower:]')" in y|yes|1|true|on) return 0 ;; *) return 1 ;; esac
}
# ask_secret VAR "question" [PRESET_VAR] — never echoed, never logged.
ask_secret() {
    local __var="$1" __q="$2" __pre="${3:-}" __ans=""
    if [ -n "$__pre" ] && [ -n "${!__pre:-}" ]; then
        __ans="${!__pre}"; info "$__q (from ${__pre})"
    elif [ "$ASSUME_YES" -eq 1 ]; then
        die "--yes: no value for ${__pre}: $__q"
    else
        read -rsp "    ${__q}: " __ans </dev/tty || die "input closed at: $__q"; echo
    fi
    printf -v "$__var" '%s' "$__ans"
    log_raw "Q: $__q -> ***"
}

# ─────────────────────────────────────────────────────────────────────────────
# Utilities
# ─────────────────────────────────────────────────────────────────────────────
have() { command -v "$1" >/dev/null 2>&1; }
ver_ge() { [ "$(printf '%s\n%s\n' "$2" "$1" | sort -V | head -1)" = "$2" ]; }   # ver_ge A B -> A >= B
fetch() { curl -fsSL --retry 3 --connect-timeout 15 "$@"; }
port_owner() {
    have ss || { echo ""; return 0; }
    ss -Htlnp "sport = :$1" 2>/dev/null | sed -n 's/.*users:(("\([^"]*\)".*/\1/p' | head -1
}
urlencode() {
    local s="$1" o="" c i
    for ((i=0; i<${#s}; i++)); do
        c="${s:i:1}"
        case "$c" in [a-zA-Z0-9.~_-]) o+="$c" ;; *) o+="$(printf '%%%02X' "'$c")" ;; esac
    done
    printf '%s' "$o"
}
urldecode() { local s="${1//+/ }"; printf '%b' "${s//%/\\x}"; }
# Random, url-safe. /dev/urandom + base64 (coreutils) rather than openssl or
# python: neither is guaranteed on a pristine host, and SUSE has no python3.
rand_urlsafe() { head -c "$1" /dev/urandom | base64 -w0 | tr '+/' '-_' | tr -d '='; }
rand_hex() { head -c "$1" /dev/urandom | od -An -tx1 | tr -d ' \n'; }
json_str() { local s="${1//\\/\\\\}"; s="${s//\"/\\\"}"; printf '"%s"' "$s"; }

# Strip every secret this run knows from a stream before it reaches the log
# or the screen. Secrets travel to awk by ENVIRONMENT, never as arguments.
redact() {
    RDX_1="${ADMIN_PASS:-}" RDX_2="${DB_PASS:-}" RDX_3="${DB_PASS_ENC:-}" RDX_4="${AGENT_TOKEN:-}" \
    awk 'BEGIN { n = 0; for (k in ENVIRON) if (k ~ /^RDX_[0-9]$/ && length(ENVIRON[k]) >= 6) s[++n] = ENVIRON[k] }
         { line = $0
           for (i = 1; i <= n; i++) { out = ""
               while ((p = index(line, s[i])) > 0) { out = out substr(line, 1, p - 1) "***"; line = substr(line, p + length(s[i])) }
               line = out line }
           print line; fflush() }'
}
# run_logged CMD... — output to screen AND log, redacted. Returns CMD's code.
run_logged() { local rc=0; { "$@" 2>&1; } | redact | tee -a "$LOG" || rc=$?; return "$rc"; }
# run_quiet CMD... — output to the log only, redacted. Returns CMD's code.
run_quiet()  { local rc=0; { "$@" 2>&1; } | redact >>"$LOG" || rc=$?; return "$rc"; }

PW_MIN=12
password_ok() {
    local p="$1"
    [ "${#p}" -ge "$PW_MIN" ] || { warn "at least ${PW_MIN} characters (VEYRS password_min_length)"; return 1; }
    [[ "$p" == *[[:cntrl:]]* ]] && { warn "control characters are not allowed"; return 1; }
    [[ "$p" =~ ^(.)\1*$ ]] && { warn "one repeated character is not a password"; return 1; }
    return 0
}

ADMIN_PASS=""; ADMIN_PASS_GENERATED=0; ADMIN_PASS_KEPT=0
ask_admin_password() {
    say "Password for the first administrator (${ADMIN_EMAIL})"
    if [ -n "${SETUP_ADMIN_PASSWORD:-}" ]; then
        password_ok "$SETUP_ADMIN_PASSWORD" || die "SETUP_ADMIN_PASSWORD does not meet the policy (>= ${PW_MIN} characters)"
        ADMIN_PASS="$SETUP_ADMIN_PASSWORD"; ok "password taken from SETUP_ADMIN_PASSWORD"; return 0
    fi
    if [ "$ASSUME_YES" -eq 0 ]; then
        info "Minimum ${PW_MIN} characters. Leave empty to GENERATE one into ${PW_FILE} (0600)."
        local a b
        while :; do
            read -rsp "    Password: " a </dev/tty; echo
            [ -z "$a" ] && break
            password_ok "$a" || continue
            read -rsp "    Repeat it: " b </dev/tty; echo
            [ "$a" = "$b" ] || { warn "they do not match"; continue; }
            ADMIN_PASS="$a"; ok "password accepted"; return 0
        done
    fi
    ADMIN_PASS="$(rand_urlsafe 18)"
    ADMIN_PASS_GENERATED=1
    if [ "$DRY_RUN" -eq 1 ]; then
        info "[dry-run] a password would be generated into ${PW_FILE} (0600)"
    else
        ( umask 077; printf '%s\n' "$ADMIN_PASS" > "$PW_FILE" ); chmod 600 "$PW_FILE"
        ok "password generated and stored in ${PW_FILE} (readable by root only)"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 1 — operating system and requirements
# ─────────────────────────────────────────────────────────────────────────────
OS_ID=""; OS_NAME=""; OS_FAMILY=""; PKG=""
detect_os() {
    CURRENT_STEP="1 · operating system"
    say "Step 1 · Operating system and requirements"
    [ -r /etc/os-release ] || die "no /etc/os-release: cannot identify this distribution"
    local id like ver name
    # shellcheck disable=SC1091
    id="$(. /etc/os-release; printf '%s' "${ID:-?}")"
    # shellcheck disable=SC1091
    like="$(. /etc/os-release; printf '%s' "${ID_LIKE:-}")"
    # shellcheck disable=SC1091
    ver="$(. /etc/os-release; printf '%s' "${VERSION_ID:-?}")"
    # shellcheck disable=SC1091
    name="$(. /etc/os-release; printf '%s' "${PRETTY_NAME:-}")"
    OS_ID="$id"; OS_NAME="${name:-$id $ver}"
    local major="${ver%%.*}" support=no
    case " $id $like " in
        *" debian "*|*" ubuntu "*)
            OS_FAMILY=debian; PKG=apt-get
            case "$id:$major" in debian:12|ubuntu:24) support=tested ;; debian:13|ubuntu:22) support=family ;; esac ;;
        *" rhel "*|*" centos "*|*" fedora "*|*" rocky "*|*" almalinux "*)
            OS_FAMILY=rhel; PKG=dnf; have dnf || PKG=yum
            case "$id:$major" in rocky:9|almalinux:9) support=tested ;; rhel:9|centos:9) support=family ;; esac ;;
        *" suse "*|*" opensuse "*|*" sles "*|*" opensuse-leap "*)
            OS_FAMILY=suse; PKG=zypper
            case "$id:$major" in opensuse-leap:15) support=tested ;; sles:15|sled:15) support=family ;; esac ;;
    esac
    case "$support" in
        tested) ok "system: ${OS_NAME} (family ${OS_FAMILY}) — tested" ;;
        family) warn "system: ${OS_NAME} — same family as a tested release (${OS_FAMILY}), not itself tested" ;;
        *) if [ -n "$OS_FAMILY" ] && [ "$FORCE" -eq 1 ]; then warn "system: ${OS_NAME} — NOT supported (continuing: --force)"
           else die "${OS_NAME} is not supported. Supported: Debian 12, Ubuntu 22.04/24.04, Rocky/Alma/RHEL 9, openSUSE Leap/SLES 15 (--force to try anyway)"; fi ;;
    esac
    if have systemctl && [ -d /run/systemd/system ]; then ok "systemd present"; else die "systemd is required (not detected as init)"; fi
}

NODE_IP=""; INTERNET=0
check_requirements() {
    CURRENT_STEP="1 · requirements"
    local cores mem_mb disk_mb
    cores=$(nproc 2>/dev/null || echo 1)
    mem_mb=$(awk '/MemTotal/{print int($2/1024)}' /proc/meminfo)
    disk_mb=$(df -Pm / | awk 'NR==2{print $4}')
    if [ "$cores" -ge 2 ]; then ok "CPU: ${cores} cores"; else warn "CPU: ${cores} core — 2 or more recommended"; fi
    if   [ "$mem_mb" -ge 3800 ]; then ok "RAM: ${mem_mb} MB"
    elif [ "$mem_mb" -ge 1900 ]; then warn "RAM: ${mem_mb} MB — 4 GB recommended (Docker builds need more)"
    else die "RAM: ${mem_mb} MB — not enough (minimum 2 GB, 4 GB recommended)"; fi
    if   [ "$disk_mb" -ge 12000 ]; then ok "free disk on /: $((disk_mb/1024)) GB"
    elif [ "$disk_mb" -ge 5000 ];  then warn "free disk on /: $((disk_mb/1024)) GB — the Docker mode needs ~12 GB"
    else die "free disk on /: ${disk_mb} MB — not enough (minimum 5 GB)"; fi
    NODE_IP="$(ip -4 route get 1.1.1.1 2>/dev/null | sed -n 's/.* src \([0-9.]*\).*/\1/p' | head -1 || true)"
    # `hostname -I` is net-tools/inetutils-specific (absent on some minimal
    # images); under pipefail its failure would abort the whole script here.
    [ -n "$NODE_IP" ] || NODE_IP="$(hostname -I 2>/dev/null | awk '{print $1}' || true)"
    ok "primary address: ${NODE_IP:-unknown}"
    local p o
    for p in 80 8000 8080; do
        o="$(port_owner "$p")"
        if [ -z "$o" ]; then ok "port ${p} free"; else info "port ${p} in use by: ${o}"; fi
    done
    for p in curl tar gzip; do have "$p" || warn "missing: $p (installed automatically when needed)"; done
    if have curl && curl -fsS -o /dev/null --connect-timeout 8 --max-time 20 "https://github.com" 2>/dev/null; then
        INTERNET=1; ok "Internet (github.com) reachable"
    else
        warn "github.com not reachable — only an offline install from --source is possible"
    fi
    if have getenforce; then info "SELinux: $(getenforce 2>/dev/null || echo unknown)"; fi
    if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then info "firewall: firewalld active"
    elif have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then info "firewall: ufw active"
    else info "firewall: none active"; fi
    if have docker && docker info >/dev/null 2>&1; then
        ok "Docker $(docker version -f '{{.Server.Version}}' 2>/dev/null) running$(docker compose version --short >/dev/null 2>&1 && printf ', Compose %s' "$(docker compose version --short 2>/dev/null)")"
    else
        info "Docker: not installed or not running (only needed for the Docker mode)"
    fi
}

# Tools this script itself needs (curl, tar, gzip). Minimal RHEL images ship
# no tar at all; RHEL's curl-minimal provides the curl binary and conflicts
# with the curl package, so only a MISSING binary is installed.
ensure_tools() {
    CURRENT_STEP="1 · tools"
    local missing=() t
    for t in curl tar gzip; do have "$t" || missing+=("$t"); done
    [ "${#missing[@]}" -eq 0 ] && return 0
    if [ "$DRY_RUN" -eq 1 ]; then
        # A dry run installs nothing, not even its own tools. tar and gzip are
        # needed to read the release; curl only to download it.
        info "[dry-run] would install: ${missing[*]} (nothing done)"
        for t in tar gzip; do have "$t" || die "--dry-run needs $t to read the release; install it, or run without --dry-run"; done
        if have curl; then :; elif [ -z "$SOURCE_ARG" ]; then
            die "--dry-run without curl can only read a local release: pass --source DIR|TARBALL"
        fi
        return 0
    fi
    info "installing: ${missing[*]}"
    case "$OS_FAMILY" in
        debian) run_quiet env DEBIAN_FRONTEND=noninteractive apt-get update -qq
                run_quiet env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "${missing[@]}" ;;
        rhel)   run_quiet "$PKG" -y install "${missing[@]}" ;;
        suse)   run_quiet zypper --non-interactive --gpg-auto-import-keys install -y "${missing[@]}" ;;
    esac
    for t in "${missing[@]}"; do have "$t" || die "could not install $t — install it by hand and re-run"; done
    ok "installed: ${missing[*]}"
    # Step 1 measured the Internet with a curl that did not exist yet: on a
    # pristine host that read as "offline" and refused the GitHub download.
    if [ "$INTERNET" -eq 0 ] && curl -fsS -o /dev/null --connect-timeout 8 --max-time 20 "https://github.com" 2>/dev/null; then
        INTERNET=1; ok "Internet (github.com) reachable"
    fi
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 2 — existing installation?
# ─────────────────────────────────────────────────────────────────────────────
EXISTING=""; DOCKER_PARTIAL=0; EXISTING_VERSION=""
tree_version() { sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$1/pyproject.toml" 2>/dev/null | head -1; }
detect_existing() {
    CURRENT_STEP="2 · existing installation"
    say "Step 2 · Existing installations"
    if [ -f "$NATIVE_DIR/.env" ] || systemctl cat veyrs-api.service >/dev/null 2>&1; then
        EXISTING=native; EXISTING_VERSION="$(tree_version "$NATIVE_DIR")"
        warn "a NATIVE install exists in ${NATIVE_DIR} (veyrs-api: $(systemctl is-active veyrs-api.service 2>/dev/null || true)) — version ${EXISTING_VERSION:-?}"
    fi
    if [ -f "$DOCKER_HOME/.installed" ]; then
        [ -z "$EXISTING" ] || die "both a native and a Docker install exist on this host — resolve that by hand first"
        EXISTING=docker; EXISTING_VERSION="$(tree_version "$DOCKER_HOME/current")"
        warn "a DOCKER install exists in ${DOCKER_HOME} — version ${EXISTING_VERSION:-?}"
    elif [ -f "$DOCKER_ENV" ]; then
        DOCKER_PARTIAL=1
        warn "${DOCKER_ENV} exists without a finished install (an earlier attempt stopped, or --uninstall kept the data): its secrets will be reused"
    fi
    if [ -z "$EXISTING" ] && have docker && docker info >/dev/null 2>&1 \
       && [ -n "$(docker ps -aq --filter "label=com.docker.compose.project=${COMPOSE_PROJECT}" 2>/dev/null)" ] \
       && [ "$DOCKER_PARTIAL" -eq 0 ]; then
        warn "containers of a compose project '${COMPOSE_PROJECT}' exist that this script did not create (docker/veyrs-docker.sh run by hand?)"
    fi
    [ -n "$EXISTING" ] || [ "$DOCKER_PARTIAL" -eq 1 ] || ok "no VEYRS installation on this machine"
}

# ─────────────────────────────────────────────────────────────────────────────
# Step 3 — source tree
# ─────────────────────────────────────────────────────────────────────────────
SRC_DIR=""; VERSION=""
is_tree() { [ -f "$1/install.sh" ] && [ -d "$1/backend/veyrs" ] && [ -f "$1/docker/compose.yaml" ] && [ -f "$1/pyproject.toml" ]; }

resolve_latest_version() {
    local v
    v="$(fetch --max-time 30 -H 'Accept: application/vnd.github+json' "$API_LATEST" 2>/dev/null \
         | sed -n 's/.*"tag_name"[[:space:]]*:[[:space:]]*"v\{0,1\}\([^"]*\)".*/\1/p' | head -1 || true)"
    [[ "$v" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || return 1
    printf '%s' "$v"
}

# verify_sha256 FILE SHAFILE — the .sha256 carries "<hash>  <name>"; only the
# hash is compared, so a renamed download still verifies.
verify_sha256() {
    local want got
    want="$(awk 'NR==1{print $1}' "$2" | tr '[:upper:]' '[:lower:]')"
    [[ "$want" =~ ^[0-9a-f]{64}$ ]] || die "$(basename "$2") does not contain a SHA-256"
    got="$(sha256sum "$1" | awk '{print $1}')"
    [ "$want" = "$got" ] || die "SHA-256 MISMATCH for $(basename "$1"):
       expected ${want}
       got      ${got}
     The download is incomplete or has been tampered with. Nothing was installed."
}

extract_tarball() {  # extract_tarball FILE -> sets SRC_DIR
    [ -n "$WORK" ] || { WORK="$(mktemp -d /var/tmp/veyrs-setup.XXXXXX)"; chmod 700 "$WORK"; }
    tar -xzf "$1" -C "$WORK" || die "cannot extract $(basename "$1")"
    local d
    d="$(find "$WORK" -mindepth 1 -maxdepth 1 -type d -name 'veyrs-*' | head -1)"
    [ -n "$d" ] && is_tree "$d" || die "$(basename "$1") does not contain a VEYRS tree (veyrs-<version>/install.sh, backend/, docker/)"
    SRC_DIR="$d"
}

resolve_source() {
    CURRENT_STEP="3 · source"
    say "Step 3 · Source"
    if [ -n "$SOURCE_ARG" ]; then
        if [ -d "$SOURCE_ARG" ]; then
            is_tree "$SOURCE_ARG" || die "--source $SOURCE_ARG is not a VEYRS tree (install.sh, backend/veyrs, docker/compose.yaml)"
            SRC_DIR="$(cd "$SOURCE_ARG" && pwd)"
            ok "local tree: ${SRC_DIR}"
        else
            if [ -f "${SOURCE_ARG}.sha256" ]; then
                verify_sha256 "$SOURCE_ARG" "${SOURCE_ARG}.sha256"; ok "tarball verified against $(basename "$SOURCE_ARG").sha256"
            else
                warn "no $(basename "$SOURCE_ARG").sha256 next to it: integrity NOT verified"
            fi
            extract_tarball "$SOURCE_ARG"
            ok "tarball extracted: $(basename "$SOURCE_ARG")"
        fi
    elif is_tree "$SCRIPT_DIR"; then
        SRC_DIR="$SCRIPT_DIR"
        ok "using the tree this script lives in: ${SRC_DIR}"
    else
        [ "$INTERNET" -eq 1 ] || die "no Internet and no local tree: use --source DIR|veyrs-<version>-src.tar.gz"
        if [ -n "$WANT_VERSION" ]; then VERSION="$WANT_VERSION"
        else VERSION="$(resolve_latest_version)" || die "could not resolve the latest release from ${API_LATEST} (use --version X.Y.Z)"; fi
        local tgz="veyrs-${VERSION}-src.tar.gz"
        WORK="$(mktemp -d /var/tmp/veyrs-setup.XXXXXX)"; chmod 700 "$WORK"
        info "downloading ${tgz} (release v${VERSION})"
        fetch -o "$WORK/$tgz" "${RELEASE_BASE}/v${VERSION}/${tgz}" || die "release v${VERSION} has no ${tgz} at ${RELEASE_BASE}"
        fetch -o "$WORK/$tgz.sha256" "${RELEASE_BASE}/v${VERSION}/${tgz}.sha256" \
            || die "release v${VERSION} has no ${tgz}.sha256 — refusing to install an unverifiable download"
        verify_sha256 "$WORK/$tgz" "$WORK/$tgz.sha256"
        ok "${tgz} verified (SHA-256)"
        extract_tarball "$WORK/$tgz"
    fi
    local tv; tv="$(tree_version "$SRC_DIR")"
    [ -n "$tv" ] || die "cannot read the version from ${SRC_DIR}/pyproject.toml"
    if [ -n "$WANT_VERSION" ] && [ "$tv" != "$WANT_VERSION" ]; then
        die "--version ${WANT_VERSION} was requested but the source is version ${tv}"
    fi
    VERSION="$tv"
    local m
    m="$(sed -n 's/^ *password_min_length: *int *= *\([0-9][0-9]*\).*/\1/p' "$SRC_DIR/backend/veyrs/config.py" 2>/dev/null | head -1)"
    [ -n "$m" ] && PW_MIN="$m"
    ok "VEYRS ${VERSION} (administrator password policy: >= ${PW_MIN} characters)"
}

# ─────────────────────────────────────────────────────────────────────────────
# External PostgreSQL — the role check, shared by both modes.
#
# 70 of VEYRS' 87 tables carry FORCE ROW LEVEL SECURITY: that is what keeps
# one tenant's data from another. A SUPERUSER or a BYPASSRLS role skips every
# policy silently — nothing errors, nothing logs — so such a role is refused,
# not warned about. The check runs through the same network path the
# application will use (the host for native, the stack network for Docker).
# ─────────────────────────────────────────────────────────────────────────────
DB_MODE="bundled"; DB_HOST=""; DB_PORT="5432"; DB_NAME="veyrs"; DB_USER="veyrs"; DB_PASS=""; DB_PASS_ENC=""
ROLE_SQL="select r.rolsuper, r.rolbypassrls,
  pg_get_userbyid(d.datdba) = current_user,
  pg_encoding_to_char(d.encoding),
  current_setting('server_version_num')::int
from pg_roles r, pg_database d
where r.rolname = current_user and d.datname = current_database()"

ask_external_db() {
    ask DB_HOST "PostgreSQL server (host name or address)" "" SETUP_DB_HOST
    ask DB_PORT "port" "5432" SETUP_DB_PORT
    [[ "$DB_PORT" =~ ^[0-9]+$ ]] || die "invalid port: $DB_PORT"
    ask DB_NAME "database" "veyrs" SETUP_DB_NAME
    ask DB_USER "role" "veyrs" SETUP_DB_USER
    [[ "$DB_NAME" =~ ^[A-Za-z0-9_.-]+$ ]] || die "database name '$DB_NAME': use letters, digits, _ . -"
    [[ "$DB_USER" =~ ^[A-Za-z0-9_.-]+$ ]] || die "role name '$DB_USER': use letters, digits, _ . -"
    ask_secret DB_PASS "password of role ${DB_USER}" SETUP_DB_PASSWORD
    [ -n "$DB_PASS" ] || die "the external role needs a password"
    [[ "$DB_PASS" == *"'"* ]] && die "the database password may not contain a single quote (')"
    [[ "$DB_PASS" == *[[:cntrl:]]* ]] && die "the database password may not contain control characters"
    DB_PASS_ENC="$(urlencode "$DB_PASS")"
    return 0
}

# evaluate_role "<psql -XtA -F| output>" — dies with the reason, or returns 0.
evaluate_role() {
    local out="$1" su bypass owner enc ver
    IFS='|' read -r su bypass owner enc ver <<<"$(printf '%s' "$out" | grep '|' | tail -1)"
    [ -n "${ver:-}" ] || die "unexpected answer from the role check: $(printf '%s' "$out" | tail -2 | tr '\n' ' ')"
    local refuse=""
    [ "$su" = t ] && refuse="${refuse}
     - role ${DB_USER} is a SUPERUSER"
    [ "$bypass" = t ] && refuse="${refuse}
     - role ${DB_USER} has BYPASSRLS"
    if [ -n "$refuse" ]; then
        die "REFUSED: the external database role would disable tenant isolation.${refuse}
     70 of VEYRS' 87 tables rely on FORCE ROW LEVEL SECURITY; a superuser or a
     BYPASSRLS role skips every policy silently. Use a dedicated role, created
     as the server's superuser:
       CREATE ROLE ${DB_USER} LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS PASSWORD '...';
       CREATE DATABASE ${DB_NAME} OWNER ${DB_USER} ENCODING 'UTF8' TEMPLATE template0;"
    fi
    ok "role ${DB_USER}: not superuser, no BYPASSRLS"
    [ "$owner" = t ] || die "role ${DB_USER} does not OWN database ${DB_NAME}. The schema step issues
     ALTER TABLE ... FORCE ROW LEVEL SECURITY and CREATE POLICY, which only the owner may do:
       ALTER DATABASE ${DB_NAME} OWNER TO ${DB_USER};"
    ok "role ${DB_USER} owns database ${DB_NAME}"
    [ "$enc" = UTF8 ] || die "database ${DB_NAME} is ${enc}, not UTF8. Advisories arrive in five languages and
     ${enc} corrupts them silently. Re-create it: ENCODING 'UTF8' TEMPLATE template0"
    ok "database ${DB_NAME} is UTF8"
    [ "$ver" -ge 150000 ] || die "PostgreSQL server version ${ver} is too old: VEYRS needs 15 or newer"
    ok "PostgreSQL server $((ver / 10000))"
}

# ─────────────────────────────────────────────────────────────────────────────
# Firewall (Docker mode; native hands --open-firewall to install.sh)
# ─────────────────────────────────────────────────────────────────────────────
WANT_FIREWALL=0
firewall_active() {
    { have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; } \
      || { have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; }
}
ask_firewall() {  # ask_firewall PORT
    if firewall_active; then
        if ask_yn "A host firewall is active. Open port $1/tcp for the console? (default: leave it closed)" n SETUP_FIREWALL; then WANT_FIREWALL=1; fi
    elif [ "${SETUP_FIREWALL:-no}" = yes ]; then
        info "SETUP_FIREWALL=yes but no active firewalld/ufw: nothing to open"
    fi
}
open_firewall_port() {  # open_firewall_port PORT
    [ "$WANT_FIREWALL" -eq 1 ] || return 0
    if have firewall-cmd && firewall-cmd --state >/dev/null 2>&1; then
        run_quiet firewall-cmd --permanent --add-port="$1/tcp"; run_quiet firewall-cmd --reload
        ok "firewalld: $1/tcp opened"
    elif have ufw && ufw status 2>/dev/null | grep -q 'Status: active'; then
        run_quiet ufw allow "$1/tcp"; ok "ufw: $1/tcp opened"
    fi
}

state_set() {  # state_set KEY VALUE — non-secret answers, for re-runs
    local tmp; tmp="$(mktemp /etc/.veyrs-setup.XXXXXX)"
    { [ -f "$STATE_FILE" ] && grep -v "^$1=" "$STATE_FILE" || true; printf '%s=%s\n' "$1" "$2"; } >"$tmp"
    chmod 600 "$tmp"; mv -f "$tmp" "$STATE_FILE"
}
state_get() { [ -f "$STATE_FILE" ] && sed -n "s/^$1=//p" "$STATE_FILE" | tail -1 || true; }

# Common identity questions.
SERVER_NAME=""; PUBLIC_URL=""; ENVIRONMENT=""; ORG=""; ORG_NAME=""; ADMIN_EMAIL=""
ask_org_admin() {
    ask ORG "first organization slug (lowercase, no spaces)" "veyrs" SETUP_ORG
    [[ "$ORG" =~ ^[a-z0-9][a-z0-9-]*$ ]] || die "organization slug '$ORG': lowercase letters, digits and -"
    ask ORG_NAME "organization display name" "$ORG" SETUP_ORG_NAME
    local def_mail="admin@veyrs.local"; [[ "$SERVER_NAME" == *.* ]] && def_mail="admin@${SERVER_NAME}"
    ask ADMIN_EMAIL "administrator e-mail" "$def_mail" SETUP_ADMIN_EMAIL
    [[ "$ADMIN_EMAIL" =~ ^[^@[:space:]]+@[^@[:space:]]+$ ]] || die "not an e-mail address: $ADMIN_EMAIL"
}
ask_environment() {
    local def=development; [[ "$PUBLIC_URL" == https://* ]] && def=production
    ask_choice ENVIRONMENT "environment" "production|development" "$def" SETUP_ENVIRONMENT
    if [ "$ENVIRONMENT" = production ] && [[ "$PUBLIC_URL" != https://* ]]; then
        die "production requires an https:// public URL (VEYRS refuses to boot otherwise: session
     cookies and tokens would cross the network in the clear). Give the https address
     of whatever terminates TLS in front of VEYRS, or choose development."
    fi
}

# Admin login check through the real front door. The JSON body goes to curl on
# stdin (printf is a builtin): the password never appears in any argv.
login_code() {  # login_code BASE_URL HOST_HEADER
    printf '{"organization":%s,"email":%s,"password":%s}' \
        "$(json_str "$ORG")" "$(json_str "$ADMIN_EMAIL")" "$(json_str "$ADMIN_PASS")" \
    | curl -s -o /dev/null -w '%{http_code}' --max-time 20 -H "Host: $2" \
        -H 'Content-Type: application/json' --data-binary @- "$1/api/v1/auth/login" || true
}

# ═════════════════════════════════════════════════════════════════════════════
# NATIVE
# ═════════════════════════════════════════════════════════════════════════════
native_env_get() { sed -n "s/^$1=//p" "$NATIVE_DIR/.env" 2>/dev/null | tail -1; }

# Does an administrator already exist? Asked as the APPLICATION role through
# the installed virtualenv: `users` is credential-keyed and its policy is
# permissive while no tenant is bound, which is the property login relies on.
# prints 1 / 0, or fails (unknown) — the caller treats unknown as "exists".
native_users_exist() {
    [ -x "$NATIVE_DIR/venv/bin/python" ] && [ -f "$NATIVE_DIR/.env" ] || return 1
    ( cd "$NATIVE_DIR" && PYTHONPATH="$NATIVE_DIR/backend" timeout 60 "$NATIVE_DIR/venv/bin/python" - <<'PY'
import logging, sys
logging.disable(logging.CRITICAL)
from sqlalchemy import create_engine, text
from veyrs.config import settings
eng = create_engine(settings.database_url, connect_args={"connect_timeout": 10})
with eng.connect() as c:
    if c.execute(text("select to_regclass('public.users') is not null")).scalar():
        print(1 if c.execute(text("select count(*) from users")).scalar() else 0)
    else:
        print(0)
PY
    ) 2>>"$LOG"
}

# Place the release in /opt/veyrs WITHOUT touching .env, var/ or venv/. Files
# the previous release shipped and this one does not are removed, using the
# manifest written by the previous run (so nothing the operator added is).
place_native_tree() {
    CURRENT_STEP="native: place the code in ${NATIVE_DIR}"
    local src_real dst_real=""
    src_real="$(cd "$SRC_DIR" && pwd -P)"
    [ -d "$NATIVE_DIR" ] && dst_real="$(cd "$NATIVE_DIR" && pwd -P)"
    if [ "$src_real" = "$dst_real" ]; then ok "running from ${NATIVE_DIR} itself: code already in place"; return 0; fi
    if [ -d "$NATIVE_DIR/.git" ]; then
        die "${NATIVE_DIR} is a git checkout. Update it with git and run ${NATIVE_DIR}/veyrs-setup.sh from it,
     instead of overwriting a working copy with a release tree."
    fi
    if [ -d "$NATIVE_DIR" ] && [ -n "$(ls -A "$NATIVE_DIR" 2>/dev/null)" ] && [ ! -d "$NATIVE_DIR/backend/veyrs" ]; then
        die "${NATIVE_DIR} exists, is not empty and is not VEYRS — refusing to write into it"
    fi
    mkdir -p "$NATIVE_DIR"
    local newlist; newlist="$(mktemp)"
    ( cd "$SRC_DIR" && find . \( -path ./.git -o -path ./venv -o -path ./var -o -name .env -o -name '__pycache__' \) -prune \
          -o \( -type f -o -type l \) -print | sed 's,^\./,,' | LC_ALL=C sort ) >"$newlist"
    tar -C "$SRC_DIR" -cf - -T "$newlist" | tar -C "$NATIVE_DIR" -xf -
    if [ -f "$NATIVE_DIR/.setup-manifest" ]; then
        local f n=0
        while IFS= read -r f; do
            [ -n "$f" ] || continue
            case "$f" in .env|var/*|venv/*|.setup-manifest) continue ;; esac
            if ! grep -qxF -- "$f" "$newlist" && [ -f "$NATIVE_DIR/$f" ]; then rm -f "$NATIVE_DIR/$f"; n=$((n+1)); fi
        done <"$NATIVE_DIR/.setup-manifest"
        [ "$n" -eq 0 ] || info "removed ${n} file(s) the previous release shipped and this one does not"
    fi
    install -m 600 "$newlist" "$NATIVE_DIR/.setup-manifest"; rm -f "$newlist"
    ok "VEYRS ${VERSION} code in ${NATIVE_DIR} (.env, var/ and venv/ untouched)"
}

install_native() {
    local skip_boot=0 fw_flag=0 update=0
    CURRENT_STEP="native: questions"
    say "NATIVE install (systemd + PostgreSQL + Redis + nginx on this machine)"
    [ "$EXISTING" = docker ] && die "this machine already runs VEYRS in Docker (same ports). Remove it first (--uninstall) or use another machine."

    if [ "$EXISTING" = native ]; then
        local ex
        ask_choice ex "VEYRS ${EXISTING_VERSION:-?} is installed natively. Install ${VERSION} over it (update), re-apply it (reinstall), or stop?" \
            "update|reinstall|abort" "update" SETUP_EXISTING
        [ "$ex" != abort ] || die "cancelled: the existing installation is untouched"
        update=1
        info "secrets, the database password and the administrator password are kept"
        # Everything the re-run needs comes from the installation itself.
        local url
        url="$(native_env_get VEYRS_DATABASE_URL)"
        [ -n "$url" ] || die "${NATIVE_DIR}/.env has no VEYRS_DATABASE_URL — not an installation this script can update"
        DB_USER="$(printf '%s' "$url" | sed -n 's#^[^:]*://\([^:]*\):.*#\1#p')"
        DB_PASS_ENC="$(printf '%s' "$url" | sed -n 's#^[^:]*://[^:]*:\(.*\)@[^@]*$#\1#p')"
        DB_PASS="$(urldecode "$DB_PASS_ENC")"
        DB_HOST="$(printf '%s' "$url" | sed -n 's#.*@\([^:/]*\):\([0-9]*\)/\(.*\)$#\1#p')"
        DB_PORT="$(printf '%s' "$url" | sed -n 's#.*@\([^:/]*\):\([0-9]*\)/\(.*\)$#\2#p')"
        DB_NAME="$(printf '%s' "$url" | sed -n 's#.*@\([^:/]*\):\([0-9]*\)/\(.*\)$#\3#p')"
        case "$DB_HOST" in 127.0.0.1|localhost|::1) DB_MODE=bundled ;; *) DB_MODE=external ;; esac
        PUBLIC_URL="$(native_env_get VEYRS_PUBLIC_BASE_URL)"
        ENVIRONMENT="$(native_env_get VEYRS_ENVIRONMENT)"
        SERVER_NAME="$(state_get SERVER_NAME)"; ORG="$(state_get ORG)"; ADMIN_EMAIL="$(state_get ADMIN_EMAIL)"
        [ -n "$SERVER_NAME" ] || SERVER_NAME="$(printf '%s' "$PUBLIC_URL" | sed -n 's#^[a-z]*://\([^/:]*\).*#\1#p')"
        info "database: ${DB_MODE} (${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}) · ${ENVIRONMENT:-?} · ${PUBLIC_URL:-?}"
        local n=""
        if n="$(native_users_exist)"; then :; else n=unknown; fi
        case "$n" in
            1) skip_boot=1; ADMIN_PASS_KEPT=1; ok "an administrator exists — bootstrap will NOT run (its password is unchanged)" ;;
            0) warn "no administrator exists yet (an earlier run stopped before creating it)"
               { [ -n "$ORG" ] && [ -n "$ADMIN_EMAIL" ]; } || ask_org_admin
               ask_admin_password ;;
            *) skip_boot=1; ADMIN_PASS_KEPT=1
               warn "could not tell whether an administrator exists — bootstrap skipped (never risk resetting a password)" ;;
        esac
    else
        say "Console"
        local def_name; def_name="$(hostname -f 2>/dev/null || hostname)"
        ask SERVER_NAME "host name of the console (nginx server_name)" "$def_name" SETUP_SERVER_NAME
        [[ "$SERVER_NAME" =~ ^[A-Za-z0-9_]([A-Za-z0-9.-]*[A-Za-z0-9])?$ ]] || die "invalid host name: $SERVER_NAME"
        info "nginx serves plain HTTP on port 80; put TLS in front of it (the public URL is that https address)"
        ask PUBLIC_URL "public base URL" "https://${SERVER_NAME}" SETUP_PUBLIC_URL
        [[ "$PUBLIC_URL" =~ ^https?://[^[:space:]]+$ ]] || die "invalid URL: $PUBLIC_URL"
        PUBLIC_URL="${PUBLIC_URL%/}"
        ask_environment
        say "First organization and administrator"
        ask_org_admin
        say "Database"
        info "bundled  : PostgreSQL installed on this machine by install.sh"
        info "external : a PostgreSQL 15+ server you already run (the role is checked before anything is installed)"
        ask_choice DB_MODE "PostgreSQL" "bundled|external" "bundled" SETUP_DB
        if [ "$DB_MODE" = external ]; then
            ask_external_db
            case "$DB_HOST" in 127.*|localhost|::1)
                die "an external database on THIS host is what 'bundled' is for; use SETUP_DB=bundled" ;; esac
        fi
        ask_admin_password
    fi

    if firewall_active; then
        if ask_yn "A host firewall is active. Open HTTP (80/tcp) for the console? (default: leave it closed)" n SETUP_FIREWALL; then fw_flag=1; fi
    fi

    if [ "$DB_MODE" = external ]; then
        CURRENT_STEP="native: check the external database"
        say "Checking the external database role (from this host, the path the API will use)"
        if ! have psql; then
            if [ "$DRY_RUN" -eq 1 ]; then
                warn "[dry-run] psql is not installed; a real run installs the client and checks the role here"
            else
                info "installing the PostgreSQL client"
                case "$OS_FAMILY" in
                    debian) run_quiet env DEBIAN_FRONTEND=noninteractive apt-get update -qq
                            run_quiet env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq postgresql-client ;;
                    rhel)   run_quiet "$PKG" -y install postgresql ;;
                    suse)   run_quiet zypper --non-interactive --gpg-auto-import-keys install -y postgresql16 \
                              || run_quiet zypper --non-interactive --gpg-auto-import-keys install -y postgresql ;;
                esac
                have psql || die "could not install the PostgreSQL client (psql)"
            fi
        fi
        if have psql; then
            local out
            out="$(PGPASSWORD="$DB_PASS" PGCONNECT_TIMEOUT=10 psql -h "$DB_HOST" -p "$DB_PORT" -U "$DB_USER" -d "$DB_NAME" \
                   -XtA -F'|' -v ON_ERROR_STOP=1 -c "$ROLE_SQL" 2>&1)" \
              || die "cannot log in to postgresql://${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME}:
     $(printf '%s' "$out" | redact | tail -2 | tr '\n' ' ')
     Check the password, listen_addresses, pg_hba.conf (it must admit ${NODE_IP:-this host} with
     scram-sha-256) and the database server's firewall."
            ok "login as ${DB_USER} works"
            evaluate_role "$out"
        fi
    fi

    say "Summary before installing"
    info "native · VEYRS ${VERSION} · $([ "$update" -eq 1 ] && echo "update of ${EXISTING_VERSION:-?}" || echo "new install") · database ${DB_MODE}"
    info "console ${PUBLIC_URL:-?} (nginx server_name ${SERVER_NAME:-_}) · ${ENVIRONMENT:-production}"
    [ "$DRY_RUN" -eq 1 ] && info "DRY RUN: install.sh --dry-run prints its plan and changes nothing"
    [ "$ASSUME_YES" -eq 1 ] || ask_yn "Continue?" y || die "cancelled"

    local dir="$NATIVE_DIR"
    if [ "$DRY_RUN" -eq 1 ]; then
        dir="$SRC_DIR"
    else
        place_native_tree
        state_set MODE native; state_set VERSION "$VERSION"
        state_set SERVER_NAME "$SERVER_NAME"
        [ -n "$ORG" ] && state_set ORG "$ORG"
        [ -n "$ADMIN_EMAIL" ] && state_set ADMIN_EMAIL "$ADMIN_EMAIL"
    fi

    CURRENT_STEP="native: install.sh"
    say "Running install.sh (several minutes on a new host; its output is also in ${LOG})"
    local args=(--unattended --dir "$dir")
    [ -n "$ENVIRONMENT" ] && args+=(--environment "$ENVIRONMENT")
    [ "$DB_MODE" = external ] && args+=(--skip-postgres)
    [ "$skip_boot" -eq 1 ] && args+=(--skip-bootstrap)
    [ "$fw_flag" -eq 1 ] && args+=(--open-firewall)
    [ "$DRY_RUN" -eq 1 ] && args+=(--dry-run)
    log_raw "install.sh ${args[*]}"
    # Every answer, the secrets included, travels as ENVIRONMENT: prefix
    # assignments on a builtin-free command line are not arguments, so none of
    # it is visible in ps(1). The external password goes percent-encoded,
    # because install.sh writes it verbatim into VEYRS_DATABASE_URL.
    local rc=0
    VEYRS_DIR="$dir" SERVER_NAME="$SERVER_NAME" PUBLIC_BASE_URL="$PUBLIC_URL" \
    ORG_SLUG="$ORG" ORG_NAME="${ORG_NAME:-$ORG}" ADMIN_EMAIL="$ADMIN_EMAIL" ADMIN_PASSWORD="$ADMIN_PASS" \
    DB_HOST="${DB_HOST:-127.0.0.1}" DB_PORT="$DB_PORT" DB_NAME="$DB_NAME" DB_USER="$DB_USER" \
    DB_PASSWORD="$([ "$DB_MODE" = external ] && printf '%s' "$DB_PASS_ENC")" \
        run_logged bash "$dir/install.sh" "${args[@]}" || rc=$?
    [ "$rc" -eq 0 ] || { CURRENT_STEP="native: install.sh (exit ${rc} — its message is above)"; false; }

    if [ "$DRY_RUN" -eq 1 ]; then
        SUMMARY_MODE="native — DRY RUN, nothing was changed"
        return 0
    fi

    CURRENT_STEP="native: verification"
    say "Verification"
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 http://127.0.0.1:8000/readyz || true)"
    [ "$code" = 200 ] || die "the API does not answer /readyz (got ${code}). Read: journalctl -u veyrs-api -n 50"
    ok "API ready (/readyz 200)"
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 -H "Host: ${SERVER_NAME}" http://127.0.0.1/ || true)"
    if [ "$code" = 200 ]; then ok "console served by nginx on port 80"; else warn "the console answered ${code} on port 80 (Host: ${SERVER_NAME})"; fi
    if [ "$ADMIN_PASS_KEPT" -eq 0 ] && [ -n "$ADMIN_PASS" ]; then
        code="$(login_code http://127.0.0.1:8000 "$SERVER_NAME")"
        if [ "$code" = 200 ]; then ok "administrator ${ADMIN_EMAIL} signs in with the chosen password"
        else die "the administrator could not sign in (HTTP ${code})"; fi
    fi
    SUMMARY_URL="${PUBLIC_URL}/   (nginx on http://${NODE_IP:-this-host}/, server_name ${SERVER_NAME})"
    SUMMARY_MODE="native (database ${DB_MODE})"
    SUMMARY_SECRETS="${NATIVE_DIR}/.env  <- BACK IT UP (VEYRS_ENCRYPTION_KEY cannot be regenerated)"
    SUMMARY_LOGS="systemctl status veyrs-api  ·  journalctl -u veyrs-api -f"
    SUMMARY_UNINSTALL="systemctl disable --now veyrs-api; remove ${NATIVE_DIR}, the nginx vhost and the database (see INSTALL.md)"
}

# ═════════════════════════════════════════════════════════════════════════════
# DOCKER
# ═════════════════════════════════════════════════════════════════════════════
COMPOSE_V=""
ensure_docker() {
    CURRENT_STEP="docker: engine"
    # A dry run must not install or start anything. Without a working engine
    # it says what WOULD happen and goes on to ask the questions and print the
    # plan; nothing below this point may assume Docker answers.
    if [ "$DRY_RUN" -eq 1 ] && ! { have docker && docker info >/dev/null 2>&1 && docker compose version >/dev/null 2>&1; }; then
        info "[dry-run] Docker Engine and/or Compose v2 would be installed or started here (nothing done)"
        return 0
    fi
    if have docker && docker info >/dev/null 2>&1; then
        ok "Docker $(docker version -f '{{.Server.Version}}' 2>/dev/null) running"
    else
        if ! have docker; then
            ask_yn "Docker is not installed. Install it now (Docker's packages; the distribution's on SUSE)?" y SETUP_INSTALL_DOCKER \
                || die "the Docker mode needs Docker"
            install_docker_pkgs
        fi
        run_quiet systemctl enable --now docker || die "the docker service does not start (journalctl -u docker)"
        timeout 60 bash -c 'until docker info >/dev/null 2>&1; do sleep 2; done' \
            || die "Docker is installed but does not answer. In an LXC container it needs nesting=1 (and keyctl=1 when unprivileged)."
        ok "Docker $(docker version -f '{{.Server.Version}}') running"
    fi
    if ! docker compose version >/dev/null 2>&1; then
        ask_yn "The Docker Compose v2 plugin is missing. Install it?" y SETUP_INSTALL_DOCKER || die "Compose v2 is required"
        case "$OS_FAMILY" in
            suse)   run_quiet zypper --non-interactive install -y docker-compose ;;
            debian) run_quiet env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-compose-plugin \
                      || run_quiet env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-compose-v2 ;;
            rhel)   run_quiet "$PKG" -y install docker-compose-plugin ;;
        esac
        docker compose version >/dev/null 2>&1 || die "could not install Docker Compose v2"
    fi
    COMPOSE_V="$(docker compose version --short 2>/dev/null | sed 's/^v//')"
    ver_ge "$COMPOSE_V" 2.20.0 || die "Docker Compose ${COMPOSE_V} is too old (2.20 or newer)"
    ok "Docker Compose ${COMPOSE_V}"
}
install_docker_pkgs() {
    CURRENT_STEP="docker: install packages"
    info "installing Docker (${OS_FAMILY}) — output in ${LOG}"
    case "$OS_FAMILY" in
        suse)
            run_quiet zypper --non-interactive --gpg-auto-import-keys refresh || true
            run_quiet zypper --non-interactive install -y docker docker-compose ;;
        debian)
            run_quiet env DEBIAN_FRONTEND=noninteractive apt-get update -qq
            run_quiet env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq ca-certificates curl gnupg
            install -m 0755 -d /etc/apt/keyrings
            fetch "https://download.docker.com/linux/${OS_ID}/gpg" -o /etc/apt/keyrings/docker.asc
            chmod a+r /etc/apt/keyrings/docker.asc
            local codename
            # shellcheck disable=SC1091
            codename="$(. /etc/os-release; printf '%s' "${VERSION_CODENAME:-}")"
            printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
                "$(dpkg --print-architecture)" "$OS_ID" "$codename" >/etc/apt/sources.list.d/docker.list
            run_quiet env DEBIAN_FRONTEND=noninteractive apt-get update -qq
            run_quiet env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin ;;
        rhel)
            local repo=centos; [ "$OS_ID" = rhel ] && repo=rhel; [ "$OS_ID" = fedora ] && repo=fedora
            fetch -o /etc/yum.repos.d/docker-ce.repo "https://download.docker.com/linux/${repo}/docker-ce.repo"
            run_quiet "$PKG" -y install docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin ;;
        *) die "no recipe to install Docker on ${OS_NAME}: install Docker Engine + the Compose plugin, then re-run" ;;
    esac
    have docker || die "Docker packages installed but no docker binary (read ${LOG})"
    ok "Docker packages installed"
}

env_get() { [ -f "$DOCKER_ENV" ] && sed -n "s/^$1=//p" "$DOCKER_ENV" | tail -1 | sed "s/^'\(.*\)'\$/\1/" || true; }
env_set() {  # env_set KEY VALUE — replaces the key in place, or appends it
    local k="$1" v="$2" tmp
    [ "$(env_get "$k")" = "$v" ] && grep -q "^$k=" "$DOCKER_ENV" && return 0   # unchanged: leave the file (and its md5) alone
    tmp="$(mktemp "$DOCKER_HOME/.env.XXXXXX")"
    V="$v" awk -v k="$k" 'BEGIN { done = 0 }
        $0 ~ "^" k "=" { if (!done) { print k "=" ENVIRON["V"]; done = 1 }; next }
        { print } END { if (!done) print k "=" ENVIRON["V"] }' "$DOCKER_ENV" >"$tmp"
    chmod 600 "$tmp"; mv -f "$tmp" "$DOCKER_ENV"
}
# A value compose must take literally (a password may hold $, # or spaces).
# Single quotes are literal in a compose .env; a single quote itself is refused.
env_set_literal() { env_set "$1" "'$2'"; }

compose_cmd() {  # the same file set veyrs-docker.sh builds from VEYRS_COMPOSE_OVERLAYS
    local d="$DOCKER_HOME/current/docker" ov
    COMPOSE=(docker compose --project-directory "$d" -f "$d/compose.yaml")
    for ov in $(env_get VEYRS_COMPOSE_OVERLAYS | tr -d "'\","); do COMPOSE+=(-f "$d/$ov"); done
}

place_docker_tree() {
    CURRENT_STEP="docker: place release ${VERSION}"
    local dest="$DOCKER_HOME/releases/$VERSION"
    mkdir -p "$DOCKER_HOME/releases"; chmod 700 "$DOCKER_HOME"
    rm -rf "$dest.tmp"; mkdir -p "$dest.tmp"
    ( cd "$SRC_DIR" && find . \( -path ./.git -o -path ./venv -o -path ./var -o -name .env -o -name '__pycache__' \) -prune \
          -o \( -type f -o -type l \) -print ) | tar -C "$SRC_DIR" -cf - -T - | tar -C "$dest.tmp" -xf -
    chmod +x "$dest.tmp"/docker/*.sh "$dest.tmp"/docker/initdb.d/*.sh 2>/dev/null || true
    rm -rf "$dest"; mv "$dest.tmp" "$dest"
    ln -sfn "$dest" "$DOCKER_HOME/current"
    ok "release ${VERSION} in ${dest}"
}

link_env_and_wrapper() {
    ln -sfn "$DOCKER_ENV" "$DOCKER_HOME/current/docker/.env"
    cat >"$WRAPPER" <<WRAP
#!/usr/bin/env bash
# veyrs-docker — docker/veyrs-docker.sh of the release installed by veyrs-setup.sh.
#   veyrs-docker status | ps | logs -f api | backup | cli ... | down
exec "$DOCKER_HOME/current/docker/veyrs-docker.sh" "\$@"
WRAP
    chmod 755 "$WRAPPER"
}

# write_docker_env — secrets once (never regenerated), then the answers.
write_docker_env() {
    CURRENT_STEP="docker: configuration"
    local D="$DOCKER_HOME/current/docker"
    if [ ! -f "$DOCKER_ENV" ]; then
        # Same generators as `veyrs-docker.sh init`; not `init` itself, because it
        # prints the admin password to stdout, which here is also the log.
        ( umask 077
          sed -e "s|^POSTGRES_PASSWORD=.*|POSTGRES_PASSWORD=$(rand_hex 24)|" \
              -e "s|^VEYRS_DB_PASSWORD=.*|VEYRS_DB_PASSWORD=$(rand_hex 24)|" \
              -e "s|^VEYRS_SECRET_KEY=.*|VEYRS_SECRET_KEY=$(rand_urlsafe 48)|" \
              -e "s|^VEYRS_ENCRYPTION_KEY=.*|VEYRS_ENCRYPTION_KEY=$(head -c 32 /dev/urandom | base64 -w0 | tr '+/' '-_')|" \
              -e "s|^VEYRS_ADMIN_PASSWORD=.*|VEYRS_ADMIN_PASSWORD=|" \
              "$D/env.example" >"$DOCKER_ENV" )
        chmod 600 "$DOCKER_ENV"
        ok "secrets generated in ${DOCKER_ENV} (0600)"
    else
        chmod 600 "$DOCKER_ENV"
        ok "existing secrets in ${DOCKER_ENV} reused (never regenerated)"
    fi
    # The admin password is NOT kept in .env: it reaches `init` through the
    # environment of the one `up` that creates the account, and is not needed
    # again (init.sh finds the account and leaves it alone).
    env_set VEYRS_ADMIN_PASSWORD ""
    env_set VEYRS_ADMIN_ORG "$ORG"
    [[ "${ORG_NAME:-}" == *"'"* ]] && die "the organization display name may not contain a single quote in Docker mode"
    env_set_literal VEYRS_ADMIN_NAME "${ORG_NAME:-$ORG}"
    env_set VEYRS_ADMIN_EMAIL "$ADMIN_EMAIL"
    env_set VEYRS_HTTP_BIND "$HTTP_BIND"
    env_set VEYRS_ENVIRONMENT "$ENVIRONMENT"
    env_set VEYRS_PUBLIC_BASE_URL "$PUBLIC_URL"
    env_set VEYRS_CORS_ORIGINS "$PUBLIC_URL"
    env_set TZ "$(timedatectl show -p Timezone --value 2>/dev/null || echo UTC)"
    env_set VEYRS_SETUP_WORKERS "$WORKERS"
    env_set VEYRS_SETUP_AGENT "$AGENT"
    [ -n "$AGENT_ALLOW" ] && env_set VEYRS_AGENT_ALLOW "$AGENT_ALLOW"
    [ -n "$AGENT_TOKEN" ] && env_set_literal VEYRS_AGENT_TOKEN "$AGENT_TOKEN"
    if [ "$DB_MODE" = external ]; then
        env_set VEYRS_COMPOSE_OVERLAYS compose.external-db.yaml
        env_set VEYRS_EXT_DB_HOST "$DB_HOST"
        env_set VEYRS_EXT_DB_PORT "$DB_PORT"
        env_set VEYRS_DB_USER "$DB_USER"
        env_set VEYRS_DB_NAME "$DB_NAME"
        env_set_literal VEYRS_DB_PASSWORD "$DB_PASS"
        env_set VEYRS_EXT_DATABASE_URL "postgresql+psycopg://$(urlencode "$DB_USER"):${DB_PASS_ENC}@${DB_HOST}:${DB_PORT}/$(urlencode "$DB_NAME")"
    else
        env_set VEYRS_COMPOSE_OVERLAYS ""
    fi
    env_set VEYRS_IMAGE "veyrs:${VERSION}"
    env_set VEYRS_CONSOLE_IMAGE "veyrs-console:${VERSION}"
    env_set VEYRS_AGENT_IMAGE "veyrs-agent:${VERSION}"
    ok "configuration written"
}

# The external role check, run from a container ON THE STACK NETWORK — the
# source address and the route the API will have. pg_hba.conf must admit it.
# The password is read inside the container from its compose environment
# (from .env); it is never on a command line.
docker_psql() {  # docker_psql SQL -> stdout
    compose_cmd
    "${COMPOSE[@]}" run --rm --no-deps -T --entrypoint sh postgres -c \
        'PGPASSWORD="$VEYRS_DB_PASSWORD" PGCONNECT_TIMEOUT=10 psql -h "$VEYRS_EXT_DB_HOST" -p "$VEYRS_EXT_DB_PORT" -U "$VEYRS_DB_USER" -d "$VEYRS_DB_NAME" -XtA -F"|" -v ON_ERROR_STOP=1 -c "$1"' \
        sh "$1" 2>&1
}

# bundled_users_exist -> prints 1 (an administrator exists), 0 (no users table
# or no rows), or ? (the cluster could not be asked). Starts only `postgres`
# (which `up` starts anyway) and asks as the cluster superuser over the local
# socket — `users` is RLS-forced, and the superuser sees every row.
bundled_users_exist() {
    local db n
    db="$(env_get VEYRS_DB_NAME)"; db="${db:-veyrs}"
    run_quiet "${COMPOSE[@]}" up -d postgres || { echo '?'; return 0; }
    if ! timeout 90 bash -c 'until "$@" exec -T postgres psql -U postgres -d postgres -tAc "select 1" >/dev/null 2>&1; do sleep 2; done' \
            _ "${COMPOSE[@]}"; then
        echo '?'; return 0
    fi
    # initdb.d creates the application database on the first start; until it
    # exists there is certainly no administrator.
    n="$("${COMPOSE[@]}" exec -T postgres psql -U postgres -d postgres -tAc \
          "select count(*) from pg_database where datname = '${db}'" 2>/dev/null | tr -d '[:space:]')" || { echo '?'; return 0; }
    [ "$n" = 1 ] || { echo 0; return 0; }
    n="$("${COMPOSE[@]}" exec -T postgres psql -U postgres -d "$db" -tAc \
          "select case when to_regclass('public.users') is null then 0 else (select count(*) from users) end" 2>/dev/null | tr -d '[:space:]')" \
        || { echo '?'; return 0; }
    case "$n" in 0) echo 0 ;; [1-9]*) echo 1 ;; *) echo '?' ;; esac
}

wait_ready() {  # wait_ready BIND
    CURRENT_STEP="docker: wait for readiness"
    timeout 180 bash -c "until curl -sfo /dev/null --max-time 5 'http://$1/readyz'; do sleep 3; done" \
        || die "the stack did not become ready on http://$1/readyz within 3 minutes (veyrs-docker status; veyrs-docker logs init api)"
    ok "ready: http://$1/readyz 200"
}

HTTP_BIND=""; WORKERS="no"; AGENT="no"; AGENT_ALLOW=""; AGENT_TOKEN=""
install_docker() {
    local update=0 data_exists=0
    CURRENT_STEP="docker: questions"
    say "DOCKER install (the whole VEYRS stack in containers)"
    [ "$EXISTING" = native ] && die "this machine already runs VEYRS natively (same ports). Use another machine."
    ensure_docker

    if [ "$EXISTING" = docker ]; then
        local ex
        ask_choice ex "VEYRS ${EXISTING_VERSION:-?} runs in Docker here. Install ${VERSION} over it (update), re-apply it (reinstall), or stop?" \
            "update|reinstall|abort" "update" SETUP_EXISTING
        [ "$ex" != abort ] || die "cancelled: the existing installation is untouched"
        update=1
    fi

    if [ "$update" -eq 1 ] || [ "$DOCKER_PARTIAL" -eq 1 ]; then
        # Everything comes from the existing .env; nothing is asked again.
        HTTP_BIND="$(env_get VEYRS_HTTP_BIND)"; PUBLIC_URL="$(env_get VEYRS_PUBLIC_BASE_URL)"
        ENVIRONMENT="$(env_get VEYRS_ENVIRONMENT)"; ORG="$(env_get VEYRS_ADMIN_ORG)"; ORG_NAME="$(env_get VEYRS_ADMIN_NAME)"; ADMIN_EMAIL="$(env_get VEYRS_ADMIN_EMAIL)"
        WORKERS="$(env_get VEYRS_SETUP_WORKERS)"; AGENT="$(env_get VEYRS_SETUP_AGENT)"
        AGENT_ALLOW="$(env_get VEYRS_AGENT_ALLOW)"; AGENT_TOKEN="$(env_get VEYRS_AGENT_TOKEN)"
        : "${WORKERS:=no}" "${AGENT:=no}"
        if [ -n "$(env_get VEYRS_COMPOSE_OVERLAYS)" ]; then
            DB_MODE=external; DB_HOST="$(env_get VEYRS_EXT_DB_HOST)"; DB_PORT="$(env_get VEYRS_EXT_DB_PORT)"
            DB_USER="$(env_get VEYRS_DB_USER)"; DB_NAME="$(env_get VEYRS_DB_NAME)"; DB_PASS="$(env_get VEYRS_DB_PASSWORD)"
            DB_PASS_ENC="$(urlencode "$DB_PASS")"
        fi
        [ -n "$HTTP_BIND" ] && [ -n "$ORG" ] || die "${DOCKER_ENV} is incomplete; move it away to start over (it holds the keys of any existing data)"
        info "kept settings: console ${HTTP_BIND} · ${ENVIRONMENT} · database ${DB_MODE} · workers ${WORKERS} · agent ${AGENT}"
    else
        say "Console"
        info "The console is plain HTTP. Published on 127.0.0.1 it is reachable from this machine only"
        info "(put a TLS reverse proxy in front); 0.0.0.0:PORT publishes it on every interface."
        warn "ports Docker publishes BYPASS ufw/firewalld rules — publish on 0.0.0.0 only if you mean it"
        ask HTTP_BIND "publish the console on (address:port)" "127.0.0.1:8080" SETUP_HTTP_BIND
        [[ "$HTTP_BIND" =~ ^[0-9.]+:[0-9]+$ ]] || die "expected ADDRESS:PORT, got '$HTTP_BIND'"
        local port="${HTTP_BIND##*:}" host="${HTTP_BIND%:*}" o
        o="$(port_owner "$port")"
        [ -z "$o" ] || [ "$o" = docker-proxy ] || die "port ${port} is in use by '${o}'"
        local def_url="http://localhost:${port}"
        [ "$host" = 0.0.0.0 ] && def_url="http://${NODE_IP:-localhost}:${port}"
        ask PUBLIC_URL "public base URL (the https address of your TLS proxy, if any)" "$def_url" SETUP_PUBLIC_URL
        [[ "$PUBLIC_URL" =~ ^https?://[^[:space:]]+$ ]] || die "invalid URL: $PUBLIC_URL"
        PUBLIC_URL="${PUBLIC_URL%/}"
        SERVER_NAME="$(printf '%s' "$PUBLIC_URL" | sed -n 's#^[a-z]*://\([^/:]*\).*#\1#p')"
        ask_environment
        say "First organization and administrator"
        ask_org_admin

        say "Database"
        info "bundled  : PostgreSQL 15 inside the stack (data in the volume ${COMPOSE_PROJECT}_veyrs-pgdata)"
        info "external : a PostgreSQL 15+ server you already run (checked from the stack network before start)"
        ask_choice DB_MODE "PostgreSQL" "bundled|external" "bundled" SETUP_DB
        if [ "$DB_MODE" = external ]; then
            ask_external_db
            case "$DB_HOST" in localhost|127.*|::1)
                DB_HOST="host.docker.internal"
                warn "a database on THIS host is reached as host.docker.internal: PostgreSQL must listen on the Docker bridge address and pg_hba.conf admit the stack subnet" ;;
            esac
        fi

        say "Background workers (profile 'workers': intel + digest)"
        info "intel downloads the NVD corpus on first start — HOURS of traffic against a feed that"
        info "rate-limits per source address — then refreshes NVD/EPSS/KEV and advances SLA clocks."
        warn "WITHOUT the workers the vulnerability data never refreshes and SLA deadlines never elapse;"
        warn "nothing in the console shows it. Turn them on for any install you intend to keep."
        if ask_yn "Enable the workers?" n SETUP_WORKERS; then WORKERS=yes; fi

        say "Scanner agent (profile 'agent')"
        info "The agent is the one component that sends UNSOLICITED scan traffic to other machines."
        info "It is deny-by-default: it scans only what its allowlist names, and it needs a token that"
        info "you mint in the console after the install (Settings -> Agents)."
        if ask_yn "Enable the scanner agent?" n SETUP_AGENT; then
            AGENT=yes
            ask AGENT_ALLOW "allowlist (comma-separated hosts, *.wildcards, CIDRs)" "" SETUP_AGENT_ALLOW
            if [ -n "${SETUP_AGENT_TOKEN:-}" ]; then AGENT_TOKEN="$SETUP_AGENT_TOKEN"
            elif [ "$ASSUME_YES" -eq 0 ]; then ask_secret AGENT_TOKEN "agent token (empty = add it later and re-run)" ""; fi
            [[ "$AGENT_TOKEN" == *"'"* ]] && die "the agent token may not contain a single quote"
            [ -n "$AGENT_TOKEN" ] || warn "no token yet: the agent stays OFF until you mint one, add VEYRS_AGENT_TOKEN to ${DOCKER_ENV} and re-run"
        fi
        ask_firewall "$port"

        say "Summary before installing"
        info "Docker · VEYRS ${VERSION} · database ${DB_MODE} · workers ${WORKERS} · agent ${AGENT}"
        info "console published on ${HTTP_BIND} · public URL ${PUBLIC_URL} · ${ENVIRONMENT}"
        [ "$ASSUME_YES" -eq 1 ] || ask_yn "Continue?" y || die "cancelled"
    fi
    if [ "$DRY_RUN" -eq 1 ]; then
        say "DRY RUN (Docker mode): nothing was changed. The plan is the summary above."
        SUMMARY_MODE="docker — DRY RUN, nothing was changed"; return 0
    fi

    # ── Install ─────────────────────────────────────────────────────────────
    place_docker_tree
    write_docker_env
    link_env_and_wrapper
    compose_cmd
    CURRENT_STEP="docker: validate compose configuration"
    run_quiet "${COMPOSE[@]}" config -q || die "the compose configuration is invalid (details at the end of ${LOG})"
    ok "compose configuration valid"

    if [ "$DB_MODE" = external ]; then
        CURRENT_STEP="docker: check the external database"
        say "Checking the external database role (from the stack network, the path the API will use)"
        local out
        out="$(docker_psql "$ROLE_SQL")" || die "cannot log in to postgresql://${DB_USER}@${DB_HOST}:${DB_PORT}/${DB_NAME} from the stack network:
     $(printf '%s' "$out" | redact | tail -2 | tr '\n' ' ')
     Check the password, listen_addresses, pg_hba.conf (it must admit this host — containers
     reach it NATed from ${NODE_IP:-this host}, or the stack subnet $(env_get VEYRS_SUBNET) for a
     database on this host) and the database server's firewall."
        ok "login as ${DB_USER} works"
        evaluate_role "$out"
        local has; has="$(docker_psql "select to_regclass('public.users') is not null")" || has=""
        if printf '%s' "$has" | grep -qx t; then
            local n; n="$(docker_psql "select count(*) from users" | grep -E '^[0-9]+$' | tail -1)" || n=""
            [ "${n:-0}" -gt 0 ] && data_exists=1
        fi
    elif docker volume inspect "${COMPOSE_PROJECT}_veyrs-pgdata" >/dev/null 2>&1; then
        # The volume existing is NOT proof of an administrator: `compose run`
        # (the external-role probe) and a first run that stopped before `init`
        # both leave it behind, empty or without users. Treating that as data
        # skipped the password, `init` then refused (no admin, no password)
        # and every re-run hit the same wall. So ask the cluster itself.
        data_exists="$(bundled_users_exist)"
        case "$data_exists" in
            1) ;;
            0) info "data volume present but no administrator in it yet" ;;
            *) data_exists=1
               warn "could not tell whether an administrator exists — treating it as existing (never risk resetting a password)" ;;
        esac
    fi

    if [ "$data_exists" -eq 1 ]; then
        ADMIN_PASS_KEPT=1
        ok "existing data found: the administrator account is kept and its password is unchanged"
    else
        ask_admin_password
    fi

    CURRENT_STEP="docker: build and start (veyrs-docker.sh up)"
    local up_args=()
    [ "$WORKERS" = yes ] && up_args+=(--with-workers)
    if [ "$AGENT" = yes ]; then
        if [ -n "$(env_get VEYRS_AGENT_TOKEN)" ] && [ -n "$(env_get VEYRS_AGENT_ALLOW)" ]; then up_args+=(--with-agent)
        else warn "agent requested but token/allowlist missing: not started"; fi
    fi
    say "Building the images and starting the stack (5–15 min the first time; output in ${LOG})"
    # The first administrator's password reaches compose through this
    # process's ENVIRONMENT, which takes precedence over .env for ${...}
    # interpolation. It is not written to .env and not on any command line.
    local rc=0
    VEYRS_ADMIN_PASSWORD="$ADMIN_PASS" run_quiet "$DOCKER_HOME/current/docker/veyrs-docker.sh" up "${up_args[@]}" || rc=$?
    if [ "$rc" -ne 0 ]; then
        tail -25 "$LOG" | sed 's/^/      /'
        die "veyrs-docker.sh up failed (exit ${rc}). Full output in ${LOG}; state: veyrs-docker status"
    fi
    wait_ready "$HTTP_BIND"
    local initlog; initlog="$("${COMPOSE[@]}" logs --no-log-prefix init 2>/dev/null | tail -5 || true)"
    printf '%s\n' "$initlog" | redact | sed 's/^/      init: /' | tee -a "$LOG" >/dev/null

    CURRENT_STEP="docker: verification"
    local code
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${HTTP_BIND}/" || true)"
    [ "$code" = 200 ] && ok "console answers on http://${HTTP_BIND}/" || warn "console answered ${code} on http://${HTTP_BIND}/"
    code="$(curl -s -o /dev/null -w '%{http_code}' --max-time 10 "http://${HTTP_BIND}/api/v1/assets" || true)"
    case "$code" in 401|403) ok "unauthenticated API refused (${code})" ;;
        *) die "unauthenticated /api/v1/assets answered ${code}, expected 401. DO NOT EXPOSE THIS HOST." ;; esac
    if [ "$ADMIN_PASS_KEPT" -eq 0 ]; then
        code="$(login_code "http://${HTTP_BIND}" "${HTTP_BIND%:*}")"
        [ "$code" = 200 ] && ok "administrator ${ADMIN_EMAIL} signs in with the chosen password" \
            || die "the administrator could not sign in (HTTP ${code}); read: veyrs-docker logs init"
    fi
    open_firewall_port "${HTTP_BIND##*:}"
    touch "$DOCKER_HOME/.installed"
    state_set MODE docker; state_set VERSION "$VERSION"

    SUMMARY_URL="${PUBLIC_URL}/   (published on http://${HTTP_BIND}/)"
    SUMMARY_MODE="docker (database ${DB_MODE}, workers ${WORKERS}, agent ${AGENT})"
    SUMMARY_SECRETS="${DOCKER_ENV}  <- BACK IT UP (VEYRS_ENCRYPTION_KEY cannot be regenerated)"
    SUMMARY_LOGS="veyrs-docker status  ·  veyrs-docker logs -f api"
    SUMMARY_UNINSTALL="bash veyrs-setup.sh --uninstall   (keeps the data; add --purge to delete it)"
}

uninstall_docker() {
    CURRENT_STEP="uninstall"
    [ -f "$DOCKER_ENV" ] && [ -x "$DOCKER_HOME/current/docker/veyrs-docker.sh" ] \
        || die "no Docker installation of VEYRS in ${DOCKER_HOME} (a native install is removed by hand: see INSTALL.md)"
    have docker || die "docker is not installed"
    say "Uninstall VEYRS (Docker)"
    local drv="$DOCKER_HOME/current/docker/veyrs-docker.sh"
    if [ "$PURGE" -eq 1 ]; then
        warn "--purge DELETES the database, the documents volume and the secrets. There is no way back."
        local c=""
        if [ "$ASSUME_YES" -eq 1 ]; then c=PURGE; else read -rp "    Type PURGE to confirm: " c </dev/tty || true; fi
        [ "$c" = PURGE ] || die "cancelled: nothing was removed"
        run_quiet "$drv" down --volumes --remove-orphans || die "compose down failed (see ${LOG})"
        local imgs
        imgs="$(docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -E '^(veyrs|veyrs-console|veyrs-agent):' || true)"
        [ -z "$imgs" ] || printf '%s\n' "$imgs" | xargs -r docker image rm >>"$LOG" 2>&1 || true
        rm -rf "$DOCKER_HOME" "$WRAPPER" "$STATE_FILE" "$PW_FILE"
        ok "containers, volumes, veyrs images, ${DOCKER_HOME} and the secrets removed"
    else
        run_quiet "$drv" down --remove-orphans || die "compose down failed (see ${LOG})"
        rm -f "$DOCKER_HOME/.installed"
        ok "containers stopped and removed. Data KEPT: volumes ${COMPOSE_PROJECT}_* and ${DOCKER_ENV}"
        info "installing again (bash veyrs-setup.sh) finds and reuses them; --uninstall --purge deletes them"
    fi
    log_raw "UNINSTALL OK purge=${PURGE}"
    exit 0
}

# ═════════════════════════════════════════════════════════════════════════════
# Main
# ═════════════════════════════════════════════════════════════════════════════
SUMMARY_MODE=""; SUMMARY_URL=""; SUMMARY_SECRETS=""; SUMMARY_LOGS=""; SUMMARY_UNINSTALL=""

echo "${c_b}VEYRS — guided installer ${SETUP_SELF_VERSION}${c_0}$([ "$LOG_ON" -eq 1 ] && printf '   (log: %s)' "$LOG")"
[ "$UNINSTALL" -eq 1 ] && uninstall_docker

detect_os
check_requirements
detect_existing

if [ "$CHECK_ONLY" -eq 1 ]; then
    CURRENT_STEP="check"
    say "Source"
    if [ -n "$SOURCE_ARG" ]; then info "--source ${SOURCE_ARG}"
    elif is_tree "$SCRIPT_DIR"; then ok "this script sits in a VEYRS tree (version $(tree_version "$SCRIPT_DIR")): it would install that"
    elif [ "$INTERNET" -eq 1 ]; then
        if v="$(resolve_latest_version)"; then ok "latest release: v${v}"; else warn "no published release found at ${API_LATEST}"; fi
    else warn "no local tree and no Internet: an install would need --source"; fi
    say "Check only (--check): nothing was installed or changed."
    exit 0
fi

ensure_tools
resolve_source

CURRENT_STEP="4 · mode"
say "Step 4 · Installation type"
info "native : VEYRS directly on this machine (systemd, PostgreSQL, Redis, nginx) via install.sh"
info "docker : the whole stack in containers via docker/veyrs-docker.sh"
DEF_MODE=native; { [ "$EXISTING" = docker ] || [ "$DOCKER_PARTIAL" -eq 1 ]; } && DEF_MODE=docker
if [ -n "$EXISTING" ]; then
    MODE="$EXISTING"; info "mode: ${MODE} (the existing installation)"
    [ -z "${SETUP_MODE:-}" ] || [ "$SETUP_MODE" = "$MODE" ] || die "SETUP_MODE=${SETUP_MODE} but this host has a ${MODE} installation"
elif [ "$ASSUME_YES" -eq 1 ] && [ -z "${SETUP_MODE:-}" ] && [ "$DOCKER_PARTIAL" -eq 0 ]; then
    die "--yes needs SETUP_MODE=native|docker on a host with no installation"
else
    ask_choice MODE "native or docker?" "native|docker" "$DEF_MODE" SETUP_MODE
fi

if [ "$MODE" = native ]; then install_native; else install_docker; fi

# ─────────────────────────────────────────────────────────────────────────────
# Final summary
# ─────────────────────────────────────────────────────────────────────────────
CURRENT_STEP="summary"
if [ "$DRY_RUN" -eq 1 ]; then
    echo; echo "${c_g}${c_b}Dry run finished.${c_0} ${SUMMARY_MODE}"; log_raw "END dry-run"; exit 0
fi
SUMMARY="/root/veyrs-setup-summary.txt"
{
    echo "VEYRS ${VERSION} — $(date '+%F %T')"
    echo "  Mode ............ ${SUMMARY_MODE}"
    echo "  Console ......... ${SUMMARY_URL}"
    echo "  Sign in as ...... ${ADMIN_EMAIL:-the existing administrator}${ORG:+ (organization ${ORG})}"
    if [ "$ADMIN_PASS_KEPT" -eq 1 ]; then
        echo "  Password ........ unchanged (the existing administrator's)"
    elif [ "$ADMIN_PASS_GENERATED" -eq 1 ]; then
        echo "  Password ........ in ${PW_FILE} (0600) — change it after signing in, then delete the file"
    else
        echo "  Password ........ the one you entered"
    fi
    echo "  Secrets ......... ${SUMMARY_SECRETS}"
    echo "  Setup log ....... ${LOG}"
    echo "  Logs / state .... ${SUMMARY_LOGS}"
    echo "  Uninstall ....... ${SUMMARY_UNINSTALL}"
    if [ "$MODE" = docker ] && [ "$WORKERS" != yes ]; then
        echo "  WARNING ......... workers are OFF: vulnerability intelligence does not refresh and SLA"
        echo "                    clocks do not advance. Enable: SETUP_WORKERS=yes on a re-run, or"
        echo "                    veyrs-docker up --with-workers"
    fi
} | tee "$SUMMARY"
chmod 600 "$SUMMARY"
echo
echo "${c_g}${c_b}Done.${c_0} Summary saved in ${SUMMARY}"
log_raw "END OK"
