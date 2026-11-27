#!/usr/bin/env bash
# VEYRS offline update (shipped as update.sh in veyrs-<version>-update.tar).
#
#   sudo bash update.sh              update what is installed (or install)
#   sudo bash update.sh --dry-run    print the plan, change nothing
#   sudo bash update.sh --check      check this machine, change nothing
#
# Everything it needs is in this directory: the signed release (SHA256SUMS,
# SHA256SUMS.sig, veyrs-setup.sh, veyrs-<v>-src.tar.gz). No Internet, no PyPI.
#
# Python packages: the update package carries the wheels only when the
# release changes them. Without veyrs-<v>-wheels-x86_64.tar.gz beside this
# script, a native update goes ahead only if the installed packages already
# match the new requirements.txt, and that is checked BEFORE anything is
# changed. Copy the wheels file of the same release beside it otherwise.
#
# Docker installs need the image bundle of the same release
# (veyrs-images-<v>-amd64.tar.gz) beside this script.
#
# What it does:
#   1. checks every file (SHA256SUMS; the installer then checks its signature);
#   2. finds what is installed: native (/opt/veyrs), Docker (/opt/veyrs-docker)
#      or nothing;
#   3. on an update, BACKS UP FIRST into /var/backups/veyrs (database dump as
#      the superuser + configuration), and stops if the backup fails;
#   4. runs veyrs-setup.sh with no questions: data, secrets and the
#      administrator's password are kept;
#   5. checks that the service answers with the new version.
#
# Environment (optional): VEYRS_BACKUP_DIR (default /var/backups/veyrs),
# VEYRS_SKIP_DB_BACKUP=1 (only for an EXTERNAL database you back up yourself),
# and any SETUP_* answer of veyrs-setup.sh (see: bash veyrs-setup.sh --help).
set -euo pipefail

HERE="$(cd "$(dirname "$(readlink -f "${BASH_SOURCE[0]}")")" && pwd)"
NATIVE_DIR="${VEYRS_NATIVE_DIR:-/opt/veyrs}"
DOCKER_HOME="${VEYRS_DOCKER_HOME:-/opt/veyrs-docker}"
BACKUP_DIR="${VEYRS_BACKUP_DIR:-/var/backups/veyrs}"
TS="$(date +%Y%m%d-%H%M%S)"
LOG="${VEYRS_UPDATE_LOG:-/var/log/veyrs-offline-update-${TS}.log}"

say()  { printf '\n== %s\n' "$*"; }
ok()   { printf '   ok  %s\n' "$*"; }
info() { printf '       %s\n' "$*"; }
die()  { printf '\n   FAILED: %s\n' "$*" >&2; printf '   Log: %s\n' "$LOG" >&2; exit 1; }

DRY=0; CHECK=0; WANT_MODE=""
for a in "$@"; do
    case "$a" in
        --dry-run) DRY=1 ;;
        --check)   CHECK=1 ;;
        --native)  WANT_MODE=native ;;
        --docker)  WANT_MODE=docker ;;
        -h|--help) sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//'; exit 0 ;;
        *) die "unknown option '$a' (try --help)" ;;
    esac
done

# The version is the one signed source tarball beside this script.
shopt -s nullglob
srcs=("$HERE"/veyrs-[0-9]*.[0-9]*.[0-9]*-src.tar.gz)
shopt -u nullglob
[ "${#srcs[@]}" -eq 1 ] || die "expected exactly one veyrs-<version>-src.tar.gz beside this script, found ${#srcs[@]} (extract the WHOLE tar, keep the files together)"
SRC="${srcs[0]}"
VEYRS_VERSION="$(basename "$SRC" | sed -n 's/^veyrs-\([0-9]*\.[0-9]*\.[0-9]*\)-src\.tar\.gz$/\1/p')"
WHEELS="$HERE/veyrs-${VEYRS_VERSION}-wheels-x86_64.tar.gz"
IMAGES="$HERE/veyrs-images-${VEYRS_VERSION}-amd64.tar.gz"

[ "${VEYRS_UPDATE_SKIP_ROOT_CHECK:-0}" = 1 ] || [ "$(id -u)" -eq 0 ] || die "run it as root: sudo bash update.sh"
[ "$(uname -m)" = x86_64 ] || die "this package is for x86_64; this machine is $(uname -m)"
exec > >(tee -a "$LOG") 2>&1
echo "VEYRS ${VEYRS_VERSION} offline update - $(date -u +%FT%TZ) - log ${LOG}"

# --------------------------------------------------------------- 1. files ---
say "1. Checking the files of this package"
cd "$HERE"
for f in veyrs-setup.sh SHA256SUMS SHA256SUMS.sig "$(basename "$SRC")"; do
    [ -f "$f" ] || die "missing file: $f (extract the WHOLE tar, keep the files together)"
done
# Only the files that are here: the wheels are optional (step 2 decides).
sha256sum -c --quiet --ignore-missing SHA256SUMS || die "a release file is damaged (SHA256SUMS)"
if [ -f "$IMAGES" ]; then
    [ -f "$IMAGES.sha256" ] || die "missing file: $(basename "$IMAGES").sha256"
    sha256sum -c --quiet "$(basename "$IMAGES").sha256" || die "the image bundle is damaged"
fi
ok "all checksums match (the installer verifies the signature of SHA256SUMS next)"

if [ "$CHECK" -eq 1 ]; then
    say "Checking this machine (nothing is changed)"
    exec bash "$HERE/veyrs-setup.sh" --check
fi

# ------------------------------------------------------- 2. what is here ---
say "2. What is installed"
tree_version() { sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$1/pyproject.toml" 2>/dev/null | head -1; }
MODE=""; CURRENT=""
if [ -f "$DOCKER_HOME/.installed" ]; then
    MODE=docker; CURRENT="$(tree_version "$DOCKER_HOME/current")"
fi
if [ -f "$NATIVE_DIR/.env" ] || systemctl cat veyrs-api.service >/dev/null 2>&1; then
    [ -z "$MODE" ] || die "both a native and a Docker install exist here; resolve that by hand first"
    MODE=native; CURRENT="$(tree_version "$NATIVE_DIR")"
    [ ! -d "$NATIVE_DIR/.git" ] || die "$NATIVE_DIR is a git checkout: update it with git, not with this package"
fi
if [ -n "$MODE" ]; then
    ok "VEYRS ${CURRENT:-?} installed ($MODE) -> will be UPDATED to ${VEYRS_VERSION}"
    [ -z "$WANT_MODE" ] || [ "$WANT_MODE" = "$MODE" ] \
        || die "--$WANT_MODE given, but this machine runs VEYRS $MODE (an update keeps the mode)"
    ACTION=update
else
    ACTION=install
    if [ -n "$WANT_MODE" ]; then MODE="$WANT_MODE"
    elif command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then MODE=docker
    else MODE=native; fi
    ok "no VEYRS here -> NEW install, mode $MODE (choose with --native or --docker)"
fi

if [ "$MODE" = docker ]; then
    [ -f "$IMAGES" ] || die "a Docker install needs the container images of ${VEYRS_VERSION}: put $(basename "$IMAGES") (and its .sha256) beside this script. Nothing was changed."
    ok "container images: $(basename "$IMAGES")"
elif [ -f "$WHEELS" ]; then
    ok "Python packages: $(basename "$WHEELS")"
elif [ "$ACTION" = install ]; then
    die "a NEW native install needs the Python packages: put $(basename "$WHEELS") beside this script. Nothing was changed."
else
    # The wheels are left out of the update package when the release keeps
    # the same pinned packages. Prove it against this machine before the
    # backup and before the code is replaced: pip resolves the NEW
    # requirements.txt against the installed virtualenv, with no index.
    req="$(mktemp /tmp/veyrs-requirements.XXXXXX)"
    trap 'rm -f "$req"' EXIT
    tar -xzOf "$SRC" "veyrs-${VEYRS_VERSION}/requirements.txt" >"$req" 2>/dev/null && [ -s "$req" ] \
        || die "$(basename "$SRC") holds no requirements.txt"
    pip="$NATIVE_DIR/venv/bin/pip"
    [ -x "$pip" ] || die "$pip is missing: put $(basename "$WHEELS") beside this script. Nothing was changed."
    out="$("$pip" install --dry-run --no-index --require-hashes --disable-pip-version-check -r "$req" 2>&1)" \
        && ! printf '%s\n' "$out" | grep -q '^Would install' \
        || { printf '%s\n' "$out" | grep -iE '^Would install|error|no matching' | head -3 | sed 's/^/       /'
             die "${VEYRS_VERSION} changes the Python packages of this install: put $(basename "$WHEELS") (from the same release) beside this script. Nothing was changed."; }
    ok "Python packages: the installed ones already match ${VEYRS_VERSION} (no wheels needed)"
fi

# --------------------------------------------------------------- 3. backup --
backup_native() {
    local url host db
    url="$(sed -n 's/^VEYRS_DATABASE_URL=//p' "$NATIVE_DIR/.env" | tail -1 | tr -d "\"'")"
    host="$(printf '%s' "$url" | sed -n 's#.*@\([^:/]*\):\{0,1\}\([0-9]*\)/\([^?]*\).*#\1#p')"
    db="$(printf '%s' "$url" | sed -n 's#.*@[^/]*/\([^?]*\).*#\1#p')"
    : "${db:=veyrs}"
    case "$host" in
        127.0.0.1|localhost|::1|"")
            local tmp="/var/tmp/veyrs-pre-${VEYRS_VERSION}-${TS}.dump" n
            su - postgres -c "pg_dump -d '$db' -Fc -f '$tmp'" || die "pg_dump failed: nothing was changed"
            mv "$tmp" "$BACKUP_DIR/" && chown root:root "$BACKUP_DIR/$(basename "$tmp")" \
                && chmod 600 "$BACKUP_DIR/$(basename "$tmp")"
            n="$(pg_restore --list "$BACKUP_DIR/$(basename "$tmp")" | grep -c 'TABLE DATA' || true)"
            [ "${n:-0}" -ge 10 ] || die "the dump holds only ${n:-0} tables: refusing to update without a real backup"
            ok "database dump: $BACKUP_DIR/$(basename "$tmp") (${n} tables)" ;;
        *)
            [ "${VEYRS_SKIP_DB_BACKUP:-0}" = 1 ] \
                || die "the database is EXTERNAL ($host). Back it up there as its superuser, then re-run with VEYRS_SKIP_DB_BACKUP=1"
            info "external database ($host): backup skipped on request (VEYRS_SKIP_DB_BACKUP=1)" ;;
    esac
    tar czf "$BACKUP_DIR/veyrs-pre-${VEYRS_VERSION}-${TS}-tree.tgz" --exclude=./veyrs/venv \
        -C "$(dirname "$NATIVE_DIR")" "$(basename "$NATIVE_DIR")"
    chmod 600 "$BACKUP_DIR/veyrs-pre-${VEYRS_VERSION}-${TS}-tree.tgz"
    ok "installation tree (with .env): $BACKUP_DIR/veyrs-pre-${VEYRS_VERSION}-${TS}-tree.tgz"
}
backup_docker() {
    # Dump and listing both run inside the stack's postgres container: up to
    # 0.42.0 `veyrs-docker backup` checked the dump with the HOST's
    # pg_restore, which a Docker host does not have.
    local envf="$DOCKER_HOME/veyrs.env" pg db out n
    if grep -q '^VEYRS_COMPOSE_OVERLAYS=..*' "$envf" 2>/dev/null; then
        [ "${VEYRS_SKIP_DB_BACKUP:-0}" = 1 ] \
            || die "this stack uses an EXTERNAL database. Back it up there, then re-run with VEYRS_SKIP_DB_BACKUP=1"
        info "external database: backup skipped on request (VEYRS_SKIP_DB_BACKUP=1)"
    else
        pg="$(docker ps -q --filter label=com.docker.compose.project=veyrs \
                          --filter label=com.docker.compose.service=postgres | head -1)"
        [ -n "$pg" ] || die "the stack's postgres container is not running (veyrs-docker status). Start the stack, then re-run"
        db="$(sed -n 's/^VEYRS_DB_NAME=//p' "$envf" | tail -1 | tr -d "\"'")"; : "${db:=veyrs}"
        out="$BACKUP_DIR/veyrs-pre-${VEYRS_VERSION}-${TS}.dump"
        ( umask 077; docker exec "$pg" pg_dump -U postgres -d "$db" -Fc > "$out" ) \
            || die "pg_dump in the postgres container failed: nothing was changed"
        n="$(docker exec -i "$pg" pg_restore --list < "$out" | grep -c 'TABLE DATA' || true)"
        [ "${n:-0}" -ge 10 ] || die "the dump holds only ${n:-0} tables: refusing to update without a real backup"
        ok "database dump: $out (${n} tables)"
    fi
    install -m 600 "$DOCKER_HOME/veyrs.env" "$BACKUP_DIR/veyrs-pre-${VEYRS_VERSION}-${TS}-veyrs.env"
    ok "configuration (secrets): $BACKUP_DIR/veyrs-pre-${VEYRS_VERSION}-${TS}-veyrs.env"
}

if [ "$ACTION" = update ]; then
    say "3. Backup before the update"
    if [ "$DRY" -eq 1 ]; then
        info "[dry-run] would back up the database and the configuration into $BACKUP_DIR"
    else
        install -d -m 700 "$BACKUP_DIR"
        "backup_$MODE"
    fi
else
    say "3. Backup: nothing to back up (new install)"
fi

# --------------------------------------------------------------- 4. setup ---
say "4. veyrs-setup.sh ($ACTION, $MODE, offline)"
args=(--yes --source "$SRC")
[ "$MODE" = docker ] && args+=(--images "$IMAGES")
[ "$DRY" -eq 1 ] && args+=(--dry-run)
export SETUP_MODE="$MODE"
[ "$ACTION" = update ] && export SETUP_EXISTING=update
rc=0; bash "$HERE/veyrs-setup.sh" "${args[@]}" || rc=$?
[ "$rc" -eq 0 ] || die "veyrs-setup.sh stopped (exit $rc). Read its message above. The backup is in $BACKUP_DIR"

# --------------------------------------------------------------- 5. result --
[ "$DRY" -eq 1 ] && { say "Dry run finished: nothing was changed"; exit 0; }
say "5. Result"
got=""
if [ "$MODE" = native ]; then
    got="$(curl -s --max-time 10 http://127.0.0.1:8000/healthz || true)"
else
    bind="$(sed -n 's/^VEYRS_HTTP_BIND=//p' "$DOCKER_HOME/veyrs.env" | tail -1 | tr -d "\"'")"
    bind="${bind:-127.0.0.1:8080}"; bind="${bind/0.0.0.0/127.0.0.1}"
    got="$(curl -s --max-time 10 "http://${bind}/healthz" || true)"
fi
echo "   healthz: ${got:-no answer}"
printf '%s' "$got" | grep -q "\"version\":\"${VEYRS_VERSION}\"" \
    || die "the service does not report ${VEYRS_VERSION} yet. Backup: $BACKUP_DIR"
ok "VEYRS ${VEYRS_VERSION} is running ($MODE)"
[ "$ACTION" = install ] && [ -f /root/veyrs-admin-password.txt ] \
    && info "first administrator's password: /root/veyrs-admin-password.txt (root only)"
[ "$ACTION" = update ] && info "backup kept in $BACKUP_DIR"
info "in the browser: sign out and in again, and reload once (Ctrl+Shift+R)"
echo
echo "Done. Log: $LOG"
