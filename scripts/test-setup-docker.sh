#!/usr/bin/env bash
# End-to-end test of veyrs-setup.sh in Docker mode, run ON the target host.
#
#   sudo scripts/test-setup-docker.sh dryrun   SETUP=… SRC=…
#   sudo scripts/test-setup-docker.sh registry SETUP=… SRC=…
#   sudo scripts/test-setup-docker.sh build    SETUP=… SRC=…
#   sudo scripts/test-setup-docker.sh offline  SETUP=… SRC=… IMAGES=veyrs-images-<v>-amd64.tar.gz
#
#   SETUP   the veyrs-setup.sh under test
#   SRC     a VEYRS tree or veyrs-<v>-src.tar.gz (passed as --source). Empty:
#           the installer downloads the release tarball itself, which is the
#           path an outside user takes.
#   IMAGES  the offline bundle (offline mode; its .sha256 beside it)
#
# Meant for a DISPOSABLE host restored from a snapshot before each mode: it
# installs Docker, writes /opt/veyrs-docker and, in offline mode, edits
# /etc/hosts for the duration of the run (restored on exit).
#
# What each mode proves, beyond "it came up":
#   dryrun    nothing is installed: no docker binary, no /opt/veyrs-docker, the
#             package count is unchanged.
#   registry  the running containers use ghcr.io/visionebc/*:<v> and NOTHING
#             was built here (no veyrs:<v> image exists).
#   build     the images were built here, from this tree.
#   offline   the install succeeds with every registry, PyPI and GitHub
#             unresolvable -- so it cannot have fetched anything.
# Then, for every non-dry mode: file modes, the full live-stack harness
# (scripts/test-docker-stack.sh, privileges included), an idempotent re-run
# that leaves the secrets file byte-identical and the password working.
set -uo pipefail

MODE="${1:-}"; shift || true
for kv in "$@"; do export "${kv?}"; done
: "${SETUP:?SETUP=path/to/veyrs-setup.sh}"
case "$MODE" in dryrun|registry|build|offline) ;; *) echo "mode: dryrun|registry|build|offline" >&2; exit 2 ;; esac
[[ "$MODE" != offline || -f "${IMAGES:-}" ]] || { echo "offline needs IMAGES=bundle" >&2; exit 2; }

PASS=0; FAIL=0
ok()  { printf '  PASS  %s\n' "$*"; PASS=$((PASS+1)); }
bad() { printf '  FAIL  %s\n' "$*"; FAIL=$((FAIL+1)); }
head_() { printf '\n== %s\n' "$*"; }

# Random per run, never a literal: this file is published.
PW_UNDER_TEST="$(head -c 18 /dev/urandom | base64 | tr -d "/+=")Aa1"
WORK="$(mktemp -d)"; chmod 700 "$WORK"
cat >"$WORK/answers.env" <<EOF
SETUP_MODE=docker
SETUP_EXISTING=update
SETUP_HTTP_BIND=127.0.0.1:8080
SETUP_PUBLIC_URL=http://localhost:8080
SETUP_ENVIRONMENT=development
SETUP_ORG=acme
SETUP_ORG_NAME='Acme & Co \$1'      # sourced by bash: quoted, and \$ must survive compose
SETUP_ADMIN_EMAIL=admin@acme.example
SETUP_ADMIN_PASSWORD=$PW_UNDER_TEST
SETUP_DB=bundled
SETUP_IMAGES=$([[ "$MODE" == build ]] && echo build || echo registry)
SETUP_WORKERS=no
SETUP_AGENT=no
SETUP_FIREWALL=no
SETUP_INSTALL_DOCKER=yes
EOF
chmod 600 "$WORK/answers.env"

pkgcount() { rpm -qa 2>/dev/null | wc -l || dpkg -l 2>/dev/null | grep -c '^ii'; }
args=(--yes --answers "$WORK/answers.env")
[[ -n "${SRC:-}" ]] && args+=(--source "$SRC")
[[ "$MODE" == offline ]] && args+=(--images "$IMAGES")

# Offline: make every registry and package index unresolvable for the run.
# dockerd resolves through the host's /etc/hosts, so this reaches the daemon.
restore_hosts() { [[ -f "$WORK/hosts" ]] && cat "$WORK/hosts" >/etc/hosts; rm -rf "$WORK"; }
trap restore_hosts EXIT
if [[ "$MODE" == offline ]]; then
    cp /etc/hosts "$WORK/hosts"
    for h in ghcr.io pkg-containers.githubusercontent.com registry-1.docker.io auth.docker.io \
             production.cloudflare.docker.com index.docker.io pypi.org files.pythonhosted.org \
             github.com objects.githubusercontent.com download.docker.com; do
        printf '0.0.0.0 %s\n:: %s\n' "$h" "$h" >>/etc/hosts
    done
    curl -s -m 5 -o /dev/null https://ghcr.io/v2/ && bad "ghcr.io still reachable: the offline test would prove nothing" \
        || ok "registries, PyPI and GitHub unresolvable for this run"
fi

# ---------------------------------------------------------------------------
head_ "1. Install ($MODE)"
before_pkgs="$(pkgcount)"
t0=$(date +%s)
bash "$SETUP" "${args[@]}" $([[ "$MODE" == dryrun ]] && echo --dry-run) >"$WORK/run1.log" 2>&1; rc=$?
secs=$(( $(date +%s) - t0 ))
[[ $rc -eq 0 ]] && ok "veyrs-setup.sh exit 0 in ${secs}s" \
    || { bad "veyrs-setup.sh exit $rc after ${secs}s"; tail -30 "$WORK/run1.log" | sed 's/^/        /'; }

if [[ "$MODE" == dryrun ]]; then
    command -v docker >/dev/null && bad "a dry run installed docker" || ok "docker not installed"
    [[ ! -e /opt/veyrs-docker ]] && ok "/opt/veyrs-docker not created" || bad "/opt/veyrs-docker exists after a dry run"
    [[ "$(pkgcount)" == "$before_pkgs" ]] && ok "package count unchanged ($before_pkgs)" \
        || bad "package count $before_pkgs -> $(pkgcount)"
    grep -q 'images registry' "$WORK/run1.log" && ok "the plan names the image source" || bad "the plan does not say where the images come from"
    printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"; exit $(( FAIL > 0 ))
fi
[[ $rc -eq 0 ]] || { printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"; exit 1; }

D=/opt/veyrs-docker; ENVF=$D/veyrs.env
VER="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' $D/current/pyproject.toml)"
C=(docker compose --project-directory $D/current/docker -f $D/current/docker/compose.yaml)

# ---------------------------------------------------------------------------
head_ "2. Which images run, and where they came from"
img="$(docker inspect -f '{{.Config.Image}}' "$("${C[@]}" ps -q api)")"
con="$(docker inspect -f '{{.Config.Image}}' "$("${C[@]}" ps -q console)")"
src="$(sed -n 's/^VEYRS_IMAGE_SOURCE=//p' $ENVF)"
case "$MODE" in
    registry|offline)
        [[ "$img" == "ghcr.io/visionebc/veyrs:$VER" && "$con" == "ghcr.io/visionebc/veyrs-console:$VER" ]] \
            && ok "api/console run the published $VER images" || bad "api=$img console=$con"
        docker image inspect "veyrs:$VER" >/dev/null 2>&1 && bad "a veyrs:$VER image was BUILT on this host" \
            || ok "nothing was built on this host"
        want=$([[ "$MODE" == offline ]] && echo local || echo registry)
        [[ "$src" == "$want" ]] && ok "VEYRS_IMAGE_SOURCE=$src" || bad "VEYRS_IMAGE_SOURCE=$src, expected $want" ;;
    build)
        [[ "$img" == "veyrs:$VER" && "$con" == "veyrs-console:$VER" ]] && ok "api/console run images built here ($img)" \
            || bad "api=$img console=$con"
        [[ "$src" == build ]] && ok "VEYRS_IMAGE_SOURCE=build" || bad "VEYRS_IMAGE_SOURCE=$src" ;;
esac
lv="$(docker image inspect -f '{{index .Config.Labels "org.opencontainers.image.version"}}' "$img")"
[[ "$lv" == "$VER" ]] && ok "image version label '$lv'" || bad "image version label '$lv' (tree is $VER)"

# ---------------------------------------------------------------------------
head_ "3. Files and modes"
mode_is() { [[ "$(stat -c '%a %U' "$1" 2>/dev/null)" == "$2" ]] && ok "$1 is $2" || bad "$1 is $(stat -c '%a %U' "$1" 2>/dev/null || echo missing), expected $2"; }
mode_is $D "700 root"
mode_is $ENVF "600 root"
mode_is /usr/local/sbin/veyrs-docker "755 root"
mode_is /var/log/veyrs-setup.log "600 root"
[[ "$(readlink -f $D/current/docker/.env)" == "$ENVF" ]] && ok "current/docker/.env -> veyrs.env" || bad "docker/.env is not the link to veyrs.env"
ww="$(find $D/releases -xdev -perm -0002 ! -type l 2>/dev/null | head -3)"
[[ -z "$ww" ]] && ok "no world-writable file in the release tree" || bad "world-writable: $ww"
grep -q "^VEYRS_ADMIN_PASSWORD=$" $ENVF && ok "the admin password is not stored in veyrs.env" || bad "veyrs.env holds an admin password"
grep -qF "$PW_UNDER_TEST" /var/log/veyrs-setup.log && bad "the admin password is in the setup log" || ok "the admin password is not in the setup log"
grep -q "^VEYRS_ADMIN_NAME='Acme & Co \$1'$" $ENVF && ok "the org display name is kept literally (\$ and &)" || bad "VEYRS_ADMIN_NAME mangled: $(grep ^VEYRS_ADMIN_NAME $ENVF)"

# ---------------------------------------------------------------------------
head_ "4. The live-stack harness (privileges included)"
VEYRS_TEST_ADMIN_PASSWORD="$PW_UNDER_TEST" bash $D/current/scripts/test-docker-stack.sh >"$WORK/stack.log" 2>&1
res="$(tail -1 "$WORK/stack.log" | sed 's/\x1b\[[0-9;]*m//g')"
grep -q ' 0 failed' <<<"$res" && ok "test-docker-stack.sh: $res" \
    || { bad "test-docker-stack.sh: $res"; sed 's/\x1b\[[0-9;]*m//g' "$WORK/stack.log" | grep FAIL | sed 's/^/        /'; }

# ---------------------------------------------------------------------------
head_ "5. Re-run over itself"
md5_before="$(md5sum <$ENVF)"
bash "$SETUP" "${args[@]}" >"$WORK/run2.log" 2>&1; rc=$?
[[ $rc -eq 0 ]] && ok "second run exit 0" || { bad "second run exit $rc"; tail -15 "$WORK/run2.log" | sed 's/^/        /'; }
[[ "$(md5sum <$ENVF)" == "$md5_before" ]] && ok "veyrs.env byte-identical (no secret rotated)" || bad "veyrs.env changed on re-run"
"${C[@]}" logs --no-log-prefix init 2>/dev/null | grep -q 'bootstrap not run' && ok "init: bootstrap not run" || bad "init did not skip bootstrap"
code="$(printf '{"organization":"acme","email":"admin@acme.example","password":"%s"}' "$PW_UNDER_TEST" \
    | curl -s -o /dev/null -w '%{http_code}' -H 'Content-Type: application/json' --data-binary @- http://127.0.0.1:8080/api/v1/auth/login)"
[[ "$code" == 200 ]] && ok "the original password still signs in" || bad "login after re-run: HTTP $code"

printf '\n%d passed, %d failed\n' "$PASS" "$FAIL"
exit $(( FAIL > 0 ))
