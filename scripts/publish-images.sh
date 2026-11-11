#!/usr/bin/env bash
# Build, verify and publish the VEYRS container images, and write the offline
# image bundle.
#
#   scripts/publish-images.sh                 build + verify, publish nothing
#   scripts/publish-images.sh --push          + push to ghcr.io/visionebc
#   scripts/publish-images.sh --bundle DIR    + DIR/veyrs-images-<ver>-amd64.tar.gz
#                                               and its .sha256
#   scripts/publish-images.sh --upload        + attach the bundle to GitHub
#                                               release v<ver> (needs --bundle)
#   --latest                                  also move the `latest` tags. Only
#                                             for the newest release.
#
# Environment:
#   GH_TOKEN         a token with write:packages (push) and contents:write
#                    (upload). Read from the environment only -- never put it on
#                    a command line, where every local account can read it in
#                    ps(1). It is handed to `docker login` on stdin and to curl
#                    through a 0600 header file, in a throw-away DOCKER_CONFIG
#                    that is deleted on exit, so it is never left in
#                    ~/.docker/config.json.
#   VEYRS_REGISTRY   default ghcr.io/visionebc
#   VEYRS_REVISION   the git commit, when the tree is not a git checkout
#
# What is published, per release:
#
#   ghcr.io/visionebc/veyrs:<ver>          api + init + intel/digest workers
#   ghcr.io/visionebc/veyrs-console:<ver>  operator console (nginx, uid 101)
#   ghcr.io/visionebc/veyrs-agent:<ver>    scanner runner (opt-in profile)
#   veyrs-images-<ver>-amd64.tar.gz        api + console + postgres + redis for
#                                          a host with no registry access. The
#                                          agent is NOT in it: it needs the
#                                          network to reach anything anyway.
#
# linux/amd64 only. arm64 needs an emulating builder (binfmt on the build
# host) or a native arm64 one; the Dockerfile already carries the pinned
# arm64 nuclei checksum for that day. Until then an arm64 host uses
# VEYRS_IMAGE_SOURCE=build.
#
# Every step is a MEASUREMENT of the thing just produced: the user id each
# image runs as, that no secret file is inside, that the push landed the same
# digest that was built, and that an ANONYMOUS client can pull it -- a GHCR
# package pushed from a personal account starts out PRIVATE, and a private
# image looks perfectly published from the account that pushed it.
set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
ROOT="$(cd "$HERE/.." && pwd)"
REGISTRY="${VEYRS_REGISTRY:-ghcr.io/visionebc}"
REPO="${VEYRS_GITHUB_REPO:-visionebc/veyrs}"
API="${GITHUB_API:-https://api.github.com}"
UPLOADS="${GITHUB_UPLOADS:-https://uploads.github.com}"
PLATFORM="linux/amd64"

PUSH=0; LATEST=0; UPLOAD=0; BUNDLE_DIR=""
while [[ $# -gt 0 ]]; do
    case "$1" in
        --push)   PUSH=1 ;;
        --latest) LATEST=1 ;;
        --upload) UPLOAD=1 ;;
        --bundle) shift; BUNDLE_DIR="${1:?--bundle needs a directory}" ;;
        -h|--help) awk 'NR>1 && /^#/ { sub(/^# ?/, ""); print; next } NR>1 { exit }' "$0"; exit 0 ;;
        *) echo "unknown option: $1" >&2; exit 2 ;;
    esac
    shift
done
[[ $UPLOAD -eq 0 || -n "$BUNDLE_DIR" ]] || { echo "--upload needs --bundle DIR" >&2; exit 2; }

say()  { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
ok()   { printf '     \033[32mok\033[0m  %s\n' "$*"; }
die()  { printf '\n\033[31mERROR:\033[0m %s\n' "$*" >&2; exit 1; }

command -v docker >/dev/null || die "docker is required"
# jq, not python3: SUSE's base image has no python3 at all (only python3.11),
# and a JSON step that dies AFTER the push is the worst place to find out.
command -v jq >/dev/null || die "jq is required"
docker buildx version >/dev/null 2>&1 || die "docker buildx is required"

VERSION="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$ROOT/pyproject.toml" | head -1)"
[[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || die "no X.Y.Z version in pyproject.toml"
CFG_VERSION="$(sed -n 's/^ *version: str = "\([^"]*\)".*/\1/p' "$ROOT/backend/veyrs/config.py" | head -1)"
[[ "$CFG_VERSION" == "$VERSION" ]] || die "pyproject.toml says $VERSION, config.py says $CFG_VERSION"

# A published image is built from a COMMITTED tree, or it cannot be traced
# back to anything. Uncommitted edits would ship under a revision label that
# does not contain them.
if git -C "$ROOT" rev-parse --git-dir >/dev/null 2>&1; then
    [[ -z "$(git -C "$ROOT" status --porcelain --untracked-files=no)" ]] \
        || die "the tree has uncommitted changes; images are built from a commit"
    REVISION="$(git -C "$ROOT" rev-parse HEAD)"
else
    REVISION="${VEYRS_REVISION:-}"
    [[ "$REVISION" =~ ^[0-9a-f]{40}$ ]] || die "not a git checkout: set VEYRS_REVISION to the 40-hex commit this tree is"
fi

API_IMG="$REGISTRY/veyrs:$VERSION"
CON_IMG="$REGISTRY/veyrs-console:$VERSION"
AGT_IMG="$REGISTRY/veyrs-agent:$VERSION"

WORK="$(mktemp -d)"; chmod 700 "$WORK"
cleanup() { [[ -n "${DOCKER_CONFIG:-}" && "$DOCKER_CONFIG" == "$WORK"/* ]] && docker logout "${REGISTRY%%/*}" >/dev/null 2>&1; rm -rf "$WORK"; }
trap cleanup EXIT

# ---------------------------------------------------------------------------
say "1. Build $VERSION @ ${REVISION:0:12} ($PLATFORM)"
for pair in "api:$API_IMG" "console:$CON_IMG" "agent:$AGT_IMG"; do
    target="${pair%%:*}"; tag="${pair#*:}"
    docker buildx build --platform "$PLATFORM" --target "$target" \
        --build-arg "VEYRS_VERSION=$VERSION" --build-arg "VEYRS_REVISION=$REVISION" \
        --provenance=false --load -t "$tag" -f "$ROOT/docker/Dockerfile" "$ROOT" >"$WORK/build-$target.log" 2>&1 \
        || { tail -30 "$WORK/build-$target.log" >&2; die "build of $target failed"; }
    ok "$tag  $(docker image inspect -f '{{.Id}}' "$tag" | cut -c1-19)  $(docker image inspect -f '{{.Size}}' "$tag" | awk '{printf "%.0f MB", $1/1e6}')"
done

# ---------------------------------------------------------------------------
say "2. Verify what was built"
label() { docker image inspect -f "{{index .Config.Labels \"org.opencontainers.image.$2\"}}" "$1"; }
for img in "$API_IMG" "$CON_IMG" "$AGT_IMG"; do
    [[ "$(label "$img" version)" == "$VERSION" && "$(label "$img" revision)" == "$REVISION" ]] \
        || die "$img carries version/revision labels '$(label "$img" version)'/'$(label "$img" revision)'"
done
ok "version and revision labels on all three"

uid() { docker run --rm --network none --entrypoint id "$1" -u; }
[[ "$(uid "$API_IMG")" == 10001 ]] || die "$API_IMG does not run as uid 10001"
[[ "$(uid "$AGT_IMG")" == 10001 ]] || die "$AGT_IMG does not run as uid 10001"
[[ "$(uid "$CON_IMG")" == 101 ]]   || die "$CON_IMG does not run as uid 101 (nginx) -- it would run as root"
ok "api/agent run as 10001, console as 101 -- none as root"

# Searched, not checked by path (scripts/test-docker-stack.sh explains why).
leaked="$(docker run --rm --network none --entrypoint sh "$API_IMG" -c \
    'find / -xdev \( -name ".env" -o -name ".env.*" -o -name ".bootstrap-credentials" -o -name "*.dump" -o -name ".git" \) \
       ! -name ".env.example" 2>/dev/null' || true)"
[[ -z "$leaked" ]] || die "secret-shaped files inside $API_IMG: $leaked"
ok "no .env / .bootstrap-credentials / *.dump / .git inside the api image"

got="$(docker run --rm --network none --entrypoint python "$API_IMG" -c \
    'from veyrs.config import settings; import veyrs.main; print(settings.version)' 2>"$WORK/import.err")" \
    || { cat "$WORK/import.err" >&2; die "the application does not import inside $API_IMG"; }
[[ "$got" == "$VERSION" ]] || die "the api image reports version $got"
ok "the application imports and reports $got"

docker run --rm --network none --read-only --tmpfs /tmp --tmpfs /var/cache/nginx:uid=101,gid=101 \
    --entrypoint nginx "$CON_IMG" -t >"$WORK/nginx-t.log" 2>&1 \
    || { cat "$WORK/nginx-t.log" >&2; die "nginx -t fails in $CON_IMG as uid 101 on a read-only root"; }
ok "console configuration valid as uid 101 on a read-only root filesystem"

docker run --rm --network none --entrypoint nuclei "$AGT_IMG" -version >"$WORK/nuclei.log" 2>&1 \
    || die "nuclei does not run in $AGT_IMG"
ok "agent: $(grep -oE 'v[0-9]+\.[0-9]+\.[0-9]+' "$WORK/nuclei.log" | head -1)"

# ---------------------------------------------------------------------------
HDR="$WORK/auth.hdr"; : >"$HDR"; chmod 600 "$HDR"
if [[ $PUSH -eq 1 || $UPLOAD -eq 1 ]]; then
    [[ -n "${GH_TOKEN:-}" ]] || die "--push/--upload need GH_TOKEN in the environment"
    printf 'Authorization: Bearer %s\n' "$GH_TOKEN" >"$HDR"
fi

if [[ $PUSH -eq 1 ]]; then
    say "3. Push to $REGISTRY"
    export DOCKER_CONFIG="$WORK/docker-config"; mkdir -m 700 "$DOCKER_CONFIG"
    login_user="${REGISTRY#*/}"; login_user="${login_user%%/*}"
    printf '%s' "$GH_TOKEN" | docker login "${REGISTRY%%/*}" -u "$login_user" --password-stdin >/dev/null 2>&1 \
        || die "docker login to ${REGISTRY%%/*} failed (the token needs write:packages)"
    tags=("$API_IMG" "$CON_IMG" "$AGT_IMG")
    if [[ $LATEST -eq 1 ]]; then
        for img in "$API_IMG" "$CON_IMG" "$AGT_IMG"; do
            docker tag "$img" "${img%:*}:latest"; tags+=("${img%:*}:latest")
        done
    fi
    declare -A PUSHED
    for t in "${tags[@]}"; do
        docker push "$t" >"$WORK/push.log" 2>&1 || { tail -5 "$WORK/push.log" >&2; die "push of $t failed"; }
        PUSHED[$t]="$(sed -n 's/.*digest: \(sha256:[0-9a-f]*\).*/\1/p' "$WORK/push.log" | tail -1)"
        [[ -n "${PUSHED[$t]}" ]] || die "push of $t printed no digest"
        ok "$t  ${PUSHED[$t]}"
    done
    docker logout "${REGISTRY%%/*}" >/dev/null 2>&1 || true

    # The push's exit code says the daemon sent something. It does not say
    # what the registry now serves under that name, nor to whom. Ask the
    # registry, as an ANONYMOUS client, for each tag.
    say "4. Re-read from the registry as an anonymous client"
    export DOCKER_CONFIG="$WORK/anon-config"; mkdir -m 700 "$DOCKER_CONFIG"
    for t in "${tags[@]}"; do
        # `|| true`: under set -e + pipefail a refused read would end the
        # script right here, silently -- before the message below that says
        # WHY and what to click. Measured on the first real push (0.32.4).
        remote="$(docker buildx imagetools inspect "$t" 2>"$WORK/anon.err" | sed -n 's/^Digest: *//p' || true)"
        if [[ -z "$remote" ]]; then
            pkg="${t#*/}"; pkg="${pkg#*/}"; pkg="${pkg%%:*}"
            die "$t cannot be pulled anonymously: $(head -1 "$WORK/anon.err")
A package pushed from a personal account starts PRIVATE. Make it public once at
  https://github.com/users/${REGISTRY#*/}/packages/container/${pkg}/settings
(Danger Zone -> Change visibility -> Public) and re-run with --push."
        fi
        [[ "$remote" == "${PUSHED[$t]}" ]] || die "$t: the registry serves $remote, the push wrote ${PUSHED[$t]}"
        ok "$t  public, $remote"
    done
    unset DOCKER_CONFIG
fi

# ---------------------------------------------------------------------------
if [[ -n "$BUNDLE_DIR" ]]; then
    say "5. Offline bundle"
    mkdir -p "$BUNDLE_DIR"
    # The same postgres and redis that compose.yaml pins, BY DIGEST, then
    # tagged plainly: `docker load` on the target restores the tag, and
    # veyrs-docker.sh load points the stack at those tags.
    pg_ref="$(sed -n 's/.*VEYRS_POSTGRES_IMAGE:-\([^}]*\)}.*/\1/p' "$ROOT/docker/compose.yaml" | head -1)"
    rd_ref="$(sed -n 's/.*VEYRS_REDIS_IMAGE:-\([^}]*\)}.*/\1/p' "$ROOT/docker/compose.yaml" | head -1)"
    [[ "$pg_ref" == *@sha256:* && "$rd_ref" == *@sha256:* ]] || die "compose.yaml does not pin postgres/redis by digest"
    docker pull --platform "$PLATFORM" -q "$pg_ref" >/dev/null && docker tag "$pg_ref" "${pg_ref%@*}"
    docker pull --platform "$PLATFORM" -q "$rd_ref" >/dev/null && docker tag "$rd_ref" "${rd_ref%@*}"
    name="veyrs-images-$VERSION-amd64.tar.gz"
    docker save "$API_IMG" "$CON_IMG" "${pg_ref%@*}" "${rd_ref%@*}" | gzip -6 >"$BUNDLE_DIR/$name.tmp"
    mv "$BUNDLE_DIR/$name.tmp" "$BUNDLE_DIR/$name"
    ( cd "$BUNDLE_DIR" && sha256sum "$name" >"$name.sha256" )
    # Read the bundle back rather than trusting `docker save`'s exit code.
    n="$(gzip -dc "$BUNDLE_DIR/$name" | tar -xOf - manifest.json | jq '[.[].RepoTags // [] | length] | add')"
    [[ "$n" == 4 ]] || die "the bundle lists $n tagged images, expected 4"
    ok "$name  $(du -h "$BUNDLE_DIR/$name" | cut -f1)  sha256 $(cut -c1-16 "$BUNDLE_DIR/$name.sha256")…  (4 images)"
fi

# ---------------------------------------------------------------------------
if [[ $UPLOAD -eq 1 ]]; then
    say "6. Attach the bundle to release v$VERSION"
    curl -fsS -H @"$HDR" "$API/repos/$REPO/releases/tags/v$VERSION" -o "$WORK/rel.json" \
        || die "release v$VERSION does not exist on $REPO (publish the release first)"
    rid="$(jq -r .id "$WORK/rel.json")"
    curl -fsS -H @"$HDR" "$API/repos/$REPO/releases/$rid/assets?per_page=100" -o "$WORK/assets.json"
    for f in "$name" "$name.sha256"; do
        # Replaced, never duplicated.
        for aid in $(jq -r --arg n "$f" '.[] | select(.name == $n) | .id' "$WORK/assets.json"); do
            curl -fsS -X DELETE -H @"$HDR" "$API/repos/$REPO/releases/assets/$aid" || die "could not delete the previous $f"
        done
        ctype=application/octet-stream; [[ "$f" == *.tar.gz ]] && ctype=application/gzip
        curl -fsS -H @"$HDR" -H "Content-Type: $ctype" --data-binary @"$BUNDLE_DIR/$f" \
            "$UPLOADS/repos/$REPO/releases/$rid/assets?name=$f" -o "$WORK/up.json" || die "upload of $f failed"
    done
    # Re-read: size on the release == size on disk, exactly one of each.
    curl -fsS -H @"$HDR" "$API/repos/$REPO/releases/$rid/assets?per_page=100" -o "$WORK/assets.json"
    for f in "$name" "$name.sha256"; do
        got="$(jq -r --arg n "$f" '[.[] | select(.name == $n)] | "\(length) \(.[0].size)"' "$WORK/assets.json")"
        [[ "$got" == "1 $(stat -c %s "$BUNDLE_DIR/$f")" ]] \
            || die "the release carries '$got' (count size) for $f, built $(stat -c %s "$BUNDLE_DIR/$f") bytes"
    done
    ok "release v$VERSION carries $name and its .sha256"
fi

say "Done: $VERSION @ ${REVISION:0:12}$([[ $PUSH -eq 1 ]] && echo ', pushed')$([[ -n "$BUNDLE_DIR" ]] && echo ', bundle written')$([[ $UPLOAD -eq 1 ]] && echo ', uploaded')"
