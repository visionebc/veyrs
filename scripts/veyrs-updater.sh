#!/usr/bin/env bash
# veyrs-updater.sh — the PRIVILEGED half of the in-product update (native installs).
#
# Run as root by veyrs-updater.service, which veyrs-updater.path starts when a
# request file appears in the spool. The API only writes that file (see
# backend/veyrs/services/updates.py); everything that needs root happens here:
#
#   request   read ONE request (a version string, a source keyword and who
#             asked; nothing else in it is trusted or used)
#   preflight refuse a git checkout ("managed by git deploy"), a container, a
#             target that is not newer, and an update with no backup arranged
#   download  SHA256SUMS, SHA256SUMS.sig, veyrs-setup.sh, veyrs-<v>-src.tar.gz
#             and, when SHA256SUMS lists it, veyrs-<v>-wheels-x86_64.tar.gz
#             (the Python packages, so the install needs no PyPI). From:
#               source=release  VEYRS_UPDATE_DOWNLOAD_BASE (GitHub by default)
#               source=upload   <app>/var/update-uploads/v<X.Y.Z>/ (the console's
#                               upload; the API can write there, so nothing in
#                               it is trusted until verified below)
#               source=local    VEYRS_UPDATE_LOCAL_DIR (a USB disk, an NFS share):
#                               <dir>/v<X.Y.Z>/, <dir>/veyrs-<X.Y.Z>/ or <dir>/
#             The request names only the keyword; the DIRECTORY is decided
#             here. Local files are COPIED into a root-only work directory
#             first, and everything after this step reads only that copy.
#   verify    scripts/verify-release.sh of the INSTALLED tree, with the INSTALLED
#             release/allowed_signers: the signature is REQUIRED. Unsigned, a bad
#             signature, a hash mismatch or "cannot verify" (placeholder key, no
#             ssh-keygen) all stop the run before anything is touched.
#   backup    VEYRS_UPDATE_PRE_HOOK (e.g. /opt/veyrs/scripts/backup.sh), or the
#             operator's explicit VEYRS_UPDATE_SKIP_BACKUP=1. Neither = refused.
#   install   the downloaded, verified veyrs-setup.sh --yes --source <tarball>
#             with SETUP_EXISTING=update (it re-verifies the tarball itself)
#   health    /healthz must report the new version and /readyz must be 200
#
# Every step lands in $VEYRS_UPDATE_STATUS_DIR/<id>.json (`steps[]`: name, ok,
# detail, at), which the console shows; the full output goes to <id>.log. The
# request file is removed whatever the outcome, so a failure does not loop.
#
# Configuration (the unit reads /opt/veyrs/.env):
#   VEYRS_UPDATE_SPOOL          default /var/lib/veyrs/update-requests
#   VEYRS_UPDATE_STATUS_DIR     default /var/lib/veyrs/update-status
#   VEYRS_UPDATE_DOWNLOAD_BASE  default https://github.com/visionebc/veyrs/releases/download
#   VEYRS_UPDATE_LOCAL_DIR      where source=local looks (absolute path; empty = off)
#   VEYRS_UPDATE_PRE_HOOK       absolute path of an executable run before installing
#                               (root-owned, not group/other-writable; no arguments)
#   VEYRS_UPDATE_SKIP_BACKUP    1 = proceed without a hook (the operator's call)
# Bench overrides (tests only; production never sets them):
#   VEYRS_UPDATER_APP_DIR, VEYRS_UPDATER_ALLOWED_SIGNERS, VEYRS_UPDATER_HEALTH_URL,
#   VEYRS_UPDATER_HEALTH_TIMEOUT, VEYRS_UPDATER_SETUP
#
# The body is ONE function called on the last line: bash reads a script as it
# runs, and the install step replaces this very file. Parsed up front, the old
# copy finishes as it started.
set -uo pipefail

main() {
    umask 022
    local self_root
    self_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
    APP_DIR="${VEYRS_UPDATER_APP_DIR:-$self_root}"
    SPOOL="${VEYRS_UPDATE_SPOOL:-/var/lib/veyrs/update-requests}"
    STATUS_DIR="${VEYRS_UPDATE_STATUS_DIR:-/var/lib/veyrs/update-status}"
    BASE="${VEYRS_UPDATE_DOWNLOAD_BASE:-https://github.com/visionebc/veyrs/releases/download}"
    BASE="${BASE%/}"
    SIGNERS="${VEYRS_UPDATER_ALLOWED_SIGNERS:-$APP_DIR/release/allowed_signers}"
    HEALTH="${VEYRS_UPDATER_HEALTH_URL:-http://127.0.0.1:8000}"
    HEALTH_TIMEOUT="${VEYRS_UPDATER_HEALTH_TIMEOUT:-180}"
    LOCAL_DIR="${VEYRS_UPDATE_LOCAL_DIR:-}"
    STATE="running"; STEPS=""; TARGET=""; FROM=""; WHO=""; REQ=""; WORK=""; FINISHED=0; SOURCE=""

    mkdir -p "$STATUS_DIR" || { echo "cannot create $STATUS_DIR" >&2; return 1; }
    chmod 755 "$STATUS_DIR" 2>/dev/null || true
    exec 9>"$STATUS_DIR/.lock"
    if command -v flock >/dev/null 2>&1 && ! flock -n 9; then
        echo "another veyrs-updater run holds the lock; leaving the request for it"
        return 0
    fi

    REQ="$(find "$SPOOL" -maxdepth 1 -type f -name '*.json' 2>/dev/null | LC_ALL=C sort | head -1)"
    if [[ -z "$REQ" ]]; then echo "no update request in $SPOOL"; return 0; fi
    local base_name; base_name="$(basename "$REQ" .json | tr -cd 'A-Za-z0-9-' | tail -c 48)"
    ID="$(date -u +%Y%m%dT%H%M%SZ)-${base_name:-request}"
    STARTED="$(now)"
    LOG="$STATUS_DIR/$ID.log"
    : >"$LOG"; chmod 640 "$LOG" 2>/dev/null || true
    trap on_exit EXIT
    echo "veyrs-updater: processing $REQ (status: $STATUS_DIR/$ID.json)"

    # ------------------------------------------------------------ request
    local size; size="$(stat -c %s "$REQ" 2>/dev/null || echo 99999)"
    [[ "$size" -le 4096 ]] || refuse request "the request file is ${size} bytes; a request is a few lines"
    TARGET="$(sed -n 's/.*"target_version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$REQ" | head -1)"
    WHO="$(sed -n 's/.*"requested_by"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$REQ" | head -1 \
           | LC_ALL=C tr -cd 'A-Za-z0-9@._+:-' | cut -c1-200)"
    [[ "$TARGET" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] \
        || { TARGET=""; refuse request "the request names no valid target version"; }
    # A keyword, never a path: which directory a source means is decided below.
    SOURCE="$(sed -n 's/.*"source"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p' "$REQ" | head -1)"
    case "${SOURCE:=release}" in
        release|upload|local) ;;
        *) refuse request "unknown update source '$(printf '%s' "$SOURCE" | LC_ALL=C tr -cd 'A-Za-z0-9_-' | cut -c1-20)'" ;;
    esac
    step request 1 "update to ${TARGET} from ${SOURCE} requested by ${WHO:-unknown}"

    # ---------------------------------------------------------- preflight
    if [[ -e "$APP_DIR/.git" ]]; then
        refuse preflight "managed by git deploy: ${APP_DIR} is a git checkout; update it with its git deploy, not from the console"
    fi
    if [[ -f /.dockerenv || "${VEYRS_INSTALL_MODE:-}" == docker ]]; then
        refuse preflight "a container is replaced, not patched: run veyrs-setup.sh --version ${TARGET} on the Docker host"
    fi
    [[ -f "$APP_DIR/install.sh" && -f "$APP_DIR/pyproject.toml" ]] \
        || refuse preflight "${APP_DIR} is not a native VEYRS install (no install.sh / pyproject.toml)"
    FROM="$(sed -n 's/^version *= *"\([^"]*\)".*/\1/p' "$APP_DIR/pyproject.toml" | head -1)"
    [[ -n "$FROM" ]] || refuse preflight "cannot read the installed version from ${APP_DIR}/pyproject.toml"
    if [[ "$FROM" == "$TARGET" ]] || ! newer "$TARGET" "$FROM"; then
        refuse preflight "the target ${TARGET} is not newer than the installed ${FROM}"
    fi
    if [[ -z "${VEYRS_UPDATE_PRE_HOOK:-}" ]] && ! truthy "${VEYRS_UPDATE_SKIP_BACKUP:-}"; then
        refuse preflight "no pre-update backup: set VEYRS_UPDATE_PRE_HOOK (e.g. ${APP_DIR}/scripts/backup.sh) or, deliberately, VEYRS_UPDATE_SKIP_BACKUP=1 in ${APP_DIR}/.env"
    fi
    [[ -x "$APP_DIR/scripts/verify-release.sh" ]] \
        || refuse preflight "${APP_DIR}/scripts/verify-release.sh is missing: this install cannot verify a release"
    step preflight 1 "native install in ${APP_DIR}: ${FROM} -> ${TARGET}"

    # ----------------------------------------------------------- download
    WORK="$(mktemp -d /var/tmp/veyrs-update.XXXXXX)" || fail download "cannot create a work directory"
    chmod 700 "$WORK"
    local tgz="veyrs-${TARGET}-src.tar.gz" whl="veyrs-${TARGET}-wheels-x86_64.tar.gz" f from=""
    WHEELS=""
    if [[ "$SOURCE" == release ]]; then
        from="${BASE}/v${TARGET}/"
        for f in SHA256SUMS.sig SHA256SUMS veyrs-setup.sh "$tgz"; do
            if ! curl -fsSL --proto '=https,file' --retry 3 --connect-timeout 15 --max-time 1800 \
                    -o "$WORK/$f" "$BASE/v${TARGET}/$f" >>"$LOG" 2>&1; then
                rm -f "$WORK/$f"
                [[ "$f" == SHA256SUMS.sig ]] \
                    && refuse download "UNSIGNED: release ${TARGET} has no SHA256SUMS.sig; the updater installs signed releases only"
                fail download "could not download ${f} from ${BASE}/v${TARGET}/"
            fi
        done
        # Releases from 0.34.0 carry their Python packages. If SHA256SUMS lists
        # them they are fetched, so the install needs no PyPI; older releases do not.
        if listed "$whl"; then
            curl -fsSL --proto '=https,file' --retry 3 --connect-timeout 15 --max-time 3600 \
                 -o "$WORK/$whl" "$BASE/v${TARGET}/$whl" >>"$LOG" 2>&1 \
                || fail download "SHA256SUMS lists ${whl} but it could not be downloaded from ${from}"
            WHEELS="$whl"
        fi
    else
        local dir="" cand
        if [[ "$SOURCE" == upload ]]; then
            cand="$APP_DIR/var/update-uploads/v${TARGET}"
            [[ -f "$cand/$tgz" ]] && dir="$cand"
            [[ -n "$dir" ]] || refuse download "no uploaded copy of ${TARGET} in ${cand}"
        else
            [[ -n "$LOCAL_DIR" && "$LOCAL_DIR" == /* ]] \
                || refuse download "source=local, but VEYRS_UPDATE_LOCAL_DIR is not set to an absolute path in ${APP_DIR}/.env"
            for cand in "$LOCAL_DIR/v${TARGET}" "$LOCAL_DIR/veyrs-${TARGET}" "$LOCAL_DIR"; do
                [[ -f "$cand/$tgz" ]] && { dir="$cand"; break; }
            done
            [[ -n "$dir" ]] || refuse download "${tgz} is not in ${LOCAL_DIR}, ${LOCAL_DIR}/v${TARGET} or ${LOCAL_DIR}/veyrs-${TARGET}"
        fi
        from="${dir}/"
        for f in SHA256SUMS.sig SHA256SUMS veyrs-setup.sh "$tgz" "$whl"; do
            if [[ ! -e "$dir/$f" ]]; then
                [[ "$f" == "$whl" ]] && continue
                [[ "$f" == SHA256SUMS.sig ]] \
                    && refuse download "UNSIGNED: ${dir} has no SHA256SUMS.sig; the updater installs signed releases only"
                refuse download "${dir} has no ${f}: copy every file of the release"
            fi
            # Never follow a link out of a directory somebody else may write to.
            [[ -L "$dir/$f" || ! -f "$dir/$f" ]] && refuse download "${dir}/${f} is not a regular file"
            cp --no-dereference --preserve=timestamps "$dir/$f" "$WORK/$f" 2>>"$LOG" \
                || fail download "could not copy ${dir}/${f}"
            chmod 600 "$WORK/$f"
            [[ "$f" == "$whl" ]] && WHEELS="$whl"
        done
        if [[ -z "$WHEELS" ]] && listed "$whl"; then
            refuse download "SHA256SUMS lists ${whl} but ${dir} does not have it: copy every file of the release"
        fi
    fi
    step download 1 "SHA256SUMS, SHA256SUMS.sig, veyrs-setup.sh, ${tgz}${WHEELS:+ and ${WHEELS}} from ${from}"

    # ------------------------------------------------------------- verify
    local rc=0 out
    local req_args=(--require veyrs-setup.sh --require "$tgz")
    [[ -n "$WHEELS" ]] && req_args+=(--require "$WHEELS")
    "$APP_DIR/scripts/verify-release.sh" --ignore-missing "${req_args[@]}" \
        --allowed-signers "$SIGNERS" "$WORK" >"$WORK/verify.out" 2>&1 || rc=$?
    cat "$WORK/verify.out" >>"$LOG"
    out="$(tail -3 "$WORK/verify.out" | tr '\n' ' ')"
    case "$rc" in
        0) ;;
        3) refuse verify "UNSIGNED: ${out}" ;;
        4) refuse verify "BAD SIGNATURE: the release is not signed by the trusted key. ${out}" ;;
        5) refuse verify "HASH MISMATCH: ${out}" ;;
        6) refuse verify "CANNOT VERIFY (no usable trusted key in ${SIGNERS}, or no ssh-keygen): ${out}" ;;
        *) refuse verify "verify-release.sh failed (exit ${rc}): ${out}" ;;
    esac
    local tv
    tv="$(tar -xzOf "$WORK/$tgz" "veyrs-${TARGET}/pyproject.toml" 2>/dev/null \
          | sed -n 's/^version *= *"\([^"]*\)".*/\1/p' | head -1)"
    [[ "$tv" == "$TARGET" ]] || refuse verify "the signed tarball declares version '${tv}', not ${TARGET}"
    step verify 1 "signature good (release@veyrs) and every asset matches the signed SHA256SUMS"

    # ------------------------------------------------------------- backup
    local hook="${VEYRS_UPDATE_PRE_HOOK:-}"
    if [[ -n "$hook" ]]; then
        hook_is_safe "$hook" || refuse backup "$HOOK_PROBLEM"
        rc=0
        VEYRS_UPDATE_FROM="$FROM" VEYRS_UPDATE_TARGET="$TARGET" timeout 3600 "$hook" >>"$LOG" 2>&1 || rc=$?
        [[ "$rc" -eq 0 ]] || fail backup "the pre-update hook ${hook} failed (exit ${rc}); nothing was changed"
        step backup 1 "pre-update hook ${hook} succeeded"
    else
        step backup 1 "skipped: VEYRS_UPDATE_SKIP_BACKUP is set (the operator's explicit choice)"
    fi

    # ------------------------------------------------------------ install
    local setup="${VEYRS_UPDATER_SETUP:-$WORK/veyrs-setup.sh}"
    rc=0
    local wh_args=()
    [[ -n "$WHEELS" ]] && wh_args=(--wheels "$WORK/$WHEELS")
    SETUP_EXISTING=update SETUP_MODE=native timeout 3600 \
        bash "$setup" --yes --version "$TARGET" --source "$WORK/$tgz" "${wh_args[@]}" >>"$LOG" 2>&1 || rc=$?
    if [[ "$rc" -ne 0 ]]; then
        fail install "veyrs-setup.sh exited ${rc}: $(tail -4 "$LOG" | tr '\n' ' ') -- restore from the pre-update backup if the API does not come back"
    fi
    step install 1 "veyrs-setup.sh --yes --source ${tgz} (SETUP_EXISTING=update) finished"

    # ------------------------------------------------------------- health
    local deadline=$(( $(date +%s) + HEALTH_TIMEOUT )) body="" ver="" ready=""
    while :; do
        body="$(curl -fsS --max-time 5 "$HEALTH/healthz" 2>/dev/null || true)"
        ver="$(printf '%s' "$body" | sed -n 's/.*"version"[[:space:]]*:[[:space:]]*"\([^"]*\)".*/\1/p')"
        ready="$(curl -s -o /dev/null -w '%{http_code}' --max-time 5 "$HEALTH/readyz" 2>/dev/null || true)"
        [[ "$ver" == "$TARGET" && "$ready" == 200 ]] && break
        if [[ $(date +%s) -ge $deadline ]]; then
            fail health "after ${HEALTH_TIMEOUT}s /healthz reports '${ver:-no answer}' (want ${TARGET}) and /readyz answers ${ready:-nothing}"
        fi
        sleep 3
    done
    step health 1 "/healthz reports ${TARGET}; /readyz 200"
    finish succeeded
}

# ---------------------------------------------------------------- helpers ---
now() { date -u +%Y-%m-%dT%H:%M:%SZ; }
truthy() { case "$(printf '%s' "$1" | tr '[:upper:]' '[:lower:]')" in 1|true|yes|on) return 0 ;; *) return 1 ;; esac; }
newer() { [[ "$(printf '%s\n%s\n' "$1" "$2" | sort -V | tail -1)" == "$1" ]]; }  # newer A B -> A >= B
# listed NAME: does the (not yet verified) SHA256SUMS in the work dir name it?
# Only used to decide what to fetch; verify-release.sh decides what to trust.
listed() { [[ -f "$WORK/SHA256SUMS" ]] && awk -v n="$1" '$2 == n || $2 == "*" n { f = 1 } END { exit !f }' "$WORK/SHA256SUMS"; }

# JSON string: printable ASCII only (a log tail may hold anything), escaped.
js() {
    local s
    s="$(printf '%s' "$1" | LC_ALL=C tr '\n\t\r' '   ' | LC_ALL=C tr -cd '\40-\176')"
    s="${s//\\/\\\\}"; s="${s//\"/\\\"}"
    printf '"%s"' "$s"
}
jn() { if [[ -n "$1" ]]; then js "$1"; else printf 'null'; fi; }

step() {  # step NAME OK(1|0) DETAIL
    local ok=false; [[ "$2" == 1 ]] && ok=true
    STEPS+="${STEPS:+,}{\"name\":$(js "$1"),\"ok\":$ok,\"detail\":$(js "${3:0:1500}"),\"at\":$(js "$(now)")}"
    printf '[%s] %s %s: %s\n' "$(now)" "$([[ $ok == true ]] && echo OK || echo FAIL)" "$1" "$3" | tee -a "$LOG"
    write_status
}

write_status() {
    local ok=false fin="null" tmp
    [[ "$STATE" == succeeded ]] && ok=true
    [[ "$STATE" != running ]] && fin="$(js "$(now)")"
    tmp="$STATUS_DIR/.${ID}.json.part"
    printf '{"id":%s,"state":%s,"ok":%s,"target_version":%s,"from_version":%s,"requested_by":%s,"request_file":%s,"started_at":%s,"finished_at":%s,"log":%s,"steps":[%s]}\n' \
        "$(js "$ID")" "$(js "$STATE")" "$ok" "$(jn "$TARGET")" "$(jn "$FROM")" "$(jn "$WHO")" \
        "$(js "$(basename "$REQ")")" "$(js "$STARTED")" "$fin" "$(js "$LOG")" "$STEPS" >"$tmp" \
        && chmod 644 "$tmp" && mv -f "$tmp" "$STATUS_DIR/$ID.json"
}

finish() {  # finish succeeded|failed|refused
    STATE="$1"; FINISHED=1
    write_status
    rm -f "$REQ"
    [[ -n "$WORK" && -d "$WORK" ]] && rm -rf "$WORK"
    # Keep the last 20 runs.
    local old
    for old in $(ls -1t "$STATUS_DIR"/*.json 2>/dev/null | tail -n +21); do
        rm -f "$old" "${old%.json}.log"
    done
    echo "veyrs-updater: ${STATE} (${STATUS_DIR}/${ID}.json)"
    [[ "$STATE" == succeeded ]] && exit 0
    exit 1
}
refuse() { step "$1" 0 "$2"; finish refused; }   # stopped before anything changed
fail()   { step "$1" 0 "$2"; finish failed; }

on_exit() {
    local rc=$?
    if [[ "$FINISHED" -eq 0 && -n "${ID:-}" ]]; then
        STEPS+="${STEPS:+,}{\"name\":\"updater\",\"ok\":false,\"detail\":\"terminated unexpectedly (exit ${rc})\",\"at\":$(js "$(now)")}"
        STATE=failed; write_status; rm -f "$REQ"
        [[ -n "$WORK" && -d "$WORK" ]] && rm -rf "$WORK"
    fi
}

# The hook runs as root. It must be a file only root can change, outside the
# API's one writable directory (var/): otherwise the sandboxed API could plant
# what the root updater executes.
HOOK_PROBLEM=""
hook_is_safe() {
    local h="$1" owner mode real
    [[ "$h" == /* ]] || { HOOK_PROBLEM="VEYRS_UPDATE_PRE_HOOK must be an absolute path (no arguments)"; return 1; }
    [[ -f "$h" && -x "$h" ]] || { HOOK_PROBLEM="VEYRS_UPDATE_PRE_HOOK ${h} is not an executable file"; return 1; }
    real="$(readlink -f "$h")"
    owner="$(stat -L -c %u "$h")"; mode="$(stat -L -c %a "$h")"
    [[ "$owner" == 0 ]] || { HOOK_PROBLEM="VEYRS_UPDATE_PRE_HOOK ${h} is not owned by root"; return 1; }
    if (( 8#$mode & 8#022 )); then HOOK_PROBLEM="VEYRS_UPDATE_PRE_HOOK ${h} is writable by group/other (mode ${mode})"; return 1; fi
    case "$real" in "$APP_DIR"/var/*|"$SPOOL"/*) HOOK_PROBLEM="VEYRS_UPDATE_PRE_HOOK ${h} lives in a directory the API can write"; return 1 ;; esac
    return 0
}

main "$@"; exit $?
