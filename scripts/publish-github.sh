#!/usr/bin/env bash
# Publishes the sanitised VEYRS tree to GitHub as a repository with ONE derived
# commit, and (optionally) its v<version> release with the assets.
#
# It does NOT touch the internal Gitea repo: the public tree is DERIVED with
# scripts/public-export.sh and published from a separate directory, so the
# internal history (73 commits, with the credential leak inside) never leaves.
#
# GitHub credential — two paths, the SAME guards on both:
#   * `gh` installed and authenticated  -> gh is used (the original path).
#   * no gh (the pipeline host does not ship it, nor jq): curl + python3 against
#     the REST API with GH_TOKEN. The token travels in a 0600 header file
#     (`curl -H @file`) and in git's environment
#     (http.extraheader via GIT_CONFIG_*), NEVER in argv or in a URL: argv is
#     visible to anyone running `ps`, and a URL with credentials ends up in logs.
#   USE_GH=no forces the curl path even if gh is present.
#
# Usage:
#   ./publish-github.sh                   # dry-run: exports, verifies, does NOT publish
#   ./publish-github.sh --publish         # creates the repo and publishes (fails if it exists)
#   ./publish-github.sh --update          # REPLACES the derived commit of a repo
#                                         # that already exists (force-push, guarded).
#                                         # If the remote ALREADY has exactly this
#                                         # tree, nothing is pushed (idempotent).
#   ./publish-github.sh --release-build X # builds and VERIFIES the assets of
#                                         # release X from the tree already exported
#                                         # to $OUT. No network.
#   ./publish-github.sh --release X       # re-verifies the assets, tags the
#                                         # mirror commit (annotated tag vX) and
#                                         # creates/updates the release with them.
#                                         # Re-running it REPLACES the assets,
#                                         # never duplicates them.
#
# Variables:
#   REPO=visionebc/veyrs    destination on GitHub
#   VIS=public              visibility
#   OUT=/tmp/veyrs-public   exported tree (and, after a run, the derived commit)
#   ASSETS=$OUT.assets      directory holding the release assets
#   GH_TOKEN                token (no-gh path)
#   PUB_NAME / PUB_EMAIL    author of the public commit and tag (noreply)
#   SOURCE_DATE_EPOCH       mtime of the files in the tarball (reproducible)
set -euo pipefail

REPO="${REPO:-visionebc/veyrs}"
VIS="${VIS:-public}"
# The default root is the script's own, not /opt/veyrs: the documented flow
# publishes from a COPY of the repo on another host, and a fixed path makes that
# flow use the exporter of ANOTHER tree — or fail because it does not exist. SRC=
# still works to point at a different tree on purpose.
SELF_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SRC="${SRC:-$SELF_ROOT}"
OUT="${OUT:-/tmp/veyrs-public}"
ASSETS="${ASSETS:-$OUT.assets}"
API="${GITHUB_API:-https://api.github.com}"
UPLOADS="${GITHUB_UPLOADS:-https://uploads.github.com}"
USE_GH="${USE_GH:-auto}"
# The commit email is the account's noreply address, NOT the personal one.
# GitHub rejects the push with GH007 if the private email is hidden, but the
# rejection is the least of it: a PUBLIC repo with the personal email as author
# is a leak the exporter does not cover — it sanitises files, not git metadata.
PUB_NAME="${PUB_NAME:-visionebc}"
PUB_EMAIL="${PUB_EMAIL:-34753443+visionebc@users.noreply.github.com}"

# The public model is ONE derived commit. Creating and updating are different
# operations with different risks, so they are different flags: --publish cannot
# overwrite anything because it requires the repo NOT to exist, and --update
# knows it is going to replace and proves it is safe before doing so.
VERSION=""
case "${1:-}" in
  "")              MODE=dryrun ;;
  --publish)       MODE=create ;;
  --update)        MODE=update ;;
  --release-build) MODE=relbuild; VERSION="${2:-}" ;;
  --release)       MODE=release;  VERSION="${2:-}" ;;
  *)  printf 'usage: %s [--publish|--update|--release-build X.Y.Z|--release X.Y.Z]\n' "$0" >&2
      exit 2 ;;
esac
if [[ "$MODE" == relbuild || "$MODE" == release ]]; then
  [[ "$VERSION" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
    printf 'usage: %s %s X.Y.Z  (version received: %q)\n' "$0" "$1" "$VERSION" >&2; exit 2; }
fi
PUBLISH=0
[[ "$MODE" == create || "$MODE" == update ]] && PUBLISH=1

say() { printf '\n\033[1m==> %s\033[0m\n' "$*"; }
die() { printf '\n\033[31mFAILED: %s\033[0m\n' "$*" >&2; exit 1; }

case "$PUB_EMAIL" in
  *@users.noreply.github.com) ;;
  *) die "PUB_EMAIL must be a GitHub noreply address; '$PUB_EMAIL' would be published as is." ;;
esac

WORK_TMP="$(mktemp -d "${TMPDIR:-/tmp}/veyrs-pub.XXXXXX")"
chmod 700 "$WORK_TMP"
trap 'rm -rf "$WORK_TMP"' EXIT

# ------------------------------------------------------ GitHub backend
HAVE_GH=0
if [[ "$USE_GH" != no ]] && command -v gh >/dev/null 2>&1; then HAVE_GH=1; fi

# Header file holding the token: 0600 inside a 0700 directory. printf is a
# builtin, so the token does not pass through any process's argv either.
HDR="$WORK_TMP/auth.hdr"
: >"$HDR"; chmod 600 "$HDR"
if [[ -z "${GH_TOKEN:-}" && $HAVE_GH -eq 1 && ( "$MODE" == release ) ]]; then
  GH_TOKEN="$(gh auth token 2>/dev/null || true)"
fi
[[ -n "${GH_TOKEN:-}" ]] && printf 'Authorization: Bearer %s\n' "$GH_TOKEN" >"$HDR"

# api METHOD PATH|URL [BODY_FILE] [CONTENT-TYPE]
#   Response body in $API_BODY, HTTP code in $API_CODE.
#   Returns 0 only on 2xx. A curl failure (DNS, TLS) is code 000: it is NEVER
#   read as "does not exist".
API_BODY="$WORK_TMP/api.body"
API_CODE=000
lc() { cat "$WORK_TMP/api.code" 2>/dev/null || echo 000; }
api() {
  local method="$1" url="$2" data="${3:-}" ctype="${4:-application/json}"
  [[ "$url" == http* ]] || url="$API/$url"
  local args=(-sS -o "$API_BODY" -w '%{http_code}' -X "$method"
              -H 'Accept: application/vnd.github+json'
              -H 'X-GitHub-Api-Version: 2022-11-28')
  [[ -s "$HDR" ]] && args+=(-H "@$HDR")
  [[ -n "$data" ]] && args+=(-H "Content-Type: $ctype" --data-binary "@$data")
  : >"$API_BODY"
  API_CODE="$(curl "${args[@]}" "$url" 2>"$WORK_TMP/curl.err")" || API_CODE=000
  [[ "$API_CODE" =~ ^[0-9]{3}$ ]] || API_CODE=000
  # Also to a file: the guards call api() inside $(...), and a subshell's
  # variables do not come back — the error message would say 000 for a 401.
  printf '%s' "$API_CODE" >"$WORK_TMP/api.code"
  [[ "$API_CODE" =~ ^2 ]]
}

# jget FIELD < json   ->  value, or rc=3 if missing (deny by default: a missing
# field is not an empty value). `length` = length of a list.
jget() {
  python3 -c '
import json, sys
try:
    d = json.load(sys.stdin)
except Exception:
    sys.exit(3)
p = sys.argv[1]
if p == "length":
    if not isinstance(d, list):
        sys.exit(3)
    print(len(d)); sys.exit(0)
for k in p.split("."):
    if isinstance(d, list):
        try:
            d = d[int(k)]
        except (ValueError, IndexError):
            sys.exit(3)
    elif isinstance(d, dict) and k in d and d[k] is not None:
        d = d[k]
    else:
        sys.exit(3)
if isinstance(d, bool):
    d = "true" if d else "false"
if isinstance(d, (dict, list)):
    sys.exit(3)
print(d)
' "$1"
}

# ---------------------------------------------------------- remote guards
# Each one returns the value or FAILS. Never a default value.
gh_login() {
  if [[ $HAVE_GH -eq 1 ]]; then gh api user --jq .login; return; fi
  api GET user || return 1
  jget login <"$API_BODY"
}

# repo_exists -> 0 exists, 1 does not exist (404), 2 unknown (anything else)
repo_exists() {
  if [[ $HAVE_GH -eq 1 ]]; then
    gh repo view "$REPO" >/dev/null 2>&1 && return 0
    return 1
  fi
  if api GET "repos/$REPO"; then return 0; fi
  [[ "$API_CODE" == 404 ]] && return 1
  return 2
}

remote_owner() {
  if [[ $HAVE_GH -eq 1 ]]; then gh repo view "$REPO" --json owner --jq .owner.login; return; fi
  api GET "repos/$REPO" || return 1
  jget owner.login <"$API_BODY"
}

remote_branch() {
  if [[ $HAVE_GH -eq 1 ]]; then
    gh repo view "$REPO" --json defaultBranchRef --jq .defaultBranchRef.name; return; fi
  api GET "repos/$REPO" || return 1
  jget default_branch <"$API_BODY"
}

remote_commit_count() {
  if [[ $HAVE_GH -eq 1 ]]; then gh api "repos/$REPO/commits?per_page=100" --jq 'length'; return; fi
  api GET "repos/$REPO/commits?per_page=100" || return 1
  jget length <"$API_BODY"
}

remote_has_file() {
  if [[ $HAVE_GH -eq 1 ]]; then
    gh api "repos/$REPO/contents/$1" --jq .name >/dev/null 2>&1; return; fi
  api GET "repos/$REPO/contents/$1" || return 1
  [[ "$(jget name <"$API_BODY")" == "$1" ]]
}

remote_head() { # remote_head sha|date|tree
  local field
  case "$1" in
    sha)  field=sha ;;
    date) field=commit.committer.date ;;
    tree) field=commit.tree.sha ;;
  esac
  if [[ $HAVE_GH -eq 1 ]]; then gh api "repos/$REPO/commits/HEAD" --jq ".$field"; return; fi
  api GET "repos/$REPO/commits/HEAD" || return 1
  jget "$field" <"$API_BODY"
}

remote_summary() {
  if [[ $HAVE_GH -eq 1 ]]; then
    gh api "repos/$REPO" \
      --jq '"repo: \(.name)  visibility: \(.visibility)  branch: \(.default_branch)  license: \(.license.name // "not detected")"'
    return
  fi
  api GET "repos/$REPO" || return 1
  python3 -c '
import json, sys
d = json.load(sys.stdin)
lic = (d.get("license") or {}).get("name") or "not detected"
print("repo: %s  visibility: %s  branch: %s  license: %s"
      % (d["name"], d["visibility"], d["default_branch"], lic))' <"$API_BODY"
}

remote_commits_published() {
  if [[ $HAVE_GH -eq 1 ]]; then gh api "repos/$REPO/commits" --jq 'length'; return; fi
  api GET "repos/$REPO/commits" || return 1
  jget length <"$API_BODY"
}

# git push with the token in git's ENVIRONMENT (GIT_CONFIG_*), not in the URL.
git_push_github() { # git_push_github [--force]
  if [[ $HAVE_GH -eq 1 ]]; then
    gh auth setup-git >/dev/null 2>&1 || true
    git push "$@" github main
    return
  fi
  local b64
  b64="$(printf 'x-access-token:%s' "$GH_TOKEN" | base64 -w0)"
  GIT_CONFIG_COUNT=1 \
  GIT_CONFIG_KEY_0="http.https://github.com/.extraheader" \
  GIT_CONFIG_VALUE_0="AUTHORIZATION: basic $b64" \
  GIT_TERMINAL_PROMPT=0 \
    git push "$@" github main
}

# ------------------------------------------------- tree verification
# The second verification, INDEPENDENT of the exporter: same POLICY, deliberately
# different implementation — two copies of the same code are not two checks.
# It runs on the exported tree and, for a release, on the CONTENTS of the
# already-extracted tarball: what gets uploaded is what gets checked.
verify_tree() { # verify_tree <dir>
  local here="$PWD" dir="$1"
  cd "$dir"

  for f in .bootstrap-credentials var/backups .env; do
    if [[ -e "$f" ]]; then cd "$here"; die "the tree $dir contains '$f'. Aborted."; fi
  done

  # grep: 0 = found something = leak. 1 = clean. >1 = grep's own error, which
  # must NOT be read as "clean": it aborts too.
  local out rc
  rc=0
  out="$(grep -rIlE '(VEYRS_SECRET_KEY|VEYRS_ENCRYPTION_KEY)[[:space:]]*[=:][[:space:]]*[A-Za-z0-9+/_=-]{20,}' .)" || rc=$?
  if [[ $rc -gt 1 ]]; then cd "$here"; die "grep failed while searching for secrets (rc=$rc). Aborted."; fi
  if [[ $rc -eq 0 ]]; then
    printf '%s\n' "$out" | head -20 >&2
    cd "$here"; die "secrets with real values in $dir. Aborted."
  fi
  printf '     ok: no secrets with real values\n'

  # Addresses: deny by default, allow only the documentation literals.
  # The examples are ERASED from the line, the line is not suppressed: a real
  # IP can share a line with an example.
  # LICENSE is exempt: `licensing@...` is the licensor's real contact.
  local ip_left
  ip_left="$(grep -rInE '10\.0\.0\.[0-9]{1,3}|172\.20\.10\.[0-9]{1,3}|prt0[1-9]' . \
               --exclude=LICENSE --binary-files=without-match 2>/dev/null \
             | sed -E 's/10\.0\.0\.(0|1|2|5|9|99)([^0-9]|$)/<example>\2/g' \
             | grep -E '10\.0\.0\.[0-9]|172\.20\.10\.[0-9]|prt0[1-9]' || true)"
  if [[ -n "$ip_left" ]]; then
    printf '%s\n' "$ip_left" | head -10 | cut -c1-160 >&2
    cd "$here"; die "internal addresses in $dir. Aborted."
  fi
  printf '     ok: no internal addresses (outside the documentation examples)\n'

  local host_left
  host_left="$(grep -rInE '[[:alnum:]*_-]+\.visionebc\.(com|mx)' . \
                 --exclude=LICENSE --binary-files=without-match 2>/dev/null || true)"
  if [[ -n "$host_left" ]]; then
    printf '%s\n' "$host_left" | head -10 | cut -c1-160 >&2
    cd "$here"; die "internal hostnames in $dir. Aborted."
  fi
  printf '     ok: no internal hostnames\n'

  grep -q 'Elastic License 2.0' LICENSE 2>/dev/null \
    || { cd "$here"; die "LICENSE is not Elastic 2.0 in $dir. Aborted."; }
  [[ -s README.md && -s INSTALL.md && -x install.sh ]] \
    || { cd "$here"; die "README.md / INSTALL.md / install.sh missing in $dir. Aborted."; }
  printf '     clean: %s files\n' "$(find . -type f -not -path './.git/*' | wc -l)"
  cd "$here"
}

# ============================================================== RELEASE =====
ASSET_SETUP="veyrs-setup.sh"
asset_tar() { printf 'veyrs-%s-src.tar.gz' "$VERSION"; }

# File list of the tree: what git tracks in the derived commit AND what is on
# disk must match; otherwise the tree is not the one that was exported.
tree_list() { # tree_list <dir> <output>
  local a="$WORK_TMP/tl.git" b="$WORK_TMP/tl.fs"
  git -C "$1" -c core.quotePath=false ls-files | LC_ALL=C sort >"$a" \
    || die "$1 is not the exported tree with its derived commit (no .git). Run the dry-run first."
  ( cd "$1" && find . -path ./.git -prune -o \( -type f -o -type l \) -print \
      | sed 's,^\./,,' | LC_ALL=C sort ) >"$b"
  if ! cmp -s "$a" "$b"; then
    { diff "$a" "$b" || true; } | head -20 >&2
    die "the disk contents of $1 do not match its derived commit (untracked or deleted files)."
  fi
  [[ -s "$a" ]] || die "the tree $1 is empty."
  cp "$a" "$2"
}

build_release_assets() {
  local tl="$WORK_TMP/tree.list" tar_name mtime
  tar_name="$(asset_tar)"
  tree_list "$OUT" "$tl"
  [[ -f "$OUT/$ASSET_SETUP" ]] || die "the exported tree does not contain $ASSET_SETUP: there is no installer to publish."
  rm -rf "$ASSETS"; mkdir -p "$ASSETS"
  # The installer that gets published is the one from the EXPORTED (sanitised)
  # tree, not the internal checkout's: the same substituter that cleaned
  # everything else cleaned it too.
  cp -p "$OUT/$ASSET_SETUP" "$ASSETS/$ASSET_SETUP"
  mtime="${SOURCE_DATE_EPOCH:-$(git -C "$OUT" log -1 --format=%ct)}"
  # Reproducible: fixed order, owner 0, fixed mtime, gzip -n (no name or date).
  # The tarball comes from the EXPORTED tree — never from the internal checkout,
  # which is how SATOM's tarballs ended up carrying CLAUDE.md, lab configs and
  # credentials.
  tr '\n' '\0' <"$tl" >"$WORK_TMP/tree.list0"
  # --no-recursion is positional: it must come BEFORE -T, or GNU tar aborts
  # ("options were used after any non-optional arguments").
  tar -C "$OUT" --no-recursion --owner=0 --group=0 --numeric-owner \
      --mtime="@$mtime" --format=gnu --transform "s,^,veyrs-$VERSION/,S" \
      --null -T "$WORK_TMP/tree.list0" -cf - \
    | gzip -n -9 >"$ASSETS/$tar_name" \
    || die "tar/gzip failed building $tar_name."
  ( cd "$ASSETS" && sha256sum "$ASSET_SETUP" >"$ASSET_SETUP.sha256" \
                 && sha256sum "$tar_name" >"$tar_name.sha256" )
}

# Before uploading ANYTHING: sha256 of each asset, tarball list == exported
# tree list, tarball contents clean (both verifications), the installer
# identical to the tree's, and the tarball version == the release.
verify_release_assets() {
  local tl="$WORK_TMP/tree.list" tarl="$WORK_TMP/tar.list" tar_name x
  tar_name="$(asset_tar)"
  for f in "$ASSET_SETUP" "$ASSET_SETUP.sha256" "$tar_name" "$tar_name.sha256"; do
    [[ -s "$ASSETS/$f" ]] || die "missing asset $ASSETS/$f."
  done
  ( cd "$ASSETS" && sha256sum --quiet -c "$ASSET_SETUP.sha256" "$tar_name.sha256" ) \
    || die "a .sha256 does not match its asset."
  printf '     ok: asset sha256 sums\n'

  tree_list "$OUT" "$tl"
  tar -tzf "$ASSETS/$tar_name" >"$WORK_TMP/tar.raw" || die "the tarball cannot be read."
  if grep -v "^veyrs-$VERSION/" "$WORK_TMP/tar.raw" | grep -q .; then
    die "the tarball has entries outside veyrs-$VERSION/."
  fi
  # Directory entries first (a tarball re-packed by hand carries them; they
  # are not files), THEN the prefix: stripped first, "veyrs-X/" would become
  # an empty line that no longer ends in "/".
  { grep -v '/$' "$WORK_TMP/tar.raw" || true; } | sed "s,^veyrs-$VERSION/,," | LC_ALL=C sort >"$tarl"
  if ! cmp -s "$tl" "$tarl"; then
    { diff "$tl" "$tarl" || true; } | head -20 >&2
    die "the tarball file list is NOT the exported tree's. Not publishing."
  fi
  printf '     ok: tarball list == exported tree (%s files)\n' "$(wc -l <"$tl")"

  x="$WORK_TMP/extract"
  rm -rf "$x"; mkdir -p "$x"
  tar -xzf "$ASSETS/$tar_name" -C "$x" || die "the tarball cannot be extracted."
  verify_tree "$x/veyrs-$VERSION"
  local pe_out pe_rc=0
  pe_out="$("$SRC/scripts/public-export.sh" --check-only --out "$x/veyrs-$VERSION" 2>&1)" || pe_rc=$?
  if [[ $pe_rc -ne 0 ]]; then
    printf '%s\n' "$pe_out" | tail -30 >&2
    die "the public-export.sh guards reject the tarball CONTENTS (rc=$pe_rc)."
  fi
  printf '     ok: public-export.sh --check-only on the tarball contents\n'

  cmp -s "$ASSETS/$ASSET_SETUP" "$x/veyrs-$VERSION/$ASSET_SETUP" \
    || die "published $ASSET_SETUP is not the tarball's."
  cmp -s "$ASSETS/$ASSET_SETUP" "$OUT/$ASSET_SETUP" \
    || die "published $ASSET_SETUP is not the exported tree's."
  local tv
  tv="$(grep -m1 '^version' "$x/veyrs-$VERSION/pyproject.toml" | cut -d'"' -f2 || true)"
  [[ "$tv" == "$VERSION" ]] \
    || die "the tarball declares version '$tv' but the release is $VERSION."
  printf '     ok: %s identical in tree and tarball; version %s\n' "$ASSET_SETUP" "$VERSION"
}

release_body_file() { # release_body_file <output.json> <tag> <commit>
  VERSION="$VERSION" TAG="$2" COMMIT="$3" CHANGELOG="$OUT/docs/CHANGELOG.md" \
  ASSETS="$ASSETS" TAR="$(asset_tar)" SETUP="$ASSET_SETUP" python3 - >"$1" <<'PY'
import json, os, re
v = os.environ["VERSION"]
notes = ""
try:
    text = open(os.environ["CHANGELOG"], encoding="utf-8").read()
    m = re.search(r"^## \[?%s\]?[^\n]*\n(.*?)(?=^## |\Z)" % re.escape(v), text, re.S | re.M)
    if m:
        notes = m.group(1).strip()
except OSError:
    pass
sums = []
for n in (os.environ["SETUP"], os.environ["TAR"]):
    with open(os.path.join(os.environ["ASSETS"], n + ".sha256")) as fh:
        sums.append(fh.read().strip())
body = (notes or "See docs/CHANGELOG.md.") + (
    "\n\n## Install\n\n```\ncurl -fsSLO https://github.com/visionebc/veyrs/releases/"
    "latest/download/veyrs-setup.sh\nsha256sum -c <(curl -fsSL https://github.com/"
    "visionebc/veyrs/releases/latest/download/veyrs-setup.sh.sha256)\n"
    "sudo bash veyrs-setup.sh\n```\n\n## SHA-256\n\n```\n%s\n```\n" % "\n".join(sums))
print(json.dumps({"tag_name": os.environ["TAG"], "target_commitish": os.environ["COMMIT"],
                  "name": "VEYRS " + v, "body": body[:120000],
                  "draft": False, "prerelease": False}))
PY
}

publish_release() {
  local tag="v$VERSION" local_tree remote_sha remote_tree tar_name
  tar_name="$(asset_tar)"
  [[ -s "$HDR" ]] || die "the release needs GH_TOKEN (or an authenticated gh)."
  local who
  who="$(HAVE_GH=0 gh_login)" || die "the GitHub token is not valid (HTTP $(lc))."
  printf '     authenticated as: %s\n' "$who"

  say "R1  Re-verifying the assets before uploading anything"
  verify_release_assets

  say "R2  The mirror publishes exactly the assets' tree"
  local_tree="$(git -C "$OUT" rev-parse 'HEAD^{tree}')" || die "no derived commit in $OUT."
  remote_sha="$(HAVE_GH=0 remote_head sha)" || die "could not read the mirror's HEAD (HTTP $(lc))."
  remote_tree="$(HAVE_GH=0 remote_head tree)" || die "could not read the mirror's tree (HTTP $(lc))."
  if [[ -n "${COMMIT:-}" && "$COMMIT" != "$remote_sha" ]]; then
    die "COMMIT=$COMMIT but the mirror is at $remote_sha. Aborted."
  fi
  [[ "$remote_tree" == "$local_tree" ]] \
    || die "the mirror ($remote_sha, tree ${remote_tree:0:12}) does not publish the tree of these
     assets (${local_tree:0:12}). Run --update before --release."
  printf '     mirror %s == assets tree %s\n' "${remote_sha:0:7}" "${local_tree:0:12}"

  say "R3  Annotated tag $tag on the mirror commit"
  local tag_commit=""
  if api GET "repos/$REPO/git/ref/tags/$tag"; then
    local otype osha
    otype="$(jget object.type <"$API_BODY")" || die "unreadable tag ref."
    osha="$(jget object.sha <"$API_BODY")" || die "unreadable tag ref."
    if [[ "$otype" == tag ]]; then
      api GET "repos/$REPO/git/tags/$osha" || die "could not read tag $tag (HTTP $(lc))."
      tag_commit="$(jget object.sha <"$API_BODY")" || die "unreadable tag $tag."
    else
      tag_commit="$osha"
    fi
    [[ "$tag_commit" == "$remote_sha" ]] \
      || die "tag $tag ALREADY exists on the mirror pointing to $tag_commit, not $remote_sha.
     Refusing to move a published tag. Aborted."
    printf '     %s already exists at %s (unchanged)\n' "$tag" "${tag_commit:0:7}"
  elif [[ "$API_CODE" == 404 ]]; then
    TAG="$tag" COMMIT_SHA="$remote_sha" V="$VERSION" N="$PUB_NAME" E="$PUB_EMAIL" python3 -c '
import json, os, datetime
print(json.dumps({"tag": os.environ["TAG"], "message": "VEYRS " + os.environ["V"],
  "object": os.environ["COMMIT_SHA"], "type": "commit",
  "tagger": {"name": os.environ["N"], "email": os.environ["E"],
             "date": datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")}}))' \
      >"$WORK_TMP/tag.json"
    api POST "repos/$REPO/git/tags" "$WORK_TMP/tag.json" || die "could not create the tag object (HTTP $(lc))."
    local tobj
    tobj="$(jget sha <"$API_BODY")" || die "unreadable tag response."
    printf '{"ref":"refs/tags/%s","sha":"%s"}\n' "$tag" "$tobj" >"$WORK_TMP/ref.json"
    api POST "repos/$REPO/git/refs" "$WORK_TMP/ref.json" || die "could not create refs/tags/$tag (HTTP $(lc))."
    tag_commit="$remote_sha"
    printf '     %s created -> %s\n' "$tag" "${remote_sha:0:7}"
  else
    die "could not query tag $tag (HTTP $(lc)). Aborted."
  fi

  say "R4  Release $tag"
  release_body_file "$WORK_TMP/release.json" "$tag" "$remote_sha"
  local rid
  if api GET "repos/$REPO/releases/tags/$tag"; then
    rid="$(jget id <"$API_BODY")" || die "unreadable release."
    api PATCH "repos/$REPO/releases/$rid" "$WORK_TMP/release.json" \
      || die "could not update release $rid (HTTP $(lc))."
    printf '     release %s updated\n' "$rid"
  elif [[ "$API_CODE" == 404 ]]; then
    api POST "repos/$REPO/releases" "$WORK_TMP/release.json" \
      || die "could not create the release (HTTP $(lc))."
    rid="$(jget id <"$API_BODY")" || die "release created but unreadable."
    printf '     release %s created\n' "$rid"
  else
    die "could not query release $tag (HTTP $(lc))."
  fi

  say "R5  Assets (REPLACED, never duplicated)"
  local names=("$ASSET_SETUP" "$ASSET_SETUP.sha256" "$tar_name" "$tar_name.sha256")
  api GET "repos/$REPO/releases/$rid/assets?per_page=100" \
    || die "could not list the assets (HTTP $(lc))."
  cp "$API_BODY" "$WORK_TMP/assets.json"
  local n aid
  for n in "${names[@]}"; do
    # Every copy with that name, not just the first: if a duplicate was ever
    # left behind, it is cleaned up here instead of surviving every re-run.
    for aid in $(N="$n" python3 -c '
import json, os, sys
for a in json.load(sys.stdin):
    if a.get("name") == os.environ["N"]:
        print(a["id"])' <"$WORK_TMP/assets.json"); do
      api DELETE "repos/$REPO/releases/assets/$aid" \
        || die "could not delete the previous asset $n ($aid, HTTP $(lc))."
      printf '     deleted previous %s (%s)\n' "$n" "$aid"
    done
    local ctype=application/octet-stream
    [[ "$n" == *.tar.gz ]] && ctype=application/gzip
    api POST "$UPLOADS/repos/$REPO/releases/$rid/assets?name=$n" "$ASSETS/$n" "$ctype" \
      || die "could not upload $n (HTTP $(lc))."
    printf '     uploaded %s (%s bytes)\n' "$n" "$(stat -c %s "$ASSETS/$n")"
  done

  say "R6  Re-reading the release"
  api GET "repos/$REPO/releases/$rid/assets?per_page=100" \
    || die "could not re-read the assets (HTTP $(lc))."
  ASSETS="$ASSETS" NAMES="${names[*]}" BODY="$API_BODY" python3 - <<'PY' || die "the published assets are not the ones built."
import json, os, sys
got = json.load(open(os.environ["BODY"]))
bad = []
for n in os.environ["NAMES"].split():
    hits = [a for a in got if a.get("name") == n]
    size = os.path.getsize(os.path.join(os.environ["ASSETS"], n))
    if len(hits) != 1:
        bad.append("%s appears %d times" % (n, len(hits)))
    elif hits[0].get("size") != size:
        bad.append("%s: %s bytes published, %s built" % (n, hits[0].get("size"), size))
    elif hits[0].get("state", "uploaded") != "uploaded":
        bad.append("%s in state %s" % (n, hits[0].get("state")))
for b in bad:
    print("     " + b, file=sys.stderr)
print("     %d assets, one per name, sizes == built" % len(os.environ["NAMES"].split()))
sys.exit(1 if bad else 0)
PY
  printf 'RELEASE_ID=%s\nRELEASE_TAG=%s\nTAG_COMMIT=%s\n' "$rid" "$tag" "$tag_commit"
  say "Release published: https://github.com/$REPO/releases/tag/$tag"
}

if [[ "$MODE" == relbuild ]]; then
  say "Assets for release $VERSION from $OUT"
  build_release_assets
  verify_release_assets
  ( cd "$ASSETS" && for f in *; do printf 'ASSET %s %s\n' "$f" "$(stat -c %s "$f")"; done )
  exit 0
fi
if [[ "$MODE" == release ]]; then
  publish_release
  exit 0
fi

# ---------------------------------------------------------------- 1. token
say "1/6  Checking the GitHub credential"
if [[ $HAVE_GH -eq 1 ]]; then
  gh api user --jq .login >/dev/null 2>&1 \
    || die "gh is installed but its token is not valid (401). Run: gh auth login"
  printf '     authenticated as: %s (gh)\n' "$(gh api user --jq .login)"
elif [[ -s "$HDR" ]]; then
  who="$(gh_login)" \
    || die "GH_TOKEN is not valid (HTTP $(lc)). Nothing is published without a valid token."
  printf '     authenticated as: %s (REST API, no gh)\n' "$who"
else
  printf '     neither gh nor GH_TOKEN on this host — export + verification only.\n'
  [[ $PUBLISH -eq 1 ]] && die "--publish/--update need gh or GH_TOKEN. Run this
     script without --publish here, or export GH_TOKEN (never on the command line)."
fi

# ---------------------------------------------------- 2. export + guards
say "2/6  Deriving the public tree (denylist + substitution + guards)"
rm -rf "$OUT"
"$SRC/scripts/public-export.sh" --out "$OUT" \
  || die "the exporter or its guards failed. Nothing is published."

# ------------------------------------------- 3. second, strict verification
say "3/6  Independent verification of the exported tree"
verify_tree "$OUT"
cd "$OUT"

# ------------------------------------------------------- 4. single commit
say "4/6  Creating the initial commit (new history, not the internal one)"
rm -rf .git
# Anything produced by running the tests INSIDE the tree. The exporter copies
# only tracked files (`git ls-files`), so this cannot come from it — but a
# `git add -A` would publish it all the same.
find . -name '__pycache__' -type d -prune -exec rm -rf {} + 2>/dev/null || true
find . -name '*.pyc' -o -name '*.pyo' | xargs -r rm -f
rm -rf .pytest_cache .ruff_cache .mypy_cache htmlcov .coverage
if [[ -e .env ]]; then die ".env inside the public tree. Aborted."; fi
printf '     run leftovers purged\n'
git init -q -b main
git add -A
pub_ver="$(grep -m1 '^version' pyproject.toml 2>/dev/null | cut -d'"' -f2 || true)"
git -c user.name="$PUB_NAME" -c user.email="$PUB_EMAIL" \
    commit -q -m "VEYRS — Unified Cybersecurity Risk Management${pub_ver:+ $pub_ver}

Public release under the Elastic License 2.0.
See INSTALL.md for installation and install.sh for an automated setup."
printf '     %s files in 1 commit (author %s <%s>)\n' "$(git ls-files | wc -l)" "$PUB_NAME" "$PUB_EMAIL"
printf 'BUILT_TREE=%s\n' "$(git rev-parse 'HEAD^{tree}')"

# ----------------------------------------------------------- 5. dry-run
if [[ $PUBLISH -eq 0 ]]; then
  say "5/6  DRY-RUN — nothing has been published"
  cat <<EOF

     Tree ready at: $OUT   (1 commit, branch main)
     Intended destination: github.com/$REPO  ($VIS)

     With gh authenticated, or with GH_TOKEN in the environment (no gh or jq needed):
         $0 --publish     (new repo)
         $0 --update      (existing repo: replaces the derived commit)
     And the release with its assets:
         OUT=$OUT $0 --release-build X.Y.Z
         OUT=$OUT $0 --release X.Y.Z

EOF
  exit 0
fi

# ----------------------------------------------------------- 5. publish
SKIPPED_PUSH=0
if [[ "$MODE" == create ]]; then
  say "5/6  Publishing to github.com/$REPO ($VIS) — NEW repository"
  rc=0; repo_exists || rc=$?
  if [[ $rc -eq 0 ]]; then
    die "github.com/$REPO already exists. A push to an existing repo can overwrite
     someone else's history. Use --update, delete it, or change REPO= before continuing."
  fi
  [[ $rc -eq 1 ]] || die "could not determine whether github.com/$REPO exists (HTTP $(lc)). Aborted."
  if [[ $HAVE_GH -eq 1 ]]; then
    gh repo create "$REPO" "--$VIS" \
      --description 'Unified Cybersecurity Risk Management — CVE/CVSS/EPSS/KEV to assets, exposure and business impact' \
      --source . --remote github --push
  else
    owner="${REPO%%/*}"
    REPO_NAME="${REPO#*/}" PRIV="$([[ "$VIS" == public ]] && echo false || echo true)" python3 -c '
import json, os
print(json.dumps({"name": os.environ["REPO_NAME"], "private": os.environ["PRIV"] == "true",
  "description": "Unified Cybersecurity Risk Management — CVE/CVSS/EPSS/KEV to assets, exposure and business impact"}))' \
      >"$WORK_TMP/create.json"
    if [[ "$owner" == "$who" ]]; then path=user/repos; else path="orgs/$owner/repos"; fi
    api POST "$path" "$WORK_TMP/create.json" \
      || die "could not create github.com/$REPO (HTTP $(lc))."
    git remote remove github 2>/dev/null || true
    git remote add github "https://github.com/$REPO.git"
    git_push_github
  fi
else
  say "5/6  Updating github.com/$REPO — EXISTING repository"
  rc=0; repo_exists || rc=$?
  [[ $rc -eq 1 ]] && die "github.com/$REPO does not exist. To create it use --publish."
  [[ $rc -eq 0 ]] || die "could not read github.com/$REPO (HTTP $(lc)). Aborted."

  # Updating the mirror IS replacing its single commit, i.e. a force-push.
  # First we must PROVE that what is on the other side is that derived mirror
  # and not a repository with its own history, which the push would destroy.
  # Every guard denies by default: if a read cannot be done, nothing is published.
  owner="${REPO%%/*}"
  remote_owner="$(remote_owner)" \
    || die "could not read the owner of $REPO. Aborted."
  [[ "$remote_owner" == "$owner" ]] \
    || die "the remote repo belongs to '$remote_owner', not '$owner'. Aborted."

  remote_branch="$(remote_branch)" \
    || die "could not read the default branch of $REPO. Aborted."
  [[ "$remote_branch" == "main" ]] \
    || die "the remote default branch is '$remote_branch', not 'main'. A push
     to 'main' would leave the repo serving the old branch. Aborted."

  n_commits="$(remote_commit_count)" \
    || die "could not count the commits of $REPO. Aborted."
  [[ "$n_commits" =~ ^[0-9]+$ ]] || die "unreadable commit count. Aborted."
  [[ "$n_commits" -le 5 ]] \
    || die "github.com/$REPO has $n_commits commits: that is NOT a mirror of a
     single derived commit. A force-push would destroy real history. Aborted."

  for f in INSTALL.md LICENSE install.sh; do
    remote_has_file "$f" \
      || die "the remote repo does not contain '$f': it does not look like the VEYRS mirror. Aborted."
  done

  old_sha="$(remote_head sha)" || die "could not read the current remote commit. Aborted."
  old_date="$(remote_head date)" || die "could not read the remote commit date. Aborted."
  printf '     the remote passes inspection: %s commit(s), owner %s\n' \
    "$n_commits" "$remote_owner"

  # Idempotence: if the remote ALREADY publishes exactly this tree, replacing its
  # commit would only change the date — and would orphan the release tag that
  # points to it. Failing to read it is NOT "equal": then we push, with the
  # guards above already passed.
  old_tree="$(remote_head tree 2>/dev/null || true)"
  if [[ -n "$old_tree" && "$old_tree" == "$(git rev-parse 'HEAD^{tree}')" ]]; then
    SKIPPED_PUSH=1
    printf '     the remote %s ALREADY publishes this exact tree: nothing is pushed\n' "${old_sha:0:7}"
  else
    printf '     REPLACING commit %s (%s)\n' "${old_sha:0:7}" "$old_date"
    git remote remove github 2>/dev/null || true
    git remote add github "https://github.com/$REPO.git"
    git_push_github --force
  fi
fi

# ---------------------------------------------------------- 6. verify
say "6/6  Verifying the result on GitHub"
# Read through the REST API and not `gh repo view --json`: the set of --json
# fields depends on the gh VERSION (2.23 does not know `visibility`) and a
# missing field aborts step 6 AFTER the force-push — i.e. it leaves the remote
# already replaced and unverified, which is the one state this script must
# never be able to produce. The REST API field names are stable.
remote_summary || die "could not re-read the repository on GitHub after the push."
printf '     published commits: %s (must be 1)\n' "$(remote_commits_published || echo '?')"

# A push's rc does not prove WHAT ended up on the other side. Re-read it.
local_sha="$(git rev-parse HEAD)"
local_tree="$(git rev-parse 'HEAD^{tree}')"
remote_sha="$(remote_head sha)" \
  || die "the push succeeded but the remote commit could not be re-read."
if [[ $SKIPPED_PUSH -eq 1 ]]; then
  remote_tree="$(remote_head tree)" || die "could not re-read the remote tree."
  [[ "$remote_sha" == "$old_sha" && "$remote_tree" == "$local_tree" ]] \
    || die "the remote changed between inspection and verification ($old_sha -> $remote_sha)."
  printf '     remote tree == built tree: %s (commit %s kept)\n' \
    "${local_tree:0:12}" "${remote_sha:0:7}"
else
  [[ "$local_sha" == "$remote_sha" ]] \
    || die "the remote commit ($remote_sha) is not the one just built
     ($local_sha). The push did NOT leave what was verified here."
  printf '     remote commit == built commit: %s\n' "${local_sha:0:7}"
fi
printf 'PUBLISHED_SHA=%s\nPUBLISHED_TREE=%s\n' "$remote_sha" "$local_tree"

say "Published: https://github.com/$REPO"
