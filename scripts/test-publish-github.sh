#!/usr/bin/env bash
# Test harness for publish-github.sh: --update, --publish and the release, on
# BOTH paths (gh, and the REST API without gh).
#
# It does NOT touch GitHub. It replaces `gh` with a scenario-driven stub,
# replaces `curl` with a stub that mimics the REST API (stateful: repo, tags,
# release, assets) and points the "github" remote at a LOCAL bare repository via
# GIT_CONFIG_GLOBAL + insteadOf, so the force-push REALLY runs and the final
# re-read reads a real sha.
#
#   SCRIPT=/path/to/another/copy.sh bash test-publish-github.sh
#     runs the harness against a MUTATED copy of the script (this is how you
#     check the guards bite: the mutated copy must make cases fail).
set -uo pipefail

# The root comes from THIS file's location, not a fixed path: the documented
# flow publishes from a COPY of the repo on another host, and a harness pinned
# to a path fails there with rc=127 in every case — which reads as 'the guards
# do not bite' when in fact nothing ran at all.
REPO_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SCRIPT="${SCRIPT:-$REPO_ROOT/scripts/publish-github.sh}"
W=/tmp/pubtest
rm -rf "$W"; mkdir -p "$W/bin"
BARE="$W/remote.git"
STATE="$W/api"
ARGV_LOG="$W/curl.argv"
# A token with a real shape but made up. At the end the harness checks that it
# does NOT appear in the argv of any curl call.
FAKE_TOKEN="ghs_FAKEtokenFORtheHARNESS0123456789abcd"
VER="$(grep -m1 '^version' "$REPO_ROOT/pyproject.toml" | cut -d'"' -f2)"

fresh_bare() { rm -rf "$BARE"; git init -q --bare -b main "$BARE"; }
fresh_bare

# --------------------------------------------------------------- gh stub
cat >"$W/bin/gh" <<'STUB'
#!/usr/bin/env bash
# Scenario via $SCEN. Each branch mimics gh's real output for that call.
args="$*"
sha_real() { git --git-dir="$BARE" rev-parse --verify -q main 2>/dev/null || echo 0000000000000000000000000000000000000000; }
tree_real() { git --git-dir="$BARE" rev-parse --verify -q 'main^{tree}' 2>/dev/null || echo 0000000000000000000000000000000000000000; }

case "$args" in
  "api user --jq .login")            echo visionebc-test; exit 0 ;;
  "auth setup-git")                  exit 0 ;;
esac

# does the repo exist?
if [[ "$args" == "repo view visionebc/veyrs" ]]; then
  [[ "$SCEN" == "notfound" ]] && exit 1
  exit 0
fi

case "$args" in
  "repo view visionebc/veyrs --json owner --jq .owner.login")
      [[ "$SCEN" == "foreign" ]] && { echo otherfork; exit 0; }
      echo visionebc; exit 0 ;;
  "repo view visionebc/veyrs --json defaultBranchRef --jq .defaultBranchRef.name")
      [[ "$SCEN" == "master" ]] && { echo master; exit 0; }
      echo main; exit 0 ;;
  "api repos/visionebc/veyrs/commits?per_page=100 --jq length")
      [[ "$SCEN" == "history" ]] && { echo 73; exit 0; }
      echo 1; exit 0 ;;
  "api repos/visionebc/veyrs/contents/INSTALL.md --jq .name")
      [[ "$SCEN" == "nofile" ]] && exit 1
      echo INSTALL.md; exit 0 ;;
  "api repos/visionebc/veyrs/contents/LICENSE --jq .name")   echo LICENSE;   exit 0 ;;
  "api repos/visionebc/veyrs/contents/install.sh --jq .name") echo install.sh; exit 0 ;;
  "api repos/visionebc/veyrs/commits/HEAD --jq .sha")
      [[ "$SCEN" == "phantompush" ]] && { echo deadbeefdeadbeefdeadbeefdeadbeefdeadbeef; exit 0; }
      sha_real; exit 0 ;;
  "api repos/visionebc/veyrs/commits/HEAD --jq .commit.tree.sha")
      tree_real; exit 0 ;;
  "api repos/visionebc/veyrs/commits/HEAD --jq .commit.committer.date")
      echo 2026-09-21T14:57:00Z; exit 0 ;;
  "api repos/visionebc/veyrs/commits --jq length") echo 1; exit 0 ;;
  # The step 6 summary is read through the REST API: --json depends on the gh
  # version and a missing field used to abort the step AFTER the force-push.
  "api repos/visionebc/veyrs --jq "*)
      echo 'repo: veyrs  visibility: public  branch: main  license: Other'; exit 0 ;;
  "repo create"*)
      echo "[stub] gh repo create: $args"; exit 0 ;;
esac
echo "[stub] UNEXPECTED gh call: $args" >&2
exit 90
STUB
chmod +x "$W/bin/gh"

# ------------------------------------------------------------- curl stub
# Mimics the GitHub REST API for the calls publish-github.sh makes without gh.
# With STATE in $STATE (repo created, tags, release, assets), so that a re-run
# sees what the previous one left. Requires the token in a header file
# (-H @file): without it, 401 — just like GitHub.
cat >"$W/bin/curl" <<'STUB'
#!/usr/bin/env python3
import json, os, re, subprocess, sys

argv = sys.argv[1:]
with open(os.environ["ARGV_LOG"], "a") as fh:
    fh.write(" ".join(argv) + "\n")

out = fmt = data = None
method = "GET"
headers = []
url = None
i = 0
while i < len(argv):
    a = argv[i]
    if a in ("-o",):
        out = argv[i + 1]; i += 2; continue
    if a == "-w":
        fmt = argv[i + 1]; i += 2; continue
    if a == "-X":
        method = argv[i + 1]; i += 2; continue
    if a == "-H":
        h = argv[i + 1]
        if h.startswith("@"):
            headers += open(h[1:]).read().splitlines()
        else:
            headers.append(h)
        i += 2; continue
    if a == "--data-binary":
        data = open(argv[i + 1][1:], "rb").read(); i += 2; continue
    if a.startswith("-"):
        i += 1; continue
    url = a; i += 1

scen = os.environ.get("SCEN", "normal")
state_dir = os.environ["STATE"]
os.makedirs(state_dir, exist_ok=True)
sp = os.path.join(state_dir, "state.json")
st = json.load(open(sp)) if os.path.exists(sp) else {
    "created": False, "tags": {}, "tagobjs": {}, "release": None, "assets": [], "next": 100}
if scen == "foreigntag" and not st["tags"]:
    st["tagobjs"]["t-foreign"] = "cafecafecafecafecafecafecafecafecafecafe"
    st["tags"]["v" + os.environ["VER"]] = "t-foreign"

bare = os.environ["BARE"]
ZERO = "0" * 40
def git(*a):
    r = subprocess.run(["git", "--git-dir=" + bare] + list(a), capture_output=True, text=True)
    return r.stdout.strip() if r.returncode == 0 else ZERO

def reply(code, body=None):
    json.dump(st, open(sp, "w"))
    if out:
        with open(out, "w") as fh:
            fh.write(json.dumps(body) if body is not None else "")
    if fmt:
        sys.stdout.write(fmt.replace("%{http_code}", str(code)))
    sys.exit(0)

token_ok = any(h == "Authorization: Bearer " + os.environ["FAKE_TOKEN"] for h in headers)
if not token_ok or scen == "badtoken":
    reply(401, {"message": "Bad credentials"})

m = re.match(r"https://(api|uploads)\.github\.com/(.*)$", url or "")
if not m:
    reply(599, {"message": "stub: unexpected url %s" % url})
path = m.group(2)
R = "repos/visionebc/veyrs"
exists = scen not in ("notfound",) or st["created"]

if path == "user" and method == "GET":
    reply(200, {"login": "visionebc"})
if path == "user/repos" and method == "POST":
    st["created"] = True
    reply(201, {"full_name": "visionebc/veyrs"})
if path == R and method == "GET":
    if scen == "api500":
        reply(500, {"message": "boom"})
    if not exists:
        reply(404, {"message": "Not Found"})
    reply(200, {"name": "veyrs", "visibility": "public",
                "owner": {"login": "otherfork" if scen == "foreign" else "visionebc"},
                "default_branch": "master" if scen == "master" else "main",
                "license": {"name": "Other"}})
if not exists:
    reply(404, {"message": "Not Found"})
if path == R + "/commits?per_page=100":
    reply(200, [{}] * (73 if scen == "history" else 1))
if path == R + "/commits":
    reply(200, [{}])
mm = re.match(re.escape(R) + r"/contents/(.+)$", path)
if mm:
    if scen == "nofile" and mm.group(1) == "INSTALL.md":
        reply(404, {"message": "Not Found"})
    reply(200, {"name": mm.group(1)})
if path == R + "/commits/HEAD":
    sha = git("rev-parse", "--verify", "-q", "main")
    tree = git("rev-parse", "--verify", "-q", "main^{tree}")
    if scen == "phantompush":
        sha = "deadbeef" * 5
    if scen == "foreigntree":
        tree = "abad1dea" * 5
    reply(200, {"sha": sha, "commit": {"tree": {"sha": tree},
                                       "committer": {"date": "2026-09-21T14:57:00Z"}}})
mm = re.match(re.escape(R) + r"/git/ref/tags/(.+)$", path)
if mm:
    t = st["tags"].get(mm.group(1))
    if not t:
        reply(404, {"message": "Not Found"})
    reply(200, {"object": {"type": "tag", "sha": t}})
mm = re.match(re.escape(R) + r"/git/tags/(.+)$", path)
if mm and method == "GET":
    reply(200, {"object": {"sha": st["tagobjs"][mm.group(1)], "type": "commit"}})
if path == R + "/git/tags" and method == "POST":
    b = json.loads(data)
    tid = "t-%d" % st["next"]; st["next"] += 1
    st["tagobjs"][tid] = b["object"]
    reply(201, {"sha": tid})
if path == R + "/git/refs" and method == "POST":
    b = json.loads(data)
    name = b["ref"][len("refs/tags/"):]
    if name in st["tags"]:
        reply(422, {"message": "Reference already exists"})
    st["tags"][name] = b["sha"]
    reply(201, {"ref": b["ref"]})
mm = re.match(re.escape(R) + r"/releases/tags/(.+)$", path)
if mm:
    if st["release"] and st["release"]["tag_name"] == mm.group(1):
        reply(200, st["release"])
    reply(404, {"message": "Not Found"})
if path == R + "/releases" and method == "POST":
    b = json.loads(data)
    b["id"] = 7
    st["release"] = b
    reply(201, b)
if re.match(re.escape(R) + r"/releases/7$", path) and method == "PATCH":
    st["release"].update(json.loads(data))
    reply(200, st["release"])
if path.startswith(R + "/releases/7/assets") and m.group(1) == "api" and method == "GET":
    reply(200, st["assets"])
mm = re.match(re.escape(R) + r"/releases/assets/(\d+)$", path)
if mm and method == "DELETE":
    st["assets"] = [a for a in st["assets"] if str(a["id"]) != mm.group(1)]
    reply(204)
mm = re.match(re.escape(R) + r"/releases/7/assets\?name=(.+)$", path)
if mm and m.group(1) == "uploads" and method == "POST":
    aid = st["next"]; st["next"] += 1
    st["assets"].append({"id": aid, "name": mm.group(1), "size": len(data), "state": "uploaded"})
    reply(201, {"id": aid})
reply(599, {"message": "stub: unexpected call %s %s" % (method, path)})
STUB
chmod +x "$W/bin/curl"

# ------------------------------------------- https remote -> real local bare
cat >"$W/gitconfig" <<EOF
[url "$BARE"]
    insteadOf = https://github.com/visionebc/veyrs.git
[user]
    name = test
    email = test@example.invalid
[init]
    defaultBranch = main
EOF

pass=0; fail=0
LAST_OUT=""
# run <name> <scenario> <expected_rc> <expected_pattern> -- <args...>
#   Variables that can be set for ONE call: XENV (extra assignments,
#   e.g. "USE_GH=no GH_TOKEN=..."), OUTDIR, KEEP=1 (keeps the API state).
run() {
  local name="$1" scen="$2" want_rc="$3" want_pat="$4" out rc; shift 5
  [[ "${KEEP:-0}" == 1 ]] || rm -rf "$STATE"
  local outdir="${OUTDIR:-/tmp/veyrs-pubtest-out}"
  [[ "${KEEP_OUT:-0}" == 1 ]] || rm -rf "$outdir"
  out="$(env SCEN="$scen" BARE="$BARE" STATE="$STATE" ARGV_LOG="$ARGV_LOG" VER="$VER" \
         FAKE_TOKEN="$FAKE_TOKEN" GIT_CONFIG_GLOBAL="$W/gitconfig" \
         PATH="$W/bin:$PATH" OUT="$outdir" SRC="$REPO_ROOT" ${XENV:-} \
         bash "$SCRIPT" "$@" 2>&1)"; rc=$?
  LAST_OUT="$out"
  local ok=1
  [[ "$rc" == "$want_rc" ]] || ok=0
  [[ -n "$want_pat" ]] && { grep -qE "$want_pat" <<<"$out" || ok=0; }
  if [[ $ok == 1 ]]; then
    printf '  \033[32mOK\033[0m   %-40s rc=%s\n' "$name" "$rc"; pass=$((pass+1))
  else
    printf '  \033[31mFAIL\033[0m %-40s rc=%s (expected %s, pattern: %s)\n' \
      "$name" "$rc" "$want_rc" "$want_pat"
    printf '%s\n' "$out" | tail -12 | sed 's/^/        | /'
    fail=$((fail+1))
  fi
}
check() { # check <name> <eval-able-condition>
  if eval "$2"; then
    printf '  \033[32mOK\033[0m   %s\n' "$1"; pass=$((pass+1))
  else
    printf '  \033[31mFAIL\033[0m %s\n' "$1"; fail=$((fail+1))
  fi
}

echo "== gh path: --update guards (the push runs against a local bare) =="
run "unknown arg"              normal       2 'usage: .*--publish'                   -- --bogus
run "no flag = dry-run"        normal       0 'DRY-RUN'                              --
run "--publish when it exists" normal       1 'already exists'                       -- --publish
run "--update when NOT exists" notfound     1 'does not exist. To create it'         -- --update
run "foreign owner"            foreign      1 "belongs to 'otherfork'"               -- --update
run "default branch master"    master       1 "remote default branch is 'master'"    -- --update
run "73 commits = history"     history      1 'would destroy real history'           -- --update
run "INSTALL.md missing"       nofile       1 "does not contain 'INSTALL.md'"        -- --update
run "re-read mismatch"         phantompush  1 'is not the one just built'            -- --update
fresh_bare
run "happy path"               normal       0 'remote commit == built commit'        -- --update

echo
echo "== the happy path left something REAL on the remote =="
n="$(git --git-dir="$BARE" rev-list --count main 2>/dev/null || echo 0)"
files="$(git --git-dir="$BARE" ls-tree -r --name-only main 2>/dev/null | wc -l)"
has_inst="$(git --git-dir="$BARE" ls-tree -r --name-only main 2>/dev/null | grep -cx 'install.sh')"
sha_inst="$(git --git-dir="$BARE" show main:install.sh 2>/dev/null | sha256sum | cut -d' ' -f1)"
sha_repo="$(sha256sum "$REPO_ROOT/install.sh" | cut -d' ' -f1)"
author="$(git --git-dir="$BARE" log -1 --format='%an <%ae>' main 2>/dev/null)"
printf '  commits in the bare: %s (must be 1)\n' "$n"
printf '  published files: %s\n' "$files"
printf '  install.sh present: %s\n' "$has_inst"
if [[ "$sha_inst" == "$sha_repo" ]]; then
  printf '  \033[32mOK\033[0m   published install.sh == the one in the repo (%s)\n' "${sha_inst:0:16}"; pass=$((pass+1))
else
  printf '  \033[31mFAIL\033[0m published install.sh DIFFERS\n'; fail=$((fail+1))
fi
[[ "$n" == "1" ]] && pass=$((pass+1)) || { echo "  FAIL: commits != 1"; fail=$((fail+1)); }
check "public author = visionebc noreply ($author)" \
  '[[ "$author" == "visionebc <34753443+visionebc@users.noreply.github.com>" ]]'

sha_before="$(git --git-dir="$BARE" rev-parse main)"
run "re-run, same tree = no push" normal 0 'ALREADY publishes this exact tree' -- --update
check "the mirror commit did NOT change on re-run" \
  '[[ "$(git --git-dir="$BARE" rev-parse main)" == "$sha_before" ]]'

echo
echo "== path WITHOUT gh (curl + REST API, GH_TOKEN) =="
# The gh stub stays on PATH: USE_GH=no proves it is not used, because any
# call to gh on this path would be a design flaw.
TOK="USE_GH=no GH_TOKEN=$FAKE_TOKEN"
XENV="$TOK" run "invalid token (401)"            badtoken    1 'GH_TOKEN is not valid'              -- --update
XENV="USE_GH=no" run "--update without gh or token" normal   1 'need gh or GH_TOKEN'                -- --update
XENV="$TOK" run "dry-run validates the token"    normal      0 'authenticated as: visionebc \(REST' --
XENV="$TOK" run "--publish when it exists"       normal      1 'already exists'                     -- --publish
XENV="$TOK" run "--publish with API down (500)"  api500      1 'could not determine whether'        -- --publish
XENV="$TOK" run "--update with API down (500)"   api500      1 'could not read github.com'          -- --update
XENV="$TOK" run "--update when NOT exists"       notfound    1 'does not exist. To create it'       -- --update
XENV="$TOK" run "foreign owner"                  foreign     1 "belongs to 'otherfork'"             -- --update
XENV="$TOK" run "default branch master"          master      1 "remote default branch is 'master'"  -- --update
XENV="$TOK" run "73 commits = history"           history     1 'would destroy real history'         -- --update
XENV="$TOK" run "INSTALL.md missing"             nofile      1 "does not contain 'INSTALL.md'"      -- --update
fresh_bare
XENV="$TOK" run "re-read mismatch"               phantompush 1 'is not the one just built'          -- --update
fresh_bare
XENV="$TOK" run "--publish new repo (create+push)" notfound  0 'remote commit == built commit'      -- --publish
check "--publish without gh left 1 real commit in the bare" \
  '[[ "$(git --git-dir="$BARE" rev-list --count main 2>/dev/null)" == 1 ]]'
fresh_bare
XENV="$TOK" run "happy path --update"            normal      0 'remote commit == built commit'      -- --update
sha_before="$(git --git-dir="$BARE" rev-parse main)"
XENV="$TOK" run "re-run = no push"               normal      0 'ALREADY publishes this exact tree'  -- --update
check "the mirror commit did NOT change on re-run (no gh)" \
  '[[ "$(git --git-dir="$BARE" rev-parse main)" == "$sha_before" ]]'

echo
echo "== release v$VER: assets from the EXPORTED tree =="
REL_OUT=/tmp/veyrs-pubtest-rel
REL_ASSETS=/tmp/veyrs-pubtest-rel.assets
rm -rf "$REL_ASSETS"
OUTDIR="$REL_OUT" XENV="$TOK" run "dry-run that leaves tree + commit" normal 0 'DRY-RUN' --
if [[ ! -f "$REL_OUT/veyrs-setup.sh" ]]; then
  # The installer comes from another line of work; without it the release has
  # nothing to publish. To test the MECHANICS a harmless one is added to the
  # exported tree AND to its derived commit (the script requires them to match).
  printf '#!/usr/bin/env bash\necho "veyrs-setup (harness fixture)"\n' >"$REL_OUT/veyrs-setup.sh"
  chmod +x "$REL_OUT/veyrs-setup.sh"
  git -C "$REL_OUT" add veyrs-setup.sh
  git -C "$REL_OUT" -c user.name=t -c user.email=t@example.invalid commit -q --amend --no-edit
  echo "  (veyrs-setup.sh is not in the repo yet: using a fixture)"
fi
RX="ASSETS=$REL_ASSETS SOURCE_DATE_EPOCH=1700000000"
KEEP_OUT=1 OUTDIR="$REL_OUT" XENV="$RX" run "--release-build" normal 0 'tarball list == exported tree' -- --release-build "$VER"
TARN="veyrs-$VER-src.tar.gz"
sha1="$(sha256sum "$REL_ASSETS/$TARN" | cut -d' ' -f1)"
KEEP_OUT=1 OUTDIR="$REL_OUT" XENV="$RX" run "--release-build again" normal 0 'tarball list' -- --release-build "$VER"
check "reproducible tarball (same sha256 across two builds)" \
  '[[ "$(sha256sum "$REL_ASSETS/$TARN" | cut -d" " -f1)" == "$sha1" ]]'
check "4 assets: installer, tarball and their .sha256" \
  '[[ "$(ls "$REL_ASSETS" | LC_ALL=C sort | tr "\n" " ")" == "$TARN $TARN.sha256 veyrs-setup.sh veyrs-setup.sh.sha256 " ]]'
check "the tarball does NOT carry the internal paths (.bootstrap-credentials, var/, public-export.sh, sync.sh)" \
  '! tar -tzf "$REL_ASSETS/$TARN" | grep -qE "/(\.bootstrap-credentials|var/|scripts/public-export\.sh|sync\.sh)$|/var/"'
KEEP_OUT=1 OUTDIR="$REL_OUT" XENV="$RX" run "version that is not the tree's" normal 1 'declares version' -- --release-build 0.0.1
KEEP_OUT=1 OUTDIR="$REL_OUT" XENV="$RX" run "--release-build rebuilds" normal 0 'tarball list' -- --release-build "$VER"

# The mirror must publish the assets' tree: the derived commit is left in the
# bare, as if --update had just run.
fresh_bare
git -C "$REL_OUT" push -q "$BARE" main:main
MIRROR_SHA="$(git --git-dir="$BARE" rev-parse main)"
cp -a "$REL_ASSETS" "$W/assets.good"

restore_assets() { rm -rf "$REL_ASSETS"; cp -a "$W/assets.good" "$REL_ASSETS"; }
retar() { # retar <action on the extracted tree>  -> tampered tarball + new sha
  local d="$W/tamper"; rm -rf "$d"; mkdir -p "$d"
  tar -xzf "$W/assets.good/$TARN" -C "$d"
  ( cd "$d/veyrs-$VER" && eval "$1" )
  tar -C "$d" -czf "$REL_ASSETS/$TARN" "veyrs-$VER"
  ( cd "$REL_ASSETS" && sha256sum "$TARN" >"$TARN.sha256" )
}
posts() { grep -cE -- '-X (POST|PATCH|DELETE)' "$ARGV_LOG" 2>/dev/null || true; }

RR="$TOK ASSETS=$REL_ASSETS"
restore_assets; retar 'echo extra > EXTRA_FILE.txt'; : >"$ARGV_LOG"
KEEP_OUT=1 OUTDIR="$REL_OUT" XENV="$RR" run "tarball with an extra file" normal 1 'tarball file list is NOT' -- --release "$VER"
check "…and nothing was written to GitHub" '[[ "$(posts)" == 0 ]]'
# An internal address built at run time: written literally, this very file
# would carry it into the public tree.
IP_INTERNA="10.0.0.$((80+3))"
restore_assets; retar "printf 'host %s\n' $IP_INTERNA >> README.md"; : >"$ARGV_LOG"
KEEP_OUT=1 OUTDIR="$REL_OUT" XENV="$RR" run "tarball with an internal IP inside" normal 1 'internal addresses' -- --release "$VER"
check "…and nothing was written to GitHub" '[[ "$(posts)" == 0 ]]'
restore_assets; printf 'x' >>"$REL_ASSETS/veyrs-setup.sh"
KEEP_OUT=1 OUTDIR="$REL_OUT" XENV="$RR" run "mismatched .sha256" normal 1 'does not match its asset' -- --release "$VER"

restore_assets
KEEP_OUT=1 OUTDIR="$REL_OUT" XENV="$RR" run "mirror with another tree" foreigntree 1 'does not publish the tree of these' -- --release "$VER"
KEEP_OUT=1 OUTDIR="$REL_OUT" XENV="$RR" run "tag v$VER already on another commit" foreigntag 1 'Refusing to move a published tag' -- --release "$VER"
check "…and the release was not created" '[[ "$(python3 -c "import json;print(json.load(open(\"$STATE/state.json\"))[\"release\"])")" == None ]]'

: >"$ARGV_LOG"
KEEP_OUT=1 OUTDIR="$REL_OUT" XENV="$RR" run "release: happy path" normal 0 'one per name' -- --release "$VER"
st_json="$STATE/state.json"
check "annotated tag v$VER -> mirror commit" \
  '[[ "$(python3 -c "import json;s=json.load(open(\"$st_json\"));print(s[\"tagobjs\"][s[\"tags\"][\"v$VER\"]])")" == "$MIRROR_SHA" ]]'
KEEP=1 KEEP_OUT=1 OUTDIR="$REL_OUT" XENV="$RR" run "release: re-run replaces" normal 0 'deleted previous veyrs-setup.sh' -- --release "$VER"
check "after re-run: exactly 4 assets, one per name" \
  '[[ "$(python3 -c "import json;a=[x[\"name\"] for x in json.load(open(\"$st_json\"))[\"assets\"]];print(len(a),len(set(a)))")" == "4 4" ]]'
check "the token NEVER appears in curl's argv" '! grep -qF "$FAKE_TOKEN" "$ARGV_LOG"'
check "the token is not left in any temp file" \
  '! grep -rlF "$FAKE_TOKEN" /tmp/veyrs-pub.* 2>/dev/null | grep -q .'

echo
printf '== %s passed, %s failed ==\n' "$pass" "$fail"
[[ $fail -eq 0 ]]
