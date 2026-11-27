#!/usr/bin/env bash
# Release gate: the fast, targeted guard set. Run it before tagging a release
# (the release pipeline or the operator), on a host that can run scripts/test.sh
# (a test database and a test Redis; see INSTALL.md section 9).
#
# It is NOT the full suite (that takes long and belongs on a build host); it is
# the set that catches the regressions that reach production unnoticed: documentation
# that stopped matching the code, shipped units and vhosts that cannot work, scripts
# that lost their executable bit, and an export that would leak.
#
#   scripts/ci.sh            everything below
#   scripts/ci.sh --fast     skip the Docs Center build and the export check
#
# Why a script and not .gitea/workflows/tests.yml: the internal Gitea is 1.22.3,
# which supports workflow files, but they run only on a registered act_runner and
# none is verified for this repository. A workflow with no runner is a green
# check that never ran. If a runner is registered, the whole job is one step:
#     run: scripts/ci.sh
set -uo pipefail
cd "$(dirname "$0")/.."

FAST=0
[[ "${1:-}" == "--fast" ]] && FAST=1
FAILED=()
step() { printf '\n==> %s\n' "$1"; }
run()  { local name="$1"; shift; step "$name"; "$@" || FAILED+=("$name"); }

# 1. Every shell script parses.
syntax() { local rc=0 f; for f in install.sh veyrs-setup.sh scripts/*.sh docker/*.sh infrastructure/backup/*.sh; do bash -n "$f" || rc=1; done; return $rc; }
run "shell syntax" syntax

# 2. Documentation: counts, settings, links, path:line references.
run "docs references (path:line)" python3 scripts/check-docs-refs.py --baseline tests/docs_refs_baseline.txt
if [[ $FAST -eq 0 ]]; then
    docs_site() { local t; t="$(mktemp -d)"; python3 site/build.py --out "$t/portal" >/dev/null && python3 scripts/check-docs-links.py "$t/portal"; local rc=$?; rm -rf "$t"; return $rc; }
    run "Docs Center build and links" docs_site
fi

# 3. The targeted test guards.
GUARDS=(
    tests/test_docs_are_current.py tests/test_docs_center.py tests/test_docs_worked_example.py
    tests/test_executable_bits.py tests/test_fix_deploy.py tests/test_console_vhost_names.py
    tests/test_container_stack.py tests/test_installer_timers.py tests/test_api_unit.py
    tests/test_schema_steps.py
)
run "guard tests" ./scripts/test.sh -q "${GUARDS[@]}"

# 4. Export guard: what would be published must be clean.
if [[ $FAST -eq 0 ]]; then
    run "public export check" ./scripts/public-export.sh --check-only
fi

echo
if ((${#FAILED[@]})); then
    printf 'ci: FAILED: %s\n' "${FAILED[*]}"
    exit 1
fi
echo "ci: all checks passed"
