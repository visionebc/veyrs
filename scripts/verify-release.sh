#!/usr/bin/env bash
# verify-release.sh — prove that a directory of VEYRS release assets is what the
# release key signed, and that nothing in it was altered since.
#
#   scripts/verify-release.sh [options] DIR
#
#   --allowed-signers FILE   trusted key(s), OpenSSH allowed_signers format.
#                            Default: $VEYRS_RELEASE_ALLOWED_SIGNERS, else
#                            release/allowed_signers of the tree this script is in.
#   --ignore-missing         assets listed in SHA256SUMS but absent from DIR are
#                            skipped (at least one asset must still verify).
#   --require NAME           NAME must be listed in SHA256SUMS AND verify.
#                            Repeatable. Use it with --ignore-missing to check a
#                            partial download (the updater does).
#   -q                       only print failures.
#
# Order matters and is the whole point:
#   1. SHA256SUMS.sig is checked against SHA256SUMS with the TRUSTED key
#      (namespace "veyrs-release", principal "release@veyrs"). This proves ORIGIN.
#   2. Only then is each SHA-256 in SHA256SUMS compared with the asset on disk.
#      This proves INTEGRITY. A .sha256 file sitting next to an asset proves
#      integrity only: whoever can replace the asset can replace its .sha256.
#
# Exit codes (distinct, so a caller can tell the failures apart):
#   0  every listed asset verified, signature good
#   1  usage error
#   3  UNSIGNED: SHA256SUMS or SHA256SUMS.sig is missing
#   4  BAD SIGNATURE: the signature does not verify with the trusted key
#   5  HASH MISMATCH: an asset differs from SHA256SUMS, is missing, or
#      SHA256SUMS itself is malformed
#   6  CANNOT VERIFY: no usable trusted key (e.g. the committed PLACEHOLDER) or
#      no ssh-keygen with -Y support (OpenSSH >= 8.1). Never treated as success.
set -uo pipefail

NAMESPACE="veyrs-release"
PRINCIPAL="release@veyrs"
SELF_ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
SIGNERS="${VEYRS_RELEASE_ALLOWED_SIGNERS:-$SELF_ROOT/release/allowed_signers}"
IGNORE_MISSING=0
QUIET=0
REQUIRE=()
DIR=""

usage() { sed -n '2,32p' "${BASH_SOURCE[0]}" | sed 's/^# \{0,1\}//' >&2; exit 1; }
say()  { [[ $QUIET -eq 1 ]] || printf '%s\n' "$*"; }
fail() { local rc="$1"; shift; printf 'verify-release: %s\n' "$*" >&2; exit "$rc"; }

while [[ $# -gt 0 ]]; do
  case "$1" in
    --allowed-signers) [[ $# -ge 2 ]] || usage; SIGNERS="$2"; shift 2 ;;
    --ignore-missing)  IGNORE_MISSING=1; shift ;;
    --require)         [[ $# -ge 2 ]] || usage; REQUIRE+=("$2"); shift 2 ;;
    -q)                QUIET=1; shift ;;
    -h|--help)         usage ;;
    -*)                printf 'verify-release: unknown option %s\n' "$1" >&2; usage ;;
    *)                 [[ -z "$DIR" ]] || usage; DIR="$1"; shift ;;
  esac
done
[[ -n "$DIR" && -d "$DIR" ]] || { printf 'verify-release: DIR is required and must be a directory\n' >&2; usage; }

# A valid trusted key line: the exact principal and namespace this project
# signs with, and a real ed25519 public key (its base64 always starts with the
# encoded "ssh-ed25519" type string). The committed PLACEHOLDER does not match,
# which is what turns "no key yet" into "cannot verify" instead of into a
# signature that merely fails -- or, worse, into a skipped check.
KEY_RE='^release@veyrs[[:space:]]+namespaces="veyrs-release"[[:space:]]+ssh-ed25519[[:space:]]+AAAAC3NzaC1lZDI1NTE5[A-Za-z0-9+/]+=*([[:space:]].*)?$'

[[ -r "$SIGNERS" ]] || fail 6 "CANNOT VERIFY: no trusted key file ($SIGNERS)"
if ! grep -qE "$KEY_RE" "$SIGNERS"; then
  fail 6 "CANNOT VERIFY: $SIGNERS holds no usable release key (still the PLACEHOLDER?). Refusing to report success."
fi
command -v ssh-keygen >/dev/null 2>&1 \
  || fail 6 "CANNOT VERIFY: ssh-keygen is not installed (OpenSSH >= 8.1 is needed for -Y verify)"

SUMS="$DIR/SHA256SUMS"
SIG="$DIR/SHA256SUMS.sig"
[[ -f "$SUMS" ]] || fail 3 "UNSIGNED: no SHA256SUMS in $DIR"
[[ -f "$SIG" ]]  || fail 3 "UNSIGNED: no SHA256SUMS.sig in $DIR"

# Only the trusted lines are handed to ssh-keygen: a stray line in a test or
# mirror copy must not widen who may sign.
TRUST="$(mktemp)"; ERR="$(mktemp)"
trap 'rm -f "$TRUST" "$ERR"' EXIT
grep -E "$KEY_RE" "$SIGNERS" >"$TRUST"

if ! ssh-keygen -Y verify -f "$TRUST" -I "$PRINCIPAL" -n "$NAMESPACE" -s "$SIG" \
       <"$SUMS" >"$ERR" 2>&1; then
  if grep -qiE 'usage:|illegal option|unknown option|invalid option' "$ERR"; then
    fail 6 "CANNOT VERIFY: this ssh-keygen does not support -Y verify (OpenSSH >= 8.1 is needed)"
  fi
  sed 's/^/    /' "$ERR" >&2
  fail 4 "BAD SIGNATURE: SHA256SUMS.sig does not verify with the trusted release key"
fi
say "OK   signature: $(tr -d '\n' <"$ERR" | sed 's/^Good /good /')"

# ------------------------------------------------------------- the sums ---
declare -A WANT=()
n_lines=0
while IFS= read -r line || [[ -n "$line" ]]; do
  [[ -n "$line" ]] || continue
  if [[ "$line" =~ ^([0-9a-f]{64})\ [\ *]([A-Za-z0-9][A-Za-z0-9._+-]*)$ ]]; then
    name="${BASH_REMATCH[2]}"
    [[ -z "${WANT[$name]+x}" ]] || fail 5 "HASH MISMATCH: SHA256SUMS lists $name twice"
    case "$name" in SHA256SUMS|SHA256SUMS.sig) fail 5 "HASH MISMATCH: SHA256SUMS lists $name" ;; esac
    WANT[$name]="${BASH_REMATCH[1]}"
    n_lines=$((n_lines + 1))
  else
    fail 5 "HASH MISMATCH: malformed line in SHA256SUMS: ${line:0:120}"
  fi
done <"$SUMS"
[[ $n_lines -gt 0 ]] || fail 5 "HASH MISMATCH: SHA256SUMS is empty"

verified=0
declare -A OK=()
for name in "${!WANT[@]}"; do
  f="$DIR/$name"
  if [[ ! -f "$f" ]]; then
    [[ $IGNORE_MISSING -eq 1 ]] && continue
    fail 5 "HASH MISMATCH: $name is listed in SHA256SUMS but missing from $DIR"
  fi
  got="$(sha256sum "$f" | awk '{print $1}')"
  [[ "$got" == "${WANT[$name]}" ]] \
    || fail 5 "HASH MISMATCH: $name
    expected ${WANT[$name]}
    got      $got"
  OK[$name]=1
  verified=$((verified + 1))
  say "OK   $name"
done
for name in ${REQUIRE[@]+"${REQUIRE[@]}"}; do
  [[ -n "${WANT[$name]+x}" ]] || fail 5 "HASH MISMATCH: required asset $name is not listed in SHA256SUMS"
  [[ -n "${OK[$name]+x}" ]]   || fail 5 "HASH MISMATCH: required asset $name is missing from $DIR"
done
[[ $verified -gt 0 ]] || fail 5 "HASH MISMATCH: no asset listed in SHA256SUMS is present in $DIR"

# Files nobody vouches for are reported, not silently accepted.
for f in "$DIR"/*; do
  [[ -f "$f" ]] || continue
  b="$(basename "$f")"
  case "$b" in SHA256SUMS|SHA256SUMS.sig) continue ;; esac
  [[ -n "${WANT[$b]+x}" ]] || printf 'verify-release: note: %s is not covered by SHA256SUMS (not verified)\n' "$b" >&2
done
say "OK   $verified asset(s) verified against the signed SHA256SUMS"
exit 0
