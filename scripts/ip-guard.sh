#!/usr/bin/env bash
#
# VEYRS — deny-by-default IPv4 sweep for anything that leaves the building
# (the public tree, the release tarball, the container images).
#
#   scripts/ip-guard.sh DIR
#
# Prints `path:line: literal` for every IPv4 literal outside the allowlist.
# rc 0 = clean, 1 = findings, 2 = the guard itself could not run. A caller
# must treat 2 as a failure, never as "clean".
#
# Allowed, and nothing else:
#   0.0.0.0/8 127.0.0.0/8          unspecified, loopback
#   192.0.2.0/24 198.51.100.0/24 203.0.113.0/24   RFC 5737 documentation
#   198.18.0.0/15                  RFC 2544 benchmarking (public-export target)
#   169.254.0.0/16 224.0.0.0/4 240.0.0.0/4   link-local, multicast, reserved
#   1.2.3.0/24                     universal placeholder / version tuples (1.2.3.1)
#   netmasks / wildcard masks      255.255.255.0, 0.0.0.255 ...
#   public resolvers               1.1.1.1 1.0.0.1 8.8.8.8 8.8.4.4 9.9.9.9
#   RFC1918/CGNAT block definitions, ONLY with their own prefix length
#   the Docker stack defaults      172.29.0.0/16, 172.31.250.0/24
#
# Deliberately a different implementation from the Python renumbering pass in
# public-export.sh and from verify_tree in publish-github.sh: one shared bug
# must not blind every check at once.
set -uo pipefail

dir="${1:?usage: ip-guard.sh DIR}"
[[ -d "$dir" ]] || { echo "ip-guard: $dir is not a directory" >&2; exit 2; }

raw="$(grep -rnIoP '(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?!\d)(?!\.\d)(?:/\d{1,2})?' "$dir" \
         --exclude=LICENSE --exclude-dir=.git 2>/dev/null)"
rc=$?
[[ $rc -le 1 ]] || { echo "ip-guard: grep failed (rc=$rc)" >&2; exit 2; }
[[ -z "$raw" ]] && exit 0

out="$(printf '%s\n' "$raw" | awk -v root="$dir/" '
function n(a,b,c,d) { return ((a*256+b)*256+c)*256+d }
function inr(x, a,b,c,d, len,   base, size) {
    base = n(a,b,c,d); size = 2^(32-len); return x >= base && x < base + size
}
function pow2(v) { while (v > 1 && v % 2 == 0) v /= 2; return v == 1 }
# plain arithmetic, no and(): Debian ships mawk, which has no bit functions
function mask(x) {
    if (x == 0 || x == 4294967295) return 0
    if (x >= 2147483648 && pow2(4294967295 - x + 1)) return 1   # 255.255.255.0
    if (pow2(x + 1)) return 1                                    # 0.0.0.255
    return 0
}
{
    # path:line:literal -- the literal is the last field, the path may not hold ":"
    k = split($0, f, ":"); lit = f[k]; path = f[1]; line = f[2]
    sub("^" root, "", path)
    pre = ""; ip = lit
    if (index(lit, "/")) { split(lit, s, "/"); ip = s[1]; pre = s[2] }
    split(ip, o, ".")
    if (o[1] > 255 || o[2] > 255 || o[3] > 255 || o[4] > 255) next     # not an address
    x = n(o[1],o[2],o[3],o[4])
    if (inr(x,0,0,0,0,8) || inr(x,127,0,0,0,8) || inr(x,192,0,2,0,24) || inr(x,198,51,100,0,24) \
        || inr(x,203,0,113,0,24) || inr(x,198,18,0,0,15) || inr(x,169,254,0,0,16) \
        || inr(x,224,0,0,0,4) || inr(x,240,0,0,0,4) || inr(x,1,2,3,0,24) || mask(x)) next
    if (ip ~ /^(1\.1\.1\.1|1\.0\.0\.1|8\.8\.8\.8|8\.8\.4\.4|9\.9\.9\.9)$/) next
    if ((ip == "198.19.1.0" && pre == "8") || (ip == "198.19.10.0" && pre == "12") \
        || (ip == "198.19.11.0" && pre == "16") || (ip == "198.19.9.0" && pre == "10")) next
    if (inr(x,172,29,0,0,16) || inr(x,172,31,250,0,24)) next
    printf "%s:%s: %s\n", path, line, lit
}')" || { echo "ip-guard: awk failed" >&2; exit 2; }

[[ -z "$out" ]] && exit 0
printf '%s\n' "$out"
exit 1
