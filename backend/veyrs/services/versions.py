"""Version and name normalisation used by CPE/product correlation.

Why this exists as its own module: deciding whether `FortiWeb 7.2.4` falls
inside `versionStartIncluding 7.2.0 / versionEndExcluding 7.2.5` is the single
step that turns "a CVE exists" into "*your* box is affected". Getting it wrong
in either direction is a product-defining bug -- a false negative hides a real
exposure, a false positive floods the queue and destroys trust in the tool.

The comparison follows the NVD/CPE convention rather than PEP 440: components
are compared numerically when both sides are numeric, lexically otherwise, and
pre-release markers (alpha/beta/rc) sort *before* the bare release. `*`, `-`
and the empty string mean "any", which is how NVD encodes an unbounded field.
"""
from __future__ import annotations

from urllib.parse import unquote

import re

_ANY = {"*", "-", "", None}

# Ordering of known pre-release markers. Anything unknown sorts as 0 (i.e. as a
# release-level suffix) so an unexpected token never silently outranks a real
# release.
_PRERELEASE_RANK = {
    "dev": -50, "alpha": -40, "a": -40, "beta": -30, "b": -30,
    "pre": -25, "rc": -20, "c": -20, "snapshot": -45,
    "": 0, "ga": 0, "release": 0, "final": 0,
    "p": 10, "patch": 10, "sp": 10, "hotfix": 10, "build": 5,
}

#: A Debian/RPM epoch: the `1:` in `1:9.2p1-2+deb12u10`. Packaging metadata
#: that exists to force an upgrade ordering the upstream version cannot
#: express; it never appears in an NVD range.
_EPOCH = re.compile(r"^\d+:")

#: A distribution revision: `-2+deb12u10`, `-9`, `-1ubuntu2`, `-150600.3.1`.
#: The digit right after the separator is what distinguishes it from an
#: upstream pre-release tag (`-rc1`, `-beta2`), which must NOT be stripped --
#: `7.2.4-rc1` really is older than `7.2.4` and `compare()` already models it.
_DISTRO_REVISION = re.compile(r"[-+~]\d")

_SPLIT = re.compile(r"[._\-+~:/ ]+")
_NUM_ALPHA = re.compile(r"(\d+|[A-Za-z]+)")


def normalize_name(value: str | None) -> str:
    """Fold a vendor/product name into a stable matching key.

    `Fortinet, Inc.` and `fortinet inc` must land on the same key, otherwise the
    product registry grows one duplicate vendor per advisory spelling.
    """
    if not value:
        return ""
    lowered = value.strip().lower()
    lowered = re.sub(r"\b(inc|llc|ltd|gmbh|corp|corporation|co|sa|ag|s\.a\.|plc)\b", " ", lowered)
    lowered = re.sub(r"[^a-z0-9]+", "_", lowered)
    return lowered.strip("_")


def parse(version: str | None) -> list[tuple[int, int, str]]:
    """Split a version into comparable (rank, number, text) segments.

    Each segment is a triple so that mixed numeric/alpha components compare
    deterministically: numerics sort by value, alphas by text, and a numeric
    always sorts above an alpha at the same position (2 > 2rc, 2 > 2-beta).
    """
    if version is None:
        return []
    text = str(version).strip().lower()
    # A leading "v" is presentation, not a pre-release marker: vendors ship
    # "v7.2.4" and "7.2.4" for the same build, and treating them as different
    # would silently miss the affected host.
    if len(text) > 1 and text[0] == "v" and text[1].isdigit():
        text = text[1:]
    # An epoch is stripped HERE, not only at ingest, so no caller can poison a
    # comparison with one. `_SPLIT` treats ":" as a separator, so a surviving
    # epoch becomes the leading component: `1:9.2p1` compares as `1.9.2`, which
    # falls inside "openssh <= 2.9" and manufactures a finding for a CVE fixed
    # in 2001. That is not a near miss -- it inverts the answer.
    text = _EPOCH.sub("", text, count=1)
    segments: list[tuple[int, int, str]] = []
    for chunk in _SPLIT.split(text):
        if not chunk:
            continue
        for token in _NUM_ALPHA.findall(chunk):
            if token.isdigit():
                segments.append((1, int(token), ""))
            else:
                rank = _PRERELEASE_RANK.get(token)
                if rank is None:
                    segments.append((0, 0, token))
                else:
                    segments.append((0, rank, token if rank == 0 else ""))
    return segments


def compare(left: str | None, right: str | None) -> int:
    """Return -1/0/1 for left <=> right using CPE-style ordering."""
    a, b = parse(left), parse(right)
    for i in range(max(len(a), len(b))):
        # A missing trailing component is a plain release: 7.2 == 7.2.0 but
        # 7.2 > 7.2-rc1, which the (1, 0, "") padding gives us for free.
        x = a[i] if i < len(a) else (1, 0, "")
        y = b[i] if i < len(b) else (1, 0, "")
        if x == y:
            continue
        return -1 if x < y else 1
    return 0


def version_key(version: str | None, width: int = 6, depth: int = 6) -> str:
    """Zero-padded, lexically sortable key for indexing in Postgres.

    Used by `asset_products.version_key` so "is anything older than 7.2.5
    installed" is an index scan rather than a Python loop over every asset.
    """
    if version is None:
        return ""
    parts: list[str] = []
    for kind, number, text in parse(version)[:depth]:
        if kind == 1:
            parts.append(str(number).zfill(width))
        else:
            # pre-release markers sort below any numeric component
            parts.append(("!" + text).ljust(width, "!")[:width])
    while len(parts) < depth:
        parts.append("0" * width)
    return ".".join(parts)


def in_range(
    version: str | None,
    *,
    start_including: str | None = None,
    start_excluding: str | None = None,
    end_including: str | None = None,
    end_excluding: str | None = None,
    exact: str | None = None,
) -> bool:
    """Does `version` satisfy an NVD cpeMatch version range?

    An unknown installed version returns False: claiming an asset is affected
    when we do not know what it runs would manufacture findings out of missing
    inventory data.
    """
    if version in _ANY:
        return False

    if exact not in _ANY:
        return compare(version, exact) == 0

    bounded = False
    if start_including not in _ANY:
        bounded = True
        if compare(version, start_including) < 0:
            return False
    if start_excluding not in _ANY:
        bounded = True
        if compare(version, start_excluding) <= 0:
            return False
    if end_including not in _ANY:
        bounded = True
        if compare(version, end_including) > 0:
            return False
    if end_excluding not in _ANY:
        bounded = True
        if compare(version, end_excluding) >= 0:
            return False
    # No bounds at all means the CPE covers every version of the product.
    return True if bounded else True


def is_distro_version(value: str | None) -> bool:
    """Does this string carry distribution packaging metadata?

    The question `upstream_version` cannot answer on its own: it reduces
    whatever it is given, so calling it unconditionally would truncate a real
    upstream pre-release (`7.2.4-rc1` -> `7.2.4`) and silently claim a host is
    newer than it is. This predicate is the guard that keeps the reduction
    applied to package strings only.

    True for an epoch (`1:...`) or a distro revision (`-2+deb12u10`, `-9`,
    `-1ubuntu2`). False for `1.24.0`, `7.2.4-rc1`, `5.32`.
    """
    text = (value or "").strip()
    if not text:
        return False
    return bool(_EPOCH.search(text) or _DISTRO_REVISION.search(text))


def upstream_version(raw: str | None) -> str | None:
    """Reduce a distro package version to the form CVE ranges are written in.

    `1:1.24.0-2ubuntu7.1` -> `1.24.0`.

    Both parts stripped are packaging metadata, not upstream identity: the
    leading `1:` is a Debian epoch and everything from the first separator is
    the distribution's own revision. Comparing those against an NVD range is not
    merely conservative, it is wrong in an unpredictable direction -- the
    revision sorts above the upstream version on some segments and below it on
    others.

    The cost is real and must not be hidden: distributions backport security
    fixes without moving the upstream version, so a host on `1.24.0-2ubuntu7.1`
    can already be patched for a CVE whose range says "<= 1.24.0" and will still
    be flagged. `AssetProduct.raw_version` keeps the verbatim string so an
    analyst can see that. The alternative -- matching the distro string --
    matches nothing at all, which is the worse failure because it is silent.

    This lives server-side so every collector (the agent, a CMDB export, a
    one-off script) applies the same rule. A collector that ships its own copy
    is a rule that drifts.
    """
    value = (raw or "").strip()
    if not value:
        return None
    if ":" in value:
        value = value.split(":", 1)[1]
    value = re.split(r"[-+~]", value, maxsplit=1)[0]
    return value or None


def cpe22_to_cpe23(cpe: str) -> str | None:
    """Convert a CPE 2.2 URI (`cpe:/a:vendor:product:version`) to 2.3 form.

    This exists because of a silent failure, not for completeness. Nessus
    reports a host's software identity in `HostProperties` as **2.2 URIs**, and
    `parse_cpe23` returns None for anything not starting `cpe:2.3:`. Feeding
    those tags straight to `inventory.resolve_identity` would skip its most
    authoritative path -- "the scanner told us exactly which dictionary entry
    this is" -- and quietly fall back to inferring from a vendor string. The
    result is a second Product row no CVE ever joins to, which
    `services/inventory` names as the most dangerous bug in that module.

    Nessus also appends a human gloss: `cpe:/a:openbsd:openssh:8.4 -> OpenSSH`.
    That suffix is stripped here rather than in the Nessus parser, so the next
    tool emitting the same shape gets the same handling for free.

    Returns None for anything that is not a 2.2 URI -- including a string that
    is already 2.3. A converter that silently accepts both makes "which form
    did this scanner actually give us?" unanswerable at the call site.
    """
    if not cpe:
        return None
    text = cpe.strip()
    # The " -> gloss" only. Nothing more aggressive: a product name may
    # legitimately contain a hyphen or an angle bracket.
    if " -> " in text:
        text = text.split(" -> ", 1)[0].strip()
    if not text.lower().startswith("cpe:/"):
        return None

    fields = text[len("cpe:/"):].split(":")
    if len(fields) < 7:
        fields = fields + [""] * (7 - len(fields))
    part, vendor, product, version, update, edition, language = fields[:7]
    if not part:
        return None

    parts = [
        _cpe_component(part), _cpe_component(vendor), _cpe_component(product),
        _cpe_component(version), _cpe_component(update), _cpe_component(edition),
        _cpe_component(language), "*", "*", "*", "*",
    ]
    return "cpe:2.3:" + ":".join(parts)


#: Punctuation CPE 2.3 requires escaped and 2.2 leaves bare.
_CPE_SPECIALS = set("\\:*?!\"#$%&'()+,/;<=>@[]^`{|}~")


def _cpe_component(value: str) -> str:
    """One 2.2 field as a 2.3 component: percent-decoded, then 2.3-escaped.

    2.2 percent-encodes; 2.3 backslash-escapes. Skipping the round trip is how
    `c%2b%2b` ends up a different product from `c\\+\\+` in the same registry.
    """
    if not value:
        return "*"
    decoded = unquote(value)
    return "".join(("\\" + ch) if ch in _CPE_SPECIALS else ch for ch in decoded)


def parse_cpe23(cpe: str) -> dict[str, str] | None:
    """Parse a CPE 2.3 formatted string into its 11 components.

    Returns None for anything that is not a well-formed `cpe:2.3:` URI, so a
    malformed feed record is skipped rather than poisoning the product registry.
    """
    if not cpe or not cpe.lower().startswith("cpe:2.3:"):
        return None
    # Split on unescaped colons: CPE escapes literal colons as "\:".
    body = cpe[len("cpe:2.3:"):]
    fields: list[str] = []
    current: list[str] = []
    escaped = False
    for char in body:
        if escaped:
            current.append(char)
            escaped = False
        elif char == "\\":
            current.append(char)
            escaped = True
        elif char == ":":
            fields.append("".join(current))
            current = []
        else:
            current.append(char)
    fields.append("".join(current))
    if len(fields) < 11:
        fields += ["*"] * (11 - len(fields))
    keys = ["part", "vendor", "product", "version", "update", "edition",
            "language", "sw_edition", "target_sw", "target_hw", "other"]
    return dict(zip(keys, fields[:11]))
