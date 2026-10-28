"""Phase 20: a container image reference is not a host:port.

`_split_host_port()` (commit cb7ebda) fixed a real defect - nuclei reports a
non-HTTP service as "host:22" and the port stayed glued to the hostname, so
findings on a KNOWN asset were rejected as "unknown asset". It then created the
mirror-image defect: container and cloud scanners put an ARTIFACT identifier in
`hostname`, where a colon separates a TAG, not a port. `registry.internal/api:
2.4.1` was truncated to `registry.internal` and `acme/web:1.0` to `acme`, so
every container finding lost its identity - and, because the identity feeds the
dedupe key, two different images collapsed onto one estate entry.

Two independent guards, both asserted here:
  1. the parser that knows declares `host_is_artifact=True`;
  2. a shape test catches anything a parser forgot to flag.

Guard 2 alone is not sufficient and that is the point of `test_a_numeric_tag_
survives_only_because_the_parser_declared_it`: `redis:7` is a legal image tag
AND a legal host:port. No amount of string inspection separates them, which is
why the authority has to be the parser.
"""
from __future__ import annotations

import json

from veyrs.services.importers.base import ScanRecord
from veyrs.services.importers.parsers_modern import parse_grype, parse_trivy


# ---------------------------------------------------------------------------
# The regression that was live on main
# ---------------------------------------------------------------------------
TRIVY_IMAGE = json.dumps({
    "ArtifactName": "registry.internal/api:2.4.1",
    "Results": [{
        "Target": "registry.internal/api:2.4.1 (debian 12.4)",
        "Class": "os-pkgs",
        "Type": "debian",
        "Vulnerabilities": [{
            "VulnerabilityID": "CVE-2024-0001",
            "PkgName": "libssl3",
            "InstalledVersion": "3.0.11-1",
            "FixedVersion": "3.0.13-1",
            "Severity": "HIGH",
            "Title": "openssl: a thing",
        }],
    }],
}).encode()

GRYPE_IMAGE = json.dumps({
    "source": {"type": "image", "target": {"userInput": "acme/web:1.0"}},
    "matches": [{
        "vulnerability": {"id": "CVE-2024-0002", "severity": "Critical",
                          "fix": {"versions": ["1.2.3"]}},
        "artifact": {"name": "express", "version": "4.17.1"},
    }],
}).encode()


def test_trivy_keeps_the_full_image_reference():
    record = next(iter(parse_trivy(TRIVY_IMAGE))).normalise()
    assert record.hostname == "registry.internal/api:2.4.1"
    assert record.fqdn is None            # the truncated half never appears
    assert record.port is None            # 2.4.1 is a tag, not a service port


def test_grype_keeps_the_full_image_reference():
    record = next(iter(parse_grype(GRYPE_IMAGE))).normalise()
    assert record.hostname == "acme/web:1.0"
    assert record.fqdn is None
    assert record.port is None


def test_a_numeric_tag_survives_only_because_the_parser_declared_it():
    """`redis:7` is a legal image tag and a legal host:port. Shape cannot decide."""
    flagged = ScanRecord(title="x", hostname="redis:7", host_is_artifact=True).normalise()
    assert flagged.hostname == "redis:7"
    assert flagged.port is None

    # ...and the same string WITHOUT the declaration is still read as a service,
    # because that is what it means coming from a network scanner.
    unflagged = ScanRecord(title="x", hostname="redis:7").normalise()
    assert unflagged.hostname == "redis"
    assert unflagged.port == 7


def test_shape_guard_catches_a_parser_that_forgot_the_flag():
    """Defence in depth: no flag, but nothing here is a network location."""
    for value in ("registry.internal/api:2.4.1", "acme/web:1.0", "nginx:stable-alpine",
                  "quay.io/org/img@sha256:abc123", "arn:aws:s3:::bucket/key"):
        record = ScanRecord(title="x", hostname=value).normalise()
        assert record.hostname == value, f"{value} was rewritten"
        assert record.fqdn is None, f"{value} leaked into fqdn"
        assert record.port is None, f"{value} produced a port"


# ---------------------------------------------------------------------------
# ...and cb7ebda's fix still holds. This is the half that must NOT regress.
# ---------------------------------------------------------------------------
def test_a_real_host_port_is_still_split():
    record = ScanRecord(title="x", hostname="veyrs-docs.example.com:22").normalise()
    assert record.fqdn == "veyrs-docs.example.com"
    assert record.hostname is None
    assert record.port == 22


def test_a_short_hostname_with_a_port_is_still_split():
    record = ScanRecord(title="x", hostname="dbserver:5432").normalise()
    assert record.hostname == "dbserver"
    assert record.port == 5432


def test_an_ip_with_a_port_is_still_split():
    record = ScanRecord(title="x", hostname="10.50.0.70:443").normalise()
    assert record.ip_address == "10.50.0.70"
    assert record.hostname is None
    assert record.port == 443


def test_a_bracketed_ipv6_with_a_port_is_still_split():
    record = ScanRecord(title="x", hostname="[2001:db8::1]:443").normalise()
    assert record.ip_address == "2001:db8::1"
    assert record.port == 443


def test_a_bare_ipv6_literal_is_left_alone():
    """Guessing where the address ends and the port begins moves findings."""
    record = ScanRecord(title="x", hostname="2001:db8::1").normalise()
    assert record.hostname == "2001:db8::1"
    assert record.port is None


def test_an_out_of_range_port_is_not_split():
    record = ScanRecord(title="x", hostname="app.example.com:99999").normalise()
    assert record.hostname == "app.example.com:99999"
    assert record.port is None


def test_an_explicit_port_is_not_overwritten_by_the_host_field():
    record = ScanRecord(title="x", hostname="app.example.com:22", port=2222).normalise()
    assert record.fqdn == "app.example.com"
    assert record.port == 2222


def test_the_flag_does_not_suppress_the_url_fallback():
    """An artifact record that also carries a URL still resolves its asset."""
    record = ScanRecord(title="x", url="https://veyrs-docs.example.com/x",
                        host_is_artifact=True).normalise()
    assert record.fqdn == "veyrs-docs.example.com"
