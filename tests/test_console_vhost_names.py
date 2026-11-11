"""The console vhost must answer to every hostname that reaches the nodes.

Why this file exists. The fleet reverse proxy forwards several hostnames to
the same upstream (a1 primary, a2 backup) and preserves the ``Host`` header.
On the nodes, the documentation vhost is ``listen 80 default_server`` with
``server_name _`` -- deliberately, because direct-by-IP access is how the
monitoring stack scrapes ``/metrics`` and how the probes reach ``/healthz``.

The consequence is that a hostname missing from the console's ``server_name``
does NOT fail loudly. It falls through to the default server and returns the
documentation site with HTTP 200. That is exactly what happened to
``veyrs-app-2.example.com``: every status-code check passed while the name
served the wrong document root, and a failover test that asserted only ``200``
would have confirmed a failover that served readme pages to operators.

So the assertion here is on the *set of names*, not on a response.
"""

from __future__ import annotations

import re
from pathlib import Path

import pytest

CONF = Path(__file__).resolve().parents[1] / "infrastructure" / "nginx-veyrs-console.conf"

# Every hostname the fleet proxy (10.50.0.10) proxies to `upstream veyrs_app`
# for the console, plus the per-node names. `veyrs.example.com` is
# retired and answers 301 at the proxy, but the node must still resolve it:
# non-browser clients that do not follow redirects still send it.
REQUIRED_SERVER_NAMES = {
    "veyrs-app-1.example.com",
    "veyrs-app-2.example.com",
    "veyrs.example.com",
    "veyrs-console.example.com",
}

# Names that belong to OTHER vhosts. Claiming one here would steal the
# documentation site or the public web site from its own server block.
FOREIGN_SERVER_NAMES = {
    "veyrs-docs.example.com",
    "veyrs-web.example.com",
    "veyrs-web-p.example.com",
}


def _declared_server_names() -> set[str]:
    text = CONF.read_text()
    # `server_name` may wrap across lines; it ends at the semicolon.
    match = re.search(r"^\s*server_name\s+(.*?);", text, re.MULTILINE | re.DOTALL)
    assert match, "the console vhost declares no server_name"
    return set(match.group(1).split())


def test_the_tracked_console_vhost_exists() -> None:
    assert CONF.is_file(), f"{CONF} is missing; the vhost is unversioned again"


def test_it_answers_to_every_hostname_the_proxy_forwards() -> None:
    declared = _declared_server_names()
    missing = REQUIRED_SERVER_NAMES - declared
    assert not missing, (
        f"{sorted(missing)} reach the nodes but are not on the console vhost. "
        "They will not 404 -- they fall through to the default_server and "
        "serve the documentation site with HTTP 200."
    )


def test_it_does_not_claim_another_vhost_name() -> None:
    stolen = _declared_server_names() & FOREIGN_SERVER_NAMES
    assert not stolen, f"{sorted(stolen)} belong to another server block"


def test_it_is_not_a_catch_all() -> None:
    declared = _declared_server_names()
    assert "_" not in declared, "the console must not be the catch-all vhost"
    assert not any(n.startswith("*") for n in declared), (
        "a wildcard here would swallow the documentation and web vhosts"
    )


@pytest.mark.parametrize("name", sorted(REQUIRED_SERVER_NAMES))
def test_each_required_name_is_fully_qualified(name: str) -> None:
    # A bare label (`veyrs-app-2`) does not match the Host header the proxy
    # sends, which is always the FQDN.
    assert name in _declared_server_names()
