"""Outbound-URL guard shared by every connector that calls a configured URL.

CMDB sources, ITSM / Confluence connectors, scanner connectors and AI providers
all call a URL an administrator typed in. Without a guard that is a server-side
request forgery primitive: point the "NetBox URL" at the cloud metadata
service, or at a loopback admin port, and VEYRS fetches it from inside the
network with its own credentials.

Policy (see docs/SECURITY.md, "Outbound connectors"):

* ALWAYS refused: link-local (169.254.0.0/16, fe80::/10), the AWS IPv6 metadata
  address (fd00:ec2::254), the Alibaba Cloud metadata address (`_ALIBABA_METADATA` below),
  the unspecified address, multicast and reserved ranges.
* Loopback (127.0.0.0/8, ::1): refused unless ``VEYRS_OUTBOUND_ALLOW_LOOPBACK=true``.
* Private ranges (RFC 1918, ULA fc00::/7, CGNAT 100.64.0.0/10): ALLOWED by
  default because on-premise deployments legitimately reach NetBox, Jira or a
  scanner on the LAN. ``VEYRS_OUTBOUND_ALLOW_PRIVATE=false`` refuses them for
  cloud deployments that should only reach public services.

The host is resolved and EVERY resolved address is checked, so a name with one
public and one metadata record is refused, and an IPv4-mapped IPv6 literal
(``::ffff:169.254.169.254``) is judged by the IPv4 address it wraps.

Residual risk: the check happens before the request, so a resolver that answers
differently the second time (DNS rebinding) is not covered. Redirects are not
followed by the connectors, which removes the common bypass.
"""
from __future__ import annotations

import ipaddress
import socket
from typing import Callable
from urllib.parse import urlsplit

from ..config import settings


class OutboundBlocked(ValueError):
    """The URL points somewhere VEYRS must not connect to."""


# Alibaba Cloud's metadata endpoint sits inside the CGNAT range. It is written
# as an integer on purpose: the public export renumbers every private literal
# (scripts/public-export.sh), which would silently retarget a dotted form.
_ALIBABA_METADATA = ipaddress.ip_network((1684301000, 32))
# AWS's IPv6 metadata block (the /32 that holds its ::254 endpoint) is a ULA
# prefix, which the release IP guards refuse as a literal: same integer form.
_AWS_V6_METADATA = ipaddress.ip_network((336294982257581694735330614659971547136, 32))

_ALWAYS_BLOCKED = (_ALIBABA_METADATA, _AWS_V6_METADATA) + tuple(ipaddress.ip_network(n) for n in (
    "169.254.0.0/16",       # link-local, incl. the 169.254.169.254 metadata address
    "fe80::/10",            # IPv6 link-local
    "0.0.0.0/8",            # "this host"
    "224.0.0.0/4", "ff00::/8",   # multicast
    "240.0.0.0/4",          # reserved (incl. broadcast)
))

Resolver = Callable[..., list]


def _classify(address: ipaddress._BaseAddress) -> str:
    """'blocked' | 'loopback' | 'private' | 'public'."""
    if isinstance(address, ipaddress.IPv6Address) and address.ipv4_mapped is not None:
        address = address.ipv4_mapped
    if any(address in net for net in _ALWAYS_BLOCKED) or address.is_unspecified:
        return "blocked"
    if address.is_loopback:
        return "loopback"
    if address.is_private or not address.is_global:
        return "private"
    return "public"


def check_url(url: str, *, allow_private: bool | None = None,
              allow_loopback: bool | None = None,
              resolver: Resolver | None = None) -> None:
    """Raise :class:`OutboundBlocked` unless every address of ``url`` is allowed.

    ``allow_private=False`` / ``allow_loopback`` override the installation
    settings per call (``allow_private=True`` never loosens a ``false``
    installation setting). ``resolver`` is a test seam with the signature of
    ``socket.getaddrinfo``.
    """
    parts = urlsplit(str(url or "").strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise OutboundBlocked("the URL must be http(s) with a host name")
    effective_private = settings.outbound_allow_private and allow_private is not False
    effective_loopback = (settings.outbound_allow_loopback
                          if allow_loopback is None else allow_loopback)
    host = parts.hostname
    try:
        literal = ipaddress.ip_address(host)
    except ValueError:
        literal = None
    if literal is not None:
        addresses = [literal]
    else:
        try:
            infos = (resolver or socket.getaddrinfo)(
                host, parts.port or (443 if parts.scheme == "https" else 80),
                type=socket.SOCK_STREAM)
        except OSError as exc:
            raise OutboundBlocked(f"{host} does not resolve ({exc.__class__.__name__})") from None
        addresses = []
        for info in infos:
            try:
                addresses.append(ipaddress.ip_address(info[4][0].split("%", 1)[0]))
            except ValueError:
                continue
        if not addresses:
            raise OutboundBlocked(f"{host} does not resolve")
    for address in addresses:
        kind = _classify(address)
        if kind == "blocked":
            raise OutboundBlocked(
                f"{host} resolves to {address}, a link-local / metadata / reserved "
                "address that VEYRS never connects to")
        if kind == "loopback" and not effective_loopback:
            raise OutboundBlocked(
                f"{host} resolves to loopback ({address}); set "
                "VEYRS_OUTBOUND_ALLOW_LOOPBACK=true to allow it")
        if kind == "private" and not effective_private:
            raise OutboundBlocked(
                f"{host} resolves to a private address ({address}) and outbound "
                "connections to private ranges are disabled "
                "(VEYRS_OUTBOUND_ALLOW_PRIVATE / organization setting)")


def same_origin(base_url: str, candidate: str) -> bool:
    """True when ``candidate`` (absolute) has the scheme, host and port of ``base_url``."""
    def origin(value: str) -> tuple[str, str, int | None]:
        p = urlsplit(value)
        port = p.port or {"http": 80, "https": 443}.get(p.scheme)
        return (p.scheme, (p.hostname or "").lower(), port)
    return origin(base_url) == origin(candidate)
