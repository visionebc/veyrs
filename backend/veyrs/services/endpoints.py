"""Endpoint parsing, canonicalisation and finding attachment.

An endpoint's identity has to be stable across tools or it is worthless: ZAP
reports `https://app.example.com:443/login`, Nuclei reports
`https://APP.example.com/login/`, and Burp reports `https://app.example.com/login
?next=%2F`. Those are one endpoint. Without canonicalisation the estate grows a
new "endpoint" per tool per scan and the per-endpoint mitigation tracking that
justifies the table becomes noise.

Rules applied, in order:

1. Scheme and host fold to lowercase. Hostnames are case-insensitive; paths are
   not, and are left alone.
2. The scheme's default port is dropped (`:443` on https, `:80` on http). A
   scheme with no registered default keeps its port.
3. A trailing dot on the host is removed (`example.com.` is `example.com`).
4. Path gets a leading `/` and loses a trailing one, except at the root.
5. Query parameters sort by key then value, and empty queries drop entirely.
   Parameter order carries no meaning in identity, but tools emit it in
   whatever order they happened to walk the form.
6. An empty fragment drops. A present one is kept: `#/admin` in a SPA really is
   a different screen, which the server never sees but the finding does.
"""
from __future__ import annotations

import datetime as dt
import ipaddress
import re
import uuid
from typing import Any, Iterable
from urllib.parse import parse_qsl, unquote, urlencode, urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

#: Ports a scheme implies. Only schemes where omission is unambiguous.
DEFAULT_PORTS = {
    "http": 80, "https": 443, "ftp": 21, "ssh": 22, "telnet": 23, "smtp": 25,
    "dns": 53, "ldap": 389, "ldaps": 636, "smb": 445, "rdp": 3389, "mysql": 3306,
    "postgresql": 5432, "redis": 6379, "mongodb": 27017,
}

_HOST_RE = re.compile(r"^[A-Za-z0-9._\-]+$")


class EndpointError(ValueError):
    """The endpoint is not addressable. Rejected rather than stored as junk."""


def _clean_host(host: str | None) -> str:
    if not host:
        raise EndpointError("endpoint has no host")
    host = host.strip().strip(".").lower()
    if host.startswith("[") and host.endswith("]"):  # bracketed IPv6
        host = host[1:-1]
    if not host:
        raise EndpointError("endpoint has no host")
    try:
        ipaddress.ip_address(host)
        return host
    except ValueError:
        pass
    if not _HOST_RE.match(host):
        raise EndpointError(f"host {host!r} is not a valid hostname or IP")
    return host


def _clean_path(path: str | None) -> str | None:
    if not path:
        return None
    path = path.strip()
    if not path:
        return None
    if not path.startswith("/"):
        path = "/" + path
    while "//" in path:
        path = path.replace("//", "/")
    if len(path) > 1 and path.endswith("/"):
        path = path[:-1]
    return path or "/"


def _clean_query(query: str | None) -> str | None:
    if not query:
        return None
    pairs = parse_qsl(query.strip().lstrip("?"), keep_blank_values=True)
    if not pairs:
        return None
    return urlencode(sorted(pairs, key=lambda kv: (kv[0], kv[1])))


def parse_url(url: str) -> dict[str, Any]:
    """Split a URL into the Endpoint field set. Raises `EndpointError`."""
    raw = (url or "").strip()
    if not raw:
        raise EndpointError("empty URL")
    # `urlsplit` needs a scheme to recognise the authority; a bare
    # "app.example.com/login" otherwise parses entirely as a path.
    if "://" not in raw:
        raw = "//" + raw
    parts = urlsplit(raw)
    port: int | None = None
    try:
        port = parts.port
    except ValueError as exc:  # out-of-range port in the string
        raise EndpointError(f"invalid port in {url!r}") from exc
    return {
        "protocol": (parts.scheme or None) and parts.scheme.lower(),
        "userinfo": parts.username or None,
        "host": _clean_host(parts.hostname),
        "port": port,
        "path": _clean_path(parts.path),
        "query": _clean_query(parts.query),
        "fragment": (parts.fragment or None) or None,
    }


def canonicalise(
    *,
    host: str,
    protocol: str | None = None,
    port: int | None = None,
    path: str | None = None,
    query: str | None = None,
    fragment: str | None = None,
    userinfo: str | None = None,
) -> tuple[str, dict[str, Any]]:
    """Return `(canonical_string, normalised_fields)`.

    Both halves are returned because the caller needs to store the parts (to
    query by host or port) AND the canonical form (the unique constraint), and
    deriving one from the other twice is how they drift apart.
    """
    protocol = (protocol or "").strip().lower() or None
    host = _clean_host(host)
    path = _clean_path(path)
    query = _clean_query(query)
    fragment = (fragment or "").strip() or None
    userinfo = (userinfo or "").strip() or None

    if port is not None:
        try:
            port = int(port)
        except (TypeError, ValueError):
            port = None
    if port is not None and not (0 < port <= 65535):
        port = None
    if protocol and port == DEFAULT_PORTS.get(protocol):
        port = None

    buf = []
    if protocol:
        buf.append(f"{protocol}://")
    if userinfo:
        buf.append(f"{userinfo}@")
    buf.append(f"[{host}]" if ":" in host else host)
    if port is not None:
        buf.append(f":{port}")
    if path:
        buf.append(path)
    if query:
        buf.append(f"?{query}")
    if fragment:
        buf.append(f"#{fragment}")

    fields = {
        "protocol": protocol, "userinfo": userinfo, "host": host, "port": port,
        "path": path, "query": query, "fragment": fragment,
    }
    return "".join(buf)[:2000], fields


def upsert_endpoint(
    session: Session,
    organization_id: uuid.UUID,
    *,
    host: str,
    asset_id: uuid.UUID | None = None,
    protocol: str | None = None,
    port: int | None = None,
    path: str | None = None,
    query: str | None = None,
    fragment: str | None = None,
    userinfo: str | None = None,
) -> tuple[Any, bool]:
    """Get-or-create the endpoint, binding it to an asset when we know one.

    Returns `(endpoint, created)`. The flag is returned rather than left for the
    caller to work out, because the only other way to know is to count the table
    before and after - which is O(rows) inside a per-record loop.
    """
    from ..models import Endpoint

    canonical, fields = canonicalise(
        host=host, protocol=protocol, port=port, path=path,
        query=query, fragment=fragment, userinfo=userinfo,
    )
    row = session.execute(
        select(Endpoint).where(
            Endpoint.organization_id == organization_id,
            Endpoint.canonical == canonical,
        )
    ).scalars().first()
    if row is None:
        row = Endpoint(organization_id=organization_id, canonical=canonical,
                       asset_id=asset_id, **fields)
        session.add(row)
        session.flush()
        return row, True
    if row.asset_id is None and asset_id is not None:
        # The endpoint was created before the asset register knew the host.
        row.asset_id = asset_id
    return row, False


def endpoint_from_record(
    session: Session,
    organization_id: uuid.UUID,
    record: Any,
    asset_id: uuid.UUID | None = None,
) -> tuple[Any, bool]:
    """Build the endpoint a ScanRecord describes. Returns `(endpoint, created)`.

    A record with only a port and no URL still yields an endpoint (host:port is
    a real location); a record with neither yields `(None, False)` rather than
    an endpoint on a fabricated host.
    """
    url = getattr(record, "url", None)
    if url:
        try:
            parts = parse_url(url)
        except EndpointError:
            parts = None
        if parts:
            return upsert_endpoint(session, organization_id, asset_id=asset_id, **parts)

    host = (
        getattr(record, "fqdn", None)
        or getattr(record, "hostname", None)
        or getattr(record, "ip_address", None)
    )
    if not host:
        return None, False
    port = getattr(record, "port", None)
    path = getattr(record, "path", None)
    if port is None and not path:
        # Host-level finding (a missing patch, a weak kernel setting). Those
        # belong to the asset, not to an endpoint; inventing one per finding
        # would fill the endpoint table with duplicates of the asset register.
        return None, False
    try:
        return upsert_endpoint(
            session, organization_id, asset_id=asset_id, host=host,
            protocol=getattr(record, "protocol", None), port=port, path=path,
        )
    except EndpointError:
        return None, False


def attach(
    session: Session,
    *,
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    endpoint_id: uuid.UUID,
    method: str | None = None,
    request: str | None = None,
    response: str | None = None,
    params: str | None = None,
    param_location: str | None = None,
    website: str | None = None,
):
    """Record (or refresh) "this finding was observed at this endpoint".

    Re-observing an endpoint that had been marked mitigated clears the flag:
    the fix did not hold, and leaving it mitigated is how a regression hides.
    """
    from ..models import FindingEndpoint

    now = dt.datetime.now(dt.timezone.utc)
    row = session.execute(
        select(FindingEndpoint).where(
            FindingEndpoint.organization_id == organization_id,
            FindingEndpoint.finding_id == finding_id,
            FindingEndpoint.endpoint_id == endpoint_id,
        )
    ).scalars().first()
    if row is None:
        row = FindingEndpoint(
            organization_id=organization_id, finding_id=finding_id,
            endpoint_id=endpoint_id, first_seen_at=now, last_seen_at=now,
        )
        session.add(row)
    else:
        row.last_seen_at = now
        if row.mitigated:
            row.mitigated = False
            row.mitigated_at = None
            row.mitigated_by_id = None

    if method:
        row.method = method.strip().upper()[:10]
    for field, value in (
        ("request", request), ("response", response), ("params", params),
        ("param_location", param_location), ("website", website),
    ):
        if value:
            setattr(row, field, value)
    session.flush()
    return row


def attach_described(
    session: Session,
    *,
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    described: dict[str, Any],
    asset_id: uuid.UUID | None = None,
) -> bool:
    """Attach one entry of `ScanRecord.endpoints`. Returns True if it was new.

    A malformed entry is skipped rather than raised on: one unparseable URL in
    a 4,000-instance ZAP report must not fail the whole import, and the entry
    is already preserved in the finding's evidence.
    """
    payload = dict(described or {})
    url = payload.pop("url", None)
    method = payload.pop("method", None)
    request = payload.pop("request", None)
    response = payload.pop("response", None)
    params = payload.pop("params", None)
    param_location = payload.pop("param_location", None)

    try:
        if url:
            parts = parse_url(url)
        else:
            parts = {k: payload.get(k) for k in
                     ("protocol", "host", "port", "path", "query", "fragment", "userinfo")}
            if not parts.get("host"):
                return False
        endpoint, created = upsert_endpoint(session, organization_id,
                                            asset_id=asset_id, **parts)
    except EndpointError:
        return False

    attach(
        session, organization_id=organization_id, finding_id=finding_id,
        endpoint_id=endpoint.id, method=method, request=request, response=response,
        params=params, param_location=param_location, website=url,
    )
    return created


def mitigate(
    session: Session,
    *,
    organization_id: uuid.UUID,
    finding_id: uuid.UUID,
    endpoint_ids: Iterable[uuid.UUID],
    actor_id: uuid.UUID | None = None,
) -> int:
    """Mark specific endpoints of a finding fixed. Returns how many changed."""
    from ..models import FindingEndpoint

    wanted = [e for e in endpoint_ids]
    if not wanted:
        return 0
    rows = session.execute(
        select(FindingEndpoint).where(
            FindingEndpoint.organization_id == organization_id,
            FindingEndpoint.finding_id == finding_id,
            FindingEndpoint.endpoint_id.in_(wanted),
        )
    ).scalars().all()
    now = dt.datetime.now(dt.timezone.utc)
    changed = 0
    for row in rows:
        if row.mitigated:
            continue
        row.mitigated = True
        row.mitigated_at = now
        row.mitigated_by_id = actor_id
        changed += 1
    session.flush()
    return changed


def outstanding(session: Session, organization_id: uuid.UUID, finding_id: uuid.UUID) -> int:
    """Endpoints of a finding that are still neither mitigated nor dismissed."""
    from ..models import FindingEndpoint

    rows = session.execute(
        select(FindingEndpoint).where(
            FindingEndpoint.organization_id == organization_id,
            FindingEndpoint.finding_id == finding_id,
        )
    ).scalars().all()
    return len([r for r in rows if not (r.mitigated or r.false_positive or r.risk_accepted)])


def fully_mitigated(session: Session, organization_id: uuid.UUID, finding_id: uuid.UUID) -> bool:
    """True only when the finding HAS endpoints and none are outstanding.

    A finding with no endpoints (a host-level patch) returns False: it is not
    "fully mitigated by endpoint", it simply is not endpoint-scoped, and the
    caller must not conclude anything about it from this function.
    """
    from ..models import FindingEndpoint

    total = session.execute(
        select(FindingEndpoint.id).where(
            FindingEndpoint.organization_id == organization_id,
            FindingEndpoint.finding_id == finding_id,
        )
    ).scalars().all()
    if not total:
        return False
    return outstanding(session, organization_id, finding_id) == 0
