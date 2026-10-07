"""Reading somebody else's asset inventory, and telling two of them apart.

    AssetSource -> ASSET_DRIVERS[driver] -> SourceRecord[] -> sync()
       (a row)      file | http_json | netbox     (no DB)    (the only writer)

The driver contract is the one `services/scanners.py` already established:
**drivers speak HTTP (or parse one uploaded file) and return records. They do
not touch the session, they do not create assets, and they never decide
scope.** Everything that writes is in `sync()` and `promote()`.

Three drivers, and why they are three and not one
--------------------------------------------------
* **`file`** -- a CSV/TSV/JSON/XLSX export somebody produced from a CMDB and
  uploaded by hand. The only driver that works for a customer whose CMDB VEYRS
  will never be allowed to reach.
* **`http_json`** -- any JSON API, driven by a declared `field_map`. This is
  what "connect a generic CMDB" can honestly mean: there is no such thing as
  *the* CMDB API. ServiceNow exposes a Table API, GLPI its own REST, i-doit
  **JSON-RPC**; the auth, the pagination and every field name differ. So the
  operator brings the URL and declares which path is the hostname.
* **`netbox`** -- a dedicated driver, because NetBox's schema *is* known.
  Making an operator hand-map `primary_ip4.address` when we can read the
  OpenAPI ourselves would be ceremony, not configurability.

What a sync may not do
----------------------
It may not write to `assets`. It writes staging rows and links them to assets
it recognised. Copying values into the asset register is `promote()`, a
separate and explicit act -- which is the only reason two sources can be
compared at all (see `models/cmdb.py`).
"""
from __future__ import annotations

import csv
import dataclasses
import datetime as dt
import hashlib
import io
import ipaddress
import json
import logging
import re
import uuid
from typing import Any, Iterable, Protocol, Sequence

from sqlalchemy import Integer, cast, func, select
from sqlalchemy.dialects.postgresql import array
from sqlalchemy.orm import Session

from ..models import Asset
from ..models.cmdb import (
    COMPARABLE_FIELDS, PROMOTABLE_FIELDS, SET_FIELDS, AssetSource, AssetSourceRecord,
    AssetSourceRun, MatchStatus, SourceRunStatus,
)
from ..models.assets import AssetType, Criticality, DataClassification, Environment, Exposure
from ..security.secrets import SecretError, decrypt
from . import audit, inventory

log = logging.getLogger("veyrs.cmdb")

#: Ceiling on one uploaded export and on one pulled collection. A CMDB with
#: more hosts than this is real, but it is not something to discover inside a
#: request: the cap fails loudly instead of timing out halfway through.
MAX_RECORDS = 50_000
MAX_UPLOAD_BYTES = 64 * 1024 * 1024
MAX_PAGES = 500
HTTP_TIMEOUT_S = 60
PAGE_SIZE = 200
#: Bounded sample of the rows a run refused, so "12 rejected" can be acted on.
MAX_REJECT_SAMPLES = 20

#: Fields whose value must be one of VEYRS's own enums. A value that is not is
#: kept (under `extra["unmapped"]`) and reported, never silently coerced: a
#: CMDB that says "PROD" and an import that guesses "production" agree by luck.
ENUM_FIELDS: dict[str, frozenset[str]] = {
    "asset_type": frozenset(m.value for m in AssetType),
    "criticality": frozenset(m.value for m in Criticality),
    "data_classification": frozenset(m.value for m in DataClassification),
    "exposure": frozenset(m.value for m in Exposure),
    "environment": frozenset(m.value for m in Environment),
}

#: Every normalised field a driver or a field_map may produce.
KNOWN_FIELDS: tuple[str, ...] = (
    "external_id", "name", "hostname", "fqdn", "serial", "asset_type",
    "operating_system", "os_version", "environment", "criticality", "exposure",
    "data_classification", "location", "owner_label", "team_label",
    "status_label", "ip_addresses", "mac_addresses", "tags",
)
LIST_FIELDS: frozenset[str] = frozenset({"ip_addresses", "mac_addresses", "tags"})


class CmdbError(RuntimeError):
    """A source could not be reached, authenticated, read or understood."""


@dataclasses.dataclass(frozen=True)
class SourceRecord:
    """One thing a source reported, before anything has been written."""

    external_key: str
    fields: dict[str, Any]
    raw: dict[str, Any]


@dataclasses.dataclass(frozen=True)
class SourceSpec:
    """Everything a driver needs, and nothing that touches the database."""

    driver: str
    base_url: str
    credentials: dict[str, Any]
    collections: list[str]
    field_map: dict[str, str]
    value_maps: dict[str, dict[str, str]]
    record_path: str | None = None
    verify_tls: bool = True
    timeout: int = HTTP_TIMEOUT_S
    #: Allowlist of normalised fields this source is permitted to report.
    #: **Empty means every field**, which is what every source did before the
    #: allowlist existed -- an operator who configures nothing keeps the old
    #: behaviour exactly.
    include_fields: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
def dig(obj: Any, path: str) -> Any:
    """Read `a.b[0].c` out of parsed JSON.

    A tiny subset of JSONPath on purpose: an expression language in a config
    field is a debugging surface nobody signed up for, and every CMDB payload
    seen so far is reachable with dots and indices.
    """
    if not path:
        return None
    current = obj
    for part in path.split("."):
        if current is None:
            return None
        name, _, indices = part.partition("[")
        if name:
            current = current.get(name) if isinstance(current, dict) else None
        for index in re.findall(r"(\d+)", indices):
            if not isinstance(current, (list, tuple)):
                return None
            position = int(index)
            current = current[position] if position < len(current) else None
    return current


def _text(value: Any) -> str | None:
    if value is None or isinstance(value, (dict, list)):
        return None
    text = str(value).strip()
    return text or None


def _as_list(value: Any) -> list[str]:
    if value is None:
        return []
    if isinstance(value, (list, tuple, set)):
        items = list(value)
    else:
        items = re.split(r"[,;\s]+", str(value))
    out: list[str] = []
    for item in items:
        if isinstance(item, dict):
            item = item.get("address") or item.get("name") or item.get("value")
        text = _text(item)
        if text and text not in out:
            out.append(text)
    return out


def _ip_list(value: Any) -> list[str]:
    """IPs, without the CIDR mask a network source almost always appends.

    `10.50.0.23/24` and `10.50.0.23` are the same host, and keeping both spellings
    makes every comparison between a network source and a CMDB read as a
    conflict on every row.
    """
    out: list[str] = []
    for item in _as_list(value):
        candidate = item.split("/")[0].strip()
        try:
            normalised = str(ipaddress.ip_address(candidate))
        except ValueError:
            continue
        if normalised not in out:
            out.append(normalised)
    return out


def _mac_list(value: Any) -> list[str]:
    out: list[str] = []
    for item in _as_list(value):
        digits = re.sub(r"[^0-9a-fA-F]", "", item)
        if len(digits) != 12:
            continue
        mac = ":".join(digits[i:i + 2] for i in range(0, 12, 2)).lower()
        if mac not in out:
            out.append(mac)
    return out


def normalize(
    row: dict[str, Any],
    field_map: dict[str, str],
    value_maps: dict[str, dict[str, str]],
) -> tuple[dict[str, Any], list[str]]:
    """Apply a tenant's mapping to one raw row.

    Returns the normalised fields and the list of complaints -- an enum value
    that does not exist, a mapped path that resolved to nothing. Complaints do
    NOT reject the row: an asset recorded with a missing environment is worth
    more than an asset that was dropped.
    """
    fields: dict[str, Any] = {}
    extra: dict[str, Any] = {}
    unmapped: dict[str, Any] = {}
    complaints: list[str] = []

    for target, path in (field_map or {}).items():
        if not path:
            continue
        raw_value = dig(row, path) if ("." in path or "[" in path) else row.get(path)
        if raw_value is None and path in row:
            raw_value = row[path]
        mapping = (value_maps or {}).get(target) or {}
        if mapping and _text(raw_value) is not None:
            key = str(raw_value).strip()
            raw_value = mapping.get(key, mapping.get(key.lower(), raw_value))

        if target == "ip_addresses":
            fields[target] = _ip_list(raw_value)
        elif target == "mac_addresses":
            fields[target] = _mac_list(raw_value)
        elif target == "tags":
            fields[target] = _as_list(raw_value)
        elif target in ENUM_FIELDS:
            text = (_text(raw_value) or "").lower().replace(" ", "_")
            if not text:
                continue
            if text in ENUM_FIELDS[target]:
                fields[target] = text
            else:
                unmapped[target] = _text(raw_value)
                complaints.append(f"{target} value {_text(raw_value)!r} is not a VEYRS "
                                  f"{target}; add it to this source's value_maps")
        elif target in KNOWN_FIELDS:
            text = _text(raw_value)
            if text is not None:
                fields[target] = text
        else:
            # `extra.vmid` -> extra["vmid"]. The prefix is how the operator
            # says "VEYRS has no field for this and I mean to keep it anyway";
            # the router refuses any other unknown target, so a typo cannot
            # arrive here and disappear into a blob.
            text = _text(raw_value)
            if text is not None:
                extra[target.split(".", 1)[1] if target.startswith("extra.") else target] = text

    if extra:
        fields.setdefault("extra", {}).update(extra)
    if unmapped:
        fields.setdefault("extra", {})["unmapped"] = unmapped
    return fields, complaints


def apply_include_fields(
    fields: dict[str, Any], include: Sequence[str] | None
) -> dict[str, Any]:
    """Drop every normalised field this source was not asked to report.

    Applied to the driver's OUTPUT rather than inside each driver, so the three
    drivers cannot drift on what "the operator only wants these columns" means,
    and so a driver added later inherits it without knowing it exists.

    `extra` and `raw` survive: `raw` is the audit trail of what the source
    actually said, and dropping it would make a narrowed source impossible to
    debug against the source it came from. What the allowlist governs is what
    VEYRS *reports and promotes*, not what it saw.
    """
    if not include:
        return fields
    keep = {f for f in include if f in KNOWN_FIELDS}
    out = {k: v for k, v in fields.items() if k in keep or k == "extra"}
    return out


def narrow(records: Iterable[SourceRecord], spec: SourceSpec) -> list[SourceRecord]:
    """`apply_include_fields` over a whole fetch."""
    if not spec.include_fields:
        return list(records)
    return [
        dataclasses.replace(r, fields=apply_include_fields(r.fields, spec.include_fields))
        for r in records
    ]


def identity_of(fields: dict[str, Any]) -> tuple[str | None, list[str]]:
    """The key a record is grouped by, and every key it answers to.

    The group key is the FIRST rung available, so two sources that both know a
    serial group by it; the full list exists so a serial-keyed CMDB row and an
    IP-keyed network row can still find each other through a sibling.
    """
    keys: list[str] = []
    for prefix, value in (
        ("serial", _text(fields.get("serial"))),
        ("fqdn", (_text(fields.get("fqdn")) or "").lower() or None),
        ("hostname", (_text(fields.get("hostname")) or "").lower() or None),
    ):
        if value:
            keys.append(f"{prefix}:{value.lower()}")
    for address in fields.get("ip_addresses") or []:
        keys.append(f"ip:{address}")
    for mac in fields.get("mac_addresses") or []:
        keys.append(f"mac:{mac}")
    name = (_text(fields.get("name")) or "").lower()
    if name:
        keys.append(f"name:{name}")
    return (keys[0] if keys else None), keys


def _hash(fields: dict[str, Any]) -> str:
    payload = json.dumps(fields, sort_keys=True, default=str)
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def _client(spec: SourceSpec):
    """A configured httpx client, imported locally so `import veyrs` stays free
    of network libraries (same rule as services/scanners)."""
    import httpx

    return httpx.Client(
        base_url=spec.base_url.rstrip("/"),
        verify=spec.verify_tls,
        timeout=spec.timeout,
        follow_redirects=False,
    )


def _check(response, what: str) -> None:
    if response.status_code in (401, 403):
        raise CmdbError(
            f"{what}: the source rejected these credentials (HTTP "
            f"{response.status_code}). The token may be rotated, or may not "
            f"have read permission on this collection."
        )
    if response.status_code >= 400:
        raise CmdbError(f"{what}: remote returned HTTP {response.status_code}")


def _json_body(response, what: str) -> Any:
    _check(response, what)
    try:
        return response.json()
    except ValueError as exc:
        raise CmdbError(f"{what}: remote returned a non-JSON body") from exc


def _auth_headers(credentials: dict[str, Any]) -> dict[str, str]:
    """Build the auth header the operator declared.

    `scheme` is explicit rather than sniffed: sending a bearer token to an API
    that wanted `Token ` fails as 401, and a 401 sends people to rotate a key
    that was never wrong.
    """
    scheme = str(credentials.get("scheme") or ("bearer" if credentials.get("token") else "")).lower()
    token = credentials.get("token") or credentials.get("api_key")
    if scheme == "bearer" and token:
        return {"Authorization": f"Bearer {token}"}
    if scheme == "token" and token:
        return {"Authorization": f"Token {token}"}
    if scheme == "header" and token:
        return {str(credentials.get("header_name") or "X-API-Key"): str(token)}
    if scheme == "basic":
        import base64

        pair = f"{credentials.get('username', '')}:{credentials.get('password', '')}"
        encoded = base64.b64encode(pair.encode("utf-8")).decode("ascii")
        return {"Authorization": f"Basic {encoded}"}
    if token:
        return {"Authorization": f"Bearer {token}"}
    return {}


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------
class AssetDriver(Protocol):
    driver: str
    #: What the console asks for in the credentials form.
    credential_fields: tuple[str, ...]
    #: Whether this driver needs the operator to declare a field_map.
    needs_field_map: bool

    def fetch(self, spec: SourceSpec) -> list[SourceRecord]: ...


class FileDriver:
    """A CMDB export somebody uploaded: CSV, TSV, JSON or XLSX."""

    driver = "file"
    credential_fields: tuple[str, ...] = ()
    needs_field_map = True
    default_base_url = ""

    def fetch(self, spec: SourceSpec) -> list[SourceRecord]:
        raise CmdbError(
            "this source is fed by upload: POST the export to "
            "/asset-sources/{id}/upload. VEYRS does not know where to fetch it."
        )

    # -- parsing ----------------------------------------------------------
    def rows(self, blob: bytes, filename: str | None, spec: SourceSpec) -> list[dict]:
        if len(blob) > MAX_UPLOAD_BYTES:
            raise CmdbError(f"export exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB")
        name = (filename or "").lower()
        if name.endswith(".xlsx") or blob[:2] == b"PK":
            return self._xlsx(blob)
        head = blob.lstrip()[:1]
        if name.endswith(".json") or head in (b"{", b"["):
            return self._json(blob, spec.record_path)
        return self._delimited(blob)

    def _delimited(self, blob: bytes) -> list[dict]:
        text = blob.decode("utf-8-sig", errors="replace")
        sample = text[:8192]
        try:
            dialect = csv.Sniffer().sniff(sample, delimiters=",;\t|")
        except csv.Error:
            dialect = csv.excel
        reader = csv.DictReader(io.StringIO(text), dialect=dialect)
        if not reader.fieldnames:
            raise CmdbError("the export has no header row, so no column can be mapped")
        out: list[dict] = []
        for row in reader:
            out.append({(k or "").strip(): v for k, v in row.items() if k is not None})
            if len(out) >= MAX_RECORDS:
                break
        return out

    def _json(self, blob: bytes, record_path: str | None) -> list[dict]:
        try:
            body = json.loads(blob.decode("utf-8-sig", errors="replace"))
        except ValueError as exc:
            raise CmdbError(f"the export is not readable JSON: {exc}") from exc
        return _records_in(body, record_path)

    def _xlsx(self, blob: bytes) -> list[dict]:
        try:
            from openpyxl import load_workbook
        except ImportError as exc:  # pragma: no cover - dependency present in prod
            raise CmdbError("XLSX support needs openpyxl on the server") from exc
        workbook = load_workbook(io.BytesIO(blob), read_only=True, data_only=True)
        sheet = workbook[workbook.sheetnames[0]]
        rows = sheet.iter_rows(values_only=True)
        try:
            header = [str(cell).strip() if cell is not None else "" for cell in next(rows)]
        except StopIteration:
            raise CmdbError("the workbook's first sheet is empty") from None
        out: list[dict] = []
        for row in rows:
            out.append({header[i]: row[i] for i in range(min(len(header), len(row)))
                        if header[i]})
            if len(out) >= MAX_RECORDS:
                break
        return out


class HttpJsonDriver:
    """Any JSON API, described by the operator rather than by VEYRS."""

    driver = "http_json"
    credential_fields = ("scheme", "token", "username", "password", "header_name")
    needs_field_map = True
    default_base_url = ""

    def fetch(self, spec: SourceSpec) -> list[SourceRecord]:
        if not spec.collections:
            raise CmdbError("this source has no collections configured, so it is inert")
        headers = _auth_headers(spec.credentials)
        out: list[SourceRecord] = []
        with _client(spec) as client:
            for path in spec.collections:
                out.extend(self._collection(client, spec, path, headers))
        return out

    def _collection(self, client, spec: SourceSpec, path: str,
                    headers: dict[str, str]) -> list[SourceRecord]:
        url = "/" + str(path).lstrip("/")
        params: dict[str, Any] = {}
        page_style = str(spec.credentials.get("page_style") or "next").lower()
        if page_style == "offset":
            params = {"limit": PAGE_SIZE, "offset": 0}
        out: list[SourceRecord] = []
        for _ in range(MAX_PAGES):
            body = _json_body(client.get(url, params=params, headers=headers),
                              f"reading {path}")
            rows = _records_in(body, spec.record_path)
            for index, row in enumerate(rows):
                record = _record_from_row(row, spec, collection=str(path),
                                          position=len(out) + index)
                if record is not None:
                    out.append(record)
            if len(out) >= MAX_RECORDS:
                log.warning("cmdb: %s truncated at %d records", path, MAX_RECORDS)
                break
            following = body.get("next") if isinstance(body, dict) else None
            if page_style == "offset":
                if len(rows) < PAGE_SIZE:
                    break
                params["offset"] = int(params["offset"]) + PAGE_SIZE
            elif following:
                url, params = str(following), {}
            else:
                break
        return out


#: NetBox collection -> API path. A closed map rather than free text: a typo in
#: a path returns 404, and a 404 from a source an operator just configured
#: reads as "NetBox is down".
NETBOX_COLLECTIONS: dict[str, str] = {
    "dcim.devices": "/api/dcim/devices/",
    "virtualization.virtual-machines": "/api/virtualization/virtual-machines/",
}

#: NetBox device role -> VEYRS asset type. Everything unlisted stays `server`
#: for a device and `vm` for a virtual machine, which is what NetBox itself
#: means by the endpoint.
NETBOX_ROLE_TYPES: dict[str, str] = {
    "firewall": "firewall", "router": "router", "switch": "switch",
    "access-switch": "switch", "core-switch": "switch", "load-balancer": "network_device",
    "access-point": "network_device", "wireless-ap": "network_device",
    "storage": "server", "server": "server", "workstation": "workstation",
    "laptop": "laptop", "printer": "iot", "camera": "iot", "pdu": "iot",
}


class NetBoxDriver:
    """NetBox, whose schema we know, so nothing has to be hand-mapped."""

    driver = "netbox"
    credential_fields = ("token",)
    needs_field_map = False
    default_base_url = ""

    def fetch(self, spec: SourceSpec) -> list[SourceRecord]:
        collections = [c for c in spec.collections if c in NETBOX_COLLECTIONS]
        unknown = [c for c in spec.collections if c not in NETBOX_COLLECTIONS]
        if unknown:
            raise CmdbError(
                f"unknown NetBox collections {unknown}; expected any of "
                f"{sorted(NETBOX_COLLECTIONS)}"
            )
        if not collections:
            raise CmdbError("this source has no collections configured, so it is inert")
        token = spec.credentials.get("token")
        if not token:
            raise CmdbError("NetBox needs an API token")
        headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
        out: list[SourceRecord] = []
        with _client(spec) as client:
            for collection in collections:
                out.extend(self._collection(client, spec, collection, headers))
        return out

    def _collection(self, client, spec: SourceSpec, collection: str,
                    headers: dict[str, str]) -> list[SourceRecord]:
        url = NETBOX_COLLECTIONS[collection]
        params: dict[str, Any] = {"limit": PAGE_SIZE, "offset": 0}
        out: list[SourceRecord] = []
        for _ in range(MAX_PAGES):
            body = _json_body(client.get(url, params=params, headers=headers),
                              f"reading NetBox {collection}")
            rows = body.get("results") if isinstance(body, dict) else body
            for row in rows or []:
                fields = netbox_overlay(collection, row, spec)
                key = f"{collection.split('.')[0]}.{'device' if 'dcim' in collection else 'vm'}"
                out.append(SourceRecord(
                    external_key=f"{key}:{row.get('id')}", fields=fields, raw=row,
                ))
            if len(out) >= MAX_RECORDS or not rows:
                break
            following = body.get("next") if isinstance(body, dict) else None
            if not following:
                break
            # NetBox returns an absolute URL; keep our own client and re-derive
            # the offset so a proxied deployment's hostname does not leak in.
            params["offset"] = int(params["offset"]) + PAGE_SIZE
        return out


def netbox_fields(collection: str, row: dict,
                  value_maps: dict[str, dict[str, str]] | None = None) -> dict[str, Any]:
    """One NetBox device or VM, in VEYRS's vocabulary.

    `value_maps` is consulted on the RAW NetBox token, never on the value this
    function already derived from it. Mapping the derived value would be
    useless for the case it exists for: a role slug this driver does not know
    has already collapsed to `server` by then, and every unknown role would
    have to be corrected under the same key.
    """
    is_vm = "virtual" in collection
    name = _text(row.get("name"))
    addresses: list[str] = []
    for key in ("primary_ip4", "primary_ip6", "primary_ip", "oob_ip"):
        address = dig(row, f"{key}.address")
        if address:
            addresses.extend(_ip_list(address))
    role = (_text(dig(row, "role.slug")) or _text(dig(row, "device_role.slug")) or "").lower()
    platform = _text(dig(row, "platform.name"))
    # A tenant's own role vocabulary wins over ours. `NETBOX_ROLE_TYPES` is a
    # convenience for the common slugs, not a claim to know what `hipervisor`
    # or `pve-host` means in somebody else's NetBox -- and the default it falls
    # back to (`server`) is indistinguishable from a deliberate answer.
    role_types = {str(k).strip().lower(): v
                  for k, v in ((value_maps or {}).get("asset_type") or {}).items()}
    declared_type = role_types.get(role) if role else None
    if declared_type not in ENUM_FIELDS["asset_type"]:
        declared_type = None
    fields: dict[str, Any] = {
        "name": name,
        "hostname": name,
        "serial": _text(row.get("serial")),
        "asset_type": declared_type or ("vm" if is_vm else NETBOX_ROLE_TYPES.get(role, "server")),
        "operating_system": platform,
        "location": (_text(dig(row, "site.name")) or _text(dig(row, "cluster.name"))),
        "owner_label": _text(dig(row, "tenant.name")),
        "team_label": _text(dig(row, "tenant.name")),
        "status_label": _text(dig(row, "status.value")),
        "ip_addresses": list(dict.fromkeys(addresses)),
        "tags": [t.get("name") for t in (row.get("tags") or []) if isinstance(t, dict)],
    }
    if not is_vm:
        model = _text(dig(row, "device_type.model"))
        vendor = _text(dig(row, "device_type.manufacturer.name"))
        if model:
            fields.setdefault("extra", {})["hardware_model"] = (
                f"{vendor} {model}" if vendor else model
            )
    # NetBox's `status` is a lifecycle, not an environment, and the two are
    # routinely confused: "active" says the device is racked, not that it is
    # production. It is carried as a label and never mapped to `environment`
    # BY DEFAULT -- an operator who means it can say so with
    # field_map={"environment": "status.value"} and a value_map, which is an
    # explicit act rather than a guess made on their behalf.
    for target, mapping in (value_maps or {}).items():
        if target == "asset_type" or target not in fields:
            continue
        current = fields.get(target)
        if not isinstance(current, str):
            continue
        replacement = mapping.get(current, mapping.get(current.lower()))
        if replacement is not None and (
            target not in ENUM_FIELDS or replacement in ENUM_FIELDS[target]
        ):
            fields[target] = replacement
    return {k: v for k, v in fields.items() if v not in (None, [], {})}


def netbox_overlay(collection: str, row: dict, spec: SourceSpec) -> dict[str, Any]:
    """NetBox's known schema first, then whatever this tenant declared on top.

    For this driver `field_map` is an OVERRIDE layer, not a requirement --
    `needs_field_map` stays False and a source that declares nothing behaves
    exactly as it did before the layer existed. What it buys is the half of
    NetBox no driver can know: `custom_fields.*` is installation-specific by
    definition, and until now those values were dropped in silence. This
    NetBox carries `pve_node`, `pve_tags` and `vmid`; none of them are in
    anybody's published schema, and all three are the interesting part.

    A declared path that resolves to nothing does NOT erase the default. An
    override layer that can blank a field by being slightly wrong is a way to
    lose the hostname of every host on a typo.
    """
    fields = netbox_fields(collection, row, spec.value_maps)
    if not spec.field_map:
        return fields
    declared, _ = normalize(row, spec.field_map, spec.value_maps)
    merged_extra = {**(fields.get("extra") or {}), **(declared.pop("extra", None) or {})}
    fields.update(declared)
    if merged_extra:
        fields["extra"] = merged_extra
    return fields


ASSET_DRIVERS: dict[str, Any] = {
    "file": FileDriver(),
    "http_json": HttpJsonDriver(),
    "netbox": NetBoxDriver(),
}

DRIVER_LABELS = {
    "file": "CMDB export (CSV / TSV / JSON / XLSX upload)",
    "http_json": "Generic JSON API (declare the field mapping)",
    "netbox": "NetBox (DCIM / IPAM)",
}


def describe_drivers() -> list[dict[str, Any]]:
    """What the console renders in the source form."""
    return [
        {
            "driver": key,
            "label": DRIVER_LABELS.get(key, key),
            "credential_fields": list(driver.credential_fields),
            "needs_field_map": driver.needs_field_map,
            "is_upload": key == "file",
            "collections": sorted(NETBOX_COLLECTIONS) if key == "netbox" else None,
            "fields": list(KNOWN_FIELDS),
            # Every driver ACCEPTS a field map. Only some require one, and the
            # console has to be able to tell the two apart: a form that hides
            # the mapping whenever it is not mandatory is how the NetBox
            # custom fields stayed unreachable.
            "accepts_field_map": True,
            "field_map_is_override": not driver.needs_field_map,
        }
        for key, driver in sorted(ASSET_DRIVERS.items())
    ]


def _records_in(body: Any, record_path: str | None) -> list[dict]:
    if record_path:
        body = dig(body, record_path)
    if isinstance(body, dict):
        for key in ("results", "data", "items", "records", "value"):
            if isinstance(body.get(key), list):
                body = body[key]
                break
        else:
            body = [body]
    if not isinstance(body, list):
        raise CmdbError(
            "the response holds no array of records; set record_path to the "
            "path of the list (for example 'result.items')"
        )
    return [row for row in body if isinstance(row, dict)]


def _record_from_row(row: dict, spec: SourceSpec, *, collection: str,
                     position: int) -> SourceRecord | None:
    fields, _ = normalize(row, spec.field_map, spec.value_maps)
    key = _external_key(fields, collection=collection, position=position)
    if key is None:
        return None
    return SourceRecord(external_key=key, fields=fields, raw=row)


def _external_key(fields: dict[str, Any], *, collection: str,
                  position: int) -> str | None:
    """The source's own id, or the most stable thing the row carries.

    Falling back to the row NUMBER is deliberately refused: a re-export with
    one row inserted at the top would renumber every host and the next sync
    would report the entire estate as new and the entire estate as absent.
    """
    explicit = _text(fields.get("external_id"))
    if explicit:
        return f"{collection}:{explicit}" if collection else explicit
    identity, _ = identity_of(fields)
    if identity:
        return f"{collection}:{identity}" if collection else identity
    return None


# ---------------------------------------------------------------------------
# Source -> spec
# ---------------------------------------------------------------------------
def credentials_of(source: AssetSource) -> dict[str, Any]:
    """Decrypt this source's credentials, or fail loudly.

    Fails closed, exactly as `scanners.credentials_of` does: falling back to an
    unauthenticated request turns "the encryption key changed" into a 401 that
    reads as a rotated token.
    """
    if not source.credentials_enc:
        return {}
    try:
        raw = decrypt(source.credentials_enc)
    except SecretError as exc:
        raise CmdbError(
            "stored credentials cannot be decrypted with the current "
            "VEYRS_ENCRYPTION_KEY; re-enter them"
        ) from exc
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise CmdbError("stored credentials are not readable JSON") from exc
    return parsed if isinstance(parsed, dict) else {}


def spec_for(source: AssetSource) -> SourceSpec:
    driver = ASSET_DRIVERS.get(source.driver)
    if driver is None:
        raise CmdbError(f"unknown driver {source.driver!r}")
    base_url = (source.base_url or "").strip()
    if not base_url and source.driver != "file":
        raise CmdbError("this source has no base URL")
    return SourceSpec(
        driver=source.driver,
        base_url=base_url,
        credentials=credentials_of(source),
        collections=list(source.collections or []),
        field_map=dict(source.field_map or {}),
        value_maps=dict(source.value_maps or {}),
        record_path=source.record_path,
        verify_tls=source.verify_tls,
        include_fields=tuple(source.include_fields or ()),
    )


def test_connection(source: AssetSource) -> dict[str, Any]:
    """Read-only reachability check. Touches no VEYRS row."""
    if source.driver == "file":
        return {"ok": True, "detail": "upload-fed source; nothing to reach"}
    spec = spec_for(source)
    records = narrow(ASSET_DRIVERS[source.driver].fetch(spec), spec)
    sample = records[0] if records else None
    return {
        "ok": True,
        "records": len(records),
        "sample": {"external_key": sample.external_key, "fields": sample.fields}
        if sample else None,
    }


# ---------------------------------------------------------------------------
# Matching
# ---------------------------------------------------------------------------
def resolve_asset(
    session: Session, organization_id: uuid.UUID, fields: dict[str, Any],
    match_order: Sequence[str],
) -> tuple[Asset | None, str | None]:
    """Walk the ladder and return the first asset that answers.

    Returns the rung as well: "why is this the same host" needs an answer an
    operator can disagree with, and `matched_by="hostname"` is one.
    """
    for rung in match_order or ():
        asset = None
        if rung == "external_id" and _text(fields.get("external_id")):
            asset = _first(session, organization_id,
                           Asset.external_id == _text(fields["external_id"]))
        elif rung == "serial" and _text(fields.get("serial")):
            asset = _first(session, organization_id,
                           Asset.attributes["serial"].astext == _text(fields["serial"]))
        elif rung == "fqdn" and _text(fields.get("fqdn")):
            asset = _first(session, organization_id,
                           func.lower(Asset.fqdn) == _text(fields["fqdn"]).lower())
        elif rung == "hostname" and _text(fields.get("hostname")):
            asset = _first(session, organization_id,
                           func.lower(Asset.hostname) == _text(fields["hostname"]).lower())
        elif rung == "ip":
            for address in fields.get("ip_addresses") or []:
                asset = _first(session, organization_id,
                               Asset.ip_addresses.contains([address]))
                if asset is not None:
                    break
        elif rung == "name" and _text(fields.get("name")):
            asset = _first(session, organization_id,
                           func.lower(Asset.name) == _text(fields["name"]).lower())
        if asset is not None:
            return asset, rung
    return None, None


def _first(session: Session, organization_id: uuid.UUID, predicate):
    return session.execute(
        select(Asset).where(
            Asset.organization_id == organization_id,
            Asset.deleted_at.is_(None),
            predicate,
        ).limit(1)
    ).scalars().first()


def _sibling(
    session: Session, organization_id: uuid.UUID, source_id: uuid.UUID,
    match_keys: Sequence[str],
) -> AssetSourceRecord | None:
    """A record from ANOTHER source that shares any key with this one."""
    if not match_keys:
        return None
    # `?|` (JSONB "has any of these top-level keys"), not `@>`: containment
    # would demand the sibling carry EVERY key this record does, which is
    # exactly the case that never happens between two different sources.
    return session.execute(
        select(AssetSourceRecord).where(
            AssetSourceRecord.organization_id == organization_id,
            AssetSourceRecord.source_id != source_id,
            AssetSourceRecord.match_keys.has_any(array(tuple(match_keys))),
        ).order_by(AssetSourceRecord.asset_id.is_(None)).limit(1)
    ).scalars().first()


# ---------------------------------------------------------------------------
# Sync -- the only writer
# ---------------------------------------------------------------------------
def sync(
    session: Session,
    source: AssetSource,
    *,
    records: Iterable[SourceRecord] | None = None,
    blob: bytes | None = None,
    filename: str | None = None,
    actor_id: uuid.UUID | None = None,
    dry_run: bool = False,
    mark_absent: bool | None = None,
    trigger: str = "manual",
) -> AssetSourceRun:
    """Read a source and write staging rows. Never writes to `assets`.

    `mark_absent` defaults to True for a pull driver and **False for an
    upload**: a connector reading a whole collection is making a statement
    about that collection, while an operator uploading a file may well have
    exported a filtered extract. Same reasoning as `close_absent` needing an
    engagement in the finding importers.
    """
    if not source.is_enabled:
        raise CmdbError(
            f"source {source.slug!r} is disabled. A source that reads the "
            f"moment it is saved is a connection nobody decided to make; "
            f"enable it first."
        )
    spec = spec_for(source)
    is_upload = blob is not None
    if mark_absent is None:
        mark_absent = not is_upload

    run = AssetSourceRun(
        organization_id=source.organization_id,
        source_id=source.id,
        trigger=trigger,
        dry_run=dry_run,
        filename=filename,
        started_by_id=actor_id,
        status=(SourceRunStatus.PREVIEW if dry_run else SourceRunStatus.RUNNING).value,
    )
    # Column defaults are applied by the INSERT, and a dry run never issues
    # one: without this the first `run.records_seen += 1` is None + 1. The
    # preview and the commit must count identically or the preview is a lie.
    for counter in ("records_seen", "records_created", "records_updated",
                    "records_unchanged", "records_rejected", "assets_matched",
                    "assets_unmatched", "assets_promoted", "assets_created",
                    "records_absent", "size_bytes"):
        setattr(run, counter, 0)
    run.reject_reasons = {}
    run.reject_samples = []
    if not dry_run:
        session.add(run)
        session.flush()

    try:
        if records is None:
            if is_upload:
                run.size_bytes = len(blob)
                run.content_hash = hashlib.sha256(blob).hexdigest()
                rows = ASSET_DRIVERS["file"].rows(blob, filename, spec)
                records = []
                for position, row in enumerate(rows):
                    record = _record_from_row(row, spec, collection="", position=position)
                    if record is None:
                        _reject(run, "no identifier: the row carries no external id, "
                                     "serial, fqdn, hostname, IP or name", row)
                        continue
                    records.append(record)
            else:
                records = ASSET_DRIVERS[source.driver].fetch(spec)
            records = narrow(records, spec)
        _ingest(session, source, run, list(records), dry_run=dry_run,
                mark_absent=mark_absent, actor_id=actor_id)
    except CmdbError as exc:
        run.status = SourceRunStatus.FAILED.value
        run.error = str(exc)
        run.finished_at = dt.datetime.now(dt.timezone.utc)
        if not dry_run:
            source.last_error = str(exc)
            session.flush()
        raise

    run.finished_at = dt.datetime.now(dt.timezone.utc)
    if not dry_run:
        run.status = SourceRunStatus.COMPLETE.value
        source.last_sync_at = run.finished_at
        source.last_error = None
        source.last_run_id = run.id
        session.flush()
        audit.record(
            session, action="cmdb.source.synced", object_type="asset_source",
            object_id=source.id, object_label=source.slug,
            organization_id=source.organization_id, actor_id=actor_id,
            changes={"seen": run.records_seen, "created": run.records_created,
                     "updated": run.records_updated, "matched": run.assets_matched,
                     "unmatched": run.assets_unmatched, "absent": run.records_absent,
                     "promoted": run.assets_promoted},
        )
    return run


def _reject(run: AssetSourceRun, reason: str, row: Any) -> None:
    run.records_rejected += 1
    reasons = dict(run.reject_reasons or {})
    reasons[reason] = reasons.get(reason, 0) + 1
    run.reject_reasons = reasons
    samples = list(run.reject_samples or [])
    if len(samples) < MAX_REJECT_SAMPLES:
        samples.append({"reason": reason, "row": _truncate(row)})
        run.reject_samples = samples


def _truncate(row: Any) -> Any:
    text = json.dumps(row, default=str)[:800]
    try:
        return json.loads(text)
    except ValueError:
        return text


def _ingest(
    session: Session, source: AssetSource, run: AssetSourceRun,
    records: list[SourceRecord], *, dry_run: bool, mark_absent: bool,
    actor_id: uuid.UUID | None,
) -> None:
    now = dt.datetime.now(dt.timezone.utc)
    seen_keys: set[str] = set()

    existing_rows = session.execute(
        select(AssetSourceRecord).where(
            AssetSourceRecord.organization_id == source.organization_id,
            AssetSourceRecord.source_id == source.id,
        )
    ).scalars().all()
    existing = {row.external_key: row for row in existing_rows}

    for record in records:
        run.records_seen += 1
        if record.external_key in seen_keys:
            _reject(run, "duplicate external key within one export", record.raw)
            continue
        seen_keys.add(record.external_key)

        fields = dict(record.fields)
        identity, keys = identity_of(fields)
        digest = _hash({"fields": fields, "raw": record.raw})
        row = existing.get(record.external_key)

        if row is not None and row.content_hash == digest and not row.is_absent:
            run.records_unchanged += 1
            if not dry_run:
                row.last_seen_at = now
                row.last_run_id = run.id
            if row.asset_id is not None:
                run.assets_matched += 1
            else:
                run.assets_unmatched += 1
            continue

        asset, matched_by = resolve_asset(
            session, source.organization_id, fields, source.match_order or ())
        if asset is None:
            sibling = _sibling(session, source.organization_id, source.id, keys)
            if sibling is not None and sibling.asset_id is not None:
                asset = session.get(Asset, sibling.asset_id)
                matched_by = f"sibling:{sibling.source_id}"
            elif sibling is not None and sibling.identity_key:
                identity = sibling.identity_key

        if row is None:
            run.records_created += 1
        else:
            run.records_updated += 1
        if asset is not None:
            run.assets_matched += 1
        else:
            run.assets_unmatched += 1

        if dry_run:
            continue

        if row is None:
            row = AssetSourceRecord(
                organization_id=source.organization_id,
                source_id=source.id,
                external_key=record.external_key,
                first_seen_at=now,
            )
            session.add(row)
        for field in KNOWN_FIELDS:
            if field == "external_id":
                continue
            if field in fields:
                setattr(row, field, fields[field])
            elif field in LIST_FIELDS and getattr(row, field, None) is None:
                setattr(row, field, [])
        row.extra = dict(fields.get("extra") or {})
        row.raw = record.raw
        row.identity_key = identity
        row.match_keys = keys
        row.content_hash = digest
        row.last_seen_at = now
        row.last_run_id = run.id
        row.is_absent = False
        row.absent_since = None
        if row.match_status != MatchStatus.IGNORED.value:
            row.asset_id = asset.id if asset is not None else None
            row.matched_by = matched_by
            row.match_status = (MatchStatus.MATCHED if asset is not None
                                else MatchStatus.UNMATCHED).value
        session.flush()

        if source.auto_promote and row.match_status != MatchStatus.IGNORED.value:
            created = promote_record(
                session, row, source, actor_id=actor_id,
                create_assets=source.promote_creates_assets)
            if created is not None:
                run.assets_promoted += 1
                if created:
                    run.assets_created += 1

    if mark_absent:
        for key, row in existing.items():
            if key in seen_keys or row.is_absent:
                continue
            run.records_absent += 1
            if not dry_run:
                row.is_absent = True
                row.absent_since = now
    if not dry_run:
        session.flush()


# ---------------------------------------------------------------------------
# Promotion -- the only place staging becomes the asset register
# ---------------------------------------------------------------------------
def promote_record(
    session: Session, row: AssetSourceRecord, source: AssetSource, *,
    actor_id: uuid.UUID | None = None, create_assets: bool = False,
) -> bool | None:
    """Copy one record's facts into the asset register.

    Returns True if it created the asset, False if it updated one, None if it
    declined (nothing matched and `create_assets` is off). Declining is the
    normal case for a first import and is not an error: inventing assets is how
    an asset register stops meaning anything.
    """
    if row.match_status == MatchStatus.IGNORED.value:
        return None
    if row.asset_id is None and not create_assets:
        return None

    spec: dict[str, Any] = {}
    if row.asset_id is not None:
        asset = session.get(Asset, row.asset_id)
        if asset is None or asset.organization_id != source.organization_id:
            return None
    for field in PROMOTABLE_FIELDS:
        value = getattr(row, field, None)
        if value not in (None, "", []):
            spec[field] = value
    if not spec.get("name"):
        spec["name"] = row.name or row.hostname or row.fqdn
    if not spec.get("name"):
        return None
    # Route through the asset the record already resolved to, rather than
    # letting upsert_asset re-run its own ladder: the record's link is what an
    # operator reviewed in the comparative, and silently matching something
    # else here would promote into a host nobody agreed to.
    if row.asset_id is not None:
        asset = session.get(Asset, row.asset_id)
        created = False
        for field in PROMOTABLE_FIELDS:
            if field in spec and hasattr(asset, field):
                setattr(asset, field, spec[field])
    else:
        asset, created = inventory.upsert_asset(session, source.organization_id, spec)
        row.asset_id = asset.id
        row.match_status = MatchStatus.MATCHED.value
        row.matched_by = row.matched_by or "promotion"
    attributes = dict(asset.attributes or {})
    if row.serial:
        attributes["serial"] = row.serial
    sources = dict(attributes.get("sources") or {})
    sources[source.slug] = row.external_key
    attributes["sources"] = sources
    asset.attributes = attributes
    if created:
        # Provenance is set once, at birth. Rewriting it on every promotion
        # would make `assets.source` mean "whichever feed synced most
        # recently", which is not a fact about the asset.
        asset.source = source.slug
    asset.last_seen_at = row.last_seen_at or dt.datetime.now(dt.timezone.utc)
    row.promoted_at = dt.datetime.now(dt.timezone.utc)
    row.promoted_by_id = actor_id
    session.flush()
    audit.record(
        session, action="cmdb.record.promoted", object_type="asset",
        object_id=asset.id, object_label=asset.name,
        organization_id=source.organization_id, actor_id=actor_id,
        changes={"source": source.slug, "external_key": row.external_key,
                 "created": created, **{k: str(v) for k, v in spec.items()}},
    )
    return created


def promote(
    session: Session, organization_id: uuid.UUID, record_ids: Sequence[uuid.UUID], *,
    actor_id: uuid.UUID | None = None, create_assets: bool = False,
) -> dict[str, Any]:
    """Promote a set of records, lowest `AssetSource.priority` last.

    Order matters and is the whole of phase-1 precedence: the lowest-priority
    number is applied LAST, so it is the one whose values survive. Reversing
    this is the difference between "NetBox owns the network facts" and "the
    last source to sync owns everything".
    """
    rows = session.execute(
        select(AssetSourceRecord, AssetSource)
        .join(AssetSource, AssetSourceRecord.source_id == AssetSource.id)
        .where(
            AssetSourceRecord.organization_id == organization_id,
            AssetSourceRecord.id.in_(list(record_ids)),
        )
    ).all()
    ordered = sorted(rows, key=lambda pair: -int(pair[1].priority or 100))
    promoted = created = declined = 0
    for row, source in ordered:
        outcome = promote_record(session, row, source, actor_id=actor_id,
                                 create_assets=create_assets)
        if outcome is None:
            declined += 1
        else:
            promoted += 1
            created += 1 if outcome else 0
    return {"promoted": promoted, "created": created, "declined": declined,
            "requested": len(record_ids)}


# ---------------------------------------------------------------------------
# The comparative
# ---------------------------------------------------------------------------
def _comparable(field: str, value: Any) -> Any:
    if value in (None, "", []):
        return None
    if field in SET_FIELDS:
        return sorted({str(v).strip().lower() for v in value})
    return str(value).strip().lower()


def compare(
    session: Session, organization_id: uuid.UUID, *,
    source_ids: Sequence[uuid.UUID] | None = None,
    mode: str = "conflicts",
    include_absent: bool = False,
    limit: int = 100, offset: int = 0,
) -> dict[str, Any]:
    """What two or more sources say about the same thing, side by side.

    `mode`:
      * `conflicts` -- groups where two sources disagree on a comparable field.
      * `gaps`      -- groups a selected source does not know about at all.
      * `all`       -- every group.

    Grouping is by `asset_id` when the records resolved, and by `identity_key`
    when they did not. Both halves matter: an estate that has just connected
    two sources for the first time has no assets yet, and a comparative that
    could only compare promoted records would be empty exactly when it is most
    useful.
    """
    query = select(AssetSourceRecord, AssetSource).join(
        AssetSource, AssetSourceRecord.source_id == AssetSource.id
    ).where(
        AssetSourceRecord.organization_id == organization_id,
        AssetSourceRecord.match_status != MatchStatus.IGNORED.value,
    )
    if source_ids:
        query = query.where(AssetSourceRecord.source_id.in_(list(source_ids)))
    if not include_absent:
        query = query.where(AssetSourceRecord.is_absent.is_(False))
    rows = session.execute(query).all()

    selected: dict[uuid.UUID, AssetSource] = {}
    groups: dict[str, dict[str, Any]] = {}
    for record, source in rows:
        selected.setdefault(source.id, source)
        if record.asset_id is not None:
            key = f"asset:{record.asset_id}"
        elif record.identity_key:
            key = f"key:{record.identity_key}"
        else:
            key = f"record:{record.id}"
        group = groups.setdefault(key, {
            "key": key,
            "asset_id": record.asset_id,
            "label": None,
            "records": [],
        })
        group["label"] = group["label"] or (
            record.fqdn or record.hostname or record.name or record.serial
        )
        group["records"].append((record, source))

    source_slugs = {s.id: s.slug for s in selected.values()}
    out: list[dict[str, Any]] = []
    conflict_total = gap_total = 0
    for group in groups.values():
        by_source: dict[str, dict[str, Any]] = {}
        for record, source in group["records"]:
            by_source[source.slug] = {
                "record_id": str(record.id),
                "external_key": record.external_key,
                "matched_by": record.matched_by,
                "is_absent": record.is_absent,
                "promoted_at": record.promoted_at.isoformat() if record.promoted_at else None,
                "facts": {f: getattr(record, f, None) for f in COMPARABLE_FIELDS},
            }
        conflicts: dict[str, dict[str, Any]] = {}
        for field in COMPARABLE_FIELDS:
            stated = {
                slug: entry["facts"][field] for slug, entry in by_source.items()
                if _comparable(field, entry["facts"][field]) is not None
            }
            normalised = {_comparable(field, value) if field not in SET_FIELDS
                          else tuple(_comparable(field, value))
                          for value in stated.values()}
            if len(stated) > 1 and len(normalised) > 1:
                conflicts[field] = stated
        missing = sorted(slug for sid, slug in source_slugs.items()
                         if slug not in by_source)
        if conflicts:
            conflict_total += 1
        if missing:
            gap_total += 1
        if mode == "conflicts" and not conflicts:
            continue
        if mode == "gaps" and not missing:
            continue
        out.append({
            "key": group["key"],
            "asset_id": str(group["asset_id"]) if group["asset_id"] else None,
            "label": group["label"],
            "present_in": sorted(by_source),
            "missing_from": missing,
            "conflicts": conflicts,
            "sources": by_source,
        })

    out.sort(key=lambda g: (-len(g["conflicts"]), g["label"] or ""))
    return {
        "sources": [{"id": str(s.id), "slug": s.slug, "name": s.name,
                     "driver": s.driver, "priority": s.priority}
                    for s in sorted(selected.values(), key=lambda s: s.priority)],
        "total_groups": len(groups),
        "groups_with_conflicts": conflict_total,
        "groups_with_gaps": gap_total,
        "returned": len(out[offset:offset + limit]),
        "groups": out[offset:offset + limit],
    }


def summary(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """Counters the console leads with, per source."""
    rows = session.execute(
        select(
            AssetSource,
            func.count(AssetSourceRecord.id),
            func.count(AssetSourceRecord.asset_id),
            func.sum(cast(AssetSourceRecord.is_absent, Integer)),
        )
        .outerjoin(AssetSourceRecord, AssetSourceRecord.source_id == AssetSource.id)
        .where(AssetSource.organization_id == organization_id)
        .group_by(AssetSource.id)
        .order_by(AssetSource.priority, AssetSource.slug)
    ).all()
    return {
        "sources": [
            {
                "id": str(source.id), "slug": source.slug, "name": source.name,
                "driver": source.driver, "is_enabled": source.is_enabled,
                "priority": source.priority,
                "records": int(total or 0),
                "matched": int(matched or 0),
                "unmatched": int((total or 0) - (matched or 0)),
                "absent": int(absent or 0),
                "last_sync_at": source.last_sync_at.isoformat() if source.last_sync_at else None,
                "last_error": source.last_error,
            }
            for source, total, matched, absent in rows
        ]
    }
