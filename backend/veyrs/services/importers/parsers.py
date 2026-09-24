"""Vendor export parsers (spec section 31).

Each parser is a pure function `bytes -> Iterator[ScanRecord]`. No database, no
network, no side effects -- which is why they are cheap to test against real
export fragments and why a malformed file can only ever raise `ParserError`.

XML is parsed with entity declarations rejected. A `.nessus` file is
attacker-influenced input (it describes hosts an attacker may control, and it
arrives from wherever the operator got it), so XXE defence is not optional here
any more than it is in document ingestion.
"""
from __future__ import annotations

import csv
import io
import json
import re
from typing import Any, Iterator
from xml.etree import ElementTree

from .. import xmlsafe
from ..versions import cpe22_to_cpe23
from .base import CVE_RE, HostInventory, ParserError, ScanRecord, SoftwareSpec
from .parsers_modern import MODERN_PARSERS, detect_modern_format

# Nessus severity is an integer 0-4.
NESSUS_SEVERITY = {
    "0": "informational", "1": "low", "2": "medium", "3": "high", "4": "critical",
}
# Greenbone/OpenVAS reports a threat word plus a CVSS base score.
GREENBONE_THREAT = {
    "Log": "informational", "Debug": "informational", "False Positive": "informational",
    "Low": "low", "Medium": "medium", "High": "high", "Critical": "critical",
}
# Qualys uses a 1-5 severity scale (5 = most severe).
QUALYS_SEVERITY = {
    "1": "informational", "2": "low", "3": "medium", "4": "high", "5": "critical",
}


def _decode(payload: bytes) -> str:
    for encoding in ("utf-8-sig", "utf-8", "latin-1"):
        try:
            return payload.decode(encoding)
        except UnicodeDecodeError:
            continue
    raise ParserError("file is not decodable text")


def _parse_xml(payload: bytes) -> ElementTree.Element:
    """Parse XML with entity declarations refused (XXE defence).

    The guard used to live here, attached to `XMLParser.parser` — an attribute
    Python removed in 3.9, behind an `except AttributeError: pass`. It had
    therefore never run on any interpreter this product shipped on. It is now
    `services.xmlsafe`, one implementation, exercised by its own tests.
    """
    try:
        xmlsafe.reject_entity_declarations(payload)
    except xmlsafe.UnsafeXmlError as exc:
        raise ParserError(str(exc)) from exc

    try:
        return ElementTree.fromstring(_decode(payload))
    except ParserError:
        raise
    except ElementTree.ParseError as exc:
        raise ParserError(f"invalid XML: {exc}") from exc


def _int_or_none(value: Any) -> int | None:
    try:
        number = int(str(value).strip())
    except (TypeError, ValueError):
        return None
    return number if 0 < number <= 65535 else None


def _float_or_none(value: Any) -> float | None:
    try:
        return float(str(value).strip())
    except (TypeError, ValueError):
        return None


# ---------------------------------------------------------------------------
# Nessus (.nessus v2)
# ---------------------------------------------------------------------------
def parse_nessus(payload: bytes) -> Iterator[ScanRecord]:
    root = _parse_xml(payload)
    if root.tag != "NessusClientData_v2":
        raise ParserError(f"not a Nessus v2 report (root element is {root.tag!r})")

    for host in root.iter("ReportHost"):
        properties = {
            tag.get("name"): (tag.text or "").strip()
            for tag in host.findall("./HostProperties/tag")
        }
        hostname = properties.get("host-fqdn") or host.get("name")
        fqdn = properties.get("host-fqdn")
        ip_address = properties.get("host-ip") or (
            host.get("name") if _looks_like_ip(host.get("name")) else None
        )

        for item in host.findall("ReportItem"):
            severity = NESSUS_SEVERITY.get(item.get("severity", "0"), "informational")
            cves = [e.text.strip() for e in item.findall("cve") if e.text]
            record = ScanRecord(
                hostname=None if _looks_like_ip(hostname) else hostname,
                fqdn=fqdn,
                ip_address=ip_address,
                mac_address=properties.get("mac-address"),
                operating_system=properties.get("operating-system"),
                title=item.get("pluginName") or "",
                cve_ids=cves,
                plugin_id=item.get("pluginID"),
                severity=severity,
                cvss_vector=_text(item, "cvss3_vector") or _text(item, "cvss_vector"),
                cvss_score=_float_or_none(
                    _text(item, "cvss3_base_score") or _text(item, "cvss_base_score")
                ),
                description=_text(item, "description"),
                solution=_text(item, "solution"),
                port=_int_or_none(item.get("port")),
                protocol=item.get("protocol"),
                evidence={"plugin_output": (_text(item, "plugin_output") or "")[:4000],
                          "plugin_family": item.get("pluginFamily")},
                raw={"pluginID": item.get("pluginID")},
            )
            yield record


def _text(element: ElementTree.Element, tag: str) -> str | None:
    child = element.find(tag)
    if child is None or child.text is None:
        return None
    return child.text.strip() or None


def _looks_like_ip(value: str | None) -> bool:
    return bool(value) and bool(re.fullmatch(r"[0-9.]+|[0-9a-fA-F:]+", value or ""))


# ---------------------------------------------------------------------------
# Greenbone / OpenVAS (GMP get_reports XML)
# ---------------------------------------------------------------------------
def parse_greenbone(payload: bytes) -> Iterator[ScanRecord]:
    root = _parse_xml(payload)
    results = list(root.iter("result"))
    if not results:
        raise ParserError("no <result> elements found; not a Greenbone report")

    for result in results:
        host_element = result.find("host")
        ip_address = (host_element.text or "").strip() if host_element is not None else None
        hostname = None
        if host_element is not None:
            asset_name = host_element.find("hostname")
            if asset_name is not None and asset_name.text:
                hostname = asset_name.text.strip()

        nvt = result.find("nvt")
        cves: list[str] = []
        cvss_vector = None
        cvss_score = None
        oid = None
        if nvt is not None:
            oid = nvt.get("oid")
            cvss_score = _float_or_none(_text(nvt, "cvss_base"))
            refs = nvt.find("refs")
            if refs is not None:
                cves = [r.get("id") for r in refs.findall("ref")
                        if (r.get("type") or "").lower() == "cve" and r.get("id")]
            tags = _text(nvt, "tags") or ""
            match = re.search(r"cvss_base_vector=([^|]+)", tags)
            if match:
                cvss_vector = match.group(1).strip()

        port_text = _text(result, "port") or ""
        port, protocol = _split_greenbone_port(port_text)

        yield ScanRecord(
            hostname=hostname,
            ip_address=ip_address,
            title=_text(result, "name") or (nvt is not None and _text(nvt, "name")) or "",
            cve_ids=cves,
            plugin_id=oid,
            severity=GREENBONE_THREAT.get(_text(result, "threat") or "", None),
            cvss_vector=cvss_vector,
            cvss_score=cvss_score,
            description=_text(result, "description"),
            solution=(_text(nvt, "solution") if nvt is not None else None),
            port=port,
            protocol=protocol,
            evidence={"oid": oid, "qod": _text(result, "qod")},
            raw={"oid": oid},
        )


def _split_greenbone_port(value: str) -> tuple[int | None, str | None]:
    """Greenbone writes '443/tcp' or 'general/tcp'."""
    if "/" not in value:
        return None, None
    left, _, right = value.partition("/")
    return _int_or_none(left), (right.strip().lower() or None)


# ---------------------------------------------------------------------------
# Qualys (VM scan report XML, and the CSV export)
# ---------------------------------------------------------------------------
def parse_qualys(payload: bytes) -> Iterator[ScanRecord]:
    root = _parse_xml(payload)
    hosts = list(root.iter("HOST"))
    if not hosts:
        raise ParserError("no <HOST> elements found; not a Qualys VM report")

    for host in hosts:
        ip_address = _text(host, "IP")
        hostname = _text(host, "DNS") or _text(host, "NETBIOS")
        operating_system = _text(host, "OPERATING_SYSTEM")

        for vuln in host.iter("VULN"):
            cve_ids = [
                (element.text or "").strip()
                for element in vuln.iter("ID")
                if element.text and CVE_RE.fullmatch(element.text.strip())
            ]
            if not cve_ids:
                cve_ids = CVE_RE.findall(_text(vuln, "CVE_ID_LIST") or "")
            port, protocol = _int_or_none(_text(vuln, "PORT")), _text(vuln, "PROTOCOL")
            yield ScanRecord(
                hostname=hostname,
                ip_address=ip_address,
                operating_system=operating_system,
                title=_text(vuln, "TITLE") or "",
                cve_ids=cve_ids,
                plugin_id=vuln.get("number") or _text(vuln, "QID"),
                severity=QUALYS_SEVERITY.get(vuln.get("severity") or
                                             _text(vuln, "SEVERITY") or "", None),
                cvss_score=_float_or_none(_text(vuln, "CVSS_BASE")),
                description=_text(vuln, "DIAGNOSIS") or _text(vuln, "THREAT"),
                solution=_text(vuln, "SOLUTION"),
                port=port,
                protocol=protocol,
                evidence={"qid": _text(vuln, "QID"), "result": (_text(vuln, "RESULT") or "")[:4000]},
                raw={"qid": _text(vuln, "QID")},
            )


# ---------------------------------------------------------------------------
# Generic CSV
# ---------------------------------------------------------------------------
#: Header aliases, lower-cased. Extending this is how a new tool's CSV becomes
#: supported without new code.
CSV_ALIASES: dict[str, tuple[str, ...]] = {
    "hostname": ("hostname", "host", "asset", "asset name", "machine", "device"),
    "fqdn": ("fqdn", "dns name", "dns", "full hostname"),
    "ip_address": ("ip", "ip address", "ipv4", "address"),
    "title": ("title", "name", "vulnerability", "plugin name", "issue", "finding"),
    "cve": ("cve", "cves", "cve id", "cve ids", "cve_id"),
    "severity": ("severity", "risk", "criticality", "threat"),
    "cvss_score": ("cvss", "cvss score", "cvss base score", "cvss_base_score", "score"),
    "cvss_vector": ("cvss vector", "vector", "cvss_vector"),
    "description": ("description", "synopsis", "details", "diagnosis"),
    "solution": ("solution", "remediation", "fix", "recommendation"),
    "port": ("port",),
    "protocol": ("protocol", "proto"),
    "plugin_id": ("plugin id", "plugin", "qid", "oid", "check id", "plugin_id"),
    "product": ("product", "software", "application"),
    "vendor": ("vendor", "manufacturer"),
    "version": ("version", "installed version"),
}


def _build_header_map(fieldnames: list[str]) -> dict[str, str]:
    mapping: dict[str, str] = {}
    for raw in fieldnames or []:
        key = (raw or "").strip().lower()
        for canonical, aliases in CSV_ALIASES.items():
            if key in aliases:
                mapping[canonical] = raw
                break
    return mapping


def parse_csv(payload: bytes) -> Iterator[ScanRecord]:
    text = _decode(payload)
    try:
        dialect = csv.Sniffer().sniff(text[:4096], delimiters=",;\t|")
    except csv.Error:
        dialect = csv.excel
    reader = csv.DictReader(io.StringIO(text), dialect=dialect)
    header = _build_header_map(list(reader.fieldnames or []))
    if "title" not in header:
        raise ParserError(
            "CSV has no recognisable title column; expected one of "
            f"{list(CSV_ALIASES['title'])}"
        )
    if not ({"hostname", "fqdn", "ip_address"} & set(header)):
        raise ParserError(
            "CSV has no asset identity column (hostname, FQDN or IP)"
        )

    def value(row: dict, key: str) -> str | None:
        column = header.get(key)
        if column is None:
            return None
        return (row.get(column) or "").strip() or None

    for row in reader:
        yield ScanRecord(
            hostname=value(row, "hostname"),
            fqdn=value(row, "fqdn"),
            ip_address=value(row, "ip_address"),
            title=value(row, "title") or "",
            cve_ids=CVE_RE.findall(value(row, "cve") or ""),
            plugin_id=value(row, "plugin_id"),
            severity=value(row, "severity"),
            cvss_score=_float_or_none(value(row, "cvss_score")),
            cvss_vector=value(row, "cvss_vector"),
            description=value(row, "description"),
            solution=value(row, "solution"),
            port=_int_or_none(value(row, "port")),
            protocol=value(row, "protocol"),
            product=value(row, "product"),
            vendor=value(row, "vendor"),
            version=value(row, "version"),
            raw=dict(row),
        )


# ---------------------------------------------------------------------------
# Generic JSON (VEYRS canonical shape, or a list of loose objects)
# ---------------------------------------------------------------------------
JSON_KEYS = {
    "hostname": ("hostname", "host", "asset"),
    "fqdn": ("fqdn", "dns"),
    "ip_address": ("ip", "ip_address", "address"),
    "title": ("title", "name", "vulnerability"),
    "severity": ("severity", "risk"),
    "cvss_score": ("cvss_score", "cvss", "score"),
    "cvss_vector": ("cvss_vector", "vector"),
    "description": ("description", "synopsis"),
    "solution": ("solution", "remediation"),
    "port": ("port",),
    "protocol": ("protocol", "proto"),
    "plugin_id": ("plugin_id", "plugin", "qid", "oid"),
    "product": ("product",),
    "vendor": ("vendor",),
    "version": ("version",),
}


def parse_json(payload: bytes) -> Iterator[ScanRecord]:
    try:
        document = json.loads(_decode(payload))
    except json.JSONDecodeError as exc:
        raise ParserError(f"invalid JSON: {exc}") from exc

    if isinstance(document, dict):
        for key in ("findings", "results", "vulnerabilities", "items", "data"):
            if isinstance(document.get(key), list):
                document = document[key]
                break
    if not isinstance(document, list):
        raise ParserError(
            "JSON must be a list of findings, or an object with a "
            "findings/results/vulnerabilities/items/data list"
        )

    for item in document:
        if not isinstance(item, dict):
            continue
        lowered = {str(k).lower(): v for k, v in item.items()}

        def pick(field: str) -> Any:
            for key in JSON_KEYS[field]:
                if lowered.get(key) not in (None, ""):
                    return lowered[key]
            return None

        cve_raw = lowered.get("cve") or lowered.get("cves") or lowered.get("cve_ids") or ""
        if isinstance(cve_raw, list):
            cve_raw = " ".join(str(c) for c in cve_raw)

        yield ScanRecord(
            hostname=_as_str(pick("hostname")),
            fqdn=_as_str(pick("fqdn")),
            ip_address=_as_str(pick("ip_address")),
            title=_as_str(pick("title")) or "",
            cve_ids=CVE_RE.findall(str(cve_raw)),
            plugin_id=_as_str(pick("plugin_id")),
            severity=_as_str(pick("severity")),
            cvss_score=_float_or_none(pick("cvss_score")),
            cvss_vector=_as_str(pick("cvss_vector")),
            description=_as_str(pick("description")),
            solution=_as_str(pick("solution")),
            port=_int_or_none(pick("port")),
            protocol=_as_str(pick("protocol")),
            product=_as_str(pick("product")),
            vendor=_as_str(pick("vendor")),
            version=_as_str(pick("version")),
            raw=item,
        )


def _as_str(value: Any) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


# ---------------------------------------------------------------------------
# Registry and sniffing
# ---------------------------------------------------------------------------
PARSERS = {
    "nessus": parse_nessus,
    "greenbone": parse_greenbone,
    "openvas": parse_greenbone,
    "qualys": parse_qualys,
    "csv": parse_csv,
    "json": parse_json,
}

# SAST / SCA / DAST / IaC / cloud formats live in their own module - they share
# nothing with the XML network-scanner parsers above beyond the ScanRecord
# contract, and keeping them apart stops this file becoming a 2,000-line grab
# bag. Registered here so `get_parser` and the API see one namespace.
PARSERS.update(MODERN_PARSERS)


def detect_format(payload: bytes, filename: str = "") -> str:
    """Best-effort format detection. Explicit beats implicit: the API lets the
    caller name the parser, and this is only the fallback."""
    head = payload[:2048].lstrip()
    lower_name = (filename or "").lower()

    if lower_name.endswith(".nessus") or b"NessusClientData_v2" in head:
        return "nessus"
    if head.startswith(b"{") or head.startswith(b"["):
        # Nearly every modern tool emits JSON, so "it parses as JSON" says
        # almost nothing. Sniff for a specific tool first and only fall back to
        # the generic reader when no marker matches.
        specific = detect_modern_format(payload, filename)
        return specific or "json"
    if head.startswith(b"<"):
        window = payload[:20000]
        if b"NessusClientData_v2" in window:
            return "nessus"
        if b"<VULN" in window.upper() or b"SCAN_RESULT" in window.upper():
            return "qualys"
        if b"<result" in window or b"get_reports_response" in window:
            return "greenbone"
        raise ParserError("unrecognised XML report format")
    if lower_name.endswith(".csv") or b"," in head or b";" in head:
        return "csv"
    raise ParserError("could not determine the report format; specify it explicitly")


def get_parser(name: str):
    parser = PARSERS.get((name or "").lower())
    if parser is None:
        raise ParserError(f"unknown importer {name!r}; known: {sorted(PARSERS)}")
    return parser


# ---------------------------------------------------------------------------
# Nessus / Tenable host inventory
# ---------------------------------------------------------------------------
#: Nessus plugins whose output is a software ENUMERATION rather than a finding.
#: They are already ingested as (informational) findings by `parse_nessus`; here
#: the same bytes are read for what is installed, not for what is wrong.
NESSUS_INVENTORY_PLUGINS = {
    "20811": "windows",  # Microsoft Windows Installed Software Enumeration
    "22869": "unix",     # Software Enumeration (SSH)
}

#: `Microsoft Edge [version 120.0.2210.91]` -- an EXPLICIT version delimiter,
#: which is why the Windows enumeration is safe to parse and the Unix one is not
#: without further shape checks.
_WIN_SOFTWARE = re.compile(r"^(?P<name>.+?)\s*\[version\s+(?P<version>[^\]]+)\]\s*$")

#: `bash-5.2.15-1.fc37` -- rpm's name-version-release. The version group must
#: start with a digit and carry its own release field, so `openssh-server`
#: (a name containing a hyphen and no version) does not parse as name `openssh`
#: at version `server`.
_RPM_PACKAGE = re.compile(
    r"^(?P<name>[A-Za-z0-9._+][A-Za-z0-9._+-]*?)-(?P<version>\d[A-Za-z0-9._+~]*-[A-Za-z0-9._+~]+)$"
)

#: `bash_5.2.15-2ubuntu1_amd64` -- dpkg's underscore-delimited triple.
_DPKG_PACKAGE = re.compile(
    r"^(?P<name>[a-z0-9][a-z0-9.+-]*)_(?P<version>[^_\s]+)_[a-z0-9]+$"
)


def _nessus_cpe_specs(properties: dict[str, str]) -> Iterator["SoftwareSpec"]:
    """The authoritative path: the scanner names the dictionary entry itself.

    Nessus writes `cpe`, `cpe-0`, `cpe-1`, ... into HostProperties as **CPE 2.2
    URIs**, often with a ` -> human gloss` appended. Converted to 2.3 they hit
    `inventory.resolve_identity`'s first path -- no inference, no alias table,
    no chance of minting a parallel Product row NVD never joins to.
    """
    for name, value in sorted(properties.items()):
        if name != "cpe" and not name.startswith("cpe-"):
            continue
        for token in (value or "").splitlines():
            token = token.strip()
            if not token:
                continue
            cpe = cpe22_to_cpe23(token)
            if cpe is None and token.lower().startswith("cpe:2.3:"):
                # Already 2.3 (Tenable.io emits this in places). Take it as-is
                # rather than round-tripping it through a 2.2 converter that
                # correctly refuses it.
                cpe = token
            if cpe is None:
                continue
            yield SoftwareSpec(cpe=cpe, source=f"nessus:{name}")


def _nessus_plugin_specs(host, properties: dict[str, str]) -> Iterator["SoftwareSpec"]:
    """The inferred path: read the software-enumeration plugins' text output.

    Off by default (`ImportOptions.inventory_from_plugin_output`) and that is a
    refusal, not an oversight. A CPE tag is the scanner telling us which
    dictionary entry a thing is; a line of plugin output is prose we are
    guessing at, and a wrong guess does not fail loudly -- it creates a Product
    row that looks populated and matches no CVE. Every line that does not fit a
    known packaging shape is skipped rather than approximated.
    """
    for item in host.findall("ReportItem"):
        family = NESSUS_INVENTORY_PLUGINS.get(item.get("pluginID") or "")
        if family is None:
            continue
        output = _text(item, "plugin_output") or ""
        for line in output.splitlines():
            line = line.strip()
            if not line or line.endswith(":") or line.startswith("["):
                continue
            if family == "windows":
                match = _WIN_SOFTWARE.match(line)
                if match:
                    yield SoftwareSpec(
                        product=match.group("name").strip(),
                        raw_version=match.group("version").strip(),
                        source="nessus:plugin:20811",
                    )
                continue
            match = _RPM_PACKAGE.match(line) or _DPKG_PACKAGE.match(line)
            if match:
                yield SoftwareSpec(
                    product=match.group("name"),
                    raw_version=match.group("version"),
                    source="nessus:plugin:22869",
                )


def nessus_inventory(
    payload: bytes, *, plugin_output: bool = False
) -> Iterator["HostInventory"]:
    """What Nessus knows a host HAS, as opposed to what is wrong with it.

    A scan report answers two questions and VEYRS only ever read one of them.
    The second -- the estate's software identity -- is what the correlation
    engine joins CVEs against, and it is sitting in the same file.
    """
    root = _parse_xml(payload)
    if root.tag != "NessusClientData_v2":
        raise ParserError(f"not a Nessus v2 report (root element is {root.tag!r})")

    for host in root.iter("ReportHost"):
        properties = {
            tag.get("name"): (tag.text or "").strip()
            for tag in host.findall("./HostProperties/tag")
        }
        hostname = properties.get("host-fqdn") or host.get("name")
        fqdn = properties.get("host-fqdn")
        ip_address = properties.get("host-ip") or (
            host.get("name") if _looks_like_ip(host.get("name")) else None
        )

        software = list(_nessus_cpe_specs(properties))
        if plugin_output:
            software.extend(_nessus_plugin_specs(host, properties))
        if not software:
            # Still yielded: a host Nessus scanned and found no software
            # identity on is a coverage fact, and `ingest_inventory` counts it.
            pass

        yield HostInventory(
            hostname=None if _looks_like_ip(hostname) else hostname,
            fqdn=fqdn,
            ip_address=ip_address,
            mac_address=properties.get("mac-address"),
            operating_system=properties.get("operating-system"),
            software=software,
        )


#: source key -> host-inventory parser. Deliberately sparse: most formats carry
#: no inventory at all, and `run_import` simply produces none for those rather
#: than treating the absence as an error.
INVENTORY_PARSERS = {
    "nessus": nessus_inventory,
    "tenable_io": nessus_inventory,
    "tenable_sc": nessus_inventory,
}


def get_inventory_parser(source: str):
    return INVENTORY_PARSERS.get((source or "").strip().lower())
