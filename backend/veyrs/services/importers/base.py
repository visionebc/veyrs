"""Canonical scanner record and the normalizer every importer feeds (spec 31).

A parser's only job is to turn a vendor export into `ScanRecord` objects. All
the judgement -- which asset is this, does that CVE exist, is this a new finding
or the same one seen again -- happens once, here, so Nessus and Qualys cannot
drift into behaving differently.

Two rules the normalizer will not bend:

* **Never invent an asset identity.** If a record has no hostname, FQDN or IP
  that resolves inside the tenant, it is REJECTED with a reason, not attached to
  a plausible-looking neighbour. A finding on the wrong asset is worse than a
  finding you know you dropped.
* **Never auto-close on unbounded absence.** A finding missing from today's
  export becomes a *stale candidate*. It may be closed only within the scope of
  the test that actually ran, and only after the engagement type's threshold of
  *consecutive* absences - scanners routinely skip hosts that were merely
  offline. See `services/engagements.reconcile_test()`.

Every import is scoped to an `Engagement` -> `ScanTest` (the DefectDojo model).
That scope is not decoration: it is the boundary that makes reconciliation
sound. Callers that name neither land in the tenant's "Continuous scanning"
engagement, which reconciles per scanner exactly as before - but per *sighting*,
so a partial export can no longer reach hosts the run never touched.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import ipaddress
import logging
import re
import uuid
from typing import Any, Iterable, Iterator
from urllib.parse import urlsplit

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models import Asset, AssetProduct, Cve, Engagement, Finding, ScanTest, Vulnerability
from ...models.integration import ImportRun, ImportStatus
from .. import correlation, intelligence

log = logging.getLogger("veyrs.importers")

#: `host:port` and nothing else - a single label, a dotted name or a bracketed
#: IPv6 literal, then a decimal port. Anything carrying a path separator, an
#: `@`, or a non-numeric tail is not a network location and must survive
#: normalisation unchanged.
HOST_PORT_RE = re.compile(r"^(?:[A-Za-z0-9_.-]+|\[[0-9A-Fa-f:.]+\]):[0-9]{1,5}$")

CVE_RE = re.compile(r"CVE-\d{4}-\d{4,7}", re.I)
MAX_REJECT_SAMPLES = 25

#: Vendor severity words -> the VEYRS ladder. Numeric scales are handled
#: separately per parser because 0-4 means different things to different tools.
SEVERITY_WORDS = {
    "critical": "critical", "high": "high", "medium": "medium", "moderate": "medium",
    "low": "low", "info": "informational", "informational": "informational",
    "none": "informational", "log": "informational", "debug": "informational",
}


@dataclasses.dataclass
class ScanRecord:
    """One vulnerability observation from a scanner, before VEYRS interprets it."""

    # --- asset identity (at least one must be usable)
    hostname: str | None = None
    fqdn: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    operating_system: str | None = None
    #: True when `hostname` carries an ARTIFACT identifier - a container image
    #: reference, a cloud resource, a repository - rather than a network host.
    #: Shape alone cannot decide this: `redis:7` is both a valid image tag and a
    #: valid host:port, so the parser that knows declares it and
    #: `_split_host_port` keeps its hands off. Without it that method truncated
    #: `registry.internal/api:2.4.1` to `registry.internal`, which is the same
    #: class of bug it was written to fix, in the opposite direction.
    host_is_artifact: bool = False

    # --- the finding
    title: str = ""
    cve_ids: list[str] = dataclasses.field(default_factory=list)
    plugin_id: str | None = None
    severity: str | None = None
    cvss_vector: str | None = None
    cvss_score: float | None = None
    description: str | None = None
    solution: str | None = None
    port: int | None = None
    protocol: str | None = None
    path: str | None = None
    evidence: dict[str, Any] = dataclasses.field(default_factory=dict)

    # --- product hints, used to link the finding to installed software
    vendor: str | None = None
    product: str | None = None
    version: str | None = None

    # --- identity the tool supplies itself. When a scanner already emits a
    # stable per-instance id (Checkmarx result ids, Nuclei template+matcher,
    # Snyk issue ids) rehashing our own fields on top of it is strictly worse:
    # see services/dedupe.
    unique_id: str | None = None

    # --- SAST / SCA dimensions. A code or dependency finding has no port, and
    # hashing it as though it did collapsed every issue in a repo into one.
    cwe: str | None = None
    file_path: str | None = None
    line: int | None = None
    component_name: str | None = None
    component_version: str | None = None

    # --- web dimension (Faraday's `vuln_web`). A full URL is richer than
    # host+port+path: it carries scheme, query and fragment, which is what makes
    # `?id=1` and `?id=2` on one path the same endpoint and `#/admin` a
    # different one.
    url: str | None = None
    #: Additional locations of the SAME finding. Tools differ in granularity and
    #: the parser must respect each one's: Nuclei reports one match per URL (so
    #: one record each), while ZAP reports one *alert* with N instances - which
    #: is one finding to triage and N places to fix. Flattening the second shape
    #: into N findings is how "SQL injection" gets triaged eleven times.
    #: Each entry: {"url": ...} or {"host","port","path"}, optionally with
    #: method/request/response/params/param_location.
    endpoints: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    method: str | None = None
    request: str | None = None
    response: str | None = None
    params: str | None = None
    #: query | body | header | cookie | path | json
    param_location: str | None = None

    #: The raw row, kept for reject samples so an operator can see what failed.
    raw: dict[str, Any] = dataclasses.field(default_factory=dict)

    @property
    def asset_key(self) -> str | None:
        return self.fqdn or self.hostname or self.ip_address

    def normalise(self) -> "ScanRecord":
        """Tidy the fields parsers commonly hand over dirty."""
        self.cve_ids = sorted({m.upper() for m in
                               (CVE_RE.findall(" ".join(self.cve_ids)) if self.cve_ids else [])})
        if self.severity:
            self.severity = SEVERITY_WORDS.get(self.severity.strip().lower(), self.severity)
        if self.ip_address:
            try:
                ipaddress.ip_address(self.ip_address.strip())
            except ValueError:
                # A bad IP is not fatal: hostname may still identify the asset.
                self.ip_address = None
        for field in ("hostname", "fqdn", "product", "vendor", "version"):
            value = getattr(self, field)
            if isinstance(value, str):
                setattr(self, field, value.strip() or None)
        if self.protocol:
            self.protocol = self.protocol.strip().lower()[:10]
        self.title = (self.title or "").strip()[:500]
        self._split_host_port()
        self._identify_from_url()
        return self

    def _split_host_port(self) -> None:
        """Move a port out of a host field and into `port`.

        Scanners routinely report a network service as "host:22" in the field
        VEYRS reads as the hostname - nuclei does it for every non-HTTP
        template. Stored verbatim that string matches no asset column, so
        findings on a KNOWN asset were rejected as "unknown asset": a real scan
        of veyrs-docs.example.com landed its 12 HTTP results and silently
        dropped all 10 SSH (:22) and TLS (:443) ones.

        It also has to run BEFORE `_identify_from_url`, which bails as soon as
        any host field is set - a dirty hostname was enough to suppress the URL
        fallback that would otherwise have recovered the record.

        It must NOT run on an artifact identifier. Container and cloud scanners
        put an image reference or a resource id in `hostname`, and a colon there
        separates a tag, not a port. Two independent guards: the parser's
        explicit `host_is_artifact`, and a shape test for anything a parser
        forgot to flag.
        """
        if self.host_is_artifact:
            return
        for field in ("hostname", "fqdn"):
            value = getattr(self, field)
            if not value or ":" not in value:
                continue
            if not HOST_PORT_RE.match(value.strip()):
                continue
            try:
                parts = urlsplit("//" + value)
                host = (parts.hostname or "").strip().strip(".")
                port = parts.port
            except ValueError:
                # A bare IPv6 literal ("::1") or a genuinely malformed value.
                # Leaving it untouched is right: guessing where the address
                # ends and the port begins is how findings move hosts.
                continue
            if not host:
                continue
            setattr(self, field, None)
            try:
                ipaddress.ip_address(host)
                self.ip_address = self.ip_address or host
            except ValueError:
                # Same split as _identify_from_url: a dotted name is an FQDN,
                # a single label is a short hostname, and resolve_asset matches
                # them against different columns.
                if "." in host:
                    self.fqdn = self.fqdn or host
                else:
                    self.hostname = self.hostname or host
            if self.port is None and port:
                self.port = port

    def _identify_from_url(self) -> None:
        """A DAST record identifies its asset by URL. Unpack it into the fields
        `resolve_asset` actually matches on.

        Done here rather than in each parser so every URL-shaped tool (Nuclei,
        ZAP, Burp) resolves its asset identically. Without it a record carrying
        only `url` has no `asset_key` at all and is rejected as "no hostname,
        FQDN or IP" - which is how the first Nuclei import dropped every record.
        """
        source = self.url or next(
            (e.get("url") for e in self.endpoints if e.get("url")), None
        )
        if not source or (self.hostname or self.fqdn or self.ip_address):
            return
        try:
            parts = urlsplit(source if "://" in source else "//" + source)
            host = (parts.hostname or "").strip().strip(".")
            port = parts.port
        except ValueError:
            return
        if not host:
            return
        try:
            ipaddress.ip_address(host)
            self.ip_address = host
        except ValueError:
            # A dotted name is an FQDN; a single label is a short hostname. The
            # distinction matters: resolve_asset matches them against different
            # asset columns.
            if "." in host:
                self.fqdn = host
            else:
                self.hostname = host
        if self.port is None and port:
            self.port = port
        if self.protocol is None and parts.scheme:
            self.protocol = parts.scheme.lower()[:10]


class ParserError(ValueError):
    """The file is not what it claims to be. Reported, never guessed around."""


@dataclasses.dataclass
class ImportOptions:
    #: Create assets the scanner reports but VEYRS does not know about. Off by
    #: default: an import that invents inventory quietly destroys the asset
    #: register's meaning.
    create_assets: bool = False
    #: Default criticality for assets this import creates.
    new_asset_criticality: str = "medium"
    new_asset_exposure: str = "internal"
    #: Report but do not persist.
    dry_run: bool = False
    #: Close findings absent from this export. Off by default; see module docs.
    #: DEPRECATED in favour of `close_absent`, which is scoped to the test that
    #: actually ran. Honoured only when no engagement/test scope is in play, so
    #: existing callers keep working while nothing new can opt into the
    #: organisation-wide behaviour that caused the over-closing defect.
    close_missing: bool = False
    #: Skip records at or below this severity.
    min_severity: str | None = None

    # --- inventory carried by the same report
    #: Also read what each host HAS, not only what is wrong with it, and record
    #: it against the asset. Off by default like every other write this module
    #: can perform: an operator uploading one export to triage a finding has not
    #: asked to have their asset register rewritten.
    import_inventory: bool = False
    #: Additionally mine the software-enumeration plugins' TEXT output
    #: (Nessus 20811/22869). Off by default, and it is a refusal rather than an
    #: oversight -- a CPE tag is the scanner naming a dictionary entry, a line
    #: of plugin output is prose we are guessing at, and a wrong guess here does
    #: not fail loudly: it mints a Product row that looks populated and joins to
    #: no CVE. See services/inventory's opening docstring.
    inventory_from_plugin_output: bool = False

    # --- scoping (DefectDojo's Engagement -> Test, see services/engagements)
    #: Land this import in a named engagement. None = the default
    #: "Continuous scanning" engagement.
    engagement_id: uuid.UUID | None = None
    #: Reimport into an existing test. None = reuse the engagement's test for
    #: this scanner, which is what makes a nightly import reconcile against
    #: yesterday instead of starting from an empty scope every night.
    test_id: uuid.UUID | None = None
    #: False opens a fresh test per import - correct for a pentest, where each
    #: pass is its own report, and wrong for a scheduled sweep.
    reuse_test: bool = True

    # --- reconciliation
    #: Close findings this test previously reported and no longer does. None
    #: defers to the engagement type's default (see DEFAULT_ABSENCE_THRESHOLD).
    close_absent: bool | None = None
    #: Consecutive runs a finding may be missing before it counts as fixed.
    #: 0 disables auto-closure entirely.
    absence_threshold: int | None = None

    #: Accept a payload with no bytes at all as a COMPLETED scan that found
    #: nothing, rather than rejecting it as an empty file. Off by default: a
    #: human uploading a 0-byte export has made a mistake, and silently
    #: reconciling their scope against "nothing was reported" would close every
    #: finding in it. Execution agents set it, because an agent that ran a
    #: scanner to completion with no output is stating a fact about the estate.
    allow_empty: bool = False

    #: Override the scanner's registered deduplication config for this import.
    dedupe_config: dict | None = None

    #: Asset name for records that carry no host at all - a SAST run over a
    #: repository, an SCA run over a lockfile, a cloud posture sweep. The
    #: operator names the artefact ("api-gateway", "acme/web@sha256:..."); VEYRS
    #: still never infers one, so a report with no host and no `target_asset`
    #: is rejected exactly as before rather than being attached to a guess.
    target_asset: str | None = None

    # --- CI provenance, stamped onto the test so a finding can answer "which
    # build introduced me?".
    version: str | None = None
    branch_tag: str | None = None
    commit_hash: str | None = None
    build_id: str | None = None

    SEVERITY_ORDER = ("informational", "low", "medium", "high", "critical")

    def passes_severity(self, severity: str | None) -> bool:
        if not self.min_severity:
            return True
        try:
            floor = self.SEVERITY_ORDER.index(self.min_severity)
            actual = self.SEVERITY_ORDER.index(severity or "informational")
        except ValueError:
            return True
        return actual >= floor


class ImportResult:
    """Mutable tally handed back to the caller and persisted on ImportRun."""

    def __init__(self) -> None:
        self.seen = 0
        self.created = 0
        self.updated = 0
        self.assets_created = 0
        self.rejected = 0
        self.reject_reasons: dict[str, int] = {}
        self.reject_samples: list[dict] = []
        self.stale_candidates = 0
        self.finding_ids: list[str] = []
        self.endpoints_created = 0
        self.findings_marked_absent = 0
        self.findings_closed_absent = 0
        #: Populated once the import is scoped. Carried on the run so an
        #: operator can answer "which engagement did last night's scan land in?"
        self.engagement_id: uuid.UUID | None = None
        self.test_id: uuid.UUID | None = None
        self.dedupe_algorithm: str | None = None
        # --- inventory (see ingest_inventory)
        self.inventory_hosts = 0
        self.inventory_hosts_unmatched = 0
        self.inventory_hosts_empty = 0
        self.inventory_seen = 0
        self.inventory_added = 0
        self.inventory_updated = 0
        #: Rows recorded but not resolvable to a CPE-anchored product. Recorded
        #: anyway -- losing inventory is worse than holding it unmatched -- but
        #: counted, because an unmatched install is a name to fix, not a host
        #: that is safe.
        self.inventory_unmatched = 0
        #: Rows resolved from a CPE the scanner supplied itself, i.e. with no
        #: inference at all. The ratio to `inventory_added` is the honest
        #: quality measure for an inventory import.
        self.inventory_anchored = 0

    def reject(self, reason: str, record: ScanRecord | None = None) -> None:
        self.rejected += 1
        self.reject_reasons[reason] = self.reject_reasons.get(reason, 0) + 1
        if len(self.reject_samples) < MAX_REJECT_SAMPLES:
            self.reject_samples.append({
                "reason": reason,
                "title": (record.title if record else None),
                "asset_key": (record.asset_key if record else None),
                "plugin_id": (record.plugin_id if record else None),
            })

    def as_dict(self) -> dict[str, Any]:
        return {
            "records_seen": self.seen,
            "findings_created": self.created,
            "findings_updated": self.updated,
            "assets_created": self.assets_created,
            "records_rejected": self.rejected,
            "reject_reasons": self.reject_reasons,
            "reject_samples": self.reject_samples,
            "stale_candidates": self.stale_candidates,
            "endpoints_created": self.endpoints_created,
            "findings_marked_absent": self.findings_marked_absent,
            "findings_closed_absent": self.findings_closed_absent,
            "inventory_hosts": self.inventory_hosts,
            "inventory_added": self.inventory_added,
            "inventory_updated": self.inventory_updated,
            "inventory_unmatched": self.inventory_unmatched,
        }


# ---------------------------------------------------------------------------
# Asset resolution
# ---------------------------------------------------------------------------
def resolve_asset(
    session: Session, organization_id: uuid.UUID, record: ScanRecord,
    options: ImportOptions, result: ImportResult,
) -> Asset | None:
    """Find the asset this record belongs to, or create it if allowed.

    Match order is most-specific first: FQDN, then hostname, then IP. IP is last
    because it is the least stable identity in a DHCP estate -- matching on it
    first is how findings end up on the wrong machine.
    """
    candidates = session.execute(
        select(Asset).where(Asset.organization_id == organization_id,
                            Asset.deleted_at.is_(None))
    ).scalars().all()

    if record.fqdn:
        wanted = record.fqdn.lower()
        for asset in candidates:
            if (asset.fqdn or "").lower() == wanted:
                return asset
    if record.hostname:
        wanted = record.hostname.lower()
        for asset in candidates:
            if (asset.hostname or "").lower() == wanted or asset.name.lower() == wanted:
                return asset
            # Several tools put a FULLY QUALIFIED name in the field VEYRS reads
            # as `hostname` - ZAP's `@host`, Greenbone's host element. Matching
            # it against the asset's fqdn is not a guess, it is the same string.
            # Without this the match was asymmetric (short record name vs asset
            # fqdn worked, dotted record name vs asset fqdn did not) and every
            # ZAP import was rejected as "unknown asset".
            if (asset.fqdn or "").lower() == wanted:
                return asset
            # A short hostname legitimately matches the left label of an FQDN.
            if (asset.fqdn or "").lower().split(".")[0] == wanted:
                return asset
    if record.ip_address:
        for asset in candidates:
            if record.ip_address in (asset.ip_addresses or []):
                return asset

    if not options.create_assets:
        result.reject("unknown asset (create_assets is off)", record)
        return None
    if not record.asset_key:
        result.reject("record carries no hostname, FQDN or IP", record)
        return None

    asset = Asset(
        organization_id=organization_id,
        name=record.hostname or record.fqdn or record.ip_address,
        hostname=record.hostname or (record.fqdn.split(".")[0] if record.fqdn else None),
        fqdn=record.fqdn,
        ip_addresses=[record.ip_address] if record.ip_address else [],
        mac_addresses=[record.mac_address] if record.mac_address else [],
        operating_system=record.operating_system,
        asset_type="server",
        criticality=options.new_asset_criticality,
        exposure=options.new_asset_exposure,
        external_id=f"import:{record.asset_key}",
    )
    session.add(asset)
    session.flush()
    result.assets_created += 1
    return asset


def resolve_installation(
    session: Session, organization_id: uuid.UUID, asset: Asset, record: ScanRecord
) -> AssetProduct | None:
    """Link the finding to installed software when the scanner names it."""
    if not record.product:
        return None
    product = intelligence.upsert_product(
        session, (record.vendor or "unknown"), record.product, cpe_part="a"
    )
    existing = session.execute(
        select(AssetProduct).where(AssetProduct.organization_id == organization_id,
                                   AssetProduct.asset_id == asset.id,
                                   AssetProduct.product_id == product.id)
    ).scalars().first()
    if existing is not None:
        if record.version and not existing.version:
            existing.version = record.version
        return existing
    installation = AssetProduct(
        organization_id=organization_id, asset_id=asset.id, product_id=product.id,
        version=record.version, source="scanner",
    )
    session.add(installation)
    session.flush()
    return installation


# ---------------------------------------------------------------------------
# Vulnerability resolution
# ---------------------------------------------------------------------------
def resolve_vulnerability(
    session: Session, organization_id: uuid.UUID, record: ScanRecord
) -> Vulnerability:
    """Prefer the CVE the scanner names; fall back to a scanner-native entry.

    A plugin with no CVE (a weak-cipher check, a missing header) is still a real
    finding, so it becomes a Vulnerability keyed on the plugin id rather than
    being discarded for lacking an identifier.
    """
    for cve_id in record.cve_ids:
        cve = session.get(Cve, cve_id)
        if cve is not None:
            return correlation.ensure_vulnerability(session, organization_id, cve)

    # CVE named but not yet ingested: keep the reference so a later NVD sync can
    # enrich it, without pretending we know the score.
    unknown_cve = record.cve_ids[0] if record.cve_ids else None
    internal_ref = record.plugin_id or hashlib.sha256(
        record.title.encode()).hexdigest()[:16]

    row = session.execute(
        select(Vulnerability).where(
            Vulnerability.organization_id == organization_id,
            Vulnerability.internal_ref == internal_ref,
        )
    ).scalars().first()
    if row is None:
        row = Vulnerability(
            organization_id=organization_id,
            cve_id=None,  # deliberately NULL: the CVE row does not exist yet
            internal_ref=internal_ref,
            title=record.title or internal_ref,
            description=record.description,
            source="scanner",
            state="new",
        )
        session.add(row)
        session.flush()
    row.severity = record.severity or row.severity
    if record.cvss_score is not None:
        row.cvss_score = record.cvss_score
    if record.cvss_vector:
        row.cvss_vector = record.cvss_vector
    if unknown_cve and not row.internal_ref.startswith("cve-pending:"):
        row.triage_notes = (
            f"Scanner reported {unknown_cve}, which is not yet in the VEYRS CVE "
            "database. Run an NVD sync to enrich this vulnerability."
        )
    session.flush()
    return row


# ---------------------------------------------------------------------------
# The normalizer
# ---------------------------------------------------------------------------
def resolve_scope(
    session: Session, organization_id: uuid.UUID, scanner: str, options: ImportOptions
):
    """Find or open the ScanTest this import belongs to.

    Every import lands in a test, even one that names no engagement: without a
    recorded scope, "close what the scanner no longer reports" has to infer its
    own boundary from `Finding.scanner`, which is how a three-host export used
    to close an entire estate.
    """
    from .. import engagements as engagement_service

    if options.test_id is not None:
        test = session.get(ScanTest, options.test_id)
        if test is None or test.organization_id != organization_id:
            raise ValueError(f"scan test {options.test_id} not found")
        return test

    return engagement_service.get_or_create_test(
        session, organization_id, scanner=scanner,
        engagement_id=options.engagement_id, reuse=options.reuse_test,
        version=options.version, branch_tag=options.branch_tag,
        commit_hash=options.commit_hash, build_id=options.build_id,
    )


def ingest(
    session: Session,
    organization_id: uuid.UUID,
    records: Iterable[ScanRecord],
    *,
    scanner: str,
    options: ImportOptions | None = None,
    run: ImportRun | None = None,
) -> ImportResult:
    """Turn parsed records into scored, assigned, SLA'd findings."""
    from .. import dedupe as dedupe_service
    from .. import endpoints as endpoint_service
    from .. import engagements as engagement_service

    options = options or ImportOptions()
    result = ImportResult()
    touched: set[uuid.UUID] = set()

    test = resolve_scope(session, organization_id, scanner, options)
    result.test_id = test.id
    result.engagement_id = test.engagement_id
    engagement = session.get(Engagement, test.engagement_id)

    config = dedupe_service.config_for(
        scanner, options.dedupe_config or (test.dedupe_config or None)
    )
    result.dedupe_algorithm = config.algorithm

    for record in records:
        record.normalise()
        result.seen += 1

        if options.target_asset and not record.asset_key:
            # Code/image/cloud reports have no host. The operator supplied the
            # artefact's name; this is attribution, not invention.
            record.hostname = options.target_asset
        if not record.title:
            result.reject("record has no title", record)
            continue
        if not options.passes_severity(record.severity):
            result.reject(f"below min_severity={options.min_severity}", record)
            continue

        asset = resolve_asset(session, organization_id, record, options, result)
        if asset is None:
            continue

        vulnerability = resolve_vulnerability(session, organization_id, record)
        installation = resolve_installation(session, organization_id, asset, record)

        endpoint, endpoint_created = endpoint_service.endpoint_from_record(
            session, organization_id, record, asset_id=asset.id
        )
        if endpoint_created:
            result.endpoints_created += 1

        identity = dedupe_service.resolve_identity(
            record,
            config=config,
            organization_id=organization_id,
            asset_id=asset.id,
            # Must match the legacy formula exactly, or every pre-existing
            # finding re-keys on the next import and appears to double.
            vuln_ref=vulnerability.cve_id or str(vulnerability.id),
            scanner=scanner,
            engagement_id=(
                test.engagement_id
                if engagement is not None and engagement.dedupe_within_engagement else None
            ),
            endpoint_canonical=endpoint.canonical if endpoint is not None else None,
        )

        finding, created = correlation.ensure_finding(
            session,
            organization_id=organization_id,
            vulnerability=vulnerability,
            asset=asset,
            installation=installation,
            title=record.title,
            detail=record.description,
            recommendation=record.solution,
            port=record.port,
            protocol=record.protocol,
            path=record.path,
            scanner=scanner,
            scanner_plugin_id=record.plugin_id,
            evidence=record.evidence,
            import_run_id=run.id if run is not None else None,
            identity=identity,
        )

        if endpoint is not None:
            endpoint_service.attach(
                session,
                organization_id=organization_id,
                finding_id=finding.id,
                endpoint_id=endpoint.id,
                method=record.method,
                request=record.request,
                response=record.response,
                params=record.params,
                param_location=record.param_location,
                website=record.url,
            )
        for extra in record.endpoints:
            created_extra = endpoint_service.attach_described(
                session, organization_id=organization_id, finding_id=finding.id,
                asset_id=asset.id, described=extra,
            )
            if created_extra:
                result.endpoints_created += 1
        engagement_service.record_sighting(
            session, organization_id=organization_id, test=test,
            finding_id=finding.id, import_run_id=run.id if run is not None else None,
        )
        # The scanner's own scoring wins only where VEYRS has nothing better:
        # a CVE-backed finding keeps the authoritative NVD values.
        if vulnerability.cve_id is None:
            if record.cvss_score is not None:
                finding.cvss_score = record.cvss_score
            if record.cvss_vector:
                finding.cvss_vector = record.cvss_vector
            if record.severity:
                finding.severity = record.severity

        correlation.process_finding(session, finding, is_new=created)
        touched.add(finding.id)
        result.finding_ids.append(str(finding.id))
        if created:
            result.created += 1
        else:
            result.updated += 1

    # Reconciliation is scoped to what THIS test previously reported, which is
    # the whole point of the sighting table. `close_missing` is only honoured
    # for callers that predate scoping and explicitly asked for it.
    reconciliation = engagement_service.reconcile_test(
        session,
        organization_id=organization_id,
        test=test,
        seen_finding_ids=touched,
        close_absent=(
            options.close_absent
            if options.close_absent is not None
            else (True if options.close_missing else None)
        ),
        absence_threshold=(
            options.absence_threshold
            if options.absence_threshold is not None
            else (1 if options.close_missing else None)
        ),
    )
    result.findings_marked_absent = reconciliation["marked_absent"]
    result.findings_closed_absent = reconciliation["closed"]
    #: Kept for the existing dashboard field: findings this test used to report
    #: and did not this time, whether or not they were closed.
    result.stale_candidates = reconciliation["marked_absent"]

    test.reimport_count += 1
    test.last_import_run_id = run.id if run is not None else None
    test.target_end = dt.datetime.now(dt.timezone.utc)

    session.flush()
    return result


# NOTE: `_count_stale()` and `_close_missing()` used to live here. Both scoped
# themselves to `Finding.scanner` across the whole organisation, so an export
# covering three hosts marked every Nessus finding in the estate remediated.
# They are deleted rather than deprecated: a function that cannot be called
# correctly should not remain callable. The scoped replacement is
# `services.engagements.reconcile_test()`, which reconciles against the sighting
# set of the test that actually ran.


def payload_hash(payload: bytes) -> str:
    return hashlib.sha256(payload).hexdigest()


# ---------------------------------------------------------------------------
# Host inventory carried by a scan report
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class SoftwareSpec:
    """One installed thing, in the shape `services.inventory.install` reads.

    Field names match what that module's `_attr` looks for, so a spec goes
    straight into the existing resolver rather than through a translation layer
    that would be one more place for `nginx -> f5` to be got wrong.
    """

    cpe: str | None = None
    vendor: str | None = None
    product: str | None = None
    version: str | None = None
    raw_version: str | None = None
    install_path: str | None = None
    #: Which channel of the report this was read from (`nessus:cpe-3`,
    #: `nessus:plugin:20811`). Kept for triage: "why does this host claim to run
    #: Java 6" is answerable only if the row remembers where it came from.
    source: str | None = None


@dataclasses.dataclass
class HostInventory:
    """What one host in a scan report HAS, as opposed to what is wrong with it."""

    hostname: str | None = None
    fqdn: str | None = None
    ip_address: str | None = None
    mac_address: str | None = None
    operating_system: str | None = None
    software: list[SoftwareSpec] = dataclasses.field(default_factory=list)

    def as_record(self) -> "ScanRecord":
        """A ScanRecord carrying only identity, so asset resolution is shared.

        Matching a host to an asset is subtle -- FQDN, then hostname, then IP,
        plus the short-label and dotted-name cases `resolve_asset` documents --
        and a second implementation here would drift from it within a release.
        """
        return ScanRecord(
            hostname=self.hostname, fqdn=self.fqdn, ip_address=self.ip_address,
            mac_address=self.mac_address, operating_system=self.operating_system,
            title="inventory",
        )


def ingest_inventory(
    session: Session,
    organization_id: uuid.UUID,
    hosts: Iterable[HostInventory],
    *,
    detected_by: str,
    options: "ImportOptions | None" = None,
    result: "ImportResult | None" = None,
) -> "ImportResult":
    """Record the software a scan report says each host is running.

    Four refusals are the whole design:

    **It never replaces.** `inventory.install(replace=True)` deletes rows this
    source reported before and does not now -- correct for an agent sweeping a
    host it owns, wrong here. A Nessus scan of three hosts is not a statement
    about the estate, and an unauthenticated scan is barely a statement about
    the three: it reports what it could fingerprint from the network. Letting
    it prune would delete real inventory every time a credentialled scan was
    followed by an unauthenticated one.

    **It never invents an asset on its own terms.** Inventory attaches to hosts
    VEYRS already knows unless `create_assets` is on -- the same switch, and the
    same reasoning, that governs findings.

    **A dry run writes nothing**, here as everywhere. An operator previewing an
    import is asking what it *would* do.

    **Its rejects are counted separately.** `resolve_asset` books a reject into
    the result it is handed, and `records_rejected` is a statement about
    findings. Folding "this host is not in the register" into that number would
    make an import look like it dropped vulnerability data when it dropped
    nothing of the sort, so asset resolution runs against a scratch result and
    only `assets_created` is merged back.
    """
    from .. import inventory as inventory_service

    options = options or ImportOptions()
    result = result if result is not None else ImportResult()
    scratch = ImportResult()

    for host in hosts:
        result.inventory_hosts += 1
        record = host.as_record()
        record.normalise()
        asset = resolve_asset(session, organization_id, record, options, scratch)
        if asset is None:
            result.inventory_hosts_unmatched += 1
            continue
        if not host.software:
            # A host the scanner reached and could not fingerprint. Counted,
            # because "we have inventory for 4 of 30 hosts" is the number that
            # tells an operator their scans are unauthenticated.
            result.inventory_hosts_empty += 1
            continue

        result.inventory_seen += len(host.software)
        if options.dry_run:
            continue

        outcome = inventory_service.install(
            session, asset, host.software, detected_by=detected_by, replace=False,
        )
        result.inventory_added += int(outcome.get("added", 0))
        result.inventory_updated += int(outcome.get("updated", 0))
        result.inventory_unmatched += int(outcome.get("unmatched", 0))
        result.inventory_anchored += int(outcome.get("anchored", 0))

    result.assets_created += scratch.assets_created
    return result
