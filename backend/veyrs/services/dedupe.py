"""Configurable finding deduplication (the DefectDojo model, reimplemented).

VEYRS shipped with exactly one deduplication rule, hardcoded in
`correlation.dedupe_key`: sha256 over (org, asset, vuln_ref, port, protocol,
path). That rule is correct for infrastructure scanners and wrong for almost
everything else:

* **SAST** (Semgrep, Bandit, CodeQL) reports file+line, never a port. Every
  finding on one repo asset collapses into a single key, so 400 issues become 1.
* **SCA** (Trivy, Grype, Dependabot) reports package+version. Two CVEs in two
  different packages on the same image share a key when neither carries a port.
* **Tools with their own stable ids** (Checkmarx, Semgrep fingerprints, Nuclei
  template+matcher) already solved identity upstream; rehashing their output on
  fields they populate inconsistently is strictly worse than using their id.

DefectDojo's answer - four algorithms plus a per-parser field list - is the
right one, so it is the one implemented here. Two deliberate differences:

1. **`legacy` reproduces the historical key byte-for-byte** and is the default
   for every scanner that was already in production. Changing the default would
   have re-keyed every existing finding, and a re-keyed finding is a duplicate:
   the estate would appear to double overnight. New behaviour is opt-in per
   scanner. There is no tool that moves a scanner from one algorithm to
   another; `veyrs dedupe rehash` exists for one specific migration, the key
   revision below, and does nothing else.
2. **`unique_id_or_hash_code` really matches on either.** DefectDojo stores both
   values and ORs them at query time; a single stored key cannot do that, so
   `Finding` carries `unique_id_from_tool` alongside `dedupe_key` and
   `find_existing()` performs the two-step lookup.

Field vocabulary (what may appear in a config's `fields`):

    title, description, severity, cwe, cve, plugin_id, unique_id,
    file_path, line, component_name, component_version, endpoint, asset,
    port, protocol, path, vuln_ref

`endpoint` and `asset` are pseudo-fields resolved from the resolution context,
not from the record, because the record only knows what the scanner said and we
want the identity we settled on. So is `cve`: `ScanRecord` carries `cve_ids`,
never `cve`, and the value used is the vulnerability the finding resolved to
(`cve_id`, else its `internal_ref`) -- see `cve_ref()`.

Key revision 2 (0.41.0)
-----------------------
Until 0.41.0 nothing put `cve` in the context, so it hashed as "" and every CVE
on one package and asset merged into the first finding (the SCA scanners all
list it). Fixing the field naively would re-key every SCA finding at once, and
a re-keyed finding is a duplicate. So the `cve` field is folded in as a SECOND
stage over the old key::

    base = sha256(org | scope | scanner | hash(fields, cve=""))   # revision 1
    key  = sha256(base | "cve=" + cve_ref)                         # revision 2

which means the revision-2 key of an existing finding is computable from its
STORED key and its vulnerability alone, without the component name and version
that were hashed but never stored. Two paths use that, both touching only rows
at `Finding.dedupe_revision == 1`:

* `veyrs dedupe rehash [--org SLUG] [--apply]` re-keys them in place (dry run
  by default, idempotent: a re-keyed row is at revision 2 and never selected
  again);
* the importer adopts one on the fly when a record's revision-2 key matches
  nothing but its revision-1 key matches a finding for the SAME vulnerability
  (`Identity.previous_keys`), so an import that runs before the CLI still
  matches instead of duplicating.

A finding that had merged several CVEs keeps the vulnerability it was created
for; the other CVEs get findings of their own on the next import. That is the
exposure the bug hid, not a duplicate.
"""
from __future__ import annotations

import dataclasses
import hashlib
import logging
import uuid
from typing import Any, Iterable, Sequence

from sqlalchemy import select
from sqlalchemy.orm import Session

log = logging.getLogger("veyrs.dedupe")

LEGACY = "legacy"
UNIQUE_ID = "unique_id_from_tool"
HASH_CODE = "hash_code"
UNIQUE_ID_OR_HASH = "unique_id_or_hash_code"

ALGORITHMS = (LEGACY, UNIQUE_ID, HASH_CODE, UNIQUE_ID_OR_HASH)
HASH_ALGORITHMS = (HASH_CODE, UNIQUE_ID_OR_HASH)

#: Revision of the key formula written by this code (`Finding.dedupe_revision`).
#: See "Key revision 2" in the module docstring.
KEY_REVISION = 2

#: Fields the caller may list in a config. Anything else is a configuration
#: error and is refused loudly - a typo that silently drops a field from the
#: hash quietly merges unrelated findings, which is the worst failure mode here.
VALID_FIELDS = frozenset({
    "title", "description", "severity", "cwe", "cve", "plugin_id", "unique_id",
    "file_path", "line", "component_name", "component_version",
    "endpoint", "asset", "port", "protocol", "path", "vuln_ref",
})


class DedupeConfigError(ValueError):
    """A scanner's deduplication config is not usable. Never guessed around."""


@dataclasses.dataclass(frozen=True)
class DedupeConfig:
    algorithm: str = LEGACY
    fields: tuple[str, ...] = ()
    #: "organization" (default) or "engagement". Engagement scope lets two
    #: pentests of one app each keep their own copy of a finding.
    scope: str = "organization"

    def __post_init__(self) -> None:
        if self.algorithm not in ALGORITHMS:
            raise DedupeConfigError(
                f"unknown deduplication algorithm {self.algorithm!r}; "
                f"expected one of {', '.join(ALGORITHMS)}"
            )
        unknown = set(self.fields) - VALID_FIELDS
        if unknown:
            raise DedupeConfigError(
                f"unknown deduplication field(s): {', '.join(sorted(unknown))}"
            )
        if self.algorithm in (HASH_CODE, UNIQUE_ID_OR_HASH) and not self.fields:
            raise DedupeConfigError(
                f"algorithm {self.algorithm!r} requires a non-empty field list"
            )
        if self.scope not in ("organization", "engagement"):
            raise DedupeConfigError(f"unknown dedupe scope {self.scope!r}")

    def as_dict(self) -> dict[str, Any]:
        return {"algorithm": self.algorithm, "fields": list(self.fields), "scope": self.scope}

    @classmethod
    def from_dict(cls, raw: dict[str, Any] | None) -> "DedupeConfig | None":
        if not raw:
            return None
        return cls(
            algorithm=raw.get("algorithm", LEGACY),
            fields=tuple(raw.get("fields") or ()),
            scope=raw.get("scope", "organization"),
        )


#: Scanners already in production keep `legacy` so no existing key changes.
_LEGACY_CONFIG = DedupeConfig(algorithm=LEGACY)

#: Per-scanner defaults. The field lists mirror what each tool actually
#: populates reliably - they are the whole point of the exercise.
SCANNER_REGISTRY: dict[str, DedupeConfig] = {
    # --- pre-existing importers: unchanged behaviour, on purpose.
    "nessus": _LEGACY_CONFIG,
    "qualys": _LEGACY_CONFIG,
    "greenbone": _LEGACY_CONFIG,
    "csv": _LEGACY_CONFIG,
    "json": _LEGACY_CONFIG,

    # --- DAST / web. Granularity follows the TOOL, not a house style:
    #   * ZAP and Burp report one alert with many instances -> one finding,
    #     many endpoints. The endpoint must NOT be in the hash or the alert
    #     forks per URL and gets triaged once per instance.
    #   * Nuclei reports one match per URL and gives each its own id -> one
    #     finding per URL, so the endpoint IS part of the identity.
    "zap": DedupeConfig(HASH_CODE, ("title", "cwe", "asset")),
    "burp": DedupeConfig(UNIQUE_ID_OR_HASH, ("title", "cwe", "asset")),
    "nuclei": DedupeConfig(UNIQUE_ID_OR_HASH, ("plugin_id", "endpoint", "severity")),
    "nikto": DedupeConfig(HASH_CODE, ("title", "endpoint")),

    # --- SAST: file + line + rule. No endpoint exists at all.
    "semgrep": DedupeConfig(UNIQUE_ID_OR_HASH, ("plugin_id", "file_path", "line", "asset")),
    "bandit": DedupeConfig(HASH_CODE, ("plugin_id", "file_path", "line", "asset")),
    "gitleaks": DedupeConfig(HASH_CODE, ("title", "file_path", "line", "asset")),
    "checkov": DedupeConfig(HASH_CODE, ("plugin_id", "file_path", "asset")),
    "sarif": DedupeConfig(UNIQUE_ID_OR_HASH, ("plugin_id", "file_path", "line", "asset")),
    # `codeql` is an alias of the SARIF parser, but it is a distinct *scanner*
    # name on the finding, so it needs its own entry or it silently falls back
    # to `legacy` and collapses every result in a repository into one.
    "codeql": DedupeConfig(UNIQUE_ID_OR_HASH, ("plugin_id", "file_path", "line", "asset")),

    # --- SCA / container: package identity, not location.
    "trivy": DedupeConfig(HASH_CODE, ("cve", "component_name", "component_version", "asset")),
    "grype": DedupeConfig(HASH_CODE, ("cve", "component_name", "component_version", "asset")),
    "snyk": DedupeConfig(UNIQUE_ID_OR_HASH, ("cve", "component_name", "component_version", "asset")),
    "dependabot": DedupeConfig(HASH_CODE, ("cve", "component_name", "asset")),
    "npm_audit": DedupeConfig(HASH_CODE, ("cve", "component_name", "asset")),
    "pip_audit": DedupeConfig(HASH_CODE, ("cve", "component_name", "asset")),

    # --- cloud posture: the resource is the asset, the check is the rule.
    "prowler": DedupeConfig(HASH_CODE, ("plugin_id", "asset", "title")),
    "aws_security_hub": DedupeConfig(UNIQUE_ID_OR_HASH, ("plugin_id", "asset")),
}


def config_for(scanner: str, override: dict[str, Any] | None = None) -> DedupeConfig:
    """Resolve the config for a scanner, honouring a per-test override.

    An unregistered scanner gets `legacy` rather than a guess: a new parser that
    forgets to register is then merely as good as the old behaviour, not
    silently merging everything it reports.
    """
    explicit = DedupeConfig.from_dict(override)
    if explicit is not None:
        return explicit
    return SCANNER_REGISTRY.get((scanner or "").strip().lower(), _LEGACY_CONFIG)


# ---------------------------------------------------------------------------
# Normalisation
# ---------------------------------------------------------------------------
def _norm(value: Any) -> str:
    """Fold a field to its hashable form.

    Whitespace runs collapse and case folds, because "SQL  Injection" and "SQL
    injection" from two runs of the same tool are the same finding and a hash
    that disagrees creates a duplicate every single scan.
    """
    if value is None:
        return ""
    if isinstance(value, bool):
        return "1" if value else "0"
    if isinstance(value, (list, tuple, set)):
        return ",".join(sorted(_norm(v) for v in value if v is not None))
    text = str(value).strip().lower()
    return " ".join(text.split())


def _field_value(field: str, record: Any, context: dict[str, Any]) -> str:
    if field in context:
        return _norm(context[field])
    return _norm(getattr(record, field, None))


def compute_hash_code(
    record: Any, fields: Sequence[str], context: dict[str, Any] | None = None
) -> str:
    """sha256 over the configured fields, in the configured order.

    The field NAME is hashed alongside its value. Without that, config
    `("title",)` with title="x" and config `("cwe",)` with cwe="x" produce the
    same digest, and two unrelated findings from two scanners collide.
    """
    context = context or {}
    parts: list[str] = []
    for field in fields:
        parts.append(f"{field}={_field_value(field, record, context)}")
    return hashlib.sha256("|".join(parts).encode("utf-8")).hexdigest()


def legacy_key(
    *,
    organization_id: uuid.UUID,
    asset_id: uuid.UUID,
    vuln_ref: str,
    port: int | None = None,
    protocol: str | None = None,
    path: str | None = None,
) -> str:
    """The historical VEYRS identity, byte-for-byte.

    Kept here rather than imported from `correlation` so that module can import
    this one without a cycle. `correlation.dedupe_key` now delegates here, so
    there is exactly one definition and it cannot drift.
    """
    raw = "|".join([
        str(organization_id), str(asset_id), vuln_ref.upper(),
        str(port or ""), (protocol or "").lower(), (path or "").lower(),
    ])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


def unique_id_key(
    *, organization_id: uuid.UUID, scope_ref: str, scanner: str, unique_id: str
) -> str:
    """Identity for tools that already emit a per-instance stable id.

    Deliberately excludes the asset. A tool registered for this algorithm is
    asserting that its id identifies the instance, location included; folding
    the asset back in would defeat the point and split one issue across the two
    hostnames a host answers to.
    """
    raw = "|".join([str(organization_id), scope_ref, scanner.lower(), unique_id.strip()])
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


# ---------------------------------------------------------------------------
# Resolution
# ---------------------------------------------------------------------------
def cve_ref(vulnerability: Any) -> str:
    """The `cve` dedupe field for a finding of this vulnerability.

    The CVE id when the vulnerability is CVE-backed, else its internal ref (the
    scanner's advisory id, e.g. a GHSA, or a CVE not yet in the database).
    Taken from the vulnerability rather than the record's `cve_ids` because it
    is what the finding actually stores, so the CLI can recompute it offline,
    and because a pending CVE's internal ref is the CVE id itself, so the key
    does not move when the NVD record arrives.
    """
    return (getattr(vulnerability, "cve_id", None)
            or getattr(vulnerability, "internal_ref", None) or "")


def fold_cve(base_key: str, cve: str) -> str:
    """Revision-2 key from a revision-1 key. See the module docstring."""
    return hashlib.sha256(f"{base_key}|cve={_norm(cve)}".encode("utf-8")).hexdigest()


@dataclasses.dataclass
class Identity:
    """What deduplication decided about one record."""

    algorithm: str
    dedupe_key: str
    unique_id: str | None = None
    revision: int = KEY_REVISION
    #: Keys an earlier revision of the formula gave this same record. Matched
    #: only against revision-1 findings of the same vulnerability.
    previous_keys: tuple[str, ...] = ()

    def as_dict(self) -> dict[str, Any]:
        return {
            "algorithm": self.algorithm,
            "dedupe_key": self.dedupe_key,
            "unique_id": self.unique_id,
            "revision": self.revision,
        }


def resolve_identity(
    record: Any,
    *,
    config: DedupeConfig,
    organization_id: uuid.UUID,
    asset_id: uuid.UUID,
    vuln_ref: str,
    scanner: str,
    engagement_id: uuid.UUID | None = None,
    endpoint_canonical: str | None = None,
    cve: str | None = None,
) -> Identity:
    """Produce the identity for a record under `config`.

    Falls back to `legacy` - loudly, at WARNING - when an algorithm's inputs are
    missing, e.g. a scanner registered for `unique_id_from_tool` that emitted a
    record with no id. Falling back is safe (worst case: today's behaviour);
    silently hashing an empty string is not (every such record collides).

    `cve` is the `cve` field's value; the importer passes `cve_ref()` of the
    resolved vulnerability. Omitted, the record's own `cve_ids` are used.
    """
    scope_ref = (
        str(engagement_id) if config.scope == "engagement" and engagement_id else "org"
    )
    context: dict[str, Any] = {
        "asset": str(asset_id),
        "vuln_ref": vuln_ref,
        "endpoint": endpoint_canonical or "",
    }
    unique_id = _first_present(record, ("unique_id", "unique_id_from_tool", "vuln_id_from_tool"))

    if config.algorithm == LEGACY:
        return Identity(LEGACY, legacy_key(
            organization_id=organization_id, asset_id=asset_id, vuln_ref=vuln_ref,
            port=getattr(record, "port", None), protocol=getattr(record, "protocol", None),
            path=getattr(record, "path", None),
        ), unique_id)

    if config.algorithm == UNIQUE_ID:
        if not unique_id:
            log.warning(
                "scanner %s is configured for %s but a record carried no unique id; "
                "falling back to legacy identity for it", scanner, UNIQUE_ID,
            )
            return resolve_identity(
                record, config=_LEGACY_CONFIG, organization_id=organization_id,
                asset_id=asset_id, vuln_ref=vuln_ref, scanner=scanner,
                engagement_id=engagement_id, endpoint_canonical=endpoint_canonical,
                cve=cve,
            )
        return Identity(UNIQUE_ID, unique_id_key(
            organization_id=organization_id, scope_ref=scope_ref,
            scanner=scanner, unique_id=unique_id,
        ), unique_id)

    # hash_code and unique_id_or_hash_code both need the field hash. `cve` is
    # hashed as "" here and folded in afterwards (key revision 2), so the base
    # is exactly the key revision 1 stored.
    has_cve = "cve" in config.fields
    digest = compute_hash_code(record, config.fields, {**context, "cve": ""} if has_cve
                               else context)
    key = hashlib.sha256(
        "|".join([str(organization_id), scope_ref, scanner.lower(), digest]).encode("utf-8")
    ).hexdigest()
    algorithm = HASH_CODE if config.algorithm == HASH_CODE else UNIQUE_ID_OR_HASH
    if not has_cve:
        return Identity(algorithm, key, unique_id)
    value = cve if cve is not None else _norm(getattr(record, "cve_ids", None))
    return Identity(algorithm, fold_cve(key, value), unique_id, previous_keys=(key,))


def _first_present(record: Any, names: Iterable[str]) -> str | None:
    for name in names:
        value = getattr(record, name, None)
        if value:
            return str(value).strip()
    return None


def find_existing(
    session: Session,
    *,
    organization_id: uuid.UUID,
    identity: Identity,
    scanner: str | None = None,
    vulnerability_id: uuid.UUID | None = None,
):
    """Locate the finding this identity refers to, or None.

    For `unique_id_or_hash_code` the tool's own id wins when it is present, and
    the hash is the fallback - which is what makes a tool that starts emitting
    ids mid-life not fork every finding it has ever reported.

    Last, a revision-1 finding stored under one of `identity.previous_keys` is
    adopted, but only when it belongs to `vulnerability_id`: a pre-0.41.0 SCA
    finding that merged several CVEs is the finding of the CVE it was created
    for and of no other. The caller (`correlation.ensure_finding`) then
    re-keys it, exactly as `veyrs dedupe rehash` would have.
    """
    from ..models import Finding  # local import: models import services elsewhere

    if identity.algorithm == UNIQUE_ID_OR_HASH and identity.unique_id:
        stmt = select(Finding).where(
            Finding.organization_id == organization_id,
            Finding.unique_id_from_tool == identity.unique_id,
        )
        if scanner:
            stmt = stmt.where(Finding.scanner == scanner)
        row = session.execute(stmt).scalars().first()
        if row is not None:
            return row

    row = session.execute(
        select(Finding).where(
            Finding.organization_id == organization_id,
            Finding.dedupe_key == identity.dedupe_key,
        )
    ).scalars().first()
    if row is not None or not identity.previous_keys or vulnerability_id is None:
        return row
    return session.execute(
        select(Finding).where(
            Finding.organization_id == organization_id,
            Finding.dedupe_key.in_(identity.previous_keys),
            Finding.dedupe_revision < KEY_REVISION,
            Finding.vulnerability_id == vulnerability_id,
        )
    ).scalars().first()


# ---------------------------------------------------------------------------
# `veyrs dedupe rehash` -- the key revision 1 -> 2 migration
# ---------------------------------------------------------------------------
def _config_of(session: Session, finding: Any) -> DedupeConfig:
    """The config the finding's key was computed under, as the importer chose it:
    the import's own override, else the scan test's, else the registry."""
    from ..models import ScanTest
    from ..models.integration import ImportRun

    run = session.get(ImportRun, finding.import_run_id) if finding.import_run_id else None
    override = (run.options or {}).get("dedupe_config") if run is not None else None
    if not override and run is not None and run.test_id:
        test = session.get(ScanTest, run.test_id)
        override = (test.dedupe_config or None) if test is not None else None
    try:
        return config_for(finding.scanner or "", override)
    except DedupeConfigError:
        return _LEGACY_CONFIG


def rehash(session: Session, organization_id: uuid.UUID, *, apply: bool = False
           ) -> dict[str, Any]:
    """Re-key this tenant's revision-1 findings whose config hashes `cve`.

    Dry run unless `apply`. Idempotent: only `dedupe_revision == 1` rows are
    read and a re-keyed row is written at revision 2. A row whose new key is
    already held by another finding (an import created it before this ran) is
    NOT touched and is listed under `conflicts` for an operator: merging two
    findings is a triage decision, not a migration step.
    """
    from ..models import Finding, Vulnerability

    rows = session.execute(
        select(Finding).where(
            Finding.organization_id == organization_id,
            Finding.dedupe_revision < KEY_REVISION,
            Finding.dedupe_algorithm.in_(HASH_ALGORITHMS),
        ).order_by(Finding.created_at, Finding.id)
    ).scalars().all()

    report: dict[str, Any] = {"candidates": len(rows), "rekeyed": 0, "unaffected": 0,
                              "conflicts": [], "apply": apply}
    for finding in rows:
        config = _config_of(session, finding)
        if config.algorithm not in HASH_ALGORITHMS or "cve" not in config.fields:
            report["unaffected"] += 1
            continue
        vulnerability = session.get(Vulnerability, finding.vulnerability_id)
        new_key = fold_cve(finding.dedupe_key, cve_ref(vulnerability))
        clash = session.execute(
            select(Finding.id).where(
                # Organisation-wide, like find_existing's lookup.
                Finding.organization_id == organization_id,
                Finding.dedupe_key == new_key,
                Finding.id != finding.id,
            )
        ).scalars().first()
        if clash is not None:
            report["conflicts"].append({"finding_id": str(finding.id),
                                        "held_by": str(clash)})
            continue
        report["rekeyed"] += 1
        if apply:
            finding.dedupe_key = new_key
            finding.dedupe_revision = KEY_REVISION
    if apply:
        session.flush()
    return report


def describe_registry() -> list[dict[str, Any]]:
    """Introspection for the API and the console's import settings screen."""
    return [
        {"scanner": name, **config.as_dict()}
        for name, config in sorted(SCANNER_REGISTRY.items())
    ]
