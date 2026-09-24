"""Software inventory: turning what an operator calls something into CPE identity.

This is the layer the correlation engine silently depends on and nobody thinks
about until it returns nothing.

`affected_installations` joins `AssetProduct.product_id` to
`CveCpeMatch.product_id`. Those product rows are created by NVD ingestion from
**CPE tokens**, not from commercial names: nginx lives at
`cpe:2.3:a:f5:nginx:...`, so NVD's vendor for it is `f5`. An inventory that says
`vendor="Nginx"` creates a *second*, different Product row, the join finds
nothing, and the platform reports the estate as unaffected. That failure is
silent and total, which makes it the most dangerous bug this module can have.

So identity is resolved in this order, most authoritative first:

1. **A CPE 2.3 string.** No inference at all -- the caller told us exactly which
   dictionary entry this is. Always prefer this path; it is why the bulk API
   accepts `cpe` and why the agent emits it.
2. **An exact vendor+product hit in the registry**, i.e. a product NVD has
   already created. The operator's spelling agreed with the dictionary.
3. **The product token alone, disambiguated by evidence.** If one registry
   product carries that name and it has CVE applicability rows, adopt its
   vendor. `nginx` -> `f5` falls out of the data rather than out of a hardcoded
   table.
4. **A curated alias**, for the handful of names where the dictionary has no
   entry yet or the common name differs from the token (`java` -> `jdk`).
5. **Nothing.** The row is still recorded -- losing inventory is worse than
   recording it unmatched -- but `matched=False`, and `coverage()` lists it. An
   unmatched install is a name to fix, not a host that is safe.

`verify_aliases()` exists because a hardcoded alias is a claim about somebody
else's dictionary, and claims rot. It checks each one against the CPE data
actually present and reports the ones that no longer hold.
"""
from __future__ import annotations

import datetime as dt
import uuid
from dataclasses import dataclass, field
from typing import Any, Iterable, Sequence

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Asset, AssetProduct, Cpe, CveCpeMatch, Product, Vendor
from . import intelligence
from .versions import (is_distro_version, normalize_name, parse_cpe23,
                       upstream_version, version_key)

#: Common name -> (cpe vendor token, cpe product token).
#:
#: Only for names whose CPE form is not derivable from the string itself. Every
#: entry is a claim about NVD's dictionary, so `verify_aliases()` checks them
#: against the data and this map is deliberately short: the evidence-based path
#: above handles the general case, and a long alias table is a maintenance debt
#: that silently drifts.
PRODUCT_ALIASES: dict[str, tuple[str, str]] = {
    "nginx": ("f5", "nginx"),
    "apache": ("apache", "http_server"),
    "apache2": ("apache", "http_server"),
    "httpd": ("apache", "http_server"),
    "apache_http_server": ("apache", "http_server"),
    "java": ("oracle", "jdk"),
    "openjdk": ("oracle", "openjdk"),
    "mysql": ("oracle", "mysql"),
    "mysql_server": ("oracle", "mysql"),
    "openssh": ("openbsd", "openssh"),
    "openssh_server": ("openbsd", "openssh"),
    "linux": ("linux", "linux_kernel"),
    "linux_kernel": ("linux", "linux_kernel"),
    "postgres": ("postgresql", "postgresql"),
    "postgresql": ("postgresql", "postgresql"),
    "python": ("python", "python"),
    "python3": ("python", "python"),
    "docker": ("docker", "docker"),
    "haproxy": ("haproxy", "haproxy"),
    "redis": ("redis", "redis"),
    "openssl": ("openssl", "openssl"),
    "curl": ("haxx", "curl"),
    "git": ("git-scm", "git"),
    "samba": ("samba", "samba"),
    "bind9": ("isc", "bind"),
    "bind": ("isc", "bind"),
    "sudo": ("sudo_project", "sudo"),
    "php": ("php", "php"),
    "nodejs": ("nodejs", "node.js"),
    "node": ("nodejs", "node.js"),
    "grafana": ("grafana", "grafana"),
    "jenkins": ("jenkins", "jenkins"),
    "wordpress": ("wordpress", "wordpress"),
    "gitea": ("gitea", "gitea"),
    "proxmox_ve": ("proxmox", "virtual_environment"),
    "home_assistant": ("home-assistant", "home-assistant"),
}


@dataclass
class Resolution:
    """What we decided a piece of inventory actually is, and how sure we are."""

    product: Product
    version: str | None = None
    #: The identity is pinned to a dictionary entry rather than invented from
    #: the operator's spelling. Says nothing about whether CVEs exist for it.
    anchored: bool = False
    #: CVE applicability data actually references this product, so correlation
    #: can fire. Deliberately separate from `anchored`: an explicit CPE gives
    #: perfect identity and still yields no findings if the corpus has no
    #: advisories for it, and reporting that as "matched" would be a lie the
    #: coverage view then repeats.
    matched: bool = False
    #: cpe | registry | evidence | alias | unmatched
    source: str = "unmatched"
    #: The CPE string this identity came from, when the caller supplied one.
    cpe23: str | None = None
    #: Other vendors the dictionary lists for this product name, when ambiguous.
    candidates: list[str] = field(default_factory=list)
    note: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return {
            "product_id": str(self.product.id),
            "vendor": self.product.vendor.name if self.product.vendor else None,
            "product": self.product.name,
            "version": self.version,
            "anchored": self.anchored,
            "matched": self.matched,
            "source": self.source,
            "candidates": self.candidates,
            "note": self.note,
        }


# --------------------------------------------------------------------------
# Identity resolution
# --------------------------------------------------------------------------


def _registry_hit(session: Session, vendor: str, product: str) -> Product | None:
    return session.execute(
        select(Product)
        .join(Vendor, Product.vendor_id == Vendor.id)
        .where(
            Vendor.normalized_name == normalize_name(vendor),
            Product.normalized_name == normalize_name(product),
        )
    ).scalars().first()


def _has_applicability(session: Session, product_id: uuid.UUID) -> bool:
    return session.execute(
        select(func.count()).select_from(CveCpeMatch)
        .where(CveCpeMatch.product_id == product_id)
    ).scalar_one() > 0


def _by_evidence(session: Session, product: str) -> tuple[Product | None, list[str]]:
    """Find the product by name alone, preferring the one CVEs actually cite.

    Ambiguity is real (`gitlab` exists under two vendors), so the tie-break is
    "which one does vulnerability data reference", not alphabetical luck.
    """
    rows = list(session.execute(
        select(Product).join(Vendor, Product.vendor_id == Vendor.id)
        .where(Product.normalized_name == normalize_name(product))
    ).scalars().all())
    if not rows:
        return None, []
    with_evidence = [p for p in rows if _has_applicability(session, p.id)]
    pool = with_evidence or rows
    candidates = sorted({p.vendor.name for p in rows if p.vendor})
    if len(pool) == 1:
        return pool[0], candidates
    # Still ambiguous: refuse to guess silently, take the one with the most
    # applicability rows and surface the alternatives to the caller.
    pool.sort(key=lambda p: session.execute(
        select(func.count()).select_from(CveCpeMatch)
        .where(CveCpeMatch.product_id == p.id)
    ).scalar_one(), reverse=True)
    return pool[0], candidates


def resolve_identity(
    session: Session,
    *,
    cpe: str | None = None,
    vendor: str | None = None,
    product: str | None = None,
    version: str | None = None,
) -> Resolution:
    """Decide which registry Product a piece of inventory refers to."""
    # 1. An explicit CPE is the whole point. No inference.
    if cpe:
        parts = parse_cpe23(cpe)
        if parts is None:
            raise ValueError(f"not a CPE 2.3 string: {cpe!r}")
        row = intelligence.upsert_cpe(session, cpe)
        if row is not None and row.product_id:
            resolved = session.get(Product, row.product_id)
            cpe_version = parts["version"]
            return Resolution(
                product=resolved,
                version=version or (cpe_version if cpe_version not in ("*", "-") else None),
                anchored=True, matched=_has_applicability(session, resolved.id),
                source="cpe", cpe23=cpe,
            )
        # A CPE with a wildcard vendor or product carries no identity.
        raise ValueError(f"CPE names no concrete vendor/product: {cpe!r}")

    if not product:
        raise ValueError("either cpe or product is required")

    # 2. The operator's spelling already agrees with the dictionary.
    if vendor:
        hit = _registry_hit(session, vendor, product)
        if hit is not None:
            return Resolution(product=hit, version=version, anchored=True,
                              matched=_has_applicability(session, hit.id),
                              source="registry")

    # 3. Let the data disambiguate the vendor.
    hit, candidates = _by_evidence(session, product)
    if hit is not None and _has_applicability(session, hit.id):
        note = None
        if vendor and normalize_name(vendor) != normalize_name(hit.vendor.name):
            note = (f"vendor {vendor!r} rewritten to {hit.vendor.name!r} to match "
                    "the CPE dictionary")
        return Resolution(product=hit, version=version, anchored=True, matched=True,
                          source="evidence", candidates=candidates, note=note)

    # 4. Curated alias for names the dictionary spells differently.
    alias = PRODUCT_ALIASES.get(normalize_name(product))
    if alias:
        alias_vendor, alias_product = alias
        aliased = _registry_hit(session, alias_vendor, alias_product)
        if aliased is None:
            aliased = intelligence.upsert_product(session, alias_vendor, alias_product)
        return Resolution(
            product=aliased, version=version, anchored=True,
            matched=_has_applicability(session, aliased.id),
            source="alias", candidates=candidates,
            note=f"{product!r} recorded as {alias_vendor}:{alias_product}",
        )

    # 5. Record it as given, but do not pretend it is covered.
    created = intelligence.upsert_product(session, vendor or product, product)
    return Resolution(
        product=created, version=version, anchored=False,
        matched=_has_applicability(session, created.id),
        source="registry" if hit is not None else "unmatched",
        candidates=candidates,
        note="no CVE applicability data references this product; check the "
             "vendor/product spelling against CPE",
    )


# --------------------------------------------------------------------------
# Installing inventory on an asset
# --------------------------------------------------------------------------


def install(
    session: Session,
    asset: Asset,
    specs: Iterable[Any],
    *,
    detected_by: str = "manual",
    replace: bool = False,
) -> dict[str, Any]:
    """Record installed software, resolving each row to a CPE-anchored product.

    `replace=True` drops installs this source previously reported and that are
    absent now -- the only correct semantics for a full agent inventory, where
    "no longer present" is real information. It is scoped to `detected_by` so an
    agent sweep never deletes what an operator entered by hand.
    """
    now = dt.datetime.now(dt.timezone.utc)
    results: list[dict[str, Any]] = []
    seen_products: set[uuid.UUID] = set()
    added = updated = 0

    for spec in specs:
        cpe = _attr(spec, "cpe")
        try:
            resolution = resolve_identity(
                session,
                cpe=cpe,
                vendor=_attr(spec, "vendor"),
                product=_attr(spec, "product"),
                version=_attr(spec, "version"),
            )
        except ValueError as exc:
            results.append({"input": _spec_repr(spec), "error": str(exc),
                            "matched": False})
            continue

        row_detected_by = _attr(spec, "detected_by") or detected_by
        raw_version = _attr(spec, "raw_version")
        if resolution.version is None and raw_version:
            # A collector may report only what the package manager said. The
            # upstream reduction is applied here, once, rather than in every
            # collector that would otherwise carry its own copy of the rule.
            resolution.version = upstream_version(raw_version)
        elif resolution.version and is_distro_version(resolution.version):
            # ...and a collector that fills BOTH fields with the same package
            # string must not walk around that rule. `1:9.2p1-2+deb12u10` under
            # a field named `version` is still packaging metadata; taking it at
            # face value is how a CMDB import raised 444 OpenSSH findings for
            # CVEs fixed in 2001 and 2003. The verbatim string is not lost --
            # `raw_version` below keeps it for the analyst.
            resolution.version = upstream_version(resolution.version)
        # `uq_asset_products_asset_id` is UNIQUE (asset_id, product_id,
        # version): the schema says one asset may legitimately carry several
        # versions of the same product, and RPM hosts prove it -- `gpg-pubkey`
        # has one row per trusted key. A lookup that ignored `version` and took
        # `.first()` would pick an arbitrary sibling and try to rename it onto a
        # version another row already holds, which is a UniqueViolation that
        # aborts the whole import. It only fires on the SECOND sweep of such a
        # host, when the rows exist and the insert path no longer hides it.
        candidates = session.execute(
            select(AssetProduct).where(
                AssetProduct.organization_id == asset.organization_id,
                AssetProduct.asset_id == asset.id,
                AssetProduct.product_id == resolution.product.id,
            )
        ).scalars().all()
        existing = next(
            (row for row in candidates if row.version == resolution.version), None
        )
        if (existing is None and len(candidates) == 1
                and resolution.product.id not in seen_products):
            # The ordinary case, preserved: one row for this product and the
            # version moved. An upgrade updates in place rather than growing a
            # second row nothing would ever clean up.
            #
            # `not in seen_products` is what keeps that from eating a
            # multi-version product on the FIRST sweep. Autoflush means the
            # `candidates` query above already sees the row this same batch
            # inserted a moment ago, so without the guard the second
            # `gpg-pubkey` key looks exactly like an upgrade of the first: three
            # keys collapse into one row, silently, and the host ends up
            # under-reported rather than erroring. The second sweep was only
            # ever the louder half of this bug.
            existing = candidates[0]
        # Several rows and no version match means a genuinely new version of a
        # multi-version product: insert, do not rename a sibling.
        if existing is None:
            session.add(AssetProduct(
                organization_id=asset.organization_id, asset_id=asset.id,
                product_id=resolution.product.id, version=resolution.version,
                version_key=version_key(resolution.version),
                raw_version=raw_version, cpe23=resolution.cpe23,
                install_path=_attr(spec, "install_path"),
                detected_by=row_detected_by, last_seen_at=now,
            ))
            added += 1
        else:
            existing.version = resolution.version
            existing.version_key = version_key(resolution.version)
            existing.raw_version = raw_version or existing.raw_version
            existing.cpe23 = resolution.cpe23 or existing.cpe23
            existing.install_path = _attr(spec, "install_path") or existing.install_path
            existing.detected_by = row_detected_by
            existing.last_seen_at = now
            updated += 1
        if resolution.version:
            intelligence.upsert_product_version(
                session, resolution.product, resolution.version
            )
        seen_products.add(resolution.product.id)
        results.append({"input": _spec_repr(spec), **resolution.as_dict()})

    removed = 0
    if replace:
        stale = session.execute(
            select(AssetProduct).where(
                AssetProduct.organization_id == asset.organization_id,
                AssetProduct.asset_id == asset.id,
                AssetProduct.detected_by == detected_by,
            )
        ).scalars().all()
        for row in stale:
            if row.product_id not in seen_products:
                session.delete(row)
                removed += 1

    session.flush()
    return {
        "added": added, "updated": updated, "removed": removed,
        "anchored": sum(1 for r in results if r.get("anchored")),
        "matched": sum(1 for r in results if r.get("matched")),
        "unmatched": sum(1 for r in results if not r.get("matched")),
        "results": results,
    }


def _attr(spec: Any, name: str) -> Any:
    if isinstance(spec, dict):
        return spec.get(name)
    return getattr(spec, name, None)


def _spec_repr(spec: Any) -> str:
    cpe = _attr(spec, "cpe")
    if cpe:
        return cpe
    return ":".join(str(x) for x in (
        _attr(spec, "vendor"), _attr(spec, "product"), _attr(spec, "version")
    ) if x)


# --------------------------------------------------------------------------
# Asset upsert (bulk onboarding)
# --------------------------------------------------------------------------


def upsert_asset(
    session: Session, organization_id: uuid.UUID, spec: dict[str, Any]
) -> tuple[Asset, bool]:
    """Find-or-create an asset by the most stable identifier it carries.

    Order matters: `external_id` is assigned by whatever CMDB owns the host and
    survives renames; hostnames do not. Matching on `name` first would fork an
    asset every time somebody fixes a typo.
    """
    asset: Asset | None = None
    for column, value in (
        (Asset.external_id, spec.get("external_id")),
        (Asset.fqdn, spec.get("fqdn")),
        (Asset.hostname, spec.get("hostname")),
        (Asset.name, spec.get("name")),
    ):
        if not value:
            continue
        asset = session.execute(
            select(Asset).where(
                Asset.organization_id == organization_id,
                column == value,
                Asset.deleted_at.is_(None),
            )
        ).scalars().first()
        if asset is not None:
            break

    created = asset is None
    if created:
        asset = Asset(
            organization_id=organization_id,
            name=spec.get("name") or spec.get("hostname") or spec.get("fqdn") or "unnamed",
        )
        session.add(asset)

    for attribute in ("asset_type", "external_id", "hostname", "fqdn",
                      "operating_system", "os_version", "environment",
                      "criticality", "data_classification", "exposure",
                      "location"):
        value = spec.get(attribute)
        if value is not None and hasattr(asset, attribute):
            setattr(asset, attribute, value)
    for attribute in ("ip_addresses", "mac_addresses"):
        value = spec.get(attribute)
        if value and hasattr(asset, attribute):
            setattr(asset, attribute, list(value))
    session.flush()
    return asset, created


# --------------------------------------------------------------------------
# Coverage / self-check
# --------------------------------------------------------------------------


def coverage(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """Which installed software can never produce a finding, and why.

    A tenant reading "0 findings" has two possible causes: nothing is
    vulnerable, or nothing is matchable. Those look identical in every other
    view, so this endpoint exists to tell them apart.
    """
    rows = session.execute(
        select(AssetProduct, Product, Vendor, Asset)
        .join(Product, AssetProduct.product_id == Product.id)
        .join(Vendor, Product.vendor_id == Vendor.id)
        .join(Asset, AssetProduct.asset_id == Asset.id)
        .where(AssetProduct.organization_id == organization_id)
    ).all()

    unmatched: list[dict[str, Any]] = []
    no_version: list[dict[str, Any]] = []
    matched = 0
    for install_row, product, vendor, asset in rows:
        entry = {
            "asset": asset.name, "vendor": vendor.name, "product": product.name,
            "version": install_row.version, "raw_version": install_row.raw_version,
            "detected_by": install_row.detected_by,
        }
        if not _has_applicability(session, product.id):
            entry["reason"] = ("no CVE applicability data references this product "
                               "-- either the name is wrong or no advisory exists yet")
            entry["suggestions"] = _suggest(session, product.name)
            unmatched.append(entry)
            continue
        matched += 1
        if not install_row.version:
            # `versions.in_range` returns False for an unknown version on
            # purpose, so a versionless install is inert even when the product
            # itself is well known.
            entry["reason"] = "no version recorded; range matching cannot fire"
            no_version.append(entry)

    return {
        "installations": len(rows),
        "matchable": matched,
        "unmatched": len(unmatched),
        "missing_version": len(no_version),
        "unmatched_detail": unmatched[:200],
        "missing_version_detail": no_version[:200],
    }


def _suggest(session: Session, name: str, limit: int = 5) -> list[str]:
    """Dictionary entries whose product token looks like this name."""
    token = normalize_name(name).replace("_", "")
    if not token:
        return []
    rows = session.execute(
        select(Cpe.vendor, Cpe.product)
        .where(Cpe.product.ilike(f"%{token[:24]}%"))
        .distinct().limit(limit)
    ).all()
    return [f"cpe:2.3:a:{vendor}:{product}" for vendor, product in rows]


def verify_aliases(session: Session) -> dict[str, Any]:
    """Check every curated alias against the CPE data actually loaded.

    A hardcoded alias is a claim about somebody else's dictionary. This is how
    we find out when one stops being true instead of discovering it as a tenant
    with zero findings.
    """
    confirmed: list[str] = []
    unknown: list[str] = []
    for name, (vendor, product) in sorted(PRODUCT_ALIASES.items()):
        exists = session.execute(
            select(func.count()).select_from(Cpe)
            .where(Cpe.vendor == vendor, Cpe.product == product)
        ).scalar_one()
        (confirmed if exists else unknown).append(f"{name} -> {vendor}:{product}")
    return {"aliases": len(PRODUCT_ALIASES), "confirmed": confirmed,
            "unconfirmed": unknown}


__all__ = [
    "PRODUCT_ALIASES", "Resolution", "resolve_identity", "install",
    "upsert_asset", "coverage", "verify_aliases",
]
