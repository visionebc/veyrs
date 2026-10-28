"""Fix plan: which version fixes everything open on a product, and how far away it is.

VEYRS could already say "CVE-X affects your Acme Widget 1.2.3". It could not
answer the question that actually decides a maintenance window: *which single
version closes everything open on this installation, is that a patch on my
branch or a jump to another major, and does the vendor make me stop somewhere
on the way?* This module answers it, deterministically, from data VEYRS
already holds -- no AI, no network:

* **CPE ranges** (`CveCpeMatch`). A vulnerable range that ends
  `version_end_excluding = V` says "V is the first version on this branch that
  is not affected", which is an exact, citable fixed version. A range that ends
  `version_end_including = X` says only that X is still vulnerable: the fix is
  "a version after X", and no candidate is invented from it.
* **Advisory fixed versions** (`Cve.fixed_versions`), matched to THIS
  vendor/product through `versions.normalize_name`. An entry that names no
  product is reported but never used: a version number with no product
  attached could belong to anything the advisory mentions.
* **Operator upgrade-path rules** (`UpgradePathRule`) for mandatory
  intermediate versions and prerequisites. VEYRS seeds none.

The one rule that matters more than any other: **never claim "fixed" on
missing data.** A candidate T fixes a CVE only if T sits outside EVERY
vulnerable range published for this product (decided by
`correlation.match_covers` -- the same test that created the finding, so the
plan and the finding cannot disagree) and, where an advisory lists fixed
versions for the product, T is consistent with them. A finding with no exact
fixed version is listed under `no_fix_known`, and the coverage line says how
many findings that is.

Version ordering and parsing come exclusively from `services/versions.py`.
There is no second comparator here, on purpose.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import functools
import uuid
from typing import Any, Iterable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import (
    Asset, AssetProduct, Cve, CveCpeMatch, Finding, OPEN_STATES, Product, Vendor,
    Vulnerability,
)
from ..models.upgrade import UpgradePathRule
from ..security import scope as team_scope
from .correlation import match_covers
from .versions import compare, in_range, normalize_name, parse, parse_cpe23

#: Hard cap on hops in one upgrade path. Rules are operator data; a chain of
#: them must not be able to spin the request, and a path this long is a
#: finding in itself.
MAX_HOPS = 16

_ANY = ("*", "-", "", None)

_version_key = functools.cmp_to_key(compare)


# --------------------------------------------------------------------------
# Version helpers (all built on versions.parse / versions.compare)
# --------------------------------------------------------------------------


def _known(version: str | None) -> bool:
    """A version we can reason about: present and yielding at least one segment."""
    return version not in _ANY and bool(parse(version))


def _sorted_unique(versions: Iterable[str]) -> list[str]:
    """Ascending, with `7.2` and `7.2.0` collapsed (they compare equal)."""
    out: list[str] = []
    for value in sorted({v for v in versions if _known(v)}, key=_version_key):
        if out and compare(out[-1], value) == 0:
            continue
        out.append(value)
    return out


def branch(version: str | None) -> tuple[int, int] | None:
    """`(major, minor)` when both are numeric, else None.

    A missing minor is 0 (`7` is `7.0`, which is how `compare` pads too). A
    leading non-numeric component (`r2024a`, `ga`) yields None: we cannot say
    which branch that is, and guessing is how a major jump gets labelled a
    patch.
    """
    if not _known(version):
        return None
    segments = parse(version)
    if segments[0][0] != 1:
        return None
    major = segments[0][1]
    if len(segments) == 1:
        return major, 0
    if segments[1][0] != 1:
        return None
    return major, segments[1][1]


def classify_step(installed: str | None, target: str | None) -> str:
    """`patch` (same major.minor), `minor` (same major), `major`, or `unknown`."""
    a, b = branch(installed), branch(target)
    if a is None or b is None:
        return "unknown"
    if a == b:
        return "patch"
    if a[0] == b[0]:
        return "minor"
    return "major"


def _consistent_with_advisory(target: str, fixed: list[str]) -> bool:
    """Is `target` at or after a fix the advisory names?

    True when target equals a listed fixed version, is later on the SAME
    major.minor as one, or is later than every listed one. A version on a
    branch the advisory never mentions (fixed in 7.2.5 and 7.4.1; target
    7.3.0) is NOT consistent: the advisory is silent about it, and silence is
    not a fix.
    """
    if not fixed:
        return True
    target_branch = branch(target)
    for value in fixed:
        order = compare(target, value)
        if order == 0:
            return True
        if order > 0 and target_branch is not None and branch(value) == target_branch:
            return True
    return all(compare(target, value) > 0 for value in fixed)


# --------------------------------------------------------------------------
# Facts per CVE, for one product
# --------------------------------------------------------------------------


@dataclasses.dataclass
class CveFacts:
    """What the data says about fixing ONE CVE on ONE product."""

    cve_id: str | None
    ranges: list[CveCpeMatch] = dataclasses.field(default_factory=list)
    #: `version_end_excluding` of a vulnerable range: first unaffected version.
    range_fixes: list[str] = dataclasses.field(default_factory=list)
    #: `version_end_including` of a vulnerable range: fixed "after X", inexact.
    after: list[str] = dataclasses.field(default_factory=list)
    #: Fixed versions an advisory lists for THIS vendor/product.
    advisory_fixed: list[str] = dataclasses.field(default_factory=list)
    #: Advisory entries that matched this product (for the coverage line).
    advisories: int = 0
    #: Fixed versions an advisory gives with no product attached. Shown, never used.
    unattributed: list[str] = dataclasses.field(default_factory=list)

    @property
    def exact_fixes(self) -> list[str]:
        return _sorted_unique([*self.range_fixes, *self.advisory_fixed])

    @property
    def status(self) -> str:
        if self.exact_fixes:
            return "known"
        if self.after:
            return "after"
        return "unknown"

    def fixed_by(self, target: str) -> bool:
        """Does upgrading to `target` take this product out of the CVE?

        Never True on missing data: with neither a range nor an advisory for
        this product there is nothing to say `target` is clean.
        """
        if not self.ranges and not self.advisory_fixed:
            return False
        if any(match_covers(target, match) for match in self.ranges):
            return False
        return _consistent_with_advisory(target, self.advisory_fixed)


def _identity_keys(session: Session, product_id: uuid.UUID) -> tuple[
    Product | None, Vendor | None, set[str], set[str]
]:
    """Every normalised key this product is known by, for advisory/rule matching."""
    product = session.get(Product, product_id)
    vendor = session.get(Vendor, product.vendor_id) if product is not None else None
    product_keys = {k for k in (
        product.normalized_name if product else None,
        normalize_name(product.name) if product else None,
    ) if k}
    vendor_keys = {k for k in (
        vendor.normalized_name if vendor else None,
        normalize_name(vendor.name) if vendor else None,
    ) if k}
    return product, vendor, vendor_keys, product_keys


def _as_list(value: Any) -> list[str]:
    if isinstance(value, str):
        value = [value]
    if not isinstance(value, (list, tuple)):
        return []
    return [str(v).strip() for v in value if isinstance(v, (str, int, float)) and str(v).strip()]


def _advisory_matches(entry: dict, vendor_keys: set[str], product_keys: set[str]) -> bool:
    pairs = [(entry.get("vendor"), entry.get("product"))]
    parsed = parse_cpe23(entry.get("cpe23") or "")
    if parsed:
        pairs.append((parsed.get("vendor"), parsed.get("product")))
    for vendor, product in pairs:
        if (vendor and product and normalize_name(str(vendor)) in vendor_keys
                and normalize_name(str(product)) in product_keys):
            return True
    return False


def cve_facts(
    session: Session, cve_id: str | None, product_id: uuid.UUID,
    vendor_keys: set[str], product_keys: set[str],
) -> CveFacts:
    facts = CveFacts(cve_id=cve_id)
    if not cve_id:
        return facts
    # The same rows correlation joins on: vulnerable, and resolved to THIS
    # product. A range for another product of the same advisory says nothing
    # about this installation.
    facts.ranges = list(session.execute(
        select(CveCpeMatch).where(
            CveCpeMatch.cve_id == cve_id,
            CveCpeMatch.vulnerable.is_(True),
            CveCpeMatch.product_id == product_id,
        ).order_by(CveCpeMatch.cpe23, CveCpeMatch.id)
    ).scalars().all())
    for match in facts.ranges:
        exact = (parse_cpe23(match.cpe23) or {}).get("version")
        if exact not in _ANY:
            # An exact-version CPE ("7.2.4 is affected") ignores the bounds in
            # correlation, so its bounds cannot be read as a fix here either.
            continue
        if _known(match.version_end_excluding):
            facts.range_fixes.append(match.version_end_excluding)
        if _known(match.version_end_including):
            facts.after.append(match.version_end_including)

    cve = session.get(Cve, cve_id)
    for entry in (cve.fixed_versions if cve is not None else None) or []:
        if isinstance(entry, str):
            if _known(entry):
                facts.unattributed.append(entry)
            continue
        if not isinstance(entry, dict):
            continue
        fixed = [v for v in _as_list(entry.get("fixed")) if _known(v)]
        if not fixed:
            continue
        if _advisory_matches(entry, vendor_keys, product_keys):
            facts.advisories += 1
            facts.advisory_fixed.extend(fixed)
    facts.advisory_fixed = _sorted_unique(facts.advisory_fixed)
    facts.after = _sorted_unique(facts.after)
    facts.unattributed = _sorted_unique(facts.unattributed)
    return facts


# --------------------------------------------------------------------------
# Upgrade paths (operator rules)
# --------------------------------------------------------------------------


def rules_for(
    session: Session, organization_id: uuid.UUID, vendor_keys: set[str], product_keys: set[str]
) -> list[UpgradePathRule]:
    """This tenant's enabled rules for this product.

    Filtered on `organization_id` explicitly AND by RLS: another
    organisation's rule must never shape this one's plan, and one layer of that
    guarantee is not enough.
    """
    if not vendor_keys or not product_keys:
        return []
    return list(session.execute(
        select(UpgradePathRule).where(
            UpgradePathRule.organization_id == organization_id,
            UpgradePathRule.is_enabled.is_(True),
            UpgradePathRule.vendor_key.in_(sorted(vendor_keys)),
            UpgradePathRule.product_key.in_(sorted(product_keys)),
        ).order_by(UpgradePathRule.created_at, UpgradePathRule.id)
    ).scalars().all())


def rule_covers(version: str, rule: UpgradePathRule) -> bool:
    return in_range(
        version,
        start_including=rule.from_start_including,
        start_excluding=rule.from_start_excluding,
        end_including=rule.from_end_including,
        end_excluding=rule.from_end_excluding,
    )


def _rule_ref(rule: UpgradePathRule) -> dict:
    return {
        "rule_id": str(rule.id), "via_version": rule.via_version,
        "prerequisite": rule.prerequisite, "source_url": rule.source_url,
    }


def upgrade_path(installed: str, target: str, rules: list[UpgradePathRule]) -> dict:
    """Ordered hops installed -> ... -> target, applying the operator's rules.

    At each stop, every rule whose `from_*` range covers the current version
    is considered. The LOWEST `via_version` that lies strictly between the
    current version and the target becomes the next stop. Prerequisite-only
    rules (no `via_version`) attach their note to the hop leaving the range.

    Cycle guard, two layers: a rule whose `via_version` is OLDER than the
    current stop would send the path backwards -- the only way two rules can
    form a loop -- so it is ignored and reported in `ignored_rules`; and the
    path is capped at `MAX_HOPS`, reported as incomplete if it hits the cap.
    """
    hops: list[dict] = []
    ignored: dict[str, dict] = {}
    warnings: list[str] = []
    visited = [installed]
    current = installed
    complete = True
    while True:
        covering = [r for r in rules if rule_covers(current, r)]
        for rule in covering:
            if rule.via_version and compare(rule.via_version, current) < 0:
                ignored.setdefault(str(rule.id), {
                    **_rule_ref(rule),
                    "reason": (f"via_version {rule.via_version} is older than {current}, "
                               "where this hop starts; following it would go backwards "
                               "(a rule cycle), so it was ignored"),
                })
        stops = [r for r in covering if r.via_version
                 and compare(r.via_version, current) > 0
                 and compare(r.via_version, target) < 0]
        if stops:
            nxt = min((r.via_version for r in stops), key=_version_key)
            required = [r for r in stops if compare(r.via_version, nxt) == 0]
        else:
            nxt = target
            required = [r for r in covering if r.via_version
                        and compare(r.via_version, target) == 0]
        prerequisites = [r for r in covering if not r.via_version] + required
        hops.append({
            "from": current, "to": nxt, "step": classify_step(current, nxt),
            "required_by": [_rule_ref(r) for r in required],
            "prerequisites": [
                {"note": r.prerequisite, "source_url": r.source_url, "rule_id": str(r.id)}
                for r in prerequisites if r.prerequisite
            ],
        })
        if nxt is target or compare(nxt, target) == 0:
            break
        if any(compare(nxt, seen) == 0 for seen in visited):
            # Unreachable while stops are strictly increasing; kept because the
            # cost of being wrong about that is an infinite loop in a request.
            warnings.append(f"rule cycle detected at {nxt}; path stopped")
            complete = False
            break
        visited.append(nxt)
        if len(hops) >= MAX_HOPS:
            warnings.append(
                f"stopped after {MAX_HOPS} hops without reaching {target}; "
                "check the upgrade-path rules for this product"
            )
            complete = False
            break
        current = nxt
    return {
        "target": target,
        "hops": hops,
        "path_required": len(hops) > 1,
        "complete": complete,
        "warnings": warnings,
        "ignored_rules": list(ignored.values()),
    }


# --------------------------------------------------------------------------
# The plan
# --------------------------------------------------------------------------


def _finding_row(finding: Finding, facts: CveFacts, highlight: uuid.UUID | None) -> dict:
    status = facts.status
    if status == "known":
        note = "fixed in " + ", ".join(facts.exact_fixes)
    elif status == "after":
        note = ("no exact fixed version published; the vulnerable range ends at "
                + ", ".join(facts.after) + " inclusive, so the fix is a version after that")
    elif not facts.cve_id:
        note = "not linked to a CVE, so no version data applies"
    elif not facts.ranges and not facts.advisory_fixed:
        note = "no CPE range or advisory fixed version recorded for this product"
    else:
        note = "the published ranges for this product have no upper bound"
    return {
        "finding_id": str(finding.id),
        "cve_id": facts.cve_id,
        "title": finding.title,
        "state": finding.state,
        "severity": finding.severity,
        "risk_score": finding.risk_score,
        "highlighted": highlight is not None and finding.id == highlight,
        "fix_status": status,
        "fixed_versions": facts.exact_fixes,
        "after_versions": facts.after,
        "advisory_fixed_versions": facts.advisory_fixed,
        "unattributed_advisory_versions": facts.unattributed,
        "cpe_ranges": len(facts.ranges),
        "note": note,
    }


def _target_block(version: str, installed: str, fixes: list[str], known: set[str],
                  rules: list[UpgradePathRule]) -> dict:
    return {
        "version": version,
        "step": classify_step(installed, version),
        "fixes": fixes,
        "fixes_all": known.issubset(fixes),
        "path": upgrade_path(installed, version, rules),
    }


def plan_for_installation(
    session: Session,
    organization_id: uuid.UUID,
    installation: AssetProduct,
    *,
    scope: team_scope.TeamScope = team_scope.UNRESTRICTED,
    highlight_finding_id: uuid.UUID | None = None,
) -> dict:
    """The fix plan for one installed product, over its OPEN findings."""
    stmt = select(Finding).where(
        Finding.organization_id == organization_id,
        Finding.asset_product_id == installation.id,
        Finding.state.in_(tuple(OPEN_STATES)),
    )
    # A plan lists findings, so it is a finding read and carries the scope:
    # a finding on a visible asset can still be assigned to another team.
    stmt = team_scope.findings(stmt, scope)
    findings = list(session.execute(
        stmt.order_by(Finding.risk_score.desc().nullslast(), Finding.id)
    ).scalars().all())

    product, vendor, vendor_keys, product_keys = _identity_keys(session, installation.product_id)
    installed = installation.version

    facts_by_cve: dict[str | None, CveFacts] = {}
    rows: list[tuple[Finding, CveFacts]] = []
    for finding in findings:
        vulnerability = session.get(Vulnerability, finding.vulnerability_id)
        cve_id = vulnerability.cve_id if vulnerability is not None else None
        if cve_id not in facts_by_cve:
            facts_by_cve[cve_id] = cve_facts(
                session, cve_id, installation.product_id, vendor_keys, product_keys
            )
        rows.append((finding, facts_by_cve[cve_id]))

    known_ids = {str(f.id) for f, facts in rows if facts.status == "known"}
    installed_known = _known(installed)

    candidates: list[dict] = []
    if installed_known:
        pool = _sorted_unique(v for _, facts in rows for v in facts.exact_fixes)
        for version in pool:
            if compare(version, installed) <= 0:
                continue
            fixes = [str(f.id) for f, facts in rows
                     if facts.status == "known" and facts.fixed_by(version)]
            beyond = [str(f.id) for f, facts in rows
                      if facts.status == "after" and facts.fixed_by(version)]
            candidates.append({
                "version": version,
                "step": classify_step(installed, version),
                "fixes": fixes,
                "fixes_count": len(fixes),
                "fixes_all": bool(known_ids) and known_ids.issubset(fixes),
                "outside_published_range_of": beyond,
            })

    rules = rules_for(session, organization_id, vendor_keys, product_keys)

    best = None
    reason = None
    if not findings:
        reason = "no open findings on this installation"
    elif not installed_known:
        reason = ("the installed version is not recorded, so no upgrade can be "
                  "compared against it")
    elif not known_ids:
        reason = "no open finding on this installation has a known fixed version"
    else:
        winner = next((c for c in candidates if c["fixes_all"]), None)
        if winner is None:
            reason = (f"no single version newer than {installed} fixes all "
                      f"{len(known_ids)} findings that have a known fix; "
                      "see the candidates for partial coverage")
        else:
            best = _target_block(winner["version"], installed, winner["fixes"],
                                 known_ids, rules)

    nearest = None
    installed_branch = branch(installed)
    if installed_branch is not None:
        on_branch = next((c for c in candidates
                          if c["fixes"] and branch(c["version"]) == installed_branch), None)
        if on_branch is not None:
            nearest = _target_block(on_branch["version"], installed, on_branch["fixes"],
                                    known_ids, rules)

    no_fix = [
        _finding_row(f, facts, highlight_finding_id) for f, facts in rows
        if facts.status != "known"
    ]
    ranges_used = sum(len(f.ranges) for f in facts_by_cve.values())
    advisories_used = sum(f.advisories for f in facts_by_cve.values())
    total = len(rows)
    # One fixed sentence shape, not prose that varies with plurals: the console
    # prints it verbatim and an auditor greps for it.
    statement = (
        f"{len(known_ids)} of {total} open findings have a known fixed version; "
        f"computed from {ranges_used} CPE ranges and {advisories_used} advisories"
    )
    finding_ids = {str(f.id) for f in findings}
    return {
        "available": True,
        "asset_id": str(installation.asset_id),
        "asset_product_id": str(installation.id),
        "vendor": vendor.name if vendor else None,
        "product": product.name if product else None,
        "installed_version": installed,
        "raw_version": installation.raw_version,
        "highlight_finding_id": str(highlight_finding_id) if highlight_finding_id else None,
        "highlight_open": (str(highlight_finding_id) in finding_ids)
                          if highlight_finding_id else None,
        "findings": [_finding_row(f, facts, highlight_finding_id) for f, facts in rows],
        "candidates": candidates,
        "best_single_target": best,
        "best_single_target_reason": reason,
        "nearest_on_branch": nearest,
        "no_fix_known": no_fix,
        "rules_considered": len(rules),
        "coverage": {
            "open_findings": total,
            "with_known_fix": len(known_ids),
            "cpe_ranges": ranges_used,
            "advisories": advisories_used,
            "statement": statement,
        },
        "computed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


def plan_for_finding(
    session: Session, finding: Finding, *,
    scope: team_scope.TeamScope = team_scope.UNRESTRICTED,
) -> dict:
    """The plan for the installation this finding sits on, with it highlighted."""
    installation = (session.get(AssetProduct, finding.asset_product_id)
                    if finding.asset_product_id else None)
    if installation is None or installation.organization_id != finding.organization_id:
        return {
            "available": False,
            "finding_id": str(finding.id),
            "reason": ("this finding is not linked to an installed product and version, "
                       "so there is nothing to upgrade from; record the software on the "
                       "asset and re-correlate"),
            "computed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        }
    return plan_for_installation(
        session, finding.organization_id, installation,
        scope=scope, highlight_finding_id=finding.id,
    )


def plans_for_asset(
    session: Session, asset: Asset, *,
    scope: team_scope.TeamScope = team_scope.UNRESTRICTED,
) -> dict:
    """One plan per installed product on the asset that has open findings."""
    installations = session.execute(
        select(AssetProduct).where(
            AssetProduct.organization_id == asset.organization_id,
            AssetProduct.asset_id == asset.id,
        ).order_by(AssetProduct.created_at, AssetProduct.id)
    ).scalars().all()
    plans = []
    for installation in installations:
        plan = plan_for_installation(session, asset.organization_id, installation, scope=scope)
        if plan["coverage"]["open_findings"]:
            plans.append(plan)
    unlinked = team_scope.findings(
        select(Finding.id).where(
            Finding.organization_id == asset.organization_id,
            Finding.asset_id == asset.id,
            Finding.asset_product_id.is_(None),
            Finding.state.in_(tuple(OPEN_STATES)),
        ),
        scope,
    )
    unlinked_count = len(session.execute(unlinked).scalars().all())
    return {
        "asset_id": str(asset.id),
        "plans": plans,
        # Open findings with no installed product behind them (a scanner
        # finding, a manual one). No version plan can cover them, and saying
        # how many there are is what keeps "all fixed by 2.0" honest.
        "unlinked_open_findings": unlinked_count,
        "computed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
    }


__all__ = [
    "MAX_HOPS", "branch", "classify_step", "CveFacts", "cve_facts", "rules_for",
    "rule_covers", "upgrade_path", "plan_for_installation", "plan_for_finding",
    "plans_for_asset",
]
