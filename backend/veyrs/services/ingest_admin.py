"""`veyrs dedupe ...` -- one-off data migrations of the ingest pipeline.

    veyrs dedupe rehash [--org SLUG] [--apply]
        Re-key findings stored under key revision 1 whose scanner hashes `cve`
        (TD-01; see services/dedupe.py, "Key revision 2").

    veyrs dedupe merge-duplicates [--org SLUG] [--apply]
        Resolve the rows that stop `schema_steps/step_ingest.py` from making
        two unique keys NULLS NOT DISTINCT (TD-33).

Both are dry runs unless `--apply`, print what they would do per organization,
and are idempotent: a second `--apply` finds nothing to do. Each organization
runs in its own tenant-bound session and transaction, because every table
involved is under FORCE ROW LEVEL SECURITY.
"""
from __future__ import annotations

import argparse
import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Finding, Organization, Ticket, Vulnerability
from ..models.integration import ExternalLink
from ..models.risk_register import RiskLink, RiskRaci
from . import dedupe


# ---------------------------------------------------------------------------
# merge-duplicates
# ---------------------------------------------------------------------------
def _legacy_ref(vulnerability: Vulnerability) -> str:
    return vulnerability.cve_id or str(vulnerability.id)


def _move_findings(session: Session, organization_id: uuid.UUID, keeper: Vulnerability,
                   duplicate: Vulnerability, report: dict[str, Any]) -> None:
    """Re-point a duplicate's findings at the keeper, re-keying where needed.

    A `legacy` key hashes `cve_id or str(vulnerability.id)`. For a CVE-backed
    pair that is the same string, so nothing moves; for an internal pair the
    finding would otherwise never match its next import again. A re-key that
    would collide with a finding the keeper already has on that asset is NOT
    made -- that pair is the same issue reported twice, and which one survives
    is triage -- and is listed under `parallel_findings`.
    """
    findings = session.execute(
        select(Finding).where(Finding.organization_id == organization_id,
                              Finding.vulnerability_id == duplicate.id)
    ).scalars().all()
    old_ref, new_ref = _legacy_ref(duplicate), _legacy_ref(keeper)
    for finding in findings:
        finding.vulnerability_id = keeper.id
        report["findings_moved"] += 1
        if finding.dedupe_algorithm != dedupe.LEGACY or old_ref == new_ref:
            continue
        identity = dict(organization_id=organization_id, asset_id=finding.asset_id,
                        port=finding.port, protocol=finding.protocol, path=finding.path)
        if finding.dedupe_key != dedupe.legacy_key(vuln_ref=old_ref, **identity):
            continue  # not keyed on the vulnerability id; nothing to follow
        new_key = dedupe.legacy_key(vuln_ref=new_ref, **identity)
        clash = session.execute(
            select(Finding.id).where(Finding.organization_id == organization_id,
                                     Finding.dedupe_key == new_key,
                                     Finding.id != finding.id)
        ).scalars().first()
        if clash is not None:
            report["parallel_findings"].append(
                {"finding_id": str(finding.id), "same_issue_as": str(clash)})
            continue
        finding.dedupe_key = new_key


def merge_duplicates(session: Session, organization_id: uuid.UUID, *, apply: bool = False
                     ) -> dict[str, Any]:
    """Make this tenant's data satisfy the NULLS NOT DISTINCT keys.

    * `vulnerabilities` rows with the same (cve_id, internal_ref): the oldest
      is kept; findings, tickets, external links and risk-register links of the
      others move to it, then the others are deleted.
    * rows with NEITHER a cve_id nor an internal_ref are not duplicates of each
      other -- they have no identity at all, and no code path creates them
      (fixtures did). They are not merged: every one but the oldest gets
      `internal_ref = 'unidentified:<id>'`, which keeps them apart.
    * `risk_register_raci` seats held twice by the same party: the oldest seat
      is kept (taking the other's note if it had none) and the others deleted.
    """
    report: dict[str, Any] = {
        "apply": apply, "vulnerability_groups": [], "vulnerabilities_removed": 0,
        "unidentified_named": 0, "findings_moved": 0, "parallel_findings": [],
        "raci_seats_removed": 0,
    }

    groups = session.execute(
        select(Vulnerability.cve_id, Vulnerability.internal_ref, func.count())
        .where(Vulnerability.organization_id == organization_id)
        .group_by(Vulnerability.cve_id, Vulnerability.internal_ref)
        .having(func.count() > 1)
    ).all()
    for cve_id, internal_ref, count in groups:
        rows = session.execute(
            select(Vulnerability).where(
                Vulnerability.organization_id == organization_id,
                Vulnerability.cve_id.is_not_distinct_from(cve_id),
                Vulnerability.internal_ref.is_not_distinct_from(internal_ref),
            ).order_by(Vulnerability.created_at, Vulnerability.id)
        ).scalars().all()
        keeper, others = rows[0], rows[1:]
        report["vulnerability_groups"].append({
            "cve_id": cve_id, "internal_ref": internal_ref, "rows": count,
            "keep": str(keeper.id), "others": [str(r.id) for r in others],
            "action": "name" if cve_id is None and internal_ref is None else "merge",
        })
        if cve_id is None and internal_ref is None:
            report["unidentified_named"] += len(others)
            if apply:
                for row in others:
                    row.internal_ref = f"unidentified:{row.id}"
            continue
        report["vulnerabilities_removed"] += len(others)
        if not apply:
            # Count what would move without moving it.
            report["findings_moved"] += session.execute(
                select(func.count()).select_from(Finding).where(
                    Finding.organization_id == organization_id,
                    Finding.vulnerability_id.in_([r.id for r in others]))
            ).scalar_one()
            continue
        for duplicate in others:
            _move_findings(session, organization_id, keeper, duplicate, report)
            for model in (Ticket, ExternalLink):
                for row in session.execute(
                    select(model).where(model.organization_id == organization_id,
                                        model.vulnerability_id == duplicate.id)
                ).scalars().all():
                    row.vulnerability_id = keeper.id
            for link in session.execute(
                select(RiskLink).where(RiskLink.organization_id == organization_id,
                                       RiskLink.object_type == "vulnerability",
                                       RiskLink.object_id == duplicate.id)
            ).scalars().all():
                already = session.execute(
                    select(RiskLink.id).where(RiskLink.risk_id == link.risk_id,
                                              RiskLink.object_type == "vulnerability",
                                              RiskLink.object_id == keeper.id)
                ).scalars().first()
                if already is not None:
                    session.delete(link)
                else:
                    link.object_id = keeper.id
            session.flush()
            session.delete(duplicate)
        session.flush()

    seats = session.execute(
        select(RiskRaci.risk_id, RiskRaci.raci, RiskRaci.team_id, RiskRaci.user_id)
        .where(RiskRaci.organization_id == organization_id)
        .group_by(RiskRaci.risk_id, RiskRaci.raci, RiskRaci.team_id, RiskRaci.user_id)
        .having(func.count() > 1)
    ).all()
    for risk_id, raci, team_id, user_id in seats:
        rows = session.execute(
            select(RiskRaci).where(
                RiskRaci.organization_id == organization_id,
                RiskRaci.risk_id == risk_id, RiskRaci.raci == raci,
                RiskRaci.team_id.is_not_distinct_from(team_id),
                RiskRaci.user_id.is_not_distinct_from(user_id),
            ).order_by(RiskRaci.created_at, RiskRaci.id)
        ).scalars().all()
        keeper, others = rows[0], rows[1:]
        report["raci_seats_removed"] += len(others)
        if apply:
            for row in others:
                if not keeper.note and row.note:
                    keeper.note = row.note
                session.delete(row)
    if apply:
        session.flush()
    return report


# ---------------------------------------------------------------------------
# CLI plumbing (registered from cli.py)
# ---------------------------------------------------------------------------
def add_parsers(sub: argparse._SubParsersAction) -> None:  # noqa: SLF001 - argparse API
    parser = sub.add_parser("dedupe", help="one-off migrations of finding and "
                                           "vulnerability identity (dry run by default)")
    commands = parser.add_subparsers(dest="dedupe_command", required=True)
    rehash = commands.add_parser(
        "rehash", help="re-key SCA findings stored before 0.41.0, whose key ignored the CVE")
    merge = commands.add_parser(
        "merge-duplicates", help="resolve rows that block the NULLS NOT DISTINCT unique keys "
                                 "on vulnerabilities and risk_register_raci")
    for command in (rehash, merge):
        command.add_argument("--org", action="append", metavar="SLUG",
                             help="limit to an organization (repeatable); default: all")
        command.add_argument("--apply", action="store_true",
                             help="write; without it nothing changes")


def run_cli(args: argparse.Namespace) -> int:
    from ..db import SessionLocal, set_tenant

    with SessionLocal() as session:
        stmt = select(Organization.id, Organization.slug).order_by(Organization.slug)
        if args.org:
            stmt = stmt.where(Organization.slug.in_(args.org))
        orgs = session.execute(stmt).all()
    if args.org and len(orgs) != len(set(args.org)):
        missing = sorted(set(args.org) - {slug for _, slug in orgs})
        print(f"no organization with slug(s): {', '.join(missing)}")
        return 1

    mode = "APPLY" if args.apply else "dry run (add --apply to write)"
    print(f"veyrs dedupe {args.dedupe_command}: {mode}")
    for org_id, slug in orgs:
        with SessionLocal() as session:
            set_tenant(session, org_id)
            if args.dedupe_command == "rehash":
                report = dedupe.rehash(session, org_id, apply=args.apply)
                print(f"  {slug:30} {report['rekeyed']:>6} re-keyed  "
                      f"{report['unaffected']:>6} unaffected  "
                      f"{len(report['conflicts']):>4} conflicts")
                for conflict in report["conflicts"][:20]:
                    print(f"      conflict: finding {conflict['finding_id']} -> key already "
                          f"held by {conflict['held_by']} (triage: likely the same issue)")
            else:
                report = merge_duplicates(session, org_id, apply=args.apply)
                print(f"  {slug:30} {report['vulnerabilities_removed']:>4} duplicate "
                      f"vulnerabilities  {report['findings_moved']:>5} findings moved  "
                      f"{report['unidentified_named']:>4} unidentified named  "
                      f"{report['raci_seats_removed']:>3} RACI seats")
                for group in report["vulnerability_groups"][:20]:
                    print(f"      {group['action']}: cve_id={group['cve_id']} "
                          f"internal_ref={group['internal_ref']} x{group['rows']} "
                          f"keep {group['keep']}")
                for pair in report["parallel_findings"][:20]:
                    print(f"      parallel finding {pair['finding_id']} kept beside "
                          f"{pair['same_issue_as']} (triage)")
            if args.apply:
                session.commit()
            else:
                session.rollback()
    return 0


HANDLERS = {"dedupe": run_cli}
