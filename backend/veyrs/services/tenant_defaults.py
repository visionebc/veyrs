"""Built-in defaults every tenant needs on day one.

Until 0.41.0 `seed_policies` and `seed_profiles` were only called from tests, so
a tenant created by `bootstrap` had no SLA policy (no due dates, no escalation)
and no risk profile (the engine silently fell back to default weights). Both
are seeded when an organization is created and, for tenants that already
exist, by `veyrs seed-defaults --org <slug> --apply`.

Seeding is strictly additive: it creates the built-ins a tenant is missing and
never edits a row that exists. Rows are matched by slug.
"""
from __future__ import annotations

import uuid

from sqlalchemy.orm import Session

from . import risk as risk_service
from . import sla as sla_service


def missing(session: Session, organization_id: uuid.UUID) -> dict[str, list[str]]:
    """What `seed` would add, without adding it."""
    policies = sla_service.missing_builtin_policies(session, organization_id)
    return {
        "sla_policies": policies["sla"],
        "escalation_policies": policies["escalation"],
        "risk_profiles": risk_service.missing_builtin_profiles(session, organization_id),
    }


def seed(session: Session, organization_id: uuid.UUID) -> dict[str, int]:
    created = sla_service.seed_policies(session, organization_id)
    return {
        "sla_policies": created["sla"],
        "escalation_policies": created["escalation"],
        "risk_profiles": risk_service.seed_profiles(session, organization_id),
    }


def run_cli(org_slug: str, *, apply: bool) -> int:
    """`python -m veyrs seed-defaults --org <slug> [--apply]`."""
    from sqlalchemy import select

    from ..db import SessionLocal, set_tenant
    from ..models import Organization

    with SessionLocal() as session:
        org = session.execute(
            select(Organization).where(Organization.slug == org_slug)
        ).scalar_one_or_none()
        if org is None:
            print(f"no organization with slug {org_slug!r}")
            return 1
        set_tenant(session, org.id)
        gap = missing(session, org.id)
        total = sum(len(v) for v in gap.values())
        for kind, slugs in gap.items():
            print(f"{org.slug}: {kind}: missing {slugs or 'none'}")
        if not total:
            print(f"{org.slug}: nothing to add")
            return 0
        if not apply:
            print(f"{org.slug}: dry run - re-run with --apply to add {total} built-in row(s)")
            return 0
        created = seed(session, org.id)
        session.commit()
        print(f"{org.slug}: added {created}")
    return 0
