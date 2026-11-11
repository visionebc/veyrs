"""Teams that already exist somewhere else, brought in rather than retyped.

    NetBox tenants / sites / roles  --\\
                                       >-- Candidate[] -- plan() -- apply() -- teams
    LDAP or Active Directory groups --/     (no DB)      (read)     (writes)

Two providers because the answer to "who owns this host" lives in two
different places and neither is wrong:

* **NetBox** already says which *tenant* or *site* a device belongs to, and the
  asset sync stages that answer as `team_label` on every record. Importing the
  tenants themselves turns a label into a Team that findings, SLAs and
  escalation chains can actually hang off.
* **The directory** is where the humans are. An AD group is a team that already
  has the right people in it, maintained by somebody whose job that is.

What this may not do
--------------------
**It never deletes a team.** A team absent from the import is reported as
`orphan` and left alone. The alternative -- reconciling by deletion -- means a
filter typo, an expired bind password or a directory outage silently detaches
every finding, ticket and escalation chain that pointed at it, and nothing on
the screen would say so. Ownership is not a cache.

**It never creates a user.** Membership maps directory accounts to VEYRS
accounts that already exist. Provisioning from the directory is
`jit_provisioning`, which ships off for a reason (see `services/ldap_auth`);
an importer that created accounts as a side effect of importing a team would
be a way around that decision rather than a feature.
"""
from __future__ import annotations

import dataclasses
import logging
import re
import uuid
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import Asset, Team, TeamMember, User
from ..models.cmdb import AssetSource, AssetSourceRecord
from . import audit, ldap_auth
from .cmdb import CmdbError, _client, _json_body, credentials_of

log = logging.getLogger("veyrs.team_import")

PROVIDERS: tuple[str, ...] = ("netbox", "ldap")

#: What in NetBox may stand for a team, and what it is called on screen. A
#: closed map for the same reason `NETBOX_COLLECTIONS` is one: a free-text path
#: that 404s reads to the operator as "NetBox is down".
#:
#: `tenancy.tenants` is first because it is the collection the asset driver
#: already reads into `team_label`, so importing it makes the labels resolve.
NETBOX_TEAM_COLLECTIONS: dict[str, dict[str, str]] = {
    "tenancy.tenants": {"path": "/api/tenancy/tenants/", "label": "Tenants"},
    "dcim.sites": {"path": "/api/dcim/sites/", "label": "Sites"},
    "tenancy.contact-groups": {"path": "/api/tenancy/contact-groups/",
                               "label": "Contact groups"},
    "dcim.device-roles": {"path": "/api/dcim/device-roles/", "label": "Device roles"},
}

MAX_TEAMS = 500
PAGE_SIZE = 200
MAX_PAGES = 20
SLUG_MAX = 80
NAME_MAX = 160


class TeamImportError(RuntimeError):
    """A provider could not be reached, read, or understood."""


@dataclasses.dataclass(frozen=True)
class Candidate:
    """One team a provider reported, before anything has been written."""

    slug: str
    name: str
    description: str | None = None
    email: str | None = None
    #: Where it came from, kept so a second import can tell its own rows from
    #: a team somebody typed by hand.
    external_ref: str | None = None
    member_usernames: tuple[str, ...] = ()


def slugify(value: str) -> str:
    """A team slug from a tenant name or a group CN.

    Not reversible and not meant to be: `teams.slug` is unique per tenant, so
    two directory groups that differ only in punctuation collide -- and that
    collision is REPORTED as a conflict rather than resolved by appending a
    number. A team called `soc-analysts-2` that nobody named is worse than a
    row the operator is asked about.
    """
    text = re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-")
    return text[:SLUG_MAX] or ""


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------
def from_netbox(source: AssetSource, collection: str) -> list[Candidate]:
    """Read one NetBox collection as a list of candidate teams."""
    if source.driver != "netbox":
        raise TeamImportError(
            f"source {source.slug!r} is a {source.driver} source; teams can only "
            "be read from a NetBox source")
    spec = NETBOX_TEAM_COLLECTIONS.get(collection)
    if spec is None:
        raise TeamImportError(
            f"unknown NetBox team collection {collection!r}; expected any of "
            f"{sorted(NETBOX_TEAM_COLLECTIONS)}")
    credentials = credentials_of(source)
    token = credentials.get("token")
    if not token:
        raise TeamImportError("this NetBox source has no API token")

    from .cmdb import spec_for

    headers = {"Authorization": f"Token {token}", "Accept": "application/json"}
    out: list[Candidate] = []
    params: dict[str, Any] = {"limit": PAGE_SIZE, "offset": 0}
    try:
        with _client(spec_for(source)) as client:
            for _ in range(MAX_PAGES):
                body = _json_body(
                    client.get(spec["path"], params=params, headers=headers),
                    f"reading NetBox {collection}")
                rows = (body.get("results") if isinstance(body, dict) else body) or []
                for row in rows:
                    name = (row.get("name") or "").strip()
                    if not name:
                        continue
                    # NetBox has its own slug on most of these. Preferring it
                    # keeps the two systems saying the same word, which is the
                    # entire value of importing rather than retyping.
                    slug = slugify(row.get("slug") or name)
                    if not slug:
                        continue
                    out.append(Candidate(
                        slug=slug,
                        name=name[:NAME_MAX],
                        description=(row.get("description") or "").strip() or None,
                        external_ref=f"netbox:{collection}:{row.get('id')}",
                    ))
                if len(out) >= MAX_TEAMS or not rows:
                    break
                if not (isinstance(body, dict) and body.get("next")):
                    break
                params["offset"] = int(params["offset"]) + PAGE_SIZE
    except CmdbError as exc:
        raise TeamImportError(str(exc)) from exc
    return out[:MAX_TEAMS]


def from_ldap(session: Session, organization_id: uuid.UUID, *,
              with_members: bool = False) -> list[Candidate]:
    """Read the directory's groups as candidate teams."""
    try:
        found = ldap_auth.groups(session, organization_id, with_members=with_members)
    except ldap_auth.LdapError as exc:
        raise TeamImportError(str(exc)) from exc
    out: list[Candidate] = []
    for group in found:
        slug = slugify(group.name)
        if not slug:
            continue
        out.append(Candidate(
            slug=slug,
            name=group.name[:NAME_MAX],
            description=group.description,
            email=group.email,
            external_ref=f"ldap:{group.dn}",
            member_usernames=group.member_usernames,
        ))
    return out


def collect(session: Session, organization_id: uuid.UUID, *, provider: str,
            source: AssetSource | None = None, collection: str | None = None,
            with_members: bool = False) -> list[Candidate]:
    if provider == "netbox":
        if source is None or not collection:
            raise TeamImportError("the netbox provider needs a source and a collection")
        return from_netbox(source, collection)
    if provider == "ldap":
        return from_ldap(session, organization_id, with_members=with_members)
    raise TeamImportError(f"unknown provider {provider!r}; expected one of {list(PROVIDERS)}")


# ---------------------------------------------------------------------------
# Plan and apply
# ---------------------------------------------------------------------------
def plan(session: Session, organization_id: uuid.UUID,
         candidates: Iterable[Candidate]) -> dict[str, Any]:
    """What an import would do. Writes nothing, and is what `apply` reports back.

    The same function backs the preview and the confirmation, so the screen the
    operator approved and the summary they are shown afterwards cannot describe
    two different things.
    """
    existing = {
        t.slug: t for t in session.execute(
            select(Team).where(Team.organization_id == organization_id)
        ).scalars()
    }
    rows: list[dict[str, Any]] = []
    seen: dict[str, Candidate] = {}
    for candidate in candidates:
        if candidate.slug in seen:
            rows.append({
                "slug": candidate.slug, "name": candidate.name, "action": "conflict",
                "detail": f"two source rows resolve to the slug {candidate.slug!r} "
                          f"({seen[candidate.slug].name!r} and {candidate.name!r}); "
                          "rename one of them at the source",
            })
            continue
        seen[candidate.slug] = candidate
        team = existing.get(candidate.slug)
        if team is None:
            rows.append({"slug": candidate.slug, "name": candidate.name,
                         "action": "create", "detail": None})
            continue
        changes = {
            field: getattr(candidate, field)
            for field in ("name", "description", "email")
            if getattr(candidate, field) and getattr(candidate, field) != getattr(team, field)
        }
        rows.append({
            "slug": candidate.slug, "name": candidate.name,
            "action": "update" if changes else "unchanged",
            "team_id": str(team.id),
            "detail": ", ".join(sorted(changes)) or None,
        })
    # Reported, never acted on. See the module docstring.
    for slug, team in sorted(existing.items()):
        if slug not in seen:
            rows.append({"slug": slug, "name": team.name, "action": "orphan",
                         "team_id": str(team.id),
                         "detail": "present in VEYRS, absent from this source; "
                                   "left untouched"})
    counts: dict[str, int] = {}
    for row in rows:
        counts[row["action"]] = counts.get(row["action"], 0) + 1
    return {"rows": rows, "counts": counts, "total": len(rows)}


def apply(session: Session, organization_id: uuid.UUID,
          candidates: Iterable[Candidate], *, provider: str,
          update_existing: bool = False, import_members: bool = False,
          actor_id: uuid.UUID | None = None,
          actor_label: str = "system") -> dict[str, Any]:
    """Create the teams that do not exist. Optionally reconcile the ones that do."""
    candidates = list(candidates)
    outcome = plan(session, organization_id, candidates)
    by_slug = {c.slug: c for c in candidates}
    existing = {
        t.slug: t for t in session.execute(
            select(Team).where(Team.organization_id == organization_id)
        ).scalars()
    }
    created: list[str] = []
    updated: list[str] = []
    for row in outcome["rows"]:
        candidate = by_slug.get(row["slug"])
        if candidate is None or row["action"] in ("orphan", "conflict"):
            continue
        team = existing.get(candidate.slug)
        if team is None:
            team = Team(
                organization_id=organization_id, slug=candidate.slug,
                name=candidate.name, description=candidate.description,
                email=candidate.email, escalation_chain={},
            )
            session.add(team)
            session.flush()
            existing[candidate.slug] = team
            created.append(candidate.slug)
        elif row["action"] == "update" and update_existing:
            # `manager_id`, `department_id` and `escalation_chain` are NEVER
            # touched. They are decisions somebody made inside VEYRS about who
            # gets paged; no external system knows them, so a sync that reset
            # them would be destroying data it cannot restore.
            team.name = candidate.name
            if candidate.description:
                team.description = candidate.description
            if candidate.email:
                team.email = candidate.email
            updated.append(candidate.slug)

    members = _sync_members(session, organization_id, by_slug, existing) \
        if import_members else {"added": 0, "unmatched": []}

    session.flush()
    audit.record(
        session, action="teams.imported", object_type="team",
        object_label=f"{provider}: {len(created)} created, {len(updated)} updated",
        organization_id=organization_id, actor_id=actor_id, actor_label=actor_label,
        changes={"provider": provider, "created": created, "updated": updated,
                 "counts": outcome["counts"], "members_added": members["added"]},
    )
    return {**outcome, "created": created, "updated": updated, "members": members}


def _sync_members(session: Session, organization_id: uuid.UUID,
                  by_slug: dict[str, Candidate],
                  teams: dict[str, Team]) -> dict[str, Any]:
    """Seat directory accounts on their team, where the account already exists.

    Matched on `username` first and `email` second, both lowercased -- the two
    identifiers `POST /auth/login` already accepts, so a person is seated under
    the same name they sign in with. Nobody is ever REMOVED from a team here:
    a person taken out of a group has usually changed job, not stopped owning
    the tickets already assigned to them.
    """
    wanted: dict[str, set[uuid.UUID]] = {}
    unmatched: list[str] = []
    lookup: dict[str, uuid.UUID] = {}
    for user in session.execute(
        select(User).where(User.organization_id == organization_id)
    ).scalars():
        if user.username:
            lookup[user.username.lower()] = user.id
        if user.email:
            lookup.setdefault(user.email.lower(), user.id)
            lookup.setdefault(user.email.lower().split("@")[0], user.id)

    for slug, candidate in by_slug.items():
        team = teams.get(slug)
        if team is None or not candidate.member_usernames:
            continue
        for name in candidate.member_usernames:
            user_id = lookup.get(name.lower())
            if user_id is None:
                if name not in unmatched:
                    unmatched.append(name)
                continue
            wanted.setdefault(slug, set()).add(user_id)

    added = 0
    for slug, user_ids in wanted.items():
        team = teams[slug]
        present = {
            m.user_id for m in session.execute(
                select(TeamMember).where(TeamMember.team_id == team.id)
            ).scalars()
        }
        for user_id in user_ids - present:
            session.add(TeamMember(organization_id=organization_id, team_id=team.id,
                                   user_id=user_id, role_in_team="member"))
            added += 1
    return {"added": added, "unmatched": unmatched[:50],
            "unmatched_total": len(unmatched)}


# ---------------------------------------------------------------------------
# Assigning assets to the teams that were just imported
# ---------------------------------------------------------------------------
def assign_from_records(session: Session, organization_id: uuid.UUID,
                        source: AssetSource, *, dry_run: bool = False,
                        overwrite: bool = False,
                        actor_id: uuid.UUID | None = None,
                        actor_label: str = "system") -> dict[str, Any]:
    """Point matched assets at the team their staged `team_label` names.

    Reads the STAGING rows, not the source: the label was captured by a sync
    that already happened, so this cannot disagree with what the operator
    reviewed, and it works while NetBox is unreachable.

    `Asset.team_id` is not in `PROMOTABLE_FIELDS` and this is not promotion --
    promotion copies description, this re-parents a host. It is a separate,
    explicitly-asked-for act, and `overwrite` is off so an asset somebody
    already assigned by hand keeps that assignment.
    """
    teams = {
        t.slug: t for t in session.execute(
            select(Team).where(Team.organization_id == organization_id)
        ).scalars()
    }
    by_name = {t.name.strip().lower(): t for t in teams.values()}
    records = session.execute(
        select(AssetSourceRecord).where(
            AssetSourceRecord.organization_id == organization_id,
            AssetSourceRecord.source_id == source.id,
            AssetSourceRecord.asset_id.isnot(None),
            AssetSourceRecord.team_label.isnot(None),
        )
    ).scalars().all()

    assigned = 0
    skipped_assigned = 0
    unknown_labels: list[str] = []
    for record in records:
        label = (record.team_label or "").strip()
        team = by_name.get(label.lower()) or teams.get(slugify(label))
        if team is None:
            if label and label not in unknown_labels:
                unknown_labels.append(label)
            continue
        asset = session.get(Asset, record.asset_id)
        if asset is None or asset.organization_id != organization_id:
            continue
        if asset.team_id == team.id:
            continue
        if asset.team_id is not None and not overwrite:
            skipped_assigned += 1
            continue
        if not dry_run:
            asset.team_id = team.id
        assigned += 1

    result = {
        "records": len(records), "assigned": assigned,
        "already_assigned_elsewhere": skipped_assigned,
        "unknown_labels": unknown_labels[:50],
        "unknown_labels_total": len(unknown_labels),
        "dry_run": dry_run,
    }
    if not dry_run and assigned:
        session.flush()
        audit.record(
            session, action="teams.assets_assigned", object_type="asset_source",
            object_id=source.id, object_label=source.slug,
            organization_id=organization_id, actor_id=actor_id,
            actor_label=actor_label, changes=result,
        )
    return result


def available(session: Session, organization_id: uuid.UUID) -> list[dict[str, Any]]:
    """What the console renders in the provider picker, and why one is greyed out."""
    sources = session.execute(
        select(AssetSource).where(
            AssetSource.organization_id == organization_id,
            AssetSource.driver == "netbox",
        ).order_by(AssetSource.name)
    ).scalars().all()
    ldap_state = ldap_auth.state(session, organization_id)
    team_count = session.execute(
        select(func.count(Team.id)).where(Team.organization_id == organization_id)
    ).scalar_one()
    # `ready` must mean "this can be read RIGHT NOW", not "a row exists". A
    # source with no API token answers 403 at fetch time, so a picker that
    # offers it sends the operator into a failed run to discover a missing
    # credential the server already knew about. `is_enabled` is deliberately
    # NOT part of it, for the same reason it is not part of the LDAP check
    # below: importing teams is a READ, and an estate may want the org chart
    # without also putting the source on the sync schedule.
    usable = [s for s in sources if s.credentials_enc and (s.base_url or "").strip()]
    return [
        {
            "provider": "netbox",
            "label": "NetBox",
            "ready": bool(usable),
            "detail": _netbox_detail(sources, usable),
            "sources": [{"id": str(s.id), "slug": s.slug, "name": s.name,
                         "is_enabled": s.is_enabled,
                         "credentials_set": bool(s.credentials_enc),
                         "usable": s in usable} for s in sources],
            "collections": [{"key": k, "label": v["label"]}
                            for k, v in NETBOX_TEAM_COLLECTIONS.items()],
            "supports_members": False,
            "member_detail": "NetBox holds no accounts VEYRS can seat on a team",
            "existing_teams": team_count,
        },
        {
            "provider": "ldap",
            "label": "LDAP / Active Directory",
            "ready": bool(ldap_state.get("library_available") and ldap_state.get("host")),
            "detail": _ldap_detail(ldap_state),
            "sources": [],
            "collections": [],
            "supports_members": True,
            "member_detail": "seats accounts that already exist in VEYRS; "
                             "it never creates one",
            "existing_teams": team_count,
        },
    ]


def _netbox_detail(sources: list, usable: list) -> str | None:
    """Name the reason a NetBox import cannot run, rather than just refusing."""
    if not sources:
        return "no NetBox asset source is configured on this tenant"
    if usable:
        return None
    without_token = [s.name for s in sources if not s.credentials_enc]
    if without_token:
        return ("no API token on %s; add one under Administration -> Asset "
                "sources (NetBox answers 403 without it)" % ", ".join(without_token))
    return "no base URL on the configured NetBox source"


def _ldap_detail(state: dict[str, Any]) -> str | None:
    if not state.get("library_available"):
        return "the `ldap3` package is not installed on this node"
    if not state.get("host"):
        return "no directory is configured; set one under Administration -> Directory"
    if not state.get("enabled"):
        # Importing teams is a READ. Requiring the directory to be enabled for
        # sign-in first would mean an estate cannot use AD as an org chart
        # without also handing it the login page.
        return "the directory is configured but not enabled for sign-in; "\
               "importing teams reads it either way"
    return None
