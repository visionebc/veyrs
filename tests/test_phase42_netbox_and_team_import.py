"""Phase 42 -- NetBox that a tenant can shape, and teams that come from somewhere.

Three things are pinned here, and each exists because the code was wrong in a
way that produced no error:

* **`field_map` reaches NetBox.** It was a live column the NetBox driver never
  read, so `custom_fields.pve_node`, `pve_tags` and `vmid` -- the three fields
  this estate actually added to NetBox -- were discarded on every row.
* **`include_fields` cannot starve the match ladder.** A source narrowed past
  its own match keys stages every host as unmatched, which reads as "the CMDB
  disagrees with the estate" and not as a filter set too tight.
* **A team import never deletes.** Reconciling ownership by deletion means one
  bad bind password detaches every finding and ticket that pointed at a team.
"""
from __future__ import annotations

import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Asset, Team, TeamMember, User
from veyrs.models.cmdb import AssetSource, AssetSourceRecord, MatchStatus
from veyrs.services import cmdb, team_import


def _session(org_id):
    session = SessionLocal()
    set_tenant(session, org_id)
    return session


def _spec(**kwargs):
    kwargs.setdefault("driver", "netbox")
    kwargs.setdefault("base_url", "http://netbox.test")
    kwargs.setdefault("credentials", {"token": "t"})
    kwargs.setdefault("collections", ["dcim.devices"])
    kwargs.setdefault("field_map", {})
    kwargs.setdefault("value_maps", {})
    return cmdb.SourceSpec(**kwargs)


def _device(**over):
    row = {
        "id": 7,
        "name": "hv-4",
        "serial": "SN-7",
        "role": {"slug": "hipervisor"},
        "platform": {"name": "Debian 12"},
        "site": {"name": "Zurich"},
        "tenant": {"name": "Platform"},
        "status": {"value": "active"},
        "primary_ip4": {"address": "10.50.0.51/24"},
        "custom_fields": {"pve_node": "hv-4", "pve_tags": "gpu;prod", "vmid": 360},
        "tags": [{"name": "core"}],
    }
    row.update(over)
    return row


# ---------------------------------------------------------------------------
# The NetBox override layer
# ---------------------------------------------------------------------------
def test_a_source_that_declares_nothing_behaves_exactly_as_before():
    """The override layer must be invisible until somebody uses it."""
    plain = cmdb.netbox_fields("dcim.devices", _device())
    overlaid = cmdb.netbox_overlay("dcim.devices", _device(), _spec())
    assert overlaid == plain
    # and an unknown role still collapses to the documented default
    assert plain["asset_type"] == "server"


def test_a_custom_field_is_reachable_through_field_map():
    fields = cmdb.netbox_overlay(
        "dcim.devices", _device(),
        _spec(field_map={"location": "custom_fields.pve_node"}))
    assert fields["location"] == "hv-4"          # overrode site.name
    assert fields["hostname"] == "hv-4"          # untouched default survives


def test_a_field_veyrs_has_no_column_for_is_kept_under_extra():
    fields = cmdb.netbox_overlay(
        "dcim.devices", _device(),
        _spec(field_map={"extra.vmid": "custom_fields.vmid",
                         "extra.pve_tags": "custom_fields.pve_tags"}))
    assert fields["extra"]["vmid"] == "360"
    assert fields["extra"]["pve_tags"] == "gpu;prod"
    # the prefix is stripped, not carried into the blob as a dotted key
    assert "extra.vmid" not in fields["extra"]


def test_a_declared_path_that_resolves_to_nothing_does_not_erase_the_default():
    """An override layer that blanks a field on a typo is a way to lose every
    hostname in the estate at once."""
    fields = cmdb.netbox_overlay(
        "dcim.devices", _device(),
        _spec(field_map={"hostname": "custom_fields.does_not_exist"}))
    assert fields["hostname"] == "hv-4"


def test_value_maps_decide_the_asset_type_from_the_tenants_own_role_slug():
    fields = cmdb.netbox_overlay(
        "dcim.devices", _device(),
        _spec(value_maps={"asset_type": {"hipervisor": "server"}}))
    assert fields["asset_type"] == "server"
    fields = cmdb.netbox_overlay(
        "dcim.devices", _device(),
        _spec(value_maps={"asset_type": {"hipervisor": "network_device"}}))
    assert fields["asset_type"] == "network_device"


def test_the_role_map_is_read_on_the_raw_slug_not_on_our_derived_value():
    """`hipervisor` has already become `server` by the time the default runs.
    A map keyed on the derived value could only ever say "all unknown roles are
    X", which is not a correction, it is a second default."""
    row = _device(role={"slug": "core-switch"})
    fields = cmdb.netbox_overlay(
        "dcim.devices", row, _spec(value_maps={"asset_type": {"switch": "router"}}))
    assert fields["asset_type"] == "switch", "mapped on the derived value, not the slug"


def test_a_value_map_to_a_type_veyrs_does_not_have_is_ignored_not_written():
    fields = cmdb.netbox_overlay(
        "dcim.devices", _device(),
        _spec(value_maps={"asset_type": {"hipervisor": "hypervisor"}}))
    assert fields["asset_type"] == "server"


def test_a_vm_role_can_still_be_overridden():
    row = _device(role={"slug": "pve-host"})
    fields = cmdb.netbox_overlay(
        "virtualization.virtual-machines", row,
        _spec(value_maps={"asset_type": {"pve-host": "server"}}))
    assert fields["asset_type"] == "server"


def test_netbox_status_is_still_never_an_environment_by_itself():
    fields = cmdb.netbox_fields("dcim.devices", _device())
    assert fields["status_label"] == "active"
    assert "environment" not in fields


def test_but_an_operator_may_say_so_explicitly():
    fields = cmdb.netbox_overlay(
        "dcim.devices", _device(),
        _spec(field_map={"environment": "status.value"},
              value_maps={"environment": {"active": "production"}}))
    assert fields["environment"] == "production"


# ---------------------------------------------------------------------------
# include_fields
# ---------------------------------------------------------------------------
def test_an_empty_allowlist_keeps_everything():
    fields = cmdb.netbox_fields("dcim.devices", _device())
    assert cmdb.apply_include_fields(fields, []) == fields
    assert cmdb.apply_include_fields(fields, None) == fields


def test_the_allowlist_drops_unlisted_fields_and_keeps_extra():
    fields = dict(cmdb.netbox_fields("dcim.devices", _device()))
    fields["extra"] = {"vmid": "360"}
    kept = cmdb.apply_include_fields(fields, ["hostname", "ip_addresses"])
    assert set(kept) == {"hostname", "ip_addresses", "extra"}
    assert kept["extra"] == {"vmid": "360"}


def test_narrow_applies_the_allowlist_over_a_whole_fetch():
    records = [cmdb.SourceRecord(external_key="a", fields={"hostname": "h", "serial": "s"},
                                 raw={})]
    out = cmdb.narrow(records, _spec(include_fields=("hostname",)))
    assert out[0].fields == {"hostname": "h"}
    assert out[0].raw == {}, "raw is the audit trail and is never narrowed"
    assert cmdb.narrow(records, _spec())[0].fields == {"hostname": "h", "serial": "s"}


# ---------------------------------------------------------------------------
# The router refuses the configurations that fail silently
# ---------------------------------------------------------------------------
def _create(client, headers, **over):
    payload = {"slug": f"s-{uuid.uuid4().hex[:8]}", "name": "NetBox",
               "driver": "netbox", "base_url": "http://10.50.0.60",
               "collections": ["dcim.devices"]}
    payload.update(over)
    return client.post("/api/v1/asset-sources", headers=headers, json=payload)


def test_a_field_map_typo_is_still_refused(client, admin_a):
    """The `extra.` escape must not become the place typos land."""
    response = _create(client, admin_a, field_map={"hostnmae": "name"})
    assert response.status_code == 422
    assert "hostnmae" in response.text
    assert "extra.hostnmae" in response.text, "the message must say how to keep it"


def test_an_extra_target_is_accepted(client, admin_a):
    response = _create(client, admin_a, field_map={"extra.vmid": "custom_fields.vmid"})
    assert response.status_code == 201, response.text
    assert response.json()["field_map"] == {"extra.vmid": "custom_fields.vmid"}


def test_include_fields_naming_an_unknown_field_is_refused(client, admin_a):
    response = _create(client, admin_a, include_fields=["hostname", "nonsense"])
    assert response.status_code == 422
    assert "nonsense" in response.text


def test_include_fields_that_starves_the_match_ladder_is_refused(client, admin_a):
    response = _create(client, admin_a, include_fields=["location", "tags"])
    assert response.status_code == 422
    assert "unmatched" in response.text


def test_include_fields_keeping_one_match_key_is_accepted(client, admin_a):
    response = _create(client, admin_a, include_fields=["hostname", "location"])
    assert response.status_code == 201, response.text
    assert response.json()["include_fields"] == ["hostname", "location"]


def test_a_value_map_to_an_illegal_enum_value_is_refused_at_the_form(client, admin_a):
    response = _create(client, admin_a,
                       value_maps={"asset_type": {"pve-host": "hypervisor"}})
    assert response.status_code == 422
    assert "hypervisor" in response.text


def test_a_value_map_on_a_free_text_field_is_not_policed(client, admin_a):
    response = _create(client, admin_a,
                       value_maps={"location": {"ZRH": "Zurich"}})
    assert response.status_code == 201, response.text


def test_include_fields_survives_a_round_trip_through_the_spec(client, admin_a, org_a):
    org_id = org_a[0]
    response = _create(client, admin_a, include_fields=["hostname"])
    source_id = uuid.UUID(response.json()["id"])
    session = _session(org_id)
    try:
        spec = cmdb.spec_for(session.get(AssetSource, source_id))
        assert spec.include_fields == ("hostname",)
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Team import
# ---------------------------------------------------------------------------
def test_slugify_is_not_made_unique_by_appending_a_number():
    assert team_import.slugify("SOC Analysts") == "soc-analysts"
    assert team_import.slugify("SOC  Analysts!") == "soc-analysts"
    assert team_import.slugify("!!!") == ""


def _candidate(name, **over):
    return team_import.Candidate(slug=team_import.slugify(name), name=name, **over)


def test_two_source_rows_with_one_slug_are_reported_not_renumbered(org_a):
    session = _session(org_a[0])
    try:
        outcome = team_import.plan(session, org_a[0],
                                   [_candidate("SOC Analysts"), _candidate("SOC  analysts")])
        actions = [r["action"] for r in outcome["rows"]]
        assert "conflict" in actions
        assert not any(r["slug"].endswith("-2") for r in outcome["rows"])
    finally:
        session.close()


def test_an_import_creates_teams_and_running_it_twice_changes_nothing(org_a):
    org_id = org_a[0]
    session = _session(org_id)
    try:
        cands = [_candidate("Perimeter Net"), _candidate("Web Hosting Net")]
        first = team_import.apply(session, org_id, cands, provider="netbox")
        assert sorted(first["created"]) == ["perimeter-net", "web-hosting-net"]
        session.commit()

        second = team_import.apply(session, org_id, cands, provider="netbox")
        assert second["created"] == []
        assert second["counts"].get("unchanged") == 2
        session.commit()

        rows = session.execute(
            select(Team).where(Team.organization_id == org_id,
                               Team.slug.in_(["perimeter-net", "web-hosting-net"]))
        ).scalars().all()
        assert len(rows) == 2
    finally:
        session.close()


def test_a_team_absent_from_the_source_is_reported_and_left_alone(org_a):
    org_id = org_a[0]
    session = _session(org_id)
    try:
        team_import.apply(session, org_id, [_candidate("Kept By Hand")],
                          provider="ldap")
        session.commit()
        outcome = team_import.apply(session, org_id, [_candidate("Something Else")],
                                    provider="ldap")
        session.commit()
        orphans = [r for r in outcome["rows"] if r["action"] == "orphan"]
        assert any(r["slug"] == "kept-by-hand" for r in orphans)
        survivor = session.execute(
            select(Team).where(Team.organization_id == org_id,
                               Team.slug == "kept-by-hand")).scalar_one_or_none()
        assert survivor is not None, "an import deleted a team"
    finally:
        session.close()


def test_an_import_does_not_rename_an_existing_team_unless_asked(org_a):
    org_id = org_a[0]
    session = _session(org_id)
    try:
        team_import.apply(session, org_id, [_candidate("Renamed Team")], provider="ldap")
        session.commit()
        moved = team_import.Candidate(slug="renamed-team", name="Different Name")
        team_import.apply(session, org_id, [moved], provider="ldap")
        session.commit()
        team = session.execute(
            select(Team).where(Team.organization_id == org_id,
                               Team.slug == "renamed-team")).scalar_one()
        assert team.name == "Renamed Team"

        team_import.apply(session, org_id, [moved], provider="ldap", update_existing=True)
        session.commit()
        session.refresh(team)
        assert team.name == "Different Name"
    finally:
        session.close()


def test_an_import_never_touches_the_escalation_chain_or_the_manager(org_a):
    """No external system knows who gets paged. A sync that reset it would be
    destroying data it has no way to restore."""
    org_id = org_a[0]
    session = _session(org_id)
    try:
        team_import.apply(session, org_id, [_candidate("Paged Team")], provider="ldap")
        session.commit()
        team = session.execute(
            select(Team).where(Team.organization_id == org_id,
                               Team.slug == "paged-team")).scalar_one()
        team.escalation_chain = {"levels": [{"after_minutes": 60, "target": "team"}]}
        session.commit()

        team_import.apply(session, org_id,
                          [team_import.Candidate(slug="paged-team", name="Paged Team v2")],
                          provider="ldap", update_existing=True)
        session.commit()
        session.refresh(team)
        assert team.escalation_chain == {"levels": [{"after_minutes": 60,
                                                     "target": "team"}]}
    finally:
        session.close()


def test_membership_seats_existing_accounts_and_creates_none(org_a):
    org_id = org_a[0]
    session = _session(org_id)
    try:
        existing = session.execute(
            select(User).where(User.organization_id == org_id)).scalars().first()
        assert existing is not None
        handle = (existing.username or existing.email.split("@")[0]).lower()
        before = session.execute(
            select(User).where(User.organization_id == org_id)).scalars().all()

        outcome = team_import.apply(
            session, org_id,
            [team_import.Candidate(slug="dir-team", name="Dir Team",
                                   member_usernames=(handle, "ghost-account"))],
            provider="ldap", import_members=True)
        session.commit()

        assert outcome["members"]["added"] == 1
        assert "ghost-account" in outcome["members"]["unmatched"]
        after = session.execute(
            select(User).where(User.organization_id == org_id)).scalars().all()
        assert len(after) == len(before), "the import created a user account"

        team = session.execute(
            select(Team).where(Team.organization_id == org_id,
                               Team.slug == "dir-team")).scalar_one()
        seats = session.execute(
            select(TeamMember).where(TeamMember.team_id == team.id)).scalars().all()
        assert [s.user_id for s in seats] == [existing.id]
    finally:
        session.close()


# ---------------------------------------------------------------------------
# Assigning assets from the staged label
# ---------------------------------------------------------------------------
def _staged(session, org_id, source, asset, label):
    record = AssetSourceRecord(
        organization_id=org_id, source_id=source.id,
        external_key=f"k-{uuid.uuid4().hex[:8]}", asset_id=asset.id,
        match_status=MatchStatus.MATCHED.value, team_label=label,
        hostname=asset.hostname, name=asset.name,
    )
    session.add(record)
    session.flush()
    return record


def test_assignment_reads_the_staged_label_and_respects_a_hand_assignment(org_a):
    org_id = org_a[0]
    session = _session(org_id)
    try:
        source = AssetSource(organization_id=org_id, slug=f"nb-{uuid.uuid4().hex[:6]}",
                             name="NetBox", driver="netbox",
                             base_url="http://10.50.0.60")
        session.add(source)
        team_import.apply(session, org_id, [_candidate("Platform Team")],
                          provider="netbox")
        session.flush()
        team = session.execute(
            select(Team).where(Team.organization_id == org_id,
                               Team.slug == "platform-team")).scalar_one()
        other = Team(organization_id=org_id, slug=f"other-{uuid.uuid4().hex[:6]}",
                     name="Other", escalation_chain={})
        session.add(other)
        session.flush()

        free = Asset(organization_id=org_id, name="free-host", hostname="free-host")
        taken = Asset(organization_id=org_id, name="taken-host", hostname="taken-host",
                      team_id=other.id)
        unknown = Asset(organization_id=org_id, name="odd-host", hostname="odd-host")
        session.add_all([free, taken, unknown])
        session.flush()
        _staged(session, org_id, source, free, "Platform Team")
        _staged(session, org_id, source, taken, "Platform Team")
        _staged(session, org_id, source, unknown, "Team Nobody Imported")
        session.commit()

        dry = team_import.assign_from_records(session, org_id, source, dry_run=True)
        assert dry["assigned"] == 1
        assert dry["already_assigned_elsewhere"] == 1
        assert "Team Nobody Imported" in dry["unknown_labels"]
        session.refresh(free)
        assert free.team_id is None, "a dry run wrote to the estate"

        real = team_import.assign_from_records(session, org_id, source)
        session.commit()
        assert real["assigned"] == 1
        session.refresh(free)
        session.refresh(taken)
        assert free.team_id == team.id
        assert taken.team_id == other.id, "a hand assignment was overwritten"

        forced = team_import.assign_from_records(session, org_id, source, overwrite=True)
        session.commit()
        session.refresh(taken)
        assert forced["assigned"] == 1
        assert taken.team_id == team.id
    finally:
        session.close()


# ---------------------------------------------------------------------------
# The routes
# ---------------------------------------------------------------------------
def test_the_provider_list_says_why_netbox_is_not_ready(client, admin_a):
    response = client.get("/api/v1/teams/import/providers", headers=admin_a)
    assert response.status_code == 200, response.text
    providers = {p["provider"]: p for p in response.json()}
    assert set(providers) == {"netbox", "ldap"}
    assert providers["netbox"]["ready"] is False
    assert "no NetBox asset source" in providers["netbox"]["detail"]
    assert providers["ldap"]["supports_members"] is True
    assert providers["netbox"]["supports_members"] is False


def test_a_source_without_a_token_is_listed_but_not_ready(client, admin_a):
    """`ready` means readable, not merely configured.

    A NetBox source with no API token answers 403 at fetch time. Reporting it
    as ready sends the operator into a failed run to discover a missing
    credential the server already knew about -- and the run\'s error is a bare
    403 from another system, which reads as "NetBox is broken".
    """
    _create(client, admin_a)
    response = client.get("/api/v1/teams/import/providers", headers=admin_a)
    netbox = {p["provider"]: p for p in response.json()}["netbox"]
    assert netbox["ready"] is False
    assert netbox["sources"], "it must still be LISTED, so the gap is visible"
    assert netbox["sources"][0]["credentials_set"] is False
    assert netbox["sources"][0]["usable"] is False
    assert "no API token" in netbox["detail"], netbox["detail"]


def test_the_provider_list_finds_a_netbox_source_once_one_is_usable(client, admin_a):
    _create(client, admin_a, credentials={"token": "n" * 40})
    response = client.get("/api/v1/teams/import/providers", headers=admin_a)
    netbox = {p["provider"]: p for p in response.json()}["netbox"]
    assert netbox["ready"] is True
    assert netbox["detail"] is None
    assert netbox["sources"][0]["usable"] is True
    assert [c["key"] for c in netbox["collections"]][0] == "tenancy.tenants"


def test_a_disabled_source_is_still_importable(client, admin_a):
    """Importing teams is a READ.

    Requiring `is_enabled` would mean an estate cannot use NetBox as an org
    chart without also putting it on the sync schedule -- the same reasoning
    that keeps the LDAP check off `enabled`.
    """
    _create(client, admin_a, is_enabled=False, credentials={"token": "n" * 40})
    response = client.get("/api/v1/teams/import/providers", headers=admin_a)
    netbox = {p["provider"]: p for p in response.json()}["netbox"]
    assert netbox["ready"] is True
    assert netbox["sources"][0]["is_enabled"] is False


def test_an_unknown_provider_is_refused(client, admin_a):
    response = client.post("/api/v1/teams/import/preview", headers=admin_a,
                           json={"provider": "servicenow"})
    assert response.status_code == 422
    assert "servicenow" in response.text


def test_the_netbox_provider_needs_a_source_and_a_collection(client, admin_a):
    response = client.post("/api/v1/teams/import/preview", headers=admin_a,
                           json={"provider": "netbox"})
    assert response.status_code == 502
    assert "source and a collection" in response.text


def test_a_source_from_another_tenant_is_not_readable(client, admin_a, admin_b):
    created = _create(client, admin_a)
    source_id = created.json()["id"]
    response = client.post("/api/v1/teams/import/preview", headers=admin_b,
                           json={"provider": "netbox", "source_id": source_id,
                                 "collection": "tenancy.tenants"})
    assert response.status_code == 404


def test_the_import_routes_are_not_reachable_as_a_team_id(client, admin_a):
    """`/teams/import` must not be swallowed by `/teams/{team_id}`."""
    response = client.get("/api/v1/teams/import/providers", headers=admin_a)
    assert response.status_code == 200
