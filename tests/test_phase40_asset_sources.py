"""Phase 40 -- external asset sources: CMDB export, generic JSON API, NetBox.

The invariant every test here exists to protect: **a sync writes staging rows
and never writes to `assets`.** That is what makes a comparative between two
sources possible at all -- `inventory.upsert_asset` overwrites, so two feeds
importing directly would leave one value and nothing to compare.
"""
from __future__ import annotations

import io
import json
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Asset
from veyrs.models.cmdb import AssetSource, AssetSourceRecord, MatchStatus
from veyrs.services import cmdb


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _session(org_id):
    session = SessionLocal()
    set_tenant(session, org_id)
    return session


def _source(session, org_id, *, slug=None, driver="file", **kwargs):
    kwargs.setdefault("is_enabled", True)
    kwargs.setdefault("field_map", {"hostname": "host", "ip_addresses": "ip"})
    source = AssetSource(
        organization_id=org_id,
        slug=slug or f"src-{uuid.uuid4().hex[:8]}",
        name="Test source",
        driver=driver,
        **kwargs,
    )
    session.add(source)
    session.flush()
    return source


def _record(key, **fields):
    return cmdb.SourceRecord(external_key=key, fields=fields, raw=dict(fields))


# ---------------------------------------------------------------------------
# normalisation
# ---------------------------------------------------------------------------
def test_dig_walks_dots_and_indices():
    payload = {"a": {"b": [{"c": "found"}]}}
    assert cmdb.dig(payload, "a.b[0].c") == "found"
    assert cmdb.dig(payload, "a.b[9].c") is None
    assert cmdb.dig(payload, "a.missing.c") is None


def test_an_ip_loses_the_cidr_mask_a_network_source_appends():
    """Otherwise every NetBox-vs-CMDB row reads as a conflict on the IP."""
    fields, _ = cmdb.normalize({"ip": "10.50.0.23/24"}, {"ip_addresses": "ip"}, {})
    assert fields["ip_addresses"] == ["10.50.0.23"]


def test_a_value_that_is_not_an_ip_is_dropped_not_stored():
    fields, _ = cmdb.normalize({"ip": "not-an-address"}, {"ip_addresses": "ip"}, {})
    assert fields["ip_addresses"] == []


def test_macs_are_normalised_to_one_spelling():
    fields, _ = cmdb.normalize({"m": "AA-BB-CC-DD-EE-FF"}, {"mac_addresses": "m"}, {})
    assert fields["mac_addresses"] == ["aa:bb:cc:dd:ee:ff"]


def test_an_unknown_enum_value_is_reported_and_kept_never_guessed():
    """A CMDB that says PRD and an import that guesses production agree by luck."""
    fields, complaints = cmdb.normalize({"env": "PRD"}, {"environment": "env"}, {})
    assert "environment" not in fields
    assert fields["extra"]["unmapped"]["environment"] == "PRD"
    assert complaints and "value_maps" in complaints[0]


def test_value_maps_are_how_a_tenants_vocabulary_is_translated():
    fields, complaints = cmdb.normalize(
        {"env": "PRD"}, {"environment": "env"}, {"environment": {"PRD": "production"}})
    assert fields["environment"] == "production"
    assert complaints == []


def test_identity_prefers_the_serial_then_falls_down_the_ladder():
    key, keys = cmdb.identity_of({"serial": "ABC123", "hostname": "web01",
                                  "ip_addresses": ["10.0.0.1"]})
    assert key == "serial:abc123"
    assert "hostname:web01" in keys and "ip:10.0.0.1" in keys


def test_a_row_with_no_identifier_at_all_has_no_key():
    assert cmdb.identity_of({"location": "Rack 4"}) == (None, [])


# ---------------------------------------------------------------------------
# the file driver
# ---------------------------------------------------------------------------
def test_csv_is_read_with_its_own_delimiter():
    rows = cmdb.FileDriver().rows(
        b"host;ip\nweb01;10.0.0.1\n", "cmdb.csv",
        cmdb.SourceSpec("file", "", {}, [], {}, {}))
    assert rows == [{"host": "web01", "ip": "10.0.0.1"}]


def test_json_export_is_found_under_a_wrapper_key():
    blob = json.dumps({"result": {"items": [{"host": "web01"}]}}).encode()
    rows = cmdb.FileDriver().rows(
        blob, "cmdb.json",
        cmdb.SourceSpec("file", "", {}, [], {}, {}, record_path="result.items"))
    assert rows == [{"host": "web01"}]


def test_an_export_with_no_header_is_refused_rather_than_mapped_blindly():
    with pytest.raises(cmdb.CmdbError):
        cmdb.FileDriver().rows(b"", "cmdb.csv", cmdb.SourceSpec("file", "", {}, [], {}, {}))


def test_the_external_key_never_falls_back_to_the_row_number():
    """A re-export with one row inserted at the top would renumber the estate,
    and the next sync would report every host as new AND as absent."""
    spec = cmdb.SourceSpec("file", "", {}, [], {"location": "loc"}, {})
    assert cmdb._record_from_row({"loc": "Rack 4"}, spec, collection="", position=7) is None


def test_an_upload_fed_source_refuses_to_be_fetched():
    with pytest.raises(cmdb.CmdbError) as exc:
        cmdb.FileDriver().fetch(cmdb.SourceSpec("file", "", {}, [], {}, {}))
    assert "upload" in str(exc.value)


# ---------------------------------------------------------------------------
# the NetBox driver
# ---------------------------------------------------------------------------
NETBOX_DEVICE = {
    "id": 42, "name": "fw01", "serial": "FGT-9001",
    "device_type": {"model": "FortiGate 60F", "manufacturer": {"name": "Fortinet"}},
    "role": {"slug": "firewall"}, "platform": {"name": "FortiOS"},
    "site": {"name": "hv-4"}, "tenant": {"name": "Vision EBC"},
    "status": {"value": "active"},
    "primary_ip4": {"address": "10.0.0.1/24"},
    "tags": [{"name": "core"}],
}


def test_netbox_devices_need_no_hand_written_field_map():
    fields = cmdb.netbox_fields("dcim.devices", NETBOX_DEVICE)
    assert fields["hostname"] == "fw01"
    assert fields["serial"] == "FGT-9001"
    assert fields["asset_type"] == "firewall"
    assert fields["ip_addresses"] == ["10.0.0.1"]
    assert fields["operating_system"] == "FortiOS"
    assert fields["extra"]["hardware_model"] == "Fortinet FortiGate 60F"


def test_netbox_status_is_a_lifecycle_and_is_never_read_as_an_environment():
    """`active` says the device is racked, not that it serves production."""
    fields = cmdb.netbox_fields("dcim.devices", NETBOX_DEVICE)
    assert fields["status_label"] == "active"
    assert "environment" not in fields


def test_a_netbox_vm_is_typed_as_a_vm_whatever_its_role():
    fields = cmdb.netbox_fields("virtualization.virtual-machines",
                                {"id": 7, "name": "vm01", "role": {"slug": "firewall"}})
    assert fields["asset_type"] == "vm"


def test_an_unknown_netbox_collection_is_refused_not_requested():
    source = AssetSource(organization_id=uuid.uuid4(), slug="nb", name="nb",
                         driver="netbox", base_url="http://x", is_enabled=True,
                         collections=["dcim.racks"])
    with pytest.raises(cmdb.CmdbError) as exc:
        cmdb.NetBoxDriver().fetch(cmdb.spec_for(source))
    assert "dcim.racks" in str(exc.value)


# ---------------------------------------------------------------------------
# sync -- what it writes, and what it must not
# ---------------------------------------------------------------------------
def test_a_disabled_source_refuses_to_run(org_a):
    org_id, _, _ = org_a
    with _session(org_id) as session:
        source = _source(session, org_id, is_enabled=False)
        with pytest.raises(cmdb.CmdbError) as exc:
            cmdb.sync(session, source, records=[_record("k", hostname="web01")])
        assert "disabled" in str(exc.value)


def test_a_sync_stages_the_record_and_writes_no_asset(org_a):
    org_id, _, _ = org_a
    with _session(org_id) as session:
        before = session.execute(
            select(Asset).where(Asset.organization_id == org_id)).scalars().all()
        source = _source(session, org_id)
        run = cmdb.sync(session, source, records=[_record("k1", hostname="web01")])
        session.commit()
        after = session.execute(
            select(Asset).where(Asset.organization_id == org_id)).scalars().all()
        assert run.records_created == 1
        assert run.assets_unmatched == 1
        assert len(after) == len(before), "a sync must never write to the asset register"


def test_a_dry_run_writes_nothing_at_all(org_a):
    org_id, _, _ = org_a
    with _session(org_id) as session:
        source = _source(session, org_id)
        run = cmdb.sync(session, source, records=[_record("k1", hostname="web01")],
                        dry_run=True)
        session.commit()
        rows = session.execute(select(AssetSourceRecord).where(
            AssetSourceRecord.source_id == source.id)).scalars().all()
        assert run.records_created == 1 and run.status == "preview"
        assert rows == []


def test_an_unchanged_record_is_counted_apart_from_an_updated_one(org_a):
    """A nightly sync that changes nothing must say so, not report 4000 updates."""
    org_id, _, _ = org_a
    with _session(org_id) as session:
        source = _source(session, org_id)
        cmdb.sync(session, source, records=[_record("k1", hostname="web01")])
        session.commit()
        run = cmdb.sync(session, source, records=[_record("k1", hostname="web01")])
        session.commit()
        assert run.records_unchanged == 1
        assert run.records_created == 0 and run.records_updated == 0


def test_a_record_the_source_stops_reporting_never_touches_its_asset(org_a):
    org_id, _, _ = org_a
    with _session(org_id) as session:
        asset = Asset(organization_id=org_id, name="web01", hostname="web01")
        session.add(asset)
        source = _source(session, org_id)
        cmdb.sync(session, source, records=[_record("k1", hostname="web01")])
        session.commit()
        run = cmdb.sync(session, source, records=[])
        session.commit()
        row = session.execute(select(AssetSourceRecord).where(
            AssetSourceRecord.source_id == source.id)).scalar_one()
        session.refresh(asset)
        assert run.records_absent == 1 and row.is_absent is True
        assert asset.is_active is True and asset.deleted_at is None


def test_an_upload_does_not_declare_the_rest_of_the_estate_absent(org_a):
    """An operator uploading a filtered extract has not said the rest is gone."""
    org_id, _, _ = org_a
    with _session(org_id) as session:
        source = _source(session, org_id, field_map={"hostname": "host"})
        cmdb.sync(session, source, records=[_record("k1", hostname="web01")])
        session.commit()
        run = cmdb.sync(session, source, blob=b"host\nweb02\n", filename="x.csv",
                        trigger="upload")
        session.commit()
        assert run.records_absent == 0


def test_the_ladder_records_which_rung_matched(org_a):
    org_id, _, _ = org_a
    with _session(org_id) as session:
        session.add(Asset(organization_id=org_id, name="Web One", hostname="web01"))
        source = _source(session, org_id, match_order=["fqdn", "hostname", "name"])
        cmdb.sync(session, source, records=[_record("k1", hostname="WEB01")])
        session.commit()
        row = session.execute(select(AssetSourceRecord).where(
            AssetSourceRecord.source_id == source.id)).scalar_one()
        assert row.matched_by == "hostname"
        assert row.match_status == MatchStatus.MATCHED.value


def test_two_sources_that_share_no_top_key_still_find_each_other(org_a):
    """A serial-keyed CMDB row and an IP-keyed network row are one host."""
    org_id, _, _ = org_a
    with _session(org_id) as session:
        cmdb_src = _source(session, org_id, slug=f"cmdb-{uuid.uuid4().hex[:6]}")
        netbox_src = _source(session, org_id, slug=f"nb-{uuid.uuid4().hex[:6]}")
        cmdb.sync(session, cmdb_src,
                  records=[_record("c1", serial="S1", hostname="web01")])
        cmdb.sync(session, netbox_src,
                  records=[_record("n1", hostname="web01", ip_addresses=["10.0.0.9"])])
        session.commit()
        rows = session.execute(select(AssetSourceRecord).where(
            AssetSourceRecord.organization_id == org_id,
            AssetSourceRecord.source_id.in_([cmdb_src.id, netbox_src.id]),
        )).scalars().all()
        assert len({r.identity_key for r in rows}) == 1


# ---------------------------------------------------------------------------
# the comparative
# ---------------------------------------------------------------------------
def _two_sources(session, org_id, left_fields, right_fields, **source_kwargs):
    left = _source(session, org_id, slug=f"left-{uuid.uuid4().hex[:6]}", **source_kwargs)
    right = _source(session, org_id, slug=f"right-{uuid.uuid4().hex[:6]}")
    cmdb.sync(session, left, records=[_record("l1", **left_fields)])
    cmdb.sync(session, right, records=[_record("r1", **right_fields)])
    session.commit()
    return left, right


def test_a_disagreement_between_two_sources_is_one_row(org_a):
    org_id, _, _ = org_a
    with _session(org_id) as session:
        left, right = _two_sources(
            session, org_id,
            {"serial": "S1", "location": "Zurich"},
            {"serial": "S1", "location": "Geneva"})
        report = cmdb.compare(session, org_id, source_ids=[left.id, right.id])
        assert report["groups_with_conflicts"] == 1
        assert set(report["groups"][0]["conflicts"]["location"].values()) == {
            "Zurich", "Geneva"}


def test_the_same_ips_in_a_different_order_are_not_a_conflict(org_a):
    org_id, _, _ = org_a
    with _session(org_id) as session:
        left, right = _two_sources(
            session, org_id,
            {"serial": "S2", "ip_addresses": ["10.0.0.1", "10.0.0.2"]},
            {"serial": "S2", "ip_addresses": ["10.0.0.2", "10.0.0.1"]})
        report = cmdb.compare(session, org_id, source_ids=[left.id, right.id])
        assert report["groups_with_conflicts"] == 0


def test_a_field_only_one_source_knows_is_not_a_conflict(org_a):
    """Silence is not disagreement; reporting it as one buries the real ones."""
    org_id, _, _ = org_a
    with _session(org_id) as session:
        left, right = _two_sources(session, org_id,
                                   {"serial": "S3", "location": "Zurich"},
                                   {"serial": "S3"})
        report = cmdb.compare(session, org_id, source_ids=[left.id, right.id])
        assert report["groups_with_conflicts"] == 0


def test_a_host_one_source_has_never_heard_of_is_a_gap(org_a):
    org_id, _, _ = org_a
    with _session(org_id) as session:
        left, right = _two_sources(session, org_id, {"serial": "S4"}, {"serial": "S5"})
        report = cmdb.compare(session, org_id, source_ids=[left.id, right.id],
                              mode="gaps")
        assert report["groups_with_gaps"] == 2
        assert all(group["missing_from"] for group in report["groups"])


def test_the_comparative_works_before_anything_has_been_promoted(org_a):
    """The case an operator most wants to see is two feeds into an empty estate."""
    org_id, _, _ = org_a
    with _session(org_id) as session:
        left, right = _two_sources(session, org_id,
                                   {"serial": "S6", "location": "A"},
                                   {"serial": "S6", "location": "B"})
        report = cmdb.compare(session, org_id, source_ids=[left.id, right.id])
        assert report["groups"][0]["asset_id"] is None
        assert report["groups_with_conflicts"] == 1


def test_an_ignored_record_leaves_the_comparative(org_a):
    org_id, _, _ = org_a
    with _session(org_id) as session:
        left, right = _two_sources(session, org_id,
                                   {"serial": "S7", "location": "A"},
                                   {"serial": "S7", "location": "B"})
        row = session.execute(select(AssetSourceRecord).where(
            AssetSourceRecord.source_id == right.id)).scalar_one()
        row.match_status = MatchStatus.IGNORED.value
        session.commit()
        report = cmdb.compare(session, org_id, source_ids=[left.id, right.id])
        assert report["groups_with_conflicts"] == 0


# ---------------------------------------------------------------------------
# promotion
# ---------------------------------------------------------------------------
def test_promotion_declines_to_invent_an_asset_by_default(org_a):
    org_id, _, _ = org_a
    with _session(org_id) as session:
        source = _source(session, org_id)
        cmdb.sync(session, source, records=[_record("k1", hostname="ghost01")])
        session.commit()
        row = session.execute(select(AssetSourceRecord).where(
            AssetSourceRecord.source_id == source.id)).scalar_one()
        result = cmdb.promote(session, org_id, [row.id])
        session.commit()
        assert result == {"promoted": 0, "created": 0, "declined": 1, "requested": 1}


def test_promotion_creates_the_asset_when_asked_to(org_a):
    org_id, _, _ = org_a
    with _session(org_id) as session:
        source = _source(session, org_id)
        cmdb.sync(session, source, records=[
            _record("k1", name="ghost01", hostname="ghost01", serial="SER-1")])
        session.commit()
        row = session.execute(select(AssetSourceRecord).where(
            AssetSourceRecord.source_id == source.id)).scalar_one()
        result = cmdb.promote(session, org_id, [row.id], create_assets=True)
        session.commit()
        asset = session.execute(select(Asset).where(
            Asset.organization_id == org_id, Asset.hostname == "ghost01")).scalar_one()
        assert result["created"] == 1
        assert asset.attributes["serial"] == "SER-1"
        assert asset.attributes["sources"][source.slug] == "k1"


def test_the_lower_priority_number_is_the_one_whose_value_survives(org_a):
    """Otherwise precedence means 'whichever source synced last'."""
    org_id, _, _ = org_a
    with _session(org_id) as session:
        asset = Asset(organization_id=org_id, name="web01", hostname="web01")
        session.add(asset)
        authoritative = _source(session, org_id, slug=f"auth-{uuid.uuid4().hex[:6]}",
                                priority=10)
        secondary = _source(session, org_id, slug=f"sec-{uuid.uuid4().hex[:6]}",
                            priority=90)
        cmdb.sync(session, authoritative,
                  records=[_record("a1", hostname="web01", location="Zurich")])
        cmdb.sync(session, secondary,
                  records=[_record("b1", hostname="web01", location="Geneva")])
        session.commit()
        rows = session.execute(select(AssetSourceRecord).where(
            AssetSourceRecord.organization_id == org_id,
            AssetSourceRecord.source_id.in_([authoritative.id, secondary.id]),
        )).scalars().all()
        cmdb.promote(session, org_id, [r.id for r in rows])
        session.commit()
        session.refresh(asset)
        assert asset.location == "Zurich"


def test_auto_promote_is_off_by_default(org_a):
    org_id, _, _ = org_a
    with _session(org_id) as session:
        source = _source(session, org_id)
        assert source.auto_promote is False
        assert source.promote_creates_assets is False


# ---------------------------------------------------------------------------
# the API
# ---------------------------------------------------------------------------
def test_the_drivers_endpoint_names_all_three(client, admin_a):
    body = client.get("/api/v1/asset-sources/drivers", headers=admin_a).json()
    assert {d["driver"] for d in body["drivers"]} == {"file", "http_json", "netbox"}
    assert [d for d in body["drivers"] if d["driver"] == "netbox"][0][
        "needs_field_map"] is False


def test_a_source_is_created_disabled_and_never_echoes_its_credentials(client, admin_a):
    response = client.post("/api/v1/asset-sources", headers=admin_a, json={
        "slug": "netbox", "name": "NetBox", "driver": "netbox",
        "base_url": "http://10.50.0.60", "collections": ["dcim.devices"],
        "credentials": {"token": "super-secret-token"},
    })
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["is_enabled"] is False
    assert body["credentials_set"] is True
    assert "super-secret-token" not in response.text
    assert "credentials" not in body


def test_a_field_map_targeting_a_field_veyrs_does_not_have_is_refused(client, admin_a):
    response = client.post("/api/v1/asset-sources", headers=admin_a, json={
        "slug": "cmdb", "name": "CMDB", "driver": "file",
        "field_map": {"hostnmae": "Host"},
    })
    assert response.status_code == 422
    assert "hostnmae" in response.text


def test_an_unknown_netbox_collection_is_refused_at_the_router(client, admin_a):
    response = client.post("/api/v1/asset-sources", headers=admin_a, json={
        "slug": "nb2", "name": "NetBox", "driver": "netbox",
        "base_url": "http://10.50.0.60", "collections": ["dcim.racks"],
    })
    assert response.status_code == 422


def test_a_source_with_no_collections_reports_itself_inert(client, admin_a):
    created = client.post("/api/v1/asset-sources", headers=admin_a, json={
        "slug": "nb3", "name": "NetBox", "driver": "netbox",
        "base_url": "http://10.50.0.60",
    }).json()
    assert created["is_inert"] is True


def test_a_slug_is_unique_within_a_tenant(client, admin_a):
    payload = {"slug": "dup", "name": "One", "driver": "file",
               "field_map": {"hostname": "Host"}}
    assert client.post("/api/v1/asset-sources", headers=admin_a,
                       json=payload).status_code == 201
    assert client.post("/api/v1/asset-sources", headers=admin_a,
                       json=payload).status_code == 409


def test_another_tenant_cannot_read_this_ones_source(client, admin_a, admin_b):
    created = client.post("/api/v1/asset-sources", headers=admin_a, json={
        "slug": "private", "name": "Private", "driver": "file",
        "field_map": {"hostname": "Host"}}).json()
    assert client.get(f"/api/v1/asset-sources/{created['id']}",
                      headers=admin_b).status_code == 404


def test_a_fetching_source_cannot_be_created_without_a_base_url(client, admin_a):
    response = client.post("/api/v1/asset-sources", headers=admin_a, json={
        "slug": "nb4", "name": "NetBox", "driver": "netbox",
        "collections": ["dcim.devices"]})
    assert response.status_code == 422


def test_an_upload_source_cannot_be_told_to_go_and_fetch(client, admin_a):
    created = client.post("/api/v1/asset-sources", headers=admin_a, json={
        "slug": "cmdb-up", "name": "CMDB", "driver": "file", "is_enabled": True,
        "field_map": {"hostname": "Host"}}).json()
    response = client.post(f"/api/v1/asset-sources/{created['id']}/sync",
                           headers=admin_a)
    assert response.status_code == 422
    assert "upload" in response.text


def test_a_csv_upload_lands_in_staging_and_is_reported(client, admin_a):
    created = client.post("/api/v1/asset-sources", headers=admin_a, json={
        "slug": "cmdb-csv", "name": "CMDB", "driver": "file", "is_enabled": True,
        "field_map": {"hostname": "Host", "serial": "Serial",
                      "ip_addresses": "IP", "location": "Site"},
    }).json()
    csv_bytes = b"Host,Serial,IP,Site\nweb01,S-1,10.0.0.1/24,Zurich\n"
    response = client.post(
        f"/api/v1/asset-sources/{created['id']}/upload", headers=admin_a,
        files={"file": ("cmdb.csv", io.BytesIO(csv_bytes), "text/csv")})
    assert response.status_code == 200, response.text
    run = response.json()
    assert run["records_seen"] == 1 and run["records_created"] == 1
    records = client.get("/api/v1/asset-sources/records", headers=admin_a,
                         params={"source_id": created["id"]}).json()
    assert records[0]["hostname"] == "web01"
    assert records[0]["ip_addresses"] == ["10.0.0.1"]


def test_an_empty_upload_is_refused(client, admin_a):
    created = client.post("/api/v1/asset-sources", headers=admin_a, json={
        "slug": "cmdb-empty", "name": "CMDB", "driver": "file", "is_enabled": True,
        "field_map": {"hostname": "Host"}}).json()
    response = client.post(
        f"/api/v1/asset-sources/{created['id']}/upload", headers=admin_a,
        files={"file": ("cmdb.csv", io.BytesIO(b""), "text/csv")})
    assert response.status_code == 422


def test_a_record_can_be_ignored_by_hand_and_leaves_the_comparative(client, admin_a):
    created = client.post("/api/v1/asset-sources", headers=admin_a, json={
        "slug": "cmdb-ign", "name": "CMDB", "driver": "file", "is_enabled": True,
        "field_map": {"hostname": "Host"}}).json()
    client.post(f"/api/v1/asset-sources/{created['id']}/upload", headers=admin_a,
                files={"file": ("c.csv", io.BytesIO(b"Host\nrack-4\n"), "text/csv")})
    record = client.get("/api/v1/asset-sources/records", headers=admin_a,
                        params={"source_id": created["id"]}).json()[0]
    patched = client.patch(f"/api/v1/asset-sources/records/{record['id']}",
                           headers=admin_a, json={"match_status": "ignored"})
    assert patched.status_code == 200
    assert patched.json()["match_status"] == "ignored"


def test_deleting_a_source_does_not_delete_what_it_described(client, admin_a, org_a):
    org_id, _, _ = org_a
    created = client.post("/api/v1/asset-sources", headers=admin_a, json={
        "slug": "cmdb-del", "name": "CMDB", "driver": "file", "is_enabled": True,
        "field_map": {"hostname": "Host", "name": "Host"}}).json()
    client.post(f"/api/v1/asset-sources/{created['id']}/upload", headers=admin_a,
                files={"file": ("c.csv", io.BytesIO(b"Host\nkeepme01\n"), "text/csv")})
    record = client.get("/api/v1/asset-sources/records", headers=admin_a,
                        params={"source_id": created["id"]}).json()[0]
    client.post("/api/v1/asset-sources/promote", headers=admin_a,
                json={"record_ids": [record["id"]], "create_assets": True})
    assert client.delete(f"/api/v1/asset-sources/{created['id']}",
                         headers=admin_a).status_code == 204
    with _session(org_id) as session:
        assert session.execute(select(Asset).where(
            Asset.organization_id == org_id,
            Asset.hostname == "keepme01")).scalar_one_or_none() is not None


def test_the_summary_leads_with_matched_and_unmatched(client, admin_a):
    created = client.post("/api/v1/asset-sources", headers=admin_a, json={
        "slug": "cmdb-sum", "name": "CMDB", "driver": "file", "is_enabled": True,
        "field_map": {"hostname": "Host"}}).json()
    client.post(f"/api/v1/asset-sources/{created['id']}/upload", headers=admin_a,
                files={"file": ("c.csv", io.BytesIO(b"Host\nweb01\nweb02\n"),
                                "text/csv")})
    body = client.get("/api/v1/asset-sources/summary", headers=admin_a).json()
    entry = [s for s in body["sources"] if s["id"] == created["id"]][0]
    assert entry["records"] == 2 and entry["unmatched"] == 2


# ---------------------------------------------------------------------------
# guardrails
# ---------------------------------------------------------------------------
def test_the_router_is_refused_to_a_team_scoped_identity():
    """A comparative narrowed to one team reads as a complete answer."""
    from veyrs.security.scope import EXEMPT_TAGS, REFUSED_TAGS, SCOPED_TAGS

    assert "asset sources" in REFUSED_TAGS
    assert "asset sources" not in (SCOPED_TAGS | EXEMPT_TAGS)


def test_sync_is_the_only_thing_that_writes_asset_source_records():
    """Two writers is how one of them stops applying the absence rule."""
    import pathlib
    import re

    root = pathlib.Path(cmdb.__file__).resolve().parents[1]
    offenders = []
    for path in root.rglob("*.py"):
        if path.name in ("cmdb.py", "__init__.py"):
            continue
        text = path.read_text()
        if re.search(r"\bAssetSourceRecord\s*\(", text):
            offenders.append(str(path.relative_to(root)))
    assert offenders == []
