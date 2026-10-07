"""Phase 33 - pulling from a scanner instead of waiting to be uploaded to.

The feature is small; the ways it can be quietly wrong are not. Everything
pinned here is a rule that, if it broke, would still look like a working
connector:

* a connector that starts **enabled** begins making outbound connections
  nobody decided to make;
* a connector that treats an empty allow-list as **"every scan"** ingests a
  neighbouring team's estate the first time someone clicks Sync;
* a `scan_ids` argument that is silently **filtered** rather than rejected
  tells an operator the sync succeeded on a scan it never touched;
* `close_absent` without an engagement marks hosts the scan never looked at as
  remediated -- the exact defect the deleted `_close_missing()` caused, per the
  note in `services/importers/base.py`;
* a **second ingestion path** would mean a second deduplication rule, so the
  driver's parser format must be one `importers.PARSERS` actually has.

`test_only_sync_touches_the_database` is the source-level guardrail, in the
spirit of phase 26's over `analytics.py` and phase 28's over the policies
router: drivers speak HTTP and return bytes, and the moment one of them is
handed a Session the single place that enforces the rules above stops being
single.
"""
from __future__ import annotations

import ast
import io
import json
import pathlib
import uuid
import zipfile

import pytest

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import ScannerConnector
from veyrs.models.integration import ImportRun
from veyrs.security.secrets import PREFIX, decrypt
from veyrs.services import importers, scanners

ROOT = pathlib.Path(__file__).resolve().parents[1]
SCANNERS_PY = ROOT / "backend" / "veyrs" / "services" / "scanners.py"

NESSUS_REPORT = b"""<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
  <Report name="phase33">
    <ReportHost name="10.99.0.7">
      <HostProperties>
        <tag name="host-ip">10.99.0.7</tag>
        <tag name="host-fqdn">phase33.example.test</tag>
        <tag name="operating-system">Linux Kernel 5.10</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="www" protocol="tcp" severity="4"
                  pluginID="99001" pluginName="Phase 33 test finding">
        <cve>CVE-2021-44228</cve>
        <description>A finding invented by the phase 33 suite.</description>
        <solution>Upgrade.</solution>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


def _make_connector(org_id, **overrides) -> uuid.UUID:
    fields = {
        "slug": "nessus-" + uuid.uuid4().hex[:8],
        "name": "Test scanner",
        "driver": "nessus",
        "base_url": "https://nessus.invalid:8834",
        "is_enabled": True,
        "allowed_scans": ["7"],
        "create_assets": True,
    }
    fields.update(overrides)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        connector = ScannerConnector(organization_id=org_id, **fields)
        session.add(connector)
        session.commit()
        return connector.id


# --------------------------------------------------------------------------
# Drivers
# --------------------------------------------------------------------------
def test_every_driver_names_a_parser_that_exists():
    # A driver whose parser_format is not a real parser fails at the end of a
    # download, after the credentials worked and the export was built -- the
    # most expensive possible place to discover a typo.
    for key, driver in scanners.DRIVERS.items():
        assert driver.parser_format in importers.PARSERS, (
            f"driver {key!r} declares parser {driver.parser_format!r}, which is "
            f"not in importers.PARSERS"
        )


def test_drivers_endpoint_describes_credentials(client, admin_a):
    body = client.get("/api/v1/integrations/scanner-drivers", headers=admin_a)
    assert body.status_code == 200, body.text
    drivers = {d["driver"]: d for d in body.json()["drivers"]}
    assert set(drivers) == {"nessus", "tenable_io", "tenable_sc"}
    assert drivers["nessus"]["credential_fields"] == ["access_key", "secret_key"]
    assert drivers["tenable_sc"]["credential_fields"] == ["username", "password"]
    # The cloud has a default; an on-premise console cannot be guessed.
    assert drivers["tenable_io"]["default_base_url"] == "https://cloud.tenable.com"
    assert drivers["nessus"]["default_base_url"] is None


def test_only_sync_touches_the_database():
    """Drivers take no Session. Only `sync` does."""
    tree = ast.parse(SCANNERS_PY.read_text(encoding="utf-8"))
    offenders = []
    for node in ast.walk(tree):
        if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue
        args = node.args.args + node.args.kwonlyargs + node.args.posonlyargs
        takes_session = any(
            isinstance(a.annotation, ast.Name) and a.annotation.id == "Session"
            for a in args
        )
        if takes_session and node.name != "sync":
            offenders.append(node.name)
    assert not offenders, (
        "these functions in services/scanners.py take a Session: "
        + ", ".join(offenders)
        + ". Everything that writes must stay in sync(), which is the one place "
        "the scope and allow-list rules are enforced."
    )


# --------------------------------------------------------------------------
# Enrolment
# --------------------------------------------------------------------------
def test_new_connector_is_disabled_and_inert(client, admin_a):
    response = client.post("/api/v1/integrations/scanners", headers=admin_a, json={
        "slug": "nessus-lab", "name": "Nessus (lab)", "driver": "nessus",
        "base_url": "https://nessus.invalid:8834",
        "credentials": {"access_key": "a", "secret_key": "b"},
    })
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["is_enabled"] is False
    assert body["allowed_scans"] == []
    assert body["is_inert"] is True
    assert body["credentials_set"] is True
    # No schema field carries the ciphertext, so none can leak it.
    assert "credentials" not in body and "credentials_enc" not in body


def test_credentials_are_stored_encrypted(client, admin_a, org_a):
    org_id, _, _ = org_a
    secret = "s3cr3t-" + uuid.uuid4().hex
    response = client.post("/api/v1/integrations/scanners", headers=admin_a, json={
        "slug": "nessus-enc", "name": "Nessus", "driver": "nessus",
        "base_url": "https://nessus.invalid:8834",
        "credentials": {"access_key": "a", "secret_key": secret},
    })
    assert response.status_code == 201, response.text
    with SessionLocal() as session:
        set_tenant(session, org_id)
        row = session.get(ScannerConnector, uuid.UUID(response.json()["id"]))
        assert row.credentials_enc.startswith(PREFIX)
        assert secret not in row.credentials_enc
        assert json.loads(decrypt(row.credentials_enc))["secret_key"] == secret


def test_close_absent_requires_an_engagement(client, admin_a):
    response = client.post("/api/v1/integrations/scanners", headers=admin_a, json={
        "slug": "nessus-ca", "name": "Nessus", "driver": "nessus",
        "base_url": "https://nessus.invalid:8834", "close_absent": True,
    })
    assert response.status_code == 422
    assert "engagement" in response.json()["detail"]


def test_patch_validates_the_resulting_row_not_the_patch(client, admin_a, org_a):
    """close_absent on, engagement cleared in a later request, must still 422."""
    org_id, _, _ = org_a
    connector_id = _make_connector(org_id, close_absent=False, is_enabled=False)
    response = client.patch(f"/api/v1/integrations/scanners/{connector_id}",
                            headers=admin_a, json={"close_absent": True})
    assert response.status_code == 422, response.text
    assert "engagement" in response.json()["detail"]


def test_patch_without_credentials_leaves_them_alone(client, admin_a, org_a):
    org_id, _, _ = org_a
    created = client.post("/api/v1/integrations/scanners", headers=admin_a, json={
        "slug": "nessus-keep", "name": "Nessus", "driver": "nessus",
        "base_url": "https://nessus.invalid:8834",
        "credentials": {"access_key": "a", "secret_key": "b"},
    })
    connector_id = created.json()["id"]
    response = client.patch(f"/api/v1/integrations/scanners/{connector_id}",
                            headers=admin_a, json={"name": "Renamed"})
    assert response.status_code == 200, response.text
    assert response.json()["credentials_set"] is True
    assert response.json()["name"] == "Renamed"


def test_another_tenant_cannot_see_the_connector(client, admin_b, org_a):
    org_id, _, _ = org_a
    connector_id = _make_connector(org_id)
    response = client.patch(f"/api/v1/integrations/scanners/{connector_id}",
                            headers=admin_b, json={"name": "Stolen"})
    assert response.status_code == 404


# --------------------------------------------------------------------------
# Sync refusals
# --------------------------------------------------------------------------
def _connector_row(session, connector_id):
    return session.get(ScannerConnector, connector_id)


def test_sync_refuses_a_disabled_connector(org_a):
    org_id, _, _ = org_a
    connector_id = _make_connector(org_id, is_enabled=False)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        with pytest.raises(scanners.ScannerError, match="disabled"):
            scanners.sync(session, _connector_row(session, connector_id))


def test_sync_refuses_an_inert_connector(org_a):
    org_id, _, _ = org_a
    connector_id = _make_connector(org_id, allowed_scans=[])
    with SessionLocal() as session:
        set_tenant(session, org_id)
        with pytest.raises(scanners.ScannerError, match="inert"):
            scanners.sync(session, _connector_row(session, connector_id))


def test_sync_rejects_a_scan_outside_the_allow_list(org_a):
    """Rejected, not filtered. Filtering reports success on untouched work."""
    org_id, _, _ = org_a
    connector_id = _make_connector(org_id, allowed_scans=["7"])
    with SessionLocal() as session:
        set_tenant(session, org_id)
        with pytest.raises(scanners.ScannerError, match="allowed scans"):
            scanners.sync(session, _connector_row(session, connector_id),
                          scan_ids=["7", "99"])


def test_sync_refuses_close_absent_without_an_engagement(org_a):
    org_id, _, _ = org_a
    connector_id = _make_connector(org_id, close_absent=True, engagement_id=None)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        with pytest.raises(scanners.ScannerError, match="engagement"):
            scanners.sync(session, _connector_row(session, connector_id))


# --------------------------------------------------------------------------
# Sync, with the transport stubbed
# --------------------------------------------------------------------------
@pytest.fixture()
def stub_driver(monkeypatch):
    """Replace only `fetch_report`. Everything below it is still the real path:
    real payload, real parser, real ingest, real ImportRun."""
    calls = []

    def fake_fetch(self, spec, scan_id):
        calls.append(scan_id)
        return NESSUS_REPORT

    monkeypatch.setattr(scanners._NessusApiDriver, "fetch_report", fake_fetch)
    monkeypatch.setattr(
        scanners, "spec_for",
        lambda c: scanners.ScannerSpec(driver=c.driver, base_url="https://stub",
                                       credentials={"access_key": "a",
                                                    "secret_key": "b"}),
    )
    return calls


def test_sync_ingests_through_the_normal_import_path(org_a, stub_driver):
    org_id, _, _ = org_a
    connector_id = _make_connector(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        outcomes = scanners.sync(session, _connector_row(session, connector_id))
        session.commit()

    assert [o.status for o in outcomes] == ["imported"]
    assert stub_driver == ["7"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        run = session.get(ImportRun, outcomes[0].run_id)
        # The pulled export is indistinguishable from an uploaded one by the
        # time it reaches the database -- that is the whole design.
        assert run.source == "nessus"
        assert run.status == "complete"
        assert run.records_seen == 1
        assert run.findings_created == 1
        assert run.filename.endswith(":7.nessus")


def test_an_identical_export_is_skipped_and_force_overrides(org_a, stub_driver):
    org_id, _, _ = org_a
    connector_id = _make_connector(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        scanners.sync(session, _connector_row(session, connector_id))
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        second = scanners.sync(session, _connector_row(session, connector_id))
        session.commit()
    assert [o.status for o in second] == ["skipped"]

    with SessionLocal() as session:
        set_tenant(session, org_id)
        forced = scanners.sync(session, _connector_row(session, connector_id),
                               force=True)
        session.commit()
    assert [o.status for o in forced] == ["imported"]


def test_a_dry_run_leaves_no_sync_state(org_a, stub_driver):
    """Otherwise the next real sync would skip the scan it never imported."""
    org_id, _, _ = org_a
    connector_id = _make_connector(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        scanners.sync(session, _connector_row(session, connector_id), dry_run=True)
        session.rollback()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        row = _connector_row(session, connector_id)
        assert row.sync_state == {}
        assert row.last_sync_at is None


def test_sync_endpoint_reports_per_scan_results(client, admin_a, org_a, stub_driver):
    org_id, _, _ = org_a
    connector_id = _make_connector(org_id)
    response = client.post(f"/api/v1/integrations/scanners/{connector_id}/sync",
                           headers=admin_a, json={"dry_run": False})
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["dry_run"] is False
    assert [r["status"] for r in body["results"]] == ["imported"]
    assert body["results"][0]["scan_id"] == "7"


def test_sync_endpoint_409s_on_an_inert_connector(client, admin_a, org_a):
    org_id, _, _ = org_a
    connector_id = _make_connector(org_id, allowed_scans=[])
    response = client.post(f"/api/v1/integrations/scanners/{connector_id}/sync",
                           headers=admin_a, json={})
    assert response.status_code == 409
    assert "inert" in response.json()["detail"]


# --------------------------------------------------------------------------
# Tenable.sc packaging
# --------------------------------------------------------------------------
def test_unzip_passes_a_bare_report_through():
    assert scanners._unzip_report(NESSUS_REPORT, "1") == NESSUS_REPORT


def test_unzip_extracts_the_nessus_member():
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as archive:
        archive.writestr("readme.txt", "ignore me")
        archive.writestr("report.nessus", NESSUS_REPORT)
    assert scanners._unzip_report(buf.getvalue(), "1") == NESSUS_REPORT


def test_unzip_refuses_an_oversized_member_before_reading_it(monkeypatch):
    """The ceiling is checked against the DECLARED size. Reading first and
    measuring afterwards is what makes a zip bomb work."""
    monkeypatch.setattr(scanners, "MAX_EXPORT_BYTES", 64)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("report.nessus", b"A" * 100_000)
    with pytest.raises(scanners.ScannerError, match="ceiling"):
        scanners._unzip_report(buf.getvalue(), "1")


def test_unzip_rejects_an_empty_download():
    with pytest.raises(scanners.ScannerError, match="empty"):
        scanners._unzip_report(b"", "1")


# --------------------------------------------------------------------------
# Credentials
# --------------------------------------------------------------------------
def test_undecryptable_credentials_fail_closed(org_a):
    """An unauthenticated request to a scanner console is a different request
    from the one the operator configured. It must not be made."""
    org_id, _, _ = org_a
    connector_id = _make_connector(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        row = _connector_row(session, connector_id)
        row.credentials_enc = PREFIX + "not-a-valid-fernet-token"
        session.flush()
        with pytest.raises(scanners.ScannerError, match="decrypt"):
            scanners.credentials_of(row)
