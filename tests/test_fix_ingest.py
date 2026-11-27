"""0.41.0 ingest fix round: regression tests, one block per audit item.

Every test here fails against the 0.39.1 code for the reason its docstring
names (TD-xx ids are `docs/audit/risks-and-debt.md`).
"""
from __future__ import annotations

import datetime as dt
import importlib.util
import json
import pathlib
import sys
import threading
import time
import uuid

import pytest
from sqlalchemy import event, select, text
from sqlalchemy.exc import DBAPIError, IntegrityError
from sqlalchemy.orm import Session

from veyrs.db import SessionLocal, engine, set_tenant
from veyrs.models import (
    Asset, AssetProduct, Cve, CveCpeMatch, Finding, FindingEvent, Organization, Ticket,
    TicketCounter, Vulnerability,
)
from veyrs.models.risk_register import RiskEntry, RiskRaci
from veyrs.models.tenancy import Team
from veyrs.models.vulnerability import OBSERVED_FIX_FROM
from veyrs.schema_steps import step_ingest
from veyrs.services import (
    correlation, dedupe, engagements, ingest_admin, intelligence, inventory, ticketing,
)
from veyrs.services import importers
from veyrs.services.importers import ImportOptions
from veyrs.services.importers.base import AssetIndex, ScanRecord

RUNNER = (pathlib.Path(__file__).resolve().parents[1]
          / "integrations" / "veyrs-agent" / "veyrs_agent.py")


def _load_runner():
    spec = importlib.util.spec_from_file_location("veyrs_agent_fix", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def runner():
    return _load_runner()


def _nessus(hosts: list[tuple[str, str, str]]) -> bytes:
    body = "".join(
        f'<ReportHost name="{ip}"><HostProperties><tag name="host-ip">{ip}</tag>'
        f'<tag name="host-fqdn">{fqdn}</tag></HostProperties>{items}</ReportHost>'
        for ip, fqdn, items in hosts)
    return ('<?xml version="1.0" ?><NessusClientData_v2><Report name="scan">'
            f"{body}</Report></NessusClientData_v2>").encode()


def _item(plugin: str, port: int = 443, severity: int = 2) -> str:
    return (f'<ReportItem port="{port}" protocol="tcp" severity="{severity}" '
            f'pluginID="{plugin}" pluginName="Check {plugin}"><description>d</description>'
            "</ReportItem>")


@pytest.fixture()
def two_hosts(org_a):
    org_id = org_a[0]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        a = Asset(organization_id=org_id, name="host-a", hostname="host-a",
                  fqdn="host-a.example.com", ip_addresses=["192.0.2.10"])
        b = Asset(organization_id=org_id, name="host-b", hostname="host-b",
                  fqdn="host-b.example.com", ip_addresses=["192.0.2.11"])
        session.add_all([a, b])
        engagement = engagements.create_engagement(
            session, org_id, name="CI sweep", engagement_type="ci_cd")
        session.commit()
        return {"org_id": org_id, "slug": org_a[1], "a": a.id, "b": b.id,
                "engagement": engagement.id}


def _import(org_id, payload, source="nessus", **options):
    with SessionLocal() as session:
        set_tenant(session, org_id)
        run = importers.run_import(session, org_id, payload, source=source,
                                   options=ImportOptions(**options))
        session.commit()
        assert run.status in ("complete", "preview"), run.error
        return run


def _findings(org_id, **where):
    with SessionLocal() as session:
        set_tenant(session, org_id)
        stmt = select(Finding).where(Finding.organization_id == org_id)
        for key, value in where.items():
            stmt = stmt.where(getattr(Finding, key) == value)
        rows = session.execute(stmt).scalars().all()
        session.expunge_all()
        return rows


# ===========================================================================
# TD-01: SCA deduplication hashed an empty `cve`
# ===========================================================================
def _trivy(artifact: str, vulns: list[tuple[str, str, str]]) -> bytes:
    return json.dumps({"ArtifactName": artifact, "Results": [{
        "Target": artifact, "Class": "os-pkgs", "Type": "debian",
        "Vulnerabilities": [{"VulnerabilityID": cve, "PkgName": pkg,
                             "InstalledVersion": version, "Severity": "HIGH",
                             "Title": f"{cve} in {pkg}"} for cve, pkg, version in vulns],
    }]}).encode()


def test_two_cves_on_one_package_are_two_findings(org_a):
    """0.39.1 hashed `cve` as "" for trivy/grype/snyk/dependabot/npm/pip:
    every CVE on one package+asset merged into the first finding."""
    org_id = org_a[0]
    payload = _trivy("registry.example.com/app:1.0",
                     [("CVE-2099-1001", "openssl", "3.0.1"),
                      ("CVE-2099-1002", "openssl", "3.0.1")])
    run = _import(org_id, payload, source="trivy", create_assets=True)
    assert run.findings_created == 2
    rows = _findings(org_id)
    assert len({r.dedupe_key for r in rows}) == 2
    assert all(r.dedupe_revision == dedupe.KEY_REVISION for r in rows)
    # Re-importing the same report matches both instead of duplicating.
    again = _import(org_id, payload, source="trivy", create_assets=True)
    assert (again.findings_created, again.findings_updated) == (0, 2)


def _age_to_revision_one(org_id) -> dict:
    """Turn the tenant's findings into what 0.39.1 stored: the key with `cve`
    hashed as "" (the revision-2 identity's previous key) at revision 1."""
    keys = {}
    with SessionLocal() as session:
        set_tenant(session, org_id)
        for finding in session.execute(
                select(Finding).where(Finding.organization_id == org_id)).scalars():
            vulnerability = session.get(Vulnerability, finding.vulnerability_id)
            record = ScanRecord(component_name="openssl", component_version="3.0.1")
            identity = dedupe.resolve_identity(
                record, config=dedupe.config_for("trivy"), organization_id=org_id,
                asset_id=finding.asset_id, vuln_ref=vulnerability.cve_id or str(vulnerability.id),
                scanner="trivy", cve=dedupe.cve_ref(vulnerability))
            assert identity.dedupe_key == finding.dedupe_key
            finding.dedupe_key = identity.previous_keys[0]
            finding.dedupe_revision = 1
            keys[finding.id] = identity.dedupe_key
        session.commit()
    return keys


def test_rehash_rekeys_revision_one_findings_in_place_and_is_idempotent(org_a):
    org_id, slug = org_a[0], org_a[1]
    one = _trivy("registry.example.com/api:2.0", [("CVE-2099-2001", "openssl", "3.0.1")])
    _import(org_id, one, source="trivy", create_assets=True)
    expected = _age_to_revision_one(org_id)

    with SessionLocal() as session:
        set_tenant(session, org_id)
        dry = dedupe.rehash(session, org_id, apply=False)
        session.rollback()
    assert (dry["rekeyed"], dry["conflicts"]) == (1, [])
    assert {f.id: f.dedupe_revision for f in _findings(org_id)} == {k: 1 for k in expected}

    from veyrs.cli import main
    assert main(["dedupe", "rehash", "--org", slug, "--apply"]) == 0
    rows = _findings(org_id)
    assert {r.id: r.dedupe_key for r in rows} == expected
    assert all(r.dedupe_revision == dedupe.KEY_REVISION for r in rows)

    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert dedupe.rehash(session, org_id, apply=True)["candidates"] == 0
        session.commit()
    # The next import matches the re-keyed finding instead of duplicating it.
    run = _import(org_id, one, source="trivy", create_assets=True)
    assert (run.findings_created, run.findings_updated) == (0, 1)


def test_an_import_before_the_rehash_adopts_the_finding_of_its_own_cve(org_a):
    """The deploy order must not matter: a revision-1 finding is adopted by the
    record of the CVE it was created for, and only by that one."""
    org_id = org_a[0]
    first = _trivy("registry.example.com/web:3.0", [("CVE-2099-3001", "openssl", "3.0.1")])
    _import(org_id, first, source="trivy", create_assets=True)
    (original_id, new_key), = _age_to_revision_one(org_id).items()

    both = _trivy("registry.example.com/web:3.0", [("CVE-2099-3002", "openssl", "3.0.1"),
                                                   ("CVE-2099-3001", "openssl", "3.0.1")])
    run = _import(org_id, both, source="trivy", create_assets=True)
    assert (run.findings_created, run.findings_updated) == (1, 1)
    rows = {r.id: r for r in _findings(org_id)}
    assert len(rows) == 2
    assert rows[original_id].dedupe_key == new_key
    assert rows[original_id].dedupe_revision == dedupe.KEY_REVISION


# ===========================================================================
# TD-02: closure scoped to the test, not to what the run covered
# ===========================================================================
def test_an_export_of_host_b_does_not_close_host_a(two_hosts):
    """Both runs land in the same (engagement, scanner) test. 0.39.1 counted
    host A's finding absent from host B's export and closed it (ci_cd: 1)."""
    org_id, engagement = two_hosts["org_id"], two_hosts["engagement"]
    _import(org_id, _nessus([("192.0.2.10", "host-a.example.com", _item("1001"))]),
            engagement_id=engagement)
    run = _import(org_id, _nessus([("192.0.2.11", "host-b.example.com", _item("2001"))]),
                  engagement_id=engagement, close_absent=True, absence_threshold=1)
    assert (run.findings_marked_absent, run.findings_closed_absent) == (0, 0)
    (a_finding,) = _findings(org_id, asset_id=two_hosts["a"])
    assert a_finding.state == "new"


def test_a_covered_host_still_closes_what_it_stopped_reporting(two_hosts):
    org_id, engagement = two_hosts["org_id"], two_hosts["engagement"]
    both = _nessus([("192.0.2.10", "host-a.example.com", _item("1001") + _item("1002", 22)),
                    ("192.0.2.11", "host-b.example.com", _item("2001"))])
    _import(org_id, both, engagement_id=engagement)
    # Host A comes back without 1002; host B is not in this export at all.
    run = _import(org_id, _nessus([("192.0.2.10", "host-a.example.com", _item("1001"))]),
                  engagement_id=engagement)
    assert run.findings_closed_absent == 1
    states = {f.scanner_plugin_id: f.state for f in _findings(org_id)}
    assert states == {"1001": "new", "1002": "remediated", "2001": "new"}


def test_a_record_filtered_by_severity_still_proves_coverage(two_hosts):
    org_id, engagement = two_hosts["org_id"], two_hosts["engagement"]
    _import(org_id, _nessus([("192.0.2.10", "host-a.example.com", _item("1002", 22))]),
            engagement_id=engagement)
    run = _import(org_id, _nessus([("192.0.2.10", "host-a.example.com",
                                    _item("19506", 0, severity=0))]),
                  engagement_id=engagement, min_severity="low")
    assert run.records_rejected == 1 and run.findings_closed_absent == 1


def test_an_empty_run_closes_only_on_an_attested_target(two_hosts):
    org_id, engagement = two_hosts["org_id"], two_hosts["engagement"]
    _import(org_id, _nessus([("192.0.2.10", "host-a.example.com", _item("1001")),
                             ("192.0.2.11", "host-b.example.com", _item("2001"))]),
            engagement_id=engagement)
    unattested = {"kind": "agent", "attested": False, "target": "host-a.example.com"}
    run = _import(org_id, b"", engagement_id=engagement, allow_empty=True,
                  coverage_attestation=unattested)
    assert run.findings_marked_absent == 0
    attested = {**unattested, "attested": True}
    run = _import(org_id, b"", engagement_id=engagement, allow_empty=True,
                  coverage_attestation=attested)
    assert run.findings_closed_absent == 1
    states = {f.asset_id: f.state for f in _findings(org_id)}
    assert states == {two_hosts["a"]: "remediated", two_hosts["b"]: "new"}


def test_consecutive_means_consecutive_runs_that_covered_the_asset(two_hosts):
    org_id = two_hosts["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        engagement = engagements.create_engagement(session, org_id, name="Nightly",
                                                   engagement_type="scheduled").id
        session.commit()
    a_with = ("192.0.2.10", "host-a.example.com", _item("1001") + _item("1002", 22))
    a_without = ("192.0.2.10", "host-a.example.com", _item("1001"))
    b_only = ("192.0.2.11", "host-b.example.com", _item("2001"))
    _import(org_id, _nessus([a_with, b_only]), engagement_id=engagement)
    _import(org_id, _nessus([a_without]), engagement_id=engagement)   # absence 1
    for _ in range(3):                                                  # A not scanned
        _import(org_id, _nessus([b_only]), engagement_id=engagement)
    (ssh,) = _findings(org_id, scanner_plugin_id="1002")
    assert ssh.state == "new"
    run = _import(org_id, _nessus([a_without]), engagement_id=engagement)  # absence 2
    assert run.findings_closed_absent == 1


# ===========================================================================
# TD-28: closure re-fired on findings already closed
# ===========================================================================
def test_absence_closure_fires_once(two_hosts):
    org_id, engagement = two_hosts["org_id"], two_hosts["engagement"]
    a_with = _nessus([("192.0.2.10", "host-a.example.com", _item("1001") + _item("1002", 22))])
    a_without = _nessus([("192.0.2.10", "host-a.example.com", _item("1001"))])
    _import(org_id, a_with, engagement_id=engagement)
    _import(org_id, a_without, engagement_id=engagement)
    (ssh,) = _findings(org_id, scanner_plugin_id="1002")
    first_remediated_at = ssh.remediated_at
    assert ssh.state == "remediated"

    again = _import(org_id, a_without, engagement_id=engagement)
    assert (again.findings_marked_absent, again.findings_closed_absent) == (0, 0)
    (ssh,) = _findings(org_id, scanner_plugin_id="1002")
    assert ssh.remediated_at == first_remediated_at
    with SessionLocal() as session:
        set_tenant(session, org_id)
        closes = session.execute(select(FindingEvent).where(
            FindingEvent.finding_id == ssh.id, FindingEvent.to_state == "remediated")).all()
    assert len(closes) == 1


def test_observe_fix_refuses_states_that_already_claim_a_fix():
    finding = Finding(organization_id=uuid.uuid4(), state="remediated")
    assert correlation.observe_fix(None, finding, "remediated") is False
    assert "remediated" not in OBSERVED_FIX_FROM and "verification" not in OBSERVED_FIX_FROM
    assert "accepted_risk" not in OBSERVED_FIX_FROM and "new" in OBSERVED_FIX_FROM


def test_correlation_close_missing_does_not_refire(org_a):
    org_id = org_a[0]
    tag = uuid.uuid4().hex[:10]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        product = intelligence.upsert_product(session, f"acme-{tag}", f"router-{tag}")
        cve_id = f"CVE-2098-{int(tag[:8], 16)}"
        session.add(Cve(id=cve_id, title="t", description="t", cvss3_base_score=8.1,
                        cvss3_severity="high"))
        session.flush()
        session.add(CveCpeMatch(cve_id=cve_id, product_id=product.id, vulnerable=True,
                                cpe23=f"cpe:2.3:a:acme:{product.name}:*:*:*:*:*:*:*:*",
                                version_end_excluding="2.0.0"))
        asset = Asset(organization_id=org_id, name=f"rtr-{tag}")
        session.add(asset)
        session.flush()
        install = AssetProduct(organization_id=org_id, asset_id=asset.id,
                               product_id=product.id, version="1.0.0", detected_by="manual")
        session.add(install)
        session.flush()
        cve = session.get(Cve, cve_id)
        correlation.correlate_cve(session, org_id, cve)
        install.version = "2.1.0"
        # correlate_cve returns before close_missing when NO asset is in range,
        # so keep a second, still-affected asset in the estate.
        other = Asset(organization_id=org_id, name=f"rtr2-{tag}")
        session.add(other)
        session.flush()
        session.add(AssetProduct(organization_id=org_id, asset_id=other.id,
                                 product_id=product.id, version="1.0.0", detected_by="manual"))
        session.flush()
        first = correlation.correlate_cve(session, org_id, cve, close_missing=True)
        second = correlation.correlate_cve(session, org_id, cve, close_missing=True)
        finding = session.execute(select(Finding).where(
            Finding.organization_id == org_id, Finding.asset_id == asset.id)).scalar_one()
        events = session.execute(select(FindingEvent.from_state).where(
            FindingEvent.finding_id == finding.id,
            FindingEvent.event == "no_longer_applicable")).scalars().all()
        session.rollback()
    assert (first["closed"], second["closed"]) == (1, 0)
    assert events == ["new"]


# ===========================================================================
# TD-32: an import re-creating a soft-deleted asset
# ===========================================================================
def test_an_import_revives_the_soft_deleted_asset_it_created(org_a):
    org_id = org_a[0]
    payload = _nessus([("192.0.2.50", "ghost.example.com", _item("3001"))])
    _import(org_id, payload, create_assets=True)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        asset = session.execute(select(Asset).where(
            Asset.organization_id == org_id,
            Asset.external_id == "import:ghost.example.com")).scalar_one()
        asset_id = asset.id
        asset.deleted_at = dt.datetime.now(dt.timezone.utc)
        asset.is_active = False
        session.commit()

    run = _import(org_id, payload, create_assets=True)       # 0.39.1: IntegrityError
    assert run.assets_created == 1
    with SessionLocal() as session:
        set_tenant(session, org_id)
        asset = session.get(Asset, asset_id)
        assert asset.deleted_at is None and asset.is_active
        assert session.execute(select(Asset.id).where(
            Asset.organization_id == org_id,
            Asset.external_id == "import:ghost.example.com")).scalars().all() == [asset_id]


# ===========================================================================
# TD-05: asset resolution once per run, same answers
# ===========================================================================
def _reference_match(candidates, record):
    """The 0.39.1 loop, verbatim in substance."""
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
            if (asset.fqdn or "").lower() == wanted:
                return asset
            if (asset.fqdn or "").lower().split(".")[0] == wanted:
                return asset
    if record.ip_address:
        for asset in candidates:
            if record.ip_address in (asset.ip_addresses or []):
                return asset
    return None


def test_the_asset_index_answers_exactly_like_the_old_loop():
    assets = [
        Asset(name="Web-01", hostname="web-01", fqdn="web-01.example.com",
              ip_addresses=["192.0.2.1"]),
        Asset(name="web-01.example.com", hostname=None, fqdn=None, ip_addresses=["192.0.2.1"]),
        Asset(name="db", hostname="DB", fqdn="db.example.org", ip_addresses=[]),
        Asset(name="api", hostname="api", fqdn="web-01.example.net",
              ip_addresses=["192.0.2.3", {"odd": 1}]),
        Asset(name="db.example.org", hostname="other", fqdn=None, ip_addresses=None),
        Asset(name="mail", hostname=None, fqdn="mail.example.com", ip_addresses=["192.0.2.9"]),
    ]
    index = AssetIndex(assets)
    names = ["web-01", "WEB-01", "web-01.example.com", "db", "db.example.org", "api",
             "web-01.example.net", "mail", "mail.example.com", "other", "nope", None]
    ips = ["192.0.2.1", "192.0.2.3", "192.0.2.9", "198.51.100.1", None]
    checked = 0
    for fqdn in names:
        for hostname in names:
            for ip in ips:
                record = ScanRecord(fqdn=fqdn, hostname=hostname, ip_address=ip)
                assert index.match(record) is _reference_match(assets, record), record
                checked += 1
    assert checked == len(names) ** 2 * len(ips)


def test_an_import_reads_the_asset_table_once_not_per_record(two_hosts):
    org_id = two_hosts["org_id"]
    items = "".join(_item(str(5000 + i), port=1000 + i) for i in range(25))
    payload = _nessus([("192.0.2.10", "host-a.example.com", items)])
    statements: list[str] = []

    def count(conn, cursor, statement, *args):
        if "FROM assets" in statement and "assets.deleted_at IS NULL" in statement:
            statements.append(statement)

    event.listen(engine, "before_cursor_execute", count)
    try:
        run = _import(org_id, payload)
    finally:
        event.remove(engine, "before_cursor_execute", count)
    assert run.findings_created == 25
    assert len(statements) == 1, len(statements)


# ===========================================================================
# TD-33: unique keys whose NULLs were distinct
# ===========================================================================
def test_both_keys_are_nulls_not_distinct():
    with engine.connect() as conn:
        rows = dict(conn.execute(text(
            "SELECT c.conname, i.indnullsnotdistinct FROM pg_constraint c "
            "JOIN pg_index i ON i.indexrelid = c.conindid WHERE c.conname IN "
            "('uq_vulnerabilities_organization_id', 'uq_risk_register_raci_risk_id')")).all())
    assert rows == {"uq_vulnerabilities_organization_id": True,
                    "uq_risk_register_raci_risk_id": True}


def test_a_second_internal_vulnerability_with_the_same_ref_is_refused(org_a):
    org_id = org_a[0]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        session.add(Vulnerability(organization_id=org_id, internal_ref="plugin-1", title="x"))
        session.flush()
        session.add(Vulnerability(organization_id=org_id, internal_ref="plugin-1", title="x"))
        with pytest.raises(IntegrityError):
            session.flush()
        session.rollback()


def test_insert_vulnerability_returns_the_row_a_concurrent_writer_won_with(org_a):
    org_id = org_a[0]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        winner = Vulnerability(organization_id=org_id, internal_ref="race-1", title="w")
        session.add(winner)
        session.flush()
        loser = correlation.insert_vulnerability(
            session, Vulnerability(organization_id=org_id, internal_ref="race-1", title="l"))
        assert loser.id == winner.id
        session.rollback()


def _with_duplicates(conn, org_id) -> Session:
    """Inside the caller's transaction: drop both NND keys and plant the rows
    0.39.1 allowed. Everything is rolled back by the caller."""
    conn.execute(text("ALTER TABLE vulnerabilities DROP CONSTRAINT "
                      "uq_vulnerabilities_organization_id"))
    conn.execute(text("ALTER TABLE vulnerabilities ADD CONSTRAINT "
                      "uq_vulnerabilities_organization_id UNIQUE "
                      "(organization_id, cve_id, internal_ref)"))
    conn.execute(text("ALTER TABLE risk_register_raci DROP CONSTRAINT "
                      "uq_risk_register_raci_risk_id"))
    conn.execute(text("ALTER TABLE risk_register_raci ADD CONSTRAINT "
                      "uq_risk_register_raci_risk_id UNIQUE (risk_id, raci, team_id, user_id)"))
    session = Session(bind=conn, join_transaction_mode="create_savepoint")
    set_tenant(session, org_id)
    return session


def test_the_step_refuses_duplicates_and_merge_duplicates_resolves_them(org_a):
    org_id = org_a[0]
    vuln_step = dict(step_ingest.STEPS)["vulnerabilities_identity_nulls_not_distinct"]
    raci_step = dict(step_ingest.STEPS)["risk_register_raci_seat_nulls_not_distinct"]
    with engine.connect() as conn:
        outer = conn.begin()
        try:
            session = _with_duplicates(conn, org_id)
            asset = Asset(organization_id=org_id, name="dup-host")
            keeper = Vulnerability(organization_id=org_id, internal_ref="dup-ref", title="k",
                                   created_at=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc))
            twin = Vulnerability(organization_id=org_id, internal_ref="dup-ref", title="t")
            anon = [Vulnerability(organization_id=org_id, title=f"a{i}") for i in range(2)]
            team = Team(organization_id=org_id, name="Ops", slug=f"ops-{uuid.uuid4().hex[:6]}")
            risk = RiskEntry(organization_id=org_id, code="R-1", title="r")
            session.add_all([asset, keeper, twin, *anon, team, risk])
            session.flush()
            session.add_all([RiskRaci(organization_id=org_id, risk_id=risk.id, raci="R",
                                      party_type="team", team_id=team.id) for _ in range(2)])
            twin_key = dedupe.legacy_key(organization_id=org_id, asset_id=asset.id,
                                         vuln_ref=str(twin.id), port=443)
            finding = Finding(organization_id=org_id, asset_id=asset.id,
                              vulnerability_id=twin.id, title="f", dedupe_key=twin_key,
                              dedupe_algorithm="legacy", port=443)
            ticket = Ticket(organization_id=org_id, ticket_type="remediation",
                            reference=f"T-{uuid.uuid4().hex[:6]}", title="t",
                            vulnerability_id=twin.id)
            session.add_all([finding, ticket])
            session.flush()

            with pytest.raises(DBAPIError) as refused:
                with conn.begin_nested():
                    conn.execute(text(vuln_step))
            message = str(refused.value)
            assert "veyrs dedupe merge-duplicates" in message and "Nothing was changed" in message

            dry = ingest_admin.merge_duplicates(session, org_id, apply=False)
            assert (dry["vulnerabilities_removed"], dry["unidentified_named"],
                    dry["raci_seats_removed"], dry["findings_moved"]) == (1, 1, 1, 1)
            done = ingest_admin.merge_duplicates(session, org_id, apply=True)
            assert done["parallel_findings"] == []
            session.expire_all()
            assert session.get(Vulnerability, twin.id) is None
            assert session.get(Finding, finding.id).vulnerability_id == keeper.id
            # The legacy key follows the surviving vulnerability, so the next
            # import still matches this finding.
            assert session.get(Finding, finding.id).dedupe_key == dedupe.legacy_key(
                organization_id=org_id, asset_id=asset.id, vuln_ref=str(keeper.id), port=443)
            assert session.get(Ticket, ticket.id).vulnerability_id == keeper.id
            again = ingest_admin.merge_duplicates(session, org_id, apply=True)
            assert again["vulnerability_groups"] == [] and again["raci_seats_removed"] == 0

            conn.execute(text(vuln_step))
            conn.execute(text(raci_step))
            nnd = conn.execute(text(
                "SELECT bool_and(i.indnullsnotdistinct) FROM pg_constraint c JOIN pg_index i "
                "ON i.indexrelid = c.conindid WHERE c.conname IN "
                "('uq_vulnerabilities_organization_id', 'uq_risk_register_raci_risk_id')"
            )).scalar_one()
            assert nnd is True
            session.close()
        finally:
            outer.rollback()


# ===========================================================================
# TD-52: first-use race on the ticket counter
# ===========================================================================
def test_two_first_tickets_of_a_type_do_not_collide(org_a):
    """0.39.1: both sessions found no counter row (FOR UPDATE locks nothing that
    does not exist), both inserted one, and the second failed on the key."""
    org_id = org_a[0]
    kind = "problem"
    first = SessionLocal()
    set_tenant(first, org_id)
    results: dict[str, object] = {}
    try:
        results["first"] = ticketing.next_reference(first, org_id, kind)

        def second_writer():
            with SessionLocal() as second:
                set_tenant(second, org_id)
                try:
                    results["second"] = ticketing.next_reference(second, org_id, kind)
                    second.commit()
                except Exception as exc:  # noqa: BLE001 - asserted below
                    results["second"] = exc

        worker = threading.Thread(target=second_writer)
        worker.start()
        time.sleep(0.5)            # the second writer is now blocked on the first
        first.commit()
        worker.join(timeout=20)
    finally:
        first.close()
    assert results["first"] == "VEYRS-PRB-000001"
    assert results["second"] == "VEYRS-PRB-000002", results["second"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        counter = session.execute(select(TicketCounter).where(
            TicketCounter.organization_id == org_id,
            TicketCounter.ticket_type == kind)).scalar_one()
        assert counter.last_value == 2


# ===========================================================================
# TD-25: the agent's nmap tool had no parser
# ===========================================================================
NMAP_XML = b"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE nmaprun>
<nmaprun scanner="nmap" args="nmap -oX - -Pn -sV host-a.example.com" version="7.94">
  <host starttime="1" endtime="2">
    <status state="up" reason="user-set"/>
    <address addr="192.0.2.10" addrtype="ipv4"/>
    <address addr="00:11:22:33:44:55" addrtype="mac"/>
    <hostnames>
      <hostname name="host-a.example.com" type="user"/>
      <hostname name="ptr.example.net" type="PTR"/>
    </hostnames>
    <ports>
      <extraports state="closed" count="997"/>
      <port protocol="tcp" portid="22"><state state="open" reason="syn-ack"/>
        <service name="ssh" product="OpenSSH" version="9.2p1 Debian 2" method="probed" conf="10">
          <cpe>cpe:/a:openbsd:openssh:9.2p1</cpe><cpe>cpe:/o:linux:linux_kernel</cpe>
        </service></port>
      <port protocol="tcp" portid="443"><state state="open" reason="syn-ack"/>
        <service name="https" method="table" conf="3"/></port>
      <port protocol="tcp" portid="8080"><state state="filtered" reason="no-response"/></port>
      <port protocol="udp" portid="161"><state state="open|filtered" reason="no-response"/></port>
    </ports>
    <os><osmatch name="Linux 5.0 - 5.14" accuracy="98"/></os>
  </host>
  <host><status state="down" reason="no-response"/><address addr="192.0.2.99" addrtype="ipv4"/></host>
</nmaprun>"""


def test_nmap_reports_one_informational_record_per_open_port():
    from veyrs.services.importers.parsers import detect_format, parse_nmap

    records = [r.normalise() for r in parse_nmap(NMAP_XML)]
    assert [(r.port, r.protocol) for r in records] == [(22, "tcp"), (443, "tcp")]
    assert {r.severity for r in records} == {"informational"}
    assert all(not r.cve_ids and r.product is None for r in records)
    ssh = records[0]
    assert (ssh.fqdn, ssh.ip_address, ssh.mac_address) == (
        "host-a.example.com", "192.0.2.10", "00:11:22:33:44:55")
    assert ssh.operating_system == "Linux 5.0 - 5.14"
    assert ssh.plugin_id == "nmap:tcp/22" and ssh.evidence["service"]["product"] == "OpenSSH"
    assert detect_format(NMAP_XML, "scan.xml") == "nmap"


def test_nmap_inventory_reads_cpes_only():
    from veyrs.services.importers.parsers import get_inventory_parser

    (host,) = list(get_inventory_parser("nmap")(NMAP_XML))
    assert sorted(s.cpe for s in host.software) == [
        "cpe:2.3:a:openbsd:openssh:9.2p1:*:*:*:*:*:*:*",
        "cpe:2.3:o:linux:linux_kernel:*:*:*:*:*:*:*:*",
    ]


def test_every_agent_tool_names_a_parser_the_server_has(runner):
    missing = {name: tool.parser for name, tool in runner.TOOLS.items()
               if tool.parser not in importers.PARSERS}
    assert missing == {}


def test_an_nmap_result_imports(two_hosts):
    run = _import(two_hosts["org_id"], NMAP_XML, source="nmap")
    assert (run.findings_created, run.records_rejected) == (2, 0)
    assert {f.asset_id for f in _findings(two_hosts["org_id"])} == {two_hosts["a"]}


# ===========================================================================
# TD-26: lease and timeout depended on scanner output
# ===========================================================================
class _FakeProcess:
    def __init__(self):
        self.killed = False

    def kill(self):
        self.killed = True


def test_the_watchdog_extends_and_times_out_on_its_own_clock(runner):
    now = [0.0]
    extended: list[float] = []
    process = _FakeProcess()
    dog = runner.JobWatchdog(process, timeout=300, extend=lambda: extended.append(now[0]),
                             extend_every=120, clock=lambda: now[0])
    last = 0.0
    for second in range(0, 301, 10):
        now[0] = float(second)
        last = dog.check(0.0, last)
    assert extended == [120.0, 240.0] and not process.killed
    now[0] = 301.0
    dog.check(0.0, last)
    assert dog.timed_out and process.killed


class _Client:
    def __init__(self):
        self.calls: list[tuple] = []

    def events(self, *args, **kwargs):
        self.calls.append(("events",))

    def extend(self, job_id, lease):
        self.calls.append(("extend", time.monotonic()))

    def fail(self, job_id, lease, error, requeue=True):
        self.calls.append(("fail", error))

    def submit(self, job_id, lease, payload, **kwargs):
        self.calls.append(("submit", kwargs.get("stats")))
        return {"state": "succeeded"}


def _fake_tool(runner, monkeypatch, script: str):
    tool = runner.Tool("fakescan", sys.executable, "nuclei", ["quick"],
                       lambda target, profile, params, out: [sys.executable, "-c", script],
                       stats=runner.stats_nuclei)
    monkeypatch.setitem(runner.TOOLS, "fakescan", tool)
    monkeypatch.setattr(runner, "probe_target", lambda target: {"reachable": True})
    monkeypatch.setattr(runner, "LEASE_EXTEND_SECONDS", 0.2)
    monkeypatch.setattr(runner, "WATCHDOG_TICK_SECONDS", 0.05)
    return {"id": str(uuid.uuid4()), "tool": "fakescan", "target": "app.example.com"}


STATS_ONLY = (
    "import json, time\n"
    "for i in range(12):\n"
    "    print(json.dumps({'requests': str(i), 'errors': '0', 'percent': str(i * 8)}),"
    " flush=True)\n"
    "    time.sleep(0.1)\n"
)


def test_a_scan_that_prints_only_stats_keeps_its_lease(runner, monkeypatch):
    """0.39.1: every nuclei stats line hit `continue` before the extension."""
    job = _fake_tool(runner, monkeypatch, STATS_ONLY)
    client = _Client()
    runner.run_job(client, job, "lease", ["*.example.com"], timeout=60)
    kinds = [c[0] for c in client.calls]
    assert kinds.count("extend") >= 2, kinds
    assert kinds[-1] == "submit" and client.calls[-1][1]["scanner"]["percent"] == 88


def test_a_silent_scan_is_killed_at_the_job_timeout(runner, monkeypatch):
    """0.39.1: the timeout was checked only when a line arrived."""
    job = _fake_tool(runner, monkeypatch, "import time; time.sleep(30)")
    client = _Client()
    started = time.monotonic()
    runner.run_job(client, job, "lease", ["*.example.com"], timeout=1)
    assert time.monotonic() - started < 10
    failures = [c for c in client.calls if c[0] == "fail"]
    assert failures and "TimeoutError" in failures[0][1]


# ===========================================================================
# TD-46: inventory coverage aggregated in SQL, same answer
# ===========================================================================
def _reference_coverage(session, organization_id):
    """The 0.39.1 implementation, kept as the oracle."""
    from veyrs.models import Product, Vendor

    rows = session.execute(
        select(AssetProduct, Product, Vendor, Asset)
        .join(Product, AssetProduct.product_id == Product.id)
        .join(Vendor, Product.vendor_id == Vendor.id)
        .join(Asset, AssetProduct.asset_id == Asset.id)
        .where(AssetProduct.organization_id == organization_id)
    ).all()
    unmatched, no_version, matched = [], [], 0
    for install_row, product, vendor, asset in rows:
        entry = {"asset": asset.name, "vendor": vendor.name, "product": product.name,
                 "version": install_row.version, "raw_version": install_row.raw_version,
                 "detected_by": install_row.detected_by}
        if not inventory._has_applicability(session, product.id):
            entry["reason"] = ("no CVE applicability data references this product "
                               "-- either the name is wrong or no advisory exists yet")
            entry["suggestions"] = inventory._suggest(session, product.name)
            unmatched.append(entry)
            continue
        matched += 1
        if not install_row.version:
            entry["reason"] = "no version recorded; range matching cannot fire"
            no_version.append(entry)
    return {"installations": len(rows), "matchable": matched, "unmatched": len(unmatched),
            "missing_version": len(no_version), "unmatched_detail": unmatched[:200],
            "missing_version_detail": no_version[:200]}


def test_coverage_in_sql_equals_the_row_by_row_answer(org_a):
    org_id = org_a[0]
    tag = uuid.uuid4().hex[:8]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        known = intelligence.upsert_product(session, f"acme-{tag}", f"known-{tag}")
        unknown = intelligence.upsert_product(session, f"acme-{tag}", f"unknown-{tag}")
        cve_id = f"CVE-2096-{int(tag, 16)}"
        session.add(Cve(id=cve_id, title="t", description="t"))
        session.flush()
        session.add(CveCpeMatch(cve_id=cve_id, product_id=known.id, vulnerable=True,
                                cpe23=f"cpe:2.3:a:acme:{known.name}:*:*:*:*:*:*:*:*"))
        for i, (product, version) in enumerate([(known, "1.0"), (known, None), (known, ""),
                                                 (unknown, "2.0"), (unknown, None)]):
            asset = Asset(organization_id=org_id, name=f"cov-{i}-{tag}")
            session.add(asset)
            session.flush()
            session.add(AssetProduct(organization_id=org_id, asset_id=asset.id,
                                     product_id=product.id, version=version,
                                     detected_by="test"))
        session.flush()
        new = inventory.coverage(session, org_id)
        old = _reference_coverage(session, org_id)
        session.rollback()

    def ordered(report):
        key = lambda e: (e["asset"], e["vendor"], e["product"], str(e["version"]))  # noqa: E731
        return {**report, "unmatched_detail": sorted(report["unmatched_detail"], key=key),
                "missing_version_detail": sorted(report["missing_version_detail"], key=key)}

    assert ordered(new) == ordered(old)
    assert (new["installations"], new["matchable"], new["unmatched"],
            new["missing_version"]) == (5, 3, 2, 2)
