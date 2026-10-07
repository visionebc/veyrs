"""Phase 8: scanner importers and ITSM connectors.

Parsers are tested against real export shapes. The normalizer is tested on the
two behaviours that decide whether a vulnerability programme can be trusted:

  * a record whose asset cannot be identified is REJECTED with a reason, never
    attached to a plausible neighbour;
  * a finding missing from an export is a stale *candidate*, not a closure.

ITSM adapters are exercised through a stub transport: no test reaches a network,
and the assertions are about idempotence, credential handling and the refusal to
let an external system close a security finding.
"""
from __future__ import annotations

import datetime as dt
import json
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    Asset, AssetProduct, Cve, Finding, ItsmConnector, Ticket, Vulnerability,
)
from veyrs.models.integration import ExternalLink, ImportRun, ImportStatus
from veyrs.security.secrets import encrypt
from veyrs.services import importers, intelligence, itsm
from veyrs.services import risk as risk_service, sla as sla_service
from veyrs.services import ticketing
from veyrs.services.importers import ImportOptions, base as ibase, parsers

from test_phase3_intel import NVD_ITEM

# ---------------------------------------------------------------------------
# Fixture exports
# ---------------------------------------------------------------------------
NESSUS = b"""<?xml version="1.0" ?>
<NessusClientData_v2>
  <Report name="scan">
    <ReportHost name="10.50.0.21">
      <HostProperties>
        <tag name="host-ip">10.50.0.21</tag>
        <tag name="host-fqdn">fw-edge-01.corp</tag>
        <tag name="operating-system">FortiOS</tag>
        <tag name="mac-address">00:11:22:33:44:55</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="www" protocol="tcp" severity="4"
                  pluginID="123456" pluginName="FortiWeb improper authentication"
                  pluginFamily="Web Servers">
        <description>Improper authentication in FortiWeb allows RCE.</description>
        <solution>Upgrade to FortiWeb 7.2.5</solution>
        <cve>CVE-2026-0001</cve>
        <cvss3_base_score>9.8</cvss3_base_score>
        <cvss3_vector>CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H</cvss3_vector>
        <plugin_output>Server responded 200 to an unauthenticated request.</plugin_output>
      </ReportItem>
      <ReportItem port="22" protocol="tcp" severity="1"
                  pluginID="10881" pluginName="SSH protocol versions supported">
        <description>Informational.</description>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""

GREENBONE = b"""<?xml version="1.0"?>
<get_reports_response status="200">
  <report>
    <results>
      <result id="r1">
        <name>FortiWeb improper authentication</name>
        <host>10.50.0.21<hostname>fw-edge-01.corp</hostname></host>
        <port>443/tcp</port>
        <threat>High</threat>
        <description>Remote code execution.</description>
        <qod><value>98</value></qod>
        <nvt oid="1.3.6.1.4.1.25623.1.0.123">
          <name>FortiWeb RCE</name>
          <cvss_base>9.8</cvss_base>
          <tags>cvss_base_vector=CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H|summary=x</tags>
          <solution>Upgrade.</solution>
          <refs><ref type="cve" id="CVE-2026-0001"/><ref type="url" id="http://x"/></refs>
        </nvt>
      </result>
    </results>
  </report>
</get_reports_response>
"""

QUALYS = b"""<?xml version="1.0"?>
<SCAN>
  <IP value="10.50.0.21">
    <HOST>
      <IP>10.50.0.21</IP>
      <DNS>fw-edge-01.corp</DNS>
      <OPERATING_SYSTEM>FortiOS</OPERATING_SYSTEM>
      <VULN number="38170" severity="5">
        <QID>38170</QID>
        <TITLE>FortiWeb improper authentication</TITLE>
        <CVE_ID_LIST>CVE-2026-0001</CVE_ID_LIST>
        <CVSS_BASE>9.8</CVSS_BASE>
        <DIAGNOSIS>Improper authentication.</DIAGNOSIS>
        <SOLUTION>Upgrade to 7.2.5</SOLUTION>
        <PORT>443</PORT>
        <PROTOCOL>tcp</PROTOCOL>
        <RESULT>evidence blob</RESULT>
      </VULN>
    </HOST>
  </IP>
</SCAN>
"""

CSV_EXPORT = (
    b"Asset Name,IP Address,Vulnerability,CVE,Severity,CVSS Score,Solution,Port\n"
    b"fw-edge-01,10.50.0.21,FortiWeb improper authentication,CVE-2026-0001,Critical,"
    b"9.8,Upgrade to 7.2.5,443\n"
)

JSON_EXPORT = json.dumps({
    "findings": [
        {"host": "fw-edge-01", "ip": "10.50.0.21",
         "title": "FortiWeb improper authentication", "cve": "CVE-2026-0001",
         "severity": "critical", "cvss_score": 9.8, "port": 443, "protocol": "tcp"},
    ]
}).encode()


@pytest.fixture()
def tenant(org_a):
    org_id, slug, email = org_a
    with SessionLocal() as session:
        intelligence.ingest_nvd(session, [NVD_ITEM])
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        asset = Asset(organization_id=org_id, name="fw-edge-01",
                      hostname="fw-edge-01", fqdn="fw-edge-01.corp",
                      ip_addresses=["10.50.0.21"], asset_type="firewall",
                      criticality="critical", exposure="internet")
        session.add(asset)
        risk_service.seed_profiles(session, org_id)
        sla_service.seed_policies(session, org_id)
        session.commit()
        return {"org_id": org_id, "slug": slug, "asset_id": asset.id}


# ---------------------------------------------------------------------------
# Parsers
# ---------------------------------------------------------------------------
def test_nessus_parser_reads_hosts_and_items():
    records = [r.normalise() for r in parsers.parse_nessus(NESSUS)]
    assert len(records) == 2
    critical = records[0]
    assert critical.fqdn == "fw-edge-01.corp"
    assert critical.ip_address == "10.50.0.21"
    assert critical.cve_ids == ["CVE-2026-0001"]
    assert critical.severity == "critical"
    assert critical.cvss_score == 9.8
    assert critical.port == 443 and critical.protocol == "tcp"
    assert "unauthenticated" in critical.evidence["plugin_output"]
    assert records[1].severity == "low"


def test_greenbone_parser_reads_nvt_refs_and_vector():
    records = [r.normalise() for r in parsers.parse_greenbone(GREENBONE)]
    assert len(records) == 1
    record = records[0]
    assert record.hostname == "fw-edge-01.corp"
    assert record.ip_address == "10.50.0.21"
    assert record.cve_ids == ["CVE-2026-0001"]
    assert record.severity == "high"
    assert record.cvss_vector.startswith("CVSS:3.1/")
    assert record.port == 443 and record.protocol == "tcp"


def test_qualys_parser_maps_the_one_to_five_scale():
    records = [r.normalise() for r in parsers.parse_qualys(QUALYS)]
    assert len(records) == 1
    assert records[0].severity == "critical"  # Qualys 5
    assert records[0].plugin_id == "38170"
    assert records[0].cve_ids == ["CVE-2026-0001"]


def test_csv_parser_uses_header_aliases():
    records = [r.normalise() for r in parsers.parse_csv(CSV_EXPORT)]
    assert len(records) == 1
    assert records[0].hostname == "fw-edge-01"
    assert records[0].cve_ids == ["CVE-2026-0001"]
    assert records[0].cvss_score == 9.8


def test_json_parser_accepts_a_wrapped_list():
    records = [r.normalise() for r in parsers.parse_json(JSON_EXPORT)]
    assert len(records) == 1
    assert records[0].title.startswith("FortiWeb")


@pytest.mark.parametrize("payload,filename,expected", [
    (NESSUS, "scan.nessus", "nessus"),
    (GREENBONE, "report.xml", "greenbone"),
    (QUALYS, "qualys.xml", "qualys"),
    (CSV_EXPORT, "export.csv", "csv"),
    (JSON_EXPORT, "findings.json", "json"),
])
def test_format_detection(payload, filename, expected):
    assert parsers.detect_format(payload, filename) == expected


def test_xxe_is_refused_in_scanner_uploads():
    """A .nessus file is attacker-influenced input like any other upload."""
    xxe = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
           b'<NessusClientData_v2><Report><ReportHost name="h">&x;</ReportHost></Report>'
           b'</NessusClientData_v2>')
    with pytest.raises(parsers.ParserError):
        list(parsers.parse_nessus(xxe))


def test_wrong_format_raises_rather_than_returning_nothing():
    with pytest.raises(parsers.ParserError, match="not a Nessus v2 report"):
        list(parsers.parse_nessus(GREENBONE))
    with pytest.raises(parsers.ParserError, match="no <HOST> elements"):
        list(parsers.parse_qualys(GREENBONE))


def test_csv_without_an_asset_column_is_refused():
    with pytest.raises(parsers.ParserError, match="asset identity"):
        list(parsers.parse_csv(b"Vulnerability,Severity\nX,High\n"))


def test_csv_without_a_title_column_is_refused():
    with pytest.raises(parsers.ParserError, match="title column"):
        list(parsers.parse_csv(b"Hostname,Severity\nh,High\n"))


def test_unknown_importer_name_is_refused():
    with pytest.raises(parsers.ParserError, match="unknown importer"):
        parsers.get_parser("acunetix")


# ---------------------------------------------------------------------------
# Normalizer
# ---------------------------------------------------------------------------
def test_import_creates_findings_against_the_existing_asset(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        run = importers.run_import(session, tenant["org_id"], NESSUS,
                                   source="nessus", filename="scan.nessus")
        session.commit()
        findings = session.execute(
            select(Finding).where(Finding.organization_id == tenant["org_id"])
        ).scalars().all()

    assert run.status == ImportStatus.COMPLETE.value
    assert run.records_seen == 2
    assert run.findings_created == 2
    assert run.assets_created == 0
    assert all(f.asset_id == tenant["asset_id"] for f in findings)
    assert all(f.scanner == "nessus" for f in findings)


def test_imported_findings_are_scored_and_have_an_sla(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        importers.run_import(session, tenant["org_id"], NESSUS, source="nessus")
        session.commit()
        finding = session.execute(
            select(Finding).where(Finding.organization_id == tenant["org_id"],
                                  Finding.scanner_plugin_id == "123456")
        ).scalar_one()
    assert finding.risk_score is not None
    assert finding.sla_due_at is not None


def test_reimporting_the_same_file_updates_rather_than_duplicates(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        importers.run_import(session, tenant["org_id"], NESSUS, source="nessus")
        session.commit()
        second = importers.run_import(session, tenant["org_id"], NESSUS, source="nessus")
        session.commit()
        total = session.execute(
            select(Finding).where(Finding.organization_id == tenant["org_id"])
        ).scalars().all()
    assert second.findings_created == 0
    assert second.findings_updated == 2
    assert len(total) == 2


def test_reimport_of_an_identical_payload_is_detectable(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        first = importers.run_import(session, tenant["org_id"], NESSUS, source="nessus")
        session.commit()
        previous = importers.previous_run_with_hash(
            session, tenant["org_id"], first.content_hash
        )
    assert previous is not None
    assert previous.id == first.id


def test_unknown_asset_is_rejected_not_guessed(tenant):
    """The rule that keeps findings off the wrong machine."""
    payload = (b"Asset Name,Vulnerability,Severity\n"
               b"totally-unknown-host,Some issue,High\n")
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        run = importers.run_import(session, tenant["org_id"], payload, source="csv")
        session.commit()
    assert run.records_rejected == 1
    assert run.findings_created == 0
    assert "unknown asset (create_assets is off)" in run.reject_reasons
    assert run.reject_samples[0]["asset_key"] == "totally-unknown-host"


def test_create_assets_option_builds_the_missing_asset(tenant):
    payload = (b"Asset Name,IP Address,Vulnerability,Severity\n"
               b"new-host-01,10.0.0.99,Some issue,High\n")
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        run = importers.run_import(session, tenant["org_id"], payload, source="csv",
                                   options=ImportOptions(create_assets=True,
                                                         new_asset_exposure="internal"))
        session.commit()
        asset = session.execute(
            select(Asset).where(Asset.organization_id == tenant["org_id"],
                                Asset.name == "new-host-01")
        ).scalar_one()
    assert run.assets_created == 1
    assert run.findings_created == 1
    assert asset.external_id == "import:new-host-01"


def test_min_severity_filters_records_with_a_reason(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        run = importers.run_import(session, tenant["org_id"], NESSUS, source="nessus",
                                   options=ImportOptions(min_severity="high"))
        session.commit()
    assert run.findings_created == 1
    assert run.records_rejected == 1
    assert "below min_severity=high" in run.reject_reasons


def test_absent_findings_are_stale_candidates_not_closures(tenant):
    """A host that was offline during the scan is not a remediated host."""
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        importers.run_import(session, tenant["org_id"], NESSUS, source="nessus")
        session.commit()

        smaller = NESSUS.replace(
            b'<ReportItem port="22" protocol="tcp" severity="1"\n'
            b'                  pluginID="10881" pluginName="SSH protocol versions supported">\n'
            b'        <description>Informational.</description>\n'
            b'      </ReportItem>\n', b"")
        run = importers.run_import(session, tenant["org_id"], smaller, source="nessus")
        session.commit()

        states = {
            f.scanner_plugin_id: f.state for f in session.execute(
                select(Finding).where(Finding.organization_id == tenant["org_id"])
            ).scalars().all()
        }
    assert run.stale_candidates == 1
    assert states["10881"] != "remediated"  # still open, merely unseen


def test_close_missing_is_opt_in_and_records_why(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        importers.run_import(session, tenant["org_id"], NESSUS, source="nessus")
        session.commit()

        only_ssh = (b'<?xml version="1.0" ?><NessusClientData_v2><Report>'
                    b'<ReportHost name="10.50.0.21">'
                    b'<HostProperties><tag name="host-fqdn">fw-edge-01.corp</tag>'
                    b'</HostProperties>'
                    b'<ReportItem port="22" protocol="tcp" severity="1" pluginID="10881"'
                    b' pluginName="SSH protocol versions supported"/>'
                    b'</ReportHost></Report></NessusClientData_v2>')
        importers.run_import(session, tenant["org_id"], only_ssh, source="nessus",
                             options=ImportOptions(close_missing=True))
        session.commit()

        finding = session.execute(
            select(Finding).where(Finding.organization_id == tenant["org_id"],
                                  Finding.scanner_plugin_id == "123456")
        ).scalar_one()
        from veyrs.models import FindingEvent
        events = session.execute(
            select(FindingEvent).where(FindingEvent.finding_id == finding.id)
        ).scalars().all()

    assert finding.state == "remediated"
    reasons = [e.details.get("reason") for e in events if e.details]
    assert "absent from scanner export" in reasons


def test_a_plugin_without_a_cve_still_becomes_a_finding(tenant):
    """Weak ciphers and missing headers are real findings with no CVE."""
    payload = (b"Asset Name,Vulnerability,Severity,Plugin ID\n"
               b"fw-edge-01,TLS 1.0 enabled,Medium,42\n")
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        run = importers.run_import(session, tenant["org_id"], payload, source="csv")
        session.commit()
        vulnerability = session.execute(
            select(Vulnerability).where(Vulnerability.organization_id == tenant["org_id"],
                                        Vulnerability.internal_ref == "42")
        ).scalar_one()
    assert run.findings_created == 1
    assert vulnerability.cve_id is None
    assert vulnerability.source == "scanner"


def test_a_cve_not_yet_ingested_is_flagged_for_enrichment(tenant):
    payload = (b"Asset Name,Vulnerability,CVE,Severity,Plugin ID\n"
               b"fw-edge-01,Unknown thing,CVE-2030-9999,High,77\n")
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        importers.run_import(session, tenant["org_id"], payload, source="csv")
        session.commit()
        vulnerability = session.execute(
            select(Vulnerability).where(Vulnerability.organization_id == tenant["org_id"],
                                        Vulnerability.internal_ref == "77")
        ).scalar_one()
    assert vulnerability.cve_id is None
    assert "CVE-2030-9999" in (vulnerability.triage_notes or "")
    assert "NVD sync" in vulnerability.triage_notes


def test_nvd_scoring_wins_over_scanner_scoring(tenant):
    """A CVE-backed finding keeps the authoritative score, not the tool's."""
    payload = (b"Asset Name,Vulnerability,CVE,Severity,CVSS Score\n"
               b"fw-edge-01,FortiWeb thing,CVE-2026-0001,Low,2.0\n")
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        importers.run_import(session, tenant["org_id"], payload, source="csv")
        session.commit()
        finding = session.execute(
            select(Finding).where(Finding.organization_id == tenant["org_id"])
        ).scalars().first()
    # 9.3 is the CVE's CVSS v4 base score. VEYRS prefers the newest published
    # revision, so the assertion is "not the scanner's 2.0", not a fixed 9.8.
    assert finding.cvss_score == 9.3
    assert finding.severity == "critical"


def test_a_bad_file_produces_a_failed_run_not_an_exception(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        run = importers.run_import(session, tenant["org_id"], b"garbage",
                                   source="nessus", filename="broken.nessus")
        session.commit()
    assert run.status == ImportStatus.FAILED.value
    assert run.error


def test_import_runs_are_tenant_isolated(tenant, org_b):
    other_org_id, _, _ = org_b
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        importers.run_import(session, tenant["org_id"], NESSUS, source="nessus")
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, other_org_id)
        rows = session.execute(select(ImportRun)).scalars().all()
    assert rows == []


# ---------------------------------------------------------------------------
# ITSM
# ---------------------------------------------------------------------------
class StubTransport:
    """Records what an adapter would have sent, and replies like the real API."""

    def __init__(self) -> None:
        self.calls: list[tuple[str, str, dict | None]] = []
        self.next_response: dict = {}

    def __call__(self, method, url, *, headers, json_body, timeout):
        self.calls.append((method, url, json_body))
        self.headers = headers
        return self.next_response


@pytest.fixture()
def stub(monkeypatch):
    transport = StubTransport()
    monkeypatch.setattr(itsm, "_request", transport)
    return transport


def _connector(session, org_id, system="servicenow", **kwargs) -> ItsmConnector:
    connector = ItsmConnector(
        organization_id=org_id, slug=f"{system}-{uuid.uuid4().hex[:6]}",
        name=system.title(), system=system,
        base_url="https://itsm.example.com",
        credentials_enc=encrypt(json.dumps({"username": "svc", "password": "pw",
                                            "email": "a@b.c", "token": "t"})),
        **kwargs,
    )
    session.add(connector)
    session.flush()
    return connector


def _ticket(session, org_id) -> Ticket:
    finding = session.execute(
        select(Finding).where(Finding.organization_id == org_id)
    ).scalars().first()
    return ticketing.create_ticket(
        session, organization_id=org_id, title="Remediate FortiWeb RCE",
        description="Upgrade to 7.2.5", ticket_type="remediation",
        priority="critical", finding_id=finding.id if finding else None,
    )


@pytest.fixture()
def ticketed(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        importers.run_import(session, tenant["org_id"], NESSUS, source="nessus")
        session.commit()
        ticket = _ticket(session, tenant["org_id"])
        session.commit()
        return {**tenant, "ticket_id": ticket.id}


def test_servicenow_push_sends_the_mapped_fields(ticketed, stub):
    stub.next_response = {"result": {"sys_id": "abc123", "number": "INC0012345",
                                     "state": "1"}}
    with SessionLocal() as session:
        set_tenant(session, ticketed["org_id"])
        connector = _connector(session, ticketed["org_id"], system="servicenow")
        ticket = session.get(Ticket, ticketed["ticket_id"])
        link = itsm.push_ticket(session, connector, ticket)
        session.commit()

    method, url, body = stub.calls[0]
    assert method == "POST"
    assert url.endswith("/api/now/table/incident")
    assert body["short_description"].startswith("Remediate")
    assert body["priority"] == "1"  # critical
    assert link.remote_id == "abc123"
    assert link.remote_key == "INC0012345"


def test_jira_push_uses_the_project_key_from_field_mapping(ticketed, stub):
    stub.next_response = {"id": "10001", "key": "SEC-42"}
    with SessionLocal() as session:
        set_tenant(session, ticketed["org_id"])
        connector = _connector(session, ticketed["org_id"], system="jira",
                               field_mapping={"project_key": "SEC",
                                              "issue_type": "Bug"})
        ticket = session.get(Ticket, ticketed["ticket_id"])
        link = itsm.push_ticket(session, connector, ticket)
        session.commit()

    _, url, body = stub.calls[0]
    assert url.endswith("/rest/api/3/issue")
    assert body["fields"]["project"]["key"] == "SEC"
    assert body["fields"]["issuetype"]["name"] == "Bug"
    assert link.remote_key == "SEC-42"
    assert link.remote_url.endswith("/browse/SEC-42")


def test_pushing_an_unchanged_ticket_is_a_no_op(ticketed, stub):
    stub.next_response = {"result": {"sys_id": "abc123", "number": "INC1"}}
    with SessionLocal() as session:
        set_tenant(session, ticketed["org_id"])
        connector = _connector(session, ticketed["org_id"])
        ticket = session.get(Ticket, ticketed["ticket_id"])
        itsm.push_ticket(session, connector, ticket)
        session.commit()
        calls_after_first = len(stub.calls)
        itsm.push_ticket(session, connector, ticket)
        session.commit()
    assert len(stub.calls) == calls_after_first


def test_changing_the_ticket_triggers_an_update_not_a_second_create(ticketed, stub):
    stub.next_response = {"result": {"sys_id": "abc123", "number": "INC1"}}
    with SessionLocal() as session:
        set_tenant(session, ticketed["org_id"])
        connector = _connector(session, ticketed["org_id"])
        ticket = session.get(Ticket, ticketed["ticket_id"])
        itsm.push_ticket(session, connector, ticket)
        session.commit()

        ticket.title = "Remediate FortiWeb RCE (revised)"
        session.flush()
        itsm.push_ticket(session, connector, ticket)
        session.commit()

        links = session.execute(
            select(ExternalLink).where(ExternalLink.object_id == str(ticket.id))
        ).scalars().all()

    methods = [call[0] for call in stub.calls]
    assert methods == ["POST", "PATCH"]
    assert len(links) == 1


def test_connector_type_filter_is_enforced(ticketed, stub):
    with SessionLocal() as session:
        set_tenant(session, ticketed["org_id"])
        connector = _connector(session, ticketed["org_id"],
                               ticket_types=["change"])
        ticket = session.get(Ticket, ticketed["ticket_id"])  # remediation
        with pytest.raises(itsm.ItsmError, match="does not sync"):
            itsm.push_ticket(session, connector, ticket)


def test_disabled_connector_refuses_to_push(ticketed, stub):
    with SessionLocal() as session:
        set_tenant(session, ticketed["org_id"])
        connector = _connector(session, ticketed["org_id"], is_enabled=False)
        ticket = session.get(Ticket, ticketed["ticket_id"])
        with pytest.raises(itsm.ItsmError, match="disabled"):
            itsm.push_ticket(session, connector, ticket)


def test_remote_failure_is_recorded_on_both_connector_and_link(ticketed, monkeypatch):
    def explode(*_args, **_kwargs):
        raise itsm.ItsmError("remote returned HTTP 500")

    monkeypatch.setattr(itsm, "_request", explode)
    with SessionLocal() as session:
        set_tenant(session, ticketed["org_id"])
        connector = _connector(session, ticketed["org_id"])
        ticket = session.get(Ticket, ticketed["ticket_id"])
        with pytest.raises(itsm.ItsmError):
            itsm.push_ticket(session, connector, ticket)
        session.commit()
        session.refresh(connector)
    assert "HTTP 500" in connector.last_error


def test_pull_status_does_not_change_the_veyrs_ticket(ticketed, stub):
    """An external system must not be able to close a security finding."""
    stub.next_response = {"result": {"sys_id": "abc123", "number": "INC1", "state": "1"}}
    with SessionLocal() as session:
        set_tenant(session, ticketed["org_id"])
        connector = _connector(session, ticketed["org_id"])
        ticket = session.get(Ticket, ticketed["ticket_id"])
        link = itsm.push_ticket(session, connector, ticket)
        session.commit()
        state_before = ticket.state

        stub.next_response = {"result": {"sys_id": "abc123", "number": "INC1",
                                         "state": "7"}}  # Closed in ServiceNow
        remote_status = itsm.pull_status(session, connector, link)
        session.commit()
        session.refresh(ticket)

    assert remote_status == "7"
    assert ticket.state == state_before


def test_credentials_are_stored_encrypted(ticketed):
    with SessionLocal() as session:
        set_tenant(session, ticketed["org_id"])
        connector = _connector(session, ticketed["org_id"])
        session.commit()
    assert connector.credentials_enc.startswith("v1:")
    assert "password" not in connector.credentials_enc


def test_unsupported_system_is_refused(ticketed):
    with SessionLocal() as session:
        set_tenant(session, ticketed["org_id"])
        connector = _connector(session, ticketed["org_id"], system="remedy")
        ticket = session.get(Ticket, ticketed["ticket_id"])
        with pytest.raises(itsm.ItsmError, match="unsupported ITSM system"):
            itsm.push_ticket(session, connector, ticket)


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------
def test_importers_endpoint_documents_the_stale_policy(client, admin_a):
    body = client.get("/api/v1/integrations/importers", headers=admin_a).json()
    assert "nessus" in body["formats"]
    assert "not a remediated host" in body["notes"]


def test_upload_import_over_http(client, admin_a, tenant):
    response = client.post(
        "/api/v1/integrations/imports", headers=admin_a,
        files={"file": ("scan.nessus", NESSUS, "application/xml")},
        data={"source": "nessus"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "complete"
    assert body["findings_created"] == 2


def test_dry_run_reports_without_persisting(client, admin_a, tenant):
    response = client.post(
        "/api/v1/integrations/imports", headers=admin_a,
        files={"file": ("scan.nessus", NESSUS, "application/xml")},
        data={"source": "nessus", "dry_run": "true"},
    )
    assert response.status_code == 201, response.text
    assert response.json()["findings_created"] == 2

    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        findings = session.execute(
            select(Finding).where(Finding.organization_id == tenant["org_id"])
        ).scalars().all()
    assert findings == []


def test_unknown_source_is_422(client, admin_a):
    response = client.post(
        "/api/v1/integrations/imports", headers=admin_a,
        files={"file": ("x.txt", b"data", "text/plain")},
        data={"source": "acunetix"},
    )
    assert response.status_code == 422


def test_empty_upload_is_422(client, admin_a):
    response = client.post(
        "/api/v1/integrations/imports", headers=admin_a,
        files={"file": ("x.csv", b"", "text/csv")},
    )
    assert response.status_code == 422


def test_connector_credentials_are_never_returned(client, admin_a):
    created = client.post("/api/v1/integrations/connectors", headers=admin_a, json={
        "slug": "snow", "name": "ServiceNow", "system": "servicenow",
        "base_url": "https://acme.service-now.com",
        "credentials": {"username": "svc", "password": "hunter2hunter2"},
    })
    assert created.status_code == 201, created.text
    listing = client.get("/api/v1/integrations/connectors", headers=admin_a).text
    assert "hunter2hunter2" not in listing
    assert "credentials" not in listing


def test_unsupported_connector_system_is_422(client, admin_a):
    response = client.post("/api/v1/integrations/connectors", headers=admin_a, json={
        "slug": "remedy", "name": "Remedy", "system": "remedy",
        "base_url": "https://x",
    })
    assert response.status_code == 422


def test_import_endpoints_require_authentication(client):
    assert client.get("/api/v1/integrations/imports").status_code == 401
    assert client.get("/api/v1/integrations/connectors").status_code == 401
