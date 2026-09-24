"""Phase 15: the unified ingestion core.

These tests cover the three capabilities merged in from DefectDojo and Faraday,
and one production defect the merge exposed and fixed.

**The defect.** `importers.base._close_missing()` scoped itself to
`Finding.scanner` across the whole organisation. Two engagements scanned by the
same tool - a DMZ sweep and a corporate sweep, both "nessus" - therefore closed
each other's findings: importing the corporate export marked every DMZ finding
remediated, because the DMZ hosts were not in it. `test_reimport_does_not_close_
findings_outside_its_own_scope` is the regression test for exactly that, and it
fails against the previous implementation.

**Deduplication.** Verified by asserting the *shape* of the collision the old
single algorithm produced: SAST records differing only in file and line hashed
identically under `legacy` (no port, no path) and collapse into one finding. The
point is not that the new hash is different, it is that the old one was wrong.

**Endpoints and risk acceptance** are tested on their invariants: canonical
identity across tool spellings, and an acceptance that cannot be self-approved
and does not outlive its expiry date.
"""
from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    Asset, Endpoint, Engagement, Finding, FindingEndpoint, FindingEvent, OPEN_STATES,
    RiskAcceptance, RiskAcceptanceState, ScanTest, TestFinding, User,
)
from veyrs.security.auth import hash_password
from veyrs.services import dedupe, endpoints as endpoint_service, engagements, importers
from veyrs.services import intelligence
from veyrs.services import risk as risk_service, sla as sla_service
from veyrs.services.importers import ImportOptions

from test_phase3_intel import NVD_ITEM


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
def _nessus(host_ip: str, fqdn: str, items: str) -> bytes:
    return (
        '<?xml version="1.0" ?><NessusClientData_v2><Report name="scan">'
        f'<ReportHost name="{host_ip}"><HostProperties>'
        f'<tag name="host-ip">{host_ip}</tag><tag name="host-fqdn">{fqdn}</tag>'
        f"</HostProperties>{items}</ReportHost></Report></NessusClientData_v2>"
    ).encode()


ITEM_CRITICAL = (
    '<ReportItem port="443" protocol="tcp" severity="4" pluginID="123456"'
    ' pluginName="FortiWeb improper authentication">'
    "<cve>CVE-2026-0001</cve><description>RCE</description></ReportItem>"
)
ITEM_SSH = (
    '<ReportItem port="22" protocol="tcp" severity="1" pluginID="10881"'
    ' pluginName="SSH protocol versions supported"/>'
)


@pytest.fixture()
def estate(org_a):
    """Two assets in one tenant, each scanned by the same tool separately."""
    org_id, slug, email = org_a
    with SessionLocal() as session:
        intelligence.ingest_nvd(session, [NVD_ITEM])
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        dmz = Asset(organization_id=org_id, name="fw-edge-01", hostname="fw-edge-01",
                    fqdn="fw-edge-01.corp", ip_addresses=["10.50.0.21"],
                    asset_type="firewall", criticality="critical", exposure="internet")
        corp = Asset(organization_id=org_id, name="web-02", hostname="web-02",
                     fqdn="web-02.corp", ip_addresses=["10.50.0.24"],
                     asset_type="server", criticality="high", exposure="internal")
        session.add_all([dmz, corp])
        risk_service.seed_profiles(session, org_id)
        sla_service.seed_policies(session, org_id)
        session.commit()
        return {"org_id": org_id, "slug": slug, "email": email,
                "dmz_id": dmz.id, "corp_id": corp.id}


# ---------------------------------------------------------------------------
# The regression: reimport scope
# ---------------------------------------------------------------------------
def test_reimport_does_not_close_findings_outside_its_own_scope(estate):
    """The defect that motivated the whole engagement/test hierarchy.

    Two engagements, one scanner name. Importing the corporate export used to
    close the DMZ engagement's findings, because the old scope was
    `Finding.scanner` across the entire organisation.
    """
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        dmz_engagement = engagements.create_engagement(
            session, org_id, name="DMZ quarterly sweep")
        corp_engagement = engagements.create_engagement(
            session, org_id, name="Corporate quarterly sweep")
        session.commit()
        dmz_engagement_id, corp_engagement_id = dmz_engagement.id, corp_engagement.id

    with SessionLocal() as session:
        set_tenant(session, org_id)
        importers.run_import(
            session, org_id, _nessus("10.50.0.21", "fw-edge-01.corp", ITEM_CRITICAL),
            source="nessus",
            options=ImportOptions(engagement_id=dmz_engagement_id),
        )
        session.commit()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        dmz_finding = session.execute(
            select(Finding).where(Finding.organization_id == org_id,
                                  Finding.asset_id == estate["dmz_id"])
        ).scalars().one()
        assert dmz_finding.state in OPEN_STATES

    # A completely separate engagement, same scanner, different hosts, and the
    # operator explicitly asking for absent findings to be closed.
    with SessionLocal() as session:
        set_tenant(session, org_id)
        importers.run_import(
            session, org_id, _nessus("10.50.0.24", "web-02.corp", ITEM_SSH),
            source="nessus",
            options=ImportOptions(engagement_id=corp_engagement_id,
                                  close_absent=True, absence_threshold=1),
        )
        session.commit()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        dmz_finding = session.execute(
            select(Finding).where(Finding.organization_id == org_id,
                                  Finding.asset_id == estate["dmz_id"])
        ).scalars().one()
        # THE assertion. Previously: "remediated".
        assert dmz_finding.state in OPEN_STATES, (
            "an import into another engagement closed a finding it never looked at"
        )


def test_reimport_closes_what_its_own_test_stopped_reporting(estate):
    """The other half: within its own scope, closure must still work."""
    org_id = estate["org_id"]
    both = ITEM_CRITICAL + ITEM_SSH

    with SessionLocal() as session:
        set_tenant(session, org_id)
        engagement = engagements.create_engagement(
            session, org_id, name="Edge CI", engagement_type="ci_cd")
        session.commit()
        engagement_id = engagement.id

    with SessionLocal() as session:
        set_tenant(session, org_id)
        importers.run_import(session, org_id, _nessus("10.50.0.21", "fw-edge-01.corp", both),
                             source="nessus",
                             options=ImportOptions(engagement_id=engagement_id))
        session.commit()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        open_now = session.execute(
            select(Finding).where(Finding.organization_id == org_id)
        ).scalars().all()
        assert len(open_now) == 2

    # Second run of the SAME test drops the SSH item: it was fixed.
    with SessionLocal() as session:
        set_tenant(session, org_id)
        run = importers.run_import(
            session, org_id, _nessus("10.50.0.21", "fw-edge-01.corp", ITEM_CRITICAL),
            source="nessus",
            options=ImportOptions(engagement_id=engagement_id, close_absent=True,
                                  absence_threshold=1),
        )
        session.commit()
        assert run.findings_closed_absent == 1

    with SessionLocal() as session:
        set_tenant(session, org_id)
        ssh = session.execute(
            select(Finding).where(Finding.organization_id == org_id,
                                  Finding.scanner_plugin_id == "10881")
        ).scalars().one()
        assert ssh.state == "remediated"
        events = session.execute(
            select(FindingEvent).where(FindingEvent.finding_id == ssh.id)
        ).scalars().all()
        closure = [e for e in events if (e.details or {}).get("reason")
                   == "absent from scanner export"]
        assert closure, "closure must record that it came from absence, not verification"
        assert closure[0].details["evidence"] == "absence"


def test_a_single_absence_does_not_close_on_a_scheduled_sweep(estate):
    """Scheduled scans skip offline hosts. One absence is noise, not a fix."""
    org_id = estate["org_id"]
    both = ITEM_CRITICAL + ITEM_SSH

    with SessionLocal() as session:
        set_tenant(session, org_id)
        engagement = engagements.create_engagement(
            session, org_id, name="Nightly sweep", engagement_type="scheduled")
        session.commit()
        engagement_id = engagement.id
        options = ImportOptions(engagement_id=engagement_id, close_absent=True)

    with SessionLocal() as session:
        set_tenant(session, org_id)
        importers.run_import(session, org_id, _nessus("10.50.0.21", "fw-edge-01.corp", both),
                             source="nessus", options=options)
        session.commit()

    # Night two: the host was offline, so only one item came back.
    with SessionLocal() as session:
        set_tenant(session, org_id)
        run = importers.run_import(
            session, org_id, _nessus("10.50.0.21", "fw-edge-01.corp", ITEM_CRITICAL),
            source="nessus", options=options)
        session.commit()
        assert run.findings_marked_absent == 1
        assert run.findings_closed_absent == 0

    with SessionLocal() as session:
        set_tenant(session, org_id)
        ssh = session.execute(
            select(Finding).where(Finding.organization_id == org_id,
                                  Finding.scanner_plugin_id == "10881")
        ).scalars().one()
        assert ssh.state in OPEN_STATES

    # Night three: still absent. Two consecutive absences is evidence.
    with SessionLocal() as session:
        set_tenant(session, org_id)
        run = importers.run_import(
            session, org_id, _nessus("10.50.0.21", "fw-edge-01.corp", ITEM_CRITICAL),
            source="nessus", options=options)
        session.commit()
        assert run.findings_closed_absent == 1


def test_a_reappearing_finding_resets_its_absence_counter(estate):
    org_id = estate["org_id"]
    both = ITEM_CRITICAL + ITEM_SSH
    with SessionLocal() as session:
        set_tenant(session, org_id)
        engagement = engagements.create_engagement(
            session, org_id, name="Flapping host", engagement_type="scheduled")
        session.commit()
        options = ImportOptions(engagement_id=engagement.id, close_absent=True)

    for payload in (both, ITEM_CRITICAL, both, ITEM_CRITICAL):
        with SessionLocal() as session:
            set_tenant(session, org_id)
            importers.run_import(
                session, org_id, _nessus("10.50.0.21", "fw-edge-01.corp", payload),
                source="nessus", options=options)
            session.commit()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        ssh = session.execute(
            select(Finding).where(Finding.organization_id == org_id,
                                  Finding.scanner_plugin_id == "10881")
        ).scalars().one()
        # Absent, present, absent -> one consecutive absence, never two.
        assert ssh.state in OPEN_STATES


def test_unscoped_imports_land_in_the_default_engagement(estate):
    """Callers that name no scope must keep working - and still be scoped."""
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        run = importers.run_import(
            session, org_id, _nessus("10.50.0.21", "fw-edge-01.corp", ITEM_CRITICAL),
            source="nessus")
        session.commit()
        assert run.test_id is not None and run.engagement_id is not None
        engagement = session.get(Engagement, run.engagement_id)
        assert engagement.slug == "continuous-scanning"


def test_repeated_imports_reuse_one_test(estate):
    org_id = estate["org_id"]
    for _ in range(3):
        with SessionLocal() as session:
            set_tenant(session, org_id)
            importers.run_import(
                session, org_id, _nessus("10.50.0.21", "fw-edge-01.corp", ITEM_CRITICAL),
                source="nessus")
            session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        tests = session.execute(
            select(ScanTest).where(ScanTest.organization_id == org_id)
        ).scalars().all()
        assert len(tests) == 1
        assert tests[0].reimport_count == 3


# ---------------------------------------------------------------------------
# Deduplication
# ---------------------------------------------------------------------------
class _Record:
    """Minimal ScanRecord stand-in: dedupe reads attributes, nothing else."""

    def __init__(self, **kwargs):
        defaults = dict(
            title="", severity=None, cwe=None, plugin_id=None, unique_id=None,
            file_path=None, line=None, component_name=None, component_version=None,
            port=None, protocol=None, path=None, description=None,
        )
        defaults.update(kwargs)
        for key, value in defaults.items():
            setattr(self, key, value)


ORG = uuid.uuid4()
ASSET = uuid.uuid4()


def _identity(record, config, **kwargs):
    return dedupe.resolve_identity(
        record, config=config, organization_id=ORG, asset_id=ASSET,
        vuln_ref="CVE-2026-0001", scanner="semgrep", **kwargs,
    )


def test_legacy_algorithm_collapses_sast_findings_that_differ_only_by_location():
    """Why the single hardcoded rule had to go: this is data loss, not dedupe."""
    a = _Record(title="Hardcoded secret", file_path="src/a.py", line=12)
    b = _Record(title="Hardcoded secret", file_path="src/b.py", line=88)
    legacy = dedupe.DedupeConfig(dedupe.LEGACY)
    assert _identity(a, legacy).dedupe_key == _identity(b, legacy).dedupe_key


def test_hash_code_separates_them():
    a = _Record(title="Hardcoded secret", file_path="src/a.py", line=12)
    b = _Record(title="Hardcoded secret", file_path="src/b.py", line=88)
    config = dedupe.DedupeConfig(dedupe.HASH_CODE, ("title", "file_path", "line", "asset"))
    assert _identity(a, config).dedupe_key != _identity(b, config).dedupe_key


def test_hash_code_is_stable_across_cosmetic_differences():
    """Whitespace and case must not fork a finding on every single scan."""
    config = dedupe.DedupeConfig(dedupe.HASH_CODE, ("title", "file_path"))
    a = _Record(title="SQL  Injection", file_path="src/a.py")
    b = _Record(title="sql injection", file_path="src/a.py")
    assert _identity(a, config).dedupe_key == _identity(b, config).dedupe_key


def test_field_names_are_hashed_so_values_cannot_cross_fields():
    """Config ('title',) with title='x' must not collide with ('cwe',) cwe='x'."""
    by_title = dedupe.DedupeConfig(dedupe.HASH_CODE, ("title",))
    by_cwe = dedupe.DedupeConfig(dedupe.HASH_CODE, ("cwe",))
    assert (_identity(_Record(title="x"), by_title).dedupe_key
            != _identity(_Record(cwe="x"), by_cwe).dedupe_key)


def test_unique_id_algorithm_falls_back_when_the_tool_supplies_none():
    config = dedupe.DedupeConfig(dedupe.UNIQUE_ID)
    identity = _identity(_Record(title="no id here"), config)
    assert identity.algorithm == dedupe.LEGACY


def test_unique_id_or_hash_prefers_the_tools_own_id():
    config = dedupe.DedupeConfig(dedupe.UNIQUE_ID_OR_HASH, ("title",))
    identity = _identity(_Record(title="XSS", unique_id="semgrep:abc123"), config)
    assert identity.unique_id == "semgrep:abc123"
    assert identity.algorithm == dedupe.UNIQUE_ID_OR_HASH


def test_a_bad_config_is_refused_not_silently_ignored():
    with pytest.raises(dedupe.DedupeConfigError):
        dedupe.DedupeConfig(dedupe.HASH_CODE, ("titel",))   # typo
    with pytest.raises(dedupe.DedupeConfigError):
        dedupe.DedupeConfig("magic")
    with pytest.raises(dedupe.DedupeConfigError):
        dedupe.DedupeConfig(dedupe.HASH_CODE, ())           # would hash nothing


def test_registered_scanners_keep_legacy_identity(estate):
    """The migration guarantee: no production finding is re-keyed by this work."""
    for scanner in ("nessus", "qualys", "greenbone", "csv", "json"):
        assert dedupe.config_for(scanner).algorithm == dedupe.LEGACY
    assert dedupe.config_for("a-parser-nobody-registered").algorithm == dedupe.LEGACY


def test_legacy_key_matches_the_original_correlation_formula():
    """Byte-for-byte, or every existing finding duplicates on the next import."""
    import hashlib

    from veyrs.services import correlation

    org, asset = uuid.uuid4(), uuid.uuid4()
    expected = hashlib.sha256(
        "|".join([str(org), str(asset), "CVE-2026-0001", "443", "tcp", "/admin"])
        .encode("utf-8")
    ).hexdigest()
    assert correlation.dedupe_key(
        organization_id=org, asset_id=asset, vuln_ref="cve-2026-0001",
        port=443, protocol="TCP", path="/Admin",
    ) == expected


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("raw, expected", [
    ("https://APP.example.com:443/login", "https://app.example.com/login"),
    ("https://app.example.com/login/", "https://app.example.com/login"),
    ("http://app.example.com:80/a//b", "http://app.example.com/a/b"),
    ("https://app.example.com/s?b=2&a=1", "https://app.example.com/s?a=1&b=2"),
    ("https://app.example.com:8443/x", "https://app.example.com:8443/x"),
    ("app.example.com/login", "app.example.com/login"),
    ("https://app.example.com/app#/admin", "https://app.example.com/app#/admin"),
])
def test_endpoint_canonicalisation(raw, expected):
    parts = endpoint_service.parse_url(raw)
    canonical, _ = endpoint_service.canonicalise(**parts)
    assert canonical == expected


def test_three_tools_spelling_one_url_produce_one_endpoint(estate):
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        for url in ("https://app.example.com:443/login",
                    "https://APP.example.com/login/",
                    "https://app.example.com/login"):
            endpoint_service.upsert_endpoint(
                session, org_id, **endpoint_service.parse_url(url))
        session.commit()
        rows = session.execute(
            select(Endpoint).where(Endpoint.organization_id == org_id)
        ).scalars().all()
        assert len(rows) == 1


def test_a_host_level_finding_creates_no_endpoint(estate):
    """Otherwise the endpoint table becomes a duplicate of the asset register."""
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        endpoint, created = endpoint_service.endpoint_from_record(
            session, org_id, _Record(title="Missing kernel patch"), asset_id=estate["dmz_id"])
        assert endpoint is None and created is False


def test_reobserving_a_mitigated_endpoint_clears_the_flag(estate):
    """A fix that did not hold is a regression, not a still-mitigated endpoint."""
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        importers.run_import(
            session, org_id, _nessus("10.50.0.21", "fw-edge-01.corp", ITEM_CRITICAL),
            source="nessus")
        session.commit()
        finding = session.execute(
            select(Finding).where(Finding.organization_id == org_id)
        ).scalars().first()
        link = session.execute(
            select(FindingEndpoint).where(FindingEndpoint.finding_id == finding.id)
        ).scalars().one()
        endpoint_service.mitigate(
            session, organization_id=org_id, finding_id=finding.id,
            endpoint_ids=[link.endpoint_id])
        session.commit()
        assert session.get(FindingEndpoint, link.id).mitigated is True

    with SessionLocal() as session:
        set_tenant(session, org_id)
        importers.run_import(
            session, org_id, _nessus("10.50.0.21", "fw-edge-01.corp", ITEM_CRITICAL),
            source="nessus")
        session.commit()
        refreshed = session.execute(
            select(FindingEndpoint).where(FindingEndpoint.organization_id == org_id)
        ).scalars().one()
        assert refreshed.mitigated is False


# ---------------------------------------------------------------------------
# Risk acceptance
# ---------------------------------------------------------------------------
def _two_users(session, org_id):
    users = []
    for label in ("requester", "approver"):
        user = User(organization_id=org_id, email=f"{label}-{uuid.uuid4().hex[:8]}@x.test",
                    full_name=label.title(), password_hash=hash_password("Sufficiently-Long-1"),
                    is_active=True)
        session.add(user)
        users.append(user)
    session.flush()
    return users


@pytest.fixture()
def accepted_setup(estate):
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        importers.run_import(
            session, org_id, _nessus("10.50.0.21", "fw-edge-01.corp", ITEM_CRITICAL),
            source="nessus")
        requester, approver = _two_users(session, org_id)
        session.commit()
        finding = session.execute(
            select(Finding).where(Finding.organization_id == org_id)
        ).scalars().first()
        return {"org_id": org_id, "finding_id": finding.id,
                "requester_id": requester.id, "approver_id": approver.id}


def test_a_pending_acceptance_does_not_silence_the_finding(accepted_setup):
    """Asking is not deciding, or anyone could mute a finding by requesting."""
    with SessionLocal() as session:
        set_tenant(session, accepted_setup["org_id"])
        engagements.request_acceptance(
            session, accepted_setup["org_id"], name="Legacy appliance",
            reason="Vendor patch lands in Q4; compensating WAF rule deployed.",
            finding_ids=[accepted_setup["finding_id"]],
            requested_by_id=accepted_setup["requester_id"],
            expires_on=dt.date.today() + dt.timedelta(days=30),
        )
        session.commit()
        finding = session.get(Finding, accepted_setup["finding_id"])
        assert finding.state in OPEN_STATES


def test_the_requester_cannot_approve_their_own_acceptance(accepted_setup):
    with SessionLocal() as session:
        set_tenant(session, accepted_setup["org_id"])
        acceptance = engagements.request_acceptance(
            session, accepted_setup["org_id"], name="Self serve",
            reason="Because I said so.",
            finding_ids=[accepted_setup["finding_id"]],
            requested_by_id=accepted_setup["requester_id"],
        )
        session.commit()
        with pytest.raises(ValueError, match="cannot approve their own"):
            engagements.approve(session, acceptance,
                                approved_by_id=accepted_setup["requester_id"])


def test_an_acceptance_requires_a_written_reason(accepted_setup):
    with SessionLocal() as session:
        set_tenant(session, accepted_setup["org_id"])
        with pytest.raises(ValueError, match="written reason"):
            engagements.request_acceptance(
                session, accepted_setup["org_id"], name="No reason", reason="   ",
                finding_ids=[accepted_setup["finding_id"]])


def test_approval_accepts_the_finding_and_expiry_puts_it_back(accepted_setup):
    org_id = accepted_setup["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        acceptance = engagements.request_acceptance(
            session, org_id, name="Q4 patch window",
            reason="Vendor fix scheduled; WAF virtual patch in place.",
            finding_ids=[accepted_setup["finding_id"]],
            requested_by_id=accepted_setup["requester_id"],
            expires_on=dt.date.today() - dt.timedelta(days=1),   # already due
        )
        engagements.approve(session, acceptance,
                            approved_by_id=accepted_setup["approver_id"])
        session.commit()
        assert session.get(Finding, accepted_setup["finding_id"]).state == "accepted_risk"
        acceptance_id = acceptance.id

    with SessionLocal() as session:
        set_tenant(session, org_id)
        stats = engagements.expire_due(session, org_id)
        session.commit()
        assert stats["expired"] == 1
        assert stats["findings_reactivated"] == 1
        assert session.get(RiskAcceptance, acceptance_id).state == \
            RiskAcceptanceState.EXPIRED.value
        finding = session.get(Finding, accepted_setup["finding_id"])
        assert finding.state in OPEN_STATES
        assert finding.accepted_until is None


def test_expiry_does_not_launder_an_overdue_sla(accepted_setup):
    """Reactivation keeps the ORIGINAL detection date, so the clock is not reset."""
    org_id = accepted_setup["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.get(Finding, accepted_setup["finding_id"])
        finding.detected_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=400)
        acceptance = engagements.request_acceptance(
            session, org_id, name="Old debt", reason="Deferred for a year.",
            finding_ids=[finding.id], requested_by_id=accepted_setup["requester_id"],
            expires_on=dt.date.today() - dt.timedelta(days=1),
        )
        engagements.approve(session, acceptance,
                            approved_by_id=accepted_setup["approver_id"])
        session.commit()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        engagements.expire_due(session, org_id)
        session.commit()
        finding = session.get(Finding, accepted_setup["finding_id"])
        assert finding.sla_due_at is not None
        assert finding.sla_due_at < dt.datetime.now(dt.timezone.utc), (
            "an expired acceptance must not hand the finding a fresh SLA window"
        )


def test_expire_due_is_idempotent(accepted_setup):
    org_id = accepted_setup["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        acceptance = engagements.request_acceptance(
            session, org_id, name="Once only", reason="Testing idempotence.",
            finding_ids=[accepted_setup["finding_id"]],
            requested_by_id=accepted_setup["requester_id"],
            expires_on=dt.date.today() - dt.timedelta(days=1),
        )
        engagements.approve(session, acceptance,
                            approved_by_id=accepted_setup["approver_id"])
        session.commit()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        first = engagements.expire_due(session, org_id)
        second = engagements.expire_due(session, org_id)
        session.commit()
        assert first["expired"] == 1
        assert second["expired"] == 0


def test_tenant_isolation_holds_for_the_new_tables(org_a, org_b):
    """New tables must be under RLS like everything else, not by accident."""
    org_a_id, _, _ = org_a
    org_b_id, _, _ = org_b
    with SessionLocal() as session:
        set_tenant(session, org_a_id)
        engagements.create_engagement(session, org_a_id, name="A only")
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_b_id)
        visible = session.execute(select(Engagement)).scalars().all()
        assert all(e.organization_id == org_b_id for e in visible)
        assert not [e for e in visible if e.name == "A only"]


# ---------------------------------------------------------------------------
# End to end: a code-scanner report all the way to scored findings
# ---------------------------------------------------------------------------
import json as _json   # noqa: E402 - kept local to this section


SEMGREP_TWO_HITS = _json.dumps({"results": [
    {"check_id": "python.lang.security.hardcoded-password",
     "path": "app/settings.py", "start": {"line": 12}, "end": {"line": 12},
     "extra": {"message": "Hardcoded password.", "severity": "ERROR",
               "fingerprint": "aaa111",
               "metadata": {"cwe": ["CWE-798"], "impact": "HIGH"}}},
    {"check_id": "python.lang.security.hardcoded-password",
     "path": "app/legacy/db.py", "start": {"line": 88}, "end": {"line": 88},
     "extra": {"message": "Hardcoded password.", "severity": "ERROR",
               "fingerprint": "bbb222",
               "metadata": {"cwe": ["CWE-798"], "impact": "HIGH"}}},
]}).encode()


def test_a_sast_report_becomes_two_findings_not_one(estate):
    """The whole point of configurable deduplication, proven end to end.

    Both results share a rule, a title, a severity and a CWE, and neither has a
    port or a path in the network sense. Under the single legacy algorithm they
    hashed identically and the second one was swallowed as a duplicate.
    """
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        run = importers.run_import(
            session, org_id, SEMGREP_TWO_HITS, source="semgrep",
            filename="semgrep.json",
            options=ImportOptions(target_asset="acme/api", create_assets=True),
        )
        session.commit()
        assert run.status == "complete", run.error
        assert run.records_seen == 2
        assert run.findings_created == 2, "the two hits collapsed into one"
        assert run.dedupe_algorithm == dedupe.UNIQUE_ID_OR_HASH

    with SessionLocal() as session:
        set_tenant(session, org_id)
        findings = session.execute(
            select(Finding).where(Finding.organization_id == org_id,
                                  Finding.scanner == "semgrep")
        ).scalars().all()
        assert len(findings) == 2
        assert {f.dedupe_key for f in findings} == set(f.dedupe_key for f in findings)
        assert len({f.dedupe_key for f in findings}) == 2
        assert all(f.risk_score is not None for f in findings), "risk engine did not run"
        assert all(f.sla_due_at is not None for f in findings), "SLA was not applied"


def test_reimporting_the_same_sast_report_creates_nothing_new(estate):
    org_id = estate["org_id"]
    options = ImportOptions(target_asset="acme/api", create_assets=True)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        importers.run_import(session, org_id, SEMGREP_TWO_HITS, source="semgrep",
                             options=options)
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        run = importers.run_import(session, org_id, SEMGREP_TWO_HITS, source="semgrep",
                                   options=options)
        session.commit()
        assert run.findings_created == 0
        assert run.findings_updated == 2


def test_a_report_with_no_host_and_no_target_asset_is_rejected(estate):
    """`target_asset` is attribution the operator supplies. Without it VEYRS
    still refuses to guess which asset a code finding belongs to."""
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        run = importers.run_import(session, org_id, SEMGREP_TWO_HITS, source="semgrep")
        session.commit()
        assert run.findings_created == 0
        assert run.records_rejected == 2
        assert any("asset" in reason for reason in run.reject_reasons)


NUCLEI_TWO_URLS = ("\n".join(_json.dumps(row) for row in [
    {"template-id": "exposed-panel", "info": {"name": "Exposed admin panel",
                                              "severity": "medium"},
     "host": "https://fw-edge-01.corp", "matched-at": "https://fw-edge-01.corp/admin",
     "type": "http", "matcher-name": "title"},
    {"template-id": "exposed-panel", "info": {"name": "Exposed admin panel",
                                              "severity": "medium"},
     "host": "https://fw-edge-01.corp", "matched-at": "https://fw-edge-01.corp/manager",
     "type": "http", "matcher-name": "title"},
])).encode()


def test_a_dast_report_records_one_endpoint_per_url(estate):
    """Two URLs of one issue are two remediation items, each with its own
    mitigation state - which is exactly what the endpoint model exists for."""
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        run = importers.run_import(session, org_id, NUCLEI_TWO_URLS, source="nuclei",
                                   filename="nuclei.jsonl")
        session.commit()
        assert run.status == "complete", run.error
        assert run.endpoints_created == 2

    with SessionLocal() as session:
        set_tenant(session, org_id)
        canonicals = {e.canonical for e in session.execute(
            select(Endpoint).where(Endpoint.organization_id == org_id)
        ).scalars().all()}
        assert canonicals == {"https://fw-edge-01.corp/admin",
                              "https://fw-edge-01.corp/manager"}
        links = session.execute(
            select(FindingEndpoint).where(FindingEndpoint.organization_id == org_id)
        ).scalars().all()
        assert len(links) == 2


ZAP_ONE_ALERT_TWO_URLS = _json.dumps({"site": [{
    "@name": "https://fw-edge-01.corp", "@host": "fw-edge-01.corp",
    "@port": "443", "@ssl": "true",
    "alerts": [{
        "pluginid": "10038", "alert": "Content Security Policy header missing",
        "riskcode": "2", "cweid": "693",
        "desc": "<p>No CSP header.</p>", "solution": "<p>Set the header.</p>",
        "instances": [
            {"uri": "https://fw-edge-01.corp/admin", "method": "GET"},
            {"uri": "https://fw-edge-01.corp/manager", "method": "GET"},
        ],
    }],
}]}).encode()


def test_an_aggregating_scanner_produces_one_finding_with_many_endpoints(estate):
    """ZAP reports one alert across two URLs: one thing to triage, two to fix."""
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        run = importers.run_import(session, org_id, ZAP_ONE_ALERT_TWO_URLS,
                                   source="zap", filename="zap.json")
        session.commit()
        assert run.status == "complete", run.error
        assert run.findings_created == 1, "the alert forked per URL"
        assert run.endpoints_created == 2

    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.execute(
            select(Finding).where(Finding.organization_id == org_id,
                                  Finding.scanner == "zap")
        ).scalars().one()
        links = session.execute(
            select(FindingEndpoint).where(FindingEndpoint.finding_id == finding.id)
        ).scalars().all()
        assert len(links) == 2


def test_partially_fixing_a_web_finding_is_visible(estate):
    """A header fixed on /admin but not /manager is half-fixed, and the model
    must be able to say so rather than forcing open-or-closed."""
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        importers.run_import(session, org_id, ZAP_ONE_ALERT_TWO_URLS, source="zap")
        session.commit()
        finding = session.execute(
            select(Finding).where(Finding.organization_id == org_id,
                                  Finding.scanner == "zap")
        ).scalars().one()
        admin = session.execute(
            select(Endpoint).where(Endpoint.organization_id == org_id,
                                   Endpoint.path == "/admin")
        ).scalars().one()
        endpoint_service.mitigate(session, organization_id=org_id,
                                  finding_id=finding.id, endpoint_ids=[admin.id])
        session.commit()

        assert endpoint_service.outstanding(session, org_id, finding.id) == 1
        assert endpoint_service.fully_mitigated(session, org_id, finding.id) is False

        manager = session.execute(
            select(Endpoint).where(Endpoint.organization_id == org_id,
                                   Endpoint.path == "/manager")
        ).scalars().one()
        endpoint_service.mitigate(session, organization_id=org_id,
                                  finding_id=finding.id, endpoint_ids=[manager.id])
        session.commit()
        assert endpoint_service.fully_mitigated(session, org_id, finding.id) is True


def test_a_reappearing_endpoint_reopens_only_that_endpoint(estate):
    """The fix on /admin did not hold. Its status must revert; /manager's must
    not be touched by the same import."""
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        importers.run_import(session, org_id, ZAP_ONE_ALERT_TWO_URLS, source="zap")
        session.commit()
        finding = session.execute(
            select(Finding).where(Finding.organization_id == org_id,
                                  Finding.scanner == "zap")
        ).scalars().one()
        for link in session.execute(
            select(FindingEndpoint).where(FindingEndpoint.finding_id == finding.id)
        ).scalars().all():
            endpoint_service.mitigate(session, organization_id=org_id,
                                      finding_id=finding.id,
                                      endpoint_ids=[link.endpoint_id])
        session.commit()
        assert endpoint_service.fully_mitigated(session, org_id, finding.id) is True

    only_admin = _json.dumps({"site": [{
        "@host": "fw-edge-01.corp", "@port": "443", "@ssl": "true",
        "alerts": [{"pluginid": "10038",
                    "alert": "Content Security Policy header missing",
                    "riskcode": "2", "cweid": "693", "desc": "<p>No CSP.</p>",
                    "instances": [{"uri": "https://fw-edge-01.corp/admin",
                                   "method": "GET"}]}],
    }]}).encode()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        importers.run_import(session, org_id, only_admin, source="zap")
        session.commit()
        admin = session.execute(
            select(Endpoint).where(Endpoint.organization_id == org_id,
                                   Endpoint.path == "/admin")
        ).scalars().one()
        manager = session.execute(
            select(Endpoint).where(Endpoint.organization_id == org_id,
                                   Endpoint.path == "/manager")
        ).scalars().one()
        links = {l.endpoint_id: l for l in session.execute(
            select(FindingEndpoint).where(FindingEndpoint.organization_id == org_id)
        ).scalars().all()}
        assert links[admin.id].mitigated is False, "a re-observed endpoint stayed fixed"
        assert links[manager.id].mitigated is True, "an untouched endpoint was reverted"


def test_fully_mitigated_is_false_for_a_finding_with_no_endpoints(estate):
    """`fully_mitigated` must never answer yes about a finding it knows nothing
    about. A host-level patch is not "mitigated by endpoint"; it simply is not
    endpoint-scoped, and a caller must not conclude anything from this."""
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert endpoint_service.fully_mitigated(session, org_id, uuid.uuid4()) is False


def test_a_url_only_record_still_resolves_its_asset():
    """The regression behind the first failing DAST import: a record carrying
    only a URL had no asset_key and was rejected before it reached an asset."""
    from veyrs.services.importers.base import ScanRecord

    record = ScanRecord(title="Exposed panel",
                        url="https://fw-edge-01.corp:8443/admin").normalise()
    assert record.fqdn == "fw-edge-01.corp"
    assert record.port == 8443
    assert record.protocol == "https"
    assert record.asset_key == "fw-edge-01.corp"

    short = ScanRecord(title="x", url="http://intranet/").normalise()
    assert short.hostname == "intranet" and short.fqdn is None

    numeric = ScanRecord(title="x", url="https://10.50.0.21/admin").normalise()
    assert numeric.ip_address == "10.50.0.21"

    # An explicit host always wins over the URL - the parser knew better.
    explicit = ScanRecord(title="x", url="https://other.corp/a",
                          fqdn="declared.corp").normalise()
    assert explicit.fqdn == "declared.corp"
