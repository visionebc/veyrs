"""Phase 3 (part 2): version matching, intelligence ingestion, correlation, SLA.

These tests are deliberately behavioural rather than structural: they assert on
"does a real Fortinet advisory produce a finding on the one appliance that runs
the affected version and not on the one that does not", because that is the
claim the product makes.
"""
from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    Asset, AssetProduct, AssignmentRule, Cve, Finding, KevEntry, SlaEvent, SlaPolicy, Team,
    Vulnerability,
)
from veyrs.services import correlation, intelligence, risk as risk_service, sla as sla_service
from veyrs.services.versions import (
    compare, in_range, normalize_name, parse_cpe23, version_key,
)

# --------------------------------------------------------------------------
# versions
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "left,right,expected",
    [
        ("7.2.4", "7.2.5", -1),
        ("7.2.5", "7.2.4", 1),
        ("7.2", "7.2.0", 0),
        ("7.10.0", "7.9.9", 1),          # numeric, not lexical
        ("1.0.0-rc1", "1.0.0", -1),      # pre-release sorts below release
        ("1.0.0-beta", "1.0.0-rc1", -1),
        ("2.0", "2.0-alpha", 1),
        ("10.0.19045", "10.0.19044", 1),
        ("v1.2.3", "1.2.3", 0),          # leading v is noise
        ("6.4.14", "6.4.9", 1),
    ],
)
def test_version_compare(left, right, expected):
    assert compare(left, right) == expected


def test_version_key_sorts_like_compare():
    versions = ["7.2.10", "7.2.2", "7.10.0", "1.0.0-rc1", "1.0.0"]
    by_key = sorted(versions, key=version_key)
    # 1.0.0-rc1 < 1.0.0 < 7.2.2 < 7.2.10 < 7.10.0
    assert by_key == ["1.0.0-rc1", "1.0.0", "7.2.2", "7.2.10", "7.10.0"]


def test_in_range_bounds():
    kwargs = {"start_including": "7.2.0", "end_excluding": "7.2.5"}
    assert in_range("7.2.0", **kwargs) is True
    assert in_range("7.2.4", **kwargs) is True
    assert in_range("7.2.5", **kwargs) is False
    assert in_range("7.1.9", **kwargs) is False


def test_in_range_unknown_version_is_not_affected():
    """Missing inventory data must never manufacture a finding."""
    assert in_range(None, start_including="1.0", end_excluding="2.0") is False
    assert in_range("*", start_including="1.0", end_excluding="2.0") is False


def test_in_range_exact():
    assert in_range("7.2.4", exact="7.2.4") is True
    assert in_range("7.2.3", exact="7.2.4") is False


def test_parse_cpe23():
    parsed = parse_cpe23("cpe:2.3:a:fortinet:fortiweb:7.2.4:*:*:*:*:*:*:*")
    assert parsed["part"] == "a"
    assert parsed["vendor"] == "fortinet"
    assert parsed["product"] == "fortiweb"
    assert parsed["version"] == "7.2.4"
    assert parse_cpe23("not-a-cpe") is None


def test_normalize_name_folds_corporate_suffixes():
    assert normalize_name("Fortinet, Inc.") == normalize_name("fortinet")
    assert normalize_name("Microsoft Corporation") == "microsoft"


# --------------------------------------------------------------------------
# fixtures: a realistic advisory + inventory
# --------------------------------------------------------------------------

NVD_ITEM = {
    "cve": {
        "id": "CVE-2026-0001",
        "vulnStatus": "Analyzed",
        "published": "2026-01-15T10:00:00.000",
        "lastModified": "2026-02-01T10:00:00.000",
        "descriptions": [
            {"lang": "en", "value": "Improper authentication in FortiWeb allows RCE."},
            {"lang": "es", "value": "Autenticacion incorrecta."},
        ],
        "metrics": {
            "cvssMetricV31": [{
                "type": "Primary",
                "cvssData": {
                    "version": "3.1",
                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H",
                    "baseScore": 9.8, "baseSeverity": "CRITICAL",
                },
            }],
            "cvssMetricV40": [{
                "type": "Primary",
                "cvssData": {
                    "version": "4.0",
                    "vectorString": "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N",
                    "baseScore": 9.3, "baseSeverity": "CRITICAL",
                },
            }],
            "cvssMetricV2": [{
                "type": "Primary",
                "cvssData": {"version": "2.0", "vectorString": "AV:N/AC:L/Au:N/C:C/I:C/A:C",
                             "baseScore": 10.0},
            }],
        },
        "weaknesses": [{"description": [{"lang": "en", "value": "CWE-287"}]}],
        "references": [
            {"url": "https://fortiguard.com/psirt/FG-IR-26-001", "source": "psirt",
             "tags": ["Vendor Advisory"]},
            {"url": "https://example.com/poc", "source": "exploit-db", "tags": ["Exploit"]},
        ],
        "configurations": [{
            "nodes": [{
                "operator": "OR",
                "cpeMatch": [{
                    "vulnerable": True,
                    "criteria": "cpe:2.3:a:fortinet:fortiweb:*:*:*:*:*:*:*:*",
                    "versionStartIncluding": "7.2.0",
                    "versionEndExcluding": "7.2.5",
                }],
            }],
        }],
    }
}


@pytest.fixture()
def ingested_cve():
    with SessionLocal() as session:
        stats = intelligence.ingest_nvd(session, [NVD_ITEM])
        session.commit()
    return stats


@pytest.fixture()
def tenant_inventory(org_a, ingested_cve):
    """Two FortiWeb appliances: one affected (7.2.4), one patched (7.2.6)."""
    org_id, slug, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        product = intelligence.upsert_product(session, "fortinet", "fortiweb", cpe_part="a")

        vulnerable = Asset(
            organization_id=org_id, name="fw-edge-01", asset_type="firewall",
            hostname="fw-edge-01", criticality="critical", exposure="internet",
            environment="production", data_classification="confidential",
        )
        patched = Asset(
            organization_id=org_id, name="fw-lab-01", asset_type="firewall",
            hostname="fw-lab-01", criticality="low", exposure="internal",
            environment="development",
        )
        session.add_all([vulnerable, patched])
        session.flush()
        session.add_all([
            AssetProduct(organization_id=org_id, asset_id=vulnerable.id,
                         product_id=product.id, version="7.2.4"),
            AssetProduct(organization_id=org_id, asset_id=patched.id,
                         product_id=product.id, version="7.2.6"),
        ])
        risk_service.seed_profiles(session, org_id)
        sla_service.seed_policies(session, org_id)
        session.commit()
        return {"org_id": org_id, "slug": slug,
                "vulnerable_id": vulnerable.id, "patched_id": patched.id,
                "product_id": product.id}


# --------------------------------------------------------------------------
# intelligence ingestion
# --------------------------------------------------------------------------


def test_ingest_nvd_normalizes_all_cvss_revisions(ingested_cve):
    # The CVE table is global and shared across tests in this database, so the
    # row may already exist from an earlier test. What must hold is that exactly
    # one record was touched and it carries the right data.
    assert ingested_cve["created"] + ingested_cve["updated"] == 1
    with SessionLocal() as session:
        cve = session.get(Cve, "CVE-2026-0001")
        assert cve is not None
        assert cve.cvss2_base_score == 10.0
        assert cve.cvss3_base_score == 9.8
        assert cve.cvss3_version == "3.1"
        assert cve.cvss4_score == 9.3
        assert cve.best_cvss_score == 9.3  # v4 wins
        assert cve.cwe_ids == ["CWE-287"]
        assert cve.exploit_known is True  # derived from the Exploit reference tag
        assert "fortinet:fortiweb" in cve.affected


def test_ingest_nvd_is_idempotent(ingested_cve):
    with SessionLocal() as session:
        stats = intelligence.ingest_nvd(session, [NVD_ITEM])
        session.commit()
    assert stats["created"] == 0
    assert stats["updated"] == 1
    with SessionLocal() as session:
        matches = session.execute(
            select(Cve).where(Cve.id == "CVE-2026-0001")
        ).scalars().all()
        assert len(matches) == 1
        snapshot = intelligence.intelligence_snapshot(session, "CVE-2026-0001")
        # references/cpe rows replaced wholesale, not duplicated
        assert len(snapshot["references"]) == 2
        assert len(snapshot["cpe_matches"]) == 1


def test_ingest_epss_writes_history_and_denormalizes(ingested_cve):
    day1 = dt.date(2026, 2, 1)
    day2 = dt.date(2026, 2, 2)
    with SessionLocal() as session:
        intelligence.ingest_epss(
            session, [{"cve": "CVE-2026-0001", "epss": "0.42", "percentile": "0.90"}],
            scored_on=day1,
        )
        intelligence.ingest_epss(
            session, [{"cve": "CVE-2026-0001", "epss": "0.91", "percentile": "0.99"}],
            scored_on=day2,
        )
        session.commit()
    with SessionLocal() as session:
        cve = session.get(Cve, "CVE-2026-0001")
        assert cve.epss_score == pytest.approx(0.91)
        trend = intelligence.epss_trend(session, "CVE-2026-0001", days=3650)
        assert [point["score"] for point in trend] == [pytest.approx(0.42), pytest.approx(0.91)]


def test_ingest_epss_skips_unknown_cves():
    with SessionLocal() as session:
        stats = intelligence.ingest_epss(
            session, [{"cve": "CVE-1999-99999", "epss": "0.1", "percentile": "0.5"}]
        )
        session.commit()
    assert stats["skipped"] == 1
    assert stats["created"] == 0


def test_ingest_kev_creates_stub_for_unknown_cve():
    # Unique id per run: the CVE table is global, so a fixed id would only be
    # "unknown" the first time this test executed against a given database.
    cve_id = f"CVE-2026-{uuid.uuid4().int % 90000 + 10000}"
    catalog = {
        "catalogVersion": "2026.02.01",
        "vulnerabilities": [{
            "cveID": cve_id, "vendorProject": "Acme", "product": "Widget",
            "vulnerabilityName": "Acme Widget RCE",
            "shortDescription": "Actively exploited.",
            "requiredAction": "Apply updates.",
            "dateAdded": "2026-02-01", "dueDate": "2026-02-22",
            "knownRansomwareCampaignUse": "Known",
        }],
    }
    with SessionLocal() as session:
        stats = intelligence.ingest_kev(session, catalog)
        session.commit()
    assert stats["cve_stubs"] == 1
    with SessionLocal() as session:
        cve = session.get(Cve, cve_id)
        entry = session.get(KevEntry, cve_id)
        assert cve.kev is True
        assert cve.exploit_known is True
        assert entry.known_ransomware is True
        assert entry.due_date == dt.date(2026, 2, 22)


def test_feed_run_records_failure_and_reraises():
    with SessionLocal() as session:
        with pytest.raises(RuntimeError):
            with intelligence.feed_run(session, "nvd"):
                raise RuntimeError("upstream 503")
        session.commit()
    with SessionLocal() as session:
        run = intelligence.last_successful_run(session, "nvd")
        # the failed run must not be reported as the last successful one
        assert run is None or run.status == "succeeded"


# --------------------------------------------------------------------------
# correlation
# --------------------------------------------------------------------------


def test_correlation_hits_only_the_affected_version(tenant_inventory):
    org_id = tenant_inventory["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        cve = session.get(Cve, "CVE-2026-0001")
        stats = correlation.correlate_cve(session, org_id, cve)
        session.commit()

    assert stats["assets"] == 1
    assert stats["created"] == 1

    with SessionLocal() as session:
        set_tenant(session, org_id)
        findings = session.execute(select(Finding)).scalars().all()
        assert len(findings) == 1
        assert findings[0].asset_id == tenant_inventory["vulnerable_id"]


def test_correlation_is_idempotent(tenant_inventory):
    org_id = tenant_inventory["org_id"]
    for _ in range(3):
        with SessionLocal() as session:
            set_tenant(session, org_id)
            cve = session.get(Cve, "CVE-2026-0001")
            correlation.correlate_cve(session, org_id, cve)
            session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert len(session.execute(select(Finding)).scalars().all()) == 1


def test_correlated_finding_is_scored_and_has_sla(tenant_inventory):
    org_id = tenant_inventory["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        cve = session.get(Cve, "CVE-2026-0001")
        correlation.correlate_cve(session, org_id, cve)
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.execute(select(Finding)).scalars().one()
        assert finding.risk_score is not None
        assert finding.risk_level in {"critical", "high", "medium", "low", "informational"}
        assert finding.risk_explanation  # factor-by-factor breakdown, not just a number
        assert finding.sla_due_at is not None


def test_reopened_finding_is_not_a_duplicate(tenant_inventory):
    org_id = tenant_inventory["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        cve = session.get(Cve, "CVE-2026-0001")
        correlation.correlate_cve(session, org_id, cve)
        finding = session.execute(select(Finding)).scalars().one()
        # `advance` walks the lifecycle graph; a direct triaged -> assigned jump
        # is (correctly) rejected by the transition rules.
        correlation.advance(session, finding, "remediated")
        session.commit()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        cve = session.get(Cve, "CVE-2026-0001")
        correlation.correlate_cve(session, org_id, cve)
        session.commit()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        findings = session.execute(select(Finding)).scalars().all()
        assert len(findings) == 1
        assert findings[0].state == "new"  # reopened, not duplicated


def test_illegal_transition_is_rejected(tenant_inventory):
    org_id = tenant_inventory["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        cve = session.get(Cve, "CVE-2026-0001")
        correlation.correlate_cve(session, org_id, cve)
        finding = session.execute(select(Finding)).scalars().one()
        with pytest.raises(correlation.TransitionError):
            correlation.transition(session, finding, "verified")  # new -> verified
        session.rollback()


def test_assignment_rule_routes_by_vendor(tenant_inventory):
    org_id = tenant_inventory["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        team = Team(organization_id=org_id, name="Network Security", slug="netsec")
        session.add(team)
        session.flush()
        session.add(AssignmentRule(
            organization_id=org_id, name="Fortinet to Network Security", priority=10,
            conditions={"vendor_normalized": "fortinet", "asset_type": ["firewall"]},
            team_id=team.id,
        ))
        session.commit()
        team_id = team.id

    with SessionLocal() as session:
        set_tenant(session, org_id)
        cve = session.get(Cve, "CVE-2026-0001")
        correlation.correlate_cve(session, org_id, cve)
        session.commit()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.execute(select(Finding)).scalars().one()
        assert finding.assigned_team_id == team_id
        assert finding.assignment_reason == "rule:Fortinet to Network Security"
        assert finding.state == "assigned"


def test_rule_with_unknown_field_does_not_match():
    """A typo in a rule must narrow, never widen, its scope."""
    assert correlation.rule_matches({"vendor_normalized": "fortinet"},
                                    {"vendor_normalized": "fortinet"}) is True
    assert correlation.rule_matches({"vendorr": "fortinet"},
                                    {"vendor_normalized": "fortinet"}) is False


def test_tenant_isolation_of_findings(tenant_inventory, org_b):
    """Tenant B has the same CVE globally but no inventory -> no findings."""
    org_b_id = org_b[0]
    with SessionLocal() as session:
        set_tenant(session, org_b_id)
        cve = session.get(Cve, "CVE-2026-0001")
        stats = correlation.correlate_cve(session, org_b_id, cve)
        session.commit()
    assert stats["assets"] == 0
    with SessionLocal() as session:
        set_tenant(session, org_b_id)
        assert session.execute(select(Finding)).scalars().all() == []


# --------------------------------------------------------------------------
# SLA + escalation
# --------------------------------------------------------------------------


def test_kev_internet_facing_gets_the_four_hour_policy(tenant_inventory):
    org_id = tenant_inventory["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        cve = session.get(Cve, "CVE-2026-0001")
        cve.kev = True
        session.flush()
        correlation.correlate_cve(session, org_id, cve)
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.execute(select(Finding)).scalars().one()
        policy = session.get(SlaPolicy, finding.sla_policy_id)
        assert policy.slug == "critical-kev-internet"
        delta = finding.sla_due_at - finding.detected_at
        assert delta == dt.timedelta(hours=4)


def test_sla_sweep_breaches_and_escalates(tenant_inventory):
    org_id = tenant_inventory["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        cve = session.get(Cve, "CVE-2026-0001")
        cve.kev = True
        session.flush()
        correlation.correlate_cve(session, org_id, cve)
        session.commit()

    # 30 hours later: past the 4h deadline and past escalation level 3 (24h).
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=30)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        stats = sla_service.evaluate_findings(session, org_id, now=later)
        session.commit()

    assert stats["breached"] == 1
    assert stats["escalated"] == 1
    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding = session.execute(select(Finding)).scalars().one()
        assert finding.sla_breached is True
        assert finding.escalation_level == 3
        events = session.execute(
            select(SlaEvent).where(SlaEvent.finding_id == finding.id)
        ).scalars().all()
        assert {e.event for e in events} >= {"set", "breached", "escalated"}


def test_sla_sweep_is_idempotent(tenant_inventory):
    org_id = tenant_inventory["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        cve = session.get(Cve, "CVE-2026-0001")
        correlation.correlate_cve(session, org_id, cve)
        session.commit()
    later = dt.datetime.now(dt.timezone.utc) + dt.timedelta(days=40)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        first = sla_service.evaluate_findings(session, org_id, now=later)
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        second = sla_service.evaluate_findings(session, org_id, now=later)
        session.commit()
    assert first["breached"] == 1
    assert second["breached"] == 0  # not re-reported
    assert second["escalated"] == 0


def test_business_hours_deadline_skips_the_weekend():
    friday_1600 = dt.datetime(2026, 2, 6, 16, 0, tzinfo=dt.timezone.utc)  # Friday
    assert friday_1600.weekday() == 4
    due = sla_service.add_business_hours(friday_1600, 4)
    # 1h on Friday, 3h from Monday 09:00 -> Monday 12:00
    assert due == dt.datetime(2026, 2, 9, 12, 0, tzinfo=dt.timezone.utc)


def test_sla_policy_numeric_gate_ignores_unscored_findings():
    context = {"risk": None, "severity": "critical"}
    assert sla_service.policy_matches({"min_risk": 80}, context) is False
    assert sla_service.policy_matches({"min_risk": 80}, {"risk": 90}) is True
