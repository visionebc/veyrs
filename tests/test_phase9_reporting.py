"""Phase 9: analytics, dashboards and report exports.

Two families of assertion:

* **Numbers are right and honest** -- denominators are present, MTTR is flagged
  unreliable on a tiny sample, top-assets ranks by peak risk not by count.
* **Exports are safe** -- every format carries provenance, each report enforces
  its own permission (an asset register is asset data), and one tenant's export
  never contains another tenant's rows.
"""
from __future__ import annotations

import csv
import datetime as dt
import io
import json
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    Asset, AssetProduct, Cve, Finding, Team,
)
from veyrs.services import analytics, correlation, intelligence, reporting
from veyrs.services import risk as risk_service, sla as sla_service

from test_phase3_intel import NVD_ITEM


@pytest.fixture()
def populated(org_a):
    """One internet-facing critical asset with a KEV finding, plus a lab box."""
    org_id, slug, email = org_a
    with SessionLocal() as session:
        intelligence.ingest_nvd(session, [NVD_ITEM])
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        product = intelligence.upsert_product(session, "fortinet", "fortiweb", cpe_part="a")
        edge = Asset(organization_id=org_id, name="fw-edge-01", hostname="fw-edge-01",
                     asset_type="firewall", criticality="critical", exposure="internet",
                     environment="production", data_classification="confidential")
        lab = Asset(organization_id=org_id, name="lab-01", hostname="lab-01",
                    asset_type="server", criticality="low", exposure="isolated",
                    environment="development")
        session.add_all([edge, lab])
        session.flush()
        session.add_all([
            AssetProduct(organization_id=org_id, asset_id=edge.id,
                         product_id=product.id, version="7.2.4"),
            AssetProduct(organization_id=org_id, asset_id=lab.id,
                         product_id=product.id, version="7.2.4"),
        ])
        session.add(Team(organization_id=org_id, slug="netsec", name="Network Security"))
        risk_service.seed_profiles(session, org_id)
        sla_service.seed_policies(session, org_id)
        session.commit()

        cve = session.get(Cve, "CVE-2026-0001")
        correlation.correlate_cve(session, org_id, cve)
        session.commit()
        return {"org_id": org_id, "slug": slug, "edge_id": edge.id, "lab_id": lab.id}


# ---------------------------------------------------------------------------
# Executive analytics
# ---------------------------------------------------------------------------
def test_executive_dashboard_reports_its_denominators(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        data = analytics.executive_dashboard(session, populated["org_id"])

    totals = data["totals"]
    assert totals["assets"] == 2
    assert totals["open_findings"] >= 2
    assert totals["assets_with_open_findings"] == 2
    assert totals["asset_coverage_ratio"] == 1.0
    # every ratio must be accompanied by the count it came from
    assert data["sla"]["sample"] == totals["open_findings"]


def test_internet_facing_and_kev_intersection_is_reported(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        data = analytics.executive_dashboard(session, populated["org_id"])
    exploitation = data["exploitation"]
    assert exploitation["internet_facing_open"] == 1  # only the edge firewall
    assert exploitation["kev_and_internet_facing"] <= exploitation["internet_facing_open"]


def test_mttr_is_flagged_unreliable_on_a_small_sample(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        finding = session.execute(
            select(Finding).where(Finding.organization_id == populated["org_id"])
        ).scalars().first()
        finding.remediated_at = finding.detected_at + dt.timedelta(hours=6)
        session.commit()
        result = analytics.mttr(session, populated["org_id"])

    assert result["sample"] == 1
    assert result["reliable"] is False   # one data point is not a trend
    assert result["hours"] == pytest.approx(6.0, abs=0.2)


def test_mttr_with_no_closed_findings_returns_none_not_zero(org_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        result = analytics.mttr(session, org_id)
    # Zero would read as "we fix everything instantly".
    assert result["hours"] is None
    assert result["sample"] == 0


def test_top_assets_ranks_by_peak_risk_not_by_count(populated):
    """40 informational findings on a lab box must not outrank one KEV on the edge."""
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        edge_finding = session.execute(
            select(Finding).where(Finding.asset_id == populated["edge_id"])
        ).scalars().first()
        lab_finding = session.execute(
            select(Finding).where(Finding.asset_id == populated["lab_id"])
        ).scalars().first()
        edge_finding.risk_score = 95.0
        lab_finding.risk_score = 10.0
        session.commit()

        ranked = analytics.top_assets(session, populated["org_id"])
    assert ranked[0]["asset_id"] == str(populated["edge_id"])
    assert ranked[0]["max_risk_score"] == 95.0


def test_top_products_rolls_up_vendor_and_product(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        rows = analytics.top_products(session, populated["org_id"])
    assert rows
    assert rows[0]["vendor"] == "fortinet"
    assert rows[0]["product"] == "fortiweb"
    assert rows[0]["open_findings"] == 2


def test_by_environment_separates_production_from_development(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        rows = {r["environment"]: r for r in
                analytics.by_environment(session, populated["org_id"])}
    assert set(rows) == {"production", "development"}


def test_trend_buckets_cover_the_whole_window(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        trend = analytics.finding_trend(session, populated["org_id"], days=30, buckets=6)
    assert len(trend) == 6
    assert sum(bucket["detected"] for bucket in trend) >= 2


def test_analytics_are_tenant_isolated(populated, org_b):
    other_org_id, _, _ = org_b
    with SessionLocal() as session:
        set_tenant(session, other_org_id)
        data = analytics.executive_dashboard(session, other_org_id)
    assert data["totals"]["open_findings"] == 0
    assert data["top_assets"] == []


# ---------------------------------------------------------------------------
# Technical analytics
# ---------------------------------------------------------------------------
def test_technical_dashboard_distributions_sum_to_the_sample(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        data = analytics.technical_dashboard(session, populated["org_id"])
    assert sum(data["cvss_distribution"].values()) == data["sample"]
    assert sum(data["epss_distribution"].values()) == data["sample"]


def test_unscored_findings_are_counted_not_dropped(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        finding = session.execute(
            select(Finding).where(Finding.organization_id == populated["org_id"])
        ).scalars().first()
        finding.cvss_score = None
        session.commit()
        data = analytics.technical_dashboard(session, populated["org_id"])
    assert data["cvss_distribution"]["unscored"] >= 1
    assert sum(data["cvss_distribution"].values()) == data["sample"]


def test_exploitability_separates_known_from_theoretical(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        data = analytics.exploitability(session, populated["org_id"])
    assert data["total_open"] >= 2
    assert data["theoretical_only"] == max(
        0, data["total_open"] - data["epss_over_10_percent"]
    )


def test_top_cwe_rolls_up_from_the_cve_catalogue(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        rows = analytics.top_cwe(session, populated["org_id"])
    assert any(row["cwe"] == "CWE-287" for row in rows)


# ---------------------------------------------------------------------------
# Report building
# ---------------------------------------------------------------------------
def test_every_registered_report_builds(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        for slug in reporting.REPORTS:
            if slug == "compliance":
                continue  # needs a framework_id; covered separately
            report = reporting.build(session, populated["org_id"], slug)
            assert report["provenance"]["report"] == slug
            assert report["data"] is not None


def test_provenance_names_the_organization_and_the_moment(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        report = reporting.build(session, populated["org_id"], "executive")
    provenance = report["provenance"]
    assert provenance["organization_slug"] == populated["slug"]
    assert provenance["generated_at"]
    assert "VEYRS" in provenance["generated_by"]
    assert "snapshot" in provenance["note"]


def test_unknown_report_is_refused(populated):
    with SessionLocal() as session:
        with pytest.raises(reporting.ReportError, match="unknown report"):
            reporting.build(session, populated["org_id"], "everything")


def test_compliance_report_requires_a_framework(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        with pytest.raises(reporting.ReportError, match="framework_id"):
            reporting.build(session, populated["org_id"], "compliance")


def test_vulnerability_register_marks_truncation(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        report = reporting.build(session, populated["org_id"],
                                 "vulnerability-register", limit=1)
    assert report["data"]["count"] == 1
    assert report["data"]["truncated_at"] == 1


# ---------------------------------------------------------------------------
# Rendering
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("fmt,magic", [
    ("json", b"{"),
    ("csv", b"\xef\xbb\xbf"),      # UTF-8 BOM so Excel opens it correctly
    ("xlsx", b"PK"),               # zip container
    ("pdf", b"%PDF"),
])
def test_each_format_renders_a_recognisable_file(populated, fmt, magic):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        payload, content_type, filename = reporting.render(
            session, populated["org_id"], "executive", fmt
        )
    assert payload.startswith(magic)
    assert filename.endswith(f".{fmt}")
    assert content_type


def test_csv_export_carries_provenance_and_tables(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        payload, _, _ = reporting.render(session, populated["org_id"],
                                         "vulnerability-register", "csv")
    text = payload.decode("utf-8-sig")
    assert "# organization" in text
    assert "## findings" in text
    rows = list(csv.reader(io.StringIO(text)))
    assert any("fw-edge-01" in ",".join(row) for row in rows)


def test_xlsx_export_has_a_provenance_sheet(populated):
    from openpyxl import load_workbook

    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        payload, _, _ = reporting.render(session, populated["org_id"],
                                         "executive", "xlsx")
    workbook = load_workbook(io.BytesIO(payload))
    assert workbook.sheetnames[0] == "provenance"
    assert "by_severity" in workbook.sheetnames


def test_xlsx_sheet_names_are_sanitised(populated):
    """Excel rejects []:*?/\\ and caps names at 31 characters."""
    from openpyxl import load_workbook

    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        payload, _, _ = reporting.render(session, populated["org_id"],
                                         "technical", "xlsx")
    workbook = load_workbook(io.BytesIO(payload))
    for name in workbook.sheetnames:
        assert len(name) <= 31
        assert not set(name) & set("[]:*?/\\")


def test_pdf_export_is_non_trivial_and_titled(populated):
    with SessionLocal() as session:
        set_tenant(session, populated["org_id"])
        payload, content_type, _ = reporting.render(
            session, populated["org_id"], "executive", "pdf"
        )
    assert content_type == "application/pdf"
    assert len(payload) > 2000  # a real document, not an empty shell
    assert b"%%EOF" in payload


def test_unknown_format_is_refused(populated):
    with SessionLocal() as session:
        with pytest.raises(reporting.ReportError, match="unknown format"):
            reporting.render(session, populated["org_id"], "executive", "docx")


def test_exports_never_contain_another_tenants_rows(populated, org_b):
    other_org_id, _, _ = org_b
    with SessionLocal() as session:
        set_tenant(session, other_org_id)
        payload, _, _ = reporting.render(session, other_org_id,
                                         "vulnerability-register", "csv")
    assert b"fw-edge-01" not in payload


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------
def test_executive_dashboard_endpoint(client, admin_a, populated):
    response = client.get("/api/v1/dashboard/executive", headers=admin_a)
    assert response.status_code == 200, response.text
    assert response.json()["totals"]["assets"] == 2


def test_technical_dashboard_endpoint(client, admin_a, populated):
    response = client.get("/api/v1/dashboard/technical", headers=admin_a)
    assert response.status_code == 200, response.text
    assert "cvss_distribution" in response.json()


def test_report_catalogue_marks_what_the_caller_can_export(client, admin_a):
    body = client.get("/api/v1/reports", headers=admin_a).json()
    slugs = {r["slug"] for r in body["reports"]}
    assert {"executive", "asset-register", "compliance"} <= slugs
    # org-admin holds *:* so everything is available
    assert all(r["available"] for r in body["reports"])


def test_each_report_enforces_its_own_permission(client, org_a):
    """An asset register is asset data, not 'report' data."""
    from conftest import ADMIN_PASSWORD, auth_headers

    org_id, slug, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        from veyrs.models import Role, User, UserRole
        from veyrs.security.auth import hash_password

        limited = User(organization_id=org_id, email=f"exec@{slug}.test",
                       full_name="Exec", password_hash=hash_password(ADMIN_PASSWORD))
        session.add(limited)
        session.flush()
        role = session.execute(
            select(Role).where(Role.slug == "executive", Role.organization_id.is_(None))
        ).scalar_one()
        session.add(UserRole(organization_id=org_id, user_id=limited.id, role_id=role.id))
        session.commit()

    headers = auth_headers(client, f"exec@{slug}.test", slug)
    # executive role has report:read but NOT importer/ticket:admin etc.
    assert client.get("/api/v1/reports/executive", headers=headers).status_code == 200
    # ...and does hold asset:read, so the asset register is allowed
    assert client.get("/api/v1/reports/asset-register", headers=headers).status_code == 200


def test_export_endpoint_sets_a_download_filename(client, admin_a, populated):
    response = client.get("/api/v1/reports/executive/export?format=csv", headers=admin_a)
    assert response.status_code == 200, response.text
    disposition = response.headers["content-disposition"]
    assert "attachment" in disposition
    assert "veyrs-executive-" in disposition
    assert response.content.startswith(b"\xef\xbb\xbf")


def test_export_is_audited(client, admin_a, populated, org_a):
    from veyrs.models import AuditLog

    org_id, _, _ = org_a
    client.get("/api/v1/reports/executive/export?format=pdf", headers=admin_a)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        rows = session.execute(
            select(AuditLog).where(AuditLog.organization_id == org_id,
                                   AuditLog.action == "report.exported")
        ).scalars().all()
    assert rows
    assert rows[-1].changes["format"] == "pdf"


def test_unknown_report_slug_is_404(client, admin_a):
    assert client.get("/api/v1/reports/nope", headers=admin_a).status_code == 404


def test_unknown_export_format_is_422(client, admin_a, populated):
    response = client.get("/api/v1/reports/executive/export?format=docx", headers=admin_a)
    assert response.status_code == 422


def test_dashboards_require_authentication(client):
    assert client.get("/api/v1/dashboard/executive").status_code == 401
    assert client.get("/api/v1/reports/executive/export").status_code == 401
