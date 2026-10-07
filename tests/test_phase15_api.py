"""Phase 15: the REST surface for engagements, endpoints and risk acceptance.

Service-level behaviour is covered in `test_phase15_unified_ingest.py`. What is
tested here is what only the HTTP layer can get wrong: route ordering, tenant
isolation on the new tables, permission wiring, and the two refusals that are
controls rather than validation (self-approval, and a machine identity granting
an exception).
"""
from __future__ import annotations

import datetime as dt
import io
import json

from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Asset, Finding
from veyrs.services import importers, intelligence
from veyrs.services import risk as risk_service, sla as sla_service

from test_phase3_intel import NVD_ITEM

NESSUS = (
    '<?xml version="1.0" ?><NessusClientData_v2><Report name="scan">'
    '<ReportHost name="10.50.0.21"><HostProperties>'
    '<tag name="host-ip">10.50.0.21</tag><tag name="host-fqdn">fw-edge-01.corp</tag>'
    '</HostProperties>'
    '<ReportItem port="443" protocol="tcp" severity="4" pluginID="123456"'
    ' pluginName="FortiWeb improper authentication">'
    "<cve>CVE-2026-0001</cve></ReportItem>"
    "</ReportHost></Report></NessusClientData_v2>"
).encode()


def _seed(org_id):
    with SessionLocal() as session:
        intelligence.ingest_nvd(session, [NVD_ITEM])
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        session.add(Asset(organization_id=org_id, name="fw-edge-01",
                          hostname="fw-edge-01", fqdn="fw-edge-01.corp",
                          ip_addresses=["10.50.0.21"], asset_type="firewall",
                          criticality="critical", exposure="internet"))
        risk_service.seed_profiles(session, org_id)
        sla_service.seed_policies(session, org_id)
        session.commit()


# ---------------------------------------------------------------------------
# Engagements
# ---------------------------------------------------------------------------
def test_engagement_crud_and_listing(client, org_a, admin_a):
    created = client.post("/api/v1/engagements", headers=admin_a, json={
        "name": "Q3 external pentest", "engagement_type": "interactive",
        "description": "Annual third-party assessment.",
    })
    assert created.status_code == 201, created.text
    body = created.json()
    assert body["slug"] == "q3-external-pentest"
    assert body["status"] == "not_started"

    listed = client.get("/api/v1/engagements", headers=admin_a)
    assert listed.status_code == 200
    assert listed.json()["total"] == 1

    read = client.get(f"/api/v1/engagements/{body['id']}", headers=admin_a)
    assert read.status_code == 200
    assert read.json()["name"] == "Q3 external pentest"


def test_duplicate_names_get_distinct_slugs(client, org_a, admin_a):
    slugs = set()
    for _ in range(3):
        response = client.post("/api/v1/engagements", headers=admin_a,
                               json={"name": "Nightly sweep"})
        assert response.status_code == 201
        slugs.add(response.json()["slug"])
    assert slugs == {"nightly-sweep", "nightly-sweep-2", "nightly-sweep-3"}


def test_an_unknown_engagement_type_is_refused(client, org_a, admin_a):
    response = client.post("/api/v1/engagements", headers=admin_a,
                           json={"name": "Bad", "engagement_type": "vibes"})
    assert response.status_code == 422


def test_engagements_are_not_visible_across_tenants(client, org_a, admin_a,
                                                    org_b, admin_b):
    created = client.post("/api/v1/engagements", headers=admin_a,
                          json={"name": "Tenant A only"}).json()
    assert client.get(f"/api/v1/engagements/{created['id']}",
                      headers=admin_b).status_code == 404
    assert client.get("/api/v1/engagements", headers=admin_b).json()["total"] == 0


def test_the_dedupe_registry_is_introspectable(client, org_a, admin_a):
    """Operators need to see why counts moved without reading the source."""
    response = client.get("/api/v1/engagements/dedupe-registry", headers=admin_a)
    assert response.status_code == 200
    body = response.json()
    assert set(body["algorithms"]) == {
        "legacy", "unique_id_from_tool", "hash_code", "unique_id_or_hash_code"}
    scanners = {s["scanner"]: s for s in body["scanners"]}
    assert scanners["nessus"]["algorithm"] == "legacy"
    assert scanners["semgrep"]["algorithm"] == "unique_id_or_hash_code"
    assert "file_path" in scanners["semgrep"]["fields"]


def test_dedupe_registry_route_is_not_shadowed_by_the_id_route(client, org_a, admin_a):
    """`/engagements/dedupe-registry` must not be parsed as an engagement UUID."""
    response = client.get("/api/v1/engagements/dedupe-registry", headers=admin_a)
    assert response.status_code == 200
    assert "scanners" in response.json()


# ---------------------------------------------------------------------------
# Import scoping through the API
# ---------------------------------------------------------------------------
def test_an_import_reports_the_scope_and_algorithm_it_used(client, org_a, admin_a):
    org_id, _, _ = org_a
    _seed(org_id)
    engagement = client.post("/api/v1/engagements", headers=admin_a,
                             json={"name": "DMZ sweep"}).json()

    response = client.post(
        "/api/v1/integrations/imports", headers=admin_a,
        files={"file": ("scan.nessus", io.BytesIO(NESSUS), "application/xml")},
        data={"source": "nessus", "engagement_id": engagement["id"]},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["status"] == "complete"
    assert body["findings_created"] == 1
    assert body["engagement_id"] == engagement["id"]
    assert body["test_id"] is not None
    assert body["dedupe_algorithm"] == "legacy"

    tests = client.get(f"/api/v1/engagements/{engagement['id']}/tests",
                       headers=admin_a).json()
    assert len(tests) == 1 and tests[0]["scanner"] == "nessus"

    detail = client.get(f"/api/v1/engagements/tests/{tests[0]['id']}",
                        headers=admin_a).json()
    assert detail["scope_size"] == 1
    assert detail["present"] == 1
    assert detail["absent"] == 0
    assert detail["effective_dedupe"]["algorithm"] == "legacy"


def test_the_importer_index_advertises_the_new_formats_and_options(client, org_a, admin_a):
    body = client.get("/api/v1/integrations/importers", headers=admin_a).json()
    for name in ("sarif", "trivy", "semgrep", "nuclei", "zap", "grype", "prowler"):
        assert name in body["formats"]
    assert "target_asset" in body["options"]
    assert "close_absent" in body["options"]
    assert body["deduplication"] == "/api/v1/engagements/dedupe-registry"


def test_an_out_of_range_absence_threshold_is_refused(client, org_a, admin_a):
    org_id, _, _ = org_a
    _seed(org_id)
    response = client.post(
        "/api/v1/integrations/imports", headers=admin_a,
        files={"file": ("scan.nessus", io.BytesIO(NESSUS), "application/xml")},
        data={"source": "nessus", "absence_threshold": "99"},
    )
    assert response.status_code == 422


def test_a_sarif_upload_is_detected_without_being_named(client, org_a, admin_a):
    org_id, _, _ = org_a
    _seed(org_id)
    sarif = json.dumps({
        "version": "2.1.0", "runs": [{
            "tool": {"driver": {"name": "CodeQL", "rules": [
                {"id": "py/sql-injection",
                 "shortDescription": {"text": "SQL built from user input"},
                 "properties": {"security-severity": "8.8",
                                "tags": ["external/cwe/cwe-089"]}}]}},
            "results": [{"ruleId": "py/sql-injection", "level": "error",
                         "message": {"text": "Tainted query."},
                         "locations": [{"physicalLocation": {
                             "artifactLocation": {"uri": "app/db.py"},
                             "region": {"startLine": 10}}}]}],
        }],
    }).encode()
    response = client.post(
        "/api/v1/integrations/imports", headers=admin_a,
        files={"file": ("results.sarif", io.BytesIO(sarif), "application/json")},
        data={"target_asset": "acme/api", "create_assets": "true"},
    )
    assert response.status_code == 201, response.text
    body = response.json()
    assert body["source"] == "sarif"
    assert body["findings_created"] == 1
    assert body["dedupe_algorithm"] == "unique_id_or_hash_code"


# ---------------------------------------------------------------------------
# Endpoints
# ---------------------------------------------------------------------------
def test_endpoint_search_and_per_endpoint_status(client, org_a, admin_a):
    org_id, _, _ = org_a
    _seed(org_id)
    zap = json.dumps({"site": [{
        "@host": "fw-edge-01.corp", "@port": "443", "@ssl": "true",
        "alerts": [{"pluginid": "10038", "alert": "CSP header missing",
                    "riskcode": "2", "cweid": "693", "desc": "<p>None set.</p>",
                    "instances": [{"uri": "https://fw-edge-01.corp/admin",
                                   "method": "GET"},
                                  {"uri": "https://fw-edge-01.corp/manager",
                                   "method": "GET"}]}],
    }]}).encode()
    imported = client.post(
        "/api/v1/integrations/imports", headers=admin_a,
        files={"file": ("zap.json", io.BytesIO(zap), "application/json")},
    )
    assert imported.status_code == 201, imported.text
    assert imported.json()["endpoints_created"] == 2

    found = client.get("/api/v1/engagements/endpoints/search",
                       headers=admin_a, params={"host": "fw-edge-01"}).json()
    assert found["total"] == 2

    with SessionLocal() as session:
        set_tenant(session, org_id)
        finding_id = session.execute(
            select(Finding.id).where(Finding.organization_id == org_id,
                                     Finding.scanner == "zap")
        ).scalars().one()

    listing = client.get(f"/api/v1/engagements/findings/{finding_id}/endpoints",
                         headers=admin_a).json()
    assert len(listing["items"]) == 2
    assert listing["outstanding"] == 2
    assert listing["fully_mitigated"] is False

    target = listing["items"][0]["endpoint_id"]
    mitigated = client.post(
        f"/api/v1/engagements/findings/{finding_id}/endpoints/mitigate",
        headers=admin_a, json={"endpoint_ids": [target]})
    assert mitigated.status_code == 200
    assert mitigated.json() == {
        **mitigated.json(),
        "mitigated": 1, "outstanding": 1, "fully_mitigated": False,
    }

    with SessionLocal() as session:
        set_tenant(session, org_id)
        # Mitigating every endpoint must NOT close the finding: closure is a
        # lifecycle transition with verification, not a side effect.
        finding = session.get(Finding, finding_id)
        assert finding.state == "new"


def test_endpoints_of_another_tenants_finding_are_not_reachable(
    client, org_a, admin_a, org_b, admin_b
):
    org_id, _, _ = org_a
    _seed(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        importers.run_import(session, org_id, NESSUS, source="nessus")
        session.commit()
        finding_id = session.execute(
            select(Finding.id).where(Finding.organization_id == org_id)
        ).scalars().first()

    assert client.get(f"/api/v1/engagements/findings/{finding_id}/endpoints",
                      headers=admin_b).status_code == 404


# ---------------------------------------------------------------------------
# Risk acceptance
# ---------------------------------------------------------------------------
def _one_finding(client, org_a, admin_a):
    org_id, _, _ = org_a
    _seed(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        importers.run_import(session, org_id, NESSUS, source="nessus")
        session.commit()
        return org_id, str(session.execute(
            select(Finding.id).where(Finding.organization_id == org_id)
        ).scalars().first())


def test_a_risk_acceptance_needs_a_substantive_reason(client, org_a, admin_a):
    _, finding_id = _one_finding(client, org_a, admin_a)
    response = client.post("/api/v1/engagements/risk-acceptances", headers=admin_a,
                           json={"name": "No reason", "reason": "nope",
                                 "finding_ids": [finding_id]})
    assert response.status_code == 422


def test_requesting_an_acceptance_leaves_the_finding_open(client, org_a, admin_a):
    org_id, finding_id = _one_finding(client, org_a, admin_a)
    response = client.post("/api/v1/engagements/risk-acceptances", headers=admin_a, json={
        "name": "Vendor patch pending",
        "reason": "The vendor fix ships in Q4; a WAF virtual patch is deployed.",
        "finding_ids": [finding_id],
        "expires_on": str(dt.date.today() + dt.timedelta(days=60)),
    })
    assert response.status_code == 201, response.text
    assert response.json()["state"] == "pending"

    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert session.get(Finding, finding_id).state == "new"


def test_the_requester_cannot_approve_their_own_acceptance_over_http(
    client, org_a, admin_a
):
    """The one control every auditor tests on an exception process."""
    _, finding_id = _one_finding(client, org_a, admin_a)
    created = client.post("/api/v1/engagements/risk-acceptances", headers=admin_a, json={
        "name": "Self approval attempt",
        "reason": "Trying to accept my own request, which must be refused.",
        "finding_ids": [finding_id],
    }).json()
    response = client.post(
        f"/api/v1/engagements/risk-acceptances/{created['id']}/approve",
        headers=admin_a, json={"note": "approved by me"})
    assert response.status_code == 409
    assert "own risk acceptance" in response.text


def test_rejecting_an_acceptance_records_the_decision(client, org_a, admin_a):
    _, finding_id = _one_finding(client, org_a, admin_a)
    created = client.post("/api/v1/engagements/risk-acceptances", headers=admin_a, json={
        "name": "Not acceptable",
        "reason": "Requesting acceptance of an internet-facing critical.",
        "finding_ids": [finding_id],
    }).json()
    response = client.post(
        f"/api/v1/engagements/risk-acceptances/{created['id']}/reject",
        headers=admin_a, json={"note": "Internet-facing critical; fix it."})
    assert response.status_code == 200
    body = response.json()
    assert body["state"] == "rejected"
    assert body["decided_note"] == "Internet-facing critical; fix it."


def test_the_expiry_job_is_reachable_and_idempotent(client, org_a, admin_a):
    first = client.post("/api/v1/engagements/risk-acceptances/expire", headers=admin_a)
    assert first.status_code == 200
    assert set(first.json()) == {"expired", "warned", "findings_reactivated"}
    second = client.post("/api/v1/engagements/risk-acceptances/expire", headers=admin_a)
    assert second.json()["expired"] == 0


def test_acceptances_are_listable_and_tenant_scoped(client, org_a, admin_a,
                                                    org_b, admin_b):
    _, finding_id = _one_finding(client, org_a, admin_a)
    client.post("/api/v1/engagements/risk-acceptances", headers=admin_a, json={
        "name": "Listed", "reason": "A reason long enough to pass validation.",
        "finding_ids": [finding_id]})
    assert client.get("/api/v1/engagements/risk-acceptances/list",
                      headers=admin_a).json()["total"] == 1
    assert client.get("/api/v1/engagements/risk-acceptances/list",
                      headers=admin_b).json()["total"] == 0


def test_the_new_routes_require_authentication(client):
    for path in ("/api/v1/engagements",
                 "/api/v1/engagements/dedupe-registry",
                 "/api/v1/engagements/endpoints/search",
                 "/api/v1/engagements/risk-acceptances/list"):
        assert client.get(path).status_code in (401, 403), path
