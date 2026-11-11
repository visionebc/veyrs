"""Phase 7: compliance engine.

The assertions that matter here are mostly about **honesty**, because the
failure mode of a compliance module is not a crash -- it is a confident,
wrong number in front of an auditor:

  * a partial catalogue must announce itself everywhere it is reported;
  * an automated signal must never promote a control to `implemented`;
  * an assessment snapshot must not change when the underlying data changes;
  * `not_applicable` must carry a justification;
  * coverage must count `not_assessed` against you, not ignore it.
"""
from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    Asset, AssetProduct, ComplianceAssessment, ComplianceControl, ComplianceFramework,
    ControlImplementation, Cve, Evidence, Finding, ImplementationStatus,
)
from veyrs.services import compliance as service
from veyrs.services import correlation, intelligence
from veyrs.services import risk as risk_service, sla as sla_service

from test_phase3_intel import NVD_ITEM


@pytest.fixture()
def seeded():
    """The built-in catalogues. Global data, so seeding is idempotent."""
    with SessionLocal() as session:
        service.seed_frameworks(session)
        session.commit()


@pytest.fixture()
def tenant(org_a, seeded):
    org_id, slug, email = org_a
    with SessionLocal() as session:
        intelligence.ingest_nvd(session, [NVD_ITEM])
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        product = intelligence.upsert_product(session, "fortinet", "fortiweb", cpe_part="a")
        asset = Asset(organization_id=org_id, name="fw-edge-01", hostname="fw-edge-01.corp",
                      asset_type="firewall", criticality="critical", exposure="internet",
                      environment="production", data_classification="confidential")
        session.add(asset)
        session.flush()
        session.add(AssetProduct(organization_id=org_id, asset_id=asset.id,
                                 product_id=product.id, version="7.2.4"))
        risk_service.seed_profiles(session, org_id)
        sla_service.seed_policies(session, org_id)
        session.commit()
        cve = session.get(Cve, "CVE-2026-0001")
        correlation.correlate_cve(session, org_id, cve)
        session.commit()
        return {"org_id": org_id, "slug": slug, "asset_id": asset.id}


def _framework(session, slug: str) -> ComplianceFramework:
    return session.execute(
        select(ComplianceFramework).where(ComplianceFramework.slug == slug)
    ).scalars().first()


# ---------------------------------------------------------------------------
# Catalogue integrity
# ---------------------------------------------------------------------------
def test_builtin_frameworks_are_seeded(seeded):
    with SessionLocal() as session:
        slugs = {f.slug for f in session.execute(select(ComplianceFramework)).scalars().all()}
    assert {"nist-csf", "cis-controls", "iso-27001", "iso-27002"} <= slugs


def test_seeding_is_idempotent(seeded):
    with SessionLocal() as session:
        before = session.execute(select(ComplianceControl)).scalars().all()
        service.seed_frameworks(session)
        session.commit()
        after = session.execute(select(ComplianceControl)).scalars().all()
    assert len(before) == len(after)


def test_copyrighted_catalogues_ship_no_normative_text(seeded):
    """ISO text is not ours to redistribute; identifiers and titles are enough."""
    with SessionLocal() as session:
        iso = _framework(session, "iso-27001")
        controls = session.execute(
            select(ComplianceControl).where(ComplianceControl.framework_id == iso.id)
        ).scalars().all()
    assert controls
    assert all(c.normative_text is None for c in controls)
    assert iso.licence_note and "copyright" in iso.licence_note.lower()


def test_partial_catalogues_declare_themselves(seeded):
    with SessionLocal() as session:
        iso = _framework(session, "iso-27001")
        shipped = session.execute(
            select(ComplianceControl).where(ComplianceControl.framework_id == iso.id)
        ).scalars().all()
    assert iso.is_partial is True
    assert iso.official_control_count == 93
    assert len(shipped) < iso.official_control_count
    assert "partial" in iso.coverage_disclaimer.lower()


def test_every_automation_signal_referenced_by_a_control_exists(seeded):
    """A typo'd signal name would silently mean 'this control has no evidence'."""
    with SessionLocal() as session:
        refs = {
            c.automation_signal for c in
            session.execute(select(ComplianceControl)).scalars().all()
            if c.automation_signal
        }
    unknown = refs - set(service.AUTOMATED_SIGNALS)
    assert not unknown, f"controls reference unknown signals: {sorted(unknown)}"


def test_crosswalks_only_point_at_frameworks_that_exist(seeded):
    with SessionLocal() as session:
        slugs = {f.slug for f in session.execute(select(ComplianceFramework)).scalars().all()}
        controls = session.execute(select(ComplianceControl)).scalars().all()
    for control in controls:
        for target in (control.crosswalk or {}):
            assert target in slugs, f"{control.ref} crosswalks to unknown {target!r}"


def test_veyrs_guidance_is_attributed_not_presented_as_the_standard(seeded):
    with SessionLocal() as session:
        iso = _framework(session, "iso-27001")
        control = session.execute(
            select(ComplianceControl).where(ComplianceControl.framework_id == iso.id,
                                            ComplianceControl.ref == "A.8.8")
        ).scalar_one()
    # Stored in a column named for us, and the normative column stays empty.
    assert control.veyrs_guidance
    assert control.normative_text is None


# ---------------------------------------------------------------------------
# Automated signals
# ---------------------------------------------------------------------------
def test_signals_all_evaluate_without_error(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        for name in service.AUTOMATED_SIGNALS:
            result = service.evaluate_signal(session, tenant["org_id"], name)
            assert result["signal"] == name
            assert "detail" in result and "ratio" in result


def test_signal_reports_its_derivation(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        result = service.evaluate_signal(session, tenant["org_id"],
                                         "asset_inventory_coverage")
    assert result["total"] == 1
    assert result["value"] == 1
    assert result["ratio"] == 1.0
    assert "1 of 1" in result["detail"]


def test_unknown_signal_returns_none_rather_than_raising(tenant):
    with SessionLocal() as session:
        assert service.evaluate_signal(session, tenant["org_id"], "nope") is None


def test_automated_evidence_never_reaches_implemented(tenant):
    """The whole point: a green metric is not a designed, owned control."""
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        result = service.refresh_automated_evidence(session, tenant["org_id"])
        session.commit()

        statuses = {
            i.status for i in session.execute(
                select(ControlImplementation).where(
                    ControlImplementation.organization_id == tenant["org_id"]
                )
            ).scalars().all()
        }
    assert result["evaluated"] > 0
    assert ImplementationStatus.IMPLEMENTED.value not in statuses


def test_automated_evidence_is_recorded_with_a_hash(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        service.refresh_automated_evidence(session, tenant["org_id"])
        session.commit()
        rows = session.execute(
            select(Evidence).where(Evidence.organization_id == tenant["org_id"],
                                   Evidence.is_automated.is_(True))
        ).scalars().all()
    assert rows
    assert all(e.content_hash and len(e.content_hash) == 64 for e in rows)
    assert all(e.payload.get("signal") for e in rows)


# ---------------------------------------------------------------------------
# Implementations
# ---------------------------------------------------------------------------
def test_not_applicable_requires_a_justification(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        control = session.execute(select(ComplianceControl)).scalars().first()
        implementation = service.get_or_create_implementation(
            session, tenant["org_id"], control
        )
        with pytest.raises(ValueError, match="justification"):
            service.set_status(session, implementation, "not_applicable")


def test_unknown_status_is_refused(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        control = session.execute(select(ComplianceControl)).scalars().first()
        implementation = service.get_or_create_implementation(
            session, tenant["org_id"], control
        )
        with pytest.raises(ValueError, match="unknown implementation status"):
            service.set_status(session, implementation, "totally-fine")


def test_setting_a_status_schedules_the_next_review(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        control = session.execute(select(ComplianceControl)).scalars().first()
        implementation = service.get_or_create_implementation(
            session, tenant["org_id"], control
        )
        service.set_status(session, implementation, "implemented",
                           statement="Patching runs weekly", review_period_days=90)
        session.commit()
        assert implementation.next_review_at is not None
        delta = implementation.next_review_at - implementation.last_reviewed_at
        assert 89 <= delta.days <= 90


def test_overdue_implementations_become_stale(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        control = session.execute(select(ComplianceControl)).scalars().first()
        implementation = service.get_or_create_implementation(
            session, tenant["org_id"], control
        )
        service.set_status(session, implementation, "implemented", statement="done")
        implementation.next_review_at = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=1)
        session.commit()

        moved = service.mark_stale_implementations(session, tenant["org_id"])
        session.commit()
        session.refresh(implementation)
    assert moved == 1
    assert implementation.status == ImplementationStatus.STALE.value


def test_review_period_zero_means_no_expiry(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        control = session.execute(select(ComplianceControl)).scalars().first()
        implementation = service.get_or_create_implementation(
            session, tenant["org_id"], control
        )
        service.set_status(session, implementation, "implemented", review_period_days=0)
        session.commit()
    assert implementation.next_review_at is None
    assert implementation.is_stale is False


# ---------------------------------------------------------------------------
# Coverage
# ---------------------------------------------------------------------------
def test_coverage_counts_unassessed_against_you(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        framework = _framework(session, "cis-controls")
        report = service.coverage(session, tenant["org_id"], framework)
    assert report["counts"]["not_assessed"] > 0
    assert report["implemented_ratio"] == 0.0
    assert report["framework"]["is_partial"] is True
    assert report["framework"]["disclaimer"]


def test_coverage_excludes_justified_not_applicable_from_the_denominator(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        framework = _framework(session, "cis-controls")
        before = service.coverage(session, tenant["org_id"], framework)

        control = session.execute(
            select(ComplianceControl).where(ComplianceControl.framework_id == framework.id,
                                            ComplianceControl.ref == "18")
        ).scalar_one()
        implementation = service.get_or_create_implementation(
            session, tenant["org_id"], control
        )
        service.set_status(session, implementation, "not_applicable",
                           justification="No external penetration testing programme yet")
        session.commit()
        after = service.coverage(session, tenant["org_id"], framework)

    assert after["applicable_controls"] == before["applicable_controls"] - 1


def test_coverage_reports_evidence_counts(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        framework = _framework(session, "cis-controls")
        service.refresh_automated_evidence(session, tenant["org_id"],
                                           framework_id=framework.id)
        session.commit()
        report = service.coverage(session, tenant["org_id"], framework)
    assert report["evidenced_controls"] > 0
    evidenced = [r for r in report["controls"] if r["evidence_count"]]
    assert all(r["automation_signal"] for r in evidenced)


# ---------------------------------------------------------------------------
# The chain (spec section 41)
# ---------------------------------------------------------------------------
def test_control_chain_walks_to_findings_and_evidence(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        iso = _framework(session, "iso-27001")
        control = session.execute(
            select(ComplianceControl).where(ComplianceControl.framework_id == iso.id,
                                            ComplianceControl.ref == "A.8.8")
        ).scalar_one()
        finding = session.execute(
            select(Finding).where(Finding.organization_id == tenant["org_id"])
        ).scalars().first()

        service.link_object(session, tenant["org_id"], control, "asset",
                            str(tenant["asset_id"]), rationale="edge firewall in scope")
        service.link_object(session, tenant["org_id"], control, "finding", str(finding.id))
        service.refresh_automated_evidence(session, tenant["org_id"], framework_id=iso.id)
        session.commit()

        chain = service.control_chain(session, tenant["org_id"], control.id)

    assert chain["control"]["ref"] == "A.8.8"
    assert len(chain["assets"]) == 1
    assert len(chain["findings"]) == 1
    assert chain["evidence"]
    assert chain["control"]["crosswalk"].get("nist-csf") == ["ID.RA-01"]


def test_linking_is_idempotent(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        control = session.execute(select(ComplianceControl)).scalars().first()
        first = service.link_object(session, tenant["org_id"], control, "asset",
                                    str(tenant["asset_id"]))
        second = service.link_object(session, tenant["org_id"], control, "asset",
                                     str(tenant["asset_id"]))
        session.commit()
    assert first.id == second.id


# ---------------------------------------------------------------------------
# Assessments
# ---------------------------------------------------------------------------
def test_completed_assessment_freezes_its_snapshot(tenant):
    """An audit record that follows live data is not an audit record."""
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        framework = _framework(session, "cis-controls")
        assessment = ComplianceAssessment(
            organization_id=tenant["org_id"], framework_id=framework.id,
            name="Annual review 2026", status="in_progress",
        )
        session.add(assessment)
        session.flush()
        service.complete_assessment(session, assessment, summary="Baseline")
        session.commit()
        frozen = assessment.snapshot["counts"]["not_assessed"]

    # Change reality afterwards.
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        framework = _framework(session, "cis-controls")
        control = session.execute(
            select(ComplianceControl).where(ComplianceControl.framework_id == framework.id,
                                            ComplianceControl.ref == "7")
        ).scalar_one()
        implementation = service.get_or_create_implementation(
            session, tenant["org_id"], control
        )
        service.set_status(session, implementation, "implemented", statement="running")
        session.commit()

        reloaded = session.get(ComplianceAssessment, assessment.id)
        live = service.coverage(session, tenant["org_id"], framework)

    assert reloaded.snapshot["counts"]["not_assessed"] == frozen
    assert live["counts"]["not_assessed"] != frozen


def test_completing_an_assessment_raises_gaps_for_every_shortfall(tenant):
    from veyrs.models import AssessmentGap

    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        framework = _framework(session, "iso-27002")
        assessment = ComplianceAssessment(
            organization_id=tenant["org_id"], framework_id=framework.id,
            name="ISO 27002 gap analysis", status="in_progress",
        )
        session.add(assessment)
        session.flush()
        service.complete_assessment(session, assessment)
        session.commit()

        gaps = session.execute(
            select(AssessmentGap).where(AssessmentGap.assessment_id == assessment.id)
        ).scalars().all()
        controls = session.execute(
            select(ComplianceControl).where(ComplianceControl.framework_id == framework.id)
        ).scalars().all()

    assert len(gaps) == len(controls)  # nothing assessed yet => every control is a gap
    assert all(g.severity == "high" for g in gaps)


def test_assessment_snapshot_carries_the_partial_disclaimer(tenant):
    with SessionLocal() as session:
        set_tenant(session, tenant["org_id"])
        framework = _framework(session, "iso-27001")
        assessment = ComplianceAssessment(
            organization_id=tenant["org_id"], framework_id=framework.id,
            name="ISO readiness", status="in_progress",
        )
        session.add(assessment)
        session.flush()
        service.complete_assessment(session, assessment)
        session.commit()
    assert "partial" in assessment.snapshot["framework"]["disclaimer"].lower()


# ---------------------------------------------------------------------------
# CSV import
# ---------------------------------------------------------------------------
def test_csv_import_adds_controls_and_can_clear_the_partial_flag(seeded):
    with SessionLocal() as session:
        framework = ComplianceFramework(
            slug=f"tiny-{uuid.uuid4().hex[:6]}", name="Tiny", version="1",
            publisher="Test", is_partial=True, official_control_count=2,
        )
        session.add(framework)
        session.flush()
        payload = b"ref,title,normative_text\nT.1,First control,Do the thing\nT.2,Second,More\n"
        result = service.import_controls_csv(session, framework, payload)
        session.commit()
    assert result["created"] == 2
    assert result["is_partial"] is False


def test_csv_import_rejects_a_file_without_the_required_columns(seeded):
    with SessionLocal() as session:
        framework = ComplianceFramework(
            slug=f"tiny-{uuid.uuid4().hex[:6]}", name="Tiny", version="1", publisher="T",
        )
        session.add(framework)
        session.flush()
        with pytest.raises(ValueError, match="missing required column"):
            service.import_controls_csv(session, framework, b"name,description\na,b\n")


def test_partial_import_leaves_the_flag_set(seeded):
    with SessionLocal() as session:
        framework = ComplianceFramework(
            slug=f"tiny-{uuid.uuid4().hex[:6]}", name="Tiny", version="1",
            publisher="T", is_partial=True, official_control_count=50,
        )
        session.add(framework)
        session.flush()
        result = service.import_controls_csv(session, framework, b"ref,title\nX.1,One\n")
        session.commit()
    assert result["is_partial"] is True


# ---------------------------------------------------------------------------
# HTTP surface
# ---------------------------------------------------------------------------
def test_frameworks_endpoint_surfaces_the_disclaimer(client, admin_a, seeded):
    response = client.get("/api/v1/compliance/frameworks", headers=admin_a)
    assert response.status_code == 200, response.text
    iso = next(f for f in response.json() if f["slug"] == "iso-27001")
    assert iso["is_partial"] is True
    assert iso["disclaimer"]
    assert iso["controls_shipped"] < iso["official_control_count"]


def test_coverage_endpoint_requires_permission(client, seeded):
    assert client.get(f"/api/v1/compliance/frameworks/{uuid.uuid4()}/coverage").status_code == 401


def test_implementation_roundtrip_over_http(client, admin_a, seeded):
    frameworks = client.get("/api/v1/compliance/frameworks", headers=admin_a).json()
    cis = next(f for f in frameworks if f["slug"] == "cis-controls")
    controls = client.get(f"/api/v1/compliance/frameworks/{cis['id']}/controls",
                          headers=admin_a).json()
    control = next(c for c in controls if c["ref"] == "7")

    response = client.put(
        f"/api/v1/compliance/controls/{control['id']}/implementation",
        headers=admin_a,
        json={"status": "implemented", "statement": "Weekly scans + SLA policy",
              "review_period_days": 180},
    )
    assert response.status_code == 200, response.text
    assert response.json()["status"] == "implemented"
    assert response.json()["next_review_at"]


def test_not_applicable_without_justification_is_422_not_500(client, admin_a, seeded):
    frameworks = client.get("/api/v1/compliance/frameworks", headers=admin_a).json()
    cis = next(f for f in frameworks if f["slug"] == "cis-controls")
    controls = client.get(f"/api/v1/compliance/frameworks/{cis['id']}/controls",
                          headers=admin_a).json()
    response = client.put(
        f"/api/v1/compliance/controls/{controls[0]['id']}/implementation",
        headers=admin_a, json={"status": "not_applicable"},
    )
    assert response.status_code == 422


def test_signals_endpoint_returns_derivations(client, admin_a, seeded):
    body = client.get("/api/v1/compliance/signals", headers=admin_a).json()
    assert body["pass_ratio"] == service.SIGNAL_PASS_RATIO
    assert len(body["signals"]) == len(service.AUTOMATED_SIGNALS)
    assert all("detail" in s for s in body["signals"])


def test_link_rejects_an_unlisted_object_type(client, admin_a, seeded):
    frameworks = client.get("/api/v1/compliance/frameworks", headers=admin_a).json()
    cis = next(f for f in frameworks if f["slug"] == "cis-controls")
    controls = client.get(f"/api/v1/compliance/frameworks/{cis['id']}/controls",
                          headers=admin_a).json()
    response = client.post(f"/api/v1/compliance/controls/{controls[0]['id']}/links",
                           headers=admin_a,
                           json={"object_type": "users", "object_id": "x"})
    assert response.status_code == 422


def test_custom_framework_is_scoped_to_its_creator(client, admin_a, admin_b, seeded):
    slug = f"internal-{uuid.uuid4().hex[:6]}"
    created = client.post("/api/v1/compliance/frameworks", headers=admin_a, json={
        "slug": slug, "name": "Internal Baseline", "version": "1.0",
        "publisher": "Us",
    })
    assert created.status_code == 201, created.text
    framework_id = created.json()["id"]

    # tenant A sees it
    assert any(f["id"] == framework_id
               for f in client.get("/api/v1/compliance/frameworks", headers=admin_a).json())
    # tenant B does not
    assert not any(f["id"] == framework_id
                   for f in client.get("/api/v1/compliance/frameworks",
                                       headers=admin_b).json())
    # and cannot read its controls
    assert client.get(f"/api/v1/compliance/frameworks/{framework_id}/controls",
                      headers=admin_b).status_code == 404


def test_assessment_lifecycle_over_http(client, admin_a, seeded):
    frameworks = client.get("/api/v1/compliance/frameworks", headers=admin_a).json()
    cis = next(f for f in frameworks if f["slug"] == "cis-controls")

    created = client.post("/api/v1/compliance/assessments", headers=admin_a, json={
        "framework_id": cis["id"], "name": "Q3 review", "assessor": "Internal Audit",
    })
    assert created.status_code == 201, created.text
    assessment_id = created.json()["id"]

    completed = client.post(
        f"/api/v1/compliance/assessments/{assessment_id}/complete", headers=admin_a
    )
    assert completed.status_code == 200, completed.text
    assert completed.json()["gaps"] > 0
    assert completed.json()["snapshot_disclaimer"]

    # completing twice is a conflict, not a silent re-freeze
    again = client.post(f"/api/v1/compliance/assessments/{assessment_id}/complete",
                        headers=admin_a)
    assert again.status_code == 409


def test_evidence_is_listed_with_expiry_state(client, admin_a, seeded):
    frameworks = client.get("/api/v1/compliance/frameworks", headers=admin_a).json()
    cis = next(f for f in frameworks if f["slug"] == "cis-controls")
    controls = client.get(f"/api/v1/compliance/frameworks/{cis['id']}/controls",
                          headers=admin_a).json()

    response = client.post(
        f"/api/v1/compliance/controls/{controls[0]['id']}/evidence", headers=admin_a,
        json={"kind": "attestation", "title": "CISO sign-off",
              "valid_until": str(dt.date.today() - dt.timedelta(days=1))},
    )
    assert response.status_code == 201, response.text

    listing = client.get("/api/v1/compliance/evidence?expired=true", headers=admin_a).json()
    assert listing["total"] >= 1
    assert all(item["is_expired"] for item in listing["items"])


def test_evidence_kind_must_be_known(client, admin_a, seeded):
    frameworks = client.get("/api/v1/compliance/frameworks", headers=admin_a).json()
    cis = next(f for f in frameworks if f["slug"] == "cis-controls")
    controls = client.get(f"/api/v1/compliance/frameworks/{cis['id']}/controls",
                          headers=admin_a).json()
    response = client.post(
        f"/api/v1/compliance/controls/{controls[0]['id']}/evidence", headers=admin_a,
        json={"kind": "vibes", "title": "trust me"},
    )
    assert response.status_code == 422
