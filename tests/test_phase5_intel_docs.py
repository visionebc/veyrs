"""Phase 5: document intelligence, threat feeds, knowledge base, search.

The behaviours under test are the ones the spec calls out as differentiators:
an uploaded vendor advisory becomes correlated findings, a news item is ranked
by whether it touches *your* inventory, and search never returns something the
caller is not allowed to see.
"""
from __future__ import annotations

import datetime as dt
import json
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    Asset, AssetProduct, Cve, Document, Finding, KnowledgeArticle, KnowledgeRevision,
    ThreatArticle, ThreatSource,
)
from veyrs.services import correlation, documents, intelligence, search, threatintel
from veyrs.services import risk as risk_service, sla as sla_service

from test_phase3_intel import NVD_ITEM

ADVISORY = """
Fortinet PSIRT Advisory FG-IR-26-001

An improper authentication vulnerability in FortiWeb may allow an unauthenticated
attacker to execute arbitrary code via crafted HTTP requests.

CVE ID: CVE-2026-0001
CWE-287
Severity: Critical
CVSS base score: 9.8
CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H

Affected Products:
FortiWeb 7.2.0 through 7.2.4

Solution:
Please upgrade to FortiWeb version 7.2.5 or above.
"""


@pytest.fixture()
def tenant(org_a):
    org_id, slug, _ = org_a
    with SessionLocal() as session:
        intelligence.ingest_nvd(session, [NVD_ITEM])
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        product = intelligence.upsert_product(session, "fortinet", "fortiweb")
        asset = Asset(organization_id=org_id, name="fw-edge-01", asset_type="firewall",
                      criticality="critical", exposure="internet")
        session.add(asset)
        session.flush()
        session.add(AssetProduct(organization_id=org_id, asset_id=asset.id,
                                 product_id=product.id, version="7.2.4"))
        risk_service.seed_profiles(session, org_id)
        sla_service.seed_policies(session, org_id)
        session.commit()
        return {"org_id": org_id, "asset_id": asset.id, "product_id": product.id}


# --------------------------------------------------------------------------
# Extraction
# --------------------------------------------------------------------------


def test_extract_entities_from_a_real_advisory():
    entities = documents.extract_entities(ADVISORY)
    assert entities["cve_ids"] == ["CVE-2026-0001"]
    assert entities["cwe_ids"] == ["CWE-287"]
    assert entities["severity"] == "critical"
    assert entities["max_cvss"] == 9.8
    assert "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" in entities["cvss_vectors"]
    assert "7.2.5" in entities["fixed_versions"]


def test_classify_recognises_document_kinds():
    assert documents.classify(ADVISORY, "FG-IR-26-001.pdf") == "vendor_advisory"
    assert documents.classify("Plugin ID 12345\nNessus scan report", "scan.nessus") \
        == "scan_report"


@pytest.mark.parametrize("payload,content_type,needle", [
    (b"plain text with CVE-2026-0001", "text/plain", "CVE-2026-0001"),
    (json.dumps({"cve": "CVE-2026-0001"}).encode(), "application/json", "CVE-2026-0001"),
    (b"a,b\nCVE-2026-0001,high", "text/csv", "CVE-2026-0001"),
    (b"<html><body><p>CVE-2026-0001</p></body></html>", "text/html", "CVE-2026-0001"),
    (b"<r><i>CVE-2026-0001</i></r>", "application/xml", "CVE-2026-0001"),
])
def test_extract_text_supported_formats(payload, content_type, needle):
    text, _ = documents.extract_text(payload, content_type, "f")
    assert needle in text


def test_html_script_content_is_stripped():
    text, _ = documents.extract_text(
        b"<html><script>alert('x')</script><p>real content</p></html>", "text/html", "f"
    )
    assert "alert" not in text
    assert "real content" in text


def test_xml_external_entities_are_refused():
    """XXE defence: an uploaded advisory must not be able to read the filesystem."""
    xxe = (b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/passwd">]>'
           b'<r>&x;</r>')
    with pytest.raises(documents.ExtractionError):
        documents.extract_text(xxe, "application/xml", "evil.xml")


def test_unsupported_format_raises_extraction_error():
    with pytest.raises(documents.ExtractionError):
        documents.extract_text(b"\x00\x01", "application/octet-stream", "blob.bin")


def test_chunking_preserves_all_content():
    text = "\n\n".join(f"Paragraph {i} " + "x" * 200 for i in range(20))
    chunks = documents.chunk_text(text, size=500, overlap=50)
    assert len(chunks) > 1
    joined = " ".join(chunks)
    for i in range(20):
        assert f"Paragraph {i}" in joined


def test_oversized_paragraph_is_split_not_dropped():
    chunks = documents.chunk_text("y" * 5000, size=1000, overlap=100)
    assert len(chunks) >= 5
    assert all(len(c) <= 1000 for c in chunks)


# --------------------------------------------------------------------------
# Document ingestion -> correlation
# --------------------------------------------------------------------------


def test_uploading_an_advisory_produces_findings(tenant):
    org_id = tenant["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        document, created = documents.ingest(
            session, org_id, filename="FG-IR-26-001.txt",
            data=ADVISORY.encode(), content_type="text/plain",
        )
        session.commit()
        assert created is True
        assert document.status == "processed"
        assert document.doc_class == "vendor_advisory"
        assert document.cve_ids == ["CVE-2026-0001"]

    with SessionLocal() as session:
        set_tenant(session, org_id)
        findings = session.execute(select(Finding)).scalars().all()
        assert len(findings) == 1
        assert findings[0].asset_id == tenant["asset_id"]


def test_document_ingestion_is_idempotent(tenant):
    org_id = tenant["org_id"]
    for _ in range(3):
        with SessionLocal() as session:
            set_tenant(session, org_id)
            documents.ingest(session, org_id, filename="a.txt",
                             data=ADVISORY.encode(), content_type="text/plain")
            session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert len(session.execute(select(Document)).scalars().all()) == 1
        assert len(session.execute(select(Finding)).scalars().all()) == 1


def test_document_cannot_invent_a_cve(tenant):
    """A CVE mentioned but unknown to VEYRS is reported as a gap, not accepted."""
    org_id = tenant["org_id"]
    body = "This references CVE-1999-00001 which VEYRS has never ingested."
    with SessionLocal() as session:
        set_tenant(session, org_id)
        document, _ = documents.ingest(session, org_id, filename="gap.txt",
                                       data=body.encode(), content_type="text/plain")
        session.commit()
        assert document.cve_ids == []
        assert documents.unknown_cves(document) == ["CVE-1999-00001"]


def test_malformed_upload_is_recorded_not_raised(tenant):
    org_id = tenant["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        document, _ = documents.ingest(session, org_id, filename="bad.json",
                                       data=b"{not json", content_type="application/json")
        session.commit()
        assert document.status in ("failed", "unsupported_format")
        assert document.error


def test_chunks_are_created_for_retrieval(tenant):
    org_id = tenant["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        document, _ = documents.ingest(session, org_id, filename="adv.txt",
                                       data=ADVISORY.encode(), content_type="text/plain")
        session.commit()
        assert len(document.chunks) >= 1


# --------------------------------------------------------------------------
# Threat feeds
# --------------------------------------------------------------------------


def test_article_relevance_reflects_inventory(tenant):
    org_id = tenant["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        source = ThreatSource(organization_id=org_id, slug="psirt", name="Fortinet PSIRT",
                              kind="rss", trust=0.9)
        session.add(source)
        session.flush()
        stats = threatintel.ingest_articles(session, org_id, source, [
            {"title": "FortiWeb RCE actively exploited",
             "summary": "Details on CVE-2026-0001 affecting FortiWeb.",
             "url": "https://example.com/a", "published": "2026-02-01T00:00:00Z"},
            {"title": "Unrelated cloud outage",
             "summary": "Nothing to do with your estate.",
             "url": "https://example.com/b"},
        ])
        session.commit()

    assert stats["created"] == 2
    assert stats["relevant"] == 1
    with SessionLocal() as session:
        set_tenant(session, org_id)
        digest = threatintel.feed_digest(session, org_id, days=3650)
        # The relevant item sorts first regardless of publication date.
        assert digest[0]["is_relevant"] is True
        assert digest[0]["relevant_asset_count"] == 1
        assert digest[1]["is_relevant"] is False


def test_article_confidence_follows_source_trust(tenant):
    org_id = tenant["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        trusted = ThreatSource(organization_id=org_id, slug="psirt2", name="PSIRT",
                               kind="rss", trust=1.0)
        blog = ThreatSource(organization_id=org_id, slug="blog", name="Some blog",
                            kind="rss", trust=0.2)
        session.add_all([trusted, blog])
        session.flush()
        threatintel.ingest_articles(session, org_id, trusted, [
            {"title": "Vendor advisory", "summary": "CVE-2026-0001 fixed in 7.2.5"},
        ])
        threatintel.ingest_articles(session, org_id, blog, [
            {"title": "Blog take", "summary": "CVE-2026-0001 is scary"},
        ])
        session.commit()
        rows = {a.title: a.confidence
                for a in session.execute(select(ThreatArticle)).scalars().all()}
        assert rows["Vendor advisory"] > rows["Blog take"]


def test_article_ingestion_is_idempotent(tenant):
    org_id = tenant["org_id"]
    entry = {"title": "Same story", "summary": "CVE-2026-0001", "url": "https://x/1"}
    for _ in range(3):
        with SessionLocal() as session:
            set_tenant(session, org_id)
            threatintel.ingest_articles(session, org_id, None, [entry])
            session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert len(session.execute(select(ThreatArticle)).scalars().all()) == 1


# --------------------------------------------------------------------------
# Knowledge base
# --------------------------------------------------------------------------


def test_editing_an_article_keeps_the_previous_text(tenant):
    org_id = tenant["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        article = threatintel.create_article(
            session, org_id, title="FortiWeb upgrade runbook",
            body="Step 1: read the release notes.", kind="runbook",
            cve_ids=["CVE-2026-0001"], is_published=True,
        )
        session.commit()
        article_id = article.id

    with SessionLocal() as session:
        set_tenant(session, org_id)
        article = session.get(KnowledgeArticle, article_id)
        threatintel.update_article(session, article, body="Step 1: snapshot the VM.",
                                   change_note="added snapshot step")
        session.commit()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        article = session.get(KnowledgeArticle, article_id)
        assert article.version == 2
        revisions = session.execute(
            select(KnowledgeRevision).where(KnowledgeRevision.article_id == article_id)
            .order_by(KnowledgeRevision.version)
        ).scalars().all()
        assert [r.version for r in revisions] == [1, 2]
        assert "release notes" in revisions[0].body  # the original survives


def test_no_version_bump_without_a_content_change(tenant):
    org_id = tenant["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        article = threatintel.create_article(session, org_id, title="T", body="B")
        threatintel.update_article(session, article, body="B", tags=["x"])
        session.commit()
        assert article.version == 1
        assert article.tags == ["x"]


def test_article_permission_gate(tenant):
    org_id = tenant["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        restricted = threatintel.create_article(
            session, org_id, title="Break-glass procedure", body="secret",
            required_permissions=["settings:admin"], is_published=True,
        )
        session.commit()
        assert threatintel.visible_to(restricted, {"finding:read"}, False) is False
        assert threatintel.visible_to(restricted, {"settings:admin"}, False) is True
        assert threatintel.visible_to(restricted, set(), True) is True  # superuser


def test_articles_for_cve_links_knowledge_to_the_graph(tenant):
    org_id = tenant["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        threatintel.create_article(session, org_id, title="Fix FortiWeb", body="x",
                                   cve_ids=["CVE-2026-0001"], is_published=True)
        threatintel.create_article(session, org_id, title="Unrelated", body="y",
                                   is_published=True)
        session.commit()
        hits = threatintel.articles_for_cve(session, org_id, "cve-2026-0001")
        assert [a.title for a in hits] == ["Fix FortiWeb"]


# --------------------------------------------------------------------------
# Search
# --------------------------------------------------------------------------


def test_search_spans_the_graph(tenant):
    org_id = tenant["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        documents.ingest(session, org_id, filename="adv.txt", data=ADVISORY.encode(),
                         content_type="text/plain")
        threatintel.create_article(session, org_id, title="FortiWeb runbook",
                                   body="upgrade steps", is_published=True)
        session.commit()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        result = search.search(
            session, org_id, "fortiweb",
            permissions=frozenset(search.ENTITY_PERMISSIONS.values()),
        )
        assert result["total"] > 0
        # "fortiweb" is a product/document/knowledge term here; the asset is
        # named fw-edge-01, so it is correctly absent from these results.
        assert "product" in result["results"]
        assert "document" in result["results"]
        assert "knowledge" in result["results"]

        by_hostname = search.search(
            session, org_id, "fw-edge",
            permissions=frozenset(search.ENTITY_PERMISSIONS.values()),
        )
        assert "asset" in by_hostname["results"]


def test_search_respects_permissions(tenant):
    """A caller without finding:read must not see findings in search results."""
    org_id = tenant["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        cve = session.get(Cve, "CVE-2026-0001")
        correlation.correlate_cve(session, org_id, cve)
        session.commit()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        limited = search.search(session, org_id, "CVE-2026-0001",
                                permissions=frozenset({"cve:read"}))
        assert "cve" in limited["results"]
        assert "finding" not in limited["results"]
        assert "finding" in limited["denied_types"]

        full = search.search(session, org_id, "CVE-2026-0001",
                             permissions=frozenset({"cve:read", "finding:read"}))
        assert "finding" in full["results"]


def test_search_is_tenant_scoped(tenant, org_b):
    org_id, other_id = tenant["org_id"], org_b[0]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        threatintel.create_article(session, org_id, title="Tenant A secret runbook",
                                   body="x", is_published=True)
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, other_id)
        result = search.search(session, other_id, "Tenant A secret",
                               permissions=frozenset({"knowledge:read"}))
        assert result["total"] == 0


def test_semantic_search_degrades_to_lexical_without_a_backend(tenant):
    org_id = tenant["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        threatintel.create_article(session, org_id, title="FortiWeb guidance",
                                   body="upgrade", is_published=True)
        session.commit()
        result = search.semantic_search(
            session, org_id, "fortiweb", permissions=frozenset({"knowledge:read"})
        )
        assert result["mode"] == "lexical"
        assert "not configured" in result["note"]
        assert result["total"] >= 1


def test_semantic_search_falls_back_when_the_backend_errors(tenant):
    org_id = tenant["org_id"]

    class Broken(search.VectorBackend):
        available = True

        def query(self, organization_id, text, limit=10):
            raise RuntimeError("qdrant unreachable")

    search.set_vector_backend(Broken())
    try:
        with SessionLocal() as session:
            set_tenant(session, org_id)
            result = search.semantic_search(
                session, org_id, "fortiweb", permissions=frozenset({"knowledge:read"})
            )
            assert result["mode"] == "lexical"
            assert "unreachable" in result["note"]
    finally:
        search.set_vector_backend(search.NullVectorBackend())
