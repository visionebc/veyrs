"""Phase 25: the dashboard's Name column, and the XML guard that never ran.

Two defects, found the same way — by asking what a control actually does rather
than what its docstring says.

**1. "Top CWE" could not be given a name.** `cwe` rows are created from the
identifiers an NVD record carries, and an NVD record carries no name, so every
row was written as `name = id`. The dashboard rendered `CWE-79` in a column
headed *Name*, and the MITRE dictionary — the thing that actually names a
weakness — had never been fetched by anything in the tree. `sync-cwe` fetches
it; `Cwe.resolved` is what keeps a placeholder from masquerading as an answer.

**2. The XXE guard in both XML parsers was dead code.** It attached expat
handlers to `XMLParser.parser`, an attribute Python REMOVED in 3.9, behind
`except AttributeError: pass`. Measured on this fleet's 3.11.2 before the fix,
`_parse_xml` expanded a four-level nested entity: 200 bytes of upload into
10 kB of text, which is a gigabyte at nine levels. External entities were never
resolved (ElementTree installs no handler for them), so this was amplification,
not file disclosure — `test_external_entities_are_still_not_resolved` pins that
boundary so a future interpreter cannot move it quietly.

The guard now refuses the *declaration*, and only in the prolog:
`test_a_report_that_quotes_an_entity_declaration_still_parses` is the reason —
a security report legitimately contains `<!ENTITY` in its own finding text, and
refusing that file would be a self-inflicted outage.
"""
from __future__ import annotations

import io
import uuid
import zipfile
from xml.etree import ElementTree

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.intel import feeds
from veyrs.models import Asset, Cve, Cwe, FeedRun, Finding, Vulnerability
from veyrs.services import analytics, intelligence, xmlsafe
from veyrs.services.documents import ExtractionError, _from_xml
from veyrs.services.importers.base import ParserError
from veyrs.services.importers.parsers import _parse_xml

# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
NESTED_ENTITY = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r ['
    '<!ENTITY a "aaaaaaaaaa">'
    '<!ENTITY b "&a;&a;&a;&a;&a;&a;&a;&a;&a;&a;">'
    '<!ENTITY c "&b;&b;&b;&b;&b;&b;&b;&b;&b;&b;">'
    ']><r><x>&c;</x></r>'
).encode()

EXTERNAL_ENTITY = (
    '<?xml version="1.0"?>'
    '<!DOCTYPE r [<!ENTITY x SYSTEM "file:///etc/hostname">]>'
    '<r><x>&x;</x></r>'
).encode()

# A scanner report describing an XXE finding. It contains the exact token the
# guard looks for, in the body, where it is data and not a declaration.
QUOTES_ENTITY = (
    '<report><item title="XXE in the upload endpoint" '
    'payload="&lt;!ENTITY xxe SYSTEM &quot;file:///etc/passwd&quot;&gt;">'
    '<proof><![CDATA[<!DOCTYPE r [<!ENTITY xxe SYSTEM "file:///etc/passwd">]>]]></proof>'
    '</item></report>'
).encode()

CATALOGUE = (
    '<?xml version="1.0" encoding="UTF-8"?>'
    '<Weakness_Catalog Name="CWE" Version="4.20" Date="2026-04-30" '
    'xmlns="http://cwe.mitre.org/cwe-7">'
    '<Weaknesses>'
    '<Weakness ID="999901" Name="Improper Neutralization Of A Test Fixture" '
    'Abstraction="Base" Status="Stable">'
    '<Description>The product does not neutralize the fixture.</Description>'
    '</Weakness>'
    '<Weakness ID="999902" Name="Missing Authentication For A Test" '
    'Abstraction="Class" Status="Draft"><Description>No check runs.</Description>'
    '</Weakness>'
    '</Weaknesses>'
    '<Categories>'
    '<Category ID="999903" Name="Test Category" Status="Draft">'
    '<Summary>A grouping, not a weakness.</Summary></Category>'
    '</Categories>'
    '<Views>'
    '<View ID="999904" Name="Weaknesses In A Test Slice" Type="Graph" Status="Draft">'
    '<Objective>A curated slice, not a weakness class.</Objective></View>'
    '</Views>'
    '</Weakness_Catalog>'
).encode()


def _entries():
    entries, _ = feeds.parse_cwe_catalog(CATALOGUE)
    return entries


# ---------------------------------------------------------------------------
# 1. The guard that was never installed
# ---------------------------------------------------------------------------
def test_a_nested_entity_declaration_is_refused():
    """The live regression: this expanded to 10 kB before the fix."""
    with pytest.raises(ParserError, match="entity declarations"):
        _parse_xml(NESTED_ENTITY)


def test_a_single_entity_declaration_is_refused_too():
    simple = b'<?xml version="1.0"?><!DOCTYPE r [<!ENTITY a "BOOM">]><r><x>&a;</x></r>'
    with pytest.raises(ParserError, match="entity declarations"):
        _parse_xml(simple)


def test_document_extraction_refuses_entities_as_well():
    """`documents._from_xml` carried its own copy of the same dead guard."""
    with pytest.raises(ExtractionError, match="entity declarations"):
        _from_xml(NESTED_ENTITY)


def test_a_report_that_quotes_an_entity_declaration_still_parses():
    """A scanner report about XXE contains `<!ENTITY` in its own text.

    Refusing the file for that would be the guard causing the outage it exists
    to prevent, which is why the scan stops at the document element.
    """
    root = _parse_xml(QUOTES_ENTITY)
    assert root.find("item").get("title").startswith("XXE")


def test_external_entities_are_still_not_resolved():
    """The boundary this defence assumes, asserted rather than believed.

    ElementTree installs no external-reference handler, so a SYSTEM entity is
    reported as undefined instead of read off disk. If an interpreter ever
    changes that, this fails before it becomes a file-disclosure bug.
    """
    parser = ElementTree.XMLParser()
    with pytest.raises(ElementTree.ParseError, match="undefined entity"):
        ElementTree.fromstring(EXTERNAL_ENTITY.decode(), parser=parser)


def test_the_prolog_scan_stops_at_the_document_element():
    payload = b'<?xml version="1.0"?><!DOCTYPE r []><r><x>text</x></r>'
    assert b"<r>" not in xmlsafe.prolog_of(payload)
    assert b"<!DOCTYPE" in xmlsafe.prolog_of(payload)


# ---------------------------------------------------------------------------
# 2. Reading MITRE's catalogue
# ---------------------------------------------------------------------------
def test_the_catalogue_yields_weaknesses_and_categories():
    """NVD cites category ids too. One that is never named stays a number."""
    entries, version = feeds.parse_cwe_catalog(CATALOGUE)
    assert version == "4.20"
    by_id = {e["id"]: e for e in entries}
    assert by_id["CWE-999901"]["name"].startswith("Improper Neutralization")
    assert by_id["CWE-999901"]["abstraction"] == "Base"
    assert by_id["CWE-999901"]["description"] == "The product does not neutralize the fixture."
    # a Category has a Summary, not a Description, and no Abstraction attribute
    assert by_id["CWE-999903"]["abstraction"] == "Category"
    assert by_id["CWE-999903"]["description"] == "A grouping, not a weakness."


def test_a_view_is_ingested_because_cve_records_cite_view_ids():
    """Found in production: after ingesting weaknesses and categories only,
    CWE-701, CWE-702 and CWE-1026 were still bare numbers on the dashboard.
    They are views ("Weaknesses in OWASP Top Ten (2017)"), not weakness
    classes — and an id nobody can name is the defect this feed exists to fix.
    """
    entry = {e["id"]: e for e in _entries()}["CWE-999904"]
    assert entry["name"] == "Weaknesses In A Test Slice"
    assert entry["abstraction"] == "View"
    assert entry["description"] == "A curated slice, not a weakness class."


def test_a_catalogue_that_declares_entities_is_refused():
    poisoned = CATALOGUE.replace(
        b'<?xml version="1.0" encoding="UTF-8"?>',
        b'<?xml version="1.0" encoding="UTF-8"?>'
        b'<!DOCTYPE Weakness_Catalog [<!ENTITY a "x">]>',
    )
    with pytest.raises(xmlsafe.UnsafeXmlError):
        feeds.parse_cwe_catalog(poisoned)


def test_an_empty_catalogue_fails_the_run_instead_of_reporting_success():
    """Same rule as the other feeds: a fetch that got nothing is not a success."""
    empty = (b'<?xml version="1.0"?><Weakness_Catalog Version="4.20" '
             b'xmlns="http://cwe.mitre.org/cwe-7"><Weaknesses/></Weakness_Catalog>')
    with pytest.raises(feeds.FeedError, match="zero weaknesses"):
        feeds.parse_cwe_catalog(empty)


def test_the_xml_is_taken_out_of_the_zip():
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w") as archive:
        archive.writestr("readme.txt", "ignore me")
        archive.writestr("cwec_v4.20.xml", CATALOGUE)
    assert feeds.unpack_cwe_archive(buffer.getvalue()) == CATALOGUE


def test_a_bare_xml_body_passes_through():
    assert feeds.unpack_cwe_archive(CATALOGUE) == CATALOGUE


def test_an_oversized_member_is_refused_before_it_is_inflated(monkeypatch):
    """A zip bomb is refused on its declared size, not after inflating it."""
    monkeypatch.setattr(feeds, "MAX_CWE_XML_BYTES", 16)
    buffer = io.BytesIO()
    with zipfile.ZipFile(buffer, "w", zipfile.ZIP_DEFLATED) as archive:
        archive.writestr("cwec.xml", CATALOGUE)
    with pytest.raises(feeds.FeedError, match="ceiling"):
        feeds.unpack_cwe_archive(buffer.getvalue())


# ---------------------------------------------------------------------------
# 3. A placeholder is not an answer
# ---------------------------------------------------------------------------
def test_a_row_named_after_its_own_id_is_a_placeholder():
    assert Cwe(id="CWE-79", name="CWE-79").resolved is False
    assert Cwe(id="CWE-79", name="CWE-79").display_name is None
    assert Cwe(id="CWE-79", name="Cross-site Scripting").resolved is True


def test_ingest_promotes_the_placeholder_in_place():
    """Promoted, not replaced: `cve.cwe_ids` references these rows by id."""
    with SessionLocal() as session:
        session.merge(Cwe(id="CWE-999901", name="CWE-999901"))
        session.commit()

        stats = intelligence.ingest_cwe(session, _entries(), version="4.20")
        session.commit()

        row = session.get(Cwe, "CWE-999901")
        assert row.name.startswith("Improper Neutralization")
        assert row.abstraction == "Base"
        assert row.resolved is True
        # `created` is not asserted: whether a row is new depends on what ran
        # before in the session-scoped database, and a test that only passes
        # when it runs first is a test that will be deleted rather than fixed.
        assert stats["seen"] == len(_entries()) and stats["updated"] >= 1

        run = session.execute(
            select(FeedRun).where(FeedRun.feed == "cwe")
            .order_by(FeedRun.started_at.desc()).limit(1)
        ).scalars().first()
        assert run is not None and run.status == "succeeded"
        assert run.watermark == "4.20"


# ---------------------------------------------------------------------------
# 4. The dashboard column that started this
# ---------------------------------------------------------------------------
@pytest.fixture()
def estate(org_a):
    """One open finding whose CVE carries two weaknesses: one named, one not."""
    org_id, _, _ = org_a
    named, unnamed = "CWE-999901", "CWE-999999"
    with SessionLocal() as session:
        set_tenant(session, org_id)
        session.merge(Cwe(id=unnamed, name=unnamed))          # never in the catalogue
        cve_id = f"CVE-2026-{uuid.uuid4().int % 90000 + 9000}"
        session.merge(Cve(id=cve_id, source="test", title="fixture",
                          cwe_ids=[named, unnamed]))
        intelligence.ingest_cwe(session, _entries())
        asset = Asset(organization_id=org_id, name=f"host-{uuid.uuid4().hex[:8]}")
        vulnerability = Vulnerability(organization_id=org_id, cve_id=cve_id,
                                      title="fixture vulnerability")
        session.add_all([asset, vulnerability])
        session.flush()
        session.add(Finding(organization_id=org_id, asset_id=asset.id,
                            vulnerability_id=vulnerability.id, state="new",
                            dedupe_key=uuid.uuid4().hex, title="fixture finding"))
        session.commit()
        yield session, org_id, named, unnamed


def test_top_cwe_carries_the_name_from_the_dictionary(estate):
    """The defect: this key did not exist, so the UI column was always a dash."""
    session, org_id, named, _ = estate
    rows = {row["cwe"]: row for row in analytics.top_cwe(session, org_id)}
    assert rows[named]["name"].startswith("Improper Neutralization")
    assert rows[named]["open_findings"] == 1


def test_an_unloaded_weakness_reports_no_name_rather_than_its_id(estate):
    """Repeating the id under a Name heading is how a gap looks like data."""
    session, org_id, _, unnamed = estate
    rows = {row["cwe"]: row for row in analytics.top_cwe(session, org_id)}
    assert rows[unnamed]["name"] is None


# ---------------------------------------------------------------------------
# 5. The link the console draws now goes somewhere
# ---------------------------------------------------------------------------
def test_cwe_detail_answers_with_the_tenants_own_count(client, admin_a):
    with SessionLocal() as session:
        intelligence.ingest_cwe(session, _entries())
        session.commit()
    response = client.get("/api/v1/intel/cwe/CWE-999901", headers=admin_a)
    assert response.status_code == 200
    body = response.json()
    assert body["resolved"] is True
    assert body["name"].startswith("Improper Neutralization")
    assert body["open_findings"] >= 0
    assert body["reference"].endswith("/999901.html")


def test_cwe_detail_admits_when_it_only_has_the_identifier(client, admin_a):
    with SessionLocal() as session:
        session.merge(Cwe(id="CWE-999998", name="CWE-999998"))
        session.commit()
    body = client.get("/api/v1/intel/cwe/CWE-999998", headers=admin_a).json()
    assert body["resolved"] is False
    assert body["name"] is None


def test_an_unknown_cwe_is_a_404_not_an_invented_row(client, admin_a):
    assert client.get("/api/v1/intel/cwe/CWE-999997", headers=admin_a).status_code == 404
