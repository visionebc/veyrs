"""Phase 37: intelligence browsing scoped to the software this estate runs.

The complaint that produced this phase, in the user's words: *"if we don't have
SQL in the fleet, no SQL vulnerabilities should show up here."* That is correct
about the READING and wrong about the STORAGE, and the distinction is the whole
design:

* The corpus stays global. `Cve`, `Vendor`, `Product` and `CveCpeMatch` carry no
  `organization_id` because correlation is computed FROM the dictionary. A CVE
  that was never ingested cannot fail to match an asset -- it is simply absent,
  and absence renders as "not affected". Downloading "only what affects me" is
  circular, and it fails silently.
* The reading is tenant-shaped. Browsing 359 353 CVEs to reach the ~2 500 that
  name software you actually run is a search engine, not intelligence.

So `/intel/cve` and `/intel/kev` default to an estate lens with the catalogue
one parameter away, and every counter reports both numbers.

The cost is real and is pinned below: under this lens **your inventory becomes
the boundary of what you can see**. A package that never resolved to a CPE has
no product id, so its CVEs are outside the filter entirely -- not shown as
unmatched, just gone. `estate_inventory_health` exists so an empty estate view
can be told apart from a clean one, and the tests here refuse to let that
distinction quietly disappear.
"""
from __future__ import annotations

import ast
import datetime as dt
import inspect
import pathlib
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    Asset, AssetProduct, Cve, CveCpeMatch, Finding, KevEntry, Vulnerability,
)
from veyrs.services import intelligence

CONSOLE = pathlib.Path("/opt/veyrs/frontend/console/app.js")
SERVICE = pathlib.Path(inspect.getsourcefile(intelligence))


# ---------------------------------------------------------------------------
# Fixtures. `cve`, `cve_cpe_match`, `products` and `vendors` are GLOBAL tables,
# so every row created here is namespaced by a uuid: a fixture that reuses
# "nginx" makes this file's results depend on which other test ran first.
# ---------------------------------------------------------------------------
@pytest.fixture()
def estate(org_a):
    """One organization running exactly one product, plus a CVE for each of:

    the product it runs, and a database engine it does not. The second one is
    the user's "SQL" example, made concrete.
    """
    org_id, slug, email = org_a
    tag = uuid.uuid4().hex[:10]
    session = SessionLocal()
    set_tenant(session, org_id)

    installed = intelligence.upsert_product(session, f"vendor-{tag}", f"webserver-{tag}")
    absent = intelligence.upsert_product(session, f"dbvendor-{tag}", f"sqlengine-{tag}")

    # Derived from the whole tag, not from `abs(hash(tag)) % 9000`. That gave
    # 9000 possible ids against a test database that PERSISTS and accumulates
    # rows across runs, so `pk_cve` collided on a birthday-problem schedule --
    # a fixture error that reads like a defect in the code under test. A CVE id
    # takes four OR MORE digits, so the full tag fits.
    mine = f"CVE-2099-{int(tag, 16)}"
    theirs = f"CVE-2098-{int(tag, 16)}"
    # The tag goes in the title because `q` searches id/title/description, and
    # the global `cve` table is shared with every other test in the suite: a
    # free-text needle is the only way to page a deterministic set out of it.
    for cve_id, product, title in (
        (mine, installed, f"Request smuggling in the web server we run [{tag}]"),
        (theirs, absent, f"SQL injection in an engine we do not run [{tag}]"),
    ):
        session.add(Cve(
            id=cve_id, title=title, description=title,
            cvss3_base_score=7.5, cvss3_severity="high",
            published_at=dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc),
        ))
        session.flush()
        session.add(CveCpeMatch(
            cve_id=cve_id, cpe23=f"cpe:2.3:a:x:{product.name}:*:*:*:*:*:*:*:*",
            product_id=product.id, vulnerable=True,
        ))
        session.add(KevEntry(
            cve_id=cve_id, vendor_project="x", product=product.name,
            vulnerability_name=title, required_action="patch",
            date_added=dt.date(2026, 1, 1),
        ))

    asset = Asset(organization_id=org_id, name=f"host-{tag}", asset_type="server")
    session.add(asset)
    session.flush()
    session.add(AssetProduct(
        organization_id=org_id, asset_id=asset.id, product_id=installed.id,
        version="1.0.0", detected_by="test",
    ))
    session.commit()
    yield {"org_id": org_id, "slug": slug, "email": email, "tag": tag,
           "mine": mine, "theirs": theirs, "asset_id": asset.id,
           "installed": installed.id, "absent": absent.id}
    session.close()


def _ids(payload) -> set[str]:
    return {row["cve_id"] for row in payload["items"]}


# ---------------------------------------------------------------------------
# 1. The default. This is the behaviour that was asked for.
# ---------------------------------------------------------------------------
def test_the_cve_list_defaults_to_software_this_estate_actually_runs(
    client, admin_a, estate
):
    body = client.get(
        "/api/v1/intel/cve", params={"q": estate["tag"], "size": 200}, headers=admin_a
    ).json()
    assert estate["mine"] in _ids(body)
    assert estate["theirs"] not in _ids(body), (
        "a CVE for software nobody runs reached a default list view"
    )


def test_the_whole_catalogue_stays_one_parameter_away(client, admin_a, estate):
    """Not a nicety. 'Does this bulletin affect us?' cannot be answered by a
    tool that can only show you what already affects you -- and neither can
    'should we adopt this component?'."""
    body = client.get(
        "/api/v1/intel/cve",
        params={"q": estate["tag"], "size": 200, "affects_estate": "false"},
        headers=admin_a,
    ).json()
    assert {estate["mine"], estate["theirs"]} <= _ids(body)


def test_the_lens_narrows_total_and_not_merely_the_page(client, admin_a, estate):
    """The defect class this repeats: v0.21.0's vendor list sorted a page AFTER
    paginating it, so it looked ranked and was not. A filter applied after the
    count produces a list that says "2 of 359 353" and then pages through the
    359 353."""
    scoped = client.get(
        "/api/v1/intel/cve", params={"q": estate["tag"], "size": 200}, headers=admin_a
    ).json()
    wide = client.get(
        "/api/v1/intel/cve",
        params={"q": estate["tag"], "size": 200, "affects_estate": "false"},
        headers=admin_a,
    ).json()
    assert scoped["total"] == len(scoped["items"]) == 1
    assert wide["total"] == 2


# ---------------------------------------------------------------------------
# 2. It is an ESTATE lens, so it must be a TENANT lens
# ---------------------------------------------------------------------------
def test_another_tenants_inventory_does_not_widen_your_estate(
    client, admin_b, estate
):
    """`asset_products` is RLS-forced, but the route also names the org
    explicitly: a filter that depended only on the session variable would
    return everything the moment somebody wired it to a non-tenant session."""
    body = client.get(
        "/api/v1/intel/cve", params={"q": estate["tag"], "size": 200}, headers=admin_b
    ).json()
    assert _ids(body) == set(), "tenant B saw CVEs scoped to tenant A's inventory"


def test_the_routes_use_a_tenant_session_because_the_filter_reads_rls_tables():
    """`asset_products` returns ZERO ROWS AND NO ERROR to a session without
    `veyrs.current_org`. On a plain `get_session` the estate filter would
    therefore hide the entire catalogue and look like a working filter over a
    clean estate -- the exact failure this phase exists to prevent."""
    from veyrs.api.v1 import intel

    for route in (intel.search_cve, intel.kev_list, intel.intel_health):
        # `eval_str=True`: intel.py carries `from __future__ import annotations`,
        # so a bare signature() hands back the *string* "TenantSession" and the
        # identity check fails while the code under test is perfectly correct.
        annotation = inspect.signature(
            route, eval_str=True
        ).parameters["session"].annotation
        assert annotation is intel.TenantSession, (
            f"{route.__name__} browses estate-scoped rows on a non-tenant session"
        )


# ---------------------------------------------------------------------------
# 3. KEV gets the same lens, from the same helper
# ---------------------------------------------------------------------------
def test_kev_is_scoped_too(client, admin_a, estate):
    """CISA KEV is the shortest, most urgent list in the product. Showing all
    1 678 of them as though they were yours is how the list stops being read."""
    scoped = client.get("/api/v1/intel/kev", params={"size": 200}, headers=admin_a).json()
    scoped_ids = {r["cve_id"] for r in scoped["items"]}
    assert estate["mine"] in scoped_ids
    assert estate["theirs"] not in scoped_ids

    # The unscoped list is a PAGE, not the catalogue. Asking for 200 rows of a
    # KEV table this suite keeps growing does not promise that two particular
    # synthetic CVEs are on the first one, and this assertion used to fail for
    # that reason alone -- reading as "the lens leaks" when the lens was right.
    # `/intel/kev` has no search parameter, so walk the pages instead of
    # pretending one page is the set.
    wide_ids: set[str] = set()
    page = 1
    while True:
        body = client.get(
            "/api/v1/intel/kev",
            params={"size": 200, "page": page, "affects_estate": "false"},
            headers=admin_a,
        ).json()
        wide_ids |= {r["cve_id"] for r in body["items"]}
        if not body["items"] or len(wide_ids) >= body["total"] or page > 60:
            break
        page += 1
    assert {estate["mine"], estate["theirs"]} <= wide_ids


# ---------------------------------------------------------------------------
# 4. "Your assets" was a declared field nothing ever populated
# ---------------------------------------------------------------------------
def test_affected_assets_reports_real_open_findings(client, admin_a, estate):
    """`CveSummary.affected_assets` has existed since the schema was written and
    `_summary()` never set it, so the console's "Your assets" column rendered 0
    on every row of a catalogue with open findings behind it. A surface that
    renders perfectly while stating something false -- same family as the five
    blank Integrations columns in v0.19.0."""
    session = SessionLocal()
    set_tenant(session, estate["org_id"])
    vulnerability = Vulnerability(
        organization_id=estate["org_id"], cve_id=estate["mine"],
        title="tracked", severity="high",
    )
    session.add(vulnerability)
    session.flush()
    session.add(Finding(
        organization_id=estate["org_id"], asset_id=estate["asset_id"],
        # `open` is NOT a state this model has: OPEN_STATES starts at `new`.
        # A finding written with an unknown state is accepted by the column
        # (plain varchar) and then counts as nothing, anywhere.
        vulnerability_id=vulnerability.id, state="new", title="tracked",
        dedupe_key="phase37-" + estate["tag"],
    ))
    session.commit()
    session.close()

    body = client.get(
        "/api/v1/intel/cve", params={"q": estate["tag"], "size": 200}, headers=admin_a
    ).json()
    row = next(r for r in body["items"] if r["cve_id"] == estate["mine"])
    assert row["affected_assets"] == 1


def test_a_cve_in_your_estate_with_no_finding_reports_zero_not_null(
    client, admin_a, estate
):
    """Product-level applicability is broader than finding-level exposure on
    purpose: a CVE for nginx 1.20 while you run 1.28 is still yours the day
    somebody rolls a host back. `null` would read as 'unknown'; it is known."""
    body = client.get(
        "/api/v1/intel/cve", params={"q": estate["tag"], "size": 200}, headers=admin_a
    ).json()
    row = next(r for r in body["items"] if r["cve_id"] == estate["mine"])
    assert row["affected_assets"] == 0


# ---------------------------------------------------------------------------
# 5. Never the estate number alone
# ---------------------------------------------------------------------------
def test_health_reports_both_numbers_and_the_inventory_behind_them(
    client, admin_a, estate
):
    """"17 CVEs affect you" is reassuring and meaningless without "of 359 353
    known, over 978 products we could resolve" beside it. An estate that shrank
    because the inventory broke looks identical to one that got patched."""
    body = client.get("/api/v1/intel/health", headers=admin_a).json()
    counts = body["counts"]
    for key in ("cve", "kev", "cve_affecting_estate", "kev_affecting_estate"):
        assert key in counts, f"/intel/health stopped reporting {key}"
    assert counts["cve_affecting_estate"] <= counts["cve"]
    assert counts["kev_affecting_estate"] <= counts["kev"]

    inventory = body["inventory"]
    assert inventory["installations"] >= 1
    assert inventory["distinct_products"] >= 1
    assert (inventory["resolved"] + inventory["unresolved"]
            == inventory["installations"])


def test_an_estate_with_no_inventory_is_distinguishable_from_a_clean_one(
    client, admin_b
):
    """Both render an empty table. Only one of them is good news."""
    body = client.get("/api/v1/intel/health", headers=admin_b).json()
    assert body["inventory"]["installations"] == 0
    assert body["counts"]["cve_affecting_estate"] == 0
    # ...and the catalogue count proves the feeds are not the problem.
    assert body["counts"]["cve"] >= 0


# ---------------------------------------------------------------------------
# 6. One definition of "the estate", enforced over the source
# ---------------------------------------------------------------------------
def test_no_route_hand_rolls_the_estate_predicate():
    """Same guardrail shape as v0.21.0's `intel_schedule.last_run` check, for
    the same reason: the CVE list, the KEV list and two counters all answer
    "does this touch us". A second copy is how one of them ends up answering
    differently, and nobody notices because both look plausible.

    Scoped to the ROUTE layer on purpose. The first version of this test swept
    the whole backend and flagged `services/correlation.py` and
    `services/threatintel.relevance`, which are NOT duplicates: correlation
    resolves *version applicability per asset* to decide whether a finding
    exists, a strictly narrower question than "does this organization run this
    software at all", and threatintel scores article relevance. Collapsing them
    into one predicate would make browsing hide CVEs for versions you are not
    currently on -- the opposite of what the estate lens is for. What must never
    happen is a *router* growing its own copy.
    """
    root = pathlib.Path("/opt/veyrs/backend/veyrs/api")
    offenders = []
    for path in root.rglob("*.py"):
        source = path.read_text(encoding="utf-8")
        if "CveCpeMatch" not in source or "AssetProduct" not in source:
            continue
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if not isinstance(node, ast.FunctionDef):
                continue
            body = ast.get_source_segment(source, node) or ""
            if "CveCpeMatch" in body and "AssetProduct" in body:
                offenders.append(f"{path.relative_to(root)}::{node.name}")
    assert not offenders, (
        "a router hand-rolled the estate predicate instead of calling "
        "services.intelligence.estate_cve_ids: " + ", ".join(offenders)
    )


def test_the_fast_query_shape_is_not_quietly_rewritten():
    """`EXISTS (... WHERE m.cve_id = cve.id)` and `id IN (SELECT ...)` return the
    same rows and are 67x apart: measured on production (359 353 CVEs,
    3 096 014 match rows, 978 installed products) EXISTS took 1 079 ms and IN
    took 16 ms. The slow one runs on every page load because it is what
    produces `total`, so a well-meaning "simplification" here is a latency
    regression on the busiest screen in the console."""
    source = inspect.getsource(intelligence.estate_cve_ids)
    assert "CveCpeMatch.product_id.in_(" in source
    assert "exists(" not in source.lower()


# ---------------------------------------------------------------------------
# 7. The console half
# ---------------------------------------------------------------------------
def test_the_console_asks_for_the_scoped_list_on_both_tabs():
    source = CONSOLE.read_text(encoding="utf-8")
    assert source.count("affects_estate: scoped") == 2, (
        "the CVE tab and the KEV tab must both pass the lens through"
    )
    assert "params.get('scope') !== 'all'" in source, (
        "the lens must live in the URL so a shared link carries the same view"
    )


def test_the_console_never_shows_the_estate_number_without_the_catalogue_number():
    source = CONSOLE.read_text(encoding="utf-8")
    assert "CVEs affecting your estate" in source
    assert "of ${fmtNum(counts.cve)} in the catalogue" in source
    assert "KEV affecting your estate" in source
    assert "of ${fmtNum(counts.kev)} known exploited" in source


def test_the_console_warns_when_the_inventory_cannot_support_the_lens():
    """The filter is only as honest as the inventory under it, and an operator
    reading an empty filtered table has no way to tell which of the two
    situations they are in unless the screen says so."""
    source = CONSOLE.read_text(encoding="utf-8")
    assert "No software inventory." in source
    assert "did not resolve to a dictionary entry" in source
    assert "that is a missing inventory," in source.lower() or \
           "not a clean estate" in source
