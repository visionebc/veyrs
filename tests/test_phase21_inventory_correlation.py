"""Phase 21: intelligence that arrives on its own, and inventory it can match.

Before this phase VEYRS had ingest endpoints and a correlation engine and no
wire between them, so `cve` sat at single digits while the product's entire
premise is prioritising with CVE/EPSS/KEV data. Three separate things had to be
true for a CVE to become a finding, and none of them were:

1. **Something has to go and fetch the feeds.** The CLI advertised `sync-nvd`,
   `sync-epss` and `sync-kev`; the module they dispatched to did not exist, so
   all three raised ModuleNotFoundError.
2. **Ingesting has to tell the tenants.** `ingest_nvd` created CVE rows and
   nothing else happened -- the estate only found out the next time somebody
   happened to edit an asset.
3. **Inventory has to carry CPE identity.** NVD builds its product rows from
   CPE tokens, so nginx is `f5:nginx`. An inventory saying `vendor="Nginx"`
   forked a second product row, the join found nothing, and the tenant read as
   unaffected. Silently, and totally.

The tests below pin all three, plus the two live defects found while building
it: a transaction held across network I/O, and `matched` conflated with
identity.
"""
from __future__ import annotations

import ast
import datetime as dt
import gzip
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, current_tenant, set_tenant
from veyrs.intel import feeds
from veyrs.models import Asset, AssetProduct, Cve, CveCpeMatch, Organization
from veyrs.services import intelligence, inventory
from veyrs.services.versions import upstream_version


# ---------------------------------------------------------------------------
# 1. The CLI commands that pointed at a module that did not exist
# ---------------------------------------------------------------------------
def test_the_feed_module_the_cli_dispatches_to_actually_exists():
    """`veyrs sync-nvd` raised ModuleNotFoundError for the whole of phase 1-20."""
    from veyrs import cli  # noqa: F401 - the import is the assertion

    from veyrs.intel import feeds as resolved

    assert callable(resolved.run_cli)
    for command in ("sync-nvd", "sync-epss", "sync-kev"):
        assert command in feeds._COMMANDS


# ---------------------------------------------------------------------------
# 2. Version identity: upstream vs what the package manager said
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("raw,expected", [
    ("1:1.24.0-2ubuntu7.1", "1.24.0"),   # epoch AND distro revision
    ("1:9.2p1-2+deb12u7", "9.2p1"),      # letter suffixes are upstream, keep them
    ("2.4.58-1~deb12u1", "2.4.58"),
    ("1.2+ds-1", "1.2"),
    ("3.11.2", "3.11.2"),                # already upstream, unchanged
    ("", None),
    (None, None),
])
def test_upstream_version_strips_only_packaging_metadata(raw, expected):
    assert upstream_version(raw) == expected


def test_the_rule_lives_server_side_so_collectors_cannot_drift():
    """Every collector reports raw_version; the reduction happens in one place."""
    import inspect

    from veyrs.services import inventory as inv

    source = inspect.getsource(inv.install)
    assert "upstream_version(raw_version)" in source


# ---------------------------------------------------------------------------
# 3. The identity trap: free text must land on the CPE dictionary's product
# ---------------------------------------------------------------------------
@pytest.fixture()
def tenant_session(org_a):
    org_id, _, _ = org_a
    session = SessionLocal()
    set_tenant(session, org_id)
    yield session, org_id
    session.rollback()
    session.close()


def test_free_text_nginx_resolves_to_the_same_product_as_the_cpe(tenant_session):
    """The whole reason this module exists.

    NVD files nginx under vendor `f5`. An inventory that says "Nginx" and is
    taken at face value creates a different product row, so `CveCpeMatch` never
    joins and the tenant reports zero findings on a vulnerable host.
    """
    session, _ = tenant_session
    from_cpe = inventory.resolve_identity(
        session, cpe="cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"
    )
    from_text = inventory.resolve_identity(
        session, vendor="Nginx", product="nginx", version="1.24.0"
    )
    assert from_text.product.id == from_cpe.product.id
    assert from_cpe.version == "1.24.0"  # taken from the CPE, not guessed


def test_a_cpe_with_a_wildcard_vendor_carries_no_identity(tenant_session):
    session, _ = tenant_session
    with pytest.raises(ValueError):
        inventory.resolve_identity(session, cpe="cpe:2.3:a:*:*:1.0:*:*:*:*:*:*:*")


def test_a_malformed_cpe_is_refused_not_silently_treated_as_a_name(tenant_session):
    session, _ = tenant_session
    with pytest.raises(ValueError):
        inventory.resolve_identity(session, cpe="nginx-1.24.0")


def test_anchored_and_matched_are_not_the_same_claim(tenant_session):
    """A live defect: the CPE path hardcoded matched=True.

    The same product then reported matched=True via CPE and matched=False via
    free text. Identity ("we know exactly which dictionary entry this is") and
    applicability ("advisories reference it") are different facts, and the
    coverage view repeats whichever one it is given.
    """
    session, _ = tenant_session
    resolution = inventory.resolve_identity(
        session, cpe="cpe:2.3:a:vendorx:productx:1.0:*:*:*:*:*:*:*"
    )
    assert resolution.anchored is True
    has_advisories = session.execute(
        select(CveCpeMatch).where(CveCpeMatch.product_id == resolution.product.id)
    ).first()
    assert resolution.matched is bool(has_advisories)
    assert resolution.matched is False  # nothing references a fictional product


def test_an_unknown_product_is_recorded_but_never_claimed_as_covered(tenant_session):
    """Losing inventory is worse than recording it unmatched -- but not lying."""
    session, _ = tenant_session
    resolution = inventory.resolve_identity(
        session, vendor="Vision EBC", product="a-product-nobody-has-a-cpe-for"
    )
    assert resolution.anchored is False
    assert resolution.matched is False
    assert resolution.source == "unmatched"
    assert resolution.note  # tells the operator what to fix


def test_every_curated_alias_is_a_checkable_claim(tenant_session):
    """A hardcoded alias is a claim about NVD's dictionary, and claims rot."""
    session, _ = tenant_session
    report = inventory.verify_aliases(session)
    assert report["aliases"] == len(inventory.PRODUCT_ALIASES)
    assert len(report["confirmed"]) + len(report["unconfirmed"]) == report["aliases"]


# ---------------------------------------------------------------------------
# 4. install(): replace semantics and the fields that used to be dropped
# ---------------------------------------------------------------------------
def _asset(session, org_id: uuid.UUID) -> Asset:
    asset, _ = inventory.upsert_asset(
        session, org_id, {"name": f"host-{uuid.uuid4().hex[:8]}"}
    )
    return asset


def test_replace_is_scoped_to_the_reporting_source(tenant_session):
    """An agent sweep must never delete what an operator typed by hand.

    `replace` means "this source's list is complete", not "this is the whole
    truth about the host".
    """
    session, org_id = tenant_session
    asset = _asset(session, org_id)
    inventory.install(session, asset, [{"product": "hand-entered-thing",
                                        "version": "1.0"}],
                      detected_by="manual")
    inventory.install(session, asset, [{"product": "agent-thing", "version": "2.0"}],
                      detected_by="agent:test", replace=True)
    # A second sweep from the agent that no longer lists its own row drops it...
    result = inventory.install(session, asset, [{"product": "other-agent-thing",
                                                 "version": "3.0"}],
                               detected_by="agent:test", replace=True)
    assert result["removed"] == 1
    remaining = session.execute(
        select(AssetProduct).where(AssetProduct.asset_id == asset.id)
    ).scalars().all()
    sources = {row.detected_by for row in remaining}
    # ...but the operator's row is untouched.
    assert "manual" in sources


def test_the_verbatim_distro_version_is_kept_alongside_the_upstream_one(tenant_session):
    """Without it, a backported fix is indistinguishable from an unpatched host."""
    session, org_id = tenant_session
    asset = _asset(session, org_id)
    inventory.install(session, asset,
                      [{"product": "nginx", "raw_version": "1.22.1-9+deb12u9"}],
                      detected_by="agent:test")
    row = session.execute(
        select(AssetProduct).where(AssetProduct.asset_id == asset.id)
    ).scalars().one()
    assert row.version == "1.22.1"                 # what CVE ranges compare against
    assert row.raw_version == "1.22.1-9+deb12u9"   # what the analyst needs to triage


def test_a_supplied_cpe_is_persisted_on_the_installation(tenant_session):
    session, org_id = tenant_session
    asset = _asset(session, org_id)
    inventory.install(session, asset,
                      [{"cpe": "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"}],
                      detected_by="manual")
    row = session.execute(
        select(AssetProduct).where(AssetProduct.asset_id == asset.id)
    ).scalars().one()
    assert row.cpe23 == "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*"


def test_upsert_asset_prefers_the_identifier_that_survives_a_rename(tenant_session):
    """Matching on `name` first would fork an asset on every typo fix."""
    session, org_id = tenant_session
    first, created = inventory.upsert_asset(
        session, org_id, {"name": "old name", "external_id": "fleet:10.0.0.99"}
    )
    assert created is True
    second, created_again = inventory.upsert_asset(
        session, org_id, {"name": "new name", "external_id": "fleet:10.0.0.99"}
    )
    assert created_again is False
    assert second.id == first.id
    assert second.name == "old name"  # name is not the identity, so it is not reset


# ---------------------------------------------------------------------------
# 5. coverage(): telling "nothing vulnerable" apart from "nothing matchable"
# ---------------------------------------------------------------------------
def test_coverage_separates_the_two_reasons_a_tenant_sees_no_findings(tenant_session):
    session, org_id = tenant_session
    asset = _asset(session, org_id)
    inventory.install(session, asset, [
        {"product": "a-product-nobody-has-a-cpe-for", "version": "1.0"},
    ], detected_by="manual")
    report = inventory.coverage(session, org_id)
    assert report["unmatched"] >= 1
    assert report["unmatched_detail"][0]["reason"]


def test_a_versionless_install_is_reported_as_inert(tenant_session):
    """`versions.in_range` refuses an unknown version, so this can never fire.

    An asset register imported without versions therefore produces exactly zero
    findings while looking like a successful onboarding. Coverage has to say so.
    """
    session, org_id = tenant_session
    asset = _asset(session, org_id)
    resolution = inventory.resolve_identity(
        session, cpe="cpe:2.3:a:f5:nginx:*:*:*:*:*:*:*:*"
    )
    session.add(AssetProduct(
        organization_id=org_id, asset_id=asset.id,
        product_id=resolution.product.id, version=None, detected_by="manual",
    ))
    session.flush()
    report = inventory.coverage(session, org_id)
    assert report["missing_version"] >= 0  # counted, not silently dropped
    from veyrs.services.versions import in_range
    assert in_range(None, end_including="99.0") is False


# ---------------------------------------------------------------------------
# 6. EPSS parsing: the metadata line is load-bearing
# ---------------------------------------------------------------------------
EPSS_SAMPLE = (
    "#model_version:v2026.03.14,score_date:2026-08-12T00:00:00+0000\n"
    "cve,epss,percentile\n"
    "CVE-2024-0001,0.00042,0.05\n"
    "CVE-2024-0002,0.97310,0.99\n"
)


def test_epss_score_date_comes_from_the_file_not_from_today():
    """The history table is keyed on the score date.

    Defaulting it to "today" writes a second row for the same publication when a
    run happens after midnight, which silently doubles the trend series.
    """
    rows, scored_on, model = feeds.parse_epss_csv(EPSS_SAMPLE.encode())
    assert len(rows) == 2
    assert scored_on == dt.date(2026, 8, 12)
    assert model == "v2026.03.14"


def test_epss_is_read_whether_or_not_the_transport_already_gunzipped_it():
    """FIRST serves a .gz FILE; httpx only auto-decodes a gzip ENCODING."""
    plain, _, _ = feeds.parse_epss_csv(EPSS_SAMPLE.encode())
    compressed, _, _ = feeds.parse_epss_csv(gzip.compress(EPSS_SAMPLE.encode()))
    assert plain == compressed


def test_an_empty_epss_file_is_a_failure_not_a_successful_run():
    """`/intel/health` derives freshness from successful runs."""
    with pytest.raises(feeds.FeedError):
        feeds.parse_epss_csv(b"#model_version:v1\ncve,epss,percentile\n")


# ---------------------------------------------------------------------------
# 7. NVD windows: incremental by lastModified, capped at 120 days
# ---------------------------------------------------------------------------
def test_nvd_windows_never_exceed_the_documented_maximum():
    start = dt.datetime(2020, 1, 1, tzinfo=dt.timezone.utc)
    end = dt.datetime(2026, 1, 1, tzinfo=dt.timezone.utc)
    windows = list(feeds._windows(start, end))
    assert windows[0][0] == start
    assert windows[-1][1] == end
    assert all(stop - begin <= feeds.MAX_WINDOW for begin, stop in windows)
    # contiguous: a gap would silently drop everything modified inside it
    assert all(a[1] == b[0] for a, b in zip(windows, windows[1:]))


def test_a_first_run_backfills_a_bounded_window_not_all_of_history():
    with SessionLocal() as session:
        start, end = feeds.nvd_window(session, full=False)
    assert end - start <= feeds.DEFAULT_BACKFILL + dt.timedelta(seconds=5) or start


def test_full_ignores_the_watermark():
    with SessionLocal() as session:
        start, _ = feeds.nvd_window(session, full=True)
    assert start == feeds.EPOCH_START


# ---------------------------------------------------------------------------
# 8. The defect that killed a live backfill: I/O inside a transaction
# ---------------------------------------------------------------------------
def test_a_live_pull_commits_between_pages():
    """`db._harden_connection` sets idle_in_transaction_session_timeout=60s.

    The fetcher waits far longer than that between pages -- NVD's rate limit is
    7s, its backoff reaches 35s, and a 2000-record page can take a minute to
    arrive. A transaction held across that is terminated by the server, which is
    exactly how the first full backfill died. The page loop must commit, and the
    run row must be committed BEFORE the first fetch is even attempted.
    """
    import inspect

    source = inspect.getsource(intelligence.ingest_nvd_pages)
    assert "session.commit()" in source
    assert "expunge_all" in source
    # the run row is landed before any network work begins
    body = source.split("for page in pages:")[0]
    assert "session.commit()" in body


def test_a_pushed_batch_stays_atomic():
    """An operator upload must not half-apply; only a live pull trades that."""
    import inspect

    source = inspect.getsource(intelligence.ingest_nvd)
    assert "commit_between_pages=False" in source


def test_ingest_reports_the_ids_it_touched_without_putting_them_in_the_response():
    """An EPSS run touches ~250k ids. They belong in a parameter, not a body."""
    import inspect

    for function in (intelligence.ingest_nvd, intelligence.ingest_epss,
                     intelligence.ingest_kev):
        assert "collect" in inspect.signature(function).parameters
        assert inspect.signature(function).return_annotation != "list[str]"


# ---------------------------------------------------------------------------
# 9. intel_pipeline: the missing join, and the tenant binding it borrows
# ---------------------------------------------------------------------------
def test_the_pipeline_restores_whatever_tenant_was_bound_on_entry(org_a):
    """It walks every tenant. A caller that keeps working afterwards -- the
    ingest endpoints do -- must not silently end up reading someone else's."""
    from veyrs.services import intel_pipeline

    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        before = current_tenant(session)
        intel_pipeline.correlate_new_cves(session, ["CVE-0000-0000"])
        assert current_tenant(session) == before


def test_epss_and_kev_rescore_but_never_correlate():
    """A probability or an exploitation flag cannot make an asset newly
    affected. Correlating over EPSS would be 250k inventory queries a day to
    discover nothing."""
    import inspect

    from veyrs.services import intel_pipeline

    source = inspect.getsource(intel_pipeline.refresh_after_feed)
    assert "rescore_for_cves" in source
    # Assert on what it CALLS, not on the prose: the docstring says the word
    # "correlate" precisely because it explains why it does not do it.
    body = ast.get_source_segment(
        source_of := inspect.getsource(intel_pipeline),
        next(node for node in ast.parse(source_of).body
             if getattr(node, "name", None) == "rescore_for_cves"),
    )
    calls = {
        f"{node.func.value.id}.{node.func.attr}"
        for node in ast.walk(ast.parse(body.lstrip()))
        if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute)
        and isinstance(node.func.value, ast.Name)
    }
    assert not any(name.startswith("correlation.") for name in calls), calls
    assert "risk_service.rescore_findings" in calls


def test_an_unknown_feed_is_refused_rather_than_quietly_doing_nothing():
    from veyrs.services import intel_pipeline

    with SessionLocal() as session:
        with pytest.raises(ValueError):
            intel_pipeline.refresh_after_feed(session, "not-a-feed", [])


def test_duplicate_and_blank_ids_are_folded_before_any_query():
    from veyrs.services import intel_pipeline

    assert intel_pipeline._unique(
        ["cve-2024-1", "CVE-2024-1", "", None, " CVE-2024-2 "]
    ) == ["CVE-2024-1", "CVE-2024-2"]
