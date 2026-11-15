"""0.35.1: the "Affecting you" lens and the CVE page's affected-assets table.

Two defects found on environment A on 2026-11-01:

1. Heartbleed (CVE-2014-0160) was listed under the default "Your estate" lens
   with 0 assets. The estate lens matches by PRODUCT and never compares
   versions -- by design (phase 37) -- but it was the default, so the default
   list was ~89 % CVEs for versions nobody runs. The default is now the
   finding-backed lens; the product lens stays one click away.
2. CVE-2023-44487 had 5 open findings and the CVE page's "Affected assets"
   table was empty: the route returned `findings`, the console read `assets`.
"""
from __future__ import annotations

import datetime as dt
import pathlib
import uuid

import pytest

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Asset, AssetProduct, Cve, CveCpeMatch, Finding, KevEntry, Vulnerability
from veyrs.services import intelligence

CONSOLE = pathlib.Path("/opt/veyrs/frontend/console/app.js")


@pytest.fixture()
def world(org_a):
    """One product installed on two assets.

    `hit`  -- a CVE for that product with an open finding on BOTH assets (one of
              them internet-facing) and a closed finding on a third.
    `miss` -- a CVE for the same product with no finding: the version is outside
              the range. The Heartbleed shape.
    """
    org_id, slug, email = org_a
    tag = uuid.uuid4().hex[:10]
    session = SessionLocal()
    set_tenant(session, org_id)
    product = intelligence.upsert_product(session, f"v59-{tag}", f"lib59-{tag}")
    hit = f"CVE-2097-{int(tag, 16)}"
    miss = f"CVE-2096-{int(tag, 16)}"
    for cve_id in (hit, miss):
        session.add(Cve(
            id=cve_id, title=f"phase59 [{tag}]", description=f"phase59 [{tag}]",
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
            vulnerability_name="phase59", required_action="patch",
            date_added=dt.date(2026, 1, 1),
        ))

    assets = []
    for i, exposure in enumerate(("internet", "internal", "internal")):
        a = Asset(organization_id=org_id, name=f"h59-{i}-{tag}", hostname=f"h59-{i}-{tag}.lan",
                  asset_type="server", exposure=exposure, criticality="high")
        session.add(a)
        session.flush()
        session.add(AssetProduct(organization_id=org_id, asset_id=a.id,
                                 product_id=product.id, version="3.0.0", detected_by="test"))
        assets.append(a)

    # Two vulnerability rows for the same CVE (unique key includes internal_ref):
    # the old route read only `.first()` and could miss findings on the second.
    v1 = Vulnerability(organization_id=org_id, cve_id=hit, title="t", severity="high")
    v2 = Vulnerability(organization_id=org_id, cve_id=hit, title="t", severity="high",
                       internal_ref=f"second-{tag}")
    session.add_all([v1, v2])
    session.flush()
    for asset, vuln, state in ((assets[0], v1, "new"), (assets[1], v2, "triaged"),
                               (assets[2], v1, "closed")):
        session.add(Finding(organization_id=org_id, asset_id=asset.id, vulnerability_id=vuln.id,
                            state=state, title="t", dedupe_key=f"p59-{asset.name}"))
    session.commit()
    yield {"org_id": org_id, "tag": tag, "hit": hit, "miss": miss,
           "assets": [str(a.id) for a in assets]}
    session.close()


def _ids(body) -> set[str]:
    return {r["cve_id"] for r in body["items"]}


def test_exposure_lists_the_assets_the_console_renders(client, admin_a, world):
    body = client.get(f"/api/v1/intel/cve/{world['hit']}/exposure", headers=admin_a).json()
    assert body["affected_assets"] == 2
    assert body["internet_facing"] == 1
    got = {a["asset_id"]: a for a in body["assets"]}
    assert set(got) == set(world["assets"][:2]), "closed finding's asset must not be listed"
    row = got[world["assets"][0]]
    assert row["name"].startswith("h59-0-")
    assert row["hostname"].endswith(".lan")
    assert row["criticality"] == "high"
    assert row["exposure"] == "internet" and row["internet_exposed"] is True
    assert row["finding_id"] and row["state"] == "new"


def test_exposure_counts_every_vulnerability_row_for_the_cve(client, admin_a, world):
    body = client.get(f"/api/v1/intel/cve/{world['hit']}/exposure", headers=admin_a).json()
    assert world["assets"][1] in {a["asset_id"] for a in body["assets"]}, (
        "the finding on the second vulnerability row was dropped")


def test_exposure_for_a_cve_without_findings_is_empty_not_missing(client, admin_a, world):
    body = client.get(f"/api/v1/intel/cve/{world['miss']}/exposure", headers=admin_a).json()
    assert body["affected_assets"] == 0 and body["assets"] == [] and body["internet_facing"] == 0


def test_another_tenant_sees_no_assets(client, admin_b, world):
    body = client.get(f"/api/v1/intel/cve/{world['hit']}/exposure", headers=admin_b).json()
    assert body["assets"] == [] and body["affected_assets"] == 0


def test_exposed_lens_drops_the_product_only_match(client, admin_a, world):
    q = {"q": world["tag"], "size": 200}
    estate = client.get("/api/v1/intel/cve", params=q, headers=admin_a).json()
    exposed = client.get("/api/v1/intel/cve", params={**q, "exposed": "true"},
                         headers=admin_a).json()
    assert {world["hit"], world["miss"]} <= _ids(estate), "the product lens must not change"
    assert _ids(exposed) == {world["hit"]}
    assert exposed["total"] == 1, "the lens must narrow total, not only the page"


def test_exposed_lens_applies_to_kev(client, admin_a, world):
    body = client.get("/api/v1/intel/kev", params={"size": 200, "exposed": "true"},
                      headers=admin_a).json()
    ids = _ids(body)
    assert world["hit"] in ids and world["miss"] not in ids


def test_health_reports_the_exposed_counts_beside_the_estate_ones(client, admin_a, world):
    counts = client.get("/api/v1/intel/health", headers=admin_a).json()["counts"]
    assert counts["cve_exposed"] >= 1 and counts["kev_exposed"] >= 1
    assert counts["cve_exposed"] <= counts["cve_affecting_estate"] <= counts["cve"]
    assert counts["kev_exposed"] <= counts["kev_affecting_estate"] <= counts["kev"]


def test_the_console_defaults_to_the_exposed_lens_and_reads_assets():
    src = CONSOLE.read_text(encoding="utf-8")
    assert ": 'exposed';" in src, "the intel page must default to the 'exposed' lens"
    assert "exposed: scope === 'exposed'" in src, "the CVE/KEV lists must send exposed="
    assert "counts.cve_exposed" in src and "counts.kev_exposed" in src
    assert "exposure.assets" in src, "the CVE page must render the route's `assets` key"
