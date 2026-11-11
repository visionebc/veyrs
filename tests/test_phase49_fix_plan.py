"""Phase 49 - the fix plan: which version fixes this, and how hard is getting there.

Every product in this file is fictional ("Acme Widget"); every version number
is invented for the test. The properties pinned here are the feature:

* the step from installed to target is classified patch / minor / major /
  unknown, and the classification is never guessed for a non-numeric version;
* the best single target is the LOWEST version that fixes ALL findings with a
  known fix -- and a candidate that falls inside another CVE's vulnerable
  range is rejected, because "upgrade to 1.2.5" that leaves you exposed to the
  next CVE is not a plan;
* `version_end_including` yields "a version after X", never an invented
  candidate; advisory fixed versions are used only when they name THIS product;
* findings with no known fix are listed, and counted in the coverage line;
* operator rules produce ordered hops, and a backwards rule or an endless
  chain cannot loop the request;
* team scope and tenant isolation hold on both plan routes and on the rules.
"""
from __future__ import annotations

import uuid

import pytest

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    Asset, AssetProduct, Cve, CveCpeMatch, Finding, Product, Vendor, Vulnerability,
)
from veyrs.models.tenancy import Team
from veyrs.models.upgrade import UpgradePathRule
from veyrs.services import correlation, fix_plan
from veyrs.services.versions import normalize_name, version_key

from conftest import login

PASSWORD = "Str0ng-Passw0rd!x"


def _headers(client, email, slug):
    return {"Authorization": f"Bearer {login(client, email, slug, PASSWORD)['access_token']}"}


# ---------------------------------------------------------------------------
# Builders. Vendors/products/CVEs are GLOBAL tables, so every name is unique
# per test: two tests sharing "Acme" would see each other's ranges.
# ---------------------------------------------------------------------------
def _product(session, vendor_name: str | None = None, product_name: str = "Widget"):
    vendor_name = vendor_name or f"Acme{uuid.uuid4().hex[:8]}"
    vendor = Vendor(name=vendor_name, normalized_name=normalize_name(vendor_name))
    session.add(vendor)
    session.flush()
    product = Product(vendor_id=vendor.id, name=product_name,
                      normalized_name=normalize_name(product_name))
    session.add(product)
    session.flush()
    return vendor, product


def _cve(session, product, *, ranges=(), fixed_versions=None) -> str:
    cve_id = f"CVE-2049-{uuid.uuid4().int % 9_000_000 + 1_000_000}"
    session.add(Cve(id=cve_id, source="test", title=cve_id,
                    fixed_versions=list(fixed_versions or [])))
    session.flush()
    vendor = session.get(Vendor, product.vendor_id)
    for bounds in ranges:
        bounds = dict(bounds)
        exact = bounds.pop("exact", "*")
        session.add(CveCpeMatch(
            cve_id=cve_id, product_id=product.id, vulnerable=True,
            cpe23=f"cpe:2.3:a:{vendor.normalized_name}:{product.normalized_name}:{exact}:*:*:*:*:*:*:*",
            **bounds,
        ))
    session.flush()
    return cve_id


def _install(session, org_id, product, version, *, team_id=None, asset=None):
    if asset is None:
        asset = Asset(organization_id=org_id, name=f"widget-{uuid.uuid4().hex[:8]}",
                      team_id=team_id)
        session.add(asset)
        session.flush()
    installation = AssetProduct(organization_id=org_id, asset_id=asset.id,
                                product_id=product.id, version=version,
                                version_key=version_key(version))
    session.add(installation)
    session.flush()
    return asset, installation


def _finding(session, org_id, asset, installation, cve_id, *, state="new",
             assigned_team_id=None, risk=50.0):
    vulnerability = Vulnerability(organization_id=org_id, cve_id=cve_id,
                                  title=f"{cve_id or 'internal'} vulnerability",
                                  internal_ref=None if cve_id else uuid.uuid4().hex[:12])
    session.add(vulnerability)
    session.flush()
    finding = Finding(
        organization_id=org_id, asset_id=asset.id,
        asset_product_id=installation.id if installation else None,
        vulnerability_id=vulnerability.id, state=state, dedupe_key=uuid.uuid4().hex,
        title=f"{cve_id or 'internal'} on {asset.name}", severity="high",
        risk_score=risk, assigned_team_id=assigned_team_id,
    )
    session.add(finding)
    session.flush()
    return finding


@pytest.fixture()
def tenant(org_a):
    org_id, _, _ = org_a
    session = SessionLocal()
    set_tenant(session, org_id)
    yield session, org_id
    session.rollback()
    session.close()


def _plan(session, org_id, installation, **kw):
    return fix_plan.plan_for_installation(session, org_id, installation, **kw)


def _scenario(session, org_id, installed, cve_specs):
    """One installation + one open finding per CVE spec. Returns (inst, findings, product)."""
    _, product = _product(session)
    asset, installation = _install(session, org_id, product, installed)
    findings = []
    for spec in cve_specs:
        cve_id = _cve(session, product, **spec)
        findings.append(_finding(session, org_id, asset, installation, cve_id))
    return installation, findings, product


# ---------------------------------------------------------------------------
# 1. Step classification
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("installed,target,expected", [
    ("1.2.3", "1.2.9", "patch"),
    ("1.2.3", "1.2.3.1", "patch"),
    ("1.2.3", "1.4.0", "minor"),
    ("1.2", "1.3", "minor"),
    ("1.2.3", "2.0.1", "major"),
    ("v1.2.3", "1.2.4", "patch"),         # the leading v is presentation
    ("r2024a", "r2025b", "unknown"),      # no numeric branch to compare
    ("1.2.3", None, "unknown"),
])
def test_the_step_is_classified_from_the_branch(installed, target, expected):
    assert fix_plan.classify_step(installed, target) == expected


@pytest.mark.parametrize("ranges,installed,target,step", [
    ([{"version_start_including": "1.0", "version_end_excluding": "1.2.7"}], "1.2.3", "1.2.7", "patch"),
    ([{"version_start_including": "1.0", "version_end_excluding": "1.5.0"}], "1.2.3", "1.5.0", "minor"),
    ([{"version_start_including": "1.0", "version_end_excluding": "3.0.2"}], "1.2.3", "3.0.2", "major"),
])
def test_the_plan_reports_the_step_of_its_best_target(tenant, ranges, installed, target, step):
    session, org_id = tenant
    installation, _, _ = _scenario(session, org_id, installed, [{"ranges": ranges}])
    best = _plan(session, org_id, installation)["best_single_target"]
    assert best["version"] == target
    assert best["step"] == step


# ---------------------------------------------------------------------------
# 2. Best single target
# ---------------------------------------------------------------------------
def test_the_best_target_is_the_lowest_that_fixes_all(tenant):
    session, org_id = tenant
    installation, (f1, f2, f3), _ = _scenario(session, org_id, "1.2.3", [
        {"ranges": [{"version_start_including": "1.0", "version_end_excluding": "1.2.5"}]},
        {"ranges": [{"version_start_including": "1.0", "version_end_excluding": "1.4.0"}]},
        {"ranges": [{"version_start_including": "1.0", "version_end_excluding": "2.0.1"}]},
    ])
    plan = _plan(session, org_id, installation)

    by_version = {c["version"]: c for c in plan["candidates"]}
    assert list(by_version) == ["1.2.5", "1.4.0", "2.0.1"]       # ascending
    assert set(by_version["1.2.5"]["fixes"]) == {str(f1.id)}
    assert set(by_version["1.4.0"]["fixes"]) == {str(f1.id), str(f2.id)}
    assert by_version["2.0.1"]["fixes_all"] is True
    assert [c["version"] for c in plan["candidates"] if c["fixes_all"]] == ["2.0.1"]

    best = plan["best_single_target"]
    assert best["version"] == "2.0.1" and best["step"] == "major"
    assert set(best["fixes"]) == {str(f1.id), str(f2.id), str(f3.id)}

    # The branch answer is reported separately, and says it is partial.
    nearest = plan["nearest_on_branch"]
    assert nearest["version"] == "1.2.5" and nearest["step"] == "patch"
    assert nearest["fixes_all"] is False


def test_of_several_complete_targets_the_lowest_wins(tenant):
    """1.2.7 and 3.0.2 both close everything; a maintenance window wants 1.2.7."""
    session, org_id = tenant
    installation, _, _ = _scenario(session, org_id, "1.2.3", [
        {"ranges": [{"version_start_including": "1.0", "version_end_excluding": "1.2.5"}]},
        {"ranges": [{"version_start_including": "1.0", "version_end_excluding": "1.2.7"}]},
        # a later branch's own fix: newer, also complete, and the wrong answer
        {"ranges": [{"version_start_including": "3.0", "version_end_excluding": "3.0.2"}]},
    ])
    plan = _plan(session, org_id, installation)
    assert [c["version"] for c in plan["candidates"] if c["fixes_all"]] == ["1.2.7", "3.0.2"]
    assert plan["best_single_target"]["version"] == "1.2.7"
    assert plan["best_single_target"]["step"] == "patch"


def test_a_candidate_inside_another_cves_range_is_rejected(tenant):
    """1.2.5 fixes CVE-1 and walks straight into CVE-2. Not a fix."""
    session, org_id = tenant
    installation, (f1, f2), _ = _scenario(session, org_id, "1.2.4", [
        {"ranges": [{"version_start_including": "1.0", "version_end_excluding": "1.2.5"}]},
        {"ranges": [{"version_start_including": "1.2.4", "version_end_excluding": "1.3.0"}]},
    ])
    plan = _plan(session, org_id, installation)
    by_version = {c["version"]: c for c in plan["candidates"]}
    assert by_version["1.2.5"]["fixes"] == [str(f1.id)]
    assert by_version["1.2.5"]["fixes_all"] is False
    assert plan["best_single_target"]["version"] == "1.3.0"
    assert plan["best_single_target"]["step"] == "minor"


def test_no_single_target_is_named_when_none_fixes_everything(tenant):
    """Two branches each fixed, but the fixes exclude each other."""
    session, org_id = tenant
    installation, _, _ = _scenario(session, org_id, "1.2.3", [
        # every version from 1.0 on except exactly the 1.2.x line after 1.2.5
        {"ranges": [{"version_start_including": "1.0", "version_end_excluding": "1.2.5"},
                    {"version_start_including": "1.3.0"}]},
        {"ranges": [{"version_start_including": "1.0", "version_end_excluding": "1.3.0"}]},
    ])
    plan = _plan(session, org_id, installation)
    assert plan["best_single_target"] is None
    assert "no single version" in plan["best_single_target_reason"]


# ---------------------------------------------------------------------------
# 3. What counts as a known fix
# ---------------------------------------------------------------------------
def test_an_including_end_produces_no_invented_candidate(tenant):
    session, org_id = tenant
    installation, (after_finding,), _ = _scenario(session, org_id, "1.2.3", [
        {"ranges": [{"version_start_including": "1.0", "version_end_including": "1.2.9"}]},
    ])
    plan = _plan(session, org_id, installation)
    assert plan["candidates"] == []
    assert plan["best_single_target"] is None
    row = plan["findings"][0]
    assert row["fix_status"] == "after"
    assert row["after_versions"] == ["1.2.9"]
    assert row["fixed_versions"] == []
    assert [r["finding_id"] for r in plan["no_fix_known"]] == [str(after_finding.id)]


def test_an_including_end_next_to_a_known_fix_adds_nothing_but_is_reported(tenant):
    session, org_id = tenant
    installation, (after_f, known_f), _ = _scenario(session, org_id, "1.2.3", [
        {"ranges": [{"version_start_including": "1.0", "version_end_including": "1.2.9"}]},
        {"ranges": [{"version_start_including": "1.0", "version_end_excluding": "1.3.0"}]},
    ])
    plan = _plan(session, org_id, installation)
    assert [c["version"] for c in plan["candidates"]] == ["1.3.0"]
    only = plan["candidates"][0]
    assert only["fixes"] == [str(known_f.id)]
    # 1.3.0 is past the published range of the "after" finding, and the plan
    # says so -- without crediting it as a known fix.
    assert only["outside_published_range_of"] == [str(after_f.id)]
    assert plan["coverage"]["with_known_fix"] == 1


def test_advisory_fixed_versions_are_used_for_this_product_only(tenant):
    session, org_id = tenant
    vendor, product = _product(session)
    asset, installation = _install(session, org_id, product, "1.2.3")
    cve_id = _cve(session, product, fixed_versions=[
        {"vendor": vendor.name, "product": "Widget", "versions": ["1.2.3"], "fixed": ["1.2.8"]},
        {"vendor": vendor.name, "product": "Other Gadget", "fixed": ["1.2.6"]},
        "1.2.5",                                  # names no product: never a candidate
    ])
    finding = _finding(session, org_id, asset, installation, cve_id)
    plan = _plan(session, org_id, installation)

    assert [c["version"] for c in plan["candidates"]] == ["1.2.8"]
    assert plan["best_single_target"]["version"] == "1.2.8"
    row = plan["findings"][0]
    assert row["finding_id"] == str(finding.id)
    assert row["fix_status"] == "known"
    assert row["advisory_fixed_versions"] == ["1.2.8"]
    assert row["unattributed_advisory_versions"] == ["1.2.5"]
    assert plan["coverage"]["advisories"] == 1


def test_an_advisory_cpe_identifies_the_product_too(tenant):
    session, org_id = tenant
    vendor, product = _product(session)
    asset, installation = _install(session, org_id, product, "1.2.3")
    cpe = f"cpe:2.3:a:{vendor.normalized_name}:widget:*:*:*:*:*:*:*:*"
    cve_id = _cve(session, product, fixed_versions=[{"cpe23": cpe, "fixed": "1.2.4"}])
    _finding(session, org_id, asset, installation, cve_id)
    assert _plan(session, org_id, installation)["best_single_target"]["version"] == "1.2.4"


def test_advisory_silence_on_a_branch_is_not_a_fix(tenant):
    """Fixed in 1.2.9 and 1.4.2: 1.3.0 is a branch the advisory never mentions."""
    session, org_id = tenant
    vendor, product = _product(session)
    asset, installation = _install(session, org_id, product, "1.2.3")
    ranged = _cve(session, product, ranges=[
        {"version_start_including": "1.0", "version_end_excluding": "1.3.0"}])
    advised = _cve(session, product, fixed_versions=[
        {"vendor": vendor.name, "product": product.name, "fixed": ["1.2.9", "1.4.2"]}])
    f_ranged = _finding(session, org_id, asset, installation, ranged)
    f_advised = _finding(session, org_id, asset, installation, advised)
    plan = _plan(session, org_id, installation)
    by_version = {c["version"]: c for c in plan["candidates"]}
    assert by_version["1.3.0"]["fixes"] == [str(f_ranged.id)]
    assert by_version["1.2.9"]["fixes"] == [str(f_advised.id)]   # inside the range
    assert plan["best_single_target"]["version"] == "1.4.2"


def test_findings_with_no_known_fix_are_listed_and_counted(tenant):
    session, org_id = tenant
    _, product = _product(session)
    asset, installation = _install(session, org_id, product, "1.2.3")
    known = _finding(session, org_id, asset, installation, _cve(session, product, ranges=[
        {"version_start_including": "1.0", "version_end_excluding": "1.2.4"}]))
    unbounded = _finding(session, org_id, asset, installation, _cve(session, product, ranges=[
        {"version_start_including": "1.0"}]))
    no_data = _finding(session, org_id, asset, installation, _cve(session, product))
    internal = _finding(session, org_id, asset, installation, None)
    _finding(session, org_id, asset, installation,
             _cve(session, product, ranges=[{"version_end_excluding": "9.0"}]),
             state="closed")                                     # not open: not in the plan

    plan = _plan(session, org_id, installation)
    listed = {r["finding_id"]: r for r in plan["no_fix_known"]}
    assert set(listed) == {str(unbounded.id), str(no_data.id), str(internal.id)}
    assert all(r["fix_status"] == "unknown" for r in listed.values())
    assert "not linked to a CVE" in listed[str(internal.id)]["note"]
    assert plan["best_single_target"]["version"] == "1.2.4"
    assert plan["best_single_target"]["fixes"] == [str(known.id)]
    assert plan["coverage"]["statement"] == (
        "1 of 4 open findings have a known fixed version; "
        "computed from 2 CPE ranges and 0 advisories")
    assert plan["computed_at"]


def test_an_unknown_installed_version_names_no_target(tenant):
    session, org_id = tenant
    installation, _, _ = _scenario(session, org_id, None, [
        {"ranges": [{"version_start_including": "1.0", "version_end_excluding": "1.2.4"}]}])
    plan = _plan(session, org_id, installation)
    assert plan["best_single_target"] is None
    assert "not recorded" in plan["best_single_target_reason"]
    assert plan["candidates"] == []


def test_the_plan_and_the_finding_cannot_disagree(tenant):
    """Upgrading to the best target must make correlation stop matching."""
    session, org_id = tenant
    installation, _, product = _scenario(session, org_id, "1.2.3", [
        {"ranges": [{"version_start_including": "1.0", "version_end_excluding": "1.2.5"}]},
        {"ranges": [{"version_start_including": "1.2.0", "version_end_excluding": "1.3.1"},
                    {"version_start_including": "2.0", "version_end_excluding": "2.0.4"}]},
    ])
    plan = _plan(session, org_id, installation)
    target = plan["best_single_target"]["version"]
    cve_ids = {r["cve_id"] for r in plan["findings"]}
    installation.version = target
    session.flush()
    for cve_id in cve_ids:
        hits = correlation.affected_installations(session, org_id, session.get(Cve, cve_id))
        assert installation.id not in {i.id for _, i, _ in hits}


# ---------------------------------------------------------------------------
# 4. Upgrade paths
# ---------------------------------------------------------------------------
def _rule(**kw) -> UpgradePathRule:
    kw.setdefault("id", uuid.uuid4())
    kw.setdefault("vendor", "Acme")
    kw.setdefault("product", "Widget")
    kw.setdefault("vendor_key", "acme")
    kw.setdefault("product_key", "widget")
    return UpgradePathRule(**kw)


def test_rules_produce_ordered_hops_with_their_prerequisites():
    rules = [
        _rule(from_start_including="1.9.0", from_end_excluding="3.0", via_version="2.5.0",
              prerequisite="Migrate the database", source_url="https://example.com/b"),
        _rule(from_start_including="1.0", from_end_excluding="2.0", via_version="1.9.0",
              prerequisite="Back up the configuration", source_url="https://example.com/a"),
        _rule(from_start_including="2.5.0", prerequisite="Renew the licence"),
    ]
    path = fix_plan.upgrade_path("1.2.3", "3.1.0", rules)
    assert [(h["from"], h["to"]) for h in path["hops"]] == [
        ("1.2.3", "1.9.0"), ("1.9.0", "2.5.0"), ("2.5.0", "3.1.0")]
    assert path["path_required"] is True and path["complete"] is True
    assert [p["note"] for p in path["hops"][0]["prerequisites"]] == ["Back up the configuration"]
    assert path["hops"][0]["required_by"][0]["source_url"] == "https://example.com/a"
    assert [p["note"] for p in path["hops"][1]["prerequisites"]] == ["Migrate the database"]
    assert [p["note"] for p in path["hops"][2]["prerequisites"]] == ["Renew the licence"]
    assert [h["step"] for h in path["hops"]] == ["minor", "major", "major"]


def test_no_rule_means_one_direct_hop():
    path = fix_plan.upgrade_path("1.2.3", "1.2.9", [])
    assert [(h["from"], h["to"]) for h in path["hops"]] == [("1.2.3", "1.2.9")]
    assert path["path_required"] is False


def test_a_backwards_rule_is_ignored_and_reported_not_followed():
    """Rule B would send 2.0 back to 1.5, and rule A would send 1.5 to 2.0 again."""
    rules = [
        _rule(from_start_including="1.0", from_end_excluding="2.0", via_version="2.0"),
        _rule(from_end_excluding="3.0", via_version="1.5"),
    ]
    path = fix_plan.upgrade_path("1.2", "3.1", rules)
    assert [(h["from"], h["to"]) for h in path["hops"]] == [
        ("1.2", "1.5"), ("1.5", "2.0"), ("2.0", "3.1")]
    assert path["complete"] is True
    assert [r["via_version"] for r in path["ignored_rules"]] == ["1.5"]
    assert "backwards" in path["ignored_rules"][0]["reason"]


def test_an_endless_chain_is_capped_and_reported():
    rules = [_rule(from_start_including=f"1.{k}", from_end_excluding=f"1.{k + 1}",
                   via_version=f"1.{k + 1}") for k in range(fix_plan.MAX_HOPS + 10)]
    path = fix_plan.upgrade_path("1.0", "2.0", rules)
    assert len(path["hops"]) == fix_plan.MAX_HOPS
    assert path["complete"] is False
    assert path["warnings"] and "without reaching 2.0" in path["warnings"][0]


# ---------------------------------------------------------------------------
# 5. API: plans, scope, tenancy, rules
# ---------------------------------------------------------------------------
@pytest.fixture()
def api_estate(client, admin_a, org_a):
    """Two teams; each owns one Acme Widget install with a fixable finding."""
    org_id, slug, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        net = Team(organization_id=org_id, name="Net", slug=f"net-{uuid.uuid4().hex[:6]}")
        app = Team(organization_id=org_id, name="App", slug=f"app-{uuid.uuid4().hex[:6]}")
        session.add_all([net, app])
        session.flush()
        vendor, product = _product(session)
        made = {"vendor": vendor.name, "product": product.name}
        for label, team in (("net", net), ("app", app)):
            asset, inst = _install(session, org_id, product, "1.2.3", team_id=team.id)
            cve_id = _cve(session, product, ranges=[
                {"version_start_including": "1.0", "version_end_excluding": "2.1.0"}])
            finding = _finding(session, org_id, asset, inst, cve_id)
            made[label] = {"asset": str(asset.id), "finding": str(finding.id),
                           "installation": inst}
        # A finding on the NET asset routed to the APP team: the asset is
        # visible to a Net analyst, this row is not.
        cross_cve = _cve(session, product, ranges=[
            {"version_start_including": "1.0", "version_end_excluding": "1.2.4"}])
        cross = _finding(session, org_id, session.get(Asset, uuid.UUID(made["net"]["asset"])),
                         made["net"]["installation"], cross_cve, assigned_team_id=app.id)
        made["cross"] = str(cross.id)
        session.commit()

    def user(role, scope_team=None):
        email = f"{role}-{uuid.uuid4().hex[:8]}@{slug}.test"
        body = {"email": email, "full_name": role, "password": PASSWORD, "role_slugs": [role]}
        if scope_team is not None:
            body.update(team_ids=[str(scope_team)], scope_team_ids=[str(scope_team)])
        created = client.post("/api/v1/users", headers=admin_a, json=body)
        assert created.status_code == 201, created.text
        return _headers(client, email, slug)

    return {"org_id": org_id, "slug": slug, "net_team": net.id, "app_team": app.id,
            "user": user, **made}


def test_the_finding_plan_highlights_the_finding(client, admin_a, api_estate):
    fid = api_estate["net"]["finding"]
    response = client.get(f"/api/v1/findings/{fid}/fix-plan", headers=admin_a)
    assert response.status_code == 200, response.text
    body = response.json()
    assert body["highlight_finding_id"] == fid and body["highlight_open"] is True
    assert [r["finding_id"] for r in body["findings"] if r["highlighted"]] == [fid]
    assert body["best_single_target"]["version"] == "2.1.0"
    assert body["best_single_target"]["step"] == "major"


def test_the_asset_plan_has_one_plan_per_product(client, admin_a, api_estate):
    response = client.get(f"/api/v1/assets/{api_estate['net']['asset']}/fix-plan",
                          headers=admin_a)
    assert response.status_code == 200, response.text
    body = response.json()
    assert len(body["plans"]) == 1
    assert body["plans"][0]["coverage"]["open_findings"] == 2
    assert body["unlinked_open_findings"] == 0


def test_a_restricted_user_cannot_read_another_teams_plan(client, api_estate):
    scoped = api_estate["user"]("security-manager", api_estate["net_team"])
    own = client.get(f"/api/v1/findings/{api_estate['net']['finding']}/fix-plan", headers=scoped)
    assert own.status_code == 200, own.text
    for path in (f"/api/v1/findings/{api_estate['app']['finding']}/fix-plan",
                 f"/api/v1/findings/{api_estate['cross']}/fix-plan",
                 f"/api/v1/assets/{api_estate['app']['asset']}/fix-plan"):
        assert client.get(path, headers=scoped).status_code == 404, path

    # The Net asset is visible, but the finding routed to App on it is not --
    # so it is neither listed nor allowed to steer the target.
    plan = client.get(f"/api/v1/assets/{api_estate['net']['asset']}/fix-plan",
                      headers=scoped).json()["plans"][0]
    ids = {r["finding_id"] for r in plan["findings"]}
    assert ids == {api_estate["net"]["finding"]}
    assert api_estate["cross"] not in str(plan)


def test_another_organisation_cannot_read_the_plan(client, admin_b, api_estate):
    for path in (f"/api/v1/findings/{api_estate['net']['finding']}/fix-plan",
                 f"/api/v1/assets/{api_estate['net']['asset']}/fix-plan"):
        assert client.get(path, headers=admin_b).status_code == 404


def test_another_organisations_rules_never_apply(client, admin_a, admin_b, api_estate):
    """Vendors and products are global; the rules about them are not."""
    foreign = client.post("/api/v1/upgrade-path-rules", headers=admin_b, json={
        "vendor": api_estate["vendor"], "product": api_estate["product"],
        "from_start_including": "1.0", "from_end_excluding": "2.0", "via_version": "1.9.0",
        "prerequisite": "Foreign tenant step", "source_url": "https://example.com/x",
    })
    assert foreign.status_code == 201, foreign.text
    fid = api_estate["net"]["finding"]
    plan = client.get(f"/api/v1/findings/{fid}/fix-plan", headers=admin_a).json()
    assert plan["rules_considered"] == 0
    assert plan["best_single_target"]["path"]["path_required"] is False
    assert "Foreign tenant step" not in str(plan)
    listed = client.get("/api/v1/upgrade-path-rules", headers=admin_a).json()
    assert foreign.json()["id"] not in {r["id"] for r in listed}
    rule_id = foreign.json()["id"]
    assert client.patch(f"/api/v1/upgrade-path-rules/{rule_id}", headers=admin_a,
                        json={"prerequisite": "hijack"}).status_code == 404
    assert client.delete(f"/api/v1/upgrade-path-rules/{rule_id}",
                         headers=admin_a).status_code == 404


def test_own_rules_shape_the_plan_over_http(client, admin_a, api_estate):
    created = client.post("/api/v1/upgrade-path-rules", headers=admin_a, json={
        "vendor": api_estate["vendor"].upper(), "product": f" {api_estate['product']} ",
        "from_start_including": "1.0", "from_end_excluding": "2.0", "via_version": "1.9.0",
        "prerequisite": "Back up the configuration", "source_url": "https://example.com/acme",
    })
    assert created.status_code == 201, created.text
    plan = client.get(f"/api/v1/findings/{api_estate['net']['finding']}/fix-plan",
                      headers=admin_a).json()
    path = plan["best_single_target"]["path"]
    assert [(h["from"], h["to"]) for h in path["hops"]] == [("1.2.3", "1.9.0"),
                                                          ("1.9.0", "2.1.0")]
    assert path["path_required"] is True
    assert path["hops"][0]["prerequisites"][0]["source_url"] == "https://example.com/acme"


def test_rule_writes_need_the_policy_permission(client, api_estate):
    read_only = api_estate["user"]("read-only")
    assert client.get("/api/v1/upgrade-path-rules", headers=read_only).status_code == 200
    response = client.post("/api/v1/upgrade-path-rules", headers=read_only, json={
        "vendor": "Acme", "product": "Widget", "via_version": "2.0"})
    assert response.status_code == 403
    # ...and an estate-wide grant: a team-scoped manager has sla:write, but a
    # rule changes the plan every team is handed.
    scoped = api_estate["user"]("security-manager", api_estate["net_team"])
    assert client.get("/api/v1/upgrade-path-rules", headers=scoped).status_code == 200
    assert client.post("/api/v1/upgrade-path-rules", headers=scoped, json={
        "vendor": "Acme", "product": "Widget", "via_version": "2.0"}).status_code == 403


@pytest.mark.parametrize("body,needle", [
    ({"from_start_including": "2.0", "from_end_excluding": "1.0", "via_version": "3.0"}, "empty"),
    ({"from_start_including": "1.0", "from_start_excluding": "1.1", "via_version": "3.0"}, "not both"),
    ({"from_end_including": "1.0", "from_end_excluding": "1.1", "via_version": "3.0"}, "not both"),
    ({"via_version": "!!!"}, "not a version"),
    ({"from_start_including": "2.0", "via_version": "1.5"}, "backwards"),
    ({"from_start_including": "1.0"}, "via_version, a prerequisite"),
    ({"via_version": "2.0", "source_url": "javascript:alert(1)"}, "http"),
])
def test_rules_are_validated(client, admin_a, body, needle):
    response = client.post("/api/v1/upgrade-path-rules", headers=admin_a,
                           json={"vendor": "Acme", "product": "Widget", **body})
    assert response.status_code == 422, response.text
    assert needle in response.text


def test_rule_crud_is_audited(client, admin_a):
    created = client.post("/api/v1/upgrade-path-rules", headers=admin_a, json={
        "vendor": "Acme", "product": "Widget", "from_start_including": "1.0",
        "from_end_excluding": "2.0", "via_version": "1.9", "prerequisite": "Read the notes"})
    assert created.status_code == 201, created.text
    rule = created.json()
    assert rule["vendor_key"] == "acme" and rule["product_key"] == "widget"
    rid = rule["id"]

    patched = client.patch(f"/api/v1/upgrade-path-rules/{rid}", headers=admin_a,
                           json={"via_version": "1.9.5"})
    assert patched.status_code == 200, patched.text
    assert patched.json()["via_version"] == "1.9.5"
    assert patched.json()["prerequisite"] == "Read the notes"       # untouched
    # The merged rule is validated, not just the delta.
    emptied = client.patch(f"/api/v1/upgrade-path-rules/{rid}", headers=admin_a,
                           json={"from_end_excluding": "0.5"})
    assert emptied.status_code == 422

    assert client.delete(f"/api/v1/upgrade-path-rules/{rid}", headers=admin_a).status_code == 204
    assert client.delete(f"/api/v1/upgrade-path-rules/{rid}", headers=admin_a).status_code == 404

    actions = [r["action"] for r in
               client.get(f"/api/v1/audit?limit=50&object_id={rid}",
                          headers=admin_a).json()["items"]]
    assert {"upgrade_path_rule.create", "upgrade_path_rule.update",
            "upgrade_path_rule.delete"} <= set(actions)


def test_a_finding_without_an_installation_explains_itself(client, admin_a, org_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        asset = Asset(organization_id=org_id, name=f"bare-{uuid.uuid4().hex[:6]}")
        session.add(asset)
        session.flush()
        finding = _finding(session, org_id, asset, None, None)
        session.commit()
        fid = str(finding.id)
    body = client.get(f"/api/v1/findings/{fid}/fix-plan", headers=admin_a).json()
    assert body["available"] is False
    assert "not linked to an installed product" in body["reason"]
