"""Phase 51 - "why did this finding change?": attribution of closes and reopens.

The class of defect this pins: the product made a change itself, had the row
that said so, and still showed the operator a state with no cause. Each test
drives a REAL emission path (importer, API, ITSM inbound, acceptance expiry,
inventory + correlation, workflow engine) and then asks the explainer, so a
path that stops recording its detail fails here rather than turning into an
`unknown` nobody notices.

Also pinned:
* a legacy event with no detail is `unknown` and SAYS what is missing;
* team scope: a restricted identity gets 404 on another team's finding and
  only its own slice in `/findings/changes`;
* tenant isolation on both routes;
* the 0.33.0 importer fix: a CSV row naming a product no longer fails the run.
"""
from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    Asset, AssetProduct, Cve, CveCpeMatch, Finding, FindingEvent, ItsmConnector, Ticket,
    User, Vulnerability, WorkflowDefinition,
)
from veyrs.models.integration import ExternalLink, ImportRun
from veyrs.models.tenancy import Team
from veyrs.services import (
    attribution, correlation, engagements, intelligence, inventory, itsm_inbound,
    ticketing, workflow,
)
from veyrs.services.importers import ImportOptions, run_import

from conftest import login

PASSWORD = "Str0ng-Passw0rd!x"
HEADER = b"Asset Name,Vulnerability,Severity,Vendor,Product,Version\n"


def _user_id(session, email: str) -> uuid.UUID:
    return session.execute(select(User.id).where(User.email == email)).scalar_one()


def _csv(host: str, title: str, *, product: tuple[str, str, str] | None = None) -> bytes:
    vendor, name, version = product or ("", "", "")
    return HEADER + f"{host},{title},High,{vendor},{name},{version}\n".encode()


def _explain(session, finding_id) -> dict:
    return attribution.explain(session, session.get(Finding, finding_id))


@pytest.fixture()
def host(org_a):
    org_id, slug, email = org_a
    tag = uuid.uuid4().hex[:8]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        asset = Asset(organization_id=org_id, name=f"attr-{tag}", hostname=f"attr-{tag}",
                      asset_type="server")
        session.add(asset)
        session.commit()
        return {"org_id": org_id, "slug": slug, "email": email, "tag": tag,
                "asset_id": asset.id, "name": asset.name,
                "user_id": _user_id(session, email)}


def _import(session, host, payload: bytes, **options) -> ImportRun:
    run = run_import(session, host["org_id"], payload, source="csv",
                     filename=f"weekly-{uuid.uuid4().hex[:4]}.csv",
                     options=ImportOptions(**options) if options else None,
                     actor_id=host["user_id"])
    session.commit()
    assert run.status == "complete", run.error
    return run


def _only_finding(session, org_id) -> Finding:
    return session.execute(select(Finding).where(Finding.organization_id == org_id)).scalar_one()


# ---------------------------------------------------------------------------
# 1. Re-import: closed by absence, reopened by a later sighting
# ---------------------------------------------------------------------------
def test_reimport_absence_names_the_runs_the_test_and_who_vouched(host):
    title = f"Weak cipher {host['tag']}"
    with SessionLocal() as session:
        set_tenant(session, host["org_id"])
        seen = _import(session, host, _csv(host["name"], title))
        miss1 = _import(session, host, HEADER)
        miss2 = _import(session, host, HEADER)
        finding = _only_finding(session, host["org_id"])
        assert finding.state == "remediated"
        story = _explain(session, finding.id)

    closes = [t for t in story["transitions"] if t["kind"] == "closed"]
    assert len(closes) == 1
    close = closes[0]
    assert close["cause"] == "reimport_absence"
    assert close["to"] == "remediated"
    assert close["evidence"]["ids"]["import_run_ids"] == [str(miss1.id), str(miss2.id)]
    assert close["evidence"]["ids"]["closing_import_run_id"] == str(miss2.id)
    assert str(seen.id) not in close["evidence"]["ids"]["import_run_ids"]
    sentence = close["evidence"]["sentence"]
    assert "2 consecutive runs" in sentence
    assert str(miss1.id)[:8] in sentence and str(miss2.id)[:8] in sentence
    assert "csv scan" in sentence                       # the scan test's title
    assert "imported by Test Admin" in sentence         # manual upload: who vouched
    assert "not a verified fix" in sentence
    assert close["missing"] == []
    assert story["last_closed"]["event_id"] == close["event_id"]


def test_a_reappearance_is_a_regression_with_scanner_run_and_gap(host):
    title = f"Open redirect {host['tag']}"
    with SessionLocal() as session:
        set_tenant(session, host["org_id"])
        _import(session, host, _csv(host["name"], title))
        _import(session, host, HEADER)
        _import(session, host, HEADER)
        back = _import(session, host, _csv(host["name"], title))
        finding = _only_finding(session, host["org_id"])
        assert finding.state != "remediated"
        story = _explain(session, finding.id)

    reopen = story["last_reopened"]
    assert reopen is not None and reopen["cause"] == "rescan_seen_again"
    assert reopen["from"] == "remediated" and reopen["to"] == "new"
    assert reopen["evidence"]["ids"]["import_run_id"] == str(back.id)
    regression = reopen["regression"]
    assert regression["seen_again_by"]["import_run_id"] == str(back.id)
    assert regression["seen_again_by"]["scanner"] == "csv"
    assert regression["closed_by_cause"] == "reimport_absence"
    assert regression["seconds_after_closure"] is not None
    assert regression["seconds_after_closure"] >= 0
    assert "after it was closed" in regression["sentence"]
    # Not linked to an installed product: says so instead of implying "no drift".
    assert "not linked to an installed product" in regression["sentence"]


def test_an_agent_attestation_is_named_on_the_closure(host):
    title = f"TLS 1.0 {host['tag']}"
    attestation = {"kind": "agent", "attested": True, "agent": "probe-1",
                   "job_id": str(uuid.uuid4()), "percent": 97}
    with SessionLocal() as session:
        set_tenant(session, host["org_id"])
        _import(session, host, _csv(host["name"], title))
        _import(session, host, HEADER, coverage_attestation=attestation)
        _import(session, host, HEADER, coverage_attestation=attestation)
        close = next(t for t in _explain(session, _only_finding(session, host["org_id"]).id)
                     ["transitions"] if t["kind"] == "closed")
    assert "coverage attested by agent 'probe-1'" in close["evidence"]["sentence"]
    assert "97%" in close["evidence"]["sentence"]


# ---------------------------------------------------------------------------
# 2. Inventory drift between closure and reopen
# ---------------------------------------------------------------------------
def test_a_csv_row_naming_a_product_imports_instead_of_failing_the_run(host):
    """0.33.0 fix: AssetProduct(source=...) raised TypeError for every such row."""
    product = (f"acme-{host['tag']}", f"widget-{host['tag']}", "1.2.3")
    with SessionLocal() as session:
        set_tenant(session, host["org_id"])
        run = _import(session, host, _csv(host["name"], f"Widget flaw {host['tag']}",
                                          product=product))
        finding = _only_finding(session, host["org_id"])
        installation = session.get(AssetProduct, finding.asset_product_id)
    assert run.findings_created == 1
    assert installation is not None and installation.version == "1.2.3"
    assert installation.detected_by == "scanner"


def test_an_inventory_change_between_close_and_reopen_is_reported(host):
    vendor, name = f"acme-{host['tag']}", f"widget-{host['tag']}"
    row = _csv(host["name"], f"Widget flaw {host['tag']}", product=(vendor, name, "1.2.3"))
    with SessionLocal() as session:
        set_tenant(session, host["org_id"])
        _import(session, host, row)
        _import(session, host, HEADER)
        _import(session, host, HEADER)
        asset = session.get(Asset, host["asset_id"])
        inventory.install(session, asset, [{"vendor": vendor, "product": name,
                                            "version": "1.2.4"}],
                          detected_by="agent:attr-probe", source={"agent": "attr-probe"})
        session.commit()
        _import(session, host, row)
        finding = _only_finding(session, host["org_id"])
        story = _explain(session, finding.id)

    regression = story["last_reopened"]["regression"]
    assert regression["inventory_checked"] is True
    assert len(regression["inventory_changes"]) == 1
    change = regression["inventory_changes"][0]
    assert (change["old_version"], change["new_version"]) == ("1.2.3", "1.2.4")
    assert change["detected_by"] == "agent:attr-probe"
    assert change["source"] == {"agent": "attr-probe"}
    assert "from 1.2.3 to 1.2.4" in regression["sentence"]
    assert "agent 'attr-probe'" in regression["sentence"]


def test_a_reopen_with_a_linked_product_and_no_drift_says_none_was_recorded(host):
    vendor, name = f"acme-{host['tag']}", f"gizmo-{host['tag']}"
    row = _csv(host["name"], f"Gizmo flaw {host['tag']}", product=(vendor, name, "2.0"))
    with SessionLocal() as session:
        set_tenant(session, host["org_id"])
        _import(session, host, row)
        _import(session, host, HEADER)
        _import(session, host, HEADER)
        _import(session, host, row)
        regression = _explain(session, _only_finding(session, host["org_id"]).id)[
            "last_reopened"]["regression"]
    assert regression["inventory_changes"] == []
    assert f"No installed-version change on {name}" in regression["sentence"]


@pytest.fixture()
def correlated(org_a):
    """Two assets on product 1.0.0; a CVE fixed in 2.0.0; correlation run once."""
    org_id, slug, email = org_a
    tag = uuid.uuid4().hex[:10]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        product = intelligence.upsert_product(session, f"acme-{tag}", f"router-{tag}")
        cve_id = f"CVE-2097-{int(tag, 16)}"
        session.add(Cve(id=cve_id, title=f"Acme router flaw {tag}", description="test",
                        cvss3_base_score=8.1, cvss3_severity="high"))
        session.flush()
        session.add(CveCpeMatch(cve_id=cve_id, cpe23=f"cpe:2.3:a:acme:{product.name}:*:*:*:*:*:*:*:*",
                                product_id=product.id, vulnerable=True,
                                version_end_excluding="2.0.0"))
        assets = []
        for label in ("a", "b"):
            asset = Asset(organization_id=org_id, name=f"rtr-{label}-{tag}", asset_type="network")
            session.add(asset)
            session.flush()
            session.add(AssetProduct(organization_id=org_id, asset_id=asset.id,
                                     product_id=product.id, version="1.0.0", detected_by="manual"))
            assets.append(asset.id)
        session.flush()
        correlation.correlate_cve(session, org_id, session.get(Cve, cve_id))
        session.commit()
        return {"org_id": org_id, "cve": cve_id, "assets": assets,
                "vendor": f"acme-{tag}", "product": product.name}


def test_a_correlation_close_after_an_upgrade_is_attributed_to_the_version_change(correlated):
    org_id = correlated["org_id"]
    spec = {"vendor": correlated["vendor"], "product": correlated["product"]}
    with SessionLocal() as session:
        set_tenant(session, org_id)
        upgraded = session.get(Asset, correlated["assets"][0])
        inventory.install(session, upgraded, [{**spec, "version": "2.1.0"}],
                          detected_by="agent:rtr", source={"agent": "rtr"})
        correlation.correlate_cve(session, org_id, session.get(Cve, correlated["cve"]),
                                  close_missing=True)
        session.commit()
        finding = session.execute(select(Finding).where(
            Finding.organization_id == org_id, Finding.asset_id == upgraded.id)).scalar_one()
        assert finding.state == "remediated"
        close = _explain(session, finding.id)["last_closed"]
        assert close["cause"] == "inventory_version_changed"
        assert "from 1.0.0 to 2.1.0" in close["evidence"]["sentence"]
        assert correlated["cve"] in close["evidence"]["sentence"]

        # Roll the version back: the correlation engine reopens it, and the
        # regression names the rollback.
        inventory.install(session, upgraded, [{**spec, "version": "1.0.0"}],
                          detected_by="agent:rtr", source={"agent": "rtr"})
        correlation.correlate_cve(session, org_id, session.get(Cve, correlated["cve"]))
        session.commit()
        story = _explain(session, finding.id)
    reopen = story["last_reopened"]
    assert reopen["cause"] == "correlation_rescan"
    assert "1.0.0" in reopen["evidence"]["sentence"]
    changes = reopen["regression"]["inventory_changes"]
    assert [(c["old_version"], c["new_version"]) for c in changes] == [("2.1.0", "1.0.0")]
    assert reopen["regression"]["closed_by_cause"] == "inventory_version_changed"


# ---------------------------------------------------------------------------
# 3. Operator, verification, ticket, workflow, acceptance
# ---------------------------------------------------------------------------
@pytest.fixture()
def open_finding(host):
    with SessionLocal() as session:
        set_tenant(session, host["org_id"])
        vulnerability = Vulnerability(organization_id=host["org_id"], internal_ref=host["tag"],
                                      title="Test flaw", severity="high")
        session.add(vulnerability)
        session.flush()
        finding = Finding(organization_id=host["org_id"], asset_id=host["asset_id"],
                          vulnerability_id=vulnerability.id, state="in_progress",
                          dedupe_key=uuid.uuid4().hex, title=f"Flaw {host['tag']}",
                          severity="high")
        session.add(finding)
        session.commit()
        return {**host, "finding_id": finding.id}


def test_an_operator_close_through_the_api_names_the_user(client, admin_a, open_finding):
    fid = open_finding["finding_id"]
    moved = client.post(f"/api/v1/findings/{fid}/transition", headers=admin_a,
                        json={"state": "remediated", "note": "patched in change 42"})
    assert moved.status_code == 200, moved.text
    body = client.get(f"/api/v1/findings/{fid}/attribution", headers=admin_a)
    assert body.status_code == 200, body.text
    close = body.json()["last_closed"]
    assert close["cause"] == "operator"
    assert close["actor"]["kind"] == "user"
    assert close["actor"]["id"] == str(open_finding["user_id"])
    assert "patched in change 42" in close["evidence"]["sentence"]
    assert close["missing"] == []

    for state in ("verification", "verified"):
        client.post(f"/api/v1/findings/{fid}/transition", headers=admin_a, json={"state": state})
    last = client.get(f"/api/v1/findings/{fid}/attribution", headers=admin_a).json()[
        "transitions"][-1]
    assert last["cause"] == "verification_passed"


def test_a_failed_verification_is_a_reopen_with_its_own_cause(client, admin_a, open_finding):
    fid = open_finding["finding_id"]
    for state in ("remediated", "verification", "in_progress"):
        assert client.post(f"/api/v1/findings/{fid}/transition", headers=admin_a,
                           json={"state": state}).status_code == 200
    reopen = client.get(f"/api/v1/findings/{fid}/attribution", headers=admin_a).json()[
        "last_reopened"]
    assert reopen["cause"] == "verification_failed"
    assert reopen["regression"]["closed_by_cause"] == "operator"


def test_an_external_ticket_closure_names_the_system_issue_and_status(open_finding):
    org_id = open_finding["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        connector = ItsmConnector(
            organization_id=org_id, slug=f"jira-{open_finding['tag']}", name="Jira",
            system="jira", base_url="https://jira.example.com", inbound_enabled=True,
            inbound_transitions={"In Progress": "in_progress", "Done": "resolved"},
        )
        session.add(connector)
        session.flush()
        ticket = ticketing.create_ticket(session, org_id, title="Patch it",
                                         ticket_type="remediation",
                                         finding_id=open_finding["finding_id"])
        session.add(ExternalLink(organization_id=org_id, connector_id=connector.id,
                                 object_type="ticket", object_id=str(ticket.id),
                                 remote_id="20077", remote_key="SEC-77"))
        session.flush()
        for status in ("In Progress", "Done"):
            itsm_inbound.handle_inbound(session, connector, itsm_inbound.InboundEvent(
                remote_id="20077", status=status, remote_key="SEC-77", actor="R. Engineer",
                event="jira:issue_updated"))
        session.commit()
        assert session.get(Ticket, ticket.id).state == "resolved"
        story = _explain(session, open_finding["finding_id"])
    close = story["last_closed"]
    assert close["cause"] == "ticket_closed_external"
    assert close["actor"] == {"kind": "external", "label": "R. Engineer", "system": "jira",
                              "connector": connector.slug}
    sentence = close["evidence"]["sentence"]
    assert "SEC-77" in sentence and "'Done'" in sentence and ticket.reference in sentence
    assert close["evidence"]["ids"]["ticket_id"] == str(ticket.id)


def test_a_ticket_resolved_inside_veyrs_is_not_called_external(open_finding):
    org_id = open_finding["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        ticket = ticketing.create_ticket(session, org_id, title="Patch it",
                                         ticket_type="remediation",
                                         finding_id=open_finding["finding_id"])
        ticketing.transition_ticket(session, ticket, "in_progress")
        ticketing.transition_ticket(session, ticket, "resolved", actor_id=open_finding["user_id"],
                                    actor_label="Test Admin")
        session.commit()
        close = _explain(session, open_finding["finding_id"])["last_closed"]
    assert close["cause"] == "ticket_resolved"
    assert ticket.reference in close["evidence"]["sentence"]


def test_a_workflow_transition_names_the_workflow_and_run(open_finding):
    org_id = open_finding["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        definition = WorkflowDefinition(
            organization_id=org_id, slug=f"auto-mitigate-{open_finding['tag']}",
            name="Auto mitigate", trigger="manual",
            steps=[{"action": "transition_finding", "config": {"state": "remediated"}}],
        )
        session.add(definition)
        session.flush()
        finding = session.get(Finding, open_finding["finding_id"])
        run = workflow.run_definition(session, definition, workflow.WorkflowContext(
            org_id, trigger="manual", finding=finding))
        session.commit()
        close = _explain(session, finding.id)["last_closed"]
    assert close["cause"] == "workflow_rule"
    assert close["evidence"]["ids"]["workflow_id"] == str(definition.id)
    assert close["evidence"]["ids"]["workflow_run_id"] == str(run.id)
    assert "Auto mitigate" in close["evidence"]["sentence"]


def test_acceptance_approval_and_expiry_are_both_attributed(open_finding):
    org_id = open_finding["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        approver = User(organization_id=org_id, email=f"cab-{open_finding['tag']}@example.com",
                        full_name="CAB Chair", password_hash="x")
        session.add(approver)
        session.flush()
        acceptance = engagements.request_acceptance(
            session, org_id, name="Q4 window", reason="Vendor fix scheduled for Q4.",
            finding_ids=[open_finding["finding_id"]], requested_by_id=open_finding["user_id"],
            expires_on=dt.date.today() - dt.timedelta(days=1),
        )
        engagements.approve(session, acceptance, approved_by_id=approver.id)
        session.commit()
        engagements.expire_due(session, org_id)
        session.commit()
        story = _explain(session, open_finding["finding_id"])
    approved, expired = story["transitions"][-2:]
    assert approved["cause"] == "acceptance_approved" and approved["kind"] == "closed"
    assert "CAB Chair" in approved["evidence"]["sentence"]
    assert expired["cause"] == "acceptance_expired" and expired["kind"] == "reopened"
    assert "expired on" in expired["evidence"]["sentence"]
    assert expired["regression"]["closed_by_cause"] == "acceptance_approved"


# ---------------------------------------------------------------------------
# 4. Legacy rows: unknown, with what is missing
# ---------------------------------------------------------------------------
def test_a_legacy_event_without_detail_is_unknown_and_says_what_is_missing(open_finding):
    with SessionLocal() as session:
        set_tenant(session, open_finding["org_id"])
        session.add(FindingEvent(
            organization_id=open_finding["org_id"], finding_id=open_finding["finding_id"],
            event="state_changed", actor_label="system",
            details={"from": "in_progress", "to": "remediated", "note": "ticket X resolved"},
        ))
        session.commit()
        story = _explain(session, open_finding["finding_id"])
    item = story["transitions"][-1]
    assert item["cause"] == "unknown"
    assert item["kind"] == "closed"
    assert "no event detail was recorded before 0.33.0" in item["evidence"]["sentence"]
    assert "ticket X resolved" in item["evidence"]["sentence"]   # quoted, not parsed
    assert item["missing"] and "0.33.0" in item["missing"][0]


def test_a_legacy_absence_closure_is_recognised_but_flags_the_gaps(open_finding):
    with SessionLocal() as session:
        set_tenant(session, open_finding["org_id"])
        session.add(FindingEvent(
            organization_id=open_finding["org_id"], finding_id=open_finding["finding_id"],
            event="remediated", actor_label="system",
            details={"reason": "absent from scanner export", "scanner": "nessus",
                     "test_id": str(uuid.uuid4()), "consecutive_absences": 2},
        ))
        session.commit()
        item = _explain(session, open_finding["finding_id"])["transitions"][-1]
    assert item["cause"] == "reimport_absence"
    assert any("which import runs" in gap for gap in item["missing"])
    assert any("coverage attestation" in gap for gap in item["missing"])


# ---------------------------------------------------------------------------
# 5. /findings/changes, scope, tenancy
# ---------------------------------------------------------------------------
def test_changes_lists_closes_and_reopens_with_cause_filters(client, admin_a, open_finding):
    fid = str(open_finding["finding_id"])
    for state in ("remediated", "in_progress"):
        client.post(f"/api/v1/findings/{fid}/transition", headers=admin_a, json={"state": state})
    body = client.get("/api/v1/findings/changes", headers=admin_a)
    assert body.status_code == 200, body.text   # not swallowed by /findings/{finding_id}
    mine = [i for i in body.json()["items"] if i["finding_id"] == fid]
    assert [i["kind"] for i in mine] == ["reopened", "closed"]   # newest first
    assert {i["cause"] for i in mine} == {"operator"}
    assert all(i["asset_name"] == open_finding["name"] for i in mine)

    closed = client.get("/api/v1/findings/changes", headers=admin_a,
                        params={"kind": "closed", "cause": "operator"}).json()["items"]
    assert [i["kind"] for i in closed if i["finding_id"] == fid] == ["closed"]
    none = client.get("/api/v1/findings/changes", headers=admin_a,
                      params={"cause": "reimport_absence"}).json()["items"]
    assert fid not in {i["finding_id"] for i in none}
    future = client.get("/api/v1/findings/changes", headers=admin_a,
                        params={"since": "2999-01-01T00:00:00Z"}).json()
    assert future["total"] == 0
    assert client.get("/api/v1/findings/changes", headers=admin_a,
                      params={"cause": "made-up"}).status_code == 422


@pytest.fixture()
def two_teams(client, admin_a, org_a):
    org_id, slug, _ = org_a
    tag = uuid.uuid4().hex[:6]
    made = {}
    with SessionLocal() as session:
        set_tenant(session, org_id)
        for label in ("net", "app"):
            team = Team(organization_id=org_id, name=f"{label}-{tag}", slug=f"{label}-{tag}")
            session.add(team)
            session.flush()
            asset = Asset(organization_id=org_id, name=f"{label}-{tag}", team_id=team.id)
            vulnerability = Vulnerability(organization_id=org_id, internal_ref=f"{label}-{tag}",
                                          title=label, severity="high")
            session.add_all([asset, vulnerability])
            session.flush()
            finding = Finding(organization_id=org_id, asset_id=asset.id,
                              vulnerability_id=vulnerability.id, state="in_progress",
                              dedupe_key=uuid.uuid4().hex, title=f"{label} finding")
            session.add(finding)
            session.flush()
            made[label] = {"team": team.id, "finding": str(finding.id)}
        session.commit()
    for label in ("net", "app"):
        client.post(f"/api/v1/findings/{made[label]['finding']}/transition", headers=admin_a,
                    json={"state": "remediated"})
    email = f"net-{tag}@{slug}.test"
    created = client.post("/api/v1/users", headers=admin_a, json={
        "email": email, "full_name": "Net Analyst", "password": PASSWORD,
        "role_slugs": ["security-manager"], "team_ids": [str(made["net"]["team"])],
        "scope_team_ids": [str(made["net"]["team"])],
    })
    assert created.status_code == 201, created.text
    token = login(client, email, slug, PASSWORD)["access_token"]
    return {**made, "scoped": {"Authorization": f"Bearer {token}"}}


def test_a_scoped_identity_cannot_read_another_teams_attribution(client, two_teams):
    scoped = two_teams["scoped"]
    assert client.get(f"/api/v1/findings/{two_teams['app']['finding']}/attribution",
                      headers=scoped).status_code == 404
    assert client.get(f"/api/v1/findings/{two_teams['net']['finding']}/attribution",
                      headers=scoped).status_code == 200


def test_changes_are_narrowed_to_the_callers_teams(client, admin_a, two_teams):
    everything = {i["finding_id"] for i in client.get(
        "/api/v1/findings/changes", headers=admin_a, params={"size": 200}).json()["items"]}
    assert {two_teams["net"]["finding"], two_teams["app"]["finding"]} <= everything
    body = client.get("/api/v1/findings/changes", headers=two_teams["scoped"],
                      params={"size": 200}).json()
    visible = {i["finding_id"] for i in body["items"]}
    assert visible == {two_teams["net"]["finding"]}
    assert body["scope"]["restricted"] is True


def test_attribution_never_crosses_tenants(client, admin_a, admin_b, open_finding):
    fid = open_finding["finding_id"]
    client.post(f"/api/v1/findings/{fid}/transition", headers=admin_a,
                json={"state": "remediated"})
    assert client.get(f"/api/v1/findings/{fid}/attribution", headers=admin_b).status_code == 404
    other = client.get("/api/v1/findings/changes", headers=admin_b,
                       params={"size": 200}).json()["items"]
    assert str(fid) not in {i["finding_id"] for i in other}


def test_state_changes_now_fill_the_from_and_to_columns(client, admin_a, open_finding):
    """The columns existed since phase 2 and were never written."""
    fid = open_finding["finding_id"]
    client.post(f"/api/v1/findings/{fid}/transition", headers=admin_a,
                json={"state": "remediated"})
    with SessionLocal() as session:
        set_tenant(session, open_finding["org_id"])
        row = session.execute(select(FindingEvent).where(
            FindingEvent.finding_id == fid, FindingEvent.event == "state_changed")).scalar_one()
    assert (row.from_state, row.to_state) == ("in_progress", "remediated")
    assert row.details["origin"] == "operator"
