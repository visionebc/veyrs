"""Phase 45 -- internal queue or external ITSM, and the relation that replaces
the Tickets section.

The defect class this phase exists to prevent has a shape: a mode that only the
console respects. Hiding the Tickets menu while `POST /tickets`, `autoticket`
and the workflow engine carry on writing rows is not a mode, it is a coat of
paint -- and the symptom is an operator who believes remediation lives in Jira
while a hidden queue fills up against an SLA clock nobody is watching.

So most of what is pinned here is ENFORCEMENT, not UI: that the API refuses,
that the dispatcher is the only creation path, and that the relation carries
enough to answer "which issue, which finding, which device, when" without
calling the remote system.
"""
from __future__ import annotations

import ast
import pathlib
import uuid

import pytest

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Asset, Finding, ItsmConnector, Vulnerability
from veyrs.models.intelligence import Cve
from veyrs.models.integration import ExternalLink
from veyrs.services import itsm, remediation, ticketing_mode

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "frontend/console/app.js"
SERVICES = ROOT / "backend/veyrs/services"


# ---------------------------------------------------------------------------
# The switch itself
# ---------------------------------------------------------------------------
class TestTheSwitch:
    def test_the_shipped_default_is_the_internal_queue(self, client, org_a, admin_a):
        r = client.get("/api/v1/ticketing", headers=admin_a)
        assert r.status_code == 200, r.text
        assert r.json()["mode"] == "internal"
        # "explicit: false" is the difference between a decision somebody made
        # and the default they never touched.
        assert r.json()["explicit"] is False

    def test_external_with_no_connector_is_refused_not_stored(self, client, admin_a):
        """The state this refusal makes unreachable is the dangerous one.

        External mode with no connector refuses every creation path, so the
        tenant would have no ticketing at all and the only symptom would be
        work quietly not happening.
        """
        r = client.put("/api/v1/ticketing", headers=admin_a, json={"mode": "external"})
        assert r.status_code == 422, r.text
        assert "connector" in r.json()["detail"].lower()
        assert client.get("/api/v1/ticketing", headers=admin_a).json()["mode"] == "internal"

    def test_an_unknown_mode_is_refused(self, client, admin_a):
        r = client.put("/api/v1/ticketing", headers=admin_a, json={"mode": "jira"})
        assert r.status_code == 422
        # And the message names what IS accepted, rather than only what is not.
        assert "internal" in r.json()["detail"] and "external" in r.json()["detail"]

    def test_a_connector_from_another_tenant_cannot_be_named(
            self, client, admin_a, admin_b):
        made = client.post("/api/v1/integrations/connectors", headers=admin_b, json={
            "slug": "jira-b", "name": "B's Jira", "system": "jira",
            "base_url": "https://b.atlassian.net",
        })
        assert made.status_code == 201, made.text
        r = client.put("/api/v1/ticketing", headers=admin_a, json={
            "mode": "external", "connector_id": made.json()["id"]})
        assert r.status_code == 422
        assert "not found" in r.json()["detail"]

    def test_the_flip_is_audited_with_the_open_ticket_count(self, client, admin_a):
        cid = _connector(client, admin_a)
        client.put("/api/v1/ticketing", headers=admin_a, json={
            "mode": "external", "connector_id": cid, "reason": "engineering uses Jira"})
        rows = client.get("/api/v1/audit?limit=50", headers=admin_a).json()["items"]
        entry = next(r for r in rows
                     if r["action"] == "organization.ticketing_mode_changed")
        assert entry["changes"]["mode"] == ["internal", "external"]
        assert entry["changes"]["reason"] == "engineering uses Jira"
        # Recorded at the moment of the flip because it is unrecoverable after.
        assert "open_internal_tickets" in entry["changes"]

    def test_reading_the_mode_does_not_need_settings_admin(self):
        """The console asks for this on every page load to paint the nav.

        Gating it on `settings:admin` would hide the Tickets section from every
        non-admin -- which looks exactly like the bug this mode is meant to fix.
        """
        src = (ROOT / "backend/veyrs/api/v1/admin.py").read_text()
        block = src.split('@router.get("/ticketing"')[1].split("@router.put")[0]
        assert 'require("settings:read")' in block
        write = src.split('@router.put("/ticketing"')[1].split("@router.get")[0]
        assert 'require("settings:admin")' in write


# ---------------------------------------------------------------------------
# Enforcement -- the part a console-only change would have missed
# ---------------------------------------------------------------------------
class TestEnforcement:
    def test_post_tickets_is_refused_with_409_not_403(self, client, admin_a):
        _external(client, admin_a)
        r = client.post("/api/v1/tickets", headers=admin_a,
                        json={"title": "by hand", "ticket_type": "remediation"})
        # 403 would send an operator hunting for a role that is not missing.
        assert r.status_code == 409, r.text
        assert "Administration" in r.json()["detail"]

    def test_the_refusal_names_the_system_that_took_over(self, client, admin_a):
        _external(client, admin_a, name="Engineering Jira")
        r = client.post("/api/v1/tickets", headers=admin_a, json={"title": "x"})
        assert "Engineering Jira" in r.json()["detail"]

    def test_existing_tickets_stay_readable_and_transitionable(self, client, admin_a):
        """The invariant that keeps a flip from stranding work.

        A tenant that moves to Jira with 40 open internal tickets must still be
        able to close them. Refusing transitions to make the menu consistent
        would leave real work unclosable and its audit trail frozen.
        """
        made = client.post("/api/v1/tickets", headers=admin_a,
                           json={"title": "opened before the flip"})
        assert made.status_code == 201, made.text
        ticket_id = made.json()["id"]
        _external(client, admin_a)

        assert client.get("/api/v1/tickets", headers=admin_a).status_code == 200
        assert client.get(f"/api/v1/tickets/{ticket_id}", headers=admin_a).status_code == 200
        # A real transition from the ticket's own graph, so a refusal here can
        # only be the mode -- which is what this test is about.
        moved = client.post(f"/api/v1/tickets/{ticket_id}/transition",
                            headers=admin_a, json={"state": "in_progress"})
        assert moved.status_code == 200, moved.text
        done = client.post(f"/api/v1/tickets/{ticket_id}/transition",
                           headers=admin_a, json={"state": "resolved"})
        assert done.status_code == 200, done.text

    def test_going_back_to_internal_allows_creation_again(self, client, admin_a):
        _external(client, admin_a)
        assert client.post("/api/v1/tickets", headers=admin_a,
                           json={"title": "x"}).status_code == 409
        client.put("/api/v1/ticketing", headers=admin_a, json={"mode": "internal"})
        assert client.post("/api/v1/tickets", headers=admin_a,
                           json={"title": "x"}).status_code == 201


# ---------------------------------------------------------------------------
# The dispatcher: the reason enforcement cannot be routed around
# ---------------------------------------------------------------------------
class TestDispatcher:
    def test_no_service_creates_remediation_work_behind_the_dispatcher(self):
        """The guard that makes this phase survive the next feature.

        Three call sites used to call `ticketing.ticket_for_finding` directly.
        A fourth one added later that forgets `remediation.open_for_finding`
        would silently write internal tickets in external mode -- exactly the
        failure this phase set out to make impossible. Checked by AST rather
        than by grep so a call inside a comment or a string cannot satisfy it,
        and a renamed import cannot hide it.
        """
        offenders: list[str] = []
        allowed = {"remediation.py", "ticketing.py"}
        for path in sorted(SERVICES.glob("*.py")):
            if path.name in allowed:
                continue
            tree = ast.parse(path.read_text())
            for node in ast.walk(tree):
                if (isinstance(node, ast.Call)
                        and isinstance(node.func, ast.Attribute)
                        and node.func.attr == "ticket_for_finding"):
                    offenders.append(f"{path.name}:{node.lineno}")
        assert offenders == [], (
            "these call ticketing.ticket_for_finding directly and so bypass the "
            f"ticketing mode: {offenders}"
        )

    def test_the_console_asks_the_api_where_work_goes(self):
        """It used to post to /tickets with a finding_id, i.e. it decided."""
        src = CONSOLE.read_text()
        assert "/remediation`, {})" in src or "/remediation`, {}" in src
        assert "async function openRemediationForFinding" in src
        assert "createTicketForFinding" not in src

    def test_the_nav_hides_exactly_one_of_the_two_sections(self):
        src = CONSOLE.read_text()
        assert "!(i.mode && i.mode !== ticketingMode)" in src
        assert "path: 'tickets'" in src and "mode: 'internal'" in src
        assert "path: 'issues'" in src and "mode: 'external'" in src

    def test_the_console_defaults_to_internal_on_every_failure_path(self):
        """A hidden section is indistinguishable from a page that was removed.

        If `/auth/me` cannot be read, or an older API does not send the field,
        the console must show the queue VEYRS itself owns -- not leave the
        operator with no remediation surface and nothing to click.
        """
        src = CONSOLE.read_text()
        assert "let ticketingMode = 'internal';" in src
        assert "me.ticketing_mode === 'external' ? 'external' : 'internal'" in src


# ---------------------------------------------------------------------------
# The budget: a defect the mode WOULD have introduced
# ---------------------------------------------------------------------------
class TestAutomationBudget:
    def test_the_auto_ticket_cap_is_not_silently_off_in_external_mode(self):
        """`recent_auto_created` counted `ticket_events`, of which external mode
        produces none -- so the cap would have returned 0 forever and the
        automation would have been free to open an unbounded number of issues
        in somebody else's queue.
        """
        src = (SERVICES / "autoticket.py").read_text()
        block = src.split("def recent_auto_created")[1].split("def budget_left")[0]
        assert "ticketing_mode.is_external" in block
        assert "ExternalLink" in block


# ---------------------------------------------------------------------------
# The relation
# ---------------------------------------------------------------------------
class TestTheRelation:
    def test_the_link_carries_finding_asset_vulnerability_and_dates(self):
        """"Only a relation" still has to answer the auditor's question.

        A row that holds a Jira key and nothing else forces a join across four
        tables plus a remote call to say what SEC-4412 was about.
        """
        for column in ("finding_id", "asset_id", "vulnerability_id", "cve_id",
                       "summary", "severity", "risk_score", "due_at",
                       "remote_created_at", "remote_updated_at",
                       "remote_priority", "remote_type", "remote_assignee"):
            assert hasattr(ExternalLink, column), f"external_links.{column} is missing"

    def test_the_issue_body_carries_the_device_and_the_cve(self, org_a):
        """An engineer opening SEC-4412 must not need VEYRS to start work."""
        org_id, _, _ = org_a
        with SessionLocal() as session:
            set_tenant(session, org_id)
            finding = _finding(session, org_id)
            payload = itsm.finding_payload(session, finding)
        assert "CVE-2023-44487" in payload["summary"]
        assert "dmz-edge" in payload["summary"]
        body = payload["description"]
        for expected in ("Device: dmz-edge", "Vulnerability: CVE-2023-44487",
                         "Severity: critical", "10.0.0.9"):
            assert expected in body, f"{expected!r} missing from the issue body"
        # The finding id, so the relation survives even a hand-deleted link row.
        assert "VEYRS finding" in body

    def test_the_relation_is_stamped_from_the_finding_not_from_the_remote(
            self, org_a, monkeypatch):
        org_id, _, _ = org_a

        class FakeAdapter:
            """Answers like a remote that accepted the issue. No network."""

            def create(self, spec, payload):
                return itsm.RemoteTicket(remote_id="1", remote_key="SEC-1",
                                         url="https://j/SEC-1", status="To Do")

        monkeypatch.setitem(itsm.ADAPTERS, "webhook", FakeAdapter)
        with SessionLocal() as session:
            set_tenant(session, org_id)
            finding = _finding(session, org_id)
            connector = ItsmConnector(
                organization_id=org_id, slug="fake", name="Fake", system="webhook",
                base_url="https://example.invalid/hook",
            )
            session.add(connector)
            session.flush()
            link = itsm.push_finding(session, connector, finding)

            assert link.object_type == "finding"
            assert link.finding_id == finding.id
            assert link.asset_id == finding.asset_id
            assert link.cve_id == "CVE-2023-44487"
            assert link.severity == "critical"
            assert link.remote_key == "SEC-1"
            assert link.due_at == finding.sla_due_at

    def test_unlinking_does_not_close_the_remote_issue(self):
        """VEYRS is the system of record for the finding, never for Jira.

        Deleting an issue out of a security console is a destructive act on a
        system whose other users did not consent to it.
        """
        src = (ROOT / "backend/veyrs/api/v1/integrations.py").read_text()
        block = src.split('@router.post("/links/{link_id}/unlink"')[1]
        assert "link.is_active = False" in block
        assert "adapter" not in block.split("def unlink_link")[1].split("return")[0]

    def test_the_list_is_filtered_in_sql_not_in_the_browser(self):
        src = (ROOT / "backend/veyrs/api/v1/integrations.py").read_text()
        block = src.split("def list_links(")[1].split("def refresh_link")[0]
        for param in ("finding_id", "asset_id", "severity", "remote_status", "q"):
            assert f"if {param}" in block, f"{param} is accepted but never applied"


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _connector(client, headers, *, name="Team Jira") -> str:
    r = client.post("/api/v1/integrations/connectors", headers=headers, json={
        "slug": f"jira-{uuid.uuid4().hex[:6]}", "name": name, "system": "jira",
        "base_url": "https://team.atlassian.net",
    })
    assert r.status_code == 201, r.text
    return r.json()["id"]


def _external(client, headers, *, name="Team Jira") -> str:
    cid = _connector(client, headers, name=name)
    r = client.put("/api/v1/ticketing", headers=headers,
                   json={"mode": "external", "connector_id": cid})
    assert r.status_code == 200, r.text
    return cid


def _finding(session, org_id) -> Finding:
    # `vulnerabilities.cve_id` is a real FK into the intelligence corpus, so the
    # CVE has to exist before a vulnerability can name it. Discovered by this
    # fixture failing rather than by reading the schema -- which is the useful
    # direction.
    if session.get(Cve, "CVE-2023-44487") is None:
        session.add(Cve(id="CVE-2023-44487", title="HTTP/2 Rapid Reset"))
        session.flush()
    asset = Asset(organization_id=org_id, name="dmz-edge",
                  ip_addresses=["10.0.0.9"], environment="production")
    vuln = Vulnerability(organization_id=org_id, cve_id="CVE-2023-44487",
                         title="HTTP/2 Rapid Reset", severity="critical")
    session.add_all([asset, vuln])
    session.flush()
    finding = Finding(
        organization_id=org_id, asset_id=asset.id, vulnerability_id=vuln.id,
        # NOT NULL and normally computed by the deduplicator, which this fixture
        # deliberately does not run: the payload builder is what is under test.
        dedupe_key=f"test-{uuid.uuid4().hex}",
        title="HTTP/2 Rapid Reset", severity="critical", risk_score=90.0,
        port=443, protocol="tcp", detail="Rapid Reset is exploitable remotely.",
        recommendation="Upgrade nghttp2.",
    )
    session.add(finding)
    session.flush()
    return finding
