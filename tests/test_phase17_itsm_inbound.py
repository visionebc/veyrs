"""Phase 17: inbound ITSM events (the return leg of the sync).

Three things are worth breaking a build over.

**The signature is the only credential.** No token, no session. So the tests
cover a missing signature, a wrong one, a replayed one and a body altered after
signing - each of which must be refused before anything is written.

**An external system still cannot close a security finding.** That policy was
already stated in `itsm.pull_status` and it survives here: an inbound status is
advisory unless an operator configured `inbound_transitions`, and even then the
ticket state machine still governs. `test_an_unmapped_remote_closure_changes_
nothing` is that guarantee.

**The endpoint is not a tenant oracle.** Unknown org, unknown connector and
inbound-disabled connector all answer the same 404, so the URL cannot be used to
enumerate customers.
"""
from __future__ import annotations

import json
import time
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import ItsmConnector, Ticket, TicketEvent
from veyrs.models.integration import ExternalLink
from veyrs.security.secrets import encrypt
from veyrs.services import itsm_inbound, ticketing

SECRET = "test-inbound-secret-0123456789"


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def wired(org_a):
    """A connector with inbound enabled, and a ticket already pushed to it."""
    org_id, slug, email = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        connector = ItsmConnector(
            organization_id=org_id, slug="jira-main", name="Jira", system="jira",
            base_url="https://jira.example.com",
            credentials_enc=encrypt(json.dumps({"email": "a@b.c", "token": "t"})),
            inbound_enabled=True,
            inbound_secret_enc=encrypt(SECRET),
            inbound_transitions={},
        )
        session.add(connector)
        session.flush()
        ticket = ticketing.create_ticket(
            session, organization_id=org_id, title="Patch the edge firewall",
            description="CVE-2026-0001", ticket_type="remediation", priority="critical",
        )
        link = ExternalLink(
            organization_id=org_id, connector_id=connector.id, object_type="ticket",
            object_id=str(ticket.id), remote_id="10042", remote_key="SEC-42",
            remote_url="https://jira.example.com/browse/SEC-42", remote_status="In Progress",
        )
        session.add(link)
        session.commit()
        return {"org_id": org_id, "slug": slug, "email": email,
                "connector_id": connector.id, "ticket_id": ticket.id,
                "remote_id": "10042"}


def jira_body(status: str = "Done", comment: str | None = None) -> bytes:
    body = {
        "webhookEvent": "jira:issue_updated",
        "user": {"displayName": "R. Engineer"},
        "issue": {"id": "10042", "key": "SEC-42",
                  "fields": {"status": {"name": status}}},
    }
    if comment:
        body["comment"] = {"body": comment, "author": {"displayName": "R. Engineer"}}
    return json.dumps(body).encode()


def signed(body: bytes, secret: str = SECRET, skew: float = 0.0) -> dict[str, str]:
    timestamp = str(int(time.time() + skew))
    return {"X-VEYRS-Signature": itsm_inbound.sign(secret, timestamp, body),
            "X-VEYRS-Timestamp": timestamp}


def _events(session, ticket) -> list[str]:
    """Ticket history. `Ticket` has no `events` relationship - the table is
    append-only and read by query, so nothing lazy-loads a growing log."""
    return list(session.execute(
        select(TicketEvent.event)
        .where(TicketEvent.ticket_id == ticket.id)
        .order_by(TicketEvent.created_at)
    ).scalars().all())


def _url(wired, org_slug: str | None = None, connector: str = "jira-main") -> str:
    return f"/api/v1/integrations/itsm/{org_slug or wired['slug']}/{connector}/inbound"


# ---------------------------------------------------------------------------
# 1. The signature is the only credential
# ---------------------------------------------------------------------------
def test_an_unsigned_request_is_refused(client, wired):
    body = jira_body()
    assert client.post(_url(wired), content=body).status_code == 401


def test_a_wrong_secret_is_refused(client, wired):
    body = jira_body()
    response = client.post(_url(wired), content=body,
                           headers=signed(body, secret="not-the-secret"))
    assert response.status_code == 401
    assert "signature mismatch" in response.json()["detail"]


def test_a_body_altered_after_signing_is_refused(client, wired):
    headers = signed(jira_body("Done"))
    tampered = jira_body("Closed")
    assert client.post(_url(wired), content=tampered, headers=headers).status_code == 401


@pytest.mark.parametrize("skew", [-3600, 3600])
def test_a_replayed_or_future_timestamp_is_refused(client, wired, skew):
    """Without the window, a captured request stays valid forever."""
    body = jira_body()
    response = client.post(_url(wired), content=body, headers=signed(body, skew=skew))
    assert response.status_code == 401
    assert "replay window" in response.json()["detail"]


def test_the_signature_covers_the_timestamp_not_just_the_body(client, wired):
    """Swapping in a fresh timestamp must invalidate an old signature."""
    body = jira_body()
    headers = signed(body)
    headers["X-VEYRS-Timestamp"] = str(int(time.time()) - 1)
    assert client.post(_url(wired), content=body, headers=headers).status_code == 401


# ---------------------------------------------------------------------------
# 2. The endpoint is not a tenant oracle
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("org_slug,connector", [
    ("no-such-tenant", "jira-main"),
    (None, "no-such-connector"),
])
def test_unknown_endpoints_are_indistinguishable(client, wired, org_slug, connector):
    body = jira_body()
    response = client.post(_url(wired, org_slug, connector), content=body,
                           headers=signed(body))
    assert response.status_code == 404
    assert response.json()["detail"] == "unknown webhook endpoint"


def test_a_connector_with_inbound_disabled_looks_like_it_does_not_exist(client, wired):
    with SessionLocal() as session:
        set_tenant(session, wired["org_id"])
        session.get(ItsmConnector, wired["connector_id"]).inbound_enabled = False
        session.commit()
    body = jira_body()
    response = client.post(_url(wired), content=body, headers=signed(body))
    assert response.status_code == 404
    assert response.json()["detail"] == "unknown webhook endpoint"


# ---------------------------------------------------------------------------
# 3. Advisory by default - an external system cannot close a finding
# ---------------------------------------------------------------------------
def test_an_unmapped_remote_closure_changes_nothing(client, wired):
    """THE guarantee. Jira says Done; VEYRS records it and does not move."""
    body = jira_body("Done")
    response = client.post(_url(wired), content=body, headers=signed(body))
    assert response.status_code == 200, response.text
    outcome = response.json()
    assert outcome["advisory_only"] is True
    assert outcome["state_changed"] is False
    assert outcome["status"] == "Done"

    with SessionLocal() as session:
        set_tenant(session, wired["org_id"])
        ticket = session.get(Ticket, wired["ticket_id"])
        assert ticket.state == "open", "an unmapped remote status must not move the ticket"
        link = session.execute(
            select(ExternalLink).where(ExternalLink.remote_id == wired["remote_id"])
        ).scalars().one()
        assert link.remote_status == "Done", "...but it IS recorded"
        assert link.last_pulled_at is not None
        events = _events(session, ticket)
        assert "remote_status_changed" in events, (
            "an ignored status must still be visible, or the operator never "
            "discovers the mapping they meant to configure"
        )


def test_a_configured_mapping_moves_the_ticket(client, wired):
    with SessionLocal() as session:
        set_tenant(session, wired["org_id"])
        connector = session.get(ItsmConnector, wired["connector_id"])
        connector.inbound_transitions = {"In Progress": "in_progress", "Done": "resolved"}
        session.commit()

    body = jira_body("In Progress")
    outcome = client.post(_url(wired), content=body, headers=signed(body)).json()
    assert outcome["advisory_only"] is False
    assert outcome["state_changed"] is True and outcome["new_state"] == "in_progress"

    with SessionLocal() as session:
        set_tenant(session, wired["org_id"])
        assert session.get(Ticket, wired["ticket_id"]).state == "in_progress"


def test_the_ticket_state_machine_still_governs(client, wired):
    """A remote system that jumps to a state VEYRS forbids from here is
    recorded and refused, not forced."""
    with SessionLocal() as session:
        set_tenant(session, wired["org_id"])
        session.get(ItsmConnector, wired["connector_id"]).inbound_transitions = {
            "Reopened": "verifying"}   # open -> verifying is not an allowed edge
        session.commit()

    body = jira_body("Reopened")
    outcome = client.post(_url(wired), content=body, headers=signed(body)).json()
    assert outcome["state_changed"] is False
    assert "not an allowed transition" in outcome["refused"]

    with SessionLocal() as session:
        set_tenant(session, wired["org_id"])
        ticket = session.get(Ticket, wired["ticket_id"])
        assert ticket.state == "open"
        assert "remote_transition_refused" in _events(session, ticket)


def test_replaying_the_same_event_is_idempotent(client, wired):
    with SessionLocal() as session:
        set_tenant(session, wired["org_id"])
        session.get(ItsmConnector, wired["connector_id"]).inbound_transitions = {
            "In Progress": "in_progress"}
        session.commit()

    for _ in range(3):
        body = jira_body("In Progress")
        assert client.post(_url(wired), content=body, headers=signed(body)).status_code == 200

    with SessionLocal() as session:
        set_tenant(session, wired["org_id"])
        ticket = session.get(Ticket, wired["ticket_id"])
        assert ticket.state == "in_progress"
        changes = [e for e in _events(session, ticket) if e == "state_changed"]
        assert len(changes) == 1, "a replayed event must not re-emit the transition"


# ---------------------------------------------------------------------------
# 4. Comments and unlinked records
# ---------------------------------------------------------------------------
def test_remote_comments_land_on_the_ticket(client, wired):
    body = jira_body("In Progress", comment="Patched in change CHG0031.")
    assert client.post(_url(wired), content=body, headers=signed(body)).json()[
        "comments_added"] == 1
    with SessionLocal() as session:
        set_tenant(session, wired["org_id"])
        ticket = session.get(Ticket, wired["ticket_id"])
        comment = ticket.comments[-1]
        assert comment.body == "Patched in change CHG0031."
        assert comment.author_label.startswith("jira:")


def test_an_unlinked_remote_record_is_refused_not_invented(client, wired):
    """VEYRS only tracks twins it pushed itself. Creating one from an inbound
    event would let a signed webhook manufacture tickets."""
    body = json.dumps({"webhookEvent": "jira:issue_updated",
                       "issue": {"id": "99999", "key": "OPS-1",
                                 "fields": {"status": {"name": "Done"}}}}).encode()
    response = client.post(_url(wired), content=body, headers=signed(body))
    assert response.status_code == 422
    assert "no VEYRS object is linked" in response.json()["detail"]


def test_a_payload_with_no_remote_id_is_refused(client, wired):
    body = json.dumps({"webhookEvent": "jira:issue_updated", "issue": {}}).encode()
    response = client.post(_url(wired), content=body, headers=signed(body))
    assert response.status_code == 422
    assert "remote id" in response.json()["detail"]


# ---------------------------------------------------------------------------
# 5. Vendor payload shapes
# ---------------------------------------------------------------------------
def test_servicenow_flat_and_wrapped_shapes_both_parse():
    connector = ItsmConnector(slug="sn", name="SN", system="servicenow")
    flat = itsm_inbound.parse_inbound(
        connector, json.dumps({"sys_id": "abc", "state": "6", "number": "INC0011",
                               "comments": "done", "sys_updated_by": "jdoe"}).encode())
    assert (flat.remote_id, flat.status, flat.remote_key) == ("abc", "6", "INC0011")
    assert flat.comments[0]["body"] == "done" and flat.actor == "jdoe"

    wrapped = itsm_inbound.parse_inbound(
        connector, json.dumps({"result": {"sys_id": "abc", "state": "7"}}).encode())
    assert (wrapped.remote_id, wrapped.status) == ("abc", "7")


def test_the_generic_shape_accepts_strings_or_objects_for_comments():
    connector = ItsmConnector(slug="w", name="W", system="webhook")
    event = itsm_inbound.parse_inbound(connector, json.dumps({
        "remote_id": "r1", "status": "closed",
        "comments": ["plain string", {"body": "structured", "author": "ops"}],
    }).encode())
    assert [c["body"] for c in event.comments] == ["plain string", "structured"]
    assert event.comments[1]["author"] == "ops"


def test_status_matching_ignores_case_and_separators():
    connector = ItsmConnector(slug="w", name="W", system="webhook",
                              inbound_transitions={"In Progress": "in_progress"})
    for spelling in ("in progress", "IN_PROGRESS", "  In   Progress "):
        assert itsm_inbound.mapped_state(connector, spelling) == "in_progress", spelling
    assert itsm_inbound.mapped_state(connector, "Done") is None
    assert itsm_inbound.mapped_state(connector, None) is None


def test_a_connector_with_no_secret_cannot_be_signed_for():
    connector = ItsmConnector(slug="w", name="W", system="webhook", inbound_secret_enc=None)
    with pytest.raises(itsm_inbound.InboundError) as exc:
        itsm_inbound.verify_signature(connector, body=b"{}", signature="sha256=x",
                                      timestamp=str(int(time.time())))
    assert "no inbound secret" in str(exc.value)


# ---------------------------------------------------------------------------
# 6. Secret provisioning
# ---------------------------------------------------------------------------
def test_the_secret_is_minted_once_and_never_listed(client, wired, admin_a):
    connector_id = wired["connector_id"]
    minted = client.post(f"/api/v1/integrations/connectors/{connector_id}/inbound-secret",
                         headers=admin_a)
    assert minted.status_code == 200, minted.text
    body = minted.json()
    assert len(body["secret"]) > 30
    assert body["webhook_url"].endswith(
        f"/api/v1/integrations/itsm/{wired['slug']}/jira-main/inbound")

    listed = client.get("/api/v1/integrations/connectors", headers=admin_a).json()
    serialised = json.dumps(listed)
    assert body["secret"] not in serialised
    assert "inbound_secret_enc" not in serialised
    assert any(c["inbound_enabled"] for c in listed)

    # The freshly minted secret is the one the endpoint now verifies against.
    payload = jira_body("Done")
    assert client.post(_url(wired), content=payload,
                       headers=signed(payload, secret=body["secret"])).status_code == 200
    assert client.post(_url(wired), content=payload,
                       headers=signed(payload, secret=SECRET)).status_code == 401


def test_rotating_a_secret_needs_ticket_admin(client, wired, admin_b):
    response = client.post(
        f"/api/v1/integrations/connectors/{wired['connector_id']}/inbound-secret",
        headers=admin_b)
    assert response.status_code == 404, "another tenant's connector is not addressable"
