"""Every audited write path, exercised over HTTP.

Why this file exists: audit.record() changed signature during Phase 5 and five
modules kept calling it with the old keywords. Nothing failed in CI because no
test posted to those endpoints — the bug only surfaced when a human clicked
"New asset" in the console and got HTTP 500. Unit tests that call services
directly cannot catch a broken handler; these do.

The assertion is deliberately blunt: a write endpoint may reject a request
(4xx is a legitimate answer), but it may never raise (5xx).
"""
from __future__ import annotations

import io

import pytest

from tests.conftest import _make_org, auth_headers


@pytest.fixture(scope="module")
def write_org():
    """One organization for the whole module.

    The per-test fixtures mint a fresh org and a fresh login each time; the
    production auth rate limit (10/min per IP, by design) then throttles the
    fixture itself rather than the code under test. One login, reused.
    """
    return _make_org("write-path")


@pytest.fixture(scope="module")
def admin(client_module, write_org):
    _, slug, email = write_org
    return auth_headers(client_module, email, slug)


@pytest.fixture(scope="module")
def client_module():
    from fastapi.testclient import TestClient
    from veyrs.main import app
    return TestClient(app)


def _asset(client_module, headers, name="wp-asset"):
    r = client_module.post("/api/v1/assets", headers=headers, json={
        "name": name, "hostname": f"{name}.example.internal",
        "ip_addresses": ["10.50.0.21"], "asset_type": "server",
        "criticality": "critical", "data_classification": "confidential",
        "exposure": "internet", "environment": "production",
    })
    assert r.status_code < 500, r.text
    return r


def test_asset_lifecycle_never_raises(client_module, admin):
    created = _asset(client_module, admin)
    assert created.status_code in (200, 201), created.text
    asset_id = created.json()["id"]

    got = client_module.get(f"/api/v1/assets/{asset_id}", headers=admin)
    assert got.status_code == 200, got.text
    assert got.json()["exposure"] == "internet"

    patched = client_module.patch(f"/api/v1/assets/{asset_id}", headers=admin,
                           json={"criticality": "low"})
    assert patched.status_code < 500, patched.text

    removed = client_module.delete(f"/api/v1/assets/{asset_id}", headers=admin)
    assert removed.status_code < 500, removed.text


def test_asset_create_writes_an_audit_entry(client_module, admin):
    """The audit row is the whole point of the call that used to blow up."""
    created = _asset(client_module, admin, name="wp-audited")
    assert created.status_code in (200, 201), created.text

    log = client_module.get("/api/v1/audit?limit=50", headers=admin)
    assert log.status_code == 200, log.text
    actions = [row["action"] for row in log.json()["items"]]
    assert "asset.create" in actions, actions

    client_module.delete(f"/api/v1/assets/{created.json()['id']}", headers=admin)


def test_ticket_create_and_transition_never_raise(client_module, admin):
    created = client_module.post("/api/v1/tickets", headers=admin, json={
        "title": "write-path probe", "ticket_type": "vulnerability_remediation",
        "priority": "high", "description": "created by the write-path guard",
    })
    assert created.status_code < 500, created.text
    if created.status_code >= 400:
        pytest.skip(f"ticket creation rejected: {created.text}")
    ticket = created.json()

    commented = client_module.post(f"/api/v1/tickets/{ticket['id']}/comments",
                            headers=admin, json={"body": "probe"})
    assert commented.status_code < 500, commented.text

    for state in ticket.get("allowed_transitions") or []:
        moved = client_module.post(f"/api/v1/tickets/{ticket['id']}/transition",
                            headers=admin, json={"state": state, "note": "probe",
                                                   "resolution": "probe"})
        assert moved.status_code < 500, f"{state}: {moved.text}"
        break


def test_sla_policy_write_never_raises(client_module, admin):
    created = client_module.post("/api/v1/policies/sla", headers=admin, json={
        "name": "write-path probe", "hours": 4, "priority": 10,
        "conditions": {"severity": "critical"},
    })
    assert created.status_code < 500, created.text
    if created.status_code < 400:
        pid = created.json().get("id")
        if pid:
            patched = client_module.patch(f"/api/v1/policies/sla/{pid}", headers=admin,
                                   json={"hours": 8})
            assert patched.status_code < 500, patched.text
            assert client_module.delete(f"/api/v1/policies/sla/{pid}",
                                 headers=admin).status_code < 500


def test_document_upload_never_raises(client_module, admin):
    payload = b"Fortinet advisory. CVE-2024-21762 affects FortiOS 7.4.2.\n"
    up = client_module.post(
        "/api/v1/documents", headers=admin,
        files={"file": ("advisory.txt", io.BytesIO(payload), "text/plain")},
    )
    assert up.status_code < 500, up.text
    if up.status_code < 400:
        doc_id = up.json().get("id")
        if doc_id:
            assert client_module.delete(f"/api/v1/documents/{doc_id}",
                                 headers=admin).status_code < 500


WRITE_PROBES = [
    ("POST", "/api/v1/knowledge", {"title": "probe", "body": "probe"}),
    ("POST", "/api/v1/teams", {"name": "write-path probe"}),
    ("POST", "/api/v1/departments", {"name": "write-path probe"}),
    ("POST", "/api/v1/api-keys", {"name": "write-path probe"}),
    ("POST", "/api/v1/risk/profiles", {"name": "probe", "weights": {"cvss": 1.0}}),
    ("POST", "/api/v1/intel/sources", {"name": "probe", "kind": "rss",
                                       "url": "https://example.invalid/feed.xml"}),
    ("POST", "/api/v1/workflows/seed", {}),
    ("POST", "/api/v1/policies/sla/evaluate", {}),
    ("POST", "/api/v1/risk/rescore", {}),
    ("POST", "/api/v1/notifications/dispatch", {}),
]


@pytest.mark.parametrize("method,path,body", WRITE_PROBES,
                         ids=[f"{m} {p}" for m, p, _ in WRITE_PROBES])
def test_write_endpoint_does_not_raise(client_module, admin, method, path, body):
    response = client_module.request(method, path, headers=admin, json=body)
    assert response.status_code < 500, f"{method} {path} -> {response.status_code}: {response.text}"
