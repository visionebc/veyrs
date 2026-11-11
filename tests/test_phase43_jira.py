"""Phase 43 -- the Jira connector nobody could configure, and its missing
monitoring leg.

The defects pinned here are all of the same shape: the code was present and
correct-looking, and the thing that reached the remote system was wrong. A
test that only asserted "a connector can be created" passed throughout.
"""
from __future__ import annotations

import base64
import pathlib
import types

import pytest

from veyrs.services import itsm

CONSOLE = pathlib.Path(__file__).resolve().parents[1] / "frontend/console/app.js"


def spec(credentials=None, mapping=None):
    return itsm.ConnectorSpec(
        slug="jira-sec", system="jira", base_url="https://team.atlassian.net/",
        credentials=credentials or {}, field_mapping=mapping or {},
    )


def basic(user, secret):
    return "Basic " + base64.b64encode(f"{user}:{secret}".encode()).decode()


# ---------------------------------------------------------------------------
# The credential
# ---------------------------------------------------------------------------
class TestCredentialDiscrimination:
    def test_cloud_is_email_plus_api_token_over_basic(self):
        headers = itsm.JiraAdapter()._headers(
            spec({"email": "you@example.com", "token": "atl-tok"}))
        assert headers["Authorization"] == basic("you@example.com", "atl-tok")

    def test_data_center_token_alone_is_a_bearer(self):
        headers = itsm.JiraAdapter()._headers(spec({"token": "pat-123"}))
        assert headers["Authorization"] == "Bearer pat-123"

    def test_username_and_password_is_basic(self):
        headers = itsm.JiraAdapter()._headers(
            spec({"username": "svc", "password": "pw"}))
        assert headers["Authorization"] == basic("svc", "pw")

    def test_an_unusable_credential_is_NAMED_not_silently_sent_as_empty(self):
        """The defect this whole phase starts from.

        The console posted {username, password}; the adapter looked for
        {email, token}; the fall-through built `Basic ` over an empty pair and
        sent it. Jira answered 401 and the operator blamed the password.
        """
        with pytest.raises(itsm.ItsmError) as exc:
            itsm.JiraAdapter()._headers(spec({"project_key": "SEC"}))
        message = str(exc.value)
        assert "email" in message and "token" in message and "username" in message
        # The exact header the old code produced, which must never appear again.
        assert basic("", "") == "Basic Og=="


# ---------------------------------------------------------------------------
# Cloud vs Data Center
# ---------------------------------------------------------------------------
class TestDeployment:
    def test_default_is_cloud_rest_v3(self):
        assert itsm.JiraAdapter()._api(spec(), "/issue") == \
            "https://team.atlassian.net/rest/api/3/issue"

    def test_data_center_is_rest_v2(self):
        assert itsm.JiraAdapter()._api(spec(mapping={"api_version": 2}), "/issue") == \
            "https://team.atlassian.net/rest/api/2/issue"

    def test_a_nonsense_version_falls_back_to_cloud_rather_than_building_a_404(self):
        assert itsm.JiraAdapter()._api(spec(mapping={"api_version": 99})) == \
            "https://team.atlassian.net/rest/api/3"

    def test_cloud_description_is_atlassian_document_format(self):
        body = itsm.JiraAdapter()._body(
            spec(), {"summary": "s", "description": "hello", "priority": "high"})
        assert body["fields"]["description"]["type"] == "doc"
        assert body["fields"]["description"]["content"][0]["content"][0]["text"] == "hello"

    def test_data_center_description_is_a_plain_string(self):
        body = itsm.JiraAdapter()._body(
            spec(mapping={"api_version": 2}),
            {"summary": "s", "description": "hello", "priority": "high"})
        assert body["fields"]["description"] == "hello"

    def test_an_empty_description_is_an_empty_DOCUMENT_not_an_empty_text_node(self):
        """An ADF text node with text:"" is a 400. A ticket with no description
        is ordinary, so this had to stop being encoded as one."""
        description = itsm.JiraAdapter()._body(
            spec(), {"summary": "s", "description": "", "priority": "low"}
        )["fields"]["description"]
        assert description == {"type": "doc", "version": 1, "content": []}

    def test_project_key_and_issue_type_come_from_the_field_mapping(self):
        body = itsm.JiraAdapter()._body(
            spec(mapping={"project_key": "VULN", "issue_type": "Bug"}),
            {"summary": "s", "description": "d", "priority": "high"})
        assert body["fields"]["project"] == {"key": "VULN"}
        assert body["fields"]["issuetype"] == {"name": "Bug"}


# ---------------------------------------------------------------------------
# The diagnosis
# ---------------------------------------------------------------------------
class FakeSession:
    def flush(self):
        pass


def connector(system="jira", **kw):
    row = types.SimpleNamespace(
        slug="c", system=system, base_url="https://team.atlassian.net",
        credentials_enc=None, field_mapping={}, last_error=None,
    )
    row.__dict__.update(kw)
    return row


class TestDiagnosis:
    def test_an_unsupported_system_is_a_named_step_not_an_exception(self):
        result = itsm.test_connector(FakeSession(), connector(system="notion"))
        assert result["ok"] is False
        assert result["steps"][0]["step"] == "adapter"
        assert result["steps"][0]["status"] == "failed"

    def test_a_missing_credential_is_named_before_anything_reaches_the_network(self):
        """`build_spec` cannot refuse this -- an unauthenticated webhook is
        legitimate -- so the step exists to stop a bare 401 from being the
        first thing the operator sees when nothing was ever saved."""
        result = itsm.test_connector(FakeSession(), connector(credentials_enc=None))
        steps = {s["step"]: s for s in result["steps"]}
        assert result["ok"] is False
        assert steps["credentials"]["status"] == "failed"
        assert "verify" not in steps and "authenticate" not in steps

    def test_a_webhook_with_no_credential_is_skipped_not_failed(self):
        result = itsm.test_connector(
            FakeSession(), connector(system="webhook", credentials_enc=None))
        steps = {s["step"]: s for s in result["steps"]}
        assert steps["credentials"]["status"] == "skipped"

    def test_a_verify_that_explodes_is_reported_never_raised(self, monkeypatch):
        """A test button that 500s is a test button nobody presses twice."""
        monkeypatch.setattr(itsm, "build_spec", lambda c: spec({"token": "t"}))

        class Boom:
            def verify(self, spec):
                raise ZeroDivisionError("boom")

        monkeypatch.setitem(itsm.ADAPTERS, "jira", Boom)
        result = itsm.test_connector(FakeSession(), connector(credentials_enc="x"))
        assert result["ok"] is False
        assert result["steps"][-1]["status"] == "failed"
        assert "ZeroDivisionError" in result["steps"][-1]["detail"]

    def test_a_webhook_is_SKIPPED_not_failed(self, monkeypatch):
        """A generic webhook has no read contract. Reporting that as a failure
        would make a correctly configured connector look broken."""
        monkeypatch.setattr(itsm, "build_spec",
                            lambda c: itsm.ConnectorSpec(
                                slug="w", system="webhook", base_url="https://x",
                                credentials={}, field_mapping={}))
        result = itsm.test_connector(
            FakeSession(), connector(system="webhook", credentials_enc="x"))
        assert result["ok"] is True
        assert result["steps"][-1]["status"] == "skipped"

    def test_jira_verify_checks_the_project_not_only_the_credential(self, monkeypatch):
        """A valid token pointed at a project that does not exist fails on the
        first real ticket, not on the button. That is the failure this step
        exists to move forward in time."""
        calls = []

        def fake_request(method, url, **kw):
            calls.append(url)
            if url.endswith("/myself"):
                return {"displayName": "VEYRS Bot"}
            raise itsm.ItsmError("remote returned HTTP 404")

        monkeypatch.setattr(itsm, "_request", fake_request)
        steps = itsm.JiraAdapter().verify(spec({"token": "t"},
                                               {"project_key": "NOPE"}))
        assert [s["status"] for s in steps] == ["ok", "failed"]
        assert "NOPE" in steps[1]["detail"]
        assert any(u.endswith("/project/NOPE") for u in calls)

    def test_a_wrong_issue_type_names_the_ones_that_exist(self, monkeypatch):
        def fake_request(method, url, **kw):
            if url.endswith("/myself"):
                return {"displayName": "VEYRS Bot"}
            return {"name": "Security", "issueTypes": [{"name": "Task"},
                                                       {"name": "Bug"}]}

        monkeypatch.setattr(itsm, "_request", fake_request)
        steps = itsm.JiraAdapter().verify(
            spec({"token": "t"}, {"project_key": "SEC", "issue_type": "Vulnerability"}))
        assert steps[-1]["status"] == "failed"
        assert "Bug" in steps[-1]["detail"] and "Task" in steps[-1]["detail"]


# ---------------------------------------------------------------------------
# The API surface
# ---------------------------------------------------------------------------
class TestRoutes:
    def _paths(self):
        from veyrs.api.v1.integrations import router
        return {r.path for r in router.routes}

    def test_the_polling_leg_finally_has_a_route(self):
        """`pull_status()` shipped with the ITSM leg and no endpoint ever
        called it, so a Jira Cloud tenant that cannot reach VEYRS had no way
        to learn a ticket had been closed."""
        assert "/integrations/connectors/{connector_id}/pull" in self._paths()

    def test_a_connector_can_be_tested_and_edited(self):
        paths = self._paths()
        assert "/integrations/connectors/{connector_id}/test" in paths
        assert "/integrations/connectors/{connector_id}" in paths

    def test_system_is_not_patchable(self):
        """The stored credential was entered for one system. Flipping the
        discriminator is how a ServiceNow password gets sent to Jira."""
        from veyrs.api.v1.integrations import ConnectorPatch
        assert "system" not in ConnectorPatch.model_fields
        assert "slug" not in ConnectorPatch.model_fields

    def test_omitted_credentials_mean_keep_not_erase(self):
        from veyrs.api.v1.integrations import ConnectorPatch
        assert ConnectorPatch().credentials is None
        assert "credentials" not in ConnectorPatch().model_dump(exclude_unset=True)

    def test_both_secret_flags_are_computed_not_left_at_false(self):
        """`inbound_secret_set` was declared when the inbound leg shipped and
        never populated, so it answered False for every connector that had a
        secret."""
        from veyrs.api.v1.integrations import _connector_out
        import uuid as _uuid
        row = types.SimpleNamespace(
            id=_uuid.uuid4(), slug="c", name="n", system="jira",
            base_url="https://x", is_enabled=True, ticket_types=[],
            field_mapping={}, last_sync_at=None, last_error=None,
            inbound_enabled=False, inbound_transitions={}, last_inbound_at=None,
            inbound_secret_enc="ciphertext", credentials_enc="ciphertext",
        )
        out = _connector_out(row)
        assert out.inbound_secret_set is True
        assert out.credentials_set is True

        row.inbound_secret_enc = None
        row.credentials_enc = None
        blank = _connector_out(row)
        assert blank.inbound_secret_set is False
        assert blank.credentials_set is False


# ---------------------------------------------------------------------------
# The console form -- source level, because the bug was in what it POSTed
# ---------------------------------------------------------------------------
class TestConsoleForm:
    def _source(self):
        return CONSOLE.read_text(encoding="utf-8")

    def test_the_form_asks_for_the_keys_the_jira_adapter_actually_reads(self):
        source = self._source()
        assert 'name="email"' in source
        assert 'name="token"' in source

    def test_credentials_are_built_from_all_four_keys_not_two(self):
        assert "['email', 'token', 'username', 'password']" in self._source()

    def test_the_project_key_is_sent_instead_of_defaulting_to_SEC(self):
        source = self._source()
        assert "fm.project_key = r.project_key" in source
        assert "fm.issue_type = r.issue_type" in source

    def test_the_deployment_selector_exists(self):
        assert 'name="api_version"' in self._source()

    def test_the_row_offers_test_edit_and_refresh(self):
        source = self._source()
        for hook in ("data-test=", "data-edit=", "data-pull="):
            assert hook in source, hook

    def test_editing_without_retyping_the_token_does_not_erase_it(self):
        """An empty credentials object would encrypt `{}` over the stored
        token and the connector would start failing for a reason nobody
        chose."""
        assert "if (Object.keys(credentials).length) body.credentials = credentials;" \
            in self._source()
