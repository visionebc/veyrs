"""Phase 44 -- publishing VEYRS runbooks into Confluence.

The invariant under everything here: **VEYRS is the system of record for the
runbook, Confluence is where people read it.** Publishing is one-way and
idempotent. Nothing is pulled back, because a wiki page anybody can edit is not
a source of truth for a security procedure.
"""
from __future__ import annotations

import json
import uuid

import pytest

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import ItsmConnector
from veyrs.models.knowledge import KnowledgeArticle
from veyrs.services import docs
from veyrs.security.secrets import encrypt
from veyrs.services.itsm import ConnectorSpec, ItsmError


_UNSET = object()


def spec(credentials=None, mapping=_UNSET, base="https://acme.atlassian.net"):
    """`mapping={}` must mean "no space configured", so the default is a
    sentinel and not `or`. With `or`, an empty dict fell through to the default
    and the test that meant to check the refusal made a REAL network call to
    acme.atlassian.net and asserted on its 401."""
    return ConnectorSpec(slug="wiki", system="confluence", base_url=base,
                         credentials=credentials or {"email": "a@b.c", "token": "t"},
                         field_mapping=({"space_key": "SEC"} if mapping is _UNSET
                                        else mapping))


# ---------------------------------------------------------------------------
# Markdown -> storage
# ---------------------------------------------------------------------------
class TestStorageFormat:
    def test_headings_paragraphs_and_lists(self):
        out = docs.markdown_to_storage(
            "# Title\n\nA line.\n\n- one\n- two\n\n1. first\n2. second\n")
        assert "<h1>Title</h1>" in out
        assert "<p>A line.</p>" in out
        assert "<ul><li>one</li><li>two</li></ul>" in out
        assert "<ol><li>first</li><li>second</li></ol>" in out

    def test_a_fenced_block_becomes_the_code_macro_not_pre(self):
        out = docs.markdown_to_storage("```bash\nrm -rf /tmp/x\n```")
        assert 'ac:name="code"' in out
        assert 'ac:name="language">bash' in out
        assert "rm -rf /tmp/x" in out
        # <pre> renders without highlighting and some themes strip it.
        assert "<pre>" not in out

    def test_a_runbook_that_quotes_a_payload_is_escaped_not_injected(self):
        """Runbooks quote payloads. This is not a theoretical input."""
        out = docs.markdown_to_storage("Try <script>alert(1)</script> against it.")
        assert "&lt;script&gt;" in out
        assert "<script>" not in out

    def test_escaping_happens_before_formatting_not_after(self):
        """Escaping last would turn our own <strong> into &lt;strong&gt;."""
        out = docs.markdown_to_storage("**bold** and `code` and *it*")
        assert "<strong>bold</strong>" in out
        assert "<code>code</code>" in out
        assert "<em>it</em>" in out

    def test_links_keep_their_href(self):
        out = docs.markdown_to_storage("See [the advisory](https://x.test/a?b=1).")
        assert '<a href="https://x.test/a?b=1">the advisory</a>' in out

    def test_an_unterminated_fence_does_not_lose_the_rest_of_the_runbook(self):
        out = docs.markdown_to_storage("```\nstep one\nstep two")
        assert "step one" in out and "step two" in out

    def test_the_supported_subset_is_stated_rather_than_implied(self):
        """An operator whose table came out as a paragraph is owed the list."""
        assert "headings" in docs.SUPPORTED_MARKDOWN
        assert "code" in docs.SUPPORTED_MARKDOWN


# ---------------------------------------------------------------------------
# Cloud vs Data Center
# ---------------------------------------------------------------------------
class TestDeployment:
    def test_wiki_is_appended_for_cloud_because_nobody_types_it(self):
        """The URL in the operator's address bar has no /wiki on it."""
        url = docs.ConfluenceAdapter()._api(spec(), "/content")
        assert url == "https://acme.atlassian.net/wiki/rest/api/content"

    def test_wiki_is_not_appended_twice(self):
        url = docs.ConfluenceAdapter()._api(
            spec(base="https://acme.atlassian.net/wiki"), "/content")
        assert url == "https://acme.atlassian.net/wiki/rest/api/content"

    def test_data_center_has_no_wiki_segment(self):
        url = docs.ConfluenceAdapter()._api(
            spec(base="https://wiki.acme.internal"), "/content")
        assert url == "https://wiki.acme.internal/rest/api/content"

    def test_the_operator_can_override_the_inference(self):
        url = docs.ConfluenceAdapter()._api(
            spec(base="https://acme.atlassian.net",
                 mapping={"space_key": "SEC", "deployment": "datacenter"}), "/content")
        assert "/wiki" not in url

    def test_the_v1_content_api_is_used_so_data_center_is_supportable(self):
        """v2 is Cloud only. Choosing it would repeat the Jira DC mistake."""
        assert "/rest/api/content" in docs.ConfluenceAdapter()._api(spec(), "/content")
        assert "/api/v2/" not in docs.ConfluenceAdapter()._api(spec(), "/content")


class TestCredentials:
    def test_cloud_is_email_plus_token_over_basic(self):
        h = docs.ConfluenceAdapter()._headers(spec({"email": "you@x.test", "token": "tok"}))
        assert h["Authorization"].startswith("Basic ")

    def test_data_center_token_alone_is_a_bearer(self):
        h = docs.ConfluenceAdapter()._headers(spec({"token": "pat-1"}))
        assert h["Authorization"] == "Bearer pat-1"

    def test_an_unusable_credential_is_NAMED_not_sent_as_an_empty_basic(self):
        """The 0.28.0 Jira defect, which must not reappear in a second adapter."""
        with pytest.raises(ItsmError) as exc:
            docs.ConfluenceAdapter()._headers(spec({"space_key": "SEC"}))
        message = str(exc.value)
        assert "email" in message and "token" in message and "username" in message


# ---------------------------------------------------------------------------
# The version number -- the headline Confluence gotcha
# ---------------------------------------------------------------------------
class TestVersioning:
    def test_update_reads_the_CURRENT_version_and_writes_it_plus_one(self, monkeypatch):
        """Deriving it from KnowledgeArticle.version works exactly until
        somebody edits the page in Confluence -- after which every publish 409s
        forever and the error says nothing about why.
        """
        sent: dict = {}

        def fake_request(method, url, *, headers, json_body, timeout):
            if method == "GET":
                return {"id": "77", "title": "Runbook", "version": {"number": 9},
                        "space": {"key": "SEC"},
                        "_links": {"base": "https://acme.atlassian.net/wiki",
                                   "webui": "/pages/77"}}
            sent.update(json_body or {})
            return {"id": "77", "title": "Runbook", "version": {"number": 10},
                    "space": {"key": "SEC"},
                    "_links": {"base": "https://acme.atlassian.net/wiki",
                               "webui": "/pages/77"}}

        monkeypatch.setattr(docs, "_request", fake_request)
        docs.ConfluenceAdapter().update(spec(), "77",
                                        {"title": "Runbook", "storage": "<p>x</p>"})
        assert sent["version"]["number"] == 10, (
            "the page was at version 9; Confluence rejects anything but 10")

    def test_creating_without_a_space_is_named_not_a_400_from_the_wiki(self):
        with pytest.raises(ItsmError) as exc:
            docs.ConfluenceAdapter().create(spec(mapping={}), {"title": "x", "storage": ""})
        assert "space_key" in str(exc.value)


# ---------------------------------------------------------------------------
# Publishing
# ---------------------------------------------------------------------------
class TestPublishing:
    def test_the_page_says_veyrs_is_the_system_of_record(self):
        """Without the footer, the first person to edit the wiki page has
        silently forked the runbook and nobody can tell."""
        article = KnowledgeArticle(
            organization_id=uuid.uuid4(), slug="patch-nginx", title="Patch nginx",
            body="# Steps\n\n- upgrade\n", version=3, kind="runbook")
        payload = docs.article_payload(article)
        assert "system of record" in payload["storage"]
        assert "patch-nginx" in payload["storage"]
        assert "not read back" in payload["storage"]

    def test_a_ticketing_connector_is_refused_by_name(self, org_a):
        org_id, _, _ = org_a
        with SessionLocal() as session:
            set_tenant(session, org_id)
            connector = ItsmConnector(organization_id=org_id, slug="jira",
                                      name="Jira", system="jira",
                                      base_url="https://x.atlassian.net")
            article = KnowledgeArticle(organization_id=org_id, slug="s", title="t",
                                       body="b")
            session.add_all([connector, article])
            session.flush()
            with pytest.raises(docs.DocsError) as exc:
                docs.publish_article(session, connector, article)
            assert "not a documentation one" in str(exc.value)

    def test_republishing_an_unchanged_article_is_a_no_op(self, org_a, monkeypatch):
        """Without the digest guard a scheduled publish buries the page's real
        edits under hundreds of empty revisions."""
        calls = {"n": 0}

        def fake_request(method, url, *, headers, json_body, timeout):
            calls["n"] += 1
            return {"id": "5", "title": "t", "version": {"number": 1},
                    "space": {"key": "SEC"},
                    "_links": {"base": "https://x/wiki", "webui": "/p/5"}}

        monkeypatch.setattr(docs, "_request", fake_request)
        org_id, _, _ = org_a
        with SessionLocal() as session:
            set_tenant(session, org_id)
            connector = ItsmConnector(
                organization_id=org_id, slug="wiki", name="Wiki", system="confluence",
                base_url="https://x.atlassian.net", field_mapping={"space_key": "SEC"},
                credentials_enc=encrypt(json.dumps({"email": "a@b.c", "token": "t"})))
            article = KnowledgeArticle(organization_id=org_id, slug="s2", title="t",
                                       body="b")
            session.add_all([connector, article])
            session.flush()

            first = docs.publish_article(session, connector, article)
            after_first = calls["n"]
            second = docs.publish_article(session, connector, article)

            assert second.id == first.id
            assert calls["n"] == after_first, "an unchanged article was re-sent"
            assert first.object_type == "knowledge"
            assert first.remote_id == "5"
            assert first.remote_key == "SEC"


# ---------------------------------------------------------------------------
# Routes
# ---------------------------------------------------------------------------
class TestRoutes:
    def test_publishing_with_no_connector_is_409_and_says_where_to_go(
            self, client, admin_a):
        made = client.post("/api/v1/knowledge", headers=admin_a, json={
            "slug": f"rb-{uuid.uuid4().hex[:6]}", "title": "Runbook", "body": "# x"})
        assert made.status_code in (200, 201), made.text
        r = client.post(f"/api/v1/knowledge/{made.json()['id']}/publish", headers=admin_a)
        assert r.status_code == 409, r.text
        assert "Integrations" in r.json()["detail"]

    def test_two_connectors_refuse_to_guess_which_space(self, client, admin_a):
        for n in range(2):
            assert client.post("/api/v1/integrations/connectors", headers=admin_a, json={
                "slug": f"wiki-{n}-{uuid.uuid4().hex[:4]}", "name": f"Wiki {n}",
                "system": "confluence", "base_url": "https://x.atlassian.net",
                "field_mapping": {"space_key": f"S{n}"},
            }).status_code == 201
        made = client.post("/api/v1/knowledge", headers=admin_a, json={
            "slug": f"rb-{uuid.uuid4().hex[:6]}", "title": "Runbook", "body": "# x"})
        r = client.post(f"/api/v1/knowledge/{made.json()['id']}/publish", headers=admin_a)
        # Publishing a runbook into the wrong space is not something an
        # operator finds out about quickly.
        assert r.status_code == 409
        assert "connector_id" in r.json()["detail"]

    def test_ready_is_not_merely_a_row_existing(self, client, admin_a):
        """The phase 42 lesson, applied before it could be repeated.

        A connector with no credential and no space reported ready, and
        pressing Publish surfaced the wiki's bare 403 -- which reads as "the
        wiki is broken", not "you never gave VEYRS a token".
        """
        assert client.post("/api/v1/integrations/connectors", headers=admin_a, json={
            "slug": f"wiki-bare-{uuid.uuid4().hex[:4]}", "name": "Bare",
            "system": "confluence", "base_url": "https://x.atlassian.net",
        }).status_code == 201
        state = client.get("/api/v1/knowledge-publishing", headers=admin_a).json()
        assert state["ready"] is False
        row = next(c for c in state["connectors"] if c["name"] == "Bare")
        assert row["credentials_set"] is False and row["space_key"] is None
        # Listed anyway, with the gap visible, rather than hidden.
        assert row["usable"] is False

    def test_the_connector_list_is_split_server_side(self, client, admin_a):
        slug = f"wiki-{uuid.uuid4().hex[:6]}"
        client.post("/api/v1/integrations/connectors", headers=admin_a, json={
            "slug": slug, "name": "Wiki", "system": "confluence",
            "base_url": "https://x.atlassian.net"})
        client.post("/api/v1/integrations/connectors", headers=admin_a, json={
            "slug": f"jira-{uuid.uuid4().hex[:6]}", "name": "Jira", "system": "jira",
            "base_url": "https://x.atlassian.net"})
        docs_only = client.get("/api/v1/integrations/connectors?purpose=documentation",
                               headers=admin_a).json()
        tickets_only = client.get("/api/v1/integrations/connectors?purpose=ticketing",
                                  headers=admin_a).json()
        assert {c["system"] for c in docs_only} == {"confluence"}
        assert "confluence" not in {c["system"] for c in tickets_only}
        # Default stays the whole list, so every existing caller is unaffected.
        every = client.get("/api/v1/integrations/connectors", headers=admin_a).json()
        assert len(every) >= len(docs_only) + len(tickets_only)

    def test_a_confluence_connector_can_be_created_at_all(self, client, admin_a):
        """`create_connector` validated `system in itsm.ADAPTERS`, so before
        this phase the answer was a 422."""
        r = client.post("/api/v1/integrations/connectors", headers=admin_a, json={
            "slug": f"c-{uuid.uuid4().hex[:6]}", "name": "C", "system": "confluence",
            "base_url": "https://x.atlassian.net"})
        assert r.status_code == 201, r.text
