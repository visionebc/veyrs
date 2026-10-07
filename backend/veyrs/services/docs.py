"""Confluence: publishing VEYRS runbooks into the wiki the organisation reads.

Design position, and it is the same one the ITSM module takes about tickets:
**VEYRS is the system of record for the runbook.** Confluence is where people
read it. So publishing is one-way and idempotent -- edit the article in VEYRS,
press Publish, and the same page is updated rather than a second one appearing.
Nothing is ever pulled back, because a wiki page anybody can edit is not a
source of truth for a security procedure; if it were, "who changed the
remediation steps for CVE-2023-44487?" would have no answer.

`ExternalLink` is the mirror, with `object_type = "knowledge"` -- the same
correspondence table Jira issues use, for the same reason: one article can be
mirrored into more than one space without either being "the" page id.

Three things about Confluence that are easy to get wrong and that this module
gets right on purpose:

**1. The version number is Confluence's, not ours.** Updating a page requires
`version.number` to be *exactly* the current version plus one. Using
`KnowledgeArticle.version` would work until somebody edits the page inside
Confluence, at which point every publish 409s forever and the operator has no
way to see why. So the current version is READ immediately before the write.

**2. `/wiki` is part of the Cloud path and not of the Data Center one.** An
operator who pastes `https://acme.atlassian.net` -- the URL in their address
bar -- gets a 404 on every call unless we add it. It is appended for Cloud
rather than demanded of the operator, because "your base URL needs a suffix you
have never typed" is a support ticket, not a configuration.

**3. The v1 content API is used, not v2.** v2 (`/wiki/api/v2/pages`) is Cloud
only; v1 (`/rest/api/content`) has the same path shape on both deployments and
supports `body.storage`, `ancestors` and `expand=version`. Picking the newer one
would have made Data Center unsupportable -- the exact mistake that made Jira
Data Center unsupported until 0.28.0.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import hashlib
import html
import json
import logging
import re
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.integration import ExternalLink
from ..models.knowledge import KnowledgeArticle
from ..models.ticketing import ItsmConnector
from .itsm import ConnectorSpec, ItsmError, _basic_auth, _request, _step, build_spec

log = logging.getLogger("veyrs.docs")

#: Connector `system` values this module owns. Kept as a set rather than a
#: single string so a second wiki (Notion, BookStack) is a row here and not a
#: new discriminator invented at three call sites.
DOCS_SYSTEMS = frozenset({"confluence"})


class DocsError(ItsmError):
    """The wiki refused us. Never surfaced with the response body."""


@dataclasses.dataclass(frozen=True)
class RemotePage:
    page_id: str
    title: str | None = None
    url: str | None = None
    version: int | None = None
    space_key: str | None = None


# ---------------------------------------------------------------------------
# Markdown -> Confluence storage format
# ---------------------------------------------------------------------------
#: What this converter handles. Named here rather than left for the reader to
#: infer from the regexes, because the honest thing to tell an operator whose
#: table came out as a paragraph is WHICH subset is supported -- not "markdown".
SUPPORTED_MARKDOWN = (
    "headings (# to ######), paragraphs, unordered and ordered lists, fenced "
    "code blocks, inline code, bold, italic and links"
)

_FENCE = re.compile(r"^```(\w*)\s*$")
_HEADING = re.compile(r"^(#{1,6})\s+(.*)$")
_UL = re.compile(r"^\s*[-*+]\s+(.*)$")
_OL = re.compile(r"^\s*\d+[.)]\s+(.*)$")


def _inline(text: str) -> str:
    """Escape first, then re-introduce the few tags we mean. Order matters.

    Escaping after formatting would turn our own `<strong>` into `&lt;strong&gt;`;
    escaping only the input would let a runbook containing `<script>` reach the
    wiki as markup. Neither is theoretical: runbooks quote payloads.
    """
    out = html.escape(text, quote=False)
    out = re.sub(r"`([^`]+)`", r"<code>\1</code>", out)
    out = re.sub(r"\*\*([^*]+)\*\*", r"<strong>\1</strong>", out)
    out = re.sub(r"(?<!\*)\*([^*\n]+)\*(?!\*)", r"<em>\1</em>", out)
    out = re.sub(
        r"\[([^\]]+)\]\((https?://[^)\s]+)\)",
        lambda m: f'<a href="{html.escape(m.group(2), quote=True)}">{m.group(1)}</a>',
        out,
    )
    return out


def markdown_to_storage(text: str) -> str:
    """A documented SUBSET of Markdown, rendered as Confluence storage format.

    Not a full Markdown implementation and not pretending to be one. Tables,
    blockquotes, images and nested lists are passed through as paragraphs --
    the text survives, the formatting does not. `SUPPORTED_MARKDOWN` says so,
    and the console prints it next to the Publish button, because a runbook
    that arrives subtly reformatted is worse than one that arrives plainly.
    """
    lines = (text or "").replace("\r\n", "\n").split("\n")
    out: list[str] = []
    para: list[str] = []
    items: list[str] = []
    list_tag = ""
    code: list[str] | None = None
    code_lang = ""

    def flush_para() -> None:
        nonlocal para
        if para:
            out.append("<p>" + _inline(" ".join(para)) + "</p>")
            para = []

    def flush_list() -> None:
        nonlocal items, list_tag
        if items:
            out.append(f"<{list_tag}>" + "".join(
                f"<li>{_inline(i)}</li>" for i in items) + f"</{list_tag}>")
            items = []
            list_tag = ""

    for line in lines:
        fence = _FENCE.match(line)
        if fence:
            if code is None:
                flush_para(); flush_list()
                code, code_lang = [], fence.group(1)
            else:
                # The code macro, not <pre>: Confluence renders <pre> without
                # highlighting and strips it on some themes.
                body = html.escape("\n".join(code), quote=False)
                lang = f'<ac:parameter ac:name="language">{html.escape(code_lang)}</ac:parameter>' if code_lang else ""
                out.append(
                    '<ac:structured-macro ac:name="code">' + lang
                    + f"<ac:plain-text-body><![CDATA[{body}]]></ac:plain-text-body>"
                    "</ac:structured-macro>")
                code, code_lang = None, ""
            continue
        if code is not None:
            code.append(line)
            continue

        heading = _HEADING.match(line)
        if heading:
            flush_para(); flush_list()
            level = min(len(heading.group(1)), 6)
            out.append(f"<h{level}>{_inline(heading.group(2))}</h{level}>")
            continue

        ul, ol = _UL.match(line), _OL.match(line)
        if ul or ol:
            flush_para()
            tag = "ul" if ul else "ol"
            if list_tag and list_tag != tag:
                flush_list()
            list_tag = tag
            items.append((ul or ol).group(1))
            continue

        if not line.strip():
            flush_para(); flush_list()
            continue
        para.append(line.strip())

    if code is not None:
        # An unterminated fence is the author's typo, not a reason to lose the
        # rest of the runbook.
        out.append("<p>" + _inline("\n".join(code)) + "</p>")
    flush_para(); flush_list()
    return "".join(out)


# ---------------------------------------------------------------------------
# Confluence
# ---------------------------------------------------------------------------
class ConfluenceAdapter:
    """Confluence Cloud and Confluence Data Center / Server."""

    system = "confluence"

    def _deployment(self, spec: ConnectorSpec) -> str:
        declared = str(spec.field_mapping.get("deployment") or "").lower()
        if declared in {"cloud", "datacenter"}:
            return declared
        # Inferred, not guessed at random: only Cloud lives on atlassian.net.
        return "cloud" if ".atlassian.net" in spec.base_url else "datacenter"

    def _api(self, spec: ConnectorSpec, suffix: str = "") -> str:
        base = spec.base_url.rstrip("/")
        if self._deployment(spec) == "cloud" and not base.endswith("/wiki"):
            base += "/wiki"
        return f"{base}/rest/api{suffix}"

    def _site(self, spec: ConnectorSpec) -> str:
        base = spec.base_url.rstrip("/")
        if self._deployment(spec) == "cloud" and not base.endswith("/wiki"):
            base += "/wiki"
        return base

    def _headers(self, spec: ConnectorSpec) -> dict:
        credentials = spec.credentials
        # Same discrimination as Jira, and for the same reason: both
        # deployments call their credential a token, so `email` is what tells
        # them apart. The fall-through RAISES rather than sending an empty
        # Basic header -- the 0.28.0 defect, which must not be reintroduced in
        # a second adapter.
        if credentials.get("email"):
            secret = credentials.get("token") or credentials.get("password") or ""
            authorization = _basic_auth(credentials["email"], secret)
        elif credentials.get("token"):
            authorization = f"Bearer {credentials['token']}"
        elif credentials.get("username"):
            authorization = _basic_auth(credentials["username"],
                                        credentials.get("password", ""))
        else:
            raise DocsError(
                "confluence credentials carry none of 'email' (Cloud: account "
                "email + API token), 'token' (Data Center: personal access "
                "token) or 'username' (Data Center: basic auth)"
            )
        return {"Authorization": authorization, "Content-Type": "application/json",
                "Accept": "application/json"}

    def _page(self, spec: ConnectorSpec, result: dict) -> RemotePage:
        links = result.get("_links") or {}
        url = links.get("base", self._site(spec)) + (links.get("webui") or "")
        return RemotePage(
            page_id=str(result.get("id")),
            title=result.get("title"),
            url=url if links.get("webui") else None,
            version=int((result.get("version") or {}).get("number") or 1),
            space_key=((result.get("space") or {}).get("key")),
        )

    def fetch(self, spec: ConnectorSpec, page_id: str) -> RemotePage:
        return self._page(spec, _request(
            "GET", self._api(spec, f"/content/{page_id}?expand=version,space"),
            headers=self._headers(spec), json_body=None, timeout=spec.timeout))

    def create(self, spec: ConnectorSpec, payload: dict) -> RemotePage:
        space = spec.field_mapping.get("space_key")
        if not space:
            raise DocsError(
                "this connector has no space_key: name the Confluence space "
                "VEYRS should publish into")
        body: dict[str, Any] = {
            "type": "page",
            "title": payload["title"][:255],
            "space": {"key": space},
            "body": {"storage": {"value": payload["storage"], "representation": "storage"}},
        }
        parent = spec.field_mapping.get("parent_page_id")
        if parent:
            body["ancestors"] = [{"id": str(parent)}]
        return self._page(spec, _request(
            "POST", self._api(spec, "/content"), headers=self._headers(spec),
            json_body=body, timeout=spec.timeout))

    def update(self, spec: ConnectorSpec, page_id: str, payload: dict) -> RemotePage:
        """Read the CURRENT version, then write current + 1.

        Confluence rejects any other number with a 409. Deriving it from
        `KnowledgeArticle.version` would work exactly until somebody edits the
        page in Confluence -- after which every publish fails forever and the
        error says nothing about why.
        """
        current = self.fetch(spec, page_id)
        body: dict[str, Any] = {
            "id": str(page_id),
            "type": "page",
            "title": payload["title"][:255],
            "version": {"number": (current.version or 1) + 1,
                        "message": payload.get("change_note") or "Updated from VEYRS"},
            "body": {"storage": {"value": payload["storage"], "representation": "storage"}},
        }
        space = spec.field_mapping.get("space_key")
        if space:
            body["space"] = {"key": space}
        return self._page(spec, _request(
            "PUT", self._api(spec, f"/content/{page_id}"), headers=self._headers(spec),
            json_body=body, timeout=spec.timeout))

    def verify(self, spec: ConnectorSpec) -> list[dict]:
        steps: list[dict] = []
        try:
            me = _request("GET", self._api(spec, "/user/current"),
                          headers=self._headers(spec), json_body=None,
                          timeout=spec.timeout)
            steps.append(_step("authenticate", "ok",
                               str(me.get("displayName") or me.get("username") or "ok")))
        except ItsmError as exc:
            steps.append(_step("authenticate", "failed", str(exc)))
            return steps

        space = spec.field_mapping.get("space_key")
        if not space:
            # A credential that works pointed at no space still cannot publish.
            # Reported as failed, not skipped: unlike a webhook with no read
            # contract, this one is simply not configured yet.
            steps.append(_step("space", "failed", "no space_key is configured"))
            return steps
        try:
            found = _request("GET", self._api(spec, f"/space/{space}"),
                             headers=self._headers(spec), json_body=None,
                             timeout=spec.timeout)
            steps.append(_step("space", "ok", str(found.get("name") or space)))
        except ItsmError as exc:
            steps.append(_step("space", "failed", f"space {space!r}: {exc}"))
            return steps

        parent = spec.field_mapping.get("parent_page_id")
        if not parent:
            steps.append(_step("parent page", "skipped",
                               "pages will be created at the top of the space"))
        else:
            try:
                page = self.fetch(spec, str(parent))
                steps.append(_step("parent page", "ok", page.title or str(parent)))
            except ItsmError as exc:
                steps.append(_step("parent page", "failed", str(exc)))
        return steps


DOCS_ADAPTERS: dict[str, type] = {"confluence": ConfluenceAdapter}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def article_payload(article: KnowledgeArticle) -> dict[str, Any]:
    """What gets published, and the footer that keeps authority straight.

    The footer is not decoration. Without it, a reader who finds the page in
    Confluence has no way to know the wiki is a MIRROR -- and the first person
    who edits it there has silently forked the runbook.
    """
    storage = markdown_to_storage(article.body)
    footer = (
        "<hr/><p><em>Published from VEYRS "
        f"(article <code>{html.escape(article.slug)}</code>, version {article.version}). "
        "VEYRS is the system of record: edit it there and publish again — "
        "changes made on this page are not read back.</em></p>"
    )
    return {
        "title": article.title,
        "storage": storage + footer,
        "change_note": f"VEYRS {article.slug} v{article.version}",
        "labels": ["veyrs", article.kind] + list(article.tags or [])[:10],
    }


def _digest(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()).hexdigest()


def publication_for(
    session: Session, organization_id: uuid.UUID, article_id: uuid.UUID
) -> ExternalLink | None:
    return session.execute(
        select(ExternalLink).where(
            ExternalLink.organization_id == organization_id,
            ExternalLink.object_type == "knowledge",
            ExternalLink.object_id == str(article_id),
            ExternalLink.is_active.is_(True),
        ).order_by(ExternalLink.created_at.desc())
    ).scalars().first()


def publish_article(
    session: Session, connector: ItsmConnector, article: KnowledgeArticle
) -> ExternalLink:
    """Create or update the wiki page for an article. Idempotent.

    An unchanged article is NOT re-published: the digest guard is what stops a
    nightly job from putting 400 no-op revisions into somebody's Confluence
    history and making the page's real edits impossible to find.
    """
    if connector.system not in DOCS_SYSTEMS:
        raise DocsError(
            f"connector {connector.slug} is a {connector.system} connector, not a "
            "documentation one")
    if not connector.is_enabled:
        raise DocsError(f"connector {connector.slug} is disabled")

    adapter = DOCS_ADAPTERS[connector.system]()
    spec = build_spec(connector)
    payload = article_payload(article)
    digest = _digest(payload)

    link = session.execute(
        select(ExternalLink).where(
            ExternalLink.organization_id == article.organization_id,
            ExternalLink.connector_id == connector.id,
            ExternalLink.object_type == "knowledge",
            ExternalLink.object_id == str(article.id),
        )
    ).scalar_one_or_none()

    if link is not None and link.payload_digest == digest and link.is_active:
        return link

    now = dt.datetime.now(dt.timezone.utc)
    try:
        if link is None:
            page = adapter.create(spec, payload)
            link = ExternalLink(
                organization_id=article.organization_id, connector_id=connector.id,
                object_type="knowledge", object_id=str(article.id),
                remote_id=page.page_id, remote_key=page.space_key,
                remote_url=page.url, remote_created_at=now,
            )
            session.add(link)
        else:
            page = adapter.update(spec, link.remote_id, payload)
            link.remote_url = page.url or link.remote_url
            link.remote_key = page.space_key or link.remote_key
            link.is_active = True
        link.summary = article.title[:500]
        link.remote_type = "page"
        link.remote_status = f"v{page.version}" if page.version else None
        link.remote_updated_at = now
        link.payload_digest = digest
        link.last_pushed_at = now
        link.last_error = None
        connector.last_sync_at = now
        connector.last_error = None
    except ItsmError as exc:
        connector.last_error = str(exc)[:500]
        if link is not None:
            link.last_error = str(exc)[:500]
        session.flush()
        raise
    session.flush()
    return link


def test_connector(session: Session, connector: ItsmConnector) -> dict:
    """Diagnose a documentation connector step by step. Never raises remotely."""
    steps: list[dict] = []
    adapter_class = DOCS_ADAPTERS.get(connector.system)
    if adapter_class is None:
        return {"ok": False, "steps": [_step(
            "adapter", "failed",
            f"{connector.system!r} is not a documentation system")]}
    steps.append(_step("adapter", "ok", connector.system))
    try:
        spec = build_spec(connector)
    except ItsmError as exc:
        steps.append(_step("configuration", "failed", str(exc)))
        return {"ok": False, "steps": steps}
    steps.append(_step("configuration", "ok", spec.base_url))
    if not connector.credentials_enc:
        # Unlike a webhook, there is no unauthenticated Confluence write.
        steps.append(_step("credentials", "failed",
                           "no credential is stored for this connector"))
        return {"ok": False, "steps": steps}
    steps.append(_step("credentials", "ok", "stored"))
    try:
        steps.extend(adapter_class().verify(spec))
    except ItsmError as exc:
        steps.append(_step("verify", "failed", str(exc)))
    except Exception as exc:  # noqa: BLE001
        log.exception("confluence verify raised for connector %s", connector.slug)
        steps.append(_step("verify", "failed", f"unexpected {exc.__class__.__name__}"))
    failed = [s for s in steps if s["status"] == "failed"]
    connector.last_error = failed[0]["detail"][:500] if failed else None
    session.flush()
    return {"ok": not failed, "steps": steps}


__all__ = [
    "DOCS_SYSTEMS", "DOCS_ADAPTERS", "DocsError", "RemotePage", "ConfluenceAdapter",
    "markdown_to_storage", "SUPPORTED_MARKDOWN", "article_payload",
    "publish_article", "publication_for", "test_connector",
]
