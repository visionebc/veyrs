"""ITSM connectors: ServiceNow, Jira Service Management, generic webhook.

Design position (spec section 14): VEYRS is the **system of record for the
security finding**; the ITSM is the system of record for the *work*. So:

* Push is idempotent and digest-guarded -- an unchanged ticket is not re-sent,
  because a queue full of no-op updates is how integrations get muted.
* Pull only ever changes the VEYRS ticket's state, never the finding's. A
  ServiceNow closure means "the change ticket is done", which is evidence for
  remediation, not proof of it. Verification stays a VEYRS decision.
* Credentials live encrypted (`security/secrets.py`) and are decrypted per call.
  No adapter receives the connector row itself.
* Every adapter is a class in `ADAPTERS`. There is no "run this template" path,
  for the same reason the workflow engine has an action allow-list.
"""
from __future__ import annotations

import base64
import dataclasses
import datetime as dt
import hashlib
import json
import logging
import uuid
from typing import Any, Protocol

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models import ItsmConnector, Ticket
from ..models.integration import ExternalLink
from ..security.secrets import SecretError, decrypt

log = logging.getLogger("veyrs.itsm")


class ItsmError(RuntimeError):
    """Remote system rejected us. Never surfaced with the response body."""


@dataclasses.dataclass(frozen=True)
class RemoteTicket:
    remote_id: str
    remote_key: str | None = None
    url: str | None = None
    status: str | None = None


@dataclasses.dataclass(frozen=True)
class ConnectorSpec:
    slug: str
    system: str
    base_url: str
    credentials: dict[str, Any]
    field_mapping: dict[str, Any]
    timeout: int = 30


class Adapter(Protocol):
    def create(self, spec: ConnectorSpec, payload: dict) -> RemoteTicket: ...
    def update(self, spec: ConnectorSpec, remote_id: str, payload: dict) -> RemoteTicket: ...
    def fetch(self, spec: ConnectorSpec, remote_id: str) -> RemoteTicket: ...
    def verify(self, spec: ConnectorSpec) -> list[dict]: ...


def _request(method: str, url: str, *, headers: dict, json_body: dict | None,
             timeout: int) -> dict:
    import httpx

    try:
        response = httpx.request(method, url, headers=headers, json=json_body,
                                 timeout=timeout)
    except Exception as exc:  # noqa: BLE001
        raise ItsmError(f"transport error: {exc.__class__.__name__}") from exc
    if response.status_code >= 400:
        raise ItsmError(f"remote returned HTTP {response.status_code}")
    if not response.content:
        return {}
    try:
        return response.json()
    except ValueError as exc:
        raise ItsmError("remote returned a non-JSON body") from exc


def _basic_auth(user: str, password: str) -> str:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return f"Basic {token}"


def _step(name: str, status: str, detail: str = "") -> dict[str, str]:
    """One line of a connection diagnosis.

    `status` is a THREE-valued word, not a boolean, for the same reason the
    LDAP test uses steps: "skipped" is a real outcome (a generic webhook has
    nothing that can be read back) and reporting it as False would make a
    correctly configured connector look broken.
    """
    return {"step": name, "status": status, "detail": detail}


# ---------------------------------------------------------------------------
# ServiceNow
# ---------------------------------------------------------------------------
class ServiceNowAdapter:
    """Table API. Defaults to `incident`; `table` in field_mapping overrides it
    (change_request for ITIL change records)."""

    system = "servicenow"
    #: ServiceNow priority is 1 (highest) .. 4/5.
    PRIORITY = {"critical": "1", "high": "2", "medium": "3", "low": "4"}

    def _url(self, spec: ConnectorSpec, suffix: str = "") -> str:
        table = spec.field_mapping.get("table", "incident")
        return f"{spec.base_url.rstrip('/')}/api/now/table/{table}{suffix}"

    def _headers(self, spec: ConnectorSpec) -> dict:
        credentials = spec.credentials
        if credentials.get("token"):
            authorization = f"Bearer {credentials['token']}"
        else:
            authorization = _basic_auth(credentials.get("username", ""),
                                        credentials.get("password", ""))
        return {"Authorization": authorization, "Content-Type": "application/json",
                "Accept": "application/json"}

    def _body(self, spec: ConnectorSpec, payload: dict) -> dict:
        body = {
            "short_description": payload["summary"][:160],
            "description": payload["description"],
            "priority": self.PRIORITY.get(payload.get("priority", "medium"), "3"),
            "category": spec.field_mapping.get("category", "security"),
        }
        if payload.get("assignment_group"):
            body["assignment_group"] = payload["assignment_group"]
        body.update(spec.field_mapping.get("extra_fields", {}))
        return body

    def create(self, spec: ConnectorSpec, payload: dict) -> RemoteTicket:
        result = _request("POST", self._url(spec), headers=self._headers(spec),
                          json_body=self._body(spec, payload), timeout=spec.timeout)
        record = result.get("result") or {}
        return RemoteTicket(
            remote_id=str(record.get("sys_id") or ""),
            remote_key=record.get("number"),
            url=f"{spec.base_url.rstrip('/')}/nav_to.do?uri=incident.do?sys_id="
                f"{record.get('sys_id')}",
            status=record.get("state"),
        )

    def update(self, spec: ConnectorSpec, remote_id: str, payload: dict) -> RemoteTicket:
        result = _request("PATCH", self._url(spec, f"/{remote_id}"),
                          headers=self._headers(spec),
                          json_body=self._body(spec, payload), timeout=spec.timeout)
        record = result.get("result") or {}
        return RemoteTicket(remote_id=remote_id, remote_key=record.get("number"),
                            status=record.get("state"))

    def fetch(self, spec: ConnectorSpec, remote_id: str) -> RemoteTicket:
        result = _request("GET", self._url(spec, f"/{remote_id}"),
                          headers=self._headers(spec), json_body=None,
                          timeout=spec.timeout)
        record = result.get("result") or {}
        return RemoteTicket(remote_id=remote_id, remote_key=record.get("number"),
                            status=record.get("state"))

    def verify(self, spec: ConnectorSpec) -> list[dict]:
        table = spec.field_mapping.get("table", "incident")
        url = f"{spec.base_url.rstrip('/')}/api/now/table/{table}?sysparm_limit=1"
        try:
            _request("GET", url, headers=self._headers(spec), json_body=None,
                     timeout=spec.timeout)
        except ItsmError as exc:
            return [_step("read table", "failed", f"{table}: {exc}")]
        return [_step("read table", "ok", table)]


# ---------------------------------------------------------------------------
# Jira
# ---------------------------------------------------------------------------
class JiraAdapter:
    """Jira Cloud and Jira Data Center / Server.

    These are not one API, and the difference is not cosmetic:

    * **Cloud** is ``/rest/api/3`` and expects Atlassian Document Format for
      ``description``. Its credential is an account **email** plus an **API
      token**, sent as Basic. Atlassian removed password authentication from
      the Cloud REST API in 2019, so a form that asks for "user and password"
      cannot produce a working Cloud connector no matter what is typed in it.
    * **Data Center / Server** is ``/rest/api/2`` and expects ``description``
      as a plain string. Its credential is a personal access token sent as
      ``Bearer``, or a genuine username and password over Basic.

    ``api_version`` in ``field_mapping`` selects the pair and defaults to 3.
    """

    system = "jira"

    def _version(self, spec: ConnectorSpec) -> str:
        version = str(spec.field_mapping.get("api_version") or 3)
        return version if version in {"2", "3"} else "3"

    def _api(self, spec: ConnectorSpec, suffix: str = "") -> str:
        return f"{spec.base_url.rstrip('/')}/rest/api/{self._version(spec)}{suffix}"

    def _headers(self, spec: ConnectorSpec) -> dict:
        credentials = spec.credentials
        # `email` is the discriminator, NOT "is there a token": both
        # deployments call their credential a token. The previous form of this
        # method fell through to `_basic_auth("", "")` for any other key shape
        # -- sending `Authorization: Basic Og==` and letting the operator blame
        # Jira for the 401 that came back. The console posted exactly that
        # shape, so no Jira connector built from the UI had ever authenticated.
        if credentials.get("email"):
            secret = credentials.get("token") or credentials.get("password") or ""
            authorization = _basic_auth(credentials["email"], secret)
        elif credentials.get("token"):
            authorization = f"Bearer {credentials['token']}"
        elif credentials.get("username"):
            authorization = _basic_auth(credentials["username"],
                                        credentials.get("password", ""))
        else:
            raise ItsmError(
                "jira credentials carry none of 'email' (Cloud: email + API "
                "token), 'token' (Data Center: personal access token) or "
                "'username' (Data Center: basic auth)"
            )
        return {"Authorization": authorization, "Content-Type": "application/json",
                "Accept": "application/json"}

    def _description(self, spec: ConnectorSpec, text: str) -> Any:
        text = (text or "")[:30000]
        if self._version(spec) != "3":
            return text
        # An ADF text node whose `text` is the empty string is rejected with a
        # 400. A ticket with no description is ordinary, so the empty DOCUMENT
        # -- not an empty text node -- is the encoding of "nothing to say".
        if not text:
            return {"type": "doc", "version": 1, "content": []}
        return {"type": "doc", "version": 1,
                "content": [{"type": "paragraph",
                             "content": [{"type": "text", "text": text}]}]}

    def _body(self, spec: ConnectorSpec, payload: dict) -> dict:
        fields: dict[str, Any] = {
            "project": {"key": spec.field_mapping.get("project_key", "SEC")},
            "summary": payload["summary"][:255],
            "description": self._description(spec, payload.get("description", "")),
            "issuetype": {"name": spec.field_mapping.get("issue_type", "Task")},
        }
        if spec.field_mapping.get("priority_field"):
            fields["priority"] = {"name": payload.get("priority", "Medium").title()}
        if payload.get("labels"):
            fields["labels"] = payload["labels"][:20]
        fields.update(spec.field_mapping.get("extra_fields", {}))
        return {"fields": fields}

    def create(self, spec: ConnectorSpec, payload: dict) -> RemoteTicket:
        result = _request("POST", self._api(spec, "/issue"),
                          headers=self._headers(spec),
                          json_body=self._body(spec, payload), timeout=spec.timeout)
        key = result.get("key")
        return RemoteTicket(
            remote_id=str(result.get("id") or key or ""),
            remote_key=key,
            url=f"{spec.base_url.rstrip('/')}/browse/{key}" if key else None,
        )

    def update(self, spec: ConnectorSpec, remote_id: str, payload: dict) -> RemoteTicket:
        _request("PUT", self._api(spec, f"/issue/{remote_id}"),
                 headers=self._headers(spec), json_body=self._body(spec, payload),
                 timeout=spec.timeout)
        return RemoteTicket(remote_id=remote_id)

    def fetch(self, spec: ConnectorSpec, remote_id: str) -> RemoteTicket:
        result = _request("GET", self._api(spec, f"/issue/{remote_id}"),
                          headers=self._headers(spec), json_body=None,
                          timeout=spec.timeout)
        fields = result.get("fields") or {}
        status = (fields.get("status") or {}).get("name")
        return RemoteTicket(remote_id=remote_id, remote_key=result.get("key"),
                            status=status)

    def verify(self, spec: ConnectorSpec) -> list[dict]:
        """Authenticate, then check the project and issue type actually exist.

        Stopping at "the credential works" is what makes an integration fail
        on the FIRST real ticket instead of on the test button: a valid token
        pointed at a project key that does not exist is a 404 nobody sees
        until a critical finding needs escalating.
        """
        steps: list[dict] = []
        try:
            me = _request("GET", self._api(spec, "/myself"),
                          headers=self._headers(spec), json_body=None,
                          timeout=spec.timeout)
        except ItsmError as exc:
            return [_step("authenticate", "failed", str(exc))]
        who = (me.get("displayName") or me.get("name")
               or me.get("emailAddress") or "an unnamed account")
        steps.append(_step("authenticate", "ok", f"as {who}"))

        project_key = spec.field_mapping.get("project_key", "SEC")
        try:
            project = _request("GET", self._api(spec, f"/project/{project_key}"),
                               headers=self._headers(spec), json_body=None,
                               timeout=spec.timeout)
        except ItsmError as exc:
            steps.append(_step("project", "failed", f"{project_key}: {exc}"))
            return steps
        steps.append(_step("project", "ok",
                           f"{project_key} - {project.get('name') or ''}".strip(" -")))

        wanted = spec.field_mapping.get("issue_type", "Task")
        available = [t.get("name") for t in (project.get("issueTypes") or [])
                     if t.get("name")]
        if not available:
            steps.append(_step("issue type", "skipped",
                               "the project payload carried no issue types, so "
                               f"{wanted!r} could not be checked"))
        elif wanted in available:
            steps.append(_step("issue type", "ok", wanted))
        else:
            steps.append(_step("issue type", "failed",
                               f"{wanted!r} is not one of: "
                               f"{', '.join(sorted(available))}"))
        return steps


# ---------------------------------------------------------------------------
# Generic webhook
# ---------------------------------------------------------------------------
class WebhookAdapter:
    """POST the payload and treat the response as advisory.

    For homegrown trackers. The remote id falls back to the VEYRS ticket
    reference so a link row still exists and the push is not repeated.
    """

    system = "webhook"

    def _headers(self, spec: ConnectorSpec) -> dict:
        headers = {"Content-Type": "application/json"}
        if spec.credentials.get("token"):
            headers["Authorization"] = f"Bearer {spec.credentials['token']}"
        headers.update(spec.field_mapping.get("headers", {}))
        return headers

    def create(self, spec: ConnectorSpec, payload: dict) -> RemoteTicket:
        result = _request("POST", spec.base_url, headers=self._headers(spec),
                          json_body=payload, timeout=spec.timeout)
        return RemoteTicket(remote_id=str(result.get("id") or payload["reference"]),
                            remote_key=result.get("key"), url=result.get("url"))

    def update(self, spec: ConnectorSpec, remote_id: str, payload: dict) -> RemoteTicket:
        _request("POST", spec.base_url, headers=self._headers(spec),
                 json_body={**payload, "remote_id": remote_id}, timeout=spec.timeout)
        return RemoteTicket(remote_id=remote_id)

    def fetch(self, spec: ConnectorSpec, remote_id: str) -> RemoteTicket:
        # A generic webhook has no read contract; report what we already know.
        return RemoteTicket(remote_id=remote_id)

    def verify(self, spec: ConnectorSpec) -> list[dict]:
        return [_step(
            "verify", "skipped",
            "a generic webhook has no read contract: the only way to exercise "
            "it is to send a real payload, which would create a ticket in the "
            "remote system. Push one ticket instead and read the result.",
        )]


ADAPTERS: dict[str, type] = {
    "servicenow": ServiceNowAdapter,
    "jira": JiraAdapter,
    "webhook": WebhookAdapter,
}


# ---------------------------------------------------------------------------
# Orchestration
# ---------------------------------------------------------------------------
def build_spec(connector: ItsmConnector) -> ConnectorSpec:
    try:
        credentials = json.loads(decrypt(connector.credentials_enc) or "{}")
    except SecretError as exc:
        raise ItsmError(f"connector {connector.slug}: {exc}") from exc
    except json.JSONDecodeError as exc:
        raise ItsmError(f"connector {connector.slug}: credentials are not JSON") from exc
    if not connector.base_url:
        raise ItsmError(f"connector {connector.slug} has no base_url")
    return ConnectorSpec(
        slug=connector.slug, system=connector.system, base_url=connector.base_url,
        credentials=credentials, field_mapping=connector.field_mapping or {},
    )


def ticket_payload(session: Session, ticket: Ticket) -> dict[str, Any]:
    """The canonical shape every adapter maps from."""
    return {
        "reference": ticket.reference,
        "summary": ticket.title,
        "description": ticket.description or "",
        "priority": ticket.priority,
        "type": ticket.ticket_type,
        "state": ticket.state,
        "labels": ["veyrs", f"veyrs-{ticket.ticket_type}"],
        "veyrs_url": f"/tickets/{ticket.id}",
        "due_at": ticket.due_at.isoformat() if ticket.due_at else None,
    }


def _digest(payload: dict) -> str:
    return hashlib.sha256(
        json.dumps(payload, sort_keys=True, default=str).encode()
    ).hexdigest()


def push_ticket(
    session: Session, connector: ItsmConnector, ticket: Ticket
) -> ExternalLink:
    """Create or update the remote twin of a VEYRS ticket. Idempotent."""
    if not connector.is_enabled:
        raise ItsmError(f"connector {connector.slug} is disabled")
    types = list(connector.ticket_types or [])
    if types and ticket.ticket_type not in types:
        raise ItsmError(
            f"connector {connector.slug} does not sync {ticket.ticket_type} tickets"
        )

    adapter_class = ADAPTERS.get(connector.system)
    if adapter_class is None:
        raise ItsmError(f"unsupported ITSM system {connector.system!r}")
    adapter = adapter_class()
    spec = build_spec(connector)
    payload = ticket_payload(session, ticket)
    digest = _digest(payload)

    link = session.execute(
        select(ExternalLink).where(
            ExternalLink.organization_id == ticket.organization_id,
            ExternalLink.connector_id == connector.id,
            ExternalLink.object_type == "ticket",
            ExternalLink.object_id == str(ticket.id),
        )
    ).scalar_one_or_none()

    if link is not None and link.payload_digest == digest:
        # Nothing changed since the last push. Silence is the correct action.
        return link

    try:
        if link is None:
            remote = adapter.create(spec, payload)
            link = ExternalLink(
                organization_id=ticket.organization_id, connector_id=connector.id,
                object_type="ticket", object_id=str(ticket.id),
                remote_id=remote.remote_id, remote_key=remote.remote_key,
                remote_url=remote.url, remote_status=remote.status,
            )
            session.add(link)
        else:
            remote = adapter.update(spec, link.remote_id, payload)
            link.remote_key = remote.remote_key or link.remote_key
            link.remote_status = remote.status or link.remote_status
        link.payload_digest = digest
        link.last_pushed_at = dt.datetime.now(dt.timezone.utc)
        link.last_error = None
        connector.last_sync_at = dt.datetime.now(dt.timezone.utc)
        connector.last_error = None
    except ItsmError as exc:
        # Record the failure on both rows: the connector for "is this
        # integration healthy", the link for "did THIS ticket sync".
        connector.last_error = str(exc)[:500]
        if link is not None:
            link.last_error = str(exc)[:500]
        session.flush()
        raise
    session.flush()
    return link


def pull_status(session: Session, connector: ItsmConnector, link: ExternalLink) -> str | None:
    """Refresh the remote status. Does NOT touch the VEYRS ticket state.

    Mapping a remote closure onto a VEYRS state would let an external system
    close a security finding. It stays advisory; a human or an explicit rule
    decides what a "Resolved" incident means for the finding.
    """
    adapter_class = ADAPTERS.get(connector.system)
    if adapter_class is None:
        raise ItsmError(f"unsupported ITSM system {connector.system!r}")
    spec = build_spec(connector)
    remote = adapter_class().fetch(spec, link.remote_id)
    link.remote_status = remote.status or link.remote_status
    link.last_pulled_at = dt.datetime.now(dt.timezone.utc)
    session.flush()
    return link.remote_status


def test_connector(session: Session, connector: ItsmConnector) -> dict:
    """Diagnose a connector step by step. Never raises for a remote failure.

    Same shape and same reason as the directory module's `/ldap/test`: "it
    does not work" is not a diagnosis. The operator has to be able to tell a
    wrong API token from a wrong project key from a base URL that resolves to
    a login page, and a 500 tells them none of those.

    `is_enabled` is deliberately NOT required. Testing is a READ against the
    remote system, and refusing to test a connector until it is switched on
    means the only way to find out whether the credentials work is to switch
    on an integration you are not yet sure about.
    """
    steps: list[dict] = []
    adapter_class = ADAPTERS.get(connector.system)
    if adapter_class is None:
        return {"ok": False, "steps": [_step(
            "adapter", "failed", f"unsupported ITSM system {connector.system!r}")]}
    steps.append(_step("adapter", "ok", connector.system))

    try:
        spec = build_spec(connector)
    except ItsmError as exc:
        steps.append(_step("configuration", "failed", str(exc)))
        return {"ok": False, "steps": steps}
    steps.append(_step("configuration", "ok", spec.base_url))

    # A connector with no stored credential is not a network problem, and
    # `build_spec` cannot refuse it: an unauthenticated webhook is legitimate.
    # Naming it here is what stops a bare "401" from being the first thing the
    # operator sees when the real answer is "you never saved a token".
    if not connector.credentials_enc:
        needed = connector.system != "webhook"
        steps.append(_step("credentials", "failed" if needed else "skipped",
                           "no credential is stored for this connector"))
        if needed:
            return {"ok": False, "steps": steps}
    else:
        steps.append(_step("credentials", "ok", "stored"))

    try:
        steps.extend(adapter_class().verify(spec))
    except ItsmError as exc:
        steps.append(_step("verify", "failed", str(exc)))
    except Exception as exc:  # noqa: BLE001
        # A test button that 500s is a test button nobody presses twice.
        log.exception("itsm verify raised for connector %s", connector.slug)
        steps.append(_step("verify", "failed",
                           f"unexpected {exc.__class__.__name__}"))

    failed = [s for s in steps if s["status"] == "failed"]
    connector.last_error = failed[0]["detail"][:500] if failed else None
    session.flush()
    return {"ok": not failed, "steps": steps}


def links_for_ticket(session: Session, ticket: Ticket) -> list[ExternalLink]:
    return list(session.execute(
        select(ExternalLink).where(
            ExternalLink.organization_id == ticket.organization_id,
            ExternalLink.object_type == "ticket",
            ExternalLink.object_id == str(ticket.id),
        )
    ).scalars().all())


# ---------------------------------------------------------------------------
# Findings pushed directly (external ticketing mode -- see services/ticketing_mode)
# ---------------------------------------------------------------------------
#: Fields copied onto the `external_links` row at creation, so the relation is
#: legible in VEYRS without a round trip to Jira AND stays legible if the
#: finding is later re-scored, re-assigned or the asset is renamed. A relation
#: that can only be read by asking the remote system is not a relation, it is a
#: foreign key with extra steps.
def finding_payload(session: Session, finding: Any, *, ticket_type: str = "remediation") -> dict[str, Any]:
    """The canonical shape for a finding raised straight into an external ITSM.

    Same keys as `ticket_payload` so no adapter needed changing: the adapters
    map from this dict, and a second payload shape would mean a second place to
    get Atlassian Document Format wrong.

    The description carries the relation IN THE ISSUE BODY as well as in the
    link row. An engineer who opens SEC-4412 in Jira and finds "Remediate
    CVE-2023-44487" with no host, no port and no severity has been handed a
    riddle; the whole point of external mode is that they never have to open
    VEYRS to start work.
    """
    from ..models.assets import Asset
    from ..models.tenancy import Team
    from ..models.vulnerability import Vulnerability
    from . import ticketing

    asset = session.get(Asset, finding.asset_id) if finding.asset_id else None
    vulnerability = (
        session.get(Vulnerability, finding.vulnerability_id)
        if finding.vulnerability_id else None
    )
    team = (
        session.get(Team, finding.assigned_team_id)
        if finding.assigned_team_id else None
    )
    cve = vulnerability.cve_id if vulnerability is not None else None
    where = asset.name if asset is not None else "unknown asset"

    addresses = list(asset.ip_addresses or []) if asset is not None else []
    where_exactly = ":".join(str(x) for x in [
        addresses[0] if addresses else None, finding.port] if x)

    facts = [
        ("Device", where),
        ("Address", ", ".join(str(a) for a in addresses[:4]) or None),
        ("Environment", asset.environment if asset is not None else None),
        ("Service", " ".join(str(x) for x in [
            where_exactly or None, finding.protocol, finding.path] if x) or None),
        ("Vulnerability", cve or finding.title),
        ("Severity", finding.severity),
        ("CVSS", finding.cvss_score),
        ("EPSS", finding.epss_score),
        ("KEV", "yes" if finding.kev else None),
        ("Risk score", finding.risk_score),
        ("First seen", finding.first_seen_at.isoformat() if getattr(finding, "first_seen_at", None) else None),
        ("Due", finding.sla_due_at.isoformat() if finding.sla_due_at else None),
        ("Owning team", team.name if team is not None else None),
        ("VEYRS finding", str(finding.id)),
    ]
    body = ["\n".join(f"{k}: {v}" for k, v in facts if v not in (None, "", False))]
    if finding.detail or (vulnerability.description if vulnerability else None):
        body.append("\n" + (finding.detail or vulnerability.description or ""))
    if finding.recommendation:
        body.append(f"\nRecommended action:\n{finding.recommendation}")
    summary = (finding.risk_explanation or {}).get("summary") if finding.risk_explanation else None
    if summary:
        body.append(f"\nWhy this matters:\n{summary}")

    return {
        # No VEYRS reference: in external mode there is no internal ticket to
        # quote, and inventing one would put a key in Jira that resolves to
        # nothing in VEYRS.
        "reference": f"FINDING-{str(finding.id)[:8]}",
        "summary": f"Remediate {cve or finding.title} on {where}"[:500],
        "description": "\n".join(p for p in body if p).strip(),
        "priority": ticketing.priority_for(finding.risk_score, finding.severity),
        "type": ticket_type,
        "state": finding.state,
        "labels": [x for x in ["veyrs", f"veyrs-{ticket_type}", cve,
                               "kev" if finding.kev else None] if x],
        "veyrs_url": f"/findings/{finding.id}",
        "due_at": finding.sla_due_at.isoformat() if finding.sla_due_at else None,
    }


def _stamp_relation(link: ExternalLink, session: Session, finding: Any,
                    payload: dict[str, Any]) -> None:
    """Copy the relation onto the link row: what, where, when, how bad."""
    from ..models.vulnerability import Vulnerability

    vulnerability = (
        session.get(Vulnerability, finding.vulnerability_id)
        if finding.vulnerability_id else None
    )
    link.finding_id = finding.id
    link.asset_id = finding.asset_id
    link.vulnerability_id = finding.vulnerability_id
    link.cve_id = vulnerability.cve_id if vulnerability is not None else None
    link.summary = payload.get("summary")
    link.severity = finding.severity
    link.risk_score = finding.risk_score
    link.due_at = finding.sla_due_at
    link.remote_priority = payload.get("priority")
    link.remote_type = payload.get("type")


def push_finding(
    session: Session,
    connector: ItsmConnector,
    finding: Any,
    *,
    ticket_type: str = "remediation",
    assigned_team_id: uuid.UUID | None = None,
    assigned_user_id: uuid.UUID | None = None,
) -> ExternalLink:
    """Raise the remote issue for a finding directly. Idempotent per finding.

    The internal-mode twin of this is `push_ticket`, and the two are kept
    separate rather than unified behind "an object with a payload" because the
    dedupe key differs in a way that matters: a ticket can legitimately be
    mirrored into several systems at once (`object_type='ticket'` allows one
    link per connector), while a finding in external mode has exactly ONE
    owning queue -- the one named by `ticketing_mode` -- and a second link for
    the same finding is a duplicate issue, not a second mirror.
    """
    if not connector.is_enabled:
        raise ItsmError(f"connector {connector.slug} is disabled")
    types = list(connector.ticket_types or [])
    if types and ticket_type not in types:
        raise ItsmError(
            f"connector {connector.slug} does not sync {ticket_type} tickets"
        )
    adapter_class = ADAPTERS.get(connector.system)
    if adapter_class is None:
        raise ItsmError(f"unsupported ITSM system {connector.system!r}")

    adapter = adapter_class()
    spec = build_spec(connector)
    payload = finding_payload(session, finding, ticket_type=ticket_type)
    digest = _digest(payload)

    link = session.execute(
        select(ExternalLink).where(
            ExternalLink.organization_id == finding.organization_id,
            ExternalLink.connector_id == connector.id,
            ExternalLink.object_type == "finding",
            ExternalLink.object_id == str(finding.id),
        )
    ).scalar_one_or_none()

    if link is not None and link.payload_digest == digest and link.is_active:
        return link

    now = dt.datetime.now(dt.timezone.utc)
    try:
        if link is None:
            remote = adapter.create(spec, payload)
            link = ExternalLink(
                organization_id=finding.organization_id, connector_id=connector.id,
                object_type="finding", object_id=str(finding.id),
                remote_id=remote.remote_id, remote_key=remote.remote_key,
                remote_url=remote.url, remote_status=remote.status,
                remote_created_at=now,
            )
            session.add(link)
        else:
            remote = adapter.update(spec, link.remote_id, payload)
            link.remote_key = remote.remote_key or link.remote_key
            link.remote_status = remote.status or link.remote_status
            link.remote_url = remote.url or link.remote_url
            link.is_active = True
        _stamp_relation(link, session, finding, payload)
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


def links_for_finding(
    session: Session, organization_id: uuid.UUID, finding_id: uuid.UUID
) -> list[ExternalLink]:
    return list(session.execute(
        select(ExternalLink).where(
            ExternalLink.organization_id == organization_id,
            ExternalLink.object_type == "finding",
            ExternalLink.object_id == str(finding_id),
        ).order_by(ExternalLink.created_at.desc())
    ).scalars().all())
