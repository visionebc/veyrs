"""Execution-agent lifecycle, dispatch and result intake (spec section 33).

Read ``models/agent.py`` first: it states the trust model this module enforces.
The three decisions worth defending here.

**Authorisation happens twice, and it must.** A job pinned to an agent is
checked against that agent's policy when it is queued. A job queued for "any
capable agent" cannot be - the policy that matters belongs to whichever agent
eventually claims it. So ``authorise_target()`` runs again inside
``claim_next()``, and a job the claimant may not run is simply not offered to
it. Checking only at queue time would let an operator queue an unpinned job and
have it picked up by the one agent whose allowlist should have refused it.

**Absence of DNS resolution is deliberate.** A name target is matched against
name patterns only, never resolved and compared to a CIDR. Resolving at
authorisation time authorises a *name*, while the agent later scans whatever
that name resolves to at execution time - the gap is a DNS-rebinding primitive
that turns "you may scan app.acme.example" into "you may scan 10.0.0.1". Names
are authorised as names; addresses as addresses.

**An empty result is a result.** A scan that finds nothing still submits, still
becomes an ``ImportRun``, and therefore still drives scoped reconciliation -
which is how an agent-run scan CLOSES findings that were fixed. Treating "no
output" as an error would make the platform structurally unable to observe
remediation, which is half of what it exists for.
"""
from __future__ import annotations

import datetime as dt
import fnmatch
import hashlib
import re
import ipaddress
import logging
import secrets
import uuid
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
from typing import Any, Iterable
from urllib.parse import urlsplit

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..models import (
    ACTIVE_JOB_STATES, Asset, AgentJob, AgentJobEvent, AgentStatus, AgentTool, Engagement,
    ExecAgent, ImportStatus, JobEventKind, JobState, TERMINAL_JOB_STATES,
)
from ..security.auth import new_agent_token, verify_api_key_secret
from . import audit, scanning

log = logging.getLogger("veyrs.agents")

#: Largest scanner output a single job may submit. Beyond this the operator
#: should be splitting the scan, not the platform buffering a gigabyte of XML
#: through a request handler.
MAX_RESULT_BYTES = 64 * 1024 * 1024
#: Streamed events are progress, not storage. A run that wants to ship its
#: whole stdout should submit it as the result.
MAX_EVENT_MESSAGE = 8_000
MAX_EVENTS_PER_CALL = 200
#: An agent that has not checked in for this long is presumed gone.
DEFAULT_OFFLINE_AFTER = 180


class AgentError(ValueError):
    """Base for every refusal in this module. Mapped to 4xx by the API."""


class TargetRefused(AgentError):
    """The requested target is outside what this agent may be pointed at."""


class ScanningRefused(AgentError):
    """Active scanning is off for this tenant; VEYRS is ingest-only.

    A subclass of AgentError on purpose: every route that already maps an
    AgentError to a 403 keeps working, and a caller that wants to tell "you may
    not scan THAT" apart from "this platform does not scan at all" still can.
    """


class ToolRefused(AgentError):
    """The requested tool is not declared, or not enabled by an operator."""


@dataclass(frozen=True)
class TargetDecision:
    """The outcome of authorising one target, kept for the audit record."""

    raw: str
    host: str
    port: int | None
    is_ip: bool
    asset_id: uuid.UUID | None
    matched_rule: str


# ---------------------------------------------------------------------------
# Enrolment and identity
# ---------------------------------------------------------------------------
def _require_active_scanning(session: Session, organization_id: uuid.UUID, what: str) -> None:
    """Translate the tenant switch into this module's refusal type."""
    try:
        scanning.require_enabled(session, organization_id, what)
    except scanning.ScanningDisabled as exc:
        raise ScanningRefused(str(exc)) from exc


def enroll(
    session: Session,
    organization_id: uuid.UUID,
    *,
    name: str,
    description: str | None = None,
    allowed_targets: Sequence[str] | None = None,
    denied_targets: Sequence[str] | None = None,
    require_asset_match: bool = True,
    auto_enable_tools: bool = False,
    max_concurrency: int = 1,
    lease_seconds: int = 900,
    labels: Sequence[str] | None = None,
    created_by_id: uuid.UUID | None = None,
) -> tuple[ExecAgent, str]:
    """Register an agent and mint its token. The clear token is returned ONCE.

    An agent enrolled with no ``allowed_targets`` is inert by construction: the
    allowlist is deny-by-default, so a half-finished enrolment cannot scan
    anything. That is the intended failure mode.
    """
    from .engagements import slugify

    _require_active_scanning(session, organization_id, "enrolling an agent")

    name = (name or "").strip()
    if not name:
        raise AgentError("an agent needs a name")

    base = slugify(name)
    slug, suffix = base, 1
    while session.execute(
        select(ExecAgent.id).where(
            ExecAgent.organization_id == organization_id, ExecAgent.slug == slug
        )
    ).scalars().first() is not None:
        suffix += 1
        slug = f"{base[:110]}-{suffix}"

    clear, prefix, token_hash = new_agent_token()
    for rule in list(allowed_targets or []) + list(denied_targets or []):
        _validate_rule(rule)

    agent = ExecAgent(
        organization_id=organization_id,
        name=name[:200],
        slug=slug,
        description=description,
        token_prefix=prefix,
        token_hash=token_hash,
        token_issued_at=dt.datetime.now(dt.timezone.utc),
        status=AgentStatus.PENDING.value,
        allowed_targets=[r.strip().lower() for r in (allowed_targets or [])],
        denied_targets=[r.strip().lower() for r in (denied_targets or [])],
        require_asset_match=require_asset_match,
        auto_enable_tools=auto_enable_tools,
        max_concurrency=max(1, int(max_concurrency)),
        lease_seconds=max(60, int(lease_seconds)),
        labels=list(labels or []),
        created_by_id=created_by_id,
    )
    session.add(agent)
    session.flush()
    audit.record(
        session, action="agent.enrolled", object_type="exec_agent", object_id=agent.id,
        object_label=agent.name, organization_id=organization_id, actor_id=created_by_id,
        changes={"allowed_targets": agent.allowed_targets,
                 "require_asset_match": require_asset_match},
    )
    return agent, clear


def rotate_token(
    session: Session, agent: ExecAgent, *, actor_id: uuid.UUID | None = None
) -> str:
    clear, prefix, token_hash = new_agent_token()
    agent.token_prefix = prefix
    agent.token_hash = token_hash
    agent.token_issued_at = dt.datetime.now(dt.timezone.utc)
    session.flush()
    audit.record(
        session, action="agent.token_rotated", object_type="exec_agent", object_id=agent.id,
        object_label=agent.name, organization_id=agent.organization_id, actor_id=actor_id,
    )
    return clear


def authenticate(session: Session, clear_token: str) -> ExecAgent | None:
    """Resolve an agent token. Returns None for anything that does not verify.

    Lookup is by prefix so verification hashes once instead of against every
    row - the same design as user API keys, for the same reason.
    """
    from ..security.auth import AuthError, split_agent_token

    try:
        prefix, secret = split_agent_token(clear_token)
    except AuthError:
        return None
    agent = session.execute(
        select(ExecAgent).where(ExecAgent.token_prefix == prefix)
    ).scalar_one_or_none()
    if agent is None:
        return None
    if not verify_api_key_secret(secret, agent.token_hash):
        return None
    return agent


def set_status(
    session: Session, agent: ExecAgent, status: str, *, actor_id: uuid.UUID | None = None
) -> ExecAgent:
    if status not in {s.value for s in AgentStatus}:
        raise AgentError(f"unknown agent status {status!r}")
    agent.status = status
    agent.disabled_at = (
        dt.datetime.now(dt.timezone.utc) if status == AgentStatus.DISABLED.value else None
    )
    session.flush()
    audit.record(
        session, action="agent.status_changed", object_type="exec_agent", object_id=agent.id,
        object_label=agent.name, organization_id=agent.organization_id, actor_id=actor_id,
        changes={"status": status},
    )
    return agent


# ---------------------------------------------------------------------------
# Heartbeat and capability declaration
# ---------------------------------------------------------------------------
def heartbeat(
    session: Session,
    agent: ExecAgent,
    *,
    agent_version: str | None = None,
    hostname: str | None = None,
    platform: str | None = None,
    ip_address: str | None = None,
    tools: Iterable[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    """Record a check-in and reconcile declared tools.

    A tool the agent stops declaring is disabled rather than deleted: its
    history (which jobs ran under it) stays readable, and re-adding the binary
    does not silently re-authorise it.
    """
    now = dt.datetime.now(dt.timezone.utc)
    agent.last_heartbeat_at = now
    if agent_version:
        agent.agent_version = agent_version[:40]
    if hostname:
        agent.hostname = hostname[:255]
    if platform:
        agent.platform = platform[:120]
    if ip_address:
        agent.last_ip = ip_address[:64]

    if agent.status in (AgentStatus.PENDING.value, AgentStatus.OFFLINE.value):
        agent.status = AgentStatus.IDLE.value

    declared = declare_tools(session, agent, tools) if tools is not None else {}
    session.flush()
    return {
        "status": agent.status,
        "lease_seconds": agent.lease_seconds,
        "max_concurrency": agent.max_concurrency,
        "tools": declared,
    }


#: CSI escape sequence, e.g. the colour codes nuclei's logger wraps its
#: version banner in. Matched here rather than only in the runner because the
#: field is rendered verbatim in the console and an agent is not a trusted
#: source of display text.
_ANSI_CSI = re.compile(r"\x1B\[[0-9;]*[A-Za-z]")
_CONTROL = re.compile(r"[\x00-\x1F\x7F]")


def clean_tool_version(raw: Any) -> str | None:
    """Reduce a tool's self-reported banner to something safe to print.

    The banner is whatever the binary chose to write, and several write it
    through a colour logger: stored raw, `nuclei --version` yields
    `\x1b[34mINF\x1b[0m] Nuclei Engine Version: v3.11.1`, which renders as
    line noise in a table cell. Escapes and control characters are stripped;
    the rest is kept verbatim, because which build is installed is exactly the
    detail an analyst needs and normalising it is a matching decision that
    belongs to whoever owns the dictionary.
    """
    if raw is None:
        return None
    text = _CONTROL.sub(" ", _ANSI_CSI.sub("", str(raw)))
    text = " ".join(text.split()).strip()
    return text[:60] or None


def declare_tools(
    session: Session, agent: ExecAgent, tools: Iterable[dict[str, Any]] | None
) -> dict[str, Any]:
    from .importers import PARSERS

    now = dt.datetime.now(dt.timezone.utc)
    existing = {t.name: t for t in session.execute(
        select(AgentTool).where(
            AgentTool.organization_id == agent.organization_id,
            AgentTool.agent_id == agent.id,
        )
    ).scalars().all()}

    seen: set[str] = set()
    added = updated = 0
    for spec in tools or []:
        name = str(spec.get("name") or "").strip().lower()[:60]
        if not name:
            continue
        seen.add(name)
        parser = str(spec.get("parser") or "").strip().lower() or None
        rejected_parser = None
        if parser and parser not in PARSERS:
            # Keep the declaration, refuse the mapping. An agent claiming an
            # unknown parser must not silently get its output fed to the
            # format-sniffer, which would guess.
            rejected_parser, parser = parser, None
        profiles = [str(p).strip().lower()[:60] for p in (spec.get("profiles") or []) if str(p).strip()]
        row = existing.get(name)
        if row is None:
            row = AgentTool(
                organization_id=agent.organization_id, agent_id=agent.id, name=name,
                enabled=bool(agent.auto_enable_tools),
            )
            session.add(row)
            added += 1
        else:
            updated += 1
        row.tool_version = clean_tool_version(spec.get("version"))
        row.parser = parser
        row.profiles = profiles
        row.declared_at = now
        if rejected_parser:
            row.meta = {**(row.meta or {}), "rejected_parser": rejected_parser}

    withdrawn = 0
    for name, row in existing.items():
        if name not in seen and row.enabled:
            row.enabled = False
            withdrawn += 1
    session.flush()
    return {"declared": len(seen), "added": added, "updated": updated, "withdrawn": withdrawn}


def set_tool_enabled(
    session: Session, agent: ExecAgent, tool_name: str, enabled: bool,
    *, actor_id: uuid.UUID | None = None,
) -> AgentTool:
    row = session.execute(
        select(AgentTool).where(
            AgentTool.organization_id == agent.organization_id,
            AgentTool.agent_id == agent.id,
            AgentTool.name == tool_name.strip().lower(),
        )
    ).scalars().first()
    if row is None:
        raise ToolRefused(f"agent {agent.slug} has not declared tool {tool_name!r}")
    row.enabled = bool(enabled)
    session.flush()
    audit.record(
        session, action="agent.tool_enabled" if enabled else "agent.tool_disabled",
        object_type="agent_tool", object_id=row.id, object_label=f"{agent.slug}:{row.name}",
        organization_id=agent.organization_id, actor_id=actor_id,
    )
    return row


def enabled_tool(session: Session, agent: ExecAgent, tool_name: str) -> AgentTool:
    row = session.execute(
        select(AgentTool).where(
            AgentTool.organization_id == agent.organization_id,
            AgentTool.agent_id == agent.id,
            AgentTool.name == (tool_name or "").strip().lower(),
        )
    ).scalars().first()
    if row is None:
        raise ToolRefused(f"agent {agent.slug} does not provide tool {tool_name!r}")
    if not row.enabled:
        raise ToolRefused(
            f"tool {tool_name!r} is declared by {agent.slug} but not enabled by an operator"
        )
    return row


# ---------------------------------------------------------------------------
# Target authorisation - the security boundary
# ---------------------------------------------------------------------------
def split_target(target: str) -> tuple[str, int | None]:
    """Extract (host, port) from a hostname, IP, host:port or URL."""
    raw = (target or "").strip()
    if not raw:
        raise TargetRefused("empty target")
    if "://" in raw:
        parts = urlsplit(raw)
        if not parts.hostname:
            raise TargetRefused(f"cannot read a host out of {target!r}")
        return parts.hostname.lower(), parts.port
    if raw.startswith("["):                       # [2001:db8::1]:443
        host, _, rest = raw[1:].partition("]")
        port = rest.lstrip(":")
        return host.lower(), int(port) if port.isdigit() else None
    try:                                          # bare IPv6 has many colons
        ipaddress.ip_address(raw)
        return raw.lower(), None
    except ValueError:
        pass
    if raw.count(":") == 1:
        host, _, port = raw.partition(":")
        return host.strip().lower(), int(port) if port.isdigit() else None
    return raw.lower(), None


def _as_ip(host: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    try:
        return ipaddress.ip_address(host)
    except ValueError:
        return None


def _is_reserved(address: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Loopback, link-local (incl. 169.254.169.254), multicast, unspecified.

    The link-local case is the one that matters: every cloud provider serves
    instance credentials from 169.254.169.254, so an agent that can be pointed
    at it is a credential-exfiltration primitive wearing a scanner costume.
    """
    return bool(
        address.is_loopback or address.is_link_local or address.is_multicast
        or address.is_unspecified or address.is_reserved
    )


def validate_rules(rules: Iterable[str]) -> None:
    """Reject a malformed policy at write time, not at authorisation time."""
    for rule in rules:
        _validate_rule(rule)


def _validate_rule(rule: str) -> None:
    rule = (rule or "").strip()
    if not rule:
        raise AgentError("empty target rule")
    if "/" in rule:
        try:
            ipaddress.ip_network(rule, strict=False)
        except ValueError as exc:
            raise AgentError(f"invalid network rule {rule!r}: {exc}") from exc


def _matches(host: str, is_ip: bool, rule: str) -> bool:
    """Does this host match one policy rule?

    Names are never resolved (see the module docstring): a name matches name
    patterns, an address matches networks and addresses. A rule of one kind
    silently matching the other is how an allowlist stops meaning anything.
    """
    rule = (rule or "").strip().lower()
    if not rule:
        return False
    if "/" in rule:
        if not is_ip:
            return False
        try:
            return _as_ip(host) in ipaddress.ip_network(rule, strict=False)
        except ValueError:
            return False
    if is_ip:
        other = _as_ip(rule)
        return other is not None and other == _as_ip(host)
    if rule == "*":
        return True
    return fnmatch.fnmatch(host, rule)


def find_asset(session: Session, organization_id: uuid.UUID, host: str) -> Asset | None:
    """Locate the asset a target refers to: hostname, FQDN or recorded address."""
    host = (host or "").strip().lower()
    if not host:
        return None
    stmt = select(Asset).where(
        Asset.organization_id == organization_id,
        Asset.deleted_at.is_(None),
        or_(
            func.lower(Asset.hostname) == host,
            func.lower(Asset.fqdn) == host,
            Asset.ip_addresses.contains([host]),
        ),
    )
    return session.execute(stmt).scalars().first()


def authorise_target(
    session: Session,
    organization_id: uuid.UUID,
    agent: ExecAgent | None,
    target: str,
) -> TargetDecision:
    """Decide whether this target may be scanned. Raises TargetRefused if not.

    With ``agent=None`` only the tenant-wide rules are applied (reserved-range
    refusal, asset register). That is the queue-time check for an unpinned job;
    the claiming agent's own policy is applied later, in ``claim_next()``.
    """
    host, port = split_target(target)
    address = _as_ip(host)
    is_ip = address is not None

    if is_ip and _is_reserved(address):
        # An explicit, literal allowlist entry is the only way in - a CIDR that
        # merely happens to contain it is far too easy to write by accident.
        literal = agent is not None and host in [r.strip().lower() for r in agent.allowed_targets]
        if not literal:
            raise TargetRefused(
                f"{host} is in a reserved range (loopback/link-local/multicast); "
                "scanning it would target the agent's own host or the cloud "
                "metadata service. Allow the exact address explicitly if this is "
                "a lab."
            )

    matched = "tenant-policy"
    if agent is not None:
        for rule in agent.denied_targets or []:
            if _matches(host, is_ip, rule):
                raise TargetRefused(f"{host} is denied by agent policy rule {rule!r}")
        if not agent.allowed_targets:
            raise TargetRefused(
                f"agent {agent.slug} has no allowed targets configured; "
                "the allowlist is deny-by-default"
            )
        matched = next(
            (rule for rule in agent.allowed_targets if _matches(host, is_ip, rule)), ""
        )
        if not matched:
            raise TargetRefused(f"{host} is not covered by agent {agent.slug}'s allowlist")

    asset = find_asset(session, organization_id, host)
    if agent is not None and agent.require_asset_match and asset is None:
        raise TargetRefused(
            f"{host} does not match any asset in the register and agent "
            f"{agent.slug} requires it. Register the asset, or clear "
            "require_asset_match if this agent scans discovery ranges."
        )
    return TargetDecision(
        raw=target, host=host, port=port, is_ip=is_ip,
        asset_id=asset.id if asset else None, matched_rule=matched,
    )


# ---------------------------------------------------------------------------
# Dispatch
# ---------------------------------------------------------------------------
def queue_job(
    session: Session,
    organization_id: uuid.UUID,
    *,
    tool: str,
    target: str,
    agent: ExecAgent | None = None,
    profile: str | None = None,
    params: dict | None = None,
    engagement_id: uuid.UUID | None = None,
    reason: str | None = None,
    priority: int = 0,
    max_attempts: int = 3,
    requested_by_id: uuid.UUID | None = None,
) -> AgentJob:
    """Queue work. Pinned jobs are authorised now; unpinned ones also at claim."""
    _require_active_scanning(session, organization_id, "queueing a scan job")
    tool = (tool or "").strip().lower()
    if not tool:
        raise ToolRefused("a job needs a tool")
    if not (reason or "").strip():
        # Cheap control, high value: it is what makes the audit trail answer
        # "why was production scanned at 03:00" without an archaeology session.
        raise AgentError("a job needs a reason; it is recorded in the audit trail")

    if agent is not None:
        if not agent.is_enabled:
            raise AgentError(f"agent {agent.slug} is disabled")
        tool_row = enabled_tool(session, agent, tool)
        if profile and tool_row.profiles and profile.strip().lower() not in tool_row.profiles:
            raise ToolRefused(
                f"agent {agent.slug} does not implement profile {profile!r} for {tool}"
            )
    else:
        # Unpinned: refuse now if NO agent in the tenant could ever run it,
        # rather than parking a job that will sit queued until it expires.
        capable = session.execute(
            select(AgentTool.id).where(
                AgentTool.organization_id == organization_id,
                AgentTool.name == tool,
                AgentTool.enabled.is_(True),
            )
        ).scalars().first()
        if capable is None:
            raise ToolRefused(f"no enabled agent in this organization provides {tool!r}")

    decision = authorise_target(session, organization_id, agent, target)

    if engagement_id is not None:
        engagement = session.get(Engagement, engagement_id)
        if engagement is None or engagement.organization_id != organization_id:
            raise AgentError("engagement not found")
        if not engagement.is_open:
            raise AgentError(
                f"engagement {engagement.slug} is {engagement.status}; "
                "reopen it or pick another scope"
            )

    job = AgentJob(
        organization_id=organization_id,
        agent_id=agent.id if agent else None,
        requested_agent_id=agent.id if agent else None,
        tool=tool,
        target=target.strip()[:500],
        profile=(profile or "").strip().lower()[:60] or None,
        params=dict(params or {}),
        engagement_id=engagement_id,
        asset_id=decision.asset_id,
        state=JobState.QUEUED.value,
        priority=int(priority),
        reason=reason.strip(),
        max_attempts=max(1, int(max_attempts)),
        requested_by_id=requested_by_id,
        meta={"authorised_host": decision.host, "matched_rule": decision.matched_rule},
    )
    session.add(job)
    session.flush()
    audit.record(
        session, action="agent.job_queued", object_type="agent_job", object_id=job.id,
        object_label=f"{tool} {decision.host}", organization_id=organization_id,
        actor_id=requested_by_id,
        changes={"tool": tool, "target": job.target, "agent": agent.slug if agent else None,
                 "asset_id": str(decision.asset_id) if decision.asset_id else None,
                 "reason": job.reason},
    )
    return job


def active_job_count(session: Session, agent: ExecAgent) -> int:
    return len(session.execute(
        select(AgentJob.id).where(
            AgentJob.organization_id == agent.organization_id,
            AgentJob.agent_id == agent.id,
            AgentJob.state.in_(tuple(ACTIVE_JOB_STATES - {JobState.QUEUED.value})),
        )
    ).scalars().all())


def claim_next(session: Session, agent: ExecAgent) -> AgentJob | None:
    """Lease the next job this agent may run, or None.

    ``FOR UPDATE SKIP LOCKED`` is what makes several agents polling the same
    queue safe without a broker: two claimants never see the same row, and a
    slow one never blocks a fast one.
    """
    if not agent.is_enabled:
        raise AgentError("agent is disabled")
    # Checked HERE and not only at queue time: work queued before the switch
    # was thrown would otherwise drain into the estate afterwards, and the
    # operator who turned scanning off would be wrong about what their platform
    # is doing.
    _require_active_scanning(session, agent.organization_id, "claiming a scan job")
    if active_job_count(session, agent) >= agent.max_concurrency:
        return None

    candidates = session.execute(
        select(AgentJob)
        .where(
            AgentJob.organization_id == agent.organization_id,
            AgentJob.state == JobState.QUEUED.value,
            or_(AgentJob.agent_id == agent.id, AgentJob.agent_id.is_(None)),
        )
        .order_by(AgentJob.priority.desc(), AgentJob.created_at.asc())
        .limit(20)
        .with_for_update(skip_locked=True)
    ).scalars().all()

    for job in candidates:
        try:
            enabled_tool(session, agent, job.tool)
            # Re-authorise: for an unpinned job THIS is the check that counts.
            authorise_target(session, agent.organization_id, agent, job.target)
        except AgentError:
            continue
        return _lease(session, agent, job)
    return None


def _lease(session: Session, agent: ExecAgent, job: AgentJob) -> AgentJob:
    now = dt.datetime.now(dt.timezone.utc)
    job.agent_id = agent.id
    job.state = JobState.LEASED.value
    job.lease_token = secrets.token_urlsafe(32)[:64]
    job.leased_at = now
    job.lease_expires_at = now + dt.timedelta(seconds=agent.lease_seconds)
    job.attempts += 1
    agent.status = AgentStatus.BUSY.value
    session.flush()
    append_event(session, job, kind=JobEventKind.STATUS.value,
                 message=f"leased by {agent.slug} (attempt {job.attempts})")
    return job


def verify_lease(job: AgentJob, agent: ExecAgent, lease_token: str | None) -> None:
    """Only the agent currently holding the lease may write to a job."""
    if job.agent_id != agent.id:
        raise AgentError("this job is not leased to this agent")
    if job.is_terminal:
        raise AgentError(f"job is already {job.state}")
    if not job.lease_token or not lease_token or not secrets.compare_digest(
        job.lease_token, lease_token
    ):
        raise AgentError("invalid or expired lease token")


def mark_running(session: Session, job: AgentJob) -> AgentJob:
    if job.state == JobState.LEASED.value:
        job.state = JobState.RUNNING.value
        job.started_at = dt.datetime.now(dt.timezone.utc)
        session.flush()
    return job


def extend_lease(session: Session, job: AgentJob, agent: ExecAgent) -> dt.datetime:
    job.lease_expires_at = dt.datetime.now(dt.timezone.utc) + dt.timedelta(
        seconds=agent.lease_seconds
    )
    session.flush()
    return job.lease_expires_at


# ---------------------------------------------------------------------------
# Streaming
# ---------------------------------------------------------------------------
def append_event(
    session: Session, job: AgentJob, *, kind: str = JobEventKind.STDOUT.value,
    message: str | None = None, data: dict | None = None,
) -> AgentJobEvent:
    job.last_event_seq += 1
    row = AgentJobEvent(
        organization_id=job.organization_id, job_id=job.id, seq=job.last_event_seq,
        kind=kind if kind in {k.value for k in JobEventKind} else JobEventKind.STDOUT.value,
        message=(message or "")[:MAX_EVENT_MESSAGE] or None,
        data=dict(data or {}),
    )
    session.add(row)
    session.flush()
    return row


def append_events(
    session: Session, job: AgentJob, events: Sequence[dict[str, Any]]
) -> dict[str, int]:
    if len(events) > MAX_EVENTS_PER_CALL:
        raise AgentError(f"at most {MAX_EVENTS_PER_CALL} events per call")
    mark_running(session, job)
    for spec in events:
        append_event(
            session, job,
            kind=str(spec.get("kind") or JobEventKind.STDOUT.value),
            message=spec.get("message"),
            data=spec.get("data") or {},
        )
    return {"accepted": len(events), "last_seq": job.last_event_seq}


def read_events(
    session: Session, job: AgentJob, *, since_seq: int = 0, limit: int = 500
) -> list[AgentJobEvent]:
    return list(session.execute(
        select(AgentJobEvent)
        .where(
            AgentJobEvent.organization_id == job.organization_id,
            AgentJobEvent.job_id == job.id,
            AgentJobEvent.seq > since_seq,
        )
        .order_by(AgentJobEvent.seq.asc())
        .limit(min(max(1, limit), 2000))
    ).scalars().all())


# ---------------------------------------------------------------------------
# Result intake
# ---------------------------------------------------------------------------
#: CSI escape sequences emitted by colourising scanners.
_ANSI = re.compile(r"\x1b\[[0-9;]*[A-Za-z]")


def _failure_detail(
    session: Session, job: AgentJob, exit_code: int, *, lines: int = 3
) -> str:
    """Fold the tail of the agent's output into the job error.

    "agent reported exit code 1" tells an operator nothing, and the reason is
    already streamed as events - nuclei prints "no templates provided for scan"
    and exits 1 when a severity filter and a tag filter select disjoint sets.
    Nobody reads an event stream to triage a red job, so the last few lines go
    where the failure is displayed.
    """
    tail = session.execute(
        select(AgentJobEvent.message)
        .where(
            AgentJobEvent.job_id == job.id,
            AgentJobEvent.kind.in_(
                (JobEventKind.STDOUT.value, JobEventKind.STDERR.value)
            ),
            AgentJobEvent.message.is_not(None),
        )
        .order_by(AgentJobEvent.seq.desc())
        .limit(lines)
    ).scalars().all()
    base = f"agent reported exit code {exit_code}"
    # Scanners colour their own output; those escapes are noise in a stored
    # error and render as literal "[[1;31mFTL[0m]" in the console and in email.
    detail = " | ".join(
        _ANSI.sub("", m).strip() for m in reversed(tail) if m and m.strip()
    )
    return (f"{base}: {detail}" if detail else base)[:2000]


# ---------------------------------------------------------------------------
# Coverage - the difference between "found nothing" and "saw nothing"
# ---------------------------------------------------------------------------
#: Below this share of the scan completed, the run did not observe the estate.
#: Measured on this fleet: a scanner resolving an internal host to its public
#: address completes 5%; the same scan pointed at the internal resolver
#: completes 97%. Anything in between is a scan worth re-running, not a result
#: worth believing.
MIN_COVERAGE_PERCENT = 80
#: Errors per request. A healthy run sits near 0.01; a run that never opened a
#: connection reports more errors than requests.
MAX_ERROR_RATE = 0.5


def _coverage(stats: Mapping[str, Any] | None, payload: bytes) -> tuple[bool, str | None]:
    """Is this run evidence about the estate? Returns (attested, refusal).

    An exit code is not enough, and this is the defect that proves it: nuclei
    resolving an internal host to its public address exits 0, writes no output
    and matches nothing - three facts indistinguishable from a clean scan. The
    only place the difference is visible is how much of the scan completed.

    Two outcomes, deliberately different:

    * **refusal** - there is nothing to import and no attestation either. The
      job fails. Reconciling it would close findings because the scanner was
      blind, which is the worst thing this platform can do.
    * **not attested, no refusal** - there is output, so it is ingested and
      believed as far as it goes, but it may not CLOSE anything. Partial
      evidence adds findings; only a run that covered the target removes them.
    """
    if not isinstance(stats, Mapping) or not stats:
        if payload.strip():
            return False, None
        return False, (
            "the agent reported no scan coverage, so an empty result cannot be "
            "read as a clean scan. Upgrade the agent (>= 1.1.0) or submit output."
        )

    probe = stats.get("probe")
    if isinstance(probe, Mapping) and probe.get("reachable") is False:
        return False, (
            f"the agent could not reach {probe.get('host') or 'the target'} on any of "
            f"its probed ports (resolved to {probe.get('resolved_ips') or 'nothing'}); "
            "a scan of an unreachable host is not evidence that it is clean"
        )

    scanner = stats.get("scanner")
    if not isinstance(scanner, Mapping) or not scanner:
        # A tool with no coverage numbers of its own. The reachability probe is
        # the whole attestation, and it passed.
        return True, None

    percent = scanner.get("percent")
    requests = scanner.get("requests") or 0
    errors = scanner.get("errors") or 0
    if isinstance(percent, int) and percent < MIN_COVERAGE_PERCENT:
        return False, (
            f"the scanner completed {percent}% of its checks "
            f"({requests} requests, {errors} errors) and then stopped; "
            "an aborted scan is not a clean scan"
        )
    if requests > 0 and errors / requests > MAX_ERROR_RATE:
        return False, (
            f"the scanner failed {errors} of {requests} requests "
            f"({errors / requests:.0%}); it did not observe the target"
        )
    return True, None



def submit_result(
    session: Session,
    agent: ExecAgent,
    job: AgentJob,
    *,
    payload: bytes,
    scanner: str | None = None,
    exit_code: int = 0,
    filename: str | None = None,
    dry_run: bool = False,
    close_absent: bool | None = None,
    stats: Mapping[str, Any] | None = None,
) -> dict[str, Any]:
    """Ingest a finished job's output through the normal importer pipeline.

    The job's scope is the import's scope, so an agent-produced result is
    reconciled exactly like an uploaded one - including closing findings the
    scan no longer reports, which is why an EMPTY payload is accepted.
    """
    from .importers import ImportOptions, detect_format, run_import

    if len(payload) > MAX_RESULT_BYTES:
        raise AgentError(
            f"result is {len(payload)} bytes; the limit is {MAX_RESULT_BYTES}. "
            "Split the scan rather than the upload."
        )

    tool_row = session.execute(
        select(AgentTool).where(
            AgentTool.organization_id == agent.organization_id,
            AgentTool.agent_id == agent.id,
            AgentTool.name == job.tool,
        )
    ).scalars().first()
    source = (scanner or (tool_row.parser if tool_row else None) or "").strip().lower() or None
    if source is None and payload.strip():
        source = detect_format(payload, filename or "")
    if source is None:
        # An empty submission is a statement about the estate ("I ran this and
        # found nothing"), and reconciling it needs to know WHICH scanner's
        # sighting set to reconcile. Guessing would close the wrong scope.
        raise AgentError(
            "an empty result must name its scanner: declare a parser for tool "
            f"{job.tool!r} in the agent's heartbeat, or pass scanner= on submit"
        )

    now = dt.datetime.now(dt.timezone.utc)
    job.exit_code = exit_code
    job.finished_at = now
    job.output_bytes = len(payload)
    job.output_sha256 = hashlib.sha256(payload).hexdigest()

    # A scanner that exited non-zero did NOT establish what is on the estate,
    # so its output is not evidence of remediation. Reconciling it anyway reads
    # a crash as a clean scan - the same failure family as closing findings
    # outside the test's scope. Therefore:
    #   * a failed run never closes a finding (close_absent forced off), and
    #   * a failed run with no output is not imported at all.
    # A SUCCESSFUL empty run still reconciles: that is the only way an
    # agent-run scan closes something it no longer sees.
    attested, refusal = _coverage(stats, payload)
    if stats:
        job.meta = {**(job.meta or {}), "scan_stats": dict(stats)}
    # A run that did not cover its target is a failed run, whatever it exited
    # with - it goes down the same path as a crash, for the same reason.
    failed = exit_code != 0 or refusal is not None
    run = None
    if not (failed and not payload.strip()):
        options = ImportOptions(
            engagement_id=job.engagement_id,
            test_id=job.test_id,
            reuse_test=True,
            close_absent=False if (failed or not attested) else close_absent,
            dry_run=dry_run,
            # An agent that ran a scanner to completion and got nothing is
            # reporting a clean estate, not submitting a broken file. This is
            # the ONLY way a scan closes a finding, so it must reach
            # reconciliation - but only when the scanner actually completed.
            allow_empty=not failed,
            # The authorised host is the artefact name for host-less reports
            # (a SAST/SCA run against a repo checkout on that target).
            target_asset=job.meta.get("authorised_host") if isinstance(job.meta, dict) else None,
        )
        run = run_import(
            session, agent.organization_id, payload,
            source=source, filename=filename or f"{job.tool}-{job.id}",
            options=options, actor_id=job.requested_by_id,
        )
        job.import_run_id = run.id
        if run.test_id:
            # Pin the test so a repeat of this job reconciles against the same
            # sighting set instead of opening a fresh, empty scope.
            job.test_id = run.test_id

    if failed:
        job.state = JobState.FAILED.value
        job.error = (
            _failure_detail(session, job, exit_code) if exit_code != 0
            else f"scan coverage refused: {refusal}"[:2000]
        )
    elif run is not None and run.status == ImportStatus.FAILED.value:
        job.state = JobState.FAILED.value
        job.error = (run.error or "import failed")[:2000]
    else:
        job.state = JobState.SUCCEEDED.value

    job.lease_token = None
    session.flush()
    append_event(
        session, job, kind=JobEventKind.STATUS.value,
        message=f"result submitted ({len(payload)} bytes) -> {job.state}",
        data={"import_run_id": str(run.id) if run else None,
              "scanner": source, "exit_code": exit_code,
              "coverage_attested": attested, "scan_stats": dict(stats) if stats else None},
    )
    _release_agent(session, agent)
    audit.record(
        session, action="agent.job_finished", object_type="agent_job", object_id=job.id,
        object_label=f"{job.tool} {job.target}", organization_id=agent.organization_id,
        actor_label=f"agent:{agent.slug}",
        changes={"state": job.state, "import_run_id": str(run.id) if run else None,
                 "output_bytes": job.output_bytes},
    )
    return {
        "job_id": str(job.id),
        "state": job.state,
        "import_run_id": str(run.id) if run else None,
        "findings_created": run.findings_created if run else 0,
        "findings_updated": run.findings_updated if run else 0,
        "findings_closed_absent": run.findings_closed_absent if run else 0,
        "coverage_attested": attested,
        "error": job.error,
    }


def submit_inventory(
    session: Session,
    agent: ExecAgent,
    *,
    target: str,
    items: Sequence[Mapping[str, Any]],
    operating_system: str | None = None,
    os_version: str | None = None,
    replace: bool = True,
    correlate: bool = True,
) -> dict[str, Any]:
    """Record a host's installed software as reported by an execution agent.

    This is the piece that makes correlation continuous instead of episodic. A
    scanner tells you what was vulnerable at the moment it ran; an inventory
    tells you what you have, so a CVE published tomorrow raises a finding
    tomorrow without anyone re-scanning anything.

    It is deliberately held to the *same* target policy as a scan. An agent that
    could rewrite inventory for any host would be able to make an asset look
    clean (report nothing) or bury the queue (report a thousand fictional
    packages) on infrastructure it was never authorised to touch, without ever
    running a scanner. So: allowlist, deny rules, reserved-range literal rule
    and `require_asset_match` all apply exactly as they do in `queue_job`.

    `replace` defaults to True because a package-manager sweep is *complete*
    information: software the sweep no longer lists is genuinely gone, and
    keeping it would leave findings open against a package that was removed. It
    is scoped to this agent's own `detected_by`, so it never deletes what an
    operator entered by hand or what another source reported.
    """
    from . import correlation as correlation_service
    from . import inventory as inventory_service

    decision = authorise_target(session, agent.organization_id, agent, target)

    asset = None
    if decision.asset_id is not None:
        asset = session.get(Asset, decision.asset_id)
    if asset is None:
        if agent.require_asset_match:
            # authorise_target already refuses this case; belt and braces, in
            # case the policy changes between the two reads.
            raise TargetRefused(
                f"{decision.host} is not a registered asset and agent "
                f"{agent.slug} requires it"
            )
        # Only reachable for an agent an operator explicitly put in discovery
        # mode. Creating the asset is the point of that mode.
        asset, _ = inventory_service.upsert_asset(
            session, agent.organization_id,
            {"name": decision.host, "hostname": decision.host,
             "operating_system": operating_system, "os_version": os_version},
        )

    if operating_system and not asset.operating_system:
        asset.operating_system = operating_system
    if os_version and not asset.os_version:
        asset.os_version = os_version

    source = f"agent:{agent.slug}"
    result = inventory_service.install(
        session, asset, items, detected_by=source, replace=replace
    )
    agent.last_seen_at = dt.datetime.now(dt.timezone.utc)

    out: dict[str, Any] = {
        "asset_id": str(asset.id), "asset": asset.name, "source": source,
        "items": len(items), **{k: result[k] for k in
                                ("added", "updated", "removed", "anchored",
                                 "matched", "unmatched")},
    }
    if correlate:
        out["correlation"] = correlation_service.correlate_asset(
            session, agent.organization_id, asset
        )
    # The per-row verdicts matter to whoever has to fix a name, but a 900-package
    # sweep would make the response unreadable; only the failures are returned.
    out["unmatched_detail"] = [
        r for r in result["results"] if not r.get("matched")
    ][:100]
    return out


def fail_job(
    session: Session, agent: ExecAgent, job: AgentJob, *, error: str, exit_code: int | None = None,
    requeue: bool = True,
) -> AgentJob:
    """The agent could not run the job. Requeue while attempts remain."""
    job.error = (error or "agent reported failure")[:2000]
    job.exit_code = exit_code
    job.lease_token = None
    if requeue and job.attempts < job.max_attempts:
        job.state = JobState.QUEUED.value
        job.agent_id = job.requested_agent_id
        job.lease_expires_at = None
    else:
        job.state = JobState.FAILED.value
        job.finished_at = dt.datetime.now(dt.timezone.utc)
    session.flush()
    append_event(session, job, kind=JobEventKind.STATUS.value,
                 message=f"failed: {job.error}", data={"state": job.state})
    _release_agent(session, agent)
    return job


def cancel_job(
    session: Session, job: AgentJob, *, actor_id: uuid.UUID | None = None, note: str | None = None
) -> AgentJob:
    if job.is_terminal:
        raise AgentError(f"job is already {job.state}")
    job.state = JobState.CANCELLED.value
    job.finished_at = dt.datetime.now(dt.timezone.utc)
    job.lease_token = None
    job.error = note
    session.flush()
    append_event(session, job, kind=JobEventKind.STATUS.value,
                 message=f"cancelled{': ' + note if note else ''}")
    audit.record(
        session, action="agent.job_cancelled", object_type="agent_job", object_id=job.id,
        object_label=f"{job.tool} {job.target}", organization_id=job.organization_id,
        actor_id=actor_id,
    )
    return job


def _release_agent(session: Session, agent: ExecAgent) -> None:
    if agent.status == AgentStatus.BUSY.value and active_job_count(session, agent) == 0:
        agent.status = AgentStatus.IDLE.value
        session.flush()


# ---------------------------------------------------------------------------
# Housekeeping (scheduled)
# ---------------------------------------------------------------------------
def reap_expired_leases(
    session: Session, organization_id: uuid.UUID | None = None, *, now: dt.datetime | None = None
) -> dict[str, int]:
    """Requeue or expire jobs whose holder went silent.

    A job that runs out of attempts becomes EXPIRED, not FAILED: nothing is
    known about whether the scan ever ran, and reporting "the scan failed"
    would invite reading it as "we looked and the host was fine".
    """
    now = now or dt.datetime.now(dt.timezone.utc)
    stmt = select(AgentJob).where(
        AgentJob.state.in_((JobState.LEASED.value, JobState.RUNNING.value)),
        AgentJob.lease_expires_at.is_not(None),
        AgentJob.lease_expires_at < now,
    )
    if organization_id is not None:
        stmt = stmt.where(AgentJob.organization_id == organization_id)

    requeued = expired = 0
    for job in session.execute(stmt).scalars().all():
        job.lease_token = None
        job.lease_expires_at = None
        if job.attempts < job.max_attempts:
            job.state = JobState.QUEUED.value
            job.agent_id = job.requested_agent_id
            requeued += 1
            append_event(session, job, kind=JobEventKind.STATUS.value,
                         message="lease expired; requeued")
        else:
            job.state = JobState.EXPIRED.value
            job.finished_at = now
            job.error = f"lease expired after {job.attempts} attempts"
            expired += 1
            append_event(session, job, kind=JobEventKind.STATUS.value,
                         message="lease expired; no attempts left")
    session.flush()
    return {"requeued": requeued, "expired": expired}


def mark_stale_agents_offline(
    session: Session, organization_id: uuid.UUID | None = None, *,
    offline_after: int = DEFAULT_OFFLINE_AFTER, now: dt.datetime | None = None,
) -> int:
    now = now or dt.datetime.now(dt.timezone.utc)
    cutoff = now - dt.timedelta(seconds=offline_after)
    stmt = select(ExecAgent).where(
        ExecAgent.status.in_((AgentStatus.IDLE.value, AgentStatus.BUSY.value)),
        or_(ExecAgent.last_heartbeat_at.is_(None), ExecAgent.last_heartbeat_at < cutoff),
    )
    if organization_id is not None:
        stmt = stmt.where(ExecAgent.organization_id == organization_id)
    count = 0
    for agent in session.execute(stmt).scalars().all():
        agent.status = AgentStatus.OFFLINE.value
        count += 1
    session.flush()
    return count


def queue_summary(session: Session, organization_id: uuid.UUID) -> dict[str, int]:
    rows = session.execute(
        select(AgentJob.state, func.count(AgentJob.id))
        .where(AgentJob.organization_id == organization_id)
        .group_by(AgentJob.state)
    ).all()
    summary = {state: 0 for state in
               [s.value for s in JobState]}
    for state, count in rows:
        summary[state] = int(count)
    summary["active"] = sum(
        summary[s] for s in ACTIVE_JOB_STATES if s in summary
    )
    summary["terminal"] = sum(
        summary[s] for s in TERMINAL_JOB_STATES if s in summary
    )
    return summary
