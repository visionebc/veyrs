"""Execution agents: control plane and agent data plane (spec section 33).

Two audiences share one prefix and must never share a credential:

* `/agents/...` - operators, authorised by the usual `Principal` +
  `agent:{read,write,admin}` permissions. Enrol agents, decide which tools they
  may run, queue work, watch it, cancel it.
* `/agents/self/...` - the agents themselves, authorised by `X-Agent-Token`.
  Four verbs and nothing else. An agent token reaching any other route is a
  401, because `get_principal()` does not know how to parse it and never will.

Route order in this file is load-bearing: `/self/*` and `/jobs/*` are declared
before `/{agent_id}`, or FastAPI would try to parse "jobs" as a UUID and answer
422 to a perfectly good request.

Permission mapping:
  * `agent:admin` - enrol, rotate a token, delete, change execution policy,
    enable a tool. Everything that WIDENS what may be executed where.
  * `agent:write` - queue and cancel jobs within the policy an admin set.
  * `agent:read`  - see agents, jobs and their output.
"""
from __future__ import annotations

import datetime as dt
import json
import uuid
from typing import Annotated, Any

from fastapi import (APIRouter, Body, Depends, Header, HTTPException, Query, Request,
                     Response, status)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, select

from ...models import ACTIVE_JOB_STATES, AgentJob, AgentTool, ExecAgent
from ...security.agent_auth import AgentSession, CurrentAgent
from ...security.deps import Principal, TenantSession, require
from ...services import agents as agent_service
from ...services import audit, scanning
from .schemas import Page

router = APIRouter(prefix="/agents", tags=["agents"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class AgentToolOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    tool_version: str | None
    parser: str | None
    enabled: bool
    profiles: list
    declared_at: dt.datetime | None


class AgentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    name: str
    slug: str
    description: str | None
    status: str
    agent_version: str | None
    hostname: str | None
    platform: str | None
    last_ip: str | None
    last_heartbeat_at: dt.datetime | None
    allowed_targets: list
    denied_targets: list
    require_asset_match: bool
    auto_enable_tools: bool
    max_concurrency: int
    lease_seconds: int
    labels: list
    created_at: dt.datetime
    tools: list[AgentToolOut] = []


class AgentEnrolled(AgentOut):
    token: str = Field(
        description="Shown exactly once. VEYRS stores only its Argon2 hash."
    )


class AgentCreate(BaseModel):
    name: str = Field(min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    #: Deny-by-default. An agent with an empty allowlist can run nothing, which
    #: is the correct state for a half-finished enrolment.
    allowed_targets: list[str] = Field(default_factory=list, max_length=200)
    denied_targets: list[str] = Field(default_factory=list, max_length=200)
    require_asset_match: bool = True
    auto_enable_tools: bool = False
    max_concurrency: int = Field(default=1, ge=1, le=32)
    lease_seconds: int = Field(default=900, ge=60, le=86_400)
    labels: list[str] = Field(default_factory=list, max_length=40)


class AgentUpdate(BaseModel):
    name: str | None = Field(default=None, min_length=2, max_length=200)
    description: str | None = Field(default=None, max_length=4000)
    status: str | None = None
    allowed_targets: list[str] | None = Field(default=None, max_length=200)
    denied_targets: list[str] | None = Field(default=None, max_length=200)
    require_asset_match: bool | None = None
    auto_enable_tools: bool | None = None
    max_concurrency: int | None = Field(default=None, ge=1, le=32)
    lease_seconds: int | None = Field(default=None, ge=60, le=86_400)
    labels: list[str] | None = Field(default=None, max_length=40)


class ToolToggle(BaseModel):
    enabled: bool


class JobOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    agent_id: uuid.UUID | None
    requested_agent_id: uuid.UUID | None
    tool: str
    target: str
    profile: str | None
    params: dict
    engagement_id: uuid.UUID | None
    test_id: uuid.UUID | None
    asset_id: uuid.UUID | None
    state: str
    priority: int
    reason: str | None
    attempts: int
    max_attempts: int
    leased_at: dt.datetime | None
    lease_expires_at: dt.datetime | None
    started_at: dt.datetime | None
    finished_at: dt.datetime | None
    exit_code: int | None
    error: str | None
    import_run_id: uuid.UUID | None
    output_bytes: int | None
    last_event_seq: int
    created_at: dt.datetime


class JobCreate(BaseModel):
    tool: str = Field(min_length=1, max_length=60)
    target: str = Field(min_length=1, max_length=500)
    #: None = queue for any capable agent. The claiming agent's own policy is
    #: then what authorises the target, checked again at claim time.
    agent_id: uuid.UUID | None = None
    profile: str | None = Field(default=None, max_length=60)
    params: dict[str, Any] = Field(default_factory=dict)
    engagement_id: uuid.UUID | None = None
    #: Not optional. It lands in the audit trail, and "why was this host
    #: scanned" is the question that trail exists to answer.
    reason: str = Field(min_length=5, max_length=2000)
    priority: int = Field(default=0, ge=-100, le=100)
    max_attempts: int = Field(default=3, ge=1, le=10)


class JobEventOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    seq: int
    kind: str
    message: str | None
    data: dict
    created_at: dt.datetime


class HeartbeatIn(BaseModel):
    agent_version: str | None = Field(default=None, max_length=40)
    hostname: str | None = Field(default=None, max_length=255)
    platform: str | None = Field(default=None, max_length=120)
    #: [{"name": "nuclei", "version": "3.2.0", "parser": "nuclei",
    #:   "profiles": ["quick", "full"]}]
    tools: list[dict[str, Any]] | None = Field(default=None, max_length=200)


class EventIn(BaseModel):
    kind: str = "stdout"
    message: str | None = Field(default=None, max_length=8000)
    data: dict[str, Any] = Field(default_factory=dict)


class EventBatch(BaseModel):
    events: list[EventIn] = Field(min_length=1, max_length=200)


class JobFailure(BaseModel):
    error: str = Field(min_length=1, max_length=4000)
    exit_code: int | None = None
    requeue: bool = True


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------
def _agent_or_404(session, organization_id: uuid.UUID, agent_id: uuid.UUID) -> ExecAgent:
    row = session.get(ExecAgent, agent_id)
    if row is None or row.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "agent not found")
    return row


def _job_or_404(session, organization_id: uuid.UUID, job_id: uuid.UUID) -> AgentJob:
    row = session.get(AgentJob, job_id)
    if row is None or row.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "job not found")
    return row


def _refused(exc: Exception) -> HTTPException:
    """Map a service refusal to a status code, with its explanation intact.

    The messages here are written for the operator who has to fix the policy,
    so they are passed through rather than flattened into "forbidden".

    422 says "your request cannot be processed as submitted", which is true of
    an unauthorised target or an unknown tool and false of a platform that does
    not scan at all: there is no correction to the body that would make it
    work. That one is **403** -- the same distinction phase 28 drew for
    estate-wide policy writes, and the only answer that tells an operator to go
    and change a setting rather than go and fix their JSON.
    """
    if isinstance(exc, agent_service.ScanningRefused):
        return HTTPException(status.HTTP_403_FORBIDDEN, str(exc))
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, str(exc))


# ===========================================================================
# AGENT DATA PLANE - X-Agent-Token only. Declared first; see module docstring.
# ===========================================================================
@router.post("/self/heartbeat", summary="Agent check-in and capability declaration")
def agent_heartbeat(
    body: HeartbeatIn,
    request: Request,
    agent: CurrentAgent,
    session: AgentSession,
) -> dict[str, Any]:
    result = agent_service.heartbeat(
        session, agent,
        agent_version=body.agent_version,
        hostname=body.hostname,
        platform=body.platform,
        ip_address=request.client.host if request.client else None,
        tools=body.tools,
    )
    # The agent is TOLD, rather than left to discover it by being refused at
    # claim time: a runner that knows scanning is off can idle quietly instead
    # of hammering a door that now answers 403 forever.
    result["active_scanning"] = scanning.is_enabled(session, agent.organization_id)
    session.commit()
    return {"agent_id": str(agent.id), "slug": agent.slug, **result}


@router.post("/self/jobs/claim", summary="Lease the next authorised job")
def agent_claim(
    agent: CurrentAgent,
    session: AgentSession,
    response: Response,
) -> dict[str, Any] | None:
    try:
        job = agent_service.claim_next(session, agent)
    except agent_service.AgentError as exc:
        raise HTTPException(status.HTTP_403_FORBIDDEN, str(exc)) from exc
    if job is None:
        session.commit()
        response.status_code = status.HTTP_204_NO_CONTENT
        return None
    session.commit()
    # The lease token is returned ONCE, to the winner only. It is the proof of
    # ownership every later write to this job must present.
    return {
        "job": JobOut.model_validate(job).model_dump(mode="json"),
        "lease_token": job.lease_token,
        "lease_expires_at": job.lease_expires_at.isoformat() if job.lease_expires_at else None,
    }


@router.post("/self/jobs/{job_id}/events", summary="Stream job output")
def agent_events(
    job_id: uuid.UUID,
    body: EventBatch,
    agent: CurrentAgent,
    session: AgentSession,
    x_lease_token: Annotated[str | None, Query(alias="lease_token")] = None,
) -> dict[str, Any]:
    job = _job_or_404(session, agent.organization_id, job_id)
    try:
        agent_service.verify_lease(job, agent, x_lease_token)
        result = agent_service.append_events(
            session, job, [e.model_dump() for e in body.events]
        )
    except agent_service.AgentError as exc:
        raise _refused(exc) from exc
    session.commit()
    return result


@router.post("/self/jobs/{job_id}/lease", summary="Extend a lease on a long scan")
def agent_extend_lease(
    job_id: uuid.UUID,
    agent: CurrentAgent,
    session: AgentSession,
    x_lease_token: Annotated[str | None, Query(alias="lease_token")] = None,
) -> dict[str, Any]:
    job = _job_or_404(session, agent.organization_id, job_id)
    try:
        agent_service.verify_lease(job, agent, x_lease_token)
        expires = agent_service.extend_lease(session, job, agent)
    except agent_service.AgentError as exc:
        raise _refused(exc) from exc
    session.commit()
    return {"job_id": str(job.id), "lease_expires_at": expires.isoformat()}


@router.post("/self/jobs/{job_id}/result", summary="Submit scanner output for ingestion")
async def agent_result(
    job_id: uuid.UUID,
    request: Request,
    agent: CurrentAgent,
    session: AgentSession,
    lease_token: str | None = Query(default=None),
    scanner: str | None = Query(default=None, max_length=60),
    exit_code: int = Query(default=0),
    filename: str | None = Query(default=None, max_length=400),
    x_agent_scan_stats: Annotated[str | None, Header()] = None,
) -> dict[str, Any]:
    """Raw request body = the scanner's output file, verbatim.

    An EMPTY body is meaningful - a completed scan that found nothing is what
    has to reach reconciliation for remediated findings to close - but only
    when ``X-Agent-Scan-Stats`` shows the scan actually covered the target. An
    empty body with no coverage is a blind scanner, and is refused.
    """
    job = _job_or_404(session, agent.organization_id, job_id)
    payload = await request.body()
    stats = None
    if x_agent_scan_stats:
        try:
            stats = json.loads(x_agent_scan_stats)
        except ValueError:
            stats = None
        if not isinstance(stats, dict):
            stats = None
    try:
        agent_service.verify_lease(job, agent, lease_token)
        result = agent_service.submit_result(
            session, agent, job, payload=payload, scanner=scanner,
            exit_code=exit_code, filename=filename, stats=stats,
        )
    except agent_service.AgentError as exc:
        raise _refused(exc) from exc
    session.commit()
    return result


class InventoryItemReport(BaseModel):
    cpe: str | None = Field(default=None, max_length=600)
    vendor: str | None = Field(default=None, max_length=200)
    product: str | None = Field(default=None, max_length=300)
    version: str | None = Field(default=None, max_length=120,
                                description="Upstream version, for CVE range matching")
    raw_version: str | None = Field(default=None, max_length=200,
                                    description="Verbatim package-manager version")
    install_path: str | None = None


class InventoryReport(BaseModel):
    """A host's complete installed-software list as the agent sees it."""

    target: str = Field(min_length=1, max_length=400,
                        description="The host this inventory belongs to. Subject to "
                                    "the agent's allowlist exactly like a scan target.")
    items: list[InventoryItemReport] = Field(default_factory=list, max_length=20000)
    operating_system: str | None = None
    os_version: str | None = None
    replace: bool = Field(
        default=True,
        description="A package-manager sweep is complete information, so the "
                    "default drops what this agent no longer reports. Set false "
                    "for a partial or filtered collection.",
    )


@router.post("/self/inventory", summary="Report a host's installed software")
def agent_inventory(
    body: InventoryReport,
    agent: CurrentAgent,
    session: AgentSession,
) -> dict[str, Any]:
    """Continuous correlation starts here.

    A scan says what was vulnerable when it ran. An inventory says what exists,
    so a CVE published next week raises a finding next week without anyone
    re-running anything. Refusals are 422 with the policy reason intact, because
    the fix is always a policy edit an operator has to make.
    """
    try:
        result = agent_service.submit_inventory(
            session, agent,
            target=body.target,
            items=[item.model_dump() for item in body.items],
            operating_system=body.operating_system,
            os_version=body.os_version,
            replace=body.replace,
        )
    except agent_service.AgentError as exc:
        raise _refused(exc) from exc
    session.commit()
    return result


@router.post("/self/jobs/{job_id}/fail", summary="Report that a job could not run")
def agent_fail(
    job_id: uuid.UUID,
    body: JobFailure,
    agent: CurrentAgent,
    session: AgentSession,
    lease_token: str | None = Query(default=None),
) -> JobOut:
    job = _job_or_404(session, agent.organization_id, job_id)
    try:
        agent_service.verify_lease(job, agent, lease_token)
        job = agent_service.fail_job(
            session, agent, job, error=body.error, exit_code=body.exit_code,
            requeue=body.requeue,
        )
    except agent_service.AgentError as exc:
        raise _refused(exc) from exc
    session.commit()
    return JobOut.model_validate(job)


# ===========================================================================
# CONTROL PLANE - jobs
# ===========================================================================
@router.get("/jobs", response_model=Page[JobOut])
def list_jobs(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:read"))],
    state: str | None = Query(default=None),
    agent_id: uuid.UUID | None = Query(default=None),
    tool: str | None = Query(default=None),
    active: bool = Query(default=False, description="Only queued/leased/running"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Page[JobOut]:
    statement = select(AgentJob).where(AgentJob.organization_id == principal.organization_id)
    if state:
        statement = statement.where(AgentJob.state == state)
    if active:
        statement = statement.where(AgentJob.state.in_(tuple(ACTIVE_JOB_STATES)))
    if agent_id:
        statement = statement.where(AgentJob.agent_id == agent_id)
    if tool:
        statement = statement.where(AgentJob.tool == tool.strip().lower())
    total = session.execute(select(func.count()).select_from(statement.subquery())).scalar_one()
    rows = session.execute(
        statement.order_by(AgentJob.created_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return Page(items=[JobOut.model_validate(r) for r in rows],
                total=total, limit=limit, offset=offset)


@router.post("/jobs", response_model=JobOut, status_code=201)
def queue_job(
    body: JobCreate,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:write"))],
) -> JobOut:
    target_agent = (
        _agent_or_404(session, principal.organization_id, body.agent_id)
        if body.agent_id else None
    )
    try:
        job = agent_service.queue_job(
            session, principal.organization_id,
            tool=body.tool, target=body.target, agent=target_agent,
            profile=body.profile, params=body.params, engagement_id=body.engagement_id,
            reason=body.reason, priority=body.priority, max_attempts=body.max_attempts,
            requested_by_id=principal.user_id,
        )
    except agent_service.AgentError as exc:
        raise _refused(exc) from exc
    session.commit()
    return JobOut.model_validate(job)


@router.get("/jobs/summary")
def jobs_summary(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:read"))],
) -> dict[str, int]:
    return agent_service.queue_summary(session, principal.organization_id)


@router.get("/jobs/{job_id}", response_model=JobOut)
def get_job(
    job_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:read"))],
) -> JobOut:
    return JobOut.model_validate(_job_or_404(session, principal.organization_id, job_id))


@router.get("/jobs/{job_id}/events", response_model=list[JobEventOut])
def job_events(
    job_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:read"))],
    since_seq: int = Query(default=0, ge=0),
    limit: int = Query(default=500, ge=1, le=2000),
) -> list[JobEventOut]:
    """Incremental tail. Poll with the last `seq` you saw.

    Deliberately not a websocket: the console needs yesterday's scrollback as
    much as today's tail, one durable log serves both, and a polling client
    survives a restart of either end without a reconnect protocol.
    """
    job = _job_or_404(session, principal.organization_id, job_id)
    rows = agent_service.read_events(session, job, since_seq=since_seq, limit=limit)
    return [JobEventOut.model_validate(r) for r in rows]


@router.post("/jobs/{job_id}/cancel", response_model=JobOut)
def cancel_job(
    job_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:write"))],
    note: str | None = Body(default=None, embed=True, max_length=2000),
) -> JobOut:
    job = _job_or_404(session, principal.organization_id, job_id)
    try:
        job = agent_service.cancel_job(session, job, actor_id=principal.user_id, note=note)
    except agent_service.AgentError as exc:
        raise _refused(exc) from exc
    session.commit()
    return JobOut.model_validate(job)


@router.post("/maintenance/reap", summary="Requeue expired leases, mark silent agents offline")
def reap(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:write"))],
    offline_after: int = Query(default=agent_service.DEFAULT_OFFLINE_AFTER, ge=30, le=86_400),
) -> dict[str, int]:
    """Idempotent housekeeping. Safe to call from cron as often as you like."""
    result = agent_service.reap_expired_leases(session, principal.organization_id)
    result["agents_offline"] = agent_service.mark_stale_agents_offline(
        session, principal.organization_id, offline_after=offline_after
    )
    session.commit()
    return result


# ===========================================================================
# CONTROL PLANE - agents
# ===========================================================================
@router.get("", response_model=Page[AgentOut])
def list_agents(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:read"))],
    status_filter: str | None = Query(default=None, alias="status"),
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Page[AgentOut]:
    statement = select(ExecAgent).where(ExecAgent.organization_id == principal.organization_id)
    if status_filter:
        statement = statement.where(ExecAgent.status == status_filter)
    total = session.execute(select(func.count()).select_from(statement.subquery())).scalar_one()
    rows = session.execute(
        statement.order_by(ExecAgent.created_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return Page(items=[AgentOut.model_validate(r) for r in rows],
                total=total, limit=limit, offset=offset)


@router.post("", response_model=AgentEnrolled, status_code=201)
def enroll_agent(
    body: AgentCreate,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:admin"))],
) -> AgentEnrolled:
    """Enrol an agent and return its token once.

    Requires `agent:admin`, not `agent:write`: enrolment creates a new place
    from which scans can originate, which is a change to the estate's attack
    surface rather than a day-to-day operation.
    """
    try:
        agent, token = agent_service.enroll(
            session, principal.organization_id,
            name=body.name, description=body.description,
            allowed_targets=body.allowed_targets, denied_targets=body.denied_targets,
            require_asset_match=body.require_asset_match,
            auto_enable_tools=body.auto_enable_tools,
            max_concurrency=body.max_concurrency, lease_seconds=body.lease_seconds,
            labels=body.labels, created_by_id=principal.user_id,
        )
    except agent_service.AgentError as exc:
        raise _refused(exc) from exc
    session.commit()
    payload = AgentOut.model_validate(agent).model_dump()
    return AgentEnrolled(**payload, token=token)


@router.get("/{agent_id}", response_model=AgentOut)
def get_agent_detail(
    agent_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:read"))],
) -> AgentOut:
    return AgentOut.model_validate(_agent_or_404(session, principal.organization_id, agent_id))


@router.patch("/{agent_id}", response_model=AgentOut)
def update_agent(
    agent_id: uuid.UUID,
    body: AgentUpdate,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:admin"))],
) -> AgentOut:
    agent = _agent_or_404(session, principal.organization_id, agent_id)
    changes = body.model_dump(exclude_unset=True)
    try:
        agent_service.validate_rules(
            list(changes.get("allowed_targets") or []) + list(changes.get("denied_targets") or [])
        )
        if "status" in changes and changes["status"] is not None:
            agent_service.set_status(session, agent, changes.pop("status"),
                                     actor_id=principal.user_id)
    except agent_service.AgentError as exc:
        raise _refused(exc) from exc
    for field, value in changes.items():
        if value is None:
            continue
        if field in ("allowed_targets", "denied_targets"):
            value = [str(v).strip().lower() for v in value]
        setattr(agent, field, value)
    session.flush()
    audit.record(session, action="agent.updated", object_type="exec_agent", object_id=agent.id,
                 object_label=agent.name, organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label,
                 changes={k: v for k, v in changes.items() if k != "description"})
    session.commit()
    return AgentOut.model_validate(agent)


@router.post("/{agent_id}/rotate-token")
def rotate_agent_token(
    agent_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:admin"))],
) -> dict[str, str]:
    agent = _agent_or_404(session, principal.organization_id, agent_id)
    token = agent_service.rotate_token(session, agent, actor_id=principal.user_id)
    session.commit()
    return {"agent_id": str(agent.id), "token": token}


@router.delete("/{agent_id}", status_code=204)
def delete_agent(
    agent_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:admin"))],
) -> Response:
    agent = _agent_or_404(session, principal.organization_id, agent_id)
    active = session.execute(
        select(func.count(AgentJob.id)).where(
            AgentJob.organization_id == principal.organization_id,
            AgentJob.agent_id == agent.id,
            AgentJob.state.in_(tuple(ACTIVE_JOB_STATES)),
        )
    ).scalar_one()
    if active:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            f"{active} job(s) are still queued or running on this agent; "
            "cancel them or disable the agent instead",
        )
    audit.record(session, action="agent.deleted", object_type="exec_agent", object_id=agent.id,
                 object_label=agent.name, organization_id=principal.organization_id,
                 actor_id=principal.user_id, actor_label=principal.label)
    session.delete(agent)
    session.commit()
    return Response(status_code=status.HTTP_204_NO_CONTENT)


@router.get("/{agent_id}/tools", response_model=list[AgentToolOut])
def list_agent_tools(
    agent_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:read"))],
) -> list[AgentToolOut]:
    agent = _agent_or_404(session, principal.organization_id, agent_id)
    rows = session.execute(
        select(AgentTool).where(
            AgentTool.organization_id == principal.organization_id,
            AgentTool.agent_id == agent.id,
        ).order_by(AgentTool.name)
    ).scalars().all()
    return [AgentToolOut.model_validate(r) for r in rows]


@router.patch("/{agent_id}/tools/{tool_name}", response_model=AgentToolOut)
def toggle_agent_tool(
    agent_id: uuid.UUID,
    tool_name: str,
    body: ToolToggle,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("agent:admin"))],
) -> AgentToolOut:
    """Authorise (or withdraw) one tool on one agent.

    This is the decision that turns a declaration into an execution right, so
    it sits behind `agent:admin` and lands in the audit trail.
    """
    agent = _agent_or_404(session, principal.organization_id, agent_id)
    try:
        row = agent_service.set_tool_enabled(
            session, agent, tool_name, body.enabled, actor_id=principal.user_id
        )
    except agent_service.AgentError as exc:
        raise _refused(exc) from exc
    session.commit()
    return AgentToolOut.model_validate(row)
