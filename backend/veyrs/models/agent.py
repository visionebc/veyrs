"""Execution agents: remote workers that RUN scanners (spec section 33).

Faraday's contribution to this platform is the idea that the tool does not have
to be driven by a human on a laptop: a long-lived agent sits inside a network
segment, receives work, executes a scanner and streams the result back. VEYRS
until now could only *import* what somebody else had already run.

The concept is reimplemented here; **no Faraday code was read or copied**. That
matters legally - Faraday is GPL-3.0 and VEYRS is not - and it matters
technically, because Faraday's agent model has a property VEYRS must not
inherit: its agents accept the arguments the server sends. That makes the
server's job queue a remote shell for every network the agents live in.

So the trust model here is inverted, and the inversion is the whole design:

* **The server never sends a command line.** A job is
  ``{tool, target, profile, params}``. The agent owns the mapping from that to
  an argv, refuses tools it does not implement, and never interpolates a string
  into a shell. A compromised VEYRS can ask for nmap against an authorised
  target; it cannot ask for ``sh -c``.
* **A declared tool is not an authorised tool.** An agent advertises what it can
  run; an operator decides what it may run (``AgentTool.enabled``, default
  False). Enrolment therefore grants zero execution rights on its own.
* **A target must be in scope.** Every job is checked against the agent's
  network policy AND, by default, against the tenant's own asset register. An
  agent cannot be pointed at a third party, at loopback, or at the cloud
  metadata endpoint. See ``services/agents.authorise_target()``.
* **Every dispatch is an audit record**, because "who scanned that host on the
  14th, and who approved it" is the first question after an incident.

The reward for the constraint: results come back through exactly the ingestion
core built in the previous phase. An agent run is an ``ImportRun`` bound to the
job's Engagement/ScanTest, so dedupe, sightings and scoped reconciliation all
work identically whether a human uploaded the file or an agent produced it.
"""
from __future__ import annotations

import datetime as dt
import enum
import uuid

from sqlalchemy import (
    Boolean, DateTime, ForeignKey, Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .base import Base, TenantMixin, TimestampMixin, uuid_pk


class AgentStatus(str, enum.Enum):
    #: Enrolled, token issued, has never checked in.
    PENDING = "pending"
    IDLE = "idle"
    BUSY = "busy"
    #: Missed enough heartbeats to be presumed gone. Jobs stop being offered.
    OFFLINE = "offline"
    #: Operator switched it off. Authentication still succeeds (so the agent can
    #: be told why) but it is never leased work.
    DISABLED = "disabled"


ACTIVE_AGENT_STATES = frozenset({AgentStatus.IDLE.value, AgentStatus.BUSY.value})


class JobState(str, enum.Enum):
    QUEUED = "queued"
    #: Claimed by an agent, holding a time-limited lease.
    LEASED = "leased"
    RUNNING = "running"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"
    #: The lease expired too many times. Distinct from FAILED: nothing is known
    #: about whether the scan ran, so it must not be read as "the host is clean".
    EXPIRED = "expired"


TERMINAL_JOB_STATES = frozenset({
    JobState.SUCCEEDED.value, JobState.FAILED.value,
    JobState.CANCELLED.value, JobState.EXPIRED.value,
})
ACTIVE_JOB_STATES = frozenset({
    JobState.QUEUED.value, JobState.LEASED.value, JobState.RUNNING.value,
})


class JobEventKind(str, enum.Enum):
    STDOUT = "stdout"
    STDERR = "stderr"
    PROGRESS = "progress"
    STATUS = "status"
    #: A partial result the agent chose to stream before finishing.
    PARTIAL = "partial"


class ExecAgent(Base, TenantMixin, TimestampMixin):
    """A registered remote worker.

    Named ``ExecAgent`` and not ``Agent`` because ``services/ai`` already owns
    the word "agent" for LLM assistants, and a schema in which ``agents`` means
    two unrelated things is a bug waiting for a Friday.
    """

    __tablename__ = "exec_agents"
    __table_args__ = (
        UniqueConstraint("organization_id", "slug"),
        # Global, not per-tenant: the token prefix IS the lookup key at
        # authentication time, when the tenant is not yet known.
        UniqueConstraint("token_prefix"),
        Index("ix_exec_agents_org_status", "organization_id", "status"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    name: Mapped[str] = mapped_column(String(200), nullable=False)
    slug: Mapped[str] = mapped_column(String(120), nullable=False)
    description: Mapped[str | None] = mapped_column(Text, default=None)

    #: veyrsagent_<prefix>_<secret>; only the Argon2 hash of the secret is
    #: stored, exactly as for user API keys.
    token_prefix: Mapped[str] = mapped_column(String(16), nullable=False)
    token_hash: Mapped[str] = mapped_column(String(255), nullable=False)
    token_issued_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )

    status: Mapped[str] = mapped_column(
        String(20), default=AgentStatus.PENDING.value, nullable=False
    )
    agent_version: Mapped[str | None] = mapped_column(String(40), default=None)
    hostname: Mapped[str | None] = mapped_column(String(255), default=None)
    platform: Mapped[str | None] = mapped_column(String(120), default=None)
    #: Where the agent called from, as observed by the API. Not self-reported:
    #: an agent that claims to be somewhere else is exactly the case to catch.
    last_ip: Mapped[str | None] = mapped_column(String(64), default=None)
    last_heartbeat_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )

    # --- execution policy ---------------------------------------------------
    #: Hosts/networks this agent may be pointed at. Entries are CIDRs
    #: (10.0.0.0/24), bare addresses, or name globs (*.acme.example).
    #: EMPTY MEANS NOTHING IS ALLOWED, not everything: an agent enrolled and
    #: forgotten must be inert, and fail-open here means scanning strangers.
    allowed_targets: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    #: Evaluated after the allowlist and wins over it. For carve-outs inside an
    #: allowed range (the DC gateway, a fragile PLC).
    denied_targets: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    #: Also require the target to resolve to an asset in the tenant's register.
    #: On by default: the estate is the authorisation boundary VEYRS already
    #: maintains, and "I only scan what I have written down that I own" is the
    #: answer an abuse complaint needs.
    require_asset_match: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: Newly declared tools are usable immediately. Off by default; turning it
    #: on means an agent binary upgrade can silently widen what it may run.
    auto_enable_tools: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    max_concurrency: Mapped[int] = mapped_column(Integer, default=1, nullable=False)
    #: Seconds an agent may hold a claimed job before the lease is reaped.
    lease_seconds: Mapped[int] = mapped_column(Integer, default=900, nullable=False)

    labels: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    meta: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    created_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    disabled_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)

    tools: Mapped[list["AgentTool"]] = relationship(
        back_populates="agent", cascade="all, delete-orphan", lazy="selectin",
    )

    @property
    def is_enabled(self) -> bool:
        return self.status != AgentStatus.DISABLED.value

    @property
    def can_receive_work(self) -> bool:
        return self.status in ACTIVE_AGENT_STATES


class AgentTool(Base, TenantMixin, TimestampMixin):
    """One scanner an agent says it has, and whether an operator allows it.

    ``parser`` is the key into ``services/importers.PARSERS`` used to interpret
    this tool's output. It is stored per agent-tool rather than inferred from
    the name so an agent can expose a wrapper (nuclei-web) that still produces
    parsable Nuclei JSON.
    """

    __tablename__ = "agent_tools"
    __table_args__ = (
        UniqueConstraint("organization_id", "agent_id", "name"),
        Index("ix_agent_tools_org_name", "organization_id", "name"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    agent_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("exec_agents.id", ondelete="CASCADE"), nullable=False
    )
    name: Mapped[str] = mapped_column(String(60), nullable=False)
    tool_version: Mapped[str | None] = mapped_column(String(60), default=None)
    #: Parser key for this tool's output. NULL = results are accepted but must
    #: name their own format on submission.
    parser: Mapped[str | None] = mapped_column(String(60), default=None)
    #: The operator's decision. Declaration alone never grants execution.
    enabled: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    #: Profile names the agent implements ("quick", "full", "safe"). The server
    #: validates a job's profile against this list instead of accepting free
    #: text that the agent would then have to interpret.
    profiles: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    declared_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    meta: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    agent: Mapped[ExecAgent] = relationship(back_populates="tools")


class AgentJob(Base, TenantMixin, TimestampMixin):
    """One unit of work: run this tool against this target, in this scope."""

    __tablename__ = "agent_jobs"
    __table_args__ = (
        Index("ix_agent_jobs_org_state", "organization_id", "state"),
        Index("ix_agent_jobs_agent_state", "agent_id", "state"),
        Index("ix_agent_jobs_queue", "organization_id", "state", "priority"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    #: NULL = queued for any capable agent in the tenant. Set on claim.
    agent_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("exec_agents.id", ondelete="SET NULL"), default=None
    )
    #: The agent originally requested, if the job was pinned to one. Kept
    #: separate from agent_id so a reaped-and-requeued job still remembers it.
    requested_agent_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("exec_agents.id", ondelete="SET NULL"), default=None
    )

    tool: Mapped[str] = mapped_column(String(60), nullable=False)
    #: Hostname, FQDN, IP or URL. One target per job: a job is the unit of
    #: authorisation, and a list would make a partial refusal ambiguous.
    target: Mapped[str] = mapped_column(String(500), nullable=False)
    profile: Mapped[str | None] = mapped_column(String(60), default=None)
    #: Structured knobs the agent maps onto its own argv. Never a command line.
    params: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    #: Where the results land. Scoping is not optional: an agent result is an
    #: import, and an unscoped import cannot be reconciled.
    engagement_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("engagements.id", ondelete="SET NULL"), default=None
    )
    test_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("scan_tests.id", ondelete="SET NULL"), default=None
    )
    #: Asset the target resolved to at authorisation time, when it did.
    asset_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("assets.id", ondelete="SET NULL"), default=None
    )

    state: Mapped[str] = mapped_column(String(20), default=JobState.QUEUED.value, nullable=False)
    priority: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    #: Free-text justification. Required by the API: an unexplained scan against
    #: production is the thing the audit trail exists to make expensive.
    reason: Mapped[str | None] = mapped_column(Text, default=None)

    requested_by_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )

    #: Opaque secret returned only to the claiming agent. Every subsequent write
    #: to the job must present it, so a second agent holding a stale copy of the
    #: job id cannot overwrite the winner's results.
    lease_token: Mapped[str | None] = mapped_column(String(64), default=None)
    leased_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    lease_expires_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )
    attempts: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    max_attempts: Mapped[int] = mapped_column(Integer, default=3, nullable=False)

    started_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    finished_at: Mapped[dt.datetime | None] = mapped_column(DateTime(timezone=True), default=None)
    exit_code: Mapped[int | None] = mapped_column(Integer, default=None)
    error: Mapped[str | None] = mapped_column(Text, default=None)

    #: The ingestion this job's output produced. The join that makes an agent
    #: run indistinguishable from a manual upload downstream.
    import_run_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("import_runs.id", ondelete="SET NULL"), default=None
    )
    output_bytes: Mapped[int | None] = mapped_column(Integer, default=None)
    output_sha256: Mapped[str | None] = mapped_column(String(64), default=None)
    #: Sequence number of the last streamed event, so a console can poll with
    #: ?since_seq= without counting rows.
    last_event_seq: Mapped[int] = mapped_column(Integer, default=0, nullable=False)

    meta: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)

    @property
    def is_terminal(self) -> bool:
        return self.state in TERMINAL_JOB_STATES


class AgentJobEvent(Base, TenantMixin):
    """A streamed line of a job's progress. Append-only, monotonic per job.

    Streaming lives in the database rather than in Redis pub/sub on purpose: the
    console needs the scrollback of a run that finished yesterday as much as the
    live tail of one running now, and one durable log serves both. ``seq`` is
    assigned server-side from ``AgentJob.last_event_seq`` so a retrying agent
    cannot renumber history.
    """

    __tablename__ = "agent_job_events"
    __table_args__ = (
        UniqueConstraint("organization_id", "job_id", "seq"),
        Index("ix_agent_job_events_job_seq", "job_id", "seq"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    job_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("agent_jobs.id", ondelete="CASCADE"), nullable=False
    )
    seq: Mapped[int] = mapped_column(Integer, nullable=False)
    kind: Mapped[str] = mapped_column(
        String(20), default=JobEventKind.STDOUT.value, nullable=False
    )
    message: Mapped[str | None] = mapped_column(Text, default=None)
    data: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    created_at: Mapped[dt.datetime] = mapped_column(
        DateTime(timezone=True), nullable=False,
        default=lambda: dt.datetime.now(dt.timezone.utc),
    )
