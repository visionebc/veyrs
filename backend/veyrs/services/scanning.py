"""Active scanning: the switch that decides whether VEYRS probes anything.

VEYRS does two different jobs and only one of them touches the estate. It
**ingests** what scanners report -- uploads, connector pulls, agent results --
and it **executes** scans itself, through an enrolled agent running nuclei. An
operator who already owns a scanner wants the first job and not the second: the
platform becomes vulnerability management and traceability, and somebody else's
tool does the probing.

Turning that off is not a UI concern. Hiding a button leaves the API, the queue
and the agent exactly as they were -- the same defect class as the MFA that
checked a code was *present* (phase 24): a control that looks enforced and is
not. So the switch is enforced where work is CREATED and where it is HANDED
OUT, and it is deliberately NOT enforced where work is FINISHED:

===================== ========= ==================================================
call                  with off  why
===================== ========= ==================================================
``queue_job``         refused   no new scan is scheduled.
``claim_next``        refused   **this is the one that matters.** Without it, a
                                backlog queued before the flip drains afterwards
                                and the estate gets scanned by a platform whose
                                operator believes it was stopped.
``enroll``            refused   a runner cannot be added to a platform that does
                                not run scans.
``heartbeat``         allowed   and answers ``active_scanning: false`` so a live
                                agent learns to stand down instead of polling a
                                door that is now locked.
``submit_result``     allowed   a scan already in flight when the switch flipped
                                has ALREADY touched the estate. Refusing its
                                output discards the only thing of value it
                                produced and wedges the job in ``running``
                                forever.
``/self/inventory``   allowed   reporting what is installed is not scanning, and
                                a platform that stops taking inventory blinds
                                its own correlation engine -- the capability an
                                ingest-only deployment leans on hardest.
``run_import``        allowed   ingestion is the entire point of the mode.
===================== ========= ==================================================

**Queued jobs are cancelled when the switch is turned off**, unless the caller
asks otherwise. A job that can never be claimed is not queued, it is stuck, and
a queue depth that only counts work nobody will ever do is a lie the operator
reads on the dashboard.

The state lives in ``organizations.settings["scanning"]`` -- the same JSONB the
team-scope guardrail uses (``security/scope.py``) -- rather than in a new
column, because it is tenant policy and not an entity.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.agent import AgentJob, JobState
from ..models.tenancy import Organization

#: Key under ``organizations.settings``.
SETTINGS_KEY = "scanning"

#: Default when the key is absent. True preserves the behaviour of every
#: deployment that existed before the switch: a platform does not silently stop
#: doing what its operator configured it to do because it was upgraded.
DEFAULT_ENABLED = True


class ScanningDisabled(RuntimeError):
    """Raised where work would be created or handed out with scanning off."""


def _block(organization: Organization | None) -> dict[str, Any]:
    settings = (organization.settings or {}) if organization is not None else {}
    block = settings.get(SETTINGS_KEY)
    return dict(block) if isinstance(block, dict) else {}


def state(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """The switch as the console and the agent should read it."""
    organization = session.get(Organization, organization_id)
    block = _block(organization)
    return {
        "active_scanning_enabled": bool(block.get("enabled", DEFAULT_ENABLED)),
        "changed_at": block.get("changed_at"),
        "changed_by_id": block.get("changed_by_id"),
        "reason": block.get("reason"),
        # Never defaulted away: an operator reading "disabled" needs to know
        # whether that is a decision somebody made or the shipped default.
        "explicit": "enabled" in block,
    }


def is_enabled(session: Session, organization_id: uuid.UUID) -> bool:
    return bool(state(session, organization_id)["active_scanning_enabled"])


def require_enabled(session: Session, organization_id: uuid.UUID, what: str) -> None:
    """Refuse `what` when the tenant has turned active scanning off."""
    if not is_enabled(session, organization_id):
        raise ScanningDisabled(
            f"active scanning is disabled for this organization, so {what} is "
            "refused; VEYRS is running as an ingest-only vulnerability "
            "management platform. Re-enable it in Administration -> Scanning."
        )


def queued_job_count(session: Session, organization_id: uuid.UUID) -> int:
    return len(session.execute(
        select(AgentJob.id).where(
            AgentJob.organization_id == organization_id,
            AgentJob.state == JobState.QUEUED.value,
        )
    ).scalars().all())


def cancel_queued(
    session: Session,
    organization_id: uuid.UUID,
    *,
    reason: str,
    actor_id: uuid.UUID | None = None,
) -> int:
    """Cancel work that can no longer be claimed. Running jobs are left alone.

    A leased or running job is finishing something that already happened on the
    estate; cancelling it here would strand output that ``submit_result`` is
    still willing to accept.

    It goes through ``agents.cancel_job`` rather than a bulk UPDATE so each
    cancellation lands in the job's own event stream AND in the audit log --
    the same trail a hand cancellation leaves. A silent bulk state change is
    how a queue empties itself with nobody able to say who emptied it.
    """
    from . import agents as agent_service

    jobs = session.execute(
        select(AgentJob).where(
            AgentJob.organization_id == organization_id,
            AgentJob.state == JobState.QUEUED.value,
        )
    ).scalars().all()
    for job in jobs:
        agent_service.cancel_job(session, job, actor_id=actor_id, note=reason)
    return len(jobs)


def set_enabled(
    session: Session,
    organization_id: uuid.UUID,
    enabled: bool,
    *,
    actor_id: uuid.UUID | None = None,
    reason: str | None = None,
    cancel_queued_jobs: bool = True,
) -> dict[str, Any]:
    """Flip the switch. Returns the new state plus what the flip did."""
    organization = session.get(Organization, organization_id)
    if organization is None:
        raise ValueError("organization not found")

    block = _block(organization)
    block.update({
        "enabled": bool(enabled),
        "changed_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "changed_by_id": str(actor_id) if actor_id else None,
        "reason": (reason or "").strip()[:500] or None,
    })
    # Reassign rather than mutate in place: SQLAlchemy does not track mutation
    # of a plain dict inside JSONB, and an in-place update is a write that
    # silently does not happen.
    settings = dict(organization.settings or {})
    settings[SETTINGS_KEY] = block
    organization.settings = settings
    session.flush()

    cancelled = 0
    if not enabled and cancel_queued_jobs:
        cancelled = cancel_queued(
            session, organization_id, actor_id=actor_id,
            reason="active scanning was disabled for this organization",
        )

    result = state(session, organization_id)
    result["jobs_cancelled"] = cancelled
    return result
