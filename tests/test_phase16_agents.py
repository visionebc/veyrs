"""Phase 16: execution agents.

What these tests are actually protecting, in order of how badly it would hurt
to get it wrong:

1. **The dispatcher is not a remote shell.** An agent is inert on enrolment,
   a declared tool is not an authorised tool, and a target outside policy is
   refused. The reserved-range and DNS-rebinding cases have their own tests
   because both are the difference between a scanner and an exfiltration tool.
2. **Authorisation is re-run at claim time.** An unpinned job must be refused
   to an agent whose own allowlist does not cover the target, even though the
   job was accepted when it was queued. Checking only once is the subtle hole.
3. **Results land in the existing ingestion core**, scope and all - including
   an EMPTY result, which is how an agent-run scan closes a fixed finding.
4. **Tenant isolation** holds for a credential type that authenticates before
   the tenant is known.
"""
from __future__ import annotations

import datetime as dt
import json
import uuid

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    Asset, AgentJob, AgentStatus, ExecAgent, Finding, ImportRun, JobState, OPEN_STATES,
)
from veyrs.services import agents as agent_service
from veyrs.services import engagements, risk as risk_service, sla as sla_service

# One critical finding on app.example.com, in the format the nuclei parser reads.
NUCLEI_HIT = (
    json.dumps({
        "template-id": "CVE-2021-44228",
        "info": {"name": "Apache Log4j2 RCE", "severity": "critical",
                 "classification": {"cve-id": ["CVE-2021-44228"], "cwe-id": ["CWE-502"],
                                    "cvss-score": 10.0}},
        "host": "https://app.example.com",
        "matched-at": "https://app.example.com/api/v1",
        "type": "http", "matcher-name": "jndi",
    }) + "\n"
).encode()

TOOLS = [{"name": "nuclei", "version": "3.2.0", "parser": "nuclei",
          "profiles": ["quick", "full"]}]


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def estate(org_a):
    """A tenant with one registered web asset and the usual policy seeds."""
    org_id, slug, email = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        asset = Asset(organization_id=org_id, name="app-01", hostname="app",
                      fqdn="app.example.com", ip_addresses=["10.44.0.10"],
                      asset_type="server", criticality="high", exposure="internet")
        session.add(asset)
        risk_service.seed_profiles(session, org_id)
        sla_service.seed_policies(session, org_id)
        session.commit()
        return {"org_id": org_id, "slug": slug, "email": email, "asset_id": asset.id}


def _enroll(session, org_id, **kwargs) -> tuple[ExecAgent, str]:
    kwargs.setdefault("name", f"agent-{uuid.uuid4().hex[:6]}")
    kwargs.setdefault("allowed_targets", ["*.example.com", "10.44.0.0/24"])
    return agent_service.enroll(session, org_id, **kwargs)


def _ready_agent(org_id, **kwargs) -> uuid.UUID:
    """Enrol, check in, and have an operator authorise nuclei. Returns its id."""
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent, _ = _enroll(session, org_id, **kwargs)
        agent_service.heartbeat(session, agent, tools=TOOLS)
        agent_service.set_tool_enabled(session, agent, "nuclei", True)
        session.commit()
        return agent.id


# ---------------------------------------------------------------------------
# 1. The dispatcher is not a remote shell
# ---------------------------------------------------------------------------
def test_a_freshly_enrolled_agent_can_run_nothing(estate):
    """Enrolment grants zero execution rights. Both halves must fail closed."""
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent, token = _enroll(session, org_id, allowed_targets=[])
        session.commit()

        assert token.startswith("veyrsagent_")
        assert agent.status == AgentStatus.PENDING.value

        # No tools declared yet.
        with pytest.raises(agent_service.ToolRefused):
            agent_service.queue_job(session, org_id, tool="nuclei",
                                    target="app.example.com", agent=agent,
                                    reason="smoke test")

        # ...and even once it declares one, an empty allowlist allows nothing.
        agent_service.heartbeat(session, agent, tools=TOOLS)
        agent_service.set_tool_enabled(session, agent, "nuclei", True)
        with pytest.raises(agent_service.TargetRefused) as exc:
            agent_service.queue_job(session, org_id, tool="nuclei",
                                    target="app.example.com", agent=agent,
                                    reason="smoke test")
        assert "deny-by-default" in str(exc.value)


def test_a_declared_tool_is_not_an_authorised_tool(estate):
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent, _ = _enroll(session, org_id)
        agent_service.heartbeat(session, agent, tools=TOOLS)
        session.commit()

        tool = agent.tools[0]
        assert tool.name == "nuclei"
        assert tool.enabled is False, "declaration must not grant execution"

        with pytest.raises(agent_service.ToolRefused) as exc:
            agent_service.queue_job(session, org_id, tool="nuclei",
                                    target="app.example.com", agent=agent,
                                    reason="check the operator gate")
        assert "not enabled by an operator" in str(exc.value)

        agent_service.set_tool_enabled(session, agent, "nuclei", True)
        job = agent_service.queue_job(session, org_id, tool="nuclei",
                                      target="app.example.com", agent=agent,
                                      reason="now it should pass")
        assert job.state == JobState.QUEUED.value


def test_a_job_needs_a_reason(estate):
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent = session.get(ExecAgent, agent_id)
        with pytest.raises(agent_service.AgentError) as exc:
            agent_service.queue_job(session, org_id, tool="nuclei",
                                    target="app.example.com", agent=agent, reason="  ")
        assert "audit trail" in str(exc.value)


@pytest.mark.parametrize("target", [
    "127.0.0.1",                 # the agent's own host
    "169.254.169.254",           # cloud instance metadata - credentials
    "::1",
    "224.0.0.1",
])
def test_reserved_ranges_are_refused(estate, target):
    """The metadata endpoint is the one that turns a scanner into an exfil tool."""
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id, allowed_targets=["0.0.0.0/0", "::/0", "*"])
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent = session.get(ExecAgent, agent_id)
        with pytest.raises(agent_service.TargetRefused) as exc:
            agent_service.authorise_target(session, org_id, agent, target)
        assert "reserved range" in str(exc.value)


def test_a_reserved_address_can_be_allowed_explicitly(estate):
    """A lab is a legitimate case - but it must be written down, address by
    address. A CIDR that merely contains loopback is far too easy to type."""
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent, _ = _enroll(session, org_id, allowed_targets=["127.0.0.1"],
                           require_asset_match=False)
        session.commit()
        decision = agent_service.authorise_target(session, org_id, agent, "127.0.0.1")
        assert decision.host == "127.0.0.1"


def test_a_name_target_never_matches_a_network_rule(estate):
    """The DNS-rebinding guard.

    If a name were resolved at authorisation time and matched against a CIDR,
    VEYRS would be authorising a NAME while the agent later scans whatever that
    name resolves to at EXECUTION time. Names match name patterns; addresses
    match networks. Never across.
    """
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent, _ = _enroll(session, org_id, allowed_targets=["10.44.0.0/24"],
                           require_asset_match=False)
        session.commit()
        # Resolves into the allowed range in real DNS. Still refused.
        with pytest.raises(agent_service.TargetRefused):
            agent_service.authorise_target(session, org_id, agent, "app.example.com")
        # The address itself is fine.
        assert agent_service.authorise_target(
            session, org_id, agent, "10.44.0.10").is_ip


def test_deny_rules_beat_allow_rules(estate):
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent, _ = _enroll(session, org_id, allowed_targets=["10.44.0.0/24"],
                           denied_targets=["10.44.0.10"], require_asset_match=False)
        session.commit()
        with pytest.raises(agent_service.TargetRefused) as exc:
            agent_service.authorise_target(session, org_id, agent, "10.44.0.10")
        assert "denied by agent policy" in str(exc.value)


def test_unregistered_hosts_are_refused_when_the_register_is_the_boundary(estate):
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent, _ = _enroll(session, org_id, allowed_targets=["*.example.com"],
                           require_asset_match=True)
        session.commit()
        with pytest.raises(agent_service.TargetRefused) as exc:
            agent_service.authorise_target(session, org_id, agent, "unknown.example.com")
        assert "asset in the register" in str(exc.value)

        decision = agent_service.authorise_target(session, org_id, agent, "app.example.com")
        assert decision.asset_id == estate["asset_id"]


def test_targets_are_parsed_out_of_urls_and_host_ports():
    assert agent_service.split_target("https://app.example.com:8443/x?y=1") == (
        "app.example.com", 8443)
    assert agent_service.split_target("app.example.com:443") == ("app.example.com", 443)
    assert agent_service.split_target("10.44.0.10") == ("10.44.0.10", None)
    assert agent_service.split_target("[2001:db8::1]:443") == ("2001:db8::1", 443)


# ---------------------------------------------------------------------------
# 2. Claiming, leasing, re-authorisation
# ---------------------------------------------------------------------------
def test_claim_leases_a_job_and_respects_concurrency(estate):
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent = session.get(ExecAgent, agent_id)
        for i in range(2):
            agent_service.queue_job(session, org_id, tool="nuclei",
                                    target="app.example.com", agent=agent,
                                    reason=f"job {i}")
        session.commit()

        first = agent_service.claim_next(session, agent)
        assert first is not None
        assert first.state == JobState.LEASED.value
        assert first.lease_token and first.attempts == 1
        assert agent.status == AgentStatus.BUSY.value
        session.commit()

        # max_concurrency defaults to 1: no second job while one is in flight.
        assert agent_service.claim_next(session, agent) is None


def test_an_unpinned_job_is_re_authorised_against_the_claiming_agent(estate):
    """The check that only running once would miss.

    The job is queued for "any capable agent" and is legitimate for agent B.
    Agent A can run nuclei too, but its allowlist does not cover the target, so
    it must never be handed the work.
    """
    org_id = estate["org_id"]
    a_id = _ready_agent(org_id, allowed_targets=["10.44.0.0/24"])   # addresses only
    b_id = _ready_agent(org_id, allowed_targets=["*.example.com"])  # names

    with SessionLocal() as session:
        set_tenant(session, org_id)
        job = agent_service.queue_job(session, org_id, tool="nuclei",
                                      target="app.example.com", agent=None,
                                      reason="whoever can reach it")
        session.commit()
        assert job.agent_id is None

        agent_a = session.get(ExecAgent, a_id)
        assert agent_service.claim_next(session, agent_a) is None, (
            "agent A's allowlist does not cover this target"
        )
        agent_b = session.get(ExecAgent, b_id)
        claimed = agent_service.claim_next(session, agent_b)
        assert claimed is not None and claimed.id == job.id
        assert claimed.agent_id == b_id


def test_an_unrunnable_tool_is_refused_at_queue_time(estate):
    org_id = estate["org_id"]
    _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        with pytest.raises(agent_service.ToolRefused) as exc:
            agent_service.queue_job(session, org_id, tool="metasploit",
                                    target="app.example.com", reason="nope")
        assert "no enabled agent" in str(exc.value)


def test_only_the_lease_holder_may_write_to_a_job(estate):
    org_id = estate["org_id"]
    a_id = _ready_agent(org_id)
    b_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent_a = session.get(ExecAgent, a_id)
        agent_b = session.get(ExecAgent, b_id)
        agent_service.queue_job(session, org_id, tool="nuclei", target="app.example.com",
                                agent=agent_a, reason="lease test")
        session.commit()
        job = agent_service.claim_next(session, agent_a)
        session.commit()

        with pytest.raises(agent_service.AgentError):
            agent_service.verify_lease(job, agent_a, "not-the-token")
        with pytest.raises(agent_service.AgentError):
            agent_service.verify_lease(job, agent_b, job.lease_token)
        agent_service.verify_lease(job, agent_a, job.lease_token)   # must not raise


def test_events_stream_incrementally_and_seq_is_server_assigned(estate):
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent = session.get(ExecAgent, agent_id)
        agent_service.queue_job(session, org_id, tool="nuclei", target="app.example.com",
                                agent=agent, reason="streaming")
        session.commit()
        job = agent_service.claim_next(session, agent)
        session.commit()

        # The lease itself emitted a status event, so the tail starts at 1.
        first_seq = job.last_event_seq
        assert first_seq >= 1

        agent_service.append_events(session, job, [
            {"kind": "stdout", "message": "scanning /api"},
            {"kind": "progress", "message": "40%", "data": {"pct": 40}},
        ])
        session.commit()
        assert job.state == JobState.RUNNING.value

        tail = agent_service.read_events(session, job, since_seq=first_seq)
        assert [e.seq for e in tail] == [first_seq + 1, first_seq + 2]
        assert tail[1].data == {"pct": 40}
        assert agent_service.read_events(session, job, since_seq=job.last_event_seq) == []


# ---------------------------------------------------------------------------
# 3. Results go through the real ingestion core
# ---------------------------------------------------------------------------
def test_a_result_becomes_findings_in_the_jobs_engagement(estate):
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        engagement = engagements.create_engagement(session, org_id, name="Agent sweep")
        agent = session.get(ExecAgent, agent_id)
        agent_service.queue_job(session, org_id, tool="nuclei", target="app.example.com",
                                agent=agent, engagement_id=engagement.id,
                                reason="quarterly web sweep")
        session.commit()
        engagement_id = engagement.id

        job = agent_service.claim_next(session, agent)
        result = agent_service.submit_result(session, agent, job, payload=NUCLEI_HIT)
        session.commit()

        assert result["state"] == JobState.SUCCEEDED.value
        assert result["import_run_id"] is not None
        assert result["findings_created"] == 1

        run = session.get(ImportRun, uuid.UUID(result["import_run_id"]))
        assert run.source == "nuclei"
        assert run.engagement_id == engagement_id, "the job's scope IS the import's scope"

        finding = session.execute(
            select(Finding).where(Finding.organization_id == org_id)
        ).scalars().one()
        assert finding.asset_id == estate["asset_id"]
        assert finding.state in OPEN_STATES

        # The agent is free again and the job remembers where to reconcile next.
        assert job.test_id == run.test_id
        assert session.get(ExecAgent, agent_id).status == AgentStatus.IDLE.value


def test_an_empty_result_is_a_clean_scan_and_closes_what_was_fixed(estate):
    """The case that would be lost by treating "no output" as an error.

    A scanner that stops reporting a finding is the only signal VEYRS gets that
    something was remediated. If an empty submission were rejected, an
    agent-driven programme could never observe a fix.
    """
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        engagement = engagements.create_engagement(
            session, org_id, name="CI web scan", engagement_type="ci_cd")
        agent = session.get(ExecAgent, agent_id)
        agent_service.queue_job(session, org_id, tool="nuclei", target="app.example.com",
                                agent=agent, engagement_id=engagement.id,
                                reason="first pass")
        session.commit()
        job = agent_service.claim_next(session, agent)
        agent_service.submit_result(session, agent, job, payload=NUCLEI_HIT)
        session.commit()

        finding_id = session.execute(
            select(Finding.id).where(Finding.organization_id == org_id)
        ).scalars().one()

        # Second run of the same job: the scanner reports nothing at all.
        agent_service.queue_job(session, org_id, tool="nuclei", target="app.example.com",
                                agent=agent, engagement_id=engagement.id,
                                reason="after the fix")
        session.commit()
        second = agent_service.claim_next(session, agent)
        outcome = agent_service.submit_result(
            session, agent, second, payload=b"[]", scanner="nuclei",
            # b"[]" parses to zero records, so this run CLOSES a finding. That
            # needs the scan to vouch for its own coverage: an empty document
            # from a scanner that never reached the host says nothing.
            stats={"probe": {"host": "app.example.com", "reachable": True},
                   "scanner": {"percent": 98, "requests": 5000, "errors": 9}})
        session.commit()

        assert outcome["state"] == JobState.SUCCEEDED.value
        finding = session.get(Finding, finding_id)
        session.refresh(finding)
        # ci_cd threshold is 1 consecutive absence: one clean run is enough.
        assert finding.state == "remediated"


def test_a_nonzero_exit_code_fails_the_job_even_with_parsable_output(estate):
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent = session.get(ExecAgent, agent_id)
        agent_service.queue_job(session, org_id, tool="nuclei", target="app.example.com",
                                agent=agent, reason="partial run")
        session.commit()
        job = agent_service.claim_next(session, agent)
        result = agent_service.submit_result(
            session, agent, job, payload=NUCLEI_HIT, exit_code=2)
        session.commit()
        assert result["state"] == JobState.FAILED.value
        # The partial output is still ingested: findings the scan DID observe
        # are real, and dropping them would hide them until the next full run.
        assert result["import_run_id"] is not None


def test_an_oversized_result_is_refused_without_a_partial_import(estate):
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent = session.get(ExecAgent, agent_id)
        agent_service.queue_job(session, org_id, tool="nuclei", target="app.example.com",
                                agent=agent, reason="oversize")
        session.commit()
        job = agent_service.claim_next(session, agent)
        oversized = b"x" * (agent_service.MAX_RESULT_BYTES + 1)
        with pytest.raises(agent_service.AgentError):
            agent_service.submit_result(session, agent, job, payload=oversized)
        assert job.import_run_id is None


# ---------------------------------------------------------------------------
# 4. Failure, expiry, housekeeping
# ---------------------------------------------------------------------------
def test_a_failed_job_requeues_until_attempts_run_out(estate):
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent = session.get(ExecAgent, agent_id)
        agent_service.queue_job(session, org_id, tool="nuclei", target="app.example.com",
                                agent=agent, reason="flaky", max_attempts=2)
        session.commit()

        job = agent_service.claim_next(session, agent)
        agent_service.fail_job(session, agent, job, error="nuclei not on PATH")
        session.commit()
        assert job.state == JobState.QUEUED.value and job.attempts == 1

        job = agent_service.claim_next(session, agent)
        agent_service.fail_job(session, agent, job, error="still missing")
        session.commit()
        assert job.state == JobState.FAILED.value and job.attempts == 2


def test_an_expired_lease_is_requeued_then_expired_not_failed(estate):
    """EXPIRED, not FAILED: nothing is known about whether the scan ran, and
    "failed" invites reading it as "we looked and found nothing"."""
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent = session.get(ExecAgent, agent_id)
        agent_service.queue_job(session, org_id, tool="nuclei", target="app.example.com",
                                agent=agent, reason="agent dies mid-scan", max_attempts=1)
        session.commit()
        job = agent_service.claim_next(session, agent)
        session.commit()

        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=2)
        result = agent_service.reap_expired_leases(session, org_id, now=future)
        session.commit()
        assert result == {"requeued": 0, "expired": 1}
        session.refresh(job)
        assert job.state == JobState.EXPIRED.value


def test_a_silent_agent_is_marked_offline(estate):
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        future = dt.datetime.now(dt.timezone.utc) + dt.timedelta(hours=1)
        assert agent_service.mark_stale_agents_offline(session, org_id, now=future) == 1
        session.commit()
        assert session.get(ExecAgent, agent_id).status == AgentStatus.OFFLINE.value

        # ...and a check-in brings it straight back.
        agent = session.get(ExecAgent, agent_id)
        agent_service.heartbeat(session, agent, tools=TOOLS)
        session.commit()
        assert agent.status == AgentStatus.IDLE.value


def test_withdrawing_a_tool_disables_it_rather_than_deleting_history(estate):
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent = session.get(ExecAgent, agent_id)
        agent_service.heartbeat(session, agent, tools=[])   # the binary went away
        session.commit()
        session.refresh(agent)
        assert [t.name for t in agent.tools] == ["nuclei"]
        assert agent.tools[0].enabled is False


def test_an_unknown_parser_is_refused_not_guessed(estate):
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent, _ = _enroll(session, org_id)
        agent_service.heartbeat(session, agent, tools=[
            {"name": "custom", "parser": "definitely-not-a-parser"}])
        session.commit()
        tool = agent.tools[0]
        assert tool.parser is None
        assert tool.meta["rejected_parser"] == "definitely-not-a-parser"


# ---------------------------------------------------------------------------
# 5. The API surface: credential separation and tenant isolation
# ---------------------------------------------------------------------------
def test_agent_token_is_not_a_principal(client, estate, admin_a):
    """An agent credential must be worthless everywhere except /agents/self."""
    org_id = estate["org_id"]
    with SessionLocal() as session:
        set_tenant(session, org_id)
        _, token = _enroll(session, org_id)
        session.commit()

    assert client.get("/api/v1/agents", headers={"X-API-Key": token}).status_code == 401
    assert client.get("/api/v1/findings",
                      headers={"Authorization": f"Bearer {token}"}).status_code == 401
    assert client.get("/api/v1/assets", headers={"X-Agent-Token": token}).status_code == 401

    # ...and the operator's own token does not work on the agent data plane.
    assert client.post("/api/v1/agents/self/heartbeat", json={},
                       headers=admin_a).status_code == 401


def test_enrol_queue_claim_and_submit_over_http(client, estate, admin_a):
    """The whole loop as an agent would actually drive it."""
    created = client.post("/api/v1/agents", headers=admin_a, json={
        "name": "dmz-runner",
        "allowed_targets": ["*.example.com"],
    })
    assert created.status_code == 201, created.text
    agent = created.json()
    token = agent["token"]
    headers = {"X-Agent-Token": token}

    beat = client.post("/api/v1/agents/self/heartbeat", headers=headers,
                       json={"agent_version": "1.0.0", "platform": "linux",
                             "tools": TOOLS})
    assert beat.status_code == 200
    assert beat.json()["tools"]["added"] == 1

    # Not yet authorised by an operator.
    refused = client.post("/api/v1/agents/jobs", headers=admin_a, json={
        "tool": "nuclei", "target": "app.example.com", "agent_id": agent["id"],
        "reason": "before the operator says yes"})
    assert refused.status_code == 422
    assert "not enabled" in refused.json()["detail"]

    toggled = client.patch(f"/api/v1/agents/{agent['id']}/tools/nuclei",
                           headers=admin_a, json={"enabled": True})
    assert toggled.status_code == 200 and toggled.json()["enabled"] is True

    queued = client.post("/api/v1/agents/jobs", headers=admin_a, json={
        "tool": "nuclei", "target": "https://app.example.com/",
        "agent_id": agent["id"], "profile": "quick",
        "reason": "authorised weekly sweep"})
    assert queued.status_code == 201, queued.text
    job_id = queued.json()["id"]

    claim = client.post("/api/v1/agents/self/jobs/claim", headers=headers)
    assert claim.status_code == 200
    lease = claim.json()["lease_token"]
    assert claim.json()["job"]["id"] == job_id

    # A wrong lease token is refused before anything is written.
    assert client.post(
        f"/api/v1/agents/self/jobs/{job_id}/events?lease_token=wrong",
        headers=headers, json={"events": [{"message": "hi"}]},
    ).status_code == 422

    streamed = client.post(
        f"/api/v1/agents/self/jobs/{job_id}/events?lease_token={lease}",
        headers=headers, json={"events": [{"kind": "stdout", "message": "starting"}]},
    )
    assert streamed.status_code == 200

    submitted = client.post(
        f"/api/v1/agents/self/jobs/{job_id}/result?lease_token={lease}&scanner=nuclei",
        headers=headers, content=NUCLEI_HIT,
    )
    assert submitted.status_code == 200, submitted.text
    assert submitted.json()["state"] == "succeeded"

    detail = client.get(f"/api/v1/agents/jobs/{job_id}", headers=admin_a).json()
    assert detail["import_run_id"] is not None
    assert detail["output_bytes"] == len(NUCLEI_HIT)

    events = client.get(f"/api/v1/agents/jobs/{job_id}/events", headers=admin_a).json()
    assert [e["kind"] for e in events][0] == "status"
    assert any(e["message"] == "starting" for e in events)

    # An empty queue answers 204, not an error.
    assert client.post("/api/v1/agents/self/jobs/claim", headers=headers).status_code == 204


def test_agents_and_jobs_are_invisible_across_tenants(client, estate, admin_a, admin_b):
    created = client.post("/api/v1/agents", headers=admin_a, json={
        "name": "tenant-a-runner", "allowed_targets": ["*.example.com"]}).json()

    assert client.get(f"/api/v1/agents/{created['id']}", headers=admin_b).status_code == 404
    assert client.get("/api/v1/agents", headers=admin_b).json()["total"] == 0
    assert client.patch(f"/api/v1/agents/{created['id']}/tools/nuclei",
                        headers=admin_b, json={"enabled": True}).status_code == 404


def test_an_agent_cannot_touch_another_tenants_job(client, estate, org_b, admin_a):
    """Tenant B's agent, tenant A's job id. RLS plus the ownership check."""
    org_b_id, _, _ = org_b
    with SessionLocal() as session:
        set_tenant(session, org_b_id)
        _, foreign_token = _enroll(session, org_b_id)
        session.commit()

    agent = client.post("/api/v1/agents", headers=admin_a, json={
        "name": "a-runner", "allowed_targets": ["*.example.com"]}).json()
    a_headers = {"X-Agent-Token": agent["token"]}
    client.post("/api/v1/agents/self/heartbeat", headers=a_headers, json={"tools": TOOLS})
    client.patch(f"/api/v1/agents/{agent['id']}/tools/nuclei", headers=admin_a,
                 json={"enabled": True})
    job_id = client.post("/api/v1/agents/jobs", headers=admin_a, json={
        "tool": "nuclei", "target": "app.example.com", "agent_id": agent["id"],
        "reason": "cross-tenant probe"}).json()["id"]

    stolen = client.post(
        f"/api/v1/agents/self/jobs/{job_id}/result?lease_token=whatever",
        headers={"X-Agent-Token": foreign_token}, content=NUCLEI_HIT,
    )
    assert stolen.status_code == 404, "a foreign job must not even be addressable"


def test_a_disabled_agent_is_told_why(client, estate, admin_a):
    agent = client.post("/api/v1/agents", headers=admin_a, json={
        "name": "retired-runner", "allowed_targets": ["*.example.com"]}).json()
    headers = {"X-Agent-Token": agent["token"]}
    assert client.post("/api/v1/agents/self/heartbeat", headers=headers,
                       json={}).status_code == 200

    client.patch(f"/api/v1/agents/{agent['id']}", headers=admin_a, json={"status": "disabled"})
    blocked = client.post("/api/v1/agents/self/heartbeat", headers=headers, json={})
    # 403, not 401: the credential is fine, so the agent stops rotating its
    # token and starts asking its operator instead.
    assert blocked.status_code == 403
    assert "disabled" in blocked.json()["detail"]


def test_deleting_an_agent_with_live_work_is_refused(client, estate, admin_a):
    agent = client.post("/api/v1/agents", headers=admin_a, json={
        "name": "busy-runner", "allowed_targets": ["*.example.com"]}).json()
    headers = {"X-Agent-Token": agent["token"]}
    client.post("/api/v1/agents/self/heartbeat", headers=headers, json={"tools": TOOLS})
    client.patch(f"/api/v1/agents/{agent['id']}/tools/nuclei", headers=admin_a,
                 json={"enabled": True})
    job_id = client.post("/api/v1/agents/jobs", headers=admin_a, json={
        "tool": "nuclei", "target": "app.example.com", "agent_id": agent["id"],
        "reason": "still queued"}).json()["id"]

    refused = client.delete(f"/api/v1/agents/{agent['id']}", headers=admin_a)
    assert refused.status_code == 409

    client.post(f"/api/v1/agents/jobs/{job_id}/cancel", headers=admin_a, json={"note": "done"})
    assert client.delete(f"/api/v1/agents/{agent['id']}", headers=admin_a).status_code == 204


def test_queue_summary_counts_states(client, estate, admin_a):
    summary = client.get("/api/v1/agents/jobs/summary", headers=admin_a)
    assert summary.status_code == 200
    body = summary.json()
    assert body["queued"] == 0 and body["active"] == 0
