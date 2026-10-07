"""Phase 18: four defects found by running VEYRS against itself.

The first real agent-run scan of `veyrs-docs.example.com` found a fault in VEYRS,
and reading the code to diagnose it surfaced three more. Each test here pins the
behaviour that was wrong, not merely the behaviour that is now right:

1. **A metrics label was attacker-controlled.** An unrouted request path went
   into `veyrs_requests_total{path=...}` verbatim, so any caller could mint an
   unbounded number of series - and a path containing a quote emitted a line no
   scraper can parse, dropping *every* metric for the target.
2. **`/metrics` was unauthenticated.** The nginx `allow 10.0.0.0/24` in front of
   it is not the control it looks like: every request arrives from the fleet
   reverse proxy, whose own address is inside that range.
3. **A crashed scan was reconciled as a clean one.** `submit_result()` ran the
   import before it looked at `exit_code`, so a scanner that died with no output
   closed findings as remediated. Same family as the `_close_missing()`
   over-closure bug: an absence of evidence read as evidence of absence.
4. **The suite could run against production.** With no `.env` loaded, the test
   database URL resolved to empty and `veyrs.config` fell back to its built-in
   default - the production database.
"""
from __future__ import annotations

import json
import uuid

import pytest
from sqlalchemy import select

from veyrs import observability
from veyrs.config import settings
from veyrs.db import SessionLocal, set_tenant
from veyrs.models import (
    Asset, AgentJobEvent, ExecAgent, Finding, JobEventKind, JobState, OPEN_STATES,
)
from veyrs.services import agents as agent_service
from veyrs.services import engagements, risk as risk_service, sla as sla_service

TOOLS = [{"name": "nuclei", "version": "3.11.1", "parser": "nuclei",
          "profiles": ["quick", "full"]}]


def _nuclei_hit(template_id: str, host: str = "https://app.example.com") -> dict:
    return {
        "template-id": template_id,
        "info": {"name": template_id, "severity": "high",
                 "classification": {"cvss-score": 8.1}},
        "host": host,
        "matched-at": f"{host}/{template_id}",
        "type": "http",
    }


def _jsonl(*records: dict) -> bytes:
    return ("\n".join(json.dumps(r) for r in records) + "\n").encode()


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------
@pytest.fixture()
def estate(org_a):
    org_id, slug, email = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        session.add(Asset(organization_id=org_id, name="app-01", hostname="app",
                          fqdn="app.example.com", ip_addresses=["10.44.0.10"],
                          asset_type="server", criticality="high", exposure="internet"))
        risk_service.seed_profiles(session, org_id)
        sla_service.seed_policies(session, org_id)
        session.commit()
        return {"org_id": org_id, "slug": slug, "email": email}


def _ready_agent(org_id) -> uuid.UUID:
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent, _ = agent_service.enroll(
            session, org_id, name=f"agent-{uuid.uuid4().hex[:6]}",
            allowed_targets=["*.example.com"])
        agent_service.heartbeat(session, agent, tools=TOOLS)
        agent_service.set_tool_enabled(session, agent, "nuclei", True)
        session.commit()
        return agent.id


#: What a healthy nuclei run reports about itself. Measured, not invented: a
#: real scan of this fleet completes 97% with 108 errors in 8618 requests. A
#: scan that resolved its target wrongly reports 5% and more errors than
#: requests - see test_phase19_coverage.
_COVERED = {"probe": {"host": "app.example.com", "resolved_ips": ["10.0.0.9"],
                      "open_ports": [443], "reachable": True},
            "scanner": {"percent": 97, "requests": 8618, "errors": 108, "matched": 0}}


def _run_scan(session, org_id, agent, engagement_id, payload, *, exit_code=0,
              reason="scan", stats=_COVERED):
    """Queue -> claim -> submit, the whole agent round trip."""
    agent_service.queue_job(session, org_id, tool="nuclei", target="app.example.com",
                            agent=agent, engagement_id=engagement_id, reason=reason)
    session.commit()
    job = agent_service.claim_next(session, agent)
    result = agent_service.submit_result(
        session, agent, job, payload=payload, scanner="nuclei", exit_code=exit_code,
        stats=stats)
    session.commit()
    return job, result


# ---------------------------------------------------------------------------
# 1. Metrics labels are built by the module, bounded, and escaped
# ---------------------------------------------------------------------------
def test_a_label_value_is_escaped_for_the_prometheus_text_format():
    """Backslash, quote and newline are the three characters that break a line."""
    rendered = observability._render_labels({"path": 'a"b\\c\nd'})
    assert rendered == 'path="a\\"b\\\\c\\nd"'


def test_an_unrouted_path_never_reaches_a_label_value(client):
    """The registry must not echo whatever the caller typed.

    Before the fix this emitted `path="/api/v1/QUOTE"TEST"`: an unbalanced
    quote, which makes the whole exposition unparseable.
    """
    observability.reset_metrics()
    marker = f"QUOTE{uuid.uuid4().hex}"
    response = client.get(f'/api/v1/{marker}"TEST')
    assert response.status_code == 404

    body = observability.metrics_response().body.decode()
    assert 'path="<unmatched>"' in body
    assert marker not in body, "the caller's path became a label value"


def test_the_exposition_stays_parseable(client):
    observability.reset_metrics()
    client.get('/api/v1/x"y')
    client.get("/healthz")

    for line in observability.metrics_response().body.decode().splitlines():
        if not line or line.startswith("#"):
            continue
        # Unescaped quotes must come in pairs: name{a="1",b="2"} value.
        unescaped = line.replace('\\\\', "").replace('\\"', "")
        assert unescaped.count('"') % 2 == 0, f"unbalanced quotes: {line}"


def test_the_series_count_per_metric_is_bounded():
    """404s are free to generate; the registry must not grow with them."""
    observability.reset_metrics()
    for index in range(observability.MAX_SERIES_PER_METRIC + 200):
        observability.incr("veyrs_requests_total", {"path": f"/probe-{index}"})

    body = observability.metrics_response().body.decode()
    series = [ln for ln in body.splitlines()
              if ln.startswith("veyrs_requests_total{")]
    assert len(series) <= observability.MAX_SERIES_PER_METRIC + 1
    # The traffic past the cap is still counted, just not individually.
    assert any('overflow="1"' in ln for ln in series)


def test_a_matched_route_contributes_its_template_not_its_arguments(client):
    observability.reset_metrics()
    client.get("/healthz")
    body = observability.metrics_response().body.decode()
    assert 'path="/healthz"' in body


# ---------------------------------------------------------------------------
# 2. /metrics is authenticated
# ---------------------------------------------------------------------------
def test_metrics_requires_the_token_when_one_is_configured(client, monkeypatch):
    """404 rather than 401: a probe should not learn the endpoint is there."""
    monkeypatch.setattr(settings, "metrics_token", "metrics-token-of-real-length")

    assert client.get("/metrics").status_code == 404
    assert client.get(
        "/metrics", headers={"Authorization": "Bearer wrong"}).status_code == 404

    allowed = client.get(
        "/metrics", headers={"Authorization": "Bearer metrics-token-of-real-length"})
    assert allowed.status_code == 200
    assert "veyrs_build_info" in allowed.text


def test_the_exposition_names_the_worker_that_answered(client, monkeypatch):
    """The registry is per process; a scrape samples one of several workers."""
    monkeypatch.setattr(settings, "metrics_token", "")
    body = client.get("/metrics").text
    assert "worker=" in body


# ---------------------------------------------------------------------------
# 3. A crashed scan is not evidence of remediation
# ---------------------------------------------------------------------------
def test_a_crashed_scanner_with_no_output_is_not_reconciled(estate):
    """The defect, exactly: exit 1 with zero bytes closed live findings.

    `run_import(..., allow_empty=True)` ran unconditionally and the
    `if exit_code != 0` check came afterwards, so the reconciliation had
    already marked everything the crashed scan did not report as remediated.
    """
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        # ci_cd closes on a SINGLE consecutive absence - the harshest setting,
        # so the bug shows up on the very next run rather than the third.
        engagement = engagements.create_engagement(
            session, org_id, name="CI scan", engagement_type="ci_cd")
        agent = session.get(ExecAgent, agent_id)

        _run_scan(session, org_id, agent, engagement.id,
                  _jsonl(_nuclei_hit("CVE-2021-44228")), reason="baseline")
        finding_id = session.execute(
            select(Finding.id).where(Finding.organization_id == org_id)
        ).scalars().one()

        job, result = _run_scan(session, org_id, agent, engagement.id, b"",
                                exit_code=1, reason="scanner dies on startup")

        assert result["state"] == JobState.FAILED.value
        assert result["import_run_id"] is None, "a crash must not create an import run"
        assert job.test_id is None, "a crash must not pin a test"

        finding = session.get(Finding, finding_id)
        session.refresh(finding)
        assert finding.state in OPEN_STATES, (
            "a scanner that crashed did not observe the estate; its silence is "
            "not a fix"
        )


def test_a_crashed_scanner_with_partial_output_imports_but_closes_nothing(estate):
    """Partial evidence is still evidence - of what it found, not of absence."""
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        engagement = engagements.create_engagement(
            session, org_id, name="CI scan", engagement_type="ci_cd")
        agent = session.get(ExecAgent, agent_id)

        _run_scan(session, org_id, agent, engagement.id,
                  _jsonl(_nuclei_hit("CVE-2021-44228"), _nuclei_hit("CVE-2017-5638")),
                  reason="baseline")
        assert session.execute(
            select(Finding).where(Finding.organization_id == org_id)
        ).scalars().all().__len__() == 2

        # The scan dies half way: it reports one of the two, then exits 1.
        _, result = _run_scan(session, org_id, agent, engagement.id,
                              _jsonl(_nuclei_hit("CVE-2021-44228")),
                              exit_code=1, reason="killed mid-run")

        assert result["state"] == JobState.FAILED.value
        assert result["import_run_id"] is not None, "observed findings are kept"
        assert result["findings_closed_absent"] == 0

        states = session.execute(
            select(Finding.state).where(Finding.organization_id == org_id)
        ).scalars().all()
        assert all(state in OPEN_STATES for state in states), (
            "the finding the crashed scan never got to report is not remediated"
        )


def test_a_successful_empty_scan_still_closes_what_was_fixed(estate):
    """The guard must not cost us the only signal that something was fixed.

    "Successful" now means the run also vouched for its coverage; an empty
    result that does not is refused instead (test_phase19_coverage).
    """
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        engagement = engagements.create_engagement(
            session, org_id, name="CI scan", engagement_type="ci_cd")
        agent = session.get(ExecAgent, agent_id)

        _run_scan(session, org_id, agent, engagement.id,
                  _jsonl(_nuclei_hit("CVE-2021-44228")), reason="baseline")
        finding_id = session.execute(
            select(Finding.id).where(Finding.organization_id == org_id)
        ).scalars().one()

        _, result = _run_scan(session, org_id, agent, engagement.id, b"",
                              exit_code=0, reason="clean run after the fix")

        assert result["state"] == JobState.SUCCEEDED.value
        finding = session.get(Finding, finding_id)
        session.refresh(finding)
        assert finding.state == "remediated"


def test_a_failed_job_reports_why_and_not_just_the_exit_code(estate):
    """"agent reported exit code 1" is not a diagnosis.

    nuclei exits 1 with "no templates provided for scan" when a severity
    profile and a tag filter select disjoint template sets - a configuration
    mistake that looked identical to a crash.
    """
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent = session.get(ExecAgent, agent_id)
        agent_service.queue_job(session, org_id, tool="nuclei",
                                target="app.example.com", agent=agent,
                                reason="quick profile with an exposures tag")
        session.commit()
        job = agent_service.claim_next(session, agent)
        agent_service.append_events(session, job, [
            {"kind": JobEventKind.STDOUT.value, "message": "[INF] nuclei v3.11.1"},
            {"kind": JobEventKind.STDERR.value,
             "message": "[FTL] Could not run nuclei: no templates provided for scan"},
        ])
        agent_service.submit_result(session, agent, job, payload=b"",
                                    scanner="nuclei", exit_code=1)
        session.commit()

        assert job.state == JobState.FAILED.value
        assert "exit code 1" in job.error
        assert "no templates provided for scan" in job.error


def test_the_failure_detail_is_stripped_of_terminal_colour(estate):
    """nuclei colours its own fatals; the escapes are noise in a stored error.

    Unstripped, the console and any notification email render the literal
    "[[1;31mFTL[0m]" that this test's input contains.
    """
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent = session.get(ExecAgent, agent_id)
        agent_service.queue_job(session, org_id, tool="nuclei",
                                target="app.example.com", agent=agent,
                                reason="colourised failure")
        session.commit()
        job = agent_service.claim_next(session, agent)
        agent_service.append_events(session, job, [{
            "kind": JobEventKind.STDERR.value,
            "message": "[\x1b[1;31mFTL\x1b[0m] Could not run nuclei: "
                       "no templates provided for scan",
        }])
        agent_service.submit_result(session, agent, job, payload=b"",
                                    scanner="nuclei", exit_code=1)
        session.commit()

        assert "\x1b" not in job.error
        assert "[FTL] Could not run nuclei: no templates provided for scan" in job.error


def test_the_failure_detail_survives_a_job_with_no_events(estate):
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent = session.get(ExecAgent, agent_id)
        _, result = _run_scan(session, org_id, agent, None, b"", exit_code=7,
                              reason="silent death")
        assert result["state"] == JobState.FAILED.value
        assert "exit code 7" in result["error"]


def test_a_crashed_job_still_records_its_output_hash(estate):
    """Forensics must survive the guard: we still know what the agent sent."""
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent = session.get(ExecAgent, agent_id)
        job, _ = _run_scan(session, org_id, agent, None, b"", exit_code=1,
                           reason="crash")
        assert job.exit_code == 1
        assert job.output_bytes == 0
        assert job.output_sha256 is not None
        assert job.finished_at is not None
        events = session.execute(
            select(AgentJobEvent).where(AgentJobEvent.job_id == job.id)
        ).scalars().all()
        assert any(e.kind == JobEventKind.STATUS.value for e in events)


# ---------------------------------------------------------------------------
# 5. A port in the host field must not lose the finding
# ---------------------------------------------------------------------------
def test_a_host_field_carrying_a_port_still_resolves_its_asset():
    """nuclei reports non-HTTP services as "host:22" in the host field.

    Stored verbatim that string matches no asset column, so a real scan of
    veyrs-docs.example.com kept its 12 HTTP findings and silently rejected all
    10 SSH and TLS ones as "unknown asset" - on an asset VEYRS knew about well
    enough to authorise the scan against it.
    """
    from veyrs.services.importers.base import ScanRecord

    record = ScanRecord(title="SSH Auth Methods",
                        hostname="veyrs-docs.example.com:22").normalise()
    assert record.fqdn == "veyrs-docs.example.com"
    assert record.hostname is None
    assert record.port == 22

    short = ScanRecord(title="x", hostname="app:8443").normalise()
    assert short.hostname == "app"
    assert short.port == 8443

    numeric = ScanRecord(title="x", hostname="10.44.0.10:443").normalise()
    assert numeric.ip_address == "10.44.0.10"
    assert numeric.port == 443


def test_a_clean_host_field_is_left_alone():
    from veyrs.services.importers.base import ScanRecord

    plain = ScanRecord(title="x", fqdn="app.example.com").normalise()
    assert plain.fqdn == "app.example.com"
    assert plain.port is None

    # A bare IPv6 literal is ambiguous; guessing is how findings move hosts.
    six = ScanRecord(title="x", hostname="fe80::1").normalise()
    assert six.hostname == "fe80::1"

    bracketed = ScanRecord(title="x", hostname="[fe80::1]:443").normalise()
    assert bracketed.ip_address == "fe80::1"
    assert bracketed.port == 443


def test_an_explicit_port_is_not_overwritten_by_the_host_field():
    from veyrs.services.importers.base import ScanRecord

    record = ScanRecord(title="x", hostname="app.example.com:22", port=2222).normalise()
    assert record.fqdn == "app.example.com"
    assert record.port == 2222, "the parser's explicit port wins"


# ---------------------------------------------------------------------------
# 4. The suite cannot run against production
# ---------------------------------------------------------------------------
def test_the_suite_refuses_a_database_that_is_not_a_test_database():
    from conftest import _assert_is_test_database

    _assert_is_test_database("postgresql+psycopg://veyrs:veyrs@127.0.0.1:5432/veyrs_test")

    with pytest.raises(RuntimeError, match="must end in '_test'"):
        _assert_is_test_database("postgresql+psycopg://veyrs:veyrs@127.0.0.1:5432/veyrs")

    with pytest.raises(RuntimeError, match="no test database configured"):
        _assert_is_test_database("")
