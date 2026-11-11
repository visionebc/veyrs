"""Phase 19 - a scan that saw nothing is not a scan that found nothing.

Found by running VEYRS's own agent against two hosts of the SATOM pair on
2026-08-11. One of them has a public A record, the other does not. The scan of
the public one finished in nine seconds with no findings and was recorded
`succeeded`; the other ran ten minutes and produced 22. The asymmetry was the
whole finding.

nuclei does not use the system resolver - projectdiscovery's dialer carries
public resolvers compiled in. So on a split-horizon estate it resolved the
INTERNAL host to its PUBLIC address, could not route there, and gave up. The
three facts VEYRS had were `exit_code=0`, `output_bytes=0`, `matched=0`, which
are precisely the facts of a clean scan.

Measured on the real host, same target, same templates:

    without -r    5% complete    520 requests    703 errors   exit 0
    with    -r   97% complete   8618 requests    108 errors   exit 0

Both wrote zero bytes: at critical/high severity that host genuinely has
nothing. Which is the point - output size cannot separate them, and coverage
can. So the agent now reports coverage and the server refuses to read an
unattested empty result as a clean estate.
"""
from __future__ import annotations

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import ExecAgent, Finding, JobState
from veyrs.services import agents as agent_service
from veyrs.services import engagements

from test_phase18_hardening import (  # noqa: F401 - fixtures come with them
    OPEN_STATES, _jsonl, _nuclei_hit, _ready_agent, _run_scan, estate,
)

#: The failing run, exactly as the agent measured it on satom-mag-a1.
_BLIND = {"probe": {"host": "app.example.com", "resolved_ips": ["10.0.0.9"],
                    "open_ports": [443], "reachable": True},
          "scanner": {"percent": 5, "requests": 520, "errors": 703, "matched": 0}}
_UNREACHABLE = {"probe": {"host": "app.example.com", "resolved_ips": [],
                          "open_ports": [], "reachable": False}}


# ---------------------------------------------------------------------------
# 1. The verdict function on its own
# ---------------------------------------------------------------------------
@pytest.mark.parametrize("stats, attested", [
    ({"scanner": {"percent": 97, "requests": 8618, "errors": 108}}, True),
    ({"scanner": {"percent": 5, "requests": 520, "errors": 703}}, False),
    ({"scanner": {"percent": 100, "requests": 400, "errors": 380}}, False),
    (_UNREACHABLE, False),
    # A tool with no counters of its own: the reachability probe is the whole
    # attestation, and nmap must not be punished for not being nuclei.
    ({"probe": {"host": "h", "reachable": True}}, True),
])
def test_the_coverage_verdict_reads_the_numbers(stats, attested):
    assert agent_service._coverage(stats, b"")[0] is attested


def test_an_aborted_scan_is_refused_and_says_the_percentage():
    attested, refusal = agent_service._coverage(_BLIND, b"")
    assert attested is False
    assert "5%" in refusal and "703" in refusal


def test_output_without_coverage_is_believed_but_not_trusted_to_close():
    """No stats at all + real output: ingest it, never let it close anything."""
    attested, refusal = agent_service._coverage(None, b'{"a": 1}')
    assert attested is False
    assert refusal is None


def test_no_output_and_no_coverage_is_refused_outright():
    attested, refusal = agent_service._coverage(None, b"")
    assert attested is False
    assert "empty result" in refusal


# ---------------------------------------------------------------------------
# 2. End to end, against the real reconciliation path
# ---------------------------------------------------------------------------
def test_a_blind_scan_does_not_close_a_finding_and_does_not_pass(estate):
    """The defect itself. Before this guard the finding was remediated."""
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

        job, result = _run_scan(session, org_id, agent, engagement.id, b"",
                                exit_code=0, stats=_BLIND,
                                reason="scanner resolved the wrong address")

        assert result["state"] == JobState.FAILED.value
        assert result["coverage_attested"] is False
        assert result["import_run_id"] is None, "nothing to import, nothing to reconcile"
        assert "coverage refused" in job.error

        finding = session.get(Finding, finding_id)
        session.refresh(finding)
        assert finding.state in OPEN_STATES, (
            "a scanner that never reached the host did not observe a fix"
        )


def test_the_numbers_are_kept_on_the_job_for_the_next_person(estate):
    """A red job whose reason is 'it only completed 5%' must survive triage."""
    org_id = estate["org_id"]
    agent_id = _ready_agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent = session.get(ExecAgent, agent_id)
        job, _ = _run_scan(session, org_id, agent, None, b"", exit_code=0,
                           stats=_BLIND, reason="blind run")
        assert job.meta["scan_stats"]["scanner"]["percent"] == 5


def test_partial_output_from_a_blind_scan_is_kept_but_closes_nothing(estate):
    """Same rule as a crash: what it saw is real, what it missed is not a fix."""
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
        _, result = _run_scan(session, org_id, agent, engagement.id,
                              _jsonl(_nuclei_hit("CVE-2021-44228")),
                              exit_code=0, stats=_BLIND, reason="blind partial")

        assert result["import_run_id"] is not None, "observed findings are kept"
        assert result["findings_closed_absent"] == 0
        states = session.execute(
            select(Finding.state).where(Finding.organization_id == org_id)
        ).scalars().all()
        assert all(state in OPEN_STATES for state in states)


def test_a_covered_scan_still_closes_what_was_fixed(estate):
    """The guard is worthless if it also breaks the signal it protects."""
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
                              exit_code=0, reason="clean, and it says so")

        assert result["state"] == JobState.SUCCEEDED.value
        assert result["coverage_attested"] is True
        finding = session.get(Finding, finding_id)
        session.refresh(finding)
        assert finding.state == "remediated"


# ---------------------------------------------------------------------------
# 3. The agent side: the resolver list and the stats reader
# ---------------------------------------------------------------------------
def _agent_module():
    import importlib.util
    spec = importlib.util.spec_from_file_location(
        "veyrs_agent", "/opt/veyrs/integrations/veyrs-agent/veyrs_agent.py")
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_agent_strips_comments_from_the_resolver_list(tmp_path):
    """nuclei treats a comment as a resolver - verified, it drops coverage to 0%.

    So the file an operator can document is not the file the scanner can read.
    """
    module = _agent_module()
    listing = tmp_path / "resolvers.txt"
    listing.write_text("# the fleet resolver\n\n10.50.0.2\n")
    argv = module.load_resolvers(str(listing))
    assert argv[0] == "-r"
    assert open(argv[1]).read() == "10.50.0.2\n"


def test_a_missing_or_empty_resolver_list_is_not_an_error(tmp_path):
    module = _agent_module()
    assert module.load_resolvers(str(tmp_path / "nope.txt")) == []
    empty = tmp_path / "empty.txt"
    empty.write_text("# nothing but commentary\n")
    assert module.load_resolvers(str(empty)) == []


def test_the_nuclei_builder_passes_the_resolvers_and_asks_for_stats():
    module = _agent_module()
    module.RESOLVER_ARGS = ["-r", "/tmp/resolvers"]
    argv = module.build_nuclei("host.example.com", "full", {}, "/tmp/out.jsonl")
    assert argv[-2:] == ["-r", "/tmp/resolvers"]
    assert "-stats-json" in argv


def test_the_agent_reads_a_stats_line_and_ignores_ordinary_output():
    module = _agent_module()
    line = ('{"duration":"0:01:43","errors":"108","hosts":"1","matched":"0",'
            '"percent":"97","requests":"8618","rps":"83","templates":"4200"}')
    assert module.stats_nuclei(line) == {
        "requests": 8618, "errors": 108, "matched": 0, "percent": 97,
        "hosts": 1, "templates": 4200, "duration": "0:01:43"}
    assert module.stats_nuclei("[INF] Templates loaded for current scan: 4200") is None
    assert module.stats_nuclei('{"not": "stats"}') is None
