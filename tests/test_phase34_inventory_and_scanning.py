"""Phase 34 - the estate's inventory arrives with the scan, and scanning can stop.

Two features that look unrelated and are the same statement: VEYRS should be
able to run as a vulnerability MANAGEMENT platform fed by somebody else's
scanner. That needs the import path to carry what a host HAS (not only what is
wrong with it), and it needs a way to stop VEYRS probing anything itself.

What is pinned here is, in both halves, the set of ways this can be quietly
wrong -- a working-looking screen over a control that does nothing:

* a scanner-supplied **CPE 2.2 URI** silently failing `parse_cpe23` and falling
  through to inference is how inventory ends up on a Product row no CVE joins
  to. `services/inventory` calls that the most dangerous bug in the module, and
  it does not raise: it just reports an estate as unaffected;
* an inventory pass that **replaces** would delete real rows every time an
  unauthenticated scan followed a credentialled one;
* inventory rejects folded into `records_rejected` would make an import look
  like it dropped vulnerability data it never had;
* a scanning switch enforced only at `queue_job` lets a backlog **drain after
  the operator turned it off** -- the estate gets scanned by a platform its
  owner believes is stopped. That is the MFA-that-checked-presence defect of
  phase 24, wearing different clothes;
* a scanning switch enforced at `submit_result` would discard output from a
  scan that already ran and wedge its job in `running` forever.

`test_every_work_creating_path_consults_the_gate` is the source-level guardrail,
in the line of phase 26's over `analytics.py` and phase 28's over the policies
router: threading a check through three functions works exactly until somebody
adds the fourth.
"""
from __future__ import annotations

import ast
import pathlib
import uuid

import pytest

from veyrs.db import SessionLocal, set_tenant
from veyrs.models import Asset, AssetProduct
from veyrs.models.agent import AgentJob, ExecAgent, JobState
from veyrs.models.integration import ImportRun
from veyrs.services import agents as agent_service
from veyrs.services import importers, scanning
from veyrs.services.importers.parsers import nessus_inventory
from veyrs.services.versions import cpe22_to_cpe23, parse_cpe23

ROOT = pathlib.Path(__file__).resolve().parents[1]
AGENTS_PY = ROOT / "backend" / "veyrs" / "services" / "agents.py"

REPORT = b"""<?xml version="1.0" encoding="UTF-8"?>
<NessusClientData_v2>
  <Report name="phase34">
    <ReportHost name="10.99.34.7">
      <HostProperties>
        <tag name="host-ip">10.99.34.7</tag>
        <tag name="host-fqdn">phase34.example.test</tag>
        <tag name="mac-address">aa:bb:cc:00:34:07</tag>
        <tag name="operating-system">Linux Kernel 6.1 on Debian 12</tag>
        <tag name="cpe">cpe:/o:debian:debian_linux:12</tag>
        <tag name="cpe-0">cpe:/a:openbsd:openssh:9.2p1 -&gt; OpenBSD OpenSSH 9.2p1</tag>
        <tag name="cpe-1">cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*</tag>
        <tag name="cpe-2">not a cpe at all</tag>
      </HostProperties>
      <ReportItem port="443" svc_name="www" protocol="tcp" severity="3"
                  pluginID="99034" pluginName="Phase 34 test finding">
        <description>A finding invented by the phase 34 suite.</description>
      </ReportItem>
      <ReportItem port="0" protocol="tcp" severity="0" pluginID="22869"
                  pluginName="Software Enumeration (SSH)">
        <plugin_output>Here is the list of packages installed :

  bash-5.2.15-2.deb12u1
  nginx_1.22.1-9_amd64
  a line that is not a package at all
  libfoo
</plugin_output>
      </ReportItem>
    </ReportHost>
  </Report>
</NessusClientData_v2>
"""


def _asset(org_id: uuid.UUID, fqdn: str = "phase34.example.test") -> uuid.UUID:
    with SessionLocal() as session:
        set_tenant(session, org_id)
        asset = Asset(
            organization_id=org_id, name=fqdn, hostname=fqdn.split(".")[0],
            fqdn=fqdn, ip_addresses=["10.99.34.7"], asset_type="server",
            criticality="medium", exposure="internal",
        )
        session.add(asset)
        session.commit()
        return asset.id


def _installs(org_id: uuid.UUID, asset_id: uuid.UUID) -> list[AssetProduct]:
    with SessionLocal() as session:
        set_tenant(session, org_id)
        return list(session.query(AssetProduct).filter(
            AssetProduct.organization_id == org_id,
            AssetProduct.asset_id == asset_id,
        ).all())


def _import(org_id, payload=REPORT, **options):
    with SessionLocal() as session:
        set_tenant(session, org_id)
        run = importers.run_import(
            session, org_id, payload, source="nessus",
            filename="phase34.nessus",
            options=importers.ImportOptions(**options),
        )
        session.commit()
        return session.get(ImportRun, run.id)


# ==========================================================================
# CPE 2.2 -> 2.3
# ==========================================================================
def test_cpe22_converts_and_the_result_actually_parses():
    out = cpe22_to_cpe23("cpe:/a:openbsd:openssh:9.2p1")
    assert out == "cpe:2.3:a:openbsd:openssh:9.2p1:*:*:*:*:*:*:*"
    parts = parse_cpe23(out)
    assert parts is not None
    assert (parts["vendor"], parts["product"], parts["version"]) == (
        "openbsd", "openssh", "9.2p1")


def test_nessus_human_gloss_is_stripped():
    # Nessus writes `cpe:/a:x:y:1 -> Some Product 1`. Left in, the version
    # component swallows the sentence.
    out = cpe22_to_cpe23("cpe:/a:openbsd:openssh:9.2p1 -> OpenBSD OpenSSH 9.2p1")
    assert out == "cpe:2.3:a:openbsd:openssh:9.2p1:*:*:*:*:*:*:*"


def test_missing_trailing_components_become_wildcards():
    out = cpe22_to_cpe23("cpe:/o:debian:debian_linux")
    assert out is not None
    assert parse_cpe23(out)["version"] == "*"
    assert out.count(":") == 12  # cpe:2.3: + 11 components


def test_percent_encoding_is_decoded_then_23_escaped():
    # 2.2 percent-encodes, 2.3 backslash-escapes. Skipping the round trip makes
    # `c++` two different products in one registry.
    out = cpe22_to_cpe23("cpe:/a:vendor:c%2b%2b:1.0")
    assert parse_cpe23(out)["product"] == "c\\+\\+"


@pytest.mark.parametrize("value", [
    "",
    "not a cpe",
    "cpe:2.3:a:f5:nginx:1.24.0:*:*:*:*:*:*:*",  # already 2.3
])
def test_refuses_what_is_not_a_22_uri(value):
    # Including 2.3: a converter that silently accepts both makes "which form
    # did this scanner give us?" unanswerable at the call site.
    assert cpe22_to_cpe23(value) is None


# ==========================================================================
# The Nessus inventory parser
# ==========================================================================
def test_cpe_tags_become_software_specs():
    hosts = list(nessus_inventory(REPORT))
    assert len(hosts) == 1
    host = hosts[0]
    assert host.fqdn == "phase34.example.test"
    assert host.operating_system == "Linux Kernel 6.1 on Debian 12"
    cpes = [s.cpe for s in host.software]
    assert "cpe:2.3:o:debian:debian_linux:12:*:*:*:*:*:*:*" in cpes
    assert "cpe:2.3:a:openbsd:openssh:9.2p1:*:*:*:*:*:*:*" in cpes
    # Already-2.3 tags are taken as-is rather than dropped by a 2.2 converter
    # that correctly refuses them.
    assert "cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*" in cpes
    # And the junk tag is skipped, not approximated.
    assert len(cpes) == 3


def test_plugin_output_is_off_by_default():
    host = next(iter(nessus_inventory(REPORT)))
    assert all(s.cpe for s in host.software), (
        "software-enumeration plugin output was mined without being asked for"
    )


def test_plugin_output_parses_only_recognised_package_shapes():
    host = next(iter(nessus_inventory(REPORT, plugin_output=True)))
    mined = {(s.product, s.raw_version) for s in host.software if not s.cpe}
    assert ("bash", "5.2.15-2.deb12u1") in mined
    assert ("nginx", "1.22.1-9") in mined
    # Free text and a bare name with no version are skipped: a guess here does
    # not fail loudly, it mints a Product row that matches no CVE.
    assert not any(p.startswith("a line") for p, _ in mined)
    assert "libfoo" not in {p for p, _ in mined}


def test_a_host_with_no_software_is_still_yielded():
    payload = REPORT.replace(b'<tag name="cpe">cpe:/o:debian:debian_linux:12</tag>', b"")
    payload = payload.replace(b'<tag name="cpe-0">cpe:/a:openbsd:openssh:9.2p1 -&gt; OpenBSD OpenSSH 9.2p1</tag>', b"")
    payload = payload.replace(b'<tag name="cpe-1">cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*</tag>', b"")
    hosts = list(nessus_inventory(payload))
    assert len(hosts) == 1 and hosts[0].software == [], (
        "a host the scanner reached and could not fingerprint is a coverage "
        "fact and must be counted, not dropped"
    )


# ==========================================================================
# Ingestion
# ==========================================================================
def test_inventory_is_not_imported_unless_asked(org_a):
    org_id, _, _ = org_a
    asset_id = _asset(org_id)
    run = _import(org_id)
    assert run.inventory_hosts == 0
    assert run.inventory_added == 0
    assert _installs(org_id, asset_id) == []


def test_inventory_lands_on_the_matching_asset(org_a):
    org_id, _, _ = org_a
    asset_id = _asset(org_id)
    run = _import(org_id, import_inventory=True)
    assert run.inventory_hosts == 1
    assert run.inventory_added >= 3
    rows = _installs(org_id, asset_id)
    assert len(rows) >= 3
    assert all(r.detected_by == "scanner:nessus" for r in rows)
    # Anchored to the dictionary entry the scanner named, not to a guess.
    assert any(r.cpe23 for r in rows)


def test_unknown_host_creates_nothing_and_does_not_inflate_rejects(org_a, org_b):
    """`records_rejected` is a statement about findings, and only about findings.

    Asserted as a DIFFERENCE rather than an absolute count: the report's own
    number of report items is an incidental fact about the fixture, and pinning
    it would make this test fail for the wrong reason the day a ReportItem is
    added to it. What must hold is that turning the inventory pass on changes
    the finding-level reject count by exactly nothing.
    """
    org_with, _, _ = org_a
    org_without, _, _ = org_b
    with_inventory = _import(org_with, import_inventory=True)
    without = _import(org_without, import_inventory=False)

    assert with_inventory.inventory_hosts == 1
    assert with_inventory.inventory_added == 0  # create_assets is off
    assert with_inventory.records_rejected == without.records_rejected, (
        "the inventory pass booked its own asset-resolution rejects into the "
        "finding counter"
    )


def test_dry_run_writes_no_inventory(org_a):
    org_id, _, _ = org_a
    asset_id = _asset(org_id)
    _import(org_id, import_inventory=True, dry_run=True)
    assert _installs(org_id, asset_id) == []


def test_inventory_never_replaces(org_a):
    """A scan of three hosts is not a statement about the estate."""
    org_id, _, _ = org_a
    asset_id = _asset(org_id)
    _import(org_id, import_inventory=True)
    before = {r.product_id for r in _installs(org_id, asset_id)}
    assert before

    # A second, poorer export from the same source -- e.g. the unauthenticated
    # scan that follows a credentialled one.
    thin = REPORT.replace(b'<tag name="cpe-0">cpe:/a:openbsd:openssh:9.2p1 -&gt; OpenBSD OpenSSH 9.2p1</tag>', b"")
    thin = thin.replace(b'<tag name="cpe-1">cpe:2.3:a:postgresql:postgresql:15.4:*:*:*:*:*:*:*</tag>', b"")
    _import(org_id, thin, import_inventory=True)
    after = {r.product_id for r in _installs(org_id, asset_id)}
    assert before <= after, "an inventory import pruned rows it simply did not mention"


def test_a_broken_inventory_pass_does_not_fail_the_import(org_a, monkeypatch):
    """Losing the vulnerability data because a software list was malformed
    would be strictly worse than importing without inventory."""
    org_id, _, _ = org_a
    _asset(org_id)

    def explode(*args, **kwargs):
        raise RuntimeError("inventory parser blew up")

    monkeypatch.setattr(importers, "ingest_inventory", explode)
    run = _import(org_id, import_inventory=True, create_assets=True)
    assert run.status == "complete"
    assert run.findings_created >= 1
    assert "inventory pass failed" in run.reject_reasons


def test_import_run_reports_its_inventory_counters(org_a):
    """Phase 33's lesson: a counter the API never returns is a blank column."""
    org_id, _, _ = org_a
    _asset(org_id)
    run = _import(org_id, import_inventory=True)
    from veyrs.api.v1.integrations import ImportRunOut
    body = ImportRunOut.model_validate(run).model_dump()
    for field in ("inventory_hosts", "inventory_added", "inventory_updated",
                  "inventory_unmatched"):
        assert field in body, f"ImportRunOut does not return {field}"


# ==========================================================================
# The active-scanning switch
# ==========================================================================
def _agent(org_id):
    """An agent that can actually be given work.

    `queue_job` refuses a tool no enabled agent provides, so an agent enrolled
    without declaring its tools is not a usable fixture -- and the refusal it
    raises (`ToolRefused`) is not the one these tests are about.
    """
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent, token = agent_service.enroll(
            session, org_id, name="phase34-" + uuid.uuid4().hex[:6],
            allowed_targets=["10.99.34.0/24"], auto_enable_tools=True,
        )
        agent_service.declare_tools(
            session, agent, [{"name": "nuclei", "parser": "nuclei"}]
        )
        agent.status = "idle"
        session.commit()
        return agent.id, token


def test_scanning_is_enabled_by_default(org_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        state = scanning.state(session, org_id)
    assert state["active_scanning_enabled"] is True
    # And the console can tell a decision from a default.
    assert state["explicit"] is False


def test_disabling_refuses_to_queue_and_to_claim(org_a):
    org_id, _, _ = org_a
    agent_id, _ = _agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        job = agent_service.queue_job(
            session, org_id, tool="nuclei", target="10.99.34.7",
            reason="phase34 backlog")
        job_id = job.id
        scanning.set_enabled(session, org_id, False, reason="ingest-only",
                             cancel_queued_jobs=False)
        session.commit()

    with SessionLocal() as session:
        set_tenant(session, org_id)
        with pytest.raises(agent_service.ScanningRefused):
            agent_service.queue_job(session, org_id, tool="nuclei",
                                    target="10.99.34.7", reason="nope")
        agent = session.get(ExecAgent, agent_id)
        assert session.get(AgentJob, job_id).state == JobState.QUEUED.value
        # THE one that matters: work queued before the flip must not drain.
        with pytest.raises(agent_service.ScanningRefused):
            agent_service.claim_next(session, agent)


def test_disabling_refuses_new_enrolments(org_a):
    org_id, _, _ = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        scanning.set_enabled(session, org_id, False)
        session.commit()
    with SessionLocal() as session:
        set_tenant(session, org_id)
        with pytest.raises(agent_service.ScanningRefused):
            agent_service.enroll(session, org_id, name="late runner")


def test_disabling_cancels_queued_work_but_not_running_work(org_a):
    org_id, _, _ = org_a
    _agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        queued = agent_service.queue_job(session, org_id, tool="nuclei",
                                         target="10.99.34.7", reason="queued")
        running = agent_service.queue_job(session, org_id, tool="nuclei",
                                          target="10.99.34.8", reason="running")
        running.state = JobState.RUNNING.value
        session.flush()
        queued_id, running_id = queued.id, running.id
        out = scanning.set_enabled(session, org_id, False, reason="ingest-only")
        session.commit()

    assert out["jobs_cancelled"] >= 1
    with SessionLocal() as session:
        set_tenant(session, org_id)
        assert session.get(AgentJob, queued_id).state == JobState.CANCELLED.value
        # A running job already touched the estate; killing it here would
        # strand output submit_result is still willing to take.
        assert session.get(AgentJob, running_id).state == JobState.RUNNING.value


def test_re_enabling_restores_the_queue_path(org_a):
    org_id, _, _ = org_a
    _agent(org_id)
    with SessionLocal() as session:
        set_tenant(session, org_id)
        scanning.set_enabled(session, org_id, False)
        scanning.set_enabled(session, org_id, True, reason="back on")
        job = agent_service.queue_job(session, org_id, tool="nuclei",
                                      target="10.99.34.7", reason="after")
        session.commit()
        assert job.state == JobState.QUEUED.value


# ==========================================================================
# The switch over HTTP
# ==========================================================================
def test_scanning_state_is_readable_and_writable(client, admin_a):
    body = client.get("/api/v1/scanning", headers=admin_a)
    assert body.status_code == 200, body.text
    assert body.json()["active_scanning_enabled"] is True

    put = client.put("/api/v1/scanning", headers=admin_a, json={
        "active_scanning_enabled": False,
        "reason": "we run Nessus; VEYRS only manages the findings",
    })
    assert put.status_code == 200, put.text
    assert put.json()["active_scanning_enabled"] is False
    assert put.json()["explicit"] is True

    again = client.get("/api/v1/scanning", headers=admin_a)
    assert again.json()["reason"].startswith("we run Nessus")


def test_queueing_over_http_is_refused_when_scanning_is_off(client, admin_a, org_a):
    org_id, _, _ = org_a
    client.put("/api/v1/scanning", headers=admin_a,
               json={"active_scanning_enabled": False})
    response = client.post("/api/v1/agents/jobs", headers=admin_a, json={
        "tool": "nuclei", "target": "10.99.34.7", "reason": "should not run",
    })
    # 403 and not 422: there is no correction to the request body that would
    # make this work, so telling the caller their payload was unprocessable
    # sends them to debug the wrong thing.
    assert response.status_code == 403, response.text
    assert "ingest-only" in response.text


# ==========================================================================
# Source guardrail
# ==========================================================================
def test_every_work_creating_path_consults_the_gate():
    """Threading a check through three functions works until there is a fourth.

    The list is deliberately of *names*, not of a heuristic: `submit_result`
    and `heartbeat` must NOT appear, and a guardrail that inferred "anything
    touching AgentJob" would demand exactly the wrong thing of them.
    """
    tree = ast.parse(AGENTS_PY.read_text(encoding="utf-8"))
    gated = set()
    for node in ast.walk(tree):
        if not isinstance(node, ast.FunctionDef):
            continue
        for call in ast.walk(node):
            if (isinstance(call, ast.Call) and isinstance(call.func, ast.Name)
                    and call.func.id == "_require_active_scanning"):
                gated.add(node.name)

    must_gate = {"enroll", "queue_job", "claim_next"}
    assert must_gate <= gated, (
        "these create or hand out scan work without consulting the switch: "
        + ", ".join(sorted(must_gate - gated))
    )
    must_not_gate = {"submit_result", "submit_inventory", "heartbeat", "fail_job"}
    assert not (must_not_gate & gated), (
        "these FINISH work or report facts and must stay open with scanning "
        "off: " + ", ".join(sorted(must_not_gate & gated))
    )
