"""Phase 30 - the scanner stops being invisible, and its version stops being
line noise.

Everything the platform knows about active scanning existed only in the API:
which agent is enrolled, which engines it actually found on its PATH, what a
job was queued with, when one last ran, and how few of the findings came from a
scan at all. The console had no page for any of it, so the honest answer to
"what does VEYRS scan with?" required a database session.

What is pinned here:

* **The page is data-driven.** Every number it prints is fetched. A count, a
  version or a tool name baked into the source would be right on the day it was
  written and quietly wrong afterwards - which is worse than absent, because a
  hardcoded "62 findings" reads exactly like a measurement.
* **A declared tool version is display text, not a terminal stream.** nuclei
  reports its version through a coloured logger, so the string reaching the
  database carried ANSI escapes and rendered as `[34mINF[0m]` in a table cell.
  Stripped at the runner AND on ingest: an agent is not a trusted source of
  text the console will print back.
* **Scan output is kept verbatim apart from those escapes.** Which build is
  installed (`v3.11.1`, `build1128`) is the detail an analyst triages on;
  normalising it is a matching decision that belongs to the dictionary owner,
  not to a display helper. See the firmware rule in phase 21.
* **A succeeded scan and a failed one must not render the same.** The findings
  vocabulary has no `succeeded`/`failed`, so reusing `statePill` for a job
  flattened exactly the distinction the table is read for.
"""
from __future__ import annotations

import importlib.util
import pathlib
import re
import uuid

import pytest

from veyrs.db import SessionLocal, set_tenant
from veyrs.services import agents as agent_service

ROOT = pathlib.Path(__file__).resolve().parents[1]
CONSOLE = ROOT / "frontend" / "console"
APP_JS = CONSOLE / "app.js"
CONSOLE_CSS = CONSOLE / "console.css"
INDEX_HTML = CONSOLE / "index.html"
RUNNER = ROOT / "integrations" / "veyrs-agent" / "veyrs_agent.py"

#: The exact string `nuclei --version` writes, escapes and all.
NUCLEI_BANNER = "\x1b[34mINF\x1b[0m] Nuclei Engine Version: v3.11.1"


def _scanner_route_source() -> str:
    """The body of `route('scanner', ...)`, up to the next top-level section."""
    text = APP_JS.read_text()
    start = text.index("route('scanner'")
    end = text.index("/* ── Findings ", start)
    return text[start:end]


# ---------------------------------------------------------------------------
# 1. The version string is cleaned, and only cleaned
# ---------------------------------------------------------------------------
def test_ansi_escapes_are_stripped_from_a_declared_version():
    assert agent_service.clean_tool_version(NUCLEI_BANNER) == (
        "INF] Nuclei Engine Version: v3.11.1"
    )
    assert "\x1b" not in agent_service.clean_tool_version(NUCLEI_BANNER)


def test_the_build_survives_cleaning():
    """Stripping escapes is not normalising. The build is part of the identity
    of a firmware or a scanner release; a helper that drops it is answering a
    matching question it was never asked."""
    for raw in ("v3.11.1", "Nmap version 7.94SVN ( https://nmap.org )",
                "FortiWeb-KVM 7.6.8,build1128(GA.M),260602"):
        assert agent_service.clean_tool_version(raw) == raw


def test_control_characters_never_reach_the_console():
    """A NUL, a bare CR or an embedded newline in a field the console prints is
    an agent deciding what the operator's terminal does."""
    cleaned = agent_service.clean_tool_version("v1.0\x00\r\nrogue\ttext\x07")
    assert cleaned == "v1.0 rogue text"
    assert not any(ord(c) < 0x20 or ord(c) == 0x7F for c in cleaned)


def test_empty_and_missing_versions_stay_none():
    assert agent_service.clean_tool_version(None) is None
    assert agent_service.clean_tool_version("") is None
    # A banner that is nothing BUT escapes is absent, not an empty string: the
    # column means "the agent could not say", and "" would render as a blank
    # cell that looks like a value.
    assert agent_service.clean_tool_version("\x1b[34m\x1b[0m") is None


def test_the_column_bound_is_respected():
    assert len(agent_service.clean_tool_version("v" + "9" * 200)) == 60


# ---------------------------------------------------------------------------
# 2. ...on the way in, not merely on the way out
# ---------------------------------------------------------------------------
def test_a_heartbeat_persists_the_cleaned_version(org_a):
    org_id, _slug, _email = org_a
    with SessionLocal() as session:
        set_tenant(session, org_id)
        agent, _ = agent_service.enroll(
            session, org_id, name="phase30-runner-" + uuid.uuid4().hex[:8],
            allowed_targets=["*.example.com"],
        )
        agent_service.heartbeat(session, agent, tools=[
            {"name": "nuclei", "parser": "nuclei", "profiles": ["quick", "full"],
             "version": NUCLEI_BANNER},
        ])
        session.commit()

        stored = {t.name: t.tool_version for t in agent.tools}
        assert "\x1b" not in (stored["nuclei"] or "")
        assert "v3.11.1" in stored["nuclei"]


# ---------------------------------------------------------------------------
# 3. The runner fixes it at the source too
# ---------------------------------------------------------------------------
@pytest.fixture(scope="module")
def runner():
    spec = importlib.util.spec_from_file_location("veyrs_agent_p30", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_the_runner_strips_escapes_before_declaring(runner):
    assert runner.ANSI_ESCAPE.sub("", NUCLEI_BANNER) == "INF] Nuclei Engine Version: v3.11.1"
    source = RUNNER.read_text()
    version_fn = source[source.index("    def version(self)"):]
    version_fn = version_fn[:version_fn.index("\nTOOLS")]
    assert "ANSI_ESCAPE.sub" in version_fn, (
        "the declared version is rendered in the console; cleaning it only "
        "server-side leaves every other consumer of the agent API holding "
        "terminal escapes"
    )


# ---------------------------------------------------------------------------
# 4. The page exists, and it is in the Risk menu
# ---------------------------------------------------------------------------
def test_the_scanner_page_is_registered_and_reachable():
    text = APP_JS.read_text()
    assert "route('scanner'" in text
    assert "path: 'scanner'" in text
    assert "Vulnerability Scanner" in text


def test_the_scanner_is_reachable_from_the_findings_it_produces():
    """This test used to assert the scanner sat FIRST under a `Risk` group.

    That group no longer exists. v0.21.0 split the nav along one axis -- what
    you do every day, and what you set up once -- and the scanner page is
    configuration: a runner, its queue and its jobs. It moved to `Configure`.

    The assertion changed; **the concern did not.** The original reasoning was
    that "a reader who cannot find what produced the findings assumes nothing
    did", and that is still true and still the failure worth preventing. It is
    just no longer a claim about menu position: the Findings page itself now
    names its three producers and links to them. So this test pins the LINK
    rather than the ordering, because the link is what actually answers the
    question a reader has.

    Rewritten rather than deleted, deliberately. Deleting it would have removed
    the only record that somebody once thought about this, and the next person
    to reorganise the nav would have had to rediscover the reasoning.
    """
    text = APP_JS.read_text()
    nav = text[text.index("const NAV = ["):text.index("/* ── Sidebar state")]

    # Still exactly one door to the page: two entries are how two labels for
    # the same thing drift apart.
    assert nav.count("path: 'scanner'") == 1

    # And it lives under Configure now, next to the other set-up-once screens.
    configure = nav.index("group: 'Configure'")
    scanner = nav.index("path: 'scanner'")
    assert configure < scanner

    # The load-bearing part: whatever the menu does, the findings list has to
    # say where its rows came from and let you click through.
    findings_route = text[text.index("route('findings', listView({"):]
    findings_route = findings_route[:findings_route.index("\n}));")]
    assert "#/scanner" in findings_route, (
        "the Findings page must link to what produced its rows; without the "
        "scanner in the same menu group, this link IS the discoverability"
    )
    for origin in ("#/integrations?tab=import", "#/intel?tab=cve"):
        assert origin in findings_route, (
            f"findings also come from {origin} and the page has to say so -- "
            "naming only one producer is how an operator concludes the other "
            "two do not exist"
        )


# ---------------------------------------------------------------------------
# 5. Every number on the page is fetched
# ---------------------------------------------------------------------------
def test_the_page_reads_its_facts_from_the_api():
    body = _scanner_route_source()
    for endpoint in ("/agents?limit=", "/agents/jobs/summary", "/agents/jobs?limit=",
                     "/dashboard/technical", "/integrations/importers",
                     "/integrations/imports"):
        assert endpoint in body, f"the page must read {endpoint}, not restate it"


def test_no_measurement_is_baked_into_the_page():
    """A hardcoded count reads exactly like a live one and ages silently.

    The numbers below are today's production truth; the point is that NONE of
    them may appear as a literal. Style values (px, opacity, grid spans) are
    excluded - they are layout, not measurement.
    """
    body = _scanner_route_source()
    stripped = re.sub(r"style=\"[^\"]*\"", "", body)
    stripped = re.sub(r"\bv=\d+", "", stripped)
    for literal in ("3.11.1", "13,510", "13510", "veyrs-local-runner",
                    "345", "407", "62 ", "nuclei'", 'nuclei"'):
        assert literal not in stripped, (
            f"{literal!r} is a measurement or an instance name, not a property "
            f"of the code - it must be fetched"
        )


def test_the_engine_list_is_not_a_hardcoded_catalogue():
    """The tools table must come from what the agent declared. A static list of
    'nuclei, nmap, trivy, zap, semgrep' would show four engines that are not
    installed as though they were available."""
    body = _scanner_route_source()
    for absent in ("nmap", "trivy", "semgrep", "zap"):
        assert absent not in body.lower(), (
            f"{absent!r} is declared by the runner, not by the console"
        )


# ---------------------------------------------------------------------------
# 6. Display defences
# ---------------------------------------------------------------------------
def test_the_console_also_defends_against_a_dirty_version():
    """Rows declared before the ingest fix are still in the database and are
    not rewritten by it. The renderer has to survive them."""
    text = APP_JS.read_text()
    assert "function toolVersion(" in text
    assert "toolVersion(r.tool_version)" in _scanner_route_source()


def test_job_states_have_their_own_pills():
    body = _scanner_route_source()
    assert "jobStatePill(r.state)" in body
    assert "statePill(r.state)" not in body, (
        "statePill maps FINDING states; `succeeded` and `failed` both fall "
        "through to the same grey, which is the one distinction this table "
        "exists to show"
    )
    css = CONSOLE_CSS.read_text()
    for state in ("succeeded", "failed", "running", "expired"):
        assert f".st-{state}" in css


def test_a_stale_runner_is_called_out_rather_than_drawn_as_idle():
    """An agent that stopped checking in claims no jobs. A page that renders
    that as a quiet dash is how six days of no scanning went unnoticed."""
    body = _scanner_route_source()
    assert "RUNNER_STALE_MS" in body
    assert "No runner has checked in" in body


def test_correlation_is_not_counted_as_a_scan():
    """Most findings come from correlating the inventory against the
    dictionary. Adding them to a 'scanners' total says the estate has been
    looked at far more thoroughly than it has."""
    body = _scanner_route_source()
    assert "CORRELATION_PRODUCER" in body
    assert "not a scan" in body


# ---------------------------------------------------------------------------
# 7. Cache-busting - a console change nobody's browser loads is not deployed
# ---------------------------------------------------------------------------
def test_the_assets_are_cache_busted():
    html = INDEX_HTML.read_text()
    app_v = int(re.search(r"app\.js\?v=(\d+)", html).group(1))
    css_v = int(re.search(r"console\.css\?v=(\d+)", html).group(1))
    assert app_v >= 10
    assert css_v >= 9
