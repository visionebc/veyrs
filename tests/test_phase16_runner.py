"""Phase 16: the reference agent runner's safety-critical logic.

The runner is not part of the backend package (it ships as one standalone file
an operator drops on a jump host), so it is loaded by path. Only the parts that
would be a security incident if they were wrong are tested here:

* argv construction - the server's `params` must never become arbitrary flags;
* the local allowlist - the second of the two authorisations, and the only one
  that still holds if VEYRS itself is compromised.

There is deliberately no test that shells out to a real scanner: that would
test nmap, not VEYRS.
"""
from __future__ import annotations

import importlib.util
import pathlib

import pytest

RUNNER = (pathlib.Path(__file__).resolve().parents[1]
          / "integrations" / "veyrs-agent" / "veyrs_agent.py")


def _load():
    spec = importlib.util.spec_from_file_location("veyrs_agent", RUNNER)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


@pytest.fixture(scope="module")
def runner():
    assert RUNNER.exists(), f"reference agent missing at {RUNNER}"
    return _load()


# ---------------------------------------------------------------------------
# argv construction
# ---------------------------------------------------------------------------
def test_server_params_cannot_inject_flags(runner):
    """A hostile server sends extra keys and shell metacharacters. Neither
    reaches the argv: unknown keys are dropped, and the target is a single
    element in a list passed to a shell-less exec."""
    argv = runner.build_nuclei(
        "app.example.com; rm -rf /",
        "quick",
        {"rate_limit": 10, "extra_args": "--interactsh-server evil.example",
         "templates": "/etc/passwd", "output": "/etc/shadow"},
        "/tmp/out.jsonl",
    )
    assert "--interactsh-server" not in argv
    assert "/etc/passwd" not in argv and "/etc/shadow" not in argv
    # The metacharacters survive as ONE argv element - which is exactly why
    # shell=False matters: they are a hostname, not a command separator.
    assert "app.example.com; rm -rf /" in argv
    assert argv.count("-output") == 1 and argv[argv.index("-output") + 1] == "/tmp/out.jsonl"


def test_numeric_knobs_are_clamped_not_trusted(runner):
    fast = runner.build_nuclei("h", None, {"rate_limit": 10 ** 9}, "/tmp/o")
    assert fast[fast.index("-rate-limit") + 1] == "1000"
    slow = runner.build_nuclei("h", None, {"rate_limit": -5}, "/tmp/o")
    assert slow[slow.index("-rate-limit") + 1] == "1"
    junk = runner.build_nuclei("h", None, {"rate_limit": "; reboot"}, "/tmp/o")
    assert junk[junk.index("-rate-limit") + 1] == "150"


def test_every_registered_tool_writes_only_to_the_agents_own_temp_file(runner):
    for name, tool in runner.TOOLS.items():
        argv = tool.build("target.example.com", "quick", {}, "/tmp/veyrs-out")
        assert isinstance(argv, list) and all(isinstance(a, str) for a in argv), name
        assert argv[0] == tool.binary, name
        assert "/tmp/veyrs-out" in argv, f"{name} must write to the path the agent chose"


# ---------------------------------------------------------------------------
# local allowlist
# ---------------------------------------------------------------------------
def test_local_allowlist_is_deny_by_default(runner):
    assert runner.locally_allowed("app.example.com", []) is False
    assert runner.locally_allowed("", ["*"]) is False


@pytest.mark.parametrize("target,rules,expected", [
    ("app.example.com", ["*.example.com"], True),
    ("app.example.com", ["*.other.com"], False),
    ("https://app.example.com:8443/x", ["*.example.com"], True),
    ("10.44.0.10", ["10.44.0.0/24"], True),
    ("10.44.1.10", ["10.44.0.0/24"], False),
    # A name never matches a network rule: the DNS-rebinding guard, mirrored
    # from the server so both halves agree.
    ("app.example.com", ["10.44.0.0/24"], False),
    ("127.0.0.1", ["0.0.0.0/0"], False),
    ("169.254.169.254", ["169.254.0.0/16"], False),
    ("169.254.169.254", ["169.254.169.254"], True),
])
def test_local_allowlist_cases(runner, target, rules, expected):
    assert runner.locally_allowed(target, rules) is expected


def test_target_host_parsing_matches_the_server(runner):
    from veyrs.services import agents as agent_service

    for target in ("https://app.example.com:8443/x?y=1", "app.example.com:443",
                   "10.44.0.10", "[2001:db8::1]:443", "app.example.com"):
        assert runner.target_host(target) == agent_service.split_target(target)[0], target


def test_the_runner_refuses_to_start_without_a_local_allowlist(runner, capsys):
    code = runner.main(["--url", "https://veyrs.invalid", "--token", "veyrsagent_a_b",
                        "--allow", "", "--once"])
    assert code == 2
    assert "VEYRS_AGENT_ALLOW" in capsys.readouterr().err
