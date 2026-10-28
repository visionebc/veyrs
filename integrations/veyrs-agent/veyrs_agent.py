#!/usr/bin/env python3
"""VEYRS execution agent - the reference runner.

Sits inside a network segment, asks VEYRS for work, runs a scanner, streams the
output and submits the result. Standard library only: this thing is meant to be
copied onto a jump host, a container or a Raspberry Pi in a factory VLAN, and a
dependency tree is a liability there.

READ THIS BEFORE CHANGING IT
============================

The server is NOT trusted to decide what runs. That is the entire security
model, and every rule below exists to keep it true:

1. **The server never sends a command line.** It sends
   ``{tool, target, profile, params}``. The argv is built HERE, by the builder
   registered for that tool, from a fixed template plus a whitelist of knobs.
   A key the builder does not recognise is dropped, not passed through.
2. **No shell, ever.** ``subprocess.run(argv, shell=False)``. There is no
   string interpolation anywhere near an execution call.
3. **The allowlist is enforced twice.** The server authorises the target, and
   this agent checks it again against its OWN config before running. A
   compromised or impersonated VEYRS therefore still cannot point this agent at
   an arbitrary host - it can only ask for work inside the operator's own
   local allowlist.
4. **Tools are opt-in locally too.** Only tools present in ``TOOLS`` *and*
   found on PATH are declared; only tools an operator has enabled server-side
   are ever dispatched. Both sides must say yes.

Adding a tool means writing a builder that maps profile+params to argv. If you
find yourself wanting to pass a raw argument string from the server, stop: that
is the design being defeated, not extended.

Usage
-----
    export VEYRS_URL=https://veyrs.example.com
    export VEYRS_AGENT_TOKEN=veyrsagent_xxxx_yyyy
    export VEYRS_AGENT_ALLOW="10.44.0.0/24,*.example.com"
    python3 veyrs_agent.py

    python3 veyrs_agent.py --once      # one poll, for cron or a smoke test
    python3 veyrs_agent.py --dry-run   # claim and print the argv, run nothing
"""
from __future__ import annotations

import argparse
import fnmatch
import ipaddress
import json
import os
import platform
import re
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.parse
import urllib.request
from typing import Any, Callable
from urllib.parse import urlsplit

VERSION = "1.2.0"
DEFAULT_POLL_SECONDS = 15
DEFAULT_TIMEOUT = 3600
#: Lines of scanner stdout batched into one events call.
EVENT_BATCH = 25
#: Where an operator declares the resolvers this network segment must be scanned
#: with. See load_resolvers() for why this is not optional on a split estate.
DEFAULT_RESOLVERS_FILE = "/etc/veyrs-agent/resolvers.txt"
#: argv fragment materialised once by main(). Module-level because a builder's
#: signature is (target, profile, params, out) and this is LOCAL operator
#: config, not a server-supplied knob - the distinction this file is built on.
RESOLVER_ARGS: list[str] = []
#: Ports probed to establish that the target was reachable from here at all.
PROBE_PORTS = (443, 80, 22)
#: How often a host re-reports its installed software. Inventory changes on the
#: timescale of package upgrades, not minutes, and every report re-correlates
#: the asset server-side -- so this is deliberately hours, not the poll interval.
DEFAULT_INVENTORY_SECONDS = 6 * 3600


def load_resolvers(path: str | None) -> list[str]:
    """Materialise the operator's resolver list as an argv fragment.

    nuclei does NOT use the system resolver: projectdiscovery's dialer carries
    public resolvers compiled in. On any split-horizon estate that makes the
    scanner resolve the PUBLIC address of an internal host, fail to route to
    it, and exit 0 having scanned nothing - a silent false negative that reads
    as a clean scan. Measured on this fleet: 5% of templates completed with
    more errors than requests, versus 97% once the internal resolver is passed.

    The file an operator can document is not the file the scanner can read:
    nuclei takes one address per line and treats a comment as a resolver
    (verified - a commented file drops coverage to 0%). So this writes a
    sanitised copy and hands that over.
    """
    if not path:
        return []
    try:
        with open(path, encoding="utf-8") as handle:
            entries = [line.strip() for line in handle]
    except OSError as exc:
        log(f"resolver list {path!r} unreadable ({exc}); scanners keep their own")
        return []
    entries = [e for e in entries if e and not e.startswith("#")]
    if not entries:
        return []
    fd, clean = tempfile.mkstemp(prefix="veyrs-resolvers-", suffix=".txt")
    with os.fdopen(fd, "w", encoding="utf-8") as handle:
        handle.write("\n".join(entries) + "\n")
    log(f"resolvers: {', '.join(entries)} (from {path})")
    return ["-r", clean]


# ===========================================================================
# Tool registry - the only place an argv is ever constructed
# ===========================================================================
def _int(params: dict, key: str, default: int, low: int, high: int) -> int:
    """Read an integer knob, clamped. The server cannot widen these bounds."""
    try:
        value = int(params.get(key, default))
    except (TypeError, ValueError):
        return default
    return max(low, min(high, value))


def build_nuclei(target: str, profile: str | None, params: dict, out: str) -> list[str]:
    argv = ["nuclei", "-target", target, "-jsonl", "-output", out, "-silent",
            "-rate-limit", str(_int(params, "rate_limit", 150, 1, 1000)),
            "-timeout", str(_int(params, "timeout", 10, 1, 120))]
    if profile == "quick":
        argv += ["-severity", "critical,high"]
    elif profile == "full":
        argv += ["-severity", "critical,high,medium,low,info"]
    # Template selection is a fixed choice, never a free path: a server-supplied
    # template directory is arbitrary code execution by another name.
    if params.get("templates") in ("cves", "exposures", "misconfiguration"):
        argv += ["-tags", str(params["templates"])]
    # -stats-json is the only place nuclei says how much of the scan it actually
    # completed. Without it an aborted run and a clean run are the same three
    # facts (exit 0, no output, no matches) and VEYRS cannot tell them apart.
    argv += ["-stats", "-stats-json", "-stats-interval", "10"]
    return argv + RESOLVER_ARGS


def build_nmap(target: str, profile: str | None, params: dict, out: str) -> list[str]:
    argv = ["nmap", "-oX", out, "-Pn"]
    if profile == "quick":
        argv += ["-T4", "-F"]
    elif profile == "full":
        argv += ["-T4", "-p-", "-sV"]
    else:
        argv += ["-T3", "--top-ports", str(_int(params, "top_ports", 1000, 10, 65535))]
    return argv + [target]


def build_trivy(target: str, profile: str | None, params: dict, out: str) -> list[str]:
    # `target` for trivy is an image reference or a filesystem path the agent
    # itself owns; the server-side allowlist still gated who may ask for it.
    kind = "image" if params.get("kind") == "image" else "fs"
    return ["trivy", kind, "--format", "json", "--output", out, "--quiet",
            "--severity", "CRITICAL,HIGH,MEDIUM" if profile == "quick"
            else "CRITICAL,HIGH,MEDIUM,LOW,UNKNOWN", target]


def build_zap(target: str, profile: str | None, params: dict, out: str) -> list[str]:
    argv = ["zap-baseline.py", "-t", target, "-J", out, "-I"]
    if profile == "full":
        argv = ["zap-full-scan.py", "-t", target, "-J", out, "-I"]
    return argv


def build_semgrep(target: str, profile: str | None, params: dict, out: str) -> list[str]:
    return ["semgrep", "--config", "auto", "--json", "--output", out, "--quiet", target]


_NUM = re.compile(r"^-?\d+$")
#: CSI escape sequence. Scanner banners are written for a terminal, not
#: for a database column the console will print back verbatim.
ANSI_ESCAPE = re.compile(r"\x1B\[[0-9;]*[A-Za-z]")


def stats_nuclei(line: str) -> dict | None:
    """Recognise a -stats-json line and reduce it to integers.

    Emitted on stderr every -stats-interval seconds and cumulative, so the last
    one seen is the summary of the whole run. Returning None means "this is
    ordinary output" and the line stays in the event stream.
    """
    line = line.strip()
    if not (line.startswith("{") and '"requests"' in line and '"percent"' in line):
        return None
    try:
        raw = json.loads(line)
    except ValueError:
        return None
    out: dict[str, Any] = {}
    for key in ("requests", "errors", "matched", "percent", "hosts", "templates", "total"):
        value = str(raw.get(key, "")).strip()
        if _NUM.match(value):
            out[key] = int(value)
    if not out:
        return None
    out["duration"] = str(raw.get("duration") or "")[:20]
    return out


class Tool:
    def __init__(self, name: str, binary: str, parser: str, profiles: list[str],
                 build: Callable[[str, str | None, dict, str], list[str]],
                 suffix: str = ".json",
                 stats: Callable[[str], dict | None] | None = None):
        self.name = name
        self.binary = binary
        self.parser = parser
        self.profiles = profiles
        self.build = build
        self.suffix = suffix
        #: Optional recogniser turning one output line into coverage numbers.
        self.stats = stats

    @property
    def available(self) -> bool:
        return shutil.which(self.binary) is not None

    def version(self) -> str | None:
        """First line of `--version`, stripped of terminal escapes.

        Several scanners print their banner through a colour logger, so the
        raw first line is not display text: `nuclei --version` emits
        `\x1b[34mINF\x1b[0m] Nuclei Engine Version: v3.11.1`. VEYRS renders
        this string in the console, and the escapes survive JSON and the
        database unchanged. Stripped here at the source; the server strips it
        again on ingest, because an agent is not a trusted source of text the
        console will print.
        """
        path = shutil.which(self.binary)
        if path is None:
            return None
        try:
            probe = subprocess.run([path, "--version"], capture_output=True, timeout=15,
                                   text=True, shell=False)
            raw = (probe.stdout or probe.stderr).strip().splitlines()[0]
        except (OSError, subprocess.SubprocessError, IndexError):
            return None
        clean = ANSI_ESCAPE.sub("", raw)
        clean = "".join(ch for ch in clean if ch.isprintable())
        return " ".join(clean.split())[:60] or None


TOOLS: dict[str, Tool] = {
    t.name: t for t in [
        Tool("nuclei", "nuclei", "nuclei", ["quick", "full"], build_nuclei, ".jsonl",
             stats=stats_nuclei),
        Tool("nmap", "nmap", "nmap", ["quick", "full", "default"], build_nmap, ".xml"),
        Tool("trivy", "trivy", "trivy", ["quick", "full"], build_trivy),
        Tool("zap", "zap-baseline.py", "zap", ["quick", "full"], build_zap),
        Tool("semgrep", "semgrep", "semgrep", ["default"], build_semgrep),
    ]
}


# ===========================================================================
# Local target policy - the second half of "authorised twice"
# ===========================================================================
def target_host(target: str) -> str:
    raw = (target or "").strip()
    if "://" in raw:
        return (urlsplit(raw).hostname or "").lower()
    if raw.startswith("["):
        return raw[1:].partition("]")[0].lower()
    try:
        ipaddress.ip_address(raw)
        return raw.lower()
    except ValueError:
        pass
    return raw.partition(":")[0].lower() if raw.count(":") == 1 else raw.lower()


def locally_allowed(target: str, rules: list[str]) -> bool:
    """Would this agent's OWN operator permit this target?

    Defence in depth against a compromised or spoofed server. Empty rules means
    nothing is allowed - the same deny-by-default posture the server uses.
    """
    host = target_host(target)
    if not host or not rules:
        return False
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        address = None
    if address is not None and (address.is_loopback or address.is_link_local
                                or address.is_multicast):
        return host in [r.strip().lower() for r in rules]
    for rule in rules:
        rule = rule.strip().lower()
        if not rule:
            continue
        if "/" in rule:
            if address is None:
                continue
            try:
                if address in ipaddress.ip_network(rule, strict=False):
                    return True
            except ValueError:
                continue
        elif address is None and fnmatch.fnmatch(host, rule):
            return True
        elif address is not None and rule == host:
            return True
    return False


def probe_target(target: str) -> dict:
    """Did this agent reach the target at all, from here, right now?

    Tool-agnostic evidence, and deliberately taken with the SYSTEM resolver:
    when it disagrees with the scanner's own numbers, that disagreement is the
    finding. A scanner that resolves elsewhere will report an empty scan while
    this probe still connects - which is exactly the split-horizon failure the
    resolver list fixes, and the reason both signals are reported.
    """
    host = target_host(target)
    out: dict[str, Any] = {"host": host, "resolved_ips": [], "open_ports": [],
                           "reachable": False}
    if not host:
        return out
    try:
        addresses = sorted({info[4][0] for info in socket.getaddrinfo(host, None)})
    except (OSError, UnicodeError):
        return out
    out["resolved_ips"] = addresses[:8]
    for port in PROBE_PORTS:
        for address in addresses[:3]:
            try:
                with socket.create_connection((address, port), timeout=3):
                    out["open_ports"].append(port)
                    break
            except OSError:
                continue
    out["reachable"] = bool(out["open_ports"])
    return out


# ===========================================================================
# Transport
# ===========================================================================
# ===========================================================================
# Inventory collection
#
# A scan tells you what was vulnerable at the moment it ran. An inventory tells
# you what exists, so a CVE published next week raises a finding next week with
# nobody re-running anything. That is the whole reason this section exists, and
# it is why the collector reports EVERY package rather than a curated subset:
# the agent cannot know which package tomorrow's advisory will name.
# ===========================================================================
def read_os_release(path: str = "/etc/os-release") -> tuple[str | None, str | None]:
    values: dict[str, str] = {}
    try:
        with open(path, encoding="utf-8", errors="replace") as handle:
            for line in handle:
                key, _, value = line.strip().partition("=")
                if key:
                    values[key] = value.strip().strip('"')
    except OSError:
        return None, None
    return values.get("NAME") or values.get("ID"), values.get("VERSION_ID")


def upstream_version(raw: str) -> str | None:
    """Reduce a distro package version to the form CVE ranges are written in.

    `1:1.24.0-2ubuntu7.1` -> `1.24.0`.

    Both halves that get stripped are packaging metadata, not upstream identity:
    the leading `1:` is a Debian epoch, and everything from the first `-` is the
    distribution's own revision. Comparing those against an NVD range would be
    meaningless -- `1:1.24.0-2ubuntu7.1` sorts below `1.24.0` on some segments
    and above it on others, so the match would be wrong in an unpredictable
    direction rather than merely conservative.

    The known cost, and it is a real one: distributions backport security fixes
    without moving the upstream version, so a host on `1.24.0-2ubuntu7.1` may
    already be patched for a CVE whose range says "<= 1.24.0" and will still be
    flagged. That is why the verbatim string is reported alongside as
    `raw_version` -- the analyst needs to see it to triage the finding. The
    alternative, matching on the distro string, matches nothing at all.
    """
    value = (raw or "").strip()
    if not value:
        return None
    if ":" in value:
        value = value.split(":", 1)[1]
    value = re.split(r"[-+~]", value, maxsplit=1)[0]
    return value or None


def _capture(argv: list[str], timeout: int = 180) -> str | None:
    if not shutil.which(argv[0]):
        return None
    try:
        proc = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
    except (OSError, subprocess.SubprocessError):
        return None
    return proc.stdout if proc.returncode == 0 else None


def collect_packages() -> list[dict]:
    """Every installed package this host's package manager knows about.

    Ordered by specificity: dpkg and rpm emit a machine-readable format we can
    trust, so they are tried first. `apk info -v` is a last resort precisely
    because its output (`busybox-1.36.1-r5`) has no delimiter between name and
    version -- the split below is a heuristic, and a package whose name ends in
    something version-shaped will be parsed wrong. Alpine hosts should be
    treated as best-effort until apk grows a format string.
    """
    items: list[dict] = []

    dpkg = _capture(["dpkg-query", "-W", "-f=${Package}\t${Version}\n"])
    if dpkg:
        for line in dpkg.splitlines():
            name, _, raw = line.partition("\t")
            if name and raw:
                items.append({"product": name.split(":")[0], "vendor": None,
                              "version": upstream_version(raw), "raw_version": raw})
        return items

    rpm = _capture(["rpm", "-qa", "--qf", "%{NAME}\t%{VERSION}-%{RELEASE}\n"])
    if rpm:
        for line in rpm.splitlines():
            name, _, raw = line.partition("\t")
            if name and raw:
                items.append({"product": name, "vendor": None,
                              "version": upstream_version(raw), "raw_version": raw})
        return items

    apk = _capture(["apk", "info", "-v"])
    if apk:
        for line in apk.splitlines():
            match = re.match(r"^(?P<name>.+?)-(?P<ver>\d[^-]*(?:-r\d+)?)$", line.strip())
            if match:
                items.append({"product": match.group("name"), "vendor": None,
                              "version": upstream_version(match.group("ver")),
                              "raw_version": match.group("ver")})
        return items

    return items


class ApiError(RuntimeError):
    pass


class Client:
    def __init__(self, base_url: str, token: str, *, verify_tls: bool = True,
                 timeout: int = 60):
        self.base = base_url.rstrip("/")
        self.token = token
        self.timeout = timeout
        self.ctx = None if verify_tls else ssl._create_unverified_context()

    def _call(self, method: str, path: str, *, body: bytes | None = None,
              json_body: Any = None, content_type: str | None = None,
              extra_headers: dict[str, str] | None = None) -> tuple[int, Any]:
        url = f"{self.base}/api/v1{path}"
        data = body
        headers = {"X-Agent-Token": self.token, "User-Agent": f"veyrs-agent/{VERSION}"}
        if extra_headers:
            headers.update(extra_headers)
        if json_body is not None:
            data = json.dumps(json_body).encode()
            headers["Content-Type"] = "application/json"
        elif content_type:
            headers["Content-Type"] = content_type
        request = urllib.request.Request(url, data=data, headers=headers, method=method)
        try:
            with urllib.request.urlopen(request, timeout=self.timeout,
                                        context=self.ctx) as response:
                raw = response.read()
                if response.status == 204 or not raw:
                    return response.status, None
                return response.status, json.loads(raw)
        except urllib.error.HTTPError as exc:
            detail = exc.read().decode(errors="replace")[:500]
            raise ApiError(f"{method} {path} -> {exc.code}: {detail}") from exc
        except (urllib.error.URLError, OSError, socket.timeout) as exc:
            raise ApiError(f"{method} {path} -> transport error: {exc}") from exc

    def heartbeat(self, tools: list[dict]) -> dict:
        return self._call("POST", "/agents/self/heartbeat", json_body={
            "agent_version": VERSION,
            "hostname": socket.gethostname(),
            "platform": f"{platform.system()} {platform.release()}",
            "tools": tools,
        })[1]

    def claim(self) -> dict | None:
        status, payload = self._call("POST", "/agents/self/jobs/claim")
        return None if status == 204 else payload

    def events(self, job_id: str, lease: str, events: list[dict]) -> None:
        query = urllib.parse.urlencode({"lease_token": lease})
        self._call("POST", f"/agents/self/jobs/{job_id}/events?{query}",
                   json_body={"events": events})

    def extend(self, job_id: str, lease: str) -> None:
        query = urllib.parse.urlencode({"lease_token": lease})
        self._call("POST", f"/agents/self/jobs/{job_id}/lease?{query}")

    def submit(self, job_id: str, lease: str, payload: bytes, *, scanner: str,
               exit_code: int, filename: str, stats: dict | None = None) -> dict:
        query = urllib.parse.urlencode({
            "lease_token": lease, "scanner": scanner,
            "exit_code": exit_code, "filename": filename,
        })
        # Facts, not a verdict: the agent measures coverage, the server decides
        # what coverage is good enough. Keeping the policy server-side keeps the
        # threshold operator-tunable and identical for every agent.
        headers = {"X-Agent-Scan-Stats": json.dumps(stats)} if stats else None
        return self._call("POST", f"/agents/self/jobs/{job_id}/result?{query}",
                          body=payload, content_type="application/octet-stream",
                          extra_headers=headers)[1]

    def inventory(self, target: str, items: list[dict], *, replace: bool = True,
                  operating_system: str | None = None,
                  os_version: str | None = None) -> dict:
        return self._call("POST", "/agents/self/inventory", json_body={
            "target": target, "items": items, "replace": replace,
            "operating_system": operating_system, "os_version": os_version,
        })[1]

    def fail(self, job_id: str, lease: str, error: str, *, requeue: bool = True) -> None:
        query = urllib.parse.urlencode({"lease_token": lease})
        self._call("POST", f"/agents/self/jobs/{job_id}/fail?{query}",
                   json_body={"error": error[:4000], "requeue": requeue})


# ===========================================================================
# Execution
# ===========================================================================
def declared_tools() -> list[dict]:
    out = []
    for tool in TOOLS.values():
        if not tool.available:
            continue
        out.append({"name": tool.name, "parser": tool.parser,
                    "profiles": tool.profiles, "version": tool.version()})
    return out


def run_job(client: Client, job: dict, lease: str, rules: list[str], *,
            timeout: int, dry_run: bool = False) -> None:
    tool = TOOLS.get(job["tool"])
    if tool is None or not tool.available:
        client.fail(job["id"], lease, f"tool {job['tool']!r} is not available here",
                    requeue=True)
        return
    if not locally_allowed(job["target"], rules):
        # The server said yes; this agent's operator did not. Do NOT requeue:
        # another agent may legitimately be allowed, and retrying here would
        # just burn the job's attempts.
        client.fail(job["id"], lease,
                    f"target {job['target']!r} is outside this agent's local allowlist",
                    requeue=False)
        return

    handle, out_path = tempfile.mkstemp(prefix="veyrs-", suffix=tool.suffix)
    os.close(handle)
    argv = tool.build(job["target"], job.get("profile"), job.get("params") or {}, out_path)

    if dry_run:
        print(f"[dry-run] would run: {argv}")
        os.unlink(out_path)
        return

    log(f"job {job['id'][:8]} running {argv[0]} against {job['target']}")
    client.events(job["id"], lease, [{"kind": "status", "message": f"executing {argv[0]}",
                                      "data": {"argv0": argv[0]}}])
    buffer: list[dict] = []
    exit_code = -1
    started = time.time()
    # Taken BEFORE the scan: after a long run it would describe the estate at
    # the end, not the conditions the scan actually ran under.
    facts: dict[str, Any] = {"probe": probe_target(job["target"])}
    try:
        # shell=False and a list argv: no interpolation, no word splitting, no
        # metacharacters. This is the line the whole design protects.
        process = subprocess.Popen(argv, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                                   text=True, shell=False, bufsize=1)
        last_extend = time.time()
        for line in process.stdout:
            text = line.rstrip()
            measured = tool.stats(text) if tool.stats else None
            if measured is not None:
                # Cumulative: keep the last. Not streamed - one line every ten
                # seconds would bury the failure detail the console shows.
                facts["scanner"] = measured
                continue
            buffer.append({"kind": "stdout", "message": text[:8000]})
            if len(buffer) >= EVENT_BATCH:
                _flush(client, job["id"], lease, buffer)
            if time.time() - last_extend > 120:
                client.extend(job["id"], lease)
                last_extend = time.time()
            if time.time() - started > timeout:
                process.kill()
                raise TimeoutError(f"exceeded {timeout}s")
        exit_code = process.wait(timeout=30)
        facts["duration_s"] = round(time.time() - started, 1)
    except (OSError, subprocess.SubprocessError, TimeoutError) as exc:
        _flush(client, job["id"], lease, buffer)
        client.fail(job["id"], lease, f"{type(exc).__name__}: {exc}")
        _cleanup(out_path)
        return
    _flush(client, job["id"], lease, buffer)

    try:
        with open(out_path, "rb") as handle:
            payload = handle.read()
    except OSError:
        # No output file at all: for most scanners that means "found nothing",
        # which VEYRS accepts as a completed clean scan and reconciles.
        payload = b""
    _cleanup(out_path)

    result = client.submit(job["id"], lease, payload, scanner=tool.parser,
                           exit_code=exit_code,
                           filename=f"{tool.name}{tool.suffix}", stats=facts)
    log(f"job {job['id'][:8]} -> {result.get('state')} "
        f"({result.get('findings_created')} new, {result.get('findings_updated')} updated, "
        f"{result.get('findings_closed_absent')} closed)")


def _flush(client: Client, job_id: str, lease: str, buffer: list[dict]) -> None:
    if not buffer:
        return
    try:
        client.events(job_id, lease, buffer)
    except ApiError as exc:
        log(f"could not stream events: {exc}")
    buffer.clear()


def _cleanup(path: str) -> None:
    try:
        os.unlink(path)
    except OSError:
        pass


def log(message: str) -> None:
    print(f"{time.strftime('%Y-%m-%dT%H:%M:%S')} veyrs-agent {message}", flush=True)


# ===========================================================================
# Main loop
# ===========================================================================
def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="VEYRS execution agent")
    parser.add_argument("--url", default=os.environ.get("VEYRS_URL"))
    parser.add_argument("--token", default=os.environ.get("VEYRS_AGENT_TOKEN"))
    parser.add_argument("--allow", default=os.environ.get("VEYRS_AGENT_ALLOW", ""),
                        help="comma-separated local allowlist (CIDRs and name globs)")
    parser.add_argument("--poll", type=int,
                        default=int(os.environ.get("VEYRS_AGENT_POLL", DEFAULT_POLL_SECONDS)))
    parser.add_argument("--job-timeout", type=int,
                        default=int(os.environ.get("VEYRS_AGENT_JOB_TIMEOUT", DEFAULT_TIMEOUT)))
    parser.add_argument("--resolvers",
                        default=os.environ.get("VEYRS_AGENT_RESOLVERS",
                                               DEFAULT_RESOLVERS_FILE),
                        help="file of DNS resolvers this segment must be scanned with")
    parser.add_argument("--insecure", action="store_true",
                        help="skip TLS verification (lab use only)")
    parser.add_argument("--inventory-target",
                        default=os.environ.get("VEYRS_AGENT_INVENTORY_TARGET", ""),
                        help="report this host's installed software as belonging to "
                             "this target. Must be covered by the agent's SERVER-side "
                             "allowlist, exactly like a scan target -- an agent that "
                             "could rewrite any asset's inventory could make a host "
                             "look clean without ever running a scanner.")
    parser.add_argument("--inventory-interval", type=int,
                        default=int(os.environ.get("VEYRS_AGENT_INVENTORY_INTERVAL",
                                                   DEFAULT_INVENTORY_SECONDS)),
                        help="seconds between inventory reports (0 disables)")
    parser.add_argument("--inventory-now", action="store_true",
                        help="collect and submit one inventory, print the result, exit")
    parser.add_argument("--once", action="store_true", help="one poll, then exit")
    parser.add_argument("--dry-run", action="store_true",
                        help="claim a job and print the argv without executing")
    args = parser.parse_args(argv)

    if not args.url or not args.token:
        print("VEYRS_URL and VEYRS_AGENT_TOKEN are required", file=sys.stderr)
        return 2
    rules = [r.strip() for r in args.allow.split(",") if r.strip()]
    if not rules:
        # Refuse to start rather than start useless: an agent with no local
        # allowlist would reject every job it is handed, which looks like the
        # server being broken.
        print("VEYRS_AGENT_ALLOW is required and must not be empty", file=sys.stderr)
        return 2

    global RESOLVER_ARGS
    RESOLVER_ARGS = load_resolvers(args.resolvers)
    if not RESOLVER_ARGS:
        log(f"no resolver list at {args.resolvers!r}: scanners will use their own, "
            "which reports a clean scan on any split-horizon target")

    client = Client(args.url, args.token, verify_tls=not args.insecure)

    if args.inventory_now:
        if not args.inventory_target:
            print("--inventory-now requires --inventory-target", file=sys.stderr)
            return 2
        return _report_inventory(client, args.inventory_target, verbose=True)

    tools = declared_tools()
    log(f"starting v{VERSION}; tools: {[t['name'] for t in tools] or 'none found on PATH'}")
    if not tools:
        log("warning: no supported scanner found on PATH; this agent can only heartbeat")

    if args.inventory_target and args.inventory_interval:
        log(f"inventory enabled for {args.inventory_target!r} every "
            f"{args.inventory_interval}s")
    elif args.inventory_target:
        log("inventory target set but interval is 0; inventory is disabled")

    beat_interval, last_beat = 60, 0.0
    last_inventory = 0.0
    while True:
        try:
            if (args.inventory_target and args.inventory_interval
                    and time.time() - last_inventory > args.inventory_interval):
                # Stamp the attempt before making it: a target the server
                # refuses must not be retried every poll, or a policy mistake
                # turns into a request flood.
                last_inventory = time.time()
                _report_inventory(client, args.inventory_target)
            if time.time() - last_beat > beat_interval:
                state = client.heartbeat(tools)
                last_beat = time.time()
                log(f"heartbeat ok; server says status={state.get('status')}")
            job_envelope = client.claim()
            if job_envelope is None:
                if args.once:
                    log("no work")
                    return 0
                time.sleep(args.poll)
                continue
            run_job(client, job_envelope["job"], job_envelope["lease_token"], rules,
                    timeout=args.job_timeout, dry_run=args.dry_run)
            if args.once:
                return 0
        except ApiError as exc:
            log(f"api error: {exc}")
            if args.once:
                return 1
            time.sleep(min(args.poll * 4, 120))
        except KeyboardInterrupt:
            log("stopping")
            return 0


def _report_inventory(client: Client, target: str, *, verbose: bool = False) -> int:
    """Collect this host's packages and hand them to the server."""
    items = collect_packages()
    if not items:
        log("no package manager found here; inventory not reported")
        return 1
    name, version = read_os_release()
    try:
        result = client.inventory(target, items, operating_system=name,
                                  os_version=version)
    except ApiError as exc:
        # 422 here is a policy refusal with the reason intact -- an allowlist
        # that does not cover this target, or an asset that is not registered.
        log(f"inventory refused: {exc}")
        return 1
    log(f"inventory: {len(items)} packages -> asset {result.get('asset')}: "
        f"{result.get('added')} added, {result.get('updated')} updated, "
        f"{result.get('removed')} removed, {result.get('matched')} matchable, "
        f"{result.get('unmatched')} unmatched")
    correlation = result.get("correlation") or {}
    if correlation:
        log(f"correlation: {correlation.get('cves', 0)} CVEs, "
            f"{correlation.get('created', 0)} findings created, "
            f"{correlation.get('updated', 0)} updated")
    if verbose:
        print(json.dumps(result, indent=2)[:4000])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
