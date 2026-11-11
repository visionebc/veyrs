# VEYRS execution agent

A long-lived worker that runs scanners where the targets are and streams the
results back to VEYRS. One file, standard library only — copy it to a jump host,
a container or a box in a factory VLAN and run it.

## Why it is built this way

The server does **not** decide what gets executed. It sends
`{tool, target, profile, params}`; the agent builds the argv itself from a
registered builder, refuses tools it does not implement, and re-checks the
target against its own local allowlist before running anything.

That inversion is the point. A compromised or impersonated VEYRS can ask this
agent for `nuclei` against a host the *operator* already allowed. It cannot ask
for a shell, cannot pass raw arguments, and cannot point the agent at a host
outside `VEYRS_AGENT_ALLOW`.

Concretely:

| Property | Where it is enforced |
|---|---|
| No shell, no string interpolation | `subprocess.Popen(argv, shell=False)`, argv is a list |
| Server params cannot become arbitrary flags | each `build_*()` whitelists and clamps its knobs |
| Target authorised twice | server: `services/agents.authorise_target()` · agent: `locally_allowed()` |
| Tool authorised twice | server: `AgentTool.enabled` (operator decision) · agent: present in `TOOLS` **and** on `PATH` |
| Reserved ranges refused | both sides: loopback / link-local / multicast need an exact, literal allow |

## Enrolling

In the console (or via the API), as a user holding `agent:admin`:

```bash
curl -sX POST https://veyrs.example.com/api/v1/agents \
  -H "Authorization: Bearer $VEYRS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"name":"dmz-runner","allowed_targets":["10.44.0.0/24","*.example.com"]}'
```

The response contains `token` **once**. An agent enrolled with an empty
`allowed_targets` can run nothing — that is deliberate, not a bug.

## Running

```bash
export VEYRS_URL=https://veyrs.example.com
export VEYRS_AGENT_TOKEN=veyrsagent_xxxx_yyyy
export VEYRS_AGENT_ALLOW="10.44.0.0/24,*.example.com"
python3 veyrs_agent.py
```

| Flag / env | Meaning |
|---|---|
| `--allow` / `VEYRS_AGENT_ALLOW` | **Required.** Local allowlist: CIDRs and name globs. Empty refuses to start. |
| `--resolvers` / `VEYRS_AGENT_RESOLVERS` | DNS resolvers this segment must be scanned with (default `/etc/veyrs-agent/resolvers.txt`). See below — on a split-horizon estate this is not optional. |
| `--poll` / `VEYRS_AGENT_POLL` | Seconds between claims when the queue is empty (default 15) |
| `--job-timeout` | Hard kill for a single scan (default 3600s) |
| `--once` | One poll then exit — for cron, or a smoke test |
| `--dry-run` | Claim a job and print the argv without executing it |
| `--insecure` | Skip TLS verification. Lab only. |

After the first heartbeat the agent appears in the console with its declared
tools, **all disabled**. An operator enables the ones it may run:

```bash
curl -sX PATCH .../api/v1/agents/$AGENT_ID/tools/nuclei \
  -H "Authorization: Bearer $VEYRS_TOKEN" -H 'Content-Type: application/json' \
  -d '{"enabled": true}'
```

## systemd

```ini
[Unit]
Description=VEYRS execution agent
After=network-online.target

[Service]
Type=simple
User=veyrs-agent
EnvironmentFile=/etc/veyrs-agent.env
ExecStart=/usr/bin/python3 /opt/veyrs-agent/veyrs_agent.py
Restart=always
RestartSec=10
# The agent runs scanners; it should not be able to do anything else.
NoNewPrivileges=true
PrivateTmp=true
ProtectSystem=strict
ProtectHome=true
ReadWritePaths=/tmp

[Install]
WantedBy=multi-user.target
```

`/etc/veyrs-agent.env` should be `0600` and owned by root — it holds the token.

## Supported tools

| Tool | Binary | Parser | Profiles |
|---|---|---|---|
| nuclei | `nuclei` | `nuclei` | quick, full |
| nmap | `nmap` | `nmap` | quick, full, default |
| trivy | `trivy` | `trivy` | quick, full |
| zap | `zap-baseline.py` | `zap` | quick, full |
| semgrep | `semgrep` | `semgrep` | default |

Only tools found on `PATH` are declared.

## Resolvers — read this before trusting a green scan

**nuclei does not use the system resolver.** projectdiscovery's dialer carries
public resolvers compiled in, so on a split-horizon estate the scanner resolves
an *internal* host to its *public* address, fails to route to it, and exits 0
having scanned almost nothing. Measured on one real host, same target, same
templates:

| | completed | requests | errors | exit code | output |
|---|---|---|---|---|---|
| scanner's own resolvers | **5%** | 520 | 703 | 0 | 0 bytes |
| `-r` internal resolver | **97%** | 8618 | 108 | 0 | 0 bytes |

Note the last two columns: both runs "succeeded" and both wrote nothing. That
is why the agent also reports coverage — see below.

```
# /etc/veyrs-agent/resolvers.txt
# One address per line. Comments and blank lines are fine HERE: the agent
# strips them and hands nuclei a sanitised copy, because nuclei would treat a
# comment as a resolver and quietly drop coverage to 0%.
10.50.0.2
```

With no such file the agent starts anyway and logs a warning — a segment with a
single DNS view does not need one.

## Coverage reporting

Every result carries `X-Agent-Scan-Stats`: the scanner's own counters (nuclei
`-stats-json`) plus a reachability probe of the target, taken deliberately with
the **system** resolver. When the probe connects and the scanner reports 5%,
that disagreement is the diagnosis.

These are facts, not a verdict. The server applies the threshold
(`MIN_COVERAGE_PERCENT`, `MAX_ERROR_RATE` in `services/agents.py`) so it is the
same for every agent and an operator can tune it in one place. A run below it
is recorded **failed** with the percentage in the error, and — the part that
matters — it may not close a finding. Only a scan that vouches for its own
coverage is allowed to say something was remediated.

## Adding a tool

Write a builder and register it:

```python
def build_mytool(target, profile, params, out):
    return ["mytool", "--json", "--out", out,
            "--rate", str(_int(params, "rate", 10, 1, 100)), target]

TOOLS["mytool"] = Tool("mytool", "mytool", "sarif", ["default"], build_mytool)
```

`parser` must be a key VEYRS knows (`GET /api/v1/engagements/dedupe-registry`
lists them). If you find yourself wanting to accept a raw argument string from
the server, stop — that defeats the design rather than extending it.

## A clean scan is a result

A scan that finds nothing submits an empty payload, and VEYRS treats that as a
completed scan of the job's scope. That is what closes findings which were
actually fixed. Do not "helpfully" suppress the submission when there is no
output file — it is the only remediation signal the platform gets.
