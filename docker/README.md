# VEYRS — container stack

A single-node VEYRS on Docker Compose: the API, its PostgreSQL cluster, Redis,
and the operator console behind nginx. Intended for **evaluation and
development** — clone the repository, run two commands, sign in.

```bash
docker/veyrs-docker.sh init     # writes docker/.env with real secrets, 0600
docker/veyrs-docker.sh up       # builds, starts, waits for /readyz
```

On a host that does not have the repository, or does not have Docker yet, the
guided installer does both — it installs Docker if it is missing, places the
release under `/opt/veyrs-docker` and starts the stack (answer `docker` when it
asks for the mode):

```bash
curl -fLO https://github.com/visionebc/veyrs/releases/latest/download/veyrs-setup.sh
curl -fLO https://github.com/visionebc/veyrs/releases/latest/download/veyrs-setup.sh.sha256
sha256sum -c veyrs-setup.sh.sha256        # must print "veyrs-setup.sh: OK"
sudo bash veyrs-setup.sh --check          # inspect this host, change nothing
sudo bash veyrs-setup.sh                  # asks: native or Docker, bundled or external PostgreSQL
```

`init` prints the generated administrator password once. The console is on
`http://127.0.0.1:8080` by default.

**Full operator manual** — every variable, TLS, external PostgreSQL, upgrades,
backup/restore and troubleshooting:
[docs/DOCKER_COMPOSE_MANUAL.md](../docs/DOCKER_COMPOSE_MANUAL.md).

```bash
docker/veyrs-docker.sh status   # health, plus what is NOT running here
docker/veyrs-docker.sh logs -f api
docker/veyrs-docker.sh psql     # a shell on the database, as the app role
docker/veyrs-docker.sh backup   # a COMPLETE dump, verified (see below)
docker/veyrs-docker.sh down     # stop; `down --volumes` DESTROYS the data
```

Requires Docker Engine with the Compose **plugin** (`docker compose`, not
`docker-compose`). Verified on Docker 29.8.1 / Compose v5.5.1.

---

## The optional profiles

Everything a host install runs is here. Two pieces are **off by default**, and
the split is by blast radius rather than by importance.

```bash
./veyrs-docker.sh up                                # api + console + db
./veyrs-docker.sh up --with-workers                 # + intel + digest
./veyrs-docker.sh up --with-workers --with-agent    # + the scanner
./veyrs-docker.sh up --all                          # both profiles
./veyrs-docker.sh status                            # what is and is not running
```

| Profile | Service | Host unit | Off by default because | Cost of leaving it off |
|---|---|---|---|---|
| `workers` | `intel` | `veyrs-intel-sync.timer` | a first `up` would begin pulling the NVD corpus — hours of it, against a feed that rate-limits per source address — on a stack somebody is merely trying out | **the vulnerability data stops ageing forward and SLA deadlines stop elapsing.** NVD, EPSS and CISA KEV are never refreshed and VEYRS keeps scoring, confidently, against whatever it last knew. Nothing in the console shows this |
| `workers` | `digest` | `veyrs-digest.timer` | same tick, same reasoning | the notification rows are still written; nobody is mailed |
| `agent` | `agent` | `veyrs-agent.service` | it is the one component that sends **unsolicited traffic to other people's machines** | no scans originate here; jobs queue and their leases are reaped |

**Turn `workers` on for anything you intend to keep.** `veyrs-docker.sh status`
prints the table above filled in from what is actually running, so the answer
comes from the machine rather than from anyone's memory of which flags they
passed three weeks ago.

### The two workers run the repository's own scripts

`intel` runs `scripts/sync-intel.sh` — the same file `veyrs-intel-sync.service`
executes on a host — and `digest` runs `scripts/send-digest.sh`. Neither is
re-spelled as a compose `command`, because the feed order (CWE names what NVD
creates; EPSS skips CVEs it has never seen; KEV is the last word), the
per-feed isolation that stops a failed EPSS from cancelling KEV, and the SLA
sweep that must run even on a tick where nothing was due all live in that
script. A second copy would be a ladder written twice, and the copy that drifts
is always the one nobody runs by hand. Both scripts resolve their own root and
interpreter so they work here with no venv and no `.env`.

`docker/tick.sh` replaces the timer and **carries no schedule**: it asks
hourly, with jitter, and `veyrs intel-due` / `services.digest.due_now` answer
whether this hour is the one — from `organizations.settings`, which the console
edits. An hour written into the loop would make a setting the console displays
and the machine ignores. The tick at container start is the equivalent of
`Persistent=true`, and it is safe for exactly the same reason: the loop decides
nothing.

### Before you enable the agent

It needs two values and neither has a safe default:

```ini
VEYRS_AGENT_TOKEN=...          # console -> Settings -> Agents
VEYRS_AGENT_ALLOW=example.com,*.internal.example,10.10.0.0/24
```

**An empty allowlist means nothing is scannable, not everything.** That is
deliberate: it is defence in depth against a compromised or spoofed server
handing out targets, so the operator of *this* machine decides what it may be
pointed at. The agent refuses to start without it, and `up --with-agent` fails
early with this message rather than letting `restart: unless-stopped` turn it
into a crash loop with the reason buried in `logs`.

`NET_RAW` is **not** granted. It is what `nmap` needs for SYN scanning and also
what lets a process forge packets on the stack network; connect-scan works
without it. Granting it is a deliberate edit to `compose.yaml`, and at that
point the container is not meaningfully confined.

The ~84 MB nuclei corpus lives in the `veyrs-agent-home` **volume**, not in the
image: templates change daily, and a container up for a month would otherwise
scan with a month-old corpus and say nothing about it.
`agent-entrypoint.sh` seeds it on first start and **refuses to start if it is
empty** — a nuclei with no templates does not error, it runs every job it is
handed, finds nothing, and reports a clean scan for assets that were never
tested. That is worse than being down, because a down agent is visible. It is
the same failure `veyrs-agent.service` avoids by deliberately not setting
`ProtectHome`, arriving through a different door.

### Teardown covers every profile

`down`, `restart`, `ps`, `logs`, `build` and `status` in `veyrs-docker.sh`
always run against all profiles. Plain `docker compose down` **without** the profiles that started a
container does not stop it, prints no warning and exits 0 — so an operator who
ran `up --with-agent` and then `down` would be left with a scanner still
running on a stack they believe is off.

---

## What this stack is still not

Production separates the application and the database onto different hosts so
the standby pair means something. Collapsing them into one compose project is
the right trade for evaluation and the wrong one for an installation you intend
to keep — use `install.sh` for that.

---

## Three things that are quiet when they go wrong

### The application role is not a PostgreSQL superuser

The obvious compose file sets `POSTGRES_USER=veyrs` and lets the image create
the role. **That role is a superuser, and a PostgreSQL superuser bypasses row
level security unconditionally.**

70 of VEYRS' 87 tables carry `FORCE ROW LEVEL SECURITY`; it is the mechanism
that keeps one tenant's assets, findings and risk entries away from another.
Under a superuser every one of those policies silently stops applying —
nothing errors, nothing logs, `\d` still lists them. A cross-tenant leak would
be invisible in the container stack and fatal on a host install, and the
container stack is what people evaluate the product on.

So the superuser here is `postgres`, and `initdb.d/10-app-role.sh` creates the
application role `NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`, owning its
own databases and nothing else — the same shape as production. Two tests in
`tests/test_container_stack.py` refuse the regression, and
`scripts/test-docker-stack.sh` proves the isolation on a running stack by
reading a second tenant's rows and getting none.

### `pg_dump` as the application role produces a truncated backup

Forcing row level security applies to the **table owner too**, so the
application role — which owns all 87 tables — is refused:

```
pg_dump: error: query failed: ERROR:  query would be affected by row-level
security policy for table "agent_job_events"
```

`-Fc` writes as it goes, so what is left behind is a file that looks like a
backup. On production, measured: **392 KB where the good dump is 509 MB.**
Nothing about the filename or the exit path says which one you have.

`veyrs-docker.sh backup` runs as the superuser and then verifies by listing
the archive (`pg_restore --list`), refusing anything with implausibly few
tables. Size alone does not distinguish a truncated dump from a small
database.

---

### The console outliving the address it proxies to

nginx resolves the names in `proxy_pass` **once**, when it loads its
configuration, and caches the result for the life of the process. Anything that
recreates `api` without also recreating `console` therefore leaves nginx
proxying to an address nobody is listening on:

```
502 ... connect() failed (111: Connection refused) while connecting to
upstream, upstream: "http://172.29.0.4:8000/readyz"
```

Measured 2026-09-22: `up --with-workers` on a running stack did exactly that —
compose recreated `api` because the project changed, left `console` alone, and
the console served 502 for every request. `docker compose ps` reported **both
containers healthy** the whole time, because console's probe fetches its own
static index and api's probe runs inside api. Green on both sides, dead in
between.

`console.conf` therefore **re-resolves** the upstream: `resolver 127.0.0.11
valid=10s` (Docker's embedded DNS) plus a variable in `proxy_pass`
(`set $veyrs_api api;` … `proxy_pass http://$veyrs_api:8000;`). A variable
defers resolution to request time, so a recreated `api` is found again within
ten seconds. None of these `proxy_pass` directives carries a URI part, so the
request URI is forwarded exactly as before.

Pinning `api` to a static address was tried first and **reverted**: `docker
compose run` creates a *second* container of the service and cannot reuse a
fixed address (`Address already in use`), which breaks `veyrs-docker.sh cli`
and the tenant-isolation assertions in `scripts/test-docker-stack.sh`. Do not
go back to a literal `proxy_pass http://api:8000`, and do not pin `api`.

Only `console` is pinned (`VEYRS_CONSOLE_IP`, default `172.29.0.10`), for an
unrelated reason: uvicorn is told to trust `X-Forwarded-For` from exactly that
address. `VEYRS_SUBNET` has to contain it.

---

## Files

| file | |
|---|---|
| `compose.yaml` | the stack: `postgres`, `redis`, `init`, `api`, `console`, and the profiled `intel`, `digest`, `agent` |
| `Dockerfile` | three targets — `api` (python:3.11-slim, uid 10001), `console` (nginx) and `agent` (`api` + nuclei, pinned and checksummed) |
| `initdb.d/10-app-role.sh` | creates the unprivileged role and its databases, once |
| `init.sh` | schema + first administrator, idempotent, runs on every `up` |
| `entrypoint.sh` | uvicorn, mirroring `veyrs-api.service` |
| `tick.sh` | the hourly loop that replaces a systemd timer — interval only, never a schedule |
| `agent-entrypoint.sh` | seeds the nuclei corpus and refuses to start without it |
| `console.conf` | the console vhost and the same-origin `/api` proxy |
| `veyrs-docker.sh` | the driver — use this rather than raw `docker compose` |
| `env.example` | the template `init` fills in; every value is explained |

The build context is the **repository root**, not this directory. `Dockerfile`
copies named directories and never `COPY . .`: the working tree of a running
node carries `.env`, `.bootstrap-credentials` and `var/backups/` — a live
signing key, a live Fernet key and a production dump — and an image layer is
additive, so a secret copied in once cannot be removed by a later `RUN rm`.
`.dockerignore` at the repository root is the second line of defence.

---

## Re-running is safe

`up` is idempotent. `init.sh` checks, **as the superuser**, whether the
administrator already exists before calling `cli bootstrap` — which would
otherwise rewrite the password hash on every restart, silently reverting any
password the operator had changed, including after an unattended reboot. Use
`VEYRS_FORCE_BOOTSTRAP=1` to reset it on purpose.

`docker/.env` is never rewritten by `up`. Regenerating `VEYRS_ENCRYPTION_KEY`
against an existing database makes every stored credential permanently
unreadable, so `init` refuses to overwrite an existing file.

---

## Testing

```bash
./scripts/test.sh tests/test_container_stack.py   # guards; no Docker needed
scripts/test-docker-stack.sh                      # assertions on a running stack
```

The second one measures rather than smoke-tests: the app role's privileges,
the FORCE-RLS table count, a cross-tenant read returning nothing while the
superuser sees the rows, a cross-tenant `INSERT` refused by `WITH CHECK`, a
real login whose token is replayed eight times (an empty `VEYRS_SECRET_KEY`
makes each worker sign with its own random key, so a single login can succeed
by luck), and that no `.env` or `.bootstrap-credentials` exists anywhere in
the image.
