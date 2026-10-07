# Deployment

VEYRS 0.9.0 as deployed, and how to reproduce it.

## Current production instance

Three containers on hv-4 since 2026-08-17. The application nodes hold **no
state**; see [High availability](HIGH_AVAILABILITY.md) and
[ADR 0007](ADRs/0007-stateless-app-nodes.md).

| | |
|---|---|
| Entry point | fleet proxy CT 100 `10.50.0.10` — terminates TLS (`*.example.com`), `upstream veyrs_app` |
| Public URLs | https://veyrs-app-1.example.com (console, `-a2` and `-a` are aliases) · https://veyrs-docs.example.com (docs) |
| App node 1 | LXC 101 `veyrs-app-1` on hv-4, `10.50.0.21`, `disk-a` 60 GB, 4 vCPU / 8 GB |
| App node 2 | LXC 103 `veyrs-app-2` on hv-4, `10.50.0.22`, `disk-b` 60 GB, 4 vCPU / 8 GB |
| Database node | LXC 102 `veyrs-db-1` on hv-4, `10.50.0.31`, `disk-b` 100 GB, 6 vCPU / 12 GB |
| App | `/opt/veyrs`, venv at `/opt/veyrs/venv` (both app nodes) |
| Service | `veyrs-api.service` -> uvicorn x4 on `127.0.0.1:8000` (both app nodes) |
| Singletons | `veyrs-agent` + `veyrs-intel-sync.timer` run on **a1 only** — disabled on a2 |
| Database | PostgreSQL 15 on `10.50.0.31:5432`, database `veyrs`, **UTF8**, RLS FORCEd |
| Cache | Redis on `10.50.0.31:6379`, `requirepass` set |
| Test database | `veyrs_test` stays on each node's **local** PostgreSQL (`VEYRS_TEST_DATABASE_URL`) |

## Requirements

- 4 vCPU, 8 GB RAM, 40 GB disk minimum
- PostgreSQL 15+ with a **UTF8** database
- Redis 7+, Python 3.11+, nginx

`install.sh` covers three distribution families and was measured on five
images — it does not deduce anything from the distribution's name:

| Image | Interpreter | PostgreSQL | Redis unit | nginx vhost dir | loopback `pg_hba` |
|---|---|---|---|---|---|
| Debian 12 | `python3.11` | 15 | `redis-server` | `sites-available/` | `scram` — left alone |
| Ubuntu 24.04 | `python3.12` | 16 | `redis-server` | `sites-available/` | `scram` — left alone |
| openSUSE Leap 15.6 | `python3.11` (**no `python3`**) | 16 | `redis@default` | `vhosts.d/` | `ident` → rule added |
| Rocky 9 | `python3.11` | 16 | `redis` | `conf.d/` | `ident` → rule added |
| AlmaLinux 9 | `python3.11` | 16 | `redis` | `conf.d/` | `ident` → rule added |

Leap 15.6 is the same code base as **SLES 15 SP6** and is used as its proxy;
SLES itself needs a subscription and is therefore **not tested**. Ubuntu 22.04
and RHEL 9 proper are the same families and were not run either.

> **The database must be UTF8.** A cluster initialised without a UTF-8 locale
> produces `SQL_ASCII`, and psycopg then returns `bytes` instead of `str`. For a
> product storing CVE descriptions and vendor advisories in five languages that
> is a defect, not an inconvenience. Create with
> `CREATE DATABASE veyrs ENCODING 'UTF8' TEMPLATE template0;`

## Install

```bash
# 1. system packages
apt install -y python3-venv python3-dev build-essential libpq-dev \
               postgresql-15 redis-server nginx git

# 2. database
sudo -u postgres psql -c "CREATE ROLE veyrs LOGIN PASSWORD '<strong>';"
sudo -u postgres psql -c "CREATE DATABASE veyrs OWNER veyrs ENCODING 'UTF8' TEMPLATE template0;"
sudo -u postgres psql -c "CREATE DATABASE veyrs_test OWNER veyrs ENCODING 'UTF8' TEMPLATE template0;"

# 3. application
git clone https://github.com/visionebc/veyrs.git /opt/veyrs
cd /opt/veyrs
python3 -m venv venv && venv/bin/pip install -r requirements.txt
mkdir -p var/backups var/documents

# 4. configuration
cp .env.example .env && chmod 600 .env
PYTHONPATH=backend venv/bin/python -m veyrs.cli keygen     # -> VEYRS_ENCRYPTION_KEY
python3 -c "import secrets; print(secrets.token_urlsafe(48))"  # -> VEYRS_SECRET_KEY
$EDITOR .env

# 5. schema, RLS policies, roles, compliance catalogues
PYTHONPATH=backend venv/bin/python -m veyrs.cli init-db

# 6. first organization + administrator
PYTHONPATH=backend venv/bin/python -m veyrs.cli bootstrap \
  --org acme --name "Acme Corp" --email admin@acme.com --superuser

# 7. service
cp infrastructure/systemd/veyrs-api.service /etc/systemd/system/
systemctl daemon-reload && systemctl enable --now veyrs-api

# 8. proxy
cp infrastructure/nginx-veyrs-console.conf /etc/nginx/sites-available/veyrs
ln -sf /etc/nginx/sites-available/veyrs /etc/nginx/sites-enabled/
nginx -t && systemctl reload nginx
```

## Container stack (Docker Compose)

`docker/` is a complete single-node stack, for **evaluation and development**.
It is not a smaller production instance: production separates the application
from the database onto different nodes (`veyrs-app-1` / `veyrs-db-1` above)
precisely so the standby pair means something, and one compose project
re-couples them.

```bash
git clone https://github.com/visionebc/veyrs && cd veyrs
docker/veyrs-docker.sh init     # writes docker/.env (0600) with real secrets
docker/veyrs-docker.sh up       # builds, starts, waits for /readyz
# -> console on http://127.0.0.1:8080, admin credentials printed by `init`
```

Requires Docker with the **compose plugin** (`docker compose`, not
`docker-compose` v1). Around 41 s from a cold start on a 2-vCPU container.

### What it runs

| Service | Port | Notes |
|---|---|---|
| `console` | `127.0.0.1:8080` | nginx. The **only** published port, loopback by default |
| `api` | — | uvicorn ×4. No published port, which is what makes `X-Forwarded-For` trustworthy |
| `postgres` | — | 15, RLS forced. The application role is **not** a superuser |
| `redis` | — | rate-limit windows, no volume |
| `init` | — | one-shot `init-db` + `bootstrap`, idempotent, the only holder of the superuser credentials |

### The optional profiles

Off by default, and the split is by blast radius:

```bash
docker/veyrs-docker.sh up --with-workers            # intel + digest
docker/veyrs-docker.sh up --with-workers --with-agent
docker/veyrs-docker.sh up --all                     # both
```

| Profile | Service | Host equivalent | If absent |
|---|---|---|---|
| `workers` | `intel` | `veyrs-intel-sync.timer` | **CVE/EPSS/KEV data does not refresh and SLA deadlines stop elapsing.** The platform keeps scoring, at full confidence, against intelligence frozen on install day. Nothing in the console shows this |
| `workers` | `digest` | `veyrs-digest.timer` | notification rows are still written; nobody is mailed |
| `agent` | `agent` | `veyrs-agent.service` | no scans originate here; jobs queue and their leases are reaped |

`workers` is off by default because a first `up` would otherwise begin pulling
the NVD corpus — hours of it, against a feed that rate-limits per source
address — on a stack somebody is merely trying out. **Turn it on for anything
you intend to keep.**

`agent` is off by default for a different reason: it is the one component that
sends unsolicited traffic to other people's machines. It needs
`VEYRS_AGENT_TOKEN` (mint one in the console, Settings → Agents) and
`VEYRS_AGENT_ALLOW`. An **empty allowlist means nothing is scannable, not
everything** — deny-by-default, so the operator of the machine decides what it
may be pointed at rather than trusting whatever the server hands it. `NET_RAW`
is not granted; connect-scan works without it and SYN scanning needs a
deliberate edit to `compose.yaml`.

### Operating it

```bash
docker/veyrs-docker.sh status   # health + which background work is NOT running
docker/veyrs-docker.sh logs -f api
docker/veyrs-docker.sh psql     # as the application role, RLS included
docker/veyrs-docker.sh cli check
docker/veyrs-docker.sh backup   # COMPLETE dump, as the superuser, verified
docker/veyrs-docker.sh down     # keeps the data; `down --volumes` destroys it
```

> **`pg_dump` as the application role produces a truncated backup that looks
> fine.** 70 of the 87 tables carry `FORCE ROW LEVEL SECURITY`, and forcing it
> applies to the table **owner** too, so the `COPY` is refused mid-dump — and
> `-Fc` has already written a plausible file. Measured on production
> 2026-09-21: **392 KB where the good dump is 509 MB**. `veyrs-docker.sh
> backup` runs as the superuser and verifies by listing the archive, because
> the file size alone cannot tell a truncated dump from a small database. The
> same trap applies to a host install — see `INSTALL.md`.

`down`, `ps`, `logs` and `restart` always run against **every** profile.
`docker compose down` without the profiles that started a container does not
stop it, prints no warning and exits 0 — an operator who ran `up --with-agent`
and then `down` would be left with a scanner still running on a stack they
believe is off.

### The decision that makes it VEYRS and not an imitation

`POSTGRES_USER=veyrs` — the obvious thing — makes the application role a
PostgreSQL **superuser**, and a superuser bypasses row level security
unconditionally. Under one, all 70 `FORCE ROW LEVEL SECURITY` tables silently
stop enforcing: nothing errors, nothing logs, `\d` still lists the policies,
and tenant isolation is gone in the one deployment shape people use to evaluate
the product. The superuser is `postgres`; `docker/initdb.d/10-app-role.sh`
creates the application role `NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`,
owner of its own databases — the same shape as production.

`scripts/test-docker-stack.sh` proves the consequence against a live stack (27
assertions, including a cross-tenant read returning zero rows while the
superuser sees them); `tests/test_container_stack.py` carries the static guards
and needs no Docker daemon.


## Configuration

Everything is `VEYRS_`-prefixed. The ones that matter:

| Variable | Default | Notes |
|---|---|---|
| `VEYRS_ENVIRONMENT` | development | `production` activates the safety guards |
| `VEYRS_SECRET_KEY` | - | >=32 chars. No usable default in production |
| `VEYRS_ENCRYPTION_KEY` | - | `veyrs keygen`. **Required** in production |
| `VEYRS_DATABASE_URL` | - | Must not carry the bootstrap password in production |
| `VEYRS_REDIS_URL` | localhost | Rate-limit windows and cache. **Not a queue** — see [Architecture §3](/ARCHITECTURE.html) |
| `VEYRS_PUBLIC_BASE_URL` | - | Must be `https://` in production |
| `VEYRS_CORS_ORIGINS` | - | Explicit list; never `*` |
| `VEYRS_RATE_LIMIT_PER_MINUTE` | 240 | Per credential |
| `VEYRS_AUTH_RATE_LIMIT_PER_MINUTE` | 10 | Per source IP. Raise behind NAT |
| `VEYRS_TRUST_PROXY_HEADERS` | false | Enable **only** behind a proxy you control |
| `VEYRS_AI_ALLOW_EXTERNAL` | false | Deployment-wide default |
| `VEYRS_NVD_API_KEY` | - | Optional; raises the NVD rate limit |

`assert_production_safe()` refuses to boot production with debug on, the
bootstrap database password, plain HTTP, or a derived encryption key.

## Upgrading

```bash
cd /opt/veyrs
git pull
venv/bin/pip install -r requirements.txt
PYTHONPATH=backend venv/bin/python -m veyrs.cli init-db   # ALWAYS, it is idempotent
install -m 644 frontend/console/app.js frontend/console/console.css \
        frontend/console/index.html /var/www/veyrs-console/        # ALWAYS, see below
systemctl restart veyrs-api
timeout 30 bash -c 'until curl -sfo /dev/null http://127.0.0.1:8000/readyz; do sleep 1; done'
```

> **Never skip the console copy.** `git pull` updates the checkout; nginx serves
> `/var/www/veyrs-console`, which is a *copy*. Omit it and the node runs the new
> API behind the old front end, and every surface still answers `200` -- there is
> no health check that can see it. This is exactly how environment P was left
> serving the 0.22.0 console (`app.js?v=16`) against a 0.25.0 API for a day after
> its upgrade. Verify with the artefact, not the status code:
>
> ```bash
> md5sum /opt/veyrs/frontend/console/app.js /var/www/veyrs-console/app.js  # must match
> grep -o 'app.js?v=[0-9]*' /var/www/veyrs-console/index.html
> ```

> **Never skip `init-db`.** A release that adds tables, deployed without it,
> produces `UndefinedTable` 500s on exactly the new endpoints -- and only on
> those, so the service looks healthy. This happened on the first VEYRS
> deployment: `/compliance/frameworks` and `/ai/capabilities` returned 500 while
> `/healthz` was green.

## Verifying a deployment

```bash
curl -sf http://127.0.0.1:8000/healthz     # liveness
curl -sf http://127.0.0.1:8000/readyz      # DB + Redis
curl -so /dev/null -w '%{http_code}\n' https://<host>/api/v1/assets   # -> 401
```

Then log in and walk the list endpoints -- `tests/test_phase10_hardening.py`
contains the same walk if you prefer to run it against a staging database.

## Sizing

| Findings | vCPU | RAM | Notes |
|---|---|---|---|
| < 50k | 2 | 4 GB | single node |
| 50k-500k | 4 | 8 GB | current shape |
| 500k-5M | 8 | 16 GB | separate the database host |
| > 5M | - | - | separate workers; partition `findings` by `organization_id` |

uvicorn workers are processes because VEYRS handlers are synchronous SQLAlchemy;
throughput comes from processes, not a bigger event loop. Raise workers and the
Postgres pool together, never alone.

## Kubernetes readiness

The API is stateless: all state is in Postgres/Redis/object storage,
configuration is environment-driven, and liveness/readiness are separate probes.
Still missing for a clean Kubernetes deployment: object storage for uploaded
documents (currently a local path) and a Helm chart.

## Monitoring

`/metrics` exposes Prometheus text: `veyrs_build_info`, `veyrs_requests_total`
(by method/status/path) and `veyrs_request_duration_ms` quantiles. Route names
and traffic volume are themselves information — an exposition is a map of the
attack surface — so the endpoint is authenticated:

    Authorization: Bearer $VEYRS_METRICS_TOKEN

Set `VEYRS_METRICS_TOKEN` in `.env` (0600) and on the scrape job. A caller with
no token or a wrong one gets **404, not 401**: a probe should not learn that the
endpoint exists. Unset, the endpoint stays open in development and is refused in
production.

Do **not** rely on an `allow 10.0.0.0/24` in nginx for this. Every request
reaches this host from the fleet reverse proxy, whose address is inside that
range, so the allowlist matches the proxy and not the caller — any
`$remote_addr` rule on this box has the same flaw.

The registry is per worker process and the unit runs `--workers 4`, so one
scrape samples one worker; `veyrs_build_info` carries the pid to make that
visible. Series are capped per metric with an overflow bucket, and an unrouted
path contributes the constant `<unmatched>` rather than an attacker-supplied
label.

Logs are structured JSON on stdout with a correlation id on every line;
`journalctl -u veyrs-api` or ship to Loki.

Alert on: `readyz` failing, 5xx rate, SLA breach count rising, feed runs failing,
and `ai_audit_log` blocked-call spikes.

## Execution agents

An agent runs scanners and submits their output; it is **not** a Principal and
reaches nothing but `/api/v1/agents/self/*`. Run it as a service — a scanner
that quietly stops scanning looks exactly like an estate with no findings.

    # 1. credential + policy (0600: the token reaches the agent data plane)
    install -d -m 755 /etc/veyrs-agent
    cat > /etc/veyrs-agent/agent.env <<'EOF'
    VEYRS_URL=https://veyrs.example.com
    VEYRS_AGENT_TOKEN=veyrsagent_<prefix>_<secret>
    VEYRS_AGENT_ALLOW=*.example.com
    VEYRS_AGENT_RESOLVERS=/etc/veyrs-agent/resolvers.txt
    EOF
    chmod 600 /etc/veyrs-agent/agent.env

    # 2. resolvers. On a split-horizon estate this is not optional: nuclei
    #    ignores /etc/resolv.conf and would resolve internal hosts publicly.
    #    Comments are fine here - the agent passes nuclei a sanitised copy,
    #    because nuclei reads a comment line as a resolver.
    printf '# fleet resolver\n10.50.0.2\n' > /etc/veyrs-agent/resolvers.txt

    # 3. service
    install -m 644 integrations/veyrs-agent/veyrs-agent.service \
        /etc/systemd/system/veyrs-agent.service
    systemctl enable --now veyrs-agent
    journalctl -u veyrs-agent -n 20     # expect: resolvers, tools, heartbeat ok

`Restart=always`, and `KillSignal=SIGINT` because the runner exits 0 on
`KeyboardInterrupt`. A job in flight at shutdown is abandoned and its lease is
collected by `POST /api/v1/agents/maintenance/reap` — run that from cron.

The unit is hardened but deliberately **does not** set `ProtectHome`: nuclei
reads ~13.5k templates from `/root/nuclei-templates` and keeps state in
`/root/.config/nuclei`. Locking `/root` does not fail loudly — it produces a
zero-template run that exits 0, which is the precise failure the phase-19
coverage guard exists to catch. If you harden further, verify with a real scan
and read `job.meta.scan_stats`, not just the exit code.

Enrolment grants nothing on its own: `AgentTool.enabled` must be turned on by an
operator and `allowed_targets` must be non-empty, so an agent enrolled and
forgotten is inert.
