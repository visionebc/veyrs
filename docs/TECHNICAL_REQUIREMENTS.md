# Technical Requirements

This page lists what a VEYRS installation needs in order to run: operating system, runtime, database, cache, hardware, network, TLS and configuration. It also lists what the product guarantees once it runs: rate limits, lockout, audit, retention and availability. It describes release **0.35.1** (`pyproject.toml`, `backend/veyrs/config.py`). Every figure comes from the code or from an existing manual checked against the code, and the source file is named where it helps. For the step-by-step install, read `INSTALL.md` in the repository root. For day-to-day operation, read the [System manual](/SYSTEM_MANUAL.html).

## Purpose and scope

VEYRS (Unified Cybersecurity Risk Management) is a FastAPI application on SQLAlchemy 2 and PostgreSQL. It links assets, vulnerabilities, threat intelligence, risk, tickets, SLA, remediation, compliance and audit in one multi-tenant database. Redis holds rate-limit counters, two-factor codes and short-lived state. A static console written in plain JavaScript talks to the API on the same origin.

**VEYRS is:**

- a multi-tenant platform. Tenant isolation is enforced twice: once in the application and once by PostgreSQL row-level security (RLS), which is FORCEd on the tenant tables (`backend/veyrs/db.py`);
- usable without Internet access at run time. Outbound calls refresh public intelligence feeds, check for updates and reach integrations you configure. When a feed cannot be reached, VEYRS keeps scoring on the data it already has ([Network requirements](#network-requirements));
- run by systemd units on a host, or by a Docker Compose stack.

**VEYRS is not:**

- a TLS terminator. Neither shipped shape listens on HTTPS. TLS comes from your nginx configuration or from a proxy in front ([TLS and reverse proxy](#tls-and-reverse-proxy));
- a scanner by default. The scan agent (`veyrs-agent`) is a separate, opt-in process;
- self-failing-over. Database promotion is manual ([High availability](#high-availability)).

## Deployment shapes

| Shape | How it is installed | Intended use | Processes |
|---|---|---|---|
| Single node, native | `veyrs-setup.sh` (native) or `install.sh` | An installation you operate | `veyrs-api.service` (uvicorn, 4 workers), nginx, PostgreSQL, Redis on one host |
| HA pair, native | `install.sh` on each application node, with `--skip-postgres` and `--skip-redis` pointing at a database node | Production | Two stateless application nodes, one database node (PostgreSQL and Redis), one streaming standby |
| Docker Compose | `veyrs-setup.sh` (Docker) or `docker/veyrs-docker.sh` | Evaluation, development, a small single node | `postgres`, `redis`, `init`, `api`, `console`; optional `intel` and `digest` (profile `workers`) and `agent` (profile `agent`) |

The Docker stack keeps the application and its database in one Compose project. For a production installation with a standby, put them on separate hosts (`docker/README.md`, [Docker Compose manual](/DOCKER_COMPOSE_MANUAL.html)).

## Platform requirements

### Operating system

Two installers detect the distribution in two different ways.

**`install.sh`** (the native installer) reads `ID` and `ID_LIKE` from `/etc/os-release` and maps them to a family. It does not check the version:

| `ID` or `ID_LIKE` contains | Family | Package manager | Redis unit |
|---|---|---|---|
| `debian`, `ubuntu` | `debian` | `apt-get` | `redis-server` |
| `suse`, `sles`, `opensuse` | `suse` | `zypper` | `redis@default` |
| `rhel`, `fedora`, `centos` | `rhel` | `dnf` (else `yum`) | `redis` |

Any other distribution is refused. To override detection, pass `--distro-family debian|suse|rhel`. If you install the packages yourself, pass `--skip-system-packages`. The installer must run as root.

**`veyrs-setup.sh`** (the guided installer) also reads `VERSION_ID`. It grades the host as follows:

| Grade | Distributions | Behaviour |
|---|---|---|
| Tested | Debian 12, Ubuntu 24.04, Rocky Linux 9, AlmaLinux 9, openSUSE Leap 15 | proceeds |
| Same family, not tested | Debian 13, Ubuntu 22.04, RHEL 9, CentOS 9, SLES 15, SLED 15 | proceeds with a warning |
| Anything else | for example Debian 14, an EL 10 release, Fedora | refused unless `--force` |

Both installers require **systemd as the init system**. `veyrs-setup.sh` checks for `/run/systemd/system`. The pristine images on which `install.sh` was measured end to end are Debian 12, Ubuntu 24.04, openSUSE Leap 15.6, Rocky Linux 9 and AlmaLinux 9 (`install.sh` header). SLES 15 SP6 shares its code base with Leap 15.6 and was not run, because its repositories need a subscription.

### CPU architecture

Only **x86-64 (amd64)** is supported:

- The release wheelhouse `veyrs-<version>-wheels-x86_64.tar.gz` holds wheels for CPython 3.11, 3.12 and 3.13 on x86-64 Linux only (`install.sh`, step 4).
- Container images are published for `linux/amd64` only.
- The installer installs no compiler. On ARM, on musl (Alpine), or on a Python newer than the pinned wheels, pip tries to compile and the installer stops. It then prints the build packages you need for your family.

### Runtime stack

| Component | Native install | Docker stack | Source |
|---|---|---|---|
| Python | 3.11 or newer, in a virtualenv. The interpreter must pass a stdlib probe (`xml.parsers.expat`, `ssl`, `ctypes`, `sqlite3`, `venv`, `ensurepip`, `zlib`, `hashlib`, `lzma`) | 3.11 (`python:3.11-slim-trixie`, pinned by digest) | `pyproject.toml` `requires-python`, `install.sh` |
| Interpreter candidates | Debian family: `python3.13`, `python3.12`, `python3.11`, `python3`. SUSE: `python3.13`, `python3.12`, `python3.11` (package `python311`, plus `libexpat1`). RHEL family: `python3.12`, `python3.11`, `python3` (package `python3.11`) | n/a | `install.sh` |
| Python packages | pinned in `requirements.txt` (FastAPI 0.115.6, uvicorn 0.34.0, SQLAlchemy 2.0.36, psycopg 3.2.3, redis 5.2.1, cryptography 50.0.0) | the same file, in the image | `pyproject.toml` |
| Application server | uvicorn, 4 workers, `127.0.0.1:8000` | uvicorn, `VEYRS_WORKERS` (default 4), port 8000 on the stack network only | `infrastructure/systemd/veyrs-api.service`, `docker/entrypoint.sh` |
| PostgreSQL | 15 or newer ([PostgreSQL](#postgresql)) | `postgres:15-bookworm`, or an external server of version 15 or newer | `install.sh`, `docker/compose.yaml` |
| Redis | the distribution's package. The manuals state 7 or newer; no installer checks the version | `redis:7-alpine`, with persistence off | `INSTALL.md`, `docker/compose.yaml` |
| Web server | the distribution's nginx | `nginx:1.28-alpine`, port 8080 inside the container | `install.sh`, `docker/Dockerfile` |
| Release verification | `ssh-keygen` from OpenSSH 8.1 or later, for `SHA256SUMS.sig` | same | `veyrs-setup.sh`, `docs/DEPLOYMENT.md` |
| Docker | n/a | Docker Engine, plus the Compose v2 plugin at version **2.20 or newer**. `veyrs-setup.sh` refuses older Compose, and `docker-compose` v1 is not supported | `veyrs-setup.sh` |

The installer also needs `curl`, `git` and `ca-certificates`. On SELinux hosts in Enforcing mode, it sets `httpd_can_network_connect`; without that boolean, nginx answers 502 on `/api/`. The firewall is changed only if you pass `--open-firewall`.

No search cluster and no vector store are required. No setting in `config.py` configures one.

### PostgreSQL

| Requirement | Detail | Enforced by |
|---|---|---|
| Version 15 or newer | Older servers are refused. RHEL 9 base repositories carry 13, so the installer enables the `postgresql:16` module stream (`PG_MAJOR`, default 16). SUSE installs `postgresql16-server`. Debian and Ubuntu install the distribution's single major (15 on Debian 12, 16 on Ubuntu 24.04) | `install.sh` (`MIN_PG_MAJOR=15`), `veyrs-setup.sh` (`server_version_num >= 150000`) |
| Database encoding **UTF8** | Create the database with `ENCODING 'UTF8' TEMPLATE template0`. The installer re-reads the encoding and refuses anything else. A `SQL_ASCII` database accepts every write and corrupts advisories stored in five languages | `install.sh` step 2, `veyrs-setup.sh` |
| Application role owns the database | `init-db` runs `ALTER TABLE ... FORCE ROW LEVEL SECURITY` and `CREATE POLICY`, which only the owner may do | `veyrs-setup.sh`, [Docker Compose manual §7.1](/DOCKER_COMPOSE_MANUAL.html) |
| Application role is **not** a superuser and does **not** have `BYPASSRLS` | Either attribute silently turns off every RLS policy. Create the role with `NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS` | `veyrs-setup.sh` (external database), `docker/initdb.d/10-app-role.sh` |
| Password authentication | `pg_hba.conf` must admit the role with a password method (`scram-sha-256`), one `/32` line per application node | `install.sh` (`pg_ensure_password_auth`), `INSTALL.md` |
| Connection headroom | Each API worker process opens a pool of `pool_size=10` plus `max_overflow=20`, so one node with 4 workers can open up to 120 connections, plus CLI runs and timers. The PostgreSQL default `max_connections` is 100. Raise `max_connections` (count every application node), or lower the worker count | `backend/veyrs/db.py`, [Database](/DATABASE.html) |
| No extensions | None is required | [Database](/DATABASE.html) |

Every connection sets `statement_timeout = 30s` and `idle_in_transaction_session_timeout = 60s` (`backend/veyrs/db.py`).

### Redis

| Use | If Redis is unreachable | Source |
|---|---|---|
| Readiness | `/readyz` answers 503 with `"status": "degraded"` | `backend/veyrs/main.py` |
| Rate limiting | **Fails open.** If Redis cannot be reached the first time a worker process needs it, that worker uses an in-process window until it restarts. That window is per worker, so 4 workers allow roughly 4 times the configured rate. If a Redis call fails later, the request is allowed and a warning is logged | `backend/veyrs/security/ratelimit.py` |
| E-mail and Telegram two-factor codes, RADIUS challenges | **Fails closed.** Sign-in is refused; it never falls back to the password alone | `backend/veyrs/security/mfa_delivery.py`, [System manual §2.12](/SYSTEM_MANUAL.html) |

Redis is not a system of record and is not replicated. The native installer sets `requirepass` on a local Redis, or reuses an existing one. The Docker stack runs Redis without a password and without persistence, reachable only on the stack network.

## Sizing

### Installer gates

`veyrs-setup.sh --check` measures the host. Its gates let an installation start; they do not size it.

| Resource | Refused below | Warning below | Source |
|---|---|---|---|
| CPU cores | never refused | 2 | `veyrs-setup.sh` `check_requirements` |
| RAM | 1,900 MB ("minimum 2 GB") | 3,800 MB ("4 GB recommended") | same |
| Free disk on `/` | 5,000 MB | 12,000 MB | same |

`install.sh` performs no hardware check.

### Native single node

The sizing tables in `INSTALL.md` and the [Deployment](/DEPLOYMENT.html) manual:

| Findings | vCPU | RAM | Notes |
|---|---|---|---|
| fewer than 50k | 2 | 4 GB | single node |
| 50k to 500k | 4 | 8 GB | separate database host recommended |
| 500k to 5M | 8 | 16 GB | separate the database host |
| more than 5M | not sized | not sized | separate workers; partition `findings` by `organization_id` |

Plan **60 GB of disk** for a single node with the default EPSS retention ([Disk](#disk)).

### HA pair

The figures for the reference topology ([Deployment](/DEPLOYMENT.html), `INSTALL.md`):

| Role | vCPU | RAM | Disk |
|---|---|---|---|
| Application node (each of two) | 4 | 4 GB | 20 GB (the node holds no state) |
| Database node (PostgreSQL and Redis) | 4 to 6 | 6 to 8 GB | 100 GB: the feed data, WAL kept for the standby, and the local dumps |
| Standby database node | same as the database node | same | same |

Give the standby the same PostgreSQL tuning (`shared_buffers`, `work_mem`, `max_connections`) as the primary. A smaller standby becomes a capacity problem the moment you promote it ([High availability](/HIGH_AVAILABILITY.html)).

### Docker

The [Docker Compose manual §3.2](/DOCKER_COMPOSE_MANUAL.html) uses the `veyrs-setup.sh` gates above:

| Resource | Minimum | Recommended | Note |
|---|---|---|---|
| CPU | 1 core | 2 or more | `api` runs 4 processes by default |
| RAM | 2 GB | 4 GB | only building the images needs 4 GB |
| Disk for Docker's data root | 5 GB | about 12 GB to install | 60 GB once the `workers` profile runs with the default retention, 30 GB with 90 days of EPSS history |

The `api` container mounts a 256 MB `tmpfs` on `/tmp`, because uploads larger than 1 MB are spooled there (`docker/compose.yaml`).

### Disk

Disk use follows the intelligence feeds, not the number of findings:

- After the first sync, the NVD corpus, the CPE dictionary and EPSS take about 5 to 6 GB (`INSTALL.md` Sizing, [Docker Compose manual §3.2](/DOCKER_COMPOSE_MANUAL.html)).
- EPSS history grows by one snapshot per scored day: about 370,000 rows, roughly 80 MB per day. It is kept for `VEYRS_EPSS_HISTORY_DAYS` (default **365**, about 30 GB at steady state; 90 days is about 7 GB; `0` keeps everything). The window counts back from the newest scored day, so a stalled feed does not erase its own history (`backend/veyrs/config.py`).
- Pruning frees space inside PostgreSQL, not on the filesystem. Returning it to the filesystem needs `VACUUM FULL`, which locks the table.

## Network requirements

The authoritative list of destinations is `backend/veyrs/services/network_requirements.py`. A test fails if a host appears in the code without a row there. Platform administrators can see the same list, resolved against the live settings, under **Administration → Network access** (`GET /api/v1/admin/system/network`).

### Inbound and internal ports

| Port | Direction | Purpose | Shape |
|---|---|---|---|
| 80/tcp | clients → node | Console and same-origin `/api/` proxy, from the vhost that `install.sh` generates | native |
| 443/tcp | clients → TLS endpoint | HTTPS. You add it, either as a `listen 443 ssl` block or on a proxy in front | native, recommended for Docker |
| `VEYRS_HTTP_BIND` (default `127.0.0.1:8080`) | proxy → console container | Console and `/api/` proxy. The only published port | Docker |
| 8000/tcp | nginx → API | uvicorn on `127.0.0.1` (native) or on the stack network only (Docker). Never publish it | both |
| 5432/tcp | application nodes → database node | PostgreSQL | HA, external database |
| 6379/tcp | application nodes → database node | Redis, with `requirepass` | HA |
| 5432/tcp | standby → primary | streaming replication | HA |
| 443/tcp | scan agent → VEYRS | The agent polls for jobs and uploads results. It accepts no inbound connections | when an agent runs |
| 443/tcp | ITSM system → VEYRS | Optional signed status webhooks. The body limit is 1 MB and the timestamp must fall within a five-minute window | when configured |

### Outbound at run time

| Destination | Port | Purpose | Need | Setting |
|---|---|---|---|---|
| `services.nvd.nist.gov` | 443 | CVE records, CVSS, CPE applicability (NVD API 2.0) | recommended | `VEYRS_NVD_API_URL`, `VEYRS_NVD_API_KEY` |
| `epss.empiricalsecurity.com` | 443 | Daily EPSS scores | recommended | `VEYRS_EPSS_CSV_URL` |
| `www.cisa.gov` | 443 | CISA Known Exploited Vulnerabilities | recommended | `VEYRS_KEV_JSON_URL` |
| `cwe.mitre.org` | 443 | MITRE CWE catalogue | optional | `VEYRS_CWE_CATALOG_URL` |
| `api.github.com` | 443 | "Is there a newer release?" check, at most once an hour | optional | `VEYRS_UPDATE_URL` (empty turns it off) |
| `github.com`, `release-assets.githubusercontent.com` | 443 | Release downloads by the root updater (native only) | optional | `VEYRS_UPDATE_DOWNLOAD_BASE` |
| `api.telegram.org` | 443 | Telegram two-factor codes | only if `VEYRS_TELEGRAM_BOT_TOKEN` is set | `VEYRS_TELEGRAM_API_URL` |
| `api.openai.com`, `api.anthropic.com`, `generativelanguage.googleapis.com` | 443 | External AI providers | only if `VEYRS_AI_ALLOW_EXTERNAL=true` **and** the organization's AI policy allows external providers | per provider |
| Mail relay | `VEYRS_SMTP_PORT` (default 25) | Two-factor codes by e-mail, notifications, digests | optional | `VEYRS_SMTP_HOST` |
| Secret vault | as in `VEYRS_VAULT_ADDR` (8200 if no port is given) | Connector credentials when `VEYRS_SECRET_BACKEND` is `mirror` or `vault` | required in those modes | `VEYRS_VAULT_*` |
| Local AI endpoint | as in `VEYRS_AI_LOCAL_BASE_URL` (11434 if no port is given) | The AI gateway's default local model | optional | `VEYRS_AI_ALLOW_LOCAL` |
| LDAP / Active Directory | 636 by default | Directory sign-in and team import | when enabled | per organization |
| RADIUS servers | 1812/udp by default | Sign-in and its Access-Challenge | when enabled | per organization |
| OpenID Connect issuer | 443 (the issuer must be `https://`) | Discovery, signing keys, code exchange | when enabled | per organization |
| Ticketing, scanner and asset-source connectors | as configured | Integrations | when enabled | per organization |

Each feed has an offline path. You can POST the NVD, EPSS and KEV files to `/api/v1/intel/feeds/<feed>`, or point the URL settings at an internal mirror. Without an NVD API key, NVD allows 5 requests per 30 seconds. The sync then runs slower but still completes, which is why the unit sets `TimeoutStartSec=infinity`.

### Outbound at install and update time

| Destination | Used by | Avoid it with |
|---|---|---|
| Your distribution's package mirrors | `install.sh`, `veyrs-setup.sh` | a local mirror |
| `pypi.org`, `files.pythonhosted.org` | `install.sh` (native), every native update | the release wheelhouse (`--source`, `--wheels`), or `PIP_INDEX_URL` |
| `download.postgresql.org` | `install.sh`, RHEL family only, as the PGDG fallback | PostgreSQL 15 or newer installed from a mirror |
| `github.com`, `release-assets.githubusercontent.com`, `api.github.com` | `veyrs-setup.sh` (`api.github.com` only when `--version` is not given) | `--source` with the release tarball |
| `download.docker.com` | `veyrs-setup.sh` (Docker mode on Debian, Ubuntu and RHEL family) | Docker Engine installed beforehand |
| `ghcr.io`, `pkg-containers.githubusercontent.com` | Docker mode with `VEYRS_IMAGE_SOURCE=registry` | `--images` with the offline image bundle |
| `registry-1.docker.io`, `auth.docker.io`, `production.cloudflare.docker.com` | Docker mode: base images | the offline image bundle |

**Fully offline install.** A Docker host needs only `veyrs-<v>-src.tar.gz` and `veyrs-images-<v>-amd64.tar.gz` (with its `.sha256`), and downloads nothing. A native host needs the source tarball, the x86-64 wheelhouse, and operating-system packages from a local mirror. No bundle of operating-system packages ships.

### Scan agent

A host that runs `veyrs-agent` must reach the VEYRS host name and every target in its scan scope. It refuses any target outside `VEYRS_AGENT_ALLOW`. nuclei also contacts `github.com` for engine and template updates, unless you turn that off in the agent host's nuclei configuration.

### Time synchronisation

Keep every node on NTP. Access tokens expire after `VEYRS_ACCESS_TOKEN_MINUTES`. Inbound ITSM webhooks are refused outside a five-minute timestamp window, and RADIUS challenges expire after 180 seconds.

## TLS and reverse proxy

| Requirement | Detail |
|---|---|
| TLS is provided outside the application | uvicorn binds `127.0.0.1:8000` over plain HTTP. The vhost that `install.sh` generates listens on port 80 only. The Docker console listens on 8080 over plain HTTP and sends no HSTS header. Add a `listen 443 ssl` block, or put a TLS proxy in front |
| `VEYRS_PUBLIC_BASE_URL` must be `https://` in production | Enforced at startup (`assert_production_safe`). `install.sh` refuses to write a non-HTTPS URL when the environment is `production`. `veyrs-docker.sh` refuses to start in that case |
| Same-origin API | The console calls `/api/` on its own host name, and its CSP allows `connect-src 'self'` only. Serve the console and the API from one origin |
| `X-Forwarded-For` | With `VEYRS_TRUST_PROXY_HEADERS=true`, VEYRS takes the **first** (leftmost) entry as the client address for per-IP rate limiting (`backend/veyrs/security/ratelimit.py`). The address recorded on sign-in takes that same first entry whatever the setting (`backend/veyrs/api/v1/auth.py`). The outermost proxy must **overwrite** the header with the real client address, not append to it. The shipped vhosts append (`$proxy_add_x_forwarded_for`), so they are safe only behind a proxy that overwrites |
| Trusted proxy address | uvicorn accepts forwarded headers only from `127.0.0.1` (native) or from `VEYRS_CONSOLE_IP` (Docker, default `172.29.0.10`, which must lie inside `VEYRS_SUBNET`) |
| Request size | The shipped vhosts set `client_max_body_size 128m` and `proxy_read_timeout 300s` on `/api/`. A proxy in front needs at least the same |
| `/metrics` | Not proxied by the shipped vhosts. The Docker console answers 404. Scrape the API directly with the bearer token |
| Health probes | `/healthz` (liveness, no I/O) and `/readyz` (PostgreSQL and Redis) are proxied with `Cache-Control: no-store`. Point a load balancer at `/readyz` |

## Configuration

All settings are environment variables with the prefix `VEYRS_`, read from `/opt/veyrs/.env` (mode 0600) on a native install, or from `docker/.env` in the Docker stack. A change takes effect after a restart. The full reference is [System manual §2](/SYSTEM_MANUAL.html).

### Refused at startup in production

When `VEYRS_ENVIRONMENT=production`, `Settings.assert_production_safe()` refuses to start if any of the following holds (`backend/veyrs/config.py`):

| Setting | Condition that stops the boot |
|---|---|
| `VEYRS_DEBUG` | `true` |
| `VEYRS_DATABASE_URL` | still contains the bootstrap credentials `veyrs:veyrs@` |
| `VEYRS_PUBLIC_BASE_URL` | does not start with `https://` |
| `VEYRS_ENCRYPTION_KEY` | empty. A key derived from `VEYRS_SECRET_KEY` is refused, because rotating the session secret would orphan every stored credential. Generate one with `veyrs keygen` |
| `VEYRS_SECRET_BACKEND=mirror` or `vault` | incomplete vault block: no `VEYRS_VAULT_ADDR`, a non-`https` address, no role id and secret-id file (AppRole) or token file (token), or a named file that does not exist |

`install.sh` writes `VEYRS_ENVIRONMENT=production` by default. The Docker stack defaults to `development`.

### Required in practice

| Setting | Why |
|---|---|
| `VEYRS_SECRET_KEY` | Signs JWTs. If set, it must be at least 32 characters, or the process will not start. If unset, every process generates its own random key: with 4 workers, a token signed by one worker is rejected by the other three, and every restart signs everyone out. Production mode does **not** check for it. The Docker entrypoint refuses an empty value, and both installers generate one. Every node of an HA pair must use the same value |
| `VEYRS_ENCRYPTION_KEY` | Fernet key for stored third-party credentials. You cannot rotate it in place: changing it leaves every stored credential undecryptable. Keep a copy with your backups, and use the same value on every node |
| `VEYRS_DATABASE_URL` | Needs the `postgresql+psycopg://` driver marker |
| `VEYRS_REDIS_URL` | Default `redis://127.0.0.1:6379/0` |
| `VEYRS_CORS_ORIGINS` | The default is a host name from the vendor's reference deployment. Set it to your console origin |
| `VEYRS_METRICS_TOKEN` | Bearer token for `/metrics`. Without it, `/metrics` answers 404 in production. A missing or wrong token also gets 404, not 401. `install.sh` generates one; the Docker stack does not pass one through |
| `VEYRS_TRUST_PROXY_HEADERS` | Default `false`. `install.sh` and the Docker stack set it to `true`. Enable it only behind a proxy you control that overwrites `X-Forwarded-For` |

### Defaults to review

| Setting | Default | Note |
|---|---|---|
| `VEYRS_AI_ALLOW_LOCAL` | `true` | The default `VEYRS_AI_LOCAL_BASE_URL` points at an address in the vendor's reference deployment. `install.sh` writes `false`. In the Docker stack, set it to `false` or point the URL at your own endpoint |
| `VEYRS_AI_ALLOW_EXTERNAL` | `false` | An organization's AI policy can only narrow it |
| `VEYRS_AI_MAX_DATA_CLASSIFICATION` | `internal` | The highest data classification allowed to leave the installation |
| `VEYRS_SMTP_HOST` | empty | Empty turns off e-mail delivery, including e-mail two-factor codes |
| `VEYRS_SMTP_FROM` | the vendor's address | Set your own sender |
| `VEYRS_ACCESS_TOKEN_MINUTES` | `30` | `install.sh` writes `60` |
| `VEYRS_REFRESH_TOKEN_DAYS` | `14` | |
| `VEYRS_PASSWORD_MIN_LENGTH` | `12` | |
| `VEYRS_RATE_LIMIT_PER_MINUTE` | `240` | |
| `VEYRS_AUTH_RATE_LIMIT_PER_MINUTE` | `10` | Raise it when many users sign in from behind one NAT address |
| `VEYRS_EPSS_HISTORY_DAYS` | `365` | Drives most of the disk use |
| `VEYRS_UPDATE_URL` | the public "latest release" API | Set it empty on an air-gapped host |
| `VEYRS_UPDATE_PRE_HOOK` | empty | Without a hook, or `VEYRS_UPDATE_SKIP_BACKUP=true`, the in-product updater refuses to run |
| `VEYRS_DEFAULT_LOCALE` | `en` | Valid values: `en`, `es`, `de`, `fr`, `it` |

`VEYRS_MAX_UPLOAD_MB` (default 32) is declared in `config.py`, but no code reads it. The upload limits that apply are listed under [Request size limits](#request-size-limits).

## Console: browsers and Content-Security-Policy

### Browsers

There is no tested browser matrix. The minimums below come from the features the console uses (`frontend/console/`):

| Feature | Used for | Available from |
|---|---|---|
| CSS `color-mix()` | most colours in `console.css` | Chrome and Edge 111, Firefox 113, Safari 16.2 |
| CSS `:has()` | one checkbox highlight (cosmetic) | Chrome and Edge 105, Firefox 121, Safari 15.4 |
| JavaScript optional chaining, `async`/`await`, `fetch` | the whole console | all of the above |
| `localStorage` | access token, refresh token, organization and permissions | all of the above; the browser must not block storage for the origin |
| Clipboard API | one "copy vector" button | requires a secure context (HTTPS or `localhost`) |

The browser needs to reach the VEYRS host name and nothing else. The console loads no CDN, web font or analytics, and a test enforces this (`backend/veyrs/services/network_requirements.py`).

### Content-Security-Policy

The console vhost (`install.sh`, `infrastructure/nginx-veyrs-console.conf`, `docker/console.conf`) sends:

```
default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline';
img-src 'self' data:; font-src 'self'; connect-src 'self';
frame-ancestors 'none'; base-uri 'self'; form-action 'self'
```

API responses carry a matching policy with `base-uri 'none'`, together with `X-Frame-Options: DENY`, `X-Content-Type-Options: nosniff`, `Referrer-Policy: no-referrer`, `Cross-Origin-Opener-Policy: same-origin`, `Cross-Origin-Resource-Policy: same-origin`, `Permissions-Policy` and `Strict-Transport-Security` (`backend/veyrs/observability.py`).

The policy imposes these constraints:

- No inline script and no inline event handlers. Customisations must live in `app.js`.
- No third-party origin of any kind, for scripts, styles, fonts, images or API calls.
- The API must share the console's origin (`connect-src 'self'`).
- The console cannot be embedded in a frame (`frame-ancestors 'none'`, `X-Frame-Options: DENY`).
- Images must come from the origin or from `data:` URLs.

The console page loads `/static/veyrs-tokens.css` and brand images from `/static/`. The Docker console image includes them. The vhost that `install.sh` generates has no `/static/` location, and `install.sh` copies only `app.js`, `console.css` and `index.html`. On a native install, serve `frontend/brand/` under `/static/` yourself; otherwise those requests receive `index.html`.

## Authentication

Local accounts are always available. Every other method is **off until an administrator enables it per organization**.

| Method | Default | Requirements | Source |
|---|---|---|---|
| Local password | on | Argon2id hash; at least `VEYRS_PASSWORD_MIN_LENGTH` (12) characters | `backend/veyrs/config.py`, [Security](/SECURITY.html) |
| Two-factor, authenticator app (TOTP) | opt-in per user | Nothing on the server. The QR code is rendered server-side as SVG | `backend/veyrs/security/mfa.py` |
| Two-factor, e-mail code | opt-in per user | A mail relay (`VEYRS_SMTP_HOST`) and Redis | `backend/veyrs/security/mfa_delivery.py` |
| Two-factor, Telegram code | opt-in per user | `VEYRS_TELEGRAM_BOT_TOKEN`, outbound HTTPS to Telegram, and Redis | same |
| LDAP / Active Directory | off | LDAPS on port 636 by default, with certificate verification on; 8-second timeout | `backend/veyrs/services/ldap_auth.py` |
| RADIUS | off | Up to four servers (1812/udp by default), a shared secret of at least 16 characters, a timeout of 1 to 120 s (default 10), and Message-Authenticator on every answer. Register every application node as a RADIUS client. RadSec is not implemented | `backend/veyrs/services/radius_auth.py`, [System manual §2.13](/SYSTEM_MANUAL.html) |
| OpenID Connect SSO | off | A confidential client using the authorization code flow, an `https://` issuer, and the redirect URI `https://<console host>/api/v1/auth/oidc/callback`. Just-in-time provisioning is off by default, and so is the `amr` multi-factor requirement | `backend/veyrs/services/oidc_auth.py` |

Two-factor sign-in is opt-in for each person. No organization-wide enforcement setting exists. At sign-in, VEYRS checks the local password first, then the directory if it is enabled, then RADIUS. A platform superuser is never delegated to RADIUS. Platform administrators keep their local password under SSO.

## Backups and disaster recovery

| Requirement | Detail | Source |
|---|---|---|
| Dump as a role that bypasses RLS | RLS is FORCEd, and that applies to the table owner too. A dump as the application role fails partway through and leaves a partial file. `scripts/backup.sh` dumps as the `postgres` superuser over peer authentication, or as a `BYPASSRLS` role set in `BACKUP_DSN` | `scripts/backup.sh` |
| Back up the keys with the data | `scripts/backup.sh` archives the database dump, `.env` (which holds `VEYRS_ENCRYPTION_KEY` and `VEYRS_SECRET_KEY`), `var/documents/` if present, a manifest and `SHA256SUMS`. The archive is as sensitive as the database: mode 0600, and keep it off the host | `scripts/backup.sh` |
| Local retention | 30 days (`RETAIN_DAYS`) under `/opt/veyrs/var/backups` | `scripts/backup.sh` |
| Docker stack | `docker/veyrs-docker.sh backup` dumps as `postgres` inside the container and refuses a dump with fewer than 50 `TABLE DATA` sections. It needs `pg_restore` 15 or newer on the host. It is refused with an external database: back that database up where it lives | `docker/veyrs-docker.sh`, [Docker Compose manual](/DOCKER_COMPOSE_MANUAL.html) |
| Restore | Create the target with `createdb -E UTF8 -T template0`. Restore as `postgres`, not with `--role=veyrs`, or RLS blocks foreign-key validation. `scripts/restore.sh` does this: peer authentication as `postgres` when the database is local, otherwise `RESTORE_DSN` (a superuser connection string), and it refuses before dropping anything when neither is available | [High availability](/HIGH_AVAILABILITY.html), [Disaster recovery](/DISASTER_RECOVERY.html) |
| Update pre-hook | The in-product updater refuses to run without `VEYRS_UPDATE_PRE_HOOK` (a root-owned executable, for example `scripts/backup.sh`) unless `VEYRS_UPDATE_SKIP_BACKUP=true` | `backend/veyrs/config.py` |

For a dedicated database node, optional units ship in `infrastructure/backup/`:

| Unit | Schedule | What it checks |
|---|---|---|
| `veyrs-pgdump.timer` | daily at 02:15, with up to 5 minutes of jitter | `pg_dump -Fc` as a superuser (it refuses any other role), a 20 MB size floor, `TABLE DATA` for each canary table, then a push to an off-host account. Keeps 7 days locally and 30 days off-host |
| `veyrs-pgverify.timer` | Sundays at 04:30 | Restores the latest dump into a scratch database, then compares row counts and the RLS policy count |
| `veyrs-replcheck.timer` | every 15 minutes | The replication slot is active and not lost, the standby is streaming, and replay lag is under 128 MB |

The [Disaster recovery](/DISASTER_RECOVERY.html) manual sets design targets of **RPO 24 hours** and **RTO 1 hour**. It states that no rehearsal has been run against this build, so treat both as targets, not measurements.

## High availability

The supported topology is two stateless application nodes in front of one database node with a streaming standby (ADR 0007, [High availability](/HIGH_AVAILABILITY.html)).

| Requirement | Why |
|---|---|
| Identical `VEYRS_SECRET_KEY` and `VEYRS_ENCRYPTION_KEY` on every application node | A token issued by one node must validate on the other, and both must decrypt the same stored credentials |
| One shared Redis | Rate-limit counters and two-factor codes must be visible to every node. A code sent by one node is accepted by the other after a failover |
| Every node on the same release, including the console files | A node running the new API behind the old console still answers 200 everywhere |
| A load balancer that health-checks `/readyz` and retries on the other node | The [High availability](/HIGH_AVAILABILITY.html) runbook uses passive checks and `proxy_connect_timeout 3s`. Without that timeout, losing a node outright leaves connections hanging until nginx's 60-second default expires |
| `veyrs-agent` and the intelligence-sync timer on **exactly one** node | Two runners claim the same jobs, and two syncs compete for the same NVD rate limit |
| One `pg_hba.conf` line per application node (`/32`) | A CIDR range would make any host on that network a database client |
| Primary: `wal_level=replica`, `max_wal_senders` set, a physical replication slot, and `max_slot_wal_keep_size = 20GB` | Without the bound, a standby that is down retains WAL until the primary's disk is full |
| Standby: `hot_standby = on`, the same tuning as the primary | Promotion must not cause a capacity incident |
| A standby on a different physical host, one that is always on | A standby on the primary's host does not survive the loss of that host |

Guarantees and limits:

- **Application node loss:** the load balancer sends traffic to the surviving node. No operator action is needed.
- **Database node loss:** a full outage until an operator promotes the standby, points both `.env` files at it and provides a Redis. **Promotion is manual by design.** Promoting without fencing risks two primaries with divergent security data.
- **Batch work:** scheduled scans and the intelligence sync pause while their node is down, until an operator enables them on the other node.
- **Redis is not replicated.** Losing it loses rate-limit counters and pending two-factor codes, not data.
- The Docker stack is single-node and offers none of the above.

## Non-functional guarantees

### Rate limits

Source: `backend/veyrs/security/ratelimit.py`.

| Traffic | Budget | Key |
|---|---|---|
| Paths containing `/auth/login`, `/auth/refresh`, `/auth/mfa` or `/auth/password` | `VEYRS_AUTH_RATE_LIMIT_PER_MINUTE` (10) per 60 s | client IP |
| Everything else | `VEYRS_RATE_LIMIT_PER_MINUTE` (240) per 60 s | a digest of the bearer token, the API key prefix, or else the client IP |
| `/healthz`, `/readyz`, `/metrics`, and all `OPTIONS` requests | exempt | |

A refused request receives `429` with `Retry-After`, `X-RateLimit-Limit` and `X-RateLimit-Remaining: 0`. With Redis, the window is a fixed per-minute bucket shared by every worker and node. For the behaviour without Redis, see [Redis](#redis).

### Sign-in and session limits

| Control | Value | Source |
|---|---|---|
| Account lockout | 10 failed attempts lock the account for 15 minutes. Password and two-factor failures count against the same budget | `backend/veyrs/api/v1/auth.py` |
| Access token | 30 minutes by default; HS256, HS384 or HS512 | `backend/veyrs/config.py` |
| Refresh token | 14 days, rotated on every use | `backend/veyrs/config.py`, [Security](/SECURITY.html) |
| E-mail and Telegram codes | 6 digits, valid for `VEYRS_MFA_CODE_TTL` (default 300 s, range 60 to 900), single use, 5 wrong tries burn the code | `backend/veyrs/security/mfa_delivery.py` |
| Code sending | at most one per 30 s and six per 15 minutes | same |
| Recovery codes | 10, issued once at activation | same |
| RADIUS challenge | 180 s, single use, bound to the account | [System manual §2.13](/SYSTEM_MANUAL.html) |

### Database session limits

Every connection runs with `statement_timeout = 30s` and `idle_in_transaction_session_timeout = 60s`. Each worker process has a pool of 10 connections plus 20 overflow, with `pool_pre_ping` on (`backend/veyrs/db.py`).

### Request size limits

| Limit | Value | Source |
|---|---|---|
| nginx body size on `/api/` | 128 MB | the shipped vhosts |
| Scanner export | 128 MB | `backend/veyrs/services/scanners.py` |
| CMDB export | 64 MB | `backend/veyrs/services/cmdb.py` |
| Agent result | 64 MB | `backend/veyrs/services/agents.py` |
| Inbound ITSM webhook | 1 MB | `backend/veyrs/services/itsm_inbound.py` |
| Update upload chunk | 8 MB | `backend/veyrs/services/updates.py` |

Validation errors (422) return the field location and message, never the submitted value (`backend/veyrs/main.py`).

### Audit and logging

- `audit_log`, `auth_events` and `ai_audit_log` are append-only: the application has no update or delete path for them, and no job prunes them ([System manual §8](/SYSTEM_MANUAL.html)).
- Every endpoint authorizes server-side. A test walks the route table to prove that no route is unprotected.
- Logs are structured JSON on stdout (journald on a native install). Every request carries an `X-Correlation-ID` that also appears in error bodies.
- `/metrics` exposes Prometheus counters for each worker process. One scrape samples one worker.
- In production, `/docs` and `/redoc` are off. `/api/v1/openapi.json` is always served.

### Retention defaults

| Data | Default | Setting |
|---|---|---|
| EPSS history | 365 days | `VEYRS_EPSS_HISTORY_DAYS` |
| Refresh tokens | 14 days | `VEYRS_REFRESH_TOKEN_DAYS` |
| `scripts/backup.sh` archives | 30 days | `RETAIN_DAYS` |
| `veyrs-pgdump` dumps | 7 days local, 30 days off-host | `KEEP_LOCAL_DAYS`, `KEEP_REMOTE_DAYS` |
| Audit, auth and AI audit trails | kept indefinitely | none |

### Intelligence feed cadence

Each organization chooses its own feed intervals. The default is 1,440 minutes for CWE, NVD, EPSS and KEV, and the allowed range is 60 to 43,200 minutes. A feed shared by several organizations is fetched at the shortest interval any of them chose (`backend/veyrs/services/intel_schedule.py`). The scheduler (`veyrs intel-due`) runs only when its timer fires:

| Shape | Timer | Source |
|---|---|---|
| Native | `veyrs-intel-sync.timer`: hourly tick, with up to 10 minutes of jitter | `integrations/systemd/veyrs-intel-sync.timer` |
| Docker (`workers` profile) | hourly tick, with up to 10 minutes of jitter | `docker/compose.yaml` |

Both shapes tick hourly, so any interval of an hour or more takes effect as set. `install.sh` installs and enables the intelligence timer (and the digest timer); on a multi-node install keep the intel timer enabled on one node only. The agent unit ships in `integrations/veyrs-agent/` and is installed by hand.

## Known limits

- **x86-64 only.** No arm64 wheels or images are published.
- **No TLS listener** in either shipped shape.
- **No automatic database failover.** Redis is not replicated.
- **The Docker stack is single-node.** Its `workers` and `agent` profiles are off by default. Without `workers`, the intelligence data stops refreshing, and the console does not show it.
- **Native installs must serve `/static/` themselves** ([Content-Security-Policy](#content-security-policy)).
- **Supported distributions are those listed above.** `veyrs-setup.sh` refuses newer major releases without `--force`. `install.sh` accepts any member of the three families but has been measured only on the five images listed.
- **`/healthz` answering 200 says nothing about the database.** Use `/readyz`.
