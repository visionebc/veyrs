# VEYRS on Docker Compose — the operator manual

This manual covers everything you need to install, configure, operate, back up,
secure, troubleshoot and remove the VEYRS container stack in
[`docker/`](../docker/README.md). Each statement here comes from the files that
ship in this repository: [`docker/compose.yaml`](../docker/compose.yaml),
[`docker/compose.external-db.yaml`](../docker/compose.external-db.yaml),
[`docker/veyrs-docker.sh`](../docker/veyrs-docker.sh),
[`docker/env.example`](../docker/env.example) and the guided installer
[`veyrs-setup.sh`](../veyrs-setup.sh). When this manual and those files
disagree, the files are right. Please report the mismatch as a documentation bug.

After reading it you will be able to:

- bring up a working VEYRS console in about five commands;
- decide which optional services to run, and know what breaks if you leave them off;
- put the stack behind TLS, or point it at a PostgreSQL server you already run;
- take a backup you can restore, and prove the backup is complete;
- recognise the failure modes that give no error message.

> **Who this is for.** You are comfortable with a Linux shell and have used
> Docker before. You do not need to know VEYRS internals.
>
> **What this stack is for.** The stack is for **evaluation, development and
> small single-node installations**. It puts the application and its database
> in one Compose project. A production VEYRS keeps them on separate hosts, so
> the standby pair means something. For that, use the host installer
> ([INSTALL.md](../INSTALL.md)). This manual says where the trade-off matters.

---

## Contents

1. [What you get](#1-what-you-get)
2. [Architecture](#2-architecture)
3. [Requirements](#3-requirements)
4. [Quick start](#4-quick-start)
5. [Step-by-step installation](#5-step-by-step-installation)
6. [Configuration reference](#6-configuration-reference)
7. [Using an external PostgreSQL](#7-using-an-external-postgresql)
8. [TLS and a reverse proxy in front](#8-tls-and-a-reverse-proxy-in-front)
9. [Day-2 operations](#9-day-2-operations)
10. [Backup and restore](#10-backup-and-restore)
11. [Security model](#11-security-model)
12. [Troubleshooting](#12-troubleshooting)
13. [Uninstalling](#13-uninstalling)
14. [FAQ](#14-faq)
15. [Related documents](#15-related-documents)

### Conventions

- Commands run from the **repository root**, the directory that contains
  `docker/`, `backend/` and `install.sh`. If you installed with
  `veyrs-setup.sh`, the same tree is at `/opt/veyrs-docker/current`, and the
  command `veyrs-docker` is equivalent to `docker/veyrs-docker.sh`.
- `docker/veyrs-docker.sh` is called **the driver**.
- Where a raw `docker compose` command is unavoidable, this manual uses a
  variable `C` that describes **the whole stack**, every profile included:

  ```bash
  C="docker compose --project-directory docker -f docker/compose.yaml --profile workers --profile agent"
  # If docker/.env sets VEYRS_COMPOSE_OVERLAYS, add one -f per overlay, e.g.:
  # C="$C -f docker/compose.external-db.yaml"
  ```

  Use the driver when it has a verb for what you want. It always passes the
  right files and profiles. §9.10 explains why raw commands are risky.

---

## 1. What you get

### 1.1 Services

Every VEYRS image is tagged with the release version (`:0.32.4`). Where the
images come from — pulled, built or loaded offline — is §2.3.

| Service | Image | Profile | Runs | Published port | Role |
|---|---|---|---|---|---|
| `postgres` | `postgres:15-bookworm` (pinned by digest) | *(base)* | always | **none** | PostgreSQL 15. The superuser is `postgres`, and the application role is **not** a superuser (§11.1) |
| `redis` | `redis:7-alpine` (pinned by digest) | *(base)* | always | none | Rate-limit counters and short-lived cache. No persistence and no volume, because the data can be rebuilt. `/readyz` returns 503 without it |
| `init` | `ghcr.io/visionebc/veyrs` | *(base)* | on every `up`, then exits 0 | none | Fixes volume ownership as root, **drops to uid 10001**, then applies the schema (`veyrs init-db`) and creates the first administrator **only if it does not exist** |
| `api` | `ghcr.io/visionebc/veyrs` | *(base)* | always | **none** (`expose: 8000` only) | FastAPI on uvicorn, 4 processes by default, running as uid 10001 |
| `console` | `ghcr.io/visionebc/veyrs-console` | *(base)* | always | `127.0.0.1:8080` → 8080 | nginx, running as uid 101 (not root). Serves the operator console and proxies `/api/`, `/healthz`, `/readyz`, `/docs` and `/redoc` to `api`. This is the **only** published port |
| `intel` | `ghcr.io/visionebc/veyrs` | `workers` | hourly tick | none | Runs `scripts/sync-intel.sh`: NVD, EPSS, CISA KEV and CWE feeds, plus the SLA sweep |
| `digest` | `ghcr.io/visionebc/veyrs` | `workers` | hourly tick | none | Runs `scripts/send-digest.sh`: the daily digest e-mail |
| `agent` | `ghcr.io/visionebc/veyrs-agent` | `agent` | long-running poller | none | Scanner runner: nuclei 3.11.1, pinned and checksum-verified |

### 1.2 Profiles

The split is by **blast radius**, not by importance:

| How you start it | What runs |
|---|---|
| `docker/veyrs-docker.sh up` | base: `postgres`, `redis`, `init`, `api`, `console` |
| `docker/veyrs-docker.sh up --with-workers` | base + `intel` + `digest` |
| `docker/veyrs-docker.sh up --with-agent` | base + `agent` |
| `docker/veyrs-docker.sh up --all` | everything (identical to `--with-workers --with-agent`) |

### 1.3 What is NOT running by default, and what it costs you

| Missing service | Off by default because | What happens if you leave it off |
|---|---|---|
| `intel` | The first run pulls the whole NVD corpus. That takes hours, and the feed rate-limits per source address. You should not trigger it on a machine you are only trying out | **The vulnerability data stops ageing forward, and SLA deadlines stop elapsing.** NVD, EPSS and KEV never refresh. VEYRS keeps scoring, with full confidence, against whatever it last knew. **Nothing in the console shows this.** |
| `digest` | Same tick, same reasoning | Notification rows are still written, so nothing is lost. Nobody gets the e-mail |
| `agent` | It is the one component that sends **unsolicited network traffic to other people's machines** | No scans start from this node. Scan jobs queue, and their leases are reaped |

> **Turn `workers` on for any installation you intend to keep.**
> `docker/veyrs-docker.sh status` prints this table, filled in from what is
> actually running, so the answer comes from the machine and not from your
> memory of which flags you passed three weeks ago.

### 1.4 How it maps to a host install

| Host install (systemd) | This stack |
|---|---|
| `veyrs-api.service` (runs as root, hardened with `ProtectSystem=strict`) | `api` (runs as uid 10001, no root) |
| nginx console vhost | `console` |
| `veyrs-intel-sync.timer` (hourly, `RandomizedDelaySec`, `Persistent=true`) | `intel`: `docker/tick.sh` every 3600 s plus 0–600 s of jitter, with one catch-up tick at start |
| `veyrs-digest.timer` | `digest`: every 3600 s plus 0–300 s of jitter, with one catch-up tick at start |
| `veyrs-agent.service` | `agent` |

**A tick is not a schedule.** Both loops only ask, once an hour, whether
something is due. The real cadence lives in the database
(`organizations.settings.intel_schedule` and `organizations.settings.digest`),
and you edit it in the console. `veyrs intel-due` and the digest's "due now"
check make the decision. A failed run never ends the loop. It logs `FAILED` and
the next tick retries.

---

## 2. Architecture

### 2.1 Containers, network, ports and volumes

```
 Docker host
 ─────────────────────────────────────────────────────────────────────────────
   browser / TLS proxy
          │  http://127.0.0.1:8080   (VEYRS_HTTP_BIND — the ONLY published port)
          ▼
 ┌─────────────────────────────────── network veyrs_veyrs (bridge) ───────────┐
 │                                    subnet VEYRS_SUBNET = 172.29.0.0/16      │
 │                                                                             │
 │  ┌──────────────────────────────┐                                           │
 │  │ console (nginx 1.28, uid 101)│  STATIC 172.29.0.10 (VEYRS_CONSOLE_IP)    │
 │  │  /           console SPA     │                                           │
 │  │  /static/    brand + tokens  │                                           │
 │  │  /api/ /healthz /readyz      │── proxy_pass http://$veyrs_api:8000 ──┐   │
 │  │  /docs /redoc (dev only)     │   re-resolved via 127.0.0.11,         │   │
 │  │  /metrics → 404              │   valid=10s                           │   │
 │  └──────────────────────────────┘                                       │   │
 │                                                                         ▼   │
 │  ┌──────────────────────────────┐  completed_ok   ┌────────────────────────┐│
 │  │ init (one-shot, root→10001)  │────────────────▶│ api  (uvicorn ×4)      ││
 │  │  chown veyrs-var             │                 │  :8000, NO host port   ││
 │  │  veyrs init-db               │                 │  uid 10001             ││
 │  │  bootstrap admin if absent   │                 │  trusts XFF only from  ││
 │  │  ONLY holder of PG superuser │                 │  172.29.0.10           ││
 │  └──────┬───────────────────────┘                 └───────┬───────┬───────┘│
 │         │ (superuser)                   (app role, RLS)   │       │        │
 │         ▼                                                 ▼       ▼        │
 │  ┌──────────────────────────────┐                  ┌──────────────────────┐│
 │  │ postgres 15                  │◀─────────────────│ redis 7              ││
 │  │  superuser  = postgres       │                  │  no volume, no AOF   ││
 │  │  app role   = veyrs          │                  └──────────────────────┘│
 │  │  NOSUPERUSER NOBYPASSRLS     │                                          │
 │  │  NO host port                │                                          │
 │  └──────────────────────────────┘                                          │
 │                                                                            │
 │  ── profile workers ─────────────────────────────────────────────────────  │
 │  ┌──────────────────────────┐   ┌──────────────────────────┐               │
 │  │ intel  tick 3600s+0..600 │   │ digest  tick 3600s+0..300│  → postgres,  │
 │  │ scripts/sync-intel.sh    │   │ scripts/send-digest.sh   │    redis      │
 │  └──────────┬───────────────┘   └──────────┬───────────────┘               │
 │  ── profile agent ───────────────────────────────────────────────────────  │
 │  ┌──────────────────────────────────────────────┐                          │
 │  │ agent  nuclei 3.11.1, uid 10001, no NET_RAW  │── http://api:8000 ──▶ api│
 │  └──────────┬───────────────────────────────────┘                          │
 └─────────────┼──────────────────────┼───────────────────────────────────────┘
               ▼ outbound             ▼ outbound
     NVD / EPSS / KEV / CWE, SMTP     github.com (templates), scan targets

 Every VEYRS container: cap_drop ALL, no-new-privileges, read-only root
 filesystem (§11.4). init alone gets CHOWN/DAC_OVERRIDE/FOWNER/SETUID/SETGID.

 Named volumes (Compose project "veyrs")
   veyrs_veyrs-pgdata      → postgres:/var/lib/postgresql/data     THE DATABASE
   veyrs_veyrs-var         → init, api, intel, digest:/opt/veyrs/var
                             evidence files, reports, uploaded documents
   veyrs_veyrs-agent-home  → agent:/opt/veyrs/agent-home
                             nuclei config, cache, ~84 MB template corpus
```

### 2.2 Start-up order

Compose enforces this order with `depends_on` conditions:

| Service | Starts after |
|---|---|
| `postgres` | nothing. It is **healthy** only when the *application role* can log in to the *application database* (`psql … -c 'SELECT 1'`), not merely when `pg_isready` answers |
| `redis` | nothing. Healthy when `redis-cli ping` returns `PONG` |
| `init` | `postgres` healthy **and** `redis` healthy |
| `api` | `init` **completed successfully**. Healthy when `GET /readyz` returns 200 from inside the container |
| `console` | `api` **healthy** |
| `intel`, `digest` | `init` completed successfully |
| `agent` | `api` healthy |

If `init` fails, `api`, `console`, `intel` and `digest` never start. This is
deliberate: nothing serves traffic against a half-built schema.

### 2.3 Images

All images come from one [`docker/Dockerfile`](../docker/Dockerfile). Each
release publishes them, built from the release commit, so most installations
never build anything.

| Published image | Dockerfile target | Base (pinned by digest) | Contents | Runs as |
|---|---|---|---|---|
| `ghcr.io/visionebc/veyrs:<version>` | `api` | `python:3.11-slim-trixie` | `backend/`, `scripts/`, entrypoints, pinned `requirements.txt`. Explicit `COPY` lines only, never `COPY . .`. Used by `init`, `api`, `intel` and `digest` | uid/gid 10001 |
| `ghcr.io/visionebc/veyrs-console:<version>` | `console` | `nginx:1.28-alpine` | `frontend/console/`, brand assets and `veyrs-tokens.css` under `/static/`, and `docker/console.conf` as the default server. Listens on 8080 | uid/gid 101 (`nginx`) |
| `ghcr.io/visionebc/veyrs-agent:<version>` | `agent` | `api` stage | nuclei 3.11.1 (SHA-256 checked) and `integrations/veyrs-agent/` | uid/gid 10001 |

Each image carries `org.opencontainers.image.version` and `…revision` labels:
the release number and the full commit it was built from.
`docker/veyrs-docker.sh status` prints them for what is running.

**Platform:** `linux/amd64` only. On another architecture, use
`VEYRS_IMAGE_SOURCE=build`. The arm64 nuclei checksum is already in the
Dockerfile, but nothing else for arm64 has been verified.

#### Where the images come from: `VEYRS_IMAGE_SOURCE`

| Value | `up` does | Needs | Use it when |
|---|---|---|---|
| `registry` | `docker compose pull`, then starts | `ghcr.io` and Docker Hub (for `postgres`, `redis`) | normal installs. **This is what `init` and `veyrs-setup.sh` write.** About a minute, no compiler, no PyPI |
| `build` | builds the three images from **this tree**, pulls `postgres`/`redis`, then starts | Docker Hub, PyPI, Debian mirrors, `github.com` (nuclei) | you changed the code, or you want a version that was never published, or you are not on amd64. 5–15 minutes |
| `local` | starts with what is already on the host. **Never pulls, never builds** | nothing | an **offline** host after `veyrs-docker.sh load` (§5.C) |

In every mode, `up` starts the stack with `--no-build --pull never`. That keeps
Compose from quietly building an image it could not find. In `local` mode, any
missing image is listed by name before anything starts.

An env file written before 0.32.4 has no `VEYRS_IMAGE_SOURCE`, so it keeps
building, as it did when it was written. Set `VEYRS_IMAGE_SOURCE=registry` and
the three image names to switch it (§9.4).

#### The offline bundle

Each release also attaches `veyrs-images-<version>-amd64.tar.gz` plus a
`.sha256` file. It is one `docker save` archive of the `veyrs` and
`veyrs-console` images and the exact `postgres` and `redis` images that
`compose.yaml` pins. The agent is not included, because it needs the network
to do anything. §5.C shows how to use it.

#### Why the bases are pinned by digest

A tag is a pointer that the registry can move. `python:3.11-slim` moved from
Debian 12 to Debian 13 under this Dockerfile without any line of it changing.
Pinned, two builds of the same commit start from the same bytes, and refreshing
a base image is a reviewed edit.

The bundled `postgres` also stays on **bookworm** on purpose. PostgreSQL orders
text indexes by the C library's collation rules, and those changed between
Debian 12 and 13. Moving an existing data volume to a trixie-based image would
leave text indexes silently mis-ordered until a `REINDEX`.

---

## 3. Requirements

### 3.1 Software on the Docker host

| Requirement | Minimum | Notes |
|---|---|---|
| Docker Engine | a current release | Tested with Docker 29.x |
| Docker Compose **v2 plugin** (`docker compose`) | **2.20** (`veyrs-setup.sh` refuses anything older) | `docker-compose` v1 does not work. The driver checks for `docker compose version`. Tested up to Compose v5.x |
| `bash`, `curl` | — | The driver polls `/readyz` with `curl` from the host |
| `openssl` | — | `docker/veyrs-docker.sh init` generates every secret with it |
| `pg_restore` (PostgreSQL client, **15 or newer**) | — | Only for `docker/veyrs-docker.sh backup`. The verification step runs `pg_restore --list` **on the host**. See §10.2 |
| systemd | — | Only for `veyrs-setup.sh`, which also refuses unsupported distributions |

`veyrs-setup.sh` supports Debian 12, Ubuntu 22.04 and 24.04, Rocky, Alma and
RHEL 9, and openSUSE Leap and SLES 15. `--force` lets you try anything else.
The driver itself only needs Docker and bash.

**Running Docker inside an LXC container?** The container needs `nesting=1`,
plus `keyctl=1` when it is unprivileged. Without them the Docker daemon installs
but never answers.

### 3.2 Hardware

These figures are the thresholds `veyrs-setup.sh` checks:

| Resource | Minimum | Recommended | Why |
|---|---|---|---|
| CPU | 1 core | **2 or more** | Image builds; `api` runs 4 processes by default |
| RAM | 2 GB | **4 GB** | Only *building* images needs the 4 GB; the running stack fits in 2 |
| Free disk on `/` (Docker's data root) | 5 GB | **about 12 GB** | Base images, three built images, the database and, with `agent`, an 84 MB template corpus. The NVD corpus pulled by `intel` grows the database considerably |
| CPU architecture | x86-64 | x86-64 | The dependency set was frozen against x86-64 wheels. The agent stage carries a pinned arm64 nuclei checksum, but arm64 is not otherwise verified |

With published images (`registry`), the first start takes about **2 minutes**:
roughly 400 MB to download, then about 40 seconds to become ready on a 2-vCPU
machine. Building the images yourself (`build`) takes **5 to 15 minutes** the
first time.

### 3.3 Outbound network, by phase and profile

| When | Destination | Needed for |
|---|---|---|
| `up` with `VEYRS_IMAGE_SOURCE=registry` | `ghcr.io` (VEYRS images), Docker Hub (`postgres`, `redis`) | normal install |
| `up` with `VEYRS_IMAGE_SOURCE=build` | Docker Hub (`python`, `nginx`, `postgres`, `redis`), PyPI | building from source |
| Build of `agent` | Debian package mirrors, `github.com` (the nuclei release zip) | `build` with `--with-agent` / `--all` |
| `up` with `VEYRS_IMAGE_SOURCE=local` | **nothing** | offline bundle (§5.C) |
| `veyrs-setup.sh` | `github.com` / `api.github.com` (release tarball, unless you pass `--source`), Docker's package repository (if it installs Docker) | guided install |
| Run: base profile | **nothing** | — |
| Run: `workers` / `intel` | `services.nvd.nist.gov`, `epss.empiricalsecurity.com`, `www.cisa.gov`, `cwe.mitre.org` (HTTPS) | vulnerability intelligence |
| Run: `workers` / `digest` | your SMTP relay (`VEYRS_SMTP_HOST:VEYRS_SMTP_PORT`) | digest e-mail |
| Run: `agent` | `github.com` (template corpus on first start and on refresh), **every target you allow it to scan** | scanning |

Inbound: only the console port you publish with `VEYRS_HTTP_BIND`.

---

## 4. Quick start

```bash
git clone https://github.com/visionebc/veyrs.git && cd veyrs
docker/veyrs-docker.sh init                   # writes docker/.env (0600), prints the admin login ONCE
docker/veyrs-docker.sh up --with-workers      # pull the published images, start, wait for /readyz
docker/veyrs-docker.sh status                 # health, and what is NOT running
# open http://127.0.0.1:8080 and sign in with the organization, e-mail and password printed by `init`
```

To try it without the multi-hour NVD pull, drop `--with-workers`. Then read
§1.3 before you keep that installation.

For one complete installation with every value filled in, see the worked
example in §5.D.

`init` points the stack at the published images **of the version in the tree**
(`pyproject.toml`). A checkout of a commit between releases has no published
images. `up` then stops and names the fix: set `VEYRS_IMAGE_SOURCE=build` in
`docker/.env`.

---

## 5. Step-by-step installation

There are two ways to install, plus an offline variant of either (§5.C). All of
them end up running the same driver and the same Compose files.
§5.D then walks through one complete installation, from an empty machine to a
restored backup, with every command, every value and the real output.

| | A. The driver (`docker/veyrs-docker.sh`) | B. The guided installer (`veyrs-setup.sh`, Docker mode) |
|---|---|---|
| Installs Docker for you | no | yes, if it is missing |
| Where the code lives | your git checkout | `/opt/veyrs-docker/releases/<version>`, with `current` pointing at it |
| Secrets file | `docker/.env` | `/opt/veyrs-docker/veyrs.env`, symlinked as `current/docker/.env` |
| Admin password | generated and printed once, **kept in `docker/.env`** | typed twice or generated into `/root/veyrs-admin-password.txt` (0600). **Not** kept in the env file |
| External PostgreSQL | you edit the env file (§7) | asked, and the role is **checked and refused** if unsafe |
| Unattended | not applicable | `--yes --answers FILE` |

### 5.A Installing with the driver

#### Step 1: get the source

```bash
git clone https://github.com/visionebc/veyrs.git
cd veyrs
```

#### Step 2: generate the secrets

```bash
docker/veyrs-docker.sh init
```

This copies [`docker/env.example`](../docker/env.example) to `docker/.env`
with mode 0600 and fills in:

| Variable | Generated as |
|---|---|
| `POSTGRES_PASSWORD` | `openssl rand -hex 24` |
| `VEYRS_DB_PASSWORD` | `openssl rand -hex 24` |
| `VEYRS_SECRET_KEY` | 48 random bytes, URL-safe base64 (at least 32 characters are required) |
| `VEYRS_ENCRYPTION_KEY` | a Fernet key: 32 random bytes, URL-safe base64 |
| `VEYRS_ADMIN_PASSWORD` | 18 random bytes, URL-safe base64, **unless** you exported `VEYRS_ADMIN_PASSWORD` before running `init` |
| `VEYRS_IMAGE_SOURCE`, `VEYRS_IMAGE`, `VEYRS_CONSOLE_IMAGE`, `VEYRS_AGENT_IMAGE` | `registry` and `ghcr.io/visionebc/veyrs*:<version of this tree>` |

It then prints the console URL, the administrator login and the organization.
**The password is printed only once.** It stays in `docker/.env`.

`init` **refuses to run if `docker/.env` already exists**. Regenerating
`VEYRS_ENCRYPTION_KEY` against an existing database makes every stored
credential permanently unreadable, so starting over requires deleting the file
yourself, on purpose.

#### Step 3: review the file

Open `docker/.env` and decide at least these values (all are explained in §6):

- `VEYRS_HTTP_BIND`: keep `127.0.0.1:8080` unless you know you need more (§8).
- `VEYRS_ADMIN_ORG` and `VEYRS_ADMIN_EMAIL`: the first organization slug and
  the administrator's e-mail. They are used **once**, on the first `up`.
- `VEYRS_PUBLIC_BASE_URL` and `VEYRS_CORS_ORIGINS`: the address users will type.
- `VEYRS_SMTP_*`: only if you enable `workers` and want mail.

#### Step 4: get the images and start

```bash
docker/veyrs-docker.sh up                  # base only
# or
docker/veyrs-docker.sh up --with-workers   # recommended for anything you keep
```

`up` validates `docker/.env` first. It refuses empty secrets, a
`VEYRS_CONSOLE_IP` outside `VEYRS_SUBNET`, and `VEYRS_ENVIRONMENT=production`
without an `https://` `VEYRS_PUBLIC_BASE_URL`. It then gets the images for the
chosen profiles (pulls, builds or checks them, per `VEYRS_IMAGE_SOURCE`),
starts them, and polls `http://<VEYRS_HTTP_BIND>/readyz`
for up to **180 seconds**. On success it prints the `/healthz` JSON (application
name and version). On timeout it prints `ps` and the last 40 log lines of
`init`, `api` and `console`, and exits 1.

With `VEYRS_IMAGE_SOURCE=build`, arguments after the profile flags go to
`docker compose build`, for example `docker/veyrs-docker.sh up --with-workers --pull`.
With `registry` or `local` they are ignored. The profile flags must come
**first**: the driver stops reading profile flags at the first argument it does
not recognise, so `up --pull --with-workers` passes `--with-workers` to
`docker compose build`, which rejects it.

#### Step 5: sign in

Open `http://127.0.0.1:8080` (or your `VEYRS_HTTP_BIND`). Sign in with the
organization slug, e-mail and password that `init` printed. **Change the
password** once you are in (§9.8).

#### Step 6 (recommended): enable the workers

If you skipped them in step 4:

```bash
docker/veyrs-docker.sh up --with-workers
docker/veyrs-docker.sh logs -f intel       # watch the first sync start
```

The first NVD pull takes hours. The console works throughout.

#### Step 7 (optional): enable the scanner agent

Read §9.11 first. In short:

1. Sign in, open **Settings → Agents**, and mint an agent token.
2. Add both values to `docker/.env`:

   ```ini
   VEYRS_AGENT_TOKEN=<the token you minted>
   VEYRS_AGENT_ALLOW=scanme.example.com,*.lab.example.com,192.0.2.0/24
   ```

3. Start it, repeating any profile that is already running:

   ```bash
   docker/veyrs-docker.sh up --with-workers --with-agent
   ```

`up --with-agent` refuses to start while `VEYRS_AGENT_ALLOW` is empty.

### 5.B Installing with `veyrs-setup.sh` (Docker mode)

`veyrs-setup.sh` is a guided installer for both native and Docker installs. In
Docker mode it installs Docker if necessary, places the release, writes the env
file, checks an external database, runs the driver, and then verifies the
result. It must run as root. Its flags at the time of writing:

| Flag | Meaning |
|---|---|
| *(none)* | interactive |
| `--check` | check this machine only. Changes nothing and writes nothing, not even the log |
| `--yes` | no questions. Every answer comes from a `SETUP_*` variable or its default |
| `--answers FILE` | a `KEY=VALUE` file with the `SETUP_*` answers (use it with `--yes`) |
| `--version X.Y.Z` | the release to install (default: latest) |
| `--source DIR\|TARBALL` | install from a local tree or `veyrs-<ver>-src.tar.gz` (offline). A `TARBALL.sha256` next to it is verified |
| `--images FILE` | Docker mode, **offline**: load `veyrs-images-<ver>-amd64.tar.gz` instead of pulling or building. `FILE.sha256` must sit next to it. It is verified before anything is loaded (§5.C) |
| `--dry-run` | ask the questions, print the plan, and stop before placing the release or writing the env file. It does **not** install anything, not even Docker or the tools the installer itself uses (curl): on a host without Docker it says so and carries on to the plan. Use `--check` for a pure host inspection with no questions |
| `--force` | continue on an unsupported operating system |
| `--uninstall` | remove the Docker install, **keeping** the volumes and the secrets file |
| `--purge` | with `--uninstall`, also delete the volumes, the images and the secrets. You must type `PURGE` |

Interactive:

```bash
curl -fLO https://github.com/visionebc/veyrs/releases/latest/download/veyrs-setup.sh
sudo bash veyrs-setup.sh --check          # see what it would find
sudo bash veyrs-setup.sh                  # answer "docker" at step 4
```

Unattended, with an answers file (the Docker-relevant `SETUP_*` keys):

```ini
# answers.env
SETUP_MODE=docker
SETUP_HTTP_BIND=127.0.0.1:8080
SETUP_PUBLIC_URL=https://veyrs.example.com
SETUP_ENVIRONMENT=production            # requires an https:// SETUP_PUBLIC_URL
SETUP_ORG=acme
SETUP_ADMIN_EMAIL=admin@veyrs.example.com
SETUP_ADMIN_PASSWORD=                   # empty = generate into /root/veyrs-admin-password.txt
SETUP_DB=bundled                        # or external + SETUP_DB_HOST/PORT/NAME/USER/PASSWORD
SETUP_IMAGES=registry                   # or build (from the release source); --images FILE overrides
SETUP_WORKERS=yes
SETUP_AGENT=no                          # yes needs SETUP_AGENT_ALLOW and SETUP_AGENT_TOKEN
SETUP_FIREWALL=no
SETUP_INSTALL_DOCKER=yes
```

```bash
sudo bash veyrs-setup.sh --yes --answers answers.env
```

`SETUP_ORG_NAME` (the organization's display name) is written to
`VEYRS_ADMIN_NAME` in the env file and used when the first organization is
created. Left empty, it defaults to the slug. It may not contain a single quote.

What it leaves behind:

| Path | What |
|---|---|
| `/opt/veyrs-docker/releases/<version>/` | the release tree |
| `/opt/veyrs-docker/current` | symlink to the active release |
| `/opt/veyrs-docker/veyrs.env` | the secrets file (0600), linked as `current/docker/.env`. **Back it up** |
| `/usr/local/sbin/veyrs-docker` | wrapper for `current/docker/veyrs-docker.sh`, e.g. `veyrs-docker status` |
| `/root/veyrs-admin-password.txt` | generated admin password (0600). Delete it after you change the password |
| `/root/veyrs-setup-summary.txt` | the final summary |
| `/etc/veyrs-setup.conf` | install state (0600). A Docker install records `MODE=docker` and `VERSION`. The answers themselves are re-read from the env file |
| `/var/log/veyrs-setup.log` | the install log |

Behaviour worth knowing:

- **Re-running is safe.** It never rotates the admin password, the database
  password, `VEYRS_SECRET_KEY` or `VEYRS_ENCRYPTION_KEY`. On an existing
  install it offers `update`, `reinstall` or `abort`, and reuses every answer
  from the env file, including whether workers and agent were on
  (`VEYRS_SETUP_WORKERS`, `VEYRS_SETUP_AGENT`).
- The admin password reaches the first `up` **through the process
  environment only**. It is not written to the env file and never appears on a
  command line.
- If the agent is requested but the token or allowlist is missing, the install
  completes with the agent **off** and a warning.
- **Images.** It asks *registry* (default) or *build*, then checks with the
  registry that images for that version exist. If they don't (a `--version`
  older than 0.32.4, or no route to `ghcr.io`), it warns and builds from the
  release source instead. On an update it keeps the source the installation
  already uses; an install from before 0.32.4 keeps building unless
  `SETUP_IMAGES=registry` says otherwise. An install that runs offline images
  (`local`) must be given the new bundle with `--images`, and it stops with
  that instruction if you leave it out.
- The final checks are: the console answers 200, unauthenticated
  `/api/v1/assets` answers 401 or 403 (anything else aborts with *"DO NOT
  EXPOSE THIS HOST"*), and, when this run created the administrator, a real
  sign-in with the chosen password. When existing data is found, the
  administrator and its password are left untouched and the sign-in check is
  skipped.

### 5.C Offline installation (no registry, no internet)

You need three things from the release page
(`https://github.com/visionebc/veyrs/releases/tag/v<version>`), copied to the
target host by whatever means you have:

| File | What |
|---|---|
| `veyrs-setup.sh` | the guided installer |
| `veyrs-<version>-src.tar.gz` + `.sha256` | the release tree (compose files, driver, `initdb.d`) |
| `veyrs-images-<version>-amd64.tar.gz` + `.sha256` | the images: `veyrs`, `veyrs-console`, `postgres`, `redis` |

Docker itself must already be installed. On an offline host, the installer
cannot fetch Docker's packages either.

```bash
sha256sum -c veyrs-<version>-src.tar.gz.sha256 veyrs-images-<version>-amd64.tar.gz.sha256
sudo bash veyrs-setup.sh --source veyrs-<version>-src.tar.gz \
                         --images veyrs-images-<version>-amd64.tar.gz
```

Or with the driver from an extracted tree:

```bash
docker/veyrs-docker.sh init
docker/veyrs-docker.sh load veyrs-images-<version>-amd64.tar.gz   # verifies .sha256, then docker load
docker/veyrs-docker.sh up
```

`load` refuses a bundle that has no `.sha256` beside it, or whose checksum does
not match. On a host with no registry to compare against, that checksum is the
only thing showing that these are the published images. After loading, it sets
`VEYRS_IMAGE_SOURCE=local` and points `VEYRS_IMAGE`, `VEYRS_CONSOLE_IMAGE`,
`VEYRS_POSTGRES_IMAGE` and `VEYRS_REDIS_IMAGE` at the loaded tags.
`postgres` and `redis` are referenced **by tag** here, not by digest. An image
that came through `docker save`/`docker load` does not reliably keep its
registry digest, so a digest reference would be refused even though the image
is on the host.

What does not work offline, and why:

- the `workers` profile: NVD, EPSS, KEV and CWE are on the internet. The stack
  runs, but its vulnerability data never refreshes (§1.3);
- the `agent`: its template corpus comes from `github.com`, and it is not in
  the bundle.

### 5.D Worked example: one complete installation, every step and every value

This section is **one real installation**, from an empty machine to a backup
that was restored and a stack that was removed again. The commands and outputs
come from a run on 2026-10-07. Where a command printed hundreds of lines, the
output is shortened, and `…` marks the cut. Generated secrets are replaced by
`<…>` placeholders, because yours will be different.

Use it as a model: change the values in the table below to your own and run the
same commands in the same order. Each step links to the section that explains
the options.

#### The example installation

| Item | Value in this example |
|---|---|
| Operating system | openSUSE Leap 15.6 (the same commands apply to SLES 15) |
| Machine | 4 vCPU, 4 GB RAM, 30 GB disk, x86-64 |
| Docker | Engine 28.5.1-ce, Compose 2.22.0 (distribution packages) |
| VEYRS release | 0.32.4 |
| Install directory | `/opt/veyrs` (the extracted release tree) |
| How the images arrive | the offline bundle from the release page (§5.C). With the registry, only step 7 changes |
| Public address | `https://veyrs.acme.example` (TLS terminated by nginx on the same machine, step 11) |
| Console bind | `127.0.0.1:8080`, loopback only |
| Environment | `production` |
| First organization | slug `acme`, display name `ACME Corp` |
| First administrator | `secops@acme.example`, full name `Alex Morgan` |
| Time zone | `Europe/Zurich` |
| Mail relay | `smtp.acme.example:587`, user `veyrs-mailer`, sender `veyrs@acme.example`, STARTTLS |
| Optional services | `workers` on, `agent` off |
| Backups | `/root/veyrs-backups/` (copy them off the machine afterwards) |

Run every command as `root`. From step 4 onwards they run from `/opt/veyrs`.

#### Step 1: install Docker and the Compose plugin

```bash
zypper --non-interactive install docker docker-compose
systemctl enable --now docker
docker version --format 'Engine {{.Server.Version}}'
docker compose version
```

```
Engine 28.5.1-ce
Docker Compose version 2.22.0
```

On Debian, Ubuntu, RHEL, Rocky or Alma, install Docker Engine and the
`docker-compose-plugin` package from
[Docker's own repository](https://docs.docker.com/engine/install/), or let `veyrs-setup.sh` do it
(§5.B). Compose must be **2.20 or newer**, and `docker-compose` v1 does not work
(§3.1).

Running Docker inside an LXC container needs `nesting=1` (and `keyctl=1` when
unprivileged) on that container. Without them the daemon installs but never
answers.

#### Step 2: download the release and check it

```bash
mkdir -p /root/veyrs-download && cd /root/veyrs-download
V=0.32.4
for f in veyrs-$V-src.tar.gz veyrs-$V-src.tar.gz.sha256 \
         veyrs-images-$V-amd64.tar.gz veyrs-images-$V-amd64.tar.gz.sha256; do
    curl -fsSLO "https://github.com/visionebc/veyrs/releases/download/v$V/$f"
done
sha256sum -c veyrs-$V-src.tar.gz.sha256 veyrs-images-$V-amd64.tar.gz.sha256
```

```
veyrs-0.32.4-src.tar.gz: OK
veyrs-images-0.32.4-amd64.tar.gz: OK
```

| File | Size | What it is |
|---|---|---|
| `veyrs-0.32.4-src.tar.gz` | 5.0 MB | the release tree: `docker/`, the driver, the Compose files, `initdb.d` |
| `veyrs-images-0.32.4-amd64.tar.gz` | 293 MB | the `veyrs`, `veyrs-console`, `postgres` and `redis` images |

Do not continue if a line says anything other than `OK`.

#### Step 3: place the release tree

```bash
mkdir -p /opt/veyrs
tar xzf /root/veyrs-download/veyrs-0.32.4-src.tar.gz -C /opt/veyrs --strip-components=1
cd /opt/veyrs
ls docker
```

```
agent-entrypoint.sh  compose.external-db.yaml  compose.yaml  console.conf  Dockerfile
entrypoint.sh  env.example  initdb.d  init.sh  README.md  tick.sh  veyrs-docker.sh
```

#### Step 4: generate the secrets

```bash
docker/veyrs-docker.sh init
```

```
==> wrote /opt/veyrs/docker/.env (0600) -- images: ghcr.io/visionebc/veyrs*:0.32.4

    console   http://127.0.0.1:8080
    login     admin@veyrs.local / <generated admin password>
    org       veyrs

warning: this is the only time the admin password is printed; it is in /opt/veyrs/docker/.env
```

The login shown here uses the template defaults. Step 5 replaces them before
anything has started, which is allowed: the organization and administrator are
created on the first `up`, not by `init`. The generated password stays.

#### Step 5: set this installation's values in `docker/.env`

Open `docker/.env` in an editor and change these lines. The values on the left
are what `init` wrote:

| Variable | Written by `init` | Set to |
|---|---|---|
| `VEYRS_ADMIN_ORG` | `veyrs` | `acme` |
| `VEYRS_ADMIN_EMAIL` | `admin@veyrs.local` | `secops@acme.example` |
| `VEYRS_ENVIRONMENT` | `development` | `production` |
| `VEYRS_PUBLIC_BASE_URL` | `http://localhost:8080` | `https://veyrs.acme.example` |
| `VEYRS_CORS_ORIGINS` | `http://localhost:8080` | `https://veyrs.acme.example` |
| `TZ` | `UTC` | `Europe/Zurich` |
| `VEYRS_SMTP_HOST` | *(empty)* | `smtp.acme.example` |
| `VEYRS_SMTP_PORT` | `25` | `587` |
| `VEYRS_SMTP_USER` | *(empty)* | `veyrs-mailer` |
| `VEYRS_SMTP_PASSWORD` | *(empty)* | `'Smtp#Example$2026'` (single quotes: the value has `#` and `$`, §6.1) |
| `VEYRS_SMTP_FROM` | *(empty)* | `veyrs@acme.example` |

And add two lines at the end. They are not in the template (§6.3) and are used
only on the first `up`:

```ini
VEYRS_ADMIN_NAME='ACME Corp'
VEYRS_ADMIN_FULL_NAME='Alex Morgan'
```

`production` is accepted here only because `VEYRS_PUBLIC_BASE_URL` is
`https://`. The driver refuses the combination with an `http://` address
(§5.A, step 4).

This is the complete file without its comments, as it stood after step 7. Every
variable the stack reads is in it:

```ini
POSTGRES_PASSWORD=<48 hex characters, generated by init>
VEYRS_DB_USER=veyrs
VEYRS_DB_PASSWORD=<48 hex characters, generated by init>
VEYRS_DB_NAME=veyrs
VEYRS_SECRET_KEY=<64 url-safe characters, generated by init>
VEYRS_ENCRYPTION_KEY=<Fernet key, 44 characters, generated by init>
VEYRS_ADMIN_ORG=acme
VEYRS_ADMIN_EMAIL=secops@acme.example
VEYRS_ADMIN_PASSWORD=<generated admin password, cleared again in step 12>
VEYRS_HTTP_BIND=127.0.0.1:8080
VEYRS_ENVIRONMENT=production
VEYRS_PUBLIC_BASE_URL=https://veyrs.acme.example
VEYRS_CORS_ORIGINS=https://veyrs.acme.example
VEYRS_WORKERS=4
TZ=Europe/Zurich
VEYRS_SUBNET=172.29.0.0/16
VEYRS_CONSOLE_IP=172.29.0.10
VEYRS_SMTP_HOST=smtp.acme.example
VEYRS_SMTP_PORT=587
VEYRS_SMTP_USER=veyrs-mailer
VEYRS_SMTP_PASSWORD='Smtp#Example$2026'
VEYRS_SMTP_FROM=veyrs@acme.example
VEYRS_SMTP_STARTTLS=true
VEYRS_AGENT_TOKEN=
VEYRS_AGENT_ALLOW=
VEYRS_IMAGE_SOURCE=local
VEYRS_IMAGE=ghcr.io/visionebc/veyrs:0.32.4
VEYRS_CONSOLE_IMAGE=ghcr.io/visionebc/veyrs-console:0.32.4
VEYRS_AGENT_IMAGE=ghcr.io/visionebc/veyrs-agent:0.32.4
VEYRS_ADMIN_NAME='ACME Corp'
VEYRS_ADMIN_FULL_NAME='Alex Morgan'
VEYRS_POSTGRES_IMAGE=postgres:15-bookworm
VEYRS_REDIS_IMAGE=redis:7-alpine
```

The file must stay at mode `0600` and owned by root. It holds the database
passwords, the signing key and the encryption key. **Copy it somewhere safe
now**: without `VEYRS_ENCRYPTION_KEY` a database backup cannot be fully used
(§9.9).

#### Step 6: check the configuration before starting anything

Compose renders the files with your values without starting a container. `C` is
the whole-stack variable from the Conventions at the top of this manual:

```bash
C="docker compose --project-directory docker -f docker/compose.yaml --profile workers --profile agent"
$C config --quiet && echo "config OK"
$C config --services
$C config --images | sort -u
$C config | grep -E 'VEYRS_SMTP_PASSWORD|VEYRS_ADMIN_NAME'
```

```
config OK
postgres
redis
init
api
agent
console
digest
intel
ghcr.io/visionebc/veyrs-agent:0.32.4
ghcr.io/visionebc/veyrs-console:0.32.4
ghcr.io/visionebc/veyrs:0.32.4
postgres:15-bookworm@sha256:d4a8e1f88f475ee3e0137fa89d21ebc59f6c6ab16bf369ee92907607cc3455ae
redis:7-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499
      VEYRS_ADMIN_NAME: ACME Corp
      VEYRS_SMTP_PASSWORD: Smtp#Example$$2026
```

The `$$` is how `config` prints a literal `$`. Step 13 shows that the container
receives `Smtp#Example$2026`. A value that went wrong here (a cut-off password,
an unquoted `#`) is far easier to fix now than after the first `up`.

#### Step 7: get the images

This example loads the offline bundle. `load` checks the `.sha256` before
loading anything:

```bash
docker/veyrs-docker.sh load /root/veyrs-download/veyrs-images-0.32.4-amd64.tar.gz
```

```
==> checksum ok (17b61097bd83999f64aa9c9027d4ab709d35d5b3044cb998795647a3c1c9e12d)
Loaded image: postgres:15-bookworm
Loaded image: redis:7-alpine
Loaded image: ghcr.io/visionebc/veyrs:0.32.4
Loaded image: ghcr.io/visionebc/veyrs-console:0.32.4
==> VEYRS_IMAGE_SOURCE=local -- next: docker/veyrs-docker.sh up
```

```bash
docker image ls --format '{{.Repository}}:{{.Tag}}  {{.Size}}'
```

```
ghcr.io/visionebc/veyrs-console:0.32.4  64.6MB
ghcr.io/visionebc/veyrs:0.32.4  284MB
postgres:15-bookworm  436MB
redis:7-alpine  39.1MB
```

`load` switched `docker/.env` to `VEYRS_IMAGE_SOURCE=local` and set the four
image names, as listed in step 5.

**With the registry instead:** skip `load` and leave
`VEYRS_IMAGE_SOURCE=registry`, which is what `init` wrote. Step 8 then pulls
the images itself. **With a build from source:** set
`VEYRS_IMAGE_SOURCE=build`; step 8 then builds them, which takes 5 to 15
minutes (§2.3).

#### Step 8: start the stack

```bash
docker/veyrs-docker.sh up
```

```
==> using the images already on this host (VEYRS_IMAGE_SOURCE=local)
==> starting
 Network veyrs_veyrs  Created
 Volume "veyrs_veyrs-pgdata"  Created
 Volume "veyrs_veyrs-var"  Created
 Container veyrs-redis-1  Created
 Container veyrs-postgres-1  Created
 Container veyrs-init-1  Created
 Container veyrs-api-1  Created
 Container veyrs-console-1  Created
 Container veyrs-postgres-1  Healthy
 Container veyrs-redis-1  Healthy
 Container veyrs-init-1  Exited
 Container veyrs-api-1  Healthy
 Container veyrs-console-1  Started
==> waiting for http://127.0.0.1:8080/readyz
==> ready -- console on http://127.0.0.1:8080
{"status":"ok","app":"VEYRS","version":"0.32.4"}
```

That took **15 seconds**. The start order is §2.2: `postgres` and `redis`
first, then the one-shot `init`, then `api` once `init` has exited
successfully, then `console` once `api` is healthy.

This first `up` starts the base profile only. Step 13 adds the workers.

#### Step 9: read what `init` did

```bash
docker/veyrs-docker.sh logs --no-log-prefix init
```

```
[init] data directory /opt/veyrs/var owned by uid 10001; dropping root
[init] running as uid 10001
[init] applying schema (create tables, reconcile columns, bind RLS, seed)
schema: 87 tables ensured
schema reconcile: 0 columns, 0 indexes, 0 constraints added
row level security: 66 tables strictly isolated, 4 credential-keyed (permissive only while unbound)
builtin roles: 10 created, 0 updated, 10 total
compliance catalogues: 4 frameworks, 85 controls created, 0 updated
[init] creating organization 'acme' and administrator secops@acme.example
organization created: acme (177ba29c-e4a2-4d0d-9934-45da4c96a7e5)
user created: secops@acme.example (7a4b1cd5-9cb3-4f21-b2da-0f204ab1e243)
granted role: org-admin
[init] done
```

The database confirms the result: the display name was taken from
`VEYRS_ADMIN_NAME`, 70 of the 87 tables enforce row level security, and the
application role is not a superuser (§11.1):

```bash
$C exec -T postgres psql -U postgres -d veyrs \
  -c "select slug, name from organizations" \
  -c "select count(*) filter (where relforcerowsecurity) as forced_rls, count(*) as tables
        from pg_class where relkind = 'r' and relnamespace = 'public'::regnamespace" \
  -c "select rolname, rolsuper, rolbypassrls, rolcreatedb, rolcreaterole
        from pg_roles where rolname in ('postgres', 'veyrs')"
```

```
 slug |   name
------+-----------
 acme | ACME Corp

 forced_rls | tables
------------+--------
         70 |     87

 rolname  | rolsuper | rolbypassrls | rolcreatedb | rolcreaterole
----------+----------+--------------+-------------+---------------
 postgres | t        | t            | t           | t
 veyrs    | f        | f            | f           | f
```

#### Step 10: check the running stack

```bash
docker/veyrs-docker.sh ps --format 'table {{.Service}}\t{{.Status}}\t{{.Ports}}'
```

```
SERVICE    STATUS                    PORTS
api        Up 19 seconds (healthy)   8000/tcp
console    Up 14 seconds (healthy)   80/tcp, 127.0.0.1:8080->8080/tcp
postgres   Up 28 seconds (healthy)   5432/tcp
redis      Up 28 seconds (healthy)   6379/tcp
```

Only `127.0.0.1:8080` is published to the host. The `80/tcp` shown for
`console` is a port the nginx base image declares; nothing listens on it and it
is not published.

```bash
docker/veyrs-docker.sh status
```

```
…the same table, with image and command columns…

Images (VEYRS_IMAGE_SOURCE=local):
  ghcr.io/visionebc/veyrs:0.32.4                       0.32.4 @ db9b534beb914364d443aae0487755dddde80715
  ghcr.io/visionebc/veyrs-console:0.32.4               0.32.4 @ db9b534beb914364d443aae0487755dddde80715

{"status":"ok","app":"VEYRS","version":"0.32.4"}

Background work (host equivalent -> this stack):
  intel   NOT running (veyrs-intel-sync.timer) -- enable with `up --with-workers`
     CVE/EPSS/KEV data does not refresh and SLA deadlines do not elapse;
     the platform keeps scoring confidently against intelligence that has
     stopped learning
  digest  NOT running (veyrs-digest.timer) -- enable with `up --with-workers`
     no daily digest mail goes out; the notification rows are still
     written, so nothing is lost -- nobody is told
  agent   NOT running (veyrs-agent.service) -- enable with `up --with-agent`
     no scans run from this node; scan jobs queue and their leases are
     reaped
```

Now the endpoints, and a real sign-in through the API. The password is read
from `docker/.env` so that it never appears on a command line you type:

```bash
B=http://127.0.0.1:8080
for p in / /healthz /readyz /api/v1/assets /docs /metrics; do
    printf '%-16s %s\n' "$p" "$(curl -s -o /dev/null -w '%{http_code}' "$B$p")"
done
curl -s "$B/readyz"; echo

PW=$(sed -n 's/^VEYRS_ADMIN_PASSWORD=//p' docker/.env)
curl -s -X POST "$B/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"organization\":\"acme\",\"email\":\"secops@acme.example\",\"password\":\"$PW\"}"
```

```
/                200
/healthz         200
/readyz          200
/api/v1/assets   401
/docs            404
/metrics         404
{"status":"ok","checks":{"database":"ok","redis":"ok"}}
{"access_token":"<…>","refresh_token":"<…>","token_type":"bearer",
 "expires_at":"2026-10-07T19:43:58.053520Z",
 "organization_id":"177ba29c-e4a2-4d0d-9934-45da4c96a7e5",
 "user_id":"7a4b1cd5-9cb3-4f21-b2da-0f204ab1e243",
 "permissions":["agent:admin","agent:delete", … ,"workflow:write"]}
```

| Check | Expected | Why |
|---|---|---|
| `/api/v1/assets` without a token | `401` | anything else means the API is open. `veyrs-setup.sh` stops with *"DO NOT EXPOSE THIS HOST"* on this |
| `/docs`, `/metrics` | `404` | `production` closes the API explorer, and `/metrics` needs a token |
| the same login with a wrong password | `401` | |
| `GET /api/v1/auth/me` with the access token | `200`, `"full_name":"Alex Morgan"` | the token is accepted, so every API process uses the same `VEYRS_SECRET_KEY` |

#### Step 11: put TLS in front

The stack serves plain HTTP on loopback. The TLS terminator runs on the same
machine (§8). First, the name `veyrs.acme.example` must resolve to this machine
in your DNS.

The certificate: use your real one, for example from your internal CA or ACME.
For a test, a self-signed one will do:

```bash
mkdir -p /etc/ssl/veyrs.acme.example
openssl req -x509 -newkey rsa:2048 -nodes -days 30 \
  -subj "/CN=veyrs.acme.example" -addext "subjectAltName=DNS:veyrs.acme.example" \
  -keyout /etc/ssl/veyrs.acme.example/privkey.pem \
  -out    /etc/ssl/veyrs.acme.example/fullchain.pem
chmod 600 /etc/ssl/veyrs.acme.example/privkey.pem
```

Install nginx (`zypper --non-interactive install nginx`) and create the site.
On SUSE the file goes in `/etc/nginx/vhosts.d/`; on Debian and Ubuntu in
`/etc/nginx/sites-available/` with a link in `sites-enabled/`; on RHEL, Rocky
and Alma in `/etc/nginx/conf.d/`:

```nginx
# /etc/nginx/vhosts.d/veyrs.conf
server {
    listen 443 ssl;
    server_name veyrs.acme.example;

    ssl_certificate     /etc/ssl/veyrs.acme.example/fullchain.pem;
    ssl_certificate_key /etc/ssl/veyrs.acme.example/privkey.pem;

    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 128m;          # the console allows 128 MB (scanner exports, PDFs)

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $remote_addr;   # OVERWRITE, do not append
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;        # matches the console's /api/ timeout
    }
}

server {
    listen 80;
    server_name veyrs.acme.example;
    return 301 https://$host$request_uri;
}
```

```bash
nginx -t && systemctl enable --now nginx
curl -s  -o /dev/null -w 'http  -> %{http_code} %{redirect_url}\n' http://veyrs.acme.example/
curl -sk -o /dev/null -w 'https -> %{http_code}\n'                  https://veyrs.acme.example/
curl -sk https://veyrs.acme.example/readyz; echo
curl -skI https://veyrs.acme.example/ | grep -i strict
```

```
nginx: configuration file /etc/nginx/nginx.conf test is successful
http  -> 301 https://veyrs.acme.example/
https -> 200
{"status":"ok","checks":{"database":"ok","redis":"ok"}}
Strict-Transport-Security: max-age=31536000
```

`-k` is needed only because the test certificate is self-signed. If the
machine runs a firewall, open 80 and 443 and **not** 8080. Port 8080 is bound
to loopback and is not reachable from outside anyway.

#### Step 12: sign in and change the administrator password

Open `https://veyrs.acme.example`. Sign in with organization `acme`, e-mail
`secops@acme.example` and the password from step 4, then change the password
in the console. The same thing through the API, as done in this run:

```bash
B=https://veyrs.acme.example
OLD=$(sed -n 's/^VEYRS_ADMIN_PASSWORD=//p' docker/.env)
NEW='<your new password, at least 12 characters>'
TOKEN=$(curl -sk -X POST "$B/api/v1/auth/login" -H 'Content-Type: application/json' \
  -d "{\"organization\":\"acme\",\"email\":\"secops@acme.example\",\"password\":\"$OLD\"}" \
  | sed -n 's/.*"access_token":"\([^"]*\)".*/\1/p')
curl -sk -o /dev/null -w 'change password -> %{http_code}\n' -X POST "$B/api/v1/auth/password" \
  -H "Authorization: Bearer $TOKEN" -H 'Content-Type: application/json' \
  -d "{\"current_password\":\"$OLD\",\"new_password\":\"$NEW\"}"
```

```
change password -> 204
```

Then remove the first password from the env file. It is not needed any more,
and nobody should find a working password in it:

```bash
sed -i 's/^VEYRS_ADMIN_PASSWORD=.*/VEYRS_ADMIN_PASSWORD=/' docker/.env
```

A later `up` does not touch the new password. The next step's `init` log shows
it:

```
[init] bootstrap not run: secops@acme.example already exists in 'acme'
[init]   (set VEYRS_FORCE_BOOTSTRAP=1 to reset that password on purpose)
```

After that, the old password was refused and the new one accepted.

#### Step 13: turn on the workers

```bash
docker/veyrs-docker.sh up --with-workers
```

```
==> using the images already on this host (VEYRS_IMAGE_SOURCE=local)
==> starting
 Container veyrs-redis-1  Running
 Container veyrs-postgres-1  Running
 Container veyrs-api-1  Running
 Container veyrs-console-1  Running
 Container veyrs-intel-1  Created
 Container veyrs-digest-1  Created
 Container veyrs-init-1  Exited
 Container veyrs-intel-1  Started
 Container veyrs-digest-1  Started
==> ready -- console on http://127.0.0.1:8080
{"status":"ok","app":"VEYRS","version":"0.32.4"}
```

The containers that were already running are left alone. `init` runs again
(it always does on `up`) and finds nothing to do. From now on, **repeat
`--with-workers` on every `up`**, or the workers keep running an old
configuration (§9.4).

The SMTP secret reaches `digest` intact and does not reach `api`, which never
sends mail. `api` does not hold the PostgreSQL superuser password either:

```bash
$C exec -T digest printenv VEYRS_SMTP_PASSWORD
$C exec -T api    printenv VEYRS_SMTP_PASSWORD || echo "(api: not set)"
$C exec -T api    printenv POSTGRES_PASSWORD   || echo "(api: not set)"
```

```
Smtp#Example$2026
(api: not set)
(api: not set)
```

The first tick runs one to ten minutes after the start:

```bash
docker/veyrs-docker.sh logs intel digest
```

```
veyrs-intel-1   | tick[intel]: every 3600s (+0..600s jitter): bash /opt/veyrs/scripts/sync-intel.sh
veyrs-intel-1   | tick[intel]: startup catch-up in 69s
veyrs-intel-1   | tick[intel]: running at 2026-10-07T21:15:56+02:00
veyrs-intel-1   | === schedule 2026-10-07T21:15:56+02:00 ===
veyrs-intel-1   | DUE  cwe   never completed successfully
veyrs-intel-1   | DUE  nvd   never completed successfully
veyrs-intel-1   | DUE  epss  never completed successfully
veyrs-intel-1   | DUE  kev   never completed successfully
veyrs-intel-1   | === run-sla 2026-10-07T21:15:57+02:00 ===
veyrs-intel-1   | acme: checked 0 · warned 0 · breached 0 · escalated 0
veyrs-intel-1   | === done 2026-10-07T21:15:58+02:00, status 0 ===
veyrs-intel-1   | tick[intel]: ok at 2026-10-07T21:15:58+02:00
veyrs-digest-1  | tick[digest]: running at 2026-10-07T21:17:18+02:00
veyrs-digest-1  | tick[digest]: ok at 2026-10-07T21:17:18+02:00
```

> **This log is from 0.32.4, which has a defect fixed in 0.32.5: the feeds
> listed as `DUE` do not run.** Look at the log above: four `DUE` lines, and no
> `=== sync-cwe`, `=== sync-nvd`, `=== sync-epss` or `=== sync-kev` after them.
> From 0.21.0 to 0.32.4, when two or more feeds were due at the same time,
> `scripts/sync-intel.sh` ran none of them and still reported `status 0`. On a
> new installation all four are due, so the vulnerability data was never
> loaded. On 0.32.5 and later the same tick prints a `=== sync-<feed>` section
> for every `DUE` line.
>
> 0.32.4 also could not load NVD at all: `sync-nvd` failed with `value too long
> for type character varying(1000)`, because one NVD record carries a reference
> URL longer than the column that stored it, and that row rolled back the whole
> run. 0.32.5 stores the URL as `TEXT` (an update widens the existing column),
> and a record the database still refuses is now skipped alone: the rest of the
> pull is stored, the record is named in the output, and the command exits 3.
>
> **On 0.32.4, update (step 19).** If you cannot update yet, load the three
> feeds that work by hand:
>
> ```bash
> docker/veyrs-docker.sh cli sync-cwe
> docker/veyrs-docker.sh cli sync-kev
> docker/veyrs-docker.sh cli sync-epss
> ```
>
> ```
> cwe: seen=1450 created=1450 updated=0
> kev: seen=1734 created=0 updated=1734 cve_stubs=0
> epss: rows=384189 seen=384189 created=1444 updated=9967 skipped=372778
> ```
>
> Check where you stand with `docker/veyrs-docker.sh cli intel-due`. A feed
> that has run shows `skip … min since last success`.

#### Step 14 (optional, not run in this example): the scanner agent

The `agent` image is **not** in the offline bundle, because the agent needs the
network to do anything. It comes from the registry or from a build
(`VEYRS_IMAGE_SOURCE=build`). The procedure is §5.A step 7, and the operating
rules are §9.11. With this example's values it would be:

```ini
# docker/.env
VEYRS_AGENT_TOKEN=<minted in the console: Settings → Agents>
VEYRS_AGENT_ALLOW=*.lab.acme.example,192.0.2.0/24
```

```bash
docker/veyrs-docker.sh up --with-workers --with-agent
```

From then on, every `up` needs both flags (or `--all`).

#### Step 15: take a backup and check it

```bash
mkdir -p /root/veyrs-backups && chmod 700 /root/veyrs-backups
docker/veyrs-docker.sh backup /root/veyrs-backups/veyrs-20261007.dump
```

```
==> dumping as the postgres superuser
==> /root/veyrs-backups/veyrs-20261007.dump — 20M, 87 tables with data
```

The verification runs `pg_restore --list` **on the host**, so this machine
needs a PostgreSQL 15+ client. On SUSE, `zypper install postgresql16` provides
it (§10.2).

The dump file is created **world-readable** (`0644`). It contains every
password hash and every encrypted credential, so restrict it, together with the
two other things a restore needs:

```bash
chmod 600 /root/veyrs-backups/veyrs-20261007.dump
cp -p docker/.env /root/veyrs-backups/veyrs.env.20261007          # stays 0600
cd /root/veyrs-backups && docker run --rm -v veyrs_veyrs-var:/data:ro -v "$PWD":/out \
  postgres:15-bookworm tar -czf /out/veyrs-var-20261007.tar.gz -C /data .
chmod 600 /root/veyrs-backups/veyrs-var-20261007.tar.gz
cd /opt/veyrs
```

| File | What | Restore needs it |
|---|---|---|
| `veyrs-20261007.dump` | the database | yes |
| `veyrs.env.20261007` | the secrets, `VEYRS_ENCRYPTION_KEY` above all | yes: the dump's stored credentials are useless without it |
| `veyrs-var-20261007.tar.gz` | evidence, reports and uploaded documents (`veyrs_veyrs-var`) | yes, if anything was uploaded |

Then copy all three **off this machine**. The nightly job is the cron line in
§10.2.

#### Step 16: restore drill

Restore the backup into the same machine, as described in §10.4. **This
deletes the current database.** Run it only with a dump that passed step 15:

```bash
DUMP=/root/veyrs-backups/veyrs-20261007.dump
docker/veyrs-docker.sh down
docker volume rm veyrs_veyrs-pgdata
$C up -d --wait postgres
$C cp "$DUMP" postgres:/var/tmp/veyrs.dump
$C exec -T postgres pg_restore -U postgres -d veyrs /var/tmp/veyrs.dump
$C exec -T postgres rm -f /var/tmp/veyrs.dump
docker run --rm -v veyrs_veyrs-var:/data -v /root/veyrs-backups:/in:ro postgres:15-bookworm \
  tar -xzf /in/veyrs-var-20261007.tar.gz -C /data
docker/veyrs-docker.sh up --with-workers
```

`pg_restore` finished with exit code 0 and no `errors ignored on restore` line.
Then the checks from §10.5:

```bash
$C exec -T postgres psql -U postgres -d veyrs -tAc "select count(*) from pg_tables where schemaname = 'public'"
$C exec -T postgres psql -U postgres -d veyrs -tAc "select count(*) from pg_class where relkind = 'r' and relforcerowsecurity"
$C exec -T postgres psql -U postgres -d veyrs -tAc "select count(*) from users"
```

```
87
70
1
```

The `init` log showed `bootstrap not run`, and the administrator signed in with
the same password as before the restore.

#### Step 17: what happens on a reboot

The machine was rebooted. Nothing was run by hand afterwards:

```bash
docker/veyrs-docker.sh ps --format 'table {{.Service}}\t{{.Status}}'
```

```
SERVICE    STATUS
api        Up 6 seconds (healthy)
console    Up 6 seconds (healthy)
digest     Up 6 seconds
intel      Up 6 seconds
postgres   Up 6 seconds (healthy)
redis      Up 6 seconds (healthy)
```

`/readyz` answered 200 and the administrator could sign in. The stack comes
back by itself because the Docker service is enabled (step 1) and every
long-running service has `restart: unless-stopped` (§9.5). A stack stopped with
`down` stays stopped until the next `up`.

#### Step 18: everyday commands for this installation

Each driver command, and the raw Compose command it runs. Prefer the driver: it
always passes every profile and overlay (§9.10).

| Task | Driver | Raw Compose (`$C` from step 6) |
|---|---|---|
| status, health, what is not running | `docker/veyrs-docker.sh status` | `$C ps`, then `curl -s http://127.0.0.1:8080/healthz` |
| containers | `docker/veyrs-docker.sh ps` | `$C ps` |
| follow logs | `docker/veyrs-docker.sh logs -f api` | `$C logs -f api` |
| apply a change to `docker/.env` | `docker/veyrs-docker.sh up --with-workers` | `docker compose --project-directory docker -f docker/compose.yaml --profile workers up -d --no-build --pull never`. **Not `$C up`**: `$C` names the `agent` profile too, so it would start the scanner |
| restart one service, same configuration | `docker/veyrs-docker.sh restart api` | `$C restart api` |
| stop everything, keep the data | `docker/veyrs-docker.sh down` | `$C down` |
| database shell (app role, RLS applies) | `docker/veyrs-docker.sh psql` | `$C exec postgres sh -lc 'PGPASSWORD=$VEYRS_DB_PASSWORD psql -h 127.0.0.1 -U $VEYRS_DB_USER -d $VEYRS_DB_NAME'` |
| VEYRS command line | `docker/veyrs-docker.sh cli check` | `$C run --rm --no-deps api python -m veyrs.cli check` |
| database backup | `docker/veyrs-docker.sh backup FILE` | `$C exec -T postgres pg_dump -U postgres -d veyrs -Fc > FILE`, then check it with `pg_restore --list` |

`restart` does **not** re-read `docker/.env`. After an edit, use `up` with the
same flags as always (§9.3).

#### Step 19: upgrading this installation (not run in this example)

No later release existed at the time of this run. When one does, the order for
this installation is §9.4:

```bash
cd /opt/veyrs
docker/veyrs-docker.sh backup /root/veyrs-backups/veyrs-before-upgrade.dump    # always first
# download and check the new release as in step 2, then give it its own directory:
N=<new version>
mkdir -p /opt/veyrs-$N
tar xzf /root/veyrs-download/veyrs-$N-src.tar.gz -C /opt/veyrs-$N --strip-components=1
cp -p /opt/veyrs/docker/.env /opt/veyrs-$N/docker/.env                         # the SAME secrets
cd /opt/veyrs-$N
docker/veyrs-docker.sh load /root/veyrs-download/veyrs-images-$N-amd64.tar.gz
docker/veyrs-docker.sh up --with-workers                                       # the same flags as before
docker/veyrs-docker.sh status
```

The Compose project name is fixed in `compose.yaml` (`name: veyrs`), so the new
tree drives the same containers and the same volumes. `up` recreates the
containers on the new images, and `init` brings the schema up to date. The old
directory stays as it was, for a rollback together with the backup. The
tarball never contains a `docker/.env`, which is why it is copied.

With the registry, point the three image names at the new version instead of
running `load`. §9.4 has the `sed` line.

#### Step 20: remove the installation

Stop it and keep the data. The volumes stay, so a later `up` continues where it
stopped:

```bash
docker/veyrs-docker.sh down
docker volume ls --filter label=com.docker.compose.project=veyrs
```

```
DRIVER    VOLUME NAME
local     veyrs_veyrs-agent-home
local     veyrs_veyrs-pgdata
local     veyrs_veyrs-var
```

Remove everything. **This cannot be undone**, so take the backup in step 15
first:

```bash
docker/veyrs-docker.sh down --volumes
docker image rm ghcr.io/visionebc/veyrs:0.32.4 ghcr.io/visionebc/veyrs-console:0.32.4 \
                postgres:15-bookworm redis:7-alpine
rm -rf /opt/veyrs                         # the tree, including docker/.env
```

```
 Volume veyrs_veyrs-pgdata  Removed
 Volume veyrs_veyrs-var  Removed
 Volume veyrs_veyrs-agent-home  Removed
```

In this run `down --volumes` came **after** a plain `down`, and two unnamed
volumes survived it. The `redis` image declares an anonymous volume for
`/data`, and once `down` has removed the containers, nothing links those
volumes to the project any more. To remove everything in one go, run
`down --volumes` on the running stack. To clean up afterwards:

```bash
docker volume prune -f        # unused anonymous volumes only; named volumes are kept
```

```
Deleted Volumes:
de3b9498e1740aed9e5c2f0c3c378dba0ca1ccded1eb55a11cca1e534faf462b
00d0132c4284830cbccb36795836aa0906c648457df2868af73a23a8b1f21558

Total reclaimed space: 0B
```

Afterwards, `docker volume ls` and `docker ps -a` listed nothing. The nginx site
from step 11 and the certificate are yours to remove too. §13 covers both
uninstall paths in more detail.

#### The complete `docker/compose.yaml`

This is the whole file that ran every step above, unchanged from the release.
Every `${…}` in it is filled in from `docker/.env` (step 5). Where a variable
is not set, the default after `:-` applies, and where it is required, the
message after `:?` explains why. `tests/test_docs_worked_example.py` checks that
this copy matches the file byte for byte.

```yaml
# VEYRS — single-node evaluation stack.
#
#   docker/veyrs-docker.sh init     # generate .env with real secrets
#   docker/veyrs-docker.sh up       # build + start + wait for ready
#
# Run it through that wrapper rather than by hand: the build context is the
# repository root (one level up from this file) and there are two images, so
# a bare `docker compose up` from this directory builds the wrong thing.
#
# ===========================================================================
# WHAT THIS STACK IS NOT
# ===========================================================================
# It is NOT the production deployment, and it is not trying to be.
#
# The three background units a host install runs are all present here, behind
# COMPOSE PROFILES, and the split is by blast radius rather than by importance:
#
#   profile `workers`   intel (NVD + EPSS + CISA KEV + SLA) and digest.
#                       Outbound HTTPS and SMTP. Not on by default because a
#                       first `up` would start pulling the NVD corpus -- hours
#                       of it, against a feed that rate-limits per source
#                       address -- on a stack somebody is merely trying out.
#                       WITHOUT THEM THE DATA DOES NOT AGE FORWARD: the
#                       platform keeps scoring confidently against
#                       intelligence that has stopped refreshing, and SLA
#                       deadlines stop elapsing. `veyrs-docker.sh status` says
#                       so out loud from the machine itself.
#
#   profile `agent`     the scanner runner. This one sends unsolicited traffic
#                       to other people's machines. It needs a template
#                       corpus, a network posture that reaches the targets,
#                       and -- for SYN scanning -- NET_RAW. A container given
#                       those is a smaller VM with more steps. It gets an
#                       explicit opt-in and a README paragraph, not a default.
#
#   docker/veyrs-docker.sh up --with-workers        # intel + digest
#   docker/veyrs-docker.sh up --with-workers --with-agent
#
# Production also separates the application and the database onto different
# hosts so the standby pair means something. Collapsing them
# into one compose project is the right trade for evaluation and the wrong one
# for an installation you intend to keep.
#
# ===========================================================================

name: veyrs

# ---------------------------------------------------------------------------
# The environment is its OWN anchor, separate from any service anchor.
#
# Not style: in Compose a service-level `environment:` REPLACES the mapping
# inherited through `<<:` on the service, it does not merge into it. Written
# the obvious way -- one anchor carrying both -- giving `init` its extra
# variables would have DROPPED VEYRS_DATABASE_URL and VEYRS_SECRET_KEY from
# that container, and it would then have fallen back to the defaults in
# config.py: 127.0.0.1:5432 (the init container itself, where nothing listens)
# and a freshly minted random key. Merged at the environment level instead.
# ---------------------------------------------------------------------------
x-veyrs-env: &veyrs-env
  # `postgres` and `redis` are the compose service names. The defaults in
  # config.py are 127.0.0.1, which inside a container is that container -- the
  # app would start, connect to nothing, and log normally.
  VEYRS_DATABASE_URL: postgresql+psycopg://${VEYRS_DB_USER:-veyrs}:${VEYRS_DB_PASSWORD:?VEYRS_DB_PASSWORD is required - run docker/veyrs-docker.sh init}@postgres:5432/${VEYRS_DB_NAME:-veyrs}
  VEYRS_REDIS_URL: redis://redis:6379/0

  # Both refused rather than defaulted, and for different reasons.
  #
  # SECRET_KEY: config.py mints a RANDOM key per process when this is empty.
  # With 4 uvicorn workers that is 4 different signing keys -- a token issued
  # by one worker is rejected by the other three, so most authenticated
  # requests fail intermittently and the failure moves when retried.
  #
  # ENCRYPTION_KEY: the Fernet key for stored credentials (ITSM tokens, LDAP
  # binds, scanner keys). Empty means "derive it from SECRET_KEY", which ties
  # every stored secret to the session key: rotating one silently destroys the
  # other. Generated once by `veyrs-docker.sh init` and kept.
  VEYRS_SECRET_KEY: ${VEYRS_SECRET_KEY:?VEYRS_SECRET_KEY is required - run docker/veyrs-docker.sh init}
  VEYRS_ENCRYPTION_KEY: ${VEYRS_ENCRYPTION_KEY:?VEYRS_ENCRYPTION_KEY is required - run docker/veyrs-docker.sh init}

  VEYRS_ENVIRONMENT: ${VEYRS_ENVIRONMENT:-development}

  # The console is the ONLY hop in front of the API and it is inside this
  # stack, so X-Forwarded-For here is trustworthy. Left at the default of
  # false, ratelimit.py falls back to request.client.host -- which in a
  # container is always the console's address, so all callers share ONE
  # rate-limit bucket and the first busy user locks out everyone else.
  #
  # This is only safe while the api service publishes no port. There is a test.
  VEYRS_TRUST_PROXY_HEADERS: "true"

  # Same-origin: the console proxies /api/ on its own hostname, so CORS is not
  # load bearing for this deployment. Set it only if you put something else in
  # front. The default in config.py is a fleet hostname that means nothing here.
  VEYRS_CORS_ORIGINS: ${VEYRS_CORS_ORIGINS:-http://localhost:8080}
  VEYRS_PUBLIC_BASE_URL: ${VEYRS_PUBLIC_BASE_URL:-http://localhost:8080}

  TZ: ${TZ:-UTC}

# ---------------------------------------------------------------------------
# Least privilege, applied to every VEYRS container.
#
#   no-new-privileges  no process can GAIN privilege through a setuid binary
#                      or file capabilities after start.
#   cap_drop ALL       the API, console, workers and agent need no Linux
#                      capability at all: they run as uid 10001 / 101, bind
#                      ports above 1024 and write only their volumes. (The
#                      agent does not get NET_RAW either -- see below.)
#   read_only          the image filesystem cannot be modified at run time; a
#                      compromised process cannot drop a file next to the code
#                      that the next restart would execute. /tmp is a tmpfs,
#                      and the data lives in named volumes as before.
#
# `init` is the single exception and gets its own, narrower block below.
# Measured, not assumed: scripts/test-docker-stack.sh reads every one of these
# back from `docker inspect`.
# ---------------------------------------------------------------------------
x-hardening: &hardening
  security_opt:
    - "no-new-privileges:true"
  cap_drop:
    - ALL
  read_only: true
  tmpfs:
    - /tmp:size=64m,mode=1777

services:
  # -------------------------------------------------------------------------
  postgres:
    # Pinned by digest (see the Dockerfile header for why). The DISTRIBUTION is
    # pinned too, and on purpose: PostgreSQL text indexes are ordered by the C
    # library's collation rules, and those changed between Debian 12 (glibc
    # 2.36) and Debian 13. Moving an existing data volume to a trixie-based
    # postgres image would leave every text index silently mis-ordered until
    # REINDEX. Bookworm stays until that migration is a documented step.
    image: ${VEYRS_POSTGRES_IMAGE:-postgres:15-bookworm@sha256:d4a8e1f88f475ee3e0137fa89d21ebc59f6c6ab16bf369ee92907607cc3455ae}
    restart: unless-stopped
    # The official image starts as root and switches to `postgres` with gosu,
    # so it keeps its default capabilities; it still cannot gain new ones.
    security_opt:
      - "no-new-privileges:true"
    environment:
      # The SUPERUSER is `postgres`, NOT the application role.
      #
      # Setting POSTGRES_USER=veyrs -- the obvious thing -- makes the
      # application role a superuser, and a PostgreSQL superuser BYPASSES ROW
      # LEVEL SECURITY unconditionally. 70 of VEYRS' 87 tables carry FORCE ROW
      # LEVEL SECURITY; it is what keeps one tenant from reading another's
      # assets and risk entries. Under a superuser every one of those policies
      # silently stops applying: nothing errors, nothing logs, \d still lists
      # them. See initdb.d/10-app-role.sh.
      POSTGRES_USER: postgres
      POSTGRES_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required - run docker/veyrs-docker.sh init}
      POSTGRES_DB: postgres
      # Consumed by initdb.d/10-app-role.sh on the first start only.
      VEYRS_DB_USER: ${VEYRS_DB_USER:-veyrs}
      VEYRS_DB_PASSWORD: ${VEYRS_DB_PASSWORD:?VEYRS_DB_PASSWORD is required}
      VEYRS_DB_NAME: ${VEYRS_DB_NAME:-veyrs}
      TZ: ${TZ:-UTC}
    volumes:
      - veyrs-pgdata:/var/lib/postgresql/data
      # Executed ONLY when PGDATA is empty. Editing this script after the first
      # `up` changes nothing until the volume is destroyed.
      - ./initdb.d:/docker-entrypoint-initdb.d:ro
    # DELIBERATELY NO `ports:`. The database is reachable only on this stack's
    # network; an operator who needs psql goes through veyrs-docker.sh psql.
    networks:
      - veyrs
    healthcheck:
      # A real login as the APPLICATION role into the APPLICATION database.
      #
      # `pg_isready` is not enough: it answers "accepting connections" as soon
      # as the postmaster is listening, which on a first start is BEFORE
      # initdb.d has created the veyrs role. The init service then starts,
      # fails authentication, and the error reads like a wrong password in
      # .env rather than a race. Healthy here means the app can actually get in.
      test: ["CMD-SHELL", "PGPASSWORD=$$VEYRS_DB_PASSWORD psql -h 127.0.0.1 -U $$VEYRS_DB_USER -d $$VEYRS_DB_NAME -c 'SELECT 1' >/dev/null 2>&1"]
      interval: 5s
      timeout: 5s
      retries: 30
      start_period: 30s

  # -------------------------------------------------------------------------
  redis:
    image: ${VEYRS_REDIS_IMAGE:-redis:7-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499}
    restart: unless-stopped
    security_opt:
      - "no-new-privileges:true"
    # Rate-limit counters and short-lived cache only -- derivable state, so no
    # volume: losing it on restart resets a window, it does not lose data.
    #
    # It is still a REQUIRED service, not an optional one: /readyz reports
    # degraded (503) without it, which is the correct signal. Persistence is
    # off for the same reason -- an RDB snapshot of rate-limit counters is
    # write amplification for data that is worthless one minute later.
    command: ["redis-server", "--save", "", "--appendonly", "no"]
    networks:
      - veyrs
    healthcheck:
      test: ["CMD-SHELL", "redis-cli ping | grep -q PONG"]
      interval: 5s
      timeout: 3s
      retries: 12
      start_period: 5s

  # -------------------------------------------------------------------------
  # Schema + first administrator. Runs to completion before `api` starts, on
  # every `up`, and is idempotent -- see docker/init.sh for the guard that
  # stops it from resetting the admin password on every restart.
  init:
    build: &veyrs-build
      # One level up: the Dockerfile copies backend/, frontend/, scripts/ and
      # requirements.txt, none of which are under docker/.
      context: ..
      dockerfile: docker/Dockerfile
      target: api
      # Filled in by veyrs-docker.sh from pyproject.toml and git, so a locally
      # built image says what it is in `status` instead of "dev".
      args:
        VEYRS_VERSION: ${VEYRS_BUILD_VERSION:-dev}
        VEYRS_REVISION: ${VEYRS_BUILD_REVISION:-unknown}
    image: ${VEYRS_IMAGE:-veyrs:local}
    restart: "no"
    # Root, for exactly one reason: named volumes are created EMPTY AND
    # ROOT-OWNED on first `up`, whatever the image did at build time, and the
    # API runs as uid 10001. init.sh chowns /opt/veyrs/var and then re-executes
    # itself as 10001 (setpriv) before touching the database.
    #
    # The capabilities are the five that step needs and no more: CHOWN,
    # DAC_OVERRIDE and FOWNER to take ownership of whatever is in the volume,
    # SETUID and SETGID to give root up. Everything the stock root set adds on
    # top (NET_RAW, MKNOD, SYS_CHROOT, KILL, ...) is gone.
    user: "0:0"
    security_opt:
      - "no-new-privileges:true"
    cap_drop:
      - ALL
    cap_add:
      - CHOWN
      - DAC_OVERRIDE
      - FOWNER
      - SETUID
      - SETGID
    read_only: true
    tmpfs:
      - /tmp:size=64m,mode=1777
    command: ["/opt/veyrs/docker/init.sh"]
    environment:
      <<: *veyrs-env
      # The SUPERUSER credentials go to THIS service and to no other.
      #
      # init.sh needs them to read `users` -- an RLS-forced table -- to decide
      # whether an administrator already exists. The api service never
      # receives them: a long-lived, network-reachable process holding the
      # credentials that bypass tenant isolation is the single worst thing
      # this stack could hand an attacker who finds an SSRF or a template bug.
      VEYRS_DB_HOST: postgres
      VEYRS_DB_PORT: "5432"
      VEYRS_DB_NAME: ${VEYRS_DB_NAME:-veyrs}
      VEYRS_DB_SUPERUSER: postgres
      VEYRS_DB_SUPERUSER_PASSWORD: ${POSTGRES_PASSWORD:?POSTGRES_PASSWORD is required}
      VEYRS_ADMIN_ORG: ${VEYRS_ADMIN_ORG:-veyrs}
      VEYRS_ADMIN_EMAIL: ${VEYRS_ADMIN_EMAIL:-admin@veyrs.local}
      VEYRS_ADMIN_PASSWORD: ${VEYRS_ADMIN_PASSWORD:-}
      VEYRS_ADMIN_NAME: ${VEYRS_ADMIN_NAME:-}
      VEYRS_ADMIN_FULL_NAME: ${VEYRS_ADMIN_FULL_NAME:-}
      VEYRS_FORCE_BOOTSTRAP: ${VEYRS_FORCE_BOOTSTRAP:-0}
    volumes:
      - veyrs-var:/opt/veyrs/var
    depends_on:
      postgres:
        condition: service_healthy
      redis:
        condition: service_healthy
    networks:
      - veyrs
    healthcheck:
      # The image HEALTHCHECK curls :8000. This service does not listen, so it
      # would sit at "starting" and settle on "unhealthy" forever. A health
      # signal that is permanently red for a container doing its job is worse
      # than none: it teaches the operator to ignore the column meant to carry
      # the alarm.
      disable: true

  # -------------------------------------------------------------------------
  api:
    <<: *hardening
    build: *veyrs-build
    image: ${VEYRS_IMAGE:-veyrs:local}
    restart: unless-stopped
    # Larger than the anchor's 64m on purpose: Starlette spools every upload
    # over 1 MB to /tmp, and the console accepts 128 MB (client_max_body_size
    # in console.conf). A /tmp smaller than that turns a large scanner export
    # into "No space left on device". tmpfs only uses memory for what is in it.
    tmpfs:
      - /tmp:size=256m,mode=1777
    environment:
      <<: *veyrs-env
      VEYRS_WORKERS: ${VEYRS_WORKERS:-4}
      # Only the console may be believed about the caller's address. "*" would
      # let anyone who reaches this port claim any source IP; the default of
      # "trust nobody" would make every request look like it came from the
      # console. Pinned to the console's static address below -- which is why
      # that address is static.
      VEYRS_FORWARDED_ALLOW_IPS: ${VEYRS_CONSOLE_IP:-172.29.0.10}
    volumes:
      - veyrs-var:/opt/veyrs/var
    depends_on:
      init:
        condition: service_completed_successfully
    # DELIBERATELY NO `ports:`. The API is reached through `console`.
    #
    # Publishing it would also break VEYRS_TRUST_PROXY_HEADERS above: with the
    # port open, any caller can set X-Forwarded-For and mint a fresh
    # rate-limit identity per request, which turns the credential-stuffing
    # limit on /auth/* into decoration. tests/test_container_stack.py fails if
    # a `ports:` key appears here.
    expose:
      - "8000"

    # NOT pinned to a static address, and that was tried.
    #
    # nginx caches the address it resolves for `proxy_pass` at config load, so
    # a recreated `api` on a new address makes the console serve 502 while both
    # containers still report healthy (see console.conf). Pinning api looked
    # like the tidy fix and broke `docker compose run`, which creates a SECOND
    # container of this service and cannot reuse the address:
    #
    #   Error response from daemon: failed to set up container networking:
    #   Address already in use
    #
    # That is `veyrs-docker.sh cli`, and the tenant-isolation assertions in
    # scripts/test-docker-stack.sh, both gone. The stale-upstream problem is
    # solved in nginx instead, where it belongs.
    networks:
      - veyrs

  # -------------------------------------------------------------------------
  console:
    <<: *hardening
    build:
      <<: *veyrs-build
      target: console
    image: ${VEYRS_CONSOLE_IMAGE:-veyrs-console:local}
    restart: unless-stopped
    # nginx's temp/cache tree, on top of the /tmp the hardening block gives.
    # `tmpfs` here REPLACES the anchor's list rather than extending it, so /tmp
    # is repeated.
    tmpfs:
      - /tmp:size=64m,mode=1777
      - /var/cache/nginx:size=64m,uid=101,gid=101,mode=0700
    depends_on:
      api:
        # Not service_started: nginx resolves `api` at config load and exits
        # with "host not found in upstream" if the container is not up yet,
        # and a restart loop there looks like a broken config file.
        condition: service_healthy
    ports:
      # Bound to LOOPBACK by default. An evaluation stack that arrives
      # listening on every interface is a VEYRS console -- an operator surface
      # with a login form -- published to the local network by an operator who
      # only meant to try it. Override VEYRS_HTTP_BIND deliberately.
      #
      # Container side 8080: the console runs as uid 101 (Dockerfile).
      - "${VEYRS_HTTP_BIND:-127.0.0.1:8080}:8080"
    networks:
      veyrs:
        # STATIC, because VEYRS_FORWARDED_ALLOW_IPS above matches an exact
        # address. A dynamic address means uvicorn stops believing its own
        # proxy after any recreate that reorders container startup -- and it
        # fails quietly: every user lands in one rate-limit bucket and every
        # audit entry records the proxy as the actor.
        ipv4_address: ${VEYRS_CONSOLE_IP:-172.29.0.10}

  # -------------------------------------------------------------------------
  # intel — what veyrs-intel-sync.timer does on a host. Profile: workers.
  intel:
    <<: *hardening
    profiles: ["workers"]
    build: *veyrs-build
    image: ${VEYRS_IMAGE:-veyrs:local}
    restart: unless-stopped
    # It runs scripts/sync-intel.sh -- THE SAME SCRIPT the host timer runs,
    # not a re-implementation of it.
    #
    # That matters more than it looks. The script carries the feed ORDER (CWE
    # names what NVD creates; EPSS skips CVEs it has never seen; KEV is the
    # last word), the per-feed isolation that keeps a failed EPSS from
    # cancelling KEV, and the SLA sweep that must run even on a tick where no
    # feed was due. Spelling that out again as a compose `command` would be
    # the same ladder written twice, and the copy that drifts is always the
    # one nobody runs by hand. scripts/sync-intel.sh resolves its own root and
    # interpreter so that it works here with no venv and no .env.
    #
    # 3600s, because the host unit is OnCalendar=hourly -- and for the same
    # reason: THE TICK IS NOT THE SCHEDULE. The cadence lives in
    # organizations.settings.intel_schedule and `veyrs intel-due` decides
    # which feeds have actually come due. 600s of jitter matches
    # RandomizedDelaySec on the host unit: NVD rate-limits per source address.
    command: ["/opt/veyrs/docker/tick.sh", "intel", "3600", "600",
              "bash", "/opt/veyrs/scripts/sync-intel.sh"]
    environment:
      <<: *veyrs-env
    volumes:
      - veyrs-var:/opt/veyrs/var
    depends_on:
      init:
        condition: service_completed_successfully
    networks:
      - veyrs
    healthcheck:
      # Same reasoning as `init`: this container opens no port, so the image's
      # /readyz probe would be permanently red for a process doing its job.
      disable: true

  # -------------------------------------------------------------------------
  # digest — what veyrs-digest.timer does on a host. Profile: workers.
  digest:
    <<: *hardening
    profiles: ["workers"]
    build: *veyrs-build
    image: ${VEYRS_IMAGE:-veyrs:local}
    restart: unless-stopped
    # Hourly tick again, and again NOT a schedule: the hour lives in
    # organizations.settings.digest and `services.digest.due_now` refuses a
    # run that already went out inside the last twelve hours. Pinning 07:00
    # here would make the console's setting decorative.
    #
    # 300s of jitter, matching the host unit -- and there it is not for rate
    # limiting: it keeps the digest off the exact minute the intel sync
    # starts, so a fanned-out mail run and an NVD pull are not competing for
    # the same single-core container.
    command: ["/opt/veyrs/docker/tick.sh", "digest", "3600", "300",
              "bash", "/opt/veyrs/scripts/send-digest.sh"]
    environment:
      <<: *veyrs-env
      # Without a host the digest has nowhere to go. Left empty it is not an
      # error: `veyrs digest` writes the notification rows either way, and the
      # next tick retries the transport. Set these to actually deliver mail.
      VEYRS_SMTP_HOST: ${VEYRS_SMTP_HOST:-}
      VEYRS_SMTP_PORT: ${VEYRS_SMTP_PORT:-25}
      VEYRS_SMTP_USER: ${VEYRS_SMTP_USER:-}
      VEYRS_SMTP_PASSWORD: ${VEYRS_SMTP_PASSWORD:-}
      VEYRS_SMTP_FROM: ${VEYRS_SMTP_FROM:-}
      VEYRS_SMTP_STARTTLS: ${VEYRS_SMTP_STARTTLS:-true}
    volumes:
      - veyrs-var:/opt/veyrs/var
    depends_on:
      init:
        condition: service_completed_successfully
    networks:
      - veyrs
    healthcheck:
      disable: true

  # -------------------------------------------------------------------------
  # agent — the scanner runner. Profile: agent. READ docker/README.md FIRST.
  agent:
    <<: *hardening
    profiles: ["agent"]
    build:
      <<: *veyrs-build
      target: agent
    image: ${VEYRS_AGENT_IMAGE:-veyrs-agent:local}
    restart: unless-stopped
    environment:
      # Straight to the API on the stack network, not through the console:
      # this is machine-to-machine traffic and there is no reason to put an
      # nginx hop in it. The agent sends no X-Forwarded-For, so uvicorn --
      # which is pinned to believe only the console's address -- correctly
      # rate-limits it as itself.
      VEYRS_URL: ${VEYRS_AGENT_URL:-http://api:8000}

      # NOT `${VEYRS_AGENT_TOKEN:?...}`, deliberately.
      #
      # Compose interpolates the WHOLE file when it loads it, profiles or not.
      # A required-variable marker here would make every `up`, `ps`, `logs`
      # and `down` of the base stack fail for a service the operator never
      # asked to run. The guard belongs where it already is: veyrs_agent.py
      # refuses to start without VEYRS_URL, VEYRS_AGENT_TOKEN and a non-empty
      # VEYRS_AGENT_ALLOW, and repeating it here would be a second copy to
      # drift. Mint the token in the console: Settings -> Agents.
      VEYRS_AGENT_TOKEN: ${VEYRS_AGENT_TOKEN:-}

      # Deny-by-default, enforced by the agent itself: an empty allowlist
      # means NOTHING is scannable, not everything. This is defence in depth
      # against a compromised or spoofed server handing out targets -- the
      # operator of the machine decides what it may point at, and that
      # decision does not live on the server.
      VEYRS_AGENT_ALLOW: ${VEYRS_AGENT_ALLOW:-}
      VEYRS_AGENT_POLL: ${VEYRS_AGENT_POLL:-5}
      VEYRS_AGENT_JOB_TIMEOUT: ${VEYRS_AGENT_JOB_TIMEOUT:-1800}
      TZ: ${TZ:-UTC}
    volumes:
      # The ~84 MB nuclei corpus, in a volume rather than an image layer.
      # Templates change daily: baked in, a container up for a month scans
      # with a month-old corpus and says nothing about it. Seeded on first
      # start by docker/agent-entrypoint.sh, which REFUSES TO START if the
      # corpus is empty -- a nuclei with no templates does not error, it
      # reports a clean scan for every asset it is handed.
      - veyrs-agent-home:/opt/veyrs/agent-home
    depends_on:
      api:
        condition: service_healthy
    networks:
      - veyrs
    # SIGINT, not SIGTERM: veyrs_agent.py exits 0 on KeyboardInterrupt, so
    # this is its graceful stop. The host unit sets the same KillSignal for
    # the same reason. A job in flight is abandoned either way and its lease
    # is collected by POST /api/v1/agents/maintenance/reap.
    stop_signal: SIGINT
    stop_grace_period: 60s

    # NET_RAW is NOT granted.
    #
    # It is what nmap needs for SYN scanning, and it is also the capability
    # that lets a process forge packets on the stack network. Connect-scan
    # works without it. Uncomment only if you have decided that this container
    # is allowed to do that, and know that it stops being meaningfully
    # confined at that point:
    #
    # cap_add:
    #   - NET_RAW

networks:
  veyrs:
    driver: bridge
    ipam:
      config:
        # Pinned so the console's static address above is allocatable. Change
        # both together, or neither.
        - subnet: ${VEYRS_SUBNET:-172.29.0.0/16}

volumes:
  # The cluster. Destroying this destroys the installation -- `down -v` is not
  # a restart.
  veyrs-pgdata:
  # Evidence files, generated reports and uploaded documents: the only thing
  # the application writes outside the database.
  veyrs-var:
  # The scanner agent's HOME: nuclei's config, cache and ~84 MB template
  # corpus. Created only when the `agent` profile is used. Deleting it is not
  # destructive -- the next start re-downloads the corpus -- but the first
  # start after that is several minutes of GitHub traffic.
  veyrs-agent-home:
```

---

## 6. Configuration reference

### 6.1 How configuration reaches the containers

- The driver runs Compose with `--project-directory docker`, so Compose reads
  **`docker/.env`** for `${VARIABLE}` interpolation. This is **not** the
  repository-root `.env.example`, which belongs to the host install. Do not mix
  them.
- **Only the variables named in `compose.yaml` reach the containers.** A line
  such as `VEYRS_NVD_API_KEY=…` added to `docker/.env` is silently ignored,
  because no service's `environment:` mentions it. To pass anything else, use a
  local overlay (§6.5).
- Changing `docker/.env` affects containers **only when they are recreated**:
  run `docker/veyrs-docker.sh up …`, not `restart` (§9.3).
- Compose interpolates `$` in unquoted values and treats ` #` as the start of
  a comment. Wrap a value containing `$`, `#` or spaces in **single quotes**,
  which is how `veyrs-setup.sh` writes passwords. A single quote inside a value
  is not supported.

### 6.2 Variables in `docker/env.example`

| Variable | Meaning | Default | Required | Security note |
|---|---|---|---|---|
| `POSTGRES_PASSWORD` | Password of the PostgreSQL **superuser** `postgres`. Used by the cluster and by `init` (to read the RLS-forced `users` table) | generated by `init` | **yes**: Compose refuses to start without it | Reaches `postgres` and `init` **only**. `api` never receives it. Applied only when the cluster is first created (§9.9) |
| `VEYRS_DB_USER` | Application role name | `veyrs` | no | Created `NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS` (§11.1). Used only when the cluster is first created |
| `VEYRS_DB_PASSWORD` | Application role password | generated | **yes** | Used in `VEYRS_DATABASE_URL` for every app container. Changing it later needs an `ALTER ROLE` (§9.9) |
| `VEYRS_DB_NAME` | Application database. A second database `<name>_test` is created next to it | `veyrs` | no | Both are owned by the app role, with `PUBLIC` access revoked |
| `VEYRS_SECRET_KEY` | Session and JWT signing key | generated (64 characters) | **yes**, at least 32 characters | **Empty is dangerous, not a default.** Each process would mint its own random key, and with 4 workers, 3 of every 4 authenticated requests fail intermittently. Compose and the API entrypoint (exit 78) both refuse it |
| `VEYRS_ENCRYPTION_KEY` | Fernet key for credentials at rest (ITSM tokens, LDAP binds, scanner keys) | generated | **yes** | **Never rotate or lose it.** There is no re-encryption path: the stored credentials become unreadable forever. Back it up **with** the database |
| `VEYRS_ADMIN_ORG` | Slug of the first organization | `veyrs` | no | Used only when no administrator exists |
| `VEYRS_ADMIN_EMAIL` | First administrator's e-mail | `admin@veyrs.local` | no | Same |
| `VEYRS_ADMIN_PASSWORD` | First administrator's password, at least 12 characters | generated by the driver's `init`; **left empty** by `veyrs-setup.sh` | only on the **first** `up` against an empty database | Changing it later does **not** change the password (§9.8). If it is empty and no administrator exists, `init` exits 78 |
| `VEYRS_HTTP_BIND` | Where the console is published, as `ADDRESS:PORT` | `127.0.0.1:8080` | no | Loopback by default. `0.0.0.0:…` publishes a login form on every interface, and **Docker-published ports bypass ufw and firewalld rules** |
| `VEYRS_ENVIRONMENT` | `development` or `production` (the application also knows `staging`) | `development` | no | `production` closes `/docs` and `/redoc`, refuses `/metrics` without a token, and requires an `https://` public URL. The driver checks that before starting |
| `VEYRS_PUBLIC_BASE_URL` | External base URL used in links (e-mails, digests) | `http://localhost:8080` | no | Must be `https://` in production. With a TLS proxy it is the proxy's address |
| `VEYRS_CORS_ORIGINS` | Allowed browser origins, comma-separated | `http://localhost:8080` | no | The console is same-origin, so this only matters if another front end calls the API |
| `VEYRS_WORKERS` | uvicorn processes in `api` | `4` | no | See the connection arithmetic in §9.6 |
| `TZ` | Container time zone (log timestamps) | `UTC` | no | The intel and digest cadence is configured in the console, not here |
| `VEYRS_SUBNET` | Stack network subnet | `172.29.0.0/16` | no | Change it together with `VEYRS_CONSOLE_IP`, for example if it overlaps a LAN or VPN route |
| `VEYRS_CONSOLE_IP` | Static console address. uvicorn trusts `X-Forwarded-For` from this address only | `172.29.0.10` | no | Must lie inside `VEYRS_SUBNET` (the driver checks this) |
| `VEYRS_SMTP_HOST` | SMTP relay for the digest | empty (no mail sent; rows are still written) | no | Passed to `digest` **only** |
| `VEYRS_SMTP_PORT` | SMTP port | `25` | no | — |
| `VEYRS_SMTP_USER` | SMTP username | empty | no | — |
| `VEYRS_SMTP_PASSWORD` | SMTP password | empty | no | Secret. `docker/.env` is 0600 |
| `VEYRS_SMTP_FROM` | Sender address | empty in this stack | no | Set it. An empty sender is rejected by most relays |
| `VEYRS_SMTP_STARTTLS` | Use STARTTLS | `true` | no | Keep it `true` across untrusted networks |
| `VEYRS_AGENT_TOKEN` | Agent credential, minted in **Settings → Agents** | empty | **yes for `agent`** | A credential on the agent data plane. The agent exits 2 without it |
| `VEYRS_AGENT_ALLOW` | Local scan allowlist: hosts, `*.wildcards`, CIDRs, comma-separated | empty = **nothing** is scannable | **yes for `agent`** | Deny by default. The machine's operator decides what may be scanned, whatever the server asks for |

### 6.3 Variables not listed in `env.example`

These are read by the Compose files, by the driver or by `veyrs-setup.sh`. Add
them to `docker/.env` yourself when you need them.

| Variable | Meaning | Default | Notes |
|---|---|---|---|
| `VEYRS_COMPOSE_OVERLAYS` | Extra Compose files, as **space-separated file names** that must exist inside `docker/` (no paths). Read by the driver, not by Compose | empty | The driver passes them to **every** verb. `veyrs-setup.sh` sets `compose.external-db.yaml` for an external database. Do not separate names with commas: the driver deletes commas, so `a.yaml,b.yaml` becomes the single, non-existent name `a.yamlb.yaml` |
| `VEYRS_EXT_DATABASE_URL` | `postgresql+psycopg://USER:PASSWORD@HOST:PORT/DB`, with user and password **percent-encoded** | — | Required with `compose.external-db.yaml` (§7) |
| `VEYRS_EXT_DB_HOST` | External server, as seen **from a container** | — | Required with the overlay. For a server on the Docker host, use `host.docker.internal` |
| `VEYRS_EXT_DB_PORT` | External server port | `5432` | — |
| `VEYRS_IMAGE_SOURCE` | `registry`, `build` or `local` (§2.3) | `build` when absent | `init` and `veyrs-setup.sh` write `registry`; `load` writes `local` |
| `VEYRS_IMAGE` | Image for api, init, intel and digest | `veyrs:local` | `init`: `ghcr.io/visionebc/veyrs:<version>`. `veyrs-setup.sh` with `build`: `veyrs:<version>` |
| `VEYRS_CONSOLE_IMAGE` | Console image | `veyrs-console:local` | as above, `veyrs-console` |
| `VEYRS_POSTGRES_IMAGE` | Override for the bundled database image | the digest-pinned `postgres:15-bookworm@sha256:…` in `compose.yaml` | set only by `load` (a tag). Do not move an existing volume to another major version or distribution |
| `VEYRS_REDIS_IMAGE` | Override for the Redis image | the digest-pinned `redis:7-alpine@sha256:…` | set only by `load` |
| `VEYRS_AGENT_IMAGE` | Agent image | `veyrs-agent:local` | as above, `veyrs-agent` |
| `VEYRS_ADMIN_NAME` | Display name of the first organization (`bootstrap --name`) | slug, title-cased | First `up` only |
| `VEYRS_ADMIN_FULL_NAME` | Administrator's full name (`bootstrap --full-name`) | local part of the e-mail | First `up` only |
| `VEYRS_FORCE_BOOTSTRAP` | `1` resets the administrator's password to `VEYRS_ADMIN_PASSWORD` on the next `up` | `0` | Set it back to `0` afterwards (§9.8) |
| `VEYRS_AGENT_URL` | API address the agent calls | `http://api:8000` | Direct to `api`, not through the console |
| `VEYRS_AGENT_POLL` | Agent poll interval, in seconds | `5` | — |
| `VEYRS_AGENT_JOB_TIMEOUT` | Maximum job runtime, in seconds | `1800` | — |
| `VEYRS_SETUP_WORKERS`, `VEYRS_SETUP_AGENT` | Bookkeeping by `veyrs-setup.sh` (`yes`/`no`) | — | Not read by Compose. They decide which flags a re-run passes to `up` |

### 6.4 Values fixed by `compose.yaml` (not configurable in `.env`)

| Variable in the containers | Value | Why |
|---|---|---|
| `VEYRS_DATABASE_URL` | `postgresql+psycopg://${VEYRS_DB_USER}:${VEYRS_DB_PASSWORD}@postgres:5432/${VEYRS_DB_NAME}` (or `VEYRS_EXT_DATABASE_URL`) | The application's built-in default is `127.0.0.1`, which inside a container is the container itself |
| `VEYRS_REDIS_URL` | `redis://redis:6379/0` | Same reason |
| `VEYRS_TRUST_PROXY_HEADERS` | `true` | The console is the only hop in front of `api`. Without it, every caller shares **one** rate-limit bucket (the console's address) |
| `VEYRS_FORWARDED_ALLOW_IPS` (api) | `$VEYRS_CONSOLE_IP` | uvicorn believes proxy headers only from the console |

### 6.5 Passing other settings: a local overlay

Settings such as `VEYRS_NVD_API_KEY` (raises NVD's rate limit),
`VEYRS_METRICS_TOKEN`, a larger `max_connections`, or a resolver file for the
agent need a Compose overlay. Put the file **in `docker/`** and list it in
`docker/.env`:

```yaml
# docker/compose.local.yaml
services:
  api:
    environment:
      VEYRS_NVD_API_KEY: ${VEYRS_NVD_API_KEY:-}
      VEYRS_METRICS_TOKEN: ${VEYRS_METRICS_TOKEN:-}
  intel:
    environment:
      VEYRS_NVD_API_KEY: ${VEYRS_NVD_API_KEY:-}
```

```ini
# docker/.env
VEYRS_COMPOSE_OVERLAYS=compose.local.yaml
VEYRS_NVD_API_KEY=<your key>
```

Combine overlays with a space (not a comma): `VEYRS_COMPOSE_OVERLAYS=compose.external-db.yaml compose.local.yaml`.
Check the merged result before you start anything:

```bash
docker compose --project-directory docker -f docker/compose.yaml -f docker/compose.local.yaml \
  --profile workers config | grep NVD_API_KEY
```

The driver refuses an overlay name that contains `/` or does not exist in
`docker/`.

---

## 7. Using an external PostgreSQL

Use an external PostgreSQL when you already run a managed or replicated
PostgreSQL and want VEYRS's data there, not in a volume on the Docker host.
Redis stays inside the stack.

### 7.1 Requirements for the server

| Requirement | Why |
|---|---|
| PostgreSQL **15 or newer** | `veyrs-setup.sh` refuses older servers |
| A **dedicated** role: `NOSUPERUSER`, `NOBYPASSRLS` | Tenant isolation depends on it (§7.3) |
| The role **owns** the database | `init-db` runs `ALTER TABLE … FORCE ROW LEVEL SECURITY` and `CREATE POLICY`, which only the owner may do. A role with plain `CONNECT`/`CREATE` gets through table creation, then fails on the first `ALTER`, leaving tables without policies |
| Database encoding **UTF8** | Advisories arrive in five languages. `SQL_ASCII` accepts any byte and corrupts them without an error |
| `pg_hba.conf` admits the connection with a password method | See §7.4 |

### 7.2 Create the role and database

Run this as the server's superuser, and choose a strong password:

```sql
CREATE ROLE veyrs LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS
    PASSWORD 'CHANGE-ME-long-random-password';
CREATE DATABASE veyrs OWNER veyrs ENCODING 'UTF8' TEMPLATE template0;
REVOKE ALL ON DATABASE veyrs FROM PUBLIC;
```

`REVOKE … FROM PUBLIC` matches what the bundled cluster does. Without it, any
role that can log in can connect to the database.

Verify it. Connect **as the `veyrs` role** to the `veyrs` database and run the
same query `veyrs-setup.sh` uses:

```sql
SELECT r.rolsuper, r.rolbypassrls,
       pg_get_userbyid(d.datdba) = current_user AS owns_db,
       pg_encoding_to_char(d.encoding)          AS encoding,
       current_setting('server_version_num')::int AS server_version
FROM pg_roles r, pg_database d
WHERE r.rolname = current_user AND d.datname = current_database();
```

The expected result is `f | f | t | UTF8 | 150000` or higher.

### 7.3 Why a superuser silently disables tenant isolation

VEYRS keeps tenants apart with PostgreSQL **row level security**. 70 of its 87
tables carry `FORCE ROW LEVEL SECURITY`, and every query is filtered to the
tenant bound to the session. A PostgreSQL **superuser**, or any role with
**`BYPASSRLS`**, skips every policy **unconditionally**. Nothing errors and
nothing is logged. `\d` still lists the policies. The application works, and
every tenant can read every other tenant's assets, findings and risk entries.

This is why the obvious shortcuts are wrong: `POSTGRES_USER=veyrs` in the
bundled stack, or pointing VEYRS at the `postgres` account of an existing
server. `veyrs-setup.sh` checks `rolsuper` and `rolbypassrls` through the
stack's own network path and **refuses to continue**. If you configure the
overlay by hand (§7.5), you are the check.

`FORCE` (as opposed to plain `ENABLE`) matters because the application role
owns every table. Plain RLS exempts the owner, and `FORCE` removes that
exemption.

### 7.4 Network path and `pg_hba.conf`

- **Database on another host.** Containers reach it through the Docker host's
  outbound NAT, so the server sees the **Docker host's address**. Admit that
  address:

  ```
  # pg_hba.conf on db.internal.example
  host  veyrs  veyrs  198.51.100.20/32  scram-sha-256
  ```

- **Database on the Docker host itself.** Use `VEYRS_EXT_DB_HOST=host.docker.internal`
  (the overlay maps it to the host gateway). PostgreSQL must listen on the
  Docker bridge address, not only on `localhost` (`listen_addresses`), and
  `pg_hba.conf` must admit the stack subnet (`VEYRS_SUBNET`, default
  `172.29.0.0/16`). `localhost` inside a container is the container.

### 7.5 Configure the stack

**With `veyrs-setup.sh`:** answer `external` at the database question, or set
`SETUP_DB=external` and `SETUP_DB_HOST/PORT/NAME/USER/PASSWORD`. It writes
every variable below, percent-encodes the URL, and checks the role before
anything starts.

**By hand:** after `docker/veyrs-docker.sh init`, edit `docker/.env`:

```ini
VEYRS_COMPOSE_OVERLAYS=compose.external-db.yaml
VEYRS_EXT_DB_HOST=db.internal.example
VEYRS_EXT_DB_PORT=5432
VEYRS_DB_USER=veyrs
VEYRS_DB_NAME=veyrs
VEYRS_DB_PASSWORD='CHANGE-ME-long-random-password'
# user and password PERCENT-ENCODED: @ → %40, : → %3A, / → %2F, % → %25 …
VEYRS_EXT_DATABASE_URL=postgresql+psycopg://veyrs:CHANGE-ME-long-random-password@db.internal.example:5432/veyrs
```

`POSTGRES_PASSWORD` must still be non-empty, because the driver checks it, but
it is unused in this mode.

**Check the role before the first `up`.** The driver does **not** refuse a
superuser or `BYPASSRLS` role; only `veyrs-setup.sh` does. Run the same check
from the stack network (the path the API will use), with the values from
`docker/.env`:

```bash
C="docker compose --project-directory docker -f docker/compose.yaml -f docker/compose.external-db.yaml --profile workers --profile agent"
$C run --rm --no-deps -T --entrypoint sh postgres -c \
  'PGPASSWORD="$VEYRS_DB_PASSWORD" psql -h "$VEYRS_EXT_DB_HOST" -p "$VEYRS_EXT_DB_PORT" -U "$VEYRS_DB_USER" -d "$VEYRS_DB_NAME" -XtA \
   -c "select rolsuper, rolbypassrls from pg_roles where rolname = current_user"'
```

The answer must be `f|f`. If either value is `t`, **stop**: starting VEYRS on
that role switches off tenant isolation without any error. Create a dedicated
role (§7.2) instead. When the answer is `f|f`, run `docker/veyrs-docker.sh up`
as usual.

### 7.6 What changes with the overlay

| Aspect | Bundled | External (`compose.external-db.yaml`) |
|---|---|---|
| `postgres` service | the cluster | **a probe**: `sleep infinity`, and its health check is a real login into the external database as the app role, so `init` still starts only when the database accepts the app |
| `veyrs_veyrs-pgdata` volume | the database | declared but stays empty |
| `init` admin-existence check | as the superuser | as the **application role** (`users` is readable before a tenant is bound, the same property login relies on) |
| `docker/veyrs-docker.sh psql` | bundled cluster | the external database, as the app role |
| `docker/veyrs-docker.sh backup` | full dump | **refused**. Back the database up where it lives (§10.6) |
| `<name>_test` database | created | not created |

Removing the `postgres` service entirely would need `!reset`, which requires
Compose 2.24.4 or newer, and some supported distributions ship older Compose.
That is why it stays as a probe.

---

## 8. TLS and a reverse proxy in front

The stack serves **plain HTTP** and sends no HSTS header. This is deliberate:
HSTS from `http://localhost:8080` would pin `localhost` to HTTPS for a year for
every project on that machine. TLS belongs to whatever you put in front.

### 8.1 Rules

1. **Keep the console on loopback** (`VEYRS_HTTP_BIND=127.0.0.1:8080`) and run
   the TLS proxy on the same host. Ports that Docker publishes on `0.0.0.0`
   **bypass ufw and firewalld rules**.
2. **Never publish the `api` port.** `api` has no `ports:` key on purpose, and
   `tests/test_container_stack.py` fails if one appears. Trusting
   `X-Forwarded-For` is safe only because nothing but the console can reach
   `api`.
3. The proxy must **overwrite** `X-Forwarded-For` with the real client address,
   not append to it (§8.3).
4. Set these values in `docker/.env`, then run `docker/veyrs-docker.sh up …`:

   ```ini
   VEYRS_PUBLIC_BASE_URL=https://veyrs.example.com
   VEYRS_CORS_ORIGINS=https://veyrs.example.com
   VEYRS_ENVIRONMENT=production      # optional; requires the https URL above
   ```

### 8.2 Example: nginx on the Docker host

```nginx
server {
    listen 443 ssl;
    server_name veyrs.example.com;

    ssl_certificate     /etc/ssl/veyrs.example.com/fullchain.pem;
    ssl_certificate_key /etc/ssl/veyrs.example.com/privkey.pem;

    add_header Strict-Transport-Security "max-age=31536000" always;

    client_max_body_size 128m;          # the console allows 128 MB (scanner exports, PDFs)

    location / {
        proxy_pass http://127.0.0.1:8080;
        proxy_set_header Host              $host;
        proxy_set_header X-Forwarded-For   $remote_addr;   # OVERWRITE, do not append
        proxy_set_header X-Forwarded-Proto https;
        proxy_read_timeout 300s;        # matches the console's /api/ timeout
    }
}

server {
    listen 80;
    server_name veyrs.example.com;
    return 301 https://$host$request_uri;
}
```

### 8.3 How the client address travels, and one limitation

```
client ──TLS──▶ front proxy ──▶ console (nginx) ──▶ api (uvicorn)
               sets XFF=client   appends its peer     trusts headers only from
                                 ($proxy_add_x_       VEYRS_CONSOLE_IP; the app
                                  forwarded_for)      takes the FIRST XFF entry
```

The application uses the **first** (leftmost) `X-Forwarded-For` entry as the
client address, both for rate limiting of unauthenticated requests (such as
`/auth/*`) and for audit records. The console **appends** to whatever
`X-Forwarded-For` it receives. Therefore:

- **Behind a proxy that overwrites the header** (as in §8.2), the first entry
  is the real client address. This is correct.
- **With the console exposed directly** (`VEYRS_HTTP_BIND=0.0.0.0:…` and no
  proxy), a client can send its own `X-Forwarded-For` and choose the address
  VEYRS records and rate-limits. For anything reachable by untrusted clients,
  put a proxy that overwrites the header in front.

The console always sends `X-Forwarded-Proto: http` to `api`, because it only
listens on HTTP. VEYRS learns its external `https://` address **only** from
`VEYRS_PUBLIC_BASE_URL`.

---

## 9. Day-2 operations

### 9.1 Driver command reference

These are all the verbs `docker/veyrs-docker.sh` accepts. There is no other.

| Command | What it does |
|---|---|
| `init` | Write `docker/.env` with fresh secrets (0600). Refuses if the file exists |
| `up [--with-workers] [--with-agent] [--all] [BUILD ARGS…]` | Validate `.env`, build, `up -d` the chosen profiles, and wait up to 180 s for `/readyz` |
| `down [ARGS…]` | `docker compose down` across **all** profiles. Keeps the volumes, and `--volumes` **destroys** them |
| `restart [SERVICE…]` | `docker compose restart` across all profiles. Does **not** re-read `.env` |
| `ps [ARGS…]` | Container list across all profiles |
| `logs [ARGS…]` | Logs across all profiles, e.g. `logs -f api`, `logs --tail 100 init` |
| `build [ARGS…]` | Build images for all profiles without starting anything |
| `status` | `ps`, the `/healthz` answer, and which background services are **not** running, with the consequence of each |
| `psql` | Interactive `psql` **as the application role**, so row level security applies |
| `cli ARGS…` | `veyrs` CLI in a throwaway `api` container (`run --rm --no-deps`) |
| `backup [FILE]` | Full dump **as the superuser**, then verified (§10) |
| `help`, `-h`, `--help` | Print the script's header |

`veyrs-setup.sh` installs `veyrs-docker` as a wrapper for the same commands.

### 9.2 Status and health

```bash
docker/veyrs-docker.sh status
```

This prints three things: the container table, the `/healthz` JSON
(`{"status":"ok","app":"VEYRS","version":"…"}`), and a *Background work*
section listing `intel`, `digest` and `agent` as running or **NOT running**,
with what that means.

Two probes, two meanings:

| Endpoint | Answers | Use it for |
|---|---|---|
| `/healthz` | 200 whenever the process is up, **even without a database** | liveness |
| `/readyz` | 200 only if PostgreSQL **and** Redis answer, 503 otherwise | readiness. It is what the `api` health check, the driver and a load balancer should use |

Both are proxied by the console: `curl -s http://127.0.0.1:8080/readyz`.
`init`, `intel` and `digest` have health checks **disabled** because they open
no port, and `agent` has none. An empty health column there is expected.

### 9.3 Logs, restart and applying `.env` changes

```bash
docker/veyrs-docker.sh logs -f api            # follow one service
docker/veyrs-docker.sh logs --tail 50 init    # the initialiser's last run
docker/veyrs-docker.sh logs -f intel digest   # the tick loops: "tick[intel]: ok at …"
docker/veyrs-docker.sh restart api            # restart ONE service, same config
```

**`restart` does not apply `.env` changes.** A container's environment is fixed
when it is created. After editing `docker/.env`, run `up` again **with the same
profile flags** you normally use. Compose recreates only the containers whose
configuration changed:

```bash
docker/veyrs-docker.sh up --with-workers
```

### 9.4 Upgrading

**Git checkout (driver install):**

```bash
docker/veyrs-docker.sh backup                  # always first (§10)
git pull                                       # or check out the release tag
docker/veyrs-docker.sh up --with-workers       # SAME flags as before, e.g. --all
docker/veyrs-docker.sh status
```

With `VEYRS_IMAGE_SOURCE=registry`, also point the three image variables at the
new version before `up`:

```bash
v=$(sed -n 's/^version *= *"\(.*\)"/\1/p' pyproject.toml)
sed -i -E "s#^(VEYRS_(CONSOLE_|AGENT_)?IMAGE=ghcr\.io/visionebc/veyrs(-console|-agent)?):.*#\1:$v#" docker/.env
```

`up` pulls (or, with `build`, rebuilds) the images and recreates changed
containers. `init` then runs
`veyrs init-db`, which is idempotent: it creates missing tables, reconciles
columns, re-applies the RLS policies and upserts the role and compliance
catalogues. The administrator's password is left alone.

**Repeat every profile flag you use.** Services in a profile you do not name
are neither rebuilt nor recreated. They keep running the **old** image
alongside a new API.

**`veyrs-setup.sh` install:** download the new `veyrs-setup.sh` and run it.
Choose `update` (or set `SETUP_EXISTING=update` with `--yes`). It places the new
release next to the old one, re-points `current`, reuses the env file and the
profile choices, moves the image tags to the new version, and runs `up` with
the same flags. An offline install needs the new bundle: `--images FILE`.

**Moving an install from before 0.32.4 to the published images.** Those
installs built their images, and an update keeps building them. To pull
instead, run the update with `SETUP_IMAGES=registry` (or `--yes` and that key
in the answers file). With the driver, set `VEYRS_IMAGE_SOURCE=registry` and
the three `ghcr.io/visionebc/…:<version>` names in `docker/.env`.

**The console now listens on 8080 inside its container (0.32.4).** The host
side is still `VEYRS_HTTP_BIND`, so nothing changes for users or for a reverse
proxy in front of it. This matters only if you wrote your own compose overlay
that names the console's container port.

### 9.5 Restarting after a host reboot

Every long-running service has `restart: unless-stopped`, so the stack comes
back when the Docker daemon starts. `init` does **not** re-run on a reboot; it
runs on `up`. If you stopped the stack with `down`, bring it back with `up`.

### 9.6 Scaling

- **API throughput:** raise `VEYRS_WORKERS`, then run `up`. VEYRS handlers use
  synchronous SQLAlchemy, so throughput comes from processes, not threads.
- **Watch the connection arithmetic.** Each API process can open up to **30**
  PostgreSQL connections (pool 10 + overflow 20, fixed in `backend/veyrs/db.py`).
  `intel`, `digest`, `init` and `cli` add their own. PostgreSQL's default
  `max_connections` is usually 100. Four workers can already reach 120 at peak.
  To raise the bundled server's limit, use a local overlay (§6.5):

  ```yaml
  services:
    postgres:
      command: ["postgres", "-c", "max_connections=200"]
  ```

  Check the result with `docker/veyrs-docker.sh psql`, then `SHOW max_connections;`.
- **Do not scale `intel` or `digest`** (`--scale`). Parallel ticks double the
  load on NVD, which rate-limits per source address, and add nothing.
- **Running several `api` replicas is not supported by the driver or tested.**
  For horizontal scale, use the host install with separate application nodes.

### 9.7 CLI access

```bash
docker/veyrs-docker.sh cli check                     # self-test: configuration, storage, engines
docker/veyrs-docker.sh cli intel-due                 # which feeds are due now
docker/veyrs-docker.sh cli sync-kev                  # refresh one feed by hand
docker/veyrs-docker.sh cli sync-nvd                  # incremental NVD pull (--full reloads everything)
docker/veyrs-docker.sh cli run-sla                   # evaluate SLA state and fire escalations now
docker/veyrs-docker.sh cli digest --dry-run          # build digests, send nothing
docker/veyrs-docker.sh cli recompute-risk --org acme
docker/veyrs-docker.sh cli --help                    # every subcommand
```

Available subcommands: `init-db`, `sync-schema`, `check`, `keygen`,
`bootstrap`, `sync-kev`, `sync-epss`, `sync-nvd`, `sync-cwe`, `recompute-risk`,
`run-sla`, `digest`, `intel-due`, `import-inventory`.

`cli` starts a **new** `api` container with the application role's
environment. It does not need `api` to be running, but it does need
`postgres` and `redis` to be up. It is also why `api` has **no static IP
address**: a second container of the same service cannot reuse one.

To give `import-inventory` a file, mount it with raw Compose:

```bash
$C run --rm --no-deps -v "$PWD/hosts.json:/tmp/hosts.json:ro" api \
  python -m veyrs.cli import-inventory --file /tmp/hosts.json --org acme
```

### 9.8 Changing or resetting the administrator password

`VEYRS_ADMIN_PASSWORD` is used **once**. On every later `up`, `init` checks
(as the superuser, failing closed) whether the administrator exists and, if so,
skips bootstrap: `bootstrap not run: … already exists`. **Editing the value in
`.env` changes nothing.** This is deliberate: an unattended reboot must never
revert a password an operator changed.

| Situation | Do this |
|---|---|
| You know the current password | Change it in the console while signed in. The API endpoint is `POST /api/v1/auth/password`. Every existing session of that user is revoked |
| Password lost (interactive) | `docker/veyrs-docker.sh cli bootstrap --org <slug> --email <admin e-mail>`. It prompts `admin password:` (at least 12 characters) and prints `user exists, password reset`. Nothing is written to disk or to argv |
| Password lost (unattended) | Set `VEYRS_FORCE_BOOTSTRAP=1` and the new `VEYRS_ADMIN_PASSWORD` in `docker/.env`, then run `up` with your usual flags. The log shows `the admin password WILL be reset`. **Then set `VEYRS_FORCE_BOOTSTRAP=0` and clear `VEYRS_ADMIN_PASSWORD` again**, or every `up` resets it |

Never pass `--password` to `bootstrap`. Command-line arguments of container
processes are visible in `ps` on the Docker host.

### 9.9 Rotating other secrets

| Secret | Can you rotate it? | How |
|---|---|---|
| `VEYRS_SECRET_KEY` | yes | Generate at least 32 characters (`openssl rand -base64 48 \| tr -d '\n=' \| tr '+/' '-_'`), edit `.env`, run `up`. Every issued token becomes invalid, so everyone signs in again |
| `VEYRS_ENCRYPTION_KEY` | **no** | There is no re-encryption tool in this version. A new key makes every stored third-party credential unreadable. If it is lost, see "Encryption key loss" in [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md) |
| `VEYRS_DB_PASSWORD` | yes, in two steps | The role's password lives **in the database**, and `initdb.d` runs only once. First `$C exec postgres psql -U postgres -d postgres`, then `\password veyrs`. Put the same value in `.env` and run `up`. Editing `.env` alone leaves `postgres` unhealthy (its health check logs in with the new value) |
| `POSTGRES_PASSWORD` | yes, in two steps | `\password postgres` in the same session, then `.env`, then `up`. `init` uses it over TCP |
| `VEYRS_AGENT_TOKEN` | yes | Mint a new token in **Settings → Agents**, update `.env`, run `up --with-agent …`, then revoke the old one |

Keep `docker/.env` at mode 0600 after editing it.

### 9.10 Profiles: turning services on and off, and the `down` trap

**Turning on:** run `up` with the extra flag, for example
`up --with-workers --with-agent`.

**Turning off one profile while keeping the rest:**

```bash
$C stop agent && $C rm -f agent          # the agent
$C stop intel digest && $C rm -f intel digest   # the workers
```

Then drop the flag from your future `up` commands. **Remove** the containers,
do not just stop them: `docker/veyrs-docker.sh restart` works across all
profiles and restarts stopped containers too.

**The trap:** plain `docker compose down` **without** the profile that started
a container **does not stop that container**. It prints no warning and exits 0.
After `up --with-agent`, a bare `docker compose down` leaves the scanner
running and holding job leases on a stack you believe is off. `ps` and `logs`
without the profile simply omit those containers. The driver's `down`,
`restart`, `ps`, `logs` and `build` always pass **every** profile, as does the
`C` variable in this manual. There is a test for this.

The same rule applies to overlays. The driver reads `VEYRS_COMPOSE_OVERLAYS`
for every verb, so `up` and `down` always describe the same stack.

### 9.11 Operating the scanner agent

- **Two keys, both required.** `VEYRS_AGENT_TOKEN` comes from **Settings →
  Agents**. `VEYRS_AGENT_ALLOW` is this machine's **local** allowlist. The
  server also keeps its own allowlist per agent. A target must pass both.
- **Allowlist syntax:** comma-separated hosts (`scanme.example.com`), name
  globs (`*.lab.example.com`) and CIDRs (`192.0.2.0/24`). Empty means nothing
  is scannable, and the agent refuses to start.
- **Template corpus:** on first start the entrypoint downloads the nuclei
  templates (~84 MB from GitHub) into `veyrs_veyrs-agent-home`. If fewer than
  100 templates are present afterwards, the agent **refuses to start (exit
  78)**. A nuclei with no templates reports a clean scan for every asset it
  touches, which is worse than being down. To refresh the corpus in place:

  ```bash
  $C exec agent nuclei -update-templates -update-template-dir /opt/veyrs/agent-home/nuclei-templates
  ```

- **DNS for internal targets:** nuclei does **not** use the system resolver. It
  carries public resolvers compiled in. On a split-horizon network it resolves
  the *public* address of an internal name, fails to reach it, and reports a
  clean scan. The agent reads a resolver list from
  `/etc/veyrs-agent/resolvers.txt` (one address per line). The container has no
  such file, and the agent logs `no resolver list at …` at start. Mount one with
  an overlay:

  ```yaml
  # docker/compose.agent-resolvers.yaml   (list it in VEYRS_COMPOSE_OVERLAYS)
  services:
    agent:
      volumes:
        - ./resolvers.txt:/etc/veyrs-agent/resolvers.txt:ro
  ```

  Put your internal DNS servers in `docker/resolvers.txt`, one address per
  line. The agent strips comment lines before handing the file to nuclei.
- **No `NET_RAW`:** SYN scanning is not possible. Connect-based scanning works.
  Granting `cap_add: [NET_RAW]` is a deliberate edit, and after it the container
  can forge packets on the stack network.
- **Stopping:** the agent stops on `SIGINT` with a 60-second grace period. A job
  in flight is abandoned, and its lease is reaped by the server.

---

## 10. Backup and restore

### 10.1 What to back up

| Item | Where | How | Without it |
|---|---|---|---|
| The database | volume `veyrs_veyrs-pgdata` | `docker/veyrs-docker.sh backup` | everything is lost |
| Evidence, reports, uploaded documents | volume `veyrs_veyrs-var` | tar the volume (§10.3). **`backup` does not include it** | attachments are lost; database rows point at missing files |
| Secrets | `docker/.env` (setup installs: `/opt/veyrs-docker/veyrs.env`) | copy it, keep it encrypted | **`VEYRS_ENCRYPTION_KEY` cannot be regenerated.** Stored credentials become unreadable |
| Agent home | volume `veyrs_veyrs-agent-home` | not needed | re-downloaded on the next start |
| Redis | none | not needed | rate-limit windows reset |

### 10.2 Database backup

```bash
docker/veyrs-docker.sh backup                               # → ./veyrs-YYYYMMDD-HHMMSS.dump
docker/veyrs-docker.sh backup /var/backups/veyrs/nightly.dump
```

What it does:

1. Runs `pg_dump -U postgres -d $VEYRS_DB_NAME -Fc` **inside** the `postgres`
   container, **as the superuser**, and writes the dump to the host.
2. Counts the `TABLE DATA` entries with `pg_restore --list` **on the host**,
   and refuses the result (exit 1) if there are fewer than 50.
3. Prints `<file> — <size>, <N> tables with data`.

A refused backup **leaves the file on disk**. The driver reports the problem
but does not delete the file, so remove it (or rename it) before a later job
mistakes it for a good backup.

**Why as the superuser?** Forcing row level security applies **to the table
owner too**. A `pg_dump` run as the application role, which owns every table,
is refused partway through:

```
pg_dump: error: query failed: ERROR:  query would be affected by row-level
security policy for table "agent_job_events"
```

Custom format writes as it goes, so what remains **looks like a backup**. One
measured case: 392 KB where the complete dump was 509 MB. **Verify by listing
the archive, never by file size**, because half a megabyte is plausible for a
small installation.

**Host prerequisite.** The verification needs `pg_restore` version 15 or newer
**on the host**. If it is missing or older, the count comes back as 0 and
`backup` reports a *truncated dump*, even though the file may be fine. Install
the client (for example `postgresql-client` from the PostgreSQL project's
repository, version 15+), or verify inside the container, which needs nothing
on the host:

```bash
$C exec -T postgres pg_restore --list < veyrs-20260101-020000.dump | grep -c 'TABLE DATA'
```

**Schedule it** from the host's cron, then copy the files **off the host**:

```cron
# /etc/cron.d/veyrs-backup — nightly at 02:30, as root (cd into YOUR tree: a checkout, or /opt/veyrs-docker/current)
30 2 * * * root cd /opt/veyrs-docker/current && docker/veyrs-docker.sh backup /var/backups/veyrs/veyrs-$(date -u +\%Y\%m\%d).dump >>/var/log/veyrs-backup.log 2>&1
```

A backup on the same disk as the database protects you from mistakes, not from
losing the disk.

### 10.3 Documents volume backup

Use the `postgres` image, which is already on the host and includes `tar`:

```bash
docker run --rm -v veyrs_veyrs-var:/data:ro -v "$PWD":/out postgres:15-bookworm \
  tar -czf /out/veyrs-var-$(date -u +%Y%m%d).tar.gz -C /data .
```

### 10.4 Restore (bundled database)

This procedure replaces the database. **Verify your dump first**
(`pg_restore --list … | grep -c 'TABLE DATA'`).

Run it from the repository root. On a `veyrs-setup.sh` install, run
`cd /opt/veyrs-docker/current` first; the relative `docker/…` paths below then
resolve, and `docker/.env` is the symlink to `/opt/veyrs-docker/veyrs.env`.

```bash
C="docker compose --project-directory docker -f docker/compose.yaml --profile workers --profile agent"
DUMP=/var/backups/veyrs/veyrs-20260101.dump

# 1. Use the docker/.env that belongs to this data: same VEYRS_ENCRYPTION_KEY,
#    and the same VEYRS_DB_USER (the dump assigns its tables to that role).

# 2. Stop everything (the volumes are kept).
docker/veyrs-docker.sh down

# 3. Remove the old database volume. DESTRUCTIVE: only with a verified dump in hand.
docker volume rm veyrs_veyrs-pgdata

# 4. Start ONLY postgres. initdb.d creates the application role and empty databases;
#    --wait returns once the health check (a real app-role login) passes.
$C up -d --wait postgres

# 5. Restore AS THE SUPERUSER, and WITHOUT --no-owner.
$C cp "$DUMP" postgres:/var/tmp/veyrs.dump
$C exec -T postgres pg_restore -U postgres -d veyrs /var/tmp/veyrs.dump
$C exec -T postgres rm -f /var/tmp/veyrs.dump

# 6. Documents (if you have that archive).
docker run --rm -v veyrs_veyrs-var:/data -v "$PWD":/in:ro postgres:15-bookworm \
  tar -xzf /in/veyrs-var-20260101.tar.gz -C /data

# 7. Start the stack. init re-applies init-db (idempotent) and finds the administrator.
docker/veyrs-docker.sh up --with-workers
```

Replace `veyrs` in step 5 with your `VEYRS_DB_NAME` if you changed it.

Why these choices:

- **As `postgres`:** restoring as the application role subjects the restore to
  row level security, and foreign-key validation fails with *"query would be
  affected by row-level security policy"*.
- **Without `--no-owner`:** the dump carries `ALTER … OWNER TO veyrs`, so the
  tables end up owned by the application role, exactly as before. With
  `--no-owner` they would belong to `postgres`, and `init-db` (running as the
  app role) could not re-apply the policies.
- **`/var/tmp`:** the `postgres` user must be able to read the file.

`pg_restore` should finish **without** a line saying `errors ignored on
restore`. If it prints one, read the errors before you start the application.

### 10.5 Verify a restore: the table-count check

```bash
# In the archive:
pg_restore --list "$DUMP" | grep -c 'TABLE DATA'

# In the restored database (as the superuser, so row level security does not hide rows):
$C exec -T postgres psql -U postgres -d veyrs -tAc \
  "select count(*) from pg_tables where schemaname = 'public'"
$C exec -T postgres psql -U postgres -d veyrs -tAc \
  "select count(*) from pg_class where relkind = 'r' and relforcerowsecurity"
$C exec -T postgres psql -U postgres -d veyrs -tAc "select count(*) from users"
```

The first two numbers should match. The `FORCE ROW LEVEL SECURITY` count should
be the same as on the source (70 at the time of writing). The `users` count
should match what you expect. Finally, sign in and compare a few counts on the
dashboard with the source.

### 10.6 External database

`docker/veyrs-docker.sh backup` **refuses** with the external overlay. The stack
holds no superuser credential for that server, and an application-role dump
would be truncated. Back the database up **where it lives**, as its superuser
or a `BYPASSRLS` backup role, and verify it the same way:

```bash
pg_dump -h db.internal.example -U postgres -d veyrs -Fc -f veyrs.dump
pg_restore --list veyrs.dump | grep -c 'TABLE DATA'
```

Restore it the same way, as a superuser and without `--no-owner`. Then run
`docker/veyrs-docker.sh up` to re-apply `init-db`.

### 10.7 Volumes

| Volume (full name) | Mounted at | Contents | Delete it and… |
|---|---|---|---|
| `veyrs_veyrs-pgdata` | `postgres:/var/lib/postgresql/data` | the PostgreSQL cluster | **the installation is gone** |
| `veyrs_veyrs-var` | `/opt/veyrs/var` in `init`, `api`, `intel`, `digest` | evidence files, reports, uploaded documents | attachments are gone |
| `veyrs_veyrs-agent-home` | `agent:/opt/veyrs/agent-home` | nuclei config, cache, templates | several minutes of re-download on the next start |

List them with `docker volume ls --filter label=com.docker.compose.project=veyrs`.

---

## 11. Security model

### 11.1 Database privilege separation

- The PostgreSQL superuser is **`postgres`**. Its password reaches the
  `postgres` and `init` containers **only**. `api`, `intel`, `digest` and
  `agent` never receive it. A long-running, network-reachable process holding
  credentials that bypass tenant isolation would be the most valuable thing an
  attacker could find through an SSRF or a template bug.
- The application role is created by `docker/initdb.d/10-app-role.sh` as
  `LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE NOBYPASSRLS`. It owns `veyrs` and
  `veyrs_test`, with `PUBLIC` access revoked.
- `FORCE ROW LEVEL SECURITY` on every tenant-owned table, audit trails included (70 of 87), keeps tenants apart, even
  against the owning role.
- `scripts/test-docker-stack.sh` proves this on a live stack. It reads a second
  tenant's rows as the app role and gets **zero**, while the superuser sees
  them, and a cross-tenant `INSERT` is refused by `WITH CHECK`.

### 11.2 Network exposure

| Surface | Exposure |
|---|---|
| `console` | the only published port, **loopback by default** |
| `api` | `expose: 8000` on the stack network only. A test fails if `ports:` appears |
| `postgres`, `redis` | no published ports. Use `docker/veyrs-docker.sh psql` |
| `/metrics` | **not** proxied by the console (404). It maps the whole API surface. In production it requires `VEYRS_METRICS_TOKEN` (set it through an overlay, §6.5) and is scraped on the stack network |
| `/docs`, `/redoc` | proxied, but exist only when `VEYRS_ENVIRONMENT` is not `production` |
| Response headers | `X-Frame-Options: DENY`, `nosniff`, `Referrer-Policy: no-referrer`, a restrictive `Permissions-Policy`, and a CSP without `unsafe-inline` for scripts. **No HSTS** (§8) |

### 11.3 Secrets handling

- `docker/.env` is created with `umask 077` and `chmod 600`. `veyrs-setup.sh`
  keeps its env file at 0600 in a 0700 directory.
- The admin password is passed to `bootstrap` through an environment variable,
  **never** as an argument. Container processes appear in the host's `ps`.
- **The image never contains secrets.** The Dockerfile copies named
  directories only (never `COPY . .`), and the root `.dockerignore` excludes
  `**/.env`, `**/.env.*` (except `**/.env.example`),
  `**/.bootstrap-credentials`, `var/`, `*.dump` and `*.sql.gz`. The `**/`
  prefix matters: a bare `.env` would only match the context root and would let
  `docker/.env` through. `scripts/test-docker-stack.sh` searches the built image
  for any `.env` or `.bootstrap-credentials`.
- The Compose file **refuses** to start with an empty `VEYRS_SECRET_KEY`,
  `VEYRS_ENCRYPTION_KEY`, `POSTGRES_PASSWORD` or `VEYRS_DB_PASSWORD`, so there
  is no silent default.

### 11.4 Container hardening and permissions

Since 0.32.4 every VEYRS container runs with **no Linux capability, no way to
gain privilege, and a read-only root filesystem**. Each line below is read back
from `docker inspect` and `/proc/1/status` on a live stack by section 9 of
[`scripts/test-docker-stack.sh`](../scripts/test-docker-stack.sh), and pinned
in the text by [`tests/test_container_images.py`](../tests/test_container_images.py).

| Container | User | Capabilities | `no-new-privileges` | Root filesystem | Writable |
|---|---|---|---|---|---|
| `api` | uid 10001 | **none** (`cap_drop: ALL`, CapEff = 0) | yes | read-only | `veyrs-var` volume, `/tmp` (tmpfs 256 MB — uploads spool there; the console accepts 128 MB) |
| `intel`, `digest` | uid 10001 | none | yes | read-only | `veyrs-var`, `/tmp` (tmpfs 64 MB) |
| `console` | uid 101 (`nginx`), **every process**, master included | none | yes | read-only | `/tmp`, `/var/cache/nginx` (tmpfs) |
| `agent` | uid 10001 | none, **no `NET_RAW`** | yes | read-only | `veyrs-agent-home` volume, `/tmp` |
| `init` | starts as root, then `setpriv` to uid 10001 | only `CHOWN`, `DAC_OVERRIDE`, `FOWNER`, `SETUID`, `SETGID` (none left after the switch) | yes | read-only | `veyrs-var`, `/tmp` |
| `postgres`, `redis` | the official images' own accounts (via `gosu`/`su-exec`) | image defaults | yes | writable | their data |

What changed in 0.32.4, and why:

- **The console was root.** The stock nginx image keeps its master process as
  uid 0 so it can bind port 80, in the one container published on the host. It
  now listens on 8080 as uid 101. The host port is still `VEYRS_HTTP_BIND`.
- **`init` ran the migration as root.** It needs root only to `chown` the
  `veyrs-var` volume, which Docker creates root-owned. `init-db` and the
  bootstrap — the two steps holding the database *superuser* password — ran
  as uid 0 for no reason. They now run as 10001.
- **No capability was dropped anywhere.** Docker's default set includes
  `NET_RAW`, `MKNOD`, `SYS_CHROOT`, `SETUID` and others. None of them is
  needed by a process that runs unprivileged and binds a port above 1024.
- **The images were writable at run time.** A compromised process could leave
  a file next to the code for the next restart to execute. The root filesystem
  is now read-only, and the data lives in the named volumes as before.

Other permissions worth knowing:

| Item | Mode / owner | Why |
|---|---|---|
| `docker/.env` / `/opt/veyrs-docker/veyrs.env` | `0600 root` | Holds the signing key, the Fernet key and both database passwords. The driver's `load` and `init` keep the mode when they edit it |
| `/opt/veyrs-docker` | `0700 root` | Release trees and the secrets file |
| `/usr/local/sbin/veyrs-docker` | `0755 root` | The wrapper only `exec`s the driver |
| `/root/veyrs-admin-password.txt` | `0600 root` | Delete it after the first password change |
| membership of the `docker` group | — | **Equivalent to root on the host.** Anyone in it can read the env file through a container. Grant it as you would grant root |
| the published images | public on `ghcr.io` | Pulling needs no account. Nothing secret is in them: `scripts/publish-images.sh` searches each image for `.env`, `.bootstrap-credentials`, `*.dump` and `.git` before it pushes |

The database role model (an application role that is **not** a superuser and
does **not** have `BYPASSRLS`) is §11.1 and §7.3.

### 11.5 What the stack does not give you

- TLS: bring your own (§8).
- A standby database and application node: use the host install.
- Secret storage beyond a 0600 file: a secrets manager is not integrated.

---

## 12. Troubleshooting

Start with these four commands. They answer most questions:

```bash
docker/veyrs-docker.sh status
docker/veyrs-docker.sh logs --tail 60 init api console
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8080/readyz
docker/veyrs-docker.sh cli check
```

| Symptom | Cause | Fix |
|---|---|---|
| Console returns **502 while `ps` shows `api` and `console` healthy** | nginx is proxying to an old `api` address. A literal `proxy_pass http://api:8000` is resolved once and cached forever, so a recreated `api` (for example by `up --with-workers` on a running stack) leaves the console talking to nobody. Both health checks stay green, because each probes its own container | The shipped `console.conf` re-resolves through Docker DNS (`resolver 127.0.0.11 valid=10s` plus a variable in `proxy_pass`), so a 502 heals within 10 seconds. If it persists, check `logs console` for `connect() failed … upstream` and make sure the console image is current (`up` rebuilds it). Do **not** "fix" it by pinning `api` to a static IP (next row) |
| `Address already in use` from `docker/veyrs-docker.sh cli` or from the test harness | `api` was given a fixed `ipv4_address`. `docker compose run` creates a **second** `api` container, which cannot take the same address | Remove the static address from `api`. Only `console` is pinned |
| **Intermittent 401 / invalid token** that moves when you retry | `VEYRS_SECRET_KEY` is empty in the API's environment, so each uvicorn process signs with its own random key | Set a key of at least 32 characters and run `up`. The shipped files refuse an empty key (Compose) and the API entrypoint exits **78**. This happens when the image is run by hand or an overlay blanks the variable |
| `init` exits **78**: `VEYRS_ADMIN_PASSWORD is not set and no administrator exists` | The database has no administrator (a new or recreated volume, or a new external database), and the env file has no admin password. `veyrs-setup.sh` deliberately does not store it | Put a password (at least 12 characters) in `VEYRS_ADMIN_PASSWORD`, run `up`, then clear it again |
| `init` exits **2**: `password must be at least 12 characters` | Admin password too short. The schema has already been built | Longer password, then `up` |
| `init` exits **3**: `could not determine whether the admin exists` | `init` could not log in as the superuser (bundled) or the app role (external). It fails **closed** so it never resets a password by mistake | Check `POSTGRES_PASSWORD` against the cluster (§9.9) or the external server's reachability and `pg_hba.conf` |
| `postgres` stays **unhealthy** after you changed `VEYRS_DB_PASSWORD`, `VEYRS_DB_USER` or `VEYRS_DB_NAME` in `.env` | `initdb.d` runs **only when the data directory is empty**. The existing cluster still has the old role, password and database. The health check logs in with the new values | Change the role in the database (`\password veyrs`, §9.9), or put the old values back. To really start over: `down --volumes` (**destroys data**) |
| You edited `docker/initdb.d/10-app-role.sh` and nothing changed | Same reason: it runs only on an empty `PGDATA` | Recreate the volume (destroys data), or apply the change by hand as `postgres` |
| `postgres` "ready to accept connections" in the logs, but `init` waits | The health check is a **real login as the app role**, not `pg_isready`. `pg_isready` answers before `initdb.d` has created the role, and a start-up race would look like a wrong password | Wait (the start period is 30 s, with up to 30 retries 5 s apart). If it never turns healthy, read `logs postgres` for errors from `10-app-role.sh` |
| `agent` restarts with exit **78**: `refusing to start. No nuclei templates` | The template download failed (no outbound access to `github.com`), leaving fewer than 100 templates | Allow outbound HTTPS to GitHub, or mount an existing template directory at `/opt/veyrs/agent-home/nuclei-templates`, then `up --with-agent` |
| `agent` exits **2**: `VEYRS_URL and VEYRS_AGENT_TOKEN are required` / `VEYRS_AGENT_ALLOW is required` | Token or allowlist missing | Set both (§9.11). `up --with-agent` already refuses an empty allowlist before starting |
| Agent scans report **clean** on internal hosts; log says `no resolver list at '/etc/veyrs-agent/resolvers.txt'` | nuclei uses its built-in public resolvers | Mount a resolver file (§9.11) |
| **Downloads hang** during the image build or `veyrs-setup.sh` (pip, apt, GitHub, Docker's repository) | The host resolves the mirror to an IPv6 address but has no working IPv6 route, so connections stall instead of failing | Compare `curl -4 -sI https://github.com` with `curl -6 -sI https://github.com`. Fix IPv6 routing, or make the host prefer IPv4 (`precedence ::ffff:0:0/96 100` in `/etc/gai.conf`) |
| `up` stops with **`could not pull the images`** | This tree's version was never published (a commit between releases), or the host cannot reach `ghcr.io` / Docker Hub | Between releases: `VEYRS_IMAGE_SOURCE=build` in `.env`. Offline: §5.C. Proxy: configure it for the Docker **daemon** (`/etc/systemd/system/docker.service.d/http-proxy.conf`), not for your shell |
| `up` stops with **`VEYRS_IMAGE_SOURCE=local, but these images are not on this host`** | `local` means "use what is here", and something is not here. Usually `postgres`/`redis`, which only the offline bundle supplies | `docker/veyrs-docker.sh load <bundle>`, or switch to `registry` / `build` |
| `load` refuses: **`no ….sha256`** or **`does not match`** | The bundle's checksum file is missing, or the bundle is truncated or altered | Copy both files again from the release page. Do not bypass the check: on an offline host it is the only proof of what you are loading |
| `docker pull ghcr.io/visionebc/…` says **`denied`** or **`unauthorized`** | A stale `docker login` for `ghcr.io` with an expired token. Anonymous pulls work; a bad credential does not fall back to anonymous | `docker logout ghcr.io` |
| Console container exits with **`bind() to 0.0.0.0:80 failed (13: Permission denied)`** | A local overlay or an old `console.conf` still says `listen 80`, and the console no longer runs as root (0.32.4) | Listen on 8080 and map `VEYRS_HTTP_BIND` to `:8080` |
| Uploads larger than about 60 MB fail with **`No space left on device`** | A local overlay replaced the api's `/tmp` tmpfs with a smaller one. Uploads spool to `/tmp` | Keep `/tmp` larger than the console's 128 MB upload limit (the shipped value is 256 MB) |
| `docker compose down` left **the agent or workers running** | Raw `down` without `--profile` does not touch profiled containers (§9.10) | Use `docker/veyrs-docker.sh down`, or add `--profile workers --profile agent` |
| Workers or agent still run **old code** after an upgrade | `up` was run without their profile flag | Re-run `up` with every flag you use |
| Changes to `.env` have **no effect** | `restart` does not recreate containers | `up` with your usual flags |
| `backup` says `lists only 0 tables with data -- that is a TRUNCATED dump` although the stack is fine | `pg_restore` is missing on the host, or older than the server's version 15 | Install a PostgreSQL 15+ client on the host, or verify inside the container (§10.2) |
| `backup` refused: `this stack uses an EXTERNAL PostgreSQL` | By design | Back it up on the database server (§10.6) |
| `up` error: `VEYRS_CONSOLE_IP (…) is not inside VEYRS_SUBNET (…)` | You moved one without the other | Change both together |
| `up` error: `VEYRS_ENVIRONMENT=production with a non-https VEYRS_PUBLIC_BASE_URL` | Production requires an https public URL | Put TLS in front (§8) and set the https URL, or use `development` |
| `api` restarts, log says `unsafe production configuration: …` | In production the API refuses `debug`, a non-https public URL, an empty encryption key, or the bootstrap database password | Fix the named item |
| `up` error: `no …/.env -- run: … init`, or `empty in …/.env: …` | No env file, or a required secret is blank | `docker/veyrs-docker.sh init`, or fill in the named key |
| `init` error: `.env already exists` | Protection against regenerating the encryption key | Keep the file. Delete it only if you are also discarding the data |
| Console port fails to bind | Something else listens on `VEYRS_HTTP_BIND` | Choose another `ADDRESS:PORT` |
| Every user shares one rate-limit bucket; audit shows the proxy's address | Proxy headers not believed or not sent: `api` recreated with a different `VEYRS_CONSOLE_IP`, or a front proxy that does not set `X-Forwarded-For` | Keep `VEYRS_CONSOLE_IP` in step with the console; configure the front proxy as in §8.2 |
| `intel` log: `tick[intel]: FAILED (exit N) … retrying on the next tick` | A feed was unreachable or rate-limited | Nothing, if it is occasional: the next tick retries. If persistent, check outbound HTTPS (§3.3) and consider an NVD API key (§6.5) |
| Digest never arrives | `VEYRS_SMTP_HOST` empty, `workers` not running, or the relay refuses the sender | `status`, `logs digest`, set `VEYRS_SMTP_FROM` |
| `veyrs-setup.sh`: `REFUSED: the external database role would disable tenant isolation` | Role is superuser or has BYPASSRLS | Create a dedicated role (§7.2) |
| `veyrs-setup.sh`: `does not OWN database` / `is SQL_ASCII, not UTF8` / `too old` | Role or database not set up as required | `ALTER DATABASE … OWNER TO …`; recreate with `ENCODING 'UTF8' TEMPLATE template0`; PostgreSQL 15+ |
| `veyrs-setup.sh`: `cannot log in … from the stack network` | Password, `listen_addresses`, `pg_hba.conf` or the server's firewall | §7.4. The server sees the Docker host's address (or the stack subnet for a local server) |
| `veyrs-setup.sh`: `Docker is installed but does not answer` | Docker inside LXC without nesting | Enable `nesting=1` (and `keyctl=1` when unprivileged) on the container |
| nginx **welcome page** instead of the console | A custom console image added a config next to the stock `default.conf` rather than replacing it | Use the shipped Dockerfile, which overwrites `conf.d/default.conf` |

---

## 13. Uninstalling

### 13.1 Keep the data

```bash
docker/veyrs-docker.sh down            # containers and network removed; volumes and docker/.env kept
```

A later `up` with the same `docker/.env` finds the database and the
administrator again.

`veyrs-setup.sh` install:

```bash
sudo bash veyrs-setup.sh --uninstall   # keeps volumes veyrs_* and /opt/veyrs-docker/veyrs.env
```

Running `veyrs-setup.sh` again later detects the kept env file and reuses its
secrets.

### 13.2 Purge everything (irreversible)

Take a backup first if there is any chance you need the data.

```bash
docker/veyrs-docker.sh down --volumes --remove-orphans     # DESTROYS the database and documents
docker image ls --format '{{.Repository}}:{{.Tag}}' | grep -E '^((ghcr\.io/visionebc/)?veyrs(-console|-agent)?):' | xargs -r docker image rm
rm docker/.env                                             # the keys; without them old backups lose stored credentials
```

That removes both the published images (`ghcr.io/visionebc/veyrs*`) and any
built locally (`veyrs*:local`, `veyrs*:<version>`). The `postgres` and `redis`
images are left alone, since other stacks on the host may use them.

`veyrs-setup.sh` install:

```bash
sudo bash veyrs-setup.sh --uninstall --purge   # asks you to type PURGE
```

This removes the containers, the volumes, the `veyrs`, `veyrs-console` and
`veyrs-agent` images (published or locally built), `/opt/veyrs-docker` (including the secrets),
`/usr/local/sbin/veyrs-docker`, `/etc/veyrs-setup.conf` and
`/root/veyrs-admin-password.txt`. Docker itself stays installed.

---

## 14. FAQ

**Can I run this in production?**
You can run a small single-node installation with it, provided you enable
`workers`, put TLS in front, set `VEYRS_ENVIRONMENT=production` and take
off-host backups. You do not get the application/database separation and
standby pair of the reference production topology. For that, use the host
install ([INSTALL.md](../INSTALL.md)) or the external-database overlay (§7) as a
step towards it.

**Why is nothing happening to my vulnerability data?**
`workers` is off. See §1.3, then run `docker/veyrs-docker.sh up --with-workers`.

**Can I just run `docker compose up` in `docker/`?**
With published images it would start, but it skips what the driver does
around it: `.env` validation, the overlays, profile handling, the image-source
logic (§2.3), and the wait for `/readyz`. With `build` it would also build
from the wrong context, because the context is the repository root. Use the
driver.

**Is there a prebuilt image?**
Yes, since 0.32.4: `ghcr.io/visionebc/veyrs`, `veyrs-console` and
`veyrs-agent`, public and tagged with each release, for `linux/amd64`. There
is also an offline bundle on every release page (§2.3, §5.C).

**Where do I set the NVD API key, the metrics token or the AI settings?**
Not in `docker/.env` alone: only variables named in `compose.yaml` reach the
containers. Use a local overlay (§6.5).

**Does the API send e-mail?**
Only the `digest` service receives the `VEYRS_SMTP_*` settings. Mail that the
API itself would send (for example, flushing the notification queue on demand)
fails with `SMTP is not configured` unless you pass the same variables to `api`
through an overlay.

**Can I change the port or listen on all interfaces?**
Yes: `VEYRS_HTTP_BIND=0.0.0.0:8443`, then `up`. Read §8 first. Docker bypasses
the host firewall for published ports, and a directly exposed console lets
clients choose their `X-Forwarded-For`.

**The `172.29.0.0/16` subnet clashes with my network.**
Set `VEYRS_SUBNET` and `VEYRS_CONSOLE_IP` together, for example
`VEYRS_SUBNET=172.31.250.0/24` and `VEYRS_CONSOLE_IP=172.31.250.10`. Then run
`down` (the network must be recreated) and `up`.

**Can I run two VEYRS stacks on one Docker host?**
Not with the shipped scripts. The Compose project name is fixed (`name: veyrs`),
and so are the volume names and `veyrs-setup.sh`'s paths.

**How do I get a shell in a container?**
`$C exec api bash` or `$C exec postgres bash`. For the database, prefer
`docker/veyrs-docker.sh psql`, which connects as the app role, so you see what
the application sees. For superuser work: `$C exec postgres psql -U postgres -d veyrs`.

**Does `init` reset my admin password on every restart?**
No. It checks first and skips bootstrap when the administrator exists (§9.8).

**How long until the stack is ready?**
About 2 minutes the first time with published images (download plus
start-up), then about 40 seconds. Building the images yourself takes 5 to 15
minutes the first time. The first full NVD sync with `workers` takes hours, in the background.

**What happens to running scans when I stop the stack?**
The agent gets `SIGINT` and 60 seconds to exit. A job in flight is abandoned,
and the server reaps its lease, so the job can run again.

**Is Redis data important?**
No. It holds rate-limit windows and cache. It has no volume, and a restart only
resets the windows. It is still required: `/readyz` reports 503 without it.

**Which tests cover the stack?**
`tests/test_container_stack.py` holds static guards and needs no Docker
(`./scripts/test.sh tests/test_container_stack.py`).
`scripts/test-docker-stack.sh` holds assertions against a running bundled
stack: privileges, the FORCE-RLS count, cross-tenant reads and writes, a real
login replayed eight times, and no secrets in the image.

---

## 15. Related documents

- [docker/README.md](../docker/README.md): the short version, and the reasoning behind each design decision
- [INSTALL.md](../INSTALL.md): the host (systemd) install
- [DEPLOYMENT.md](DEPLOYMENT.md): production topology and the container section
- [ARCHITECTURE.md](ARCHITECTURE.md): §14, deployment architecture
- [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md): backup strategy, key loss, rehearsals
- [docker/compose.yaml](../docker/compose.yaml), [docker/compose.external-db.yaml](../docker/compose.external-db.yaml), [docker/env.example](../docker/env.example): the files this manual describes
- [scripts/test-docker-stack.sh](../scripts/test-docker-stack.sh) and [tests/test_container_stack.py](../tests/test_container_stack.py): the tests that hold the stack to this description
