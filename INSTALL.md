# Installing VEYRS

VEYRS is a FastAPI application backed by PostgreSQL and Redis, served behind
nginx. [`install.sh`](install.sh) performs the whole installation; this
document is the reference for what it does, and the procedure to do it by
hand.

> **Want it done for you?** The guided installer asks a few questions and runs
> the native install below (or the Docker stack) end to end:
>
> ```bash
> curl -fLO https://github.com/visionebc/veyrs/releases/latest/download/veyrs-setup.sh
> curl -fLO https://github.com/visionebc/veyrs/releases/latest/download/veyrs-setup.sh.sha256
> sha256sum -c veyrs-setup.sh.sha256        # must print "veyrs-setup.sh: OK"
> sudo bash veyrs-setup.sh --check          # inspect this host, change nothing
> sudo bash veyrs-setup.sh                  # asks: native or Docker, bundled or external PostgreSQL
> ```
>
> This document is what it does in native mode, step by step.

> **Just trying it out?** There is a container stack:
> `docker/veyrs-docker.sh init && docker/veyrs-docker.sh up` gives you the API,
> PostgreSQL, Redis and the console on one machine in well under a minute. See
> [docker/README.md](docker/README.md). It is for **evaluation and
> development** — it puts the application and the database in one compose
> project, which is exactly the coupling a production deployment separates them
> to avoid, and its background workers are off by default. This document is the
> path for an installation you intend to operate.

Budget **15–25 minutes** on a clean host. Installed and asserted end to end
on five pristine images — Debian 12, Ubuntu 24.04 LTS, openSUSE Leap 15.6 (the
SLES 15 SP6 code base), Rocky Linux 9 and AlmaLinux 9 — each one twice, once
from clean and once re-run over itself.

> ### There is a script for all of this
>
> [`install.sh`](install.sh) performs every step below. Read this document to
> understand what it does and why; run the script to actually do it.
>
> ```bash
> sudo git clone https://github.com/visionebc/veyrs.git /opt/veyrs
> cd /opt/veyrs
> sudo ./install.sh --dry-run     # print the plan, change nothing
> sudo ./install.sh
> ```
>
> It is idempotent, it will not overwrite an existing `.env` (rotating
> `VEYRS_ENCRYPTION_KEY` would make every stored integration credential
> permanently undecryptable), and it verifies rather than assumes: UTF8
> encoding, wheels instead of compilation, `/readyz`, the console copy, and a
> 401 on an unauthenticated API call. `--help` lists the flags, including the
> `--skip-*` set for a database or cache on another host.
>
> The manual steps below remain the reference. If the script fails it names the
> step it failed in, and that is the section to read.

Every command below is meant to be copy-pasted in order. Where a step can fail
silently, the failure mode is written out — those are the ones that cost hours.

---

## 0. What you need before you start

| Requirement | Minimum | Notes |
|---|---|---|
| OS | Debian 12+ / Ubuntu 22.04+ · openSUSE Leap 15.6 / SLES 15 SP6+ · RHEL/Rocky/Alma 9+ | `install.sh` detects the family. By hand, the package AND service names differ — §1 |
| CPU / RAM / disk | 2 vCPU · 4 GB · 40 GB | See [Sizing](#sizing) — 4 vCPU / 8 GB from ~50k findings |
| Python | **3.11 or newer** | `pyproject.toml` sets `requires-python = ">=3.11"`. 3.10 will not install |
| PostgreSQL | **15 or newer** | Must be **UTF8**. Row-level security is used and is FORCEd |
| Redis | 7 or newer | Rate limiting and background coordination |
| nginx | any current | Serves the console and reverse-proxies the API |

VEYRS never requires outbound internet to run. It only reaches out to refresh
the public threat-intelligence feeds (NVD, EPSS, CISA KEV, MITRE CWE), and it
degrades to stale data rather than failing when those are unreachable.

### Permissions the install needs

Measured on Debian 12, Ubuntu 24.04, openSUSE Leap 15.6, Rocky Linux 9 and
AlmaLinux 9, and on a live split deployment where the application and the
database sit on different hosts.

**The installer must run as root.** It refuses to start otherwise and says why:
it installs distribution packages and writes systemd units. There is no
reduced-privilege mode — `sudo ./install.sh` is the expected invocation.

| Step | Privilege it needs | Why | Avoidable with |
|---|---|---|---|
| 1. System packages | **root** | `apt-get` / `zypper` / `dnf`, `systemctl enable --now` | `--skip-system-packages` |
| 2. Role and databases | **PostgreSQL superuser**, reached through the local `postgres` OS account (`su - postgres`) | `CREATE ROLE`, `CREATE DATABASE`, and — only when a password login is proven to fail — one scoped block in `pg_hba.conf` | `--skip-postgres` |
| 3. Redis | **root** | sets `requirepass`, starts the service | `--skip-redis` |
| 4. Python packages | write access to the install root | builds `/opt/veyrs/venv` | — |
| 6. Schema | the **owner of the database** — *not* a superuser | `init-db` issues DDL: tables, RLS policies, built-in roles, compliance catalogues | — |
| 7. systemd unit | **root** | writes `/etc/systemd/system/veyrs-api.service` | — |
| 8. Console and nginx | **root** | writes the console directory and the vhost, reloads nginx | `--skip-nginx` |

#### The application's own database role is deliberately unprivileged

It owns its database and its tables and needs nothing beyond that. On the
reference deployment it measures as:

```
rolsuper = false   rolcreatedb = false   rolcreaterole = false   rolcanlogin = true
```

Superuser is required **only to create** the role and the databases. Where site
policy forbids that from an installer, use `--skip-postgres` and have a DBA
create them first — see §2.

#### What the installer will not do unasked

* **It does not open the firewall.** With firewalld or ufw active it warns and
  continues. `--open-firewall` is opt-in, on the principle that an installer
  should not widen the attack surface without being told to.
* **It does not touch `pg_hba.conf` unless a password login actually fails.**
  On Debian that login already works and the file is never opened. On SUSE and
  RHEL the default loopback method is `ident`, so one block — scoped to that
  single role and its two databases — is inserted ahead of the generic rules.
* **It does not overwrite `.env`, an existing nginx vhost, an existing database
  role's password, or an existing administrator's password.** A re-run leaves
  all four alone; `--force-bootstrap` is what deliberately resets the last one.

#### SELinux

Where SELinux reports `Enforcing`, the installer sets
`setsebool -P httpd_can_network_connect 1` — without it nginx returns 502 on
`/api/` — and runs `restorecon` over the console directory. Both branches are
covered by reading the code rather than by a run: every container used for
testing reports `Disabled`.

#### File modes the install establishes

| Path | Mode | Note |
|---|---|---|
| `/opt/veyrs/.env` | `0600` | secrets. `VEYRS_ENCRYPTION_KEY` is not recoverable — back this file up |
| `/opt/veyrs/var`, `var/backups`, `var/documents` | `0750` | the only tree the service is allowed to write |
| `/etc/systemd/system/veyrs-api.service` | `0644` | |
| console files under the document root | `0644` | |

#### Ports and egress

| Direction | Port | When |
|---|---|---|
| inbound | 80, or 443 if you terminate TLS on this host | always |
| loopback | 8000 | the API binds `127.0.0.1` only; nginx proxies it |
| outbound | 5432 · 6379 | to the database and cache hosts — localhost by default |
| outbound | 443 | **during the install**: distribution repositories and PyPI |
| outbound | 443 | at runtime, optional: NVD, EPSS, CISA KEV, MITRE CWE |

#### The service runs as `root`

That is what the shipped unit does, and it is a known limitation rather than a
recommendation. What compensates for it today: `ProtectSystem=strict` with
`ReadWritePaths=/opt/veyrs/var` as the only writable path, plus
`NoNewPrivileges`, `PrivateTmp`, `ProtectHome`, `MemoryDenyWriteExecute` and
`SystemCallArchitectures=native`. The API binds loopback only. Moving it to a
dedicated unprivileged account is open work, and the paths above would have to
be re-owned in the same change.

---

## 1. System packages

**Debian 12 / Ubuntu 22.04+**

```bash
sudo apt update
sudo apt install -y \
  python3 python3-venv python3-pip \
  postgresql redis-server nginx git curl
```

**openSUSE Leap 15.6 / SLES 15 SP6+**

```bash
sudo zypper refresh
sudo zypper install -y \
  python311 python311-pip libexpat1 \
  postgresql16-server postgresql16 redis nginx git-core curl
```

Two things about this family, both measured on a stock image rather than
assumed:

* There is **no `/usr/bin/python3`**, even after `python311` is installed. The
  interpreter is `python3.11`, and every command below that says `python3`
  means that one.
* **`libexpat1` is not optional.** The `python311` in the update channel ships
  a `pyexpat` built against a newer libexpat than a stock image carries, and
  the interpreter then fails inside `ensurepip` with `undefined symbol:
  XML_SetAllocTrackerActivationThreshold`. `python3.11 -m venv venv` still
  reports a created virtualenv — one **with no `pip` in it**.

**RHEL 9 / Rocky 9 / AlmaLinux 9**

```bash
sudo dnf -y module reset postgresql && sudo dnf -y module enable postgresql:16
sudo dnf -y install \
  python3.11 python3.11-pip \
  postgresql-server postgresql redis nginx git
sudo postgresql-setup --initdb    # RHEL does not initialise the cluster on first start
```

The base repositories carry PostgreSQL 13 and Python 3.9 — both below the
minimum — which is why the module stream and the versioned Python package are
named explicitly. Do **not** add `curl`: minimal images ship `curl-minimal`,
which already provides `/usr/bin/curl` and *conflicts* with the `curl`
package, so `dnf install curl` fails outright.

### The two cross-family traps

**On SUSE and RHEL, `pg_hba.conf` authenticates loopback connections with
`ident`.** That refuses a password login for a role with no matching system
user, so step 6 dies with `FATAL: Ident authentication failed for user
"veyrs"` — after the role and both databases already exist, which reads like
an application bug and is not one. Add a rule ahead of the generic ones
(`pg_hba.conf` is first-match-wins) and reload:

```
host    veyrs,veyrs_test    veyrs    127.0.0.1/32    scram-sha-256
host    veyrs,veyrs_test    veyrs    ::1/128         scram-sha-256
```

`install.sh` does this only when a real password login has been tried and
failed, and scopes it to that one role and its two databases. On Debian the
rule is already present, so the file is never touched.

**The Redis unit is not called the same thing anywhere.** `redis-server` on
Debian, `redis` on RHEL, and `redis@default` on SUSE — where only a
`redis@.service` *template* exists and there is no config file at all until
one is seeded from `/etc/redis/default.conf.example`. This matters beyond
starting it: `infrastructure/systemd/veyrs-api.service` ships
`After=…redis-server.service`, and **systemd silently ignores an ordering
dependency on a unit that does not exist**, so on SUSE and RHEL the API may
start before its cache with nothing reported. `install.sh` rewrites that line
to the unit this host actually has.

That is the whole runtime set.

### Do I need a compiler?

**On Debian 12 / x86-64 / Python 3.11: no.** Every pinned dependency ships a
prebuilt manylinux wheel — including the three that people expect to compile:

- `psycopg[binary]` bundles its own libpq, so **`libpq-dev` is not required**
- `cryptography` and `argon2-cffi-bindings` ship binary wheels
- `lxml`, `pillow` and `reportlab` ship binary wheels

Install the build toolchain **only if** `pip` starts compiling — which happens
on ARM, on Alpine (musl), or on a Python version newer than the wheels:

```bash
# Fallback only. Skip unless step 4 tries to build from source.
sudo apt install -y build-essential python3-dev libpq-dev libffi-dev libxml2-dev libxslt1-dev
```

> **How to tell:** if `pip install` prints `Building wheel for psycopg-binary
> (pyproject.toml)` instead of `Downloading psycopg_binary-...whl`, you need the
> fallback packages. A missing compiler produces a wall of C errors, not a clear
> message.

---

## 2. Create the databases

```bash
sudo -u postgres psql -c "CREATE ROLE veyrs LOGIN PASSWORD 'CHANGE-ME-NOW';"
sudo -u postgres psql -c "CREATE DATABASE veyrs      OWNER veyrs ENCODING 'UTF8' TEMPLATE template0;"
sudo -u postgres psql -c "CREATE DATABASE veyrs_test OWNER veyrs ENCODING 'UTF8' TEMPLATE template0;"
```

> ### The database **must** be UTF8 — this is the single most common install defect
>
> A PostgreSQL cluster initialised without a UTF-8 locale silently produces
> `SQL_ASCII` databases. psycopg then hands your application `bytes` where it
> expects `str`. VEYRS stores CVE descriptions and vendor advisories in five
> languages, so this is a data-corruption bug, not a cosmetic one — and it does
> not announce itself at install time. It surfaces weeks later as a decoding
> traceback on one advisory.
>
> `TEMPLATE template0` in the commands above is what makes `ENCODING 'UTF8'`
> legal when the cluster default is not UTF-8. Do not drop it.
>
> Verify before continuing:
>
> ```bash
> sudo -u postgres psql -c "SELECT datname, pg_encoding_to_char(encoding) FROM pg_database WHERE datname LIKE 'veyrs%';"
> #  veyrs      | UTF8
> #  veyrs_test | UTF8
> ```

`veyrs_test` is only used by the test suite, which refuses to run against a
database whose name does not end in `_test`. Create it anyway — it costs
nothing and it is the guard that keeps fixtures out of production.

### Does the database have to be on the same machine?

**No — and the same installer handles both layouts.** Decide before you run it,
because it changes which of the steps below apply to you.

**Same host — the default.** `install.sh` creates the role and both databases
on the local cluster, points `VEYRS_DATABASE_URL` at `127.0.0.1:5432`, and
proves a password login works before it continues. Nothing extra to do.

**Separate host.** Skip the steps that assume a local cluster and tell the
installer where the database actually is:

```bash
sudo DB_PASSWORD='…' ./install.sh \
    --skip-postgres --skip-redis \
    --db-host db.internal.example --redis-host cache.internal.example
```

Pass the password through the **environment**, not `--db-password`: a flag is
visible in `ps(1)` to every local account on the machine.

With `--skip-postgres` the installer never connects to the remote cluster as a
superuser and never edits its `pg_hba.conf`. Create these yourself first, on
the **database** host:

```bash
sudo -u postgres psql -c "CREATE ROLE veyrs LOGIN PASSWORD 'CHANGE-ME-NOW';"
sudo -u postgres psql -c "CREATE DATABASE veyrs OWNER veyrs ENCODING 'UTF8' TEMPLATE template0;"
```

and then, still on the database host:

* `listen_addresses` must include the address the application dials — the
  distribution default is `localhost`, which is why a remote install fails with
  "connection refused" while `psql` works fine locally;
* `pg_hba.conf` needs `host veyrs veyrs <app-host>/32 scram-sha-256`;
* the link carries a plaintext credential and plaintext rows unless you enable
  TLS (`ssl = on` on the server, `?sslmode=verify-full` appended to
  `VEYRS_DATABASE_URL`). Do not run it across an untrusted network without it.

`VEYRS_TEST_DATABASE_URL` is a separate setting on purpose. Point it at a local
`veyrs_test` even when production data lives on another host: a test run then
cannot reach the production cluster at all.

The reference deployment runs exactly this way — application on one host,
PostgreSQL and Redis on another — and a re-run of the installer against it
completes in 27 seconds without modifying `.env`, the vhost, the systemd unit,
the installed package set or a single row.

### Backing up: `pg_dump` as the application role writes a truncated archive

70 of the 87 tables carry **FORCE ROW LEVEL SECURITY**, and forcing it applies
to the table owner as well. A `pg_dump` run as `veyrs` therefore fails on the
first tenant-scoped table:

```
pg_dump: error: query failed: ERROR:  query would be affected by row-level
security policy for table "agent_job_events"
```

`-Fc` writes the archive as it goes, so what is left behind is a file that
looks like a backup and is not: **392 KB in place of 509 MB** on the reference
deployment. Take backups as a **superuser**, which bypasses RLS:

```bash
sudo -u postgres pg_dump -d veyrs -Fc -f /var/backups/veyrs-$(date +%F).dump
pg_restore --list /var/backups/veyrs-$(date +%F).dump | grep -c 'TABLE DATA'
```

Verify by listing the archive, as above. A non-zero exit from `pg_dump` is easy
to lose inside a pipeline that ends in `tail`, and the size alone will not warn
you — half a megabyte is a plausible-looking file.

Set a Redis password (`requirepass`) in `/etc/redis/redis.conf` if Redis is
reachable from anything but localhost, then `sudo systemctl restart redis-server`.

---

## 3. Get the source

```bash
sudo git clone https://github.com/visionebc/veyrs.git /opt/veyrs
cd /opt/veyrs
```

---

## 4. Install the Python packages

This is the step the rest of the document exists for. Read the two-manifest
note below before running it.

```bash
cd /opt/veyrs
python3 -m venv venv
venv/bin/pip install --upgrade pip
venv/bin/pip install -r requirements.txt
```

`requirements.txt` is at the **repository root**, not under `backend/`.

Expected: ~57 packages, all downloaded as wheels, no compilation. Confirm:

```bash
venv/bin/pip check          # -> "No broken requirements found."
venv/bin/python -c "import fastapi, sqlalchemy, psycopg, redis; print('ok')"
```

### Why there are two dependency files

They are not duplicates and you install only one of them.

| File | Contains | You use it for |
|---|---|---|
| **`requirements.txt`** | The **full resolved graph** — direct *and* transitive packages, every version pinned to `==` | **Installing.** This is the lock |
| `pyproject.toml` | **Direct dependencies only** — the ~20 packages VEYRS itself imports, with the reasoning for each in comments | Understanding *why* a package is there, and bumping it deliberately |

Install from `requirements.txt`. Always. It exists so that a new node, a
disaster-recovery rebuild, or a developer laptop gets a byte-identical software
set instead of whatever PyPI happens to resolve that morning.

Versions are **pinned, not floored**, on purpose. This is a security platform:
an unattended `pip install` that silently moves `cryptography` or `SQLAlchemy`
is a change nobody reviewed.

To change a dependency: edit `pyproject.toml`, run `./scripts/freeze-deps.sh`
to regenerate the lock, run `./scripts/test.sh`, and commit **both files in the
same commit**. A lock that disagrees with `pyproject.toml` is worse than either
file alone.

### Two packages that look wrong and are not

- **`python-multipart`** is never imported by VEYRS. FastAPI needs it at runtime
  to parse scanner uploads. Without it, every import endpoint returns 500 at
  *request* time — not at boot — so the service looks healthy.
- **`ldap3`** is imported lazily, inside the two functions that talk to a
  directory. An upgrade that lands the code before the package still boots and
  reports one clear error on the Directory page, instead of failing at import
  and taking the whole API down.

There is deliberately **no** `pyotp`: TOTP is implemented on `hmac` + `struct`
from the standard library, to keep the authentication path free of a third
party.

---

## 5. Configure

```bash
cd /opt/veyrs
cp .env.example .env
chmod 600 .env
```

Generate the two secrets — **do not invent them by hand**:

```bash
# VEYRS_ENCRYPTION_KEY  (Fernet key for secrets at rest)
PYTHONPATH=backend venv/bin/python -m veyrs.cli keygen

# VEYRS_SECRET_KEY  (JWT signing, >= 32 chars)
python3 -c "import secrets; print(secrets.token_urlsafe(48))"
```

Edit `.env`. Every variable is `VEYRS_`-prefixed. The ones that matter:

| Variable | Default | Notes |
|---|---|---|
| `VEYRS_ENVIRONMENT` | `development` | Set to `production` to activate the safety guards |
| `VEYRS_SECRET_KEY` | — | ≥32 chars. **No usable default in production** |
| `VEYRS_ENCRYPTION_KEY` | — | From `keygen`. **Required** in production |
| `VEYRS_DATABASE_URL` | — | `postgresql+psycopg://veyrs:PASSWORD@127.0.0.1:5432/veyrs` |
| `VEYRS_TEST_DATABASE_URL` | — | Same, ending in `/veyrs_test` |
| `VEYRS_REDIS_URL` | localhost | `redis://:PASSWORD@127.0.0.1:6379/0` |
| `VEYRS_PUBLIC_BASE_URL` | — | Must be `https://` in production |
| `VEYRS_CORS_ORIGINS` | — | Explicit list. Never `*` |
| `VEYRS_RATE_LIMIT_PER_MINUTE` | 240 | Per credential |
| `VEYRS_AUTH_RATE_LIMIT_PER_MINUTE` | 10 | Per source IP. **Raise it if your users egress behind one NAT address** |
| `VEYRS_TRUST_PROXY_HEADERS` | false | Enable **only** behind a proxy you control — otherwise any caller mints a fresh rate-limit identity per request |
| `VEYRS_METRICS_TOKEN` | — | Bearer token for `/metrics` |
| `VEYRS_NVD_API_KEY` | — | Optional. Raises the NVD rate limit |
| `VEYRS_AI_ALLOW_EXTERNAL` | false | Deployment-wide default |

`assert_production_safe()` refuses to boot a production process with debug on,
the bootstrap database password, plain HTTP, or a derived encryption key. If the
service will not start in production, read that error first — it is telling you
one of these five things.

Create the writable directories the unit expects:

```bash
mkdir -p /opt/veyrs/var/backups /opt/veyrs/var/documents
```

---

## 6. Create the schema and the first administrator

```bash
cd /opt/veyrs

# Schema + row-level-security policies + built-in roles + compliance catalogues
PYTHONPATH=backend venv/bin/python -m veyrs.cli init-db

# Configuration / storage / engine self-test
PYTHONPATH=backend venv/bin/python -m veyrs.cli check

# First organization and its administrator (prompts for a password)
PYTHONPATH=backend venv/bin/python -m veyrs.cli bootstrap \
  --org acme --name "Acme Corp" --email admin@acme.com --superuser
```

> ### `init-db` creates tables. `sync-schema` does **not**.
>
> `sync-schema` reconciles columns, indexes and constraints on tables that
> **already exist**. Run it on a database that is missing a table entirely and
> it prints `0 columns, 0 indexes, 0 constraints added` and **exits 0** — a
> success message for a no-op.
>
> `init-db` is the one that calls `create_all()`, and it is idempotent. Run it
> on every install and every upgrade.
>
> Skipping it after an upgrade that adds tables produces `UndefinedTable` 500s
> on exactly the new endpoints and nowhere else — so `/healthz` stays green and
> the service looks fine.

Full CLI surface: `PYTHONPATH=backend venv/bin/python -m veyrs.cli --help`
(`init-db`, `sync-schema`, `check`, `keygen`, `bootstrap`, `import-inventory`,
`sync-kev`, `sync-epss`, `sync-nvd`, `sync-cwe`, `intel-due`, `recompute-risk`,
`run-sla`, `digest`).

---

## 7. Run it

### API service

```bash
sudo cp infrastructure/systemd/veyrs-api.service /etc/systemd/system/
sudo systemctl daemon-reload
sudo systemctl enable --now veyrs-api
```

The unit runs `uvicorn veyrs.main:app` with **4 worker processes** bound to
`127.0.0.1:8000`, under a hardened sandbox (`ProtectSystem=strict`, with only
`/opt/veyrs/var` writable). Workers are processes because the request handlers
are synchronous SQLAlchemy — throughput comes from processes, not from a bigger
event loop. Raise the worker count and the Postgres pool together, never alone.

Optional units in `infrastructure/systemd/`:
`veyrs-digest.{service,timer}`, `veyrs-maintenance.{service,timer}`. Backup and
replication-check units are in `infrastructure/backup/`.

There is **no worker unit and no message broker.** Background work is done by
the two hourly timers calling the CLI. A Celery worker unit was carried here
long after Celery itself was removed from the dependency set in 0.14.1, and it
could only ever have restart-looped on a binary that is not installed; it has
been deleted.

### Console and nginx

The console is **static files that nginx serves from a copy**. Install it:

```bash
sudo install -d -m 755 /var/www/veyrs-console
sudo install -m 644 frontend/console/app.js \
                    frontend/console/console.css \
                    frontend/console/index.html \
                    /var/www/veyrs-console/

sudo cp infrastructure/nginx-veyrs-console.conf /etc/nginx/sites-available/veyrs
sudo ln -sf /etc/nginx/sites-available/veyrs /etc/nginx/sites-enabled/
sudo nginx -t && sudo systemctl reload nginx
```

Edit `server_name` and the TLS certificate paths in that file for your host.

> ### Never skip the console copy on an upgrade
>
> `git pull` updates the checkout. nginx serves `/var/www/veyrs-console`, which
> is a **copy**. Omit the copy and the node runs the new API behind the old front
> end — and every surface still answers `200`. No health check can see it.
>
> Verify with the artefact, not the status code:
>
> ```bash
> md5sum /opt/veyrs/frontend/console/app.js /var/www/veyrs-console/app.js   # must match
> grep -o 'app.js?v=[0-9]*' /var/www/veyrs-console/index.html
> ```

---

## 8. Verify the install

```bash
curl -sf http://127.0.0.1:8000/healthz     # liveness  -> {"status":"ok","version":"..."}
curl -sf http://127.0.0.1:8000/readyz      # DB + Redis -> must be 200

# An unauthenticated API call must be refused, not served
curl -so /dev/null -w '%{http_code}\n' https://YOUR-HOST/api/v1/assets    # -> 401
```

`/healthz` reports the version from `config.Settings.version`. That is the
number to trust after an upgrade.

Then open `https://YOUR-HOST/` and sign in with the account from step 6.

### Sizing

| Findings | vCPU | RAM | Notes |
|---|---|---|---|
| < 50k | 2 | 4 GB | single node |
| 50k–500k | 4 | 8 GB | separate database host recommended |
| 500k–5M | 8 | 16 GB | separate the database host |
| > 5M | — | — | separate workers; partition `findings` by `organization_id` |

---

> Installed and running? [docs/SYSTEM_MANUAL.md](docs/SYSTEM_MANUAL.md) is the
> operator's reference from here on: every setting the process reads, the CLI,
> the units and timers, logs, backups and a troubleshooting table.

## 9. Running the tests

```bash
./scripts/test.sh
```

> **Never run bare `pytest`.** `conftest.py` needs `VEYRS_TEST_DATABASE_URL`
> and aborts with *"no test database configured"* rather than falling back to
> your production database. `scripts/test.sh` loads `.env`, points the suite at
> `veyrs_test`, and raises the rate limits that the suite would otherwise trip.

---

## 10. Upgrading

```bash
cd /opt/veyrs
git pull
venv/bin/pip install -r requirements.txt
PYTHONPATH=backend venv/bin/python -m veyrs.cli init-db        # ALWAYS — idempotent
sudo install -m 644 frontend/console/app.js frontend/console/console.css \
                    frontend/console/index.html /var/www/veyrs-console/   # ALWAYS
sudo systemctl restart veyrs-api
timeout 30 bash -c 'until curl -sfo /dev/null http://127.0.0.1:8000/readyz; do sleep 1; done' \
  && echo "up" || { echo "did not come up"; sudo journalctl -u veyrs-api -n 30 --no-pager; }
```

The two `ALWAYS` steps are the two that fail silently. See the boxes in §6 and §7.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `pip` compiles instead of downloading wheels | Non-x86-64, musl, or a Python newer than the pinned wheels. Install the fallback packages in §1 |
| `ERROR: Package requires a different Python` | Python < 3.11. Check `python3 -V` |
| Service will not start in production | `assert_production_safe()` — debug on, bootstrap DB password, plain HTTP, or a derived encryption key |
| Decoding errors on advisories, weeks in | Database is `SQL_ASCII`, not UTF8. See §2 |
| New endpoints 500 with `UndefinedTable`, `/healthz` green | `init-db` was skipped on upgrade. See §6 |
| New API, old UI; everything returns 200 | Console copy was skipped. Compare md5 as in §7 |
| Legitimate users rate-limited at sign-in | All egressing behind one NAT address. Raise `VEYRS_AUTH_RATE_LIMIT_PER_MINUTE` |
| `/metrics` returns 404 with a token | Deliberate: a wrong or missing token gets **404, not 401**, so a probe cannot learn the endpoint exists |
| Tests abort with "no test database configured" | You ran bare `pytest`. Use `./scripts/test.sh` |

More detail: [`docs/DEPLOYMENT.md`](docs/DEPLOYMENT.md),
[`docs/DATABASE.md`](docs/DATABASE.md),
[`docs/HIGH_AVAILABILITY.md`](docs/HIGH_AVAILABILITY.md),
[`docs/SECURITY.md`](docs/SECURITY.md).
