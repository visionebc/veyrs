# VEYRS

**Unified Cybersecurity Risk Management.**

VEYRS connects vulnerability intelligence to the things you actually own, and
then to the work of fixing them. It ingests CVE, CVSS v2/v3/v4, EPSS and the
CISA KEV catalogue, correlates them against your assets and their real exposure,
scores business impact, and drives the remediation through ticketing, SLAs,
escalation, verification, compliance and audit.

> Most vulnerability tooling stops at a ranked list. A list is not a decision.
> VEYRS is built around the part that comes after: *who owns this, what does it
> actually reach, when is it due, and can you prove it was fixed?*

---

## What it does

**Intelligence**
- CVE ingestion from NVD, with EPSS exploit-probability scores and the CISA KEV
  catalogue of vulnerabilities known to be exploited in the wild
- CVSS v2, v3 and v4 scoring engine, validated against 4382 official vectors
- MITRE CWE weakness dictionary
- Feeds degrade to stale data rather than failing; the platform never depends on
  outbound internet to serve a request

**Assets and exposure**
- Asset inventory with importable sources: files (CSV/TSV/JSON/XLSX), any JSON
  HTTP API with an operator-declared field map, and a dedicated NetBox driver
- Scanner ingestion, package inventory, artefact identity and correlation
- Risk scoring that combines vulnerability severity with exposure and business
  impact — not severity alone

**Work**
- Internal ticket queue **or** an external ITSM (Jira Cloud, Jira Data Center,
  ServiceNow, generic webhook), selected per tenant. Choosing external hides the
  internal queue and leaves a durable link between the remote issue and the
  finding, asset and date
- Confluence publishing for runbooks, one-directional by design
- SLA evaluation, escalation chains, remediation verification
- A **risk register** for security risks that are not tied to any asset, with a
  RACI matrix assignable to teams and to named people inside them

**Governance**
- Multi-tenant with PostgreSQL row-level security, FORCEd on every table
- Argon2id password hashing, TOTP MFA implemented on the standard library,
  Fernet envelope encryption for secrets at rest
- LDAP / Active Directory authentication and team import
- Compliance catalogues, audit log, evidence export (PDF/XLSX)

---

## Installation

### The fast path: the guided installer

`veyrs-setup.sh` is one script that installs VEYRS either natively (systemd +
nginx, via [`install.sh`](install.sh)) or on Docker Compose, with a bundled or
an external PostgreSQL. It asks a handful of questions, or reads them from an
answers file with `--yes`. Tested on Debian 12, Ubuntu 24.04, openSUSE Leap
15.6, Rocky 9 and AlmaLinux 9.

```bash
curl -fLO https://github.com/visionebc/veyrs/releases/latest/download/veyrs-setup.sh
curl -fLO https://github.com/visionebc/veyrs/releases/latest/download/veyrs-setup.sh.sha256
sha256sum -c veyrs-setup.sh.sha256        # must print "veyrs-setup.sh: OK"
sudo bash veyrs-setup.sh --check          # inspect this host, change nothing
sudo bash veyrs-setup.sh                  # asks: native or Docker, bundled or external PostgreSQL
```

Unattended installs, offline installs (`--source`), `--dry-run` and
`--uninstall` are in `sudo bash veyrs-setup.sh --help` and in the
[Docker Compose manual](docs/DOCKER_COMPOSE_MANUAL.md#5-step-by-step-installation).

### The reference

**→ [INSTALL.md](INSTALL.md)** — system packages, the dependency model, database
setup, schema creation, systemd and nginx, with the silent failure modes called
out at each step.

### Trying it out: Docker Compose

**→ [docker/README.md](docker/README.md)** · full operator manual:
**[docs/DOCKER_COMPOSE_MANUAL.md](docs/DOCKER_COMPOSE_MANUAL.md)**

```bash
git clone https://github.com/visionebc/veyrs.git && cd veyrs
docker/veyrs-docker.sh init     # generates secrets, prints the admin password
docker/veyrs-docker.sh up       # builds, starts, waits for /readyz
```

API, PostgreSQL, Redis and the console on one machine, ready in well under a
minute on a warm cache. The console is on `http://127.0.0.1:8080`.

The three background units a host install runs are all available, behind
**compose profiles**, and off by default:

```bash
docker/veyrs-docker.sh up --with-workers   # intel-sync + digest
docker/veyrs-docker.sh up --all            # + the scanner agent
```

| Profile | Replaces | Off by default because | If you leave it off |
|---|---|---|---|
| `workers` | `veyrs-intel-sync.timer`, `veyrs-digest.timer` | a first `up` would start a multi-hour NVD pull against a feed that rate-limits per source address | **the CVE/EPSS/KEV data never refreshes and SLA deadlines stop elapsing.** VEYRS keeps scoring, at full confidence, against what it last knew — and nothing in the console shows it |
| `agent` | `veyrs-agent.service` | it is the one component that sends unsolicited traffic to other people's machines | no scans originate here; jobs queue and their leases are reaped |

`veyrs-docker.sh status` prints that from the machine itself, filled in from
what is actually running. **Turn `workers` on for anything you intend to keep**
— and for a deployment you mean to operate, use the installer below: this stack
puts the application and the database in one project, which is precisely the
coupling production separates them to avoid.

### The scripted install

[`install.sh`](install.sh) does every step of INSTALL.md on a clean host —
packages, the PostgreSQL role and UTF8 databases, Redis, the pinned dependency
set, generated secrets, the schema, the first administrator, the systemd unit
and the nginx vhost. It detects the platform and covers three families:

| `--distro-family` | Packages | Installed and asserted end to end on | Same family, not run |
|---|---|---|---|
| `debian` | `apt-get` | Debian 12 (bookworm) · Ubuntu 24.04 LTS | Ubuntu 22.04 |
| `suse` | `zypper` | openSUSE Leap 15.6 | SLES 15 SP6 — the same code base as Leap 15.6; its repositories need a subscription |
| `rhel` | `dnf` | Rocky Linux 9 · AlmaLinux 9 | RHEL 9 |

What each image resolved to is measured, not inferred from its name:

| Image | Interpreter | PostgreSQL | Redis unit | Redis config | nginx vhost | loopback `pg_hba` |
|---|---|---|---|---|---|---|
| Debian 12 | `python3.11` | 15 | `redis-server` | `redis.conf` | `sites-available/` | already `scram-sha-256` — not touched |
| Ubuntu 24.04 | `python3.12` | 16 | `redis-server` | `redis.conf` | `sites-available/` | already `scram-sha-256` — not touched |
| openSUSE Leap 15.6 | `python3.11` | 16 | `redis@default` | `default.conf` (seeded) | `vhosts.d/` | `ident` — a rule is added |
| Rocky 9 | `python3.11` | 16 | `redis` | `redis.conf` | `conf.d/` | `ident` — a rule is added |
| AlmaLinux 9 | `python3.11` | 16 | `redis` | `redis.conf` | `conf.d/` | `ident` — a rule is added |

No pinned dependency had to be compiled on any of them: every wheel resolved
for CPython 3.11 and 3.12 on x86-64, so no compiler is required.

Package names, the Python binary, the Redis unit name, the nginx vhost
directory and the `pg_hba.conf` authentication rule all differ between them —
see [INSTALL.md §1](INSTALL.md#1-system-packages) for the measured details.
`--distro-family` overrides the detection; `--skip-system-packages` opts out.

```bash
sudo git clone https://github.com/visionebc/veyrs.git /opt/veyrs
cd /opt/veyrs
sudo ./install.sh --dry-run     # print the plan, change nothing
sudo ./install.sh               # asks only for what it cannot invent
```

It is idempotent, it never overwrites an existing `.env`, it verifies the
database is UTF8 rather than assuming it, and it refuses to report success
until `/readyz` answers and an unauthenticated API call is refused.
`--unattended` takes every answer from a flag or an environment variable;
`--skip-postgres` / `--skip-redis` / `--skip-nginx` cover split deployments.
Run `./install.sh --help` for the full list.

### Or by hand

The short version, on a clean Debian 12 host. **Package names differ on
openSUSE/SLES and RHEL** — see [INSTALL.md §1](INSTALL.md#1-system-packages),
or let `install.sh` work it out:

```bash
sudo apt install -y python3 python3-venv postgresql redis-server nginx git
sudo git clone https://github.com/visionebc/veyrs.git /opt/veyrs && cd /opt/veyrs
python3 -m venv venv && venv/bin/pip install -r requirements.txt
cp .env.example .env && chmod 600 .env    # then edit it — see INSTALL.md §5
PYTHONPATH=backend venv/bin/python -m veyrs.cli init-db
PYTHONPATH=backend venv/bin/python -m veyrs.cli bootstrap --org acme --email you@example.com --superuser
```

Requires **Python 3.11+**, **PostgreSQL 15+ with a UTF8 database**, and
**Redis 7+**.

---

## Architecture

```
nginx ──┬── /            static console (frontend/console → /var/www/veyrs-console)
        └── /api/v1      uvicorn × 4 workers → FastAPI (127.0.0.1:8000)
                                │
                                ├── PostgreSQL 15   all state, RLS FORCEd
                                └── Redis 7         rate limiting, coordination
```

Application nodes are **stateless**: all state lives in PostgreSQL, Redis and
object storage, configuration is environment-driven, and liveness (`/healthz`)
and readiness (`/readyz`) are separate probes. Adding a node is a deploy, not a
migration.

| | |
|---|---|
| Backend | FastAPI · SQLAlchemy 2 · Pydantic 2 · psycopg 3 |
| Database | PostgreSQL 15+ with row-level security |
| Cache | Redis 7+ |
| Frontend | Vanilla JavaScript, no build step |
| Security | Argon2id · Fernet · python-jose (JWT) · ldap3 |
| Documents | reportlab · openpyxl · python-docx · pypdf |

---

## Documentation

| | |
|---|---|
| [INSTALL.md](INSTALL.md) | Installation, packages, upgrade |
| [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) | System design and the ADRs behind it |
| [docs/API.md](docs/API.md) | REST API reference (`/api/v1`) |
| [docs/ADMIN_GUIDE.md](docs/ADMIN_GUIDE.md) | Administration |
| [docs/USER_MANUAL.md](docs/USER_MANUAL.md) | Full user manual |
| [docs/SYSTEM_MANUAL.md](docs/SYSTEM_MANUAL.md) | **System manual** — processes, every setting, the CLI, operation, troubleshooting |
| [docs/DATABASE.md](docs/DATABASE.md) · [docs/DATABASE_SCHEMA.md](docs/DATABASE_SCHEMA.md) | **Database manual** and the generated table-by-table reference |
| [docs/SECURITY.md](docs/SECURITY.md) · [docs/THREAT_MODEL.md](docs/THREAT_MODEL.md) | Security model and threat model |
| [docs/INTEGRATIONS.md](docs/INTEGRATIONS.md) | NetBox, Jira, Confluence, LDAP, scanners |
| [docs/HIGH_AVAILABILITY.md](docs/HIGH_AVAILABILITY.md) · [docs/DISASTER_RECOVERY.md](docs/DISASTER_RECOVERY.md) | HA and DR |
| [docs/DEVELOPMENT.md](docs/DEVELOPMENT.md) · [docs/CONTRIBUTING.md](docs/CONTRIBUTING.md) | Working on VEYRS |
| [docs/CHANGELOG.md](docs/CHANGELOG.md) | Release history |

---

## Tests

```bash
./scripts/test.sh
```

Never run bare `pytest` — `conftest.py` refuses to run without an explicit test
database rather than falling back to your production one.

---

## Security

VEYRS is a security platform, and its dependencies are **pinned, not floored**,
so that no unattended install silently moves `cryptography` or `SQLAlchemy`.

To report a vulnerability in VEYRS itself, see [docs/SECURITY.md](docs/SECURITY.md).

---

## License

VEYRS is licensed under the **Elastic License 2.0 (ELv2)**. The full text is in
[`LICENSE`](LICENSE).

In short — the licence text controls, this summary does not:

- **You may** use, modify and run VEYRS inside your own organisation, in
  production, for commercial purposes, with no fee and no user limit.
- **You may not** provide VEYRS to third parties as a hosted or managed
  service, where that service gives users a substantial set of its features.
- **You may not** remove or obscure the licensing and copyright notices.

VEYRS ships no license key and gates no feature behind one; the ELv2 clause
about license-key functionality has nothing here to restrict.

ELv2 is a source-available licence, not an OSI-approved open-source one. If you
need VEYRS under different terms — including offering it as a hosted or managed
service — contact **licensing@example.com**.
