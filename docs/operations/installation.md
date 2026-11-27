---
title: Installation
purpose: Install VEYRS from nothing in either supported shape, verify the release first, create the first administrator and prove the result.
scope: Native (veyrs-setup.sh, install.sh) and Docker Compose installation, release signature verification, first bootstrap and post-install checks; upgrades, backups and per-setting reference are in other documents.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [veyrs-setup.sh, install.sh, docker/veyrs-docker.sh, docker/init.sh, docker/compose.yaml, docker/compose.external-db.yaml, docker/env.example, scripts/verify-release.sh, release/allowed_signers, backend/veyrs/cli.py, backend/veyrs/config.py]
related: [operations/README.md, operations/services.md, operations/upgrade-rollback.md, DEPLOYMENT.md, DOCKER_COMPOSE_MANUAL.md, reference/configuration.md, SYSTEM_MANUAL.md]
---

# Installation

Two installers exist and they do different jobs. `veyrs-setup.sh` is the guided
front door: it checks the host, verifies the release, asks every question up
front and then drives the real installers. `install.sh` is the native installer
it drives. For Docker the real installer is `docker/veyrs-docker.sh`. Use the
guided one unless you need to control every step.

| # | Path | Command | Use it for |
|---|---|---|---|
| 1 | Guided, native | `sudo bash veyrs-setup.sh` and answer `native` | an installation you will operate |
| 2 | Guided, Docker | `sudo bash veyrs-setup.sh` and answer `docker` | the quickest complete stack |
| 3 | Guided, offline | `sudo bash veyrs-setup.sh --source veyrs-<v>-src.tar.gz [--images FILE] [--wheels FILE]` | a host with no internet |
| 4 | `install.sh` directly | `sudo ./install.sh` in a checkout at `/opt/veyrs` | native, when you need every flag, or a split database or Redis |
| 5 | Docker driver | `docker/veyrs-docker.sh init && docker/veyrs-docker.sh up` | development or a checkout you modify |

Prerequisites are in the [Operations manual, Requirements](README.md#requirements).

## Step 1. Verify the release

Every release from 0.33.0 carries `SHA256SUMS` and `SHA256SUMS.sig`, an OpenSSH
signature over `SHA256SUMS` made with the release key (principal `release@veyrs`,
namespace `veyrs-release`). The signature proves **origin**; the hashes then prove
**integrity** of each asset. A `.sha256` file beside an asset proves integrity only,
because whoever can replace the asset can replace its checksum.

Take the public key from the **repository**, never from the release you are
verifying: a key fetched from the same place as the signature proves nothing
(comment in `release/allowed_signers`).

```bash
# Any host with OpenSSH 8.1+; run in an empty directory.
GH=https://github.com/<owner>/veyrs          # the public repository named in the README
V=<X.Y.Z>
B=$GH/releases/download/v$V
curl -fLO $B/veyrs-setup.sh -O $B/SHA256SUMS -O $B/SHA256SUMS.sig
curl -fLo allowed_signers https://raw.githubusercontent.com/<owner>/veyrs/main/release/allowed_signers
ssh-keygen -Y verify -f allowed_signers -I release@veyrs -n veyrs-release \
    -s SHA256SUMS.sig < SHA256SUMS      # must print: Good "veyrs-release" signature ...
sha256sum -c --ignore-missing SHA256SUMS   # every downloaded file must say OK
```

If you have a source checkout, `scripts/verify-release.sh DIR` performs both steps
against `release/allowed_signers` and returns a distinct code per failure:

| Exit | Meaning |
|---|---|
| 0 | signature good and every listed asset matches |
| 3 | unsigned: `SHA256SUMS` or `SHA256SUMS.sig` is missing |
| 4 | bad signature: not made by the trusted key |
| 5 | hash mismatch, a required asset missing, or `SHA256SUMS` malformed |
| 6 | cannot verify: no usable trusted key (a `PLACEHOLDER` line counts as none) or no `ssh-keygen -Y` |

Anything other than 0 means **do not install**. `veyrs-setup.sh` embeds its own
copy of the key (a test fails if it differs from `release/allowed_signers`) and
repeats the check before it extracts anything: for 0.33.0 and later a missing or
unverifiable signature stops it unless `--allow-unsigned` is given, and a
signature that is present and wrong **always** stops it. Releases before 0.33.0
are checked against their `.sha256` only, with a warning.

| Release asset | What it is |
|---|---|
| `veyrs-setup.sh` | the guided installer |
| `SHA256SUMS`, `SHA256SUMS.sig` | hashes of every asset, and the signature over them |
| `veyrs-<v>-src.tar.gz` | the release tree |
| `veyrs-<v>-wheels-x86_64.tar.gz` | the pinned Python packages as wheels for CPython 3.11 to 3.13, so a native install needs no PyPI (0.34.0 and later) |
| `veyrs-images-<v>-amd64.tar.gz` and its `.sha256` | offline Docker image bundle (`veyrs`, `veyrs-console`, `postgres`, `redis`); not listed in `SHA256SUMS`, checked against its own `.sha256` |

## Step 2. Check the host

```bash
sudo bash veyrs-setup.sh --check     # changes and writes nothing
```

It reports the operating system and its support grade (tested, same family, or
unsupported), CPU, RAM and free disk (refusing below the minimums in the
[Operations manual](README.md#hardware)), the owners of ports 80, 8000 and 8080,
internet reachability, SELinux, firewall and Docker state, and whether a native
or Docker installation already exists. Add `--dry-run` to a real run to print the
plan: native mode runs `install.sh --dry-run`; Docker mode asks the questions,
prints the summary and stops.

## Step 3A. Guided install

```bash
sudo bash veyrs-setup.sh                     # interactive
sudo bash veyrs-setup.sh --version <X.Y.Z>   # a specific release (default: the latest)
```

What it does, in order (`veyrs-setup.sh` header and functions):

1. Checks the OS and requirements; installs `curl`, `tar`, `gzip` and `ssh-keygen` if missing.
2. Detects an existing native or Docker install and offers `update`, `reinstall` or `abort`. Both at once is refused.
3. Resolves the source: the tree it sits in, `--source DIR|TARBALL`, or the release tarball from GitHub, verified as in Step 1.
4. Asks native or Docker, and bundled or **external** PostgreSQL. An external role is checked through the real network path and **refused** if it is a superuser or has `BYPASSRLS`, does not own the database, the database is not UTF8, or the server is older than 15.
5. Sets the administrator password: asked twice (minimum from `password_min_length`, default 12), or generated into `/root/veyrs-admin-password.txt` (mode 0600). There is never a default password.
6. Installs, waits for `/readyz`, signs in as the administrator through the real front door and writes `/root/veyrs-setup-summary.txt` and the log `/var/log/veyrs-setup.log`.

Re-running is safe. It never rotates the administrator password, the database
password, `VEYRS_SECRET_KEY` or `VEYRS_ENCRYPTION_KEY`.

### Unattended

```bash
# answers.env  (every key optional unless marked)
SETUP_MODE=native                 # required with --yes on a fresh host: native | docker
SETUP_SERVER_NAME=veyrs.example.com
SETUP_PUBLIC_URL=https://veyrs.example.com
SETUP_ENVIRONMENT=production      # production requires an https URL
SETUP_ORG=acme
SETUP_ORG_NAME="Acme Corp"
SETUP_ADMIN_EMAIL=admin@example.com
SETUP_ADMIN_PASSWORD=             # empty: generate into /root/veyrs-admin-password.txt
SETUP_DB=bundled                  # or external (then SETUP_DB_HOST/PORT/NAME/USER/PASSWORD)
SETUP_FIREWALL=no                 # yes opens the console port in firewalld or ufw

sudo bash veyrs-setup.sh --yes --answers answers.env
```

Docker-only answers: `SETUP_HTTP_BIND` (default `127.0.0.1:8080`),
`SETUP_IMAGES=registry|build`, `SETUP_WORKERS=yes|no`, `SETUP_AGENT=yes|no`,
`SETUP_AGENT_ALLOW`, `SETUP_AGENT_TOKEN`, `SETUP_INSTALL_DOCKER=yes|no`. The full
list is `veyrs-setup.sh --help`.

> [!WARNING]
> In Docker mode the `workers` profile (feeds and digest) is **off by default**.
> Without it, vulnerability intelligence never refreshes and SLA deadlines never
> elapse, and nothing in the console says so. Answer `SETUP_WORKERS=yes` for any
> installation you intend to keep (`veyrs-setup.sh`, the workers question).

### Offline

Keep `SHA256SUMS` and `SHA256SUMS.sig` beside the tarball; the wheelhouse is picked
up automatically if it sits beside it.

```bash
sudo bash veyrs-setup.sh --source ./veyrs-<v>-src.tar.gz            # native, no PyPI
sudo bash veyrs-setup.sh --source ./veyrs-<v>-src.tar.gz \
     --images ./veyrs-images-<v>-amd64.tar.gz                        # Docker, no registry
```

`--images` requires `<file>.sha256` beside the bundle and refuses to load without it.

## Step 3B. Native install with `install.sh`

`install.sh` automates `INSTALL.md` end to end on a clean host. It is idempotent
(every create is guarded), never overwrites an existing `.env`, and never writes a
secret it did not generate. Run it as root from a checkout at `/opt/veyrs` (the
`--dir` option changes the path):

```bash
git clone <repository URL> /opt/veyrs && cd /opt/veyrs   # or extract a verified release tarball
sudo ./install.sh                                         # interactive
sudo ./install.sh --dry-run                               # print the plan, change nothing
```

Unattended, with the secret in the environment (a flag is visible in `ps`):

```bash
ADMIN_PASSWORD='<at least 12 characters>' sudo -E ./install.sh --unattended \
  --server-name veyrs.example.com --public-url https://veyrs.example.com \
  --org acme --org-name "Acme Corp" --admin-email admin@example.com
```

`--unattended` without `ADMIN_PASSWORD` fails in preflight unless `--skip-bootstrap`
is given, because the bootstrap reads the password from a terminal otherwise.

| Step | What `install.sh` does |
|---|---|
| 1 Packages | python, git, nginx, PostgreSQL and Redis through the family's package manager (apt-get, zypper, dnf); no compiler, every pinned dependency has a wheel |
| 1b Python | picks 3.13, 3.12 or 3.11 by probing, refuses one whose standard library is incomplete |
| 2 PostgreSQL | creates role `veyrs` (a plain `LOGIN` role: not superuser, no `BYPASSRLS`) and databases `veyrs` and `veyrs_test`, both `ENCODING 'UTF8' TEMPLATE template0`, **verifies UTF8**, and adds a scoped `scram-sha-256` rule to `pg_hba.conf` only if a password login fails (SUSE and RHEL ship `ident`) |
| 3 Redis | sets `requirepass`, enables and restarts the service, waits for `PING` |
| 4 Python | creates `/opt/veyrs/venv` and installs `requirements.txt` (the full pinned graph); with `VEYRS_PIP_WHEELHOUSE` it uses `--no-index` |
| 5 Configuration | creates `var/backups` and `var/documents` (mode 750) and writes `.env` (mode 0600) with generated `VEYRS_SECRET_KEY`, a Fernet `VEYRS_ENCRYPTION_KEY` from `veyrs keygen`, the database and Redis URLs, `VEYRS_METRICS_TOKEN` and the public URL. Production with a non-`https` URL is refused |
| 6 Schema and admin | `veyrs init-db`, `veyrs check`, then `veyrs bootstrap` unless skipped |
| 7 systemd | installs `veyrs-api.service` (paths and the Redis and PostgreSQL unit names rewritten for this host), `veyrs-updater.path` and `.service`, `veyrs-intel-sync.timer` and `veyrs-digest.timer`; waits up to 45 s for `/healthz` |
| 8 Console and nginx | copies `app.js`, `console.css`, `index.html` and `fonts/` to `/var/www/veyrs-console`, writes the vhost into the directory `nginx.conf` includes (`sites-enabled`, `vhosts.d` or `conf.d`), sets the SELinux boolean, tests and reloads nginx; opens the firewall only with `--open-firewall` |
| 9 Verify | `/healthz`, `/readyz`, an unauthenticated `/api/v1/assets` must answer 401 or 403 (otherwise "DO NOT EXPOSE THIS HOST"), console files byte-identical to the checkout, and `/healthz` through nginx on port 80 |

Options for split deployments: `--skip-postgres` (database on another host; pass
`--db-host`, `--db-port`, `--db-name`, `--db-user`, `--db-password`),
`--skip-redis`, `--skip-nginx`, `--skip-bootstrap`, `--skip-system-packages`,
`--skip-timers`. `--skip-timers` leaves the feeds and digest unscheduled: without
`veyrs-intel-sync.timer` intelligence never refreshes and SLA deadlines stop
elapsing. A second application node is installed the same way with
`--skip-postgres --skip-redis --skip-bootstrap`, a `.env` that carries the first
node's `VEYRS_SECRET_KEY` and `VEYRS_ENCRYPTION_KEY`, and the intel timer left
disabled ([Services](services.md#singleton-units-on-multi-node-installs)).

### Install by hand

`INSTALL.md` documents the same steps as commands (packages, role and databases,
virtualenv, `.env` from `.env.example`, `init-db`, `bootstrap`, unit, vhost). Use it
only when you need to deviate; every difference from `install.sh` is a place to
make a mistake. The two that matter most: create the database `UTF8` from
`template0`, and run `init-db`, not `sync-schema`, on a new database.

## Step 3C. Docker Compose

With the guided installer, answer `docker`. With the driver, from a checkout or a
verified release tree (Docker with the Compose plugin; not `docker-compose` v1):

```bash
docker/veyrs-docker.sh init                 # writes docker/.env (0600) with generated secrets, prints the admin password ONCE
docker/veyrs-docker.sh up --with-workers    # pull images, start, wait up to 180 s for /readyz
docker/veyrs-docker.sh status               # health, image versions, which background work is NOT running
```

The services, the one-shot `init`, the profiles `workers` and `agent`, the external
database overlay (`compose.external-db.yaml`), the image sources
(`VEYRS_IMAGE_SOURCE=registry|build|local`) and TLS are described in
[Services](services.md#docker-compose-services) and in depth in the
[Docker Compose manual](../DOCKER_COMPOSE_MANUAL.md). Three facts to know before
the first `up`:

- `init` creates the organization and administrator **only if the administrator does not exist**. Editing `VEYRS_ADMIN_PASSWORD` later changes nothing; `VEYRS_FORCE_BOOTSTRAP=1` resets it on purpose (`docker/init.sh`).
- `VEYRS_ENVIRONMENT=production` with a non-`https` `VEYRS_PUBLIC_BASE_URL` is refused by the driver and by the API. The stack speaks plain HTTP; TLS comes from a proxy in front.
- The database superuser is `postgres`; the application role is created `NOSUPERUSER ... NOBYPASSRLS` by `docker/initdb.d/10-app-role.sh`. Never set `POSTGRES_USER` to the application role: a superuser bypasses row level security and tenant isolation silently stops.

## First administrator (`veyrs bootstrap`)

Both installers run this for you. To run it yourself (for example after
`--skip-bootstrap`, or to add another organization):

```bash
cd /opt/veyrs
VEYRS_BOOTSTRAP_PASSWORD='<at least 12 characters>' \
  PYTHONPATH=backend venv/bin/python -m veyrs bootstrap \
  --org acme --name "Acme Corp" --email admin@example.com --superuser
```

| Option | Meaning |
|---|---|
| `--org`, `--email` | required; the organization slug and the administrator |
| `--name`, `--full-name`, `--locale` | display names; locale is one of `en es de fr it` |
| `--superuser` | marks the account as a **platform administrator**, who alone can open Software update, Installed software and Network access. Grant or revoke later with `veyrs platform-admin --email USER [--revoke]` (refuses to revoke the last one) |
| password | `VEYRS_BOOTSTRAP_PASSWORD`, else `--password` (visible in `ps`), else an interactive prompt |

> [!CAUTION]
> `bootstrap` on an **existing** user overwrites the password hash and prints
> `user exists, password reset`. Both installers check for the account first and
> skip it; calling the CLI by hand does not (`backend/veyrs/cli.py`, `bootstrap`).

The account receives the built-in `org-admin` role. Two-factor sign-in for it can
be set up from the host with `veyrs mfa-setup`
([System manual §2.12](../SYSTEM_MANUAL.md#212-two-factor-sign-in)).

## Post-install checks

Run all of them; each one has failed silently somewhere in this project's history.

```bash
# 1. Liveness and version (application node)
curl -s http://127.0.0.1:8000/healthz         # {"status":"ok","app":"VEYRS","version":"<expected>"}
# 2. Readiness: PostgreSQL and Redis both reachable
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/readyz     # 200
# 3. The API refuses anonymous callers
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/api/v1/assets   # 401 (or 403)
# 4. Configuration, storage and engines self-test
cd /opt/veyrs && PYTHONPATH=backend venv/bin/python -m veyrs check       # "all checks passed"
# 5. Units
systemctl is-active veyrs-api nginx; systemctl is-enabled veyrs-intel-sync.timer veyrs-digest.timer
# 6. The console copy matches the checkout (a stale console answers 200 too)
for f in index.html app.js console.css; do cmp /opt/veyrs/frontend/console/$f /var/www/veyrs-console/$f && echo "$f ok"; done
# 7. Through nginx, with the real Host header
curl -s -H 'Host: veyrs.example.com' http://127.0.0.1/healthz
```

```bash
# 8. Brand assets. The generated vhost has no /static/ block and install.sh does not
#    copy them, so a native install without the docs site renders unstyled until you do.
#    This mirrors what the console container image does (docker/Dockerfile, stage console).
install -d -m 755 /var/www/veyrs-console/static
install -m 644 /opt/veyrs/frontend/brand/veyrs-tokens.css /opt/veyrs/frontend/brand/logo/* /var/www/veyrs-console/static/
curl -s -o /dev/null -w '%{content_type}\n' -H 'Host: veyrs.example.com' http://127.0.0.1/static/veyrs-tokens.css   # text/css, not text/html
```

Then load intelligence now instead of waiting for the first hourly tick (the first
NVD pull takes hours without an API key):

```bash
cd /opt/veyrs
for f in sync-cwe sync-kev sync-epss sync-nvd; do PYTHONPATH=backend venv/bin/python -m veyrs $f; done
```

Finally sign in at the public URL, and run the suite once with
`./scripts/test.sh` (never bare `pytest`, see [Release](release.md#tests)).

## Uninstall

Docker installed with `veyrs-setup.sh`: `sudo bash veyrs-setup.sh --uninstall` keeps
the data volumes and the secrets file; add `--purge` to delete them (it asks you to
type `PURGE`). A native install has no uninstall script: stop and disable the
units, remove `/opt/veyrs`, the vhost and the databases by hand.

## Sources

- `veyrs-setup.sh` (usage, `signature_policy`, `evaluate_role`, `install_native`, `install_docker`, `uninstall_docker`)
- `install.sh` (steps 1 to 9, usage text)
- `docker/veyrs-docker.sh` (`cmd_init`, `cmd_up`), `docker/init.sh`
- `scripts/verify-release.sh` (exit codes), `release/allowed_signers`
- `backend/veyrs/cli.py` (`bootstrap`, `check`, `platform_admin`)
