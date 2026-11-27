---
title: Upgrade, rollback and restart
purpose: Give the procedures to move a VEYRS installation to a new version, prove it landed, restart services safely and go back when an upgrade fails.
scope: Native installs (guided, git deploy, in-product update), Docker installs, the schema step, verification, rollback and restart; installing from nothing and backup mechanics are in other documents.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [veyrs-setup.sh, install.sh, scripts/veyrs-updater.sh, scripts/verify-release.sh, backend/veyrs/api/v1/updates.py, backend/veyrs/cli.py, backend/veyrs/main.py, backend/veyrs/config.py, infrastructure/systemd/veyrs-api.service, infrastructure/systemd/veyrs-updater.path, docker/veyrs-docker.sh, docker/init.sh]
related: [operations/README.md, operations/installation.md, operations/backup-dr.md, operations/monitoring.md, DEPLOYMENT.md, DATABASE.md, troubleshooting/README.md]
---

# Upgrade, rollback and restart

## Rules that every upgrade follows

1. **Back up first.** A failed upgrade does not roll itself back ([Rollback](#rollback)). The updater refuses to run without a backup arranged for exactly this reason.
2. **Run `init-db`, never `sync-schema`, after the code lands.** VEYRS has no migration tool (`migrations/` holds a placeholder). `init-db` creates missing tables and reconciles columns; `sync-schema` only adds columns, indexes and foreign keys to tables that already exist and prints `0 columns added` on a database missing a release's new tables ([Schema step](#the-schema-step)).
3. **Refresh the console copy.** nginx serves `/var/www/veyrs-console`, a *copy* of `frontend/console/`. Skip it and the node runs the new API behind the old UI while every surface answers 200.
4. **The version lives in two places**, `pyproject.toml` and `config.Settings.version`; `/healthz` reports the second. A release where they differ reports the old number after a correct deploy ([Release](release.md#version-in-two-places)).
5. **Verify with artefacts, not status codes** ([Verification](#verification)).

```mermaid
flowchart LR
  B["Backup"] --> C["Code lands"]
  C --> P["pip install -r requirements.txt"]
  P --> S["veyrs init-db"]
  S --> U["Refresh console copy"]
  U --> R["Restart veyrs-api"]
  R --> V["Verify healthz, readyz, new endpoint"]
  V -->|"fails"| RB["Rollback"]
```

**Legend.** Boxes are steps in order; the arrow from Verify shows the only exit to rollback. The guided installer and the in-product updater perform all of these steps; a git deploy performs them by hand.

## Native: guided update (`veyrs-setup.sh`)

The supported way for an installation made by `veyrs-setup.sh` or `install.sh` from a release tree.

```bash
# On the application node, as root. Verify the release first (Installation, Step 1).
sudo bash veyrs-setup.sh --version <X.Y.Z>              # interactive: choose "update"
sudo SETUP_EXISTING=update SETUP_MODE=native bash veyrs-setup.sh --yes \
     --source ./veyrs-<X.Y.Z>-src.tar.gz                # unattended, offline
```

What it does to an existing native install (`place_native_tree`, `install_native`):

- reads the database URL, public URL and environment from `/opt/veyrs/.env`; **keeps** `.env`, `var/` and `venv/`, and never touches the administrator password (it checks whether the administrator exists and skips the bootstrap);
- copies the new tree over `/opt/veyrs` and deletes files the previous release shipped and this one does not, using the manifest `.setup-manifest` written by the previous run, so nothing you added is removed;
- refuses to run over a **git checkout** (`/opt/veyrs/.git`): update that with git;
- re-runs `install.sh --unattended`, which installs requirements (from the release wheelhouse when present), runs `init-db` and `check`, rewrites the units, copies the console files, reloads nginx and verifies;
- leaves a timer that you disabled **disabled** (the intel timer is a singleton on multi-node installs);
- checks `/readyz` and the console at the end.

**Offline hosts (0.42.1 and later).** With the wheelhouse beside the tarball, the update needs neither PyPI nor GitHub, and the operating-system repositories are optional: when they cannot be refreshed, `install.sh` checks that every required package is already installed and continues (a missing package still stops it, by name). Docker installs update offline with `--images veyrs-images-<X.Y.Z>-amd64.tar.gz`.

Do this node by node on a multi-node installation, and run it on the node that owns the database migration first ([Multi-node](#multi-node-rolling-upgrade)).

## Native: git-checkout deploy

For installations whose `/opt/veyrs` is a git checkout (the operator's own environment). The in-product updater refuses these by design ("managed by git deploy").

```bash
# On each application node, as root. Replace <sha> with the FULL commit you tested.
cd /opt/veyrs
git status --porcelain                  # must be empty; deploy from clean trees only
git fetch -q origin && git merge --ff-only <sha>
venv/bin/pip install -r requirements.txt
# On ONE node per upgrade (the database is shared). init-db is idempotent:
(cd /opt/veyrs/backend && set -a && . ../.env && set +a && PYTHONPATH=. ../venv/bin/python -m veyrs init-db)
# Console copy, ALWAYS (whole frontend/console/ with fonts, plus the brand files under static/, swapped atomically):
scripts/publish-sites.sh --only console
# Docs Center and product site, on every node (prints a fingerprint per tree to compare between nodes):
#   scripts/publish-sites.sh --only docs,web
systemctl restart veyrs-api
timeout 60 bash -c 'until curl -sfo /dev/null http://127.0.0.1:8000/readyz; do sleep 1; done' \
  && curl -s http://127.0.0.1:8000/healthz || journalctl -u veyrs-api -n 40 --no-pager
```

The documentation and product sites are separate: rebuild them with
`python3 site/build.py --out /var/www/veyrs` and
`python3 site/web/build_web.py --out /var/www/veyrs-web`, on every node, and
compare `md5sum` of the trees ([Services](services.md#documentation-and-product-sites)).

The reference environment wraps these steps in a small root script that takes a
backup of the tree, refuses a dirty tree, fast-forwards to an exact SHA, runs
`init-db` only when asked, restarts, then asserts `/healthz` version, `/readyz`
200 and zero failed units (see the internal environment record).

### Multi-node rolling upgrade

With two application nodes behind a proxy, upgrade one at a time. The upstream
proxy marks a stopped node down after a couple of failed connections and sends
traffic to the other (`HIGH_AVAILABILITY.md`, "What is protected").

1. Node 1: deploy with `init-db` (additive changes are compatible with the code still running on node 2).
2. Verify node 1 ([Verification](#verification)).
3. Node 2: deploy **without** `init-db`; verify.
4. Compare `git rev-parse HEAD` on both nodes and `md5sum` of the console files.

Both nodes must share `VEYRS_SECRET_KEY` and `VEYRS_ENCRYPTION_KEY`; rotating the
signing secret on one node rejects tokens issued by the other.

## In-product update

Administration, **Software update** (platform administrators only; API keys never
qualify) shows the installed and latest versions, whether the release is signed,
the install mode and the history of updater runs. Native installs made by the
installer can apply a signed release from three sources: the public release
(`release`), files uploaded in the console (`upload`) or a local directory such as
a USB disk (`local`, `VEYRS_UPDATE_LOCAL_DIR`).

| Endpoint (platform administrator) | Purpose |
|---|---|
| `GET /api/v1/admin/updates` | installed version, latest release, `can_apply` and the reason when false, history; `?refresh=true` bypasses the one-hour cache |
| `POST /api/v1/admin/updates/apply` | records the request in the audit trail and drops one JSON file into the spool; returns 202. The API does nothing else |
| `POST /api/v1/admin/updates/uploads`, `PUT .../uploads/{upload_id}/{name}`, `POST .../uploads/{upload_id}/finish`, `DELETE .../uploads/{version}` | stage a release uploaded from a laptop |

`can_apply` is false, with the reason in the response, for a git checkout, a
container, or when there is no newer release. Set `VEYRS_UPDATE_URL=` (empty) on an
air-gapped node: no check leaves the host.

The root half is `scripts/veyrs-updater.sh`, started by `veyrs-updater.path`:

| Step | What it does and what stops it |
|---|---|
| request | reads one small JSON (target version, source keyword, who asked); malformed is refused |
| preflight | refuses a git checkout, a container, a target not newer than the installed version, and **no backup arranged** (`VEYRS_UPDATE_PRE_HOOK` or `VEYRS_UPDATE_SKIP_BACKUP=1`) |
| download | `SHA256SUMS`, `SHA256SUMS.sig`, `veyrs-setup.sh`, the source tarball and, if listed, the wheelhouse; missing signature is refused |
| verify | `scripts/verify-release.sh` of the **installed** tree with the **installed** `release/allowed_signers`; unsigned (3), bad signature (4), mismatch (5) or cannot verify (6) stop it before anything is touched; the tarball must declare the requested version |
| backup | runs `VEYRS_UPDATE_PRE_HOOK` (an absolute path, owned by root, not group or other writable, outside `var/` and the spool); a failing hook stops the update with nothing changed |
| install | the verified `veyrs-setup.sh --yes --version <target> --source <tarball>` with `SETUP_EXISTING=update` |
| health | within 180 s `/healthz` must report the target version and `/readyz` must answer 200 |

Each run writes `/var/lib/veyrs/update-status/<id>.json` (steps with name, ok,
detail, time) and `<id>.log`; the console shows the history and the last 20 are kept.
The request file is removed whatever the outcome, so a failure does not loop.

```bash
# Enable the backup hook once (application node with a local database):
echo 'VEYRS_UPDATE_PRE_HOOK=/opt/veyrs/scripts/backup.sh' >> /opt/veyrs/.env
systemctl status veyrs-updater.path        # active (waiting)
# Watch a run:
ls -t /var/lib/veyrs/update-status/ | head -3
journalctl -u veyrs-updater -n 50 --no-pager
```

> [!WARNING]
> `scripts/backup.sh` dumps the **local** database. With the database on another
> host it exits with an error unless `BACKUP_DSN` names a superuser or `BYPASSRLS`
> role there. Since 0.41.0 the updater supports that topology without a wrapper:
> when `VEYRS_UPDATE_PRE_HOOK` is unset and `BACKUP_DSN` is set, the backup step runs
> `scripts/backup.sh` with it. Put the DSN where the API cannot read it:
>
> ```bash
> install -d -m 755 /etc/veyrs
> install -m 600 /dev/null /etc/veyrs/backup.env          # root-only; veyrs-updater.service and backup.sh load it
> echo "BACKUP_DSN='postgresql://veyrs_backup:CHANGE_ME@db.example.com:5432/veyrs'" >> /etc/veyrs/backup.env
> echo 'VEYRS_UPDATE_PRE_HOOK=/opt/veyrs/scripts/backup.sh' >> /opt/veyrs/.env   # lets the console show "backup configured"
> ```
>
> `backup.sh` also refuses a dump that has fewer `TABLE DATA` entries than tables.

## Docker

**Installed with `veyrs-setup.sh`:** download and verify the new `veyrs-setup.sh`
and run it; choose `update` (or `SETUP_EXISTING=update` with `--yes`). It places
the release in `/opt/veyrs-docker/releases/<version>`, re-points `current`, keeps
`veyrs.env` and the profile choices, moves the image tags and runs `up` with the
same flags. Offline: add `--images FILE`.

```bash
docker/veyrs-docker.sh backup                 # always first
sudo bash veyrs-setup.sh --version <X.Y.Z>    # update
veyrs-docker status
```

**Driver install from a checkout:**

```bash
docker/veyrs-docker.sh backup
git pull                                      # or check out the release tag
# with VEYRS_IMAGE_SOURCE=registry, point the three image variables at the new version in docker/.env
docker/veyrs-docker.sh up --with-workers      # the SAME profile flags as before
docker/veyrs-docker.sh status
```

`up` recreates only containers whose configuration changed, and `init` re-runs
`init-db` on every `up`. **Repeat every profile flag you use**: a service in a
profile you did not name keeps running the old image beside the new API. `restart`
does not re-read `.env`; a changed `.env` needs `up`. The in-product updater refuses
containers: a container is replaced, not patched.

## The schema step

| Command | Creates tables | Adds columns, indexes, FKs | Binds RLS, seeds roles and catalogues | Use |
|---|---|---|---|---|
| `veyrs init-db` | yes | yes (calls `sync_columns`) | yes (`ENABLE` and `FORCE ROW LEVEL SECURITY`, policy `veyrs_tenant_isolation`) | **every deploy**, and on a new database. Idempotent |
| `veyrs sync-schema` | **no** | yes; widens a `VARCHAR` or `TEXT` only | no | a column-only reconciliation. On a database missing new tables it exits 0 having done nothing |

`sync_columns` never drops, renames or narrows anything, and refuses to add a
`NOT NULL` column without a default to a non-empty table (it prints the DDL you must
run). Destructive changes are therefore manual decisions
([DATABASE.md](../DATABASE.md)). `init-db` is also what makes a new tenant table
isolated: a table that exists without its policy leaks across tenants, which is why
a restore ends with `init-db` too.

A release that adds tables, deployed without `init-db`, produces
`UndefinedTable` 500s on exactly the new endpoints while `/healthz` stays green.

## Verification

Run on every node after the restart.

```bash
curl -s http://127.0.0.1:8000/healthz                                   # version must be the release
curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/readyz   # 200
git -C /opt/veyrs rev-parse HEAD                                        # same commit on every node (git deploys)
for f in index.html app.js console.css; do md5sum /opt/veyrs/frontend/console/$f /var/www/veyrs-console/$f; done   # pairs must match
grep -o 'app.js?v=[0-9]*' /var/www/veyrs-console/index.html             # the cache-busting value of this release
systemctl --failed --no-legend                                          # empty
journalctl -u veyrs-api --since '5 min ago' --no-pager | grep -c '"level":"ERROR"'   # 0
```

Then call at least one endpoint the release added (a release deployed without
`init-db` fails only there), and on the node that runs it check the next tick:
`journalctl -u veyrs-intel-sync -n 30 --no-pager` shows `=== done ..., status 0`.

## Rollback

VEYRS has no down-migrations and `init-db` only adds, so **a code rollback is
safe against the upgraded schema**: older code ignores new tables and columns. The
exception is a release that required a manual change to an existing column; read the
changelog entry for the version you are leaving.

### Code only (the usual case)

```bash
# Git deploy: go back to the previous commit recorded before the deploy.
cd /opt/veyrs && git checkout --detach <previous-full-sha>
venv/bin/pip install -r requirements.txt          # only if requirements.txt differs
scripts/publish-sites.sh --only console           # the console copy of the checked-out commit
systemctl restart veyrs-api
curl -s http://127.0.0.1:8000/healthz             # the previous version
```

Take a tarball of the tree before every deploy
(`tar czf /root/veyrs-pre-<version>-$(date +%Y%m%d-%H%M%S).tgz --exclude=./veyrs/venv --exclude=./veyrs/var -C /opt veyrs`)
plus the recorded `HEAD`, so a rollback does not depend on the remote being
reachable. For a release-tree install, run `veyrs-setup.sh --source` with the
previous verified tarball and `SETUP_EXISTING=reinstall`; the guided script does not
compare versions (the in-product updater does, and refuses a target that is not
newer).

### Code and data

When the upgrade damaged data (a bad backfill, an accidental delete), restore the
pre-upgrade backup with `scripts/restore.sh` and then return the code to the matching
version ([Backup and DR](backup-dr.md#restore)). `restore.sh` ends with `init-db`, which
re-adds anything the restored schema lacks.

### Docker

`veyrs-setup.sh` keeps every previous release under `/opt/veyrs-docker/releases/`.
To go back: re-point `current` to the old release directory, set `VEYRS_IMAGE`,
`VEYRS_CONSOLE_IMAGE` and `VEYRS_AGENT_IMAGE` in `veyrs.env` to the old version tag
(offline: `veyrs-docker load` the old bundle, `VEYRS_IMAGE_SOURCE=local`), and run
`veyrs-docker up` with the same profile flags. If the database changed in a way the
old image cannot read, restore the `veyrs-docker backup` taken before the upgrade
([Backup and DR](backup-dr.md#docker)). This path is implemented in the scripts but
was not exercised for this document.

### After a failed in-product update

Read `/var/lib/veyrs/update-status/<id>.json` for the failing step. A refusal at
request, preflight, download, verify or backup changed nothing. A failure at
`install` or `health` may have left the host between versions: restore from the
pre-update backup if the API does not return, then fix the cause and queue the update
again.

## Restart procedures

| Action | Command | Effect |
|---|---|---|
| Restart the API | `systemctl restart veyrs-api` | about 2 s; in-flight requests get up to 30 s (`TimeoutStopSec`). Sessions survive if `VEYRS_SECRET_KEY` is unchanged; rate-limit windows live in Redis |
| Apply a `.env` change | `systemctl restart veyrs-api` | the environment is fixed when systemd starts the unit; `reload` (SIGHUP to uvicorn) is not a substitute for a restart after editing `.env` |
| Restart nginx | `nginx -t && systemctl reload nginx` | `reload` is graceful; `restart` drops connections |
| Restart the agent | `systemctl restart veyrs-agent` | SIGINT; a running scan is abandoned and its lease reaped by the server, then the job can run again |
| Run a feed tick now | `systemctl start veyrs-intel-sync.service` (blocks for hours on a cold corpus; add `--no-block`) | does exactly what the timer does |
| Docker, one service | `docker/veyrs-docker.sh restart api` | same config; does not re-read `.env` |
| Docker, apply `.env` | `docker/veyrs-docker.sh up --with-workers` | recreates changed containers |

Never wait on a restart with a bare `sleep`; poll:

```bash
systemctl restart veyrs-api
timeout 30 bash -c 'until curl -sfo /dev/null http://127.0.0.1:8000/readyz; do sleep 1; done' \
  && echo up || journalctl -u veyrs-api -n 40 --no-pager
```

**Boot order after a power loss.** PostgreSQL, then Redis, then `veyrs-api`, then
nginx. The API unit is ordered `After=` PostgreSQL and Redis but does not require
them, so on a split topology the API node can come up before the database node and
answer `/readyz` 503 until they return; it recovers by itself (the engine uses
`pool_pre_ping`). Docker stacks use `restart: unless-stopped`; `init` runs on `up`,
not on a reboot.

## Sources

- `veyrs-setup.sh` (`place_native_tree`, `install_native`, `install_docker`)
- `install.sh` (steps 5 to 9), `scripts/veyrs-updater.sh`, `backend/veyrs/api/v1/updates.py`
- `backend/veyrs/cli.py` (`init_db`, `sync_columns`), `backend/veyrs/db.py`
- `docker/veyrs-docker.sh`, `docker/init.sh`, `infrastructure/systemd/veyrs-api.service`
- Existing procedure in `docs/DEPLOYMENT.md` (Upgrading), re-verified against the scripts
