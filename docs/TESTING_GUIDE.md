# Testing Guide

This guide covers how VEYRS 0.35.1 is tested: the runner script, the test database, the fixtures, how to add and run tests, the guardrail tests that encode past incidents, and how a change is verified in the browser and after a deploy. It is written for anyone who changes the code. Everything here was checked against the repository; where a step depends on tooling that is not in the repository, the guide says so.

## The short version

- **Always use `./scripts/test.sh`, never bare `pytest`.** The script loads `.env`, points the suite at the separate `veyrs_test` database and raises the rate limits. Bare `pytest` aborts in `tests/conftest.py` before any test runs.
- **Targeted by default.** Run only the test files for the code you changed. Run the full suite only when someone explicitly asks for it.
- **Every bug fix ships with a regression test.** Prove the test by mutation: revert the fix or break the code, watch the test go red for the right reason, then restore.
- **Guardrail tests are not negotiable.** The files listed in [Guardrail tests](#guardrail-tests) each encode an incident. Never loosen one to get green.
- **Green tests prove the code, not the deployment.** A console change is verified in a real headless browser. A deploy is verified with `/healthz`, `/readyz`, the commit on both nodes and an `md5sum` of every docroot.

## How the suite is organised

Everything lives under `tests/`. `pytest.ini` at the repository root sets:

| Setting | Value | Effect |
|---|---|---|
| `pythonpath` | `backend` | `import veyrs` works without an ambient `PYTHONPATH` |
| `testpaths` | `tests` | A bare run collects only `tests/` |
| `addopts` | `-q --strict-markers` | Quiet output; an undeclared marker is an error |
| `markers` | `integration` | The only declared marker (see [Markers](#markers)) |
| `filterwarnings` | `error::DeprecationWarning:veyrs.*` | A deprecation warning raised from VEYRS code fails the test |

The tree holds 78 `test_*.py` modules, one `conftest.py`, and `tests/fixtures/` with the three official CVSS corpora (`cvss_official_v2.txt`, `cvss_official_v3.txt`, `cvss_official_v4.txt`). There is no `tests/__init__.py`.

### Naming

- **Phase files.** Most modules are named after the development phase that introduced the feature: `test_phase<N>_<topic>.py`, for example `test_phase24_mfa.py` or `test_phase48_secret_vault.py`. The module docstring states what the phase guarantees.
- **Topic files.** Guards added after an incident are named after the guarantee, not the phase: `test_write_paths.py`, `test_audit_rls.py`, `test_cvss_official.py`, `test_docs_are_current.py`.
- **Test functions state the guarantee.** `test_a_token_from_one_tenant_cannot_read_another` tells a reviewer what broke. `test_import_works` tells them nothing. [Contributing](/CONTRIBUTING.html) makes this a rule.
- **Docstrings explain the incident.** When a test exists because something shipped broken, its docstring says what broke and when. Keep that habit.

### Kinds of test

| Kind | What it proves | Examples |
|---|---|---|
| Pure engine tests | A function with no database and no I/O gives the specified answer | `test_cvss_official.py`, `test_widen_columns.py`, `test_distro_version_normalisation.py` |
| HTTP tests | A route answers, authorizes and stays inside its tenant, through FastAPI's `TestClient` | `test_phase2_core.py`, `test_write_paths.py`, `test_phase10_hardening.py` |
| Database-policy tests | Row-level security is present, forced and bites | `test_audit_rls.py`, `test_phase2_core.py` |
| Console source guards | The console's JavaScript and CSS agree with each other and with the API | `test_console_layout_classes.py`, `test_phase31_console_wiring.py`, `test_phase42_console_screens.py` |
| Script and installer tests | Shell scripts are run against local fakes, never the network | `test_phase52_release_signing.py`, `test_phase52_updates.py`, `test_installer_dry_run_guard.py`, `test_sync_intel_script.py` |
| Packaging guards | Dependencies are pinned, locked and importable; the version is consistent | `test_phase24_dependencies.py`, `test_container_stack.py`, `test_container_images.py` |
| Documentation guards | The manuals and the rendered sites still match the code | `test_docs_are_current.py`, `test_site_render.py`, `test_docs_worked_example.py` |

## The runner: scripts/test.sh

`scripts/test.sh` is the canonical entry point. Every argument you pass goes straight to pytest. In order, it does the following:

1. Sets `-euo pipefail` and changes to the repository root, so it works from any directory.
2. If `.env` exists, sources it with `set -a`, so every variable in it is exported to pytest.
3. Exports `VEYRS_ENVIRONMENT=development`. This overrides whatever `.env` says.
4. Exports `VEYRS_RATE_LIMIT_PER_MINUTE=100000` and `VEYRS_AUTH_RATE_LIMIT_PER_MINUTE=100000`. The production defaults are 240 and 10 per minute, and the whole suite calls the API from one client identity. The limiter itself is still tested, in `test_phase10_hardening.py`, against isolated apps with small limits.
5. Derives `VEYRS_TEST_DATABASE_URL`, unless you already set it. A `VEYRS_DATABASE_URL` that ends in `/veyrs` becomes the same URL ending in `/veyrs_test`. A URL that already ends in `_test` is used as it is. Anything else is passed through unchanged, so the conftest guard refuses it.
6. Runs `venv/bin/python -m pytest "$@"` with `exec`.

Only the trailing database name is swapped. A naive `s|/veyrs|/veyrs_test|` would rewrite the `//veyrs:` in the userinfo first and log in as a user called `veyrs_test`. Both the script and `conftest.py` carry the same comment about this.

The script assumes a virtual environment at `venv/` in the repository root. `python -m pytest` also puts the repository root on `sys.path`, which is what lets the modules that write `from tests.conftest import ...` or `from tests.test_phase52_release_signing import ...` resolve those imports.

### Why bare pytest fails

`tests/conftest.py` resolves the database URL before it imports anything from `veyrs`:

- It takes `VEYRS_TEST_DATABASE_URL` if set; otherwise it derives one from `VEYRS_DATABASE_URL` the same way the script does.
- If the result is empty, it raises `RuntimeError: no test database configured`.
- If the database name does not end in `_test`, it raises `refusing to run tests against database ...`.

Only then does it export the URL as `VEYRS_DATABASE_URL` for the app. The guard exists because the suite creates and destroys tenants by the thousand. Before it existed, a bare `pytest` with no `.env` loaded fell back to the built-in default URL, which is the production database, and left 1,198 orphan `tenant-*` organisations there on 2026-08-10.

> **Note:** `conftest.py` reads only the process environment, not `.env`. That is why the script sources `.env` first.

## The test database

Tests run against a real PostgreSQL database, not SQLite. The schema depends on JSONB, UUID columns and row-level security, so an in-memory stand-in would test something VEYRS does not deploy.

### Creating it

Create `veyrs_test` next to `veyrs`, owned by the application role, **in UTF8**:

```bash
sudo -u postgres psql -c "CREATE DATABASE veyrs_test OWNER veyrs ENCODING 'UTF8' TEMPLATE template0;"
sudo -u postgres psql -c "SELECT datname, pg_encoding_to_char(encoding) FROM pg_database WHERE datname LIKE 'veyrs%';"
```

- **UTF8 is mandatory.** A `SQL_ASCII` cluster returns `bytes` instead of `str`, and the failures surface weeks later as decoding errors on advisories. `TEMPLATE template0` is what makes `ENCODING 'UTF8'` legal on a cluster whose default is something else. `install.sh` creates both databases this way and verifies the encoding instead of assuming it.
- **The role must not bypass RLS.** Connect as a role that is `NOSUPERUSER` and `NOBYPASSRLS`. A superuser skips every policy, so every isolation test would pass for the wrong reason. `test_audit_rls.py::test_the_suite_is_not_running_as_a_role_that_bypasses_rls` fails the run if you get this wrong.
- **Remote production database, local test database.** `VEYRS_TEST_DATABASE_URL` is a separate setting so that you can point the suite at a local `veyrs_test` while `VEYRS_DATABASE_URL` points elsewhere. A test run then cannot reach the production cluster at all.
- **Access.** If PostgreSQL uses `pg_hba.conf` rules per database, list `veyrs_test` beside `veyrs` (`INSTALL.md` shows `host veyrs,veyrs_test veyrs 127.0.0.1/32 scram-sha-256`).

The container stack (`docker/veyrs-docker.sh init`) also gives you a correctly configured cluster: UTF8, RLS applied, and an application role created `NOSUPERUSER NOBYPASSRLS`.

### Schema

You do not run `init-db` against the test database by hand. The session-scoped autouse fixture `_schema` in `conftest.py` calls `veyrs.cli.init_db(None)` once per run. That is the same code as `python -m veyrs init-db`: it creates every table, reconciles added columns, enables and forces the `veyrs_tenant_isolation` policy on every tenant-owned table, and seeds the built-in roles and compliance catalogues. It is idempotent, so the test database keeps its rows between runs. Tests therefore create their own isolated organisations instead of assuming an empty database.

## Fixtures and helpers

All shared fixtures live in `tests/conftest.py`.

| Fixture or helper | Scope | What it gives you |
|---|---|---|
| `_schema` | session, autouse | Runs `init_db` once before the first test |
| `_clear_rate_limits` | session, autouse | Flushes the limiter's counters before and after the run |
| `client` | function | `TestClient(app)` for the real FastAPI app |
| `org_a`, `org_b` | function | A fresh organisation with an `org-admin` user; returns `(org_id, slug, email)` |
| `admin_a`, `admin_b` | function | `Authorization: Bearer ...` headers for that organisation's admin |
| `login(client, email, slug, password=ADMIN_PASSWORD)` | helper | Flushes the limiter, posts to `/api/v1/auth/login`, asserts 200, returns the token body |
| `auth_headers(client, email, slug)` | helper | The bearer header built from `login()` |
| `_make_org(prefix)` | helper | The function behind `org_a` and `org_b`, for module-scoped organisations |
| `_flush_rate_limits()` | helper | Clears the in-process limiter and every `veyrs:rl:*` key in Redis; a missing Redis is ignored |
| `ADMIN_PASSWORD` | constant | The password of every fixture admin |

Organisations are named `<prefix>-<8 hex>`, so tests never collide and never need cleanup to pass. Conftest also sets `VEYRS_ENVIRONMENT=development` and a 47-character `VEYRS_SECRET_KEY` if they are not already set.

### When you need many logins

The production auth limit is 10 per minute per IP, and every test login comes from the same identity. `login()` flushes the counters before every call for that reason. A module that makes many requests can still trip the general limit; `test_write_paths.py` shows the pattern to use instead: one module-scoped organisation (`_make_org("write-path")`), one module-scoped `TestClient`, one login reused by every test.

### Tables without a tenant

`feed_runs` and `cves` have no `organization_id`. They are the shared intelligence corpus, so they are the one place where an earlier test can pollute a later one. `test_phase35_operability.py` has helpers that make such tests hermetic (`_only_feed_runs()` deletes what an earlier test left). Use the same approach for any global table.

## Markers

`pytest.ini` declares a single marker, `integration` ("requires PostgreSQL/Redis"), and `--strict-markers` turns any other marker into an error. No test currently uses it: every database test needs PostgreSQL anyway, and `-m "not integration"` deselects nothing. To add a marker, declare it in `pytest.ini` in the same change.

The markers in real use are `parametrize` and `skipif`. Four tests skip on purpose when a tool is missing:

| Test | Skips when |
|---|---|
| `test_phase52_release_signing.py` (tests marked `needs_ssh_keygen`) | `ssh-keygen` is not installed |
| `test_phase52_release_signing.py::test_the_offline_publish_harness_passes` | The tree is not a git checkout, or `git` is missing |
| `test_phase52_updates.py` (tests marked `needs_tools`) | Any of `ssh-keygen`, `curl`, `bash`, `tar`, `sha256sum` is missing |
| `test_phase52_updates.py::test_updater_runs_a_safe_pre_hook_and_refuses_an_unsafe_one` | The run is not root |

A skip is not a pass. If a release guard skips on your machine, run it where the tool exists before you call the change verified.

## Running tests

### A file, a test, a pattern

```bash
./scripts/test.sh tests/test_phase6_ai.py                                   # one file
./scripts/test.sh tests/test_phase2_core.py::test_tenant_binding_survives_commit   # one test
./scripts/test.sh tests/test_cvss_official.py -k v4                        # by name pattern
./scripts/test.sh tests/test_write_paths.py -x                              # stop at the first failure
./scripts/test.sh tests/test_audit_rls.py -v                                # show each test id
```

Parametrized tests have readable ids. A single CVSS vector, for example, is `test_v4_official[CVSS:4.0/AV:N/...]`; use `-k` with a fragment of the vector instead of typing the whole id.

### Targeted by default

Run the files that cover what you changed, normally one to three. To find them:

```bash
ls tests/ | grep -iE 'mfa|radius|oidc'                 # by topic in the file name
grep -l 'services.reporting' tests/*.py               # by the module a test imports
```

Add the guardrail files that touch the same surface. A new route also means `test_phase10_hardening.py` (route protection and list endpoints) and `test_write_paths.py` if it writes. A docs change means `test_docs_are_current.py` and `test_site_render.py`.

### The full suite

```bash
./scripts/test.sh
```

Run it only when someone explicitly asks for it. [Development](/DEVELOPMENT.html) states that the full suite takes about 30 seconds, including the CVSS corpus. If it takes minutes, the usual cause has been two pytest processes competing for the same database, not slow code.

### Reading the result

Judge a run by pytest's exit code, not by grepping the output:

| Exit code | Meaning |
|---|---|
| `0` | Every collected test passed (skips allowed) |
| `1` | At least one test failed |
| `2` | Interrupted, or a test module failed to import during collection |
| `4` | Usage error: an unknown option, an undeclared marker, or `conftest.py` failing to load (the database guard ends the run here) |
| `5` | Nothing was collected, usually a wrong path or `-k` pattern |

### One run at a time

Never run two pytest processes against the same `veyrs_test` database. They contend for the same rows and both results become worthless. Do not edit the tree under a running suite either.

## Writing a test

1. Put it in the file of the feature it guards. If it encodes an incident that crosses features, create a topic file named after the guarantee.
2. Start the module with a docstring that says what is guaranteed and, for a regression, what broke.
3. Take `client` plus `org_a`/`admin_a` (and `org_b`/`admin_b` for any isolation claim). Never reuse another test's organisation.
4. Assert the behaviour a user or operator depends on: status code, response shape, the row that must or must not be visible. Do not assert implementation details.
5. Cover the failure shapes too: the 4xx for bad input, the 403 for a role without the permission, the 404 for another tenant's object.
6. Run the file with `./scripts/test.sh tests/<file>.py`, then mutate the code to prove the test bites (next section).

Some changes have a fixed checklist, from [Development](/DEVELOPMENT.html) and [Contributing](/CONTRIBUTING.html):

- **A new collection route:** add its path to `LIST_ENDPOINTS` in `tests/test_phase10_hardening.py`. `test_list_endpoints_return_a_valid_page` then checks the pagination contract over HTTP.
- **A new write route:** add a probe to `WRITE_PROBES` in `tests/test_write_paths.py`.
- **Any new route:** `test_every_route_is_protected` walks the live app and fails if the route has no server-side authorization.
- **A new setting:** document the `VEYRS_*` variable in `docs/SYSTEM_MANUAL.md`, or `test_docs_are_current.py` fails.
- **A model change:** regenerate `docs/DATABASE_SCHEMA.md` with `python3 scripts/gen-schema-doc.py`; the docs guard runs it with `--check`.
- **A security-relevant change:** the pull request names the test that proves the control still bites.

Never weaken a default to make a test pass. Either the default is wrong, and you change it deliberately and say so, or the test is wrong.

## Bug fixes: regression test and mutation proof

Every bug fix ships with a regression test, and the test must be proven.

1. Reproduce the bug and note the exact error.
2. Write the smallest test that shows it. Run it on the unfixed code: it must fail, and the failure message must describe this bug, not an unrelated error.
3. Apply the fix. The test goes green.
4. **Mutation check:** revert the fix, or break the invariant the test claims to protect, and run the test again. It must go red for the right reason.
5. Restore the code and run the test once more. It must be green.
6. Run the targeted files around the change.

If the test stays green against the broken code, it is not a test of the fix. Rewrite it or delete it.

Two patterns in the repository are worth copying:

- **Refuse a vacuous pass.** `test_audit_rls.py` starts by asserting that the suite is not connected as a role that bypasses RLS. Without that, every isolation assertion after it would pass for the wrong reason. If your test can pass vacuously, add a precondition test like this.
- **Run a guard against a mutated copy.** `scripts/test-publish-github.sh` accepts `SCRIPT=/path/to/a/mutated/copy.sh` and runs its whole scenario set against that copy. The mutated copy must make cases fail.

## Guardrail tests

These tests encode incidents. Each line says what it protects. Run the relevant ones whenever you touch the surface they guard.

### Write paths, tenancy and RLS

- `tests/test_write_paths.py`: every audited write endpoint is called over HTTP; it may reject (4xx) but must never raise (5xx). It exists because a changed `audit.record()` signature broke five modules and nobody noticed until "New asset" in the console returned 500.
- `tests/test_audit_rls.py`: `audit_log` and `ai_audit_log` carry a forced tenant policy, rows are invisible across tenants, a rejected audit write does not poison the request, and directory logins bind their tenant before writing.
- `tests/test_phase2_core.py::test_tenant_binding_survives_commit`: the RLS tenant binding survives `commit()`; it used to be transaction-local, and every later query silently returned zero rows.
- `tests/test_phase2_core.py` (tenant isolation block): users, objects by UUID, teams and the audit trail never cross tenants; another tenant's object is a 404, not a 403.
- `tests/test_phase10_hardening.py::test_a_token_from_one_tenant_cannot_read_another`: a valid token from tenant A cannot read tenant B's data.
- `tests/test_phase10_hardening.py::test_every_route_is_protected`: every route in the live app authorizes server-side; it flushes the limiter before every probe so a 429 cannot hide an unauthenticated 200.
- `tests/test_phase26_scope.py` and `tests/test_phase28_sla_scope.py`: a team-scoped identity sees its teams and no more, including on the SLA endpoints.

### Rate limiting

- `tests/conftest.py::login()`: calls `_flush_rate_limits()` before every login, so the production limiter (10 auth calls per minute per IP) throttles neither fixtures nor results that depend on test order.
- `tests/test_phase10_hardening.py` (rate-limiting block): the limiter returns 429 with `Retry-After`, gives auth endpoints a stricter budget, never limits the probes, separates credentials and fails open when its backend errors.

### CVSS

- `tests/test_cvss_official.py`: every vector of the official reference corpora (729 v2, 2,592 v3, 1,058 v4; 4,379 in total) must score exactly. The v4 corpus is the half-up rounding guard: Python's `round()` is half-to-even, CVSS v4 requires half-up, and 43 of the 1,058 v4 vectors were wrong by exactly 0.1 until `round_half_up_1()` in `backend/veyrs/engines/cvss/common.py` switched to `Decimal` with `ROUND_HALF_UP`.

### Schema reconciler

- `tests/test_schema_reconcile.py`: no two UNIQUE constraints on a table render to the same name, and the reconciler reads UNIQUE constraints at all.
- `tests/test_widen_columns.py`: the column reconciler may widen a VARCHAR and must never narrow or retype anything.

### Documentation

- `tests/test_docs_are_current.py`: `docs/DATABASE_SCHEMA.md` matches the models, `DATABASE.md` and `ARCHITECTURE.md` state the real table count, every `VEYRS_*` setting is documented, no setting is invented, every CLI command is in the manual, every shipped unit can start, and no doc promises a migration tool or a component that is absent.
- `tests/test_site_render.py`: `site/build.py` renders every doc without stray `>`, fences or `**` on the page; wrapped list items stay one item; the product site builds with no broken or LAN-only links.
- `tests/test_docs_worked_example.py`: the worked example in `DOCKER_COMPOSE_MANUAL.md` §5.D is byte-identical to `docker/compose.yaml` and lists every variable of `docker/env.example`, with placeholders instead of secrets.

### Version and release signing

- `tests/test_phase24_dependencies.py::test_the_running_version_matches_the_declared_one`: `pyproject.toml` and `Settings.version` in `backend/veyrs/config.py` carry the same version, because `/healthz` reports the second one; 0.27.0 shipped with only the first bumped.
- `tests/test_phase24_dependencies.py` (other tests): every dependency is pinned, in the lock, installed and importable.
- `tests/test_phase52_release_signing.py`: `scripts/verify-release.sh` accepts a correctly signed release and rejects a tampered asset, a tampered sums file, another key, a missing signature and the placeholder key; the installer's embedded key equals `release/allowed_signers`; publishing refuses without a private signing key. All keys are throwaway keys generated at run time.
- `tests/test_phase52_updates.py`: the self-updater refuses unsigned releases, bad hashes, bad signatures, the placeholder key, git checkouts and targets that are not newer, before it touches anything.
- `tests/test_phase55_local_update.py`: an uploaded or locally mounted release copy is applicable only if it is signed, complete, newer and free of symlinks, and the update request carries a keyword, never a path.

Cutting a release means bumping the version in both `pyproject.toml` and `backend/veyrs/config.py`, adding the `docs/CHANGELOG.md` entry, and running at least the version and signing files above plus the documentation guards. No test checks the CHANGELOG heading against the version, so check that by eye.

## Flaky tests

The repository has no retry plugin, no `xfail` markers and no reruns, and it should stay that way. A test that passes and fails on the same code is a defect, either in the test or in shared state:

- **Suspect shared state first.** Run the failing file on its own. If it passes alone and fails in the suite, something earlier left rows in a global table, a limiter counter, or a module-level cache.
- **Fix the cause, never the symptom.** The rate-limit flush in `login()` and per probe in `test_every_route_is_protected` are fixes of this kind. Adding 429 to an accepted status set would have hidden a real unauthenticated route.
- **Never skip or delete a flaky guard to get green.** Quarantine is not a policy here. Until it is fixed, the test is a known red, and it is reported as one.

## Console verification in a headless browser

Server-side tests read the console's source; they do not run it. A console change is verified in a real browser.

The repository contains no browser scripts. The screenshot walk and the interaction script are operator tooling, and this section describes the method. The console lives in `frontend/console/` (`index.html`, `app.js`, `console.css`). It is a single page with hash routes (`#/triage`, `#/assets`, and so on), and it keeps the session in `localStorage` under `veyrs.at`, `veyrs.rt`, `veyrs.org` and `veyrs.perms`.

### The setup

1. Start headless Chromium with remote debugging and a throwaway profile:
  ```bash
  chromium --headless=new --remote-debugging-port=9222 --user-data-dir="$(mktemp -d)" about:blank
  ```
2. Read the page target's `webSocketDebuggerUrl` from `http://127.0.0.1:9222/json`.
3. Drive it over the Chrome DevTools Protocol from a Node script that uses Node's built-in WebSocket client:
  ```bash
  node --experimental-websocket walk.mjs
  ```
4. Sign in through the login form (`#l-org`, `#l-email`, `#l-pass`), or post to `/api/v1/auth/login` and write the returned tokens and organisation slug into `localStorage` with `Runtime.evaluate`. Then call `Page.reload`.

### The screenshot walk

For each view, navigate to its hash, **reload**, wait for `Page.loadEventFired` and for `#view .loading` to disappear, check that `#login` is hidden and `#shell` is visible, then call `Page.captureScreenshot`. The registered views are `triage`, `dashboard`, `findings`, `vulnerabilities`, `assets`, `issues`, `tickets`, `risks`, `intel`, `cvss`, `compliance`, `policies`, `integrations`, `automation`, `scanner`, `reports`, `documents`, `knowledge`, `search`, `notifications`, `changes`, `audit`, `ai`, `admin`, `account` and `guide`. Look at every screenshot. A view that says "Could not load this view" or "Access denied" is a finding, not a pass.

### The interaction script

Create a probe asset through the UI and delete it again:

1. Open `#/assets`, click **New asset** (`data-act="newAsset"`), fill in a name that is unique to this run, and submit.
2. Confirm that the asset appears in the list and that its detail view opens.
3. Delete it through the **Delete asset** dialog, and confirm that it is gone from the list.
4. Take a screenshot after each step.

Run it against a test organisation, and always delete the probe, even when an earlier step fails.

### The reload gotcha

> **Warning:** `Page.navigate` to the same page with a different hash does not reload the page. It only fires `hashchange`, which runs the router (`render()`), not `boot()`. `boot()` is what reads the stored token, calls `/auth/me` and swaps the login screen for the shell. If you navigate by hash after writing the token, you photograph the login screen with the view painted underneath it, which looks almost right and proves nothing. Always follow a navigation with `Page.reload`.

The current `render()` refuses to paint while the shell is hidden, so on this version the same mistake gives a bare login screen instead. Either way, the screenshot is not of the view you asked for.

## Deploy verification

A deploy is done when the running nodes are proven to serve the commit you tested. The status code alone proves nothing: every surface still answers 200 when the console copy or `init-db` is skipped.

1. **Liveness.** `GET /healthz` returns `{"status": "ok", "app": "VEYRS", "version": "<version>"}`. The version must be the one you released. It comes from `Settings.version`, which is why the version guard above exists.
2. **Readiness.** `GET /readyz` returns 200 with `checks.database` and `checks.redis` both `ok`. Either check failing returns 503 with `"status": "degraded"`.
  ```bash
  curl -s http://127.0.0.1:8000/healthz
  curl -s -o /dev/null -w '%{http_code}\n' http://127.0.0.1:8000/readyz
  ```
3. **Same commit on both nodes.** `/healthz` reports the version, not the commit. On the primary node and on the standby node, run `git -C /opt/veyrs rev-parse HEAD` and compare the two with the commit you tested. They must be identical.
4. **Console docroot.** nginx serves `/var/www/veyrs-console`, a copy of `frontend/console/`. Compare every file with the repository, and check the cache-busting query string:
  ```bash
  cd /opt/veyrs
  for f in index.html app.js console.css; do md5sum "frontend/console/$f" "/var/www/veyrs-console/$f"; done
  grep -o 'app.js?v=[0-9]*' /var/www/veyrs-console/index.html
  ```
5. **Site docroots.** `/var/www/veyrs` (docs site, `site/build.py`) and `/var/www/veyrs-web` (product site, `site/web/build_web.py`) are local state on each app node. Build both from the repository into a temporary directory with `--out`, then compare the `md5sum` of every file with the docroot, on both nodes.
6. **The new endpoints.** Call at least one endpoint the release added. A release deployed without `init-db` answers 500 on exactly the new tables while `/healthz` stays green.

[Deployment](/DEPLOYMENT.html) and [High availability](/HIGH_AVAILABILITY.html) describe the upgrade steps these checks verify.

## Related

- [Development](/DEVELOPMENT.html): setup, layout, conventions and the traps that each became a guard
- [Contributing](/CONTRIBUTING.html): ground rules, security-sensitive changes and the review checklist
- [Deployment](/DEPLOYMENT.html): the upgrade procedure and the console copy
- [High availability](/HIGH_AVAILABILITY.html): two app nodes, and why their docroots must match
- [Threat model](/THREAT_MODEL.html): the threats the isolation and authorization tests defend against
