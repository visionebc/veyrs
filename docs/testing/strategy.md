---
title: Test strategy
purpose: Explain how the VEYRS test suite is built, why it must be run through scripts/test.sh, and what each kind of test protects.
scope: Runner, database, fixtures, markers, test kinds and how to run a targeted subset; counts per file are in the coverage matrix and open defects in the known-issues page, and neither is repeated here.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [scripts/test.sh, pytest.ini, tests/conftest.py, tests/README.md, tests/test_audit_rls.py, tests/test_write_paths.py, tests/test_phase10_hardening.py, tests/test_docs_are_current.py, scripts/gen-reference-docs.py, scripts/render-diagrams.py, scripts/check-docs-links.py]
related: [testing/coverage-matrix.md, testing/critical-flows.md, testing/known-issues.md, TESTING_GUIDE.md, DEVELOPMENT.md, CONTRIBUTING.md]
---

# Test strategy

VEYRS is tested with `pytest` against a **real PostgreSQL database**, never SQLite: the schema depends on JSONB, UUID columns and Row Level Security, so an in-memory stand-in would test something VEYRS does not deploy (`tests/conftest.py:3-6`).

> [!NOTE]
> This page was written from a static reading of the test code. The suite was **not run** while preparing it, so every statement about pass/fail behaviour is derived from reading, not from a run. Status: *Implemented*.

## Shape of the suite

| Item | Value | How counted |
|---|---|---|
| Test modules | 94 `tests/test_*.py` files plus `tests/conftest.py` (90 at 0.39.0) | `ls tests` |
| `test_*` functions | 1,643 | Python `ast` walk of `tests/*.py`, including methods inside classes |
| Items with literal parametrize expanded | 1,831 | Same walk, multiplying by the length of a literal list/tuple given to `@pytest.mark.parametrize` |
| Parametrized from a variable | not expanded above | See [Dynamic parametrization](#dynamic-parametrization) |
| Fixture data | `tests/fixtures/cvss_official_v{2,3,4}.txt` — 729 + 2,592 + 1,058 = 4,379 vectors | `wc -l` |

There is no CI configuration in the repository (no `.github/`, `.gitea/` or similar directory in the source tree), so nothing in the tree runs the suite automatically. Running it is a manual, operator-controlled act.

## Always `./scripts/test.sh`, never bare `pytest`

`scripts/test.sh` is the canonical entry point; every argument is passed to pytest (`exec venv/bin/python -m pytest "$@"`, `scripts/test.sh:46`). In order it:

1. changes to the repository root and sources `.env` if present (`set -a`), so `VEYRS_DATABASE_URL` is exported;
2. forces `VEYRS_ENVIRONMENT=development`, overriding `.env`;
3. raises `VEYRS_RATE_LIMIT_PER_MINUTE` and `VEYRS_AUTH_RATE_LIMIT_PER_MINUTE` to 100000 — the suite calls the API from one client identity; the limiter itself is tested separately in `tests/test_phase10_hardening.py` with isolated apps;
4. **blanks outbound channels**: `VEYRS_SMTP_HOST=` (empty), `VEYRS_NOTIFY_EMAIL_ENABLED=true`, `VEYRS_TELEGRAM_BOT_TOKEN=` (empty). The node's `.env` may point at a real mail relay or chat bot; fixture addresses must never reach them, and the notification tests assert the "no relay configured" path. A test that needs a channel configures it itself (`scripts/test.sh:24-30`);
5. derives `VEYRS_TEST_DATABASE_URL` unless it is already set. A URL ending in `/veyrs` becomes `…/veyrs_test`; one already ending in `_test` is kept; anything else is passed through unchanged so that `conftest.py` refuses it. Only the trailing database name is swapped, because a naive `s|/veyrs|/veyrs_test|` would rewrite the `//veyrs:` user name first (`scripts/test.sh:31-44`).

### Why bare `pytest` is refused

`tests/conftest.py` resolves the database URL **before** importing anything from `veyrs`:

- `_test_database_url()` takes `VEYRS_TEST_DATABASE_URL`, otherwise derives it from `VEYRS_DATABASE_URL` (`conftest.py:19-33`);
- `_assert_is_test_database()` raises `RuntimeError` if the URL is empty (`no test database configured`) or if the database name does not end in `_test` (`refusing to run tests against database …`) (`conftest.py:35-59`);
- only then is the URL exported as `VEYRS_DATABASE_URL` for the application.

The guard exists because with no `.env` loaded the application falls back to its built-in default URL, which is the **production** database; the docstring records 1,198 orphan `tenant-*` organisations left there on 2026-08-10. `test_phase18_hardening.py::test_the_suite_refuses_a_database_that_is_not_a_test_database` pins the guard (`tests/test_phase18_hardening.py:443`).

`conftest.py` reads the process environment only (not `.env`) when it derives the database URL; that is why the script sources `.env` first. The application's own `Settings` class separately declares `env_file=".env"` (`backend/veyrs/config.py:19`), so other settings are still read from `.env` in the current directory.

> [!WARNING]
> `scripts/test.sh` and `conftest.py` check the **name** of the database, not its host. A database called `something_test` on a production server passes the guard. Point `VEYRS_TEST_DATABASE_URL` only at a disposable cluster.

## Test database and fixtures

Create the database next to the real one, in UTF8 and owned by a role that is `NOSUPERUSER NOBYPASSRLS` — a superuser skips every RLS policy and every isolation test would pass for the wrong reason. `test_audit_rls.py::test_the_suite_is_not_running_as_a_role_that_bypasses_rls` fails the run if that is wrong (`tests/test_audit_rls.py:39`). Commands are in [Development](../DEVELOPMENT.md#setup).

| Fixture / helper | Scope | Behaviour (`tests/conftest.py`) |
|---|---|---|
| `_schema` | session, autouse | `veyrs.cli.init_db(None)` once per run: creates tables, reconciles columns, applies RLS policies, seeds roles and catalogues. Idempotent, so rows persist between runs |
| `_clear_rate_limits` | session, autouse | Flushes limiter counters (in-process and `veyrs:rl:*` Redis keys) before and after the run; a missing Redis is ignored |
| `client` | function | `TestClient(app)` over the real FastAPI app |
| `org_a`, `org_b` | function | A new organisation `tenant-a-<8 hex>` / `tenant-b-<8 hex>` with an `org-admin`; returns `(org_id, slug, email)` |
| `admin_a`, `admin_b` | function | `Authorization: Bearer …` headers for that admin |
| `login()`, `auth_headers()` | helper | Flush the limiter, POST `/api/v1/auth/login`, assert 200 |
| `_make_org(prefix)` | helper | Behind `org_a`/`org_b`; used directly for module-scoped organisations (e.g. `test_write_paths.py`) |

Consequences of the design:

- Every test creates its own tenant, so tests do not collide and need no cleanup to pass — **and the fixtures never delete what they create** (no teardown in `_make_org`). The test database grows with every run. See [known issues](known-issues.md#test-database-accumulates-tenants).
- Global tables (`cves`, `feed_runs`, …) have no `organization_id`; they are the one place where a previous test can influence a later one (`tests/test_phase35_operability.py:77` `_only_feed_runs` makes such tests hermetic).
- Email/Telegram MFA tests use an `outbox` fixture defined inside the test module, not in `conftest.py` (`tests/test_phase54_mfa_methods.py`).

## `pytest.ini`

| Setting | Value | Effect |
|---|---|---|
| `pythonpath` | `backend` | `import veyrs` works without an ambient `PYTHONPATH` |
| `testpaths` | `tests` | |
| `addopts` | `-q --strict-markers` | an undeclared marker is an error |
| `markers` | `integration: requires PostgreSQL/Redis` | declared, but **no test uses it** (`grep -rn "mark.integration" tests` finds nothing), so `-m "not integration"` deselects nothing |
| `filterwarnings` | `error::DeprecationWarning:veyrs.*` | a deprecation warning raised from VEYRS code fails the test |

Markers actually in use are `parametrize` and `skipif`; `pytest.skip()` is also called imperatively. The inventory is in [known issues](known-issues.md#skips-and-conditional-tests). There is no `xfail` anywhere in `tests/`.

## Kinds of test

The groups below are assigned by file-name pattern; counts are `test_*` functions (AST).

| Kind | Files | Functions | What it proves | Examples |
|---|---|---|---|---|
| API through `TestClient` and service-level | 53 `test_phase*` and topic modules (the remainder) | 1,256 | Routes authorize, stay inside a tenant, validate input; services behave as specified on the real database | `test_phase2_core.py`, `test_phase6_ai.py`, `test_phase15_unified_ingest.py` |
| Engine and pure-function | 7 | 65 | No-database functions give the specified answer | `test_cvss_official.py`, `test_phase3_risk.py`, `test_widen_columns.py` |
| Console source guards | 15 | 120 | The console's `app.js`/`console.css`/nginx vhost agree with each other and with the API; read as text, **not executed** (one test runs JS under Node) | `test_console_layout_classes.py`, `test_phase42_console_screens.py` |
| Documentation guards | 6 | 53 | Manuals, generated references, rendered diagrams and the rendered sites still match the code | `test_docs_are_current.py`, `test_docs_center.py`, `test_site_render.py`, `test_docs_diagrams.py`, `test_docs_reference_is_current.py` |
| Packaging, installer, container guards | 9 | 81 | Unit files, installer, Dockerfile and compose stay consistent; scripts run against local fakes | `test_container_stack.py`, `test_installer_timers.py`, `test_phase24_dependencies.py` |
| Release signing and updater | 4 | 68 | Signed-release verification and the self-updater refuse unsafe input | `test_phase52_release_signing.py`, `test_phase52_updates.py` |

Not present: browser-driven end-to-end tests, load or performance tests, fuzzing, property-based tests, coverage measurement (no `pytest-cov` in the configuration; `--cov` is never invoked by the runner), or a mutation-testing tool. "Mutation" in the repository means a **manual procedure** — revert the fix and watch the new test go red — described in [Testing guide](../TESTING_GUIDE.md#bug-fixes-regression-test-and-mutation-proof), plus `scripts/test-publish-github.sh`, which accepts `SCRIPT=/path/to/mutated-copy.sh` and runs its scenarios against it (`scripts/test-publish-github.sh:11,21`).

### Dynamic parametrization

`@pytest.mark.parametrize` over a variable is not expanded by the static count. Known cases: `LIST_ENDPOINTS` (35 paths, `tests/test_phase10_hardening.py:445`), `WRITE_PROBES` (10, `tests/test_write_paths.py:138`), `RLS_TABLES_STRICT_NULLABLE` (2, `backend/veyrs/cli.py:56`), the three CVSS corpora (4,379 vectors; the three `test_v*_official` functions each parametrize over a file read at import) and the vhost/risk-profile lists in `test_console_docs_link.py`, `test_console_redesign_0370.py`, `test_console_vhost_names.py` and `test_phase3_risk.py` (sizes not evaluated), and `MUST_BE_EXECUTABLE` (5 scripts, `tests/test_executable_bits.py:17`). The real collected count is therefore higher than 1,831.

## The guard tests and what they protect

A *guard* is a test that reads the repository rather than exercising a feature. They keep a class of drift from coming back.

| Guard family | Reads | Protects |
|---|---|---|
| `test_docs_are_current.py` (12 functions) | `docs/*.md`, models, CLI, systemd units, `backend/veyrs/config.py` | `DATABASE_SCHEMA.md` matches the models (`gen-schema-doc.py --check`); `DATABASE.md`/`ARCHITECTURE.md` state the real table count; every `VEYRS_*` setting and every CLI command is documented and no setting is invented; every shipped unit's `ExecStart` exists; no doc presents a task queue as a component; the recovery manual warns about the RLS backup trap |
| `test_docs_center.py`, `test_site_render.py` | `site/build.py`, rendered pages | every document is filed in a category, searchable and linked; no stray Markdown on the page; the public build never links to the LAN docs site |
| `test_docs_reference_is_current.py` | `scripts/gen-reference-docs.py --check` | the code-derived references (`docs/api/openapi.json`, `docs/api/reference/*`, `docs/reference/configuration.md`, `permissions.md`, `inventory.md`) are byte-identical to a fresh generation |
| `test_docs_diagrams.py` | `scripts/render-diagrams.py --check`, `docs/diagrams/rendered/` | every ```` ```mermaid ```` block has its pre-rendered SVG and no SVG is an orphan |
| `test_executable_bits.py` | the git index | `install.sh`, `scripts/public-export.sh`, `publish-github.sh`, `test-publish-github.sh`, `test.sh` stay `100755` (skips outside a git checkout) |
| `test_docs_worked_example.py` | `docs/DOCKER_COMPOSE_MANUAL.md` §5.D, `docker/compose.yaml`, `docker/env.example` | the manual's copy of `compose.yaml` is byte-identical and lists every variable |
| `test_console_*`, `test_phase31/32/42/47` | `frontend/console/*`, nginx vhosts | every CSS class the JS uses exists; no glyph/emoji icons; menu/tab structure; create dialogs send what the API accepts; the vhost answers every hostname |
| `test_container_stack.py`, `test_container_images.py` | `docker/*`, `.dockerignore` | text-level contract of the container stack, no Docker daemon needed |
| `test_installer_*`, `test_api_unit.py`, `test_sync_intel_script.py` | `install.sh`, `veyrs-setup.sh`, systemd units | installer timers and dry-run behaviour; the API unit's only writable path is the tracked `var/` |
| `test_phase24_dependencies.py` | `pyproject.toml`, `requirements.txt`, `Settings.version` | dependencies pinned, locked, installed; **`pyproject.toml` and `Settings.version` carry the same version** (`:143`) |
| `test_write_paths.py` | the live app | every audited write route may reject (4xx) but never raises (5xx); exists because a changed `audit.record()` signature broke five modules unnoticed |
| `test_phase10_hardening.py::test_every_route_is_protected` | the live route table | every route authorizes server-side |
| `test_audit_rls.py` | `pg_catalog` | audit tables carry a forced tenant policy and the suite does not run as a bypass-RLS role |
| `test_phase48_secret_vault.py::test_every_encrypted_column_is_registered` / `test_every_writer_goes_through_the_envelope` | models and service source | no encrypted column escapes the secret envelope |

Rule from the codebase: **never loosen a guard to get green.** Either the default is wrong and is changed deliberately, or the test is wrong ([Contributing](../CONTRIBUTING.md#security-sensitive-changes)).

## Documentation tooling

Three scripts maintain the documentation portal; two of them are guarded by tests. They were added with the documentation reengineering and are not part of the application.

| Script | What it does | How to run (repository root) | Guarded by |
|---|---|---|---|
| `scripts/gen-reference-docs.py` | Writes the generated references: `docs/api/openapi.json`, `docs/api/reference/*.md`, `docs/reference/{configuration,permissions,inventory}.md` (code-derived) and `docs/reference/{traceability,coverage}.md` (measured from the hand-written docs). Imports `veyrs`; needs the project venv and a git checkout for the inventory; no database connection (`scripts/gen-reference-docs.py:1-34`) | `venv/bin/python scripts/gen-reference-docs.py` to regenerate; `--check` exits 1 if a code-derived file is stale | `tests/test_docs_reference_is_current.py` (runs `--check`; traceability and coverage are checked for presence only) |
| `scripts/render-diagrams.py` | Renders every ```` ```mermaid ```` block in `docs/` to `docs/diagrams/rendered/<sha256[:16]>.svg` and prunes orphans. Needs Node.js, `mmdc` and a Chromium (`MMDC`, `MMDC_PUPPETEER` environment variables); run on a development machine, the SVGs are committed (`scripts/render-diagrams.py:1-26`) | `python3 scripts/render-diagrams.py`; `--check` exits 1 if a block lacks its SVG; `--no-prune` keeps orphans | `tests/test_docs_diagrams.py` (`--check`, plus no orphan SVG) |
| `scripts/check-docs-links.py` | Checks every internal `href`/`src` and `#fragment` of a **built** Docs Center; external links are counted, not fetched; exit 1 on a broken link (`scripts/check-docs-links.py:1-10`) | `python3 site/build.py --out /tmp/veyrs-portal` then `python3 scripts/check-docs-links.py /tmp/veyrs-portal` | no test (manual step before publishing) |

After editing a diagram, re-run `render-diagrams.py`; after adding a route, setting, permission or file, re-run `gen-reference-docs.py`; both tests fail otherwise.

## Running a targeted subset

The default is targeted: run the files for the code you changed (one to three), plus the guards that touch the same surface. Run the full suite only when someone explicitly asks for it. These commands assume the repository root as working directory, a `venv/` there, and a configured `.env`:

```bash
./scripts/test.sh tests/test_phase6_ai.py                                          # one file
./scripts/test.sh tests/test_phase2_core.py::test_tenant_binding_survives_commit   # one test
./scripts/test.sh tests/test_cvss_official.py -k v4                                # by name fragment
./scripts/test.sh tests/test_write_paths.py -x -v                                  # stop at first failure, show ids
ls tests | grep -iE 'mfa|radius|oidc'                                              # find files by topic
grep -l 'services.reporting' tests/*.py                                            # find files by imported module
```

Pairings worth remembering: a new route → `test_phase10_hardening.py` (route protection, `LIST_ENDPOINTS`) and, if it writes, `test_write_paths.py`; a docs change → `test_docs_are_current.py`, `test_docs_center.py`, `test_site_render.py`, `test_docs_diagrams.py`, `test_docs_reference_is_current.py`; a version bump → `test_phase24_dependencies.py`.

Never run two pytest processes against the same `veyrs_test` database: they contend for the same rows. The Testing guide reports a full-suite duration of about 30 seconds; this was not re-measured here (**Unknown**).

Exit codes: `0` all passed (skips allowed), `1` a test failed, `2` interrupted or a collection import error, `4` usage error (including the `conftest.py` database guard), `5` nothing collected.
