---
title: Development
purpose: Get a new engineer from a clean checkout to running tests and making a safe change to VEYRS.
scope: Local setup, repository layout, conventions, how to add the common extension points, schema changes and the traps already hit; deployment, operations and integration internals are in their own documents.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [scripts/test.sh, backend/veyrs/api/v1/__init__.py, backend/veyrs/models/base.py, backend/veyrs/cli.py, backend/veyrs/config.py, backend/veyrs/security/permissions.py, backend/veyrs/services/reporting.py, backend/veyrs/services/workflow.py, backend/veyrs/services/compliance.py, backend/veyrs/services/importers/parsers.py, frontend/console/app.js]
related: [TESTING_GUIDE.md, CONTRIBUTING.md, DATABASE.md, ARCHITECTURE.md, integrations/extending.md, testing/strategy.md]
---

# Development

## Setup

```bash
git clone https://github.com/visionebc/veyrs.git && cd veyrs
# Python >= 3.11 (pyproject.toml requires-python)
python3 -m venv venv && venv/bin/pip install -r requirements.txt
cp .env.example .env
# needs a real PostgreSQL 15+: the schema depends on JSONB, UUID and Row Level
# Security, so an in-memory stand-in would test something VEYRS does not deploy
createdb -E UTF8 -T template0 veyrs && createdb -E UTF8 -T template0 veyrs_test
PYTHONPATH=backend venv/bin/python -m veyrs.cli init-db
```

### A PostgreSQL you do not have to install

The container stack will give you one, and the rest of the platform with it:

```bash
docker/veyrs-docker.sh init && docker/veyrs-docker.sh up
```

For editing code you still want the venv above — the stack builds an image
rather than mounting the source, so a change needs a rebuild. What it is good
for is a **correctly configured database**: the cluster is UTF8, the schema and
its RLS policies are applied by `init`, and the application role is created
`NOSUPERUSER NOBYPASSRLS`, which is the only way row-level security behaves in
development as it will in production. A local `createdb` run as your own
superuser account will happily let every tenant read every other tenant's rows
and you will not find out until an integration test on someone else's machine
disagrees with yours.

The container stack's tests are `tests/test_container_stack.py` (static, no
Docker daemon required, runs in the ordinary suite) and
`scripts/test-docker-stack.sh` (assertions against a running stack).

## Running the tests

```bash
./scripts/test.sh tests/test_phase6_ai.py  # one file
./scripts/test.sh -k cvss                  # by name
./scripts/test.sh                          # the full suite, on request only
```

**Always use `scripts/test.sh`, never bare `pytest`.** It loads `.env`, derives
`VEYRS_TEST_DATABASE_URL` from `VEYRS_DATABASE_URL` (the trailing `/veyrs`
becomes `/veyrs_test`) and raises the rate limits. Bare `pytest` with neither
variable exported aborts in `tests/conftest.py` before any test runs, and so
does any database name that does not end in `_test`.

**Targeted by default.** Run the test files for the code you changed. Run the
full suite only when someone explicitly asks for it. [Testing guide](TESTING_GUIDE.md)
has the details, and the [test strategy](testing/strategy.md) explains how the suite is built
(90 modules, 1,629 test functions) and which tests are environment-dependent
([known issues](testing/known-issues.md)).

The maintainers report that the full suite runs in about 30 seconds, including the 4,379-vector CVSS corpus (not re-measured for 0.39.1).
If it takes minutes, something is wrong - historically that was two pytest
processes competing for the same database, not slow code.

## Layout

```
backend/veyrs/
  api/v1/       HTTP surface: routers, schemas, authorization decorators
  services/     business logic, one module per bounded context
  engines/      pure functions - CVSS, risk. No database, no I/O.
  models/       SQLAlchemy declarative
  security/     auth, permissions, deps, secrets, rate limiting
  intel/        feed clients - NVD, EPSS, CISA KEV
  data/         static reference data (compliance catalogues)
tests/          test_phaseN_*.py modules, focused guards, fixtures/ (CVSS corpora)
docs/           this documentation; rendered by site/build.py
infrastructure/ systemd units, nginx vhost, backup timers
scripts/        test.sh, backup.sh, restore.sh, release and maintenance tools
```

`scripts/README.md` lists every script with one line each.

Import direction is the architecture: `engines/` never imports `services/`;
`services/` never imports `api/`. That is what lets the CVSS engine be validated
with no database in the loop.

## Conventions

**Comments explain why, never what.** `# increment counter` is noise. `# anthropic
BEFORE openai: sk-ant-... also satisfies the generic sk- rule, and the audit
record must name the precise vendor` is the comment that saves the next person
an hour.

**Tests assert behaviour, not implementation.** A test named
`test_absent_findings_are_stale_candidates_not_closures` states a product
guarantee. `test_import_works` states nothing.

**Every guardrail gets a test that proves it bites.** A rate limiter with no
429 test is a rate limiter you hope works.

**Degrade, do not fail.** External dependency unavailable? Return computed data
and label it degraded. This applies to AI providers, Redis, the intelligence
feeds and the semantic-search backend (an interface only today; a vector store
such as Qdrant is Planned, `services/search.py`).

## Adding things

**A route.** Add to the relevant `api/v1/*.py` with
`Depends(require("resource:action"))`. Unknown permission strings raise at import
time. Add the path to `LIST_ENDPOINTS` in `tests/test_phase10_hardening.py` if it
is a collection - ten endpoints once shipped broken because nothing called them
over HTTP.

**A permission.** Add the resource to `security/permissions.RESOURCES`.
`validate_builtins()` runs at import and fails the build if a built-in role
references something that does not exist.

**An AI capability.** Add to `models/ai.AiCapability` and map it in
`CAPABILITY_PERMISSION`. The gateway refuses unknown capabilities with a
`ValueError` - a programming error, not a runtime 500.

**A workflow action.** Add to the `ACTIONS` registry in `services/workflow.py`.
There is no dynamic dispatch, deliberately.

**A compliance signal.** Add a function to `AUTOMATED_SIGNALS` in
`services/compliance.py` returning `{measure, value, total, ratio, detail}`. A
test asserts every control's `automation_signal` names a real entry.

**A report.** One `ReportSpec` in `services/reporting.REPORTS`: slug,
permission, builder, tabulator. It inherits authorization, all four export
formats and the provenance header.

**A scanner format.** One function in `services/importers/parsers.py` plus a
`PARSERS` entry.

### Adding a module, feature, component or integration

Check the existing extension point before inventing one.

| You are adding | Touch | Then |
|---|---|---|
| A feature with HTTP endpoints | a new `api/v1/<name>.py` with `router = APIRouter(...)`, logic in `services/<name>.py`; import the router and call `api_router.include_router(...)` in `api/v1/__init__.py` (order matters when paths overlap: `attribution` is included before `findings` for `/findings/changes`) | give every route `Depends(require(...))`; add collection paths to `LIST_ENDPOINTS` and write probes to `WRITE_PROBES`; add a `test_phaseN_<topic>.py` |
| A table | a class in `models/<area>.py`, with `TenantMixin` for tenant-owned data, exported from `models/__init__.py` (importing the package registers it on `Base.metadata`) | run `init-db`; regenerate `docs/DATABASE_SCHEMA.md` with `python3 scripts/gen-schema-doc.py`; see "Database changes" below |
| A setting | a field on `Settings` in `config.py`; the variable is `VEYRS_` plus the upper-cased field name, and `.env` is read as well | document it in `docs/SYSTEM_MANUAL.md`, or `tests/test_docs_are_current.py` fails; add it to `.env.example` (and `docker/env.example` for containers) |
| A CLI command | `sub.add_parser(...)` in `cli.py::main` plus a dispatch branch | mention the command in the manuals, or the same guard fails |
| A scheduled job | a `.service`/`.timer` pair under `infrastructure/systemd/` plus the installer wiring | `test_every_shipped_unit_can_actually_start` checks every `ExecStart` exists; `tests/test_installer_timers.py` checks the installer |
| A console screen | an entry in `NAV` and its view function in `frontend/console/app.js`, styles in `console.css` | the console guards (`test_console_*`, `test_phase31_console_wiring.py`) check that every class, icon and menu entry exists; verify in a real browser ([Testing guide](TESTING_GUIDE.md)) |
| An external integration (ITSM, scanner connector, directory, secret backend, AI provider) | follow [Extending VEYRS](integrations/extending.md), which owns the contracts and registration points | store credentials through `secret_storage` so the new column passes `test_every_encrypted_column_is_registered` |
| A separate process or component | record an ADR in `docs/ADRs/`, add the unit or container, update `ARCHITECTURE.md` | a guard fails if a document presents an absent component (for example a task queue) as real |

## Database changes

There is no Alembic and no migration files. Change the model, then:

```bash
PYTHONPATH=backend venv/bin/python -m veyrs.cli init-db
```

`init-db` creates missing tables, runs the column reconciler (`sync-schema`:
adds columns, single-column indexes and foreign keys, widens a `VARCHAR`),
applies the RLS policies and seeds roles and catalogues. It is idempotent. It
never drops, renames, narrows or retypes anything: a destructive change is
hand-written SQL. [Database](DATABASE.md) §5 has the details.

Constraint names come from `models/base.NAMING`, so generated DDL is stable.
New tenant-owned tables must carry `TenantMixin`; `init-db` then applies
RLS automatically. New global tables must be added to `GLOBAL_TABLES` in
`models/base.py` **and** to `RLS_TABLES_SKIP` in `cli.py`.

## Traps this codebase has already hit

Each of these cost real debugging time and is now guarded by a test:

1. **CVSS v4 rounding.** Python rounds half-to-even; FIRST specifies half-up.
   43 of 1,058 official vectors were wrong by exactly 0.1. Use `Decimal`.
2. **`IN (uuid, NULL)` never matches NULL rows in SQL.** Built-in roles have
   `organization_id IS NULL` and were invisible, so every login produced zero
   permissions.
3. **RLS context is transaction-local.** `set_config(..., true)` is lost after
   `commit()`, and an unbound policy matches *nothing* - queries return zero rows
   in silence. Fixed with `Session.info` + an `after_begin` hook.
4. **Middleware runs before routing.** `request.state.principal` is always empty
   in middleware, so the rate limiter keyed on it silently degraded every
   authenticated caller to one shared per-IP bucket.
5. **SQLAlchemy `default=` fires at INSERT, not construction.** A transient row
   returns `None` for every defaulted column, so a guard comparing against it
   raised `TypeError` instead of enforcing a limit.
6. **`Page(page=, size=)` when the schema declares `limit`/`offset`.** The extras
   were dropped and the response failed validation - on ten endpoints, every
   call, and no test noticed because none called them over HTTP.
7. **SQL_ASCII clusters return `bytes`.** Create databases with
   `ENCODING 'UTF8' TEMPLATE template0`.

## Phase workflow

Each phase was: explain objective -> architecture -> data model -> security ->
API -> tests -> implement -> run tests -> review -> document. Tests are written
alongside the code, not after. A change runs the test files around it; the
**full** suite runs when someone explicitly asks for it (see
[Testing guide](TESTING_GUIDE.md)).
