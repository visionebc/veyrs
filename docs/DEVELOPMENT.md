# Development

## Setup

```bash
git clone https://github.com/visionebc/veyrs.git && cd veyrs
python3 -m venv venv && venv/bin/pip install -r requirements.txt
cp .env.example .env
# needs a real PostgreSQL: the schema depends on JSONB, UUID and Row Level
# Security, so an in-memory stand-in would test something VEYRS does not deploy
createdb veyrs && createdb veyrs_test
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
./scripts/test.sh                          # all 4,778
./scripts/test.sh tests/test_phase6_ai.py  # one file
./scripts/test.sh -k cvss                  # by name
```

**Always use `scripts/test.sh`, never bare `pytest`.** It loads `.env`, points
the suite at `veyrs_test` and raises the rate limits. Bare `pytest` silently
falls back to an unusable database URL.

The full suite runs in about 30 seconds, including the 4,382-vector CVSS corpus.
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
  data/         static reference data (compliance catalogues)
tests/          one file per phase, plus the official CVSS corpus
docs/           this documentation; rendered by site/build.py
infrastructure/ systemd units, nginx vhost
scripts/        test.sh, backup.sh, restore.sh
```

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
and label it degraded. This applies to AI providers, Qdrant, Redis and the
intelligence feeds.

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

## Database changes

```bash
venv/bin/alembic revision --autogenerate -m "add x"
venv/bin/alembic upgrade head
```

Constraint names come from `models/base.NAMING`, so autogenerate produces stable
diffs. New tenant-owned tables must carry `TenantMixin`; `init-db` then applies
RLS automatically. New global tables must be added to `GLOBAL_TABLES` **and** to
`RLS_TABLES_SKIP` in `cli.py`.

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
alongside the code, not after, and every phase ends with the **full** suite
green, not just its own file.
