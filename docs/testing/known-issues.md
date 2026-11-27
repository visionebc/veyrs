---
title: Test suite known issues
purpose: Record the defects, environment dependencies, skips and order-dependencies found in the VEYRS test code so nobody mistakes them for product bugs, or the reverse.
scope: Issues verified by reading tests and the code they exercise; nothing was run, so runtime failures are predicted from the code and labelled as such.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [tests/conftest.py, scripts/test.sh, tests/test_phase18_hardening.py, tests/test_phase52_release_signing.py, tests/test_phase52_updates.py, tests/test_console_redesign_0380.py, tests/test_console_layout_classes.py, tests/test_phase37_estate_lens.py, tests/test_nvd_rejects.py, backend/veyrs/main.py]
related: [testing/strategy.md, testing/coverage-matrix.md, testing/critical-flows.md, TESTING_GUIDE.md]
---

# Test suite known issues

Severity is for the test suite's reliability, not the product. "Predicted" means derived from the code; the suite was not executed while writing this page.

| # | Issue | Severity | Status |
|---|---|---|---|
| 1 | [Tests bound to `/opt/veyrs`](#tests-bound-to-optveyrs) | High | Verified in code |
| 2 | [`/metrics` exposition test depends on the environment name](#metrics-exposition-test-and-the-environment) | Medium | Verified in code |
| 3 | [The suite flushes rate-limit keys in whatever Redis `.env` names](#redis-is-shared-with-the-configured-instance) | Medium | Verified in code |
| 4 | [Full `.env` leaks into the run](#the-whole-env-reaches-the-suite) | Medium | Verified in code |
| 5 | [Test database accumulates tenants](#test-database-accumulates-tenants) | Low | Verified in code |
| 6 | [Skips and conditional tests](#skips-and-conditional-tests) | Medium | Verified in code |
| 7 | [Order-dependence and shared global state](#order-dependence-and-shared-global-state) | Medium | Verified in code |
| 8 | [No CI, no coverage tool, unused marker](#structural-gaps) | Medium | Verified in code |
| 9 | [Documentation-guard coupling](#documentation-guard-coupling) | Low | Verified in code |
| 10 | [Offline publish harness (carried failure, reported fixed in 0.39.1)](#offline-publish-harness) | Low | Verified in code |

## Tests bound to `/opt/veyrs`

Several tests read the application source through an **absolute path** `/opt/veyrs/...` instead of resolving it from `__file__` like the rest of the suite (`ROOT = Path(__file__).resolve().parents[1]`).

| File | Line | Path |
|---|---|---|
| `tests/test_console_layout_classes.py` | 21 | `/opt/veyrs/frontend/console` |
| `tests/test_phase42_console_screens.py` | 15 | `/opt/veyrs/frontend/console/app.js` |
| `tests/test_phase37_estate_lens.py` | 43, 326 | `.../app.js`, `/opt/veyrs/backend/veyrs/api` |
| `tests/test_phase59_cve_exposure.py` | 25 | `/opt/veyrs/frontend/console/app.js` |
| `tests/test_phase26_scope.py` | 283 | `/opt/veyrs/backend/veyrs/services/analytics.py` |
| `tests/test_phase19_coverage.py` | 186 | `/opt/veyrs/integrations/veyrs-agent/veyrs_agent.py` |

Effects, predicted from the code:

- On a host **without** `/opt/veyrs` (a developer laptop, the Docker image, any other install directory): `test_console_layout_classes.py` and `test_phase42_console_screens.py` **skip** (they call `pytest.skip` when the file is absent), so a console regression passes silently; the others have no existence check and fail with `FileNotFoundError`.
- On a host where `/opt/veyrs` **is** the deployed tree but the checkout under test lives elsewhere, these tests validate the *deployed* tree, not the change being tested. A fix in a feature branch is invisible to them.
- `/opt/veyrs` on an application node is a shared checkout, so the verdict depends on whoever last edited it.

Not affected: tests that use `ROOT` (`test_phase47_risk_matrix.py:29`, `test_docs_*`, `test_container_*`, …). The fix is mechanical (`ROOT / "frontend/console/app.js"`); it was not applied because test code is out of scope for this documentation work.

A related, benign literal: `tests/test_api_unit.py:23` asserts that the unit file's `ReadWritePaths` equals `/opt/veyrs/var` — that is the unit file's own content, read from `ROOT`, and correct for the shipped unit.

## `/metrics` exposition test and the environment

`tests/test_phase18_hardening.py::test_the_exposition_names_the_worker_that_answered` (line 186) sets `settings.metrics_token` to `""` and expects `GET /metrics` to contain `worker=`.

The route (`backend/veyrs/main.py:115-139`) returns **404 when no token is configured and `settings.is_production` is true**, and serves the exposition when the environment is anything else. `TestClient` itself does not change this. So the test passes under `scripts/test.sh` (which exports `VEYRS_ENVIRONMENT=development`) and fails with a 404 body if the process runs with `VEYRS_ENVIRONMENT=production` — for example by exporting `VEYRS_TEST_DATABASE_URL` yourself and invoking `pytest` directly with a production `.env` sourced. `conftest.py` only does `os.environ.setdefault("VEYRS_ENVIRONMENT", "development")` (line 65), which does not override an existing value.

The sibling `test_metrics_are_prometheus_formatted` (`tests/test_phase10_hardening.py:411`) is token-aware (it sends `Bearer <settings.metrics_token>` when one is set) and does not share the problem. Treat a 404 in the former as an environment error, not a product defect. This corrects the wording "404 under TestClient": the trigger is the environment name, not the client.

## Redis is shared with the configured instance

`conftest.py::_flush_rate_limits` (lines 86-103) deletes every key matching `veyrs:rl:*` from `ratelimit._redis()`, which connects to `settings.redis_url` (default `redis://127.0.0.1:6379/0`, `backend/veyrs/config.py:63`). `scripts/test.sh` redirects the **database** to `*_test` but does not redirect Redis. Running the suite on a node whose `.env` points at the production Redis therefore resets the live rate-limit windows of real callers at the start, end and on every `login()` call. The effect is a brief loss of throttling state, not data loss, but it is a side effect on production state from a test run. If Redis is unreachable the limiter falls back to in-process windows and the flush is a no-op (exceptions are swallowed).

Mitigation: run the suite against a Redis of its own (set `VEYRS_REDIS_URL` — see [configuration](../reference/configuration.md) — to a separate database index before invoking the script).

## The whole `.env` reaches the suite

`scripts/test.sh` sources `.env` with `set -a` and overrides only: `VEYRS_ENVIRONMENT`, the two rate limits, `VEYRS_SMTP_HOST`, `VEYRS_NOTIFY_EMAIL_ENABLED`, `VEYRS_TELEGRAM_BOT_TOKEN` and the database URL. `Settings` additionally declares `env_file=".env"` (`backend/veyrs/config.py:19`), so even a direct `pytest` run from the repository root reads `.env` for every setting not present in the process environment. Every other setting (metrics token, update URL, secret-vault mode, LDAP/OIDC/RADIUS, AI provider defaults, …) comes from the node's real configuration. Tests that depend on such a setting monkeypatch it explicitly where the authors noticed the dependency (for example `monkeypatch.setattr(settings, "metrics_token", ...)`); a setting nobody noticed is an environment-sensitive test. Which tests those are was **not determined** (Unknown); the safe procedure is a dedicated `.env` for test runs.

## Test database accumulates tenants

`_make_org()` creates an organisation with a random suffix and never deletes it; there is no teardown in `org_a`/`org_b` or in the module-scoped helpers. The `veyrs_test` database therefore grows by roughly two organisations per test that requests both fixtures, run after run. This is by design (unique names remove the need for cleanup) but means: counts of "all organisations" are meaningless in tests; the database must be dropped and recreated occasionally; and `_schema` runs `init_db` against an ever-larger database. The recovery of 1,198 orphan production tenants in the `conftest.py` docstring is the same effect on the wrong database.

## Skips and conditional tests

Verified with `grep -rn "skip\|xfail" tests/`. There is **no `xfail`** and no retry plugin.

| Site | Condition | What is lost when it skips |
|---|---|---|
| `tests/test_phase52_release_signing.py:39,106` | `ssh-keygen` missing. The module fixture `keys` skips, and 16 test functions request `keys`; 2 more carry `@needs_ssh_keygen` | Almost the whole release-signature verification suite |
| `tests/test_phase52_release_signing.py:400-402` | not a git checkout (`ROOT/.git` absent) or no `git`: `test_the_offline_publish_harness_passes` | The end-to-end publish flow against a stubbed GitHub (`scripts/test-publish-github.sh`, timeout 900 s). **The documentation source tree used for this page is not a git checkout, so this test would skip there** |
| `tests/test_executable_bits.py:22-25` | not a git checkout (`git ls-files -s` fails): all five cases of `test_script_is_executable_in_git` | The executable bit of `install.sh` and four scripts (0.39.1). Also skipped on the documentation source tree |
| `tests/test_phase52_release_signing.py:346` | the real release key is embedded in `veyrs-setup.sh` | By design, the placeholder-key refusal path stops being tested once the real key ships |
| `tests/test_phase52_updates.py:303` `needs_tools` | any of `ssh-keygen`, `curl`, `bash`, `tar`, `sha256sum` missing (9 tests here, 10 more in `test_phase55_local_update.py`, which imports it) | The root updater scenarios |
| `tests/test_phase52_updates.py:477` | not running as root (`os.geteuid() != 0`) | `test_updater_runs_a_safe_pre_hook_and_refuses_an_unsafe_one`: hook-ownership check |
| `tests/test_console_redesign_0380.py:69-72` | `node` not on `PATH` and `/root/.nvm/versions/node/v20.20.2/bin/node` absent | `test_the_smoothed_curve_never_overshoots_a_measured_value`, the only test that **executes** console JavaScript. The fallback is a hard-coded per-user path |
| `tests/test_console_layout_classes.py:40`, `test_phase42_console_screens.py:21`, `test_phase47_risk_matrix.py:36` | console files absent | Console guards (see issue 1 for why the first two are unreliable) |
| `tests/test_write_paths.py:93` | `POST /api/v1/tickets` returns 4xx | The ticket write-path probe **skips instead of failing**: a regression that turns ticket creation into a 4xx would be reported as a skip |

A skip is not a pass: before calling a release or updater change verified, check the skip count of the run.

## Order-dependence and shared global state

Most tests are isolated by random tenant names. The exceptions, verified in code:

- **Global tables.** `cves`, `cve_*`, `products`, `vendors`, `feed_runs`, `cwe` have no tenant. `tests/test_phase35_operability.py:77` (`_only_feed_runs`) deletes every `FeedRun` row for a feed before asserting, and `tests/test_epss_retention.py:47` deletes CVEs it created. `test_phase37_estate_lens.py` and `test_phase59_cve_exposure.py` namespace their rows with a UUID; the first documents why: a fixture that reuses "nginx" makes the file's results depend on which other test ran first.
- **Schema mutation inside a test.** `tests/test_nvd_rejects.py::test_init_db_widens_the_url_column_on_an_existing_install` (lines 123-135) runs `DELETE FROM cve_references WHERE length(url) > 1000` and `ALTER TABLE cve_references ALTER COLUMN url TYPE VARCHAR(1000)` on the shared test database, then runs the reconciler. It comments that "the long URL another test stored would not fit". If the test aborts between the two statements, the column stays narrow until the next `init_db` (the session fixture does re-widen it). `test_schema_reconcile.py` and `test_widen_columns.py` also exercise DDL.
- **Rate limiter windows.** The Redis-backed limiter shares a fixed window across the session; `tests/test_phase10_hardening.py:63-71` uses a unique bearer token per test and `_clear_backend("auth:testclient")` (line 101) for the IP-keyed auth bucket. Running two pytest processes concurrently, or against a Redis used by anything else, makes these tests flaky.
- **One run at a time.** Two processes against the same `veyrs_test` database contend for rows; the Testing guide attributes a historical "minutes instead of 30 seconds" run to exactly that.
- **Wall-clock.** Tests that build deadlines use `datetime.now()` (for example `_only_feed_runs`); `test_phase50_report_builder.py:491` uses a real `pg_sleep(0.2)` to provoke a timeout. No clock is frozen anywhere, so tests close to a day boundary can in principle disagree with themselves; no instance of this was found.

## Structural gaps

- **No CI.** The repository holds no CI configuration (no `.github/`, `.gitea/`, `.gitlab-ci.yml`, `Jenkinsfile`). Nothing runs the suite on a push; the operator rule "targeted by default, full suite on request" makes regressions outside the touched files easy to miss.
- **No coverage measurement.** Neither `pytest.ini` nor `scripts/test.sh` enables coverage; `pytest-cov` is not in `requirements.txt`. See the [coverage matrix](coverage-matrix.md) for the static substitute and its limits.
- **Unused marker.** `integration` is declared (`pytest.ini`) but no test carries it, so it cannot be used to separate database tests from pure ones.
- **No browser tests.** Console behaviour is checked by reading `app.js` as text; one test runs a JS snippet under Node. Rendering, layout and event wiring are verified by hand (the Testing guide describes the manual headless-browser method; no script for it is in the repository).
- **Dynamic parametrization hides sizes** from static counting (see [strategy](strategy.md#dynamic-parametrization)).
- **`.env` name guard only.** The conftest guard checks that the database name ends in `_test`, not where it lives.

## Documentation-guard coupling

`tests/test_docs_are_current.py`, `test_docs_center.py` and `test_site_render.py` read the documentation. `test_site_render.py::test_every_doc_renders_without_stray_markup` globs only the top-level `docs/*.md` (`tests/test_site_render.py:76`); `test_no_doc_leaves_markdown_emphasis_on_the_page` uses `rglob` and covers sub-folders (`:139`). The current `site/build.py` (1,058 lines) strips the YAML front matter (`parse_front_matter`, `site/build.py:123`) and walks every sub-folder (`discover`, `:447`), so front matter no longer renders as a stray rule; this replaces the 0.39.0 baseline builder (498 lines) that did neither. Two newer guards couple the docs to generators: `test_docs_diagrams.py` fails when an edited ```` ```mermaid ```` block has no re-rendered SVG, and `test_docs_reference_is_current.py` fails when a route, setting, permission or file changes without regenerating the reference (see [strategy](strategy.md#documentation-tooling)).

The settings, CLI and table-count guards require specific facts to stay in the manuals (every `VEYRS_*` setting, every CLI command, the real table count, the RLS backup-trap warning, the byte-identical `compose.yaml` in `DOCKER_COMPOSE_MANUAL.md` §5.D). Editing those manuals needs the matching guard run: `./scripts/test.sh tests/test_docs_are_current.py tests/test_docs_worked_example.py`.

## Offline publish harness

`tests/test_phase52_release_signing.py::test_the_offline_publish_harness_passes` was recorded in the changelog as a known failure from 0.37.0 to 0.39.0. Two causes: the public-export binary guard refused the console's six self-hosted `.woff2` fonts, and `install.sh` had lost its executable bit, so `publish-github.sh` refused the tree. 0.39.1 allows `font/woff2` only for `frontend/console/fonts/*.woff2` (`scripts/public-export.sh:509-511`), restores `install.sh` to mode `100755`, and pins both with `tests/test_console_readability_0391.py::test_export_allows_console_fonts_only_in_their_directory` and `tests/test_executable_bits.py` (`docs/CHANGELOG.md`, 0.39.1). The fix is **reported fixed in the 0.39.1 changelog, not re-run** for this page. The harness itself skips outside a git checkout (`tests/test_phase52_release_signing.py:400-401`), and `test_executable_bits.py` skips there too (it reads modes from the git index), so neither proves anything on a plain copy of the tree.
