---
title: Contributing
purpose: State the rules a change to VEYRS must meet before it is merged or released.
scope: Ground rules, security-sensitive changes, compliance-framework content rules, commit messages, the review checklist and release-quality steps; setup and how-to-extend are in Development.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [scripts/test.sh, backend/veyrs/data/frameworks.py, pyproject.toml, backend/veyrs/config.py, tests/test_phase24_dependencies.py, tests/test_phase52_release_signing.py, tests/test_docs_are_current.py]
related: [DEVELOPMENT.md, TESTING_GUIDE.md, THREAT_MODEL.md, testing/strategy.md, testing/known-issues.md]
---

# Contributing

## Before you start

Read [Development](DEVELOPMENT.md), especially "Traps this codebase has
already hit". Most of them are subtle, and all of them shipped once. To add a
route, table, setting, CLI command, console screen or integration, use the
["Adding a module, feature, component or integration"](DEVELOPMENT.md#adding-a-module-feature-component-or-integration)
table there.

## Ground rules

**The tests around your change must be green.** Run the test files for the code
you changed; run the full suite when someone explicitly asks for it. See
[Testing guide](TESTING_GUIDE.md).

```bash
./scripts/test.sh tests/test_phase6_ai.py   # targeted, the default
./scripts/test.sh                           # the full suite, on request
```

**New behaviour needs a test that would fail without it.** A test that passes
before and after your change is documentation, not verification.

**Name tests after the guarantee.**
`test_confidential_data_cannot_reach_an_external_provider` tells a reviewer what
breaks. `test_gateway_2` does not.

**Comment the why.** If a line looks wrong but is right, say why it is right. If
a rule exists because of an incident, name the incident.

## Security-sensitive changes

Anything touching authentication, authorization, tenancy, the AI gateway or the
importers needs, in the pull request:

1. Which threat in [Threat Model](THREAT_MODEL.md) it affects
2. The test that proves the control still bites
3. An explicit statement of any new residual risk

**Never weaken a default to make a test pass.** If the test fights the default,
either the default is wrong (change it deliberately, and say so) or the test is
wrong.

## Adding a compliance framework

Read the header of `backend/veyrs/data/frameworks.py` first. Non-negotiable:

- Never reproduce normative text from a copyrighted standard
- Always set `source_url`, `licence_note` and `official_control_count`
- `is_partial` is **derived**, never hand-set to false
- VEYRS commentary goes in `veyrs_guidance`, clearly attributed to us
- Crosswalks are editorial and are labelled as such

Inventing a regulatory requirement to fill a gap is the one thing that would make
this module worse than useless.

## Commit messages

Say what changed and **why**, especially when the why is a bug you found:

```
Phase 8: scanner importers + ITSM connectors

- One normalizer for every vendor, with two rules it will not bend: a record
  whose asset cannot be identified is REJECTED with a reason (never attached to
  a plausible neighbour), and a finding absent from an export is a stale
  CANDIDATE, not a closure -- an offline host is not a remediated host.
```

## Review checklist

- [ ] Targeted tests green (full suite when requested)
- [ ] New routes carry `require(...)` and appear in the list-endpoint walk
- [ ] No credential field in any response schema
- [ ] Errors do not echo submitted values
- [ ] Tenant scoping is applied by VEYRS code, never taken from input
- [ ] External calls degrade rather than 500
- [ ] Comments explain why
- [ ] Documentation updated if behaviour changed

## Release quality

There is no CI configuration in the repository, so these checks are manual:

1. **Version.** Bump `version` in `pyproject.toml` **and** `Settings.version` in `backend/veyrs/config.py`. They must match: `tests/test_phase24_dependencies.py::test_the_running_version_matches_the_declared_one` fails otherwise, and `/healthz` reports the second one.
2. **Changelog.** Add the `docs/CHANGELOG.md` entry. No test checks its heading against the version, so check it by eye.
3. **Guards.** Run at least the version and signing files (`test_phase24_dependencies.py`, `test_phase52_release_signing.py`, `test_phase52_updates.py`, `test_phase55_local_update.py`) and the documentation guards (`test_docs_are_current.py`, `test_docs_center.py`, `test_site_render.py`, `test_docs_worked_example.py`), each through `./scripts/test.sh`.
4. **Skips are not passes.** The signing and updater tests skip when `ssh-keygen`, `curl`, `tar`, `sha256sum` or `git` are missing, and the publish harness skips outside a git checkout. Check the skip count of the run; see [known issues](testing/known-issues.md#skips-and-conditional-tests).
5. **Signed release.** `scripts/verify-release.sh` verifies a release against `release/allowed_signers`; publishing refuses without a signing key. Do not publish unsigned unless that is asked for by name.
6. **Run where the code lives.** Several console and agent guards read `/opt/veyrs/...` rather than the checkout under test ([known issues](testing/known-issues.md#tests-bound-to-optveyrs)); run them from a tree at that path or treat their result as unverified.
