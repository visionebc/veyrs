# Contributing

## Before you start

Read [Development](/DEVELOPMENT.html), especially "Traps this codebase has
already hit". Most of them are subtle, and all of them shipped once.

## Ground rules

**The full test suite must be green.** Not your file - all 4,778.

```bash
./scripts/test.sh
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

1. Which threat in [Threat Model](/THREAT_MODEL.html) it affects
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

- [ ] Full suite green
- [ ] New routes carry `require(...)` and appear in the list-endpoint walk
- [ ] No credential field in any response schema
- [ ] Errors do not echo submitted values
- [ ] Tenant scoping is applied by VEYRS code, never taken from input
- [ ] External calls degrade rather than 500
- [ ] Comments explain why
- [ ] Documentation updated if behaviour changed
