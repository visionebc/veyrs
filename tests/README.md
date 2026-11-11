# tests

The pytest suite. It runs against a real PostgreSQL database whose name ends in
`_test`, never SQLite. Run it with `./scripts/test.sh`, never bare `pytest`:
`conftest.py` refuses to start without a test database URL.

- `conftest.py` holds the shared fixtures and runs `init-db` once per session.
- `test_phaseN_*.py` modules cover the feature phases; the other modules are
  focused guards (docs, installers, containers, write paths, audit RLS).
- `fixtures/` holds the official CVSS v2, v3 and v4 reference corpora.

Run the files around your change by default; run the full suite only on
explicit request. See `docs/TESTING_GUIDE.md`.
