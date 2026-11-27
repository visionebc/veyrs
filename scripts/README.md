# scripts

Operator and developer tools. Each script's header comment is the full
reference.

| Script | What it does |
|---|---|
| `test.sh` | The only supported way to run the tests: loads `.env` then `.env.test`, derives the `veyrs_test` database URL, points the app at a test Redis (`VEYRS_TEST_REDIS_URL`, default database 15), runs pytest |
| `ci.sh` | Release gate: shell syntax, docs references and links, the targeted guard tests, the export check. Run before tagging; `--fast` skips the site build and export |
| `publish-sites.sh` | Per node: builds the Docs Center, the product site and the console copy beside the live roots, swaps them atomically, prints a fingerprint per tree |
| `migrate-service-user.sh` | Moves an existing native node's API from root to the `veyrs` account; idempotent, auto-rollback, `--rollback` |
| `check-docs-refs.py` | Verifies every `path:line` reference in the hand-written docs (file exists, line in range) against a baseline; reports symbol drift |
| `check-docs-links.py` | Checks every internal link and anchor of a built Docs Center |
| `backup.sh` | Database dump (as a role that bypasses RLS), `.env` and key material, `var/documents` if present; verifies the dump is readable |
| `restore.sh` | Restores a `backup.sh` directory as a database superuser (peer auth when the database is local, else `RESTORE_DSN`); drops and recreates the schema, so it requires `--yes`; runs `init-db` afterwards |
| `sync-intel.sh` | Refreshes the intelligence feeds (CWE, KEV, EPSS, NVD) in order, then notifies the tenants |
| `send-digest.sh` | One tick of the daily digest; each organization's settings decide whether it is due |
| `veyrs-updater.sh` | Privileged half of the in-product update on native installs, started by `veyrs-updater.path` |
| `verify-release.sh` | Checks that a directory of release assets matches the signed sums file |
| `gen-schema-doc.py` | Generates `docs/DATABASE_SCHEMA.md` from the models; `--check` exits 1 if it is stale |
| `freeze-deps.sh` | Regenerates `requirements.txt` from the running venv, with the sha256 of every published file of every pin (needs network) |
| `osv-check.py` | Queries OSV for every pin of `requirements.txt` (or given files or `name==version` pins); exit 1 on any advisory, 2 if OSV is unreachable |
| `sbom.sh` | CycloneDX 1.5 JSON SBOM from `requirements.txt` (names, versions, purls, hashes); standard library only, no network |
| `public-export.sh` | Builds the sanitised tree for the public repository |
| `ip-guard.sh` | Deny-by-default sweep for IPv4 literals in anything published (tree, tarball, images) |
| `publish-github.sh` | Publishes the sanitised tree and, optionally, the release assets to GitHub |
| `publish-images.sh` | Builds, verifies and optionally publishes the container images and the offline bundle |
| `test-docker-stack.sh` | Assertions against a running container stack |
| `test-setup-docker.sh` | End-to-end test of `veyrs-setup.sh` in Docker mode, run on the target host |
| `test-publish-github.sh` | Test harness for `publish-github.sh` with a stubbed `gh`; never touches GitHub |
