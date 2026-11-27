---
title: Security risk register
purpose: Record the security risks and technical debt found while auditing VEYRS 0.39.1 against its code, with evidence, impact, recommendation and priority.
scope: Findings from reading the backend, nginx and systemd configs, container stack, scripts and the pinned dependency list, plus read-only checks on a running node; no attack was executed and no write request was sent.
version: 0.39.1
verified: 2026-11-17
status: Partial
sources: [backend/veyrs/security/ratelimit.py, backend/veyrs/observability.py, backend/veyrs/services/audit.py, backend/veyrs/models/audit.py, backend/veyrs/api/v1/auth.py, backend/veyrs/services/search.py, backend/veyrs/security/scope.py, backend/veyrs/config.py, infrastructure/systemd/veyrs-api.service, scripts/public-export.sh, requirements.txt, docker/compose.yaml]
related: [security/security-architecture.md, security/hardening.md, security/authorization.md, security/authentication.md, THREAT_MODEL.md, SECURITY.md]
---

# Security risk register

How to read this register. **Severity** is High, Medium or Low, judged on impact if exploited and on how reachable the weakness is in a standard deployment. **Priority** is P1 (fix before the next release), P2 (next release) or P3 (backlog). **Basis** says how the finding was established: *Read* means derived from reading code or config; *Live* means observed with a read-only request on a running node; *Query* means an external advisory lookup. No finding below was exploited. Where reachability depends on framework behaviour or on a proxy that was not tested, the entry says so.

## Summary

| ID | Title | Severity | Priority | Basis | Status |
|---|---|---|---|---|---|
| R-01 | Pinned dependencies carry known vulnerabilities (98 advisories in 10 of 54 packages) | High | P1 | Query | Fixed in 0.41.0 |
| R-02 | Internal git history contains a plaintext administrator password and a database dump | High | P1 | Read | Not a bug (verified 2026-11-17) |
| R-03 | Global search ignores team scope | Medium | P1 | Read | Fixed in 0.41.0 |
| R-04 | A client-supplied correlation id can make audit writes fail silently | Medium | P1 | Read | Fixed in 0.41.0 |
| R-05 | Audit trails are not append-only at the database; `auth_events` has no tenant policy and no read API; owner separation pending | Medium | P2 | Read | Partially fixed in 0.41.0 |
| R-06 | The native API service runs as root | Medium | P2 | Read, Live | Fixed in 0.41.0 |
| R-07 | MFA cannot be enforced per organization | Medium | P2 | Read | Fixed in 0.41.0 |
| R-08 | Access tokens survive logout and password change | Medium | P2 | Read | Fixed in 0.41.0 |
| R-09 | Outbound connector URLs have no private-address guard | Medium | P2 | Read | Partially fixed in 0.41.0 |
| R-10 | OIDC accepts a missing `email_verified` claim and links by e-mail | Medium | P2 | Read | Fixed in 0.41.0 |
| R-14 | Rate-limit identity for non-auth routes is attacker-chosen | Medium | P2 | Read | Fixed in 0.41.0 |
| R-21 | Supply chain: no hashes, no CI scan, no SBOM | Medium | P2 | Read | Partially fixed in 0.41.0 |
| R-23 | Application-layer tenant filter is a convention, not a guard | Medium | P2 | Read | Fixed in 0.41.0 |
| R-11 | OIDC `state` is not bound to the initiating browser | Low | P3 | Read | Fixed in 0.41.0 |
| R-12 | SSO sign-in ignores account lock and clears it | Low | P3 | Read | Fixed in 0.41.0 |
| R-13 | Account lockout can be used to deny service, including to administrators | Low | P3 | Read | Fixed in 0.41.0 |
| R-15 | Refresh family equals user; refresh ignores lock state | Low | P3 | Read | Fixed in 0.41.0 |
| R-16 | Tokens are stored in `localStorage` | Low | P3 | Read | Accepted |
| R-17 | OpenAPI schema is public in production | Low | P3 | Live | Fixed in 0.41.0 |
| R-18 | Production boot does not reject an unset secret key | Low | P3 | Read | Fixed in 0.41.0 |
| R-19 | Container stack defaults to `development` mode | Low | P3 | Read | Partially fixed in 0.41.0 |
| R-20 | Hand-written HKDF | Low | P3 | Read | Fixed in 0.41.0 |
| R-22 | Test database URL present in the production environment file | Low | P3 | Live | Fixed in 0.41.0 |
| R-24 | Password verification endpoints do not charge the lockout budget | Low | P3 | Read | Fixed in 0.41.0 |
| R-25 | Rate limiter never retries Redis once it has fallen back | Low | P3 | Read | Fixed in 0.41.0 |
| R-26 | Delivered-code attempt counter is not atomic | Low | P3 | Read | Fixed in 0.41.0 |
| R-27 | nginx locations with their own `add_header` drop the security headers | Low | P3 | Read | Fixed in 0.41.0 |
| R-28 | Redis has no authentication by default | Low | P3 | Read | Fixed in 0.41.0 |

IDs are stable; they are not renumbered when items are fixed.

**Totals (2026-11-17, after the 0.41.0 fix round).** 28 risks: **22 fixed** (R-01, R-03, R-04, R-06, R-07, R-08, R-10 to R-15, R-17, R-18, R-20, R-22 to R-28), **4 partially fixed** (R-05, R-09, R-19, R-21), **1 accepted** (R-16), **1 not a bug** (R-02), **0 open**.

## R-01 Dependency vulnerabilities (High, P1)

**Status: Fixed in 0.41.0.** Re-queried on 2026-11-17 against the new lock (55 pins, `scripts/osv-check.py`): **0 advisories in 0 packages**. Upgrades: `pypdf` 6.15.0 to 6.21.4, `python-multipart` 0.0.20 to 0.0.31, `starlette` 0.41.3 to 1.3.1 (with `fastapi` 0.115.6 to 0.134.0, the first release family that allows Starlette 1.x and the floor `>=0.46`), `pillow` 12.3.0 to 13.0.0 (now a direct pin), `certifi` 2026.7.22 to 2026.10.18, `dnspython` 2.8.0 to 2.9.2, `pyasn1` 0.6.4 to 0.6.5, `pytest` 8.3.4 to 9.0.3. `python-jose` 3.3.0 (an unfixed advisory, GHSA-3qf3-8w2g-rqmx) and its dependencies `ecdsa` and `rsa` were removed and replaced by `PyJWT` 2.15.1: local tokens (HS256) in `security/auth.py` and OIDC ID-token verification (RS/PS/ES against the provider JWKS, `at_hash` checked by hand) in `services/oidc_auth.py`. The algorithm allow-lists are unchanged. `pytest` stays in the lock because `scripts/test.sh` runs on the nodes; splitting a dev lock is deferred. Re-run the check before every release.

**Method.** On 2026-11-17 the 54 exact pins of `requirements.txt` were submitted to the public OSV service (`https://api.osv.dev/v1/querybatch`, package name, ecosystem `PyPI` and version only), then each advisory was fetched for severity and fix versions. `pip-audit` was not used. The versions installed on the primary application node match the pins (checked by listing the package directories read-only). OSV reports 149 records (98 distinct GitHub advisories plus their `PYSEC` aliases) against **10 of 54** packages. The other 44 packages had no advisory at query time. Results change daily; re-run the query (see [hardening.md](hardening.md)).

| Package (pinned) | Advisories | Worst severity | Fixed in | Reachable in VEYRS? |
|---|---|---|---|---|---|
| `pypdf` 6.15.0 | 29 (18 High, 10 Medium, 1 Low) | High | 6.21.4 | Yes. User-uploaded PDFs are parsed in the API process (`backend/veyrs/services/documents.py:173`); denial of service by CPU or memory exhaustion from a crafted file. Needs `document:write`. |
| `python-multipart` 0.0.20 | 7 | High | 0.0.31 | Yes, probably before authentication. FastAPI parses a multipart body before it resolves dependencies, so the parser is reachable on every route with upload or form parameters (23, per `pyproject.toml`). Not exercised here. Advisories include unbounded multipart part headers and quadratic parsing. |
| `starlette` 0.41.3 | 7 (3 High) | High | 1.3.1 | Partly. GHSA-86qp-5c8j-p5mr ("BadHost"): a malformed `Host` header makes `request.url.path` differ from the routed path, bypassing path-based middleware. `RateLimitMiddleware` decides exemptions and the auth tier from `request.url.path` (`backend/veyrs/security/ratelimit.py:174-182`). Reachable only if the front proxy forwards such a header; nginx normally rejects it, but this was not tested. Others: Range-header DoS in `FileResponse`, form limits ignored. |
| `pillow` 12.3.0 | 43 (5 Critical, 24 High) | Critical | 13.0.0 | Unlikely. Installed as a dependency of `reportlab`; VEYRS does not import it (`grep` over `backend/`). Reachable only if report generation decodes untrusted images. Pin and upgrade anyway. |
| `certifi` 2026.7.22 | 1 | Critical | 2026.10.18 | Yes, indirectly. The bundle trusts roots the advisory says are compromised; affects TLS verification of every outbound `httpx` call (feeds, IdP, vault, ITSM). |
| `dnspython` 2.8.0 | 2 | High | 2.9.2 | Low. Resolver DoS; transitive via `email-validator`. |
| `pyasn1` 0.6.4 | 4 | High | 0.6.5 | Low. BER decoding DoS; used by `ldap3` on answers from the configured directory. |
| `python-jose` 3.3.0 | 3 (2 Critical) | Critical | 3.4.0 for two; none for GHSA-3qf3-8w2g-rqmx | **Not exploitable as configured.** The algorithm-confusion advisories need an HS algorithm verified with an asymmetric key. Local tokens allow only HS256/384/512 with a symmetric secret (`backend/veyrs/config.py:58`); the OIDC verifier allow-lists RS/PS/ES algorithms only (`backend/veyrs/services/oidc_auth.py:57`). The library is still flagged by every scanner and is unmaintained in practice. |
| `ecdsa` 0.19.2 | 1 | High (timing, Minerva) | none listed | Not reachable: pulled by `python-jose`, no ECDSA signing by VEYRS. |
| `pytest` 8.3.4 | 1 | Medium | 9.0.3 | Development only (`pyproject.toml` optional `dev`), but it is in the production lock file. |

**Impact.** Remote denial of service of the API by a low-privilege user (pypdf) or by an anonymous one (multipart); possible bypass of the rate-limit tiers (starlette, conditional); weakened outbound TLS trust (certifi).

**Recommendation.**

1. Upgrade `pypdf`, `python-multipart`, `certifi`, `dnspython`, `pyasn1` now; they are drop-in. Re-run the full test suite.
2. Move FastAPI to a release compatible with a fixed Starlette (>= 1.3.1 per the advisories); this is a framework upgrade, plan and test it.
3. Pin `pillow >= 13.0.0` explicitly (it is currently implicit through `reportlab`).
4. Replace `python-jose` with a maintained JWT library and drop `ecdsa`; keep the algorithm allow-lists.
5. Split dev dependencies out of the production lock (`pytest`).
6. Make the check recurring (R-21).

Meanwhile, cap the multipart surface at the proxy: keep `client_max_body_size` as low as your largest legitimate upload.

## R-02 Secrets in the internal git history (High, P1)

**Evidence.** `scripts/public-export.sh:27-29` states that the internal history "carries a plaintext administrator password and a full production database dump in 72 of its commits", and the script deliberately publishes a single squashed commit for that reason. `scripts/public-export.sh:67` also lists `.bootstrap-credentials` as a plaintext administrator password file to exclude.

**Impact.** Anyone with read access to the internal repository (or any clone or mirror of it) can recover a credential and a data set. The public export protects only the public repository.

**Recommendation.** Confirm that the exposed administrator credential has been rotated and that no production account still uses it. Treat the dump's contents as disclosed to everyone with repository access: rotate any secret that was in it (encryption key, API keys, connector credentials) per the key-rotation procedure in the recovery manual. Restrict the internal repository, and run a secret scanner over history before any other export. Do not rewrite history without planning, but do not leave the credential valid.

**Status: Not a bug.** Verified 2026-11-17: no object under var/backups or .bootstrap-credentials in any ref of the internal repository (history rewritten 2026-11-11); the stale comment in `scripts/public-export.sh` is corrected. Clones that predate the rewrite may still hold the old objects.

## R-03 Global search ignores team scope (Medium, P1)

**Status.** Fixed in 0.41.0. `services/search.py` takes the caller's `TeamScope` and narrows vulnerabilities, findings, assets and tickets exactly like the list endpoints; `/search`, `/search/semantic` and the assistant's grounding pass `principal.scope`. Documents, knowledge articles and news are not team-owned and are unchanged.

**Evidence.** `GET /api/v1/search` and `/search/semantic` (`backend/veyrs/api/v1/knowledge.py:672-697`) pass only `permissions` and `is_superuser` to `services/search.py`, which has no scope parameter; its finding, asset and ticket queries filter by `organization_id` and permission only (`backend/veyrs/services/search.py:96-140`). The router's tag `intelligence & knowledge` is in `EXEMPT_TAGS` (`backend/veyrs/security/scope.py:78-80`), so `enforce_route_policy` lets restricted principals through.

**Impact.** A team-restricted user holding `finding:read`, `asset:read` or `ticket:read` can discover titles, hostnames, risk scores and states of findings, assets and tickets that belong to other teams, defeating the purpose of team scope.

**Recommendation.** Apply `scope.assets/findings/tickets` to the search queries, or refuse restricted principals on these two routes (`refuse_if_restricted`) until they are scope-aware. Add a test that walks every route reachable by a restricted principal, like the existing anonymous walk.

## R-04 Correlation-id header can suppress audit rows (Medium, P1)

**Status.** Fixed in 0.41.0. The middleware keeps the client's `X-Correlation-ID` only when it matches `[A-Za-z0-9._:-]` (truncated to 64 characters); anything else is replaced by a UUID.

**Evidence.** The correlation id is taken from `X-Correlation-ID` unchanged (`backend/veyrs/observability.py:199`) and copied into audit writes (`backend/veyrs/api/v1/auth.py:366,384-389`, `backend/veyrs/security/deps.py:251`). The columns are `VARCHAR(64)` in `audit_log` and `auth_events` (`backend/veyrs/models/audit.py:50,71`). `audit.record` and `record_auth` catch every exception and only log it (`backend/veyrs/services/audit.py:118-119,145-146`). CORS explicitly allows this header (`backend/veyrs/main.py:82-83`).

**Impact.** By the code, a header longer than 64 characters makes the audit INSERT fail inside its savepoint and the row is dropped while the request itself succeeds. A caller who knows this can act (including failed or successful logins) without leaving `auth_events` or `audit_log` rows. Lockout still counts because it lives on the user row. This was derived from reading and not exercised, because crafted requests were out of scope.

**Recommendation.** Validate the header (for example `^[A-Za-z0-9._-]{1,64}$`, else generate a UUID). Independently, make audit-write failures visible: increment a metric and alert on `audit write failed` log lines.

## R-05 Audit trails are not enforced append-only (Medium, P2)

**Evidence.** `backend/veyrs/models/audit.py:10-11` says "the DB role used by the API is granted INSERT and SELECT only (see infrastructure/rls.sql)". The file `infrastructure/rls.sql` does not exist in the repository. The container initdb script makes the application role the **owner** of its database (`docker/initdb.d/10-app-role.sh`), and owners may update and delete. Separately, `auth_events` is skipped by RLS (`backend/veyrs/cli.py:30-39`) and nothing in `backend/veyrs/api/` reads it, so authentication events can only be reviewed with direct SQL.

**Impact.** An attacker who gains the application's database credentials (or code execution) can alter or delete audit history; the documented "append-only" property holds only for application code paths. The SOC log cannot be used through the product, and its tenant isolation relies on a column filter nobody queries.

**Recommendation.** Either create the restricted role and `REVOKE UPDATE, DELETE, TRUNCATE` on the three audit tables (and ship the SQL the model comment promises), or correct the comment and documentation. Expose `auth_events` through an `audit:read` endpoint scoped by organization, give it a strict RLS policy, and define a retention job for all three logs.


**Status: Partially fixed in 0.41.0** (trigger refuses UPDATE/DELETE/TRUNCATE on the three audit tables except retention deletes under `SET LOCAL veyrs.audit_prune = 'on'` and FK cascades; `auth_events` row policies; `GET /api/v1/auth-events`; the stale model comment corrected). Remains: the application role still owns the tables and can disable the trigger; a non-owner role is documented in hardening.md, not shipped. Retention itself is the prune command of the `sla` workstream.
## R-06 API service runs as root (Medium, P2)

**Evidence.** `infrastructure/systemd/veyrs-api.service:9` sets `User=root`; a running node shows the uvicorn process owned by `root` (observed 2026-11-17). Mitigations exist: `NoNewPrivileges`, `ProtectSystem=strict`, `ProtectHome`, `PrivateTmp`, a single writable path and `MemoryDenyWriteExecute` (`:32-51`). The container images run as UID 10001 (`docker/Dockerfile:87`).

**Impact.** A code-execution bug in the API (see R-01) lands as root inside the sandbox, with read access to `.env` (encryption key, secret key, database password) and all of `/opt/veyrs`.

**Recommendation.** Run as a dedicated unprivileged user that owns only `/opt/veyrs/var`, keep `.env` readable by that user alone (`0600`), and let the root-owned updater and backup units remain separate. Add `CapabilityBoundingSet=` (empty) and `RestrictAddressFamilies=AF_INET AF_INET6 AF_UNIX`.

**Status.** Fixed in 0.41.0 (unit runs as `veyrs` with an empty capability set; `install.sh` creates the account; `scripts/migrate-service-user.sh` moves existing nodes, with rollback). The updater stays a separate root unit.

## R-07 MFA cannot be enforced per organization (Medium, P2)

**Evidence.** MFA is enrolled by each user (`backend/veyrs/api/v1/auth.py:877-958`); nothing reads an organization or role policy to require it. OIDC can require an `amr` claim (`require_mfa_amr`, `backend/veyrs/services/oidc_auth.py:285-286`), but SSO bypasses VEYRS MFA by design.

**Impact.** Privileged local accounts (the platform administrator in particular, who cannot use SSO) can run on a password alone indefinitely, and account takeover of any user needs only the password.

**Recommendation.** Add an organization setting "require MFA" enforced at login for local and directory credentials, with a grace period and an operator break-glass (`veyrs mfa-reset` already exists), and make MFA mandatory for `is_superuser` accounts.


**Status.** Fixed in 0.41.0 (per-organization `require_mfa` via `PUT /api/v1/mfa-policy`; accounts without a factor, platform administrators included, get an enrolment-only token from their password; password-only sessions from before the switch end at their next refresh). No grace period: enrolment is immediate but never a lock-out.
## R-08 Access tokens survive logout and password change (Medium, P2)

**Evidence.** `logout` and `change_password` revoke refresh tokens only (`backend/veyrs/api/v1/auth.py:619-630,783-785`); access tokens are stateless with no `jti` denylist (`backend/veyrs/security/auth.py:80-91`). Deactivating a user does take effect immediately because state is re-read (`backend/veyrs/security/deps.py:292`). The lifetime is `VEYRS_ACCESS_TOKEN_MINUTES`: 30 by default, **60 on the inspected node**.

**Impact.** A stolen access token keeps working for up to its lifetime after the owner signs out or changes the password.

**Recommendation.** Keep the lifetime short (15 minutes), and store a per-user `tokens_valid_after` timestamp compared with `iat` in `_principal_from_jwt`; set it on logout, password change, MFA reset and role-set changes.


**Status.** Fixed in 0.41.0 (`users.token_version` carried as `tv` in every access token and compared in `_principal_from_jwt`, which already loads the user; bumped by logout, password change, `veyrs mfa-reset`, deactivation and deletion). Not bumped by the automatic lockout, on purpose. The default lifetime is unchanged (30 minutes).
## R-09 Connector URLs have no private-address guard (Medium, P2)

**Status: Partially fixed in 0.41.0.** `services/net_guard.py` resolves the host and checks every address before any CMDB, ITSM, Confluence, scanner or AI-provider call. Link-local, cloud-metadata, unspecified, multicast and reserved addresses are always refused; loopback needs `VEYRS_OUTBOUND_ALLOW_LOOPBACK=true`; private ranges are allowed by default (on-premise NetBox/Jira) and refused with `VEYRS_OUTBOUND_ALLOW_PRIVATE=false`. Residual: the check precedes the request, so DNS rebinding is not covered (redirects are not followed); per-organization override and the e-mail/Telegram transports (operator-configured, not tenant-configured) are not covered.

**Evidence.** ITSM, scanner and CMDB clients call administrator-configured base URLs with only `follow_redirects=False` (`backend/veyrs/services/itsm.py:64`, `backend/veyrs/services/scanners.py:97-107`, `backend/veyrs/services/cmdb.py:341`); there is no loopback, link-local or RFC 1918 check, and scanner TLS verification can be switched off per connector (`scanners.py:90`). Execution-agent targets, by contrast, do refuse reserved addresses (`backend/veyrs/services/agents.py:435-440`).

**Impact.** In a multi-tenant installation, a tenant administrator (who can configure connectors) can make the API server request internal services or a cloud metadata endpoint; connector "verify" results are shown back to the caller. In a single-tenant installation the risk is limited to a compromised administrator.

**Recommendation.** Resolve the host before each request and refuse loopback, link-local, multicast and (configurable) private ranges unless an explicit allow-list entry exists; re-check after redirects (currently disabled); restrict who may disable TLS verification.

## R-10 OIDC accepts a missing `email_verified` and links by e-mail (Medium, P2)

**Evidence.** The callback rejects only `claims.get("email_verified") is False` (`backend/veyrs/api/v1/auth.py:1077`), so a provider that omits the claim passes. The local account is found by exact e-mail match within the organization (`auth.py:1080-1081`), and an existing local, password-holding account is signed in without any further proof.

**Impact.** If the configured identity provider lets users set an unverified address, such a user can sign in as the local account that owns that address (other than superusers).

**Recommendation.** Require `email_verified` to be present and true unless the organization explicitly opts out for a trusted IdP; prefer matching on the stable `sub` claim recorded at first link.


**Status.** Fixed in 0.41.0 (`email_verified` must be present and true; no per-organization relaxation). Matching on `sub` was not added.
## R-14 Rate-limit identity is attacker-chosen (Medium, P2)

**Evidence.** For non-auth paths the bucket key is a SHA-256 of the presented bearer token or the `X-API-Key` prefix, with no validation (`backend/veyrs/security/ratelimit.py:140-163`). Any random string yields a fresh bucket of 240 requests per minute. The strict auth tier is keyed by IP and is not affected (`:178-183`).

**Impact.** The general limit protects nothing against a determined client: unauthenticated requests with rotating junk credentials are never throttled beyond the fresh bucket, including expensive public paths (for example SSO start, which triggers an outbound discovery fetch) and invalid API keys (each valid-looking prefix costs an Argon2 verification only if the prefix exists).

**Recommendation.** Key unauthenticated or unverifiable requests by IP, and key by credential only after verification (move the check after `get_principal`, or maintain two buckets: IP and credential). Add an overall per-IP ceiling.


**Status.** Fixed in 0.41.0 (the general bucket is the subject of a bearer token that verifies, or an API key already verified in that worker; anything else is the client address). No separate overall per-IP ceiling was added.
## R-21 Supply-chain controls are thin (Medium, P2)

**Status: Partially fixed in 0.41.0.** Done: `requirements.txt` carries the sha256 of every published file of every pin (`scripts/freeze-deps.sh` generates them from PyPI), and `install.sh`, `docker/Dockerfile` and the release wheelhouse build and verification in `scripts/publish-github.sh` install with `--require-hashes`; `scripts/sbom.sh` writes a CycloneDX 1.5 SBOM (name, version, purl, hashes) from the lock with the standard library only; `scripts/osv-check.py` queries OSV for every pin and exits 1 on any advisory (2 if OSV is unreachable), so it can gate CI or the release job. Tests: `tests/test_phase24_dependencies.py`. Remaining: the repository still has no CI definition, so nothing runs `osv-check.py` or a secret scanner automatically yet; the SBOM is not yet added to `SHA256SUMS` by the release script (`deploy` workstream); the offline image bundle still lacks an entry in `SHA256SUMS`.

**Evidence.** `requirements.txt` has exact versions but no hashes, and installs run `pip install -r requirements.txt` without `--require-hashes` (`docker/Dockerfile:55`). The repository has no CI definition (no `.github`), no SBOM, no dependency or secret scanner configuration (searched: no `pip-audit`, `trivy`, `gitleaks` or `cyclonedx` outside unrelated parser code). The legacy threat model claimed "dependency and secret scanning in CI, SBOM generation"; that was not true of the repository and has been corrected. Positives: digest-pinned base images (`docker/Dockerfile:29,110`, `docker/compose.yaml:162,211`), a release-signing chain with an ed25519 key and an embedded verifier (`release/allowed_signers`, `veyrs-setup.sh`), an offline wheelhouse mode with `--no-index` (`install.sh:903-925`), and an `ip-guard` and public-export guard against leaking internals.

**Impact.** A compromised or typosquatted package, or a re-uploaded file under the same version, would install silently; R-01 shows the lock goes stale without anyone noticing.

**Recommendation.** Generate hashes (`pip-compile --generate-hashes` or `uv pip compile --generate-hashes`) and install with `--require-hashes`; run `pip-audit` (or OSV) and a secret scanner on every change and nightly; publish a CycloneDX SBOM with each release and sign it with `SHA256SUMS`; include the offline image bundle in `SHA256SUMS` (today it has only a `.sha256`).

## R-23 Application-layer tenant filter is a convention (Medium, P2)

**Evidence.** The module docstring of `backend/veyrs/db.py:1-12` and the legacy security documents describe two independent layers, the first being `TenantSession.query()` refusing statements without an organization filter. No such method exists; `TenantSession` in `backend/veyrs/security/deps.py:381-390` is an annotated session whose tenant is bound. Tenant safety of a query therefore comes from the author remembering `organization_id ==` plus RLS. RLS is the real control, and it is disabled for a superuser database role and permissive-when-unbound on four tables (`backend/veyrs/cli.py:44-62`). The comment in `docker/initdb.d/10-app-role.sh` still says "70 of VEYRS' 87 tables" while `init-db` now applies policies to 72 of 89.

**Impact.** One missing filter combined with a misconfigured database role (superuser or `BYPASSRLS`, a common native-install mistake) is a cross-tenant leak with no error. Documentation overstates the independence of the layers.

**Recommendation.** Add a startup check that the application role is neither superuser nor `BYPASSRLS` and refuse to start in production otherwise (the verification query is in [hardening.md](hardening.md)); add a test that walks the tenant-scoped models and fails on unfiltered selects, or implement the guard the docstring describes; correct the docstring.


**Status.** Fixed in 0.41.0 within its scope (`security/tenant_guard.py`: the production API refuses a role that bypasses RLS; an ORM hook flags tenant-table statements run with no tenant bound, logged under `VEYRS_DEBUG`; a test walks every GET route with it; the `db.py` docstring corrected). A query that is bound but forgets its own filter is still caught only by RLS, by design.
## R-11 OIDC `state` is not bound to the browser (Low, P3)

**Evidence.** `state` and the PKCE verifier live in Redis keyed by `state` only (`backend/veyrs/services/oidc_auth.py:219-244`); no cookie or session ties the callback to the browser that started the flow. The same applies to the post-callback handoff.

**Impact.** Login CSRF: an attacker can start a flow, complete it at the IdP, and induce a victim's browser to open the callback, signing the victim into the attacker's account (a confusion attack; it does not reveal the victim's data directly).

**Recommendation.** Bind the flow to a short-lived `HttpOnly`, `SameSite=Lax` cookie set at `start` and compared at `callback`.


**Status.** Fixed in 0.41.0 (an HttpOnly, SameSite=Lax cookie set at `start` holds a random binder whose hash is stored with the flow and then with the hand-off; callback and exchange refuse a browser that cannot present it).
## R-12 SSO ignores account lock and clears it (Low, P3)

**Evidence.** The callback and exchange check `is_active` and `is_superuser` but not `is_locked` or organization state, and the exchange sets `failed_logins = 0` and `locked_until = None` (`backend/veyrs/api/v1/auth.py:1089-1118`). `get_principal` still rejects locked users on the next request, but the successful exchange has already removed the lock.

**Impact.** An SSO sign-in resets a lock that password failures had set; locks cannot be used as a response to a compromised account that also has an SSO identity.

**Recommendation.** Refuse locked or inactive-organization users in callback and exchange, and do not reset the counters there.


**Status.** Fixed in 0.41.0 (callback and exchange refuse locked users and disabled organizations; the lock and its counter are no longer cleared by SSO).
## R-13 Lockout can deny service (Low, P3)

**Evidence.** Ten failures lock any account, including a platform administrator, for 15 minutes (`backend/veyrs/api/v1/auth.py:58-59,111-113`); the counter resets on lock, so ten more attempts after the lock expires repeat it. The per-IP login limit (10 per minute) permits exactly that from one address. There is no unlock endpoint or CLI command.

**Impact.** Anyone who knows an administrator's e-mail can keep the break-glass account locked.

**Recommendation.** Exempt known-good source networks, add progressive (exponential) delay instead of a flat lock for platform administrators, and add `veyrs unlock --email` for operators.


**Status.** Fixed in 0.41.0 (`security/lockout.py`: per-source exponential back-off; an account-wide lock only from failures spread over at least four sources; `VEYRS_LOCKOUT_EXEMPT_NETWORKS`; `veyrs unlock`). A distributed attacker can still trip the account lock; exempt networks and `veyrs unlock` are the answer for administrators.
## R-15 Refresh-token family is the user (Low, P3)

**Evidence.** Every new login stores `family_id = user.id` (`backend/veyrs/api/v1/auth.py:88`), so detected reuse of any one refresh token revokes all of that user's sessions (`:575-585`). `refresh` checks `is_active` and `is_deleted` but not `is_locked` or the organization state (`:560-616`).

**Impact.** A user with several devices is signed out everywhere after one replay, and a locked user can keep refreshing (access tokens are rejected for locked users, so the practical effect is limited).

**Recommendation.** Use a new family id per login; reject locked users and inactive organizations in `refresh`.


**Status.** Fixed in 0.41.0 (a new family per sign-in; reuse revokes that family only; refresh refuses locked users and disabled organizations).
## R-16 Tokens in `localStorage` (Low, P3)

**Status: Accepted risk, compensating controls verified 2026-11-17.** Moving the refresh token to an `HttpOnly` cookie was considered and declined for this round: the API authenticates with bearer tokens, a cookie session adds a CSRF surface (and `SameSite` alone does not cover the API clients and the SSO hand-off), and it would break non-browser API clients. What holds the risk down: (1) the console's CSP (`infrastructure/nginx-veyrs-console.conf`) is `default-src 'self'; script-src 'self'; connect-src 'self'; frame-ancestors 'none'; base-uri 'self'; form-action 'self'`, so inline script, third-party script and any foreign origin (including exfiltration through `fetch`) are refused; `style-src` allows `'unsafe-inline'` for styles only. (2) `index.html` loads exactly one script, `/app.js`, and `app.js` has no inline event-handler attribute; `tests/test_console_keyboard_a11y.py::test_the_console_csp_forbids_inline_script_and_foreign_origins` pins both. (3) The CSP is set on the server and is not dropped for the HTML page (`location /` declares no `add_header`; the `/static/` and health locations do, see R-27, but they serve no documents). (4) The access token lives 30 to 60 minutes; the refresh token rotates and reuse revokes the family (`security/auth.py`); the console stores no other secret. (5) Output escaping goes through `esc()`; the 182 `innerHTML` assignments were not individually audited and remain the residual risk. Revisit if the console ever needs a script from another origin, or if `'unsafe-inline'` for styles is exploited as a CSS-exfiltration route.

**Evidence.** The console stores access and refresh tokens in `localStorage` (`frontend/console/app.js:16-26`). The console loads no third-party script and its CSP forbids inline script (`infrastructure/nginx-veyrs-console.conf:30`), but 181 `innerHTML` assignments exist in `frontend/console/app.js` and were not individually audited.

**Impact.** Any cross-site-scripting bug exposes the refresh token (14 days).

**Recommendation.** Keep the strict CSP, audit the `innerHTML` call sites for escaping, and consider an `HttpOnly` `SameSite=Strict` cookie for the refresh token.

## R-17 Public OpenAPI schema in production (Low, P3)

**Status.** Fixed in 0.41.0. `/docs`, `/redoc` and `/api/v1/openapi.json` are served only outside production, or with `VEYRS_EXPOSE_OPENAPI=true`.

**Evidence.** `openapi_url` is always `/api/v1/openapi.json` (`backend/veyrs/main.py:68`) and is listed in the public routes (`tests/test_phase10_hardening.py:195-197`); a running production node answered 200 anonymously. `/docs` and `/redoc` are off in production.

**Impact.** The full route, parameter and schema list is available to anonymous callers, easing reconnaissance (266 documented paths).

**Recommendation.** Serve the schema only when not in production, or require authentication; if it must stay public, document that it is public.

## R-18 Production boot accepts an unset secret key (Low, P3)

**Evidence.** An empty `VEYRS_SECRET_KEY` becomes a random per-process key (`backend/veyrs/config.py:150-159`) and `assert_production_safe()` does not check it (`:214-231`). Only the container entrypoint refuses (`docker/entrypoint.sh:34-39`). The installer generates one (`install.sh:980-1005`).

**Impact.** A hand-built native install with four workers authenticates intermittently (each worker signs with its own key) and sessions do not survive a restart.

**Recommendation.** Make `assert_production_safe` fail when the secret key was not supplied.


**Status.** Fixed in 0.41.0 (`assert_production_safe` refuses a secret key that was not supplied).
## R-19 Container stack defaults to development mode (Low, P3)

**Evidence.** `docker/env.example:78` sets `VEYRS_ENVIRONMENT=development`. In that mode `assert_production_safe` is skipped, `/docs` and `/redoc` are served, and `/metrics` is open without a token (`backend/veyrs/main.py:59-67,129-135`); the console nginx returns 404 for `/metrics` (`docker/console.conf:140`) but proxies `/docs`.

**Impact.** An evaluation stack exposed beyond loopback runs without the production guards.

**Recommendation.** Keep the default for evaluation, but print a warning at start and document the switch to `production` in the Docker manual; `VEYRS_HTTP_BIND` already defaults to loopback.

**Status: Partially fixed in 0.41.0** (`compose.yaml` defaults `VEYRS_ENVIRONMENT` to `production`; `env.example` opts into `development` explicitly and `up` warns; `init` takes `VEYRS_ENVIRONMENT=production` plus an https `VEYRS_PUBLIC_BASE_URL`). Remains: an operator who sets `development` explicitly, or keeps an older `docker/.env`, still runs without the production guards (the warning is the only control).

## R-20 Hand-written HKDF (Low, P3)

**Evidence.** `backend/veyrs/security/secrets.py:72-81` implements RFC 5869 HKDF with an empty salt by hand, used only when no encryption key is configured (`:84-92`). Production refuses that configuration (`backend/veyrs/config.py:222-225`).

**Impact.** Negligible in production; the project rule is not to hand-roll key derivation.

**Recommendation.** Use `cryptography.hazmat.primitives.kdf.hkdf.HKDF` or remove the derived-key path.


**Status.** Fixed in 0.41.0 (`cryptography`'s HKDF; byte-identical output checked against fixed vectors from the previous implementation).
## R-22 Test database URL in the production environment file (Low, P3)

**Evidence.** The production node's `.env` defines the key `VEYRS_TEST_DATABASE_URL` (key name observed live; value not read).

**Impact.** Running the test suite on that host could target a database it should not; tests create and delete tenants.

**Recommendation.** Remove the key from production environments; run tests only on a build host.

**Status.** Fixed in 0.41.0 (the installer no longer writes the key into `.env`; the suite reads `.env.test`, loaded by `scripts/test.sh`; the application never reads it). Existing nodes move the line by hand (environment A procedure).

## R-24 Password endpoints do not charge the lockout budget (Low, P3)

**Evidence.** `/auth/password`, `/auth/mfa/disable` and `/auth/mfa/recovery-codes` verify the current password and return a plain 401 or 422 on failure without `_spend_attempt` (`backend/veyrs/api/v1/auth.py:771-790,960-1000`). They are covered only by the per-IP limit of 10 per minute.

**Impact.** Someone holding a stolen access token can guess the account password and second factor at 10 attempts per minute per source address without triggering lockout or audit rows (R-04 aside).

**Recommendation.** Charge failures to the same counter and record an `auth_events` row.


**Status.** Fixed in 0.41.0 (wrong passwords and codes on `/auth/password`, `/auth/mfa/disable` and `/auth/mfa/recovery-codes` are charged to the lockout budget and recorded in `auth_events`; a waiting source gets 429).
## R-25 Rate limiter stays in-process after one Redis failure (Low, P3)

**Evidence.** `_redis()` runs once per process; on failure it sets `_redis_checked` and never retries (`backend/veyrs/security/ratelimit.py:80-100`).

**Impact.** If Redis is down when a worker first handles a request, that worker enforces per-process windows (about N times the budget across N workers) until restarted, even after Redis returns.

**Recommendation.** Retry the connection periodically (for example every 30 seconds).


**Status.** Fixed in 0.41.0 (a worker retries Redis every 30 seconds; a Redis error mid-request counts in the in-process window instead of allowing the request outright).
## R-26 Delivered-code attempt counter is not atomic (Low, P3)

**Evidence.** `check()` reads the stored attempt record, increments in Python and writes it back (`backend/veyrs/security/mfa_delivery.py:286-314`). Concurrent guesses can all read the same count.

**Impact.** The five-guess limit per delivered code can be exceeded by parallel requests; the per-IP limit (10 per minute) and the shared lockout bound the practical effect.

**Recommendation.** Use an atomic `INCR` on a separate counter key.


**Status.** Fixed in 0.41.0 (an atomic `INCR` counter per code, incremented before the comparison).
## R-27 Security headers dropped by nested `add_header` (Low, P3)

**Evidence.** nginx does not inherit `add_header` into a location that defines its own. `location /static/` and the health-check location define `Cache-Control` headers (`infrastructure/nginx-veyrs-console.conf:56-60,72-75`), so those responses carry no CSP, `nosniff` or frame protections.

**Impact.** Minor; static CSS and probe responses. It becomes real if a script or HTML file is ever served from `/static/`.

**Recommendation.** Repeat the security headers in those locations or use an `include` snippet.

**Status.** Fixed in 0.41.0 (locations that need their own `add_header` repeat the server headers, `/static/` uses `expires`; `tests/test_fix_deploy.py` guards every shipped vhost and the installer heredoc).

## R-28 Redis has no authentication by default (Low, P3)

**Evidence.** The default `VEYRS_REDIS_URL` is `redis://127.0.0.1:6379/0` (`backend/veyrs/config.py:63`); the container Redis runs without `requirepass` (`docker/compose.yaml:222`) on the internal network. Redis holds delivered MFA codes (hashed), OIDC flow state, RADIUS challenges and rate counters.

**Impact.** Anything that can reach the Redis port can read or write that state, including planting an MFA code hash for a known user id.

**Recommendation.** Bind Redis to loopback or the stack network only, and set a password in the URL (`redis://:CHANGE_ME@host:6379/0`) for any multi-host deployment.

**Status.** Fixed in 0.41.0 (Redis starts with `--requirepass` from a generated `VEYRS_REDIS_PASSWORD`, wired into `VEYRS_REDIS_URL`; `up` generates it for an older `docker/.env`).

## Positive observations

Recorded so that readers can calibrate the register against what already works: generic authentication failures with timing equalization; refresh rotation with replay detection; argon2id for passwords and API-key secrets; MFA fail-closed behaviour; RADIUS Message-Authenticator mandatory; LDAP empty-password refusal; a mechanical anonymous route walk; unknown permission strings rejected at import; production boot guards for debug, bootstrap password, plain HTTP and derived encryption key; vault credential files refused when world-readable; systemd and container hardening; digest-pinned images; signed releases. These are documented with sources in the [security architecture](security-architecture.md).
