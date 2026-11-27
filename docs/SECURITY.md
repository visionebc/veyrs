---
title: Security
purpose: Summarise VEYRS's security principles, controls and known gaps, and say how to report a vulnerability.
scope: Overview of authentication, authorization, transport, secrets, audit, supply chain and test coverage at 0.39.1; the detailed, line-referenced treatment is in the security section.
version: 0.39.1
verified: 2026-11-17
status: Partial
sources: [backend/veyrs/security/auth.py, backend/veyrs/security/deps.py, backend/veyrs/security/permissions.py, backend/veyrs/security/ratelimit.py, backend/veyrs/security/secrets.py, backend/veyrs/security/secret_vault.py, backend/veyrs/config.py, backend/veyrs/main.py, backend/veyrs/observability.py, backend/veyrs/api/v1/auth.py, backend/veyrs/services/audit.py, scripts/publish-github.sh, release/allowed_signers]
related: [security/security-architecture.md, security/authentication.md, security/authorization.md, security/risk-register.md, security/hardening.md, THREAT_MODEL.md, AI_SECURITY.md]
---

# Security

Security architecture, controls and reporting for VEYRS 0.39.1. This page is the overview; every control with its source line and verification status is in [Security architecture](security/security-architecture.md), and what is known to be weak is in the [risk register](security/risk-register.md).

## Reporting a vulnerability

Email the maintainers. Do not open a public issue. Include a proof of concept
and the affected version. We aim to acknowledge within two business days.

## Principles

- **Server-side authorization, always.** Nothing is enforced only in the UI.
  `tests/test_phase10_hardening.py::test_every_route_is_protected` walks the live
  application and fails the build if a new route forgets.
- **Defence in depth.** Tenant isolation is PostgreSQL RLS plus per-query
  `organization_id` filters, so one missing filter is caught by the database —
  provided the application role is not a superuser or `BYPASSRLS` (see
  [Authorization](security/authorization.md#4-tenant-isolation-as-a-security-control)).
- **Least privilege.** Ten role presets mapped to operational personas, not to
  generic admin/editor/viewer tiers.
- **Fail closed on authorization, fail open on availability controls.** A
  permission check that cannot be evaluated denies. A rate limiter whose backing
  store is down allows — it must not become the outage it was meant to prevent.

## Authentication

| Control | Implementation |
|---|---|
| Password hashing | Argon2id (`argon2-cffi`), per-password salt |
| Minimum length | 12 characters, configurable upward |
| Sign-in methods | Local password, then LDAP/AD, then RADIUS (Message-Authenticator mandatory); OIDC single sign-on with PKCE S256, `state` and `nonce`. Platform administrators are never delegated to a directory or SSO. See [Authentication](security/authentication.md) |
| Tokens | JWT HS256/384/512, default 30-minute access (`VEYRS_ACCESS_TOKEN_MINUTES`; the `.env` written by `install.sh` sets 60), 14-day refresh (`VEYRS_REFRESH_TOKEN_DAYS`) |
| Refresh rotation | Every use issues a new token and revokes the old one; refresh tokens are stored as SHA-256 |
| Reuse detection | A revoked refresh token presented again revokes every active refresh token of the same family. Each sign-in is its own family, so a replay ends that session, not the person's other devices. Refresh is refused for locked users and disabled organizations |
| Access-token revocation | Logout, password change, `veyrs mfa-reset`, deactivation and deletion bump the account's token version; every older access token is refused from the next request (no denylist: the user row is read anyway) |
| API keys | `veyrs_<prefix>_<secret>`; only the Argon2id hash of the secret is stored; the prefix is the lookup; scopes cannot exceed the creator's permissions |
| Agent tokens | `veyrsagent_<prefix>_<secret>` in `X-Agent-Token`; Argon2id hash; no permission set, reach `/agents/self/*` only |
| MFA | TOTP (RFC 6238, standard library, `security/mfa.py`), e-mail and Telegram codes, ten single-use recovery codes (`security/mfa_delivery.py`) — opt-in per user, or required per organization (`PUT /api/v1/mfa-policy`): an account without a factor then signs in into enrolment only |
| Lockout | Per source (account + address): 5 free failures, then 30 s doubling to 15 min between attempts. Per account: only failures spread over several addresses lock it (1 min doubling to 1 h), except from `VEYRS_LOCKOUT_EXEMPT_NETWORKS`. Password and MFA share the budget, as do the password checks of `/auth/password` and the MFA management routes; every attempt is recorded in `auth_events`. `veyrs unlock` lifts a lock |

Permissions are re-read from the database per request. A revoked role takes
effect on the next call, not at token expiry.

## Authorization

`resource:action` (29 resources x 4 actions = 116 permissions), validated at
import time. A route decorated with a permission string that does not exist
raises on startup — a typo cannot fail open. Roles are additive (no deny rules).

Cross-tenant object access returns **404**, not 403: confirming that an object
exists in another tenant is itself a disclosure.

Tenant isolation is PostgreSQL row level security (`FORCE ROW LEVEL SECURITY`,
73 tables) plus per-query `organization_id` filters. The second is a coding
convention, so the application's database role must never be a superuser or
have `BYPASSRLS`; the production API refuses to start under such a role, and a
debug-mode hook flags tenant-table queries run with no tenant bound
(`security/tenant_guard.py`). Team scope narrows
assets, findings and tickets inside a tenant, and global search honours it
(fixed in 0.41.0, risk R-03). Details: [Authorization](security/authorization.md).

## Transport and headers

TLS terminates at a reverse proxy in front of the node. The shipped vhost
(`infrastructure/nginx-veyrs-console.conf`) listens on plain HTTP port 80, and
the container console on 8080; put a TLS-terminating proxy (TLS 1.2/1.3) in
front of either. The application binds `127.0.0.1` only.

Every API response carries (`observability.SECURITY_HEADERS`, observed on a
running node):

```
Strict-Transport-Security   X-Content-Type-Options: nosniff
X-Frame-Options: DENY       Referrer-Policy: no-referrer
Content-Security-Policy     Permissions-Policy
Cross-Origin-Opener-Policy  Cross-Origin-Resource-Policy
```

The console vhost adds the same set; a location that defines its own
`add_header` (`/static/`, the health-check location) does not inherit it
(risk R-27).

CORS is an explicit origin allow-list, never `*`.

## Rate limiting

Two tiers (`security/ratelimit.py`):

- `/auth/login`, `/auth/refresh`, `/auth/mfa*`, `/auth/password*` — strict
  per-source-IP budget (default 10/min). Keyed on IP, not on
  the submitted email, or an attacker rotates the email field and never hits it.
  Raise `VEYRS_AUTH_RATE_LIMIT_PER_MINUTE` for offices behind one NAT address.
- everything else — per credential (bearer digest or API key prefix), default
  240/min.

The caller's address is `request.client.host`, and the application never reads
`X-Forwarded-For` itself: uvicorn resolves the address through its trusted-proxy
list (`VEYRS_FORWARDED_ALLOW_IPS`, default `127.0.0.1`), so it is the nearest
untrusted hop. The header's first entry is whatever the caller sent, so reading
it would let any caller mint a fresh identity per request. Behind a second proxy
list both proxies in `VEYRS_FORWARDED_ALLOW_IPS`.

For the general tier the bucket key is a VERIFIED identity: the subject of a
bearer token whose signature and expiry check out, or an API key that this
worker has already verified. Anything else (no credential, junk, a key not yet
verified) is keyed by the client address, so rotating junk credentials buys
nothing; the auth tier is keyed by IP.

Redis-backed in production. If Redis is unreachable, a worker uses an
in-process window and asks Redis again every 30 seconds; the fallback is
per-worker, so with N workers it permits roughly N × the configured rate while
it lasts — stated here rather than being quietly wrong. A Redis error is
counted in the in-process window and logged; it never fails the request.

## Input handling

- **SQL injection** — SQLAlchemy parameter binding throughout. The natural-language
  search path never produces SQL: the model emits JSON against a closed grammar,
  and VEYRS compiles the query itself.
- **XXE** — every XML path (document ingestion, Nessus/Qualys/Greenbone imports)
  parses with entity declarations refused. Uploaded scanner exports are
  attacker-influenced input.
- **XSS** — the API returns JSON; the docs site escapes all rendered content.
- **SSRF** — outbound calls go only to administrator-configured base URLs (AI
  providers, ITSM connectors, scanners, CMDB sources, feeds), never to a URL taken
  from an ordinary request. Since 0.41.0 every connector call goes through one
  guard (`services/net_guard.py`, risk R-09): the host is resolved and every
  address checked. Link-local and cloud-metadata addresses (169.254.0.0/16,
  `fd00:ec2::254`, Alibaba Cloud's metadata address), the unspecified address, multicast and
  reserved ranges are always refused; loopback only with
  `VEYRS_OUTBOUND_ALLOW_LOOPBACK=true`; private ranges are allowed by default
  because on-premise installations reach NetBox or Jira on the LAN, and refused
  with `VEYRS_OUTBOUND_ALLOW_PRIVATE=false`. Redirects are not followed. The
  check runs before the request, so DNS rebinding is not covered. The same
  helper covers asset sources, ITSM and Confluence connectors, scanners and AI
  providers; the e-mail relay and Telegram endpoints are operator settings, not
  tenant settings, and are not checked. Execution-agent targets keep their own
  reserved-address check.
- **Upload limits** — nginx refuses bodies over 128 MB
  (`client_max_body_size`) before they reach the API. The API then enforces
  32 MB for documents, 128 MB for scanner exports, 64 MB for CMDB exports and
  agent results, 8 MB for compliance imports and 1 MB for inbound ITSM
  webhooks.
- **Zip/XML bombs** — extraction is bounded by size and character count.

## Secrets

| Secret | Storage |
|---|---|
| User passwords | Argon2id hash, irreversible |
| API keys | Argon2id hash of the secret + public prefix (refresh tokens and MFA recovery codes are SHA-256) |
| Third-party credentials | Fernet, `v1:` prefixed, `security/secrets.py` — or an external vault (`VEYRS_SECRET_BACKEND`, below) |
| Session signing key | `VEYRS_SECRET_KEY`, ≥32 chars. Unset, each process generates a random key (sessions do not survive a restart or cross workers); `assert_production_safe()` does not check it, only the container entrypoint refuses an empty one — always set it |
| Data key | `VEYRS_ENCRYPTION_KEY`, generated by `veyrs keygen` |

`assert_production_safe()` refuses to boot production with a derived encryption
key, the bootstrap database password, plain HTTP, or debug on. A derived key is
tied to `SECRET_KEY`, so rotating the session secret would silently orphan every
stored third-party credential.

`VEYRS_ENCRYPTION_KEY` can be rotated without losing a credential:
`VEYRS_ENCRYPTION_KEY_PREVIOUS` holds earlier keys that decrypt but never
encrypt, and `veyrs secrets rekey --apply` re-seals every local copy under the
current key. Procedure: [DISASTER_RECOVERY.md §Planned key rotation](DISASTER_RECOVERY.md#planned-key-rotation-the-old-key-is-known).

Credential values are not returned by the read APIs; the only responses that
carry a secret are the one-time ones (a new API key, a TOTP enrolment secret,
recovery codes), shown once at creation.

### Secrets at rest

VEYRS has to replay third-party credentials, so they are reversibly protected,
never hashed. The complete list is the registry
`services/secret_storage.COLUMNS` (a test fails if a new `*_enc` column is not
in it):

| Where | What |
|---|---|
| `ai_providers.api_key_enc` | AI provider API keys |
| `itsm_connectors.credentials_enc` | ITSM / documentation connector credentials (ServiceNow, Jira, Confluence, webhook) |
| `itsm_connectors.inbound_secret_enc` | HMAC secret for inbound ITSM webhooks |
| `scanner_connectors.credentials_enc` | Scanner API credentials |
| `asset_sources.credentials_enc` | CMDB / NetBox / inventory source credentials |
| `threat_sources.credentials_enc` | Intelligence source credentials |
| `webhook_endpoints.secret_enc` | Outbound webhook signing secrets (column only: no route or service writes `webhook_endpoints`; outbound webhooks are Partial) |
| `users.mfa_secret` | TOTP shared secrets |
| `organizations.settings.ldap.bind_password_enc` | LDAP / AD service-account password |

`VEYRS_SECRET_BACKEND` decides where they live:

| Mode | Stored value | Where the credential is | Exposed to whoever reads this host's disk? |
|---|---|---|---|
| `local` (default) | `v1:<fernet>` | Database, encrypted with `VEYRS_ENCRYPTION_KEY` from `.env` on the same host | **Yes** — key and ciphertext sit side by side |
| `mirror` | `vm1:<uuid>:<fernet>` | External vault **and** the database copy | **Yes** — the local copy is still there. A migration step, not a control |
| `vault` | `vault:<uuid>` | External vault only (HashiCorp Vault / OpenBao, KV v2) | **No** for the credentials. The AppRole secret-id file is on the host, so a full host compromise can still log in to the vault *while the role is valid* — bound the role with CIDR and TTL limits, and revoke it to cut access off |

Properties held by the code and asserted by `tests/test_phase48_secret_vault.py`:

* `decrypt()` follows the stored prefix, not the current mode: a `vault:` row
  stays readable after the mode is switched back to `local`, as long as the
  vault settings are present (and says which settings are missing otherwise).
* In `vault` mode a credential that cannot be read **raises** (`SecretError`,
  surfaced by the API as `503 secret_storage_unavailable` with a generic
  message). It is never returned as empty: an empty password sent to a
  directory or an ITSM locks the service account out. LDAP refuses to bind with
  a stored password it cannot read; MFA refuses the login (fail closed).
* In `vault` mode a write the vault refuses raises instead of quietly keeping
  the credential on the host. `mirror` degrades to a local-only copy with a
  warning, which `veyrs secrets status` then counts as `local`.
* Only the vault token is cached; every credential read is a vault read, so the
  vault audit log is complete.
* The vault's own configuration is environment-only (never in the database the
  vault is protecting), and the secret-id / token are read from files, not from
  environment variables (`/proc/<pid>/environ`, `docker inspect`). A
  world-readable credential file is refused.
* The status endpoint `GET /api/v1/secret-storage` (`settings:admin`, refused to
  team-scoped identities) names the vault address and counts, never a token, a
  secret-id or a value. There is no web endpoint that migrates: that is
  `veyrs secrets migrate` on the host.

**Availability trade-off.** In `vault` mode the vault becomes a dependency of
every feature that needs a credential, including MFA sign-ins and LDAP
sign-ins. Plan the vault's availability (or keep a local break-glass
administrator without MFA-in-vault) accordingly.

## Audit

Three logs that the application only appends to, because they answer three
different questions:

- `audit_log` — who changed which business object (ITIL/ISO evidence)
- `auth_events` — authentication outcomes (SOC use). Read with
  `GET /api/v1/auth-events` (`audit:read`), isolated per organization by its own
  row policies
- `ai_audit_log` — every AI call: provider, model, classification, decision

"Append-only" is enforced in the database: a trigger refuses `UPDATE`, `DELETE`
and `TRUNCATE` on the three logs except retention deletes run under
`SET LOCAL veyrs.audit_prune = 'on'` and foreign-key cascades. The application
role still owns the tables, so it could disable the trigger; a non-owner role
is not shipped (risk R-05, [hardening](security/hardening.md)). Audit writes never raise into the request: a failed write is logged
at ERROR and the request proceeds, and a client `X-Correlation-ID` is kept only if
it is at most 64 characters of `[A-Za-z0-9._:-]` (longer values are truncated,
anything else is replaced by a UUID), so it can no longer make the write fail
(risk R-04, fixed in 0.41.0).

Report exports are audited as egress. A blocked AI call is audited too: a block
that leaves no trace is indistinguishable from a call that never happened.

## Build and supply chain

The documentation site generator is under 300 lines of standard library with **zero
third-party dependencies**, on purpose: the public host of a security product
should not drag in an npm or pip dependency tree that then needs auditing.

Backend dependencies are pinned to exact versions (`requirements.txt`,
regenerated by `scripts/freeze-deps.sh`, never hand-edited) but without hashes.
The repository ships no CI pipeline, no SBOM and no dependency or secret
scanner; the test suite runs through `scripts/test.sh` (risk R-21). On
2026-11-17 an OSV lookup of the 54 pins found advisories in 10 packages,
including `pypdf`, `python-multipart` and `starlette`
([risk R-01](security/risk-register.md#r-01-dependency-vulnerabilities-high-p1)).

### Release signing

A `.sha256` downloaded from the same place as its asset proves **integrity**,
not **origin**: whoever can replace the asset can replace its checksum. From
0.33.0 each GitHub release therefore also carries:

| Asset | What it is |
|---|---|
| `SHA256SUMS` | the SHA-256 of every other asset of the release |
| `SHA256SUMS.sig` | an OpenSSH signature over `SHA256SUMS` (`ssh-keygen -Y sign`, namespace `veyrs-release`, principal `release@veyrs`, ed25519) |

The public key is `release/allowed_signers` in the repository. No new tool is
involved: `ssh-keygen` from OpenSSH 8.1+ ships on every supported distribution.

- **Publishing** (`scripts/publish-github.sh --release`) signs with the key named
  by `VEYRS_RELEASE_SIGNING_KEY` (a path; the file must not be readable by group
  or other), verifies the signature against `release/allowed_signers` before
  uploading anything, and **refuses to publish unsigned** unless `--unsigned` is
  given — which it then announces as an unsigned release.
- **Installing**: `veyrs-setup.sh` is downloaded on its own, so it carries an
  **embedded copy** of the key (a test fails if the copy and
  `release/allowed_signers` differ). It verifies the signature, then the
  tarball's hash from the signed list, before extracting. From 0.33.0 a missing
  or unverifiable signature is fatal unless `--allow-unsigned`; a present but
  wrong signature is always fatal. Older releases fall back to `.sha256`, with a
  warning.
- **Updating in place**: the root updater verifies with the key of the
  **installed** tree and refuses anything unsigned — there is no override.
- **No key, no trust**: if `release/allowed_signers` holds the marked
  placeholder, every consumer reports "cannot verify", never success. The
  0.39.1 tree contains a real public key. `scripts/verify-release.sh DIR` checks a
  directory of assets and exits 3 (unsigned), 4 (bad signature), 5 (hash
  mismatch) or 6 (cannot verify).

The offline image bundle (`veyrs-images-<v>-amd64.tar.gz`, attached by
`scripts/publish-images.sh`) is not yet covered by `SHA256SUMS`; it is checked
against its `.sha256` only.

### Self-update privilege split

The API process never updates itself. A platform administrator's "apply" is
audited (`software.update.requested`) and becomes one JSON file — a version and
who asked, nothing secret — in `/var/lib/veyrs/update-requests`, the only path
outside `var/` the sandboxed API may write. The root `veyrs-updater.service`
(started by `veyrs-updater.path`) does the verification, the pre-update backup
hook, the install and the health check, and parses nothing from the request but
a version string. The hook must be root-owned and not writable by group/other,
and may not live where the API can write. Git checkouts and containers are
refused outright.

## Test coverage of security properties

The security-relevant tests in `tests/` assert, among others:

- every route rejects anonymous callers (walked mechanically)
- a token from one tenant cannot read another's objects
- role permissions are enforced per route
- confidential data cannot reach an external AI provider under default policy
- secrets and PII are stripped before any provider sees the prompt
- prompt injection in ingested content blocks the call and is audited
- a hallucinated field, team or query operator is rejected, not executed
- XXE is refused in both document and scanner-import paths
- validation errors never echo submitted values
- production configuration guards actually raise

## Known gaps

Stated plainly rather than omitted. The full list with evidence and priorities is
the [risk register](security/risk-register.md); the ones that matter most:

1. **Known-vulnerable dependencies** are pinned (R-01), and the internal git
   history holds a plaintext administrator password and a database dump (R-02).
2. **MFA is opt-in unless an organization requires it** (`require_mfa`, since
   0.41.0); single sign-on relies on the provider's MFA (`require_mfa_amr`).
3. The audit tables are append-only against everything but their owner role
   (R-05). (Global search ignoring team scope, R-03, and over-long correlation
   ids suppressing audit rows, R-04, were fixed in 0.41.0.)
4. **The native API service runs as root** inside a systemd sandbox (R-06).
5. **SAML** is not implemented; OIDC, LDAP / Active Directory and RADIUS are.
6. **No external penetration test** has been performed against this build.
7. **Database failover is manual** — the application nodes are redundant, but
   promoting the PostgreSQL standby is an operator step and Redis is not
   replicated (see [High availability](HIGH_AVAILABILITY.md)). The in-process
   rate-limit fallback applies if Redis is absent.
