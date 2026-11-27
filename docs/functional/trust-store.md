---
title: TLS trust store
purpose: Document the installation trust store - the certificate authorities VEYRS accepts when it connects out - and how every outbound client uses it.
scope: backend/veyrs/services/trust_store.py, backend/veyrs/api/v1/trust_store.py, backend/veyrs/models/trust.py and the outbound clients that read them. The certificate VEYRS itself presents to browsers is not covered here.
version: 0.40.0
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/services/trust_store.py, backend/veyrs/api/v1/trust_store.py, backend/veyrs/models/trust.py, tests/test_trust_store.py]
related: [functional/administration-platform.md, functional/updates.md, functional/integrations.md, functional/cmdb-asset-sources.md, security/security-architecture.md]
---

# TLS trust store

Console: Configure → Platform → **Trust store** (`#/admin?tab=truststore`).

## Why it exists

Enterprise estates sign internal services (CMDB, ITSM, scanners, directory, identity provider, mail relay, vault) with their own certificate authority. Before 0.40.0 every outbound client in VEYRS verified against the public roots only, so a connector pointing at an internal service had two options: verification on (fails with "unable to get local issuer certificate") or verification off. The trust store is where the company root goes.

## Rules

- **Added to the public roots, never substituted.** The verification context is the system store + certifi + the enabled private CAs. With no private CA, httpx keeps its own default (`verify=True`).
- **Never downgrades to no verification.** If the table cannot be read, clients fall back to the public roots: internal endpoints fail visibly, nothing is silently unverified.
- **A connector's own "verify TLS: off" stays off.** The store only changes what *verified* connections accept.
- **CA certificates only.** A certificate without `basicConstraints CA:TRUE` is rejected with the reason; a server's self-signed leaf has no CA to trust.
- **Installation-wide.** Table `trusted_cas` is in `GLOBAL_TABLES` (no `organization_id`, no RLS): TLS verification is process-wide. Only platform administrators (`is_superuser`, user tokens) can read or change it.
- **Database is the source of truth; nothing is written to disk.** Each API node builds its context in memory and re-reads the enabled set every 30 seconds, so a change made through one node reaches the other on its own, and the standby database carries the store.

## Clients that use it

| Client | Module |
|---|---|
| Asset sources (CMDB, NetBox) | `services/cmdb.py` |
| Scanner connectors | `services/scanners.py` |
| ITSM (Jira, ServiceNow…) and Confluence | `services/itsm.py` (`services/docs.py` reuses its transport) |
| Directory (LDAPS / StartTLS) | `services/ldap_auth.py` (`ca_certs_data`) |
| Single sign-on (OIDC discovery, token exchange) | `services/oidc_auth.py` |
| SMTP STARTTLS (notifications, e-mail 2FA) | `services/notifications.py`, `security/mfa_delivery.py` |
| Telegram 2FA | `security/mfa_delivery.py` |
| AI providers | `services/ai/providers.py` |
| Secret vault (when `VEYRS_VAULT_CA_FILE` is not set) | `security/secret_vault.py` |
| Update check | `services/updates.py` |
| Intelligence feeds | `intel/feeds.py` |

`tests/test_trust_store.py::test_every_module_that_opens_outbound_tls_goes_through_the_trust_store` fails if a module imports `httpx`, `smtplib` or `ldap3` without referencing the trust store. The scan agent is a separate program and keeps its own TLS configuration.

## API

All under `/api/v1/admin/trust-store`, platform administrators only, every change audited.

| Method and path | What |
|---|---|
| `GET /admin/trust-store` | CAs, summary (roots, intermediates, expired, expiring within 30 days), chain gaps, number of public roots |
| `POST /admin/trust-store` | Import `{pem, name?, note?}`: one certificate or a chain. 201 with `imported`, `updated`, `rejected`; 422 when nothing was a CA. Audit `trust_store.import` |
| `GET /admin/trust-store/{id}` | Decoded content (subject, issuer, validity, key, SHA-256, extensions, PEM) |
| `PATCH /admin/trust-store/{id}` | `is_enabled`, `name`, `note`. Audit `trust_store.update` |
| `DELETE /admin/trust-store/{id}` | Remove. Audit `trust_store.delete` |
| `POST /admin/trust-store/probe` | `{host, port}`: TLS handshake from the API node against the current store; returns the presented certificate, `chain_ok`, `hostname_ok`, `verified`, a `reason` and an `advice`. Audit `trust_store.probe` |

## Diagnosis

"Test a server" checks the chain with host-name checking off and on; together they name the fix:

| Outcome | Meaning | Fix |
|---|---|---|
| chain and name verify | nothing to do | keep verification on |
| chain trusted, name wrong | the certificate does not cover the address the connector uses | use a name from its SAN, or re-issue with that name |
| issuer not trusted | the CA that signed it is not in the store | import that CA (and any intermediate above it) |
| self-signed | the server is its own issuer | re-issue from your CA, or keep verification off for that connector |
| expired | the server certificate lapsed | re-issue; trusting a CA cannot rescue it |

An enabled intermediate whose issuer is neither in the store nor a public root is shown as an **incomplete chain**: it imports cleanly but every handshake through it fails.
