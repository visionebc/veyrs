---
title: API reference: administration
purpose: Every HTTP endpoint tagged `administration`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: administration

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


65 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `GET` | [`/api/v1/admin/system/network`](#get-apiv1adminsystemnetwork) | Every network destination VEYRS needs, and why | Platform admin | - |
| `GET` | [`/api/v1/admin/system/software`](#get-apiv1adminsystemsoftware) | OS components and Python packages installed on this node | Platform admin | - |
| `GET` | [`/api/v1/admin/trust-store`](#get-apiv1admintrust-store) | Trusted certificate authorities, health and chain gaps | Platform admin | - |
| `POST` | [`/api/v1/admin/trust-store`](#post-apiv1admintrust-store) | Import a CA certificate or chain (PEM) | Platform admin | - |
| `POST` | [`/api/v1/admin/trust-store/probe`](#post-apiv1admintrust-storeprobe) | Test a server's certificate against the current trust store | Platform admin | - |
| `DELETE` | [`/api/v1/admin/trust-store/{ca_id}`](#delete-apiv1admintrust-storeca_id) | Remove a CA from the trust store | Platform admin | - |
| `GET` | [`/api/v1/admin/trust-store/{ca_id}`](#get-apiv1admintrust-storeca_id) | Decoded content of one trusted CA | Platform admin | - |
| `PATCH` | [`/api/v1/admin/trust-store/{ca_id}`](#patch-apiv1admintrust-storeca_id) | Enable, disable, rename or annotate a trusted CA | Platform admin | - |
| `GET` | [`/api/v1/admin/updates`](#get-apiv1adminupdates) | Installed version, latest release and updater history | Platform admin | - |
| `POST` | [`/api/v1/admin/updates/apply`](#post-apiv1adminupdatesapply) | Queue the latest signed release for the root updater (native installs) | Platform admin | - |
| `POST` | [`/api/v1/admin/updates/uploads`](#post-apiv1adminupdatesuploads) | Start uploading a release | Platform admin | - |
| `POST` | [`/api/v1/admin/updates/uploads/{upload_id}/finish`](#post-apiv1adminupdatesuploadsupload_idfinish) | Finish an upload: stage it under its version | Platform admin | - |
| `PUT` | [`/api/v1/admin/updates/uploads/{upload_id}/{name}`](#put-apiv1adminupdatesuploadsupload_idname) | Append one chunk of a release file | Platform admin | - |
| `DELETE` | [`/api/v1/admin/updates/uploads/{version}`](#delete-apiv1adminupdatesuploadsversion) | Delete an uploaded release copy | Platform admin | - |
| `GET` | [`/api/v1/admin/web-certificate`](#get-apiv1adminweb-certificate) | Served certificate, requests, history and what each node serves | Platform admin | - |
| `POST` | [`/api/v1/admin/web-certificate/certificate`](#post-apiv1adminweb-certificatecertificate) | Attach the certificate the CA signed to its pending request | Platform admin | - |
| `POST` | [`/api/v1/admin/web-certificate/import`](#post-apiv1adminweb-certificateimport) | Import a certificate AND its private key issued elsewhere (PEM or PKCS#12) | Platform admin | - |
| `PUT` | [`/api/v1/admin/web-certificate/policy`](#put-apiv1adminweb-certificatepolicy) | Redirect plain HTTP to HTTPS on the app nodes | Platform admin | - |
| `POST` | [`/api/v1/admin/web-certificate/requests`](#post-apiv1adminweb-certificaterequests) | Generate a private key here and a certificate signing request (CSR) | Platform admin | - |
| `POST` | [`/api/v1/admin/web-certificate/uninstall`](#post-apiv1adminweb-certificateuninstall) | Stop serving HTTPS from the app nodes | Platform admin | - |
| `DELETE` | [`/api/v1/admin/web-certificate/{cert_id}`](#delete-apiv1adminweb-certificatecert_id) | Discard a request or certificate (its key is destroyed) | Platform admin | - |
| `GET` | [`/api/v1/admin/web-certificate/{cert_id}/csr`](#get-apiv1adminweb-certificatecert_idcsr) | Download the CSR (PEM) to take to the CA | Platform admin | - |
| `POST` | [`/api/v1/admin/web-certificate/{cert_id}/install`](#post-apiv1adminweb-certificatecert_idinstall) | Serve this certificate on every app node | Platform admin | - |
| `GET` | [`/api/v1/api-keys`](#get-apiv1api-keys) | List API keys | Authenticated | `apikey:read` |
| `POST` | [`/api/v1/api-keys`](#post-apiv1api-keys) | Issue an API key (secret shown once) | Authenticated | `apikey:write` |
| `DELETE` | [`/api/v1/api-keys/{key_id}`](#delete-apiv1api-keyskey_id) | Revoke an API key | Authenticated | `apikey:delete` |
| `GET` | [`/api/v1/audit`](#get-apiv1audit) | Query the audit trail | Authenticated | `audit:read` |
| `GET` | [`/api/v1/auth-events`](#get-apiv1auth-events) | Sign-in and session events (the SOC log) | Authenticated | `audit:read` |
| `GET` | [`/api/v1/departments`](#get-apiv1departments) | List departments | Authenticated | `team:read` |
| `POST` | [`/api/v1/departments`](#post-apiv1departments) | Create a department | Authenticated | `team:write` |
| `GET` | [`/api/v1/ldap`](#get-apiv1ldap) | Directory authentication settings | Authenticated | `settings:admin` |
| `PUT` | [`/api/v1/ldap`](#put-apiv1ldap) | Configure directory authentication | Authenticated | `settings:admin` |
| `POST` | [`/api/v1/ldap/test`](#post-apiv1ldaptest) | Test the directory connection | Authenticated | `settings:admin` |
| `GET` | [`/api/v1/mfa-policy`](#get-apiv1mfa-policy) | Does this organization require a second factor? | Authenticated | `settings:read` |
| `PUT` | [`/api/v1/mfa-policy`](#put-apiv1mfa-policy) | Require (or stop requiring) a second factor for everyone | Authenticated | `settings:admin` |
| `GET` | [`/api/v1/oidc`](#get-apiv1oidc) | Single sign-on (OIDC) settings | Authenticated | `settings:admin` |
| `PUT` | [`/api/v1/oidc`](#put-apiv1oidc) | Configure single sign-on (OIDC) | Authenticated | `settings:admin` |
| `POST` | [`/api/v1/oidc/test`](#post-apiv1oidctest) | Check the saved identity provider (discovery, keys, PKCE) | Authenticated | `settings:admin` |
| `GET` | [`/api/v1/organization`](#get-apiv1organization) | Own organization | Authenticated | `organization:read` |
| `PATCH` | [`/api/v1/organization`](#patch-apiv1organization) | Update own organization | Authenticated | `organization:write` |
| `GET` | [`/api/v1/permissions`](#get-apiv1permissions) | Every assignable permission | Authenticated | `role:read` |
| `GET` | [`/api/v1/radius`](#get-apiv1radius) | RADIUS authentication settings | Authenticated | `settings:admin` |
| `PUT` | [`/api/v1/radius`](#put-apiv1radius) | Configure RADIUS authentication | Authenticated | `settings:admin` |
| `POST` | [`/api/v1/radius/test`](#post-apiv1radiustest) | Test RADIUS with a test account (real exchange) | Authenticated | `settings:admin` |
| `GET` | [`/api/v1/risk-register`](#get-apiv1risk-register) | Does this organization keep a risk register? | Authenticated | `settings:read` |
| `PUT` | [`/api/v1/risk-register`](#put-apiv1risk-register) | Turn the risk register on or off | Authenticated | `settings:admin` |
| `GET` | [`/api/v1/roles`](#get-apiv1roles) | List roles (built-in + tenant) | Authenticated | `role:read` |
| `POST` | [`/api/v1/roles`](#post-apiv1roles) | Create a custom role | Authenticated | `role:admin` |
| `PATCH` | [`/api/v1/roles/{role_id}`](#patch-apiv1rolesrole_id) | Update a custom role | Authenticated | `role:admin` |
| `GET` | [`/api/v1/scanning`](#get-apiv1scanning) | Is VEYRS allowed to run scans itself? | Authenticated | `settings:read` |
| `PUT` | [`/api/v1/scanning`](#put-apiv1scanning) | Turn active scanning on or off | Authenticated | `settings:admin` |
| `GET` | [`/api/v1/secret-storage`](#get-apiv1secret-storage) | Where stored credentials live (read-only) | Authenticated | `settings:admin` |
| `GET` | [`/api/v1/teams`](#get-apiv1teams) | List teams | Authenticated | `team:read` |
| `POST` | [`/api/v1/teams`](#post-apiv1teams) | Create a team | Authenticated | `team:write` |
| `PATCH` | [`/api/v1/teams/{team_id}`](#patch-apiv1teamsteam_id) | Update a team | Authenticated | `team:write` |
| `DELETE` | [`/api/v1/teams/{team_id}/members/{user_id}`](#delete-apiv1teamsteam_idmembersuser_id) | Remove a team member | Authenticated | `team:write` |
| `POST` | [`/api/v1/teams/{team_id}/members/{user_id}`](#post-apiv1teamsteam_idmembersuser_id) | Add a team member | Authenticated | `team:write` |
| `GET` | [`/api/v1/ticketing`](#get-apiv1ticketing) | Which system owns remediation work | Authenticated | `settings:read` |
| `PUT` | [`/api/v1/ticketing`](#put-apiv1ticketing) | Choose the internal queue or an external ITSM | Authenticated | `settings:admin` |
| `GET` | [`/api/v1/users`](#get-apiv1users) | List users | Authenticated | `user:read` |
| `POST` | [`/api/v1/users`](#post-apiv1users) | Create a user | Authenticated | `user:write` |
| `DELETE` | [`/api/v1/users/{user_id}`](#delete-apiv1usersuser_id) | Deactivate a user (soft delete) | Authenticated | `user:delete` |
| `GET` | [`/api/v1/users/{user_id}`](#get-apiv1usersuser_id) | Get a user | Authenticated | `user:read` |
| `PATCH` | [`/api/v1/users/{user_id}`](#patch-apiv1usersuser_id) | Update a user | Authenticated | `user:write` |
| `PUT` | [`/api/v1/users/{user_id}/scope`](#put-apiv1usersuser_idscope) | Narrow a user's grants to teams | Authenticated | `role:admin` |

## GET /api/v1/admin/system/network

**Every network destination VEYRS needs, and why**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/system.py:33` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/admin/system/software

**OS components and Python packages installed on this node**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/system.py:21` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `refresh` | query | boolean | no | default `false` | bypass the one-minute cache |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/admin/trust-store

**Trusted certificate authorities, health and chain gaps**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/trust_store.py:53` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/admin/trust-store

**Import a CA certificate or chain (PEM)**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/trust_store.py:58` |

**Request body** (`application/json`, required): `TrustCaImport`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/admin/trust-store/probe

**Test a server's certificate against the current trust store**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/trust_store.py:135` |

**Request body** (`application/json`, required): `TrustProbe`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## DELETE /api/v1/admin/trust-store/{ca_id}

**Remove a CA from the trust store**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/trust_store.py:120` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `ca_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/admin/trust-store/{ca_id}

**Decoded content of one trusted CA**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/trust_store.py:86` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `ca_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## PATCH /api/v1/admin/trust-store/{ca_id}

**Enable, disable, rename or annotate a trusted CA**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/trust_store.py:92` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `ca_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `TrustCaUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/admin/updates

**Installed version, latest release and updater history**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/updates.py:51` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `refresh` | query | boolean | no | default `false` | bypass the one-hour cache |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/admin/updates/apply

**Queue the latest signed release for the root updater (native installs)**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 202 |
| Handler | `backend/veyrs/api/v1/updates.py:61` |

**Request body** (`application/json`): `ApplyRequest` (nullable)

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `202` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/admin/updates/uploads

**Start uploading a release**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/updates.py:132` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/admin/updates/uploads/{upload_id}/finish

**Finish an upload: stage it under its version**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/updates.py:154` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `upload_id` | path | string | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## PUT /api/v1/admin/updates/uploads/{upload_id}/{name}

**Append one chunk of a release file**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/updates.py:137` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `upload_id` | path | string | yes |  |  |
| `name` | path | string | yes |  |  |
| `offset` | query | integer | yes | ≥ 0 |  |
| `total` | query | integer | yes | > 0 |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## DELETE /api/v1/admin/updates/uploads/{version}

**Delete an uploaded release copy**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/updates.py:174` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `version` | path | string | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/admin/web-certificate

**Served certificate, requests, history and what each node serves**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/web_tls.py:88` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/admin/web-certificate/certificate

**Attach the certificate the CA signed to its pending request**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/web_tls.py:124` |

**Request body** (`application/json`, required): `WebCertAttach`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/admin/web-certificate/import

**Import a certificate AND its private key issued elsewhere (PEM or PKCS#12)**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/web_tls.py:145` |

**Request body** (`application/json`, required): `WebCertImport`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## PUT /api/v1/admin/web-certificate/policy

**Redirect plain HTTP to HTTPS on the app nodes**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/web_tls.py:221` |

**Request body** (`application/json`, required): `WebCertPolicy`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/admin/web-certificate/requests

**Generate a private key here and a certificate signing request (CSR)**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/web_tls.py:93` |

**Request body** (`application/json`, required): `WebCertRequestCreate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/admin/web-certificate/uninstall

**Stop serving HTTPS from the app nodes**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/web_tls.py:189` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## DELETE /api/v1/admin/web-certificate/{cert_id}

**Discard a request or certificate (its key is destroyed)**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/web_tls.py:205` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `cert_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/admin/web-certificate/{cert_id}/csr

**Download the CSR (PEM) to take to the CA**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/web_tls.py:113` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `cert_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/admin/web-certificate/{cert_id}/install

**Serve this certificate on every app node**

| | |
|---|---|
| Authentication | Platform admin |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/web_tls.py:172` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `cert_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/api-keys

**List API keys**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `apikey:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:1031` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `ApiKeyOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/api-keys

**Issue an API key (secret shown once)**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `apikey:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/admin.py:1040` |

**Request body** (`application/json`, required): `ApiKeyCreate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `ApiKeyCreated` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/api-keys/{key_id}

**Revoke an API key**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `apikey:delete` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/admin.py:1077` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `key_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/audit

**Query the audit trail**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `audit:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:1093` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `limit` | query | integer | no | ≥ 1; ≤ 500; default `100` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |
| `action` | query | string (nullable) | no | max length 80 |  |
| `object_type` | query | string (nullable) | no | max length 80 |  |
| `object_id` | query | string (nullable) | no | max length 80 |  |
| `since` | query | string (date-time) (nullable) | no |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_AuditOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/auth-events

**Sign-in and session events (the SOC log)**

`auth_events`, newest first, for the caller's organization.

Row level security does the tenant filtering too (`schema_steps/step_auth`). Attempts that named nobody this installation knows belong to no tenant; only a platform administrator can list them, with `unattributed=true`.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `audit:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:1123` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `limit` | query | integer | no | ≥ 1; ≤ 500; default `100` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |
| `event` | query | string (nullable) | no | max length 60 |  |
| `success` | query | boolean (nullable) | no |  |  |
| `user_id` | query | string (uuid) (nullable) | no |  |  |
| `email` | query | string (nullable) | no | max length 255 |  |
| `ip` | query | string (nullable) | no | max length 64 |  |
| `reason` | query | string (nullable) | no | max length 160 |  |
| `since` | query | string (date-time) (nullable) | no |  |  |
| `until` | query | string (date-time) (nullable) | no |  |  |
| `unattributed` | query | boolean | no | default `false` | Platform administrators only: the attempts that named no known account (no organization). |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/departments

**List departments**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `team:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:934` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `DepartmentOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/departments

**Create a department**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `team:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/admin.py:943` |

**Request body** (`application/json`, required): `DepartmentCreate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `DepartmentOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/ldap

**Directory authentication settings**

`settings:admin`, and NOT read-open like `/scanning`.

The scanning switch is read-open because an operator staring at an empty queue has to be able to tell "nothing scheduled" from "this deployment does not scan". Nothing here is that: this payload names the directory host, the service-account DN, the search base and the exact group-to-role mapping -- a map of how to become an administrator, drawn for whoever asks. The password never leaves the process at all (`ldap_auth.state`).

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:334` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PUT /api/v1/ldap

**Configure directory authentication**

Same refusal as the scanning switch, for the same reason.

A team-scoped identity that could point this at a directory it controls would own every account in the tenant on the next login. This is the single most privileged write in the API and it takes an estate-wide grant.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:356` |

**Request body** (`application/json`, required): `LdapSettingsUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/ldap/test

**Test the directory connection**

Diagnose the CURRENTLY SAVED configuration, step by step.

It tests what is stored, not what is on screen, and that is deliberate: the thing an operator needs to know is whether the configuration the login path will actually use works. A test that ran against unsaved form values could pass and leave sign-in broken.

Never 500s on a bad directory. Unreachable, wrong service account, wrong base DN and wrong filter are four different fixes, so they are four different steps with their own outcome rather than one boolean.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:411` |

**Request body** (`application/json`, required): `LdapTestRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/mfa-policy

**Does this organization require a second factor?**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:158` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PUT /api/v1/mfa-policy

**Require (or stop requiring) a second factor for everyone**

Accounts without a factor are sent to enrolment at their next sign-in.

Never a lock-out: the password still opens the enrolment screen. Applies to platform administrators of this organization too.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:166` |

**Request body** (`application/json`, required): `MfaPolicyUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/oidc

**Single sign-on (OIDC) settings**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:441` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PUT /api/v1/oidc

**Configure single sign-on (OIDC)**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:451` |

**Request body** (`application/json`, required): `OidcSettingsUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/oidc/test

**Check the saved identity provider (discovery, keys, PKCE)**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:479` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/organization

**Own organization**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `organization:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:61` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `OrganizationOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/organization

**Update own organization**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `organization:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:70` |

**Request body** (`application/json`, required): `OrganizationUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `OrganizationOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/permissions

**Every assignable permission**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `role:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:975` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of string |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/radius

**RADIUS authentication settings**

Same rules as the directory: it decides who gets in, so it is not read-open.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:492` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PUT /api/v1/radius

**Configure RADIUS authentication**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:503` |

**Request body** (`application/json`, required): `RadiusSettingsUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/radius/test

**Test RADIUS with a test account (real exchange)**

Runs against the SAVED configuration. The password is used once, never stored or logged.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:531` |

**Request body** (`application/json`, required): `RadiusTestRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/risk-register

**Does this organization keep a risk register?**

Read-open, like `/scanning` and `/ticketing`.

The console needs this on every page load to decide whether the Risk Register section exists at all, so gating it on `settings:admin` would hide the menu from every non-admin -- which looks exactly like the bug the switch is supposed to make visible. It names no host, no account and no secret.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:268` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PUT /api/v1/risk-register

**Turn the risk register on or off**

Same refusal as the scanning and ticketing switches, for the same reason.

Nothing is deleted. Entries written before the flip stay readable and stay exportable -- a switch that tidied a menu by dropping the record of an accepted risk would be destroying the only evidence that it was ever accepted.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:283` |

**Request body** (`application/json`, required): `RiskRegisterUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/roles

**List roles (built-in + tenant)**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `role:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:964` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `RoleOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/roles

**Create a custom role**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `role:admin` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/admin.py:980` |

**Request body** (`application/json`, required): `RoleCreate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `RoleOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/roles/{role_id}

**Update a custom role**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `role:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:1003` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `role_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `RoleUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `RoleOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/scanning

**Is VEYRS allowed to run scans itself?**

Read-open on purpose.

An operator looking at an empty scan queue has to be able to tell "nothing is scheduled" from "this platform does not scan"; making that answer an admin secret is how the first one gets debugged for an afternoon.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:93` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PUT /api/v1/scanning

**Turn active scanning on or off**

`settings:admin`, and never a team-scoped grant.

The switch governs the whole estate: a team that could turn scanning off would silently stop the sweeps every other team's findings depend on. The refusal is the same one policy writes take in `policies` (phase 28).

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:109` |

**Request body** (`application/json`, required): `ScanningUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/secret-storage

**Where stored credentials live (read-only)**

Mode, vault health and this organization's credential counts.

`settings:admin` and estate-wide, like `/ldap`: the answer names the vault address and says how many credentials sit on the host. It never names the token, the secret-id or a value. There is deliberately no PUT: moving every tenant's credentials is `veyrs secrets migrate` on the host, by whoever holds the host and the vault policy -- not a button in one tenant's console.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:554` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/teams

**List teams**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `team:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:838` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `limit` | query | integer | no | ≥ 1; ≤ 500; default `100` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_TeamOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/teams

**Create a team**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `team:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/admin.py:862` |

**Request body** (`application/json`, required): `TeamCreate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `TeamOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/teams/{team_id}

**Update a team**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `team:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:880` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `team_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `TeamUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `TeamOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/teams/{team_id}/members/{user_id}

**Remove a team member**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `team:write` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/admin.py:918` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `team_id` | path | string (uuid) | yes |  |  |
| `user_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/teams/{team_id}/members/{user_id}

**Add a team member**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `team:write` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/admin.py:897` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `team_id` | path | string (uuid) | yes |  |  |
| `user_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/ticketing

**Which system owns remediation work**

Read-open, like `/scanning` and unlike `/ldap`.

The console needs this on EVERY page load to decide whether the Tickets section exists at all, so gating it on `settings:admin` would hide the menu from every non-admin -- which looks exactly like the bug this mode is supposed to fix. It is also safe to read: unlike the directory payload, it names no host, no service account and no secret. The connector's own credentials stay behind `ticket:admin` in `/integrations/connectors`.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:197` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PUT /api/v1/ticketing

**Choose the internal queue or an external ITSM**

Same refusal as the scanning switch, for the same reason.

Nothing is migrated or closed. Internal tickets that already exist stay open and stay transitionable -- see the table in `services/ticketing_mode`. A switch that tidied the menu by closing 40 tickets in flight would be destroying the record of work somebody is doing.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `settings:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:214` |

**Request body** (`application/json`, required): `TicketingUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/users

**List users**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `user:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:577` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `limit` | query | integer | no | ≥ 1; ≤ 500; default `50` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |
| `q` | query | string (nullable) | no | max length 120 |  |
| `active` | query | boolean (nullable) | no |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_UserOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/users

**Create a user**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `user:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/admin.py:605` |

**Request body** (`application/json`, required): `UserCreate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `UserOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/users/{user_id}

**Deactivate a user (soft delete)**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `user:delete` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/admin.py:815` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `user_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/users/{user_id}

**Get a user**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `user:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:750` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `user_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `UserOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/users/{user_id}

**Update a user**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `user:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:762` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `user_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `UserUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `UserOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PUT /api/v1/users/{user_id}/scope

**Narrow a user's grants to teams**

Re-point every one of the user's role grants at the given teams.

Needs `role:admin`, not `user:write`: clearing the list restores estate-wide visibility, which grants privilege rather than merely editing a profile.

A caller cannot narrow their own grants. Not paternalism -- an administrator who scopes themselves loses `role:admin` reach over the users outside that scope and cannot undo it, which turns a mistake into a support call.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `role:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/admin.py:703` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `user_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `UserScopeUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## Schemas

Request and response models used on this page.

#### `ApiKeyCreate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes | min length 2; max length 160 |  |
| `scopes` | array of string | no |  |  |
| `expires_in_days` | integer (nullable) | no | ≥ 1.0; ≤ 3650.0; default `365` |  |

#### `ApiKeyCreated`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `name` | string | yes |  |  |
| `prefix` | string | yes |  |  |
| `scopes` | array of string | yes |  |  |
| `expires_at` | string (date-time) (nullable) | yes |  |  |
| `last_used_at` | string (date-time) (nullable) | yes |  |  |
| `revoked_at` | string (date-time) (nullable) | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |
| `api_key` | string | yes |  | Shown exactly once. VEYRS stores only its hash. |

#### `ApiKeyOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `name` | string | yes |  |  |
| `prefix` | string | yes |  |  |
| `scopes` | array of string | yes |  |  |
| `expires_at` | string (date-time) (nullable) | yes |  |  |
| `last_used_at` | string (date-time) (nullable) | yes |  |  |
| `revoked_at` | string (date-time) (nullable) | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |

#### `ApplyRequest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `version` | string (nullable) | no | max length 32 |  |
| `source` | string enum | no | one of `release`, `upload`, `local`; default `"release"` |  |

#### `AuditOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |
| `actor_label` | string | yes |  |  |
| `action` | string | yes |  |  |
| `object_type` | string | yes |  |  |
| `object_id` | string (nullable) | yes |  |  |
| `object_label` | string (nullable) | yes |  |  |
| `changes` | object | yes |  |  |
| `correlation_id` | string (nullable) | yes |  |  |
| `ip_address` | string (nullable) | yes |  |  |

#### `DepartmentCreate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes | min length 2; max length 160 |  |
| `description` | string (nullable) | no |  |  |
| `manager_id` | string (uuid) (nullable) | no |  |  |

#### `DepartmentOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `name` | string | yes |  |  |
| `description` | string (nullable) | yes |  |  |
| `manager_id` | string (uuid) (nullable) | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `LdapSettingsUpdate`

Directory (LDAP / Active Directory) configuration for this tenant.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `enabled` | boolean (nullable) | no |  |  |
| `host` | string (nullable) | no | max length 255 |  |
| `port` | integer (nullable) | no | ≥ 1.0; ≤ 65535.0 |  |
| `use_ssl` | boolean (nullable) | no |  |  |
| `start_tls` | boolean (nullable) | no |  |  |
| `verify_certificate` | boolean (nullable) | no |  |  |
| `timeout_seconds` | integer (nullable) | no | ≥ 1.0; ≤ 60.0 |  |
| `bind_dn` | string (nullable) | no | max length 512 |  |
| `bind_password` | string (nullable) | no | max length 512 |  |
| `clear_bind_password` | boolean | no | default `false` |  |
| `base_dn` | string (nullable) | no | max length 512 |  |
| `user_filter` | string (nullable) | no | max length 1024 |  |
| `attr_username` | string (nullable) | no | max length 64 |  |
| `attr_email` | string (nullable) | no | max length 64 |  |
| `attr_full_name` | string (nullable) | no | max length 64 |  |
| `attr_member_of` | string (nullable) | no | max length 64 |  |
| `group_role_map` | object (nullable) | no |  |  |
| `jit_provisioning` | boolean (nullable) | no |  |  |
| `default_role_slugs` | array of string (nullable) | no |  |  |
| `sync_roles_on_login` | boolean (nullable) | no |  |  |

#### `LdapTestRequest`

Optionally name somebody to look up, to prove the filter finds them.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `sample_identifier` | string (nullable) | no | max length 320 |  |

#### `MfaPolicyUpdate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `require_mfa` | boolean | yes |  |  |

#### `OidcSettingsUpdate`

Single sign-on for this tenant. Absent keys are left alone.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `enabled` | boolean (nullable) | no |  |  |
| `issuer` | string (nullable) | no | max length 500 |  |
| `client_id` | string (nullable) | no | max length 255 |  |
| `redirect_uri` | string (nullable) | no | max length 500 |  |
| `scopes` | string (nullable) | no | max length 300 |  |
| `email_claim` | string (nullable) | no | max length 100 |  |
| `groups_claim` | string (nullable) | no | max length 100 |  |
| `group_role_map` | object (nullable) | no |  |  |
| `jit_provisioning` | boolean (nullable) | no |  |  |
| `require_mfa_amr` | boolean (nullable) | no |  |  |
| `button_label` | string (nullable) | no | max length 60 |  |
| `client_secret` | string (nullable) | no | min length 8; max length 500 |  |

#### `OrganizationOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `name` | string | yes |  |  |
| `slug` | string | yes |  |  |
| `invoicing_code` | string (nullable) | yes |  |  |
| `default_locale` | string | yes |  |  |
| `timezone` | string | yes |  |  |
| `is_active` | boolean | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |

#### `OrganizationUpdate`

Profile fields only.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string (nullable) | no | min length 2; max length 200 |  |
| `invoicing_code` | string (nullable) | no | max length 40 |  |
| `default_locale` | string (nullable) | no | pattern ^(en\|es\|de\|fr\|it)$ |  |
| `timezone` | string (nullable) | no |  |  |

#### `Page_AuditOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `AuditOut` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `Page_TeamOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `TeamOut` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `Page_UserOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `UserOut` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `RadiusSettingsUpdate`

RADIUS for this tenant. Absent keys are left alone (`exclude_unset`).

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `enabled` | boolean (nullable) | no |  |  |
| `servers` | array of string (nullable) | no | max items 4 |  |
| `timeout_seconds` | integer (nullable) | no | ≥ 1.0; ≤ 120.0 |  |
| `retries` | integer (nullable) | no | ≥ 0.0; ≤ 3.0 |  |
| `nas_identifier` | string (nullable) | no | max length 64 |  |
| `role_attribute` | string (nullable) | no | max length 20 |  |
| `value_role_map` | object (nullable) | no |  |  |
| `secret` | string (nullable) | no | min length 16; max length 128 |  |

#### `RadiusTestRequest`

A real exchange needs a real account: use a dedicated test account.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `user_name` | string | yes | min length 1; max length 253 |  |
| `password` | string | yes | min length 1; max length 128 |  |
| `code` | string (nullable) | no | max length 64 |  |

#### `RiskRegisterUpdate`

Turn this tenant's risk register on or off.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `risk_register_enabled` | boolean | yes |  |  |
| `reason` | string (nullable) | no |  |  |

#### `RoleCreate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes | min length 2; max length 120 |  |
| `slug` | string | yes | min length 2; max length 80; pattern ^[a-z0-9][a-z0-9-]*$ |  |
| `description` | string (nullable) | no |  |  |
| `permissions` | array of string | no |  |  |

#### `RoleOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `name` | string | yes |  |  |
| `slug` | string | yes |  |  |
| `description` | string (nullable) | yes |  |  |
| `is_builtin` | boolean | yes |  |  |
| `permissions` | array of string | yes |  |  |
| `organization_id` | string (uuid) (nullable) | yes |  |  |

#### `RoleUpdate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string (nullable) | no | min length 2; max length 120 |  |
| `description` | string (nullable) | no |  |  |
| `permissions` | array of string (nullable) | no |  |  |

#### `ScanningUpdate`

Turn this tenant's active scanning on or off.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `active_scanning_enabled` | boolean | yes |  |  |
| `reason` | string (nullable) | no |  |  |
| `cancel_queued_jobs` | boolean | no | default `true` |  |

#### `TeamCreate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes | min length 2; max length 160 |  |
| `slug` | string | yes | min length 2; max length 80; pattern ^[a-z0-9][a-z0-9-]*$ |  |
| `description` | string (nullable) | no |  |  |
| `email` | string (nullable) | no |  |  |
| `department_id` | string (uuid) (nullable) | no |  |  |
| `manager_id` | string (uuid) (nullable) | no |  |  |
| `escalation_chain` | object | no |  |  |

#### `TeamOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `name` | string | yes |  |  |
| `slug` | string | yes |  |  |
| `description` | string (nullable) | yes |  |  |
| `email` | string (nullable) | yes |  |  |
| `department_id` | string (uuid) (nullable) | yes |  |  |
| `manager_id` | string (uuid) (nullable) | yes |  |  |
| `escalation_chain` | object | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |
| `member_count` | integer | no | default `0` |  |

#### `TeamUpdate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string (nullable) | no | min length 2; max length 160 |  |
| `description` | string (nullable) | no |  |  |
| `email` | string (nullable) | no |  |  |
| `department_id` | string (uuid) (nullable) | no |  |  |
| `manager_id` | string (uuid) (nullable) | no |  |  |
| `escalation_chain` | object (nullable) | no |  |  |

#### `TicketingUpdate`

Choose which system owns remediation work for this tenant.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `mode` | string | yes |  |  |
| `connector_id` | string (uuid) (nullable) | no |  |  |
| `reason` | string (nullable) | no |  |  |

#### `TrustCaImport`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `pem` | string | yes | min length 1; max length 200000 |  |
| `name` | string (nullable) | no | max length 180 |  |
| `note` | string (nullable) | no | max length 500 |  |

#### `TrustCaUpdate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `is_enabled` | boolean (nullable) | no |  |  |
| `name` | string (nullable) | no | min length 1; max length 200 |  |
| `note` | string (nullable) | no | max length 500 |  |

#### `TrustProbe`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `host` | string | yes | min length 1; max length 253 |  |
| `port` | integer | no | ≥ 1.0; ≤ 65535.0; default `443` |  |

#### `UserCreate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `email` | string | yes |  |  |
| `username` | string (nullable) | no |  |  |
| `full_name` | string | yes | min length 2; max length 200 |  |
| `password` | string (nullable) | no | max length 512 |  |
| `job_title` | string (nullable) | no | max length 160 |  |
| `locale` | string | no | pattern ^(en\|es\|de\|fr\|it)$; default `"en"` |  |
| `role_slugs` | array of string | no |  |  |
| `team_ids` | array of string (uuid) | no |  |  |
| `scope_team_ids` | array of string (uuid) | no |  |  |

#### `UserOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `email` | string | yes |  |  |
| `username` | string (nullable) | no |  |  |
| `ldap_dn` | string (nullable) | no |  |  |
| `full_name` | string | yes |  |  |
| `job_title` | string (nullable) | yes |  |  |
| `locale` | string | yes |  |  |
| `is_active` | boolean | yes |  |  |
| `is_superuser` | boolean | yes |  |  |
| `mfa_enabled` | boolean | yes |  |  |
| `last_login_at` | string (date-time) (nullable) | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |
| `roles` | array of string | no |  |  |

#### `UserScopeUpdate`

Rewrite which teams a user's role grants are narrowed to.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `team_ids` | array of string (uuid) | no |  |  |

#### `UserUpdate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `full_name` | string (nullable) | no | min length 2; max length 200 |  |
| `username` | string (nullable) | no |  |  |
| `job_title` | string (nullable) | no | max length 160 |  |
| `locale` | string (nullable) | no | pattern ^(en\|es\|de\|fr\|it)$ |  |
| `is_active` | boolean (nullable) | no |  |  |
| `role_slugs` | array of string (nullable) | no |  |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |

#### `WebCertAttach`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `certificate` | string | yes | min length 1; max length 400000 |  |
| `chain` | string (nullable) | no | max length 400000 |  |
| `request_id` | string (uuid) (nullable) | no |  |  |

#### `WebCertImport`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `certificate` | string (nullable) | no | max length 400000 |  |
| `private_key` | string (nullable) | no | max length 100000 |  |
| `chain` | string (nullable) | no | max length 400000 |  |
| `pkcs12_base64` | string (nullable) | no | max length 600000 |  |
| `passphrase` | string (nullable) | no | max length 1024 |  |
| `note` | string (nullable) | no | max length 500 |  |

#### `WebCertPolicy`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `redirect_http` | boolean | yes |  |  |

#### `WebCertRequestCreate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `common_name` | string | yes | min length 1; max length 253 |  |
| `extra_names` | string (nullable) | no | max length 20000 |  |
| `key_type` | string | no | max length 16; default `"rsa-3072"` |  |
| `organization` | string (nullable) | no | max length 64 |  |
| `organizational_unit` | string (nullable) | no | max length 64 |  |
| `locality` | string (nullable) | no | max length 64 |  |
| `state` | string (nullable) | no | max length 64 |  |
| `country` | string (nullable) | no | max length 2 |  |
| `note` | string (nullable) | no | max length 500 |  |
