---
title: API reference: authentication
purpose: Every HTTP endpoint tagged `authentication`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: authentication

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


17 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `POST` | [`/api/v1/auth/login`](#post-apiv1authlogin) | Exchange credentials for tokens | Public | - |
| `POST` | [`/api/v1/auth/logout`](#post-apiv1authlogout) | Sign out everywhere: end every session of this account | Authenticated | - |
| `GET` | [`/api/v1/auth/me`](#get-apiv1authme) | The authenticated identity | Authenticated | - |
| `GET` | [`/api/v1/auth/me/preferences`](#get-apiv1authmepreferences) | My console preferences | Authenticated | - |
| `PATCH` | [`/api/v1/auth/me/preferences`](#patch-apiv1authmepreferences) | Remember a console preference | Authenticated | - |
| `GET` | [`/api/v1/auth/me/scope`](#get-apiv1authmescope) | What this identity may see, and what nobody can | Authenticated | - |
| `GET` | [`/api/v1/auth/mfa`](#get-apiv1authmfa) | My two-factor status and the methods this installation offers | Authenticated | - |
| `POST` | [`/api/v1/auth/mfa/activate`](#post-apiv1authmfaactivate) | Confirm enrolment, require MFA at login, get recovery codes | Authenticated | - |
| `POST` | [`/api/v1/auth/mfa/disable`](#post-apiv1authmfadisable) | Turn MFA off (password AND a valid code) | Authenticated | - |
| `POST` | [`/api/v1/auth/mfa/enroll`](#post-apiv1authmfaenroll) | Begin MFA enrolment with a method (totp, email or telegram) | Authenticated | - |
| `POST` | [`/api/v1/auth/mfa/recovery-codes`](#post-apiv1authmfarecovery-codes) | Replace my recovery codes (password AND a valid code) | Authenticated | - |
| `POST` | [`/api/v1/auth/mfa/send-code`](#post-apiv1authmfasend-code) | Send a code by my e-mail / Telegram method | Authenticated | - |
| `POST` | [`/api/v1/auth/oidc/exchange`](#post-apiv1authoidcexchange) | Swap the one-time SSO handoff for tokens | Public | - |
| `GET` | [`/api/v1/auth/oidc/{org_slug}/start`](#get-apiv1authoidcorg_slugstart) | Where to send the browser to sign in with SSO | Public | - |
| `POST` | [`/api/v1/auth/password`](#post-apiv1authpassword) | Change own password | Authenticated | - |
| `POST` | [`/api/v1/auth/refresh`](#post-apiv1authrefresh) | Rotate a refresh token | Public | - |
| `GET` | [`/api/v1/auth/sso`](#get-apiv1authsso) | Is single sign-on offered on this installation? | Public | - |

## POST /api/v1/auth/login

**Exchange credentials for tokens**

| | |
|---|---|
| Authentication | Public |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/auth.py:395` |

**Request body** (`application/json`, required): `LoginRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `TokenPair` |
| `422` | Validation Error | `HTTPValidationError` |

## POST /api/v1/auth/logout

**Sign out everywhere: end every session of this account**

Every refresh token revoked and every access token voided, on every device.

The access side is the token-version bump (`security.auth.end_sessions`): without it a copied access token kept working for its whole lifetime after the owner signed out.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/auth.py:688` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/auth/me

**The authenticated identity**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/auth.py:706` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `MeResponse` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/auth/me/preferences

**My console preferences**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/auth.py:782` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## PATCH /api/v1/auth/me/preferences

**Remember a console preference**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/auth.py:787` |

**Request body** (`application/json`, required): `UserPreferencesPatch`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/auth/me/scope

**What this identity may see, and what nobody can**

The scope plus the estate's unowned residue.

The second half is the point. Deny-by-default on unowned rows means work with no team is invisible to every scoped user at once -- a blind spot that grows quietly as new assets arrive without an owner. Counting it here turns "my queue is empty" into a question with an answer.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/auth.py:820` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/auth/mfa

**My two-factor status and the methods this installation offers**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/auth.py:971` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/auth/mfa/activate

**Confirm enrolment, require MFA at login, get recovery codes**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/auth.py:1040` |

**Request body** (`application/json`, required): `MfaActivate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/auth/mfa/disable

**Turn MFA off (password AND a valid code)**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/auth.py:1094` |

**Request body** (`application/json`, required): `MfaDisable`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/auth/mfa/enroll

**Begin MFA enrolment with a method (totp, email or telegram)**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/auth.py:987` |

**Request body** (`application/json`): `MfaEnrollRequest` (nullable)

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/auth/mfa/recovery-codes

**Replace my recovery codes (password AND a valid code)**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/auth.py:1075` |

**Request body** (`application/json`, required): `MfaDisable`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/auth/mfa/send-code

**Send a code by my e-mail / Telegram method**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/auth.py:1029` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/auth/oidc/exchange

**Swap the one-time SSO handoff for tokens**

| | |
|---|---|
| Authentication | Public |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/auth.py:1259` |

**Request body** (`application/json`, required): `OidcExchange`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `TokenPair` |
| `422` | Validation Error | `HTTPValidationError` |

## GET /api/v1/auth/oidc/{org_slug}/start

**Where to send the browser to sign in with SSO**

The authorization URL, plus a cookie that ties the flow to THIS browser.

The cookie (HttpOnly, SameSite=Lax, scoped to `/auth/oidc`) carries a random binder whose hash is stored with the flow; the callback and the hand-off exchange accept the flow only from the browser that holds it. Without it, an attacker could start a flow, sign in at the provider as themselves, and get a victim's browser to complete it (login CSRF).

| | |
|---|---|
| Authentication | Public |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/auth.py:1155` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `org_slug` | path | string | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |

## POST /api/v1/auth/password

**Change own password**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | none beyond authentication |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/auth.py:844` |

**Request body** (`application/json`, required): `PasswordChange`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/auth/refresh

**Rotate a refresh token**

| | |
|---|---|
| Authentication | Public |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/auth.py:614` |

**Request body** (`application/json`, required): `RefreshRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `TokenPair` |
| `422` | Validation Error | `HTTPValidationError` |

## GET /api/v1/auth/sso

**Is single sign-on offered on this installation?**

A boolean only: listing WHICH organizations use SSO would enumerate tenants.

| | |
|---|---|
| Authentication | Public |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/auth.py:1134` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |

## Schemas

Request and response models used on this page.

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `LoginRequest`

Credentials. The identifier may be a username OR an email address.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `identifier` | string (nullable) | no | min length 1; max length 320 | Username or email address. |
| `email` | string (nullable) | no | max length 320 |  |
| `password` | string | yes | min length 1; max length 512 |  |
| `organization` | string (nullable) | no |  | Organization slug. Required when the identifier exists in several tenants. |
| `mfa_code` | string (nullable) | no | max length 20 |  |
| `radius_challenge` | string (nullable) | no | max length 64 |  |

#### `MeResponse`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `email` | string | yes |  |  |
| `username` | string (nullable) | no |  |  |
| `full_name` | string | yes |  |  |
| `locale` | string | yes |  |  |
| `job_title` | string (nullable) | yes |  |  |
| `organization_id` | string (uuid) | yes |  |  |
| `is_superuser` | boolean | yes |  |  |
| `mfa_enabled` | boolean | yes |  |  |
| `mfa_method` | string (nullable) | no |  |  |
| `last_login_at` | string (date-time) (nullable) | yes |  |  |
| `permissions` | array of string | no |  |  |
| `roles` | array of string | no |  |  |
| `teams` | array of string | no |  |  |
| `scope` | object | no |  |  |
| `preferences` | object | no |  |  |
| `active_scanning` | boolean | no | default `true` |  |
| `ticketing_mode` | string | no | default `"internal"` |  |
| `ticketing_usable` | boolean | no | default `true` |  |
| `risk_register_enabled` | boolean | no | default `true` |  |

#### `MfaActivate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `code` | string | yes | min length 6; max length 20 |  |

#### `MfaDisable`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `password` | string | yes | min length 1; max length 512 |  |
| `code` | string | yes | min length 6; max length 20 |  |

#### `MfaEnrollRequest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `method` | string enum | no | one of `totp`, `email`, `telegram`; default `"totp"` |  |
| `telegram_chat_id` | string (nullable) | no | max length 32 |  |

#### `OidcExchange`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `handoff` | string | yes | min length 20; max length 100 |  |

#### `PasswordChange`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `current_password` | string | yes | min length 1; max length 512 |  |
| `new_password` | string | yes | max length 512 |  |

#### `RefreshRequest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `refresh_token` | string | yes | min length 10; max length 512 |  |

#### `TokenPair`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `access_token` | string | yes |  |  |
| `refresh_token` | string (nullable) | yes |  |  |
| `token_type` | string | no | default `"bearer"` |  |
| `expires_at` | string (date-time) | yes |  |  |
| `organization_id` | string (uuid) | yes |  |  |
| `user_id` | string (uuid) | yes |  |  |
| `permissions` | array of string | yes |  |  |
| `mfa_enrollment_required` | boolean | no | default `false` |  |

#### `UserPreferencesPatch`

Merge by field: only what is sent is changed.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `dashboard_team_id` | string (uuid) (nullable) | no |  |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |
