---
title: API reference: operations
purpose: Every HTTP endpoint tagged `operations`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: operations

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


2 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `GET` | [`/healthz`](#get-healthz) | Liveness probe | Public | - |
| `GET` | [`/readyz`](#get-readyz) | Readiness probe | Public | - |

## GET /healthz

**Liveness probe**

| | |
|---|---|
| Authentication | Public |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/main.py:102` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |

## GET /readyz

**Readiness probe**

| | |
|---|---|
| Authentication | Public |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/main.py:106` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | - |
