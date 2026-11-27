---
title: API reference: agents
purpose: Every HTTP endpoint tagged `agents`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: agents

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


22 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `GET` | [`/api/v1/agents`](#get-apiv1agents) | List Agents | Authenticated | `agent:read` |
| `POST` | [`/api/v1/agents`](#post-apiv1agents) | Enroll Agent | Authenticated | `agent:admin` |
| `GET` | [`/api/v1/agents/jobs`](#get-apiv1agentsjobs) | List Jobs | Authenticated | `agent:read` |
| `POST` | [`/api/v1/agents/jobs`](#post-apiv1agentsjobs) | Queue Job | Authenticated | `agent:write` |
| `GET` | [`/api/v1/agents/jobs/summary`](#get-apiv1agentsjobssummary) | Jobs Summary | Authenticated | `agent:read` |
| `GET` | [`/api/v1/agents/jobs/{job_id}`](#get-apiv1agentsjobsjob_id) | Get Job | Authenticated | `agent:read` |
| `POST` | [`/api/v1/agents/jobs/{job_id}/cancel`](#post-apiv1agentsjobsjob_idcancel) | Cancel Job | Authenticated | `agent:write` |
| `GET` | [`/api/v1/agents/jobs/{job_id}/events`](#get-apiv1agentsjobsjob_idevents) | Job Events | Authenticated | `agent:read` |
| `POST` | [`/api/v1/agents/maintenance/reap`](#post-apiv1agentsmaintenancereap) | Requeue expired leases, mark silent agents offline | Authenticated | `agent:write` |
| `POST` | [`/api/v1/agents/self/heartbeat`](#post-apiv1agentsselfheartbeat) | Agent check-in and capability declaration | Agent credential | - |
| `POST` | [`/api/v1/agents/self/inventory`](#post-apiv1agentsselfinventory) | Report a host's installed software | Agent credential | - |
| `POST` | [`/api/v1/agents/self/jobs/claim`](#post-apiv1agentsselfjobsclaim) | Lease the next authorised job | Agent credential | - |
| `POST` | [`/api/v1/agents/self/jobs/{job_id}/events`](#post-apiv1agentsselfjobsjob_idevents) | Stream job output | Agent credential | - |
| `POST` | [`/api/v1/agents/self/jobs/{job_id}/fail`](#post-apiv1agentsselfjobsjob_idfail) | Report that a job could not run | Agent credential | - |
| `POST` | [`/api/v1/agents/self/jobs/{job_id}/lease`](#post-apiv1agentsselfjobsjob_idlease) | Extend a lease on a long scan | Agent credential | - |
| `POST` | [`/api/v1/agents/self/jobs/{job_id}/result`](#post-apiv1agentsselfjobsjob_idresult) | Submit scanner output for ingestion | Agent credential | - |
| `DELETE` | [`/api/v1/agents/{agent_id}`](#delete-apiv1agentsagent_id) | Delete Agent | Authenticated | `agent:admin` |
| `GET` | [`/api/v1/agents/{agent_id}`](#get-apiv1agentsagent_id) | Get Agent Detail | Authenticated | `agent:read` |
| `PATCH` | [`/api/v1/agents/{agent_id}`](#patch-apiv1agentsagent_id) | Update Agent | Authenticated | `agent:admin` |
| `POST` | [`/api/v1/agents/{agent_id}/rotate-token`](#post-apiv1agentsagent_idrotate-token) | Rotate Agent Token | Authenticated | `agent:admin` |
| `GET` | [`/api/v1/agents/{agent_id}/tools`](#get-apiv1agentsagent_idtools) | List Agent Tools | Authenticated | `agent:read` |
| `PATCH` | [`/api/v1/agents/{agent_id}/tools/{tool_name}`](#patch-apiv1agentsagent_idtoolstool_name) | Toggle Agent Tool | Authenticated | `agent:admin` |

## GET /api/v1/agents

**List Agents**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:566` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `status` | query | string (nullable) | no |  |  |
| `limit` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_AgentOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/agents

**Enroll Agent**

Enrol an agent and return its token once.

Requires `agent:admin`, not `agent:write`: enrolment creates a new place from which scans can originate, which is a change to the estate's attack surface rather than a day-to-day operation.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:admin` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/agents.py:585` |

**Request body** (`application/json`, required): `AgentCreate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `AgentEnrolled` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/agents/jobs

**List Jobs**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:444` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `state` | query | string (nullable) | no |  |  |
| `agent_id` | query | string (uuid) (nullable) | no |  |  |
| `tool` | query | string (nullable) | no |  |  |
| `active` | query | boolean | no | default `false` | Only queued/leased/running |
| `limit` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_JobOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/agents/jobs

**Queue Job**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/agents.py:472` |

**Request body** (`application/json`, required): `JobCreate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `JobOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/agents/jobs/summary

**Jobs Summary**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:496` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/agents/jobs/{job_id}

**Get Job**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:504` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `job_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `JobOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/agents/jobs/{job_id}/cancel

**Cancel Job**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:532` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `job_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`): `Body_cancel_job_api_v1_agents_jobs__job_id__cancel_post`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `JobOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/agents/jobs/{job_id}/events

**Job Events**

Incremental tail. Poll with the last `seq` you saw.

Deliberately not a websocket: the console needs yesterday's scrollback as much as today's tail, one durable log serves both, and a polling client survives a restart of either end without a reconnect protocol.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:513` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `job_id` | path | string (uuid) | yes |  |  |
| `since_seq` | query | integer | no | ≥ 0; default `0` |  |
| `limit` | query | integer | no | ≥ 1; ≤ 2000; default `500` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `JobEventOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/agents/maintenance/reap

**Requeue expired leases, mark silent agents offline**

Idempotent housekeeping. Safe to call from cron as often as you like.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:548` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `offline_after` | query | integer | no | ≥ 30; ≤ 86400; default `180` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/agents/self/heartbeat

**Agent check-in and capability declaration**

| | |
|---|---|
| Authentication | Agent credential |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:239` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `X-Agent-Token` | header | string (nullable) | no |  |  |

**Request body** (`application/json`, required): `HeartbeatIn`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/agents/self/inventory

**Report a host's installed software**

Continuous correlation starts here.

A scan says what was vulnerable when it ran. An inventory says what exists, so a CVE published next week raises a finding next week without anyone re-running anything. Refusals are 422 with the policy reason intact, because the fix is always a policy edit an operator has to make.

| | |
|---|---|
| Authentication | Agent credential |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:392` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `X-Agent-Token` | header | string (nullable) | no |  |  |

**Request body** (`application/json`, required): `InventoryReport`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/agents/self/jobs/claim

**Lease the next authorised job**

| | |
|---|---|
| Authentication | Agent credential |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:262` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `X-Agent-Token` | header | string (nullable) | no |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object (nullable) |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/agents/self/jobs/{job_id}/events

**Stream job output**

| | |
|---|---|
| Authentication | Agent credential |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:286` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `job_id` | path | string (uuid) | yes |  |  |
| `lease_token` | query | string (nullable) | no |  | Deprecated: send the X-Agent-Lease header. Accepted until the next minor release for agents older than 0.41.0. |
| `X-Agent-Token` | header | string (nullable) | no |  |  |
| `X-Agent-Lease` | header | string (nullable) | no |  |  |

**Request body** (`application/json`, required): `EventBatch`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/agents/self/jobs/{job_id}/fail

**Report that a job could not run**

| | |
|---|---|
| Authentication | Agent credential |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:420` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `job_id` | path | string (uuid) | yes |  |  |
| `lease_token` | query | string (nullable) | no |  | Deprecated: send the X-Agent-Lease header. Accepted until the next minor release for agents older than 0.41.0. |
| `X-Agent-Token` | header | string (nullable) | no |  |  |
| `X-Agent-Lease` | header | string (nullable) | no |  |  |

**Request body** (`application/json`, required): `JobFailure`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `JobOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/agents/self/jobs/{job_id}/lease

**Extend a lease on a long scan**

| | |
|---|---|
| Authentication | Agent credential |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:306` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `job_id` | path | string (uuid) | yes |  |  |
| `lease_token` | query | string (nullable) | no |  | Deprecated: send the X-Agent-Lease header. Accepted until the next minor release for agents older than 0.41.0. |
| `X-Agent-Token` | header | string (nullable) | no |  |  |
| `X-Agent-Lease` | header | string (nullable) | no |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## POST /api/v1/agents/self/jobs/{job_id}/result

**Submit scanner output for ingestion**

Raw request body = the scanner's output file, verbatim.

An EMPTY body is meaningful - a completed scan that found nothing is what has to reach reconciliation for remediated findings to close - but only when ``X-Agent-Scan-Stats`` shows the scan actually covered the target. An empty body with no coverage is a blind scanner, and is refused.

| | |
|---|---|
| Authentication | Agent credential |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:323` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `job_id` | path | string (uuid) | yes |  |  |
| `scanner` | query | string (nullable) | no | max length 60 |  |
| `exit_code` | query | integer | no | default `0` |  |
| `filename` | query | string (nullable) | no | max length 400 |  |
| `lease_token` | query | string (nullable) | no |  | Deprecated: send the X-Agent-Lease header. Accepted until the next minor release for agents older than 0.41.0. |
| `x-agent-scan-stats` | header | string (nullable) | no |  |  |
| `X-Agent-Token` | header | string (nullable) | no |  |  |
| `X-Agent-Lease` | header | string (nullable) | no |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## DELETE /api/v1/agents/{agent_id}

**Delete Agent**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:admin` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/agents.py:668` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `agent_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/agents/{agent_id}

**Get Agent Detail**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:614` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `agent_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AgentOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/agents/{agent_id}

**Update Agent**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:623` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `agent_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `AgentUpdate`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AgentOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/agents/{agent_id}/rotate-token

**Rotate Agent Token**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:656` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `agent_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/agents/{agent_id}/tools

**List Agent Tools**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:696` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `agent_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `AgentToolOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/agents/{agent_id}/tools/{tool_name}

**Toggle Agent Tool**

Authorise (or withdraw) one tool on one agent.

This is the decision that turns a declaration into an execution right, so it sits behind `agent:admin` and lands in the audit trail.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `agent:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/agents.py:712` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `agent_id` | path | string (uuid) | yes |  |  |
| `tool_name` | path | string | yes |  |  |

**Request body** (`application/json`, required): `ToolToggle`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `AgentToolOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## Schemas

Request and response models used on this page.

#### `AgentCreate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string | yes | min length 2; max length 200 |  |
| `description` | string (nullable) | no | max length 4000 |  |
| `allowed_targets` | array of string | no | max items 200 |  |
| `denied_targets` | array of string | no | max items 200 |  |
| `require_asset_match` | boolean | no | default `true` |  |
| `auto_enable_tools` | boolean | no | default `false` |  |
| `max_concurrency` | integer | no | ≥ 1.0; ≤ 32.0; default `1` |  |
| `lease_seconds` | integer | no | ≥ 60.0; ≤ 86400.0; default `900` |  |
| `labels` | array of string | no | max items 40 |  |

#### `AgentEnrolled`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `name` | string | yes |  |  |
| `slug` | string | yes |  |  |
| `description` | string (nullable) | yes |  |  |
| `status` | string | yes |  |  |
| `agent_version` | string (nullable) | yes |  |  |
| `hostname` | string (nullable) | yes |  |  |
| `platform` | string (nullable) | yes |  |  |
| `last_ip` | string (nullable) | yes |  |  |
| `last_heartbeat_at` | string (date-time) (nullable) | yes |  |  |
| `allowed_targets` | array of any | yes |  |  |
| `denied_targets` | array of any | yes |  |  |
| `require_asset_match` | boolean | yes |  |  |
| `auto_enable_tools` | boolean | yes |  |  |
| `max_concurrency` | integer | yes |  |  |
| `lease_seconds` | integer | yes |  |  |
| `labels` | array of any | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |
| `tools` | array of `AgentToolOut` | no |  |  |
| `token` | string | yes |  | Shown exactly once. VEYRS stores only its Argon2 hash. |

#### `AgentOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `name` | string | yes |  |  |
| `slug` | string | yes |  |  |
| `description` | string (nullable) | yes |  |  |
| `status` | string | yes |  |  |
| `agent_version` | string (nullable) | yes |  |  |
| `hostname` | string (nullable) | yes |  |  |
| `platform` | string (nullable) | yes |  |  |
| `last_ip` | string (nullable) | yes |  |  |
| `last_heartbeat_at` | string (date-time) (nullable) | yes |  |  |
| `allowed_targets` | array of any | yes |  |  |
| `denied_targets` | array of any | yes |  |  |
| `require_asset_match` | boolean | yes |  |  |
| `auto_enable_tools` | boolean | yes |  |  |
| `max_concurrency` | integer | yes |  |  |
| `lease_seconds` | integer | yes |  |  |
| `labels` | array of any | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |
| `tools` | array of `AgentToolOut` | no |  |  |

#### `AgentToolOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `name` | string | yes |  |  |
| `tool_version` | string (nullable) | yes |  |  |
| `parser` | string (nullable) | yes |  |  |
| `enabled` | boolean | yes |  |  |
| `profiles` | array of any | yes |  |  |
| `declared_at` | string (date-time) (nullable) | yes |  |  |

#### `AgentUpdate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string (nullable) | no | min length 2; max length 200 |  |
| `description` | string (nullable) | no | max length 4000 |  |
| `status` | string (nullable) | no |  |  |
| `allowed_targets` | array of string (nullable) | no | max items 200 |  |
| `denied_targets` | array of string (nullable) | no | max items 200 |  |
| `require_asset_match` | boolean (nullable) | no |  |  |
| `auto_enable_tools` | boolean (nullable) | no |  |  |
| `max_concurrency` | integer (nullable) | no | ≥ 1.0; ≤ 32.0 |  |
| `lease_seconds` | integer (nullable) | no | ≥ 60.0; ≤ 86400.0 |  |
| `labels` | array of string (nullable) | no | max items 40 |  |

#### `Body_cancel_job_api_v1_agents_jobs__job_id__cancel_post`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `note` | string (nullable) | no | max length 2000 |  |

#### `EventBatch`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `events` | array of `EventIn` | yes | min items 1; max items 200 |  |

#### `EventIn`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `kind` | string | no | default `"stdout"` |  |
| `message` | string (nullable) | no | max length 8000 |  |
| `data` | object | no |  |  |

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `HeartbeatIn`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `agent_version` | string (nullable) | no | max length 40 |  |
| `hostname` | string (nullable) | no | max length 255 |  |
| `platform` | string (nullable) | no | max length 120 |  |
| `tools` | array of object (nullable) | no | max items 200 |  |

#### `InventoryItemReport`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `cpe` | string (nullable) | no | max length 600 |  |
| `vendor` | string (nullable) | no | max length 200 |  |
| `product` | string (nullable) | no | max length 300 |  |
| `version` | string (nullable) | no | max length 120 | Upstream version, for CVE range matching |
| `raw_version` | string (nullable) | no | max length 200 | Verbatim package-manager version |
| `install_path` | string (nullable) | no |  |  |

#### `InventoryReport`

A host's complete installed-software list as the agent sees it.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `target` | string | yes | min length 1; max length 400 | The host this inventory belongs to. Subject to the agent's allowlist exactly like a scan target. |
| `items` | array of `InventoryItemReport` | no | max items 20000 |  |
| `operating_system` | string (nullable) | no |  |  |
| `os_version` | string (nullable) | no |  |  |
| `replace` | boolean | no | default `true` | A package-manager sweep is complete information, so the default drops what this agent no longer reports. Set false for a partial or filtered collection. |

#### `JobCreate`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `tool` | string | yes | min length 1; max length 60 |  |
| `target` | string | yes | min length 1; max length 500 |  |
| `agent_id` | string (uuid) (nullable) | no |  |  |
| `profile` | string (nullable) | no | max length 60 |  |
| `params` | object | no |  |  |
| `engagement_id` | string (uuid) (nullable) | no |  |  |
| `reason` | string | yes | min length 5; max length 2000 |  |
| `priority` | integer | no | ≥ -100.0; ≤ 100.0; default `0` |  |
| `max_attempts` | integer | no | ≥ 1.0; ≤ 10.0; default `3` |  |

#### `JobEventOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `seq` | integer | yes |  |  |
| `kind` | string | yes |  |  |
| `message` | string (nullable) | yes |  |  |
| `data` | object | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |

#### `JobFailure`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `error` | string | yes | min length 1; max length 4000 |  |
| `exit_code` | integer (nullable) | no |  |  |
| `requeue` | boolean | no | default `true` |  |

#### `JobOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `agent_id` | string (uuid) (nullable) | yes |  |  |
| `requested_agent_id` | string (uuid) (nullable) | yes |  |  |
| `tool` | string | yes |  |  |
| `target` | string | yes |  |  |
| `profile` | string (nullable) | yes |  |  |
| `params` | object | yes |  |  |
| `engagement_id` | string (uuid) (nullable) | yes |  |  |
| `test_id` | string (uuid) (nullable) | yes |  |  |
| `asset_id` | string (uuid) (nullable) | yes |  |  |
| `state` | string | yes |  |  |
| `priority` | integer | yes |  |  |
| `reason` | string (nullable) | yes |  |  |
| `attempts` | integer | yes |  |  |
| `max_attempts` | integer | yes |  |  |
| `leased_at` | string (date-time) (nullable) | yes |  |  |
| `lease_expires_at` | string (date-time) (nullable) | yes |  |  |
| `started_at` | string (date-time) (nullable) | yes |  |  |
| `finished_at` | string (date-time) (nullable) | yes |  |  |
| `exit_code` | integer (nullable) | yes |  |  |
| `error` | string (nullable) | yes |  |  |
| `import_run_id` | string (uuid) (nullable) | yes |  |  |
| `output_bytes` | integer (nullable) | yes |  |  |
| `last_event_seq` | integer | yes |  |  |
| `created_at` | string (date-time) | yes |  |  |

#### `Page_AgentOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `AgentOut` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `Page_JobOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `JobOut` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `ToolToggle`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `enabled` | boolean | yes |  |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |
