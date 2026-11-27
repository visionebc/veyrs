---
title: API reference: integrations
purpose: Every HTTP endpoint tagged `integrations`, generated from the running application's routes.
scope: Method, path, authentication, permissions, parameters, request and response schemas. Behaviour is explained in the functional docs.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/api/v1]
related: [api/reference/README.md, API.md]
---

# API reference: integrations

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


25 operations. Authentication classes are explained in the [reference index](README.md#authentication-classes).

| Method | Path | Summary | Auth | Permissions |
|---|---|---|---|---|
| `GET` | [`/api/v1/integrations/connectors`](#get-apiv1integrationsconnectors) | List Connectors | Authenticated | `ticket:read` |
| `POST` | [`/api/v1/integrations/connectors`](#post-apiv1integrationsconnectors) | Create Connector | Authenticated | `ticket:admin` |
| `DELETE` | [`/api/v1/integrations/connectors/{connector_id}`](#delete-apiv1integrationsconnectorsconnector_id) | Delete Connector | Authenticated | `ticket:admin` |
| `PATCH` | [`/api/v1/integrations/connectors/{connector_id}`](#patch-apiv1integrationsconnectorsconnector_id) | Update Connector | Authenticated | `ticket:admin` |
| `POST` | [`/api/v1/integrations/connectors/{connector_id}/inbound-secret`](#post-apiv1integrationsconnectorsconnector_idinbound-secret) | Rotate Inbound Secret | Authenticated | `ticket:admin` |
| `POST` | [`/api/v1/integrations/connectors/{connector_id}/pull`](#post-apiv1integrationsconnectorsconnector_idpull) | Pull Connector | Authenticated | `ticket:write` |
| `POST` | [`/api/v1/integrations/connectors/{connector_id}/push/{ticket_id}`](#post-apiv1integrationsconnectorsconnector_idpushticket_id) | Push Ticket | Authenticated | `ticket:write` |
| `POST` | [`/api/v1/integrations/connectors/{connector_id}/test`](#post-apiv1integrationsconnectorsconnector_idtest) | Test Connector | Authenticated | `ticket:admin` |
| `GET` | [`/api/v1/integrations/importers`](#get-apiv1integrationsimporters) | List Importers | Authenticated | `importer:read` |
| `GET` | [`/api/v1/integrations/imports`](#get-apiv1integrationsimports) | List Imports | Authenticated | `importer:read` |
| `POST` | [`/api/v1/integrations/imports`](#post-apiv1integrationsimports) | Create Import | Authenticated | `importer:write` |
| `GET` | [`/api/v1/integrations/imports/{run_id}`](#get-apiv1integrationsimportsrun_id) | Read Import | Authenticated | `importer:read` |
| `POST` | [`/api/v1/integrations/itsm/{organization_slug}/{connector_slug}/inbound`](#post-apiv1integrationsitsmorganization_slugconnector_sluginbound) | Signed webhook from an ITSM system | Signed webhook | - |
| `GET` | [`/api/v1/integrations/links`](#get-apiv1integrationslinks) | External issues and what they are about | Authenticated | `ticket:read` |
| `POST` | [`/api/v1/integrations/links/{link_id}/refresh`](#post-apiv1integrationslinkslink_idrefresh) | Re-read one issue's remote status | Authenticated | `ticket:write` |
| `POST` | [`/api/v1/integrations/links/{link_id}/unlink`](#post-apiv1integrationslinkslink_idunlink) | Detach a relation without touching the remote | Authenticated | `ticket:write` |
| `GET` | [`/api/v1/integrations/scanner-drivers`](#get-apiv1integrationsscanner-drivers) | List Scanner Drivers | Authenticated | `importer:read` |
| `GET` | [`/api/v1/integrations/scanners`](#get-apiv1integrationsscanners) | List Scanner Connectors | Authenticated | `importer:read` |
| `POST` | [`/api/v1/integrations/scanners`](#post-apiv1integrationsscanners) | Create Scanner Connector | Authenticated | `importer:admin` |
| `DELETE` | [`/api/v1/integrations/scanners/{connector_id}`](#delete-apiv1integrationsscannersconnector_id) | Delete Scanner Connector | Authenticated | `importer:admin` |
| `PATCH` | [`/api/v1/integrations/scanners/{connector_id}`](#patch-apiv1integrationsscannersconnector_id) | Update Scanner Connector | Authenticated | `importer:admin` |
| `GET` | [`/api/v1/integrations/scanners/{connector_id}/scans`](#get-apiv1integrationsscannersconnector_idscans) | List Scanner Scans | Authenticated | `importer:read` |
| `POST` | [`/api/v1/integrations/scanners/{connector_id}/sync`](#post-apiv1integrationsscannersconnector_idsync) | Sync Scanner Connector | Authenticated | `importer:write` |
| `POST` | [`/api/v1/integrations/scanners/{connector_id}/test`](#post-apiv1integrationsscannersconnector_idtest) | Test Scanner Connector | Authenticated | `importer:admin` |
| `GET` | [`/api/v1/integrations/tickets/{ticket_id}/links`](#get-apiv1integrationsticketsticket_idlinks) | Ticket Links | Authenticated | `ticket:read` |

## GET /api/v1/integrations/connectors

**List Connectors**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:303` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `purpose` | query | string (nullable) | no | pattern ^(ticketing\|documentation)$ |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `ConnectorOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/integrations/connectors

**Create Connector**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:admin` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/integrations.py:324` |

**Request body** (`application/json`, required): `ConnectorWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `ConnectorOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/integrations/connectors/{connector_id}

**Delete Connector**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:admin` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/integrations.py:503` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `connector_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/integrations/connectors/{connector_id}

**Update Connector**

Edit a connector in place, including rotating its credential.

Without this, changing a base URL or replacing an expired API token meant deleting the connector -- which cascades `external_links` and throws away every recorded correspondence between a VEYRS ticket and its remote twin. Rotating a token should not lose the audit trail.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:363` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `connector_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `ConnectorPatch`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `ConnectorOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/integrations/connectors/{connector_id}/inbound-secret

**Rotate Inbound Secret**

Mint the HMAC secret the remote system will sign with. Shown once.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:583` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `connector_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/integrations/connectors/{connector_id}/pull

**Pull Connector**

Refresh the remote status of this connector's links.

`pull_status()` has existed since the ITSM leg shipped and NO route ever called it, so the only way to learn that an engineer had closed a Jira issue was the inbound webhook -- which requires the remote system to be able to REACH VEYRS. A Jira Cloud tenant cannot call into a console that is not published on the internet, so for those deployments this is the only monitoring leg there is.

Unchanged safety property: this writes `ExternalLink.remote_status` and nothing else. A remote closure is evidence about the work, not proof the finding is fixed; moving a VEYRS ticket stays an `inbound_transitions` decision the operator has to opt into.

Bounded, and it reports what it did not reach. Least-recently-pulled first, so calling it repeatedly sweeps the whole set instead of re-reading the same page -- a silent top-N here would read as "everything is current".

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:441` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `connector_id` | path | string (uuid) | yes |  |  |
| `limit` | query | integer | no | ≥ 1; ≤ 500; default `100` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/integrations/connectors/{connector_id}/push/{ticket_id}

**Push Ticket**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:519` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `connector_id` | path | string (uuid) | yes |  |  |
| `ticket_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/integrations/connectors/{connector_id}/test

**Test Connector**

Per-step diagnosis of a connector. See services.itsm.test_connector.

`ticket:admin` rather than `ticket:read` because the response names the base URL, the service account and the project -- the same reasoning that puts `GET /ldap` behind `settings:admin`.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:418` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `connector_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/integrations/importers

**List Importers**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:146` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/integrations/imports

**List Imports**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:265` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `source` | query | string (nullable) | no |  |  |
| `limit` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |
| `offset` | query | integer | no | ≥ 0; default `0` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `Page_ImportRunOut_` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/integrations/imports

**Create Import**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:write` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/integrations.py:191` |

**Request body** (`multipart/form-data`, required): `Body_create_import_api_v1_integrations_imports_post`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `ImportRunOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/integrations/imports/{run_id}

**Read Import**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:288` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `run_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `ImportRunOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/integrations/itsm/{organization_slug}/{connector_slug}/inbound

**Signed webhook from an ITSM system**

Apply one signed remote change.

No user credential is involved: the HMAC proves the sender, and the tenant comes from the path rather than from anything the sender asserts in the body. That ordering matters - resolving the tenant from the payload would let a signed message for one connector be replayed against another.

Every failure answers the same shape and, for anything before the signature verifies, the same 404/401 regardless of whether the org, the connector or the signature was wrong. A webhook endpoint that distinguishes them is an enumeration oracle for tenant slugs.

| | |
|---|---|
| Authentication | Signed webhook |
| Permissions | - |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:612` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `organization_slug` | path | string | yes |  |  |
| `connector_slug` | path | string | yes |  |  |
| `X-VEYRS-Signature` | header | string (nullable) | no |  |  |
| `X-VEYRS-Timestamp` | header | string (nullable) | no |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |

## GET /api/v1/integrations/links

**External issues and what they are about**

The list the console shows where Tickets used to be.

Filtering happens in SQL and not in the browser, for the reason phase 31 settled: a client-side overlay over one page of results silently answers a different question than the one the operator asked.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:1072` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `finding_id` | query | string (uuid) (nullable) | no |  |  |
| `asset_id` | query | string (uuid) (nullable) | no |  |  |
| `connector_id` | query | string (uuid) (nullable) | no |  |  |
| `object_type` | query | string (nullable) | no | pattern ^(ticket\|finding)$ |  |
| `remote_status` | query | string (nullable) | no |  |  |
| `severity` | query | string (nullable) | no |  |  |
| `q` | query | string (nullable) | no |  |  |
| `is_active` | query | boolean (nullable) | no |  |  |
| `page` | query | integer | no | ≥ 1; default `1` |  |
| `size` | query | integer | no | ≥ 1; ≤ 200; default `50` |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/integrations/links/{link_id}/refresh

**Re-read one issue's remote status**

Never raises for a remote failure -- it records it on the row.

A refresh button that 500s when Jira is down is a button that makes an outage look like a VEYRS bug. The error lands in `last_error`, where the list view already prints it.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:1131` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `link_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/integrations/links/{link_id}/unlink

**Detach a relation without touching the remote**

Marks the relation inactive. It does NOT close or delete the remote issue.

VEYRS is the system of record for the finding, never for somebody else's queue -- deleting a Jira issue from a security console is a destructive act on a system whose other users did not consent to it. Unlinking frees the finding to be raised again, which is the only reason to press this.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:1161` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `link_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/integrations/scanner-drivers

**List Scanner Drivers**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:783` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/integrations/scanners

**List Scanner Connectors**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:798` |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of `ScannerConnectorOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/integrations/scanners

**Create Scanner Connector**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:admin` |
| Success status | 201 |
| Handler | `backend/veyrs/api/v1/integrations.py:811` |

**Request body** (`application/json`, required): `ScannerConnectorWrite`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `201` | Successful Response | `ScannerConnectorOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## DELETE /api/v1/integrations/scanners/{connector_id}

**Delete Scanner Connector**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:admin` |
| Success status | 204 |
| Handler | `backend/veyrs/api/v1/integrations.py:901` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `connector_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `204` | Successful Response | - |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## PATCH /api/v1/integrations/scanners/{connector_id}

**Update Scanner Connector**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:862` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `connector_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `ScannerConnectorPatch`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | `ScannerConnectorOut` |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/integrations/scanners/{connector_id}/scans

**List Scanner Scans**

What the remote console holds. Read-only, and it writes no finding.

Deliberately available without `importer:admin`: choosing which scans a connector may pull is the decision that bounds every later sync, and an operator who cannot see the list would be picking ids out of the air.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:918` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `connector_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/integrations/scanners/{connector_id}/sync

**Sync Scanner Connector**

Pull the allowed scans and ingest each one as its own ImportRun.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:write` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:975` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `connector_id` | path | string (uuid) | yes |  |  |

**Request body** (`application/json`, required): `ScannerSyncRequest`

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## POST /api/v1/integrations/scanners/{connector_id}/test

**Test Scanner Connector**

Prove the credentials work, without importing anything.

The result is persisted to `last_error` even on success (as a clear), so the connector list reflects the last thing that actually happened rather than the last thing an operator remembers doing.

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `importer:admin` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:943` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `connector_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## GET /api/v1/integrations/tickets/{ticket_id}/links

**Ticket Links**

| | |
|---|---|
| Authentication | Authenticated |
| Permissions | `ticket:read` |
| Success status | 200 |
| Handler | `backend/veyrs/api/v1/integrations.py:547` |

**Parameters**

| Name | In | Type | Required | Constraints | Description |
|---|---|---|---|---|---|
| `ticket_id` | path | string (uuid) | yes |  |  |

**Responses**

| Status | Meaning | Body |
|---|---|---|
| `200` | Successful Response | array of object |
| `422` | Validation Error | `HTTPValidationError` |
| `401` | Missing or invalid credential (added by the auth dependency) | `{detail}` |
| `403` | Authenticated but lacking a listed permission or outside team scope | `{detail}` |

## Schemas

Request and response models used on this page.

#### `Body_create_import_api_v1_integrations_imports_post`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `file` | string | yes |  |  |
| `source` | string (nullable) | no |  |  |
| `create_assets` | boolean | no | default `false` |  |
| `dry_run` | boolean | no | default `false` |  |
| `close_missing` | boolean | no | default `false` |  |
| `min_severity` | string (nullable) | no |  |  |
| `new_asset_criticality` | string | no | default `"medium"` |  |
| `new_asset_exposure` | string | no | default `"internal"` |  |
| `target_asset` | string (nullable) | no |  |  |
| `engagement_id` | string (uuid) (nullable) | no |  |  |
| `test_id` | string (uuid) (nullable) | no |  |  |
| `reuse_test` | boolean | no | default `true` |  |
| `close_absent` | boolean (nullable) | no |  |  |
| `absence_threshold` | integer (nullable) | no |  |  |
| `version` | string (nullable) | no |  |  |
| `branch_tag` | string (nullable) | no |  |  |
| `commit_hash` | string (nullable) | no |  |  |
| `build_id` | string (nullable) | no |  |  |
| `import_inventory` | boolean | no | default `false` |  |
| `inventory_from_plugin_output` | boolean | no | default `false` |  |

#### `ConnectorOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `slug` | string | yes |  |  |
| `name` | string | yes |  |  |
| `system` | string | yes |  |  |
| `base_url` | string (nullable) | yes |  |  |
| `is_enabled` | boolean | yes |  |  |
| `ticket_types` | array of any | yes |  |  |
| `field_mapping` | object | yes |  |  |
| `last_sync_at` | string (date-time) (nullable) | yes |  |  |
| `last_error` | string (nullable) | yes |  |  |
| `inbound_enabled` | boolean | yes |  |  |
| `inbound_transitions` | object | yes |  |  |
| `last_inbound_at` | string (date-time) (nullable) | yes |  |  |
| `inbound_secret_set` | boolean | no | default `false` |  |
| `credentials_set` | boolean | no | default `false` |  |

#### `ConnectorPatch`

Everything about a connector EXCEPT `slug` and `system`.

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string (nullable) | no | min length 1; max length 200 |  |
| `base_url` | string (nullable) | no | min length 1; max length 600 |  |
| `credentials` | object (nullable) | no |  |  |
| `ticket_types` | array of string (nullable) | no |  |  |
| `field_mapping` | object (nullable) | no |  |  |
| `is_enabled` | boolean (nullable) | no |  |  |
| `inbound_enabled` | boolean (nullable) | no |  |  |
| `inbound_transitions` | object (nullable) | no |  |  |

#### `ConnectorWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `slug` | string | yes | min length 1; max length 80 |  |
| `name` | string | yes | min length 1; max length 200 |  |
| `system` | string | yes |  |  |
| `base_url` | string | yes | min length 1; max length 600 |  |
| `credentials` | object | no |  |  |
| `ticket_types` | array of string | no |  |  |
| `field_mapping` | object | no |  |  |
| `is_enabled` | boolean | no | default `true` |  |
| `inbound_enabled` | boolean | no | default `false` |  |
| `inbound_transitions` | object | no |  |  |

#### `HTTPValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `detail` | array of `ValidationError` | no |  |  |

#### `ImportRunOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `source` | string | yes |  |  |
| `filename` | string (nullable) | yes |  |  |
| `status` | string | yes |  |  |
| `records_seen` | integer | yes |  |  |
| `findings_created` | integer | yes |  |  |
| `findings_updated` | integer | yes |  |  |
| `assets_created` | integer | yes |  |  |
| `records_rejected` | integer | yes |  |  |
| `reject_reasons` | object | yes |  |  |
| `reject_samples` | array of any | yes |  |  |
| `stale_candidates` | integer | yes |  |  |
| `findings_marked_absent` | integer | yes |  |  |
| `findings_closed_absent` | integer | yes |  |  |
| `endpoints_created` | integer | yes |  |  |
| `inventory_hosts` | integer | yes |  |  |
| `inventory_added` | integer | yes |  |  |
| `inventory_updated` | integer | yes |  |  |
| `inventory_unmatched` | integer | yes |  |  |
| `engagement_id` | string (uuid) (nullable) | yes |  |  |
| `test_id` | string (uuid) (nullable) | yes |  |  |
| `dedupe_algorithm` | string (nullable) | yes |  |  |
| `error` | string (nullable) | yes |  |  |
| `started_at` | string (date-time) | yes |  |  |
| `finished_at` | string (date-time) (nullable) | yes |  |  |

#### `Page_ImportRunOut_`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `items` | array of `ImportRunOut` | yes |  |  |
| `total` | integer | yes |  |  |
| `limit` | integer | yes |  |  |
| `offset` | integer | yes |  |  |
| `page` | integer | no | default `1` |  |
| `size` | integer | no | default `50` |  |

#### `ScannerConnectorOut`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `id` | string (uuid) | yes |  |  |
| `slug` | string | yes |  |  |
| `name` | string | yes |  |  |
| `driver` | string | yes |  |  |
| `base_url` | string (nullable) | yes |  |  |
| `is_enabled` | boolean | yes |  |  |
| `verify_tls` | boolean | yes |  |  |
| `allowed_scans` | array of any | yes |  |  |
| `engagement_id` | string (uuid) (nullable) | yes |  |  |
| `create_assets` | boolean | yes |  |  |
| `close_absent` | boolean | yes |  |  |
| `absence_threshold` | integer | yes |  |  |
| `min_severity` | string (nullable) | yes |  |  |
| `import_inventory` | boolean | yes |  |  |
| `inventory_from_plugin_output` | boolean | yes |  |  |
| `last_sync_at` | string (date-time) (nullable) | yes |  |  |
| `last_error` | string (nullable) | yes |  |  |
| `last_run_id` | string (uuid) (nullable) | yes |  |  |
| `credentials_set` | boolean | no | default `false` |  |
| `is_inert` | boolean | no | default `false` |  |

#### `ScannerConnectorPatch`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `name` | string (nullable) | no | min length 1; max length 200 |  |
| `base_url` | string (nullable) | no | max length 600 |  |
| `credentials` | object (nullable) | no |  |  |
| `is_enabled` | boolean (nullable) | no |  |  |
| `verify_tls` | boolean (nullable) | no |  |  |
| `allowed_scans` | array of string (nullable) | no |  |  |
| `engagement_id` | string (uuid) (nullable) | no |  |  |
| `create_assets` | boolean (nullable) | no |  |  |
| `close_absent` | boolean (nullable) | no |  |  |
| `absence_threshold` | integer (nullable) | no | ≥ 0.0; ≤ 30.0 |  |
| `min_severity` | string (nullable) | no |  |  |
| `import_inventory` | boolean (nullable) | no |  |  |
| `inventory_from_plugin_output` | boolean (nullable) | no |  |  |

#### `ScannerConnectorWrite`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `slug` | string | yes | min length 1; max length 80 |  |
| `name` | string | yes | min length 1; max length 200 |  |
| `driver` | string | yes |  |  |
| `base_url` | string | no | max length 600; default `""` |  |
| `credentials` | object | no |  |  |
| `is_enabled` | boolean | no | default `false` |  |
| `verify_tls` | boolean | no | default `true` |  |
| `allowed_scans` | array of string | no |  |  |
| `engagement_id` | string (uuid) (nullable) | no |  |  |
| `create_assets` | boolean | no | default `false` |  |
| `close_absent` | boolean | no | default `false` |  |
| `absence_threshold` | integer | no | ≥ 0.0; ≤ 30.0; default `0` |  |
| `min_severity` | string (nullable) | no |  |  |
| `import_inventory` | boolean | no | default `true` |  |
| `inventory_from_plugin_output` | boolean | no | default `false` |  |

#### `ScannerSyncRequest`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `scan_ids` | array of string (nullable) | no |  |  |
| `force` | boolean | no | default `false` |  |
| `dry_run` | boolean | no | default `false` |  |

#### `ValidationError`

| Field | Type | Required | Constraints | Description |
|---|---|---|---|---|
| `loc` | array of string \| integer | yes |  |  |
| `msg` | string | yes |  |  |
| `type` | string | yes |  |  |
| `input` | object | no |  |  |
| `ctx` | object | no |  |  |
