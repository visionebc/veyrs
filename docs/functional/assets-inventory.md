---
title: Assets and software inventory
purpose: Describe how VEYRS stores the asset register, business services and installed-software inventory, and how identity resolution decides whether software can ever match a CVE.
scope: Backend behaviour of the `assets` API tag (asset CRUD, business services, bulk ownership, software inventory and coverage). External CMDB feeds are in cmdb-asset-sources.md; team import is in authentication-accounts.md; the per-asset fix plan route is in remediation-fix-plans.md.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/api/v1/assets.py, backend/veyrs/api/v1/vuln_schemas.py, backend/veyrs/services/inventory.py, backend/veyrs/services/versions.py, backend/veyrs/models/assets.py, backend/veyrs/security/scope.py]
related: [functional/README.md, functional/cmdb-asset-sources.md, functional/vulnerability-management.md, functional/risk-engine.md, api/guide.md, DATABASE_SCHEMA.md]
---

# Assets and software inventory

Assets carry the **business context** (criticality, data classification, exposure, environment, owner, team) that the risk engine multiplies CVSS by. Installed software (`asset_products`) is the join that turns a CVE into a finding: CVE -> product -> version range -> installation -> asset. If the software cannot be resolved to a CPE-anchored product, no finding can ever be raised, silently. Most of this module exists to make that failure visible.

Full per-endpoint parameter reference: [`../api/reference/assets.md`](../api/reference/assets.md).

## Vocabulary

Enumerations are validated in `backend/veyrs/api/v1/vuln_schemas.py:166-193` against `backend/veyrs/models/assets.py:23-71`.

| Field | Allowed values |
|-------|----------------|
| `asset_type` | `server`, `vm`, `container`, `kubernetes`, `workstation`, `laptop`, `firewall`, `router`, `switch`, `network_device`, `application`, `database`, `website`, `api`, `cloud_resource`, `saas`, `iot`, `other` |
| `criticality` | `critical`, `high`, `medium`, `low` |
| `data_classification` | `restricted`, `confidential`, `internal`, `public` |
| `exposure` | `internet`, `partner`, `internal`, `isolated` |
| `environment` | `production`, `staging`, `test`, `development`, `dr` |

Weights fed to the risk engine live next to the enums (`models/assets.py:75-79`): for example `exposure` internet 1.0, partner 0.7, internal 0.4, isolated 0.1. See [risk-engine.md](risk-engine.md).

## Team scope on this router

`assets` is in `SCOPED_TAGS` (`backend/veyrs/security/scope.py:52`). A team-restricted principal only sees assets of its teams. Every single-asset route funnels through `_get_asset` (`api/v1/assets.py:37-50`), which answers **404, not 403**, for an asset that is deleted, in another organization or out of scope, so existence is never confirmed. API keys are never narrowed (`security/deps.py`, `Principal.scope` comment).

## Features

### 1. Business services

| Item | Detail |
|------|--------|
| What | A named service the business sells or depends on, with criticality, optional owner/team, `revenue_per_hour` and `currency` (default `CHF`). |
| Why | ITIL-style CMDB grouping; `revenue_per_hour` feeds the Executive risk profile (`models/assets.py:98-100`). |
| How | `create_service` `api/v1/assets.py:115`; `list_services` `api/v1/assets.py:129` (ordered by name, `page`/`size`, `size` max 200). Unique per `(organization_id, name)` (`models/assets.py:86`). |
| Use | `POST /api/v1/assets/services`, `GET /api/v1/assets/services`. Console: Assets, business services. |
| Permissions | `asset:write` (create), `asset:read` (list). |
| Data | `business_services`. |
| Errors | 422 validation (`name` 1-200 chars, `currency` exactly 3 chars, `vuln_schemas.py:24-30`). A duplicate name is **not** handled in code: the unique constraint raises `IntegrityError`, which is a `SQLAlchemyError` and therefore surfaces as the generic 500 `internal_error` envelope (`main.py` handler). |
| Exceptional | No update or delete route exists for business services. List is not team-scoped. |
| Status | Implemented |

### 2. Create, list, read, update, delete assets

| Item | Detail |
|------|--------|
| What | CRUD of the asset register with soft delete. |
| Why | Single source of business context for risk, SLA, ownership and compliance signals. |
| How | `create_asset` `api/v1/assets.py:152`: persists, installs optional `products`, then **correlates immediately** (`correlation.correlate_asset`) so a known-vulnerable host does not wait for the next feed cycle (comment `assets.py:168-169`). `list_assets` `assets.py:195`. `get_asset` `assets.py:476` returns `AssetDetail` with installed products, `open_findings` and `max_risk_score` (`_detail`, `assets.py:~330`). `update_asset` `assets.py:485` applies only fields present in the body (`exclude_unset`); if any risk-relevant field changed (`criticality`, `data_classification`, `exposure`, `environment`, `business_service_id`, `compensating_controls`) every open finding on the asset is re-scored with reason `asset context changed`. `delete_asset` `assets.py:523` sets `deleted_at` and `is_active=false` (soft delete) and returns 204. |
| Use | `POST /api/v1/assets`, `GET /api/v1/assets`, `GET|PATCH|DELETE /api/v1/assets/{asset_id}`. Console: Assets. |
| Permissions | `asset:read`; `asset:write` (create/update); `asset:delete`. |
| Data | `assets`, `asset_products`, `products`, `vendors`, `findings` (read for counts / re-score), `audit_log`. |
| Components | `services/correlation.py`, `services/risk.py` (`rescore_findings`), `services/teams.py` (name resolution), `services/audit.py`. |
| Errors | 404 `asset not found`; 422 on invalid enum value; 401/403 per [API guide](../api/guide.md). |
| Exceptional | `UNIQUE(organization_id, external_id)` on assets (`models/assets.py:107`): a create with a duplicate `external_id` fails with the generic 500 envelope, not 409. Deleting an asset does not close its findings in this code path. `AssetOut` carries `team_name`, `owner_name`, `department_name` filled by one batched lookup per page (`_label`, `assets.py:53-71`). |
| Status | Verified (list and 404 observed live on environment A; see example in the [API guide](../api/guide.md)) |

#### List filters (as implemented)

`GET /api/v1/assets` (`api/v1/assets.py:195-286`):

| Parameter | Semantics |
|-----------|-----------|
| `q` | Case-insensitive substring on `name`, `hostname` or `fqdn`. |
| `asset_type`, `criticality`, `team_id`, `owner_id`, `department_id`, `business_service_id` | Exact match. |
| `exposure`, `environment` | Comma-separated list, "any of". |
| `exclude_exposure`, `exclude_environment` | Comma-separated list, "none of". Separate parameters on purpose so "not production" stays correct if a sixth environment is added. |
| `unowned=true` | Only assets with no team (invisible to team-scoped users). |
| `tag` | Asset `tags` array contains the value. |
| `is_active` | Boolean. |
| `page` (>=1), `size` (1-200, default 50) | Pagination; ordering is fixed `name`. |

The response is `Page[AssetOut]`: `items`, `total`, `limit`, `offset`, `page`, `size`.

### 3. Bulk ownership assignment

| Item | Detail |
|------|--------|
| What | Set `team_id`, `owner_id`, `department_id` on up to 500 assets in one request; fields listed in `clear` are set to null. |
| Why | Ownership drives finding routing and SLA; fixing it asset by asset does not scale. |
| How | `bulk_assign_assets` `api/v1/assets.py:288`. Ownership targets are validated **once** before the loop (`teams_service.validate_team/user/department`), so an unknown team fails the whole request, while unknown or out-of-scope assets are reported per id under `rejected`. A team-restricted principal may only assign into its own teams (403 otherwise), because handing an asset to an unseen team is a one-way door (`assets.py:312-318`). |
| Use | `POST /api/v1/assets/bulk-assign`; response `{changed, rejected, changed_count, rejected_count}`. |
| Permissions | `asset:write`. |
| Data | `assets`, `audit_log` (`asset.bulk_assign`). |
| Errors | 422 `nothing to assign: set a field or list it in clear`; 422 unknown team/user/department; 403 `cannot assign ownership outside your own team scope`. |
| Exceptional | Does not re-score findings. Because ownership is not in the risk-relevant set it does not need to, but assignment of already-open findings is not re-run either. |
| Status | Implemented |

### 4. Installed software on an asset

| Item | Detail |
|------|--------|
| What | Record which product and version is installed on an asset. Two flavours exist. |
| Why | Feeds correlation. |
| How (legacy) | `POST /assets/{asset_id}/products` (`add_products`, `assets.py:540`) takes `[{vendor, product, version, install_path, detected_by}]` and trusts the operator's vendor string (`_install_products`, `assets.py:74-112`), upserting a product by that name. A changed version records an inventory-change note on linked findings (`attribution.note_inventory_change`). Correlation runs afterwards. |
| How (CPE-aware) | `POST /assets/{asset_id}/products/bulk` (`add_products_bulk`, `assets.py:572`) resolves every row through `inventory.install` (see feature 6) and returns a per-row verdict. Options: `detected_by` (default `manual`), `replace`, `correlate` (default true). 1-5000 items (`vuln_schemas.py:88`). |
| Remove | `DELETE /assets/{asset_id}/products/{install_id}` (`remove_product`, `assets.py:556`), 204. No audit record is written for this route. |
| Permissions | `asset:write`. |
| Data | `asset_products` (unique `(asset_id, product_id, version)`, `models/assets.py:176`), `products`, `vendors`, `cpe`. |
| Errors | 404 `asset not found`, 404 `installation not found`; 422 when an item has neither `cpe` nor `product` (`vuln_schemas.py:78-81`). |
| Exceptional | The legacy route can create product rows that no CVE references; prefer the bulk route. |
| Status | Implemented (tests: `tests/test_phase21_inventory_correlation.py`) |

### 5. Re-scan (re-correlate) one asset

| Item | Detail |
|------|--------|
| What | Re-run correlation for one asset against already-ingested CVEs. |
| How | `rescan_asset` `api/v1/assets.py:604` -> `correlation.correlate_asset`; returns the stats dictionary. It does **not** launch a network scan. |
| Use | `POST /api/v1/assets/{asset_id}/rescan`. |
| Permissions | `asset:write`. |
| Errors | 404 `asset not found`. |
| Status | Implemented |

### 6. Identity resolution (CPE anchoring)

| Item | Detail |
|------|--------|
| What | Decide which registry `Product` an inventory row refers to. |
| Why | NVD creates products from CPE tokens (`nginx` is vendor `f5`). An inventory saying vendor `Nginx` creates a second product the CVE join never finds, and the estate looks unaffected (module docstring `services/inventory.py:1-37`). |
| How | `resolve_identity` `services/inventory.py:183`, in order: (1) explicit CPE 2.3 string, no inference; (2) exact vendor+product hit in the registry; (3) product token alone, disambiguated by evidence (the registry product that has CVE applicability rows); (4) curated alias map `PRODUCT_ALIASES` (`inventory.py:58`, for example `nginx` to `f5:nginx`, `apache` to `apache:http_server`); (5) record as given but `matched=false`. Each resolution reports `anchored` (identity certain) and `matched` (CVE applicability rows exist) as separate claims, plus `source` and a note. |
| Versions | `install` (`inventory.py:262`) reduces distro package versions to upstream (`1:9.2p1-2+deb12u10` becomes the upstream version) and keeps the verbatim string in `raw_version`, because a distro backport leaves the upstream version unchanged (comments `inventory.py:310-325`). A versionless install never matches a range (`coverage` reports it). |
| `replace` | Drops installs previously reported by the same `detected_by` that are absent now; scoped so an agent sweep never deletes manually entered rows (`inventory.py:392-401`). |
| Status | Implemented (tests: `tests/test_phase21_inventory_correlation.py`, names include `test_free_text_nginx_resolves_to_the_same_product_as_the_cpe`, `test_replace_is_scoped_to_the_reporting_source`) |

### 7. Dry-run resolution

| Item | Detail |
|------|--------|
| What | Show how an inventory export would be interpreted without committing. |
| How | `inventory_resolve` `api/v1/assets.py:400` resolves every item, builds per-row results and then calls `session.rollback()`. |
| Use | `POST /api/v1/assets/inventory/resolve`, body `{items:[{cpe|vendor+product, version}]}`. Response `{items, matched, results}`. |
| Permissions | `asset:read` (despite being a POST; nothing persists). |
| Errors | Per-row `error` for a malformed CPE or wildcard CPE (`not a CPE 2.3 string`, `CPE names no concrete vendor/product`), not an HTTP error. |
| Status | Implemented |

### 8. Bulk host onboarding

| Item | Detail |
|------|--------|
| What | Create or update up to 2000 hosts together with their software in one call. |
| How | `inventory_import` `api/v1/assets.py:429`. For each host: `inventory.upsert_asset` (`inventory.py:431`) finds by `external_id`, then `fqdn`, then `hostname`, then `name` (in that order, so a rename does not fork an asset), then `inventory.install`, then optional correlation (`correlate`, default true). Findings are created in the same request. |
| Use | `POST /api/v1/assets/inventory/import`. Response includes `hosts`, `assets_created`, `added`, `updated`, `removed`, `anchored`, `matched`, `unmatched`, `findings_created`, `hosts_detail`. |
| Permissions | `asset:write`. |
| Data | `assets`, `asset_products`, `findings`, `audit_log` (`asset.inventory.import` per host). |
| Exceptional | Everything is one transaction: a failure on host 1500 rolls back all hosts. Request size is bounded by the 2000-host and 5000-items-per-host schema limits only. |
| Status | Implemented |

### 9. Coverage and alias self-check

| Item | Detail |
|------|--------|
| What | Separate "nothing is vulnerable" from "nothing is matchable". |
| How | `inventory.coverage` (`inventory.py:487`) walks every installation of the organization and reports `installations`, `matchable`, `unmatched` (no applicability rows, with name suggestions) and `missing_version`, each detail list truncated to 200 entries. `inventory.verify_aliases` (`inventory.py:548`) checks each curated alias against the CPE data actually present. |
| Use | `GET /api/v1/assets/inventory/coverage`, `GET /api/v1/assets/inventory/aliases`. |
| Permissions | `asset:read`. |
| Exceptional | Since 0.41.0 `coverage` counts in SQL (one aggregate with an indexed `EXISTS` per installation) and fetches at most 200 detail rows per list, ordered by asset, vendor and product; before, it loaded every `asset_products` row and ran one applicability query per row. These two routes are declared before `/{asset_id}` deliberately (`assets.py:365-372`); reordering them breaks them with a UUID parse error. |
| Status | Verified for `coverage` (observed live: 4246 installations, 221 matchable, 4025 unmatched; the call was the slow one in a batch of GETs) |

## Errors common to the module

| Code | Condition |
|------|-----------|
| 401 | Missing or invalid credentials. |
| 403 | Missing permission; restricted team scope assigning outside scope. |
| 404 | Asset absent, soft-deleted, other tenant or out of team scope. |
| 422 | Enum validation, empty `bulk-assign`, bad CPE rows. |
| 500 | `internal_error` envelope for unhandled `SQLAlchemyError` (for example unique violations that are not pre-checked). |

## Tests

`tests/test_phase21_inventory_correlation.py`, `tests/test_phase34_inventory_and_scanning.py`, `tests/test_phase37_estate_lens.py`, `tests/test_phase10_hardening.py` exercise this module.
