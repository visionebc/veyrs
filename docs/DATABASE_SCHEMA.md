<!-- GENERATED FILE - do not edit by hand.
     Regenerate with: python3 scripts/gen-schema-doc.py
     Guarded by:      tests/test_docs_schema_is_current.py -->

# Database schema reference

Every table VEYRS creates, generated from the models that create them. The
prose manual - tenancy, RLS, the design decisions, operations - is
[DATABASE.md](DATABASE.md); this file is the reference you look a column up in.

**How to read the isolation column:**

| Marker | Meaning |
|---|---|
| **strict** | `ENABLE` + `FORCE ROW LEVEL SECURITY`, policy `veyrs_tenant_isolation`. A query with no tenant bound returns zero rows. |
| **pre-auth** | Same policy, permissive while `veyrs.current_org` is unset. Only the four tables a login must read before the tenant is known. |
| **global** | Shared reference data (the CVE catalogue and friends). Not tenant-owned, no policy. |
| **app-only** | Carries a nullable `organization_id` (a platform-level row is legal), so isolation is enforced by the application layer alone. |

Legend for column flags: `PK` primary key, `FK` foreign key (target shown),
`NOT NULL` required, `UQ` unique, `IDX` indexed, `enc` Fernet-encrypted at rest.


**87 tables**: 66 strictly isolated, 4 pre-auth, 15 global, 2 application-enforced.

The policy body, identical on every RLS table:

```sql
-- strict
USING (organization_id::text = NULLIF(current_setting('veyrs.current_org', true), ''))
-- pre-auth
USING (organization_id::text = COALESCE(NULLIF(current_setting('veyrs.current_org', true), ''), organization_id::text))
```

## Contents

- [Identity and tenancy](#identity-and-tenancy) - 9 tables
- [Intelligence catalogues](#intelligence-catalogues) - 12 tables
- [Assets](#assets) - 4 tables
- [CMDB and asset sources](#cmdb-and-asset-sources) - 3 tables
- [Vulnerabilities and findings](#vulnerabilities-and-findings) - 6 tables
- [Ticketing (ITSM)](#ticketing-itsm) - 5 tables
- [SLA and escalation](#sla-and-escalation) - 3 tables
- [Risk register](#risk-register) - 4 tables
- [Workflow and notifications](#workflow-and-notifications) - 6 tables
- [Compliance](#compliance) - 7 tables
- [Knowledge and documents](#knowledge-and-documents) - 6 tables
- [Integrations](#integrations) - 3 tables
- [Engagements](#engagements) - 7 tables
- [AI gateway](#ai-gateway) - 4 tables
- [Execution agents](#execution-agents) - 4 tables
- [Audit trails](#audit-trails) - 3 tables
- [Saved views](#saved-views) - 1 tables

## Identity and tenancy

Organizations, users, roles, teams, API keys.

Declared in `backend/veyrs/models/tenancy.py`.

#### `api_keys`

*Isolation:* **pre-auth**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `name` | `VARCHAR(160)` | NOT NULL |
| `prefix` | `VARCHAR(16)` | NOT NULL, UQ |
| `key_hash` | `VARCHAR(255)` | NOT NULL |
| `created_by_id` | `UUID` | FK -> `users.id` |
| `scopes` | `JSONB` | NOT NULL |
| `expires_at` | `DATETIME` |  |
| `last_used_at` | `DATETIME` |  |
| `revoked_at` | `DATETIME` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

#### `departments`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `name` | `VARCHAR(160)` | NOT NULL |
| `description` | `TEXT` |  |
| `manager_id` | `UUID` | FK -> `users.id` |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_departments_organization_id` (organization_id, name)

#### `organizations`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `name` | `VARCHAR(200)` | NOT NULL |
| `slug` | `VARCHAR(80)` | NOT NULL, UQ |
| `invoicing_code` | `VARCHAR(40)` | IDX |
| `default_locale` | `VARCHAR(5)` | NOT NULL |
| `timezone` | `VARCHAR(64)` | NOT NULL |
| `is_active` | `BOOLEAN` | NOT NULL |
| `settings` | `JSONB` | NOT NULL |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |
| `deleted_at` | `DATETIME` |  |

#### `refresh_tokens`

*Isolation:* **pre-auth**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `user_id` | `UUID` | FK -> `users.id`, NOT NULL, IDX |
| `token_hash` | `VARCHAR(255)` | NOT NULL, UQ |
| `family_id` | `UUID` | NOT NULL, IDX |
| `expires_at` | `DATETIME` | NOT NULL |
| `revoked_at` | `DATETIME` |  |
| `user_agent` | `VARCHAR(255)` |  |
| `ip_address` | `VARCHAR(64)` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

#### `roles`

*Isolation:* **app-only**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `organization_id` | `UUID` | FK -> `organizations.id`, IDX |
| `name` | `VARCHAR(120)` | NOT NULL |
| `slug` | `VARCHAR(80)` | NOT NULL |
| `description` | `TEXT` |  |
| `is_builtin` | `BOOLEAN` | NOT NULL |
| `permissions` | `JSONB` | NOT NULL |
| `attributes` | `JSONB` | NOT NULL |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_roles_organization_id` (organization_id, slug)

#### `team_members`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `team_id` | `UUID` | FK -> `teams.id`, NOT NULL, IDX |
| `user_id` | `UUID` | FK -> `users.id`, NOT NULL, IDX |
| `role_in_team` | `VARCHAR(40)` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_team_members_team_id` (team_id, user_id)

#### `teams`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `name` | `VARCHAR(160)` | NOT NULL |
| `slug` | `VARCHAR(80)` | NOT NULL |
| `description` | `TEXT` |  |
| `department_id` | `UUID` | FK -> `departments.id` |
| `manager_id` | `UUID` | FK -> `users.id` |
| `email` | `VARCHAR(255)` |  |
| `escalation_chain` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_teams_organization_id` (organization_id, slug)

#### `user_roles`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `user_id` | `UUID` | FK -> `users.id`, NOT NULL, IDX |
| `role_id` | `UUID` | FK -> `roles.id`, NOT NULL, IDX |
| `team_id` | `UUID` | FK -> `teams.id` |
| `origin` | `VARCHAR(16)` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_user_roles_user_id` (user_id, role_id, team_id)

#### `users`

*Isolation:* **pre-auth**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `email` | `VARCHAR(255)` | NOT NULL |
| `username` | `VARCHAR(150)` |  |
| `full_name` | `VARCHAR(200)` | NOT NULL |
| `password_hash` | `VARCHAR(255)` |  |
| `is_active` | `BOOLEAN` | NOT NULL |
| `is_superuser` | `BOOLEAN` | NOT NULL |
| `locale` | `VARCHAR(5)` | NOT NULL |
| `job_title` | `VARCHAR(160)` |  |
| `department_id` | `UUID` | FK -> `departments.id` |
| `oidc_subject` | `VARCHAR(255)` | IDX |
| `ldap_dn` | `VARCHAR(512)` | IDX |
| `mfa_enabled` | `BOOLEAN` | NOT NULL |
| `mfa_secret` | `VARCHAR(255)` |  |
| `mfa_last_step` | `BIGINT` |  |
| `last_login_at` | `DATETIME` |  |
| `failed_logins` | `INTEGER` | NOT NULL |
| `locked_until` | `DATETIME` |  |
| `attributes` | `JSONB` | NOT NULL |
| `preferences` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |
| `deleted_at` | `DATETIME` |  |

*Composite indexes:* `ix_users_org_active` (organization_id, is_active)

*Composite unique:* `uq_users_organization_id` (organization_id, email), `uq_users_organization_id_username` (organization_id, username)

## Intelligence catalogues

CVE/CWE/CPE, EPSS, CISA KEV, vendors and products. Global, not tenant-scoped.

Declared in `backend/veyrs/models/intelligence.py`.

#### `cpe`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `cpe23` | `VARCHAR(600)` | NOT NULL, UQ |
| `part` | `VARCHAR(2)` | NOT NULL |
| `vendor` | `VARCHAR(200)` | NOT NULL, IDX |
| `product` | `VARCHAR(300)` | NOT NULL, IDX |
| `version` | `VARCHAR(120)` | NOT NULL |
| `update` | `VARCHAR(120)` | NOT NULL |
| `edition` | `VARCHAR(120)` | NOT NULL |
| `language` | `VARCHAR(40)` | NOT NULL |
| `sw_edition` | `VARCHAR(120)` | NOT NULL |
| `target_sw` | `VARCHAR(120)` | NOT NULL |
| `target_hw` | `VARCHAR(120)` | NOT NULL |
| `other` | `VARCHAR(120)` | NOT NULL |
| `title` | `VARCHAR(500)` |  |
| `deprecated` | `BOOLEAN` | NOT NULL |
| `product_id` | `UUID` | FK -> `products.id`, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

#### `cve`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `id` | `VARCHAR(30)` | PK |
| `source` | `VARCHAR(40)` | NOT NULL |
| `state` | `VARCHAR(20)` | NOT NULL |
| `title` | `VARCHAR(500)` |  |
| `description` | `TEXT` |  |
| `published_at` | `DATETIME` |  |
| `modified_at` | `DATETIME` |  |
| `first_seen_at` | `DATETIME` |  |
| `last_seen_at` | `DATETIME` |  |
| `cvss2_vector` | `VARCHAR(200)` |  |
| `cvss2_base_score` | `FLOAT` |  |
| `cvss3_vector` | `VARCHAR(200)` |  |
| `cvss3_base_score` | `FLOAT` |  |
| `cvss3_severity` | `VARCHAR(20)` |  |
| `cvss3_version` | `VARCHAR(5)` |  |
| `cvss4_vector` | `VARCHAR(400)` |  |
| `cvss4_score` | `FLOAT` |  |
| `cvss4_severity` | `VARCHAR(20)` |  |
| `cvss4_nomenclature` | `VARCHAR(10)` |  |
| `cwe_ids` | `JSONB` | NOT NULL |
| `affected` | `JSONB` | NOT NULL |
| `fixed_versions` | `JSONB` | NOT NULL |
| `exploit_known` | `BOOLEAN` | NOT NULL |
| `exploit_maturity` | `VARCHAR(20)` |  |
| `exploit_references` | `JSONB` | NOT NULL |
| `epss_score` | `FLOAT` | IDX |
| `epss_percentile` | `FLOAT` |  |
| `kev` | `BOOLEAN` | NOT NULL, IDX |
| `kev_due_date` | `DATE` |  |
| `raw` | `JSONB` | NOT NULL |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

#### `cve_cpe_match`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `cve_id` | `VARCHAR(30)` | FK -> `cve.id`, NOT NULL |
| `cpe23` | `VARCHAR(600)` | NOT NULL |
| `product_id` | `UUID` | FK -> `products.id` |
| `vulnerable` | `BOOLEAN` | NOT NULL |
| `version_start_including` | `VARCHAR(120)` |  |
| `version_start_excluding` | `VARCHAR(120)` |  |
| `version_end_including` | `VARCHAR(120)` |  |
| `version_end_excluding` | `VARCHAR(120)` |  |

#### `cve_references`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `cve_id` | `VARCHAR(30)` | FK -> `cve.id`, NOT NULL |
| `url` | `VARCHAR(1000)` | NOT NULL |
| `source` | `VARCHAR(120)` |  |
| `tags` | `JSONB` | NOT NULL |

#### `cwe`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `id` | `VARCHAR(20)` | PK |
| `name` | `VARCHAR(400)` | NOT NULL |
| `description` | `TEXT` |  |
| `abstraction` | `VARCHAR(40)` |  |
| `status` | `VARCHAR(40)` |  |
| `categories` | `JSONB` | NOT NULL |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

#### `epss_history`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `cve_id` | `VARCHAR(30)` | FK -> `cve.id`, NOT NULL |
| `score` | `FLOAT` | NOT NULL |
| `percentile` | `FLOAT` | NOT NULL |
| `scored_on` | `DATE` | NOT NULL |

*Composite indexes:* `ix_epss_history_cve_date` (cve_id, scored_on)

*Composite unique:* `uq_epss_history_cve_id` (cve_id, scored_on)

#### `epss_scores`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `cve_id` | `VARCHAR(30)` | PK, FK -> `cve.id` |
| `score` | `FLOAT` | NOT NULL, IDX |
| `percentile` | `FLOAT` | NOT NULL |
| `model_version` | `VARCHAR(40)` |  |
| `scored_on` | `DATE` | NOT NULL |
| `updated_at` | `DATETIME` | NOT NULL |

#### `feed_runs`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `feed` | `VARCHAR(40)` | NOT NULL |
| `started_at` | `DATETIME` | NOT NULL |
| `finished_at` | `DATETIME` |  |
| `status` | `VARCHAR(20)` | NOT NULL |
| `records_seen` | `INTEGER` | NOT NULL |
| `records_created` | `INTEGER` | NOT NULL |
| `records_updated` | `INTEGER` | NOT NULL |
| `watermark` | `VARCHAR(120)` |  |
| `error` | `TEXT` |  |
| `details` | `JSONB` | NOT NULL |

*Composite indexes:* `ix_feed_runs_feed_time` (feed, started_at)

#### `kev_entries`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `cve_id` | `VARCHAR(30)` | PK, FK -> `cve.id` |
| `vendor_project` | `VARCHAR(200)` |  |
| `product` | `VARCHAR(300)` |  |
| `vulnerability_name` | `VARCHAR(500)` |  |
| `short_description` | `TEXT` |  |
| `required_action` | `TEXT` |  |
| `date_added` | `DATE` | IDX |
| `due_date` | `DATE` | IDX |
| `known_ransomware` | `BOOLEAN` | NOT NULL |
| `notes` | `TEXT` |  |
| `imported_at` | `DATETIME` | NOT NULL |

#### `product_versions`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `product_id` | `UUID` | FK -> `products.id`, NOT NULL, IDX |
| `version` | `VARCHAR(120)` | NOT NULL |
| `version_key` | `VARCHAR(200)` | NOT NULL, IDX |
| `release_date` | `DATE` |  |
| `eol_date` | `DATE` |  |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_product_versions_lookup` (product_id, version)

*Composite unique:* `uq_product_versions_product_id` (product_id, version)

#### `products`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `vendor_id` | `UUID` | FK -> `vendors.id`, NOT NULL, IDX |
| `name` | `VARCHAR(300)` | NOT NULL, IDX |
| `normalized_name` | `VARCHAR(300)` | NOT NULL |
| `product_type` | `VARCHAR(40)` | NOT NULL |
| `cpe_part` | `VARCHAR(2)` | NOT NULL |
| `eol_date` | `DATE` |  |
| `default_team_hint` | `VARCHAR(80)` |  |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_products_vendor_id` (vendor_id, normalized_name)

#### `vendors`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `name` | `VARCHAR(200)` | NOT NULL, UQ |
| `normalized_name` | `VARCHAR(200)` | NOT NULL, IDX |
| `homepage` | `VARCHAR(400)` |  |
| `advisory_url` | `VARCHAR(400)` |  |
| `default_team_hint` | `VARCHAR(80)` |  |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

## Assets

The estate: assets, groups, business services, installed software.

Declared in `backend/veyrs/models/assets.py`.

#### `asset_groups`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `name` | `VARCHAR(200)` | NOT NULL |
| `description` | `TEXT` |  |
| `criteria` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_asset_groups_organization_id` (organization_id, name)

#### `asset_products`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `asset_id` | `UUID` | FK -> `assets.id`, NOT NULL, IDX |
| `product_id` | `UUID` | FK -> `products.id`, NOT NULL, IDX |
| `version` | `VARCHAR(120)` |  |
| `version_key` | `VARCHAR(200)` |  |
| `raw_version` | `VARCHAR(200)` |  |
| `cpe23` | `VARCHAR(600)` |  |
| `install_path` | `VARCHAR(500)` |  |
| `detected_by` | `VARCHAR(40)` | NOT NULL |
| `last_seen_at` | `DATETIME` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_asset_products_product` (product_id, version_key)

*Composite unique:* `uq_asset_products_asset_id` (asset_id, product_id, version)

#### `assets`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `external_id` | `VARCHAR(200)` |  |
| `name` | `VARCHAR(255)` | NOT NULL |
| `asset_type` | `VARCHAR(30)` | NOT NULL |
| `hostname` | `VARCHAR(255)` |  |
| `fqdn` | `VARCHAR(400)` |  |
| `ip_addresses` | `JSONB` | NOT NULL |
| `mac_addresses` | `JSONB` | NOT NULL |
| `operating_system` | `VARCHAR(200)` |  |
| `os_version` | `VARCHAR(120)` |  |
| `owner_id` | `UUID` | FK -> `users.id`, IDX |
| `team_id` | `UUID` | FK -> `teams.id`, IDX |
| `department_id` | `UUID` | FK -> `departments.id` |
| `business_service_id` | `UUID` | FK -> `business_services.id` |
| `criticality` | `VARCHAR(20)` | NOT NULL |
| `data_classification` | `VARCHAR(20)` | NOT NULL |
| `exposure` | `VARCHAR(20)` | NOT NULL |
| `environment` | `VARCHAR(20)` | NOT NULL |
| `location` | `VARCHAR(200)` |  |
| `compensating_controls` | `JSONB` | NOT NULL |
| `tags` | `JSONB` | NOT NULL |
| `attributes` | `JSONB` | NOT NULL |
| `source` | `VARCHAR(40)` | NOT NULL |
| `first_seen_at` | `DATETIME` |  |
| `last_seen_at` | `DATETIME` |  |
| `decommissioned_at` | `DATE` |  |
| `is_active` | `BOOLEAN` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |
| `deleted_at` | `DATETIME` |  |

*Composite indexes:* `ix_assets_hostname` (organization_id, hostname), `ix_assets_org_criticality` (organization_id, criticality), `ix_assets_org_exposure` (organization_id, exposure), `ix_assets_org_type` (organization_id, asset_type)

*Composite unique:* `uq_assets_organization_id` (organization_id, external_id)

#### `business_services`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `name` | `VARCHAR(200)` | NOT NULL |
| `description` | `TEXT` |  |
| `criticality` | `VARCHAR(20)` | NOT NULL |
| `owner_id` | `UUID` | FK -> `users.id` |
| `team_id` | `UUID` | FK -> `teams.id` |
| `revenue_per_hour` | `INTEGER` |  |
| `currency` | `VARCHAR(3)` | NOT NULL |
| `sla_tier` | `VARCHAR(40)` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_business_services_organization_id` (organization_id, name)

## CMDB and asset sources

External inventory sources and their staged records.

Declared in `backend/veyrs/models/cmdb.py`.

#### `asset_source_records`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `source_id` | `UUID` | FK -> `asset_sources.id`, NOT NULL, IDX |
| `external_key` | `VARCHAR(300)` | NOT NULL |
| `identity_key` | `VARCHAR(300)` |  |
| `match_keys` | `JSONB` | NOT NULL |
| `asset_id` | `UUID` | FK -> `assets.id` |
| `match_status` | `VARCHAR(20)` | NOT NULL |
| `matched_by` | `VARCHAR(40)` |  |
| `name` | `VARCHAR(255)` |  |
| `hostname` | `VARCHAR(255)` |  |
| `fqdn` | `VARCHAR(400)` |  |
| `serial` | `VARCHAR(200)` |  |
| `asset_type` | `VARCHAR(30)` |  |
| `operating_system` | `VARCHAR(200)` |  |
| `os_version` | `VARCHAR(120)` |  |
| `environment` | `VARCHAR(20)` |  |
| `criticality` | `VARCHAR(20)` |  |
| `exposure` | `VARCHAR(20)` |  |
| `data_classification` | `VARCHAR(20)` |  |
| `location` | `VARCHAR(200)` |  |
| `owner_label` | `VARCHAR(200)` |  |
| `team_label` | `VARCHAR(200)` |  |
| `status_label` | `VARCHAR(80)` |  |
| `ip_addresses` | `JSONB` | NOT NULL |
| `mac_addresses` | `JSONB` | NOT NULL |
| `tags` | `JSONB` | NOT NULL |
| `extra` | `JSONB` | NOT NULL |
| `raw` | `JSONB` | NOT NULL |
| `content_hash` | `VARCHAR(64)` |  |
| `first_seen_at` | `DATETIME` |  |
| `last_seen_at` | `DATETIME` |  |
| `last_run_id` | `UUID` | FK -> `asset_source_runs.id` |
| `is_absent` | `BOOLEAN` | NOT NULL |
| `absent_since` | `DATETIME` |  |
| `promoted_at` | `DATETIME` |  |
| `promoted_by_id` | `UUID` | FK -> `users.id` |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_asset_source_records_asset` (organization_id, asset_id), `ix_asset_source_records_identity` (organization_id, identity_key)

*Composite unique:* `uq_asset_source_records_organization_id` (organization_id, source_id, external_key)

#### `asset_source_runs`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `source_id` | `UUID` | FK -> `asset_sources.id`, NOT NULL, IDX |
| `status` | `VARCHAR(20)` | NOT NULL |
| `trigger` | `VARCHAR(20)` | NOT NULL |
| `dry_run` | `BOOLEAN` | NOT NULL |
| `filename` | `VARCHAR(400)` |  |
| `content_hash` | `VARCHAR(64)` | IDX |
| `size_bytes` | `INTEGER` | NOT NULL |
| `started_at` | `DATETIME` | NOT NULL |
| `finished_at` | `DATETIME` |  |
| `records_seen` | `INTEGER` | NOT NULL |
| `records_created` | `INTEGER` | NOT NULL |
| `records_updated` | `INTEGER` | NOT NULL |
| `records_unchanged` | `INTEGER` | NOT NULL |
| `records_rejected` | `INTEGER` | NOT NULL |
| `assets_matched` | `INTEGER` | NOT NULL |
| `assets_unmatched` | `INTEGER` | NOT NULL |
| `assets_promoted` | `INTEGER` | NOT NULL |
| `assets_created` | `INTEGER` | NOT NULL |
| `records_absent` | `INTEGER` | NOT NULL |
| `reject_reasons` | `JSONB` | NOT NULL |
| `reject_samples` | `JSONB` | NOT NULL |
| `error` | `TEXT` |  |
| `started_by_id` | `UUID` | FK -> `users.id` |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_asset_source_runs_org_started` (organization_id, started_at)

#### `asset_sources`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `slug` | `VARCHAR(80)` | NOT NULL |
| `name` | `VARCHAR(200)` | NOT NULL |
| `driver` | `VARCHAR(40)` | NOT NULL |
| `description` | `TEXT` |  |
| `base_url` | `VARCHAR(600)` |  |
| `is_enabled` | `BOOLEAN` | NOT NULL |
| `verify_tls` | `BOOLEAN` | NOT NULL |
| `credentials_enc` | `TEXT` | enc |
| `collections` | `JSONB` | NOT NULL |
| `record_path` | `VARCHAR(200)` |  |
| `field_map` | `JSONB` | NOT NULL |
| `value_maps` | `JSONB` | NOT NULL |
| `include_fields` | `JSONB` | NOT NULL |
| `match_order` | `JSONB` | NOT NULL |
| `auto_promote` | `BOOLEAN` | NOT NULL |
| `promote_creates_assets` | `BOOLEAN` | NOT NULL |
| `priority` | `INTEGER` | NOT NULL |
| `sync_state` | `JSONB` | NOT NULL |
| `last_sync_at` | `DATETIME` |  |
| `last_error` | `TEXT` |  |
| `last_run_id` | `UUID` | FK -> `asset_source_runs.id` |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_asset_sources_organization_id` (organization_id, slug)

## Vulnerabilities and findings

The tenant's view of a CVE, and that CVE on one asset at one location.

Declared in `backend/veyrs/models/vulnerability.py`.

#### `assignment_rules`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `name` | `VARCHAR(200)` | NOT NULL |
| `description` | `TEXT` |  |
| `priority` | `INTEGER` | NOT NULL |
| `is_enabled` | `BOOLEAN` | NOT NULL |
| `conditions` | `JSONB` | NOT NULL |
| `team_id` | `UUID` | FK -> `teams.id` |
| `user_id` | `UUID` | FK -> `users.id` |
| `match_count` | `INTEGER` | NOT NULL |
| `last_matched_at` | `DATETIME` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_assignment_rules_org_priority` (organization_id, priority)

#### `finding_events`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `finding_id` | `UUID` | FK -> `findings.id`, NOT NULL |
| `created_at` | `DATETIME` | NOT NULL |
| `actor_id` | `UUID` | FK -> `users.id` |
| `actor_label` | `VARCHAR(200)` | NOT NULL |
| `event` | `VARCHAR(60)` | NOT NULL |
| `from_state` | `VARCHAR(30)` |  |
| `to_state` | `VARCHAR(30)` |  |
| `note` | `TEXT` |  |
| `details` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite indexes:* `ix_finding_events_finding` (finding_id, created_at)

#### `findings`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `vulnerability_id` | `UUID` | FK -> `vulnerabilities.id`, NOT NULL, IDX |
| `asset_id` | `UUID` | FK -> `assets.id`, NOT NULL |
| `asset_product_id` | `UUID` | FK -> `asset_products.id` |
| `dedupe_key` | `VARCHAR(64)` | NOT NULL |
| `dedupe_algorithm` | `VARCHAR(40)` | NOT NULL |
| `unique_id_from_tool` | `VARCHAR(255)` |  |
| `state` | `VARCHAR(30)` | NOT NULL |
| `severity` | `VARCHAR(20)` |  |
| `title` | `VARCHAR(500)` | NOT NULL |
| `detail` | `TEXT` |  |
| `recommendation` | `TEXT` |  |
| `port` | `INTEGER` |  |
| `protocol` | `VARCHAR(10)` |  |
| `path` | `VARCHAR(500)` |  |
| `evidence` | `JSONB` | NOT NULL |
| `cvss_vector` | `VARCHAR(400)` |  |
| `cvss_score` | `FLOAT` |  |
| `epss_score` | `FLOAT` |  |
| `kev` | `BOOLEAN` | NOT NULL |
| `risk_score` | `FLOAT` | IDX |
| `risk_level` | `VARCHAR(20)` |  |
| `technical_risk` | `FLOAT` |  |
| `exploitability_risk` | `FLOAT` |  |
| `business_risk` | `FLOAT` |  |
| `exposure_risk` | `FLOAT` |  |
| `risk_explanation` | `JSONB` | NOT NULL |
| `risk_profile_id` | `UUID` | FK -> `risk_profiles.id` |
| `assigned_team_id` | `UUID` | FK -> `teams.id` |
| `assigned_user_id` | `UUID` | FK -> `users.id` |
| `assignment_reason` | `VARCHAR(300)` |  |
| `sla_policy_id` | `UUID` | FK -> `sla_policies.id` |
| `sla_due_at` | `DATETIME` |  |
| `sla_breached` | `BOOLEAN` | NOT NULL |
| `sla_breached_at` | `DATETIME` |  |
| `escalation_level` | `INTEGER` | NOT NULL |
| `escalated_at` | `DATETIME` |  |
| `detected_at` | `DATETIME` | NOT NULL |
| `first_seen_at` | `DATETIME` |  |
| `last_seen_at` | `DATETIME` |  |
| `triaged_at` | `DATETIME` |  |
| `assigned_at` | `DATETIME` |  |
| `remediated_at` | `DATETIME` |  |
| `verified_at` | `DATETIME` |  |
| `closed_at` | `DATETIME` |  |
| `accepted_by_id` | `UUID` | FK -> `users.id` |
| `accepted_reason` | `TEXT` |  |
| `accepted_until` | `DATE` |  |
| `scanner` | `VARCHAR(60)` |  |
| `scanner_plugin_id` | `VARCHAR(80)` |  |
| `import_run_id` | `UUID` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_findings_due` (organization_id, sla_due_at), `ix_findings_org_risk` (organization_id, risk_score), `ix_findings_org_state` (organization_id, state), `ix_findings_team` (organization_id, assigned_team_id, state), `ix_findings_unique_id` (organization_id, unique_id_from_tool)

*Composite unique:* `uq_findings_organization_id` (organization_id, asset_id, dedupe_key)

#### `risk_profiles`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `name` | `VARCHAR(160)` | NOT NULL |
| `slug` | `VARCHAR(80)` | NOT NULL |
| `description` | `TEXT` |  |
| `is_default` | `BOOLEAN` | NOT NULL |
| `is_builtin` | `BOOLEAN` | NOT NULL |
| `weights` | `JSONB` | NOT NULL |
| `options` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_risk_profiles_organization_id` (organization_id, slug)

#### `risk_score_history`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `finding_id` | `UUID` | FK -> `findings.id`, NOT NULL |
| `created_at` | `DATETIME` | NOT NULL |
| `risk_profile_id` | `UUID` |  |
| `risk_score` | `FLOAT` | NOT NULL |
| `risk_level` | `VARCHAR(20)` | NOT NULL |
| `technical_risk` | `FLOAT` |  |
| `exploitability_risk` | `FLOAT` |  |
| `business_risk` | `FLOAT` |  |
| `exposure_risk` | `FLOAT` |  |
| `reason` | `VARCHAR(200)` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite indexes:* `ix_risk_history_finding` (finding_id, created_at)

#### `vulnerabilities`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `cve_id` | `VARCHAR(30)` | FK -> `cve.id`, IDX |
| `internal_ref` | `VARCHAR(80)` |  |
| `title` | `VARCHAR(500)` | NOT NULL |
| `description` | `TEXT` |  |
| `source` | `VARCHAR(40)` | NOT NULL |
| `state` | `VARCHAR(30)` | NOT NULL |
| `severity` | `VARCHAR(20)` | IDX |
| `cvss_vector` | `VARCHAR(400)` |  |
| `cvss_version` | `VARCHAR(5)` |  |
| `cvss_score` | `FLOAT` |  |
| `epss_score` | `FLOAT` |  |
| `epss_percentile` | `FLOAT` |  |
| `kev` | `BOOLEAN` | NOT NULL |
| `risk_score` | `FLOAT` |  |
| `risk_level` | `VARCHAR(20)` |  |
| `triaged_by_id` | `UUID` | FK -> `users.id` |
| `triaged_at` | `DATETIME` |  |
| `triage_notes` | `TEXT` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_vulns_org_risk` (organization_id, risk_score), `ix_vulns_org_state` (organization_id, state)

*Composite unique:* `uq_vulnerabilities_organization_id` (organization_id, cve_id, internal_ref)

## Ticketing (ITSM)

Internal queue, counters, and external ITSM connectors.

Declared in `backend/veyrs/models/ticketing.py`.

#### `itsm_connectors`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `slug` | `VARCHAR(80)` | NOT NULL |
| `name` | `VARCHAR(200)` | NOT NULL |
| `system` | `VARCHAR(40)` | NOT NULL |
| `base_url` | `VARCHAR(600)` |  |
| `is_enabled` | `BOOLEAN` | NOT NULL |
| `credentials_enc` | `TEXT` | enc |
| `ticket_types` | `JSONB` | NOT NULL |
| `field_mapping` | `JSONB` | NOT NULL |
| `last_sync_at` | `DATETIME` |  |
| `last_error` | `TEXT` |  |
| `inbound_enabled` | `BOOLEAN` | NOT NULL |
| `inbound_secret_enc` | `TEXT` | enc |
| `inbound_transitions` | `JSONB` | NOT NULL |
| `last_inbound_at` | `DATETIME` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_itsm_connectors_organization_id` (organization_id, slug)

#### `ticket_comments`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `ticket_id` | `UUID` | FK -> `tickets.id`, NOT NULL |
| `created_at` | `DATETIME` | NOT NULL |
| `author_id` | `UUID` | FK -> `users.id` |
| `author_label` | `VARCHAR(200)` | NOT NULL |
| `body` | `TEXT` | NOT NULL |
| `is_internal` | `BOOLEAN` | NOT NULL |
| `external_key` | `VARCHAR(120)` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite indexes:* `ix_ticket_comments_ticket` (ticket_id, created_at)

#### `ticket_counters`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `ticket_type` | `VARCHAR(30)` | NOT NULL |
| `last_value` | `INTEGER` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite unique:* `uq_ticket_counters_organization_id` (organization_id, ticket_type)

#### `ticket_events`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `ticket_id` | `UUID` | FK -> `tickets.id`, NOT NULL |
| `created_at` | `DATETIME` | NOT NULL |
| `actor_id` | `UUID` | FK -> `users.id` |
| `actor_label` | `VARCHAR(200)` | NOT NULL |
| `event` | `VARCHAR(60)` | NOT NULL |
| `details` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite indexes:* `ix_ticket_events_ticket` (ticket_id, created_at)

#### `tickets`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `reference` | `VARCHAR(40)` | NOT NULL |
| `ticket_type` | `VARCHAR(30)` | NOT NULL |
| `state` | `VARCHAR(30)` | NOT NULL |
| `priority` | `VARCHAR(20)` | NOT NULL |
| `title` | `VARCHAR(500)` | NOT NULL |
| `description` | `TEXT` |  |
| `resolution` | `TEXT` |  |
| `assigned_team_id` | `UUID` | FK -> `teams.id` |
| `assigned_user_id` | `UUID` | FK -> `users.id` |
| `requested_by_id` | `UUID` | FK -> `users.id` |
| `approver_id` | `UUID` | FK -> `users.id` |
| `approved_at` | `DATETIME` |  |
| `approval_note` | `TEXT` |  |
| `finding_id` | `UUID` | FK -> `findings.id`, IDX |
| `vulnerability_id` | `UUID` | FK -> `vulnerabilities.id` |
| `asset_id` | `UUID` | FK -> `assets.id` |
| `business_service_id` | `UUID` | FK -> `business_services.id` |
| `parent_id` | `UUID` | FK -> `tickets.id` |
| `change_type` | `VARCHAR(20)` |  |
| `risk_of_change` | `VARCHAR(20)` |  |
| `scheduled_start` | `DATETIME` |  |
| `scheduled_end` | `DATETIME` |  |
| `implementation_plan` | `TEXT` |  |
| `rollback_plan` | `TEXT` |  |
| `due_at` | `DATETIME` |  |
| `sla_breached` | `BOOLEAN` | NOT NULL |
| `resolved_at` | `DATETIME` |  |
| `closed_at` | `DATETIME` |  |
| `external_system` | `VARCHAR(40)` |  |
| `external_key` | `VARCHAR(120)` |  |
| `external_url` | `VARCHAR(600)` |  |
| `external_state` | `VARCHAR(60)` |  |
| `external_synced_at` | `DATETIME` |  |
| `sync_direction` | `VARCHAR(20)` | NOT NULL |
| `labels` | `JSONB` | NOT NULL |
| `attributes` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_tickets_external` (external_system, external_key), `ix_tickets_org_state` (organization_id, state), `ix_tickets_org_type` (organization_id, ticket_type)

*Composite unique:* `uq_tickets_organization_id` (organization_id, reference)

## SLA and escalation

Due dates, breach events and escalation chains.

Declared in `backend/veyrs/models/sla.py`.

#### `escalation_policies`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `name` | `VARCHAR(200)` | NOT NULL |
| `slug` | `VARCHAR(80)` | NOT NULL |
| `description` | `TEXT` |  |
| `is_enabled` | `BOOLEAN` | NOT NULL |
| `is_default` | `BOOLEAN` | NOT NULL |
| `levels` | `JSONB` | NOT NULL |
| `targets` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_escalation_policies_organization_id` (organization_id, slug)

#### `sla_events`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `finding_id` | `UUID` | FK -> `findings.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL |
| `event` | `VARCHAR(40)` | NOT NULL |
| `sla_policy_id` | `UUID` |  |
| `escalation_level` | `INTEGER` |  |
| `details` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite indexes:* `ix_sla_events_org_time` (organization_id, created_at)

#### `sla_policies`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `name` | `VARCHAR(200)` | NOT NULL |
| `slug` | `VARCHAR(80)` | NOT NULL |
| `description` | `TEXT` |  |
| `priority` | `INTEGER` | NOT NULL |
| `is_enabled` | `BOOLEAN` | NOT NULL |
| `is_default` | `BOOLEAN` | NOT NULL |
| `conditions` | `JSONB` | NOT NULL |
| `remediate_within_hours` | `INTEGER` | NOT NULL |
| `triage_within_hours` | `INTEGER` |  |
| `verify_within_hours` | `INTEGER` |  |
| `warn_at_percent` | `INTEGER` | NOT NULL |
| `business_hours_only` | `BOOLEAN` | NOT NULL |
| `escalation_policy_id` | `UUID` | FK -> `escalation_policies.id` |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_sla_policies_org_priority` (organization_id, priority)

*Composite unique:* `uq_sla_policies_organization_id` (organization_id, slug)

## Risk register

Security risks that are not attached to an asset, with their RACI.

Declared in `backend/veyrs/models/risk_register.py`.

#### `risk_register`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `code` | `VARCHAR(40)` | NOT NULL |
| `title` | `VARCHAR(300)` | NOT NULL |
| `description` | `TEXT` |  |
| `category` | `VARCHAR(60)` | IDX |
| `source` | `VARCHAR(40)` |  |
| `status` | `VARCHAR(30)` | NOT NULL |
| `treatment` | `VARCHAR(30)` | NOT NULL |
| `treatment_plan` | `TEXT` |  |
| `likelihood` | `INTEGER` |  |
| `impact` | `INTEGER` |  |
| `score` | `INTEGER` | IDX |
| `residual_likelihood` | `INTEGER` |  |
| `residual_impact` | `INTEGER` |  |
| `residual_score` | `INTEGER` | IDX |
| `identified_at` | `DATE` |  |
| `review_due_at` | `DATE` |  |
| `closed_at` | `DATETIME` |  |
| `closure_note` | `TEXT` |  |
| `tags` | `JSONB` | NOT NULL |
| `external_ref` | `VARCHAR(300)` |  |
| `created_by_id` | `UUID` | FK -> `users.id` |
| `updated_by_id` | `UUID` | FK -> `users.id` |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |
| `deleted_at` | `DATETIME` |  |

*Composite indexes:* `ix_risk_register_org_review` (organization_id, review_due_at), `ix_risk_register_org_status` (organization_id, status)

*Composite unique:* `uq_risk_register_organization_id` (organization_id, code)

#### `risk_register_events`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `risk_id` | `UUID` | FK -> `risk_register.id`, NOT NULL, IDX |
| `event` | `VARCHAR(40)` | NOT NULL |
| `actor_id` | `UUID` | FK -> `users.id` |
| `actor_label` | `VARCHAR(200)` | NOT NULL |
| `details` | `JSONB` | NOT NULL |
| `note` | `TEXT` |  |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite indexes:* `ix_risk_register_events_risk` (risk_id, created_at)

#### `risk_register_links`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `risk_id` | `UUID` | FK -> `risk_register.id`, NOT NULL, IDX |
| `object_type` | `VARCHAR(30)` | NOT NULL |
| `object_id` | `UUID` | NOT NULL |
| `label` | `VARCHAR(300)` |  |
| `note` | `VARCHAR(400)` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_risk_register_links_object` (object_type, object_id)

*Composite unique:* `uq_risk_register_links_risk_id` (risk_id, object_type, object_id)

#### `risk_register_raci`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `risk_id` | `UUID` | FK -> `risk_register.id`, NOT NULL, IDX |
| `raci` | `VARCHAR(1)` | NOT NULL |
| `party_type` | `VARCHAR(10)` | NOT NULL |
| `team_id` | `UUID` | FK -> `teams.id` |
| `user_id` | `UUID` | FK -> `users.id` |
| `note` | `VARCHAR(400)` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_risk_register_raci_risk_id` (risk_id, raci, team_id, user_id)

## Workflow and notifications

Rules, runs, templates, deliveries, webhooks.

Declared in `backend/veyrs/models/workflow.py`.

#### `notification_preferences`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `user_id` | `UUID` | FK -> `users.id`, NOT NULL |
| `event` | `VARCHAR(60)` | NOT NULL |
| `email` | `BOOLEAN` | NOT NULL |
| `in_app` | `BOOLEAN` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite unique:* `uq_notification_preferences_organization_id` (organization_id, user_id, event)

#### `notification_templates`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `slug` | `VARCHAR(80)` | NOT NULL |
| `locale` | `VARCHAR(5)` | NOT NULL |
| `subject` | `VARCHAR(300)` | NOT NULL |
| `body` | `TEXT` | NOT NULL |
| `body_html` | `TEXT` |  |
| `is_builtin` | `BOOLEAN` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_notification_templates_organization_id` (organization_id, slug, locale)

#### `notifications`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `created_at` | `DATETIME` | NOT NULL |
| `channel` | `VARCHAR(20)` | NOT NULL |
| `event` | `VARCHAR(60)` | NOT NULL |
| `subject` | `VARCHAR(300)` | NOT NULL |
| `body` | `TEXT` | NOT NULL |
| `locale` | `VARCHAR(5)` | NOT NULL |
| `recipient_user_id` | `UUID` | FK -> `users.id` |
| `recipient_team_id` | `UUID` | FK -> `teams.id` |
| `recipient_address` | `VARCHAR(320)` |  |
| `finding_id` | `UUID` |  |
| `ticket_id` | `UUID` |  |
| `status` | `VARCHAR(20)` | NOT NULL |
| `attempts` | `INTEGER` | NOT NULL |
| `sent_at` | `DATETIME` |  |
| `read_at` | `DATETIME` |  |
| `error` | `TEXT` |  |
| `payload` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite indexes:* `ix_notifications_org_status` (organization_id, status), `ix_notifications_recipient` (recipient_user_id, read_at)

#### `webhook_endpoints`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `slug` | `VARCHAR(80)` | NOT NULL |
| `name` | `VARCHAR(200)` | NOT NULL |
| `url` | `VARCHAR(1000)` | NOT NULL |
| `is_enabled` | `BOOLEAN` | NOT NULL |
| `events` | `JSONB` | NOT NULL |
| `secret_enc` | `TEXT` | enc |
| `last_status` | `INTEGER` |  |
| `last_error` | `TEXT` |  |
| `last_sent_at` | `DATETIME` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_webhook_endpoints_organization_id` (organization_id, slug)

#### `workflow_definitions`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `slug` | `VARCHAR(80)` | NOT NULL |
| `name` | `VARCHAR(200)` | NOT NULL |
| `description` | `TEXT` |  |
| `is_enabled` | `BOOLEAN` | NOT NULL |
| `trigger` | `VARCHAR(40)` | NOT NULL |
| `conditions` | `JSONB` | NOT NULL |
| `steps` | `JSONB` | NOT NULL |
| `stop_on_error` | `BOOLEAN` | NOT NULL |
| `run_count` | `INTEGER` | NOT NULL |
| `last_run_at` | `DATETIME` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_workflows_org_trigger` (organization_id, trigger)

*Composite unique:* `uq_workflow_definitions_organization_id` (organization_id, slug)

#### `workflow_runs`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `definition_id` | `UUID` | FK -> `workflow_definitions.id`, NOT NULL |
| `trigger` | `VARCHAR(40)` | NOT NULL |
| `started_at` | `DATETIME` | NOT NULL |
| `finished_at` | `DATETIME` |  |
| `status` | `VARCHAR(20)` | NOT NULL |
| `finding_id` | `UUID` |  |
| `ticket_id` | `UUID` |  |
| `context` | `JSONB` | NOT NULL |
| `step_results` | `JSONB` | NOT NULL |
| `error` | `TEXT` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite indexes:* `ix_workflow_runs_org_time` (organization_id, started_at)

## Compliance

Frameworks, controls, implementations, evidence, assessments.

Declared in `backend/veyrs/models/compliance.py`.

#### `assessment_gaps`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `assessment_id` | `UUID` | FK -> `compliance_assessments.id`, NOT NULL |
| `control_id` | `UUID` | FK -> `compliance_controls.id` |
| `severity` | `VARCHAR(20)` | NOT NULL |
| `title` | `VARCHAR(400)` | NOT NULL |
| `detail` | `TEXT` |  |
| `remediation_plan` | `TEXT` |  |
| `due_date` | `DATE` |  |
| `ticket_id` | `UUID` | FK -> `tickets.id` |
| `closed_at` | `DATETIME` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

#### `compliance_assessments`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `framework_id` | `UUID` | FK -> `compliance_frameworks.id`, NOT NULL |
| `name` | `VARCHAR(240)` | NOT NULL |
| `status` | `VARCHAR(20)` | NOT NULL |
| `scope` | `TEXT` |  |
| `assessor` | `VARCHAR(200)` |  |
| `started_on` | `DATE` |  |
| `completed_on` | `DATE` |  |
| `snapshot` | `JSONB` | NOT NULL |
| `summary` | `TEXT` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_assessments_org_framework` (organization_id, framework_id)

#### `compliance_controls`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `framework_id` | `UUID` | FK -> `compliance_frameworks.id`, NOT NULL |
| `ref` | `VARCHAR(40)` | NOT NULL |
| `title` | `VARCHAR(400)` | NOT NULL |
| `normative_text` | `TEXT` |  |
| `veyrs_guidance` | `TEXT` |  |
| `theme` | `VARCHAR(120)` |  |
| `parent_ref` | `VARCHAR(40)` |  |
| `sort_order` | `INTEGER` | NOT NULL |
| `crosswalk` | `JSONB` | NOT NULL |
| `automation_signal` | `VARCHAR(60)` |  |

*Composite indexes:* `ix_controls_framework_ref` (framework_id, ref)

*Composite unique:* `uq_compliance_controls_framework_id` (framework_id, ref)

#### `compliance_evidence`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `implementation_id` | `UUID` | FK -> `control_implementations.id` |
| `kind` | `VARCHAR(30)` | NOT NULL |
| `title` | `VARCHAR(300)` | NOT NULL |
| `summary` | `TEXT` |  |
| `document_id` | `UUID` | FK -> `documents.id` |
| `ticket_id` | `UUID` | FK -> `tickets.id` |
| `finding_id` | `UUID` | FK -> `findings.id` |
| `asset_id` | `UUID` | FK -> `assets.id` |
| `external_url` | `VARCHAR(1000)` |  |
| `payload` | `JSONB` | NOT NULL |
| `collected_at` | `DATETIME` | NOT NULL, IDX |
| `collected_by_id` | `UUID` | FK -> `users.id` |
| `valid_until` | `DATE` |  |
| `content_hash` | `VARCHAR(64)` |  |
| `is_automated` | `BOOLEAN` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_evidence_collected` (organization_id, collected_at), `ix_evidence_org_control` (organization_id, implementation_id)

#### `compliance_frameworks`

*Isolation:* **global**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `slug` | `VARCHAR(60)` | NOT NULL, IDX |
| `name` | `VARCHAR(200)` | NOT NULL |
| `version` | `VARCHAR(40)` | NOT NULL |
| `publisher` | `VARCHAR(120)` | NOT NULL |
| `description` | `TEXT` |  |
| `source_url` | `VARCHAR(500)` |  |
| `licence_note` | `TEXT` |  |
| `is_partial` | `BOOLEAN` | NOT NULL |
| `official_control_count` | `INTEGER` |  |
| `is_builtin` | `BOOLEAN` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, IDX |

*Composite unique:* `uq_compliance_frameworks_slug` (slug, version)

#### `control_implementations`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `control_id` | `UUID` | FK -> `compliance_controls.id`, NOT NULL |
| `status` | `VARCHAR(20)` | NOT NULL |
| `owner_id` | `UUID` | FK -> `users.id` |
| `team_id` | `UUID` | FK -> `teams.id` |
| `statement` | `TEXT` |  |
| `justification` | `TEXT` |  |
| `review_period_days` | `INTEGER` | NOT NULL |
| `last_reviewed_at` | `DATETIME` |  |
| `next_review_at` | `DATETIME` | IDX |
| `automated_result` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_ctrl_impl_org_status` (organization_id, status)

*Composite unique:* `uq_control_implementations_organization_id` (organization_id, control_id)

#### `control_risk_links`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `control_id` | `UUID` | FK -> `compliance_controls.id`, NOT NULL |
| `object_type` | `VARCHAR(30)` | NOT NULL |
| `object_id` | `VARCHAR(80)` | NOT NULL |
| `rationale` | `TEXT` |  |
| `linked_by_id` | `UUID` | FK -> `users.id` |
| `is_automatic` | `BOOLEAN` | NOT NULL |
| `confidence` | `FLOAT` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_ctrl_link_org_control` (organization_id, control_id)

*Composite unique:* `uq_control_risk_links_organization_id` (organization_id, control_id, object_type, object_id)

## Knowledge and documents

Runbooks, revisions, documents, threat sources.

Declared in `backend/veyrs/models/knowledge.py`.

#### `document_chunks`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `document_id` | `UUID` | FK -> `documents.id`, NOT NULL |
| `ordinal` | `INTEGER` | NOT NULL |
| `text` | `TEXT` | NOT NULL |
| `tokens` | `INTEGER` | NOT NULL |
| `embedded` | `BOOLEAN` | NOT NULL |
| `vector_id` | `VARCHAR(80)` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite unique:* `uq_document_chunks_document_id` (document_id, ordinal)

#### `documents`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `filename` | `VARCHAR(400)` | NOT NULL |
| `title` | `VARCHAR(400)` |  |
| `notes` | `TEXT` |  |
| `content_type` | `VARCHAR(120)` | NOT NULL |
| `source_url` | `VARCHAR(1000)` |  |
| `size_bytes` | `INTEGER` | NOT NULL |
| `content_hash` | `VARCHAR(64)` | NOT NULL |
| `storage_key` | `VARCHAR(600)` |  |
| `status` | `VARCHAR(20)` | NOT NULL |
| `error` | `TEXT` |  |
| `text_content` | `TEXT` |  |
| `page_count` | `INTEGER` |  |
| `ocr_used` | `BOOLEAN` | NOT NULL |
| `doc_class` | `VARCHAR(40)` |  |
| `extracted` | `JSONB` | NOT NULL |
| `cve_ids` | `JSONB` | NOT NULL |
| `manual_cve_ids` | `JSONB` | NOT NULL |
| `team_id` | `UUID` | FK -> `teams.id` |
| `vendor_id` | `UUID` | FK -> `vendors.id` |
| `uploaded_by_id` | `UUID` | FK -> `users.id` |
| `data_classification` | `VARCHAR(20)` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_documents_org_status` (organization_id, status)

*Composite unique:* `uq_documents_organization_id` (organization_id, content_hash)

#### `knowledge_articles`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `slug` | `VARCHAR(120)` | NOT NULL |
| `title` | `VARCHAR(400)` | NOT NULL |
| `kind` | `VARCHAR(40)` | NOT NULL |
| `body` | `TEXT` | NOT NULL |
| `summary` | `TEXT` |  |
| `locale` | `VARCHAR(5)` | NOT NULL |
| `version` | `INTEGER` | NOT NULL |
| `is_published` | `BOOLEAN` | NOT NULL |
| `required_permissions` | `JSONB` | NOT NULL |
| `tags` | `JSONB` | NOT NULL |
| `cve_ids` | `JSONB` | NOT NULL |
| `product_ids` | `JSONB` | NOT NULL |
| `cwe_ids` | `JSONB` | NOT NULL |
| `author_id` | `UUID` | FK -> `users.id` |
| `view_count` | `INTEGER` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_knowledge_org_kind` (organization_id, kind)

*Composite unique:* `uq_knowledge_articles_organization_id` (organization_id, slug)

#### `knowledge_revisions`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `article_id` | `UUID` | FK -> `knowledge_articles.id`, NOT NULL |
| `version` | `INTEGER` | NOT NULL |
| `title` | `VARCHAR(400)` | NOT NULL |
| `body` | `TEXT` | NOT NULL |
| `created_at` | `DATETIME` | NOT NULL |
| `author_id` | `UUID` | FK -> `users.id` |
| `change_note` | `TEXT` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite indexes:* `ix_knowledge_revisions_article` (article_id, version)

*Composite unique:* `uq_knowledge_revisions_article_id` (article_id, version)

#### `threat_articles`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `source_id` | `UUID` | FK -> `threat_sources.id` |
| `external_id` | `VARCHAR(400)` |  |
| `url` | `VARCHAR(1000)` |  |
| `title` | `VARCHAR(600)` | NOT NULL |
| `summary` | `TEXT` |  |
| `body` | `TEXT` |  |
| `author` | `VARCHAR(200)` |  |
| `language` | `VARCHAR(5)` | NOT NULL |
| `published_at` | `DATETIME` |  |
| `content_hash` | `VARCHAR(64)` | NOT NULL |
| `cve_ids` | `JSONB` | NOT NULL |
| `product_ids` | `JSONB` | NOT NULL |
| `vendors` | `JSONB` | NOT NULL |
| `severity` | `VARCHAR(20)` |  |
| `confidence` | `FLOAT` | NOT NULL |
| `relevant_asset_count` | `INTEGER` | NOT NULL |
| `is_relevant` | `BOOLEAN` | NOT NULL, IDX |
| `read_by` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_threat_articles_org_published` (organization_id, published_at)

*Composite unique:* `uq_threat_articles_organization_id` (organization_id, content_hash)

#### `threat_sources`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `slug` | `VARCHAR(80)` | NOT NULL |
| `name` | `VARCHAR(200)` | NOT NULL |
| `kind` | `VARCHAR(30)` | NOT NULL |
| `url` | `VARCHAR(1000)` |  |
| `vendor_id` | `UUID` | FK -> `vendors.id` |
| `is_enabled` | `BOOLEAN` | NOT NULL |
| `trust` | `FLOAT` | NOT NULL |
| `credentials_enc` | `TEXT` | enc |
| `poll_interval_minutes` | `INTEGER` | NOT NULL |
| `last_polled_at` | `DATETIME` |  |
| `last_error` | `TEXT` |  |
| `tags` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_threat_sources_organization_id` (organization_id, slug)

## Integrations

Scanners, importers, external links, connector state.

Declared in `backend/veyrs/models/integration.py`.

#### `external_links`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `connector_id` | `UUID` | FK -> `itsm_connectors.id`, NOT NULL |
| `object_type` | `VARCHAR(30)` | NOT NULL |
| `object_id` | `VARCHAR(80)` | NOT NULL |
| `remote_id` | `VARCHAR(120)` | NOT NULL |
| `remote_key` | `VARCHAR(120)` |  |
| `remote_url` | `VARCHAR(1000)` |  |
| `remote_status` | `VARCHAR(60)` |  |
| `last_pushed_at` | `DATETIME` |  |
| `last_pulled_at` | `DATETIME` |  |
| `last_error` | `TEXT` |  |
| `payload_digest` | `VARCHAR(64)` |  |
| `is_active` | `BOOLEAN` | NOT NULL |
| `finding_id` | `UUID` | FK -> `findings.id`, IDX |
| `asset_id` | `UUID` | FK -> `assets.id`, IDX |
| `vulnerability_id` | `UUID` | FK -> `vulnerabilities.id` |
| `cve_id` | `VARCHAR(40)` | IDX |
| `summary` | `VARCHAR(500)` |  |
| `severity` | `VARCHAR(20)` |  |
| `risk_score` | `FLOAT` |  |
| `due_at` | `DATETIME` |  |
| `remote_created_at` | `DATETIME` |  |
| `remote_updated_at` | `DATETIME` |  |
| `remote_priority` | `VARCHAR(40)` |  |
| `remote_type` | `VARCHAR(60)` |  |
| `remote_assignee` | `VARCHAR(200)` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_external_links_remote` (organization_id, remote_id)

*Composite unique:* `uq_external_links_organization_id` (organization_id, connector_id, object_type, object_id)

#### `import_runs`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `source` | `VARCHAR(40)` | NOT NULL, IDX |
| `filename` | `VARCHAR(400)` |  |
| `content_hash` | `VARCHAR(64)` | IDX |
| `size_bytes` | `INTEGER` | NOT NULL |
| `status` | `VARCHAR(20)` | NOT NULL |
| `started_at` | `DATETIME` | NOT NULL |
| `finished_at` | `DATETIME` |  |
| `records_seen` | `INTEGER` | NOT NULL |
| `findings_created` | `INTEGER` | NOT NULL |
| `findings_updated` | `INTEGER` | NOT NULL |
| `assets_created` | `INTEGER` | NOT NULL |
| `records_rejected` | `INTEGER` | NOT NULL |
| `reject_reasons` | `JSONB` | NOT NULL |
| `reject_samples` | `JSONB` | NOT NULL |
| `stale_candidates` | `INTEGER` | NOT NULL |
| `findings_marked_absent` | `INTEGER` | NOT NULL |
| `findings_closed_absent` | `INTEGER` | NOT NULL |
| `endpoints_created` | `INTEGER` | NOT NULL |
| `inventory_hosts` | `INTEGER` | NOT NULL |
| `inventory_added` | `INTEGER` | NOT NULL |
| `inventory_updated` | `INTEGER` | NOT NULL |
| `inventory_unmatched` | `INTEGER` | NOT NULL |
| `engagement_id` | `UUID` | FK -> `engagements.id` |
| `test_id` | `UUID` | FK -> `scan_tests.id` |
| `dedupe_algorithm` | `VARCHAR(40)` |  |
| `options` | `JSONB` | NOT NULL |
| `error` | `TEXT` |  |
| `started_by_id` | `UUID` | FK -> `users.id` |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_import_runs_org_started` (organization_id, started_at)

#### `scanner_connectors`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `slug` | `VARCHAR(80)` | NOT NULL |
| `name` | `VARCHAR(200)` | NOT NULL |
| `driver` | `VARCHAR(40)` | NOT NULL |
| `base_url` | `VARCHAR(600)` |  |
| `is_enabled` | `BOOLEAN` | NOT NULL |
| `verify_tls` | `BOOLEAN` | NOT NULL |
| `credentials_enc` | `TEXT` | enc |
| `allowed_scans` | `JSONB` | NOT NULL |
| `engagement_id` | `UUID` | FK -> `engagements.id` |
| `create_assets` | `BOOLEAN` | NOT NULL |
| `close_absent` | `BOOLEAN` | NOT NULL |
| `absence_threshold` | `INTEGER` | NOT NULL |
| `min_severity` | `VARCHAR(20)` |  |
| `import_inventory` | `BOOLEAN` | NOT NULL |
| `inventory_from_plugin_output` | `BOOLEAN` | NOT NULL |
| `sync_state` | `JSONB` | NOT NULL |
| `last_sync_at` | `DATETIME` |  |
| `last_error` | `TEXT` |  |
| `last_run_id` | `UUID` | FK -> `import_runs.id` |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite unique:* `uq_scanner_connectors_organization_id` (organization_id, slug)

## Engagements

Pentest/assessment engagements and their findings.

Declared in `backend/veyrs/models/engagement.py`.

#### `endpoints`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `asset_id` | `UUID` | FK -> `assets.id` |
| `protocol` | `VARCHAR(20)` |  |
| `userinfo` | `VARCHAR(120)` |  |
| `host` | `VARCHAR(255)` | NOT NULL |
| `port` | `INTEGER` |  |
| `path` | `VARCHAR(1000)` |  |
| `query` | `VARCHAR(1000)` |  |
| `fragment` | `VARCHAR(500)` |  |
| `canonical` | `VARCHAR(2000)` | NOT NULL |
| `tags` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_endpoints_org_host` (organization_id, host)

*Composite unique:* `uq_endpoints_organization_id` (organization_id, canonical)

#### `engagements`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `name` | `VARCHAR(200)` | NOT NULL |
| `slug` | `VARCHAR(120)` | NOT NULL |
| `description` | `TEXT` |  |
| `engagement_type` | `VARCHAR(20)` | NOT NULL |
| `status` | `VARCHAR(20)` | NOT NULL |
| `business_service_id` | `UUID` | FK -> `business_services.id` |
| `asset_group_id` | `UUID` | FK -> `asset_groups.id` |
| `target_start` | `DATE` |  |
| `target_end` | `DATE` |  |
| `started_at` | `DATETIME` |  |
| `completed_at` | `DATETIME` |  |
| `lead_user_id` | `UUID` | FK -> `users.id` |
| `version` | `VARCHAR(80)` |  |
| `branch_tag` | `VARCHAR(200)` |  |
| `commit_hash` | `VARCHAR(80)` |  |
| `build_id` | `VARCHAR(120)` |  |
| `dedupe_within_engagement` | `BOOLEAN` | NOT NULL |
| `tags` | `JSONB` | NOT NULL |
| `meta` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_engagements_org_status` (organization_id, status)

*Composite unique:* `uq_engagements_organization_id` (organization_id, slug)

#### `finding_endpoints`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `finding_id` | `UUID` | FK -> `findings.id`, NOT NULL |
| `endpoint_id` | `UUID` | FK -> `endpoints.id`, NOT NULL |
| `first_seen_at` | `DATETIME` | NOT NULL |
| `last_seen_at` | `DATETIME` | NOT NULL |
| `mitigated` | `BOOLEAN` | NOT NULL |
| `mitigated_at` | `DATETIME` |  |
| `mitigated_by_id` | `UUID` | FK -> `users.id` |
| `false_positive` | `BOOLEAN` | NOT NULL |
| `risk_accepted` | `BOOLEAN` | NOT NULL |
| `method` | `VARCHAR(10)` |  |
| `request` | `TEXT` |  |
| `response` | `TEXT` |  |
| `params` | `TEXT` |  |
| `param_location` | `VARCHAR(20)` |  |
| `website` | `VARCHAR(500)` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite unique:* `uq_finding_endpoints_organization_id` (organization_id, finding_id, endpoint_id)

#### `risk_acceptance_findings`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `acceptance_id` | `UUID` | FK -> `risk_acceptances.id`, NOT NULL |
| `finding_id` | `UUID` | FK -> `findings.id`, NOT NULL |
| `added_at` | `DATETIME` | NOT NULL |
| `previous_state` | `VARCHAR(30)` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite unique:* `uq_risk_acceptance_findings_organization_id` (organization_id, acceptance_id, finding_id)

#### `risk_acceptances`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `name` | `VARCHAR(300)` | NOT NULL |
| `decision` | `VARCHAR(30)` | NOT NULL |
| `state` | `VARCHAR(20)` | NOT NULL |
| `reason` | `TEXT` | NOT NULL |
| `compensating_controls` | `TEXT` |  |
| `requested_by_id` | `UUID` | FK -> `users.id` |
| `approved_by_id` | `UUID` | FK -> `users.id` |
| `approved_at` | `DATETIME` |  |
| `decided_note` | `TEXT` |  |
| `expires_on` | `DATE` |  |
| `expiration_warned_at` | `DATETIME` |  |
| `expired_at` | `DATETIME` |  |
| `reactivate_on_expiry` | `BOOLEAN` | NOT NULL |
| `restart_sla_on_expiry` | `BOOLEAN` | NOT NULL |
| `proof_document_id` | `UUID` | FK -> `documents.id` |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_risk_acceptances_expiry` (organization_id, expires_on), `ix_risk_acceptances_org_state` (organization_id, state)

#### `scan_tests`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `engagement_id` | `UUID` | FK -> `engagements.id`, NOT NULL |
| `title` | `VARCHAR(300)` |  |
| `scanner` | `VARCHAR(60)` | NOT NULL |
| `environment` | `VARCHAR(30)` |  |
| `target_start` | `DATETIME` |  |
| `target_end` | `DATETIME` |  |
| `version` | `VARCHAR(80)` |  |
| `branch_tag` | `VARCHAR(200)` |  |
| `commit_hash` | `VARCHAR(80)` |  |
| `build_id` | `VARCHAR(120)` |  |
| `last_import_run_id` | `UUID` | FK -> `import_runs.id` |
| `reimport_count` | `INTEGER` | NOT NULL |
| `dedupe_config` | `JSONB` | NOT NULL |
| `meta` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_scan_tests_org_engagement` (organization_id, engagement_id), `ix_scan_tests_org_scanner` (organization_id, scanner)

#### `test_findings`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `test_id` | `UUID` | FK -> `scan_tests.id`, NOT NULL |
| `finding_id` | `UUID` | FK -> `findings.id`, NOT NULL |
| `status` | `VARCHAR(20)` | NOT NULL |
| `first_seen_at` | `DATETIME` | NOT NULL |
| `last_seen_at` | `DATETIME` | NOT NULL |
| `last_import_run_id` | `UUID` |  |
| `consecutive_absences` | `INTEGER` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite indexes:* `ix_test_findings_test_status` (test_id, status)

*Composite unique:* `uq_test_findings_organization_id` (organization_id, test_id, finding_id)

## AI gateway

Providers, policy, conversations, messages.

Declared in `backend/veyrs/models/ai.py`.

#### `ai_conversations`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `user_id` | `UUID` | FK -> `users.id` |
| `title` | `VARCHAR(240)` | NOT NULL |
| `capability` | `VARCHAR(40)` | NOT NULL |
| `permission_snapshot` | `JSONB` | NOT NULL |
| `locale` | `VARCHAR(5)` | NOT NULL |
| `is_archived` | `BOOLEAN` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_ai_conv_org_user` (organization_id, user_id)

#### `ai_messages`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `conversation_id` | `UUID` | FK -> `ai_conversations.id`, NOT NULL |
| `role` | `VARCHAR(20)` | NOT NULL |
| `content` | `TEXT` | NOT NULL |
| `citations` | `JSONB` | NOT NULL |
| `provider` | `VARCHAR(60)` |  |
| `model` | `VARCHAR(160)` |  |
| `blocked` | `BOOLEAN` | NOT NULL |
| `block_reason` | `VARCHAR(200)` |  |
| `redactions` | `JSONB` | NOT NULL |
| `duration_ms` | `INTEGER` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_ai_messages_conv` (conversation_id, created_at)

#### `ai_policies`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `allow_external` | `BOOLEAN` | NOT NULL |
| `allow_local` | `BOOLEAN` | NOT NULL |
| `allowed_providers` | `JSONB` | NOT NULL |
| `allowed_models` | `JSONB` | NOT NULL |
| `max_external_classification` | `VARCHAR(20)` | NOT NULL |
| `max_local_classification` | `VARCHAR(20)` | NOT NULL |
| `redact_secrets` | `BOOLEAN` | NOT NULL |
| `redact_pii` | `BOOLEAN` | NOT NULL |
| `block_on_injection` | `BOOLEAN` | NOT NULL |
| `disabled_capabilities` | `JSONB` | NOT NULL |
| `max_prompt_chars` | `INTEGER` | NOT NULL |
| `daily_call_limit` | `INTEGER` | NOT NULL |
| `notes` | `TEXT` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

#### `ai_providers`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `slug` | `VARCHAR(60)` | NOT NULL |
| `name` | `VARCHAR(160)` | NOT NULL |
| `kind` | `VARCHAR(40)` | NOT NULL |
| `base_url` | `VARCHAR(500)` |  |
| `model` | `VARCHAR(160)` | NOT NULL |
| `is_external` | `BOOLEAN` | NOT NULL |
| `is_enabled` | `BOOLEAN` | NOT NULL |
| `is_default` | `BOOLEAN` | NOT NULL |
| `api_key_enc` | `TEXT` | enc |
| `timeout_seconds` | `INTEGER` | NOT NULL |
| `temperature` | `FLOAT` | NOT NULL |
| `max_output_tokens` | `INTEGER` | NOT NULL |
| `capabilities` | `JSONB` | NOT NULL |
| `last_error` | `TEXT` |  |
| `last_used_at` | `DATETIME` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_ai_providers_org_enabled` (organization_id, is_enabled)

*Composite unique:* `uq_ai_providers_organization_id` (organization_id, slug)

## Execution agents

Scanner runners, their leases and jobs.

Declared in `backend/veyrs/models/agent.py`.

#### `agent_job_events`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `job_id` | `UUID` | FK -> `agent_jobs.id`, NOT NULL |
| `seq` | `INTEGER` | NOT NULL |
| `kind` | `VARCHAR(20)` | NOT NULL |
| `message` | `TEXT` |  |
| `data` | `JSONB` | NOT NULL |
| `created_at` | `DATETIME` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |

*Composite indexes:* `ix_agent_job_events_job_seq` (job_id, seq)

*Composite unique:* `uq_agent_job_events_organization_id` (organization_id, job_id, seq)

#### `agent_jobs`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `agent_id` | `UUID` | FK -> `exec_agents.id` |
| `requested_agent_id` | `UUID` | FK -> `exec_agents.id` |
| `tool` | `VARCHAR(60)` | NOT NULL |
| `target` | `VARCHAR(500)` | NOT NULL |
| `profile` | `VARCHAR(60)` |  |
| `params` | `JSONB` | NOT NULL |
| `engagement_id` | `UUID` | FK -> `engagements.id` |
| `test_id` | `UUID` | FK -> `scan_tests.id` |
| `asset_id` | `UUID` | FK -> `assets.id` |
| `state` | `VARCHAR(20)` | NOT NULL |
| `priority` | `INTEGER` | NOT NULL |
| `reason` | `TEXT` |  |
| `requested_by_id` | `UUID` | FK -> `users.id` |
| `lease_token` | `VARCHAR(64)` |  |
| `leased_at` | `DATETIME` |  |
| `lease_expires_at` | `DATETIME` |  |
| `attempts` | `INTEGER` | NOT NULL |
| `max_attempts` | `INTEGER` | NOT NULL |
| `started_at` | `DATETIME` |  |
| `finished_at` | `DATETIME` |  |
| `exit_code` | `INTEGER` |  |
| `error` | `TEXT` |  |
| `import_run_id` | `UUID` | FK -> `import_runs.id` |
| `output_bytes` | `INTEGER` |  |
| `output_sha256` | `VARCHAR(64)` |  |
| `last_event_seq` | `INTEGER` | NOT NULL |
| `meta` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_agent_jobs_agent_state` (agent_id, state), `ix_agent_jobs_org_state` (organization_id, state), `ix_agent_jobs_queue` (organization_id, state, priority)

#### `agent_tools`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `agent_id` | `UUID` | FK -> `exec_agents.id`, NOT NULL |
| `name` | `VARCHAR(60)` | NOT NULL |
| `tool_version` | `VARCHAR(60)` |  |
| `parser` | `VARCHAR(60)` |  |
| `enabled` | `BOOLEAN` | NOT NULL |
| `profiles` | `JSONB` | NOT NULL |
| `declared_at` | `DATETIME` |  |
| `meta` | `JSONB` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_agent_tools_org_name` (organization_id, name)

*Composite unique:* `uq_agent_tools_organization_id` (organization_id, agent_id, name)

#### `exec_agents`

*Isolation:* **pre-auth**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `name` | `VARCHAR(200)` | NOT NULL |
| `slug` | `VARCHAR(120)` | NOT NULL |
| `description` | `TEXT` |  |
| `token_prefix` | `VARCHAR(16)` | NOT NULL |
| `token_hash` | `VARCHAR(255)` | NOT NULL |
| `token_issued_at` | `DATETIME` |  |
| `status` | `VARCHAR(20)` | NOT NULL |
| `agent_version` | `VARCHAR(40)` |  |
| `hostname` | `VARCHAR(255)` |  |
| `platform` | `VARCHAR(120)` |  |
| `last_ip` | `VARCHAR(64)` |  |
| `last_heartbeat_at` | `DATETIME` |  |
| `allowed_targets` | `JSONB` | NOT NULL |
| `denied_targets` | `JSONB` | NOT NULL |
| `require_asset_match` | `BOOLEAN` | NOT NULL |
| `auto_enable_tools` | `BOOLEAN` | NOT NULL |
| `max_concurrency` | `INTEGER` | NOT NULL |
| `lease_seconds` | `INTEGER` | NOT NULL |
| `labels` | `JSONB` | NOT NULL |
| `meta` | `JSONB` | NOT NULL |
| `created_by_id` | `UUID` | FK -> `users.id` |
| `disabled_at` | `DATETIME` |  |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_exec_agents_org_status` (organization_id, status)

*Composite unique:* `uq_exec_agents_organization_id` (organization_id, slug)

## Audit trails

Append-only: audit log, auth events, AI audit log.

Declared in `backend/veyrs/models/audit.py`.

#### `ai_audit_log`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `created_at` | `DATETIME` | NOT NULL |
| `organization_id` | `UUID` |  |
| `user_id` | `UUID` |  |
| `capability` | `VARCHAR(60)` | NOT NULL, IDX |
| `provider` | `VARCHAR(40)` | NOT NULL |
| `model` | `VARCHAR(120)` | NOT NULL |
| `external` | `BOOLEAN` | NOT NULL |
| `data_classification` | `VARCHAR(20)` | NOT NULL |
| `decision` | `VARCHAR(20)` | NOT NULL |
| `block_reason` | `VARCHAR(200)` |  |
| `prompt_tokens` | `INTEGER` |  |
| `completion_tokens` | `INTEGER` |  |
| `duration_ms` | `INTEGER` |  |
| `redactions` | `JSONB` | NOT NULL |
| `prompt_digest` | `VARCHAR(64)` |  |
| `notes` | `TEXT` |  |

*Composite indexes:* `ix_ai_audit_org_time` (organization_id, created_at)

#### `audit_log`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `organization_id` | `UUID` | FK -> `organizations.id`, IDX |
| `created_at` | `DATETIME` | NOT NULL |
| `actor_id` | `UUID` | FK -> `users.id` |
| `actor_label` | `VARCHAR(255)` | NOT NULL |
| `action` | `VARCHAR(80)` | NOT NULL, IDX |
| `object_type` | `VARCHAR(80)` | NOT NULL |
| `object_id` | `VARCHAR(80)` |  |
| `object_label` | `VARCHAR(255)` |  |
| `changes` | `JSONB` | NOT NULL |
| `correlation_id` | `VARCHAR(64)` | IDX |
| `ip_address` | `VARCHAR(64)` |  |
| `user_agent` | `VARCHAR(255)` |  |

*Composite indexes:* `ix_audit_object` (object_type, object_id), `ix_audit_org_time` (organization_id, created_at)

#### `auth_events`

*Isolation:* **app-only**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `created_at` | `DATETIME` | NOT NULL |
| `organization_id` | `UUID` |  |
| `user_id` | `UUID` |  |
| `email_attempted` | `VARCHAR(255)` | IDX |
| `event` | `VARCHAR(60)` | NOT NULL, IDX |
| `success` | `BOOLEAN` | NOT NULL |
| `reason` | `VARCHAR(160)` |  |
| `ip_address` | `VARCHAR(64)` | IDX |
| `user_agent` | `VARCHAR(255)` |  |
| `correlation_id` | `VARCHAR(64)` |  |

## Saved views

Per-user saved filters and column sets.

Declared in `backend/veyrs/models/views.py`.

#### `saved_views`

*Isolation:* **strict**

| Column | Type | Notes |
|---|---|---|
| `id` | `UUID` | PK |
| `owner_id` | `UUID` | FK -> `users.id`, NOT NULL |
| `entity` | `VARCHAR(30)` | NOT NULL |
| `name` | `VARCHAR(120)` | NOT NULL |
| `description` | `VARCHAR(400)` |  |
| `filters` | `JSONB` | NOT NULL |
| `is_shared` | `BOOLEAN` | NOT NULL |
| `is_pinned` | `BOOLEAN` | NOT NULL |
| `position` | `INTEGER` | NOT NULL |
| `organization_id` | `UUID` | FK -> `organizations.id`, NOT NULL, IDX |
| `created_at` | `DATETIME` | NOT NULL, IDX |
| `updated_at` | `DATETIME` | NOT NULL |

*Composite indexes:* `ix_saved_views_org_entity` (organization_id, entity)

*Composite unique:* `uq_saved_views_owner_name` (organization_id, owner_id, entity, name)
