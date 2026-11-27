---
title: API reference
purpose: Index of every HTTP operation VEYRS exposes, generated from the application.
scope: Machine-derived endpoint catalogue. Conventions, examples and error handling are in the API guide.
version: current
verified: 2026-11-17
status: Verified
sources: [scripts/gen-reference-docs.py, backend/veyrs/main.py, backend/veyrs/security/deps.py]
related: [API.md, reference/permissions.md]
---

# API reference

> [!NOTE]
> GENERATED from the code by `scripts/gen-reference-docs.py` - do not edit by hand. Regenerate with `python3 scripts/gen-reference-docs.py`.


**350 operations** on **282 paths** in **19 tags**. The OpenAPI document is [openapi.json](../openapi.json) (also served live at `/api/v1/openapi.json`).

## Authentication classes

| Class | Operations | Meaning |
|---|---|---|
| Public | 7 | No credential. Reachable before sign-in (login, refresh, SSO, health). |
| Authenticated | 309 | `Authorization: Bearer <access token>` or `X-API-Key: veyrs_...`. Binds the caller's tenant (RLS) and applies its team scope. Permissions listed are additionally required; an empty list means any signed-in principal. |
| Platform admin | 26 | Authenticated **and** a platform administrator user (`veyrs platform-admin`). Installation-wide pages, not one organization. |
| Agent credential | 7 | A scan agent's own key, not a user token (`/agents/self/*`). |
| Signed webhook | 1 | No session; the body must carry a valid `X-VEYRS-Signature` HMAC-SHA256 made with the connector's inbound secret. |

> [!IMPORTANT]
> Permissions are read from each route's `require(...)` dependency. A few handlers check permissions inside the function body as well (for example per-report permissions); those checks are not visible here - read the handler.

## Tags

| Tag | Operations | Page |
|---|---|---|
| administration | 65 | [administration.md](administration.md) |
| agents | 22 | [agents.md](agents.md) |
| ai | 20 | [ai.md](ai.md) |
| asset sources | 19 | [asset-sources.md](asset-sources.md) |
| assets | 17 | [assets.md](assets.md) |
| authentication | 17 | [authentication.md](authentication.md) |
| compliance | 16 | [compliance.md](compliance.md) |
| cvss | 9 | [cvss.md](cvss.md) |
| dashboards & reports | 17 | [dashboards-reports.md](dashboards-reports.md) |
| engagements | 15 | [engagements.md](engagements.md) |
| integrations | 25 | [integrations.md](integrations.md) |
| intelligence & knowledge | 20 | [intelligence-knowledge.md](intelligence-knowledge.md) |
| operations | 2 | [operations.md](operations.md) |
| policies | 16 | [policies.md](policies.md) |
| risk register | 10 | [risk-register.md](risk-register.md) |
| saved views | 4 | [saved-views.md](saved-views.md) |
| threat intelligence | 14 | [threat-intelligence.md](threat-intelligence.md) |
| ticketing | 26 | [ticketing.md](ticketing.md) |
| vulnerability management | 16 | [vulnerability-management.md](vulnerability-management.md) |

## Every operation

| Method | Path | Tag | Auth |
|---|---|---|---|
| `GET` | [`/api/v1/admin/system/network`](administration.md#get-apiv1adminsystemnetwork) | administration | Platform admin |
| `GET` | [`/api/v1/admin/system/software`](administration.md#get-apiv1adminsystemsoftware) | administration | Platform admin |
| `GET` | [`/api/v1/admin/trust-store`](administration.md#get-apiv1admintrust-store) | administration | Platform admin |
| `POST` | [`/api/v1/admin/trust-store`](administration.md#post-apiv1admintrust-store) | administration | Platform admin |
| `POST` | [`/api/v1/admin/trust-store/probe`](administration.md#post-apiv1admintrust-storeprobe) | administration | Platform admin |
| `DELETE` | [`/api/v1/admin/trust-store/{ca_id}`](administration.md#delete-apiv1admintrust-storeca_id) | administration | Platform admin |
| `GET` | [`/api/v1/admin/trust-store/{ca_id}`](administration.md#get-apiv1admintrust-storeca_id) | administration | Platform admin |
| `PATCH` | [`/api/v1/admin/trust-store/{ca_id}`](administration.md#patch-apiv1admintrust-storeca_id) | administration | Platform admin |
| `GET` | [`/api/v1/admin/updates`](administration.md#get-apiv1adminupdates) | administration | Platform admin |
| `POST` | [`/api/v1/admin/updates/apply`](administration.md#post-apiv1adminupdatesapply) | administration | Platform admin |
| `POST` | [`/api/v1/admin/updates/uploads`](administration.md#post-apiv1adminupdatesuploads) | administration | Platform admin |
| `POST` | [`/api/v1/admin/updates/uploads/{upload_id}/finish`](administration.md#post-apiv1adminupdatesuploadsupload_idfinish) | administration | Platform admin |
| `PUT` | [`/api/v1/admin/updates/uploads/{upload_id}/{name}`](administration.md#put-apiv1adminupdatesuploadsupload_idname) | administration | Platform admin |
| `DELETE` | [`/api/v1/admin/updates/uploads/{version}`](administration.md#delete-apiv1adminupdatesuploadsversion) | administration | Platform admin |
| `GET` | [`/api/v1/admin/web-certificate`](administration.md#get-apiv1adminweb-certificate) | administration | Platform admin |
| `POST` | [`/api/v1/admin/web-certificate/certificate`](administration.md#post-apiv1adminweb-certificatecertificate) | administration | Platform admin |
| `POST` | [`/api/v1/admin/web-certificate/import`](administration.md#post-apiv1adminweb-certificateimport) | administration | Platform admin |
| `PUT` | [`/api/v1/admin/web-certificate/policy`](administration.md#put-apiv1adminweb-certificatepolicy) | administration | Platform admin |
| `POST` | [`/api/v1/admin/web-certificate/requests`](administration.md#post-apiv1adminweb-certificaterequests) | administration | Platform admin |
| `POST` | [`/api/v1/admin/web-certificate/uninstall`](administration.md#post-apiv1adminweb-certificateuninstall) | administration | Platform admin |
| `DELETE` | [`/api/v1/admin/web-certificate/{cert_id}`](administration.md#delete-apiv1adminweb-certificatecert_id) | administration | Platform admin |
| `GET` | [`/api/v1/admin/web-certificate/{cert_id}/csr`](administration.md#get-apiv1adminweb-certificatecert_idcsr) | administration | Platform admin |
| `POST` | [`/api/v1/admin/web-certificate/{cert_id}/install`](administration.md#post-apiv1adminweb-certificatecert_idinstall) | administration | Platform admin |
| `GET` | [`/api/v1/agents`](agents.md#get-apiv1agents) | agents | Authenticated |
| `POST` | [`/api/v1/agents`](agents.md#post-apiv1agents) | agents | Authenticated |
| `GET` | [`/api/v1/agents/jobs`](agents.md#get-apiv1agentsjobs) | agents | Authenticated |
| `POST` | [`/api/v1/agents/jobs`](agents.md#post-apiv1agentsjobs) | agents | Authenticated |
| `GET` | [`/api/v1/agents/jobs/summary`](agents.md#get-apiv1agentsjobssummary) | agents | Authenticated |
| `GET` | [`/api/v1/agents/jobs/{job_id}`](agents.md#get-apiv1agentsjobsjob_id) | agents | Authenticated |
| `POST` | [`/api/v1/agents/jobs/{job_id}/cancel`](agents.md#post-apiv1agentsjobsjob_idcancel) | agents | Authenticated |
| `GET` | [`/api/v1/agents/jobs/{job_id}/events`](agents.md#get-apiv1agentsjobsjob_idevents) | agents | Authenticated |
| `POST` | [`/api/v1/agents/maintenance/reap`](agents.md#post-apiv1agentsmaintenancereap) | agents | Authenticated |
| `POST` | [`/api/v1/agents/self/heartbeat`](agents.md#post-apiv1agentsselfheartbeat) | agents | Agent credential |
| `POST` | [`/api/v1/agents/self/inventory`](agents.md#post-apiv1agentsselfinventory) | agents | Agent credential |
| `POST` | [`/api/v1/agents/self/jobs/claim`](agents.md#post-apiv1agentsselfjobsclaim) | agents | Agent credential |
| `POST` | [`/api/v1/agents/self/jobs/{job_id}/events`](agents.md#post-apiv1agentsselfjobsjob_idevents) | agents | Agent credential |
| `POST` | [`/api/v1/agents/self/jobs/{job_id}/fail`](agents.md#post-apiv1agentsselfjobsjob_idfail) | agents | Agent credential |
| `POST` | [`/api/v1/agents/self/jobs/{job_id}/lease`](agents.md#post-apiv1agentsselfjobsjob_idlease) | agents | Agent credential |
| `POST` | [`/api/v1/agents/self/jobs/{job_id}/result`](agents.md#post-apiv1agentsselfjobsjob_idresult) | agents | Agent credential |
| `DELETE` | [`/api/v1/agents/{agent_id}`](agents.md#delete-apiv1agentsagent_id) | agents | Authenticated |
| `GET` | [`/api/v1/agents/{agent_id}`](agents.md#get-apiv1agentsagent_id) | agents | Authenticated |
| `PATCH` | [`/api/v1/agents/{agent_id}`](agents.md#patch-apiv1agentsagent_id) | agents | Authenticated |
| `POST` | [`/api/v1/agents/{agent_id}/rotate-token`](agents.md#post-apiv1agentsagent_idrotate-token) | agents | Authenticated |
| `GET` | [`/api/v1/agents/{agent_id}/tools`](agents.md#get-apiv1agentsagent_idtools) | agents | Authenticated |
| `PATCH` | [`/api/v1/agents/{agent_id}/tools/{tool_name}`](agents.md#patch-apiv1agentsagent_idtoolstool_name) | agents | Authenticated |
| `POST` | [`/api/v1/ai/ask`](ai.md#post-apiv1aiask) | ai | Authenticated |
| `GET` | [`/api/v1/ai/audit`](ai.md#get-apiv1aiaudit) | ai | Authenticated |
| `GET` | [`/api/v1/ai/capabilities`](ai.md#get-apiv1aicapabilities) | ai | Authenticated |
| `GET` | [`/api/v1/ai/conversations`](ai.md#get-apiv1aiconversations) | ai | Authenticated |
| `GET` | [`/api/v1/ai/conversations/{conversation_id}`](ai.md#get-apiv1aiconversationsconversation_id) | ai | Authenticated |
| `POST` | [`/api/v1/ai/cve/{cve_id}/analysis`](ai.md#post-apiv1aicvecve_idanalysis) | ai | Authenticated |
| `POST` | [`/api/v1/ai/findings/{finding_id}/explain`](ai.md#post-apiv1aifindingsfinding_idexplain) | ai | Authenticated |
| `POST` | [`/api/v1/ai/findings/{finding_id}/remediation`](ai.md#post-apiv1aifindingsfinding_idremediation) | ai | Authenticated |
| `POST` | [`/api/v1/ai/findings/{finding_id}/suggest-team`](ai.md#post-apiv1aifindingsfinding_idsuggest-team) | ai | Authenticated |
| `POST` | [`/api/v1/ai/findings/{finding_id}/ticket-draft`](ai.md#post-apiv1aifindingsfinding_idticket-draft) | ai | Authenticated |
| `GET` | [`/api/v1/ai/policy`](ai.md#get-apiv1aipolicy) | ai | Authenticated |
| `PUT` | [`/api/v1/ai/policy`](ai.md#put-apiv1aipolicy) | ai | Authenticated |
| `GET` | [`/api/v1/ai/providers`](ai.md#get-apiv1aiproviders) | ai | Authenticated |
| `POST` | [`/api/v1/ai/providers`](ai.md#post-apiv1aiproviders) | ai | Authenticated |
| `DELETE` | [`/api/v1/ai/providers/{provider_id}`](ai.md#delete-apiv1aiprovidersprovider_id) | ai | Authenticated |
| `POST` | [`/api/v1/ai/providers/{provider_id}/test`](ai.md#post-apiv1aiprovidersprovider_idtest) | ai | Authenticated |
| `POST` | [`/api/v1/ai/scan`](ai.md#post-apiv1aiscan) | ai | Authenticated |
| `POST` | [`/api/v1/ai/search`](ai.md#post-apiv1aisearch) | ai | Authenticated |
| `GET` | [`/api/v1/ai/search/grammar`](ai.md#get-apiv1aisearchgrammar) | ai | Authenticated |
| `POST` | [`/api/v1/ai/threat-summary`](ai.md#post-apiv1aithreat-summary) | ai | Authenticated |
| `GET` | [`/api/v1/api-keys`](administration.md#get-apiv1api-keys) | administration | Authenticated |
| `POST` | [`/api/v1/api-keys`](administration.md#post-apiv1api-keys) | administration | Authenticated |
| `DELETE` | [`/api/v1/api-keys/{key_id}`](administration.md#delete-apiv1api-keyskey_id) | administration | Authenticated |
| `GET` | [`/api/v1/asset-sources`](asset-sources.md#get-apiv1asset-sources) | asset sources | Authenticated |
| `POST` | [`/api/v1/asset-sources`](asset-sources.md#post-apiv1asset-sources) | asset sources | Authenticated |
| `GET` | [`/api/v1/asset-sources/compare`](asset-sources.md#get-apiv1asset-sourcescompare) | asset sources | Authenticated |
| `GET` | [`/api/v1/asset-sources/drivers`](asset-sources.md#get-apiv1asset-sourcesdrivers) | asset sources | Authenticated |
| `POST` | [`/api/v1/asset-sources/promote`](asset-sources.md#post-apiv1asset-sourcespromote) | asset sources | Authenticated |
| `GET` | [`/api/v1/asset-sources/records`](asset-sources.md#get-apiv1asset-sourcesrecords) | asset sources | Authenticated |
| `PATCH` | [`/api/v1/asset-sources/records/{record_id}`](asset-sources.md#patch-apiv1asset-sourcesrecordsrecord_id) | asset sources | Authenticated |
| `GET` | [`/api/v1/asset-sources/summary`](asset-sources.md#get-apiv1asset-sourcessummary) | asset sources | Authenticated |
| `DELETE` | [`/api/v1/asset-sources/{source_id}`](asset-sources.md#delete-apiv1asset-sourcessource_id) | asset sources | Authenticated |
| `GET` | [`/api/v1/asset-sources/{source_id}`](asset-sources.md#get-apiv1asset-sourcessource_id) | asset sources | Authenticated |
| `PATCH` | [`/api/v1/asset-sources/{source_id}`](asset-sources.md#patch-apiv1asset-sourcessource_id) | asset sources | Authenticated |
| `GET` | [`/api/v1/asset-sources/{source_id}/runs`](asset-sources.md#get-apiv1asset-sourcessource_idruns) | asset sources | Authenticated |
| `POST` | [`/api/v1/asset-sources/{source_id}/sync`](asset-sources.md#post-apiv1asset-sourcessource_idsync) | asset sources | Authenticated |
| `POST` | [`/api/v1/asset-sources/{source_id}/test`](asset-sources.md#post-apiv1asset-sourcessource_idtest) | asset sources | Authenticated |
| `POST` | [`/api/v1/asset-sources/{source_id}/upload`](asset-sources.md#post-apiv1asset-sourcessource_idupload) | asset sources | Authenticated |
| `GET` | [`/api/v1/assets`](assets.md#get-apiv1assets) | assets | Authenticated |
| `POST` | [`/api/v1/assets`](assets.md#post-apiv1assets) | assets | Authenticated |
| `POST` | [`/api/v1/assets/bulk-assign`](assets.md#post-apiv1assetsbulk-assign) | assets | Authenticated |
| `GET` | [`/api/v1/assets/inventory/aliases`](assets.md#get-apiv1assetsinventoryaliases) | assets | Authenticated |
| `GET` | [`/api/v1/assets/inventory/coverage`](assets.md#get-apiv1assetsinventorycoverage) | assets | Authenticated |
| `POST` | [`/api/v1/assets/inventory/import`](assets.md#post-apiv1assetsinventoryimport) | assets | Authenticated |
| `POST` | [`/api/v1/assets/inventory/resolve`](assets.md#post-apiv1assetsinventoryresolve) | assets | Authenticated |
| `GET` | [`/api/v1/assets/services`](assets.md#get-apiv1assetsservices) | assets | Authenticated |
| `POST` | [`/api/v1/assets/services`](assets.md#post-apiv1assetsservices) | assets | Authenticated |
| `DELETE` | [`/api/v1/assets/{asset_id}`](assets.md#delete-apiv1assetsasset_id) | assets | Authenticated |
| `GET` | [`/api/v1/assets/{asset_id}`](assets.md#get-apiv1assetsasset_id) | assets | Authenticated |
| `PATCH` | [`/api/v1/assets/{asset_id}`](assets.md#patch-apiv1assetsasset_id) | assets | Authenticated |
| `GET` | [`/api/v1/assets/{asset_id}/fix-plan`](assets.md#get-apiv1assetsasset_idfix-plan) | assets | Authenticated |
| `POST` | [`/api/v1/assets/{asset_id}/products`](assets.md#post-apiv1assetsasset_idproducts) | assets | Authenticated |
| `POST` | [`/api/v1/assets/{asset_id}/products/bulk`](assets.md#post-apiv1assetsasset_idproductsbulk) | assets | Authenticated |
| `DELETE` | [`/api/v1/assets/{asset_id}/products/{install_id}`](assets.md#delete-apiv1assetsasset_idproductsinstall_id) | assets | Authenticated |
| `POST` | [`/api/v1/assets/{asset_id}/rescan`](assets.md#post-apiv1assetsasset_idrescan) | assets | Authenticated |
| `GET` | [`/api/v1/audit`](administration.md#get-apiv1audit) | administration | Authenticated |
| `GET` | [`/api/v1/auth-events`](administration.md#get-apiv1auth-events) | administration | Authenticated |
| `POST` | [`/api/v1/auth/login`](authentication.md#post-apiv1authlogin) | authentication | Public |
| `POST` | [`/api/v1/auth/logout`](authentication.md#post-apiv1authlogout) | authentication | Authenticated |
| `GET` | [`/api/v1/auth/me`](authentication.md#get-apiv1authme) | authentication | Authenticated |
| `GET` | [`/api/v1/auth/me/preferences`](authentication.md#get-apiv1authmepreferences) | authentication | Authenticated |
| `PATCH` | [`/api/v1/auth/me/preferences`](authentication.md#patch-apiv1authmepreferences) | authentication | Authenticated |
| `GET` | [`/api/v1/auth/me/scope`](authentication.md#get-apiv1authmescope) | authentication | Authenticated |
| `GET` | [`/api/v1/auth/mfa`](authentication.md#get-apiv1authmfa) | authentication | Authenticated |
| `POST` | [`/api/v1/auth/mfa/activate`](authentication.md#post-apiv1authmfaactivate) | authentication | Authenticated |
| `POST` | [`/api/v1/auth/mfa/disable`](authentication.md#post-apiv1authmfadisable) | authentication | Authenticated |
| `POST` | [`/api/v1/auth/mfa/enroll`](authentication.md#post-apiv1authmfaenroll) | authentication | Authenticated |
| `POST` | [`/api/v1/auth/mfa/recovery-codes`](authentication.md#post-apiv1authmfarecovery-codes) | authentication | Authenticated |
| `POST` | [`/api/v1/auth/mfa/send-code`](authentication.md#post-apiv1authmfasend-code) | authentication | Authenticated |
| `POST` | [`/api/v1/auth/oidc/exchange`](authentication.md#post-apiv1authoidcexchange) | authentication | Public |
| `GET` | [`/api/v1/auth/oidc/{org_slug}/start`](authentication.md#get-apiv1authoidcorg_slugstart) | authentication | Public |
| `POST` | [`/api/v1/auth/password`](authentication.md#post-apiv1authpassword) | authentication | Authenticated |
| `POST` | [`/api/v1/auth/refresh`](authentication.md#post-apiv1authrefresh) | authentication | Public |
| `GET` | [`/api/v1/auth/sso`](authentication.md#get-apiv1authsso) | authentication | Public |
| `GET` | [`/api/v1/compliance/assessments`](compliance.md#get-apiv1complianceassessments) | compliance | Authenticated |
| `POST` | [`/api/v1/compliance/assessments`](compliance.md#post-apiv1complianceassessments) | compliance | Authenticated |
| `GET` | [`/api/v1/compliance/assessments/{assessment_id}`](compliance.md#get-apiv1complianceassessmentsassessment_id) | compliance | Authenticated |
| `POST` | [`/api/v1/compliance/assessments/{assessment_id}/complete`](compliance.md#post-apiv1complianceassessmentsassessment_idcomplete) | compliance | Authenticated |
| `GET` | [`/api/v1/compliance/controls/{control_id}/chain`](compliance.md#get-apiv1compliancecontrolscontrol_idchain) | compliance | Authenticated |
| `POST` | [`/api/v1/compliance/controls/{control_id}/evidence`](compliance.md#post-apiv1compliancecontrolscontrol_idevidence) | compliance | Authenticated |
| `PUT` | [`/api/v1/compliance/controls/{control_id}/implementation`](compliance.md#put-apiv1compliancecontrolscontrol_idimplementation) | compliance | Authenticated |
| `POST` | [`/api/v1/compliance/controls/{control_id}/links`](compliance.md#post-apiv1compliancecontrolscontrol_idlinks) | compliance | Authenticated |
| `GET` | [`/api/v1/compliance/evidence`](compliance.md#get-apiv1complianceevidence) | compliance | Authenticated |
| `GET` | [`/api/v1/compliance/frameworks`](compliance.md#get-apiv1complianceframeworks) | compliance | Authenticated |
| `POST` | [`/api/v1/compliance/frameworks`](compliance.md#post-apiv1complianceframeworks) | compliance | Authenticated |
| `GET` | [`/api/v1/compliance/frameworks/{framework_id}/controls`](compliance.md#get-apiv1complianceframeworksframework_idcontrols) | compliance | Authenticated |
| `POST` | [`/api/v1/compliance/frameworks/{framework_id}/controls:import`](compliance.md#post-apiv1complianceframeworksframework_idcontrolsimport) | compliance | Authenticated |
| `GET` | [`/api/v1/compliance/frameworks/{framework_id}/coverage`](compliance.md#get-apiv1complianceframeworksframework_idcoverage) | compliance | Authenticated |
| `POST` | [`/api/v1/compliance/frameworks/{framework_id}/refresh-signals`](compliance.md#post-apiv1complianceframeworksframework_idrefresh-signals) | compliance | Authenticated |
| `GET` | [`/api/v1/compliance/signals`](compliance.md#get-apiv1compliancesignals) | compliance | Authenticated |
| `POST` | [`/api/v1/cvss/assist`](cvss.md#post-apiv1cvssassist) | cvss | Authenticated |
| `POST` | [`/api/v1/cvss/compare`](cvss.md#post-apiv1cvsscompare) | cvss | Authenticated |
| `POST` | [`/api/v1/cvss/explain`](cvss.md#post-apiv1cvssexplain) | cvss | Authenticated |
| `POST` | [`/api/v1/cvss/generate`](cvss.md#post-apiv1cvssgenerate) | cvss | Authenticated |
| `GET` | [`/api/v1/cvss/metrics/{version}`](cvss.md#get-apiv1cvssmetricsversion) | cvss | Authenticated |
| `POST` | [`/api/v1/cvss/score`](cvss.md#post-apiv1cvssscore) | cvss | Authenticated |
| `GET` | [`/api/v1/cvss/severity`](cvss.md#get-apiv1cvssseverity) | cvss | Authenticated |
| `POST` | [`/api/v1/cvss/validate`](cvss.md#post-apiv1cvssvalidate) | cvss | Authenticated |
| `GET` | [`/api/v1/cvss/versions`](cvss.md#get-apiv1cvssversions) | cvss | Authenticated |
| `GET` | [`/api/v1/dashboard/executive`](dashboards-reports.md#get-apiv1dashboardexecutive) | dashboards & reports | Authenticated |
| `GET` | [`/api/v1/dashboard/sla`](dashboards-reports.md#get-apiv1dashboardsla) | dashboards & reports | Authenticated |
| `GET` | [`/api/v1/dashboard/technical`](dashboards-reports.md#get-apiv1dashboardtechnical) | dashboards & reports | Authenticated |
| `GET` | [`/api/v1/dashboard/trends`](dashboards-reports.md#get-apiv1dashboardtrends) | dashboards & reports | Authenticated |
| `GET` | [`/api/v1/departments`](administration.md#get-apiv1departments) | administration | Authenticated |
| `POST` | [`/api/v1/departments`](administration.md#post-apiv1departments) | administration | Authenticated |
| `GET` | [`/api/v1/documents`](intelligence-knowledge.md#get-apiv1documents) | intelligence & knowledge | Authenticated |
| `POST` | [`/api/v1/documents`](intelligence-knowledge.md#post-apiv1documents) | intelligence & knowledge | Authenticated |
| `DELETE` | [`/api/v1/documents/{document_id}`](intelligence-knowledge.md#delete-apiv1documentsdocument_id) | intelligence & knowledge | Authenticated |
| `GET` | [`/api/v1/documents/{document_id}`](intelligence-knowledge.md#get-apiv1documentsdocument_id) | intelligence & knowledge | Authenticated |
| `PATCH` | [`/api/v1/documents/{document_id}`](intelligence-knowledge.md#patch-apiv1documentsdocument_id) | intelligence & knowledge | Authenticated |
| `GET` | [`/api/v1/engagements`](engagements.md#get-apiv1engagements) | engagements | Authenticated |
| `POST` | [`/api/v1/engagements`](engagements.md#post-apiv1engagements) | engagements | Authenticated |
| `GET` | [`/api/v1/engagements/dedupe-registry`](engagements.md#get-apiv1engagementsdedupe-registry) | engagements | Authenticated |
| `GET` | [`/api/v1/engagements/endpoints/search`](engagements.md#get-apiv1engagementsendpointssearch) | engagements | Authenticated |
| `GET` | [`/api/v1/engagements/findings/{finding_id}/endpoints`](engagements.md#get-apiv1engagementsfindingsfinding_idendpoints) | engagements | Authenticated |
| `POST` | [`/api/v1/engagements/findings/{finding_id}/endpoints/mitigate`](engagements.md#post-apiv1engagementsfindingsfinding_idendpointsmitigate) | engagements | Authenticated |
| `POST` | [`/api/v1/engagements/risk-acceptances`](engagements.md#post-apiv1engagementsrisk-acceptances) | engagements | Authenticated |
| `POST` | [`/api/v1/engagements/risk-acceptances/expire`](engagements.md#post-apiv1engagementsrisk-acceptancesexpire) | engagements | Authenticated |
| `GET` | [`/api/v1/engagements/risk-acceptances/list`](engagements.md#get-apiv1engagementsrisk-acceptanceslist) | engagements | Authenticated |
| `POST` | [`/api/v1/engagements/risk-acceptances/{acceptance_id}/approve`](engagements.md#post-apiv1engagementsrisk-acceptancesacceptance_idapprove) | engagements | Authenticated |
| `POST` | [`/api/v1/engagements/risk-acceptances/{acceptance_id}/reject`](engagements.md#post-apiv1engagementsrisk-acceptancesacceptance_idreject) | engagements | Authenticated |
| `POST` | [`/api/v1/engagements/risk-acceptances/{acceptance_id}/revoke`](engagements.md#post-apiv1engagementsrisk-acceptancesacceptance_idrevoke) | engagements | Authenticated |
| `GET` | [`/api/v1/engagements/tests/{test_id}`](engagements.md#get-apiv1engagementsteststest_id) | engagements | Authenticated |
| `GET` | [`/api/v1/engagements/{engagement_id}`](engagements.md#get-apiv1engagementsengagement_id) | engagements | Authenticated |
| `GET` | [`/api/v1/engagements/{engagement_id}/tests`](engagements.md#get-apiv1engagementsengagement_idtests) | engagements | Authenticated |
| `GET` | [`/api/v1/findings`](vulnerability-management.md#get-apiv1findings) | vulnerability management | Authenticated |
| `POST` | [`/api/v1/findings/bulk-assign`](vulnerability-management.md#post-apiv1findingsbulk-assign) | vulnerability management | Authenticated |
| `POST` | [`/api/v1/findings/bulk-transition`](vulnerability-management.md#post-apiv1findingsbulk-transition) | vulnerability management | Authenticated |
| `GET` | [`/api/v1/findings/changes`](vulnerability-management.md#get-apiv1findingschanges) | vulnerability management | Authenticated |
| `GET` | [`/api/v1/findings/{finding_id}`](vulnerability-management.md#get-apiv1findingsfinding_id) | vulnerability management | Authenticated |
| `POST` | [`/api/v1/findings/{finding_id}/accept-risk`](vulnerability-management.md#post-apiv1findingsfinding_idaccept-risk) | vulnerability management | Authenticated |
| `GET` | [`/api/v1/findings/{finding_id}/attribution`](vulnerability-management.md#get-apiv1findingsfinding_idattribution) | vulnerability management | Authenticated |
| `GET` | [`/api/v1/findings/{finding_id}/fix-plan`](vulnerability-management.md#get-apiv1findingsfinding_idfix-plan) | vulnerability management | Authenticated |
| `POST` | [`/api/v1/findings/{finding_id}/remediation`](ticketing.md#post-apiv1findingsfinding_idremediation) | ticketing | Authenticated |
| `POST` | [`/api/v1/findings/{finding_id}/rescore`](vulnerability-management.md#post-apiv1findingsfinding_idrescore) | vulnerability management | Authenticated |
| `POST` | [`/api/v1/findings/{finding_id}/transition`](vulnerability-management.md#post-apiv1findingsfinding_idtransition) | vulnerability management | Authenticated |
| `GET` | [`/api/v1/integrations/connectors`](integrations.md#get-apiv1integrationsconnectors) | integrations | Authenticated |
| `POST` | [`/api/v1/integrations/connectors`](integrations.md#post-apiv1integrationsconnectors) | integrations | Authenticated |
| `DELETE` | [`/api/v1/integrations/connectors/{connector_id}`](integrations.md#delete-apiv1integrationsconnectorsconnector_id) | integrations | Authenticated |
| `PATCH` | [`/api/v1/integrations/connectors/{connector_id}`](integrations.md#patch-apiv1integrationsconnectorsconnector_id) | integrations | Authenticated |
| `POST` | [`/api/v1/integrations/connectors/{connector_id}/inbound-secret`](integrations.md#post-apiv1integrationsconnectorsconnector_idinbound-secret) | integrations | Authenticated |
| `POST` | [`/api/v1/integrations/connectors/{connector_id}/pull`](integrations.md#post-apiv1integrationsconnectorsconnector_idpull) | integrations | Authenticated |
| `POST` | [`/api/v1/integrations/connectors/{connector_id}/push/{ticket_id}`](integrations.md#post-apiv1integrationsconnectorsconnector_idpushticket_id) | integrations | Authenticated |
| `POST` | [`/api/v1/integrations/connectors/{connector_id}/test`](integrations.md#post-apiv1integrationsconnectorsconnector_idtest) | integrations | Authenticated |
| `GET` | [`/api/v1/integrations/importers`](integrations.md#get-apiv1integrationsimporters) | integrations | Authenticated |
| `GET` | [`/api/v1/integrations/imports`](integrations.md#get-apiv1integrationsimports) | integrations | Authenticated |
| `POST` | [`/api/v1/integrations/imports`](integrations.md#post-apiv1integrationsimports) | integrations | Authenticated |
| `GET` | [`/api/v1/integrations/imports/{run_id}`](integrations.md#get-apiv1integrationsimportsrun_id) | integrations | Authenticated |
| `POST` | [`/api/v1/integrations/itsm/{organization_slug}/{connector_slug}/inbound`](integrations.md#post-apiv1integrationsitsmorganization_slugconnector_sluginbound) | integrations | Signed webhook |
| `GET` | [`/api/v1/integrations/links`](integrations.md#get-apiv1integrationslinks) | integrations | Authenticated |
| `POST` | [`/api/v1/integrations/links/{link_id}/refresh`](integrations.md#post-apiv1integrationslinkslink_idrefresh) | integrations | Authenticated |
| `POST` | [`/api/v1/integrations/links/{link_id}/unlink`](integrations.md#post-apiv1integrationslinkslink_idunlink) | integrations | Authenticated |
| `GET` | [`/api/v1/integrations/scanner-drivers`](integrations.md#get-apiv1integrationsscanner-drivers) | integrations | Authenticated |
| `GET` | [`/api/v1/integrations/scanners`](integrations.md#get-apiv1integrationsscanners) | integrations | Authenticated |
| `POST` | [`/api/v1/integrations/scanners`](integrations.md#post-apiv1integrationsscanners) | integrations | Authenticated |
| `DELETE` | [`/api/v1/integrations/scanners/{connector_id}`](integrations.md#delete-apiv1integrationsscannersconnector_id) | integrations | Authenticated |
| `PATCH` | [`/api/v1/integrations/scanners/{connector_id}`](integrations.md#patch-apiv1integrationsscannersconnector_id) | integrations | Authenticated |
| `GET` | [`/api/v1/integrations/scanners/{connector_id}/scans`](integrations.md#get-apiv1integrationsscannersconnector_idscans) | integrations | Authenticated |
| `POST` | [`/api/v1/integrations/scanners/{connector_id}/sync`](integrations.md#post-apiv1integrationsscannersconnector_idsync) | integrations | Authenticated |
| `POST` | [`/api/v1/integrations/scanners/{connector_id}/test`](integrations.md#post-apiv1integrationsscannersconnector_idtest) | integrations | Authenticated |
| `GET` | [`/api/v1/integrations/tickets/{ticket_id}/links`](integrations.md#get-apiv1integrationsticketsticket_idlinks) | integrations | Authenticated |
| `POST` | [`/api/v1/intel/articles`](intelligence-knowledge.md#post-apiv1intelarticles) | intelligence & knowledge | Authenticated |
| `GET` | [`/api/v1/intel/cve`](threat-intelligence.md#get-apiv1intelcve) | threat intelligence | Authenticated |
| `GET` | [`/api/v1/intel/cve/{cve_id}`](threat-intelligence.md#get-apiv1intelcvecve_id) | threat intelligence | Authenticated |
| `GET` | [`/api/v1/intel/cve/{cve_id}/epss-history`](threat-intelligence.md#get-apiv1intelcvecve_idepss-history) | threat intelligence | Authenticated |
| `GET` | [`/api/v1/intel/cve/{cve_id}/exposure`](threat-intelligence.md#get-apiv1intelcvecve_idexposure) | threat intelligence | Authenticated |
| `GET` | [`/api/v1/intel/cwe/{cwe_id}`](threat-intelligence.md#get-apiv1intelcwecwe_id) | threat intelligence | Authenticated |
| `POST` | [`/api/v1/intel/feeds/epss`](threat-intelligence.md#post-apiv1intelfeedsepss) | threat intelligence | Platform admin |
| `POST` | [`/api/v1/intel/feeds/kev`](threat-intelligence.md#post-apiv1intelfeedskev) | threat intelligence | Platform admin |
| `POST` | [`/api/v1/intel/feeds/nvd`](threat-intelligence.md#post-apiv1intelfeedsnvd) | threat intelligence | Platform admin |
| `GET` | [`/api/v1/intel/feeds/runs`](threat-intelligence.md#get-apiv1intelfeedsruns) | threat intelligence | Authenticated |
| `GET` | [`/api/v1/intel/health`](threat-intelligence.md#get-apiv1intelhealth) | threat intelligence | Authenticated |
| `GET` | [`/api/v1/intel/kev`](threat-intelligence.md#get-apiv1intelkev) | threat intelligence | Authenticated |
| `GET` | [`/api/v1/intel/news`](intelligence-knowledge.md#get-apiv1intelnews) | intelligence & knowledge | Authenticated |
| `GET` | [`/api/v1/intel/schedule`](threat-intelligence.md#get-apiv1intelschedule) | threat intelligence | Authenticated |
| `PUT` | [`/api/v1/intel/schedule`](threat-intelligence.md#put-apiv1intelschedule) | threat intelligence | Authenticated |
| `GET` | [`/api/v1/intel/sources`](intelligence-knowledge.md#get-apiv1intelsources) | intelligence & knowledge | Authenticated |
| `POST` | [`/api/v1/intel/sources`](intelligence-knowledge.md#post-apiv1intelsources) | intelligence & knowledge | Authenticated |
| `GET` | [`/api/v1/intel/vendors`](threat-intelligence.md#get-apiv1intelvendors) | threat intelligence | Authenticated |
| `GET` | [`/api/v1/knowledge`](intelligence-knowledge.md#get-apiv1knowledge) | intelligence & knowledge | Authenticated |
| `POST` | [`/api/v1/knowledge`](intelligence-knowledge.md#post-apiv1knowledge) | intelligence & knowledge | Authenticated |
| `GET` | [`/api/v1/knowledge-publishing`](intelligence-knowledge.md#get-apiv1knowledge-publishing) | intelligence & knowledge | Authenticated |
| `GET` | [`/api/v1/knowledge/{article_id}`](intelligence-knowledge.md#get-apiv1knowledgearticle_id) | intelligence & knowledge | Authenticated |
| `PATCH` | [`/api/v1/knowledge/{article_id}`](intelligence-knowledge.md#patch-apiv1knowledgearticle_id) | intelligence & knowledge | Authenticated |
| `GET` | [`/api/v1/knowledge/{article_id}/publications`](intelligence-knowledge.md#get-apiv1knowledgearticle_idpublications) | intelligence & knowledge | Authenticated |
| `POST` | [`/api/v1/knowledge/{article_id}/publish`](intelligence-knowledge.md#post-apiv1knowledgearticle_idpublish) | intelligence & knowledge | Authenticated |
| `GET` | [`/api/v1/knowledge/{article_id}/revisions/{version}`](intelligence-knowledge.md#get-apiv1knowledgearticle_idrevisionsversion) | intelligence & knowledge | Authenticated |
| `POST` | [`/api/v1/knowledge/{article_id}/view`](intelligence-knowledge.md#post-apiv1knowledgearticle_idview) | intelligence & knowledge | Authenticated |
| `GET` | [`/api/v1/ldap`](administration.md#get-apiv1ldap) | administration | Authenticated |
| `PUT` | [`/api/v1/ldap`](administration.md#put-apiv1ldap) | administration | Authenticated |
| `POST` | [`/api/v1/ldap/test`](administration.md#post-apiv1ldaptest) | administration | Authenticated |
| `GET` | [`/api/v1/mfa-policy`](administration.md#get-apiv1mfa-policy) | administration | Authenticated |
| `PUT` | [`/api/v1/mfa-policy`](administration.md#put-apiv1mfa-policy) | administration | Authenticated |
| `GET` | [`/api/v1/notifications`](ticketing.md#get-apiv1notifications) | ticketing | Authenticated |
| `GET` | [`/api/v1/notifications/digest`](ticketing.md#get-apiv1notificationsdigest) | ticketing | Authenticated |
| `PUT` | [`/api/v1/notifications/digest`](ticketing.md#put-apiv1notificationsdigest) | ticketing | Authenticated |
| `POST` | [`/api/v1/notifications/digest/preview`](ticketing.md#post-apiv1notificationsdigestpreview) | ticketing | Authenticated |
| `POST` | [`/api/v1/notifications/digest/send`](ticketing.md#post-apiv1notificationsdigestsend) | ticketing | Authenticated |
| `POST` | [`/api/v1/notifications/dispatch`](ticketing.md#post-apiv1notificationsdispatch) | ticketing | Authenticated |
| `GET` | [`/api/v1/notifications/preferences`](ticketing.md#get-apiv1notificationspreferences) | ticketing | Authenticated |
| `PUT` | [`/api/v1/notifications/preferences`](ticketing.md#put-apiv1notificationspreferences) | ticketing | Authenticated |
| `POST` | [`/api/v1/notifications/{notification_id}/read`](ticketing.md#post-apiv1notificationsnotification_idread) | ticketing | Authenticated |
| `GET` | [`/api/v1/oidc`](administration.md#get-apiv1oidc) | administration | Authenticated |
| `PUT` | [`/api/v1/oidc`](administration.md#put-apiv1oidc) | administration | Authenticated |
| `POST` | [`/api/v1/oidc/test`](administration.md#post-apiv1oidctest) | administration | Authenticated |
| `GET` | [`/api/v1/organization`](administration.md#get-apiv1organization) | administration | Authenticated |
| `PATCH` | [`/api/v1/organization`](administration.md#patch-apiv1organization) | administration | Authenticated |
| `GET` | [`/api/v1/permissions`](administration.md#get-apiv1permissions) | administration | Authenticated |
| `GET` | [`/api/v1/policies/assignment`](policies.md#get-apiv1policiesassignment) | policies | Authenticated |
| `POST` | [`/api/v1/policies/assignment`](policies.md#post-apiv1policiesassignment) | policies | Authenticated |
| `POST` | [`/api/v1/policies/assignment/test`](policies.md#post-apiv1policiesassignmenttest) | policies | Authenticated |
| `GET` | [`/api/v1/policies/escalation`](policies.md#get-apiv1policiesescalation) | policies | Authenticated |
| `POST` | [`/api/v1/policies/escalation`](policies.md#post-apiv1policiesescalation) | policies | Authenticated |
| `GET` | [`/api/v1/policies/sla`](policies.md#get-apiv1policiessla) | policies | Authenticated |
| `POST` | [`/api/v1/policies/sla`](policies.md#post-apiv1policiessla) | policies | Authenticated |
| `POST` | [`/api/v1/policies/sla/evaluate`](policies.md#post-apiv1policiesslaevaluate) | policies | Authenticated |
| `GET` | [`/api/v1/policies/sla/events`](policies.md#get-apiv1policiesslaevents) | policies | Authenticated |
| `GET` | [`/api/v1/policies/sla/summary`](policies.md#get-apiv1policiesslasummary) | policies | Authenticated |
| `DELETE` | [`/api/v1/policies/sla/{policy_id}`](policies.md#delete-apiv1policiesslapolicy_id) | policies | Authenticated |
| `PATCH` | [`/api/v1/policies/sla/{policy_id}`](policies.md#patch-apiv1policiesslapolicy_id) | policies | Authenticated |
| `GET` | [`/api/v1/radius`](administration.md#get-apiv1radius) | administration | Authenticated |
| `PUT` | [`/api/v1/radius`](administration.md#put-apiv1radius) | administration | Authenticated |
| `POST` | [`/api/v1/radius/test`](administration.md#post-apiv1radiustest) | administration | Authenticated |
| `GET` | [`/api/v1/report-builder/catalog`](dashboards-reports.md#get-apiv1report-buildercatalog) | dashboards & reports | Authenticated |
| `POST` | [`/api/v1/report-builder/export`](dashboards-reports.md#post-apiv1report-builderexport) | dashboards & reports | Authenticated |
| `GET` | [`/api/v1/report-builder/queries`](dashboards-reports.md#get-apiv1report-builderqueries) | dashboards & reports | Authenticated |
| `POST` | [`/api/v1/report-builder/queries`](dashboards-reports.md#post-apiv1report-builderqueries) | dashboards & reports | Authenticated |
| `DELETE` | [`/api/v1/report-builder/queries/{query_id}`](dashboards-reports.md#delete-apiv1report-builderqueriesquery_id) | dashboards & reports | Authenticated |
| `GET` | [`/api/v1/report-builder/queries/{query_id}`](dashboards-reports.md#get-apiv1report-builderqueriesquery_id) | dashboards & reports | Authenticated |
| `PATCH` | [`/api/v1/report-builder/queries/{query_id}`](dashboards-reports.md#patch-apiv1report-builderqueriesquery_id) | dashboards & reports | Authenticated |
| `POST` | [`/api/v1/report-builder/queries/{query_id}/export`](dashboards-reports.md#post-apiv1report-builderqueriesquery_idexport) | dashboards & reports | Authenticated |
| `POST` | [`/api/v1/report-builder/queries/{query_id}/run`](dashboards-reports.md#post-apiv1report-builderqueriesquery_idrun) | dashboards & reports | Authenticated |
| `POST` | [`/api/v1/report-builder/run`](dashboards-reports.md#post-apiv1report-builderrun) | dashboards & reports | Authenticated |
| `GET` | [`/api/v1/reports`](dashboards-reports.md#get-apiv1reports) | dashboards & reports | Authenticated |
| `GET` | [`/api/v1/reports/{slug}`](dashboards-reports.md#get-apiv1reportsslug) | dashboards & reports | Authenticated |
| `GET` | [`/api/v1/reports/{slug}/export`](dashboards-reports.md#get-apiv1reportsslugexport) | dashboards & reports | Authenticated |
| `GET` | [`/api/v1/risk-register`](administration.md#get-apiv1risk-register) | administration | Authenticated |
| `PUT` | [`/api/v1/risk-register`](administration.md#put-apiv1risk-register) | administration | Authenticated |
| `GET` | [`/api/v1/risk/profiles`](vulnerability-management.md#get-apiv1riskprofiles) | vulnerability management | Authenticated |
| `POST` | [`/api/v1/risk/profiles`](vulnerability-management.md#post-apiv1riskprofiles) | vulnerability management | Authenticated |
| `POST` | [`/api/v1/risk/rescore`](vulnerability-management.md#post-apiv1riskrescore) | vulnerability management | Authenticated |
| `POST` | [`/api/v1/risk/simulate`](vulnerability-management.md#post-apiv1risksimulate) | vulnerability management | Authenticated |
| `GET` | [`/api/v1/risks`](risk-register.md#get-apiv1risks) | risk register | Authenticated |
| `POST` | [`/api/v1/risks`](risk-register.md#post-apiv1risks) | risk register | Authenticated |
| `GET` | [`/api/v1/risks/meta`](risk-register.md#get-apiv1risksmeta) | risk register | Authenticated |
| `GET` | [`/api/v1/risks/summary`](risk-register.md#get-apiv1riskssummary) | risk register | Authenticated |
| `DELETE` | [`/api/v1/risks/{risk_id}`](risk-register.md#delete-apiv1risksrisk_id) | risk register | Authenticated |
| `GET` | [`/api/v1/risks/{risk_id}`](risk-register.md#get-apiv1risksrisk_id) | risk register | Authenticated |
| `PATCH` | [`/api/v1/risks/{risk_id}`](risk-register.md#patch-apiv1risksrisk_id) | risk register | Authenticated |
| `POST` | [`/api/v1/risks/{risk_id}/links`](risk-register.md#post-apiv1risksrisk_idlinks) | risk register | Authenticated |
| `DELETE` | [`/api/v1/risks/{risk_id}/links/{link_id}`](risk-register.md#delete-apiv1risksrisk_idlinkslink_id) | risk register | Authenticated |
| `PUT` | [`/api/v1/risks/{risk_id}/raci`](risk-register.md#put-apiv1risksrisk_idraci) | risk register | Authenticated |
| `GET` | [`/api/v1/roles`](administration.md#get-apiv1roles) | administration | Authenticated |
| `POST` | [`/api/v1/roles`](administration.md#post-apiv1roles) | administration | Authenticated |
| `PATCH` | [`/api/v1/roles/{role_id}`](administration.md#patch-apiv1rolesrole_id) | administration | Authenticated |
| `GET` | [`/api/v1/saved-views`](saved-views.md#get-apiv1saved-views) | saved views | Authenticated |
| `POST` | [`/api/v1/saved-views`](saved-views.md#post-apiv1saved-views) | saved views | Authenticated |
| `DELETE` | [`/api/v1/saved-views/{view_id}`](saved-views.md#delete-apiv1saved-viewsview_id) | saved views | Authenticated |
| `PATCH` | [`/api/v1/saved-views/{view_id}`](saved-views.md#patch-apiv1saved-viewsview_id) | saved views | Authenticated |
| `GET` | [`/api/v1/scanning`](administration.md#get-apiv1scanning) | administration | Authenticated |
| `PUT` | [`/api/v1/scanning`](administration.md#put-apiv1scanning) | administration | Authenticated |
| `GET` | [`/api/v1/search`](intelligence-knowledge.md#get-apiv1search) | intelligence & knowledge | Authenticated |
| `GET` | [`/api/v1/search/semantic`](intelligence-knowledge.md#get-apiv1searchsemantic) | intelligence & knowledge | Authenticated |
| `GET` | [`/api/v1/secret-storage`](administration.md#get-apiv1secret-storage) | administration | Authenticated |
| `GET` | [`/api/v1/teams`](administration.md#get-apiv1teams) | administration | Authenticated |
| `POST` | [`/api/v1/teams`](administration.md#post-apiv1teams) | administration | Authenticated |
| `POST` | [`/api/v1/teams/import`](asset-sources.md#post-apiv1teamsimport) | asset sources | Authenticated |
| `POST` | [`/api/v1/teams/import/assign-assets`](asset-sources.md#post-apiv1teamsimportassign-assets) | asset sources | Authenticated |
| `POST` | [`/api/v1/teams/import/preview`](asset-sources.md#post-apiv1teamsimportpreview) | asset sources | Authenticated |
| `GET` | [`/api/v1/teams/import/providers`](asset-sources.md#get-apiv1teamsimportproviders) | asset sources | Authenticated |
| `PATCH` | [`/api/v1/teams/{team_id}`](administration.md#patch-apiv1teamsteam_id) | administration | Authenticated |
| `DELETE` | [`/api/v1/teams/{team_id}/members/{user_id}`](administration.md#delete-apiv1teamsteam_idmembersuser_id) | administration | Authenticated |
| `POST` | [`/api/v1/teams/{team_id}/members/{user_id}`](administration.md#post-apiv1teamsteam_idmembersuser_id) | administration | Authenticated |
| `GET` | [`/api/v1/ticketing`](administration.md#get-apiv1ticketing) | administration | Authenticated |
| `PUT` | [`/api/v1/ticketing`](administration.md#put-apiv1ticketing) | administration | Authenticated |
| `GET` | [`/api/v1/tickets`](ticketing.md#get-apiv1tickets) | ticketing | Authenticated |
| `POST` | [`/api/v1/tickets`](ticketing.md#post-apiv1tickets) | ticketing | Authenticated |
| `GET` | [`/api/v1/tickets-metrics`](ticketing.md#get-apiv1tickets-metrics) | ticketing | Authenticated |
| `GET` | [`/api/v1/tickets/automation`](ticketing.md#get-apiv1ticketsautomation) | ticketing | Authenticated |
| `PUT` | [`/api/v1/tickets/automation`](ticketing.md#put-apiv1ticketsautomation) | ticketing | Authenticated |
| `POST` | [`/api/v1/tickets/automation/backfill`](ticketing.md#post-apiv1ticketsautomationbackfill) | ticketing | Authenticated |
| `POST` | [`/api/v1/tickets/automation/preview`](ticketing.md#post-apiv1ticketsautomationpreview) | ticketing | Authenticated |
| `GET` | [`/api/v1/tickets/{ticket_id}`](ticketing.md#get-apiv1ticketsticket_id) | ticketing | Authenticated |
| `POST` | [`/api/v1/tickets/{ticket_id}/comments`](ticketing.md#post-apiv1ticketsticket_idcomments) | ticketing | Authenticated |
| `POST` | [`/api/v1/tickets/{ticket_id}/transition`](ticketing.md#post-apiv1ticketsticket_idtransition) | ticketing | Authenticated |
| `GET` | [`/api/v1/upgrade-path-rules`](policies.md#get-apiv1upgrade-path-rules) | policies | Authenticated |
| `POST` | [`/api/v1/upgrade-path-rules`](policies.md#post-apiv1upgrade-path-rules) | policies | Authenticated |
| `DELETE` | [`/api/v1/upgrade-path-rules/{rule_id}`](policies.md#delete-apiv1upgrade-path-rulesrule_id) | policies | Authenticated |
| `PATCH` | [`/api/v1/upgrade-path-rules/{rule_id}`](policies.md#patch-apiv1upgrade-path-rulesrule_id) | policies | Authenticated |
| `GET` | [`/api/v1/users`](administration.md#get-apiv1users) | administration | Authenticated |
| `POST` | [`/api/v1/users`](administration.md#post-apiv1users) | administration | Authenticated |
| `DELETE` | [`/api/v1/users/{user_id}`](administration.md#delete-apiv1usersuser_id) | administration | Authenticated |
| `GET` | [`/api/v1/users/{user_id}`](administration.md#get-apiv1usersuser_id) | administration | Authenticated |
| `PATCH` | [`/api/v1/users/{user_id}`](administration.md#patch-apiv1usersuser_id) | administration | Authenticated |
| `PUT` | [`/api/v1/users/{user_id}/scope`](administration.md#put-apiv1usersuser_idscope) | administration | Authenticated |
| `GET` | [`/api/v1/vulnerabilities`](vulnerability-management.md#get-apiv1vulnerabilities) | vulnerability management | Authenticated |
| `GET` | [`/api/v1/vulnerabilities/{vulnerability_id}`](vulnerability-management.md#get-apiv1vulnerabilitiesvulnerability_id) | vulnerability management | Authenticated |
| `GET` | [`/api/v1/workflows`](ticketing.md#get-apiv1workflows) | ticketing | Authenticated |
| `POST` | [`/api/v1/workflows`](ticketing.md#post-apiv1workflows) | ticketing | Authenticated |
| `GET` | [`/api/v1/workflows/actions`](ticketing.md#get-apiv1workflowsactions) | ticketing | Authenticated |
| `GET` | [`/api/v1/workflows/runs`](ticketing.md#get-apiv1workflowsruns) | ticketing | Authenticated |
| `POST` | [`/api/v1/workflows/seed`](ticketing.md#post-apiv1workflowsseed) | ticketing | Authenticated |
| `PATCH` | [`/api/v1/workflows/{workflow_id}`](ticketing.md#patch-apiv1workflowsworkflow_id) | ticketing | Authenticated |
| `GET` | [`/healthz`](operations.md#get-healthz) | operations | Public |
| `GET` | [`/readyz`](operations.md#get-readyz) | operations | Public |
