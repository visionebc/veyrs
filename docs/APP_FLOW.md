# App Flow

This page maps the VEYRS 0.35.1 console as the code implements it: how you sign in, where you land, which menu holds which screen and which permission the server checks behind it, and the path through each everyday task, with the API calls each step makes and what each step writes to the audit trail. Task-level detail is in the [User Guide](/USER_GUIDE.html), the [User Manual](/USER_MANUAL.html) and the [Administrator Guide](/ADMIN_GUIDE.html); request and response shapes are in the [API reference](/API.html).

> The console is a single page served at `https://veyrs.example.com/`. Every screen is a hash route (`#/findings`, `#/admin?tab=users`), and every number on it comes from `/api/v1`. The server enforces every permission; the console only decides what to ask for.

## From sign-in to your first screen

```text
Open https://veyrs.example.com/
  -> no stored session: Sign in form (Organization, Email or username, Password)
  -> POST /api/v1/auth/login
       401 mfa_required  -> the Two-factor code field appears; submit again with the code
       401 other         -> "invalid credentials" (same answer for every failure)
       200 tokens        -> GET /api/v1/auth/me -> the console shell opens
  -> no hash in the address: #/triage (Triage queue, "Never triaged" tab)
  -> a hash in the address: that screen
```

### Sign in with a password

1. Type the **Organization** slug, your **Email or username** and your **Password**, then **Sign in**. The Organization field is pre-filled with the slug last used in that browser, and empty on a browser that has never signed in.
2. The console sends `POST /auth/login` with `identifier`, `password` and `organization`. The legacy field `email` is still accepted in place of `identifier`.
3. The server finds the account in that organization by email or username and checks the password in a fixed order: the local password first, then the directory (LDAP or Active Directory) when the organization has one enabled, then RADIUS when enabled. A platform administrator (superuser) is only ever checked against the local password.
4. Wrong password, unknown account, disabled account, disabled organization and a locked account all return the same `401 invalid credentials`. Ten failed attempts lock the account for 15 minutes; wrong second-factor codes count against the same budget.
5. With no local account and a directory that has just-in-time provisioning switched on, a successful directory bind creates the account (no local password) and grants the roles the directory group map names. Off by default.
6. On success the server issues an access token and a refresh token, resets the failure counter, records `last_login_at` and writes a `login` entry to the authentication event log (not to the Audit Log screen; see [Audit log](#audit-log)).

### Two-factor authentication

If the account has two-factor sign-in turned on, the first `POST /auth/login` returns `401 {"error": "mfa_required", "method": ...}`. This does not count as a failed attempt.

| Method | How the code arrives | What the console shows |
|---|---|---|
| `totp` | An authenticator app | *Enter the 6-digit code from your authenticator app.* |
| `email` | Sent to the account e-mail after the password is proved; needs an SMTP relay | *We sent a code to {masked address}. It expires in a few minutes.* |
| `telegram` | Sent by the configured Telegram bot after the password is proved | *Code from Telegram* |
| Recovery code | One of ten single-use codes shown at activation | Accepted in the same field for any method |

Submit the form again with the code. A wrong, expired or replayed code is a failed attempt. If an e-mail or Telegram code cannot be delivered, the server answers `503 mfa_delivery_failed` and the console tells you to use a recovery code. An account whose stored authenticator secret is unreadable cannot sign in with an app code; a recovery code still works.

You turn two-factor sign-in on yourself under **My account** (`#/account`, the link on your name in the top bar):

1. Choose a method and **Continue**: `POST /auth/mfa/enroll`. For `totp` the response carries the secret and a QR code; for `email` and `telegram` the first code is sent now. Nothing is enforced yet.
2. Type the code and **Turn on**: `POST /auth/mfa/activate`. Two-factor sign-in is now required, and ten recovery codes are shown once.
3. **New recovery codes…** (`POST /auth/mfa/recovery-codes`) and **Turn off…** (`POST /auth/mfa/disable`) both need your password and a valid code.

Enrol, activate, replace and disable are written to the audit log as `mfa.enroll`, `mfa.activate`, `mfa.recovery_codes.replace` and `mfa.disable`; a recovery code used at sign-in is written as `mfa.recovery_code.used`.

### Sign in through RADIUS

When **Administration → RADIUS** is on and the RADIUS server answers the password with an Access-Challenge (a push or one-time code from its own second factor):

1. `POST /auth/login` returns `401 mfa_required` with `method: "radius"`, the server's own prompt and a `radius_challenge` id that is valid for two minutes and once.
2. The console shows the server's prompt as the label of the code field. Type the code and sign in again; the console sends `mfa_code` and `radius_challenge`.
3. When the RADIUS challenge is answered, VEYRS does not also ask for its own second factor.

The account must already exist in VEYRS; its username or e-mail is sent as the RADIUS User-Name. Roles can be synchronised from the `Class` or `Filter-Id` reply attribute.

### Sign in with SSO (OpenID Connect)

The **Sign in with SSO** button appears only when `GET /auth/sso` reports that at least one organization has SSO turned on.

1. Type the **Organization** slug, then **Sign in with SSO**. The console calls `GET /auth/oidc/{org}/start` and sends the browser to the identity provider. An unknown organization and an organization without SSO return the same `404`.
2. The provider sends the browser back to `GET /api/v1/auth/oidc/callback`, which validates the answer, matches the account by its verified e-mail address in that organization, optionally creates it (just-in-time provisioning) and synchronises roles from the groups claim.
3. The callback redirects to `#/sso?h={handoff}`. The console swaps the one-time handoff for tokens with `POST /auth/oidc/exchange` and removes it from the address bar.
4. Any refusal returns to `#/sso?error=...` and the sign-in page shows *Single sign-on: {reason}*. Platform administrators are always refused: they sign in with their local password.

### First sign-in after installation

There is no sign-up page and no API that creates an organization. The installer (or an operator on the host) runs the bootstrap command once:

```bash
python -m veyrs bootstrap --org acme --name "Acme" --email admin@acme.example --superuser
```

It creates the organization `acme`, an administrator with the password from `VEYRS_BOOTSTRAP_PASSWORD` (or a prompt; at least 12 characters), grants the built-in `org-admin` role and, with `--superuser`, makes the account a platform administrator. Running it again for an existing account resets that account's password. `python -m veyrs platform-admin --email ... [--revoke]` grants or revokes platform administration later.

The administrator then signs in with organization `acme`, the e-mail and the password. There is no forced password change on first sign-in; change it under **My account → Password**. The console opens on an empty Triage queue; **Getting Started** (`#/guide`) shows which link of the scan → risk → ticket chain is still missing.

### Session, refresh and sign-out

| Event | What happens |
|---|---|
| Token storage | Access token, refresh token, permission list and organization slug are kept in the browser's local storage |
| Access token expiry | Default 30 minutes. A `401` from any call triggers one shared `POST /auth/refresh`, then the call is retried |
| Refresh | Default 14 days. Every refresh rotates the refresh token; presenting an already-rotated one revokes the whole token family |
| Refresh fails | The console clears the session and shows the sign-in page with *Session expired* |
| Role change | The server re-reads permissions from the database on every request, so a revoked role takes effect at once |
| **Sign out** | `POST /auth/logout` revokes **every** refresh token of the account, in every browser, then clears local storage |
| Password change | `POST /auth/password` (at least 12 characters, must differ) revokes every refresh token; the console signs you out after a second |

## Screen map

The sidebar has seven groups. Groups and sub-menus start collapsed; the group holding the current screen is always open. The sidebar is **not** filtered by your permissions: a screen your role cannot read still has its entry and answers *Access denied* when opened. The `Ctrl-K` / `⌘K` command palette does filter by permission.

| Menu | Screens | Route | Gate in the console |
|---|---|---|---|
| **Overview** | Triage queue, Getting Started, Dashboards (Executive, Technical, SLA) | `#/triage`, `#/guide`, `#/dashboard?tab=` | `finding:read`; none; `report:read` |
| **Work** | Findings (All, Critical, New / untriaged, My teams' queue, No owner at all), Recent changes, Tickets or Issues, Vulnerabilities, Risk Register | `#/findings`, `#/changes`, `#/tickets` or `#/issues`, `#/vulnerabilities`, `#/risks` | `finding:read`; `ticket:read`; `vulnerability:read`; `riskregister:read` |
| **Estate** | Inventory (All assets, Internet-exposed, Not internet-facing, Business-critical, Production, Non-production, No owning team) | `#/assets` | `asset:read` |
| **Intelligence** | Threat Intel (CVE, CISA KEV, News, Sources, Feed runs, Schedule), Documents & Advisories, Knowledge Base, AI Assistant | `#/intel?tab=`, `#/documents`, `#/knowledge`, `#/ai?tab=` | `cve:read`; `document:read`; `knowledge:read`; `ai:read` |
| **Reporting** | Reports, Compliance, Audit Log | `#/reports`, `#/compliance`, `#/audit` | `report:read`; `compliance:read`; `audit:read` |
| **Tools** | CVSS Calculator | `#/cvss?v=` | none |
| **Configure** | Vulnerability scanner, Data sources, SLA & Policies, Automation, Administration | `#/scanner`, `#/integrations?tab=`, `#/policies?tab=`, `#/automation?tab=`, `#/admin?tab=` | `agent:read`; `importer:read`; `sla:read`; `workflow:read`; `user:read` |

Three entries depend on organization settings read from `GET /auth/me` at sign-in, not on your role:

- **Vulnerability scanner** leaves the menu and the palette while active scanning is off (**Administration → Scanning**). `#/scanner` stays reachable and explains the mode.
- **Tickets** or **Issues**: exactly one is shown. **Tickets** when remediation work lives in the VEYRS queue, **Issues** when an external ITSM owns it (**Administration → Ticketing**).
- **Risk Register** leaves the menu while the organization does not keep a register (**Administration → Risk register**). Its entries stay readable by URL and API.

Screens without a sidebar entry: **Search** (`#/search?q=`, the top-bar search box), **Notifications** (`#/notifications`, the bell; the unread count is polled every 60 seconds), **My account** (`#/account`, your name in the top bar). `#/workflows` redirects to `#/automation?tab=workflows`; `#/sso` is the SSO landing and is handled before the shell opens.

> The **Gate** column is the permission the console uses for the palette, not the one the server checks for every call on the screen. The SLA dashboard tab also reads `sla:read`; the ITSM connectors and Documentation tabs of Data sources need `ticket:read` and `knowledge:read` rather than `importer:read`. The table in the next section lists what the server actually checks.

## View → route → API → permission

Paths are relative to `/api/v1`. "Signed in" means any authenticated account. Detail routes take the record id after the list route (`#/findings/{id}`).

| View | Route | API calls | Server permission |
|---|---|---|---|
| Triage queue | `#/triage?queue=new`, `critical`, `kev`, `sla`, `mine`; `#/triage?view={id}` | GET `/saved-views?seed=true`, GET `/findings`, GET `/findings/{id}`, POST `/findings/bulk-assign`, POST `/findings/{id}/transition`, POST `/findings/{id}/accept-risk`, POST `/findings/{id}/remediation` | `finding:read`; assign and transition `finding:write`; accept `risk:admin`; ticket `ticket:write` |
| Getting Started | `#/guide` | GET `/agents`, GET `/agents/jobs/summary` (scanning on only), GET `/findings`, GET `/tickets` | each optional: `agent:read`, `finding:read`, `ticket:read` |
| Dashboards | `#/dashboard?tab=executive`, `technical`, `sla`; `&team={id}` or `all` | GET `/dashboard/executive`, `/dashboard/technical`; GET `/dashboard/sla`, `/policies/sla/summary`; GET `/teams`; PATCH `/auth/me/preferences` | `report:read`; SLA tab `sla:read`; team picker `team:read` |
| Findings | `#/findings`, `#/findings/{id}` | GET `/findings`, `/findings/{id}`, `/findings/{id}/fix-plan`, `/findings/{id}/attribution`; POST `/findings/{id}/transition`, `/findings/{id}/rescore`, `/findings/{id}/accept-risk`, `/findings/{id}/remediation`, `/findings/bulk-assign`, `/ai/findings/{id}/explain`, `/ai/findings/{id}/remediation` | `finding:read`; `finding:write`; rescore `risk:write`; accept `risk:admin`; remediation `ticket:write`; AI explain `risk:read` |
| Recent changes | `#/changes?kind=&cause=&days=` | GET `/findings/changes` | `finding:read` |
| Tickets | `#/tickets`, `#/tickets/{id}` | GET `/tickets`, `/tickets/{id}`, `/integrations/tickets/{id}/links`; POST `/tickets`, `/tickets/{id}/transition`, `/tickets/{id}/comments`, `/integrations/connectors/{cid}/push/{id}` | `ticket:read`; writes `ticket:write` |
| Issues | `#/issues` | GET `/integrations/links`; POST `/integrations/links/{id}/refresh`, `/integrations/links/{id}/unlink` | `ticket:read`; `ticket:write` |
| Vulnerabilities | `#/vulnerabilities`, `#/vulnerabilities/{id}` | GET `/vulnerabilities`, `/vulnerabilities/{id}` | `vulnerability:read` |
| Risk Register | `#/risks`, `#/risks/{id}` | GET `/risks`, `/risks/summary`, `/risks/meta`, `/risks/{id}`, `/users`; POST/PATCH `/risks`; PUT `/risks/{id}/raci`; POST/DELETE `/risks/{id}/links`; DELETE `/risks/{id}` | `riskregister:read`, `write`, `delete`; people picker `user:read` |
| Inventory | `#/assets`, `#/assets/{id}` | GET `/assets`, `/assets/{id}`, `/findings?asset_id=`, `/assets/{id}/fix-plan`; POST `/assets`, `/assets/bulk-assign`, `/assets/{id}/rescan`; DELETE `/assets/{id}` | `asset:read`; `asset:write`; delete `asset:delete`; fix plan also `finding:read` |
| Threat Intel | `#/intel?tab=cve`, `kev`, `news`, `sources`, `runs`, `schedule`; `&scope=estate` or `all` | GET `/intel/health`, `/intel/cve`, `/intel/kev`, `/intel/news`, `/intel/sources`, `/intel/feeds/runs`, `/intel/schedule`; POST `/intel/sources`; PUT `/intel/schedule` | lists `cve:read`; health, news, sources, runs, schedule `intel:read`; writes `intel:write` |
| CVE detail | `#/intel/cve/{id}` | GET `/intel/cve/{id}`, `/intel/cve/{id}/exposure`, `/intel/cve/{id}/epss-history`; POST `/ai/cve/{id}/analysis` | `cve:read`; exposure `finding:read` |
| CWE detail | `#/intel/cwe/{id}` | GET `/intel/cwe/{id}` | `cve:read` |
| Documents & Advisories | `#/documents`, `#/documents/{id}` | GET `/documents`, `/documents/{id}`, `/intel/vendors`; POST `/documents`; PATCH and DELETE `/documents/{id}` | `document:read`, `write`, `delete` |
| Knowledge Base | `#/knowledge`, `#/knowledge/{id}` | GET `/knowledge`, `/knowledge/{id}`, `/knowledge/{id}/publications`, `/knowledge-publishing`; POST `/knowledge`, `/knowledge/{id}/publish`; PATCH `/knowledge/{id}` | `knowledge:read`; `knowledge:write` |
| AI Assistant | `#/ai?tab=ask`, `search`, `policy`, `providers`, `audit` | GET `/ai/capabilities`, `/ai/search/grammar`, `/ai/policy`, `/ai/providers`, `/ai/audit`; POST `/ai/ask`, `/ai/search`, `/ai/providers`; PUT `/ai/policy`; DELETE `/ai/providers/{id}` | `ai:read`; policy and providers writes `ai:admin`; AI audit `audit:read` |
| Reports | `#/reports?tab=fixed`, `builder` | GET `/reports`, `/reports/{slug}/export?format=`; GET `/report-builder/catalog`, `/report-builder/queries`; POST `/report-builder/run`, `/report-builder/export`, `/report-builder/queries`; PATCH and DELETE `/report-builder/queries/{id}` | catalogue: signed in; each export its own permission; builder `report:read`, sharing `report:write` |
| Compliance | `#/compliance`, `#/compliance/{framework}` | GET `/compliance/frameworks`, `/compliance/frameworks/{id}/coverage`, `/compliance/controls/{id}/chain`; POST `/compliance/frameworks/{id}/refresh-signals` | `compliance:read`; refresh `compliance:write` |
| Audit Log | `#/audit?action=&object_type=` | GET `/audit` | `audit:read` |
| CVSS Calculator | `#/cvss?v=2.0`, `3.0`, `3.1`, `4.0` | GET `/cvss/metrics/{v}`; POST `/cvss/score`, `/cvss/explain`, `/cvss/validate`, `/cvss/assist` | `vulnerability:read` |
| Vulnerability scanner | `#/scanner` | GET `/agents`, `/agents/jobs/summary`, `/agents/jobs`, `/dashboard/technical`, `/integrations/importers`, `/integrations/imports`, `/scanning` | each optional: `agent:read`, `report:read`, `importer:read`, `settings:read` |
| Data sources | `#/integrations?tab=import`, `scanners`, `runs`, `connectors`, `docs` | GET `/integrations/importers` (optional: the format list and page blurb), `/integrations/imports`, `/integrations/scanners`, `/integrations/scanner-drivers`, `/integrations/connectors`, `/knowledge-publishing`; POST `/integrations/imports`, `/integrations/scanners`, `/integrations/scanners/{id}/test`, `/integrations/scanners/{id}/sync`, `/integrations/connectors`, `/integrations/connectors/{id}/test`; PATCH and DELETE on both | `importer:read` for the import, scanner connector and import run tabs; upload and sync `importer:write`; scanner connector setup `importer:admin`; ITSM connectors `ticket:read`, setup `ticket:admin` |
| SLA & Policies | `#/policies?tab=sla`, `escalation`, `assignment`, `risk`, `events`, `upgrade` | GET `/policies/sla`, `/policies/escalation`, `/policies/assignment`, `/risk/profiles`, `/policies/sla/events`, `/upgrade-path-rules`; POST `/policies/sla`, `/policies/sla/evaluate`, `/policies/assignment/test`, `/risk/profiles`, `/risk/simulate`, `/risk/rescore`, `/upgrade-path-rules`; PATCH and DELETE `/upgrade-path-rules/{id}` | `sla:read`; `escalation:read`; assignment `finding:read`; profiles `riskprofile:read`, `write`; simulate `risk:read`; re-score all `risk:admin`; SLA and upgrade-path writes `sla:write` |
| Automation | `#/automation?tab=tickets`, `workflows`, `runs` | GET `/tickets/automation`, `/workflows`, `/workflows/actions`, `/workflows/runs`; POST `/tickets/automation/preview`, `/tickets/automation/backfill`, `/workflows`, `/workflows/seed`; PUT `/tickets/automation`; PATCH `/workflows/{id}` | `ticket:read`; automatic tickets save and backfill `ticket:admin`; `workflow:read`, `write`; seed `workflow:admin` |
| Administration | `#/admin?tab=` | see [Change administration settings](#change-administration-settings) | per tab |
| Search | `#/search?q=` | GET `/search`, `/search/semantic` | signed in; each result type needs its own read permission |
| Notifications | `#/notifications?tab=inbox`, `preferences`, `digest` | GET `/notifications`, `/notifications/preferences`, `/notifications/digest`; POST `/notifications/{id}/read`, `/notifications/digest/preview`, `/notifications/digest/send`; PUT `/notifications/preferences`, `/notifications/digest` | inbox and preferences: signed in; digest policy `notification:read`, change and send `notification:admin`; preview `finding:read` |
| My account | `#/account` | GET `/auth/mfa`; POST `/auth/mfa/enroll`, `/auth/mfa/send-code`, `/auth/mfa/activate`, `/auth/mfa/recovery-codes`, `/auth/mfa/disable`, `/auth/password` | signed in |

## Core journeys

Each journey lists the screens in order, the calls behind them, the permission the server checks, and what is written. "Audited" means an entry in the audit log you read under **Reporting → Audit Log**.

### Onboard an organization, users and roles

```text
Host: python -m veyrs bootstrap --org acme ...      organization + org-admin account
Sign in as that administrator                        #/triage
Administration -> Organization                      name, locale, invoicing code
Administration -> Teams -> New team                  teams own assets and findings
Administration -> Users -> Invite user               e-mail, username, full name, password, one role
Administration -> Users -> Scope...                  optional: narrow a user to teams
Administration -> Directory / RADIUS / Single sign-on   optional external sign-in
```

| Step | Screen | Call | Permission | Written / audited |
|---|---|---|---|---|
| Create the tenant | Host command | `veyrs bootstrap` | Host access | Organization, user, `org-admin` grant (no audit entry) |
| Organization settings | `#/admin?tab=org` | GET and PATCH `/organization` | `organization:read`, `organization:write` | `organization.update` |
| Create a team | `#/admin?tab=teams` | POST `/teams` | `team:write` | `team.create` |
| Add a team member | API only | POST `/teams/{id}/members/{user_id}` | `team:write` | `team.member.add` |
| Import teams from NetBox or the directory | `#/admin?tab=teamimport` | POST `/teams/import/preview`, `/teams/import`, `/teams/import/assign-assets` | `team:write` | teams and memberships |
| Create a user | `#/admin?tab=users` → **Invite user** | GET `/roles`, POST `/users` with `role_slugs` | `user:write` | `user.create` |
| Change roles or deactivate | API only | PATCH `/users/{id}`, DELETE `/users/{id}` | `user:write`, `user:delete` | `user.update`, `user.delete` |
| Narrow a user to teams | **Scope…** on the user row | PUT `/users/{id}/scope` | `role:admin` | `user.scope` |
| See roles and the permission catalogue | `#/admin?tab=roles` | GET `/roles`, `/permissions` | `role:read` | nothing |
| Create a custom role | API only | POST `/roles`, PATCH `/roles/{id}` | `role:admin` | `role.create`, `role.update` |
| Departments | `#/admin?tab=departments` | GET and POST `/departments` | `team:read`, `team:write` | `department.create` |
| API keys | `#/admin?tab=apikeys` | GET, POST and DELETE `/api-keys` | `apikey:read`, `write`, `delete` | `apikey.create`, `apikey.revoke`; the key is shown once |

Permissions are `resource:action` with actions `read`, `write`, `delete`, `admin`. A role is a list of them (wildcards `resource:*` and `*:*` allowed). The built-in roles are `org-admin`, `security-manager`, `security-engineer`, `team-lead`, `asset-owner`, `compliance-officer`, `executive`, `auditor`, `service-account` and `read-only`; see [How your role changes the flow](#how-your-role-changes-the-flow). Team membership never widens what a user may read; only a scope set with **Scope…** narrows it. Every tenant table is protected by PostgreSQL row-level security, and each request is bound to the caller's organization before any query runs.

### Build the asset inventory

There are four ways in; all of them end in the same asset register.

```text
By hand:        Inventory -> New asset -> asset page
From a scan:    Data sources -> Scanner import (Create assets ticked) -> Import runs
From a CMDB:    Administration -> Asset sources -> Test -> Sync -> staged records -> promote
From an agent:  agent host -> POST /agents/self/inventory -> correlation
```

1. **By hand.** **Inventory → New asset** asks for name, hostname, IP addresses, type, environment, criticality, data classification, exposure (`internet`, `partner`, `internal`, `isolated`), location and tags. `POST /assets` (`asset:write`), audited as `asset.create`. The asset page opens.
2. **From a scanner report.** **Data sources → Scanner import**: pick the file, keep **Dry run** ticked for a first pass, tick **Create assets the scanner reports but VEYRS does not know** and, for software inventory, **Also record what each host has installed**. `POST /integrations/imports` (multipart, `importer:write`), audited as `import.run`. A record whose asset cannot be identified is rejected with a reason; read **Import runs** (`GET /integrations/imports`) for rejected and inventory counts.
3. **From a CMDB.** **Administration → Asset sources** (`importer:read`; add, edit, test and delete need `importer:admin`). **Sync** (`POST /asset-sources/{id}/sync`, `importer:write`) reads the source into staging; a file-based source is fed with `POST /asset-sources/{id}/upload`. Staged records reach the register automatically when the source has auto-promote on, or through `POST /asset-sources/promote` (`asset:write`), which the console does not offer. Audited as `cmdb.source.*` and `cmdb.record.updated`.
4. **From an agent.** An enrolled agent reports a host's installed software with `POST /agents/self/inventory`, authenticated by its `X-Agent-Token`, not by a user session. Inventory reporting stays allowed when active scanning is off. Enrolment is `POST /agents` (`agent:admin`, refused while scanning is off) and returns the agent token once; the console has no enrolment form. There is no network discovery: an agent scan job targets one named host that must be on the agent's allow-list.

On the asset page (`#/assets/{id}`): **Re-correlate** (`POST /assets/{id}/rescan`, `asset:write`) re-runs CVE correlation for the asset; **Delete** (`DELETE /assets/{id}`, `asset:delete`, audited `asset.delete`) soft-deletes it: the row is marked deleted and inactive. **Assign to team…** on the list (`POST /assets/bulk-assign`, `asset:write`) sets the owning team; a finding with no explicit assignee inherits it.

### Follow a vulnerability from feed to affected asset

```text
Feeds (NVD, EPSS, KEV, CWE) on their schedule
  -> Threat Intel -> CVE tab, "Affecting you" lens (default)
  -> CVE page: CVSS, EPSS, KEV, weaknesses, affected products, Your exposure
  -> Affected assets table -> asset page or finding page
```

1. Feeds run on the schedule under **Threat Intel → Schedule** (`GET` and `PUT /intel/schedule`; changing it needs `intel:write`, audited `organization.intel_schedule_changed`). A host timer wakes hourly and runs each feed whose interval has passed since its last success. The CVE corpus is shared by every organization on the installation, so the interval in force is the tightest one any organization asked for. **Feed runs** (`GET /intel/feeds/runs`) lists every run. A manual run is `POST /intel/feeds/nvd`, `/epss` or `/kev` (`intel:write`) or `veyrs sync-nvd` and friends on the host; the console has no button for it.
2. **Threat Intel → CVE** (`GET /intel/cve`, `cve:read`) opens on the **Affecting you** lens: only CVEs with an open finding in your organization (`exposed=true`). **Software you run** (`&scope=estate`) lists CVEs that name a product you run without comparing versions; **Whole catalogue** (`&scope=all`) lists everything. The lens carries across the CVE and CISA KEV tabs. The header counters come from `GET /intel/health`.
3. Open a CVE (`#/intel/cve/{id}`). `GET /intel/cve/{id}` gives the record; `GET /intel/cve/{id}/exposure` (`finding:read`) gives **Your exposure** and the **Affected assets** table: one row per asset with an open finding, with criticality, exposure, state, risk and SLA date. **✦ Analyse** (`POST /ai/cve/{id}/analysis`) is shown with `ai:read`.
4. From the table, open the asset (`#/assets/{id}`) or the finding (`#/findings/{id}`).

A banner warns when no software inventory exists or when installations did not resolve to a dictionary entry: an empty lens then means a missing inventory, not a clean estate. **Documents & Advisories** (`POST /documents`, `document:write`, audited `document.upload`) is the other way in: an uploaded advisory is parsed for CVEs, products and versions and correlated against the inventory.

### Work a finding from open to closed

```text
Main line:   new -> triaged -> risk_assessed -> assigned -> in_progress -> mitigation -> remediated
Closing:     remediated -> verification -> verified -> closed
Side exits:  false_positive, duplicate, deferred (from new on); accepted_risk, exception (from triaged on)
Reopen:      remediated, verification, verified, closed -> in_progress
```

Two screens do the work. The **Triage queue** (`#/triage`) shows one open finding at a time with five tabs: *Never triaged* (`state=new`), *Critical*, *Known exploited*, *Past its deadline* and *My teams' queue*, plus your saved views. The **Findings** list and its detail page (`#/findings/{id}`) offer the same actions with a free choice of target state.

| Action | Where | Call | Permission | Result | Audited |
|---|---|---|---|---|---|
| Create ticket / Raise issue (`T`) | Triage, finding page, bulk on Findings | POST `/findings/{id}/remediation` | `ticket:write` | One open remediation ticket (or external issue) per finding; an existing one is returned | `finding.remediation_opened` |
| Assign to team (`A`) | Triage, bulk on Findings | POST `/findings/bulk-assign` | `finding:write` | Owner changes, state does not; a finding event records from and to | `finding.bulk_assign` |
| False positive (`F`) | Triage | POST `/findings/{id}/transition` `{"state": "false_positive"}` | `finding:write` | Closed; a later detection reopens it as `new` | `finding.transition` |
| Accept risk (`R`) | Triage, finding page (**Accept risk…**) | POST `/findings/{id}/transition` to `triaged` when the finding is `new`, then POST `/findings/{id}/accept-risk?reason=...&until=...` | `risk:admin` | `accepted_risk`, with the accepting user, the reason (10 characters minimum) and the optional date | `finding.accept_risk` |
| Transition… | Finding page | POST `/findings/{id}/transition` `{"state", "note"}` | `finding:write` | Any edge in the table below; anything else is `409` | `finding.transition` |
| Re-score | Finding page | POST `/findings/{id}/rescore` | `risk:write` | Risk recomputed with the default profile | not audited; a changed score is written to the risk score history |
| Skip (`S`), `J` / `K`, `↵` | Triage | none | none | Next, previous, open the detail | nothing |

Allowed transitions (`models/vulnerability.py`):

| From | To |
|---|---|
| `new` | `triaged`, `false_positive`, `duplicate`, `deferred` |
| `triaged` | `risk_assessed`, `false_positive`, `duplicate`, `accepted_risk`, `exception`, `deferred` |
| `risk_assessed` | `assigned`, `accepted_risk`, `exception`, `deferred`, `false_positive` |
| `assigned` | `in_progress`, `mitigation`, `deferred`, `accepted_risk`, `exception` |
| `in_progress` | `mitigation`, `remediated`, `deferred`, `accepted_risk`, `exception` |
| `mitigation` | `remediated`, `in_progress`, `accepted_risk`, `exception` |
| `remediated` | `verification`, `in_progress` |
| `verification` | `verified`, `in_progress` |
| `verified` | `closed`, `in_progress` |
| `closed` | `in_progress` |
| `false_positive`, `duplicate` | `new` |
| `accepted_risk`, `exception` | `triaged`, `in_progress` |
| `deferred` | `triaged`, `assigned`, `in_progress` |

Open states are `new` through `verification` plus `deferred`; `verified`, `closed`, `false_positive`, `duplicate`, `accepted_risk` and `exception` count as closed.

Paths that move a finding without an operator:

- **A remediation ticket resolved** in VEYRS advances its finding to `remediated` through every intermediate state. Only the `remediation` ticket type does this.
- **A re-import** with *Close findings this test previously reported and no longer does* closes findings of that scan test that the new report no longer contains; closure is scoped to the test that ran.
- **A detection of a `remediated`, `verified` or `closed` finding** reopens it as a regression.
- **Formal risk acceptances** created under `POST /engagements/risk-acceptances` (`risk:write`; approve, reject and revoke the same) expire on their date and put their findings back in the queue. A `until` date set through `POST /findings/{id}/accept-risk` is stored on the finding but no job acts on it.

**Recent changes** (`#/changes`, `GET /findings/changes`) and the finding's **Why did this change?** panel (`GET /findings/{id}/attribution`) show every close and reopen with its recorded cause.

### Score risk

**CVSS Calculator** (`#/cvss?v=3.1`) scores a vector with the server's engine. The version tabs are CVSS v2.0, v3.0, v3.1 and v4.0.

1. `GET /cvss/metrics/{version}` returns the metric groups; mandatory metrics start on their first value.
2. Each click recomputes with `POST /cvss/score`; the panel shows base, temporal or threat, environmental score, severity and the vector. **Explain** calls `POST /cvss/explain`.
3. **Load a vector → Parse & load** scores a pasted vector and switches to its version; **Validate** calls `POST /cvss/validate`.
4. **Analyse a bulletin…** sends advisory text to `POST /cvss/assist`. A vector printed in the bulletin wins; the AI model, when your AI policy allows it, proposes only the metrics the text leaves open, and each metric carries a *bulletin* or *model* chip. The result also lists the CVEs and products the text names that exist in your inventory. **Fill the calculator with this** applies it; nothing is saved.

All calculator calls need `vulnerability:read`, although the menu entry has no gate. Nothing is written.

**VEYRS risk** (0–100) is computed per finding, not typed:

| Sub-score | Built from |
|---|---|
| Technical | CVSS × 10; 40 when no CVSS exists |
| Exploitability | √EPSS × 60, +30 for CISA KEV, +15 active exploitation or +10 known exploit or +5 proof of concept |
| Business | asset criticality × 55 + data classification × 25 + environment × 10, plus business-service and revenue bonuses |
| Exposure | exposure weight × 60 (internet 1.0, partner 0.7, internal 0.4, isolated 0.1), + attack vector points, + 15 when no privileges and no user interaction are needed, minus compensating-control credit (capped at 50 %) |

The default profile `balanced` weights them 0.30, 0.30, 0.25, 0.15. Then: KEV floor 75, internet-facing KEV floor 90, active-exploitation floor 80, and an age penalty of 3 points per full 30 days since detection, doubled once the SLA deadline has passed, capped at 15. A CVSS of 0.0 with no exploitation signal scores 0. Levels: ≥ 90 critical, ≥ 70 high, ≥ 40 medium, ≥ 10 low, below that informational. Built-in profiles are `balanced`, `technical-security`, `executive-risk`, `internet-exposure` and `compliance`.

Under **SLA & Policies → Risk profiles**: **Simulate** (`POST /risk/simulate`, `risk:read`) scores raw inputs without saving; **Re-score everything** (`POST /risk/rescore`, `risk:admin`, refused to team-scoped users) rescores every open finding and rolls the scores up to vulnerabilities. Every finding stores its explanation, shown as **Why this score** on the finding.

### Raise and track remediation

Which system owns the work is set under **Administration → Ticketing** (`GET` and `PUT /ticketing`, `settings:admin` to change, audited `organization.ticketing_mode_changed`).

```text
Internal mode:  finding -> Create ticket -> #/tickets/{id} -> Transition... -> resolved -> finding remediated
External mode:  finding -> Raise issue -> issue in the ITSM -> #/issues row -> Refresh / Unlink
```

1. From a finding, **Create ticket** (or **Raise issue**) calls `POST /findings/{id}/remediation` (`ticket:write`). The server decides by the organization's mode and answers with `kind` (`internal` or `external`) and `created`. Internal tickets take their priority from the risk score (≥ 90 critical, ≥ 70 high, ≥ 40 medium, else low) and their due date from the finding's SLA deadline. External issues are composed by the server from the finding, asset, CVE, ports and SLA date. A remote refusal is `502`; an unusable mode is `409`.
2. **Tickets** (`#/tickets`) lists open tickets (`GET /tickets`, `ticket:read`). **New ticket** (`POST /tickets`) creates one by hand; audited `ticket.create`.
3. On a ticket, **Transition…** offers only the states the server lists in `allowed_transitions` (`POST /tickets/{id}/transition`, `ticket:write`, audited `ticket.transition`). Default graph: `open` → `in_progress`, `on_hold`, `resolved`, `cancelled`; `in_progress` → `on_hold`, `verifying`, `resolved`, `cancelled`; `verifying` → `resolved`, `in_progress`; `resolved` → `closed`, `in_progress`. A `change` ticket must go `open` → `awaiting_approval` → `approved` → `scheduled` → `implemented` → `verifying` → `resolved` → `closed`; approval records the approver.
4. **Comment…** (`POST /tickets/{id}/comments`) and **Push to ITSM…** (`POST /integrations/connectors/{cid}/push/{id}`, audited `itsm.ticket.pushed`) need `ticket:write`.
5. In external mode, **Issues** (`#/issues`, `GET /integrations/links`) lists which issue covers which finding on which device. **Refresh** re-reads the remote status; **Unlink** forgets the relation without touching the remote issue (`ticket:write`).
6. **Automation → Automatic tickets** opens tickets by rule. It is off by default; **Preview** (`POST /tickets/automation/preview`) counts without writing; saving (`PUT /tickets/automation`) and the backlog **backfill** (`POST /tickets/automation/backfill`) need `ticket:admin` and are audited as `organization.auto_ticket_policy_changed` and `ticket.auto_backfill`.

ITSM connectors (Jira, ServiceNow, webhook, Confluence for publishing) are configured under **Data sources → ITSM connectors** and **Documentation** (`ticket:admin`, audited `itsm.connector.*`). Inbound webhooks are signed with a secret from `POST /integrations/connectors/{id}/inbound-secret`.

### Set policies and keep knowledge

**SLA & Policies** (`#/policies`) holds six tabs:

| Tab | What it decides | Read | Write | Audited |
|---|---|---|---|---|
| SLA policies | Deadline per matching finding; the policy with the lowest priority number wins | `sla:read` | `sla:write`, estate-wide grant only | `sla.create`, `sla.update` |
| Escalation | Who is notified after a breach | `escalation:read` | `escalation:write` (API only) | not audited |
| Assignment rules | Which team a new or re-scored finding is routed to; rules tried by ascending priority, asset team as fallback | `finding:read` | `finding:write` (API only) | not audited |
| Risk profiles | Sub-score weights and floors | `riskprofile:read` | `riskprofile:write` | not audited |
| SLA events | Warnings, breaches and escalations the sweep produced | `sla:read` | none | none |
| Upgrade paths | Vendor-mandated intermediate versions used by fix plans | `finding:read` | `sla:write` | `upgrade_path_rule.create`, `.update`, `.delete` |

A built-in SLA set ships: critical + KEV + internet-exposed 4 h, critical 24 h, high 7 days, medium 30 days, low 90 days, default 90 days. **Evaluate SLA now** (`POST /policies/sla/evaluate`, `sla:write`) runs the sweep over your scope; on the host, `veyrs run-sla` does the same.

**Knowledge Base** (`#/knowledge`) holds versioned articles: **New article** (`POST /knowledge`) and edits (`PATCH /knowledge/{id}`) need `knowledge:write`; each edit keeps the previous revision (`GET /knowledge/{id}/revisions/{version}`). **Publish to Confluence** (`POST /knowledge/{id}/publish`, `knowledge:write`) is one-way and audited as `knowledge.published`. **Documents & Advisories** stores uploaded files with their extracted CVEs and products; updates and deletes are audited as `document.update` and `document.delete`.

### Produce reports and exports

1. **Reports → Fixed reports** lists the catalogue from `GET /reports` (any signed-in user); each entry says whether your role may export it.
2. A format button downloads `GET /reports/{slug}/export?format=json`, `csv`, `xlsx` or `pdf` through an authenticated fetch. Each export checks the report's own permission and is audited as `report.exported`. Team-scoped users are refused: fixed exports cover the whole estate. **Compliance Coverage** first asks which framework and sends it as `framework_id`. **Preview** shows the report's data (`GET /reports/{slug}`) in a dialog; it is not audited, because nothing leaves the platform.

| Report | Slug | Permission |
|---|---|---|
| Executive Risk Summary | `executive` | `report:read` |
| Technical Vulnerability Report | `technical` | `report:read` |
| SLA Compliance Report | `sla` | `report:read` |
| Vulnerability Register | `vulnerability-register` | `finding:read` |
| Asset Register | `asset-register` | `asset:read` |
| Team Performance | `team-performance` | `report:read` |
| Compliance Coverage | `compliance` | `compliance:read`, and a `framework_id` parameter |
| Ticket Report | `tickets` | `ticket:read` |

3. **Reports → Builder** builds a tabular report from the server's catalogue (`GET /report-builder/catalog`) over findings, assets, vulnerabilities, tickets or the risk register. **Run** is `POST /report-builder/run`; **Export** is `POST /report-builder/export` (CSV, XLSX, JSON); **Save** is `POST /report-builder/queries`. All need `report:read`, plus the entity's own read permission; sharing a saved report needs `report:write`. Builder exports are narrowed to a team-scoped user's slice and say so in their provenance.
4. **Dashboards** (`#/dashboard`) show the same figures on screen. The **Scope** picker narrows them to one owning team (`?team_id=`) and is remembered in your profile through `PATCH /auth/me/preferences` (not audited).

### Audit log

**Reporting → Audit Log** (`#/audit`, `GET /audit`, `audit:read`) lists the organization's audit entries, newest first, filterable by exact **Action** and **Object type**. Each row shows the time, actor, action, object, a summary of the changes and the client IP. The log has no edit or delete path.

What lands here, by journey: the `*.create`, `*.update`, `*.delete` entries of users, teams, roles, API keys, assets, documents, SLA policies, risk register entries and connectors; finding transitions, assignments, acceptances and remediation; ticket creation and transitions; imports and syncs; report exports; organization switches (scanning, ticketing, risk register, directory, SSO, RADIUS, intelligence schedule); MFA changes and password changes.

What does not: sign-in, sign-out and token-refresh attempts go to a separate authentication event table that no API route or screen reads. AI calls have their own log under **AI Assistant → AI audit** (`GET /ai/audit`, `audit:read`).

### Change administration settings

**Administration** (`#/admin?tab=`) opens on **Users**. Each tab calls its own endpoints:

| Tab | Calls | Permission | Audited |
|---|---|---|---|
| Users | GET `/users`, POST `/users`, GET `/users/{id}`, PUT `/users/{id}/scope` | `user:read`, `user:write`, scope `role:admin` | `user.create`, `user.scope` |
| Teams | GET and POST `/teams` | `team:read`, `team:write` | `team.create` |
| Roles | GET `/roles`, `/permissions` | `role:read` | none |
| Departments | GET and POST `/departments` | `team:read`, `team:write` | `department.create` |
| API keys | GET, POST, DELETE `/api-keys` | `apikey:read`, `write`, `delete` | `apikey.create`, `apikey.revoke` |
| Directory | GET and PUT `/ldap`, POST `/ldap/test` | `settings:admin` | `organization.directory_configured` |
| RADIUS | GET and PUT `/radius`, POST `/radius/test` | `settings:admin` | `organization.radius_configured`, `organization.radius_tested` |
| Single sign-on | GET and PUT `/oidc`, POST `/oidc/test` | `settings:admin` | `organization.oidc_configured` |
| Ticketing | GET and PUT `/ticketing`, GET `/integrations/connectors` | `settings:read`, `settings:admin`; `ticket:read` | `organization.ticketing_mode_changed` |
| Asset sources | `/asset-sources`, `/asset-sources/drivers`, `/{id}/test`, `/{id}/sync` | `importer:read`, `importer:admin`, `importer:write` | `cmdb.source.*` |
| Import teams | `/teams/import/providers`, `/preview`, `/teams/import`, `/assign-assets` | `team:write` | teams and memberships |
| Scanning | GET and PUT `/scanning` | `settings:read`, `settings:admin` | `organization.scanning_mode_changed` |
| Risk register | GET and PUT `/risk-register` | `settings:read`, `settings:admin` | `organization.risk_register_changed` |
| Secret storage | GET `/secret-storage` | `settings:admin` | none |
| Organization | GET and PATCH `/organization` | `organization:read`, `organization:write` | `organization.update` |
| Installed software | GET `/admin/system/software` | platform administrator | none |
| Network access | GET `/admin/system/network` | platform administrator | none |
| Software update | GET `/admin/updates`, POST `/admin/updates/apply`, upload routes | platform administrator | outcome of each update shown on the tab |

Turning **Scanning**, **Ticketing** or **Risk register** on or off changes the sidebar on the same click. Directory, RADIUS and SSO secrets are write-only: the forms show whether one is stored, never its value. Platform-administrator tabs answer `403` to everyone else, including `org-admin`.

## How your role changes the flow

The built-in roles, from `security/permissions.py`. A custom role can mix any permissions; `org-admin` holds all of them.

| Role | Findings | Accept risk | Tickets | Assets | Imports | Threat Intel | Dashboards, reports | Audit Log | SLA & Policies | Administration |
|---|---|---|---|---|---|---|---|---|---|---|
| `org-admin` | Work | Yes | Create, automate | Write, delete | Yes | Yes | Yes | Yes | Write | All tabs but platform tabs |
| `security-manager` | Work | Formal acceptance (API) | Create, automate | Write | Yes | Yes | Yes | Yes | Write | Users and Teams (read) |
| `security-engineer` | Work | No | Create | Write | No | Yes | Yes | No | Read | No |
| `team-lead` | Work | No | Create | Read | No | Yes | Yes | No | Read | No |
| `asset-owner` | Read | No | Create | Write | No | Yes | Yes | No | No | No |
| `compliance-officer` | Read | No | Read | Read | No | No | Yes | Yes | Read | No |
| `executive` | Read | Formal acceptance (API) | Read | Read | No | No | Yes | Yes | Read | No |
| `auditor` | Read | No | Read | Read | No | No | Yes | Yes | Read | No |
| `service-account` | Work | No | Read | Write | Yes | Yes | No | No | No | No |
| `read-only` | Read | No | Read | Read | No | Yes | Yes | No | No | No |

"Work" means `finding:write`: triage, assign, transition. "Accept risk: Yes" means `risk:admin`, which the console's **Accept risk** uses; only the `*:*` wildcard of `org-admin` carries it among the built-in roles. "Formal acceptance (API)" means `risk:write`, which allows `POST /engagements/risk-acceptances` and its approve, reject and revoke routes, but not the console button. Threat Intel lists need `cve:read`, which `executive`, `auditor` and `compliance-officer` do not hold.

### What you see without a permission

- **The menu entry is still drawn.** Opening it shows *Access denied — Your role does not carry the permission this view requires*, with the server's `missing permission: {permission}` text.
- **The command palette hides it.** `Ctrl-K` / `⌘K` lists only screens whose console gate your cached permissions satisfy.
- **Some buttons are hidden, some are not.** Bulk actions, **Create ticket**, risk-register writes, intelligence schedule editing and the digest policy are hidden without the permission. **Transition…**, **Re-score**, **Accept risk…**, **Re-correlate** and **Delete** on the finding and asset pages are always drawn; the server answers `403` and the console shows the message.
- **Parts of a page degrade.** Getting Started, the scanner page and the dashboard team picker show *your role cannot read…* for the part they could not load.
- **A team-scoped user** sees a *Team view* banner on queues and dashboards; estate-wide operations (re-score everything, fixed report exports, SLA and assignment writes, intelligence schedule, secret storage, agents) answer `403`.
- **Signed out**, any screen shows the sign-in form; a call that carried an expired session reports *Session expired*.

## Where the work goes

| You did | It is recorded as | You find it again in |
|---|---|---|
| A finding state change, assignment, acceptance or remediation | A finding event plus an audit entry | **Why did this change?** on the finding, **Recent changes**, **Audit Log** |
| A ticket transition | A ticket event and an audit entry `ticket.transition` | The ticket's **History**, **Audit Log** |
| A ticket comment | The comment itself | The ticket's **Comments** |
| An import, connector sync or agent scan | An import run (and agent job events) | **Data sources → Import runs**, **Vulnerability scanner → Recent scans** |
| A report export | An audit entry `report.exported` | **Audit Log**, action `report.exported` |
| An SLA warning, breach or escalation | An SLA event and a notification | **SLA & Policies → SLA events**, the bell, **Notifications** |
| A setting change | An audit entry `organization.*` | **Audit Log** |
| A sign-in attempt | An authentication event | No screen; database only |

## Console behaviour that differs from the API

None known in the 0.35.3 console. The eleven gaps listed here for 0.35.1 were
fixed in 0.35.3 (see the [Changelog](/CHANGELOG.html)): Accept risk on the
finding page, New SLA policy, New risk profile, New team and Invite user
answered `422` because their payloads had drifted from the API schemas; the
Compliance Coverage export sent no framework; Preview on a report card led
nowhere; the Dashboards and Data sources gates named permissions that do not
exist; Data sources needed `importer:read` on every tab; the empty CVE and KEV
lists named a button that does not exist; and the risk-profile help text
misstated the age penalty.

`tests/test_console_dialog_payloads.py` compares the payload each create
dialog sends with the schema of the route it posts to, so that class of drift
now fails a test instead of a click.

## Related

- [User Guide](/USER_GUIDE.html): the everyday tasks, API-first.
- [User Manual](/USER_MANUAL.html): every screen and the reasoning behind it.
- [Administrator Guide](/ADMIN_GUIDE.html): roles, policies, connectors, secret storage, updates.
- [API reference](/API.html): request and response contracts.
