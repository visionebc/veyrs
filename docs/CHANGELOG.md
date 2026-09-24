# Changelog

## 0.32.0 - 2026-09-24 - one guided installer, and the password that was in ps(1)

`veyrs-setup.sh` is the single entry point for a new node. It asks the
questions once (or reads them from `--answers FILE` with `--yes`), then installs
either natively through `install.sh` or as the Docker Compose stack, from a
verified release tarball (`--source` for offline installs, a `.sha256` next to
it is checked). `--check` inspects the host and writes nothing; `--dry-run`
prints the plan and changes nothing in either mode, Docker included; a re-run
is idempotent and never rotates secrets or resets the administrator;
`--uninstall` removes the Docker install and keeps the data volumes and the
secrets file so a later install finds its data.

The Docker stack can use an external PostgreSQL (`docker/compose.external-db.yaml`).
The installer logs in from the stack network before starting anything and
refuses a role that is SUPERUSER or BYPASSRLS: either one silently disables the
row-level security that separates tenants.

The bootstrap administrator password no longer travels as a command-line
argument anywhere. `veyrs.cli bootstrap` reads `VEYRS_BOOTSTRAP_PASSWORD`, and
`install.sh`, `docker/init.sh` and `veyrs-setup.sh` all pass it that way: an
argument is readable by any local account in ps(1), and a container's processes
are in the host's process table.

New operator manual: `docs/DOCKER_COMPOSE_MANUAL.md`, covering install,
configuration, profiles, external database, backups (as superuser, verified
with `pg_restore --list`), restore, upgrade, uninstall and troubleshooting.

`scripts/publish-github.sh` gains `--release-build` and `--release`: the
release assets (installer, source tarball and their checksums) are built from
the exported public tree, verified, and attached to a GitHub release whose tag
points at the mirror commit. The token never appears in an argument list or a
temporary file.

No API change, no schema change.

## 0.31.3 - 2026-09-17 - the nav accordion

Expansion in the console navigation was a set of everything ever expanded, so
opening a section closed nothing. The set now holds at most one key per level:
opening a section closes its siblings. The section holding the current route is
forced open by the render and refuses a click instead of silently flipping a key
that decided which branch was open after the next navigation.

No API change, no schema change.

## 0.31.2 - 2026-09-14 - the 5x5 explained

"How a risk is scored" is a dialog on the Risk Register page and beside the
Likelihood/Impact selects: the whole 5x5 as a heat map, the band ranges and
what each level means. Nothing in it restates a threshold -- the heat map and
the bands are derived from `meta.band_of`, the map the API has published since
0.31.0, so moving a boundary in Python cannot leave the console disagreeing.
The dialog is not gated on `riskregister:write`: readers are the ones most
likely to need it.

## 0.31.1 - 2026-09-14 - the register's layout

The Risk Register summary row used `cols-4` without `grid`, so its four cards
fell back to stacked blocks. Fixed, together with the detail page and the three
inline forms, which used the form-field and flex-row primitives instead of the
console's card and form grids. A new guard parses compound selectors and fails
on a modifier class used without the class it modifies.

No API change, no schema change.

## 0.31.0 - 2026-09-14 - the risk register, its RACI, and the switch that removes it

Risks that are not findings -- the supplier with no exit plan, the process
nobody documented, the single person who knows how a payment batch is released.
Four RLS-forced tables (`risk_register`, `_raci`, `_links`, `_events`).
The Accountable RACI row is the owner (exactly one named person, enforced by a
partial unique index); linking a risk to the estate is optional; scores are
derived and a caller-sent score is a 422. `riskregister:*` is a new permission
resource, separate from `risk:*`.

## 0.30.0 - Confluence, and the credential flag that was lying

**`POST /knowledge/{id}/publish`** publishes a Knowledge Base runbook into a
Confluence space, and re-publishes the same page in place when the article
changes. `ExternalLink` with `object_type = "knowledge"` is the mirror -- the
same correspondence table Jira issues use.

**One way, on purpose.** Nothing is ever read back from the wiki. A page anybody
can edit is not a source of truth for a security procedure: if it were, "who
changed the remediation steps for CVE-2023-44487?" would have no answer, which
is the question a runbook exists to make answerable. Every published page
carries a footer naming VEYRS as the system of record, so the first person to
edit it in Confluence knows they are editing a mirror.

### Three Confluence traps, handled rather than discovered later

- **The version number is Confluence's, not ours.** An update must send
  `version.number` = current + 1, so the current version is READ immediately
  before the write. Deriving it from `KnowledgeArticle.version` would work
  until somebody edits the page in Confluence, after which every publish 409s
  forever and the error says nothing about why.
- **`/wiki` is part of the Cloud path and not the Data Center one.** It is
  appended for Cloud rather than demanded of the operator: "your base URL needs
  a suffix you have never typed" is a support ticket, not a configuration.
- **The v1 content API is used, not v2.** v2 is Cloud-only; v1 has the same
  path shape on both. Picking the newer one would have made Data Center
  unsupportable -- the exact mistake that left Jira DC unsupported until
  0.28.0. The credential discrimination is the same as Jira's, and its
  fall-through **raises a named error** rather than sending an empty Basic
  header.

Markdown is converted to Confluence storage format over a **documented
subset** -- headings, paragraphs, lists, fenced code, inline code, bold, italic
and links. Anything else arrives as plain paragraphs, and the console says so
next to the button: a runbook that arrives subtly reformatted is worse than one
that arrives plainly. Escaping happens **before** formatting, so a runbook that
quotes a payload is escaped rather than injected.

### The defect this phase uncovered

**`credentials_set` answered True for connectors that have no credential.**
`ConnectorWrite.credentials` defaults to `{}`, and the create path stored
`encrypt("{}")` -- a non-null column. Two silent consequences: the console
offered "replace the token" for a token that never existed, and
`itsm.test_connector`'s `if not connector.credentials_enc` branch -- the 0.28.0
diagnosis that says *"you never saved a token"* instead of letting a bare 401 be
misread as a wrong password -- **could never fire. It was dead code from the day
it shipped.** An empty dict is no longer stored as a credential, on both the
create and the rotate path.

### Also

- `GET /integrations/connectors?purpose=ticketing|documentation` filters
  server-side; the default stays the whole list, so every existing caller is
  unaffected.
- `POST /connectors/{id}/test` dispatches on the connector's own system. One
  Test button that knows what it is testing beats two the operator has to
  choose between correctly.
- `GET /knowledge-publishing` reports `ready` as *has a credential and names a
  space*, not *a row exists* -- the phase 42 lesson applied before it could be
  repeated.
- Publishing with two documentation connectors and no `connector_id` is a
  **409**, not a guess: a runbook published into the wrong space is not
  something an operator finds out about quickly.

## 0.29.0 - one ticketing system, and the relation that replaces the other

**Administration -> Ticketing** chooses who owns remediation work for a tenant:
VEYRS' own queue, or an external ITSM. Pick the external one and the **Tickets
section disappears from the console**, `POST /tickets` is refused, and what
VEYRS keeps is the **relation** -- which issue covers which finding, on which
device, raised when, due when, at what severity.

**The mode is `external`, not `jira`.** The connector layer already speaks Jira
Cloud, Jira Data Center, ServiceNow and a generic webhook; naming a tenant
policy after one vendor is the mistake that made `/rest/api/3` hardcoded and
Data Center unsupported until 0.28.0. `connector_id` names who holds the
authority, so "where did this ticket go?" is answered by a row.

### A mode, not a coat of paint

Hiding the menu would have left `POST /tickets`, `autoticket` and the workflow
engine all still writing internal rows -- an operator who believes remediation
lives in Jira while a hidden queue fills up against an SLA clock nobody is
watching. So there is now ONE creation path, `services/remediation`, and the
three call sites were moved onto it. `tests/test_phase45_ticketing_mode.py`
pins that by **AST**, so a fourth path added later fails a named test instead of
regressing silently.

Enforced where work is **created**; deliberately not where it is **finished**
or **read**:

| call | in external mode | why |
|---|---|---|
| `POST /tickets` | **409** | the internal queue is not the authority |
| raise remediation for a finding | redirected | the issue is created in the ITSM |
| automatic tickets, workflow actions | redirected | automation cannot route around it |
| transition an existing internal ticket | **allowed** | a flip must not strand 40 open tickets unclosable |
| read `/tickets` and its history | **allowed** | evidence from before the flip is not deleted to tidy a menu |
| the inbound webhook | allowed | it updates the relation |

409 and not 403: the caller has the permission, the tenant is in a state where
the request does not apply. A 403 sends an operator hunting for a role that is
not missing.

### The relation

`external_links` gained the columns that make it readable on its own:
`finding_id`, `asset_id`, `vulnerability_id`, `cve_id`, `summary`, `severity`,
`risk_score`, `due_at`, `remote_created_at`, `remote_updated_at`,
`remote_priority`, `remote_type`, `remote_assignee`. Denormalised on purpose --
a relation that can only be read by joining four tables and then calling Jira is
not one an operator can put in a report, and the snapshot stays true after the
finding is re-scored.

The new **Issues** screen prints the remote status and the *current* VEYRS
finding state side by side. A finding VEYRS has since verified as fixed while
its Jira issue is still open is the most useful disagreement this screen can
show, and it only exists because both are on the row.

- `GET /integrations/links` -- filtered in SQL, never as a client-side overlay.
- `POST /integrations/links/{id}/refresh` -- never raises for a remote failure;
  it records it. A refresh button that 500s makes an outage look like our bug.
- `POST /integrations/links/{id}/unlink` -- marks the relation inactive and
  **does not close or delete the remote issue**. VEYRS is the system of record
  for the finding, never for somebody else's queue.
- `POST /findings/{id}/remediation` -- one route, both modes. The console used
  to post to `/tickets` with a `finding_id`, which hardcoded the internal queue
  into the front end.

The issue body carries the device, addresses, service, CVE, severity, CVSS,
EPSS, KEV, risk, first-seen and due date. An engineer who opens SEC-4412 and
finds a bare CVE id with no host has been handed a riddle.

### Defects fixed on the way

- **The automatic-ticket budget was about to become silently unlimited.**
  `recent_auto_created` counts `ticket_events`, of which external mode produces
  none -- so the cap would have returned 0 forever and the automation would have
  been free to open an unbounded number of issues in somebody else's queue. It
  now counts external links in the window. That over-counts slightly, which is
  the safe direction.
- **A second console creation path.** The rapid-triage queue called the
  ticket helper directly; nothing on the Findings page or the finding detail
  would have revealed it. The AST guard did.
- `saved_views` gained the `issues` entity, and the phase 36 guard was extended
  to it -- without that, its allow-list would never have been checked against a
  real route.

Nothing is migrated, closed or deleted when the mode is flipped. The count of
open internal tickets is recorded in the audit entry at the moment of the flip,
because it is unrecoverable afterwards.

## 0.28.0 - Jira you can actually configure, and a monitoring leg

**The Jira connector was complete and had never authenticated once.** The
console posted `{username, password}`; `JiraAdapter._headers` read `email` and
`token`, and its fall-through built `Authorization: Basic Og==` from an empty
pair. Every Jira connector created from the UI returned 401, indistinguishable
from a wrong password.

- The form now asks for the credential the deployment actually takes, and says
  which is which: **Jira Cloud** = account email + API token (Atlassian removed
  password auth from the Cloud REST API in 2019); **Data Center / Server** =
  a personal access token as `Bearer`, or a real username and password.
- An unusable credential shape now raises a **named** error instead of being
  sent as an empty Basic header.
- **Data Center is supported.** `api_version` in `field_mapping` selects
  `/rest/api/3` + Atlassian Document Format (Cloud, default) or `/rest/api/2` +
  plain text (DC). The adapter had hardcoded the Cloud pair.
- An **empty description** is now an empty ADF *document*, not a text node with
  `text: ""` -- which Jira rejects with a 400.
- The **project key and issue type** are sent. The form collected a project key
  into a field nothing read, so every issue landed in the default `SEC`.

**New: `POST /integrations/connectors/{id}/test`** -- per-step diagnosis
(adapter, configuration, credentials, authenticate, project, issue type), in
the shape `/ldap/test` uses. It authenticates AND checks the project and issue
type exist: a valid token pointed at a project that does not exist otherwise
fails on the first real ticket. It never raises for a remote failure.

**New: `POST /integrations/connectors/{id}/pull`** -- `pull_status()` shipped
with the ITSM leg and no route ever called it, so the only monitoring path was
the inbound webhook, which needs the remote system to be able to reach VEYRS.
A Jira Cloud tenant cannot call into a console that is not published. Bounded,
least-recently-pulled first, and it reports what it did not reach. Unchanged
safety property: it writes `ExternalLink.remote_status` and nothing else.

**New: `PATCH /integrations/connectors/{id}`** -- edit in place and rotate a
credential without deleting the connector, which cascaded `external_links` and
threw away every VEYRS-to-remote correspondence. `system` and `slug` are not
patchable: the stored credential was entered for one system. Omitting
`credentials` keeps the stored secret. Enabling inbound with no signing secret
is a 422 instead of a silently broken row.

**Fixed: `inbound_secret_set` was declared and never populated**, so it
answered `false` for every connector including those with a secret. Joined by
`credentials_set`.

Tests: `tests/test_phase43_jira.py` (31), mutation-checked against three
restored defects. No schema change.

## 0.27.1 - 2026-09-07

**The two long configuration forms are read in order again.** Asked as: the
"Which data to collect" checkboxes and the Active Directory / LDAP
configuration look oversaturated — make them ordered.

### The saturation was a missing stylesheet rule, not too much content

`.grid2` was written into three forms in 0.27.0 and **never added to
`console.css`**. The browser drops an unknown class in silence, so every
two-column block — identification, credentials, team import — rendered as one
stacked column. The markup was right, every test was green, and the screen was
wrong.

Two more of the same kind, both shipped in 0.27.0: **`.st-ok` and `.st-warn`
have no rule**, so the asset-source table drew "Enabled" and "Disabled" as the
same grey pill, and the team-import preview drew `create`, `update` and
`unchanged` alike. A status colour that is absent does not fail — it agrees
with everything.

`tests/test_console_layout_classes.py` now fails on any class `app.js` uses and
`console.css` does not define, with an allowlist limited to five behaviour-only
hooks. Mutation-checked: removing `.grid2` and `.st-ok` fails three assertions
and names both.

### Which data to collect

Nineteen checkboxes in a wrapping flex row read as one ragged paragraph. They
are now a fixed-column grid inside four named groups (identity, classification,
platform, ownership), with `Everything` / `Nothing` / `Identity only` and a
live count. The grouping is **total by construction**: a field the API adds and
this map has not heard of lands in `Other` rather than vanishing from the
picker, and a test pins the current set against `KNOWN_FIELDS`.

The count also says what the paragraph used to bury — nothing ticked means
every field, and a subset with no match-ladder field carries the warning that
**the server will refuse it**, before the save does. The ladder names `ip`
while the field is `ip_addresses`; comparing the two literally is how the
picker would warn about a selection the server accepts.

### Directory (LDAP / Active Directory)

Five ruled sections instead of one wall, a consistent two-column field grid,
switches on their own line with the consequence next to them, and the
multi-sentence reasoning folded into `Why` disclosures — closed by default,
because it explains a decision already made for the operator. The
provisioning warning stays **visible** as a callout rather than folded: it is
the one thing on the page that can let everyone the domain binds into the
estate.

Also fixed: the "erase it" checkbox sat inside another `<label>`. Nested labels
are invalid HTML with no defined click behaviour.

No API change and no schema change. Field names, the PUT body and the read
paths are untouched; `console.css?v=12`, `app.js?v=23`.

## 0.27.0 - 2026-09-07

**Somebody else's inventory, shaped by the tenant that reads it — and teams
that come from where teams already are.** Asked as: connect NetBox, let the
connection be configured in settings, let the operator choose which data is
collected, and bring teams in from NetBox or from LDAP / Active Directory.

### The module was already written, and was half-deployed in production

The three drivers (`file`, `http_json`, `netbox`) shipped as an unreleased
commit that reached `origin/main` through the fleet auto-commit backup. On a1
its routes were **registered and answering** while `asset_sources`,
`asset_source_runs` and `asset_source_records` were **absent from the
database** — every authenticated call was an `UndefinedTable` 500 waiting to
happen. It was backed out on 2026-09-07 and is released here properly: cherry-
picked onto the deployed line, its **630-line suite run for the first time**
(51 passed) *before* any production schema was touched.

### NetBox stops being a closed schema

Three gaps, all of which failed silently:

- **`field_map` was a live column the NetBox driver never read.** It now
  applies as an **override layer** on top of the known schema. A source that
  declares nothing behaves exactly as before; a declared path that resolves to
  nothing does **not** erase the default, because an override that can blank a
  field on a typo is a way to lose every hostname at once. This is what reaches
  `custom_fields.*` — this NetBox carries `pve_node`, `pve_tags` and `vmid`,
  none of them in anybody's published schema, all three discarded until now.
- **`value_maps` are read on the RAW NetBox token**, not on the value we
  derived from it. `hipervisor` has already collapsed to `server` by the time
  the default runs, so a map keyed on the derived value could only ever say
  "every unknown role is X" — a second default, not a correction. A mapping to
  a type VEYRS does not have is refused at the **form** (422), not complained
  about on every row of a run that already happened.
- **`asset_sources.include_fields`** (new JSONB column) is an allowlist of the
  fields a source may report. Empty = every field. A **separate column, not a
  sentinel inside `field_map`**: "map this to nothing" and "do not collect
  this" would otherwise share one key. An allowlist rather than a denylist,
  because a denylist silently starts collecting whatever the next NetBox
  upgrade adds.

`field_map` targets outside VEYRS's vocabulary are kept under `extra` **only
with an explicit `extra.` prefix**. Accepting any unknown target would make a
typo (`hostnmae`) file itself under `extra` and produce an import that runs
cleanly and reports no hostnames — the existing Phase 40 test that pins this
caught exactly that regression while it was being written.

### Teams, imported rather than retyped

`POST /teams/import` with two providers, plus `/preview` and `/providers`.
The **same `plan()` backs the preview and the result**, so the screen an
operator approved and the summary they are shown cannot describe two different
things.

- **NetBox** — tenants, sites, contact groups or device roles. Tenants first:
  it is already what the asset driver reads into every device's `team_label`,
  so importing it makes those labels resolve.
- **LDAP / Active Directory** — `ldap_auth.groups()`, new. Deliberately **not**
  filtered by `group_role_map`: that map says which groups grant a *role*, and
  a team is not a role. Importing teams reads the directory **even when
  sign-in against it is off** — an estate may want AD as an org chart without
  handing it the login page.
- **`POST /teams/import/assign-assets`** points matched assets at the team
  their staged label names. Reads the **staging rows**, not the source, so it
  agrees with what was reviewed and works while NetBox is down.

Three things it may not do, each because the failure is unrecoverable:

- **It never deletes.** A team absent from the source is reported as `orphan`
  and left alone. Reconciling ownership by deletion means one expired bind
  password detaches every finding, ticket and escalation chain pointing at it,
  and nothing on screen would say so.
- **It never creates a user.** Membership seats accounts that already exist,
  matched on username then email. Provisioning from the directory is
  `jit_provisioning`, which ships off; an importer that created accounts as a
  side effect would be a way around that decision.
- **It never touches `manager_id`, `department_id` or `escalation_chain`.**
  No external system knows who gets paged.

Slug collisions are **reported as conflicts, not renumbered**. A team called
`soc-analysts-2` that nobody named is worse than a row the operator is asked
about.

### Defects found on the way

- **`assign_from_records` wrote `asset.owning_team_id`, a column `Asset` does
  not have** (it is `team_id`). On a SQLAlchemy model that is not an error —
  it sets a plain Python attribute that is never persisted. The route would
  have reported `assigned: 42` having written nothing.
- The unknown-provider 422 did not name the provider it rejected.

### Console

`Administration → Asset sources` and `Administration → Import teams`. Phase 40
shipped **API-only, with no UI at all**; without these two screens "the user
chooses which data to collect" has no door. The source form shows the field
mapping for **every** driver, not only the ones that require one — hiding it
whenever it is optional is precisely how the NetBox custom fields stayed
unreachable. Neither entry is flagged `scan: true`: reading somebody else's
inventory is what an ingest-only deployment *does*.

### State

Schema: **1 new column** (`asset_sources.include_fields`) on top of Phase 40's
three tables. New tests: `tests/test_phase42_netbox_and_team_import.py`, 35
tests. Built on `release/0.26.0`, not on `main` — `main` still carries the
half-deployed Phase 40 commit, so **`git pull origin main` on a node remains
unsafe; fetch the release branch and reset to its commit.** Environment P did
not receive this release: the ask was environment A only.

## 0.26.0 - 2026-09-07

**A second way to sign in, and somewhere else to check the password.** Asked as
one request: accept a username as well as an email address, and support Active
Directory / LDAP. Before this release VEYRS had neither -- `LoginRequest` was
`email` only, and a `grep` for `ldap|active.?directory|saml|kerberos` across the
whole backend returned two hits, one a port number in a service table and one a
comment anticipating federation. The `users.oidc_subject` column was written by
nothing and read by nothing.

### Username login

- **`users.username`**, optional, lowercase, unique **per organization**.
  `jsmith` in two tenants is two different people, exactly as two `jsmith@`
  addresses already are.
- **`POST /auth/login` takes `identifier`**, which may be a username or an
  address. The old `email` field still works and is no longer syntax-checked as
  an address, so a client that predates this release posting `email: "jsmith"`
  gets an answer rather than a 422.
- **`@` is refused in a username.** The lookup is `email == x OR username == x`
  within one tenant; a username shaped like an address would let its owner sit
  in front of somebody else's account, and the collision is unresolvable once
  both rows exist.
- Console: the sign-in field is `type="text"` -- as `type="email"` the browser
  refused `jsmith` before the form was ever submitted. Users list gains
  **Username** and **Source** columns; the invite form gains the field.

### Directory authentication (LDAP / Active Directory)

New `services/ldap_auth.py`, `organizations.settings["ldap"]`, and
`GET`/`PUT /api/v1/ldap` + `POST /api/v1/ldap/test` under `settings:admin`.
Console: **Administration -> Directory**.

- **Service account + search is the only bind mode.** Direct bind
  (`DOMAIN\{user}`) needs no service account and cannot read `mail`,
  `displayName` or `memberOf` -- so it can neither map a group to a role nor
  provision an account any notification would reach.
- **Group -> role mapping is explicit.** A group may be written as a full DN or
  a bare CN. Nothing is granted by name resemblance.
- **`UserRole.origin`** (`manual` | `directory`) makes login-time role sync
  safe. Without provenance the only options are wiping an administrator's
  hand-made exception on every login, or letting somebody removed from a group
  keep the role forever.
- **Just-in-time provisioning is off**, and its default role set is empty.
- The bind password is Fernet-encrypted and **never returned by the API**;
  `bind_password_set` answers the only question the form has.
- **An unencrypted bind is refused.** LDAPS or StartTLS, not both, not neither.
- `POST /ldap/test` diagnoses the **saved** configuration step by step --
  library, configuration, bind, search base, optional user lookup -- because
  "it does not work" has five causes needing five different fixes.

### Two doors that only close once

- **A directory login never writes a local password.** `needs_rehash("")` is
  True, so the pre-existing rehash branch would have fired on every directory
  login and stored `hash_password(the domain password)` on a row whose entire
  point is having none. The estate would have silently acquired a frozen local
  copy of every domain password typed into it, each surviving revocation
  upstream forever -- the exact failure delegating authentication removes.
- **A platform superuser is never delegated.** Every failure mode here is a bad
  directory configuration; if the account that can repair it depends on the
  directory, the deployment locks its operator out of the repair.

### Fixed on the way

- **The Organization box on the sign-in page had never done anything.** The
  console posts `organization_slug`; `LoginRequest` declared `organization`, so
  pydantic dropped it. Latent with one tenant -- but the moment an address
  exists in two, the backend answers `409 organization_required` and the
  console cannot satisfy it, ever. Both spellings are now accepted. Same family
  as the `title` of the document upload (0.21.0) and `format`/`source` (0.20.0).
- `PATCH /users/{id}` answered **500** on a duplicate username at commit time;
  it now answers 409, and names both constraints rather than only the email.

### Schema

Three columns, no new tables: `users.username`, `users.ldap_dn`,
`user_roles.origin`. `sync-schema` is the right tool.

New dependency: **`ldap3==2.9.1`** (pure Python). It is imported lazily inside
the two functions that talk to a directory, so a node that receives this code
before the package still boots and reports one clear error on the Directory
page instead of failing at import.

## 0.25.2 - 2026-09-07

**A distro package string was being compared as if it were an upstream
version, and it manufactured findings.** Found by auditing environment P after
the DMZ import: **560 of 2818 findings (20%) were false positives**, 444 of
them OpenSSH, including CVE-2001-0529 (`openssh <= 2.9`) raised against
OpenSSH 9.2p1.

The mechanism is the Debian **epoch**. `services/versions.parse()` treats `:`
as a component separator, so `1:9.2p1-2+deb12u10` parsed as `1.9.2` -- the
epoch became the major version and the host sorted *below* every range written
for OpenSSH 2.x. Measured, not inferred:

    compare("1:9.2p1-2+deb12u10", "2.9")  ->  -1        (before)
    in_range(..., end_including="2.9")    ->  True      (finding created)

`upstream_version()` already existed and already handled this correctly. It
was simply never reached: `services/inventory.install()` applied the reduction
**only when the collector omitted `version`**, and the DMZ CMDB import filled
`version` and `raw_version` with the same package string. Environment A was
never affected -- its collectors send `raw_version` alone (0 epochs across its
4246 installations).

### What changed

- **`versions.parse()` strips a leading epoch.** At the comparison layer, so no
  caller -- a future collector, a hand-typed row, a migration -- can poison a
  range check with one. An epoch is packaging metadata and never appears in an
  NVD range.
- **`versions.is_distro_version()`** is new: does this string carry packaging
  metadata (epoch, or a revision like `-2+deb12u10`, `-9`, `-1ubuntu2`)? It is
  the guard that keeps the reduction off genuine upstream pre-releases --
  truncating `7.2.4-rc1` to `7.2.4` would claim a host is newer than it is and
  **hide** findings, which is the worse direction.
- **`inventory.install()` applies the reduction to a declared `version` too**
  when that predicate says it is a package string. `raw_version` still keeps
  the verbatim string, which is what an analyst needs to spot a backport.
- **`tests/test_distro_version_normalisation.py`** (21 tests) pins both layers,
  the incident case by name, and the fact that a pre-release still sorts below
  its release.

### Known, unchanged, and reported rather than fixed

`_PRERELEASE_RANK` gives `p`/`patch`/`sp` a positive rank so they sort *above*
a bare release, but `parse()` emits them with `kind=0`, and `compare()` ranks
any numeric above any alpha at the same position. The positive ranks are
therefore dead: `9.2p1` sorts **below** `9.2`. Pre-existing, orthogonal to this
bug, and a change there moves every comparison in the product -- it needs its
own release, not a ride on this one.

## 0.25.1 - 2026-09-07

**A failed sign-in stops presenting itself as an expired session.** Reported
from environment P: an operator typed a password into the console and got
**"Session expired"** on an account created minutes earlier that had never held
a session. The node's access log settles it — four `POST /auth/login` answered
`401` with a 32-byte body, which is literally `{"detail":"invalid
credentials"}`, between two successful `curl` logins with the same account
either side. The API was right; the console relabelled its answer.

`api()` is the single client for every call in the console, the login form
included, and it ended a 401 with an unconditional `logout(); throw new
ApiError(401, 'Session expired')`. That sent the reader to inspect a token
instead of the field they had actually got wrong — and where a stale
`veyrs.rt` was still in localStorage, the same 401 first spent it trying to
rescue a request that had never been authenticated.

### What changed

- **`AUTH_ENTRY` names the routes that establish a session** (`/auth/login`,
  `/auth/refresh`) rather than consume one. Their 401 skips both the refresh
  branch and the logout, and falls through to the generic error path — so the
  login form now renders the API's own `detail`. `/auth/refresh` is on the list
  for its own reason: a refresh must never be answered with a refresh.
- **"Session expired" is now conditional on having carried a token.** A 401 on
  a request made with no session at all reads **"Sign in to continue."** —
  there was no session to lose, and saying otherwise points at an expiry that
  never happened.
- Fixed in `api()`, not by forking the login call path: one client, one 401
  policy. `tests/test_login_error_message.py` pins the route list, both guards,
  the wording condition, and the API verdict the console has to relay
  (including that an unknown account and a wrong password are indistinguishable
  — the form must not enumerate users).

- **`docs/DEPLOYMENT.md` "Upgrading" now copies the console to the docroot.**
  The step was missing from the runbook, and the omission is not cosmetic:
  `git pull` updates the checkout while nginx serves a *copy* under
  `/var/www/veyrs-console`. Environment P spent a day serving the 0.22.0
  console (`app.js?v=16`) against a 0.25.0 API because of it, with every
  surface answering `200` and no health check able to see the mismatch. The
  runbook now verifies the artefact (`md5sum`), not the status code.

No schema change, no API change. Console `app.js?v=20`.

## 0.25.0 - 2026-08-28

**An ingest-only deployment stops advertising a scanner.** 0.20.0 shipped the
switch that turns active scanning off and deliberately left the navigation
alone: the Vulnerability scanner page got a *banner* instead of being hidden,
on the reasoning that an operator staring at an empty queue must be able to
tell "nothing is scheduled" from "this deployment does not scan". That
reasoning was right about the question and wrong about who has to answer it.
The operator of an ingest-only platform does not want a page explaining that a
capability is off; they want a console that describes the product they run.

### What changed

- **`GET /auth/me` now carries `active_scanning`.** The console reads it once
  at boot, alongside `preferences`, and hides the **Vulnerability scanner**
  entry — from the sidebar and from the command palette — while the tenant is
  ingest-only. Flipping the switch moves the menu in the same click; nobody has
  to reload to see it.
- **Findings, Assets, Getting Started and the intelligence estate-lens banner**
  stop naming a producer this deployment does not have. Getting Started also
  stops issuing the two agent/queue requests that can only come back empty.
- **`#/agents` is gone.** That hash was never a registered route: the "No
  software inventory" banner on the intelligence page had been sending
  operators to *No view is registered* since the estate lens shipped in 0.23.0.

### What deliberately does NOT move

Three doors that only close once, each pinned by a test:

- **`Administration → Scanning` stays in the menu.** It is the switch. Hiding
  it together with the thing it controls is a one-way door: whoever turned
  scanning off would have no menu path left to turn it back on.
- **`Data sources` stays.** Ingestion *is* the mode. A menu with no import
  screen would be perfectly consistent and the product would be dead.
- **`route('scanner')` stays registered.** A bookmark or a link in somebody's
  runbook must not land on *No view is registered*, and the page already
  carries the banner naming the mode and linking to the switch.

### Why the flag rides on the identity

It could not come from `GET /scanning`. That route requires `settings:read`,
and of the ten built-in roles only the wildcard `org-admin` carries it — so a
console driving its menu from it would clean the nav for exactly the persona
that did not need it cleaned, and take a 403 for everyone else. The mode is
tenant state, not a permission, and it is already read-open by design.

The default is `true` and every failure path leaves it `true`, including an API
too old to send the field (`!== false`, never a truthiness test). A hidden menu
entry is indistinguishable from a page that was removed, and the operator has
nothing left to click to find out which it was.

## 0.24.0 - 2026-08-27

**The dashboard scope is remembered in the user's profile.** Filtering the
dashboards to one team has been possible since 0.16.0; keeping that choice has
not. Every reload, every new browser and every link from an email put the
operator back on the whole estate, so somebody who runs one team re-picked it
several times a day and, on the occasions they forgot, read an estate figure
as theirs. The filter was already correct. What it lacked was a memory.

### What changed

- **`users.preferences`** — a new JSONB column, whitelisted to the keys in
  `api/v1/auth.PREFERENCE_KEYS` (`dashboard_team_id`, for now). Deliberately
  not folded into `users.attributes`: that column is reserved for the policy
  engine, and a value the user may write about themselves must not share a
  namespace with one an authorization decision will later read.
- **`GET` and `PATCH /auth/me/preferences`.** PATCH, not PUT: a console that
  predates a key would wipe it on every save under replace semantics.
  `extra="forbid"`, so an unknown key is a 422 rather than an unbounded blob
  written to a user row by anyone holding a session.
- **`GET /auth/me` now carries `preferences`.** A second call at boot would let
  the first dashboard paint under the estate scope and then jump — half a
  second of figures nobody asked for, which is the misread this screen exists
  to prevent.
- **Console:** the Scope picker on Dashboards saves as you use it. Three
  sources resolve one answer, in order: `?team=` in the URL (a link somebody
  followed — it wins for that render and is *not* written back, so a
  colleague's screenshot link cannot silently repoint your dashboard), then the
  profile preference, then the estate.

### The three ways this goes wrong, and where each is stopped

- **A stored id rots.** The server refuses a dangling team on write, which does
  nothing for the row that was valid when it was written. A team deleted
  afterwards must degrade to the estate view rather than 404 the dashboard on
  every load for the one person who had it selected — so the console validates
  the saved id against the current team list before using it.
- **"Whole estate" must be sayable.** `null` is a value, not an absence:
  `exclude_unset` keeps "I choose the estate" apart from "I did not mention
  this key". Fold them together and the picker becomes a one-way door.
- **The estate choice is explicit in the URL (`team=all`).** With no token for
  it, picking Whole estate produces a URL with no `team=`, which the next
  render reads as "use the preference" — and the picker springs back to the
  team just left. Invisible until the preference is non-empty, which is
  precisely when the feature is in use.

### What this is not

A preference is a **default, not an authorization**. Nothing server-side reads
it to decide a scope: `?team_id=` is resolved from scratch on every dashboard
read and can only ever intersect the caller's own grants. A role narrowed at
09:00 is obeyed, not overridden by a value written at 08:00. Saving a team
outside your scope is accepted — refusing there would make the route a second,
weaker copy of the scope check — and changes not one figure.

Not audited, on purpose: the picker writes on every change, and an audit trail
that fills with "looked at one team instead of the estate" buries the entries
somebody will one day need to find.

### Where the console half lives

The `frontend/console` edits for this release are in commit **`961c182`**, not
here. A concurrent session working the same checkout committed and pushed while
this change sat in the working tree, and its message — *"console: point the
finding AI buttons at the /ai router"* — describes only its own six lines. It
was already on `origin/main` when this was noticed, so it was left alone rather
than rewritten under a session that may still be running. If you are bisecting
the Scope picker's memory, `961c182` is the commit.

### Trap recorded on the way

`teams` and `team_members` are RLS-FORCED **with no unbound escape**, unlike
`users`, whose policy carries a `COALESCE(..., organization_id)` so login can
find an account before the tenant is known. A `SessionLocal()` that has not had
`veyrs.current_org` set therefore reads **zero teams with no error**. In a real
request this is not a hole — `get_principal` binds the tenant and FastAPI
caches `get_session` per request, so `DbSession` is the same bound session —
but any probe script that reasons about team membership from an unbound session
is measuring RLS, not the data.

## 0.23.0 - 2026-08-26

**The estate lens. The intelligence screens browsed a 359 353-row global
catalogue with no way to reduce it to the software this organization actually
runs — and the one column that promised to do it had never been populated.**

Raised by the operator, in these words: *"if we do not have SQL in the fleet,
no SQL vulnerabilities should show up here."* Correct about the reading, wrong
about the storage, and the whole design sits on that distinction.

Measured against production before anything was written:

| | |
|---|---|
| `cve` / `cve_cpe_match` / `vendors` / `products` | 359 353 · 3 096 014 · 37 345 · 171 284 — **no `organization_id` on any of them** |
| CVEs whose applicability names installed software | **2 578** (0.7 %) |
| KEV entries that do | **8** of 1 678 |
| `asset_products` | 4 246 installations, 978 distinct products, 0 unresolved |

### What changed

- **`GET /intel/cve` and `GET /intel/kev` take `affects_estate`, default
  `true`.** The predicate is applied before the count, so `total` is the
  narrowed number and pagination walks the narrowed set — the failure the
  vendor list carried until v0.21.0, where a page was sorted after being
  paginated and looked ranked without being ranked.
- **`GET /intel/health` reports `cve_affecting_estate`, `kev_affecting_estate`
  and an `inventory` block** (installations, resolved, unresolved, distinct
  products).
- **Console:** the Intelligence counters lead with the estate figure and always
  print the catalogue figure beside it; both lists carry a two-button switch
  labelled with the row count behind each option; the lens lives in the URL so a
  shared link carries the same view; and an unresolved or absent inventory
  raises a banner where the numbers are.

### The defect this uncovered

**`CveSummary.affected_assets` has been a declared field since the schema was
written and `_summary()` never set it.** The console's *Your assets* column
therefore rendered `0` on every row of a catalogue with 408 open findings behind
it — a surface that renders perfectly while stating something false, the same
family as the five blank Integrations columns fixed in v0.19.0. It now counts
distinct assets with an open finding, for the rows on the page only.

### Decisions worth not re-litigating

- **The corpus stays global, and shrinking it was refused.** Correlation is
  computed *from* the dictionary: a CVE that was never ingested cannot fail to
  match an asset, it is simply missing, and missing renders as *not affected*.
  Ingesting "only what affects us" is circular and it fails silently — which
  `services/inventory` already documents as the most dangerous bug it has.
- **The lens is product-level, not finding-level.** A CVE for a version you are
  not currently on stays in the list; it is yours the day somebody rolls a host
  back. Finding-level is the Findings page.
- **The whole catalogue stays one parameter away.** *"Does this bulletin affect
  us?"* and *"should we adopt this component?"* cannot be answered by a tool
  that can only show you what already affects you.
- **Both numbers, always.** *"17 CVEs affect you"* is reassuring and meaningless
  without *"of 359 353 known, over 978 products we could resolve"* beside it.
  An estate that shrank because the inventory broke looks exactly like one that
  got patched.

### Performance, because the shape of the query is load-bearing

`EXISTS (... WHERE m.cve_id = cve.id)` and `id IN (SELECT ...)` return the same
rows. On production the first plans a semi-join over the CVE table and takes
**1 079 ms**; the second drives off `ix_cve_cpe_product` and takes **16 ms**.
The slow one would run on every page load, because it is what produces `total`.
A test pins the fast shape so a well-meaning simplification cannot quietly
reintroduce a 67x latency regression on the busiest screen in the console.

### Traps recorded on the way

- **`asset_products` is RLS-forced**, so the filter had to move to
  `TenantSession`: on a plain `get_session` it returns zero rows with no error,
  which would have hidden the entire catalogue and looked like a working filter
  over a clean estate. A test asserts the annotation on all three routes.
- `intel.py` carries `from __future__ import annotations`, so
  `inspect.signature()` hands back the *string* `"TenantSession"` — use
  `eval_str=True` or the assertion fails while the code is correct.
- **`"open"` is not a finding state.** `OPEN_STATES` starts at `new`; the column
  is a plain varchar, so a row written with an invented state is accepted and
  then counts as nothing, anywhere.
- The first version of the single-definition guardrail swept the whole backend
  and flagged `services/correlation.py`. That was a false positive worth
  keeping the reasoning for: correlation resolves *version applicability per
  asset*, a strictly narrower question. The guardrail now watches the router
  layer, where a second copy would actually be a bug.

Suite **5365 passed, 1 failed** of 5366 collected (was 5351). Tests:
`tests/test_phase37_estate_lens.py` (15). No schema change. Console
`app.js?v=17`.

**The one failure predates this change and is not part of it.**
`test_phase18_hardening.py::test_the_exposition_names_the_worker_that_answered`
gets `404` from `/metrics` under `TestClient`. Verified by stashing the three
modified files and re-running that test alone: it fails identically on a clean
tree. `backend/veyrs/main.py` has not been touched since phase 18. Left open
deliberately rather than folded into this release — it is a separate defect in
the observability path and deserves its own diagnosis.

## 0.22.0 - 2026-08-23

**The disposition half. VEYRS could see everything and dispose of nothing: a
triage queue, saved views, a daily digest and a command palette, plus five
console surfaces that rendered perfectly over contracts the API never had.**

The measurement this round started from, read-only against production:

| | |
|---|---|
| Findings | **408** — 149 never touched, 258 assigned, **1** remediated |
| Tickets | **5**, for 408 findings |
| Risk acceptances · documents · webhooks · API keys | **0 · 0 · 0 · 0** |
| Notifications generated · delivered outside the console | **74 · 0** |
| `organizations.settings` | **`{}`** — every automation at its default |
| Users | 2, one of whom had not signed in for 13 days |

The ingestion half works. What did not exist was **anywhere to make a
decision**, **any way to keep the query you make it from**, and **any reason to
come back tomorrow**. Adding a twenty-ninth screen would have made that worse,
so nothing here is a new module: it is the missing verbs.

### `#/triage` — one finding, four decisions, no mouse

The first entry in the nav and the console's landing route. It hands you the
open findings of one queue, one at a time, with what is needed to judge them —
the asset and how exposed it is, the CVE, EPSS, KEV, the deadline, the risk
factors and the recommended fix — and four verbs: **ticket**, **assign**,
**false positive**, **accept risk**, on `T` `A` `F` `R`, with `S` to skip and
`J`/`K` to move.

- **Nothing new was added to the API.** Every action was already there and
  unreachable from any screen. The ticket route has deduped per finding since
  phase 4; the console never called it from a queue.
- **A dashboard is not a place to work.** The landing route moved from
  `#/dashboard` to `#/triage`. Anyone who wants the numbers is one click away;
  nobody was one click away from acting on them.
- **Accepting a risk from `new` transitions to `triaged` first**, and says so.
  `ALLOWED_TRANSITIONS['new']` has no edge to `accepted_risk` — so an Accept
  button that did not know this would have 409'd on 149 of the 408 findings in
  production, which is to say on the most common case on the screen.
- **A disposed finding leaves the buffer rather than advancing the cursor**, and
  the buffer refills from the next page before the queue is declared clear.
  Otherwise "12 of 149" counts work already done, and fifty findings read as
  four hundred.
- The keyboard yields to text fields and to any open dialog: a keystroke that
  fires while a reason is being typed disposes of the finding being explained.

### Saved views

`saved_views` (new table, RLS-forced) plus `/api/v1/saved-views`. Chips on
Findings, Tickets, Assets and Vulnerabilities; a **Save this view** button on
each; three starter queues seeded per user on first visit — and never re-seeded
for somebody who deleted them, which would be the console arguing with them
once a day.

- **A view stores a QUERY, never an answer.** Applying it goes back through the
  entity's own list endpoint, which is permission- and team-scope aware, so a
  shared estate-wide view opened by a restricted operator returns their slice
  rather than 403ing or leaking somebody else's estate. That is why the router
  is exempt from team scope — and, unlike `policies` before v0.17.1, the claim
  is asserted by a test that reads the router's source.
- **Filters are validated against an allow-list at write time, and unknown keys
  are REJECTED rather than dropped.** An unvalidated blob is a place to park a
  parameter and wait for a future release to start honouring it; a silently
  dropped one returns 201 for a view that answers a different question.
- The allow-list is asserted against the **actual signatures** of the four list
  routes, so a renamed parameter breaks the suite instead of quietly producing
  views that filter nothing.
- `page`/`size` are not saveable. A view pinned to page 3 shows nothing the day
  the queue gets shorter.

### The daily digest

`organizations.settings["digest"]`, `services/digest.py`, `veyrs digest`, and
`veyrs-digest.timer` — an hourly **tick**, not a schedule: the hour lives in the
setting the console shows, so `OnCalendar` cannot silently disagree with it.

- **Off by default**, per organization. Turning it on starts mail for everyone.
- **Recipients come from permissions, not from team membership.** Membership
  answers *whose queue is this*; grants answer *what may you read*. A digest
  sent on membership mails somebody the estate they just joined.
- **Every digest is built under its own recipient's scope** — not one estate
  digest fanned out to a list. An email carries no scope banner to qualify the
  number in it.
- **An empty digest is not sent.** A daily "nothing happened" trains its reader
  to delete it unread, and then the one that matters goes too.
- **Preview and send are the same function**, the discipline
  `autoticket.matches()` was written with: two implementations is how a preview
  promises 12 and the send produces 300.
- `/notifications/preferences` finally exposes `NotificationPreference`, which
  has existed since v1 with no way to read or write it. Muting an unmutable
  event is a **422**, not a row `_muted()` ignores — a switch that stays on is
  worse than no switch.

### ⌘K, and the two search surfaces that never worked

A command palette over the nav, the triage queues, the saved views and the same
permission-aware `/search` the Search page uses.

### Five console surfaces that rendered perfectly and were wrong

Same family as the Integrations page in v0.19.0 and the upload dialog in
v0.21.0: no status code ever changes, so nothing looks broken.

1. **The notifications list read `created_at`, `kind` and `message`.** The route
   returns `at`, `event`, `subject` and `body` — three blank columns on every
   row since the page existed, over 74 real messages. Its "Mark read" button was
   never wired to a handler at all.
2. **The Search page read `.items`.** `GET /search` returns
   `{results: {type: [...]}}` and never had an `items` key, so `pageOf()`
   yielded an empty list and every search printed "No matches", including the
   ones that matched.
3. **`GET /findings` was documented internally as `limit`/`offset`.** It takes
   `page`/`size` like the other list routes.
4. **`PATCH /saved-views` would have ignored `entity`** — pydantic drops an
   undeclared field, so the client gets 200 and an unchanged row. It is declared
   in order to be refused.
5. **The empty state could not tell "never configured" from "over-filtered".**
   Every list showed the same "Nothing here yet" whether the module had never
   been set up or a filter simply matched nothing. `listView` now picks on
   whether any filter is applied, and the unconfigured branch names the setup
   steps with links.

### Schema

One new table (`saved_views`) — so `init-db`, not `sync-schema`, which
reconciles columns on existing tables and would have reported
`0 columns added` for a table that does not exist. 79 → 80 tables, RLS enabled
and forced.

**Suite: 5349 passed, 0 failed** (was 5305). New: `tests/test_phase36_disposition.py`.

## 0.21.0 - 2026-08-23

**The console stops being a rendering of the data model. Configuration is
separated from daily work, four screens that could not be configured now can
be, and three controls that looked like they worked are fixed.**

This round came from twelve questions and change requests, and most of them
turned out to be the same complaint: VEYRS exposed everything it knows to
everybody, in the vocabulary of its own schema, with no way to tell platform
configuration from a work queue and no way to change the things that *were*
configuration.

### The navigation splits along one axis

Eight groups became seven, organised by **how often you touch them** rather
than by which part of the schema they render.

- `Governance` is **gone as a group.** It held four unrelated things whose only
  common property was that senior people cared about them: Compliance and
  Reports are outputs and moved to `Reporting`; Integrations and Administration
  are setup and moved to `Configure`.
- `Work` (Findings, Tickets, Vulnerabilities) and `Estate` (Inventory) are the
  daily lane. `Configure` holds the scanner, data sources, SLA & Policies,
  Automation and Administration.
- **The vulnerability scanner moved out of the daily lane.** Phase 33 put it
  first under `Risk` on the reasoning that *a reader who cannot find what
  produced the findings assumes nothing did* — still true, and now served by
  the Findings page naming its three producers and linking to each, rather than
  by a menu position. `test_phase30_scanner_page` was **rewritten rather than
  deleted**: the assertion changed, the concern it encoded did not.
- `#/workflows` **redirects** to its new home. A bookmark landing on "no view
  is registered" teaches people the console is unreliable.

### Every configuration screen explains itself

A new `explainer()` panel answers the same three questions in the same order:
*what this decides · who normally touches it · **what changes if you change
it***. The third is the one that was always missing — "Escalation policy" names
the row; "raise a level here and the CISO starts getting paged at hour 24"
tells an operator whether to touch it. Collapsible, remembered per browser, and
**version-keyed** so rewriting an explainer re-opens it for people who had
dismissed the old text.

### Workflows: a guided builder instead of hand-written JSON

`services/workflow.ACTION_SCHEMA` describes every action — label, summary, what
it needs in context, and its fields — **next to the functions that execute
them**, and `/workflows/actions` returns it. The console renders its form from
that, so the form and the engine cannot describe a step differently. An
`assert` keeps `ACTION_SCHEMA` and `ACTIONS` the same set at import.

This closes the defect phase 29 found and could only document: the console's
example put parameters under `"params"` while the engine reads
`step.get("config")`, so every workflow built from it ran with an empty
configuration **and reported success.** The builder cannot emit that shape, the
list view flags any existing step that has it, and the editor reads `params`
when opening an old workflow so nothing is silently blanked.

Also fixed: `POST /workflows` requires a `slug` the old editor never sent, so
"New workflow" had **never once worked**.

### Automatic ticket creation

`services/autoticket.py` + four routes under `/tickets/automation`. Production
had 407 findings and 0 tickets; the capability existed and nothing exercised it.

**Off by default, and enabling it changes nothing about findings that already
exist.** Both deliberate: an estate with hundreds of open findings would
otherwise produce hundreds of tickets, each with a reference number, an SLA
deadline and notifications, from one click — and undoing that is manual.

- `matches()` is the **single** predicate. The preview, the backfill and the
  live hook all call it; two implementations of "which findings matter" is how
  a preview promises 12 and the automation produces 300.
- `preview()` answers *how many tickets this would create* from the real
  estate, writing nothing, and accepts a hypothetical policy so the console can
  answer "what if I set the threshold to 50?" before anybody saves it.
- The cap is enforced from `ticket_events` over a **wall-clock hour**, not from
  a counter threaded through the call path. There is no such thing as "a run":
  findings are processed one at a time from four entry points, and a per-process
  counter would give each API worker its own full budget.
- The backlog is an explicit `backfill()` with `dry_run` defaulting to **True**,
  and a hit cap is **reported** (`capped`, `remaining`). A clean count over
  silently dropped work is how a backfill gets believed and re-run forever.
- Hooked into `correlation.process_finding` **after** scoring, assignment and
  SLA: the policy reads `risk_score`, `assigned_team_id` and `sla_due_at`, and
  evaluating it earlier would judge every finding on values that are still
  None — which reads as "nothing qualifies" rather than as a bug.
- `security-manager` gains `ticket:admin` explicitly. Without it the only
  identity able to configure this would have been the wildcard org-admin.

### The intelligence cadence became a setting

`services/intel_schedule.py` + `GET`/`PUT /intel/schedule` + `veyrs intel-due`.
`veyrs-intel-sync.timer` now **ticks hourly** and the script asks the database
what is due, so changing a cadence no longer means editing a systemd unit over
SSH. Defaults reproduce the previous behaviour exactly: four feeds, all
enabled, all daily.

Two properties that are stated in the payload rather than hidden:

- **Due is measured from the last *successful* run.** A failure does not reset
  the clock, so a broken feed keeps reporting itself as due.
- **The corpus is shared**, so the effective cadence is the **tightest demand
  across active tenants**. Both numbers are shown, because an administrator who
  sets 24h and observes 1h is not looking at a bug. Averaging would give
  everybody a cadence nobody chose; taking the loosest would let one tenant
  starve another, in the direction of stale intelligence.

`run-sla` now runs on **every** tick rather than nightly: deadlines elapse with
the wall clock, not with the arrival of new intelligence, and the escalation
engine only ever moves a finding *up* a level, so an hourly sweep is not
chattier — it is just less late.

**The bug this shipped with, caught by its own test.** The first draft matched
`FeedRun.status == "success"`; the column holds `"succeeded"`. Every feed
reported "never completed successfully" and the scheduler would have run all
four on every hourly tick — a cadence setting that silently does the opposite
of what it says. `last_run` now delegates to
`intelligence.last_successful_run`, and a source-level test asserts there is no
second copy of that predicate anywhere in the module.

### The CVSS calculator reads bulletins

`services/cvss_assist.py` + `POST /cvss/assist`. Paste an advisory; VEYRS
extracts the CVE identifiers and any printed CVSS vector, cross-checks both
against **your** inventory, and asks the model only about the metrics nothing
else could settle — with a per-metric rationale.

Three refusals make it a helper rather than a liar:

- **The score is never the model's.** Whatever vector comes out is scored by
  `engines.cvss`, validated against the official corpora.
- **A printed vector beats a proposed one, always**, and every metric carries a
  provenance chip. Touch a metric yourself and the chip clears — provenance
  that survives being overruled is a lie.
- **Every proposed value is validated against the official catalogue and
  dropped if unknown**, with the rejects reported. A model answering `AV:Q`
  must not reach a form that then 422s at the user.

The bulletin goes in as `AiRequest.untrusted` and is fenced: an advisory
containing "ignore previous instructions" is exactly the input this feature is
designed to accept.

`cvss` moved from `EXEMPT_TAGS` to `SCOPED_TAGS` — that set asserts its routes
carry no asset- or finding-level rows, and this one now reads both. The same
reclassification `policies` needed in v0.17.1, for the same reason: a tag is a
claim about **every** route beneath it.

### The estate can be asked what it is *not*

`GET /assets` gains `exclude_environment` and `exclude_exposure`, and the
positive `exposure`/`environment` filters accept comma-separated lists.
*Inventory → Non-production* and *→ Not internet-facing* are now one click.

Negation is its own parameter rather than four positive options because the two
are not equivalent in practice: "not production" has to keep meaning that when
a sixth environment is added, and a client spelling out the five it knows about
would silently stop covering the estate — while still returning rows.

### Documents became filable

`documents` gains `title`, `notes`, `team_id`, `vendor_id` and
`manual_cve_ids`, plus `PATCH /documents/{id}` and filters by team, vendor, CVE
and title. Renamed *Documents & Advisories* in the nav: next to "Knowledge
Base", "Documents" read as "files somebody uploaded" and gave no clue that this
is where a vendor advisory goes.

- **`filename` is not editable.** It is evidence: the content hash was taken
  over those exact bytes. `title` is the field for a nicer name.
- **Hand-attached CVEs live in their own column.** Machine-derived and
  human-decided have different lifetimes; appending to `cve_ids` would let the
  next re-extraction silently discard somebody's judgement. Searching by CVE
  covers both.
- **A CVE outside the catalogue is refused.** A document may reference a
  vulnerability; it cannot invent one.

Also fixed: the upload dialog appended `title` to the multipart body while the
route declares it as a query parameter, so **every document uploaded through
the console was filed under its filename** and the title field did nothing.

### `GET /intel/vendors`

The CPE dictionary made reachable, with an `installations` count per vendor and
`?in_use=true`. Documented in the manual as what it is: **the global CPE
dictionary, shared by every tenant — not third-party risk management.** A
dictionary of 37 345 vendors is noise until you can see which 978 of them
describe your estate.

The first implementation sorted the page **after** paginating it, which
produced a list that looked ranked and was not: the alphabetically-first 50
vendors, all with zero installations, tidily sorted among themselves. The
ranking is now a join and an `ORDER BY`.

### `audit.scrub` no longer 500s on a UUID

Found by a new test, and a real defect with a nasty shape: `audit.diff({"team_id":
<UUID>}, ...)` raised *Object of type UUID is not JSON serializable* inside
`session.commit()` — **after** the business change had been flushed. The
operation was lost, and the audit entry meant to record it was what killed it.
Every ownership column in this schema is a UUID, so the fix is in `scrub()`
rather than at one call site: non-JSON-native values are rendered
(datetimes to ISO-8601, everything else to `str`) rather than dropped.

### Documentation

`docs/USER_MANUAL.md` gains six sections and grows by ~470 lines: how the
console is organised, what nuclei actually is and how VEYRS drives it, the risk
formula factor by factor, where the CVEs come from, finding versus
vulnerability, how tickets open, SLA & Policies tab by tab, what the vendor
dictionary is, documents, and the bulletin assistant.

Suite **5305 passed, 0 failed** (was 5258). Schema: 5 columns, 2 FKs, no new
tables. Console `console.css?v=10`, `app.js?v=15`.

## 0.20.0 - 2026-08-23

**VEYRS now harvests the estate's software inventory out of the scan it already
downloads, and can be told to stop scanning altogether — running as a pure
vulnerability management and traceability platform on top of somebody else's
scanner.**

Two features that look unrelated and are the same statement.

### The scan report answers two questions; VEYRS read only one

A Nessus export says what is *wrong* with each host **and** what each host
*has*. The second is the thing the correlation engine joins CVEs against, and
until now the import path threw it away: `services/inventory` was fed only by
the execution agent and by hand.

- **`ImportOptions.import_inventory`** adds a second *read* of the same bytes,
  never a second ingestion route. It produces `AssetProduct` rows and no
  findings, so it cannot touch deduplication or reconciliation.
- **`ScannerConnector.import_inventory` defaults to True**, and the asymmetry
  with the hand upload (False) is deliberate: a person uploading one export is
  triaging a file, a connector exists to keep the platform fed from a scanner
  it does not control.
- Provenance is per source: `scanner:nessus` for an upload,
  `connector:<slug>` for a pull, alongside the existing `agent:<slug>` and
  `fleet-ssh`.

**The bug this feature would have had, and does not.** Nessus reports a host's
software identity in `HostProperties` as **CPE 2.2 URIs**
(`cpe:/a:openbsd:openssh:9.2p1 -> OpenBSD OpenSSH 9.2p1`), and
`versions.parse_cpe23` returns `None` for anything not starting `cpe:2.3:`.
Passed straight through, every tag would have skipped
`inventory.resolve_identity`'s most authoritative path — *the scanner told us
exactly which dictionary entry this is* — and fallen back to inferring from a
vendor string. `services/inventory` names that as the most dangerous bug in the
module, and it does not raise: it reports an estate as unaffected.
**`versions.cpe22_to_cpe23`** does the conversion, strips the human gloss, and
round-trips 2.2 percent-encoding into 2.3 backslash escaping so `c%2b%2b` and
`c\+\+` stay one product.

Four refusals in `ingest_inventory`:

- **it never replaces.** `install(replace=True)` prunes rows a source no longer
  reports — right for an agent sweeping a host it owns, wrong here. An
  unauthenticated scan following a credentialled one would delete real
  inventory every time;
- **it never invents an asset on its own terms**, deferring to `create_assets`;
- **a dry run writes nothing**;
- **its rejects are counted separately.** `records_rejected` is a statement
  about findings; folding "this host is not in the register" into it would make
  an import look like it dropped vulnerability data it never had.

A failure in the inventory pass is recorded on the run and swallowed: losing
the vulnerability data because a software list was malformed would be strictly
worse than importing without inventory.

**Software-enumeration plugin output (Nessus 20811/22869) is opt-in and off by
default.** A CPE tag is the scanner naming a dictionary entry; a line of plugin
output is prose being guessed at, and a wrong guess does not fail loudly — it
mints a Product row that looks populated and matches no CVE. Lines that do not
fit a known rpm/dpkg/Windows shape are skipped rather than approximated.

New `ImportRun` counters (`inventory_hosts`, `inventory_added`,
`inventory_updated`, `inventory_unmatched`) are returned by `ImportRunOut` and
shown on the Import runs table — phase 33's lesson that a counter the API never
returns is a blank column nobody notices.

### Active scanning can be turned off

`organizations.settings["scanning"]` + **`services/scanning.py`** +
`GET/PUT /api/v1/scanning`. With it off, VEYRS probes nothing: findings arrive
from uploads, connectors and agent results, and the platform does triage,
ownership, SLA, ticketing and traceability on top of them.

Hiding a button is not a control — that is the MFA-that-checked-presence defect
of phase 24 wearing different clothes. The switch is enforced where work is
**created** and where it is **handed out**, and deliberately not where work is
**finished**:

| call | with scanning off | why |
|---|---|---|
| `queue_job` | refused (**403**) | no new scan is scheduled |
| `claim_next` | refused | **the one that matters** — work queued before the flip must not drain into the estate afterwards |
| `enroll` | refused | a runner cannot be added to a platform that does not scan |
| `heartbeat` | allowed | answers `active_scanning: false` so a live agent stands down instead of polling a locked door |
| `submit_result` | allowed | that scan already touched the estate; refusing its output discards it and wedges the job in `running` forever |
| `/self/inventory` | allowed | reporting what is installed is not scanning |
| imports and connector pulls | allowed | ingestion is the entire point of the mode |

- **403, not 422.** There is no correction to the request body that would make
  it work, so `_refused()` now distinguishes the two.
- **Queued jobs are cancelled** when the switch goes off (opt-out), through
  `agents.cancel_job` so each one lands in its own event stream and in the
  audit log. A job that can never be claimed is not queued, it is stuck.
  Jobs already `running` are left alone.
- **`settings:admin`, and never a team-scoped grant**: a team that could stop
  scanning would silently stop the sweeps every other team depends on.
- The Vulnerability scanner page carries a banner rather than disappearing from
  the nav — an operator at an empty queue must be able to tell "nothing is
  scheduled" from "this deployment does not scan".

`tests/test_phase34_inventory_and_scanning.py` (26) includes a source-level
guardrail over `services/agents.py`: the three work-creating paths must consult
the gate, and `submit_result` / `submit_inventory` / `heartbeat` / `fail_job`
must not. Suite **5258 passed, 0 failed**. Schema: 6 columns added, no new
tables.

## 0.19.0 - 2026-08-23

**VEYRS can now go and fetch a scan instead of waiting to be handed one, and
the Integrations page stopped lying about the API it talks to.**

### Scanner connectors — the pull path

`ScannerConnector` + `services/scanners.py` + six routes under
`/api/v1/integrations/scanners`. Three drivers: **Nessus Professional /
Manager**, **Tenable Vulnerability Management** (cloud) and **Tenable Security
Center**.

The design constraint that shaped everything: **a pulled export goes through
`importers.run_import`, and therefore through `parsers.parse_nessus`, the same
parser an uploaded file uses.** A driver's entire job is to end up holding the
bytes an operator would have downloaded by hand. A second ingestion route would
mean a second deduplication rule, two sets of reject counters and two answers
to "why did my findings double".

Four refusals, each enforced in code rather than described in a form:

- **A new connector is created disabled and inert.** `is_enabled` defaults to
  False and `allowed_scans` defaults to empty, where **empty means inert, not
  "every scan"**. The blast radius of a sync is the set of scans it pulls;
  defaulting that to the whole remote console is how an operator wiring up one
  test import ingests a neighbouring team's estate.
- **A `scan_ids` argument naming anything outside `allowed_scans` is rejected,
  not filtered.** Silently narrowing a caller's request reports success on work
  that never happened.
- **`close_absent` requires an engagement**, validated on create, on patch
  (against the *resulting* row, not the patch — otherwise enabling it in one
  request and clearing the engagement in the next slips through) and again in
  `sync()`. Absence-based closure outside a scope is the over-closing defect
  documented where `_close_missing()` used to live.
- **Undecryptable credentials fail closed.** Falling back to an unauthenticated
  request would report the resulting 401 as a connectivity problem.

Credentials use the same Fernet envelope as ITSM connectors and MFA secrets.
No schema carries the ciphertext — there is no field to accidentally re-add,
only a `credentials_set` boolean.

Each scan gets its **own** `ImportRun`: one run covering three scans could not
report which of them rejected 400 records, and reconciliation is per test. An
export byte-identical to the last one imported is **skipped** (`sync_state`
holds a sha256 per scan), so a sync run twice in an hour does not inflate
`findings_updated`; `force` overrides. A dry run leaves no `sync_state`, or the
next real sync would skip a scan it never imported.

Permissions reuse the existing `importer:*` resource rather than inventing
`scanner:*`: pulling an export *is* an import, and a new resource would have to
be added to every built-in role, where the first one forgotten silently loses a
capability it already had. `integrations` is already in
`security.scope.REFUSED_TAGS`, so a team-scoped identity is refused rather than
served a narrowed view — enrolling a scanner is an estate-wide act.

Tenable Security Center is a separate driver class, not a flag: it authenticates
with a session (token *plus* cookie on every call), lists via `/rest/scanResult`
and returns a **zip**. The zip is opened against the export ceiling using each
member's **declared** size — reading first and measuring afterwards is what
makes a zip bomb work, the same ordering lesson as the entity expansion in
phase 25.

### Integrations console: four defects, none of which changed a status code

The 0.18.1 audit swept every list view and missed this page, because its
failures are in a form body and in column keys — surfaces that render perfectly
while being wrong.

- **"Add ITSM connector" had never worked.** It posted
  `{name, kind, base_url, username, secret}`; `ConnectorWrite` requires `slug`,
  `system` and a nested `credentials` object. Every submission was a 422.
- **The import form's Format selector was ignored.** It sent `format`; the route
  reads `source`. The server fell back to detection, which usually agreed — so
  the control looked functional.
- **Import runs showed five blank columns.** It read `format`, `parsed`,
  `imported`, `rejected` and `dry_run`; `ImportRunOut` serialises `source`,
  `records_seen`, `findings_created`, `records_rejected` and a `status` of
  `preview`. The page read as "the import did nothing".
- **The ITSM connector list claimed every row was enabled.** It read `kind` and
  `enabled`; the API returns `system` and `is_enabled`, so the ternary always
  fell to "Yes".

The import form also moves from the deprecated `close_missing` to `close_absent`,
which is the option scoped to the test that actually ran.

New **Scanner connectors** tab: enrol, test credentials, browse the remote scan
list and tick which scans the connector may pull, then sync (dry run first by
default). State is shown as *Disabled* / *Inert — no allowed scans* / *Enabled*,
because an enabled connector that will refuse every sync should not look ready.

### Guardrails

`tests/test_phase33_scanner_connectors.py` (23 tests), including two source-level
audits in the spirit of phases 26 and 28: **every driver's `parser_format` must
exist in `importers.PARSERS`** (a typo there fails after the credentials worked
and the export was built — the most expensive place to find one), and **no
function in `services/scanners.py` except `sync()` may take a `Session`**.
Drivers speak HTTP and return bytes; the moment one is handed a session, the
single place enforcing the rules above stops being single.

Suite **5232 passed, 0 failed**. Schema: one new table, `scanner_connectors`,
RLS enabled and FORCEd (61 → 62 policies). Console `app.js?v=13`.

## 0.18.1 - 2026-08-23

**A section-by-section audit of the console against the live API, and the SLA
engine finally has a way to run.** Every view was exercised end to end with an
authenticated identity; seven console defects and one backend defect came out,
all of the "renders fine, shows the wrong thing" kind that a status code never
catches.

### The one that mattered: `run-sla` had never run

`python -m veyrs run-sla` imported `veyrs.engines.sla` — a module that has
never existed — inside the CLI, so the command died on import since v1 and no
finding had ever received an SLA deadline outside a request. The engine itself
(`services.sla.evaluate_findings`) was complete and tested; nothing called it.

- `services/sla.py` gains `run_cli()` (same shape as `engines.risk.run_cli`:
  every active organization, unscoped — this is the nightly sweep the scope
  docstring already described), and `cli.py` imports from `services`.
- `scripts/sync-intel.sh` now runs `run-sla` after the feeds, so tonight's KEV
  additions carry their urgency when deadlines are computed. A clock that only
  advances when somebody opens a dashboard is not a clock.

### Console: pagination was pinned to page one

Most list routers paginate `page`/`size`; the console sent `limit`/`offset`,
which those routers silently ignore. Every findings/assets/vulnerabilities/
tickets/documents/knowledge list therefore showed the first 50 rows forever —
with 407 findings in production, "Next" was a no-op that redrew the same page.
`listView` now sends **both** dialects (unknown query params are ignored
server-side, so each router picks its own), and every hard-coded `?limit=` on
a page/size route became `?size=`.

### Console: fields that never existed

- **Threat Intel header** read `health.cve_count` / `epss_count` / `kev_count`
  / `last_run_at` — none exist. The cards showed "—" over a 359k-CVE corpus.
  Now reads `counts.*` and shows per-feed freshness pills (status + age) from
  the same payload.
- **The three "Ingest" buttons are gone.** `POST /intel/feeds/{feed}` expects
  the *caller* to supply records (an operator upload): with the console's empty
  body, NVD reported success having ingested nothing and EPSS returned 422.
  The page now says what is true — feeds sync nightly via
  `veyrs-intel-sync.timer` — instead of offering a button that lies.
- **Feed runs table** read `created`/`updated`/`message`; the payload carries
  `records_created`/`records_updated`/`error`. Also gained Seen and Finished.
- **Compliance framework detail** rendered the bare catalogue (which carries no
  state) so every control showed "Not Assessed" forever, and read
  `coverage_ratio`/`partial`/`framework_name` — all absent. It now renders
  `coverage.controls` (real status, evidence count, staleness, automation
  signal), the partial-catalogue disclaimer, and `implemented_ratio`.
- **API key creation** displayed `k.key || k.secret || k.token`; the field is
  `api_key`. The one-time secret rendered as an empty box and was lost.
- **Teams admin** showed member counts from a `members` array the list payload
  does not carry (always 0) and read/wrote `contact_email` where the API says
  `email`.

### Production state changes (operator actions, recorded here for the audit)

- Remediation tickets VEYRS-REM-000001…000005 created for the five KEV /
  risk ≥ 70 findings (all CVE-2023-44487) through the service layer, workflows
  triggered, server-side dedupe verified.
- Built-in SLA ladder (6 policies) + standard escalation ladder + the four
  default workflows seeded via the product's own `seed_*` functions.
- First SLA sweep: 407 findings clocked, 91 breached, 407 escalated.
- The three teams had zero members, so every notification evaporated with a
  warning; the admin user is now a member of all three.


**The console finally shows the pipeline it exists to run.** Production had 407
findings and zero tickets — not because nobody cared, but because the console
never exposed the one call that closes the chain, and the two places that
mentioned ticket types taught a type the backend does not have.

### Getting Started (new view)

`#/guide`, first item in the nav. The scan → risk → ticket chain as a place:
each step says where it is configured, what it produces, and shows live
numbers (enrolled agents, job queue, findings, critical findings, remediation
tickets). When findings exist and no remediation ticket tracks a fix, the view
says so in a banner instead of leaving the gap implied. This is also the first
screen that surfaces agents and scan jobs at all — both existed only in the
API until now.

### Findings → tickets, exposed

- **Create ticket** on the finding detail page: `POST /tickets` with
  `finding_id`, so the server auto-fills asset, vulnerability and SLA due date,
  and returns the existing open remediation ticket instead of a duplicate.
- **Create tickets…** as a bulk action on the findings list. Priority mirrors
  `services/ticketing.priority_for` (risk 90/70/40, severity fallback).

### Console defects fixed

- The ticket type lists offered `vulnerability_remediation`. The backend's
  canonical type is `remediation` — the only type whose resolution advances
  the finding, the only one deduplicated per finding, the only one with the
  REM reference prefix. A ticket created under the misspelt type was a
  dead-end record that never moved its finding.
- The workflow editor's example steps used `"params"`; the engine reads
  `step.config` and silently ignored everything else. The example now teaches
  the shape the engine executes.

### Notion-style reskin (light theme)

White canvas, warm-grey sidebar with dark text, hairline borders, no card
shadows, softer radii. VEYRS blue survives only as the interaction accent;
severity colours are untouched. Scoped to `[data-theme="light"]` — the dark
theme keeps the original token set — and `boot()` now always sets the theme
attribute explicitly so the scope always applies. Login page unchanged: it is
the brand surface.


## 0.17.1 - 2026-08-18

**The SLA endpoints stop answering with the estate.** 0.17.0 shipped with this
written down as a known gap and left open: `breach_summary()` took no scope, so
a team-restricted identity read fleet-wide breach counters at
`/policies/sla/summary`, and the console papered over it by hiding the widget
whenever a team filter was on. Closing it turned up **four** defects in the same
router, not one.

The root cause was the classification, not the function. The `policies` tag sat
in `EXEMPT_TAGS`, whose comment claims its routes carry "no asset- or
finding-level tenant rows" — true of most of the router and false of four
routes. `policies` is now in `SCOPED_TAGS`. **A tag is a claim about every route
beneath it, not about the majority of them.**

### Reads that answered with the estate

- **`GET /policies/sla/summary`** is narrowed by the caller's scope and accepts
  the same `?team_id=` as the dashboards, with the same rules: it only
  intersects, answers **404** for a team outside scope, and carries the
  dashboards' `scope` block so a filtered figure cannot be read under an estate
  heading. The console shows the widget under a filter again — hiding it was
  the workaround, these counters are the fix.
- **`GET /policies/sla/events`** is scoped by the finding each event belongs to.
  `sla_events` has no team of its own, the same shape as
  `analytics._scoped_history`. Asking for an invisible finding's events returns
  an empty page rather than 404: the subquery simply does not contain it.

### A sweep that wrote across the estate

- **`POST /policies/sla/evaluate`** narrows *what it touches*, not just what it
  counts. The engine flips `sla_breached`, moves `escalation_level`, writes
  `SlaEvent` rows and fires notification workflows — run unscoped for a
  team-restricted operator it pages a team that operator cannot even read. It
  deliberately takes **no** `?team_id=`: a view filter steering a mutation means
  "I only meant to look" becomes a sentence you can say about a page-out.

### The one nobody was looking for

- **`PATCH /policies/sla/{id}` re-applies the changed deadline to every open
  finding in the organization** (`reapply=true` by default, `force=True`). A
  team-scoped identity held a write over rows it cannot list. Narrowing the
  re-apply was the tempting fix and is wrong — the policy row is
  organization-wide either way, so a partial re-apply leaves the other teams
  governed by a deadline nobody recomputed. **Policy writes now require an
  estate-wide grant** (`create/update/delete` SLA, escalation policies and
  assignment rules → **403**). An assignment rule is the same defect from the
  other end: it routes work *to* teams, so a team that can write one decides its
  own queue.
  **Reading policy stays open** — an operator must be able to see the SLA they
  are judged against.
  This was found by the source guardrail below while it was hunting read leaks.

### Consolidation

- `security.scope.resolve_view()` and `refuse_if_restricted()` now hold the two
  patterns that were private to the reports router. Two copies of "look up the
  team, 404 on another tenant's, name it in the response" is how one of the
  three goes missing.

`tests/test_phase28_sla_scope.py` — 23 tests, including a source-level guardrail
asserting that no route in the policies router touches finding-level rows
without either narrowing them or declaring itself estate-wide. No schema change.

## 0.17.0 - 2026-08-18

**The dashboards can be read one team at a time.** Phase 26 gave the estate an
ownership dimension; this makes it something you can actually look through.
`?team_id=` on `/dashboard/{executive,technical,sla,trends}` narrows every
figure on the screen to the assets and findings one team owns, and the console
carries a *Scope* selector in the dashboard head.

It is a **view filter**, not an authorization decision, and the distinction is
the design:

- **It routes through `TeamScope`, not through a new argument.** The
  twenty-four tenant predicates in `services.analytics` are already scope-aware,
  so the per-team dashboard is the estate dashboard with a smaller set — and a
  query added next month is filtered without anyone remembering to. A
  `team_id=` parameter threaded through each function would be correct only
  where somebody thought of it, which is the failure phase 25 documented.
- **It can only intersect.** A principal already restricted to teams A and B
  that asks for C gets **404, not 403** — the answer the rest of the platform
  gives for a row outside scope, because 403 confirms the team exists.
- **`filtered` and `restricted` stay apart in the payload.** The `scope` block
  now carries `team_filter: {team_id, team_name}` alongside `restricted`.
  Collapsing them would either tell a full-visibility administrator their
  access is capped, or let one team's figure pass under an estate heading. The
  console prints a different banner for each.
- **A team filter excludes unowned rows**, even where the organization sets
  `team_scope.unowned_visible`. "The platform team's dashboard" must not fold
  in every asset nobody owns; that work is real and is triaged from the estate
  view, which counts it.
- **Exports still take no team.** A dashboard is read in context and states its
  scope; an exported PDF outlives that context and gets filed as *the* asset
  register. Unchanged from 0.16.0, and now pinned by a test.
- `/dashboard/trends` assembled its `scope` block by hand and so would have
  reported the filter differently from the other three. It now uses the same
  builder (`analytics.scope_block`).

The console's SLA tab drops the `/policies/sla/summary` panel while a team
filter is active: that endpoint reports the whole estate and takes no team, and
an estate total sitting beside filtered counters is exactly the misread this
screen exists to prevent. (Known gap, pre-existing: `breach_summary()` takes no
scope at all, so a team-restricted identity reads estate-wide SLA counters
there. `policies` is in `EXEMPT_TAGS`. Tracked, not fixed here. **Closed in
0.17.1**, which also found three more defects in the same router.)

`tests/test_phase27_team_dashboard.py` — 11 tests. No schema change.

## 0.16.0 - 2026-08-18

**Assets and findings divide by team, and a team can be made to see only its
own.** Two features that were asked for together and are deliberately separate:
one is an organizing dimension, the other is an authorization boundary.

### Part 1 - ownership became reachable

Every column already existed (`Asset.team_id`, `Finding.assigned_team_id`,
`AssignmentRule`, `Team`, `TeamMember`, the *Open risk by team* chart) and none
of it could be used: `GET /assets` had no team filter, list responses returned
raw UUIDs, and nothing could be moved in bulk.

- **`GET /assets` filters on `team_id`, `owner_id`, `department_id` and
  `unowned`.** The last one exists because unowned assets are the residue that
  scoping makes invisible; finding them has to be one click.
- **`GET /findings?owning_team_id=` filters on the *effective* owner** -
  explicit assignment first, the asset's team as the fallback
  (`services.teams.owning_team()`). This is the important one: most findings
  are never explicitly assigned, so filtering on `assigned_team_id` answers
  "this team has no work" for an estate that is fully owned. `?my_teams=true`,
  `?mine=true` and `?unowned=true` are the same filter from three angles.
- **`POST /assets/bulk-assign` and `POST /findings/bulk-assign`** move up to
  500 rows. `team_id: null` cannot mean "unassign" - an omitted optional field
  is also null - so nulling a column requires `clear: ["team_id"]` and a
  request that forgets a field can never silently orphan a batch. Ownership is
  validated once, before the loop; unknown *rows* are still reported per id.
- **Every finding assignment writes a `FindingEvent`**, not just an audit row.
  "Why did a breached SLA sit with the wrong team for a week" is answered from
  the finding's own history, and a reassignment is the usual answer.
- **List responses carry names.** `team_name`, `owner_name`,
  `department_name`, `assigned_team_name`, `owning_team_id/‑name`, resolved
  with one batched lookup per page. `security-engineer` and `asset-owner`
  gained `team:read`: you cannot route work to a team whose name you may not
  read.

### Part 2 - `UserRole.team_id` finally means something

It has been in the schema since the first release, documented as "the ABAC
seam", and read by nobody. RLS answered *which tenant*; inside a tenant
everyone saw everything.

- **A principal is restricted only when EVERY role grant names a team.** One
  estate-wide grant anywhere wins, so nothing that exists today changes
  behaviour - all existing grants have `team_id NULL`.
- **Membership never grants visibility.** `TeamMember` answers "whose queue is
  this" (`?my_teams=true`); grants answer "what may you read". If joining a
  team widened visibility, any user who can join one would own the
  authorization decision.
- **Out of scope answers 404, never 403.** A 403 confirms the row exists.
- **Unowned rows are invisible by default** (`organization.settings.team_scope.
  unowned_visible` flips it), and the blind spot is *counted* rather than
  assumed away: `GET /auth/me/scope` reports it and warns.
- **Routers that do not understand a scope are refused, not served
  unfiltered.** `agents`, `ai`, `compliance`, `engagements` and `integrations`
  answer 403 for a scoped identity, as do report *exports* - a dashboard is
  read in context and states its scope, an exported PDF outlives that context
  and gets filed as "the asset register".
- **Every dashboard ships a `scope` block** and the console renders a banner
  from it, because "0 critical" and "0 critical that you can see" are different
  sentences under the same heading.
- **`PUT /users/{id}/scope`** sets or clears it, needs `role:admin` (clearing
  is a privilege *grant*), and refuses to narrow the caller's own grants.
- Analytics was refactored so all 24 tenant predicates go through four scoped
  helpers, with `test_phase26_scope.py` asserting on the source that no new
  query bypasses them. Threading a scope through fifteen functions works
  exactly until someone adds the sixteenth.

### The trap this round

`services.teams.owning_team()` **must** call `.correlate(Finding)`. Left to
auto-correlate, SQLAlchemy also correlates `assets` whenever the enclosing
statement already joins it - the subquery loses its FROM clause entirely and
compilation dies. It only fires on the queries that join `Asset` (the
internet-exposure counters, `?exposure=`), so it presents as an unrelated
dashboard 500.

Suite **5147 passed, 0 failed**. No schema change: `UserRole.team_id`,
`Asset.team_id` and `Finding.assigned_team_id` were already there.

## 0.15.1 - 2026-08-18

**A dashboard column that could never be filled, and an XML guard that never
ran.** Both were found by asking what the code does rather than what it says.

- **"Top CWE" had a Name column and no source of names.** `cwe` rows are
  created the moment an NVD record mentions an identifier, and an NVD record
  carries no name — so every row was written `name = id` and the dashboard
  printed `CWE-79` under a heading that said *Name*. Nothing in the tree had
  ever fetched the MITRE dictionary. **`veyrs sync-cwe`** now does
  (`intel/feeds.parse_cwe_catalog` + `services.intelligence.ingest_cwe`), and
  it is the first feed in the nightly `sync-intel.sh` run, so the placeholders
  NVD creates tonight are named on the same pass.

- **`Cwe.resolved` keeps a placeholder from posing as an answer.** `name` is
  NOT NULL, so a row with only an identifier has to carry *something*;
  `display_name` returns None until the dictionary has been loaded. Analytics
  and `/intel/cwe/{id}` both read it, because reporting the id as its own name
  makes an un-ingested dictionary look like an ingested one.

- **Categories are ingested alongside weaknesses**, and the catalogue is
  streamed with `iterparse` and cleared element by element: 18 MB of XML, 1391
  entries, **97 MB peak RSS**. Building the whole tree would cost an order of
  magnitude more on the node an intelligence job has already OOM-killed once.

- **`sync-cwe` deliberately does not correlate.** A weakness name changes no
  tenant's exposure — it is vocabulary, not an advisory. EPSS and KEV rescore
  without re-correlating for the same reason; this feed has not even a score to
  move.

- **The console's CWE links were dead.** `route('intel')` only ever inspected
  `cve`, so every identifier in Top CWE silently landed back on the Intel tab,
  and the weakness list on a CVE page linked to `#`. There is now a CWE view:
  definition, abstraction, catalogue status, and **this tenant's open findings
  for that weakness class**.

### The XXE guard had never executed

- **`_parse_xml` and `documents._from_xml` both attached expat handlers to
  `XMLParser.parser` — an attribute deprecated in Python 3.8 and REMOVED in
  3.9 — inside `except AttributeError: pass`.** On this fleet's 3.11.2 the
  guard therefore did nothing, and both modules documented it as XXE defence.
  Measured before the fix: `_parse_xml` expanded a four-level nested entity
  from 200 bytes to 10 kB, which is a gigabyte at nine levels. **Billion
  laughs, live, on every endpoint that accepts a `.nessus`/`.xml` upload.**

- **Scope, probed rather than assumed:** external entities were never resolved
  (ElementTree installs no handler for them), so this was amplification/DoS,
  not file disclosure or SSRF. `test_external_entities_are_still_not_resolved`
  pins that boundary so a future interpreter cannot move it quietly.

- **The fix is one module, `services/xmlsafe.py`**, replacing two copies that
  had drifted into being decorative. It refuses the entity *declaration*, and
  only inside the prolog: a security report legitimately quotes `<!ENTITY` in
  its own finding text, and refusing that file would be the guard causing the
  outage it exists to prevent.

- Regression net: `tests/test_phase25_cwe_catalog.py` (19 tests).

## 0.15.0 - 2026-08-17

**MFA was decorative, and the dependency set was undeclared.** Both were found
by auditing what the venv actually contained. Suite: **5090 passed, 0 failed**.

- **`/auth/login` never verified the MFA code.** The check was
  `if user.mfa_enabled and not payload.mfa_code` — it asserted the field was
  *present* and then fell through to issuing tokens. Any six characters
  satisfied it, `users.mfa_secret` was read by nothing, and no TOTP
  implementation existed anywhere in the tree. **No account had `mfa_enabled`
  set, so nothing was breached**; the defect was that the first operator to
  turn MFA on would have got a green padlock and no second factor.
  `security/mfa.py` now implements RFC 6238 on `hmac`/`struct` from the
  standard library — `pyotp` had been installed for this since the first
  deployment and never imported, and it was removed rather than adopted, to
  keep the authentication path free of a third party.

- **Four properties the new implementation holds, each of which is a way this
  could have been re-broken:**
  - the secret is stored **encrypted** (`security/secrets.py`, the same Fernet
    envelope as third-party credentials) — it cannot be hashed, TOTP needs it
    back;
  - a code is **single-use**: `verify()` returns the time step that matched and
    the login persists it in the new `users.mfa_last_step`, so a code captured
    off a proxy log or over a shoulder is refused inside its own 30s window;
  - MFA failures **spend the same lockout budget** as password failures — two
    separate budgets would let an attacker who already has the password make
    unlimited guesses at six digits;
  - `mfa_enabled` with a missing or undecryptable secret **fails closed**.
    Falling back to password-only would silently downgrade the one account that
    explicitly asked for more.

- **`str.isdigit()` was not a sufficient guard, and the fix's own test caught
  it.** It returns True for Arabic-Indic digits, and `hmac.compare_digest`
  raises `TypeError` on non-ASCII strings — so `mfa_code: "٠٠٠٠٠٠"` turned an
  unauthenticated login attempt into a 500. `verify()` now requires
  `isascii() and isdigit()`.

- **Enrolment is three steps, not one.** `POST /auth/mfa/enroll` hands out a
  secret and an `otpauth://` URI but leaves the account on password-only;
  `POST /auth/mfa/activate` requires a working code before MFA is enforced;
  `POST /auth/mfa/disable` requires the password **and** a code, so a stolen
  access token cannot strip the second factor off the account it was stolen
  from. Enabling in one step is how administrators lock themselves out of the
  console they administer.

- **The repository declares its dependencies now.** There was no
  `requirements.txt` and no `pyproject.toml`: the production venv was whatever
  had been `pip install`-ed by hand, so a new node could not be reproduced and
  dead weight accumulated invisibly. Removed, all with zero imports in the
  tree: **alembic** (there are no migrations — schema evolves through
  `veyrs sync-schema`), the whole **Celery** stack left behind by 0.14.1
  (`kombu`, `billiard`, `amqp`, `vine` and their CLI dependencies),
  **feedparser**, **beautifulsoup4**, **lxml**'s direct entry, **jinja2**,
  **PyYAML**, **python-dateutil**, **pyotp**, and **defusedxml** (the XXE
  defence is hand-rolled on expat in `importers/parsers.py` and always was).
  **73 packages to 52.**

- **`python-multipart` stays, and is annotated in `pyproject.toml`, because it
  looks exactly like the packages that were removed.** Nothing imports it;
  FastAPI needs it at runtime to parse the 23 `UploadFile`/`Form` parameters
  the scanner-import endpoints declare. Without it those endpoints 500 at
  request time, not at boot — which is the worst place to discover a missing
  dependency.

- **`tests/test_phase24_dependencies.py` is the guard.** It pins that every
  declared dependency is pinned, present in the lock at the same version,
  installed and importable; that `python-multipart` is present despite being
  unimported; and that the eight removed packages stay removed. Regenerate the
  lock with `./scripts/freeze-deps.sh` — never by hand, because a hand-edited
  lock is a lock that lies.

## 0.14.1 - 2026-08-16

**The nightly intelligence sync had been dying for three nights, and the feed it
took down with it was KEV.** Suite: **5063 passed, 0 failed**.

- **`ingest_epss` is set-based now.** It was `session.get(Cve, id)` per row plus
  two ORM inserts, all inside one transaction: three instances per row held in
  the identity map until a single terminal commit, and `Cve` carries a
  description. Against the real file from FIRST (360,399 rows) that is not a
  slow import, it is a dead one - the OOM killer took it at 03:3x on 2026-08-14,
  -15 and -16. Rewritten as batched `ON CONFLICT` upserts over id sets, with the
  denormalised `cve.epss_score` / `cve.epss_percentile` refreshed **from
  `epss_scores` itself** rather than from the payload, so a partial batch cannot
  leave the two disagreeing. Measured on production: **peak RSS 8 GB+ (killed)
  to 365 MB, and it finishes, in 136 s**. `commit_between_batches` mirrors
  `ingest_nvd_pages`: off by default, because a caller holding every row (an
  upload, a test) still wants all-or-nothing.

- **The reason KEV never ran.** `sync-intel.sh` isolates its three feeds on
  purpose - a stale EPSS is a degraded signal, a stale KEV is a missed
  emergency - but the systemd default `OOMPolicy=stop` SIGTERMs the whole unit
  when the kernel OOM-kills any process in its cgroup, so the wrapper shell died
  mid-loop and the isolation the script implements was silently overridden. The
  unit now sets **`OOMPolicy=continue`**. Both fixes are kept: not OOM-ing is
  the fix, surviving one is the guardrail.

- **`rescore_for_cves` windows its id list.** For EPSS the argument is not a
  delta, it is the corpus - a quarter of a million bind parameters that psycopg
  renders and Postgres plans before a single row comes back. Windowed at
  `RESCORE_ID_WINDOW = 5000`, findings deduplicated by id.

- **Celery removed from the venv.** There was never any Celery in VEYRS: zero
  imports, one mention in a `services/sla.py` docstring describing a beat job
  that does not exist. The declared stack said otherwise. Related debt, not
  fixed here: the repo still has no `requirements.txt` or `pyproject.toml`, so
  the venv is not reproducible.

## 0.14.0 — 2026-08-12

**VEYRS now goes and gets its own intelligence, and knows what you have.**
Until this release the product had ingest endpoints and a correlation engine and
no wire between them: `cve` held 5 rows, `asset_products` held 0, and the whole
premise — prioritise with CVE/CVSS/EPSS/KEV against real exposure — could not
run. Suite: **5063 passed, 0 failed** (34 new).

- **The feed collector that the CLI already advertised.** `veyrs sync-nvd`,
  `sync-epss` and `sync-kev` dispatched to `veyrs.intel.feeds`, a module that
  did not exist, so all three raised `ModuleNotFoundError`. It exists now, as
  the only code in the backend that reaches NVD, FIRST or CISA. NVD is walked
  incrementally by `lastModified` (never by publication — a CVE re-scored
  yesterday has to come back) in ≤120-day windows, with the rate limit enforced
  client-side because exceeding it answers **403**, which reads like an auth
  failure rather than a limit. A `veyrs-intel-sync.timer` runs all three daily
  at 03:30 with jitter.

- **Ingesting now tells the tenants.** `services/intel_pipeline.py` is the
  missing join. NVD records get the full correlation, because they can create
  findings that did not exist. EPSS and KEV **rescore instead**: a probability
  or an exploitation flag never changes *what* is affected, only how urgent it
  is, and correlating over EPSS would be ~250k inventory queries a day to
  discover nothing. Every call restores whatever tenant was bound on entry —
  the ingest endpoints keep working afterwards.

- **Inventory carries CPE identity, or admits it does not.** NVD builds product
  rows from CPE tokens, so nginx is `f5:nginx`. An inventory saying
  `vendor="Nginx"` forked a second product row, `CveCpeMatch` never joined, and
  the tenant read as unaffected — silently and totally. `services/inventory.py`
  resolves identity most-authoritative-first (explicit CPE → registry hit →
  the product token disambiguated by which candidate CVEs actually cite →
  curated alias → recorded but unmatched). `verify_aliases()` checks every
  curated entry against the loaded dictionary, because a hardcoded alias is a
  claim about somebody else's data and claims rot.

  `Resolution` reports **`anchored`** (identity is pinned to a dictionary entry)
  separately from **`matched`** (advisories reference it). Conflating them was a
  live defect: the same product answered `matched=True` via CPE and `False` via
  free text.

- **`GET /assets/inventory/coverage`** separates *nothing is vulnerable* from
  *nothing is matchable*. Both render as an empty findings list everywhere else
  and only one is good news. New: `POST /assets/{id}/products/bulk`,
  `POST /assets/inventory/import`, `POST /assets/inventory/resolve` (dry run),
  `GET /assets/inventory/aliases`, and `veyrs import-inventory` for the initial
  load.

- **Agents report inventory, not just scans.** `POST /agents/self/inventory`,
  held to exactly the same target policy as a scan — an agent that could rewrite
  any asset's software could make a host look clean without running anything.
  Reference runner **1.2.0** collects from dpkg/rpm/apk. This is what makes
  correlation continuous: a CVE published next week raises a finding next week,
  with nobody re-scanning.

- **`AssetProduct.raw_version`.** Matching must use the upstream version
  (`1:1.24.0-2ubuntu7.1` → `1.24.0`) or it never fires at all, but distributions
  backport fixes without moving it, so that match can be already-remediated. The
  verbatim string is kept so an analyst can see which. The reduction lives in
  `services.versions.upstream_version` — server-side, once, because a collector
  carrying its own copy is a rule that drifts.

### Two defects found by running it

- **A transaction held across network I/O killed the first full backfill.**
  `db._harden_connection` sets `idle_in_transaction_session_timeout = 60s` (a
  correct guard for a web API); the fetcher waits far longer between pages, and
  `feed_run()`'s opening flush left a transaction open across the *first* page
  fetch. `ingest_nvd_pages` now commits per page and lands the run row before
  any network work. A pushed batch stays atomic — only a live pull trades that.

- **`Session.in_transaction()` is not the backend's transaction status.** It
  reports SQLAlchemy's autobegin and stays `True` after a commit while the
  connection is `IDLE`. The instrumentation written to verify the fix above
  measured the wrong layer and reported five violations that were not.

## 0.13.1 — 2026-08-12

Three loose ends left open by 0.13.0, all of them things that looked settled and
were not. **The suite is green for the first time: 5029 passed, 0 failed.**

- **A container image reference is not a `host:port`.** `_split_host_port()`,
  added in 0.12.0 to stop nuclei's `host:22` from losing a finding, truncated
  every container and cloud artifact it met: `registry.internal/api:2.4.1` →
  `registry.internal`, `acme/web:1.0` → `acme`. Trivy, Grype and Prowler put an
  artifact identifier in the field VEYRS reads as a hostname, and a colon there
  separates a *tag*, not a port. The identity feeds the dedupe key, so two
  different images collapsed onto one estate entry — the same class of defect
  0.12.0 fixed, in the opposite direction, and it shipped with two failing tests
  that said so.

  Fixed with two independent guards, because one is not enough: `ScanRecord`
  now carries **`host_is_artifact`**, set by the parser that knows, and
  `_split_host_port` additionally requires the value to *look* like a network
  location. Shape alone cannot decide it — `redis:7` is a legal image tag and a
  legal `host:port` — which is exactly why the authority has to be the parser
  and the shape test is only a backstop for one that forgets.
  Regression net: `tests/test_phase20_artifact_identity.py` (12 tests), which
  also pins the half that must not regress — a real `host:port` still splits.

- **`/metrics` is token-gated, and the docs said otherwise.** The Monitoring
  section still described the endpoint as "LAN-restricted at the proxy", the
  control 0.12.0 proved is no control at all: every request arrives from the
  fleet reverse proxy, whose address is inside the allowed range. A document
  asserting a protection that does not exist is worse than no document. It now
  describes `VEYRS_METRICS_TOKEN` and the deliberate 404.
  `test_metrics_are_prometheus_formatted` was scraping a 404 body and failing on
  a contract that was never broken; it now authenticates, so the format
  assertion holds *through* the gate rather than around it.

- **The execution agent is a supervised service.** It ran as a bare background
  process and did not survive a reboot — a scanner that quietly stops scanning
  is the same failure mode phase 19 was about, one level up. Now
  **`veyrs-agent.service`** with `EnvironmentFile=/etc/veyrs-agent/agent.env`
  (0600, carries the agent token), `Restart=always`, and `KillSignal=SIGINT`
  because the runner exits cleanly on `KeyboardInterrupt` where `SIGTERM` just
  kills it. Hardened but deliberately **not** `ProtectHome`: nuclei reads its
  templates from `/root/nuclei-templates` and locking that turns every scan into
  a silent zero-template run.

- **The original false-green job is no longer green.** Job `8125ce7a` — the
  blind scan of `satom-mag-a1`, `exit 0`, 0 bytes, recorded `succeeded` — is
  reclassified `failed` with the coverage reason, because leaving it green means
  the history answers "when was this host last scanned successfully?" with a
  date on which it was never reached. The original state is preserved in
  `job.meta.reclassified` rather than discarded: verified before writing it,
  the run imported 0 records and the asset had no findings yet, so nothing was
  wrongly closed — the same job against an already-scanned asset would have
  closed its estate.

## 0.13.0 — 2026-08-12

### Phase 19 · A scan that saw nothing is not a scan that found nothing

Found by running VEYRS's own agent against the two hosts of the SATOM pair.
One has a public `A` record, the other does not. The scan of the public one
finished in nine seconds with no findings and was recorded **succeeded**; the
other ran ten minutes and produced 22 findings. That asymmetry was the finding.

- **The scanner was not using the fleet resolver.** nuclei ignores
  `/etc/resolv.conf` — projectdiscovery's dialer carries public resolvers
  compiled in. On a split-horizon estate it therefore resolved an *internal*
  host to its *public* address, could not route there, and gave up. Every
  internal host with a public `A` record was scannable in name only. The agent
  now passes `-r` from `/etc/veyrs-agent/resolvers.txt`
  (`--resolvers` / `VEYRS_AGENT_RESOLVERS`), and sanitises it first: nuclei
  treats a comment line as a resolver, which silently drops coverage to 0%.
- **VEYRS could not tell that apart from a clean estate.** The three facts it
  had — `exit_code=0`, `output_bytes=0`, `matched=0` — are exactly the facts of
  a successful empty scan, which is the one signal that closes a remediated
  finding. Measured on the same host, same templates:

  | | completed | requests | errors | exit | output |
  |---|---|---|---|---|---|
  | wrong resolver | **5%** | 520 | 703 | 0 | 0 bytes |
  | fleet resolver | **97%** | 8618 | 108 | 0 | 0 bytes |

  Both wrote zero bytes — at critical/high that host genuinely has nothing. So
  payload size cannot separate them and coverage can.
- **The agent now reports coverage; the server decides what it is worth.**
  `X-Agent-Scan-Stats` carries nuclei's own `-stats-json` counters plus a
  tool-agnostic reachability probe taken with the system resolver (when the
  probe and the scanner disagree, that disagreement *is* the diagnosis). Policy
  stays server-side so the threshold is operator-tunable and identical for
  every agent: below `MIN_COVERAGE_PERCENT` (80) or above `MAX_ERROR_RATE`
  (0.5), the job goes **failed** with the percentage in `job.error`, and the
  counters are kept on `job.meta.scan_stats` for triage.
- **Closing a finding now requires a positive attestation, not merely "did not
  crash".** An unattested result is still imported — what it saw is real — but
  `close_absent` is forced off, so only a run that vouches for its own coverage
  can mark something remediated. An empty result with no attestation at all is
  refused outright rather than reconciled.

Agent reference runner → **1.1.0**. An older agent still submits successfully;
its empty results are refused instead of being read as a clean estate.

## 0.12.0 — 2026-08-11

### Phase 18 · Four things that looked like controls and were not

(Backfilled: this release shipped without a changelog entry.)

- `/metrics` was LAN-exposed and unauthenticated, and the nginx
  `allow 10.0.0.0/24` in front of it matched the fleet reverse proxy rather
  than the caller. Gated on `VEYRS_METRICS_TOKEN`, answering 404 when absent.
- Metric labels are built by `observability.incr()` from a mapping and escaped;
  an unmatched route contributes a constant, and series are capped.
- A crashed scan no longer reconciles: a failed run never closes a finding, and
  a failed run with no output is not imported at all.
- A failed job records *why* — the tail of the agent's output, ANSI stripped.
- `tests/conftest.py` refuses any database whose name does not end in `_test`;
  the 1,198 fixture orgs a bare `pytest` had written to production were purged.

## 0.11.0 — 2026-08-11

### Phase 16 · Execution agents
- Agents that **run** scanners, not just import them: enrolment, capability
  declaration, target policy, leased dispatch, durable output streaming and
  results that land in the phase-15 ingestion core.
- Trust model inverted relative to the tools this borrows from: the server
  sends `{tool, target, profile, params}` and never a command line; a declared
  tool is not an authorised tool; a target is authorised at queue time **and**
  again against the claiming agent's own policy; reserved ranges (loopback,
  link-local, `169.254.169.254`) need an exact literal allow; names are never
  resolved to match a network rule.
- Separate credential type (`veyrsagent_…`, `X-Agent-Token`). An agent is not a
  principal: it reaches `/agents/self/*` and nothing else.
- Reference runner in `integrations/veyrs-agent/` — one standard-library file,
  `shell=False`, per-tool argv builders with clamped knobs, and a local
  allowlist so a compromised server still cannot redirect it.
- New `agent` permission resource (`read` / `write` / `admin`); the catalogue
  moves 108 → 112.

### Phase 17 · ITSM inbound
- Signed webhook (`hmac-sha256` over `timestamp.body`, 300s replay window) so
  ServiceNow/Jira push status back instead of being polled.
- Advisory by default: an inbound status updates the link and imports comments
  but moves nothing. State changes need an explicit per-connector
  `inbound_transitions` map, and still go through the ticket state machine.
- Unknown org, unknown connector and inbound-disabled all answer the same 404 —
  the endpoint is not a tenant enumeration oracle.

### Fixed
- **A clean scan could not be expressed.** Every parser rejected an empty
  result as a format mismatch, so a scan that found nothing — the only signal
  the platform gets that something was remediated — was reported as a parse
  error. Nuclei, Dependabot and Prowler now treat an empty record set as a
  clean run, and `ImportOptions.allow_empty` accepts a zero-byte payload from
  an agent (off for human uploads, where it is a mistake).
- **The schema reconciler could not add a JSONB column.** `sync-schema`
  reported every new NOT NULL JSONB column on an existing table as needing a
  manual migration, because `default=dict` is a callable that SQLAlchemy wraps.
  It now unwraps `dict`/`list` — and only those two, by identity — so the case
  the guard actually exists for (`lambda: now()`) is still refused.

**4,983 tests pass.**

## 0.10.0 — 2026-08-11

### Phase 15 · Unified ingestion core
Written up retroactively: the phase shipped in commit `785e024` without a
changelog entry, and a gap between 0.9.0 and 0.11.0 would read as a lost
release rather than a missed note.

- Engagement → ScanTest hierarchy with a sighting table, so reimport closes
  only what the test that ran had previously reported.
- **Fixed a production defect**: `_close_missing()` scoped closure to
  `Finding.scanner` across the whole organisation, so a three-host Nessus
  export marked the entire estate's Nessus findings remediated.
- Configurable deduplication (4 algorithms, per-scanner registry). `legacy`
  reproduces the historical key byte-for-byte and stays the default for
  nessus/qualys/greenbone/csv/json, so no existing finding re-keys.
- Endpoint model with the web dimension (method/request/response/params) on the
  finding-endpoint link rather than as a second class of finding.
- RiskAcceptance with approver, expiry and reactivation.
- Parsers 5 → 20: SARIF, Trivy, Grype, Semgrep, Bandit, Gitleaks, Checkov,
  Nuclei, ZAP, npm audit, pip-audit, Dependabot, Prowler.
- `veyrs sync-schema`: an additive reconciler, because `create_all()` creates
  missing tables and silently ignores missing columns. There is no Alembic.

**4,913 tests pass.**

## 0.9.0 — 2026-08-10

First feature-complete build. All ten phases implemented. **4,778 tests pass.**

### Phase 1–2 · Core platform
- CVSS engine: v2, v3.0, v3.1, v4.0 from the published algorithms. Validated
  against **4,382 official vectors** (729 v2 + 2,592 v3 + 1,058 v4).
- Multi-tenancy in two layers: application filters plus PostgreSQL Row Level
  Security on 45 tables.
- RBAC: 108 permissions, 10 built-in roles, validated at import time.
- Argon2id passwords, rotating refresh tokens with reuse detection, API keys,
  three append-only audit logs, structured logging, Prometheus metrics.

### Phase 3 · Intelligence, assets, risk
- Idempotent, watermarked ingestion of NVD, EPSS (with history) and CISA KEV.
- CVE → product → version → asset correlation with CPE-compliant version
  comparison.
- Vulnerability/finding split, 15-state lifecycle, regression reopening.
- Risk engine: four sub-scores, configurable profiles, KEV floors, age penalty,
  compensating-control credit, stored factor-by-factor explanation.
- Declarative assignment rules, SLA policies, escalation ladders.

### Phase 4 · ITSM
- Ticketing with per-type ITIL state graphs; change tickets require approval.
- Workflow engine with an **allow-listed action registry** — no `eval`, no
  tenant-supplied code.
- Notifications in five languages; escalations cannot be muted.

### Phase 5 · Documents, threat intel, knowledge, search
- Extraction from PDF, DOCX, HTML, XML, CSV, JSON with XXE hardening.
- Deterministic entity extraction: CVE, CWE, product, affected and fixed
  versions, CVSS vectors, severity.
- Threat feeds ranked by relevance to your inventory, weighted by source trust.
- Versioned knowledge base; permission-aware search with an optional vector
  layer that degrades to lexical.

### Phase 6 · AI
- Provider abstraction: OpenAI-compatible, Anthropic, Gemini, Ollama, plus a
  deterministic backend that answers from VEYRS data when no model is reachable.
- Gateway enforcing capability→permission mapping, per-provider-class data
  classification ceilings, budget caps, degrade-not-fail, output scanning, and
  an audit row for allowed, degraded **and blocked** calls.
- Guardrails: secret, PII and prompt-injection detection. Luhn-gated card
  redaction so CVE identifiers survive.
- Natural-language search against a closed, published grammar.
- `security/secrets.py`: Fernet envelope encryption for the `*_enc` columns that
  earlier phases declared but nothing wrote.

### Phase 7 · Compliance
- NIST CSF 2.0, CIS Controls v8, ISO/IEC 27001:2022 Annex A, ISO/IEC 27002:2022,
  plus custom frameworks — shipped as identifiers and titles only, with the
  copyright position stated and a disclaimer that cannot be turned off.
- 12 automated signals that report their own derivation. A passing signal reaches
  `partial`, never `implemented`.
- Evidence, control↔object links, frozen assessment snapshots, auto-raised gaps.

### Phase 8 · Integrations
- Importers: Nessus, Qualys, Greenbone/OpenVAS, CSV, JSON. Unidentifiable assets
  are rejected with a reason; absent findings are stale candidates, not closures.
- ITSM connectors: ServiceNow, Jira, webhook. Idempotent push; pull cannot close
  a VEYRS finding.

### Phase 9 · Analytics and reporting
- Executive and technical dashboards, MTTR, SLA attainment, trends, top
  products/assets/teams. Every ratio ships with its denominator; every average
  with its sample size and a reliability flag.
- 8 reports × 4 formats (JSON, CSV, XLSX, PDF) with mandatory provenance.

### Phase 10 · Hardening and deployment
- Two-tier rate limiting, hardened systemd units, nginx vhost, backup/restore
  with checksums and a manifest.
- Live at https://veyrs-docs.example.com.

### Defects found and fixed during development

Each was found by a test or by the deployment, not by reading code:

- CVSS v4 banker's rounding vs FIRST's half-up — 43 of 1,058 vectors wrong.
- `IN (uuid, NULL)` never matches NULL — built-in roles invisible, so every
  login produced **zero permissions**.
- `effective_permissions()` ran before the RLS tenant was bound.
- RLS context lost after `commit()` — handlers saw zero rows in silence.
- Remediated findings could never reopen (checked `closed_at`, which
  `remediated` never sets) — a failed patch vanished from the queue.
- Risk engine crashed on any finding with a CVE attached (`cvss4_version`).
- Rate limiter keyed on `request.state.principal`, which middleware never sees.
- Transient `AiPolicy` returned `None` for every defaulted column, so the prompt
  size guard raised instead of enforcing.
- Ten list endpoints built `Page(page=, size=)` — fields the schema does not
  declare — returning 500 on **every** call.
- PostgreSQL cluster was `SQL_ASCII`; recreated as UTF8.

### Known gaps

- Frontend (Next.js) not built. The API is the interface.
- MFA enrollable but not enforced. SAML prepared, not implemented.
- MISP/OpenCTI modelled as source kinds; pull adapters not implemented.
- No external penetration test. No DR rehearsal. Single-node deployment.
