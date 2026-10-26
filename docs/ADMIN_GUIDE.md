# Administrator Guide

For `org-admin`, `security-manager` and `compliance-officer` roles.

## Users, teams and roles

```
POST /api/v1/users        {"email": "...", "full_name": "...", "role_slugs": ["security-engineer"]}
POST /api/v1/teams        {"slug": "netsec", "name": "Network Security"}
POST /api/v1/teams/{id}/members/{user_id}
```

Ten built-in roles map to operational personas rather than generic tiers:

| Role | For |
|---|---|
| `org-admin` | Full control inside one organization, including RBAC |
| `security-manager` | Owns risk posture: triage, profiles, SLA policy, escalation |
| `security-engineer` | Day-to-day triage and remediation |
| `team-lead` | Accountable for their team's queue and SLA |
| `asset-owner` | Business owner; accepts risk, confirms remediation |
| `compliance-officer` | Control mapping, evidence, audit readiness |
| `executive` | Read-only executive view plus formal risk acceptance |
| `auditor` | Immutable read across evidence and audit trail. No writes at all |
| `service-account` | Machine identity for importers and ITSM webhooks |
| `read-only` | Baseline visibility |

Custom roles: `POST /api/v1/roles` with a permission list. `GET /permissions`
returns the complete `resource:action` registry.

## Risk profiles

```
GET  /api/v1/risk/profiles
POST /api/v1/risk/simulate   {"finding_id": "...", "profile_id": "..."}
```

Built-in: `technical`, `executive`, `internet-exposure`, `compliance`. Create
your own by adjusting the four sub-score weights and the policy options
(`kev_floor`, `internet_kev_floor`, `age_penalty`, `control_credit`). **No
deployment is required** - the weights are rows, not code.

Use `simulate` before switching the default. It answers "what would our queue
look like under the executive profile?" without rescoring anything.

## SLA and escalation policies

```
POST /api/v1/policies/sla
{
  "slug": "critical-kev-internet", "name": "Critical + KEV + internet",
  "conditions": {"severity": ["critical"], "kev": true, "exposure": ["internet"]},
  "duration_hours": 4, "priority": 100
}
```

Highest `priority` matching policy wins. Then attach an escalation ladder:

```
POST /api/v1/policies/escalation
{"slug": "critical", "levels": [
  {"after_hours": 4,  "target": "team"},
  {"after_hours": 8,  "target": "team_manager"},
  {"after_hours": 24, "target": "security_manager"},
  {"after_hours": 48, "target": "ciso"}]}
```

## Assignment rules

```
POST /api/v1/policies/assignment
{"slug": "fortinet-to-netsec", "priority": 100,
 "conditions": {"vendor": "fortinet", "asset_type": "firewall"},
 "team_slug": "netsec"}
```

Rules are declarative and evaluated most-specific-first. `POST
/ai/findings/{id}/suggest-team` proposes an owner from your actual team list -
advisory only, and a hallucinated team is rejected rather than applied.

## Scanner imports

```
POST /api/v1/integrations/imports   (multipart)
  file=@scan.nessus  source=nessus  create_assets=false  min_severity=low
```

Formats: `nessus`, `qualys`, `greenbone`/`openvas`, `csv`, `json`.

Two defaults that are deliberate and that you should understand before changing:

- **`create_assets=false`.** An import that invents inventory quietly destroys
  the asset register's meaning. Records whose asset cannot be identified are
  *rejected with a reason*, and the reasons plus a sample are on the import run.
  Read them - a renamed hostname column silently creating a 4,000-row blind spot
  is the classic failure.
- **`close_missing=false`.** Findings absent from an export become
  `stale_candidates`, not closures. Scanners routinely skip hosts that were
  merely offline.

`dry_run=true` parses and reports without persisting.

## Asset sources (Administration → Asset sources)

Where VEYRS reads somebody else's inventory from. Three drivers:

| Driver | For | Field mapping |
|---|---|---|
| `file` | A CSV / TSV / JSON / XLSX export uploaded by hand | **Required** |
| `http_json` | Any JSON API (ServiceNow, GLPI, i-doit) | **Required** |
| `netbox` | NetBox DCIM / IPAM | Optional — an override layer |

**A sync never writes to `assets`.** It writes staging rows and links them to
the assets it recognises; copying values into the register is *promotion*, a
separate act. That separation is the only reason two sources can be compared
instead of overwriting each other.

### NetBox

The published schema is already mapped — device and VM name, serial, role,
platform, site, tenant, status and primary IPs. You only add a field mapping to:

- **Reach a custom field.** `custom_fields.*` is installation-specific by
  definition, so no driver can know it. This fleet's NetBox carries
  `pve_node`, `pve_tags` and `vmid`. Map them onto a VEYRS field
  (`location` ← `custom_fields.pve_node`) or keep them as-is with the
  `extra.` prefix (`extra.vmid` ← `custom_fields.vmid`).
- **Override a default** you disagree with.

A mapped path that resolves to nothing **leaves the default alone**, so a typo
costs you the override, not the field.

The `extra.` prefix is required. Any other unrecognised target is refused with
a 422 naming it — otherwise `hostnmae` would file itself quietly under `extra`
and you would get an import that runs cleanly and reports no hostnames.

### Value translation

For fields VEYRS holds as a fixed vocabulary. A role slug the driver does not
recognise collapses to `server`, which is indistinguishable from a deliberate
answer, so say what your own roles mean:

```json
{"value_maps": {"asset_type": {"hipervisor": "server", "pve-host": "server"}}}
```

Read on the **raw NetBox token** (`role.slug`), not on the value already
derived from it. A translation to a type VEYRS does not have is refused when
you save, not complained about on every row of a run that already happened.

NetBox `status` is a **lifecycle**, not an environment: `active` says the
device is racked, not that it is production. It is carried as a label and is
never mapped to `environment` unless you say so explicitly with a field map
plus a translation.

### Choosing which data to collect

`include_fields` is an allowlist. **Empty means every field.** Tick a subset
and the source may report only those — `extra` and the raw payload survive,
because the raw payload is the audit trail of what the source actually said.

Keep at least one field the match ladder reads (`external_id`, `serial`,
`fqdn`, `hostname`, `ip`, `name`). A source narrowed past its own match keys
stages every host as unmatched, which reads as "the CMDB disagrees with the
estate" rather than as a filter set too tight. The server refuses that
combination.

### Permissions

`importer:read` to see the screen, `importer:write` to test and sync,
`importer:admin` to add, edit or delete a source. Of the built-in roles only
`security-manager` holds read and write; **admin is `org-admin` only.**

## Importing teams (Administration → Import teams)

Creates VEYRS teams from a system that already has them.

- **NetBox** — tenants, sites, contact groups or device roles. Pick **tenants**
  first: it is already what the asset driver reads into every device's team
  label, so importing it makes those labels resolve to a real team.
- **LDAP / Active Directory** — every group under the configured group base.
  Not filtered by the group-to-role map: that map says which groups grant a
  *role*, and a team is not a role. This reads the directory **even when
  sign-in against it is off**, so you can use AD as an org chart without
  handing it the login page.

Preview first. The same code backs the preview and the result, so the screen
you approved and the summary you are shown cannot describe two different
things.

Three limits, each deliberate:

- **It never deletes.** A team absent from the source is reported as `orphan`
  and left alone. Reconciling by deletion means one expired bind password
  detaches every finding, ticket and escalation chain that pointed at it.
- **It never creates a user.** Membership seats accounts that already exist,
  matched on username then email. Directory provisioning is `jit_provisioning`
  under **Directory**, and it is off.
- **It never touches the manager, the department or the escalation chain.**
  No external system knows who gets paged.

Slug collisions are reported as `conflict`, not renumbered — rename one of them
at the source.

### Assigning assets

**Assign assets** points matched assets at the team their staged label names.
It reads the staging rows from the last sync, not NetBox, so it agrees with
what you reviewed and works while NetBox is unreachable. Dry-run first. An
asset somebody assigned by hand keeps that assignment unless you tick
overwrite.

Findings do not need individual assignment: a finding with no explicit owner
belongs to its asset's team.

Needs `team:write`, which of the built-in roles only `org-admin` holds.

## ITSM connectors

```
POST /api/v1/integrations/connectors
{"slug": "snow", "name": "ServiceNow", "system": "servicenow",
 "base_url": "https://acme.service-now.com",
 "credentials": {"username": "svc", "password": "..."},
 "ticket_types": ["remediation", "change"],
 "field_mapping": {"table": "incident", "category": "security"}}
```

Systems: `servicenow`, `jira`, `webhook`. Credentials are Fernet-encrypted and
never appear in any response.

Push is digest-guarded: an unchanged ticket is not re-sent. Pull refreshes the
remote status **only** - an external system cannot close a VEYRS finding.

## AI policy

The single most important admin setting. Defaults are restrictive:

```
PUT /api/v1/ai/policy
{"allow_external": false, "allow_local": true,
 "max_external_classification": "public",
 "max_local_classification": "confidential"}
```

Before enabling an external provider, dry-run the guardrails on real content:

```
POST /api/v1/ai/scan   {"text": "<paste a real advisory or ticket body>"}
```

It reports what would be redacted and whether the call would be blocked, without
echoing the sensitive text back.

`GET /api/v1/ai/capabilities` shows what is available right now and *why not*
otherwise. `GET /api/v1/ai/audit?decision=blocked` shows every refusal.

## Compliance

```
GET  /api/v1/compliance/frameworks
POST /api/v1/compliance/frameworks/{id}/refresh-signals
GET  /api/v1/compliance/frameworks/{id}/coverage
```

Built-in catalogues: NIST CSF 2.0, CIS Controls v8, ISO/IEC 27001:2022 Annex A,
ISO/IEC 27002:2022. **All are shipped partial** - identifiers and short titles
only, because the normative text of the ISO standards is copyrighted and we will
not redistribute it, and every coverage report says so in a disclaimer you
cannot turn off.

To complete a catalogue you license:

```
POST /api/v1/compliance/frameworks/{id}/controls:import   (CSV: ref,title,normative_text)
```

`is_partial` clears automatically when the imported count reaches the
publisher's official control count. It is derived, never hand-set.

Twelve automated signals compute evidence from live data and report their own
derivation. **A passing signal lifts a control to `partial` at most, never to
`implemented`** - a green metric proves the machinery runs, not that the control
is designed, owned and operating. Human claims are still required, and that is
what an auditor actually interviews about.

Other guardrails: `not_applicable` requires a justification; `implemented`
decays to `stale` when its review period lapses; `not_assessed` counts against
coverage; a completed assessment freezes its snapshot and auto-raises a gap per
shortfall.

## Operations

```bash
veyrs sync-nvd [--full]     # CVE catalogue
veyrs sync-epss             # EPSS scores + history
veyrs sync-kev              # CISA KEV
veyrs run-sla               # evaluate SLA state, fire escalations
veyrs recompute-risk [--org SLUG]
veyrs check                 # self-test config, storage, engines
veyrs keygen                # a fresh VEYRS_ENCRYPTION_KEY
```

Schedule `sync-*` daily and `run-sla` hourly. `GET /api/v1/intel/health` shows
feed freshness.

## Secret storage: local or an external vault

VEYRS stores credentials for the systems it talks to (ITSM, scanners, CMDB, AI
providers, the LDAP service account, TOTP secrets). By default they are
encrypted with `VEYRS_ENCRYPTION_KEY` — which lives in `.env` **on the same
host as the database**. Anyone who can read that disk can read every one of
them. Pointing VEYRS at HashiCorp Vault or OpenBao moves them off the host.
What is stored where is in [SECURITY.md §Secrets at rest](SECURITY.md#secrets-at-rest);
the settings are in [SYSTEM_MANUAL.md §2.2.1](SYSTEM_MANUAL.md#221-secret-storage-local-fernet-or-an-external-vault).

**Administration → Secret storage** shows the current mode, whether the vault
answers, is unsealed and accepts VEYRS's credentials, how many of this
organization's credentials are still on the host, and the next command to run.
It is read-only **on purpose**: migration moves every tenant's credentials and
needs the host and the vault policy, so it is a CLI operation for whoever runs
the platform, not a button in one tenant's console.

### Moving credentials into the vault

1. **Prepare the vault.** A KV version 2 mount for this installation (default
   `veyrs`), an AppRole with the policy in SYSTEM_MANUAL §2.2.1, and its
   secret-id in a file readable only by the service account:

   ```bash
   install -m 0600 -o veyrs -g veyrs /dev/null /etc/veyrs/vault-secret-id
   # write the secret-id into it, then in /opt/veyrs/.env:
   VEYRS_VAULT_ADDR=https://vault.example.com:8200
   VEYRS_VAULT_ROLE_ID=<role-id>
   VEYRS_VAULT_SECRET_ID_FILE=/etc/veyrs/vault-secret-id
   ```

2. **Check it** without changing anything: `veyrs secrets status` must say
   `reachable: yes  sealed: no  auth: ok`. The backend is still `local`.

3. **Mirror.** Set `VEYRS_SECRET_BACKEND=mirror`, restart the API (and the
   timers' next run picks it up), then:

   ```bash
   veyrs secrets migrate --to mirror            # dry run: reads every value, writes nothing
   veyrs secrets migrate --to mirror --apply
   ```

   New and existing credentials now have a vault copy, but the local copies are
   **still on the host**. Run in this mode until you trust the vault: if it
   goes down, VEYRS falls back to the local copies and logs a warning.

4. **Vault only.** Set `VEYRS_SECRET_BACKEND=vault`, restart, then:

   ```bash
   veyrs secrets migrate --to vault --apply
   veyrs secrets status                         # "still on this host": 0
   ```

   The mirror → vault step reuses each vault entry and drops the local copy. From
   now on an unreachable or sealed vault makes credential-using features fail
   (`503 secret_storage_unavailable`, LDAP and MFA sign-ins refused) instead of
   guessing.

5. **Backups.** Database backups made before step 4 still contain the local
   copies. Age them out (or re-key them) on your normal retention schedule.

A row that cannot be read during a migration (corrupt, key changed, vault
missing the entry) is listed with its organization, column and row id and left
**exactly as it was** — never blanked. Fix it or re-enter that credential, then
run the same command again; it skips rows already in the target form.
`--org SLUG` limits a run to one organization.

### Rolling back

```bash
# keep the VEYRS_VAULT_* settings in place while doing this
VEYRS_SECRET_BACKEND=local   # in .env, then restart the API
veyrs secrets migrate --to local --apply
veyrs secrets status         # vault: 0, mirror: 0
```

`decrypt` follows each stored value, not the mode, so nothing breaks between the
restart and the migration: `vault:` rows are still read from the vault. Only
after `status` shows no `vault`/`mirror` rows may the `VEYRS_VAULT_*` settings be
removed. The migration does not delete vault entries, so the rollback itself can
be rolled back; delete them later with `gc`.

### Orphans

Replacing a credential stores a new vault entry and leaves the old one. List
and remove them:

```bash
veyrs secrets gc                    # lists unreferenced entries
veyrs secrets gc --apply            # deletes them
```

Entries younger than `--min-age-minutes` (default 60) are kept: they may belong
to a save whose database row has not been committed yet. `gc` also reports rows
whose vault entry is **missing** — those credentials will fail on their next
use and must be re-entered. Use one mount (or namespace) per VEYRS installation:
`gc` treats every unreferenced key under `secrets/` as its own.

## Audit

```
GET /api/v1/audit?action=finding.state_changed&limit=100
GET /api/v1/ai/audit?decision=blocked
```

Append-only. There is no update or delete path in the application for any of the
three logs.

## Running VEYRS as an ingest-only platform (Administration → Scanning)

VEYRS does two different jobs and only one of them touches your estate. It
**ingests** what scanners report — uploads, scanner connectors, agent results —
and it **executes** scans itself, through an enrolled agent running nuclei.

If you already own a scanner, you want the first job and not the second.
Turning **active scanning** off makes VEYRS a vulnerability *management* and
*traceability* platform: findings arrive from your tool, and VEYRS does the
correlation, risk scoring, ownership, SLA, escalation, ticketing, verification
and audit on top of them. It probes nothing.

### Where it is

`Administration → Scanning`, or `PUT /api/v1/scanning`. It needs
**`settings:admin`** and is refused to a team-scoped identity: the switch
governs the whole estate, and a team that could turn scanning off would
silently stop the sweeps every other team's findings depend on.

### What "off" actually refuses

Hiding a button is not a control. The switch is enforced where work is
**created** and where it is **handed out**, and deliberately **not** where work
is **finished**.

| Capability | With scanning off |
|---|---|
| Queue a scan job | **refused** (403) |
| An agent claims a job | **refused** |
| Enrol a new agent | **refused** |
| Agent heartbeat | allowed — answers `active_scanning: false` so the runner stands down |
| Submit a scan result | allowed |
| Report host inventory | allowed |
| Import a file, pull a connector | allowed |

Three of those deserve their reasons out loud:

- **`claim_next` is the one that matters.** Enforcing this only at queue time
  would let a backlog queued before the flip drain into the estate afterwards —
  the estate gets scanned by a platform whose owner believes it stopped.
- **`submit_result` stays open.** A scan already in flight has already touched
  the estate. Refusing its output would discard the only thing of value it
  produced and leave its job wedged in `running` forever.
- **Inventory reporting stays open.** Reporting what is installed is not
  scanning, and an ingest-only deployment leans on the correlation engine
  harder than any other — blinding it would defeat the mode.

### Queued work

Turning scanning off **cancels jobs that are still queued** (you can opt out).
A job that can never be claimed is not queued, it is stuck, and a queue depth
counting work nobody will run is a number the dashboard reports wrongly. Each
cancellation goes through the normal path, so it appears in the job's own event
stream and in the audit log. Jobs already **running** are left alone.

### Turning it back on

The same screen. Previously cancelled jobs are not resurrected — re-queue what
you still want. The switch records **who** changed it, **when**, and the
**reason** you typed; "who stopped scanning production, and why" is the
question this setting will be asked six months from now.

### What it does not do

It does not stop or uninstall the agent process on the runner host. The agent
is *told* to stand down and is refused work; whether its systemd unit keeps
running is a decision for whoever owns that machine.

## Software update (Administration → Software update)

Platform administrators only: the installed version belongs to the
installation, not to one organization.

The tab shows the installed version, the latest release and its release notes,
whether that release is **signed** (it carries `SHA256SUMS.sig`), how this node
is installed, and the outcome of each past update with its steps. The check
runs at most once an hour (**Check now** forces it); with `VEYRS_UPDATE_URL`
empty — an air-gapped node — it is off and says so.

**Apply** appears only when all of this holds: a native install, a newer
release, a signed one, a pre-update backup arranged (`VEYRS_UPDATE_PRE_HOOK`, or
a deliberate `VEYRS_UPDATE_SKIP_BACKUP=1`), and no request already queued.
Otherwise the tab states which condition failed. Applying only queues the
request: a root service on the host verifies the signature, runs the backup
hook, re-runs the installer and checks health while the API restarts. A Docker
node shows the host command to run instead; a git checkout is "managed by git
deploy" and never updates from here. Procedure and failure handling:
[DEPLOYMENT.md](DEPLOYMENT.md#in-product-update-native-installs).
