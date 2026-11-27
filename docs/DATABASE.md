---
title: Database manual
purpose: Describe how the VEYRS schema is organised, which guarantees it makes and how to operate PostgreSQL for it.
scope: Overview manual for the single PostgreSQL database; the architecture deep dive, diagrams, lifecycle, queries and backup views are in the database/ folder, and the generated column reference is DATABASE_SCHEMA.md.
version: 0.39.1
verified: 2026-11-17
status: Implemented
sources: [backend/veyrs/db.py, backend/veyrs/cli.py, backend/veyrs/models/base.py, backend/veyrs/services/secret_storage.py, backend/veyrs/security/secrets.py, scripts/backup.sh, scripts/restore.sh, scripts/gen-schema-doc.py, extract/schema.json]
related: [DATABASE_SCHEMA.md, database/README.md, database/er-diagrams.md, database/lifecycle.md, database/queries.md, database/backup-recovery.md, DISASTER_RECOVERY.md, HIGH_AVAILABILITY.md, THREAT_MODEL.md]
---

# Database manual

PostgreSQL 15. **93 tables.** Multi-tenancy enforced in two independent layers.

This is the manual: how the schema is organised, what guarantees it makes, and
how to operate it. The table-by-table reference — every column, type, key and
index — is [DATABASE_SCHEMA.md](DATABASE_SCHEMA.md), and it is **generated from
the models**, not written by hand.

Deeper views, each verified against the code: [architecture, RLS and schema
management](database/README.md), [ER diagrams](database/er-diagrams.md) (all 90
tables), [data lifecycle and retention](database/lifecycle.md), [heavy
queries](database/queries.md) and [backup and recovery at data
level](database/backup-recovery.md).

| | |
|---|---|
| Engine | PostgreSQL 15 or newer (tested on 15.19; the installers refuse anything older) |
| Driver | `psycopg` 3, SQLAlchemy 2.0 ORM |
| Encoding | **UTF8 mandatory** — see [INSTALL.md](../INSTALL.md#2-create-the-databases) |
| Extensions | none required; `pg_trgm` optional (installed by a superuser, it enables the search trigram indexes, 0.41.0) |
| Tables | 90 |
| RLS | 68 strictly isolated + 4 credential-keyed + `auth_events` with its own policies (73 tables carry `FORCE ROW LEVEL SECURITY`) |
| Global (shared) tables | 16 (incl. `trusted_cas`, 0.40.0) |
| Pool | `pool_size` = `VEYRS_DB_POOL_SIZE` (8), `max_overflow` = `VEYRS_DB_MAX_OVERFLOW` (12), `pool_pre_ping=True` per worker process (0.41.0) |

> **Sizing the pool.** The API runs 4 uvicorn workers by default, so the ceiling
> is `4 × (8 + 12) = 80` connections with the 0.41.0 defaults, plus the CLI and
> any timer unit that happens to be running. Postgres ships with
> `max_connections = 100`. Raise
> `max_connections`, or lower the worker count, **before** raising `pool_size` —
> a pool bigger than the server accepts fails at peak, which is the one moment
> it matters.

---

## 1. The tenancy model

Every tenant-owned table carries `organization_id NOT NULL`, indexed, and it is
the first key of nearly every composite index.

**Layer 1 — application.** Services filter on `organization_id` explicitly.

**Layer 2 — PostgreSQL Row Level Security.** Tables are `ENABLE` + **`FORCE`**
row level security with one policy:

```sql
CREATE POLICY veyrs_tenant_isolation ON <table>
  USING      (organization_id::text = NULLIF(current_setting('veyrs.current_org', true), ''))
  WITH CHECK (organization_id::text = NULLIF(current_setting('veyrs.current_org', true), ''));
```

A bug in one layer cannot leak another organization's rows. `FORCE` is the part
that matters: without it the policy does not apply to the table **owner**, which
is exactly the role the application connects as.

### 1.1 The transaction-local gotcha

`set_config('veyrs.current_org', v, true)` is **transaction-local**. A `commit()`
ends the transaction and the binding disappears — after which an RLS policy with
no tenant matches *nothing*, so subsequent queries **silently return zero rows**.
Handlers that commit and keep working (create ticket → fire workflow) hit this.

VEYRS remembers the tenant on `Session.info` and re-applies it from an
`after_begin` event hook. See `backend/veyrs/db.py::set_tenant`.

> This is also the number one cause of a confusing test failure. A raw query
> opened on a fresh `SessionLocal()` against an RLS-forced table returns **zero
> rows with no error** — in a soft-delete test that reads as a hard delete. Call
> `set_tenant(session, org_id)` before believing the result.

### 1.2 Pre-auth tables

`users`, `refresh_tokens`, `api_keys` and `exec_agents` are queried **before**
the tenant is known (login looks up by email, refresh by token hash, API keys by
prefix, agents by token). A strict policy would make login impossible, so they
get a permissive-when-unbound policy:

```sql
USING (organization_id::text = COALESCE(
         NULLIF(current_setting('veyrs.current_org', true), ''), organization_id::text))
```

Visible while `veyrs.current_org` is unset — the pre-auth window only, since
`get_principal` binds it immediately — and tenant-filtered once bound.
Documented as **T-TENANT-01** in the [Threat Model](THREAT_MODEL.md).

### 1.3 Global tables

Shared reference data, deliberately not tenant-scoped, because a CVE is the same
CVE for everyone:

`cve`, `cwe`, `cpe`, `cve_references`, `cve_cpe_match`, `epss_scores`,
`epss_history`, `kev_entries`, `vendors`, `products`, `product_versions`,
`compliance_frameworks`, `compliance_controls`, plus `organizations` and
`feed_runs`. `roles` (built-ins have no organization) carries a nullable
`organization_id` and is scoped by the application layer, not by RLS;
`auth_events` (nullable too) has its own row policies since 0.41.0
(`schema_steps/step_auth.py`).
`compliance_frameworks` is also in the no-policy set although it has a nullable
`organization_id` (tenant-authored custom frameworks): its visibility rule lives
in `api/v1/compliance.py`, and its unique key `(slug, version)` is global.

### 1.4 Nullable-tenant tables, and why the audit trails are strict anyway

A few tables carry a **nullable** `organization_id`. As a rule `init-db` skips
them: a strict policy on a nullable column makes any NULL-tenant row invisible
forever, since `NULL = anything` is never true.

**`audit_log` and `ai_audit_log` are the exception** (`RLS_TABLES_STRICT_NULLABLE`
in `cli.py`) and get the strict policy since 0.32.3. An audit trail readable
across tenants tells one organization who changed what in every other one, and
no writer needs a NULL tenant: every `audit.record()` and `record_ai()` call
passes one, including the first login of a directory-provisioned user, which
binds its organization before writing. Production deployments already carried
this policy; before 0.32.3 a fresh `init-db` was the laxer of the two (it forced
two tables fewer than production did).

Audit writes run inside a SAVEPOINT (`services/audit.py`). A row the policy
rejects is logged as `audit write failed` and dropped, and the request carries
on. Without the savepoint, the rejected INSERT would leave the session needing a
rollback and fail the very request it was only meant to record. §7.3 shows how
to check a deployment.

---

## 2. Entity relationships

### Identity

```
organizations ─┬─< users ─< user_roles >─ roles
               ├─< teams ─< team_members >─ users
               ├─< departments
               └─< api_keys, refresh_tokens
```

### Intelligence → asset → finding (the spine)

```
cve ──< cve_references
 │   ──< cve_cpe_match >── cpe
 │   ──1 epss_scores        ──< epss_history
 │   ──1 kev_entries
 │
 └──< vulnerabilities (per tenant)
         │
         └──< findings >── assets ──< asset_products >── products >── vendors
                 │            └── business_services
                 ├──< finding_events        (append-only lifecycle history)
                 ├──< risk_score_history
                 └──< tickets
```

### Inventory ingestion (asset sources)

```
asset_sources ──< asset_source_records ──promote──> assets
     │
     └── driver: file | http_json | netbox
         field_map      (override layer over the driver's own mapping)
         value_maps     (applied to the RAW token, before typing)
         include_fields (allowlist; empty = every field)
```

A record is **staged first** and promoted second. A record whose asset cannot be
identified is rejected with a reason — never attached to a plausible neighbour.

### Remediation: internal queue **or** external ITSM

```
organizations.settings["ticketing"] = {mode: internal|external, connector_id}

internal:  findings ──< tickets ──< ticket_comments, ticket_events
                          └── ticket_counters  (per-tenant sequence, FOR UPDATE)
           references look like VEYRS-INC-000001 (INC, PRB, CHG, REQ, REM, EXC)

external:  findings ──< external_links >── itsm_connectors
                          (finding_id, asset_id, vulnerability_id, cve_id,
                           summary, severity, risk_score, due_at,
                           remote_status, remote_priority, remote_assignee, …)
```

`external_links` is the same table that mirrors Confluence pages
(`object_type = "knowledge"`). It is **deliberately denormalised**: a relation
you can only read by joining four tables and calling Jira is not a relation an
operator can put in a report, and the snapshot stays true after the finding is
re-scored.

### SLA, workflow, notifications

```
sla_policies ──< sla_events
escalation_policies
workflow_definitions ──< workflow_runs
notification_templates ──< notifications ──> notification_preferences
webhook_endpoints
```

### Risk register (not attached to an asset)

```
risk_register ──< risk_register_raci   (R/A/C/I; A is exactly one PERSON)
     │        ──< risk_register_links  (asset | finding | vulnerability | control)
     └────────< risk_register_events   (append-only history)
```

There is **no `owner_team_id` column**. The `A` row of the RACI *is* the owner —
a second column answering the same question is how two authorities get created.
A partial unique index enforces it in the database, not only in the service:

```sql
CREATE UNIQUE INDEX uq_risk_register_one_accountable
  ON risk_register_raci (risk_id) WHERE raci = 'A';
```

### Compliance

```
compliance_frameworks ──< compliance_controls
                              │
        control_implementations ──< compliance_evidence
                              │
                     control_risk_links ──→ asset | finding | ticket
compliance_assessments ──< assessment_gaps
```

### Knowledge and AI

```
knowledge_articles ──< knowledge_revisions
        └──publish──> external_links (object_type="knowledge") >── itsm_connectors
documents ──< document_chunks
threat_sources ──< threat_articles

ai_policies (1 per org)   ai_providers
ai_conversations ──< ai_messages
ai_audit_log      (append-only; every call, including the blocked ones)
```

---

## 3. Design decisions worth not re-litigating

**Findings vs vulnerabilities.** A `Vulnerability` is the tenant's view of one
CVE. A `Finding` is that vulnerability *on one asset at one location*
(port/protocol/path). One CVE on 40 servers is 1 vulnerability and 40 findings.

**Dedupe key.** `findings.dedupe_key` is `NOT NULL` and unique per
`(organization_id, asset_id, dedupe_key)`. The default `legacy` algorithm hashes
`(org, asset, vuln_ref, port, protocol, path)`; a scanner may be registered with
another algorithm (`unique_id_from_tool`, `hash_code`, `unique_id_or_hash_code`;
`services/dedupe.py`) and `findings.dedupe_algorithm` records which one produced
the key. It is normally computed by the deduplicator — a fixture that invents a
finding must supply one. Re-importing a scan updates rather than duplicating. A finding seen again after
`remediated` is **reopened** as a regression, keyed on the *state* — not on
`closed_at`, which `remediated` never sets. That distinction was a real bug: a
failed patch silently vanished.

**CVSS revisions side by side.** `cve` stores `cvss2_*`, `cvss3_*` and `cvss4_*`
in parallel rather than collapsing them, because the risk engine and the UI both
want to show the difference. `best_cvss_score` prefers v4 > v3 > v2.

**`vulnerabilities.cve_id` is a real foreign key** against the `cve` table. A
fixture that invents a CVE identifier fails with `ForeignKeyViolation`; seed the
catalogue row first.

**Soft delete is the default for assets.** `DELETE /assets/{id}` sets
`deleted_at` + `is_active = false`; packages, findings and tickets survive, and
the deletion is reversible with an `UPDATE`. Two consequences to know: the
importer's `resolve_asset()` **does** filter `deleted_at`
(`services/importers/base.py:436`), so after a soft delete an import with
`create_assets` on tries to insert a **new** asset instead of re-attaching to the
old one — and an asset created by an earlier import carries
`external_id = import:<key>`, unique per organization (`uq_assets_organization_id`),
so that insert can collide with the soft-deleted row (read from the code, not
reproduced); and the executive dashboard counts findings without joining `deleted_at` — so
its open-findings number can exceed the number of findings on live assets.

**Append-only logs.** `audit_log`, `auth_events` and `ai_audit_log` have no
UPDATE or DELETE path in the application, and since 0.41.0 a trigger
(`schema_steps/step_auth.py`) refuses `UPDATE`, `DELETE` and `TRUNCATE` on them
in the database, except retention deletes inside a transaction that ran
`SET LOCAL veyrs.audit_prune = 'on'` and foreign-key cascades (`audit_log`
rows are still deleted with their organization by `ON DELETE CASCADE`). The
application role owns the tables and could disable the trigger.
`compliance_evidence` has no update route: a changed control position produces
*new* evidence, so "what did you have on 2026-03-01?" survives later edits.

**Per-tenant sequences.** `ticket_counters` issues `VEYRS-INC-000001` (prefix by
ticket type) and, since the risk register, `RISK-000001` under
`ticket_type='risk_register'`. The table is
badly named for the second use; it is reused because it is already a per-tenant
sequence taken `FOR UPDATE` and already isolated by RLS.

**Naming convention.** Constraint names are declared in `models/base.NAMING`, so
generated DDL and any future migration tool produce stable, reviewable names
rather than database-assigned ones.

---

## 4. Indexing

Composite indexes lead with `organization_id`. The ones that matter under load:

| Index | Serves |
|---|---|
| `ix_findings_org_risk` | the default findings list, ordered by risk |
| `ix_findings_org_state` | open-queue counts on every dashboard |
| `ix_cve_cvss3`, `ix_cve_cvss4` | severity filters over the global catalogue |
| `epss_scores.score` | "EPSS above X" queries |
| `kev_entries.due_date` | the KEV overdue queue |
| `ix_audit_org_time` | audit trail paging |
| `uq_findings_organization_id` (organization_id, asset_id, dedupe_key) | the importer upsert path and duplicate protection |
| `uq_risk_register_one_accountable` | one accountable person per risk |

---

## 5. Schema management

**There is no Alembic, and no migration files.** `migrations/` holds only a
README. Schema changes are applied by two CLI commands, and the difference
between them has already cost one release:

| Command | Does | Does **not** |
|---|---|---|
| `veyrs init-db` | `create_all()` (missing **tables**), then `sync-schema`, then RLS policies, then seeds built-in roles and compliance catalogues | drop, rename, narrow or retype anything |
| `veyrs sync-schema` | add **columns**; create **indexes** declared in the models and missing by name (composite and partial included); create missing **named unique constraints** (as unique indexes); add a **foreign key only for a column it just added**; **widen** a `VARCHAR(n)` whose model is now longer or `TEXT` (0.32.5) | **create tables**, repair a foreign key on an existing column, drop, rename, narrow, retype |

> **The deploy trap.** On a database missing a release's new tables,
> `sync-schema` prints `0 columns, 0 indexes, 0 constraints added` and exits
> **0** — a success message for a no-op, followed by `UndefinedTable` 500s on
> exactly the new endpoints. Run `init-db`; it is idempotent and safe on every
> deploy. `scripts/restore.sh` runs it unconditionally for this reason.

`sync-schema` **refuses** to add a `NOT NULL` column with no usable default
(it does not check whether the table is empty) — on a non-empty table Postgres
cannot, and guessing a backfill value is exactly the kind of invention this
codebase does not do. It prints the three statements the
operator needs and moves on.

Widening is the one change to an existing column it makes:
`VARCHAR(n)` to `VARCHAR(m > n)` or to `TEXT`. Both keep every value, and
PostgreSQL does them without rewriting the table. It prints
`~ column <table>.<col> widened to <type>`. If PostgreSQL refuses (a view over
the column, for instance) it prints the `ALTER` for the operator and moves on.
0.32.5 needed it: `cve_references.url` went from `VARCHAR(1000)` to `TEXT`
because one NVD reference URL was longer, and without the widening every
existing install would have kept the old column and kept failing on that
record.

A destructive change (drop, rename, narrowing, any other retype) is a decision,
not a reconciliation: write the SQL, review it, run it during a window.

---

## 6. Encryption at rest

Reversible secrets live in these columns (the list in
`services/secret_storage.py`), Fernet
envelope-encrypted with a `v1:` prefix (`backend/veyrs/security/secrets.py`):

- `ai_providers.api_key_enc`
- `itsm_connectors.credentials_enc`
- `itsm_connectors.inbound_secret_enc`
- `scanner_connectors.credentials_enc`
- `threat_sources.credentials_enc`
- `webhook_endpoints.secret_enc`
- `asset_sources.credentials_enc`
- `users.mfa_secret` (the TOTP seed; recovery codes are SHA-256 hashes, not sealed)
- the directory secrets in `organizations.settings` (`ldap.bind_password_enc`,
  and the RADIUS and OIDC secrets alongside it)

With `VEYRS_SECRET_BACKEND=vault` the column holds a `vault:` reference instead
of the ciphertext.

Passwords are **not** here — those are Argon2id hashes in `users.password_hash`
and are never reversible.

> **Do not just replace `VEYRS_ENCRYPTION_KEY`.** Swapping the value makes the
> existing ciphertext undecryptable. Rotate it with the keyring instead: put the
> new key in `VEYRS_ENCRYPTION_KEY`, the old one in
> `VEYRS_ENCRYPTION_KEY_PREVIOUS`, restart, run
> `python -m veyrs secrets rekey --apply` (dry run without `--apply`), then drop
> the previous key — see [database/README.md](database/README.md#encryption-at-rest-of-columns)
> and [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md). A backup archive that omits
> the key is a backup of unrecoverable ciphertext, which is why
> `scripts/backup.sh` includes it — and why that archive is as sensitive as the
> database itself.

> **An empty credential is not a credential.** `{}` used to be stored as
> `encrypt("{}")`, which made `credentials_set` report `true` for connectors
> that had none — and made the "you never saved a token" diagnosis unreachable
> code. Both create and rotate now refuse to store an empty dict.

---

## 7. Operating the database

### 7.1 Backup and restore

```bash
/opt/veyrs/scripts/backup.sh      # database + .env secrets + uploaded documents
/opt/veyrs/scripts/restore.sh     # documented AND tested; runs init-db afterwards
```

**The dump must run as a role that bypasses RLS.** Every tenant table is
`FORCE ROW LEVEL SECURITY`, which applies to the table owner too — so a plain
`pg_dump` as the `veyrs` role fails partway with *"query would be affected by
row-level security policy"*, **after** writing a partial file. That is the worst
failure mode a backup has: it looks like it ran.

Use the `postgres` superuser over peer authentication, or a dedicated role:

```sql
CREATE ROLE veyrs_backup LOGIN BYPASSRLS PASSWORD '…';
GRANT pg_read_all_data TO veyrs_backup;
```

and point `BACKUP_DSN` at it. Two more practicalities: `pg_dump` running as the
`postgres` OS user **cannot write to `/root`** (use `/var/tmp`), and a restore
target must be created with `ENCODING 'UTF8'`.

`scripts/backup.sh` proves only that the archive is *readable*
(`pg_restore --list`), not that it holds data. Check the content as well:
`pg_restore --list veyrs.dump | grep -c 'TABLE DATA'` should equal the table
count (90). Details, the database-node timers and `RESTORE_DSN` are in
[database/backup-recovery.md](database/backup-recovery.md).

See [DISASTER_RECOVERY.md](DISASTER_RECOVERY.md) for the full drill and
[HIGH_AVAILABILITY.md](HIGH_AVAILABILITY.md) for streaming replication.

### 7.2 Verifying tenancy after a deploy

```sql
-- every table that should be isolated, and whether it actually is
SELECT c.relname,
       c.relrowsecurity      AS rls_enabled,
       c.relforcerowsecurity AS rls_forced,
       p.polname
FROM   pg_class c
JOIN   pg_namespace n ON n.oid = c.relnamespace
LEFT   JOIN pg_policy p ON p.polrelid = c.oid
WHERE  c.relkind = 'r' AND n.nspname = 'public'
ORDER  BY c.relrowsecurity DESC, c.relname;
```

Expect `rls_enabled = t`, `rls_forced = t`, `polname = veyrs_tenant_isolation`
on every tenant table. A table with `organization_id NOT NULL` and no policy is
a finding, not a curiosity.

### 7.3 Checking the audit trails (§1.4)

```sql
SELECT c.relname, c.relforcerowsecurity, p.polname
FROM   pg_class c
JOIN   pg_namespace n ON n.oid = c.relnamespace
LEFT   JOIN pg_policy p ON p.polrelid = c.oid
WHERE  n.nspname = 'public' AND c.relname IN ('audit_log', 'ai_audit_log');
```

Expect `t` and `veyrs_tenant_isolation` on both rows. A deployment created
before 0.32.3 with a fresh `init-db` shows `f` and no policy. Running
`python -m veyrs.cli init-db` again brings it in line, which is idempotent and
touches no data. Then:

```sql
SELECT count(*) FROM audit_log    WHERE organization_id IS NULL;  -- as a BYPASSRLS role
SELECT count(*) FROM ai_audit_log WHERE organization_id IS NULL;
```

A non-zero count means rows from an older writer that the application can no
longer read back. They are still there for a superuser, and nothing deletes them.

### 7.4 Size and growth

```sql
SELECT relname,
       pg_size_pretty(pg_total_relation_size(c.oid)) AS total,
       n_live_tup
FROM   pg_class c
JOIN   pg_namespace n ON n.oid = c.relnamespace
LEFT   JOIN pg_stat_user_tables s ON s.relid = c.oid
WHERE  c.relkind = 'r' AND n.nspname = 'public'
ORDER  BY pg_total_relation_size(c.oid) DESC
LIMIT  15;
```

The catalogues dominate: `cve`, `cve_cpe_match`, `cpe` and `epss_history` are
global and grow with the feeds, not with your estate. `epss_history` is the one
to watch — it gains a row per scored CVE per refresh **by design**, because
"was this exploited-in-the-wild score rising when we deprioritised it?" is a
question that needs history to answer. It is the only table the code prunes:
`VEYRS_EPSS_HISTORY_DAYS` (default 365, `0` keeps everything) is applied after
every `sync-epss`, and `python -m veyrs prune-epss-history` runs it by hand. The
audit, event and history tables are never pruned; see
[database/lifecycle.md](database/lifecycle.md).

### 7.5 Autovacuum

Defaults are fine. The tables worth a lower `autovacuum_vacuum_scale_factor` if
your estate is large are `findings` (updated on every scan import) and
`epss_scores` (updated wholesale on every refresh).

### 7.6 Connecting by hand

```bash
set -a; . /opt/veyrs/.env; set +a
psql "$(sed 's|postgresql+psycopg|postgresql|' <<<"$VEYRS_DATABASE_URL")"
```

Remember you are subject to RLS: `SELECT * FROM findings` returns **nothing**
until you bind a tenant.

```sql
SELECT set_config('veyrs.current_org', '<organization uuid>', false);
SELECT count(*) FROM findings;
```

`false` makes the binding session-local rather than transaction-local, which is
what you want in an interactive shell and never what the application wants.

---

## 8. The full reference, and how it stays true

[DATABASE_SCHEMA.md](DATABASE_SCHEMA.md) lists all 93 tables with every column,
type, key, index and isolation marker. It is **generated**:

```bash
python3 scripts/gen-schema-doc.py            # regenerate
python3 scripts/gen-schema-doc.py --check    # exit 1 if stale
```

`tests/test_docs_are_current.py` runs `--check`, so a model change that
skips the regeneration fails a test with a name — instead of quietly publishing
a schema reference that describes last month's database. That guard exists
because the hand-written version of this page claimed **67 tables** for six
weeks while the models carried 87, and nothing failed.

No database connection is needed to regenerate it: `init-db` builds the schema
from the same metadata the generator reads, so the models *are* the schema.
