"""Audit trails append-only in the database; `auth_events` tenant policies (R-05).

Append-only
-----------
A trigger on `audit_log`, `ai_audit_log` and `auth_events` refuses UPDATE,
DELETE and TRUNCATE, whoever sends them. Two exits, both deliberate:

* **Retention.** A DELETE runs when the transaction has set
  `SET LOCAL veyrs.audit_prune = 'on'`. Only the retention prune command may
  do that; it is the single, greppable place that removes audit history. The
  same setting widens the row policies below so the prune can see every
  tenant's rows (and the unattributed ones) in one pass.
* **Foreign-key cascades.** `audit_log.organization_id` is ON DELETE CASCADE
  and `audit_log.actor_id` ON DELETE SET NULL. A hard delete of an
  organization or user row would otherwise be impossible; those statements
  arrive through the referential-integrity trigger, i.e. at trigger depth > 1.
  The application never hard-deletes either (both are soft-deleted).

This stops every application path and a casual `UPDATE` from an operator. It
does NOT stop the table owner, which today is the application role itself:
an owner can `ALTER TABLE ... DISABLE TRIGGER`. Closing that needs the API to
connect as a non-owner role (docs/security/hardening.md).

`auth_events` row policies
--------------------------
`init-db` skips this table (`cli.RLS_TABLES_SKIP`) because its writer is
mostly pre-authentication: a failed login for an unknown address has no
tenant at all, and a failed login for a known one is written before the
tenant is bound. So the policies are per command:

* INSERT: any session (a forged event needs code execution in the API, which
  is already beyond what a row policy defends).
* SELECT: the bound organization's rows only -- the strict predicate every
  tenant table uses. Rows with no organization (attempts that named nobody)
  are visible only in a transaction that set
  `veyrs.auth_events_unattributed = 'on'`; the API does that for platform
  administrators who ask for them (`GET /auth-events?unattributed=true`).
* DELETE: only under `veyrs.audit_prune = 'on'`.
* UPDATE: no policy, so it matches no row (and the trigger refuses anyway).

The `audit_prune` read/delete policies are added to `audit_log` and
`ai_audit_log` too; their tenant policy (`veyrs_tenant_isolation`) is
created by `init-db` and permissive policies combine with OR.
"""
from __future__ import annotations

_AUDIT_TABLES = ("audit_log", "ai_audit_log", "auth_events")

_PRUNE = "current_setting('veyrs.audit_prune', true) = 'on'"
_STRICT = "organization_id::text = NULLIF(current_setting('veyrs.current_org', true), '')"
_UNATTRIBUTED = ("(organization_id IS NULL AND "
                 "current_setting('veyrs.auth_events_unattributed', true) = 'on')")

_FUNCTION = r"""
CREATE OR REPLACE FUNCTION veyrs_audit_append_only() RETURNS trigger
LANGUAGE plpgsql AS $$
BEGIN
    IF TG_OP IN ('DELETE', 'TRUNCATE')
       AND current_setting('veyrs.audit_prune', true) = 'on' THEN
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NULL;
    END IF;
    IF TG_LEVEL = 'ROW' AND pg_trigger_depth() > 1 THEN
        -- a foreign-key cascade (organization or user hard delete)
        IF TG_OP = 'DELETE' THEN
            RETURN OLD;
        END IF;
        RETURN NEW;
    END IF;
    RAISE EXCEPTION 'veyrs: % on % refused: audit trails are append-only', TG_OP, TG_TABLE_NAME
        USING ERRCODE = 'insufficient_privilege',
              HINT = 'retention deletes run with SET LOCAL veyrs.audit_prune = ''on''';
END
$$
"""


def _steps() -> list[tuple[str, str]]:
    steps: list[tuple[str, str]] = [("audit_append_only_function", _FUNCTION)]
    for table in _AUDIT_TABLES:
        steps += [
            (f"{table}_append_only_rows",
             f'CREATE OR REPLACE TRIGGER veyrs_append_only BEFORE UPDATE OR DELETE ON "{table}" '
             "FOR EACH ROW EXECUTE FUNCTION veyrs_audit_append_only()"),
            (f"{table}_append_only_truncate",
             f'CREATE OR REPLACE TRIGGER veyrs_append_only_truncate BEFORE TRUNCATE ON "{table}" '
             "FOR EACH STATEMENT EXECUTE FUNCTION veyrs_audit_append_only()"),
            (f"{table}_prune_read_policy_drop",
             f'DROP POLICY IF EXISTS veyrs_audit_prune_read ON "{table}"'),
            (f"{table}_prune_read_policy",
             f'CREATE POLICY veyrs_audit_prune_read ON "{table}" FOR SELECT USING ({_PRUNE})'),
            (f"{table}_prune_delete_policy_drop",
             f'DROP POLICY IF EXISTS veyrs_audit_prune_delete ON "{table}"'),
            (f"{table}_prune_delete_policy",
             f'CREATE POLICY veyrs_audit_prune_delete ON "{table}" FOR DELETE USING ({_PRUNE})'),
        ]
    steps += [
        ("auth_events_rls_enable", 'ALTER TABLE "auth_events" ENABLE ROW LEVEL SECURITY'),
        ("auth_events_rls_force", 'ALTER TABLE "auth_events" FORCE ROW LEVEL SECURITY'),
        ("auth_events_insert_policy_drop",
         'DROP POLICY IF EXISTS veyrs_auth_events_insert ON "auth_events"'),
        ("auth_events_insert_policy",
         'CREATE POLICY veyrs_auth_events_insert ON "auth_events" FOR INSERT WITH CHECK (true)'),
        ("auth_events_read_policy_drop",
         'DROP POLICY IF EXISTS veyrs_auth_events_read ON "auth_events"'),
        ("auth_events_read_policy",
         f'CREATE POLICY veyrs_auth_events_read ON "auth_events" FOR SELECT '
         f"USING ({_STRICT} OR {_UNATTRIBUTED})"),
        # The tenant-scoped reader filters on organization and time.
        ("auth_events_org_time_index",
         'CREATE INDEX IF NOT EXISTS ix_auth_events_org_time ON "auth_events" '
         "(organization_id, created_at)"),
    ]
    return steps


STEPS: list[tuple[str, str]] = _steps()
