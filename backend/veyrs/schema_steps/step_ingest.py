"""Ingest workstream DDL: unique keys whose NULLs must not be distinct (TD-33).

`vulnerabilities (organization_id, cve_id, internal_ref)` and
`risk_register_raci (risk_id, raci, team_id, user_id)` each have a column that
is NULL on every row of one kind, and PostgreSQL's default NULLS DISTINCT makes
such a key enforce nothing: two concurrent correlators could both insert
(org, CVE-X, NULL), and one team could hold the same RACI seat twice. The
models now declare `postgresql_nulls_not_distinct=True`, which `create_all`
honours on a fresh database; these steps convert an existing one.

Each step is idempotent: it does nothing when the backing index already has
`indnullsnotdistinct` (PostgreSQL 15+). Otherwise it rebuilds the constraint in
a sub-transaction, and if rows that differ only by NULL already exist the
rebuild hits a unique violation, the original constraint is kept, and the step
FAILS with the offending key and the command that merges such rows. Duplicates
are never deleted here -- which copy survives is a decision, so it belongs to
`veyrs dedupe merge-duplicates`, which lists them first (dry run by default).
The check cannot simply count the duplicates: under FORCE ROW LEVEL SECURITY
this role sees no tenant rows without a bound tenant, while the index build
does see them all.
"""
from __future__ import annotations


def _nulls_not_distinct(table: str, constraint: str, columns: str) -> str:
    return f"""
DO $$
DECLARE
    already boolean;
    clash text;
BEGIN
    SELECT i.indnullsnotdistinct INTO already
      FROM pg_constraint c JOIN pg_index i ON i.indexrelid = c.conindid
     WHERE c.conrelid = '{table}'::regclass AND c.conname = '{constraint}';
    IF already THEN
        RETURN;
    END IF;
    BEGIN
        ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {constraint};
        ALTER TABLE {table} ADD CONSTRAINT {constraint}
            UNIQUE NULLS NOT DISTINCT ({columns});
    EXCEPTION WHEN unique_violation THEN
        GET STACKED DIAGNOSTICS clash = PG_EXCEPTION_DETAIL;
        RAISE EXCEPTION
            '{table} holds rows that differ only by NULL in ({columns}), so '
            'the unique key cannot be made NULLS NOT DISTINCT (first clash: %). '
            'Nothing was changed. List them with `veyrs dedupe merge-duplicates`, '
            'merge them with `veyrs dedupe merge-duplicates --apply`, then re-run '
            '`veyrs init-db`.', coalesce(clash, SQLERRM);
    END;
END
$$;
"""


STEPS: list[tuple[str, str]] = [
    ("vulnerabilities_identity_nulls_not_distinct", _nulls_not_distinct(
        "vulnerabilities", "uq_vulnerabilities_organization_id",
        "organization_id, cve_id, internal_ref")),
    ("risk_register_raci_seat_nulls_not_distinct", _nulls_not_distinct(
        "risk_register_raci", "uq_risk_register_raci_risk_id",
        "risk_id, raci, team_id, user_id")),
]
