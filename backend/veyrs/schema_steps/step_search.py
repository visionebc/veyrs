"""Trigram indexes for the lexical search (TD-54, 0.41.0).

`services/search.py` matches `ILIKE '%term%'`, which a b-tree cannot serve.
A GIN index with `gin_trgm_ops` can, but it needs the `pg_trgm` extension,
and `CREATE EXTENSION` needs a superuser while init-db runs as the
application role. So each statement only acts when the extension is already
installed; otherwise it does nothing and search keeps working unindexed.

Enable once, as the database superuser (then run `veyrs init-db`):

    CREATE EXTENSION IF NOT EXISTS pg_trgm;
"""
from __future__ import annotations

# (index, table, column): the columns search.py filters with ILIKE.
_TRGM = [
    ("ix_trgm_cve_id", "cve", "id"),
    ("ix_trgm_cve_title", "cve", "title"),
    ("ix_trgm_vuln_title", "vulnerabilities", "title"),
    ("ix_trgm_finding_title", "findings", "title"),
    ("ix_trgm_asset_name", "assets", "name"),
    ("ix_trgm_asset_hostname", "assets", "hostname"),
    ("ix_trgm_asset_fqdn", "assets", "fqdn"),
    ("ix_trgm_product_name", "products", "name"),
]


def _guarded(index: str, table: str, column: str) -> str:
    return (
        "DO $$ BEGIN "
        "IF EXISTS (SELECT 1 FROM pg_extension WHERE extname = 'pg_trgm') "
        "AND EXISTS (SELECT 1 FROM information_schema.columns "
        f"WHERE table_name = '{table}' AND column_name = '{column}') THEN "
        f'EXECUTE \'CREATE INDEX IF NOT EXISTS "{index}" ON "{table}" '
        f'USING gin ("{column}" gin_trgm_ops)\'; '
        "END IF; END $$"
    )


STEPS = [(index, _guarded(index, table, column)) for index, table, column in _TRGM]
