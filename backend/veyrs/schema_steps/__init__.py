"""Idempotent DDL that `create_all` and `sync-schema` cannot express.

`create_all` creates missing tables and `sync-schema` adds missing columns,
but neither changes an existing constraint, index option or trigger. Those
changes live here, one module per concern (`step_<name>.py`), each exposing

    STEPS: list[tuple[str, str]]   # (identifier, SQL statement)

Every statement MUST be idempotent (`IF NOT EXISTS`, `CREATE OR REPLACE`,
`DROP … IF EXISTS` then `CREATE`, or a `DO $$ … $$` block that checks the
catalogue first): `veyrs init-db` runs all of them on every call, in module
name order, each in its own transaction, as the role in VEYRS_DATABASE_URL
(table owner). A failing step stops init-db with its identifier.
"""
from __future__ import annotations

import importlib
import pkgutil

from sqlalchemy import text
from sqlalchemy.engine import Engine


def all_steps() -> list[tuple[str, str]]:
    steps: list[tuple[str, str]] = []
    for mod in sorted(m.name for m in pkgutil.iter_modules(__path__) if m.name.startswith("step_")):
        module = importlib.import_module(f"{__name__}.{mod}")
        for ident, sql in getattr(module, "STEPS", []):
            steps.append((f"{mod}:{ident}", sql))
    return steps


def apply_all(engine: Engine) -> int:
    n = 0
    for ident, sql in all_steps():
        try:
            with engine.begin() as conn:
                conn.execute(text(sql))
        except Exception as exc:  # noqa: BLE001 - re-raised with the step name
            raise RuntimeError(f"schema step {ident} failed: {exc}") from exc
        n += 1
    return n
