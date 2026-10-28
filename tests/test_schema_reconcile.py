"""The reconciler must be able to build every invariant the models declare.

Two failures produced this file, both of them silent:

* `sync-schema` never looked at UNIQUE constraints on an existing table, so a
  model could promise an invariant the database did not hold. `users.username`
  shipped exactly that way.
* The naming convention in `models/base.py` is
  `uq_%(table_name)s_%(column_0_name)s` -- it keys on the FIRST column only, so
  a second per-tenant constraint on the same table renders to a name that is
  already taken. The DDL is then unbuildable and the failure looks like
  "0 constraints added".

Neither is visible from a passing request; both are visible from the metadata.
"""

from collections import Counter

import pytest
from sqlalchemy import UniqueConstraint

from veyrs.models.base import Base


def _named_uniques(table):
    return [c for c in table.constraints if isinstance(c, UniqueConstraint)]


def test_no_two_unique_constraints_on_a_table_share_a_name():
    """The convention keys on column_0, so collisions are easy and invisible."""
    collisions = {}
    for name, table in Base.metadata.tables.items():
        counts = Counter(c.name for c in _named_uniques(table) if c.name)
        dupes = {n: k for n, k in counts.items() if k > 1}
        if dupes:
            collisions[name] = dupes
    assert not collisions, (
        "these tables declare several UNIQUE constraints that render to the same "
        f"name, so only one can ever exist: {collisions}. Pass an explicit "
        "name= to the extra ones."
    )


def test_every_unique_constraint_has_a_name_the_reconciler_can_use():
    """An unnamed constraint is skipped by sync_columns() -- it cannot address it."""
    unnamed = {
        name: [tuple(c.name for c in uq.columns) for uq in _named_uniques(table)
               if not uq.name]
        for name, table in Base.metadata.tables.items()
    }
    unnamed = {k: v for k, v in unnamed.items() if v}
    assert not unnamed, f"unnamed UNIQUE constraints are unreconcilable: {unnamed}"


def test_username_is_unique_per_tenant_not_globally():
    """A global constraint would let the first tenant deny `jsmith` to everyone."""
    users = Base.metadata.tables["users"]
    match = [uq for uq in _named_uniques(users)
             if {c.name for c in uq.columns} == {"organization_id", "username"}]
    assert len(match) == 1, "the per-tenant username constraint is gone"
    assert match[0].name == "uq_users_organization_id_username", (
        "it must stay explicitly named -- the convention collides with the email "
        "constraint, which is how it went missing from the database in the first "
        "place"
    )


def test_the_reconciler_reads_unique_constraints_at_all():
    """Pin the behaviour, not the prose: a grep for the docstring is not a test."""
    import ast
    import inspect as _inspect

    from veyrs import cli

    tree = ast.parse(_inspect.getsource(cli.sync_columns))
    names = {n.id for n in ast.walk(tree) if isinstance(n, ast.Name)}
    attrs = {n.attr for n in ast.walk(tree) if isinstance(n, ast.Attribute)}
    assert "UniqueConstraint" in names, (
        "sync_columns() no longer inspects UniqueConstraint; a model-declared "
        "invariant would again land as a column with no constraint behind it"
    )
    assert "get_unique_constraints" in attrs, (
        "sync_columns() must ask the live database what it already has, or it "
        "will try to rebuild constraints on every run"
    )
