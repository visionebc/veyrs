"""`sync_columns` may widen a VARCHAR and must not retype anything else.

Pure: no database. The rule is the whole safety argument for letting the
reconciler touch an existing column at all, so each side of it is pinned.
"""
from __future__ import annotations

import pytest
from sqlalchemy import Enum, Integer, String, Text
from sqlalchemy.dialects.postgresql import JSONB, VARCHAR

from veyrs.cli import _widened_type


@pytest.mark.parametrize("live,model,expected", [
    (VARCHAR(1000), Text(), "TEXT"),
    (VARCHAR(100), String(), "TEXT"),           # unbounded model
    (VARCHAR(100), String(200), "VARCHAR(200)"),
])
def test_widens(live, model, expected):
    target = _widened_type(live, model)
    assert target is not None
    assert str(target.compile()) == expected


@pytest.mark.parametrize("live,model", [
    (VARCHAR(200), String(100)),     # narrowing loses data
    (VARCHAR(200), String(200)),     # already right
    (Text(), String(100)),           # TEXT -> VARCHAR is narrowing
    (Text(), Text()),
    (VARCHAR(), Text()),             # already unbounded
    (VARCHAR(20), Integer()),        # different family
    (VARCHAR(20), JSONB()),
    (VARCHAR(20), Enum("a", "b", name="x")),
    (Integer(), Text()),
])
def test_leaves_alone(live, model):
    assert _widened_type(live, model) is None
