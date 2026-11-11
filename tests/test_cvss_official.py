"""Validate the VEYRS CVSS_ENGINE against official / reference expected scores.

The fixtures are the vector corpora published with the FIRST-conformant
reference implementation (RedHatProductSecurity/cvss test suite): 4379 vectors
in total, each line `<vector> - (<expected...>)`. We assert exact equality on
every one - a CVSS engine that is "close" is a broken CVSS engine.
"""
from __future__ import annotations

import ast
import pathlib

import pytest

from veyrs.engines import cvss

FIXTURES = pathlib.Path(__file__).parent / "fixtures"


def _load(name: str) -> list[tuple[str, tuple]]:
    rows = []
    for line in (FIXTURES / name).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        vector, _, expected = line.rpartition(" - ")
        rows.append((vector.strip(), ast.literal_eval(expected.strip())))
    return rows


V2 = _load("cvss_official_v2.txt")
V3 = _load("cvss_official_v3.txt")
V4 = _load("cvss_official_v4.txt")


def test_corpora_loaded():
    assert len(V2) > 700 and len(V3) > 2500 and len(V4) > 1000


@pytest.mark.parametrize("vector,expected", V2, ids=[v for v, _ in V2])
def test_v2_official(vector, expected):
    r = cvss.score(vector, "2.0")
    base, temporal, env = (list(expected) + [None, None])[:3]
    # the reference suite emits -0.0 for a 0.0 base
    assert r.base_score == pytest.approx(abs(base)), f"{vector}: base"
    if temporal is not None:
        assert r.temporal_score == pytest.approx(abs(temporal)), f"{vector}: temporal"
    if env is not None:
        assert r.environmental_score == pytest.approx(abs(env)), f"{vector}: env"


@pytest.mark.parametrize("vector,expected", V3, ids=[v for v, _ in V3])
def test_v3_official(vector, expected):
    r = cvss.score(vector)
    base, temporal, env = (list(expected) + [None, None])[:3]
    assert r.base_score == pytest.approx(base), f"{vector}: base"
    if temporal is not None:
        assert r.temporal_score == pytest.approx(temporal), f"{vector}: temporal"
    if env is not None:
        assert r.environmental_score == pytest.approx(env), f"{vector}: env"


@pytest.mark.parametrize("vector,expected", V4, ids=[v for v, _ in V4])
def test_v4_official(vector, expected):
    r = cvss.score(vector, "4.0")
    assert r.score == pytest.approx(expected[0]), f"{vector}"


def test_v4_extremes():
    worst = "CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:H/SI:H/SA:H"
    best = "CVSS:4.0/AV:P/AC:H/AT:P/PR:H/UI:A/VC:N/VI:N/VA:N/SC:N/SI:N/SA:N"
    assert cvss.score(worst).score == 10.0
    assert cvss.score(best).score == 0.0


def test_facade_helpers():
    v = "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
    assert cvss.detect_version(v) == "3.1"
    ok, err = cvss.validate(v)
    assert ok and err is None
    bad_ok, bad_err = cvss.validate("CVSS:3.1/AV:Z/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H")
    assert not bad_ok and bad_err
    exp = cvss.explain(v)
    assert exp["score"] == 9.8 and exp["drivers"]
    gen = cvss.generate(
        {"AV": "N", "AC": "L", "PR": "N", "UI": "N", "S": "U", "C": "H", "I": "H", "A": "H"},
        "3.1",
    )
    assert gen == v
    cmp = cvss.compare([v, "CVSS:2.0/AV:N/AC:L/Au:N/C:C/I:C/A:C"])
    assert cmp["max_score"] == 10.0
