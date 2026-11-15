"""One record the database refuses must not stop the NVD feed (0.32.5).

Production's NVD pull failed on every run that reached a single reference URL
longer than `cve_references.url` VARCHAR(1000): the whole page rolled back, the
watermark never moved, and the next run reached the same record again. Two
fixes, and each gets a test:

* the column is TEXT, and `init-db` widens it on an existing install;
* a live pull writes each record inside its own SAVEPOINT, so a record the
  database still refuses is rolled back alone, named in the run, and the
  command exits non-zero instead of green.

The upload path (`ingest_nvd`) keeps its all-or-nothing contract, and that is
tested too, because isolating records there would be the wrong fix.
"""
from __future__ import annotations

import copy
import random

import pytest
from sqlalchemy import Text, inspect, select, text
from sqlalchemy.exc import DBAPIError

from veyrs import cli
from veyrs.db import SessionLocal, engine
from veyrs.intel import feeds
from veyrs.models import Cve, CveReference, FeedRun
from veyrs.services import intelligence

from test_phase3_intel import NVD_ITEM


def _item(*, url_len: int | None = None, version_len: int | None = None) -> dict:
    """A copy of the phase 3 advisory under a fresh id, optionally oversized."""
    item = copy.deepcopy(NVD_ITEM)
    cve_id = f"CVE-2099-{random.randint(10_000_000, 99_999_999)}"
    item["cve"]["id"] = cve_id
    # A product no inventory holds. Left as FortiWeb, these records correlate
    # against the phase 3 fixtures and double their findings.
    match = item["cve"]["configurations"][0]["nodes"][0]["cpeMatch"][0]
    match["criteria"] = "cpe:2.3:a:veyrs_test:nvd_rejects:*:*:*:*:*:*:*:*"
    if url_len is not None:
        base = "https://bugzilla.example.com/buglist.cgi?bug_id="
        item["cve"]["references"][0]["url"] = base + "9" * (url_len - len(base))
    if version_len is not None:
        # cve_cpe_match.version_end_excluding is VARCHAR(120): still bounded,
        # so it is the reliable way to make the database refuse one record.
        match["versionEndExcluding"] = "7." + "1" * version_len
    return item


def _last_nvd_run(session) -> FeedRun:  # noqa: ANN001
    return session.execute(
        select(FeedRun).where(FeedRun.feed == "nvd").order_by(FeedRun.started_at.desc())
    ).scalars().first()


def test_a_reference_url_over_1000_characters_is_stored():
    item = _item(url_len=1500)
    cve_id = item["cve"]["id"]
    with SessionLocal() as session:
        stats = intelligence.ingest_nvd_pages(session, [[item]])
        session.commit()
    assert stats["created"] == 1 and stats["rejected"] == 0
    with SessionLocal() as session:
        urls = session.execute(
            select(CveReference.url).where(CveReference.cve_id == cve_id)
        ).scalars().all()
    assert max(len(u) for u in urls) == 1500


def test_a_live_pull_rolls_back_only_the_refused_record():
    good_a, bad, good_b = _item(), _item(version_len=200), _item()
    rejects: list[dict] = []
    with SessionLocal() as session:
        stats = intelligence.ingest_nvd_pages(
            session, [[good_a, bad], [good_b]], rejects=rejects
        )
        session.commit()
    assert stats == {"seen": 3, "created": 2, "updated": 0, "skipped": 0, "rejected": 1}
    assert [r["id"] for r in rejects] == [bad["cve"]["id"]]
    assert "StringDataRightTruncation" in rejects[0]["error"]

    with SessionLocal() as session:
        assert session.get(Cve, good_a["cve"]["id"]) is not None
        assert session.get(Cve, good_b["cve"]["id"]) is not None
        # the savepoint took the parent row with it, not just the child
        assert session.get(Cve, bad["cve"]["id"]) is None
        run = _last_nvd_run(session)
        assert run.status == "succeeded"
        assert run.details["rejected"] == 1
        assert run.details["rejected_records"][0]["id"] == bad["cve"]["id"]


def test_the_upload_path_stays_all_or_nothing():
    good, bad = _item(), _item(version_len=200)
    with SessionLocal() as session:
        with pytest.raises(DBAPIError):
            intelligence.ingest_nvd(session, [good, bad])
        session.rollback()
    with SessionLocal() as session:
        assert session.get(Cve, good["cve"]["id"]) is None


def test_sync_nvd_exits_non_zero_when_a_record_was_rejected(monkeypatch, capsys):
    bad, good = _item(version_len=200), _item()

    class _Client:
        def close(self) -> None:
            pass

    monkeypatch.setattr(feeds, "http_client", lambda: _Client())
    monkeypatch.setattr(feeds, "iter_nvd_pages", lambda *a, **k: iter([[bad, good]]))
    assert feeds.run_cli("sync-nvd", correlate=False) == 3
    out = capsys.readouterr().out
    assert "1 records REJECTED" in out
    assert bad["cve"]["id"] in out

    monkeypatch.setattr(feeds, "iter_nvd_pages", lambda *a, **k: iter([[_item()]]))
    assert feeds.run_cli("sync-nvd", correlate=False) == 0


def test_init_db_widens_the_url_column_on_an_existing_install():
    # Put the column back the way 0.32.4 shipped it. The long URL another test
    # stored would not fit, which is the point of the change.
    with engine.begin() as conn:
        conn.execute(text("DELETE FROM cve_references WHERE length(url) > 1000"))
        conn.execute(text(
            "ALTER TABLE cve_references ALTER COLUMN url TYPE VARCHAR(1000)"
        ))
    stats = cli.sync_columns(verbose=False)
    assert stats["widened"] >= 1
    url = next(c for c in inspect(engine).get_columns("cve_references")
               if c["name"] == "url")
    assert isinstance(url["type"], Text), url["type"]
    # and a second run has nothing left to do
    assert cli.sync_columns(verbose=False)["widened"] == 0
