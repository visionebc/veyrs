"""EPSS history retention (0.33.2).

`epss_history` keeps one row per CVE per scored day -- about 370,000 rows and
80 MB a day on a full corpus -- and until 0.33.2 nothing ever deleted one: the
reference database reached 2 GB of it in 27 scored days, on course for ~30 GB
a year whatever the size of the estate. Only ~1.4% of rows repeat the previous
day's value, so storing changes only would not have helped; a retention window
is the lever.

The window counts back from the NEWEST snapshot, never from today: a feed that
has been failing for a month must not also erase the history it cannot replace.
"""
from __future__ import annotations

import datetime as dt
import uuid

import pytest
from sqlalchemy import delete, select

from veyrs import cli
from veyrs.db import SessionLocal
from veyrs.models import Cve, EpssHistory
from veyrs.services import intelligence

# Far-future days: the cutoff is global (the newest snapshot in the table), so
# the test's own newest day has to be the newest one in the database.
NEWEST = dt.date(2099, 6, 30)


@pytest.fixture()
def history():
    cves = [f"CVE-2099-{uuid.uuid4().int % 10**7:07d}" for _ in range(2)]
    days = [NEWEST - dt.timedelta(days=n) for n in (0, 1, 30, 31, 400)]
    with SessionLocal() as session:
        for cve_id in cves:
            session.add(Cve(id=cve_id, description="retention fixture"))
        session.flush()
        for cve_id in cves:
            for day in days:
                session.add(EpssHistory(cve_id=cve_id, score=0.1, percentile=0.5,
                                        scored_on=day))
        session.commit()
    yield cves
    with SessionLocal() as session:
        session.execute(delete(EpssHistory).where(EpssHistory.cve_id.in_(cves)))
        session.execute(delete(Cve).where(Cve.id.in_(cves)))
        session.commit()


def _days(session, cves):
    return sorted({d for (d,) in session.execute(
        select(EpssHistory.scored_on).where(EpssHistory.cve_id.in_(cves)))})


def test_the_window_counts_back_from_the_newest_snapshot(history):
    with SessionLocal() as session:
        out = intelligence.prune_epss_history(session, 30)
        session.commit()
        assert out["cutoff"] == (NEWEST - dt.timedelta(days=30)).isoformat()
        # 30 days back from the newest is kept; 31 and 400 are gone.
        assert _days(session, history) == [NEWEST - dt.timedelta(days=30),
                                           NEWEST - dt.timedelta(days=1), NEWEST]
        assert out["rows"] >= 4 and out["days"] >= 2


def test_zero_keeps_everything(history):
    with SessionLocal() as session:
        out = intelligence.prune_epss_history(session, 0)
        session.commit()
        assert out == {"keep_days": 0, "cutoff": None, "days": 0, "rows": 0,
                       "dry_run": False}
        assert len(_days(session, history)) == 5


def test_a_dry_run_counts_and_deletes_nothing(history):
    with SessionLocal() as session:
        out = intelligence.prune_epss_history(session, 30, dry_run=True)
        session.commit()
        assert out["rows"] >= 4
        assert len(_days(session, history)) == 5


def test_a_stale_feed_does_not_erase_its_own_history(history):
    # Nothing newer than NEWEST arrives for a long time: re-running the prune,
    # as every retried tick would, must remove nothing more.
    with SessionLocal() as session:
        intelligence.prune_epss_history(session, 30, commit_between_days=True)
        again = intelligence.prune_epss_history(session, 30, commit_between_days=True)
        assert again["rows"] == 0
        assert len(_days(session, history)) == 3


def test_the_default_retention_is_a_year():
    from veyrs.config import Settings
    assert Settings.model_fields["epss_history_days"].default == 365


def test_the_cli_dry_run_reports_and_keeps_rows(history, capsys):
    assert cli.main(["prune-epss-history", "--days", "30", "--dry-run"]) == 0
    printed = capsys.readouterr().out
    assert "would delete" in printed
    assert (NEWEST - dt.timedelta(days=30)).isoformat() in printed
    with SessionLocal() as session:
        assert len(_days(session, history)) == 5


def test_the_cli_refuses_a_negative_retention():
    assert cli.main(["prune-epss-history", "--days", "-1"]) == 2


def test_the_feed_prunes_after_it_ingests(monkeypatch, history):
    # sync_epss must land the new day BEFORE pruning: the window is measured
    # from the newest snapshot, so the order decides which day falls out.
    from veyrs.intel import feeds

    newer = NEWEST + dt.timedelta(days=1)
    monkeypatch.setattr(feeds, "fetch_epss", lambda: (
        [{"cve": history[0], "epss": "0.2", "percentile": "0.6"}], newer, "v-test"))
    monkeypatch.setattr(feeds.settings, "epss_history_days", 30)
    with SessionLocal() as session:
        out = feeds.sync_epss(session, correlate=False)
        assert out["history"]["cutoff"] == (newer - dt.timedelta(days=30)).isoformat()
        # NEWEST-30 is now 31 days before the newest snapshot: gone.
        assert _days(session, history) == [NEWEST - dt.timedelta(days=1), NEWEST, newer]
        session.execute(delete(EpssHistory).where(EpssHistory.scored_on == newer))
        session.commit()
