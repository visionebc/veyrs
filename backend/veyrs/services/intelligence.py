"""Ingestion of global threat intelligence: NVD/CVE, EPSS, CISA KEV.

Design notes worth keeping in mind when extending this module:

* These tables are **global**, not tenant-scoped. A CVE is the same fact for
  every organisation; only the *findings* derived from it are tenant data. That
  is why nothing here takes an `organization_id`.
* Every importer is idempotent and runs inside a `FeedRun`, which doubles as the
  watermark store and the audit record. Re-running a feed must never duplicate
  rows -- vulnerability management tools live or die on stable identity.
* Parsers accept already-decoded Python objects rather than doing HTTP
  themselves. Fetching lives in `services/feeds.py`, so the parsing logic is
  testable offline against fixture payloads and an air-gapped install can feed
  the same functions from a file drop.
"""
from __future__ import annotations

import datetime as dt
import uuid
from contextlib import contextmanager
from typing import Any, Iterable, Iterator

from sqlalchemy import func, select, update
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.orm import Session

from ..models import (
    AssetProduct, Cpe, Cve, CveCpeMatch, CveReference, Cwe, EpssHistory, EpssScore,
    FeedRun, Finding, KevEntry, OPEN_STATES, Product, ProductVersion, Vendor,
    Vulnerability,
)
from .versions import normalize_name, parse_cpe23, version_key

# --------------------------------------------------------------------------
# Feed run bookkeeping
# --------------------------------------------------------------------------


@contextmanager
def feed_run(session: Session, feed: str, *, watermark: str | None = None) -> Iterator[FeedRun]:
    """Open a FeedRun, mark it succeeded/failed, and always close it.

    A crashed importer leaving a run stuck in `running` forever would make the
    "when did intelligence last update" indicator lie, so failure is recorded
    explicitly and the exception is re-raised.
    """
    run = FeedRun(feed=feed, status="running", watermark=watermark)
    session.add(run)
    session.flush()
    try:
        yield run
    except Exception as exc:  # noqa: BLE001 - recorded then re-raised
        run.status = "failed"
        run.error = f"{type(exc).__name__}: {exc}"[:2000]
        run.finished_at = dt.datetime.now(dt.timezone.utc)
        session.flush()
        raise
    else:
        run.status = "succeeded"
        run.finished_at = dt.datetime.now(dt.timezone.utc)
        session.flush()


def last_successful_run(session: Session, feed: str) -> FeedRun | None:
    return session.execute(
        select(FeedRun)
        .where(FeedRun.feed == feed, FeedRun.status == "succeeded")
        .order_by(FeedRun.started_at.desc())
        .limit(1)
    ).scalars().first()


# --------------------------------------------------------------------------
# Vendor / product registry
# --------------------------------------------------------------------------


def upsert_vendor(session: Session, name: str, **fields: Any) -> Vendor:
    key = normalize_name(name)
    vendor = session.execute(
        select(Vendor).where(Vendor.normalized_name == key)
    ).scalars().first()
    if vendor is None:
        vendor = Vendor(name=name, normalized_name=key, **fields)
        session.add(vendor)
        session.flush()
    else:
        for attr, value in fields.items():
            if value is not None and getattr(vendor, attr, None) in (None, ""):
                setattr(vendor, attr, value)
    return vendor


def upsert_product(
    session: Session, vendor_name: str, product_name: str, *, cpe_part: str = "a", **fields: Any
) -> Product:
    vendor = upsert_vendor(session, vendor_name)
    key = normalize_name(product_name)
    product = session.execute(
        select(Product).where(
            Product.vendor_id == vendor.id, Product.normalized_name == key
        )
    ).scalars().first()
    if product is None:
        product = Product(
            vendor_id=vendor.id, name=product_name, normalized_name=key,
            cpe_part=cpe_part,
            product_type=fields.pop("product_type", _product_type_for(cpe_part)),
            **fields,
        )
        session.add(product)
        session.flush()
    return product


def _product_type_for(cpe_part: str) -> str:
    return {"o": "operating_system", "h": "hardware"}.get(cpe_part, "application")


def upsert_product_version(session: Session, product: Product, version: str) -> ProductVersion:
    row = session.execute(
        select(ProductVersion).where(
            ProductVersion.product_id == product.id, ProductVersion.version == version
        )
    ).scalars().first()
    if row is None:
        row = ProductVersion(
            product_id=product.id, version=version, version_key=version_key(version)
        )
        session.add(row)
        session.flush()
    return row


def upsert_cpe(session: Session, cpe23: str) -> Cpe | None:
    """Register a CPE string and link it to the product registry."""
    parts = parse_cpe23(cpe23)
    if parts is None:
        return None
    row = session.execute(select(Cpe).where(Cpe.cpe23 == cpe23)).scalars().first()
    if row is not None:
        return row
    product = None
    if parts["vendor"] not in ("*", "-") and parts["product"] not in ("*", "-"):
        product = upsert_product(
            session,
            parts["vendor"].replace("_", " "),
            parts["product"].replace("_", " "),
            cpe_part=parts["part"],
        )
    row = Cpe(
        cpe23=cpe23, part=parts["part"], vendor=parts["vendor"], product=parts["product"],
        version=parts["version"], update_field=parts["update"], edition=parts["edition"],
        language=parts["language"], sw_edition=parts["sw_edition"],
        target_sw=parts["target_sw"], target_hw=parts["target_hw"], other=parts["other"],
        product_id=product.id if product else None,
    )
    session.add(row)
    session.flush()
    return row


# --------------------------------------------------------------------------
# NVD 2.0 CVE parsing
# --------------------------------------------------------------------------

_SEVERITY_FROM_SCORE = [
    (9.0, "critical"), (7.0, "high"), (4.0, "medium"), (0.1, "low"),
]


def severity_for_score(score: float | None) -> str | None:
    if score is None:
        return None
    for threshold, label in _SEVERITY_FROM_SCORE:
        if score >= threshold:
            return label
    return "none"


def _pick_metric(metrics: dict, keys: tuple[str, ...]) -> dict | None:
    """Prefer the NVD's own (Primary) assessment over a CNA's self-scoring."""
    for key in keys:
        entries = metrics.get(key) or []
        primary = [e for e in entries if e.get("type") == "Primary"]
        chosen = primary[0] if primary else (entries[0] if entries else None)
        if chosen:
            return chosen
    return None


def parse_nvd_cve(item: dict) -> dict:
    """Normalise one NVD 2.0 `vulnerabilities[].cve` record into our shape."""
    cve = item.get("cve", item)
    cve_id = cve.get("id")
    descriptions = cve.get("descriptions") or []
    english = next(
        (d.get("value") for d in descriptions if d.get("lang") == "en"),
        (descriptions[0].get("value") if descriptions else None),
    )

    metrics = cve.get("metrics") or {}
    payload: dict[str, Any] = {
        "id": cve_id,
        "source": "nvd",
        "state": cve.get("vulnStatus") or "PUBLISHED",
        "description": english,
        "published_at": _parse_dt(cve.get("published")),
        "modified_at": _parse_dt(cve.get("lastModified")),
        "raw": cve,
    }

    v40 = _pick_metric(metrics, ("cvssMetricV40",))
    # v3.1 and v3.0 share one column pair; the newer revision wins when both exist.
    v3 = _pick_metric(metrics, ("cvssMetricV31", "cvssMetricV30"))
    v2 = _pick_metric(metrics, ("cvssMetricV2",))

    if v2:
        data = v2.get("cvssData") or {}
        payload["cvss2_vector"] = data.get("vectorString")
        payload["cvss2_base_score"] = data.get("baseScore")
    if v3:
        data = v3.get("cvssData") or {}
        payload["cvss3_vector"] = data.get("vectorString")
        payload["cvss3_base_score"] = data.get("baseScore")
        payload["cvss3_version"] = str(data.get("version") or "3.1")
        severity = data.get("baseSeverity") or severity_for_score(data.get("baseScore"))
        payload["cvss3_severity"] = severity.lower() if severity else None
    if v40:
        data = v40.get("cvssData") or {}
        payload["cvss4_vector"] = data.get("vectorString")
        payload["cvss4_score"] = data.get("baseScore")
        severity = data.get("baseSeverity") or severity_for_score(data.get("baseScore"))
        payload["cvss4_severity"] = severity.lower() if severity else None

    payload["cwe_ids"] = sorted({
        desc.get("value")
        for weakness in (cve.get("weaknesses") or [])
        for desc in (weakness.get("description") or [])
        if str(desc.get("value", "")).startswith("CWE-")
    })

    payload["references"] = [
        {"url": ref.get("url"), "source": ref.get("source"), "tags": ref.get("tags") or []}
        for ref in (cve.get("references") or []) if ref.get("url")
    ]
    payload["exploit_known"] = any(
        "exploit" in (tag or "").lower()
        for ref in payload["references"] for tag in ref["tags"]
    )

    payload["cpe_matches"] = list(_iter_cpe_matches(cve.get("configurations") or []))
    payload["affected"] = sorted({
        f"{m['parsed']['vendor']}:{m['parsed']['product']}"
        for m in payload["cpe_matches"] if m.get("parsed")
    })
    return payload


def _iter_cpe_matches(configurations: list) -> Iterator[dict]:
    for config in configurations:
        for node in config.get("nodes") or []:
            for match in node.get("cpeMatch") or []:
                criteria = match.get("criteria")
                if not criteria:
                    continue
                yield {
                    "cpe23": criteria,
                    "parsed": parse_cpe23(criteria),
                    "vulnerable": bool(match.get("vulnerable", True)),
                    "version_start_including": match.get("versionStartIncluding"),
                    "version_start_excluding": match.get("versionStartExcluding"),
                    "version_end_including": match.get("versionEndIncluding"),
                    "version_end_excluding": match.get("versionEndExcluding"),
                }


def _parse_dt(value: str | None) -> dt.datetime | None:
    if not value:
        return None
    text = value.replace("Z", "+00:00")
    try:
        parsed = dt.datetime.fromisoformat(text)
    except ValueError:
        return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def upsert_cve(session: Session, payload: dict) -> tuple[Cve, bool]:
    """Insert or update one normalised CVE. Returns (row, created)."""
    cve_id = payload["id"]
    now = dt.datetime.now(dt.timezone.utc)
    row = session.get(Cve, cve_id)
    created = row is None
    if created:
        row = Cve(id=cve_id, first_seen_at=now)
        session.add(row)

    simple = (
        "source", "state", "title", "description", "published_at", "modified_at",
        "cvss2_vector", "cvss2_base_score",
        "cvss3_vector", "cvss3_base_score", "cvss3_severity", "cvss3_version",
        "cvss4_vector", "cvss4_score", "cvss4_severity", "cvss4_nomenclature",
        "cwe_ids", "affected", "fixed_versions", "exploit_known", "exploit_maturity",
        "exploit_references", "raw",
    )
    for field in simple:
        if field in payload and payload[field] is not None:
            if hasattr(row, field):
                setattr(row, field, payload[field])
    row.last_seen_at = now

    for cwe_id in payload.get("cwe_ids") or []:
        if session.get(Cwe, cwe_id) is None:
            # An NVD record carries the identifier and no name, so this is a
            # placeholder: `name == id` is the invariant `Cwe.resolved` reads,
            # and `ingest_cwe` is what clears it.
            session.add(Cwe(id=cwe_id, name=cwe_id))
    session.flush()

    if payload.get("references"):
        _replace_children(
            session, CveReference, CveReference.cve_id == cve_id,
            [CveReference(cve_id=cve_id, url=r["url"], source=r.get("source"),
                          tags=r.get("tags") or []) for r in payload["references"]],
        )

    if payload.get("cpe_matches"):
        rows = []
        for match in payload["cpe_matches"]:
            cpe_row = upsert_cpe(session, match["cpe23"])
            rows.append(CveCpeMatch(
                cve_id=cve_id, cpe23=match["cpe23"],
                product_id=cpe_row.product_id if cpe_row else None,
                vulnerable=match.get("vulnerable", True),
                version_start_including=match.get("version_start_including"),
                version_start_excluding=match.get("version_start_excluding"),
                version_end_including=match.get("version_end_including"),
                version_end_excluding=match.get("version_end_excluding"),
            ))
        _replace_children(session, CveCpeMatch, CveCpeMatch.cve_id == cve_id, rows)

    session.flush()
    return row, created


def _replace_children(session: Session, model: Any, where: Any, rows: list) -> None:
    """Replace a CVE's child rows wholesale.

    NVD rewrites the full reference/configuration list on every revision, so a
    merge would leave withdrawn entries behind forever.
    """
    session.query(model).filter(where).delete(synchronize_session=False)
    for row in rows:
        session.add(row)
    session.flush()


def ingest_nvd_pages(
    session: Session,
    pages: Iterable[Iterable[dict]],
    *,
    watermark: str | None = None,
    collect: list[str] | None = None,
    commit_between_pages: bool = True,
) -> dict[str, int]:
    """Ingest NVD 2.0 `vulnerabilities[]` entries, one fetched page at a time.

    The page boundary is the only safe place to commit during a live pull, and
    committing there is not an optimisation -- it is a correctness requirement.
    `db._harden_connection` sets `idle_in_transaction_session_timeout = 60s` on
    every connection (a good guard for a web API), while the fetcher sleeps for
    NVD's rate limit and backs off over its 403s between pages. A transaction
    held open across that wait is terminated by the server, and a full backfill
    dies somewhere in the middle with a `PendingRollbackError` cascade that
    hides the real cause. Committing per page leaves the connection idle
    *outside* a transaction while the network work happens.

    It also bounds memory: `expunge_all()` drops the identity map, which would
    otherwise accumulate every one of NVD's ~290k CVEs plus their references.

    `collect`, when supplied, receives the id of every CVE touched, so the
    caller can correlate exactly those against tenant inventories. It is an
    out-parameter rather than part of the return value because the return value
    is serialised into the HTTP response and an EPSS-sized list has no business
    being there.
    """
    stats = {"seen": 0, "created": 0, "updated": 0, "skipped": 0}

    def _stamp(run: FeedRun) -> None:
        run.records_seen = stats["seen"]
        run.records_created = stats["created"]
        run.records_updated = stats["updated"]
        run.details = dict(stats)

    with feed_run(session, "nvd", watermark=watermark) as run:
        if commit_between_pages:
            # `feed_run` flushes the run row, which OPENS a transaction -- and
            # the very next thing that happens is the first page fetch, which
            # for 2000 NVD records routinely takes longer than the 60s
            # idle-in-transaction guard. Land the run row and go idle before
            # touching the network. This exact ordering killed a backfill on
            # its first page.
            session.commit()
        for page in pages:
            for item in page:
                payload = parse_nvd_cve(item)
                if not payload.get("id"):
                    stats["skipped"] += 1
                    continue
                stats["seen"] += 1
                _, created = upsert_cve(session, payload)
                stats["created" if created else "updated"] += 1
                if collect is not None:
                    collect.append(payload["id"])
            _stamp(run)
            if commit_between_pages:
                session.commit()
                # Detaches everything, `run` included; re-add it so the context
                # manager can still stamp the terminal status on the same row.
                session.expunge_all()
                session.add(run)
        _stamp(run)
    return stats


def ingest_nvd(
    session: Session,
    items: Iterable[dict],
    *,
    watermark: str | None = None,
    collect: list[str] | None = None,
) -> dict[str, int]:
    """Ingest one batch of NVD records atomically.

    This is the path a caller uses when it already holds the records: an
    operator upload, a test, a replayed file. It is a single page and therefore
    a single transaction -- a half-applied upload is worse than a rejected one.
    Live pulls use `ingest_nvd_pages`, which trades that atomicity for the
    ability to survive a multi-hour fetch.
    """
    return ingest_nvd_pages(
        session, [list(items)], watermark=watermark, collect=collect,
        commit_between_pages=False,
    )


# --------------------------------------------------------------------------
# EPSS
# --------------------------------------------------------------------------


#: Rows per EPSS batch. FIRST publishes ~290k rows daily and the whole file
#: is one logical unit, so the batch size is the only thing standing between
#: this import and the machine.
EPSS_BATCH = 5000


def _batched(rows: Iterable[dict], size: int) -> Iterator[list[dict]]:
    """Yield fixed-size batches from an arbitrary iterable of rows."""
    batch: list[dict] = []
    for row in rows:
        batch.append(row)
        if len(batch) >= size:
            yield batch
            batch = []
    if batch:
        yield batch


def ingest_epss(
    session: Session,
    rows: Iterable[dict],
    *,
    scored_on: dt.date | None = None,
    model_version: str | None = None,
    collect: list[str] | None = None,
    commit_between_batches: bool = False,
) -> dict[str, int]:
    """Ingest EPSS rows (`{cve, epss, percentile}`) from FIRST's daily CSV.

    Unknown CVEs are skipped rather than auto-created: EPSS covers ~250k CVEs
    and materialising all of them would bloat the CVE table with records that
    carry no description, no CPE and therefore no way to match an asset.

    Set-based on purpose, and this is the important part. The obvious ORM shape
    -- `session.get(Cve, id)` per row, then mutate -- is O(corpus) in resident
    memory: every instance it loads stays in the identity map until the
    transaction ends, three per row (`Cve` + `EpssScore` + `EpssHistory`), and
    `Cve` carries a description. At EPSS's real size that is not a slow import,
    it is a dead one -- it OOM-killed the nightly sync three nights running
    (2026-08-14..16) and, because systemd's default `OOMPolicy` stops the whole
    unit, took `sync-kev` down with it every time.

    So nothing here loads an ORM instance: existence is a set of ids, writes are
    `ON CONFLICT` upserts, and the denormalised columns on `cve` are refreshed
    *from `epss_scores` itself* rather than from the payload, so the two cannot
    drift apart after a partial batch.

    `commit_between_batches` trades atomicity for a bounded transaction, exactly
    as `ingest_nvd_pages` does, and for the same reason. It is off by default: a
    caller that already holds every row (an operator upload, a test) wants
    all-or-nothing.
    """
    scored_on = scored_on or dt.date.today()
    stats = {"seen": 0, "created": 0, "updated": 0, "skipped": 0}
    with feed_run(session, "epss", watermark=scored_on.isoformat()) as run:
        if commit_between_batches:
            # `feed_run` opened a transaction on its flush. Land the run row now
            # so it is visible for the whole import rather than only at the end.
            session.commit()
            session.expunge_all()
            session.add(run)
        for batch in _batched(rows, EPSS_BATCH):
            # Deduplicate inside the batch: `ON CONFLICT` cannot touch the same
            # row twice in one statement, and a feed is allowed to repeat an id.
            candidates: dict[str, dict] = {}
            for row in batch:
                cve_id = (row.get("cve") or row.get("cve_id") or "").strip().upper()
                if not cve_id:
                    continue
                stats["seen"] += 1
                candidates[cve_id] = row
            if not candidates:
                continue

            ids = list(candidates)
            known = set(session.execute(
                select(Cve.id).where(Cve.id.in_(ids))
            ).scalars())
            already_scored = set(session.execute(
                select(EpssScore.cve_id).where(EpssScore.cve_id.in_(ids))
            ).scalars())

            payload: list[dict[str, Any]] = []
            for cve_id, row in candidates.items():
                if cve_id not in known:
                    stats["skipped"] += 1
                    continue
                try:
                    score = float(row.get("epss"))
                    percentile = float(row.get("percentile"))
                except (TypeError, ValueError):
                    stats["skipped"] += 1
                    continue
                payload.append(
                    {"cve_id": cve_id, "score": score, "percentile": percentile}
                )
                stats["updated" if cve_id in already_scored else "created"] += 1
            if not payload:
                continue

            now = dt.datetime.now(dt.timezone.utc)
            current = pg_insert(EpssScore).values([
                {**item, "scored_on": scored_on,
                 "model_version": model_version, "updated_at": now}
                for item in payload
            ])
            session.execute(current.on_conflict_do_update(
                index_elements=[EpssScore.__table__.c.cve_id],
                set_={
                    "score": current.excluded.score,
                    "percentile": current.excluded.percentile,
                    "scored_on": current.excluded.scored_on,
                    # An unversioned file must not erase a version we already
                    # know -- the original `model_version or current.model_version`.
                    "model_version": func.coalesce(
                        current.excluded.model_version,
                        EpssScore.__table__.c.model_version,
                    ),
                    "updated_at": current.excluded.updated_at,
                },
            ))

            history = pg_insert(EpssHistory).values([
                {"id": uuid.uuid4(), "scored_on": scored_on, **item}
                for item in payload
            ])
            session.execute(history.on_conflict_do_update(
                index_elements=[EpssHistory.__table__.c.cve_id,
                                EpssHistory.__table__.c.scored_on],
                set_={"score": history.excluded.score,
                      "percentile": history.excluded.percentile},
            ))

            written = [item["cve_id"] for item in payload]
            session.execute(
                update(Cve)
                .where(Cve.id == EpssScore.cve_id, Cve.id.in_(written))
                .values(epss_score=EpssScore.score,
                        epss_percentile=EpssScore.percentile)
                .execution_options(synchronize_session=False)
            )

            if collect is not None:
                collect.extend(written)
            if commit_between_batches:
                session.commit()
                # Detaches everything, `run` included; re-add it so the context
                # manager can still stamp the terminal status on the same row.
                session.expunge_all()
                session.add(run)
            else:
                session.flush()

        run.records_seen = stats["seen"]
        run.records_created = stats["created"]
        run.records_updated = stats["updated"]
        run.details = dict(stats)
        session.flush()
    return stats


def epss_trend(session: Session, cve_id: str, days: int = 90) -> list[dict]:
    """Historical EPSS series for the trend chart the spec asks for."""
    since = dt.date.today() - dt.timedelta(days=days)
    rows = session.execute(
        select(EpssHistory)
        .where(EpssHistory.cve_id == cve_id, EpssHistory.scored_on >= since)
        .order_by(EpssHistory.scored_on)
    ).scalars().all()
    return [
        {"date": r.scored_on.isoformat(), "score": r.score, "percentile": r.percentile}
        for r in rows
    ]


# --------------------------------------------------------------------------
# CISA KEV
# --------------------------------------------------------------------------


def ingest_kev(
    session: Session, catalog: dict, *, collect: list[str] | None = None
) -> dict[str, int]:
    """Ingest the CISA Known Exploited Vulnerabilities catalogue.

    A KEV entry for a CVE we have never seen still creates a stub CVE row: KEV
    means *actively exploited in the wild*, and silently dropping it because NVD
    has not synced yet is the one failure mode this feed cannot have.
    """
    stats = {"seen": 0, "created": 0, "updated": 0, "cve_stubs": 0}
    version = catalog.get("catalogVersion")
    with feed_run(session, "kev", watermark=str(version) if version else None) as run:
        for item in catalog.get("vulnerabilities") or []:
            cve_id = (item.get("cveID") or "").strip().upper()
            if not cve_id:
                continue
            stats["seen"] += 1

            cve = session.get(Cve, cve_id)
            if cve is None:
                cve = Cve(
                    id=cve_id, source="cisa-kev",
                    title=item.get("vulnerabilityName"),
                    description=item.get("shortDescription"),
                    first_seen_at=dt.datetime.now(dt.timezone.utc),
                )
                session.add(cve)
                session.flush()
                stats["cve_stubs"] += 1

            entry = session.get(KevEntry, cve_id)
            fields = {
                "vendor_project": item.get("vendorProject"),
                "product": item.get("product"),
                "vulnerability_name": item.get("vulnerabilityName"),
                "short_description": item.get("shortDescription"),
                "required_action": item.get("requiredAction"),
                "date_added": _parse_date(item.get("dateAdded")),
                "due_date": _parse_date(item.get("dueDate")),
                "known_ransomware": str(
                    item.get("knownRansomwareCampaignUse") or ""
                ).strip().lower() == "known",
                "notes": item.get("notes"),
            }
            if entry is None:
                session.add(KevEntry(cve_id=cve_id, **fields))
                stats["created"] += 1
            else:
                for key, value in fields.items():
                    setattr(entry, key, value)
                entry.imported_at = dt.datetime.now(dt.timezone.utc)
                stats["updated"] += 1

            cve.kev = True
            cve.kev_due_date = fields["due_date"]
            cve.exploit_known = True
            if not cve.exploit_maturity:
                cve.exploit_maturity = "attacked"
            if collect is not None:
                collect.append(cve_id)
        session.flush()
        run.records_seen = stats["seen"]
        run.records_created = stats["created"]
        run.records_updated = stats["updated"]
        run.details = dict(stats)
    return stats


def ingest_cwe(
    session: Session, entries: list[dict], *, version: str | None = None
) -> dict[str, int]:
    """Ingest the MITRE CWE dictionary.

    Until this existed, `cwe` held one placeholder per identifier NVD happened
    to mention, with `name` set to the id — so "Top CWE" could only ever print
    `CWE-79` twice and call one of them a name.

    Placeholders are promoted **in place**, never replaced: they are referenced
    by id from `cve.cwe_ids`, so a delete/insert would churn the whole table to
    change a string.
    """
    stats = {"seen": 0, "created": 0, "updated": 0}
    with feed_run(session, "cwe", watermark=version) as run:
        for entry in entries:
            cwe_id = (entry.get("id") or "").strip().upper()
            name = (entry.get("name") or "").strip()
            if not cwe_id or not name:
                continue
            stats["seen"] += 1
            fields = {
                "name": name[:400],
                "description": entry.get("description") or None,
                "abstraction": (entry.get("abstraction") or None),
                "status": (entry.get("status") or None),
            }
            row = session.get(Cwe, cwe_id)
            if row is None:
                session.add(Cwe(id=cwe_id, **fields))
                stats["created"] += 1
            else:
                for key, value in fields.items():
                    setattr(row, key, value)
                stats["updated"] += 1
        session.flush()
        run.records_seen = stats["seen"]
        run.records_created = stats["created"]
        run.records_updated = stats["updated"]
        run.details = dict(stats)
    return stats


def _parse_date(value: str | None) -> dt.date | None:
    if not value:
        return None
    try:
        return dt.date.fromisoformat(str(value)[:10])
    except ValueError:
        return None


# --------------------------------------------------------------------------
# Read helpers used by the API layer
# --------------------------------------------------------------------------


def intelligence_snapshot(session: Session, cve_id: str) -> dict | None:
    """Everything the CVE detail page needs, in one call."""
    cve = session.get(Cve, cve_id)
    if cve is None:
        return None
    kev = session.get(KevEntry, cve_id)
    epss = session.get(EpssScore, cve_id)
    references = session.execute(
        select(CveReference).where(CveReference.cve_id == cve_id)
    ).scalars().all()
    matches = session.execute(
        select(CveCpeMatch).where(CveCpeMatch.cve_id == cve_id)
    ).scalars().all()
    return {
        "cve_id": cve.id,
        "state": cve.state,
        "title": cve.title,
        "description": cve.description,
        "published_at": cve.published_at.isoformat() if cve.published_at else None,
        "modified_at": cve.modified_at.isoformat() if cve.modified_at else None,
        "age_days": cve.age_days,
        "severity": (
            cve.cvss4_severity or cve.cvss3_severity
            or severity_for_score(cve.best_cvss_score)
        ),
        "cvss": {
            "score": cve.best_cvss_score,
            "vector": cve.cvss4_vector or cve.cvss3_vector or cve.cvss2_vector,
            "v2": {"score": cve.cvss2_base_score, "vector": cve.cvss2_vector},
            "v3": {"score": cve.cvss3_base_score, "vector": cve.cvss3_vector,
                   "version": cve.cvss3_version, "severity": cve.cvss3_severity},
            "v4": {"score": cve.cvss4_score, "vector": cve.cvss4_vector,
                   "severity": cve.cvss4_severity,
                   "nomenclature": cve.cvss4_nomenclature},
        },
        "epss": None if epss is None else {
            "score": epss.score, "percentile": epss.percentile,
            "scored_on": epss.scored_on.isoformat(), "model_version": epss.model_version,
        },
        "kev": None if kev is None else {
            "date_added": kev.date_added.isoformat() if kev.date_added else None,
            "due_date": kev.due_date.isoformat() if kev.due_date else None,
            "days_until_due": kev.days_until_due,
            "required_action": kev.required_action,
            "vendor_project": kev.vendor_project,
            "product": kev.product,
            "known_ransomware": kev.known_ransomware,
        },
        "cwe_ids": cve.cwe_ids,
        "exploit_known": cve.exploit_known,
        "exploit_maturity": cve.exploit_maturity,
        "references": [{"url": r.url, "source": r.source, "tags": r.tags} for r in references],
        "cpe_matches": [{
            "cpe23": m.cpe23, "vulnerable": m.vulnerable, "product_id": str(m.product_id)
            if m.product_id else None,
            "version_start_including": m.version_start_including,
            "version_start_excluding": m.version_start_excluding,
            "version_end_including": m.version_end_including,
            "version_end_excluding": m.version_end_excluding,
        } for m in matches],
    }


def kev_due_soon(session: Session, within_days: int = 14) -> list[KevEntry]:
    cutoff = dt.date.today() + dt.timedelta(days=within_days)
    return session.execute(
        select(KevEntry).where(KevEntry.due_date.is_not(None), KevEntry.due_date <= cutoff)
        .order_by(KevEntry.due_date)
    ).scalars().all()



# ---------------------------------------------------------------------------
# The estate lens
# ---------------------------------------------------------------------------
#
# The corpus stays global on purpose. `Cve`, `Vendor`, `Product` and
# `CveCpeMatch` carry no `organization_id` because correlation is computed FROM
# the dictionary: a CVE that was never ingested cannot fail to match an asset,
# it is simply absent -- and absence reads on screen as "you are not affected".
# Shrinking the corpus to "only what affects us" is circular and it fails
# silently, which is the worst failure mode this module has.
#
# What has to be tenant-shaped is the READING of it. Browsing 359 353 CVEs to
# reach the ~2 500 that name software you actually run is not intelligence, it
# is a search engine. These helpers are the ONLY definition of "touches this
# organization's estate"; the CVE list, the KEV list and the counters all call
# them, so the three cannot answer differently.
#
# The predicate is PRODUCT-level, not finding-level, and the difference is the
# whole design:
#   * product-level = software this organization runs is named in the CVE's
#     applicability. Includes versions you are not currently on.
#   * finding-level = we raised a finding against a specific asset. That is
#     already the Findings page, and it is a strictly smaller set.
# Browsing wants the first. A CVE for nginx 1.20 while you run 1.28 is still
# yours the day somebody rolls a host back.
#
# THE COST, stated plainly because it is a security trade and not a UI tweak:
# under this lens your INVENTORY becomes the boundary of what you can see. A
# package that never resolved to a CPE has no product id, so its CVEs are not
# "shown as unmatched" -- they are outside the filter entirely. That is why
# every caller also reports the catalogue total next to the estate total, and
# why `estate_product_ids` counts nulls separately: an estate view over an
# empty inventory must look empty, never clean.


def estate_product_ids(organization_id: uuid.UUID) -> Any:
    """SELECT of the distinct product ids this organization has installed."""
    return (
        select(AssetProduct.product_id)
        .where(
            AssetProduct.organization_id == organization_id,
            AssetProduct.product_id.is_not(None),
        )
        .distinct()
    )


def estate_cve_ids(organization_id: uuid.UUID) -> Any:
    """SELECT of the CVE ids whose applicability names software in the estate.

    Written as `id IN (SELECT ...)` and not as the more natural-reading
    `EXISTS (... WHERE m.cve_id = cve.id)`. Measured against production
    (359 353 CVEs, 3 096 014 match rows, 978 distinct installed products) the
    EXISTS form plans a semi-join over the CVE table and takes **1 079 ms**;
    this one drives off `ix_cve_cpe_product` and takes **16 ms**. Identical
    answer, 67x apart -- and the slow one would run on every page load, because
    it is what produces `total`.
    """
    return (
        select(CveCpeMatch.cve_id)
        .where(CveCpeMatch.product_id.in_(estate_product_ids(organization_id)))
        .distinct()
    )


def estate_cve_count(session: Session, organization_id: uuid.UUID) -> int:
    return session.execute(
        select(func.count()).select_from(estate_cve_ids(organization_id).subquery())
    ).scalar_one()


def estate_kev_count(session: Session, organization_id: uuid.UUID) -> int:
    return session.execute(
        select(func.count()).select_from(KevEntry).where(
            KevEntry.cve_id.in_(estate_cve_ids(organization_id))
        )
    ).scalar_one()


def estate_inventory_health(session: Session, organization_id: uuid.UUID) -> dict:
    """How much of the inventory can actually be correlated.

    Exists so the console can tell "nothing affects you" apart from "nothing in
    your inventory resolved to a dictionary entry". Under the estate lens those
    two produce the same empty table and mean opposite things.
    """
    total, resolved = session.execute(
        select(
            func.count(AssetProduct.id),
            func.count(AssetProduct.product_id),
        ).where(AssetProduct.organization_id == organization_id)
    ).one()
    distinct = session.execute(
        select(func.count()).select_from(estate_product_ids(organization_id).subquery())
    ).scalar_one()
    return {
        "installations": int(total or 0),
        "resolved": int(resolved or 0),
        "unresolved": int((total or 0) - (resolved or 0)),
        "distinct_products": int(distinct or 0),
    }


def affected_asset_counts(
    session: Session, organization_id: uuid.UUID, cve_ids: Iterable[str]
) -> dict[str, int]:
    """Open findings per CVE for this tenant, for the rows of a single page.

    Deliberately NOT folded into the list query as an outer join: a page is at
    most 200 rows, and keeping the aggregate off the main statement keeps it off
    the count that produces `total`.
    """
    ids = [c for c in cve_ids if c]
    if not ids:
        return {}
    rows = session.execute(
        select(Vulnerability.cve_id, func.count(func.distinct(Finding.asset_id)))
        .select_from(Finding)
        .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
        .where(
            Finding.organization_id == organization_id,
            Finding.state.in_(list(OPEN_STATES)),
            Vulnerability.cve_id.in_(ids),
        )
        .group_by(Vulnerability.cve_id)
    ).all()
    return {cve_id: int(n or 0) for cve_id, n in rows}


__all__ = [
    "feed_run", "last_successful_run", "ingest_cwe", "upsert_vendor", "upsert_product",
    "upsert_product_version", "upsert_cpe", "parse_nvd_cve", "upsert_cve", "ingest_nvd",
    "ingest_epss", "epss_trend", "ingest_kev", "intelligence_snapshot", "kev_due_soon",
    "severity_for_score", "estate_product_ids", "estate_cve_ids", "estate_cve_count",
    "estate_kev_count", "estate_inventory_health", "affected_asset_counts",
]
