"""Fetch NVD 2.0, EPSS and CISA KEV, hand them to the ingest layer, correlate.

VEYRS had the ingest endpoints and the correlation engine but nothing that went
out and got the data, so `cve`, `epss` and `kev` sat at single-digit row counts
while the product's whole premise is prioritising with them. This module closes
that loop.

Things here that look like fussiness and are not:

* **NVD is incremental by `lastModified`, never by publication.** A CVE
  published in 2019 and re-scored yesterday has to come back, or the estate
  keeps a stale CVSS forever. The watermark is the last modification boundary
  we asked for, not the time the job ran.
* **NVD refuses a `lastModified` range wider than 120 days.** A backfill is
  walked in windows; asking for "everything" earns a 404 that says nothing.
* **The NVD rate limit is per source address and answers 403.** That reads like
  an auth failure, not a rate limit, so the delay is enforced client-side
  rather than discovered from the response.
* **The EPSS file is a gzip *file*, not a gzip *encoding*.** httpx transparently
  handles `Content-Encoding: gzip`; it does not gunzip a body whose content type
  merely happens to be gzip. Both cases are handled because FIRST has served it
  both ways.
* **A feed that fetches nothing must not be recorded as a successful run.** The
  freshness indicator in `/intel/health` is derived from successful runs, so a
  silently empty fetch would report healthy intelligence that does not exist.
"""
from __future__ import annotations

import csv
import datetime as dt
import gzip
import io
import re
import time
import zipfile
from collections.abc import Iterator
from typing import Any
from xml.etree import ElementTree

import httpx
from sqlalchemy.orm import Session

from ..config import settings
from ..services import intel_pipeline, intelligence, xmlsafe

#: NVD rejects a lastModified window wider than this.
MAX_WINDOW = dt.timedelta(days=120)
#: How far back a first run reaches when there is no watermark. `--full`
#: ignores it and walks to EPOCH_START instead.
DEFAULT_BACKFILL = dt.timedelta(days=90)
#: NVD's earliest record. Only used by `--full`.
EPOCH_START = dt.datetime(2002, 1, 1, tzinfo=dt.timezone.utc)
#: NVD's documented maximum page size.
PAGE_SIZE = 2000
#: Published NVD budgets: 5 requests / 30 s anonymous, 50 / 30 s with a key.
#: One second of headroom each, because the window is enforced server-side on a
#: rolling basis and a burst that is exactly at the limit still trips it.
DELAY_ANONYMOUS = 7.0
DELAY_WITH_KEY = 1.0
#: Transient NVD/CISA responses worth retrying rather than failing the run.
RETRY_STATUSES = (403, 429, 500, 502, 503, 504)
MAX_ATTEMPTS = 4
#: The CWE catalogue is ~2 MB zipped / ~18 MB of XML. This ceiling is a
#: zip-bomb guard, not an estimate: `ZipFile.read` inflates whatever it is
#: given, and this feed runs unattended on a node that has already been OOM
#: killed once by an intelligence job.
MAX_CWE_XML_BYTES = 128 * 1024 * 1024
CWE_NS = "{http://cwe.mitre.org/cwe-7}"


class FeedError(RuntimeError):
    """A feed could not be collected. Recorded on the FeedRun, then re-raised."""


# --------------------------------------------------------------------------
# HTTP
# --------------------------------------------------------------------------


def http_client() -> httpx.Client:
    return httpx.Client(
        timeout=settings.feed_http_timeout,
        follow_redirects=True,
        headers={"User-Agent": f"VEYRS/{settings.version} (+intelligence-sync)"},
    )


def _get(client: httpx.Client, url: str, **kwargs: Any) -> httpx.Response:
    """GET with backoff over the statuses NVD and CISA use for "come back"."""
    last: Exception | None = None
    for attempt in range(1, MAX_ATTEMPTS + 1):
        try:
            response = client.get(url, **kwargs)
        except httpx.HTTPError as exc:
            last = exc
        else:
            if response.status_code not in RETRY_STATUSES:
                response.raise_for_status()
                return response
            last = FeedError(f"{url} answered {response.status_code}")
        if attempt < MAX_ATTEMPTS:
            time.sleep(min(60.0, 5.0 * (2 ** (attempt - 1))))
    raise FeedError(f"giving up on {url} after {MAX_ATTEMPTS} attempts: {last}")


def _decompress(body: bytes) -> bytes:
    """Gunzip when the payload is a gzip member, pass through when it is not."""
    if body[:2] == b"\x1f\x8b":
        return gzip.decompress(body)
    return body


# --------------------------------------------------------------------------
# CISA KEV
# --------------------------------------------------------------------------


def fetch_kev(client: httpx.Client | None = None) -> dict:
    owns = client is None
    client = client or http_client()
    try:
        catalog = _get(client, settings.kev_json_url).json()
    finally:
        if owns:
            client.close()
    if not isinstance(catalog, dict) or not catalog.get("vulnerabilities"):
        raise FeedError("KEV catalogue came back with no vulnerabilities")
    return catalog


def sync_kev(session: Session, *, correlate: bool = True) -> dict[str, Any]:
    catalog = fetch_kev()
    touched: list[str] = []
    stats = intelligence.ingest_kev(session, catalog, collect=touched)
    session.commit()
    out: dict[str, Any] = {"feed": "kev", "catalog_version": catalog.get("catalogVersion"),
                           **stats}
    if correlate:
        out["refresh"] = intel_pipeline.refresh_after_feed(session, "kev", touched)
    return out


# --------------------------------------------------------------------------
# EPSS
# --------------------------------------------------------------------------


def parse_epss_csv(body: bytes) -> tuple[list[dict], dt.date | None, str | None]:
    """Parse FIRST's daily CSV.

    The first line is a `#`-prefixed metadata comment carrying the model version
    and the score date; the score date is what the history table is keyed on, so
    defaulting it to "today" when the file says otherwise would silently write a
    second row for the same publication.
    """
    text = _decompress(body).decode("utf-8", errors="replace")
    scored_on: dt.date | None = None
    model_version: str | None = None

    lines = text.splitlines()
    start = 0
    for index, line in enumerate(lines):
        if not line.startswith("#"):
            start = index
            break
        for chunk in line.lstrip("#").split(","):
            key, _, value = chunk.partition(":")
            key = key.strip().lower()
            value = value.strip()
            if key == "model_version":
                model_version = value or None
            elif key == "score_date" and value:
                try:
                    scored_on = dt.datetime.fromisoformat(
                        value.replace("Z", "+00:00").replace("+0000", "+00:00")
                    ).date()
                except ValueError:
                    scored_on = None

    reader = csv.DictReader(io.StringIO("\n".join(lines[start:])))
    rows = [row for row in reader if row.get("cve")]
    if not rows:
        raise FeedError("EPSS file parsed to zero rows")
    return rows, scored_on, model_version


def fetch_epss(
    client: httpx.Client | None = None,
) -> tuple[list[dict], dt.date | None, str | None]:
    owns = client is None
    client = client or http_client()
    try:
        body = _get(client, settings.epss_csv_url).content
    finally:
        if owns:
            client.close()
    return parse_epss_csv(body)


def sync_epss(session: Session, *, correlate: bool = True) -> dict[str, Any]:
    rows, scored_on, model_version = fetch_epss()
    touched: list[str] = []
    stats = intelligence.ingest_epss(
        session, rows, scored_on=scored_on, model_version=model_version,
        collect=touched,
        # The live feed is the whole corpus. One transaction over ~290k rows is
        # what OOM-killed this service on 2026-08-14..16.
        commit_between_batches=True,
    )
    session.commit()
    out: dict[str, Any] = {"feed": "epss", "rows": len(rows),
                           "scored_on": scored_on.isoformat() if scored_on else None,
                           "model_version": model_version, **stats}
    if correlate:
        out["refresh"] = intel_pipeline.refresh_after_feed(session, "epss", touched)
    return out


# --------------------------------------------------------------------------
# NVD 2.0
# --------------------------------------------------------------------------


def _nvd_stamp(moment: dt.datetime) -> str:
    """NVD wants extended ISO-8601 with an explicit offset and milliseconds."""
    return moment.astimezone(dt.timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000") + "+00:00"


def _windows(start: dt.datetime, end: dt.datetime) -> Iterator[tuple[dt.datetime, dt.datetime]]:
    cursor = start
    while cursor < end:
        stop = min(cursor + MAX_WINDOW, end)
        yield cursor, stop
        cursor = stop


def iter_nvd_pages(
    client: httpx.Client,
    start: dt.datetime,
    end: dt.datetime,
    *,
    api_key: str = "",
    on_page: Any = None,
) -> Iterator[list[dict]]:
    """Yield one fetched page of `vulnerabilities[]` at a time.

    Pages, not a flat stream of records, because the consumer has to be able to
    commit between them. Everything slow lives in this generator -- the rate
    limit sleep, the backoff over NVD's 403s, the request itself -- and the
    consumer resumes it only after committing, so no transaction is ever open
    while we wait on the network. Flattening this cost a whole backfill to
    `idle_in_transaction_session_timeout`.
    """
    headers = {"apiKey": api_key} if api_key else {}
    delay = DELAY_WITH_KEY if api_key else DELAY_ANONYMOUS
    first_request = True
    for window_start, window_end in _windows(start, end):
        index = 0
        while True:
            if not first_request:
                time.sleep(delay)
            first_request = False
            params = {
                "lastModStartDate": _nvd_stamp(window_start),
                "lastModEndDate": _nvd_stamp(window_end),
                "resultsPerPage": PAGE_SIZE,
                "startIndex": index,
            }
            payload = _get(client, settings.nvd_api_url, params=params,
                           headers=headers).json()
            items = payload.get("vulnerabilities") or []
            yield items
            if on_page is not None:
                on_page(window_start, window_end, index, payload.get("totalResults", 0))
            index += payload.get("resultsPerPage", len(items)) or len(items)
            if index >= (payload.get("totalResults") or 0) or not items:
                break


def nvd_window(session: Session, *, full: bool = False,
               now: dt.datetime | None = None) -> tuple[dt.datetime, dt.datetime]:
    """Where the next NVD pull starts.

    A watermark is the *end* of the window we last asked for, so the next run
    resumes there. Re-asking for the boundary second is harmless -- ingest is
    idempotent -- and losing a record that changed inside it is not.
    """
    end = now or dt.datetime.now(dt.timezone.utc)
    if full:
        return EPOCH_START, end
    run = intelligence.last_successful_run(session, "nvd")
    if run is not None and run.watermark:
        try:
            start = dt.datetime.fromisoformat(run.watermark)
        except ValueError:
            start = end - DEFAULT_BACKFILL
        else:
            if start.tzinfo is None:
                start = start.replace(tzinfo=dt.timezone.utc)
            return start, end
    return end - DEFAULT_BACKFILL, end


def sync_nvd(
    session: Session,
    *,
    full: bool = False,
    correlate: bool = True,
    verbose: bool = False,
) -> dict[str, Any]:
    start, end = nvd_window(session, full=full)
    client = http_client()

    def _log(w_start, w_end, index, total):  # noqa: ANN001
        if verbose:
            print(f"  nvd {w_start:%Y-%m-%d}..{w_end:%Y-%m-%d} "
                  f"offset {index} of {total}", flush=True)

    touched: list[str] = []
    try:
        pages = iter_nvd_pages(
            client, start, end, api_key=settings.nvd_api_key, on_page=_log
        )
        stats = intelligence.ingest_nvd_pages(
            session, pages, watermark=end.isoformat(), collect=touched
        )
    except Exception:
        # `feed_run` already stamped the run as failed but only flushed it. With
        # batched commits the records really are on disk, so the failure has to
        # be too -- otherwise the next run reads a watermark-less "never ran"
        # state and starts over from the beginning.
        session.commit()
        raise
    finally:
        client.close()
    session.commit()

    out: dict[str, Any] = {"feed": "nvd", "window_start": start.isoformat(),
                           "window_end": end.isoformat(), **stats}
    if correlate:
        out["refresh"] = intel_pipeline.refresh_after_feed(session, "nvd", touched)
    return out


# --------------------------------------------------------------------------
# CLI
# --------------------------------------------------------------------------

# --------------------------------------------------------------------------
# MITRE CWE dictionary
# --------------------------------------------------------------------------


def unpack_cwe_archive(body: bytes) -> bytes:
    """Return the XML inside MITRE's zip (or the body, if it is already XML)."""
    if body[:2] != b"PK":
        return body
    try:
        archive = zipfile.ZipFile(io.BytesIO(body))
    except zipfile.BadZipFile as exc:
        raise FeedError(f"CWE archive is not a zip: {exc}") from exc
    with archive:
        members = [m for m in archive.infolist() if m.filename.lower().endswith(".xml")]
        if not members:
            raise FeedError("CWE archive contains no XML member")
        member = max(members, key=lambda m: m.file_size)
        if member.file_size > MAX_CWE_XML_BYTES:
            raise FeedError(
                f"CWE archive declares {member.file_size} bytes of XML, "
                f"over the {MAX_CWE_XML_BYTES} ceiling"
            )
        return archive.read(member)


def fetch_cwe(client: httpx.Client | None = None) -> bytes:
    owns = client is None
    client = client or http_client()
    try:
        body = _get(client, settings.cwe_catalog_url).content
    finally:
        if owns:
            client.close()
    return unpack_cwe_archive(body)


def _flatten(node: ElementTree.Element | None) -> str | None:
    """Element text including xhtml children, whitespace collapsed."""
    if node is None:
        return None
    text = re.sub(r"\s+", " ", "".join(node.itertext())).strip()
    return text or None


def parse_cwe_catalog(xml: bytes) -> tuple[list[dict], str | None]:
    """Stream the catalogue into `(entries, catalog_version)`.

    Parsed with `iterparse`, clearing each element as it closes: the document
    is 18 MB and building the whole tree costs an order of magnitude more
    resident memory than ~1.4k short rows are worth. That is the same mistake
    `ingest_epss` was rewritten to stop making, and this feed shares its timer.

    **Categories and views are ingested alongside weaknesses.** They are not
    weakness classes -- a view is a curated slice such as "Weaknesses in OWASP
    Top Ten (2017)" -- but CVE records cite their ids anyway, and this estate
    proves it: after ingesting weaknesses and categories only, CWE-701, CWE-702
    and CWE-1026 were still bare numbers on the dashboard. An id nobody can
    name is the defect this feed exists to fix, whatever section it lives in.
    """
    xmlsafe.reject_entity_declarations(xml)
    entries: list[dict] = []
    version: str | None = None
    wanted = {f"{CWE_NS}Weakness", f"{CWE_NS}Category", f"{CWE_NS}View"}
    try:
        for event, element in ElementTree.iterparse(
            io.BytesIO(xml), events=("start", "end")
        ):
            if event == "start":
                if element.tag == f"{CWE_NS}Weakness_Catalog":
                    version = element.get("Version")
                continue
            if element.tag not in wanted:
                continue
            identifier, name = element.get("ID"), element.get("Name")
            if identifier and name:
                # Weakness carries <Description>, Category <Summary>,
                # View <Objective>. Same field, three names.
                body = next(
                    (found for tag in ("Description", "Summary", "Objective")
                     if (found := element.find(f"{CWE_NS}{tag}")) is not None),
                    None,
                )
                kind = element.tag[len(CWE_NS):]
                entries.append({
                    "id": f"CWE-{identifier}",
                    "name": name,
                    "description": _flatten(body),
                    "abstraction": element.get("Abstraction")
                                   or (kind if kind in ("Category", "View") else None),
                    "status": element.get("Status"),
                })
            element.clear()
    except ElementTree.ParseError as exc:
        raise FeedError(f"CWE catalogue is not valid XML: {exc}") from exc
    if not entries:
        raise FeedError("CWE catalogue parsed to zero weaknesses")
    return entries, version


def sync_cwe(session: Session) -> dict[str, Any]:
    """Refresh the weakness dictionary. Deliberately does **not** correlate.

    A CWE name changes no tenant's exposure — it is vocabulary, not an
    advisory. EPSS and KEV rescore without re-correlating for the same reason;
    this feed goes one step further, because there is not even a score to move.
    """
    entries, version = parse_cwe_catalog(fetch_cwe())
    stats = intelligence.ingest_cwe(session, entries, version=version)
    session.commit()
    return {"feed": "cwe", "catalog_version": version, **stats}


_COMMANDS = {"sync-kev": "kev", "sync-epss": "epss", "sync-nvd": "nvd",
             "sync-cwe": "cwe"}


def run_cli(command: str, *, full: bool = False, correlate: bool = True) -> int:
    """`python -m veyrs sync-{kev,epss,nvd}`."""
    from ..db import SessionLocal

    feed = _COMMANDS.get(command)
    if feed is None:
        print(f"unknown feed command {command!r}")
        return 2

    with SessionLocal() as session:
        try:
            if feed == "kev":
                result = sync_kev(session, correlate=correlate)
            elif feed == "cwe":
                result = sync_cwe(session)
            elif feed == "epss":
                result = sync_epss(session, correlate=correlate)
            else:
                result = sync_nvd(session, full=full, correlate=correlate, verbose=True)
        except FeedError as exc:
            session.rollback()
            print(f"{feed}: {exc}")
            return 1

    counters = " ".join(
        f"{key}={value}" for key, value in result.items()
        if isinstance(value, int)
    )
    print(f"{feed}: {counters}")
    refresh = result.get("refresh")
    if refresh:
        if feed == "nvd":
            print(f"  correlated {refresh['cve_ids']} CVEs across "
                  f"{refresh['organizations']} tenants: "
                  f"{refresh['created']} findings created, "
                  f"{refresh['updated']} updated")
        else:
            print(f"  rescored {refresh['findings']} findings across "
                  f"{refresh['organizations']} tenants "
                  f"({refresh['changed']} scores moved)")
    return 0


__all__ = [
    "FeedError", "http_client", "fetch_kev", "fetch_epss", "parse_epss_csv",
    "fetch_cwe", "unpack_cwe_archive", "parse_cwe_catalog",
    "iter_nvd_pages", "nvd_window", "sync_kev", "sync_epss", "sync_nvd",
    "sync_cwe", "run_cli",
]
