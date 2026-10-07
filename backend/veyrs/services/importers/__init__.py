"""Scanner import framework (spec section 31).

    bytes -> parsers.<vendor> -> ScanRecord[] -> base.ingest() -> Finding[]

`run_import` wraps that pipeline in an `ImportRun` so every ingestion leaves an
audit record with its reject reasons, whether it succeeded or not.
"""
from __future__ import annotations

import datetime as dt
import logging
import uuid

from sqlalchemy import select
from sqlalchemy.orm import Session

from ...models.integration import ImportRun, ImportStatus
from .base import (
    HostInventory, ImportOptions, ImportResult, ParserError, ScanRecord,
    SoftwareSpec, ingest, ingest_inventory, payload_hash,
)
from .parsers import (
    INVENTORY_PARSERS, PARSERS, detect_format, get_inventory_parser, get_parser,
)

log = logging.getLogger("veyrs.importers")


def run_import(
    session: Session,
    organization_id: uuid.UUID,
    payload: bytes,
    *,
    source: str | None = None,
    filename: str = "",
    options: ImportOptions | None = None,
    actor_id: uuid.UUID | None = None,
    inventory_detected_by: str | None = None,
) -> ImportRun:
    """Parse and ingest one export. Always returns a persisted ImportRun.

    A parse failure is recorded as a FAILED run rather than raised, because
    "the import you ran at 09:12 rejected the whole file because it was not a
    Nessus v2 report" is information the operator needs later, not just now.
    """
    options = options or ImportOptions()
    digest = payload_hash(payload)

    run = ImportRun(
        organization_id=organization_id,
        source=source or "unknown",
        filename=filename[:400] or None,
        content_hash=digest,
        size_bytes=len(payload),
        status=ImportStatus.RUNNING.value,
        options={
            "create_assets": options.create_assets,
            "dry_run": options.dry_run,
            "close_missing": options.close_missing,
            "close_absent": options.close_absent,
            "absence_threshold": options.absence_threshold,
            "min_severity": options.min_severity,
            "reuse_test": options.reuse_test,
            "engagement_id": str(options.engagement_id) if options.engagement_id else None,
            "test_id": str(options.test_id) if options.test_id else None,
            "dedupe_config": options.dedupe_config,
            "allow_empty": options.allow_empty,
            "import_inventory": options.import_inventory,
            "inventory_from_plugin_output": options.inventory_from_plugin_output,
            "version": options.version,
            "branch_tag": options.branch_tag,
            "commit_hash": options.commit_hash,
            "build_id": options.build_id,
        },
        started_by_id=actor_id,
    )
    session.add(run)
    session.flush()

    try:
        resolved = source or detect_format(payload, filename)
        run.source = resolved
        if options.allow_empty and not payload.strip():
            # A completed scan with no output. There is nothing to parse, but
            # there IS something to reconcile: the test's previously reported
            # findings are all absent, which is how remediation is observed.
            records = []
        else:
            parser = get_parser(resolved)
            records = list(parser(payload))
    except ParserError as exc:
        run.status = ImportStatus.FAILED.value
        run.error = str(exc)[:2000]
        run.finished_at = dt.datetime.now(dt.timezone.utc)
        session.flush()
        return run

    try:
        result = ingest(session, organization_id, records, scanner=run.source,
                        options=options, run=run)
    except Exception as exc:  # noqa: BLE001 - the run must record its own failure
        log.exception("import run %s failed during ingest", run.id)
        run.status = ImportStatus.FAILED.value
        run.error = f"{exc.__class__.__name__}: {exc}"[:2000]
        run.finished_at = dt.datetime.now(dt.timezone.utc)
        session.flush()
        return run

    if options.import_inventory:
        # A SECOND read of the same bytes, not a second ingestion route. It
        # produces AssetProduct rows, never findings, so it cannot affect
        # deduplication or reconciliation -- which is why a failure here is
        # recorded and swallowed rather than failing the whole run: losing the
        # vulnerability data because a software list was malformed would be a
        # strictly worse outcome than importing without inventory.
        inventory_parser = get_inventory_parser(run.source)
        if inventory_parser is not None:
            try:
                hosts = inventory_parser(
                    payload, plugin_output=options.inventory_from_plugin_output
                )
                ingest_inventory(
                    session, organization_id, hosts,
                    detected_by=inventory_detected_by or f"scanner:{run.source}",
                    options=options, result=result,
                )
            except Exception as exc:  # noqa: BLE001 - see the comment above
                log.exception("import run %s: inventory pass failed", run.id)
                result.reject_reasons["inventory pass failed"] = 1
                result.reject_samples.append(
                    {"reason": f"inventory pass failed: {exc.__class__.__name__}: {exc}"[:400]}
                )

    for field, value in result.as_dict().items():
        setattr(run, field, value)
    # Scope and identity settings are recorded on the run itself, not folded
    # into the counters dict, so "which engagement did last night land in, and
    # under which dedupe algorithm?" is one query rather than JSON archaeology.
    run.engagement_id = result.engagement_id
    run.test_id = result.test_id
    run.dedupe_algorithm = result.dedupe_algorithm
    run.status = (ImportStatus.PREVIEW if options.dry_run else ImportStatus.COMPLETE).value
    run.finished_at = dt.datetime.now(dt.timezone.utc)
    session.flush()
    return run


def previous_run_with_hash(
    session: Session, organization_id: uuid.UUID, digest: str
) -> ImportRun | None:
    """Has this exact file been imported before? Warns about double counting."""
    return session.execute(
        select(ImportRun)
        .where(ImportRun.organization_id == organization_id,
               ImportRun.content_hash == digest,
               ImportRun.status == ImportStatus.COMPLETE.value)
        .order_by(ImportRun.started_at.desc())
    ).scalars().first()


__all__ = [
    "HostInventory", "ImportOptions", "ImportResult", "ParserError",
    "ScanRecord", "SoftwareSpec", "PARSERS", "INVENTORY_PARSERS",
    "detect_format", "get_parser", "get_inventory_parser", "ingest",
    "ingest_inventory", "payload_hash", "run_import", "previous_run_with_hash",
]
