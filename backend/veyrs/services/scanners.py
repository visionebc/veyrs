"""Pulling scan results from a scanner's own API (spec section 31, phase 33).

The counterpart to `services/importers`, which is the *push* path: an operator
uploads a `.nessus` file, or an execution agent runs a tool on its own host and
uploads the raw output. This module lets VEYRS go and fetch that same file.

    ScannerConnector -> DRIVERS[driver] -> bytes -> importers.run_import()

**The last arrow is the point of this module.** A pulled export goes through
`run_import` and therefore through `parsers.parse_nessus`, the same parser the
upload path uses. Adding a second ingestion route would mean two deduplication
rules, two sets of reject counters and two answers to "why did my findings
double" -- so the driver's entire job is to end up holding the same bytes an
operator would have downloaded by hand.

What a driver may NOT do
------------------------
Drivers speak HTTP and return bytes. They do not touch the session, they do not
create findings, and they never decide scope. Everything that writes to the
database is in `sync()`, in one place, under one set of rules.

Credentials
-----------
`ScannerConnector.credentials_enc` is the same Fernet envelope as ITSM
connectors and MFA secrets (`security/secrets.py`). They are decrypted into a
dict for the duration of one call and never returned by any schema. A failure
to decrypt is an error, never a fallback to unauthenticated -- an anonymous
request to a scanner console is a very different request from the one the
operator configured.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import io
import json
import logging
import time
import uuid
import zipfile
from typing import Any, Iterable, Protocol

from sqlalchemy.orm import Session

from ..models import ScannerConnector
from ..models.integration import ImportRun
from ..security.secrets import SecretError, decrypt
from . import importers
from .importers import ImportOptions

log = logging.getLogger("veyrs.scanners")

#: Ceiling on one downloaded export, and on one member extracted from a
#: Tenable.sc zip. The upload path caps the same thing at the router; a pull has
#: no router in front of it, so the cap lives here.
MAX_EXPORT_BYTES = 128 * 1024 * 1024
#: How long `fetch_report` waits for the remote to finish building the export.
#: Bounded on purpose: this runs inside a request, and an unbounded poll turns a
#: slow appliance into a hung worker.
EXPORT_TIMEOUT_S = 120
EXPORT_POLL_S = 3.0
HTTP_TIMEOUT_S = 60


class ScannerError(RuntimeError):
    """A connector could not be reached, authenticated, or read."""


@dataclasses.dataclass(frozen=True)
class RemoteScan:
    """One scan as the remote console lists it."""

    id: str
    name: str
    status: str | None = None
    finished_at: str | None = None
    folder: str | None = None

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


@dataclasses.dataclass(frozen=True)
class ScannerSpec:
    """Everything a driver needs, and nothing that touches the database."""

    driver: str
    base_url: str
    credentials: dict[str, Any]
    verify_tls: bool = True
    timeout: int = HTTP_TIMEOUT_S


# ---------------------------------------------------------------------------
# HTTP
# ---------------------------------------------------------------------------
def _client(spec: ScannerSpec):
    """A configured httpx client. Imported locally, as elsewhere in the tree,
    so `import veyrs` stays free of network libraries."""
    import httpx

    return httpx.Client(
        base_url=spec.base_url.rstrip("/"),
        verify=spec.verify_tls,
        timeout=spec.timeout,
        follow_redirects=False,
    )


def _check(response, what: str) -> None:
    """Translate an HTTP failure into a message an operator can act on.

    401/403 are called out by name because they are the overwhelmingly common
    failure -- a rotated key, or a key without the scan's permissions -- and
    "remote returned HTTP 403" sends people to check the network instead.
    """
    if response.status_code in (401, 403):
        raise ScannerError(
            f"{what}: the scanner rejected these credentials (HTTP "
            f"{response.status_code}). The key may be rotated, or may not have "
            f"permission on this scan."
        )
    if response.status_code >= 400:
        raise ScannerError(f"{what}: remote returned HTTP {response.status_code}")


def _json(response, what: str) -> dict:
    _check(response, what)
    try:
        return response.json()
    except ValueError as exc:
        raise ScannerError(f"{what}: remote returned a non-JSON body") from exc


# ---------------------------------------------------------------------------
# Drivers
# ---------------------------------------------------------------------------
class Driver(Protocol):
    driver: str
    #: The `importers.PARSERS` key the downloaded bytes must be parsed with.
    parser_format: str
    #: Credential keys the operator must supply, in order, for the UI to render.
    credential_fields: tuple[str, ...]

    def list_scans(self, spec: ScannerSpec) -> list[RemoteScan]: ...
    def fetch_report(self, spec: ScannerSpec, scan_id: str) -> bytes: ...


class _NessusApiDriver:
    """Nessus Professional / Manager, and Tenable.io -- one implementation.

    They are not merely similar: Tenable.io exposes the same `/scans` export
    endpoints with the same `X-ApiKeys` header, and the difference is the base
    URL and the fact that the cloud omits the export `token`. Writing this twice
    would mean fixing every export-flow bug twice.
    """

    driver = "nessus"
    parser_format = "nessus"
    credential_fields = ("access_key", "secret_key")
    default_base_url = ""

    def _headers(self, spec: ScannerSpec) -> dict[str, str]:
        access = str(spec.credentials.get("access_key") or "").strip()
        secret = str(spec.credentials.get("secret_key") or "").strip()
        if not access or not secret:
            raise ScannerError(
                "this driver needs an access_key and a secret_key "
                "(Nessus: Settings -> My Account -> API Keys)"
            )
        return {
            "X-ApiKeys": f"accessKey={access}; secretKey={secret}",
            "Accept": "application/json",
        }

    def list_scans(self, spec: ScannerSpec) -> list[RemoteScan]:
        with _client(spec) as client:
            body = _json(client.get("/scans", headers=self._headers(spec)),
                         "listing scans")
        out: list[RemoteScan] = []
        for row in (body.get("scans") or []):
            finished = row.get("last_modification_date")
            out.append(RemoteScan(
                id=str(row.get("id")),
                name=str(row.get("name") or f"scan {row.get('id')}"),
                status=row.get("status"),
                finished_at=(
                    dt.datetime.fromtimestamp(finished, dt.timezone.utc).isoformat()
                    if isinstance(finished, (int, float)) else None
                ),
                folder=str(row.get("folder_id")) if row.get("folder_id") else None,
            ))
        return sorted(out, key=lambda s: s.name.lower())

    def fetch_report(self, spec: ScannerSpec, scan_id: str) -> bytes:
        headers = self._headers(spec)
        with _client(spec) as client:
            started = _json(
                client.post(f"/scans/{scan_id}/export", headers=headers,
                            json={"format": "nessus"}),
                f"requesting an export of scan {scan_id}",
            )
            file_id = started.get("file")
            if file_id is None:
                raise ScannerError(
                    f"scan {scan_id}: the remote accepted the export request but "
                    f"named no file. It may still be running."
                )

            deadline = time.monotonic() + EXPORT_TIMEOUT_S
            while True:
                state = _json(
                    client.get(f"/scans/{scan_id}/export/{file_id}/status",
                               headers=headers),
                    f"polling the export of scan {scan_id}",
                )
                if state.get("status") == "ready":
                    break
                if time.monotonic() >= deadline:
                    raise ScannerError(
                        f"scan {scan_id}: the export was still "
                        f"{state.get('status') or 'unknown'} after "
                        f"{EXPORT_TIMEOUT_S}s. Nothing was imported."
                    )
                time.sleep(EXPORT_POLL_S)

            response = client.get(f"/scans/{scan_id}/export/{file_id}/download",
                                  headers=headers)
        _check(response, f"downloading the export of scan {scan_id}")
        payload = response.content
        if len(payload) > MAX_EXPORT_BYTES:
            raise ScannerError(
                f"scan {scan_id}: export is {len(payload)} bytes, over the "
                f"{MAX_EXPORT_BYTES}-byte ceiling"
            )
        return payload


class NessusDriver(_NessusApiDriver):
    """An on-premise Nessus Professional or Manager console, normally :8834."""

    driver = "nessus"


class TenableIoDriver(_NessusApiDriver):
    """Tenable Vulnerability Management (formerly Tenable.io), the SaaS."""

    driver = "tenable_io"
    default_base_url = "https://cloud.tenable.com"


class TenableScDriver:
    """Tenable Security Center (formerly Tenable.sc).

    A genuinely different API, which is why it is a separate class rather than a
    flag: authentication is a session (a token *plus* a cookie, both required on
    every subsequent call), listing is `/rest/scanResult`, and the download
    returns a **zip**, not the report. The zip is opened here so that everything
    downstream still receives one `.nessus` document.
    """

    driver = "tenable_sc"
    parser_format = "nessus"
    credential_fields = ("username", "password")
    default_base_url = ""

    def _login(self, client) -> dict[str, str]:
        credentials = getattr(client, "_veyrs_credentials", {})
        username = str(credentials.get("username") or "").strip()
        password = str(credentials.get("password") or "")
        if not username or not password:
            raise ScannerError("this driver needs a username and a password")
        body = _json(
            client.post("/rest/token",
                        json={"username": username, "password": password}),
            "authenticating",
        )
        token = (body.get("response") or {}).get("token")
        if token is None:
            raise ScannerError("authenticating: the remote returned no session token")
        return {"X-SecurityCenter": str(token), "Accept": "application/json"}

    def _logout(self, client, headers: dict[str, str]) -> None:
        # Best effort. A leaked session on the appliance is worse than a noisy
        # log line, but failing the caller's import because the logout 500'd
        # would discard work that already succeeded.
        try:
            client.delete("/rest/token", headers=headers)
        except Exception:  # noqa: BLE001
            log.warning("tenable.sc: logout failed; session left to expire")

    def _session(self, spec: ScannerSpec):
        client = _client(spec)
        client._veyrs_credentials = spec.credentials  # noqa: SLF001 - see _login
        return client

    def list_scans(self, spec: ScannerSpec) -> list[RemoteScan]:
        with self._session(spec) as client:
            headers = self._login(client)
            try:
                body = _json(
                    client.get("/rest/scanResult",
                               params={"fields": "id,name,status,finishTime"},
                               headers=headers),
                    "listing scan results",
                )
            finally:
                self._logout(client, headers)
        rows = (body.get("response") or {}).get("usable") or []
        out = [
            RemoteScan(
                id=str(row.get("id")),
                name=str(row.get("name") or f"scan {row.get('id')}"),
                status=row.get("status"),
                finished_at=str(row.get("finishTime")) if row.get("finishTime") else None,
            )
            for row in rows
        ]
        return sorted(out, key=lambda s: s.name.lower())

    def fetch_report(self, spec: ScannerSpec, scan_id: str) -> bytes:
        with self._session(spec) as client:
            headers = self._login(client)
            try:
                response = client.post(f"/rest/scanResult/{scan_id}/download",
                                       headers=headers,
                                       json={"downloadType": "v2"})
                _check(response, f"downloading scan result {scan_id}")
                blob = response.content
            finally:
                self._logout(client, headers)
        return _unzip_report(blob, scan_id)


def _unzip_report(blob: bytes, scan_id: str) -> bytes:
    """Extract the single `.nessus` document from a Tenable.sc download.

    The size ceiling is checked against the member's DECLARED size before
    reading it, not after: `read()` on a zip bomb allocates before any length
    check downstream could fire. Same class of defect as the entity expansion
    fixed in phase 25 -- the guardrail has to run before the expansion, not
    after.
    """
    if not blob:
        raise ScannerError(f"scan {scan_id}: the remote returned an empty download")
    if not blob.startswith(b"PK"):
        # Some versions hand back the report directly. Accept it rather than
        # failing on an assumption about the packaging.
        return blob
    try:
        archive = zipfile.ZipFile(io.BytesIO(blob))
    except zipfile.BadZipFile as exc:
        raise ScannerError(f"scan {scan_id}: download is not a readable zip") from exc
    members = [m for m in archive.infolist() if not m.is_dir()]
    reports = [m for m in members if m.filename.lower().endswith(".nessus")] or members
    if not reports:
        raise ScannerError(f"scan {scan_id}: the download archive is empty")
    member = reports[0]
    if member.file_size > MAX_EXPORT_BYTES:
        raise ScannerError(
            f"scan {scan_id}: {member.filename} declares {member.file_size} bytes, "
            f"over the {MAX_EXPORT_BYTES}-byte ceiling"
        )
    with archive.open(member) as handle:
        return handle.read(MAX_EXPORT_BYTES + 1)[:MAX_EXPORT_BYTES]


DRIVERS: dict[str, Driver] = {
    "nessus": NessusDriver(),
    "tenable_io": TenableIoDriver(),
    "tenable_sc": TenableScDriver(),
}

DRIVER_LABELS = {
    "nessus": "Nessus Professional / Manager",
    "tenable_io": "Tenable Vulnerability Management (cloud)",
    "tenable_sc": "Tenable Security Center",
}


def describe_drivers() -> list[dict[str, Any]]:
    """What the console renders in the connector form."""
    return [
        {
            "driver": key,
            "label": DRIVER_LABELS.get(key, key),
            "credential_fields": list(driver.credential_fields),
            "parser_format": driver.parser_format,
            "default_base_url": getattr(driver, "default_base_url", "") or None,
        }
        for key, driver in sorted(DRIVERS.items())
    ]


# ---------------------------------------------------------------------------
# Connector -> spec
# ---------------------------------------------------------------------------
def credentials_of(connector: ScannerConnector) -> dict[str, Any]:
    """Decrypt this connector's credentials, or fail loudly.

    An undecryptable credential FAILS CLOSED. Falling through to an empty dict
    would send an unauthenticated request to a scanner console and report the
    resulting 401 as a connectivity problem, which is a much longer debugging
    session than "the encryption key changed".
    """
    if not connector.credentials_enc:
        return {}
    try:
        raw = decrypt(connector.credentials_enc)
    except SecretError as exc:
        raise ScannerError(
            "stored credentials cannot be decrypted with the current "
            "VEYRS_ENCRYPTION_KEY; re-enter them"
        ) from exc
    if not raw:
        return {}
    try:
        parsed = json.loads(raw)
    except ValueError as exc:
        raise ScannerError("stored credentials are not readable JSON") from exc
    return parsed if isinstance(parsed, dict) else {}


def spec_for(connector: ScannerConnector) -> ScannerSpec:
    driver = DRIVERS.get(connector.driver)
    if driver is None:
        raise ScannerError(f"unknown driver {connector.driver!r}")
    base_url = (connector.base_url or "").strip() or getattr(
        driver, "default_base_url", "")
    if not base_url:
        raise ScannerError("this connector has no base URL")
    return ScannerSpec(
        driver=connector.driver,
        base_url=base_url,
        credentials=credentials_of(connector),
        verify_tls=connector.verify_tls,
    )


def list_remote_scans(connector: ScannerConnector) -> list[RemoteScan]:
    """Read-only: what the remote console holds. Touches no VEYRS row."""
    return DRIVERS[connector.driver].list_scans(spec_for(connector))


# ---------------------------------------------------------------------------
# Sync
# ---------------------------------------------------------------------------
@dataclasses.dataclass
class SyncOutcome:
    scan_id: str
    status: str          # imported | skipped | failed
    detail: str | None = None
    run_id: uuid.UUID | None = None

    def as_dict(self) -> dict[str, Any]:
        return {"scan_id": self.scan_id, "status": self.status,
                "detail": self.detail,
                "run_id": str(self.run_id) if self.run_id else None}


def sync(
    session: Session,
    connector: ScannerConnector,
    *,
    actor_id: uuid.UUID | None = None,
    scan_ids: Iterable[str] | None = None,
    force: bool = False,
    dry_run: bool = False,
) -> list[SyncOutcome]:
    """Pull the connector's allowed scans and ingest each through `run_import`.

    Refusals, all of them deliberate:

    * a **disabled** connector does nothing, so that a connector left half
      configured cannot be triggered into life by a scheduler;
    * an **empty `allowed_scans`** does nothing -- see the model docstring;
    * a `scan_ids` argument naming anything outside `allowed_scans` is
      **rejected**, not silently filtered. Silently narrowing a caller's request
      means an operator watching one scan gets told the sync succeeded while
      that scan was never touched;
    * **`close_absent` without an engagement is refused.** Absence-based closure
      outside a scope is the over-closing defect documented in
      `services/importers/base.py`; enforcing it here rather than trusting the
      form is the difference between a rule and a comment.

    Each scan gets its OWN `ImportRun`. One run covering three scans could not
    report which of them rejected 400 records, and reconciliation is per test.

    When `import_inventory` is on, the SAME bytes are read a second time for
    what each host has installed (`importers.ingest_inventory`). It is a second
    *read*, never a second ingestion route: it produces `AssetProduct` rows and
    no findings, so it cannot touch deduplication or reconciliation. That is
    what lets VEYRS build an estate inventory out of somebody else's scanner
    without owning a scanner of its own.
    """
    if not connector.is_enabled:
        raise ScannerError("connector is disabled")
    allowed = [str(s) for s in (connector.allowed_scans or [])]
    if not allowed:
        raise ScannerError(
            "connector has no allowed scans; it is inert until an operator "
            "names the scans it may pull"
        )
    if connector.close_absent and connector.engagement_id is None:
        raise ScannerError(
            "close_absent requires an engagement: a pull covering some hosts "
            "cannot mark the rest of the estate remediated"
        )

    if scan_ids is None:
        targets = allowed
    else:
        targets = [str(s) for s in scan_ids]
        unknown = sorted(set(targets) - set(allowed))
        if unknown:
            raise ScannerError(
                f"not in this connector's allowed scans: {', '.join(unknown)}"
            )

    driver = DRIVERS[connector.driver]
    spec = spec_for(connector)
    state = dict(connector.sync_state or {})
    outcomes: list[SyncOutcome] = []

    for scan_id in targets:
        try:
            payload = driver.fetch_report(spec, scan_id)
        except ScannerError as exc:
            connector.last_error = str(exc)[:2000]
            outcomes.append(SyncOutcome(scan_id, "failed", str(exc)))
            continue

        digest = importers.payload_hash(payload)
        if not force and state.get(scan_id) == digest:
            outcomes.append(SyncOutcome(
                scan_id, "skipped",
                "the export is byte-identical to the last one imported",
            ))
            continue

        options = ImportOptions(
            create_assets=connector.create_assets,
            dry_run=dry_run,
            min_severity=connector.min_severity,
            engagement_id=connector.engagement_id,
            reuse_test=True,
            close_absent=connector.close_absent,
            absence_threshold=connector.absence_threshold,
            import_inventory=connector.import_inventory,
            inventory_from_plugin_output=connector.inventory_from_plugin_output,
        )
        run = importers.run_import(
            session,
            connector.organization_id,
            payload,
            source=driver.parser_format,
            filename=f"{connector.slug}:{scan_id}.nessus",
            options=options,
            actor_id=actor_id,
            # Provenance names the CONNECTOR, not the driver. `inventory.install`
            # scopes everything it can prune to `detected_by`, and two Nessus
            # appliances pulled under one label would be able to overwrite each
            # other's view of the same host the day pruning is ever turned on.
            inventory_detected_by=f"connector:{connector.slug}",
        )
        if run.status == "failed":
            connector.last_error = (run.error or "import failed")[:2000]
            outcomes.append(SyncOutcome(scan_id, "failed", run.error, run.id))
            continue

        if not dry_run:
            state[scan_id] = digest
        connector.last_run_id = run.id
        outcomes.append(SyncOutcome(scan_id, "imported", None, run.id))

    if not dry_run:
        connector.sync_state = state
        connector.last_sync_at = dt.datetime.now(dt.timezone.utc)
        if all(o.status != "failed" for o in outcomes):
            connector.last_error = None
    session.flush()
    return outcomes


__all__ = [
    "DRIVERS", "DRIVER_LABELS", "ImportRun", "RemoteScan", "ScannerError",
    "ScannerSpec", "SyncOutcome", "credentials_of", "describe_drivers",
    "list_remote_scans", "spec_for", "sync",
]
