"""TLS trust store: import CAs, build the verification context every outbound
client uses, and diagnose a server's certificate in terms an operator can act on.

Companion to :mod:`veyrs.models.trust`. Three rules hold it together:

* **The store ADDS to the public roots, it never replaces them.** httpx
  verifies against certifi by default, smtplib and ldap3 against the system
  store. A context built from the private CAs alone would break every public
  endpoint (NVD, CISA, GitHub, a SaaS ITSM) the moment the first company root
  is imported -- which reads as "the trust store broke VEYRS". So the context
  is system roots + certifi + the enabled private CAs.
* **A store that cannot be read NEVER downgrades to no verification.** Any
  failure reading the table falls back to the public roots (a visible
  failure on internal endpoints), never to ``verify=False`` (silent,
  installation-wide, unverified TLS).
* **Only CA certificates are accepted.** OpenSSL will not anchor a chain on a
  ``CA:FALSE`` certificate: importing a server's own self-signed leaf would
  appear to work and then fail every handshake. It is rejected at import with
  the reason.

An operator's explicit "do not verify" on a connector (``verify_tls=False``)
stays exactly that: :func:`httpx_verify` returns ``False`` for it.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import logging
import re
import socket
import ssl
import threading
import time
import uuid
import warnings
from typing import Any

import certifi
from cryptography import x509
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.serialization import Encoding
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.trust import ROLE_INTERMEDIATE, ROLE_ROOT, TrustedCa

log = logging.getLogger(__name__)

#: How long a node keeps the enabled-CA set before re-reading the table. Short
#: enough that an import on one app node reaches the other on its own; long
#: enough that a sync making hundreds of requests does not query per request.
RESOLVE_TTL_S = 30.0
EXPIRY_WARNING_DAYS = 30

_lock = threading.Lock()
_resolved: tuple[float, str | None] | None = None
_ctx_cache: dict[str, ssl.SSLContext] = {}
_public_subjects: frozenset[str] | None = None


class TrustStoreError(ValueError):
    """An import or probe the operator can fix; the message is shown verbatim."""


# ---------------------------------------------------------------------------
# parsing
# ---------------------------------------------------------------------------

def _dn(name: x509.Name) -> str:
    try:
        return name.rfc4514_string()
    except Exception:  # noqa: BLE001
        return str(name)


def _common_name(cert: x509.Certificate) -> str:
    try:
        vals = cert.subject.get_attributes_for_oid(x509.oid.NameOID.COMMON_NAME)
        if vals:
            return str(vals[0].value)
    except Exception:  # noqa: BLE001
        pass
    return _dn(cert.subject)[:120]


def _is_ca(cert: x509.Certificate) -> bool:
    try:
        return bool(cert.extensions.get_extension_for_class(x509.BasicConstraints).value.ca)
    except x509.ExtensionNotFound:
        # Ancient roots omit basicConstraints. Treat as NOT a CA rather than
        # guess: a wrong "yes" fails at handshake time instead of at import.
        return False


def _describe(cert: x509.Certificate) -> dict:
    der = cert.public_bytes(Encoding.DER)
    subject, issuer = _dn(cert.subject), _dn(cert.issuer)
    return {
        "cert": cert,
        "pem": cert.public_bytes(Encoding.PEM).decode("ascii"),
        "fingerprint": hashlib.sha256(der).hexdigest(),
        "subject": subject,
        "issuer": issuer,
        "serial": format(cert.serial_number, "x"),
        "is_ca": _is_ca(cert),
        "self_signed": subject == issuer,
        "role": ROLE_ROOT if subject == issuer else ROLE_INTERMEDIATE,
        "not_before": cert.not_valid_before_utc,
        "not_after": cert.not_valid_after_utc,
        "common_name": _common_name(cert),
    }


def parse_pem(blob: str | bytes) -> list[dict]:
    """Every certificate in ``blob``: one PEM, a pasted chain, or DER."""
    raw = blob.encode() if isinstance(blob, str) else bytes(blob)
    raw = raw.strip()
    if not raw:
        raise TrustStoreError("Nothing to import: paste or upload a PEM certificate.")
    if b"-----BEGIN" in raw:
        try:
            certs = x509.load_pem_x509_certificates(raw)
        except Exception as exc:  # noqa: BLE001
            raise TrustStoreError(f"Could not parse the PEM: {exc}") from exc
    else:
        try:
            certs = [x509.load_der_x509_certificate(raw)]
        except Exception as exc:  # noqa: BLE001
            raise TrustStoreError(
                "Not a certificate. Expected PEM text starting with "
                "'-----BEGIN CERTIFICATE-----', or a DER file."
            ) from exc
    if not certs:
        raise TrustStoreError("The input parsed but contained no certificate.")
    return [_describe(c) for c in certs]


NOT_A_CA = (
    "not a CA certificate (basicConstraints CA:FALSE or absent): OpenSSL cannot anchor a "
    "chain on it. If this is a server's own self-signed certificate there is no CA to "
    "trust; re-issue that server's certificate from your CA, or keep verification off "
    "for that one connector."
)


def import_pem(session: Session, blob: str | bytes, *, name_hint: str = "", note: str = "",
               actor_id: uuid.UUID | None = None, actor_label: str = "") -> dict:
    """Import every CA in ``blob``. Idempotent per fingerprint.

    Partial success is a real outcome: a pasted chain often carries the leaf,
    and the CAs in it should still land. Returns
    ``{"imported": [...], "updated": [...], "rejected": [{name, reason}]}``.
    The caller commits."""
    parsed = parse_pem(blob)
    out: dict[str, list] = {"imported": [], "updated": [], "rejected": []}
    for info in parsed:
        label = info["common_name"] or info["subject"]
        if not info["is_ca"]:
            out["rejected"].append({"name": label, "reason": NOT_A_CA})
            continue
        row = session.execute(
            select(TrustedCa).where(TrustedCa.fingerprint == info["fingerprint"])
        ).scalar_one_or_none()
        if row is not None:
            row.pem, row.subject, row.issuer = info["pem"], info["subject"][:1000], info["issuer"][:1000]
            row.serial, row.role = info["serial"][:80], info["role"]
            row.not_before, row.not_after = info["not_before"], info["not_after"]
            if note:
                row.note = note[:500]
            out["updated"].append({"id": str(row.id), "name": row.name, "role": row.role})
            continue
        name = (name_hint or label or info["fingerprint"][:16]).strip()[:180]
        if len(parsed) > 1 and name_hint:
            name = f"{name_hint} ({info['role']})"[:180]
        base, n = name, 2
        while session.execute(select(TrustedCa.id).where(TrustedCa.name == name)).first():
            name = f"{base} #{n}"[:200]
            n += 1
        row = TrustedCa(
            name=name, pem=info["pem"], fingerprint=info["fingerprint"],
            subject=info["subject"][:1000], issuer=info["issuer"][:1000],
            serial=info["serial"][:80], role=info["role"],
            not_before=info["not_before"], not_after=info["not_after"],
            is_enabled=True, note=(note or "")[:500],
            added_by_id=actor_id, added_by_label=(actor_label or "")[:255],
        )
        session.add(row)
        session.flush()
        out["imported"].append({"id": str(row.id), "name": row.name, "role": row.role})
    invalidate()
    return out


def _hex_colon(b: bytes) -> str:
    return ":".join(f"{x:02X}" for x in b)


def describe(pem: str) -> dict:
    """The decoded fields an operator compares against the CA they meant to
    import, plus the PEM. Public material only."""
    from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa

    cert = x509.load_pem_x509_certificate(pem.encode())
    der = cert.public_bytes(Encoding.DER)
    pk = cert.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        key = f"RSA {pk.key_size} bits"
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        key = f"EC {pk.curve.name} ({pk.key_size} bits)"
    elif isinstance(pk, ed25519.Ed25519PublicKey):
        key = "Ed25519"
    elif isinstance(pk, ed448.Ed448PublicKey):
        key = "Ed448"
    else:
        key = type(pk).__name__
    oid = cert.signature_algorithm_oid
    exts = []
    for ext in cert.extensions:
        v = ext.value
        if isinstance(v, x509.BasicConstraints):
            text = ("CA:TRUE" if v.ca else "CA:FALSE") + (
                f", pathlen:{v.path_length}" if v.path_length is not None else "")
        elif isinstance(v, x509.KeyUsage):
            names = ("digital_signature", "content_commitment", "key_encipherment",
                     "data_encipherment", "key_agreement", "key_cert_sign", "crl_sign")
            text = ", ".join(n for n in names if getattr(v, n))
        elif isinstance(v, x509.ExtendedKeyUsage):
            text = ", ".join(u._name or u.dotted_string for u in v)
        elif isinstance(v, x509.SubjectKeyIdentifier):
            text = _hex_colon(v.digest)
        elif isinstance(v, x509.AuthorityKeyIdentifier):
            text = _hex_colon(v.key_identifier) if v.key_identifier else "—"
        elif isinstance(v, x509.SubjectAlternativeName):
            text = ", ".join(str(n.value) for n in v)
        else:
            text = ""
        exts.append({"name": ext.oid._name or ext.oid.dotted_string,
                     "critical": bool(ext.critical), "value": text})
    return {
        "subject": _dn(cert.subject),
        "issuer": _dn(cert.issuer),
        "serial": _hex_colon(cert.serial_number.to_bytes(
            (cert.serial_number.bit_length() + 7) // 8 or 1, "big")),
        "not_before": cert.not_valid_before_utc.isoformat(),
        "not_after": cert.not_valid_after_utc.isoformat(),
        "public_key": key,
        "signature_algorithm": getattr(oid, "_name", "") or oid.dotted_string,
        "sha256": _hex_colon(hashlib.sha256(der).digest()),
        "sha1": _hex_colon(cert.fingerprint(hashes.SHA1())),  # noqa: S303 - display only
        "extensions": exts,
        "pem": cert.public_bytes(Encoding.PEM).decode("ascii"),
    }


# ---------------------------------------------------------------------------
# listing and health
# ---------------------------------------------------------------------------

def _public_root_subjects() -> frozenset[str]:
    """Subjects of the public roots (certifi), parsed once per process."""
    global _public_subjects
    if _public_subjects is None:
        # One certificate at a time: certifi ships a root with a non-positive
        # serial that newer `cryptography` refuses. Parsed as one bundle, that
        # single root would empty the whole set and every intermediate signed
        # by a public root would be reported as an incomplete chain.
        subjects: set[str] = set()
        try:
            with open(certifi.where(), "rb") as fh:
                blocks = fh.read().split(b"-----END CERTIFICATE-----")
        except OSError:
            blocks = []
        with warnings.catch_warnings():
            warnings.simplefilter("ignore")
            for block in blocks:
                if b"-----BEGIN CERTIFICATE-----" not in block:
                    continue
                try:
                    cert = x509.load_pem_x509_certificate(block + b"-----END CERTIFICATE-----\n")
                except Exception:  # noqa: BLE001
                    continue
                subjects.add(_dn(cert.subject))
        _public_subjects = frozenset(subjects)
    return _public_subjects


def chain_gaps(rows: list[TrustedCa]) -> list[dict]:
    """Enabled intermediates whose issuer is neither in the store nor a public
    root. Such a chain imports cleanly and then fails every handshake with
    "unable to get issuer certificate", which points at the server, not at
    the missing root."""
    enabled = [r for r in rows if r.is_enabled]
    subjects = {r.subject for r in enabled}
    public = _public_root_subjects()
    return [{"id": str(r.id), "name": r.name, "issuer": r.issuer}
            for r in enabled
            if r.role != ROLE_ROOT and r.issuer not in subjects and r.issuer not in public]


def _state(row: TrustedCa, now: dt.datetime) -> str:
    if row.not_after and row.not_after < now:
        return "expired"
    if row.not_before and row.not_before > now:
        return "not_yet_valid"
    if row.not_after and row.not_after < now + dt.timedelta(days=EXPIRY_WARNING_DAYS):
        return "expiring"
    return "valid"


def row_out(row: TrustedCa, now: dt.datetime | None = None) -> dict:
    now = now or dt.datetime.now(dt.timezone.utc)
    return {
        "id": str(row.id), "name": row.name, "role": row.role, "subject": row.subject,
        "issuer": row.issuer, "serial": row.serial, "fingerprint": row.fingerprint,
        "not_before": row.not_before.isoformat() if row.not_before else None,
        "not_after": row.not_after.isoformat() if row.not_after else None,
        "is_enabled": row.is_enabled, "note": row.note,
        "added_by": row.added_by_label or None,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "state": _state(row, now),
    }


def overview(session: Session) -> dict:
    rows = list(session.execute(
        select(TrustedCa).order_by(TrustedCa.role.desc(), TrustedCa.name)).scalars())
    now = dt.datetime.now(dt.timezone.utc)
    items = [row_out(r, now) for r in rows]
    enabled = [i for i in items if i["is_enabled"]]
    return {
        "items": items,
        "summary": {
            "total": len(items),
            "enabled": len(enabled),
            "roots": sum(1 for i in enabled if i["role"] == ROLE_ROOT),
            "intermediates": sum(1 for i in enabled if i["role"] == ROLE_INTERMEDIATE),
            "expired": sum(1 for i in enabled if i["state"] == "expired"),
            "expiring": sum(1 for i in enabled if i["state"] == "expiring"),
        },
        "gaps": chain_gaps(rows),
        "public_roots": len(_public_root_subjects()),
        "refresh_seconds": int(RESOLVE_TTL_S),
    }


# ---------------------------------------------------------------------------
# what the outbound clients use
# ---------------------------------------------------------------------------

def invalidate() -> None:
    """Make the next client on THIS node re-read the table. The other node
    picks the change up within RESOLVE_TTL_S."""
    global _resolved
    with _lock:
        _resolved = None
        _ctx_cache.clear()


def _read_enabled_pem() -> str | None:
    from ..db import SessionLocal  # local: keep model imports cheap for the CLI

    with SessionLocal() as session:
        pems = session.execute(
            select(TrustedCa.pem).where(TrustedCa.is_enabled.is_(True)).order_by(TrustedCa.fingerprint)
        ).scalars().all()
    if not pems:
        return None
    return "".join(p if p.endswith("\n") else p + "\n" for p in pems)


def extra_pem() -> str | None:
    """PEM of every enabled private CA, or ``None``. Never raises: a store
    that cannot be read means public roots only, never no verification."""
    global _resolved
    now = time.monotonic()
    cached = _resolved
    if cached is not None and (now - cached[0]) < RESOLVE_TTL_S:
        return cached[1]
    try:
        value = _read_enabled_pem()
    except Exception as exc:  # noqa: BLE001 - a broken store must not disable TLS
        log.warning("trust store unreadable, using public roots only: %s", exc)
        return None  # not cached: a transient failure must not stick
    with _lock:
        _resolved = (now, value)
    return value


def _build_context(extra: str) -> ssl.SSLContext:
    ctx = ssl.create_default_context()
    try:
        ctx.load_verify_locations(cafile=certifi.where())
    except (OSError, ssl.SSLError):
        pass
    if extra:
        try:
            ctx.load_verify_locations(cadata=extra)
        except (ssl.SSLError, ValueError) as exc:
            log.warning("trust store PEM rejected by OpenSSL, public roots only: %s", exc)
    return ctx


def ssl_context(verify: bool = True) -> ssl.SSLContext:
    """System roots + certifi + the enabled private CAs (``load_verify_locations``
    adds, it does not replace). ``verify=False`` is the operator's explicit
    "do not check" and is honoured."""
    if not verify:
        ctx = ssl.create_default_context()
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
        return ctx
    extra = extra_pem() or ""
    key = hashlib.sha256(extra.encode()).hexdigest()
    ctx = _ctx_cache.get(key)
    if ctx is not None:
        return ctx
    ctx = _build_context(extra)
    with _lock:
        _ctx_cache.clear()          # one live context per node: the current set
        _ctx_cache[key] = ctx
    return ctx


def httpx_verify(verify: bool = True) -> ssl.SSLContext | bool:
    """``verify=`` for httpx. ``False`` stays ``False``; with no private CA it
    is ``True`` (httpx's own certifi, unchanged behaviour); otherwise a
    context carrying the public roots plus the store."""
    if not verify:
        return False
    if not extra_pem():
        return True
    return ssl_context(True)


def ca_data() -> str | None:
    """For clients that take PEM text (ldap3 ``ca_certs_data``): certifi plus the
    private CAs, or ``None`` when there is nothing private to add. certifi is
    included because giving ldap3 CA data stops it loading the defaults."""
    extra = extra_pem()
    if not extra:
        return None
    try:
        with open(certifi.where(), encoding="ascii") as fh:
            public = fh.read()
    except OSError:
        public = ""
    return public + ("\n" if public and not public.endswith("\n") else "") + extra


# ---------------------------------------------------------------------------
# diagnosis
# ---------------------------------------------------------------------------

_HOST_RE = re.compile(r"^(?=.{1,253}$)[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
                      r"(?:\.[A-Za-z0-9](?:[A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)*\.?$")


def _check_target(host: str, port: int) -> str:
    host = (host or "").strip()
    if host.startswith("[") and host.endswith("]"):
        host = host[1:-1]
    try:
        ipaddress.ip_address(host)
    except ValueError:
        if not _HOST_RE.match(host):
            raise TrustStoreError("Enter a host name or an IP address, without scheme or path.") from None
    if not 1 <= int(port) <= 65535:
        raise TrustStoreError("The port must be between 1 and 65535.")
    return host


def _leaf_of(host: str, port: int, timeout: float) -> dict:
    """The certificate the server presents, read WITHOUT validating it.
    ``getpeercert()`` is empty under CERT_NONE, so parse the DER."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    with socket.create_connection((host, port), timeout=timeout) as sock:
        with ctx.wrap_socket(sock, server_hostname=host) as tls:
            der = tls.getpeercert(binary_form=True)
            proto, cipher = tls.version(), (tls.cipher() or ("", "", 0))[0]
    cert = x509.load_der_x509_certificate(der)
    info = _describe(cert)
    try:
        names = [str(n.value) for n in
                 cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value]
    except x509.ExtensionNotFound:
        names = []
    return {
        "subject": info["subject"], "issuer": info["issuer"],
        "common_name": info["common_name"], "self_signed": info["self_signed"],
        "sans": names, "not_before": info["not_before"].isoformat(),
        "not_after": info["not_after"].isoformat(), "fingerprint": info["fingerprint"],
        "protocol": proto, "cipher": cipher, "_not_after": info["not_after"],
    }


def _try_verify(host: str, port: int, timeout: float, check_hostname: bool) -> tuple[bool, str]:
    # Same anchors as the clients, but a private context: check_hostname must
    # never be flipped on the shared one the outbound clients are using.
    ctx = _build_context(extra_pem() or "")
    ctx.check_hostname = check_hostname
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=host):
                return True, ""
    except ssl.SSLCertVerificationError as exc:
        return False, (getattr(exc, "verify_message", "") or str(exc))
    except Exception as exc:  # noqa: BLE001
        return False, str(exc)


def probe(host: str, port: int = 443, timeout: float = 8.0) -> dict[str, Any]:
    """Diagnose one server's TLS against the CURRENT store, naming the cause:
    untrusted issuer, hostname mismatch, expired, or self-signed. The chain is
    tested with hostname checking off and on; the pair names the fix."""
    host = _check_target(host, port)
    port = int(port)
    res: dict[str, Any] = {"host": host, "port": port, "reachable": False, "leaf": None,
                           "chain_ok": False, "hostname_ok": False, "verified": False,
                           "reason": "", "advice": ""}
    try:
        leaf = _leaf_of(host, port, timeout)
        res["reachable"] = True
    except Exception as exc:  # noqa: BLE001
        res["reason"] = f"could not open a TLS connection: {exc}"
        res["advice"] = ("The server did not complete a TLS handshake. This is reachability, "
                         "not trust: check the host, the port and the firewall from this node.")
        return res
    not_after = leaf.pop("_not_after")
    res["leaf"] = leaf
    chain_ok, chain_err = _try_verify(host, port, timeout, False)
    res["chain_ok"] = chain_ok
    if chain_ok:
        name_ok, name_err = _try_verify(host, port, timeout, True)
        res["hostname_ok"] = res["verified"] = name_ok
        if name_ok:
            res["reason"] = "the certificate chain and the host name both verify"
            res["advice"] = "Connectors pointing at this address can keep TLS verification on."
        else:
            names = ", ".join(leaf["sans"]) or leaf["common_name"]
            res["reason"] = f"the chain is trusted but the host name does not match: {name_err}"
            res["advice"] = (f"The CA is trusted; only the name is wrong. The certificate covers: "
                             f"{names}. Point the connector at one of those names, or re-issue the "
                             f"certificate with '{host}' in its SAN.")
        return res
    if not_after < dt.datetime.now(dt.timezone.utc):
        res["reason"] = f"the server certificate expired on {not_after:%Y-%m-%d}"
        res["advice"] = "Re-issue the server certificate. Trusting a CA cannot rescue an expired leaf."
    elif leaf["self_signed"]:
        res["reason"] = "the server presents a SELF-SIGNED certificate: there is no CA to trust"
        res["advice"] = ("Nothing to import. Re-issue the server's certificate from your CA (then "
                         "import that CA here), or keep verification off for that connector.")
    else:
        res["reason"] = f"the issuer is not trusted: {chain_err or 'unable to get issuer certificate'}"
        res["advice"] = (f"Import the CA that signed it. The certificate names its issuer as: "
                         f"{leaf['issuer']}. Add that CA (and any intermediate above it), then test again.")
    return res
