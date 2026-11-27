"""The certificate VEYRS serves: request it here, have it signed anywhere,
install it on every app node.

The flow an operator follows (Configure -> Administration -> Platform -> Web
certificate):

1. **Request.** :func:`create_request` generates the private key HERE and a
   certificate signing request (CSR) for the names VEYRS answers to. The key is
   sealed immediately (`security.secrets`) and is never shown, downloaded or
   returned by any endpoint.
2. **Sign elsewhere.** The operator takes the CSR to their CA (corporate CA,
   public CA) and gets back the certificate and its chain.
3. **Attach.** :func:`attach_certificate` matches the certificate to the key by
   public key and runs every check (:func:`evaluate`). A certificate that fails
   a hard check is refused with the reason; nothing half-valid is stored.
4. **Install.** :func:`activate` marks it as THE certificate. Each app node's
   root installer (`veyrs tls-sync`, run by `veyrs-tls-sync.timer`) writes it
   for nginx, tests the configuration, reloads, connects to its own :443 and
   reports what it serves (:func:`sync_node`). The page shows each node.

A certificate and key issued elsewhere can also be brought in directly
(:func:`import_certificate`, PEM or PKCS#12) and go through the same checks.

Hard rules, each with its reason:

* **The chain must verify** against the public roots plus the installation
  trust store, for a name the certificate covers. Verification uses
  `cryptography.x509.verification` (RFC 5280 path building), not a home-made
  issuer comparison. A private CA's root goes into Trust store first; that is
  also what lets VEYRS check its own certificate later.
* **The API never touches the node.** It runs sandboxed (ProtectSystem=strict,
  NoNewPrivileges) and cannot write nginx's files or reload it; it only records
  the decision. The installer is a separate root unit, so a compromised API
  process cannot rewrite the web server configuration.
* **A failed install never leaves the node broken.** Files are swapped as a
  set, `nginx -t` runs before any reload, and a failing test restores the
  previous set. The node keeps serving what it served before and reports the
  error.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import logging
import os
import re
import shutil
import socket
import ssl
import subprocess
import uuid
import warnings
from pathlib import Path
from typing import Any, Callable

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed448, ed25519, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import select
from sqlalchemy.orm import Session

from ..models.trust import TrustedCa
from ..models.web_tls import (
    CERT_ACTIVE, CERT_PENDING, CERT_READY, CERT_RETIRED, InstallationSetting, WebCertificate,
    WebTlsNode,
)
from ..security import secrets

log = logging.getLogger(__name__)

KEY_TYPES = {
    "rsa-2048": "RSA 2048",
    "rsa-3072": "RSA 3072",
    "rsa-4096": "RSA 4096",
    "ec-p256": "ECDSA P-256",
    "ec-p384": "ECDSA P-384",
}
DEFAULT_KEY_TYPE = "rsa-3072"
EXPIRY_WARNING_DAYS = 30
#: Browsers refuse PUBLICLY trusted server certificates valid longer than this.
#: A private CA is not bound by it, so it is a warning, not a refusal.
PUBLIC_MAX_LIFETIME_DAYS = 398
#: A node that has not reported for this long is shown as "not reporting".
NODE_STALE_SECONDS = 180

POLICY_KEY = "web_tls"

DEFAULT_TLS_DIR = Path("/etc/veyrs/tls")
#: What every VEYRS nginx server block carries. A glob that matches nothing is
#: valid nginx, so the line ships in the vhosts before any certificate exists.
INCLUDE_GLOB = "nginx/*.conf"
MANAGED_FILES = ("server.crt", "server.key", "nginx/listen.conf", "nginx/redirect.conf")


class WebTlsError(ValueError):
    """Refused input or transition; the message is shown to the operator verbatim."""


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


# ---------------------------------------------------------------------------
# names
# ---------------------------------------------------------------------------

_LABEL = r"(?!-)[A-Za-z0-9-]{1,63}(?<!-)"
_DNS_RE = re.compile(rf"^(\*\.)?{_LABEL}(\.{_LABEL})+$")


def parse_names(common_name: str, extra: str | list[str] | None) -> list[str]:
    """The CN first, then every extra name, de-duplicated, validated.

    Accepts host names (one leading wildcard label allowed) and IP addresses.
    A single-label name ("veyrs") or a URL is refused: no CA will sign it for a
    browser, and it usually means the operator pasted the wrong thing."""
    raw = [common_name or ""]
    if isinstance(extra, str):
        raw += re.split(r"[\s,;]+", extra)
    elif extra:
        raw += list(extra)
    out: list[str] = []
    for item in raw:
        name = (item or "").strip().rstrip(".").lower()
        if not name:
            continue
        try:
            name = str(ipaddress.ip_address(name))
        except ValueError:
            if "://" in name or "/" in name:
                raise WebTlsError(f"{item!r} looks like a URL: enter only the host name.") from None
            if not _DNS_RE.match(name):
                raise WebTlsError(
                    f"{item!r} is not a valid host name (a fully qualified name such as "
                    "veyrs.example.com, optionally starting with '*.', or an IP address).")
        if name not in out:
            out.append(name)
    if not out:
        raise WebTlsError("Enter the host name VEYRS is reached at (the common name).")
    if len(out) > 100:
        raise WebTlsError("At most 100 names per certificate.")
    return out


def _general_name(name: str) -> x509.GeneralName:
    try:
        return x509.IPAddress(ipaddress.ip_address(name))
    except ValueError:
        return x509.DNSName(name)


def _cert_names(cert: x509.Certificate) -> list[str]:
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    except x509.ExtensionNotFound:
        return []
    names = [n.lower() for n in san.get_values_for_type(x509.DNSName)]
    names += [str(ip) for ip in san.get_values_for_type(x509.IPAddress)]
    return names


def name_covered(name: str, names: list[str]) -> bool:
    """RFC 6125 matching: exact, or one wildcard label at the left."""
    name = name.lower()
    if name in names:
        return True
    try:
        ipaddress.ip_address(name)
        return False                      # an IP is never matched by a wildcard
    except ValueError:
        pass
    head, _, rest = name.partition(".")
    return bool(rest) and f"*.{rest}" in names


# ---------------------------------------------------------------------------
# key and CSR
# ---------------------------------------------------------------------------

def _generate_key(key_type: str):
    if key_type not in KEY_TYPES:
        raise WebTlsError(f"Unknown key type {key_type!r}; choose one of {', '.join(KEY_TYPES)}.")
    if key_type.startswith("rsa-"):
        return rsa.generate_private_key(public_exponent=65537, key_size=int(key_type[4:]))
    return ec.generate_private_key(ec.SECP256R1() if key_type == "ec-p256" else ec.SECP384R1())


def _spki_fingerprint(public_key) -> str:
    der = public_key.public_bytes(serialization.Encoding.DER,
                                  serialization.PublicFormat.SubjectPublicKeyInfo)
    return hashlib.sha256(der).hexdigest()


def _key_type_of(key) -> str:
    if isinstance(key, rsa.RSAPrivateKey):
        return f"rsa-{key.key_size}"
    if isinstance(key, ec.EllipticCurvePrivateKey):
        return {"secp256r1": "ec-p256", "secp384r1": "ec-p384"}.get(key.curve.name, f"ec-{key.curve.name}")
    return type(key).__name__.lower()


def _key_pem(key) -> str:
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption()).decode("ascii")


SUBJECT_FIELDS = {
    "organization": NameOID.ORGANIZATION_NAME,
    "organizational_unit": NameOID.ORGANIZATIONAL_UNIT_NAME,
    "locality": NameOID.LOCALITY_NAME,
    "state": NameOID.STATE_OR_PROVINCE_NAME,
    "country": NameOID.COUNTRY_NAME,
}


def create_request(session: Session, *, common_name: str, extra_names: str | list[str] | None = None,
                   key_type: str = DEFAULT_KEY_TYPE, subject: dict[str, str] | None = None,
                   note: str = "", actor_id: uuid.UUID | None = None,
                   actor_label: str = "") -> WebCertificate:
    """Generate the key and the CSR. The key is sealed before the row exists."""
    names = parse_names(common_name, extra_names)
    fields: dict[str, str] = {}
    attrs = [x509.NameAttribute(NameOID.COMMON_NAME, names[0])]
    for field, oid in SUBJECT_FIELDS.items():
        value = ((subject or {}).get(field) or "").strip()
        if not value:
            continue
        if field == "country" and not re.fullmatch(r"[A-Za-z]{2}", value):
            raise WebTlsError("Country must be the two-letter ISO code (for example CH, MX, US).")
        if len(value) > 64:
            raise WebTlsError(f"{field.replace('_', ' ').title()} is longer than 64 characters.")
        value = value.upper() if field == "country" else value
        fields[field] = value
        attrs.append(x509.NameAttribute(oid, value))
    key = _generate_key(key_type)
    csr = (x509.CertificateSigningRequestBuilder()
           .subject_name(x509.Name(attrs))
           .add_extension(x509.SubjectAlternativeName([_general_name(n) for n in names]), critical=False)
           .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
           .sign(key, hashes.SHA256()))
    row = WebCertificate(
        status=CERT_PENDING, source="csr", common_name=names[0], requested_names=names,
        requested_subject=fields, key_type=key_type, key_sealed=secrets.encrypt(_key_pem(key)),
        key_fingerprint=_spki_fingerprint(key.public_key()),
        csr_pem=csr.public_bytes(serialization.Encoding.PEM).decode("ascii"),
        note=(note or "")[:500], created_by_id=actor_id, created_by_label=(actor_label or "")[:255],
    )
    session.add(row)
    session.flush()
    return row


# ---------------------------------------------------------------------------
# reading what the operator brings back
# ---------------------------------------------------------------------------

def _load_certs(blob: str | bytes | None) -> list[x509.Certificate]:
    if not blob:
        return []
    raw = blob.encode() if isinstance(blob, str) else bytes(blob)
    raw = raw.strip()
    if not raw:
        return []
    if b"-----BEGIN" in raw:
        if b"CERTIFICATE REQUEST" in raw and b"BEGIN CERTIFICATE-----" not in raw:
            raise WebTlsError("That is the certificate REQUEST (CSR), not the signed certificate. "
                              "Upload what the CA sent back.")
        try:
            return x509.load_pem_x509_certificates(raw)
        except Exception as exc:  # noqa: BLE001
            raise WebTlsError(f"Could not read the certificate PEM: {exc}") from None
    try:
        return [x509.load_der_x509_certificate(raw)]
    except Exception:  # noqa: BLE001
        raise WebTlsError("Not a certificate: expected PEM text ('-----BEGIN CERTIFICATE-----') "
                          "or a DER file.") from None


def _split_leaf(certs: list[x509.Certificate], key_fps: set[str]) -> tuple[x509.Certificate, list]:
    """The certificate whose public key is one of ours, and the rest as chain."""
    for i, cert in enumerate(certs):
        if _spki_fingerprint(cert.public_key()) in key_fps:
            return cert, certs[:i] + certs[i + 1:]
    raise WebTlsError("None of these certificates matches a key generated here. Upload the "
                      "certificate the CA issued for one of the pending requests (a certificate "
                      "issued for a different request, or a CA certificate alone, cannot match).")


def _anchors_and_intermediates(session: Session) -> tuple[list[x509.Certificate], list[x509.Certificate]]:
    """Public roots (certifi, parsed one by one) + the enabled trust-store CAs."""
    import certifi

    anchors: list[x509.Certificate] = []
    with open(certifi.where(), "rb") as fh:
        blocks = fh.read().split(b"-----END CERTIFICATE-----")
    with warnings.catch_warnings():
        warnings.simplefilter("ignore")      # certifi ships a root with a non-positive serial
        for block in blocks:
            if b"-----BEGIN CERTIFICATE-----" not in block:
                continue
            try:
                anchors.append(x509.load_pem_x509_certificate(block + b"-----END CERTIFICATE-----\n"))
            except Exception:  # noqa: BLE001 - one odd public root must not empty the store
                continue
    private = [x509.load_pem_x509_certificate(p.encode()) for p in session.execute(
        select(TrustedCa.pem).where(TrustedCa.is_enabled.is_(True))).scalars()]
    return anchors + private, private


def _fp(cert: x509.Certificate) -> str:
    return hashlib.sha256(cert.public_bytes(serialization.Encoding.DER)).hexdigest()


def _pem(cert: x509.Certificate) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode("ascii")


def evaluate(session: Session, leaf: x509.Certificate, chain: list[x509.Certificate],
             requested: list[str] | None = None, now: dt.datetime | None = None
             ) -> tuple[list[dict], list[x509.Certificate]]:
    """Every check, in the order an operator reads them. Returns (checks, the
    chain to serve). A check is {check, result: pass|warn|fail, detail}."""
    from cryptography.x509.verification import PolicyBuilder, Store, VerificationError

    now = now or _now()
    checks: list[dict] = []

    def add(check: str, result: str, detail: str) -> None:
        checks.append({"check": check, "result": result, "detail": detail})

    names = _cert_names(leaf)
    # 1. it is a server certificate
    try:
        is_ca = leaf.extensions.get_extension_for_class(x509.BasicConstraints).value.ca
    except x509.ExtensionNotFound:
        is_ca = False
    add("Server certificate", "fail" if is_ca else "pass",
        "This is a CA certificate. Upload the server certificate the CA issued; its CA belongs in "
        "Trust store." if is_ca else "Not a CA certificate.")
    try:
        eku = leaf.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
        server_ok = ExtendedKeyUsageOID.SERVER_AUTH in eku
        add("Extended key usage", "pass" if server_ok else "fail",
            "Includes TLS Web Server Authentication." if server_ok else
            "The certificate is not valid for TLS servers (no serverAuth): browsers refuse it. "
            "Ask the CA for a web server certificate (template 'Web Server' or equivalent).")
    except x509.ExtensionNotFound:
        add("Extended key usage", "pass", "Not restricted.")
    # 2. names
    if not names:
        add("Names (SAN)", "fail", "The certificate has no Subject Alternative Name. Browsers ignore the "
            "common name; a certificate without SAN is refused by every current browser.")
    else:
        missing = [n for n in (requested or []) if not name_covered(n, names)]
        if missing:
            add("Names (SAN)", "warn", f"Covers {', '.join(names)}. Requested but NOT covered: "
                f"{', '.join(missing)} - VEYRS reached at those names will show a certificate error.")
        else:
            add("Names (SAN)", "pass", f"Covers {', '.join(names)}.")
    # 3. validity
    nb, na = leaf.not_valid_before_utc, leaf.not_valid_after_utc
    if na <= now:
        add("Validity", "fail", f"Expired on {na:%Y-%m-%d %H:%M} UTC.")
    elif nb > now + dt.timedelta(minutes=5):
        add("Validity", "fail", f"Not valid before {nb:%Y-%m-%d %H:%M} UTC. Check the CA's clock or "
            "come back then.")
    else:
        days = (na - now).days
        lifetime = (na - nb).days
        if days < EXPIRY_WARNING_DAYS:
            add("Validity", "warn", f"Valid until {na:%Y-%m-%d} - only {days} days left.")
        elif lifetime > PUBLIC_MAX_LIFETIME_DAYS:
            add("Validity", "warn", f"Valid until {na:%Y-%m-%d} ({lifetime} days in total). Accepted from a "
                f"private CA; a PUBLIC CA certificate longer than {PUBLIC_MAX_LIFETIME_DAYS} days is "
                "refused by browsers.")
        else:
            add("Validity", "pass", f"Valid until {na:%Y-%m-%d} ({days} days left).")
    # 4. key and signature strength
    pk = leaf.public_key()
    if isinstance(pk, rsa.RSAPublicKey):
        add("Key", "pass" if pk.key_size >= 2048 else "fail",
            f"RSA {pk.key_size} bits" + ("" if pk.key_size >= 2048 else " - below the 2048-bit minimum."))
    elif isinstance(pk, ec.EllipticCurvePublicKey):
        good = pk.curve.name in ("secp256r1", "secp384r1", "secp521r1")
        add("Key", "pass" if good else "fail", f"ECDSA {pk.curve.name}" + (
            "" if good else " - browsers accept only P-256, P-384 and P-521."))
    elif isinstance(pk, (ed25519.Ed25519PublicKey, ed448.Ed448PublicKey)):
        add("Key", "fail", "Ed25519/Ed448 server certificates are not accepted by browsers.")
    else:
        add("Key", "fail", f"Unsupported key type {type(pk).__name__}.")
    algo = leaf.signature_hash_algorithm
    weak = algo is None or algo.name in ("md5", "sha1")
    add("Signature", "fail" if weak else "pass",
        f"Signed with {algo.name.upper() if algo else 'an unknown hash'}" + (
            " - browsers reject it; ask the CA to sign with SHA-256 or better." if weak else "."))
    # 5. chain of trust
    served: list[x509.Certificate] = [leaf] + [c for c in chain if c.subject != c.issuer]
    anchors, private = _anchors_and_intermediates(session)
    subject = next((n for n in names if not n.startswith("*.")), None) or (names[0][2:] if names else None)
    if subject is None:
        add("Chain of trust", "fail", "Cannot verify a certificate without names.")
    else:
        if subject.startswith("*."):
            subject = "veyrs-check." + subject[2:]
        try:
            target: x509.GeneralName
            try:
                target = x509.IPAddress(ipaddress.ip_address(subject))
            except ValueError:
                target = x509.DNSName(subject)
            verifier = (PolicyBuilder().store(Store(anchors)).time(now.replace(tzinfo=None))
                        .build_server_verifier(target))
            path = verifier.verify(leaf, chain + private)
            served = [c for c in path if c.subject != c.issuer]
            root = path[-1]
            via_store = any(_fp(root) == _fp(p) for p in private)
            add("Chain of trust", "pass",
                f"Verifies up to {root.subject.rfc4514_string()}" +
                (" (from Trust store)." if via_store else " (a public root)."))
        except VerificationError as exc:
            issuer = leaf.issuer.rfc4514_string()
            add("Chain of trust", "fail",
                f"Does not verify: {exc}. Issuer: {issuer}. If this is your company CA, import its "
                "root (and any intermediate) in Configure > Platform > Trust store, or upload "
                "the certificate together with its full chain.")
        except Exception as exc:  # noqa: BLE001
            add("Chain of trust", "fail", f"Could not be checked: {exc}")
    return checks, served


def _failed(checks: list[dict]) -> list[dict]:
    return [c for c in checks if c["result"] == "fail"]


def _record_cert(row: WebCertificate, leaf: x509.Certificate, served: list[x509.Certificate],
                 checks: list[dict]) -> None:
    row.cert_pem = _pem(leaf)
    row.chain_pem = "".join(_pem(c) for c in served[1:]) or None
    row.cert_fingerprint = _fp(leaf)
    row.subject = leaf.subject.rfc4514_string()[:1000]
    row.issuer = leaf.issuer.rfc4514_string()[:1000]
    row.serial = format(leaf.serial_number, "x")[:80]
    row.names = _cert_names(leaf)
    row.not_before, row.not_after = leaf.not_valid_before_utc, leaf.not_valid_after_utc
    row.checks = checks
    row.status = CERT_READY


def attach_certificate(session: Session, blob: str | bytes, chain_blob: str | bytes | None = None,
                       request_id: uuid.UUID | None = None) -> tuple[WebCertificate, list[dict]]:
    """Attach the CA's answer to the pending request it belongs to.

    `blob` may already carry the chain (leaf + intermediates in one file, the
    usual "fullchain"); `chain_blob` adds more. Refused, with every check,
    when a hard check fails -- nothing is stored then."""
    certs = _load_certs(blob) + _load_certs(chain_blob)
    if not certs:
        raise WebTlsError("Upload the signed certificate (PEM or DER).")
    q = select(WebCertificate).where(WebCertificate.status == CERT_PENDING)
    if request_id is not None:
        q = q.where(WebCertificate.id == request_id)
    pending = list(session.execute(q).scalars())
    if not pending:
        raise WebTlsError("There is no pending request to attach a certificate to. Create a "
                          "request first, or use 'Import certificate and key'.")
    by_fp = {r.key_fingerprint: r for r in pending}
    leaf, chain = _split_leaf(certs, set(by_fp))
    row = by_fp[_spki_fingerprint(leaf.public_key())]
    checks, served = evaluate(session, leaf, chain, row.requested_names)
    if _failed(checks):
        raise CertificateRefused(checks)
    _record_cert(row, leaf, served, checks)
    return row, checks


class CertificateRefused(WebTlsError):
    def __init__(self, checks: list[dict]):
        self.checks = checks
        reasons = "; ".join(f"{c['check']}: {c['detail']}" for c in _failed(checks))
        super().__init__(f"The certificate was not accepted. {reasons}")


def _load_private_key(blob: str | bytes, passphrase: str | None):
    raw = blob.encode() if isinstance(blob, str) else bytes(blob)
    pw = passphrase.encode() if passphrase else None
    try:
        return serialization.load_pem_private_key(raw.strip(), password=pw)
    except TypeError:
        raise WebTlsError("The private key is encrypted: enter its passphrase.") from None
    except ValueError as exc:
        msg = str(exc)
        if "password" in msg.lower() or "decrypt" in msg.lower():
            raise WebTlsError("The passphrase does not open this private key.") from None
        raise WebTlsError("Could not read the private key (expected PEM, '-----BEGIN ... PRIVATE KEY-----').") from None


def import_certificate(session: Session, *, certificate: str | bytes | None = None,
                       private_key: str | bytes | None = None, chain: str | bytes | None = None,
                       pkcs12_data: bytes | None = None, passphrase: str | None = None,
                       note: str = "", actor_id: uuid.UUID | None = None,
                       actor_label: str = "") -> tuple[WebCertificate, list[dict]]:
    """A certificate AND its key issued elsewhere (PEM pair or PKCS#12).

    Prefer a request generated here: then the key was never anywhere else. This
    path exists for certificates an organization already has."""
    if pkcs12_data:
        try:
            key, cert, extra = pkcs12.load_key_and_certificates(
                pkcs12_data, passphrase.encode() if passphrase else None)
        except ValueError:
            raise WebTlsError("Could not open the PKCS#12 file: wrong passphrase or not a PKCS#12 "
                              "(.pfx/.p12) file.") from None
        if key is None or cert is None:
            raise WebTlsError("The PKCS#12 file must contain the certificate AND its private key.")
        certs = [cert] + list(extra or []) + _load_certs(chain)
    else:
        if not certificate or not private_key:
            raise WebTlsError("Provide the certificate and its private key (or a PKCS#12 file).")
        key = _load_private_key(private_key, passphrase)
        certs = _load_certs(certificate) + _load_certs(chain)
    if not isinstance(key, (rsa.RSAPrivateKey, ec.EllipticCurvePrivateKey)):
        raise WebTlsError("Only RSA and ECDSA keys can serve browsers.")
    kfp = _spki_fingerprint(key.public_key())
    leaf, rest = _split_leaf(certs, {kfp})
    if session.execute(select(WebCertificate.id).where(
            WebCertificate.cert_fingerprint == _fp(leaf))).first():
        raise WebTlsError("This certificate is already here.")
    names = _cert_names(leaf)
    checks, served = evaluate(session, leaf, rest, names)
    if _failed(checks):
        raise CertificateRefused(checks)
    cn = leaf.subject.get_attributes_for_oid(NameOID.COMMON_NAME)
    row = WebCertificate(
        status=CERT_READY, source="imported",
        common_name=(str(cn[0].value) if cn else (names[0] if names else "certificate"))[:255],
        requested_names=names, requested_subject={}, key_type=_key_type_of(key),
        key_sealed=secrets.encrypt(_key_pem(key)), key_fingerprint=kfp, csr_pem=None,
        note=(note or "")[:500], created_by_id=actor_id, created_by_label=(actor_label or "")[:255],
    )
    _record_cert(row, leaf, served, checks)
    session.add(row)
    session.flush()
    return row, checks


# ---------------------------------------------------------------------------
# transitions
# ---------------------------------------------------------------------------

def get(session: Session, cert_id: uuid.UUID) -> WebCertificate:
    row = session.get(WebCertificate, cert_id)
    if row is None:
        raise LookupError("no such certificate")
    return row


def active(session: Session) -> WebCertificate | None:
    return session.execute(select(WebCertificate).where(
        WebCertificate.status == CERT_ACTIVE)).scalar_one_or_none()


def activate(session: Session, cert_id: uuid.UUID, actor_label: str = "") -> tuple[WebCertificate, WebCertificate | None]:
    """Make `cert_id` THE served certificate. Re-checked now: a certificate that
    was fine when attached may have expired, or its CA may have been removed
    from the trust store since."""
    row = get(session, cert_id)
    if row.status not in (CERT_READY, CERT_RETIRED):
        raise WebTlsError("Only a certificate that came back from the CA (ready) or a previous one "
                          "(retired) can be installed.")
    leaf = x509.load_pem_x509_certificate(row.cert_pem.encode())
    chain = _load_certs(row.chain_pem)
    checks, served = evaluate(session, leaf, chain, row.requested_names)
    if _failed(checks):
        row.checks = checks
        raise CertificateRefused(checks)
    previous = active(session)
    if previous is not None and previous.id != row.id:
        previous.status = CERT_RETIRED
        session.flush()
    row.checks = checks
    row.chain_pem = "".join(_pem(c) for c in served[1:]) or None
    row.status = CERT_ACTIVE
    row.activated_at = _now()
    row.activated_by_label = (actor_label or "")[:255]
    session.flush()
    return row, previous


def deactivate(session: Session) -> WebCertificate | None:
    """Stop serving HTTPS from the nodes (the certificate is kept as retired)."""
    row = active(session)
    if row is not None:
        row.status = CERT_RETIRED
        session.flush()
    return row


def discard(session: Session, cert_id: uuid.UUID) -> WebCertificate:
    row = get(session, cert_id)
    if row.status == CERT_ACTIVE:
        raise WebTlsError("This certificate is being served. Install another one or stop HTTPS first.")
    session.delete(row)
    session.flush()
    return row


def policy(session: Session) -> dict:
    row = session.get(InstallationSetting, POLICY_KEY)
    value = dict(row.value) if row else {}
    return {"redirect_http": bool(value.get("redirect_http", False))}


def set_policy(session: Session, *, redirect_http: bool, actor_label: str = "") -> dict:
    row = session.get(InstallationSetting, POLICY_KEY)
    if row is None:
        row = InstallationSetting(key=POLICY_KEY, value={})
        session.add(row)
    row.value = {**(row.value or {}), "redirect_http": bool(redirect_http)}
    row.updated_at = _now()
    row.updated_by_label = (actor_label or "")[:255]
    session.flush()
    return policy(session)


# ---------------------------------------------------------------------------
# what the console reads
# ---------------------------------------------------------------------------

def _iso(v: dt.datetime | None) -> str | None:
    return v.isoformat() if v else None


def cert_out(row: WebCertificate, now: dt.datetime | None = None) -> dict:
    now = now or _now()
    days = (row.not_after - now).days if row.not_after else None
    return {
        "id": str(row.id), "status": row.status, "source": row.source,
        "common_name": row.common_name, "requested_names": row.requested_names,
        "requested_subject": row.requested_subject, "key_type": row.key_type,
        "key_label": KEY_TYPES.get(row.key_type, row.key_type),
        "csr_pem": row.csr_pem, "has_certificate": bool(row.cert_pem),
        "subject": row.subject, "issuer": row.issuer, "serial": row.serial,
        "names": row.names, "fingerprint": row.cert_fingerprint,
        "not_before": _iso(row.not_before), "not_after": _iso(row.not_after),
        "days_left": days,
        "expiry": (None if days is None else "expired" if days < 0 else
                   "expiring" if days < EXPIRY_WARNING_DAYS else "valid"),
        "checks": row.checks, "note": row.note, "created_by": row.created_by_label or None,
        "created_at": _iso(row.created_at), "activated_at": _iso(row.activated_at),
        "activated_by": row.activated_by_label,
    }


def node_out(n: WebTlsNode, desired: str | None, now: dt.datetime) -> dict:
    stale = n.checked_at is None or (now - n.checked_at).total_seconds() > NODE_STALE_SECONDS
    in_sync = (n.desired_fingerprint == desired) and (
        desired is None or n.served_fingerprint == desired)
    return {
        "node": n.node, "state": "not_reporting" if stale else n.state, "reported_state": n.state,
        "detail": n.detail, "served_fingerprint": n.served_fingerprint, "in_sync": in_sync and not stale,
        "redirect_http": n.redirect_http, "nginx_version": n.nginx_version,
        "checked_at": _iso(n.checked_at), "applied_at": _iso(n.applied_at),
    }


def overview(session: Session) -> dict:
    now = _now()
    rows = list(session.execute(select(WebCertificate).order_by(WebCertificate.created_at.desc())).scalars())
    act = next((r for r in rows if r.status == CERT_ACTIVE), None)
    desired = act.cert_fingerprint if act else None
    nodes = [node_out(n, desired, now) for n in session.execute(
        select(WebTlsNode).order_by(WebTlsNode.node)).scalars()]
    return {
        "active": cert_out(act, now) if act else None,
        "pending": [cert_out(r, now) for r in rows if r.status == CERT_PENDING],
        "ready": [cert_out(r, now) for r in rows if r.status == CERT_READY],
        "retired": [cert_out(r, now) for r in rows if r.status == CERT_RETIRED],
        "nodes": nodes,
        "policy": policy(session),
        "key_types": [{"value": k, "label": v} for k, v in KEY_TYPES.items()],
        "default_key_type": DEFAULT_KEY_TYPE,
        "stale_seconds": NODE_STALE_SECONDS,
    }


# ---------------------------------------------------------------------------
# the node installer (root; `veyrs tls-sync`)
# ---------------------------------------------------------------------------

LISTEN_CONF = """\
# Managed by VEYRS (`veyrs tls-sync`, veyrs-tls-sync.timer). Rewritten from the
# database every cycle: change the certificate in the console, not here.
listen {listen} ssl http2;
ssl_certificate     {dir}/server.crt;
ssl_certificate_key {dir}/server.key;
ssl_protocols TLSv1.2 TLSv1.3;
ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305;
ssl_prefer_server_ciphers off;
ssl_session_timeout 1d;
ssl_session_cache shared:VEYRS_TLS:10m;
ssl_session_tickets off;
"""

# Health probes and the metrics scrape stay on plain HTTP: load balancers and
# monitoring reach them there (the scrape by IP, which no certificate names),
# and a 301 would mark every node down at once.
REDIRECT_CONF = """\
# Managed by VEYRS (`veyrs tls-sync`). HTTP -> HTTPS, except probes and metrics.
set $veyrs_to_https "";
if ($scheme = http) { set $veyrs_to_https "1"; }
if ($uri ~ "^/(healthz|readyz|metrics)$") { set $veyrs_to_https ""; }
if ($veyrs_to_https = "1") { return 301 https://$host$request_uri; }
"""


def _key_on_disk_matches(path: Path, fingerprint: str) -> bytes | None:
    """The key file's bytes when it already holds the key with `fingerprint`."""
    try:
        raw = path.read_bytes()
        key = serialization.load_pem_private_key(raw, password=None)
    except (OSError, ValueError, TypeError):
        return None
    return raw if _spki_fingerprint(key.public_key()) == fingerprint else None


def render(row: WebCertificate | None, pol: dict, tls_dir: Path,
           listen: str = "443") -> dict[str, tuple[bytes, int]]:
    """The managed files for this state: relative path -> (content, mode).

    The sealed key is opened only when the node does not already hold it (in
    vault mode every unseal is a vault read, and this runs every 30 seconds)."""
    if row is None:
        return {}
    key_bytes = _key_on_disk_matches(tls_dir / "server.key", row.key_fingerprint)
    if key_bytes is None:
        key_pem = secrets.decrypt(row.key_sealed)
        if not key_pem:
            raise RuntimeError("the private key of the active certificate cannot be unsealed")
        key_bytes = key_pem.encode()
    files = {
        "server.crt": ((row.cert_pem + (row.chain_pem or "")).encode(), 0o644),
        "server.key": (key_bytes, 0o600),
        "nginx/listen.conf": (LISTEN_CONF.format(dir=str(tls_dir), listen=listen).encode(), 0o644),
    }
    if pol.get("redirect_http"):
        files["nginx/redirect.conf"] = (REDIRECT_CONF.encode(), 0o644)
    return files


def _read_current(tls_dir: Path) -> dict[str, bytes]:
    out = {}
    for rel in MANAGED_FILES:
        p = tls_dir / rel
        if p.is_file():
            out[rel] = p.read_bytes()
    return out


def _swap_in(tls_dir: Path, desired: dict[str, tuple[bytes, int]]) -> Path:
    """Write the desired set; return the backup dir holding the previous set."""
    backup = tls_dir / ".previous"
    if backup.exists():
        shutil.rmtree(backup)
    (backup / "nginx").mkdir(parents=True, mode=0o700)
    (tls_dir / "nginx").mkdir(parents=True, exist_ok=True, mode=0o755)
    for rel in MANAGED_FILES:
        cur = tls_dir / rel
        if cur.exists():
            shutil.copy2(cur, backup / rel)
    for rel in MANAGED_FILES:
        target = tls_dir / rel
        if rel in desired:
            content, mode = desired[rel]
            tmp = target.with_name("." + target.name + ".tmp")
            fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, mode)
            with os.fdopen(fd, "wb") as fh:
                fh.write(content)
            os.chmod(tmp, mode)
            os.replace(tmp, target)
        elif target.exists():
            target.unlink()
    return backup


def _restore(tls_dir: Path, backup: Path) -> None:
    for rel in MANAGED_FILES:
        target, saved = tls_dir / rel, backup / rel
        if saved.exists():
            shutil.copy2(saved, target)
        elif target.exists():
            target.unlink()


def _run(cmd: list[str], timeout: int = 30) -> tuple[int, str]:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)  # noqa: S603
        return p.returncode, (p.stdout + p.stderr).strip()
    except FileNotFoundError:
        return 127, f"{cmd[0]}: not found"
    except subprocess.TimeoutExpired:
        return 124, f"{' '.join(cmd)}: timed out"


def served_fingerprint(sni: str | None, port: int = 443, host: str = "127.0.0.1",
                       timeout: float = 5.0) -> str | None:
    """SHA-256 of the certificate this node's :443 presents for `sni`."""
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((host, port), timeout=timeout) as sock:
            with ctx.wrap_socket(sock, server_hostname=sni) as tls:
                der = tls.getpeercert(binary_form=True)
    except OSError:
        return None
    return hashlib.sha256(der).hexdigest() if der else None


def sync_node(*, tls_dir: Path = DEFAULT_TLS_DIR, node: str | None = None,
              nginx: list[str] | None = None, reload: list[str] | None = None,
              probe: Callable[[str | None], str | None] = served_fingerprint,
              listen: str = "443",
              session_factory: Callable[[], Session] | None = None) -> dict[str, Any]:
    """Make THIS node serve what the database says, then report it.

    Idempotent and cheap when nothing changed (one query, a few file reads,
    one handshake). Never leaves the node with a configuration nginx refuses:
    `nginx -t` runs before the reload and a failure restores the previous files.
    """
    from ..db import SessionLocal

    nginx = nginx or ["nginx"]
    reload = reload or ["systemctl", "reload", "nginx"]
    node = node or socket.gethostname()
    factory = session_factory or SessionLocal
    now = _now()
    with factory() as session:
        row = active(session)
        pol = policy(session)
        desired_fp = row.cert_fingerprint if row else None
        sni = None
        if row:
            sni = next((n for n in (row.names or []) if not n.startswith("*.")), None)
            try:
                ipaddress.ip_address(sni or "")
                sni = None                    # no SNI for an IP address
            except ValueError:
                pass
        desired = render(row, pol, tls_dir, listen)
    tls_dir.mkdir(parents=True, exist_ok=True, mode=0o750)
    current = _read_current(tls_dir)
    want = {k: v[0] for k, v in desired.items()}
    state, detail, applied_now, served = "", "", False, None
    _rc, version = _run(nginx + ["-v"])
    version = (version.split("/")[-1] if "/" in version else version)[:64]

    if want != current:
        backup = _swap_in(tls_dir, desired)
        rc, out = _run(nginx + ["-t"])
        if rc != 0:
            _restore(tls_dir, backup)
            state, detail = "error", ("nginx refused the new configuration; the previous files were "
                                      "restored and nothing was reloaded. nginx -t said: " + out[-800:])
        else:
            rc, out = _run(reload)
            if rc != 0:
                _restore(tls_dir, backup)
                _run(nginx + ["-t"])
                state, detail = "error", "nginx reload failed; previous files restored: " + out[-800:]
            else:
                applied_now = True
    if not state:
        rc, dump = _run(nginx + ["-T"])
        included = rc == 0 and str(tls_dir / INCLUDE_GLOB) in dump
        if row is None:
            state = "off"
            detail = ("No certificate is installed: this node serves HTTP only." if included else
                      "No certificate is installed, and this node's nginx does not include "
                      f"{tls_dir / INCLUDE_GLOB} yet (needed before one can be served).")
        elif not included:
            state = "not_configured"
            detail = (f"The certificate files are in {tls_dir}, but no VEYRS server block includes "
                      f"them. Add `include {tls_dir / INCLUDE_GLOB};` to each VEYRS server block "
                      "(console, documentation, product site), then `nginx -t && systemctl reload nginx`.")
        else:
            served = probe(sni)
            if served == desired_fp:
                state, detail = "applied", f"Serving the certificate on :443 (checked {now:%H:%M:%S} UTC)."
            elif served is None:
                state, detail = "error", "Nothing answers TLS on 127.0.0.1:443 after the reload."
            else:
                state, detail = "error", (f"Port 443 answers with a different certificate "
                                          f"({served[:16]}...). Another server block or process owns :443.")
    with factory() as session:
        n = session.get(WebTlsNode, node)
        if n is None:
            n = WebTlsNode(node=node)
            session.add(n)
        prev_state = n.state
        n.state, n.detail = state, detail[:4000]
        n.desired_fingerprint = desired_fp
        n.served_fingerprint = served
        n.redirect_http = bool(pol.get("redirect_http")) and row is not None
        n.nginx_version = version or None
        n.checked_at = now
        if applied_now or (state == "applied" and prev_state != "applied"):
            n.applied_at = now
        session.commit()
    if state in ("error", "not_configured"):
        log.warning("tls-sync %s: %s - %s", node, state, detail)
    return {"node": node, "state": state, "detail": detail, "changed": applied_now}


def run_cli(args) -> int:
    """`veyrs tls-sync` -- root only, run by veyrs-tls-sync.timer."""
    tls_dir = Path(getattr(args, "tls_dir", None) or DEFAULT_TLS_DIR)
    if os.geteuid() != 0 and not getattr(args, "allow_non_root", False):
        print("veyrs tls-sync must run as root (it writes nginx's files and reloads nginx); "
              "it is run by veyrs-tls-sync.timer.")
        return 2
    res = sync_node(tls_dir=tls_dir)
    print(f"{res['node']}: {res['state']} - {res['detail']}")
    return 0 if res["state"] in ("applied", "off") else 1
