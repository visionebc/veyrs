"""0.40.0 -- TLS trust store: the CAs this installation accepts when it connects out.

Covers the service (parse, import, chain gaps, the verification context every
outbound client uses, the never-downgrade rule), the platform-admin API, a
real TLS handshake against a local server signed by a throwaway CA, and a
static guard that every module opening outbound TLS goes through the store.
"""
from __future__ import annotations

import ast
import datetime as dt
import ipaddress
import socket
import ssl
import threading
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID
from sqlalchemy import delete, select

from tests.conftest import auth_headers
from veyrs.db import SessionLocal, set_tenant
from veyrs.models import GLOBAL_TABLES, TrustedCa, User
from veyrs.models.audit import AuditLog
from veyrs.services import trust_store as ts

ROOT = Path(__file__).resolve().parents[1]
PKG = ROOT / "backend" / "veyrs"


# ---------------------------------------------------------------------------
# a throwaway PKI
# ---------------------------------------------------------------------------

def _name(cn: str) -> x509.Name:
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VEYRS test PKI")])


def _cert(subject_cn, key, issuer_cert=None, issuer_key=None, *, ca=False, sans=(), days=30,
          not_before=None):
    now = not_before or (dt.datetime.now(dt.timezone.utc) - dt.timedelta(minutes=5))
    issuer_name = issuer_cert.subject if issuer_cert is not None else _name(subject_cn)
    b = (x509.CertificateBuilder().subject_name(_name(subject_cn)).issuer_name(issuer_name)
         .public_key(key.public_key()).serial_number(x509.random_serial_number())
         .not_valid_before(now).not_valid_after(now + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True))
    if ca:
        b = b.add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                          key_encipherment=False, data_encipherment=False,
                                          key_agreement=False, key_cert_sign=True, crl_sign=True,
                                          encipher_only=False, decipher_only=False), critical=True)
    if sans:
        b = b.add_extension(x509.SubjectAlternativeName(list(sans)), critical=False)
    return b.sign(issuer_key or key, hashes.SHA256())


def _pem(cert) -> str:
    return cert.public_bytes(serialization.Encoding.PEM).decode()


@pytest.fixture(scope="module")
def pki():
    rk, ik, lk = (ec.generate_private_key(ec.SECP256R1()) for _ in range(3))
    root = _cert("Test Root CA", rk, ca=True)
    inter = _cert("Test Issuing CA", ik, root, rk, ca=True)
    leaf = _cert("localhost", lk, inter, ik,
                 sans=[x509.DNSName("localhost"), x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    sk = ec.generate_private_key(ec.SECP256R1())
    selfsigned = _cert("self.test", sk, sans=[x509.IPAddress(ipaddress.ip_address("127.0.0.1"))])
    return {"root": root, "inter": inter, "leaf": leaf, "leaf_key": lk,
            "self": selfsigned, "self_key": sk}


@pytest.fixture(autouse=True)
def _clean_store():
    """The store is installation-wide: every test starts and ends with it empty."""
    def wipe():
        with SessionLocal() as s:
            s.execute(delete(TrustedCa))
            s.commit()
        ts.invalidate()
    wipe()
    yield
    wipe()


def _import(*certs, name=""):
    with SessionLocal() as s:
        out = ts.import_pem(s, "".join(_pem(c) for c in certs), name_hint=name)
        s.commit()
    ts.invalidate()
    return out


# ---------------------------------------------------------------------------
# model / schema
# ---------------------------------------------------------------------------

def test_the_table_is_installation_wide():
    assert "trusted_cas" in GLOBAL_TABLES
    assert "organization_id" not in TrustedCa.__table__.c


# ---------------------------------------------------------------------------
# import
# ---------------------------------------------------------------------------

def test_a_chain_imports_both_cas_and_reimport_updates_in_place(pki):
    out = _import(pki["root"], pki["inter"])
    assert {i["role"] for i in out["imported"]} == {"root", "intermediate"}
    again = _import(pki["root"])
    assert not again["imported"] and len(again["updated"]) == 1
    with SessionLocal() as s:
        assert s.execute(select(TrustedCa)).scalars().all().__len__() == 2


def test_a_leaf_is_rejected_with_the_reason_and_the_cas_in_the_paste_still_land(pki):
    out = _import(pki["leaf"], pki["inter"], pki["root"])
    assert len(out["imported"]) == 2
    assert [r["name"] for r in out["rejected"]] == ["localhost"]
    assert "not a CA" in out["rejected"][0]["reason"]


def test_garbage_is_refused_with_a_readable_message():
    with SessionLocal() as s, pytest.raises(ts.TrustStoreError, match="Not a certificate"):
        ts.import_pem(s, b"\x00\x01 definitely not der")
    with SessionLocal() as s, pytest.raises(ts.TrustStoreError, match="Nothing to import"):
        ts.import_pem(s, "   ")


def test_an_intermediate_without_its_root_is_reported_as_a_gap(pki):
    _import(pki["inter"])
    with SessionLocal() as s:
        gaps = ts.overview(s)["gaps"]
    assert [g["name"] for g in gaps] == ["Test Issuing CA"]
    _import(pki["root"])
    with SessionLocal() as s:
        assert ts.overview(s)["gaps"] == []


# ---------------------------------------------------------------------------
# what the clients receive
# ---------------------------------------------------------------------------

def _subjects(ctx: ssl.SSLContext) -> set[str]:
    out = set()
    for c in ctx.get_ca_certs():
        for rdn in c.get("subject", ()):
            for k, v in rdn:
                if k == "commonName":
                    out.add(v)
    return out


def test_no_private_ca_leaves_httpx_on_its_own_roots_and_off_stays_off(pki):
    assert ts.httpx_verify() is True
    assert ts.httpx_verify(False) is False
    assert ts.ca_data() is None
    _import(pki["root"])
    assert ts.httpx_verify(False) is False      # the operator's "do not verify" is honoured


def test_an_enabled_ca_is_added_to_the_public_roots_not_substituted(pki):
    _import(pki["root"])
    ctx = ts.httpx_verify()
    assert isinstance(ctx, ssl.SSLContext)
    names = _subjects(ctx)
    assert "Test Root CA" in names
    assert len(names) > 50, "the public roots must still be there"
    data = ts.ca_data()
    assert data and data.count("BEGIN CERTIFICATE") > 50 and _pem(pki["root"]).strip() in data


def test_a_disabled_ca_leaves_every_client(pki):
    _import(pki["root"])
    with SessionLocal() as s:
        s.execute(select(TrustedCa)).scalar_one().is_enabled = False
        s.commit()
    ts.invalidate()
    assert ts.httpx_verify() is True


def test_an_unreadable_store_never_turns_verification_off(monkeypatch):
    def broken():
        raise RuntimeError("database is down")
    monkeypatch.setattr(ts, "_read_enabled_pem", broken)
    ts.invalidate()
    assert ts.httpx_verify() is True
    assert ts.ssl_context().verify_mode == ssl.CERT_REQUIRED


# ---------------------------------------------------------------------------
# a real handshake
# ---------------------------------------------------------------------------

@pytest.fixture()
def tls_server(pki, tmp_path):
    """A TLS server on 127.0.0.1 presenting `leaf` (+ its intermediate) or the self-signed cert."""
    servers = []

    def start(which="leaf"):
        cert, key = (pki["leaf"], pki["leaf_key"]) if which == "leaf" else (pki["self"], pki["self_key"])
        chain = _pem(cert) + (_pem(pki["inter"]) if which == "leaf" else "")
        cf, kf = tmp_path / f"{which}.crt", tmp_path / f"{which}.key"
        cf.write_text(chain)
        kf.write_bytes(key.private_bytes(serialization.Encoding.PEM,
                                         serialization.PrivateFormat.PKCS8,
                                         serialization.NoEncryption()))
        sctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        sctx.load_cert_chain(cf, kf)
        sock = socket.create_server(("127.0.0.1", 0))
        sock.settimeout(10)
        stop = threading.Event()

        def serve():
            while not stop.is_set():
                try:
                    conn, _ = sock.accept()
                except OSError:
                    return
                try:
                    with sctx.wrap_socket(conn, server_side=True) as t:
                        t.recv(1)
                except (OSError, ssl.SSLError):
                    pass

        th = threading.Thread(target=serve, daemon=True)
        th.start()
        servers.append((sock, stop))
        return sock.getsockname()[1]

    yield start
    for sock, stop in servers:
        stop.set()
        sock.close()


def test_probe_names_the_untrusted_issuer_then_verifies_once_the_ca_is_imported(pki, tls_server):
    port = tls_server("leaf")
    before = ts.probe("127.0.0.1", port, timeout=5)
    assert before["reachable"] and not before["chain_ok"]
    assert "issuer is not trusted" in before["reason"]
    assert "Test Issuing CA" in before["advice"]

    _import(pki["root"])
    after = ts.probe("127.0.0.1", port, timeout=5)
    assert after["chain_ok"] and after["hostname_ok"] and after["verified"], after

    # and the context the outbound clients use completes the same handshake
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with ts.ssl_context().wrap_socket(raw, server_hostname="127.0.0.1") as t:
            assert t.version()


def test_probe_says_a_self_signed_server_has_no_ca_to_trust(tls_server):
    port = tls_server("self")
    res = ts.probe("127.0.0.1", port, timeout=5)
    assert res["reachable"] and not res["verified"]
    assert "SELF-SIGNED" in res["reason"]


def test_probe_refuses_urls_and_bad_ports():
    for host in ("https://x.example/", "a b", "host/path"):
        with pytest.raises(ts.TrustStoreError):
            ts.probe(host, 443)
    with pytest.raises(ts.TrustStoreError):
        ts.probe("example.invalid", 0)


# ---------------------------------------------------------------------------
# API
# ---------------------------------------------------------------------------

def _platform_admin(client, org):
    org_id, slug, email = org
    with SessionLocal() as s:
        set_tenant(s, org_id)
        s.execute(select(User).where(User.email == email)).scalar_one().is_superuser = True
        s.commit()
    return auth_headers(client, email, slug)


def test_the_api_is_platform_admin_only(client, org_a):
    _, slug, email = org_a
    org_admin = auth_headers(client, email, slug)
    base = "/api/v1/admin/trust-store"
    assert client.get(base).status_code == 401
    assert client.get(base, headers=org_admin).status_code == 403
    assert client.post(base, headers=org_admin, json={"pem": "x"}).status_code == 403
    assert client.post(base + "/probe", headers=org_admin, json={"host": "127.0.0.1"}).status_code == 403


def test_import_list_toggle_delete_through_the_api_is_audited(client, org_a, pki):
    h = _platform_admin(client, org_a)
    base = "/api/v1/admin/trust-store"
    r = client.post(base, headers=h, json={"pem": _pem(pki["root"]) + _pem(pki["leaf"]),
                                           "name": "Corp", "note": "company root"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert len(body["imported"]) == 1 and len(body["rejected"]) == 1
    ca_id = body["imported"][0]["id"]

    listed = client.get(base, headers=h).json()
    assert listed["summary"]["enabled"] == 1 and listed["items"][0]["note"] == "company root"
    detail = client.get(f"{base}/{ca_id}", headers=h).json()
    assert "Test Root CA" in detail["content"]["subject"] and "BEGIN CERTIFICATE" in detail["content"]["pem"]

    assert client.patch(f"{base}/{ca_id}", headers=h, json={"is_enabled": False}).json()["is_enabled"] is False
    assert ts.httpx_verify() is True
    assert client.delete(f"{base}/{ca_id}", headers=h).status_code == 204
    assert client.get(base, headers=h).json()["items"] == []

    leaf_only = client.post(base, headers=h, json={"pem": _pem(pki["leaf"])})
    assert leaf_only.status_code == 422 and "not a CA" in leaf_only.json()["detail"]

    org_id = org_a[0]
    with SessionLocal() as s:
        set_tenant(s, org_id)
        actions = set(s.execute(select(AuditLog.action).where(
            AuditLog.action.like("trust_store.%"))).scalars())
    assert {"trust_store.import", "trust_store.update", "trust_store.delete"} <= actions


# ---------------------------------------------------------------------------
# guard: no outbound TLS client bypasses the store
# ---------------------------------------------------------------------------

NETWORK_MODULES = ("httpx", "smtplib", "ldap3")


def test_every_module_that_opens_outbound_tls_goes_through_the_trust_store():
    """A new connector built on bare httpx/smtplib/ldap3 would verify against the
    public roots only, and an internal service behind the company CA would fail
    with "unable to get local issuer certificate" although the CA is in the
    store. Every such module must reference trust_store."""
    offenders = []
    for path in PKG.rglob("*.py"):
        if path.name == "trust_store.py":
            continue
        src = path.read_text(encoding="utf-8")
        tree = ast.parse(src)
        imported = set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Import):
                imported |= {a.name.split(".")[0] for a in node.names}
            elif isinstance(node, ast.ImportFrom) and node.module and node.level == 0:
                imported.add(node.module.split(".")[0])
        if imported & set(NETWORK_MODULES) and "trust_store" not in src:
            offenders.append(str(path.relative_to(ROOT)))
    assert not offenders, f"outbound TLS without the trust store: {offenders}"
