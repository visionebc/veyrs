"""0.42.0 -- the certificate VEYRS serves: request, sign elsewhere, attach, install.

Covers the service (names, key + CSR, every check on the returned certificate,
import of a PEM pair and of PKCS#12, the active/retired transitions), the node
installer against a fake nginx (apply, refused configuration rolled back,
missing include, uninstall, redirect) and against a REAL nginx on a test port,
the platform-admin API (the private key never appears in any response), and
static guards on the vhosts, units and installer.
"""
from __future__ import annotations

import datetime as dt
import os
import re
import shutil
import stat
import subprocess
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, rsa
from cryptography.hazmat.primitives.serialization import pkcs12
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID
from sqlalchemy import delete, select

from tests.conftest import auth_headers
from veyrs.db import SessionLocal, set_tenant
from veyrs.models import GLOBAL_TABLES, TrustedCa, User
from veyrs.models.audit import AuditLog
from veyrs.models.web_tls import InstallationSetting, WebCertificate, WebTlsNode
from veyrs.services import trust_store as ts
from veyrs.services import web_tls as wt

ROOT = Path(__file__).resolve().parents[1]
NOW = dt.datetime.now(dt.timezone.utc)


# ---------------------------------------------------------------------------
# a throwaway CA
# ---------------------------------------------------------------------------

def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn),
                      x509.NameAttribute(NameOID.ORGANIZATION_NAME, "VEYRS test PKI")])


def _ca(cn, key, issuer=None, issuer_key=None):
    b = (x509.CertificateBuilder().subject_name(_name(cn))
         .issuer_name(issuer.subject if issuer else _name(cn)).public_key(key.public_key())
         .serial_number(x509.random_serial_number())
         .not_valid_before(NOW - dt.timedelta(days=1)).not_valid_after(NOW + dt.timedelta(days=3650))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False,
                                      key_agreement=False, key_cert_sign=True, crl_sign=True,
                                      encipher_only=False, decipher_only=False), critical=True)
         .add_extension(x509.SubjectKeyIdentifier.from_public_key(key.public_key()), critical=False))
    if issuer is not None:
        b = b.add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(issuer_key.public_key()),
                            critical=False)
    return b.sign(issuer_key or key, hashes.SHA256())


@pytest.fixture(scope="module")
def pki():
    rk, ik = ec.generate_private_key(ec.SECP256R1()), ec.generate_private_key(ec.SECP256R1())
    root = _ca("Web Test Root", rk)
    inter = _ca("Web Test Issuing", ik, root, rk)
    return {"root": root, "inter": inter, "inter_key": ik}


def sign(pki, public_key, names, *, days=90, start=None, eku=(ExtendedKeyUsageOID.SERVER_AUTH,),
         ca=False):
    start = start or NOW - dt.timedelta(minutes=10)
    sans = []
    for n in names:
        try:
            import ipaddress
            sans.append(x509.IPAddress(ipaddress.ip_address(n)))
        except ValueError:
            sans.append(x509.DNSName(n))
    b = (x509.CertificateBuilder().subject_name(_name(names[0])).issuer_name(pki["inter"].subject)
         .public_key(public_key).serial_number(x509.random_serial_number())
         .not_valid_before(start).not_valid_after(start + dt.timedelta(days=days))
         .add_extension(x509.BasicConstraints(ca=ca, path_length=None), critical=True)
         .add_extension(x509.SubjectAlternativeName(sans), critical=False)
         .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(pki["inter_key"].public_key()),
                        critical=False))
    if eku:
        b = b.add_extension(x509.ExtendedKeyUsage(list(eku)), critical=False)
    return b.sign(pki["inter_key"], hashes.SHA256())


def pem(c):
    return c.public_bytes(serialization.Encoding.PEM).decode()


def sign_request(pki, row, **kw):
    csr = x509.load_pem_x509_csr(row.csr_pem.encode())
    return sign(pki, csr.public_key(), row.requested_names, **kw)


@pytest.fixture(autouse=True)
def _clean():
    def wipe():
        with SessionLocal() as s:
            s.execute(delete(WebCertificate))
            s.execute(delete(WebTlsNode))
            s.execute(delete(InstallationSetting))
            s.execute(delete(TrustedCa))
            s.commit()
        ts.invalidate()
    wipe()
    yield
    wipe()


def trust_root(pki):
    with SessionLocal() as s:
        ts.import_pem(s, pem(pki["root"]))
        s.commit()
    ts.invalidate()


def new_request(names=("veyrs.example.com", "veyrs-a1.example.com"), key_type="ec-p256"):
    with SessionLocal() as s:
        row = wt.create_request(s, common_name=names[0], extra_names=list(names[1:]), key_type=key_type,
                                subject={"organization": "Example", "country": "ch"}, actor_label="test")
        s.commit()
        s.refresh(row)
        return row


def attach(blob, chain=None):
    with SessionLocal() as s:
        row, checks = wt.attach_certificate(s, blob, chain)
        s.commit()
        s.refresh(row)
        return row, checks


# ---------------------------------------------------------------------------
# schema, names
# ---------------------------------------------------------------------------

def test_the_tables_are_installation_wide():
    for t in ("web_certificates", "web_tls_nodes", "installation_settings"):
        assert t in GLOBAL_TABLES
    assert "organization_id" not in WebCertificate.__table__.c


def test_names_are_validated_and_deduplicated():
    assert wt.parse_names("VEYRS.example.com.", "*.example.com\n198.19.2.3, veyrs.example.com") == [
        "veyrs.example.com", "*.example.com", "198.19.2.3"]
    for bad in ("https://veyrs.example.com/", "veyrs", "a b.example.com", "-x.example.com"):
        with pytest.raises(wt.WebTlsError):
            wt.parse_names(bad, None)
    assert wt.name_covered("a.example.com", ["*.example.com"])
    assert not wt.name_covered("a.b.example.com", ["*.example.com"])
    assert not wt.name_covered("198.19.1.1", ["*.example.com"])


# ---------------------------------------------------------------------------
# request
# ---------------------------------------------------------------------------

@pytest.mark.parametrize("key_type,check", [
    ("rsa-3072", lambda k: isinstance(k, rsa.RSAPublicKey) and k.key_size == 3072),
    ("ec-p256", lambda k: isinstance(k, ec.EllipticCurvePublicKey) and k.curve.name == "secp256r1"),
])
def test_the_request_carries_every_name_and_the_key_stays_sealed(key_type, check):
    row = new_request(key_type=key_type)
    csr = x509.load_pem_x509_csr(row.csr_pem.encode())
    assert csr.is_signature_valid and check(csr.public_key())
    san = csr.extensions.get_extension_for_class(x509.SubjectAlternativeName).value
    assert san.get_values_for_type(x509.DNSName) == ["veyrs.example.com", "veyrs-a1.example.com"]
    assert ExtendedKeyUsageOID.SERVER_AUTH in csr.extensions.get_extension_for_class(x509.ExtendedKeyUsage).value
    assert csr.subject.get_attributes_for_oid(NameOID.COUNTRY_NAME)[0].value == "CH"
    assert "PRIVATE KEY" not in row.key_sealed
    assert "PRIVATE KEY" in wt.secrets.decrypt(row.key_sealed)


def test_a_bad_country_or_key_type_is_refused():
    with SessionLocal() as s, pytest.raises(wt.WebTlsError, match="two-letter"):
        wt.create_request(s, common_name="v.example.com", subject={"country": "Mexico"})
    with SessionLocal() as s, pytest.raises(wt.WebTlsError, match="key type"):
        wt.create_request(s, common_name="v.example.com", key_type="dsa-1024")


# ---------------------------------------------------------------------------
# attach + checks
# ---------------------------------------------------------------------------

def test_a_private_ca_is_refused_until_its_root_is_in_the_trust_store(pki):
    row = new_request()
    cert = sign_request(pki, row)
    with pytest.raises(wt.CertificateRefused) as exc:
        attach(pem(cert) + pem(pki["inter"]))
    failed = {c["check"] for c in exc.value.checks if c["result"] == "fail"}
    assert failed == {"Chain of trust"}
    assert "Trust store" in str(exc.value)
    with SessionLocal() as s:
        assert s.get(WebCertificate, row.id).status == "pending"     # nothing stored

    trust_root(pki)
    got, checks = attach(pem(cert) + pem(pki["inter"]))
    assert got.status == "ready" and all(c["result"] == "pass" for c in checks), checks
    assert pem(pki["inter"]) in got.chain_pem and pem(pki["root"]) not in got.chain_pem
    assert got.names == ["veyrs.example.com", "veyrs-a1.example.com"]


def test_the_chain_can_come_as_a_separate_file(pki):
    trust_root(pki)
    row = new_request()
    got, _ = attach(pem(sign_request(pki, row)), pem(pki["inter"]))
    assert got.status == "ready"


def test_a_certificate_for_another_key_does_not_attach(pki):
    trust_root(pki)
    new_request()
    other = sign(pki, ec.generate_private_key(ec.SECP256R1()).public_key(), ["veyrs.example.com"])
    with pytest.raises(wt.WebTlsError, match="matches a key generated here"):
        attach(pem(other) + pem(pki["inter"]))


def test_the_csr_uploaded_by_mistake_gets_a_clear_answer():
    row = new_request()
    with pytest.raises(wt.WebTlsError, match="REQUEST"):
        attach(row.csr_pem)


@pytest.mark.parametrize("kw,check", [
    ({"start": NOW - dt.timedelta(days=100), "days": 30}, "Validity"),
    ({"eku": (ExtendedKeyUsageOID.CLIENT_AUTH,)}, "Extended key usage"),
])
def test_expired_or_client_only_certificates_are_refused(pki, kw, check):
    trust_root(pki)
    row = new_request()
    with pytest.raises(wt.CertificateRefused) as exc:
        attach(pem(sign_request(pki, row, **kw)) + pem(pki["inter"]))
    assert check in {c["check"] for c in exc.value.checks if c["result"] == "fail"}


def test_a_name_the_ca_dropped_is_a_warning_not_a_refusal(pki):
    trust_root(pki)
    row = new_request()
    csr = x509.load_pem_x509_csr(row.csr_pem.encode())
    cert = sign(pki, csr.public_key(), ["veyrs.example.com"])
    got, checks = attach(pem(cert) + pem(pki["inter"]))
    names = next(c for c in checks if c["check"] == "Names (SAN)")
    assert names["result"] == "warn" and "veyrs-a1.example.com" in names["detail"]
    assert got.status == "ready"


# ---------------------------------------------------------------------------
# import of a pair made elsewhere
# ---------------------------------------------------------------------------

def test_import_pem_pair_with_passphrase_and_pkcs12(pki):
    trust_root(pki)
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    cert = sign(pki, key.public_key(), ["imported.example.com"])
    enc = key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                            serialization.BestAvailableEncryption(b"s3cret")).decode()
    with SessionLocal() as s, pytest.raises(wt.WebTlsError, match="passphrase"):
        wt.import_certificate(s, certificate=pem(cert), private_key=enc, chain=pem(pki["inter"]))
    with SessionLocal() as s:
        row, _ = wt.import_certificate(s, certificate=pem(cert), private_key=enc,
                                       chain=pem(pki["inter"]), passphrase="s3cret")
        s.commit()
        assert row.status == "ready" and row.source == "imported" and row.key_type == "rsa-2048"
        assert "PRIVATE KEY" not in row.key_sealed

    key2 = ec.generate_private_key(ec.SECP256R1())
    cert2 = sign(pki, key2.public_key(), ["p12.example.com"])
    blob = pkcs12.serialize_key_and_certificates(b"x", key2, cert2, [pki["inter"]],
                                                 serialization.BestAvailableEncryption(b"pw"))
    with SessionLocal() as s, pytest.raises(wt.WebTlsError, match="PKCS#12"):
        wt.import_certificate(s, pkcs12_data=blob, passphrase="wrong")
    with SessionLocal() as s:
        row, _ = wt.import_certificate(s, pkcs12_data=blob, passphrase="pw")
        s.commit()
        assert row.status == "ready" and row.names == ["p12.example.com"]


# ---------------------------------------------------------------------------
# transitions
# ---------------------------------------------------------------------------

def _ready(pki, names=("veyrs.example.com",)):
    row = new_request(names=names)
    got, _ = attach(pem(sign_request(pki, row)) + pem(pki["inter"]))
    return got


def test_one_active_certificate_and_rollback(pki):
    trust_root(pki)
    first, second = _ready(pki, ("one.example.com",)), _ready(pki, ("two.example.com",))
    with SessionLocal() as s:
        wt.activate(s, first.id, "t")
        s.commit()
        _, prev = wt.activate(s, second.id, "t")
        s.commit()
        assert prev.id == first.id
        assert s.get(WebCertificate, first.id).status == "retired"
        with pytest.raises(wt.WebTlsError, match="being served"):
            wt.discard(s, second.id)
        wt.activate(s, first.id, "t")          # reinstall the previous one
        s.commit()
        assert wt.active(s).id == first.id
        wt.deactivate(s)
        s.commit()
        assert wt.active(s) is None


def test_install_rechecks_and_refuses_when_the_ca_was_removed(pki):
    trust_root(pki)
    ready = _ready(pki)
    with SessionLocal() as s:
        s.execute(delete(TrustedCa))
        s.commit()
    with SessionLocal() as s, pytest.raises(wt.CertificateRefused):
        wt.activate(s, ready.id, "t")


# ---------------------------------------------------------------------------
# the node installer, fake nginx
# ---------------------------------------------------------------------------

@pytest.fixture()
def fake_nginx(tmp_path):
    """A stand-in for nginx: -t fails when `refuse` exists, -T prints a config
    that includes the managed glob unless `noinclude` exists."""
    tls = tmp_path / "tls"
    script = tmp_path / "nginx"
    script.write_text(f"""#!/bin/sh
case "$1" in
  -v) echo "nginx version: nginx/9.9.9" >&2 ;;
  -t) [ -e {tmp_path}/refuse ] && {{ echo "emerg: bad"; exit 1; }}; echo ok ;;
  -T) [ -e {tmp_path}/noinclude ] && echo "server {{}}" || echo "include {tls}/nginx/*.conf;" ;;
esac
""")
    script.chmod(0o755)
    return {"dir": tls, "nginx": [str(script)], "flags": tmp_path}


def _sync(fake, probe):
    return wt.sync_node(tls_dir=fake["dir"], node="node-test", nginx=fake["nginx"],
                        reload=["true"], probe=probe)


def test_the_installer_applies_reports_and_rolls_back(pki, fake_nginx):
    trust_root(pki)
    first, second = _ready(pki, ("one.example.com",)), _ready(pki, ("two.example.com",))
    with SessionLocal() as s:
        wt.activate(s, first.id, "t")
        s.commit()
    res = _sync(fake_nginx, lambda sni: first.cert_fingerprint)
    d = fake_nginx["dir"]
    assert res["state"] == "applied" and res["changed"]
    assert stat.S_IMODE((d / "server.key").stat().st_mode) == 0o600
    assert (d / "server.crt").read_text().startswith(first.cert_pem)
    assert "listen 443 ssl" in (d / "nginx/listen.conf").read_text()
    assert not (d / "nginx/redirect.conf").exists()
    with SessionLocal() as s:
        n = s.get(WebTlsNode, "node-test")
        assert n.state == "applied" and n.served_fingerprint == first.cert_fingerprint
        assert n.nginx_version == "9.9.9"
    assert _sync(fake_nginx, lambda sni: first.cert_fingerprint)["changed"] is False

    # nginx refuses the next configuration: previous files restored, not reloaded
    with SessionLocal() as s:
        wt.activate(s, second.id, "t")
        s.commit()
    (fake_nginx["flags"] / "refuse").touch()
    res = _sync(fake_nginx, lambda sni: first.cert_fingerprint)
    assert res["state"] == "error" and "restored" in res["detail"]
    assert (d / "server.crt").read_text().startswith(first.cert_pem)
    (fake_nginx["flags"] / "refuse").unlink()
    assert _sync(fake_nginx, lambda sni: second.cert_fingerprint)["state"] == "applied"

    # redirect on -> its file appears
    with SessionLocal() as s:
        wt.set_policy(s, redirect_http=True)
        s.commit()
    _sync(fake_nginx, lambda sni: second.cert_fingerprint)
    assert "return 301 https://" in (d / "nginx/redirect.conf").read_text()

    # a vhost without the include is reported, not silently "applied"
    (fake_nginx["flags"] / "noinclude").touch()
    res = _sync(fake_nginx, lambda sni: second.cert_fingerprint)
    assert res["state"] == "not_configured" and "include" in res["detail"]
    (fake_nginx["flags"] / "noinclude").unlink()

    # a different certificate on :443 is an error
    assert _sync(fake_nginx, lambda sni: "0" * 64)["state"] == "error"

    # uninstall: every managed file leaves the node
    with SessionLocal() as s:
        wt.deactivate(s)
        s.commit()
    assert _sync(fake_nginx, lambda sni: None)["state"] == "off"
    assert not any((d / f).exists() for f in wt.MANAGED_FILES)


def test_the_cli_refuses_to_run_unprivileged(monkeypatch, capsys):
    monkeypatch.setattr(os, "geteuid", lambda: 1000)

    class A:
        tls_dir = None
    assert wt.run_cli(A()) == 2
    assert "root" in capsys.readouterr().out


# ---------------------------------------------------------------------------
# the node installer, REAL nginx on a test port
# ---------------------------------------------------------------------------

NGINX = shutil.which("nginx") or ("/usr/sbin/nginx" if Path("/usr/sbin/nginx").exists() else None)


@pytest.mark.skipif(NGINX is None or os.geteuid() != 0, reason="needs nginx and root (API nodes)")
def test_a_real_nginx_serves_the_installed_certificate(pki, tmp_path):
    trust_root(pki)
    ready = _ready(pki, ("veyrs-it.example.com",))
    with SessionLocal() as s:
        wt.activate(s, ready.id, "t")
        s.commit()
    tls = tmp_path / "tls"
    conf = tmp_path / "nginx.conf"
    conf.write_text(f"""
pid {tmp_path}/nginx.pid;
error_log {tmp_path}/error.log;
events {{}}
http {{
    access_log off;
    client_body_temp_path {tmp_path}/body;
    proxy_temp_path {tmp_path}/proxy;
    fastcgi_temp_path {tmp_path}/fcgi;
    uwsgi_temp_path {tmp_path}/uwsgi;
    scgi_temp_path {tmp_path}/scgi;
    server {{
        listen 127.0.0.1:18480;
        include {tls}/nginx/*.conf;
        location / {{ return 200 "ok"; }}
    }}
}}
""")
    base = [NGINX, "-c", str(conf)]
    assert subprocess.run(base, capture_output=True).returncode == 0      # starts with HTTP only
    try:
        res = wt.sync_node(tls_dir=tls, node="node-real", nginx=base, reload=base + ["-s", "reload"],
                           listen="127.0.0.1:18443",
                           probe=lambda sni: wt.served_fingerprint(sni, port=18443))
        assert res["state"] == "applied", res
        # and a client that trusts only our root verifies it by name
        import socket
        import ssl
        ctx = ssl.create_default_context(cadata=pem(pki["root"]))
        with socket.create_connection(("127.0.0.1", 18443), timeout=5) as raw:
            with ctx.wrap_socket(raw, server_hostname="veyrs-it.example.com") as t:
                assert t.version() in ("TLSv1.2", "TLSv1.3")
    finally:
        subprocess.run(base + ["-s", "stop"], capture_output=True)


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
    h = auth_headers(client, email, slug)
    base = "/api/v1/admin/web-certificate"
    assert client.get(base).status_code == 401
    assert client.get(base, headers=h).status_code == 403
    assert client.post(base + "/requests", headers=h, json={"common_name": "x.example.com"}).status_code == 403


def test_the_whole_flow_through_the_api_never_returns_the_key(client, org_a, pki):
    h = _platform_admin(client, org_a)
    base = "/api/v1/admin/web-certificate"
    bodies = []

    def call(method, path, **kw):
        r = client.request(method, base + path, headers=h, **kw)
        bodies.append(r.text)
        return r

    r = call("POST", "/requests", json={"common_name": "veyrs.example.com",
                                        "extra_names": "veyrs-a1.example.com", "key_type": "ec-p256"})
    assert r.status_code == 201, r.text
    req_id = r.json()["id"]
    csr = call("GET", f"/{req_id}/csr")
    assert csr.status_code == 200 and "CERTIFICATE REQUEST" in csr.text
    assert csr.headers["content-disposition"].endswith('veyrs.example.com.csr"')

    cert = sign(pki, x509.load_pem_x509_csr(csr.content).public_key(),
                ["veyrs.example.com", "veyrs-a1.example.com"])
    refused = call("POST", "/certificate", json={"certificate": pem(cert) + pem(pki["inter"])})
    assert refused.status_code == 422
    assert any(c["check"] == "Chain of trust" and c["result"] == "fail"
               for c in refused.json()["detail"]["checks"])

    trust_root(pki)
    ok = call("POST", "/certificate", json={"certificate": pem(cert) + pem(pki["inter"])})
    assert ok.status_code == 200 and ok.json()["status"] == "ready"
    assert call("PUT", "/policy", json={"redirect_http": True}).status_code == 409   # nothing installed
    ov = call("POST", f"/{req_id}/install").json()
    assert ov["active"]["id"] == req_id
    assert call("PUT", "/policy", json={"redirect_http": True}).json()["redirect_http"] is True
    assert call("POST", "/uninstall").status_code == 200
    assert call("GET", "").json()["policy"]["redirect_http"] is False     # redirect left with HTTPS
    assert call("DELETE", f"/{req_id}").status_code == 204

    for b in bodies:
        assert "PRIVATE KEY" not in b and "key_sealed" not in b
    with SessionLocal() as s:
        set_tenant(s, org_a[0])
        actions = set(s.execute(select(AuditLog.action).where(
            AuditLog.action.like("web_certificate.%"))).scalars())
    assert {"web_certificate.request", "web_certificate.attach_refused", "web_certificate.attach",
            "web_certificate.install", "web_certificate.policy", "web_certificate.uninstall",
            "web_certificate.discard"} <= actions


# ---------------------------------------------------------------------------
# static guards
# ---------------------------------------------------------------------------

INCLUDE = "include /etc/veyrs/tls/nginx/*.conf;"


VHOSTS = sorted((ROOT / "infrastructure").glob("nginx-veyrs-*.conf"))


def test_every_shipped_vhost_carries_the_tls_include():
    # Console, Docs Center and product site: one certificate serves all three.
    # A vhost without the include stays on HTTP while the page says HTTPS.
    assert {v.name for v in VHOSTS} >= {"nginx-veyrs-console.conf", "nginx-veyrs-docs.conf", "nginx-veyrs-web.conf"}
    for v in VHOSTS:
        assert v.read_text().count(INCLUDE) == 1, f"{v.name}: needs exactly one {INCLUDE}"
    heredoc = (ROOT / "install.sh").read_text()
    start = heredoc.index('cat > "$NGINX_SITE" <<NGEOF')
    assert INCLUDE in heredoc[start:heredoc.index("\nNGEOF", start)]


def test_no_location_drops_the_security_headers():
    """An add_header inside a location replaces EVERY add_header of the server
    block: /static/ went out without CSP, HSTS and X-Frame-Options until
    0.42.0. Only the health probes (JSON, never rendered) may set their own."""
    # A location may set headers of its own only if it repeats every security
    # header its server sets (what the health probes and 0.41.0's /static/ do).
    must = ("Content-Security-Policy", "Strict-Transport-Security", "X-Frame-Options")
    for rel in [str(v.relative_to(ROOT)) for v in VHOSTS] + ["docker/console.conf"]:
        text = re.sub(r"#[^\n]*", "", (ROOT / rel).read_text())
        server = re.sub(r"location\s+[^{]+\{[^{}]*\}", "", text)
        for m in re.finditer(r"location\s+([^{]+)\{([^{}]*)\}", text):
            if "add_header" not in m.group(2):
                continue
            for h in must:
                if h in server:
                    assert h in m.group(2), f"{rel}: location {m.group(1).strip()} drops {h}"


def test_the_installer_ships_and_enables_the_root_timer():
    for unit in ("veyrs-tls-sync.service", "veyrs-tls-sync.timer"):
        assert (ROOT / "infrastructure/systemd" / unit).is_file()
    text = (ROOT / "install.sh").read_text()
    assert "enable --now veyrs-tls-sync.timer" in text
    svc = (ROOT / "infrastructure/systemd/veyrs-tls-sync.service").read_text()
    assert "User=root" in svc and "-m veyrs tls-sync" in svc


def test_the_redirect_spares_the_probes_and_the_metrics_scrape():
    """Load balancers probe /healthz and /readyz on HTTP; Prometheus scrapes
    /metrics by IP address, which no certificate names. A 301 on any of them
    marks every node down or breaks the scrape."""
    m = re.search(r'if \(\$uri ~ "\^/\(([^)]+)\)\$"\)', wt.REDIRECT_CONF)
    assert m, "the redirect exemption changed shape"
    assert set(m.group(1).split("|")) == {"healthz", "readyz", "metrics"}


def test_the_page_offers_both_ways_as_equals():
    """Owner request (0.42.0): the CSR flow and "bring a certificate and its
    key" are two choices at the top of the page, not a CSR flow with the
    import folded away at the bottom behind a <details>."""
    js = (ROOT / "frontend/console/app.js").read_text()
    page = js[js.index("async function adminWebCertificate(body)"):]
    page = page[:page.index("\n}\n")]
    assert 'role="radiogroup"' in page
    for path in ("csr", "import"):
        assert f'data-path="{path}"' in page and f'data-pane="{path}"' in page
    assert "<details" not in page, "a way to get the certificate is hidden again"
    # Each path shows its own refused checks next to its own form.
    for target in ("#wt-checks", "#wt-imp-checks", "#wt-inst-checks"):
        assert target[1:] in page
