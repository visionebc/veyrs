"""Phase 58 -- single sign-on (OpenID Connect), configurable and off by default.

A fake provider (own RSA key, JWKS, discovery, token endpoint) stands in for
Authentik / Entra ID / Okta. What must never regress: the ID token is believed
only with the provider's signature, this client's audience, this sign-in's
nonce; state and handoff are single use; no superuser through SSO; tokens
never travel in a URL.
"""
from __future__ import annotations

import time
import uuid
from urllib.parse import parse_qs, urlsplit

import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from jose import jwk, jwt
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models.tenancy import User
from veyrs.security import mfa_delivery
from veyrs.services import oidc_auth

ISSUER = "https://idp.test/application/o/veyrs/"
REDIRECT = "https://console.test/api/v1/auth/oidc/callback"


def _key():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption()).decode()
    pub = jwk.construct(k.public_key().public_bytes(serialization.Encoding.PEM,
                        serialization.PublicFormat.SubjectPublicKeyInfo).decode(), "RS256").to_dict()
    pub.update(kid="k1", use="sig", alg="RS256")
    pub = {k2: (v.decode() if isinstance(v, bytes) else v) for k2, v in pub.items()}
    return pem, pub


class Provider:
    def __init__(self):
        self.pem, self.pub = _key()
        self.other_pem, _ = _key()
        self.claims: dict = {}
        self.sign_with_other = False
        self.last_post: dict = {}

    def id_token(self):
        return jwt.encode(self.claims, self.other_pem if self.sign_with_other else self.pem,
                          algorithm="RS256", headers={"kid": "k1"})


class Resp:
    def __init__(self, data, code=200):
        self._d, self.status_code = data, code

    def json(self):
        return self._d

    def raise_for_status(self):
        pass


@pytest.fixture()
def idp(monkeypatch):
    import httpx

    p = Provider()
    monkeypatch.setattr(mfa_delivery, "_store", mfa_delivery.MemoryStore())
    oidc_auth._cache.clear()

    def get(url, **_k):
        if url.endswith("/.well-known/openid-configuration"):
            return Resp({"issuer": ISSUER, "authorization_endpoint": "https://idp.test/authorize",
                         "token_endpoint": "https://idp.test/token", "jwks_uri": "https://idp.test/jwks",
                         "code_challenge_methods_supported": ["S256"]})
        if url == "https://idp.test/jwks":
            return Resp({"keys": [p.pub]})
        raise httpx.ConnectError(url)

    def post(url, data=None, **_k):
        p.last_post = dict(data or {})
        return Resp({"id_token": p.id_token(), "token_type": "Bearer"})

    monkeypatch.setattr(httpx, "get", get)
    monkeypatch.setattr(httpx, "post", post)
    return p


def _configure(org, **extra):
    org_id, slug, _ = org
    with SessionLocal() as s:
        set_tenant(s, org_id)
        oidc_auth.set_config(s, org_id, {"enabled": True, "issuer": ISSUER, "client_id": "veyrs-client",
                                         "redirect_uri": REDIRECT, **extra}, client_secret="s3cret-client")
        s.commit()
    return slug


def _start(client, slug):
    r = client.get(f"/api/v1/auth/oidc/{slug}/start")
    assert r.status_code == 200, r.text
    q = parse_qs(urlsplit(r.json()["authorization_url"]).query)
    assert q["code_challenge_method"] == ["S256"] and q["client_id"] == ["veyrs-client"]
    return q["state"][0], q["nonce"][0]


def _claims(idp, email, nonce, **extra):
    now = int(time.time())
    idp.claims = {"iss": ISSUER, "aud": "veyrs-client", "sub": str(uuid.uuid4()), "iat": now,
                  "exp": now + 300, "nonce": nonce, "email": email, "email_verified": True, **extra}


def _callback(client, state):
    r = client.get(f"/api/v1/auth/oidc/callback?code=abc&state={state}", follow_redirects=False)
    return r, parse_qs(urlsplit(r.headers.get("location", "")).fragment.split("?", 1)[-1])


def test_off_by_default(client, org_a, idp):
    # Per organization: other tenants of a shared test database may have SSO on.
    with SessionLocal() as s:
        assert not oidc_auth.is_enabled_cfg(oidc_auth.config(s, org_a[0]))
    assert client.get(f"/api/v1/auth/oidc/{org_a[1]}/start").status_code == 404
    assert client.get("/api/v1/auth/oidc/no-such-org/start").status_code == 404   # same answer: no enumeration


def test_full_sign_in_and_single_use(client, org_a, idp):
    slug = _configure(org_a)
    assert client.get("/api/v1/auth/sso").json() == {"available": True}
    state, nonce = _start(client, slug)
    _claims(idp, org_a[2], nonce)
    r, back = _callback(client, state)
    assert r.status_code == 303 and r.headers["location"].startswith("https://console.test/#/sso?")
    assert "access_token" not in r.headers["location"]
    assert idp.last_post["code_verifier"] and idp.last_post["client_secret"] == "s3cret-client"
    tok = client.post("/api/v1/auth/oidc/exchange", json={"handoff": back["h"][0]})
    assert tok.status_code == 200 and tok.json()["access_token"]
    assert client.post("/api/v1/auth/oidc/exchange", json={"handoff": back["h"][0]}).status_code == 401
    r2, _ = _callback(client, state)                      # state is single use
    assert r2.status_code == 400


@pytest.mark.parametrize("bad", ["nonce", "aud", "iss", "expired", "signature", "unverified"])
def test_untrustworthy_id_tokens_are_refused(client, org_a, idp, bad):
    slug = _configure(org_a)
    state, nonce = _start(client, slug)
    _claims(idp, org_a[2], nonce)
    if bad == "nonce":
        idp.claims["nonce"] = "someone-elses"
    elif bad == "aud":
        idp.claims["aud"] = "another-client"
    elif bad == "iss":
        idp.claims["iss"] = "https://evil.test/"
    elif bad == "expired":
        idp.claims["exp"] = int(time.time()) - 600
    elif bad == "signature":
        idp.sign_with_other = True
    elif bad == "unverified":
        idp.claims["email_verified"] = False
    r, back = _callback(client, state)
    assert r.status_code == 303 and "error" in back and "h" not in back, (bad, back)


def test_unknown_account_needs_jit(client, org_a, idp):
    slug = _configure(org_a)
    state, nonce = _start(client, slug)
    _claims(idp, "newcomer@example.org", nonce)
    _, back = _callback(client, state)
    assert "error" in back
    _configure(org_a, jit_provisioning=True)
    state, nonce = _start(client, slug)
    _claims(idp, "newcomer@example.org", nonce, name="New Comer")
    _, back = _callback(client, state)
    assert "h" in back
    with SessionLocal() as s:
        set_tenant(s, org_a[0])
        u = s.execute(select(User).where(User.email == "newcomer@example.org")).scalar_one()
        assert u.password_hash is None and u.full_name == "New Comer"


def test_no_superuser_through_sso(client, org_a, idp):
    slug = _configure(org_a)
    with SessionLocal() as s:
        set_tenant(s, org_a[0])
        s.execute(select(User).where(User.email == org_a[2])).scalar_one().is_superuser = True
        s.commit()
    state, nonce = _start(client, slug)
    _claims(idp, org_a[2], nonce)
    _, back = _callback(client, state)
    assert "error" in back and "local password" in back["error"][0]


def test_required_mfa_claim(client, org_a, idp):
    slug = _configure(org_a, require_mfa_amr=True)
    state, nonce = _start(client, slug)
    _claims(idp, org_a[2], nonce, amr=["pwd"])
    _, back = _callback(client, state)
    assert "error" in back
    state, nonce = _start(client, slug)
    _claims(idp, org_a[2], nonce, amr=["pwd", "mfa"])
    _, back = _callback(client, state)
    assert "h" in back


def test_admin_api_hides_the_secret_and_checks_the_provider(client, org_a, admin_a, idp):
    body = {"issuer": ISSUER, "client_id": "veyrs-client", "redirect_uri": REDIRECT}
    assert client.put("/api/v1/oidc", headers=admin_a, json={**body, "issuer": "http://idp.test/"}).status_code == 422
    assert client.put("/api/v1/oidc", headers=admin_a, json={**body, "client_secret": "s3cret-client"}).status_code == 200
    st = client.get("/api/v1/oidc", headers=admin_a).json()
    assert st["client_secret_set"] and "s3cret" not in str(st) and st["enabled"] is False
    t = client.post("/api/v1/oidc/test", headers=admin_a).json()
    assert t["ok"], t
