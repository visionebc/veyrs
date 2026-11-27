"""R-01: python-jose was replaced by PyJWT; the verification rules must not have loosened."""
from __future__ import annotations

import base64
import hashlib
import hmac
import json
import time

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from veyrs.security import auth
from veyrs.services import oidc_auth

AUD, ISS = "client-1", "https://idp.example.com/"


def _rsa():
    k = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    pem = k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                          serialization.NoEncryption())
    jwk = jwt.algorithms.RSAAlgorithm.to_jwk(k.public_key(), as_dict=True)
    jwk.update(kid="k1", use="sig", alg="RS256")
    return pem, jwk, k.public_key().public_bytes(serialization.Encoding.PEM,
                                                 serialization.PublicFormat.SubjectPublicKeyInfo)


def _claims(**extra):
    now = int(time.time())
    return {"iss": ISS, "aud": AUD, "sub": "u1", "exp": now + 300, "iat": now, **extra}


def _verify(token, jwks, access_token=None):
    return oidc_auth.verify_id_token(token, {"keys": [jwks]}, audience=AUD, issuer=ISS, access_token=access_token)


def test_a_valid_rs256_id_token_verifies():
    pem, jwk, _ = _rsa()
    token = jwt.encode(_claims(), pem, algorithm="RS256", headers={"kid": "k1"})
    assert _verify(token, jwk)["sub"] == "u1"


@pytest.mark.parametrize("bad", ["aud", "iss", "exp"])
def test_audience_issuer_and_expiry_are_enforced(bad):
    pem, jwk, _ = _rsa()
    claims = _claims()
    claims.update({"aud": "someone-else"} if bad == "aud" else {"iss": "https://evil/"} if bad == "iss"
                  else {"exp": int(time.time()) - 10})
    token = jwt.encode(claims, pem, algorithm="RS256", headers={"kid": "k1"})
    with pytest.raises(jwt.PyJWTError):
        _verify(token, jwk)


def test_algorithm_confusion_is_refused():
    """An HS256 token MACed with the provider's PUBLIC key must never verify (the python-jose advisory class)."""
    _, jwk, public_pem = _rsa()
    # PyJWT itself refuses to MAC with a PEM key, so build the forgery by hand.
    def b64(raw: bytes) -> str:
        return base64.urlsafe_b64encode(raw).rstrip(b"=").decode()

    signing = b64(json.dumps({"alg": "HS256", "typ": "JWT", "kid": "k1"}).encode()) + "." + \
        b64(json.dumps(_claims()).encode())
    forged = signing + "." + b64(hmac.new(public_pem, signing.encode(), hashlib.sha256).digest())
    with pytest.raises(jwt.PyJWTError):
        _verify(forged, jwk)


def test_an_unsigned_token_is_refused():
    _, jwk, _ = _rsa()
    unsigned = jwt.encode(_claims(), key=None, algorithm="none", headers={"kid": "k1"})
    with pytest.raises(jwt.PyJWTError):
        _verify(unsigned, jwk)


def test_a_token_signed_by_another_key_is_refused():
    _, jwk, _ = _rsa()
    other_pem, _, _ = _rsa()
    token = jwt.encode(_claims(), other_pem, algorithm="RS256", headers={"kid": "k1"})
    with pytest.raises(jwt.PyJWTError):
        _verify(token, jwk)


def _at_hash(access_token: str) -> str:
    half = hashlib.sha256(access_token.encode()).digest()[:16]
    return base64.urlsafe_b64encode(half).rstrip(b"=").decode()


def test_at_hash_is_checked_when_present():
    pem, jwk, _ = _rsa()
    token = jwt.encode(_claims(at_hash=_at_hash("the-access-token")), pem, algorithm="RS256", headers={"kid": "k1"})
    assert _verify(token, jwk, access_token="the-access-token")["sub"] == "u1"
    with pytest.raises(jwt.PyJWTError):
        _verify(token, jwk, access_token="another-access-token")
    with pytest.raises(jwt.PyJWTError):
        _verify(token, jwk, access_token=None)


def test_local_access_tokens_round_trip_and_reject_tampering():
    import uuid

    token, _ = auth.create_access_token(user_id=uuid.uuid4(), organization_id=uuid.uuid4(), permissions=["x:read"])
    assert auth.decode_access_token(token)["perms"] == ["x:read"]
    with pytest.raises(auth.AuthError):
        auth.decode_access_token(token[:-2] + ("AA" if not token.endswith("AA") else "BB"))
    with pytest.raises(auth.AuthError):
        auth.decode_access_token("not-a-jwt")
