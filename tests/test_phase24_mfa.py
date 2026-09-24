"""Phase 24 - MFA is a control, not a checkbox.

The defect this file pins down: `/auth/login` used to accept ANY value in
`mfa_code` when `users.mfa_enabled` was true. It asserted the field was
present and never verified it, `users.mfa_secret` was never read, and no TOTP
implementation existed anywhere in the tree. Nobody had MFA enabled, so nothing
was breached -- the trap was that the first operator to turn it on would have
had a green padlock and no second factor.

The direction that must never regress is the first test here: a wrong code has
to be refused.
"""
from __future__ import annotations

import time

import pytest
from sqlalchemy import select

from conftest import ADMIN_PASSWORD, _flush_rate_limits, auth_headers, login  # noqa: F401
from veyrs.db import SessionLocal, set_tenant
from veyrs.models.tenancy import User
from veyrs.security import mfa


# ---------------------------------------------------------------------------
# helpers
# ---------------------------------------------------------------------------
def _enroll_and_activate(client, headers) -> str:
    """Full lifecycle, returning the plaintext secret."""
    response = client.post("/api/v1/auth/mfa/enroll", headers=headers)
    assert response.status_code == 200, response.text
    secret = response.json()["secret"]

    code = mfa._code_at(secret, mfa.current_step())
    activate = client.post("/api/v1/auth/mfa/activate", headers=headers, json={"code": code})
    assert activate.status_code == 204, activate.text
    return secret


def _attempt(client, email, slug, code=None, password=ADMIN_PASSWORD):
    _flush_rate_limits()
    body = {"email": email, "password": password, "organization": slug}
    if code is not None:
        body["mfa_code"] = code
    return client.post("/api/v1/auth/login", json=body)


def _reset_lockout(user_id) -> None:
    with SessionLocal() as session:
        user = session.get(User, user_id)
        set_tenant(session, user.organization_id)
        user.failed_logins = 0
        user.locked_until = None
        session.commit()


def _user_id(email) -> object:
    with SessionLocal() as session:
        return session.execute(select(User).where(User.email == email)).scalar_one().id


# ---------------------------------------------------------------------------
# The regression that matters
# ---------------------------------------------------------------------------
def test_wrong_code_is_refused(client, org_a, admin_a):
    """THE defect. '000000' used to be accepted because it was merely present."""
    _, slug, email = org_a
    _enroll_and_activate(client, admin_a)

    assert _attempt(client, email, slug, code="000000").status_code == 401
    _reset_lockout(_user_id(email))
    assert _attempt(client, email, slug, code="123456").status_code == 401


def test_correct_code_is_accepted(client, org_a, admin_a):
    _, slug, email = org_a
    secret = _enroll_and_activate(client, admin_a)

    code = mfa._code_at(secret, mfa.current_step() + 1)  # step after activation
    response = _attempt(client, email, slug, code=code)
    assert response.status_code == 200, response.text
    assert "access_token" in response.json()


def test_missing_code_challenges_without_spending_the_lockout_budget(client, org_a, admin_a):
    """A challenge is not a failure; ten of them must not lock the account."""
    _, slug, email = org_a
    _enroll_and_activate(client, admin_a)

    for _ in range(12):
        response = _attempt(client, email, slug)
        assert response.status_code == 401
        assert response.json()["detail"]["error"] == "mfa_required"

    with SessionLocal() as session:
        user = session.execute(select(User).where(User.email == email)).scalar_one()
        assert user.failed_logins == 0
        assert user.locked_until is None


def test_bad_codes_share_the_password_lockout_budget(client, org_a, admin_a):
    """Six digits are guessable if the attempts are not capped."""
    _, slug, email = org_a
    _enroll_and_activate(client, admin_a)

    for _ in range(10):
        assert _attempt(client, email, slug, code="000000").status_code == 401

    with SessionLocal() as session:
        user = session.execute(select(User).where(User.email == email)).scalar_one()
        assert user.locked_until is not None, "MFA guessing must trip the lockout"


def test_a_code_cannot_be_replayed(client, org_a, admin_a):
    """Same digits, same 30s window, second use refused."""
    _, slug, email = org_a
    secret = _enroll_and_activate(client, admin_a)

    code = mfa._code_at(secret, mfa.current_step() + 1)
    assert _attempt(client, email, slug, code=code).status_code == 200
    _reset_lockout(_user_id(email))
    assert _attempt(client, email, slug, code=code).status_code == 401


def test_enabled_but_unusable_secret_fails_closed(client, org_a, admin_a):
    """Key rotated / row corrupt must NOT degrade to password-only."""
    _, slug, email = org_a
    _enroll_and_activate(client, admin_a)

    with SessionLocal() as session:
        user = session.execute(select(User).where(User.email == email)).scalar_one()
        set_tenant(session, user.organization_id)
        user.mfa_secret = None          # enabled, nothing enrolled
        session.commit()

    assert _attempt(client, email, slug, code="000000").status_code == 401
    _reset_lockout(_user_id(email))
    # and a *correct-looking* attempt is refused too - there is nothing to check against
    assert _attempt(client, email, slug, code="654321").status_code == 401


def test_password_still_required(client, org_a, admin_a):
    _, slug, email = org_a
    secret = _enroll_and_activate(client, admin_a)
    code = mfa._code_at(secret, mfa.current_step() + 1)
    assert _attempt(client, email, slug, code=code, password="wrong-password").status_code == 401


# ---------------------------------------------------------------------------
# Enrolment lifecycle
# ---------------------------------------------------------------------------
def test_enrolment_does_not_enable_on_its_own(client, org_a, admin_a):
    """Enrol -> still password-only, until a code proves the app works."""
    _, slug, email = org_a
    response = client.post("/api/v1/auth/mfa/enroll", headers=admin_a)
    assert response.status_code == 200

    with SessionLocal() as session:
        user = session.execute(select(User).where(User.email == email)).scalar_one()
        assert user.mfa_secret is not None
        assert user.mfa_enabled is False

    assert _attempt(client, email, slug).status_code == 200


def test_secret_is_encrypted_at_rest(client, org_a, admin_a):
    _, _, email = org_a
    secret = _enroll_and_activate(client, admin_a)
    with SessionLocal() as session:
        user = session.execute(select(User).where(User.email == email)).scalar_one()
        assert user.mfa_secret != secret
        assert user.mfa_secret.startswith("v1:")


def test_activate_rejects_a_wrong_code(client, org_a, admin_a):
    client.post("/api/v1/auth/mfa/enroll", headers=admin_a)
    response = client.post("/api/v1/auth/mfa/activate", headers=admin_a, json={"code": "000000"})
    assert response.status_code == 422


def test_cannot_re_enroll_while_enabled(client, org_a, admin_a):
    """Re-enrolling would silently invalidate a working authenticator."""
    _enroll_and_activate(client, admin_a)
    assert client.post("/api/v1/auth/mfa/enroll", headers=admin_a).status_code == 409


def test_disable_needs_both_factors(client, org_a, admin_a):
    _, _, email = org_a
    secret = _enroll_and_activate(client, admin_a)

    bad_code = client.post("/api/v1/auth/mfa/disable", headers=admin_a,
                           json={"password": ADMIN_PASSWORD, "code": "000000"})
    assert bad_code.status_code == 422

    code = mfa._code_at(secret, mfa.current_step() + 1)
    bad_pw = client.post("/api/v1/auth/mfa/disable", headers=admin_a,
                         json={"password": "nope-nope-nope", "code": code})
    assert bad_pw.status_code == 401

    ok = client.post("/api/v1/auth/mfa/disable", headers=admin_a,
                     json={"password": ADMIN_PASSWORD, "code": code})
    assert ok.status_code == 204

    with SessionLocal() as session:
        user = session.execute(select(User).where(User.email == email)).scalar_one()
        assert user.mfa_enabled is False
        assert user.mfa_secret is None


# ---------------------------------------------------------------------------
# The primitive itself
# ---------------------------------------------------------------------------
def test_rfc6238_reference_vector():
    """RFC 6238 appendix B, SHA-1, seed '12345678901234567890', T=59 -> 94287082."""
    import base64
    secret = base64.b32encode(b"12345678901234567890").decode()
    # The RFC publishes 8 digits (94287082); VEYRS emits 6, the low-order half.
    assert 59 // mfa.PERIOD == 1
    assert mfa._code_at(secret, 1) == "287082"


def test_skew_window_is_one_step_each_way():
    secret = mfa.generate_secret()
    now = time.time()
    centre = mfa.current_step(now)
    for offset in (-1, 0, 1):
        code = mfa._code_at(secret, centre + offset)
        assert mfa.verify(secret, code, now=now) == centre + offset
    assert mfa.verify(secret, mfa._code_at(secret, centre + 2), now=now) is None
    assert mfa.verify(secret, mfa._code_at(secret, centre - 2), now=now) is None


def test_malformed_codes_are_rejected_without_raising():
    secret = mfa.generate_secret()
    for junk in (None, "", "abc", "12345", "1234567890123", "12 34 56", "٠٠٠٠٠٠"):
        assert mfa.verify(secret, junk) is None


def test_generated_secrets_are_unique_and_base32():
    import base64
    seen = {mfa.generate_secret() for _ in range(50)}
    assert len(seen) == 50
    for secret in seen:
        base64.b32decode(secret + "=" * (-len(secret) % 8))


def test_provisioning_uri_shape():
    uri = mfa.provisioning_uri("ABCDEFGHIJKLMNOP", account="a@b.test", issuer="VEYRS")
    assert uri.startswith("otpauth://totp/VEYRS%3Aa%40b.test?")
    assert "secret=ABCDEFGHIJKLMNOP" in uri
    assert "digits=6" in uri and "period=30" in uri


def test_unseal_fails_closed_on_missing_or_corrupt():
    with pytest.raises(mfa.MfaError):
        mfa.unseal(None)
    with pytest.raises(mfa.MfaError):
        mfa.unseal("")
    with pytest.raises(mfa.MfaError):
        mfa.unseal("v1:not-a-real-fernet-token")


def test_seal_roundtrip():
    secret = mfa.generate_secret()
    assert mfa.unseal(mfa.seal(secret)) == secret
