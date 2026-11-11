"""Phase 54 -- two-factor by e-mail, by Telegram, and recovery codes.

What must never regress:
* a code is sent only AFTER the password is proved;
* a delivered code works once, expires, and five wrong guesses burn it;
* no transport or no Redis = the login fails CLOSED, never password-only;
* recovery codes are stored hashed and each works once;
* turning SMTP on for codes can hold the e-mail notification backlog.
"""
from __future__ import annotations

import os
import stat
import uuid
from types import SimpleNamespace

import pytest
from sqlalchemy import select

from conftest import ADMIN_PASSWORD, _flush_rate_limits  # noqa: F401
from veyrs.db import SessionLocal, set_tenant
from veyrs.models.tenancy import User
from veyrs.security import mfa, mfa_delivery
from veyrs.services import mfa_admin


@pytest.fixture()
def outbox(monkeypatch):
    """Every message 'sent', and a private code store per test."""
    sent: list[dict] = []
    monkeypatch.setattr(mfa_delivery, "_store", mfa_delivery.MemoryStore())
    monkeypatch.setattr(mfa_delivery.settings, "smtp_host", "relay.test")
    monkeypatch.setattr(mfa_delivery.settings, "telegram_bot_token", "123:test-token")

    def deliver(method, dest, subject, body):
        sent.append({"method": method, "to": dest, "subject": subject, "body": body,
                     "code": "".join(ch for ch in subject if ch.isdigit())[-6:]})

    monkeypatch.setattr(mfa_delivery, "deliver", deliver)
    return sent


def _attempt(client, email, slug, code=None, password=ADMIN_PASSWORD):
    _flush_rate_limits()
    body = {"email": email, "password": password, "organization": slug}
    if code is not None:
        body["mfa_code"] = code
    return client.post("/api/v1/auth/login", json=body)


def _user(email):
    with SessionLocal() as session:
        u = session.execute(select(User).where(User.email == email)).scalar_one()
        set_tenant(session, u.organization_id)
        return session.get(User, u.id)


def _reset(email):
    with SessionLocal() as session:
        u = session.execute(select(User).where(User.email == email)).scalar_one()
        set_tenant(session, u.organization_id)
        u = session.get(User, u.id)
        u.failed_logins, u.locked_until = 0, None
        session.commit()


def _clear_throttle(user_id):
    st = mfa_delivery.store()
    for kind in ("sent", "count"):
        st.delete(mfa_delivery._key(kind, user_id))


def _enable(client, headers, outbox, method="email", chat_id=None):
    body = {"method": method}
    if chat_id:
        body["telegram_chat_id"] = chat_id
    r = client.post("/api/v1/auth/mfa/enroll", headers=headers, json=body)
    assert r.status_code == 200, r.text
    assert r.json()["method"] == method and outbox, r.text
    act = client.post("/api/v1/auth/mfa/activate", headers=headers, json={"code": outbox[-1]["code"]})
    assert act.status_code == 200, act.text
    return act.json()["recovery_codes"]


# ------------------------------------------------------------------ e-mail ---
def test_email_lifecycle_login_and_single_use(client, org_a, admin_a, outbox):
    _, slug, email = org_a
    codes = _enable(client, admin_a, outbox, "email")
    assert len(codes) == 10 and outbox[-1]["to"] == email

    challenge = _attempt(client, email, slug)
    assert challenge.status_code == 401
    detail = challenge.json()["detail"]
    assert detail["error"] == "mfa_required" and detail["method"] == "email"
    assert "***" in detail["sent_to"] and email not in detail["sent_to"]
    code = outbox[-1]["code"]
    assert code not in challenge.text

    ok = _attempt(client, email, slug, code=code)
    assert ok.status_code == 200, ok.text
    assert _attempt(client, email, slug, code=code).status_code == 401   # single use
    _reset(email)


def test_no_code_is_sent_before_the_password_is_proved(client, org_a, admin_a, outbox):
    _, slug, email = org_a
    _enable(client, admin_a, outbox, "email")
    before = len(outbox)
    r = _attempt(client, email, slug, password="definitely-not-the-password")
    assert r.status_code == 401 and len(outbox) == before
    _reset(email)


def test_five_wrong_guesses_burn_the_code(client, org_a, admin_a, outbox):
    _, slug, email = org_a
    _enable(client, admin_a, outbox, "email")
    uid = _user(email).id
    _clear_throttle(uid)
    _attempt(client, email, slug)
    good = outbox[-1]["code"]
    wrong = "000000" if good != "000000" else "111111"
    for _ in range(mfa_delivery.MAX_TRIES):
        assert _attempt(client, email, slug, code=wrong).status_code == 401
    _reset(email)
    assert _attempt(client, email, slug, code=good).status_code == 401
    _reset(email)


def test_sending_is_throttled(client, org_a, admin_a, outbox):
    _, slug, email = org_a
    _enable(client, admin_a, outbox, "email")
    _clear_throttle(_user(email).id)
    _attempt(client, email, slug)
    n = len(outbox)
    again = _attempt(client, email, slug)
    assert again.status_code == 401 and again.json()["detail"].get("throttled") is True
    assert len(outbox) == n
    # the code from the first message still works
    assert _attempt(client, email, slug, code=outbox[-1]["code"]).status_code == 200
    _reset(email)


def test_delivery_failure_fails_closed_and_says_why(client, org_a, admin_a, outbox, monkeypatch):
    _, slug, email = org_a
    _enable(client, admin_a, outbox, "email")
    _clear_throttle(_user(email).id)

    def broken(*_a, **_k):
        raise mfa_delivery.DeliveryError("the mail relay refused the message: SMTPRecipientsRefused")

    monkeypatch.setattr(mfa_delivery, "deliver", broken)
    r = _attempt(client, email, slug)
    assert r.status_code == 503 and r.json()["detail"]["error"] == "mfa_delivery_failed"
    assert "access_token" not in r.text
    _reset(email)


def test_no_code_store_fails_closed(client, org_a, admin_a, outbox, monkeypatch):
    _, slug, email = org_a
    _enable(client, admin_a, outbox, "email")

    class Down(mfa_delivery.MemoryStore):
        def get(self, key):
            raise ConnectionError("redis down")

    monkeypatch.setattr(mfa_delivery, "_store", Down())
    assert _attempt(client, email, slug, code="123456").status_code == 401
    _reset(email)


# ---------------------------------------------------------------- telegram ---
def test_telegram_needs_a_numeric_chat_id(client, admin_a, outbox):
    r = client.post("/api/v1/auth/mfa/enroll", headers=admin_a,
                    json={"method": "telegram", "telegram_chat_id": "@someone"})
    assert r.status_code == 422


def test_telegram_lifecycle(client, org_a, admin_a, outbox):
    _, slug, email = org_a
    _enable(client, admin_a, outbox, "telegram", chat_id="987654321")
    assert outbox[-1]["method"] == "telegram" and outbox[-1]["to"] == "987654321"
    _clear_throttle(_user(email).id)
    ch = _attempt(client, email, slug)
    assert ch.json()["detail"]["method"] == "telegram" and ch.json()["detail"]["sent_to"].endswith("321")
    assert _attempt(client, email, slug, code=outbox[-1]["code"]).status_code == 200
    _reset(email)


def test_unconfigured_method_is_not_offered(client, admin_a, outbox, monkeypatch):
    monkeypatch.setattr(mfa_delivery.settings, "telegram_bot_token", "")
    st = client.get("/api/v1/auth/mfa", headers=admin_a).json()
    assert st["available"] == {"totp": True, "email": True, "telegram": False}
    r = client.post("/api/v1/auth/mfa/enroll", headers=admin_a,
                    json={"method": "telegram", "telegram_chat_id": "123456"})
    assert r.status_code == 409 and r.json()["detail"]["error"] == "mfa_method_unavailable"


def test_telegram_transport_never_leaks_the_token(monkeypatch):
    import httpx

    monkeypatch.setattr(mfa_delivery.settings, "telegram_bot_token", "999:SECRET-TOKEN")

    def boom(url, **_k):
        raise httpx.ConnectError(f"cannot connect to {url}")

    monkeypatch.setattr(httpx, "post", boom)
    with pytest.raises(mfa_delivery.DeliveryError) as exc:
        mfa_delivery.send_telegram("123456", "hi")
    assert "SECRET-TOKEN" not in str(exc.value)


# ---------------------------------------------------------- recovery codes ---
def test_recovery_codes_are_hashed_and_single_use(client, org_a, admin_a, outbox):
    _, slug, email = org_a
    codes = _enable(client, admin_a, outbox, "email")
    stored = _user(email).mfa_recovery_codes
    assert len(stored) == 10 and not any(c.replace("-", "") in str(stored) for c in codes)

    assert _attempt(client, email, slug, code=codes[0].upper()).status_code == 200  # case-insensitive
    _reset(email)
    assert _attempt(client, email, slug, code=codes[0]).status_code == 401           # spent
    _reset(email)
    assert len(_user(email).mfa_recovery_codes) == 9
    status = client.get("/api/v1/auth/mfa", headers=admin_a).json()
    assert status["recovery_codes_left"] == 9


def test_disable_with_a_recovery_code(client, org_a, admin_a, outbox):
    _, _, email = org_a
    codes = _enable(client, admin_a, outbox, "email")
    r = client.post("/api/v1/auth/mfa/disable", headers=admin_a,
                    json={"password": ADMIN_PASSWORD, "code": codes[3]})
    assert r.status_code == 204, r.text
    u = _user(email)
    assert not u.mfa_enabled and u.mfa_method is None and u.mfa_recovery_codes is None


def test_recovery_codes_can_be_replaced(client, org_a, admin_a, outbox):
    codes = _enable(client, admin_a, outbox, "email")
    r = client.post("/api/v1/auth/mfa/recovery-codes", headers=admin_a,
                    json={"password": ADMIN_PASSWORD, "code": codes[0]})
    assert r.status_code == 200, r.text
    new = r.json()["recovery_codes"]
    assert len(new) == 10 and not set(new) & set(codes)


def test_recovery_code_shape():
    shown, stored = mfa_delivery.new_recovery_codes()
    assert all(mfa_delivery.looks_like_recovery(c) for c in shown)
    assert len(set(shown)) == 10 and len(stored[0]) == 64
    assert not mfa_delivery.looks_like_recovery("123456")


# --------------------------------------------------------------------- totp ---
def test_totp_enrolment_carries_a_server_side_qr(client, admin_a):
    r = client.post("/api/v1/auth/mfa/enroll", headers=admin_a, json={"method": "totp"})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["method"] == "totp" and body["qr_svg"].startswith("<svg")
    code = mfa._code_at(body["secret"], mfa.current_step())
    act = client.post("/api/v1/auth/mfa/activate", headers=admin_a, json={"code": code})
    assert act.status_code == 200 and len(act.json()["recovery_codes"]) == 10


# ----------------------------------------------------- notification backlog ---
def test_held_email_notifications_stay_pending(org_a, monkeypatch):
    from veyrs.models.workflow import Notification
    from veyrs.services import notifications

    org_id, _, _ = org_a
    calls = []
    monkeypatch.setitem(notifications.TRANSPORTS, "email", lambda n: calls.append(n.id))
    monkeypatch.setattr(notifications.settings, "notify_email_enabled", False)
    with SessionLocal() as s:
        set_tenant(s, org_id)
        e = Notification(organization_id=org_id, channel="email", event="sla.breached",
                         subject="s", body="b", recipient_address="x@example.org")
        i = Notification(organization_id=org_id, channel="in_app", event="sla.breached",
                         subject="s", body="b")
        s.add_all([e, i])
        s.commit()
        stats = notifications.dispatch(s, org_id)
        s.commit()
        s.refresh(e)
        s.refresh(i)
        assert calls == [] and e.status == "pending" and e.attempts == 0
        assert i.status == "sent" and stats["sent"] >= 1


# ---------------------------------------------------------------------- CLI ---
def test_cli_setup_proves_delivery_first(org_a, outbox, tmp_path, monkeypatch):
    _, _, email = org_a
    path = tmp_path / "rc.txt"
    args = SimpleNamespace(email=email, method="telegram", chat_id="555000111", recovery_file=str(path))

    def refuse(*_a, **_k):
        raise mfa_delivery.DeliveryError("Telegram refused the message: chat not found")

    monkeypatch.setattr(mfa_delivery, "deliver", refuse)
    assert mfa_admin.mfa_setup(args) == 1
    assert not _user(email).mfa_enabled and not path.exists()

    monkeypatch.setattr(mfa_delivery, "deliver", lambda *a, **k: None)
    assert mfa_admin.mfa_setup(args) == 0
    u = _user(email)
    assert u.mfa_enabled and u.mfa_method == "telegram" and u.mfa_telegram_chat_id == "555000111"
    assert stat.S_IMODE(os.stat(path).st_mode) == 0o600
    assert len([l for l in path.read_text().splitlines() if not l.startswith("#")]) == 10

    assert mfa_admin.mfa_reset(SimpleNamespace(email=email, reason="test")) == 0
    assert not _user(email).mfa_enabled
