"""AI providers that sign in and renew their token (session / OAuth 2.0).

No test here reaches the network: `httpx.post` and the outbound guard are
replaced, and time is driven by hand.
"""
from __future__ import annotations

import base64
import json
import time

import pytest
from sqlalchemy import select

from veyrs.db import SessionLocal, set_tenant
from veyrs.models.ai import AiProvider
from veyrs.models.audit import AuditLog
from veyrs.security import secrets as secretstore
from veyrs.services import net_guard, secret_storage
from veyrs.services.ai import gateway, providers, token_auth
from veyrs.services.ai.providers import ProviderError, ProviderSpec


class FakeResponse:
    def __init__(self, status_code: int, body: object):
        self.status_code = status_code
        self._body = body

    def json(self):
        if isinstance(self._body, Exception):
            raise self._body
        return self._body


def _jwt(claims: dict) -> str:
    enc = lambda d: base64.urlsafe_b64encode(json.dumps(d).encode()).decode().rstrip("=")
    return f"{enc({'alg': 'none'})}.{enc(claims)}.sig"


@pytest.fixture(autouse=True)
def _isolated(monkeypatch):
    token_auth.invalidate()
    monkeypatch.setattr(net_guard, "check_url", lambda *a, **k: None)
    yield
    token_auth.invalidate()


def _auth(mode="session", **kw) -> token_auth.TokenAuth:
    base = dict(mode=mode, token_url="https://gw.example.com/token", secret="s3cret-pass",
                username="svc-veyrs", client_id="veyrs-client", cache_key=f"k-{mode}")
    base.update(kw)
    return token_auth.TokenAuth(**base)


# ---------------------------------------------------------------------------
# lifetime: Auto, and a typed value is a ceiling
# ---------------------------------------------------------------------------
def test_lifetime_comes_from_expires_in_first():
    seconds, source = token_auth.resolve_lifetime(
        _auth(), {"expires_in": 900, "expires_at": time.time() + 60}, "opaque")
    assert (seconds, source) == (900, "expires_in")


@pytest.mark.parametrize("value", [
    lambda now: now + 1200,                         # epoch seconds
    lambda now: int((now + 1200) * 1000),           # epoch milliseconds
    lambda now: __import__("datetime").datetime.fromtimestamp(
        now + 1200, __import__("datetime").timezone.utc).isoformat(),
])
def test_lifetime_from_expires_at_in_any_common_shape(value):
    now = 1_800_000_000.0
    seconds, source = token_auth.resolve_lifetime(
        _auth(), {"expires_at": value(now)}, "opaque", now=now)
    assert source == "expires_at" and abs(seconds - 1200) <= 1


def test_lifetime_from_the_jwt_exp_claim_when_the_answer_says_nothing():
    now = 1_800_000_000.0
    token = _jwt({"sub": "svc", "exp": int(now + 3600)})
    assert token_auth.resolve_lifetime(_auth(), {}, token, now=now) == (3600, "jwt exp")


@pytest.mark.parametrize("mode,expected", [("session", 240), ("oauth2", 300)])
def test_lifetime_defaults_are_conservative_when_nothing_is_known(mode, expected):
    assert token_auth.resolve_lifetime(_auth(mode), {}, "opaque") == (expected, "default")


def test_typed_lifetime_is_a_ceiling_not_a_floor():
    longer = token_auth.resolve_lifetime(_auth(lifetime_minutes=10), {"expires_in": 3600}, "t")
    assert longer == (600, "configured ceiling")
    shorter = token_auth.resolve_lifetime(_auth(lifetime_minutes=10), {"expires_in": 120}, "t")
    assert shorter == (120, "expires_in")


def test_renewal_margin_is_ten_percent_capped_at_a_minute():
    short = token_auth.Token("t", lifetime=300, source="x", obtained_at=0.0)
    long = token_auth.Token("t", lifetime=3600, source="x", obtained_at=0.0)
    assert short.renew_at == 270
    assert long.renew_at == 3540


# ---------------------------------------------------------------------------
# signing in
# ---------------------------------------------------------------------------
def _capture(monkeypatch, responses):
    calls = []
    queue = list(responses)

    def fake_post(url, **kwargs):
        calls.append((url, kwargs))
        return queue.pop(0) if len(queue) > 1 else queue[0]

    import httpx
    monkeypatch.setattr(httpx, "post", fake_post)
    return calls


def test_session_sign_in_posts_the_configured_fields(monkeypatch):
    calls = _capture(monkeypatch, [FakeResponse(200, {"data": {"token": "tok-1"}, "expires_in": 600})])
    auth = _auth(username_field="user", password_field="pass", token_field="data.token")
    token = token_auth.sign_in(auth)
    url, kwargs = calls[0]
    assert url == "https://gw.example.com/token"
    assert kwargs["json"] == {"user": "svc-veyrs", "pass": "s3cret-pass"}
    assert (token.value, token.lifetime, token.source) == ("tok-1", 600, "expires_in")


def test_session_sign_in_can_send_a_form(monkeypatch):
    calls = _capture(monkeypatch, [FakeResponse(200, {"access_token": "tok"})])
    token_auth.sign_in(_auth(body_format="form"))
    assert calls[0][1]["data"] == {"username": "svc-veyrs", "password": "s3cret-pass"}
    assert "json" not in calls[0][1]


def test_oauth2_uses_client_credentials_with_basic_auth(monkeypatch):
    calls = _capture(monkeypatch, [FakeResponse(200, {"access_token": "tok", "expires_in": 3599})])
    token_auth.sign_in(_auth("oauth2", scope="models.read"))
    kwargs = calls[0][1]
    assert kwargs["data"] == {"grant_type": "client_credentials", "scope": "models.read"}
    assert kwargs["auth"] == ("veyrs-client", "s3cret-pass")


def test_a_sign_in_answer_without_a_token_fails_without_echoing_it(monkeypatch):
    _capture(monkeypatch, [FakeResponse(200, {"message": "hello svc-veyrs"})])
    with pytest.raises(ProviderError) as exc:
        token_auth.sign_in(_auth())
    assert "svc-veyrs" not in str(exc.value)


def test_a_refused_sign_in_reports_only_the_status(monkeypatch):
    _capture(monkeypatch, [FakeResponse(403, {"error": "bad password s3cret-pass"})])
    with pytest.raises(ProviderError) as exc:
        token_auth.sign_in(_auth())
    assert exc.value.status == 403
    assert "s3cret" not in str(exc.value)


def test_token_is_cached_and_renewed_before_it_expires(monkeypatch):
    calls = _capture(monkeypatch, [FakeResponse(200, {"access_token": "a", "expires_in": 300}),
                                   FakeResponse(200, {"access_token": "b", "expires_in": 300})])
    clock = [1000.0]
    monkeypatch.setattr(token_auth.time, "monotonic", lambda: clock[0])
    auth = _auth()
    assert token_auth.get_token(auth) == "a"
    clock[0] += 269                       # inside the window: no new sign-in
    assert token_auth.get_token(auth) == "a"
    assert len(calls) == 1
    clock[0] += 2                         # past 300 - 30 s margin: renewed
    assert token_auth.get_token(auth) == "b"
    assert len(calls) == 2


# ---------------------------------------------------------------------------
# the provider: 401 -> sign in again, retry once
# ---------------------------------------------------------------------------
def _chat_spec() -> ProviderSpec:
    return ProviderSpec(slug="gw", kind="openai_compatible", model="m",
                        base_url="https://gw.example.com", auth=_auth())


def _chat_ok():
    return FakeResponse(200, {"choices": [{"message": {"content": "answer"}}], "model": "m"})


def test_provider_sends_the_token_as_bearer(monkeypatch):
    calls = _capture(monkeypatch, [FakeResponse(200, {"access_token": "tok-1"}), _chat_ok()])
    out = providers.OpenAICompatibleProvider().complete(_chat_spec(), "sys", "q")
    assert out.text == "answer"
    assert calls[1][1]["headers"]["Authorization"] == "Bearer tok-1"


def test_expired_token_is_renewed_on_401_and_the_call_retried_once(monkeypatch):
    calls = _capture(monkeypatch, [
        FakeResponse(200, {"access_token": "old"}), FakeResponse(401, {}),
        FakeResponse(200, {"access_token": "new"}), _chat_ok(),
    ])
    out = providers.OpenAICompatibleProvider().complete(_chat_spec(), "sys", "q")
    assert out.text == "answer"
    auth_headers = [c[1]["headers"].get("Authorization") for c in calls if "/chat/" in c[0]]
    assert auth_headers == ["Bearer old", "Bearer new"]


def test_a_second_401_is_an_error_not_a_loop(monkeypatch):
    calls = _capture(monkeypatch, [
        FakeResponse(200, {"access_token": "a"}), FakeResponse(401, {}),
        FakeResponse(200, {"access_token": "b"}), FakeResponse(401, {}),
    ])
    with pytest.raises(ProviderError) as exc:
        providers.OpenAICompatibleProvider().complete(_chat_spec(), "sys", "q")
    assert exc.value.status == 401
    assert len(calls) == 4


def test_other_errors_do_not_trigger_a_new_sign_in(monkeypatch):
    calls = _capture(monkeypatch, [FakeResponse(200, {"access_token": "a"}), FakeResponse(500, {})])
    with pytest.raises(ProviderError):
        providers.OpenAICompatibleProvider().complete(_chat_spec(), "sys", "q")
    assert len(calls) == 2


def test_static_key_providers_are_unchanged(monkeypatch):
    calls = _capture(monkeypatch, [FakeResponse(401, {})])
    spec = ProviderSpec(slug="k", kind="openai", model="m", api_key="sk-static")
    with pytest.raises(ProviderError):
        providers.OpenAICompatibleProvider().complete(spec, "sys", "q")
    assert len(calls) == 1
    assert calls[0][1]["headers"]["Authorization"] == "Bearer sk-static"


# ---------------------------------------------------------------------------
# configuration validation
# ---------------------------------------------------------------------------
def test_validation_rejects_what_cannot_work():
    good = {"token_url": "https://gw/t", "username": "u"}
    assert token_auth.validate_config("session", good, has_secret=True)["username"] == "u"
    with pytest.raises(ValueError, match="password"):
        token_auth.validate_config("session", good, has_secret=False)
    with pytest.raises(ValueError, match="token_url"):
        token_auth.validate_config("session", {"username": "u"}, has_secret=True)
    with pytest.raises(ValueError, match="client_id"):
        token_auth.validate_config("oauth2", {"token_url": "https://gw/t"}, has_secret=True)
    with pytest.raises(ValueError, match="unknown"):
        token_auth.validate_config("session", {**good, "password": "x"}, has_secret=True)
    with pytest.raises(ValueError, match="1440"):
        token_auth.validate_config("session", {**good, "lifetime_minutes": 0}, has_secret=True)
    assert token_auth.validate_config("api_key", {}, has_secret=False) == {}


def test_the_new_secret_column_is_registered_for_rekey_and_vault():
    assert ("ai_providers", "auth_secret_enc") in {(c.table, c.column)
                                                   for c in secret_storage.COLUMNS}


# ---------------------------------------------------------------------------
# HTTP API
# ---------------------------------------------------------------------------
SESSION_PROVIDER = {
    "slug": "client-gw", "name": "Client gateway", "kind": "openai_compatible",
    "model": "gpt-x", "base_url": "https://gw.example.com", "is_external": True,
    "auth_mode": "session", "auth_secret": "pw-never-shown-123",
    "auth_config": {"token_url": "https://gw.example.com/token", "username": "svc-veyrs"},
}


def test_session_provider_is_stored_sealed_and_listed_without_the_password(client, admin_a, org_a):
    response = client.post("/api/v1/ai/providers", headers=admin_a,
                           json={**SESSION_PROVIDER, "api_key": "sk-ignored"})
    assert response.status_code == 201, response.text
    listing = client.get("/api/v1/ai/providers", headers=admin_a).json()
    row = next(r for r in listing if r["slug"] == "client-gw")
    assert row["auth_mode"] == "session"
    assert row["auth_config"]["username"] == "svc-veyrs"
    assert "pw-never-shown-123" not in json.dumps(listing)
    with SessionLocal() as session:
        set_tenant(session, org_a[0])
        stored = session.execute(select(AiProvider).where(AiProvider.slug == "client-gw")).scalar_one()
        assert stored.api_key_enc is None                       # no stale second credential
        assert stored.auth_secret_enc != "pw-never-shown-123"
        assert secretstore.decrypt(stored.auth_secret_enc) == "pw-never-shown-123"
        spec = gateway.build_spec(stored)
        assert spec.api_key is None and spec.auth.username == "svc-veyrs"


@pytest.mark.parametrize("change,needle", [
    ({"kind": "ollama"}, "needs kind"),
    ({"auth_secret": None}, "password"),
    ({"auth_config": {"token_url": "https://gw/t", "username": "u", "bogus": 1}}, "unknown"),
    ({"auth_mode": "magic"}, "auth_mode"),
])
def test_invalid_sign_in_settings_are_refused(client, admin_a, change, needle):
    response = client.post("/api/v1/ai/providers", headers=admin_a,
                           json={**SESSION_PROVIDER, **change})
    assert response.status_code == 422
    assert needle in response.text


def test_test_button_signs_in_and_reports_the_lifetime(client, admin_a, org_a, monkeypatch):
    created = client.post("/api/v1/ai/providers", headers=admin_a, json=SESSION_PROVIDER).json()
    _capture(monkeypatch, [FakeResponse(200, {"access_token": _jwt({"exp": int(time.time()) + 1800})})])
    result = client.post(f"/api/v1/ai/providers/{created['id']}/test", headers=admin_a).json()
    assert result["ok"] is True
    assert result["lifetime_source"] == "jwt exp"
    assert 1790 <= result["lifetime_seconds"] <= 1800
    assert "access_token" not in json.dumps(result)
    with SessionLocal() as session:
        set_tenant(session, org_a[0])
        actions = session.execute(select(AuditLog.action)).scalars().all()
    assert "ai.provider.sign_in_tested" in actions


def test_test_button_reports_a_failed_sign_in_as_a_result(client, admin_a, monkeypatch):
    created = client.post("/api/v1/ai/providers", headers=admin_a, json=SESSION_PROVIDER).json()
    _capture(monkeypatch, [FakeResponse(401, {})])
    result = client.post(f"/api/v1/ai/providers/{created['id']}/test", headers=admin_a).json()
    assert result == {"auth_mode": "session", "ok": False, "error": "sign-in returned HTTP 401"}


def test_test_button_refuses_a_static_key_provider(client, admin_a):
    created = client.post("/api/v1/ai/providers", headers=admin_a, json={
        "slug": "static", "name": "Static", "kind": "ollama", "model": "m",
        "is_external": False}).json()
    response = client.post(f"/api/v1/ai/providers/{created['id']}/test", headers=admin_a)
    assert response.status_code == 422
