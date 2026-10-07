"""A failed sign-in stops presenting itself as an expired session.

Reported from environment P on 2026-09-07: the operator typed a password into
the console and got **"Session expired"** on a freshly created account that had
never held a session. The nginx log settles what actually happened -- four
`POST /auth/login` answered `401` with a 32-byte body, which is literally
`{"detail":"invalid credentials"}`, between two successful `curl` logins with
the same account minutes either side.

The console was the liar, not the API. `api()` is the single client for every
call including the login form, and it ended a 401 with an unconditional
`logout(); throw new ApiError(401, 'Session expired')`. Two consequences, both
of which sent the reader to the wrong place:

* **A login 401 is a credentials verdict, not an expiry.** It also entered the
  refresh-then-logout branch, so a stale `veyrs.rt` left in localStorage got
  spent trying to rescue a request that was never authenticated.
* **A 401 with no token at all cannot be an expiry either** -- there was no
  session to lose.

So `AUTH_ENTRY` names the routes that *establish* a session, their 401 falls
through to the generic error path (which surfaces the API's own `detail`), and
the "Session expired" wording is now conditional on having actually carried a
token. The routes are pinned here rather than the wording alone: dropping
`/auth/refresh` from the list would restore the recursion of a refresh trying
to refresh itself.
"""
from __future__ import annotations

import pathlib
import re

from conftest import ADMIN_PASSWORD, _flush_rate_limits

ROOT = pathlib.Path(__file__).resolve().parents[1]
APP_JS = ROOT / "frontend" / "console" / "app.js"

LOGIN = "/api/v1/auth/login"


def _src() -> str:
    return APP_JS.read_text(encoding="utf-8")


def _api_body() -> str:
    """The body of api(), where every 401 in the console is decided."""
    src = _src()
    start = src.index("async function api(path, opts = {})")
    end = src.index("const get  = (p)", start)
    return src[start:end]


# ── what the API actually says ────────────────────────────────────────────


def test_a_wrong_password_is_answered_as_bad_credentials(client, org_a):
    """The verdict the console has to relay, pinned so it cannot drift."""
    _flush_rate_limits()
    _, slug, email = org_a
    response = client.post(
        LOGIN, json={"email": email, "password": ADMIN_PASSWORD + "-wrong", "organization": slug}
    )
    assert response.status_code == 401, response.text
    detail = response.json()["detail"]
    assert "credential" in detail.lower()
    assert "expire" not in detail.lower()


def test_an_unknown_account_is_not_distinguished_from_a_bad_password(client, org_a):
    """Same wording for both, so the form cannot be used to enumerate users."""
    _flush_rate_limits()
    _, slug, _email = org_a
    response = client.post(
        LOGIN, json={"email": f"nobody@{slug}.test", "password": ADMIN_PASSWORD, "organization": slug}
    )
    assert response.status_code == 401, response.text
    assert "credential" in response.json()["detail"].lower()


# ── what the console does with it ─────────────────────────────────────────


def test_the_session_establishing_routes_are_named():
    src = _src()
    assert "const AUTH_ENTRY = ['/auth/login', '/auth/refresh'];" in src, (
        "both routes must be listed: login must not be reported as an expiry, and "
        "refresh must not be sent through a refresh of itself"
    )


def test_a_login_401_never_reaches_the_refresh_branch():
    body = _api_body()
    assert "if (res.status === 401 && store.rt && !entry) {" in body, (
        "a stale refresh token must not be spent on a request that was never authenticated"
    )


def test_a_login_401_never_logs_out_or_claims_an_expiry():
    body = _api_body()
    assert "if (res.status === 401 && !entry) {" in body
    # No unguarded 401 handler survives anywhere in api().
    assert not re.search(r"res\.status === 401\)\s*\{\s*logout\(\)", body), (
        "the unconditional logout-and-blame-the-session path is what produced the bug"
    )


def test_the_expiry_wording_requires_a_token_to_have_been_carried():
    body = _api_body()
    assert "const had = !!(store.at || store.rt);" in body
    assert "had ? 'Session expired' : 'Sign in to continue.'" in body
    assert _src().count("'Session expired'") == 1, (
        "one place decides this wording; a second copy is how the two cases diverge again"
    )


def test_the_login_form_still_goes_through_the_shared_client():
    """Fixed in api(), not by forking the call path -- one client, one 401 policy."""
    src = _src()
    assert "await api('/auth/login', { method: 'POST'" in src
    assert "ex.detail || 'Sign-in failed.'" in src, (
        "the form must render the API's own detail, which is what now reaches it"
    )
