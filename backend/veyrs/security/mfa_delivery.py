"""Second factors delivered to the person: a code by e-mail or by Telegram.

`security/mfa.py` is the authenticator-app factor (TOTP): nothing is sent, the
app computes the code. This module is the other two, plus recovery codes:

* **email**    -- a six-digit code to the account's own address, through the
                  SMTP relay in `VEYRS_SMTP_*`.
* **telegram** -- the same code from a Telegram bot (`VEYRS_TELEGRAM_BOT_TOKEN`)
                  to a chat id the person registered and proved at enrolment.
* **recovery codes** -- ten single-use codes handed out once at activation.
  They are the way back in when the phone or the mailbox is gone; without them
  the only way back is an operator on the host (`veyrs mfa-reset`).

Decisions worth knowing before changing anything here
-----------------------------------------------------
  * A code is sent only AFTER the password was verified (the login endpoint
    calls `issue()` from inside the MFA branch). Nobody can make VEYRS message
    somebody by typing their address.
  * Codes live in Redis, hashed with the user id, for `VEYRS_MFA_CODE_TTL`
    seconds (default 300). Redis is shared by every app node, so a code sent by
    a1 is accepted by a2 after a failover. No Redis = no code = the login fails
    CLOSED; it never falls back to password-only.
  * One code per account at a time; five wrong guesses burn it. The login
    endpoint ALSO charges every wrong code to the shared lockout budget.
  * Sending is throttled: one message per 30 s and six per 15 minutes per
    account. A script that knows the password cannot use VEYRS to flood
    somebody's phone.
  * A code is single-use: it is deleted the moment it is accepted.
  * Recovery codes are stored as SHA-256 of the normalised code. They are 60
    random bits each from a 32-symbol alphabet, not a memorised secret, so a
    slow hash would add nothing an attacker could not already afford to skip.
  * Delivery text is English, like every VEYRS surface.
"""
from __future__ import annotations

import hashlib
import hmac
import json
import re
import secrets
import smtplib
import time
from email.message import EmailMessage
from typing import Any, Protocol

from ..config import settings

METHODS = ("totp", "email", "telegram")
DELIVERED = ("email", "telegram")
DIGITS = 6
MAX_TRIES = 5
RESEND_SECONDS = 30
WINDOW_SECONDS = 900
MAX_SENDS_PER_WINDOW = 6
RECOVERY_COUNT = 10
_RECOVERY_ALPHABET = "abcdefghjkmnpqrstuvwxyz23456789"  # no 0/o, 1/l/i
_RECOVERY_RE = re.compile(r"^[a-z2-9]{4}-?[a-z2-9]{4}-?[a-z2-9]{4}$")
_CHAT_ID_RE = re.compile(r"^-?\d{3,20}$")


class DeliveryError(RuntimeError):
    """The code could not be sent (transport not configured, or it refused)."""


class Throttled(RuntimeError):
    """A code was sent too recently, or too many were sent in the window."""

    def __init__(self, message: str, retry_after: int) -> None:
        super().__init__(message)
        self.retry_after = retry_after


# ----------------------------------------------------------------- store ---
class Store(Protocol):
    def get(self, key: str) -> str | None: ...
    def set(self, key: str, value: str, ttl: int) -> None: ...
    def delete(self, key: str) -> None: ...
    def incr(self, key: str, ttl: int) -> int: ...
    def ttl(self, key: str) -> int: ...


class RedisStore:
    def __init__(self) -> None:
        import redis

        self._r = redis.Redis.from_url(settings.redis_url, socket_timeout=2, decode_responses=True)

    def get(self, key: str) -> str | None:
        return self._r.get(key)

    def set(self, key: str, value: str, ttl: int) -> None:
        self._r.set(key, value, ex=ttl)

    def delete(self, key: str) -> None:
        self._r.delete(key)

    def incr(self, key: str, ttl: int) -> int:
        value = int(self._r.incr(key))
        if value == 1:          # first send of the window starts the clock
            self._r.expire(key, ttl)
        return value

    def ttl(self, key: str) -> int:
        return max(0, int(self._r.ttl(key)))


class MemoryStore:
    """For tests and for the CLI's dry runs: same contract, in one process."""

    def __init__(self) -> None:
        self._d: dict[str, tuple[str, float]] = {}

    def _alive(self, key: str) -> tuple[str, float] | None:
        hit = self._d.get(key)
        if hit and hit[1] > time.time():
            return hit
        self._d.pop(key, None)
        return None

    def get(self, key: str) -> str | None:
        hit = self._alive(key)
        return hit[0] if hit else None

    def set(self, key: str, value: str, ttl: int) -> None:
        self._d[key] = (value, time.time() + ttl)

    def delete(self, key: str) -> None:
        self._d.pop(key, None)

    def incr(self, key: str, ttl: int) -> int:
        hit = self._alive(key)
        value = int(hit[0]) + 1 if hit else 1
        self._d[key] = (str(value), hit[1] if hit else time.time() + ttl)
        return value

    def ttl(self, key: str) -> int:
        hit = self._alive(key)
        return max(0, int(hit[1] - time.time())) if hit else 0


_store: Store | None = None


def store() -> Store:
    global _store
    if _store is None:
        _store = RedisStore()
    return _store


def _key(kind: str, user_id: Any) -> str:
    return f"veyrs:mfa:{kind}:{user_id}"


def _digest(user_id: Any, code: str) -> str:
    return hashlib.sha256(f"{user_id}:{code}".encode()).hexdigest()


# ------------------------------------------------------------ transports ---
def available() -> dict[str, bool]:
    """Which methods this installation can offer right now."""
    return {"totp": True, "email": bool(settings.smtp_host),
            "telegram": bool(settings.telegram_bot_token)}


def mask_email(address: str) -> str:
    local, _, domain = (address or "").partition("@")
    if not domain:
        return "***"
    return (local[:1] + "***" + (local[-1:] if len(local) > 2 else "")) + "@" + domain


def mask_chat(chat_id: str) -> str:
    chat_id = str(chat_id or "")
    return "Telegram chat ***" + chat_id[-3:] if chat_id else "Telegram"


def valid_chat_id(chat_id: str | None) -> bool:
    return bool(chat_id and _CHAT_ID_RE.match(str(chat_id).strip()))


def _message(code: str, purpose: str) -> tuple[str, str]:
    minutes = max(1, settings.mfa_code_ttl // 60)
    what = {"login": "sign-in", "enroll": "two-factor set-up", "verify": "confirmation",
            "test": "delivery test"}.get(purpose, "verification")
    subject = f"VEYRS {what} code: {code}"
    body = (f"Your VEYRS {what} code is {code}\n\n"
            f"It expires in {minutes} minutes and works once.\n"
            "If you did not just try to sign in to VEYRS, someone has your password: "
            "change it now.\n")
    return subject, body


def send_email(address: str, subject: str, body: str) -> None:
    if not settings.smtp_host:
        raise DeliveryError("e-mail delivery is not configured (VEYRS_SMTP_HOST is empty)")
    message = EmailMessage()
    message["From"] = settings.smtp_from
    message["To"] = address
    message["Subject"] = subject
    message.set_content(body)
    try:
        with smtplib.SMTP(settings.smtp_host, settings.smtp_port, timeout=15) as smtp:
            if settings.smtp_starttls:
                smtp.starttls()
            if settings.smtp_user:
                smtp.login(settings.smtp_user, settings.smtp_password or "")
            smtp.send_message(message)
    except (OSError, smtplib.SMTPException) as exc:
        raise DeliveryError(f"the mail relay refused the message: {type(exc).__name__}") from None


def send_telegram(chat_id: str, text: str) -> None:
    token = settings.telegram_bot_token
    if not token:
        raise DeliveryError("Telegram delivery is not configured (VEYRS_TELEGRAM_BOT_TOKEN is empty)")
    import httpx  # local: `import veyrs` stays free of network clients

    url = settings.telegram_api_url.rstrip("/") + f"/bot{token}/sendMessage"
    try:
        response = httpx.post(url, json={"chat_id": str(chat_id), "text": text,
                                         "disable_web_page_preview": True}, timeout=10)
        data = response.json()
    except (httpx.HTTPError, ValueError) as exc:
        # Never echo the URL: it carries the bot token.
        raise DeliveryError(f"Telegram could not be reached: {type(exc).__name__}") from None
    if not data.get("ok"):
        # Telegram's own words ("chat not found", "bot was blocked by the user")
        # are what the person needs to fix it; they carry no secret.
        raise DeliveryError(f"Telegram refused the message: {str(data.get('description') or '')[:160]}")


def deliver(method: str, destination: str, subject: str, body: str) -> None:
    if method == "email":
        send_email(destination, subject, body)
    elif method == "telegram":
        send_telegram(destination, body)
    else:
        raise DeliveryError(f"{method!r} is not a delivered method")


def destination(user: Any, method: str | None = None) -> str | None:
    method = method or user.mfa_method
    if method == "email":
        return user.email
    if method == "telegram":
        return user.mfa_telegram_chat_id
    return None


def masked(user: Any, method: str | None = None) -> str | None:
    method = method or user.mfa_method
    dest = destination(user, method)
    if not dest:
        return None
    return mask_email(dest) if method == "email" else mask_chat(dest)


# ------------------------------------------------------------ one-time codes ---
def issue(user: Any, method: str, *, purpose: str = "login") -> str:
    """Send a fresh code by `method`; return where it went (masked).

    Raises Throttled (nothing sent) or DeliveryError (nothing stored).
    """
    if method not in DELIVERED:
        raise DeliveryError(f"{method!r} codes are not sent")
    dest = destination(user, method)
    if not dest:
        raise DeliveryError(f"no {method} destination is registered for this account")
    st = store()
    if st.get(_key("sent", user.id)):
        raise Throttled("a code was sent less than 30 seconds ago", st.ttl(_key("sent", user.id)) or RESEND_SECONDS)
    count_key = _key("count", user.id)
    if st.incr(count_key, WINDOW_SECONDS) > MAX_SENDS_PER_WINDOW:
        raise Throttled("too many codes were sent to this account; wait a few minutes",
                        st.ttl(count_key) or WINDOW_SECONDS)
    code = f"{secrets.randbelow(10 ** DIGITS):0{DIGITS}d}"
    subject, body = _message(code, purpose)
    deliver(method, dest, subject, body)   # raises DeliveryError: nothing stored
    st.set(_key("otp", user.id), json.dumps({"h": _digest(user.id, code), "tries": 0, "m": method}),
           settings.mfa_code_ttl)
    st.set(_key("sent", user.id), "1", RESEND_SECONDS)
    return masked(user, method) or method


def check(user: Any, code: str | None, method: str | None = None) -> bool:
    """True once for the right code. Wrong guesses are counted; the fifth burns it."""
    code = re.sub(r"\s", "", code or "")
    if not re.fullmatch(rf"\d{{{DIGITS}}}", code):
        return False
    st = store()
    key = _key("otp", user.id)
    raw = st.get(key)
    if not raw:
        return False
    try:
        data = json.loads(raw)
    except ValueError:
        st.delete(key)
        return False
    if method and data.get("m") != method:
        return False
    if hmac.compare_digest(str(data.get("h", "")), _digest(user.id, code)):
        st.delete(key)
        # The resend pause guards an OUTSTANDING code. Once it is used, the next
        # sign-in (often seconds later, right after activation) may get one.
        st.delete(_key("sent", user.id))
        return True
    data["tries"] = int(data.get("tries", 0)) + 1
    if data["tries"] >= MAX_TRIES:
        st.delete(key)
    else:
        st.set(key, json.dumps(data), max(1, st.ttl(key)))
    return False


# ------------------------------------------------------------ recovery codes ---
def _norm_recovery(code: str) -> str:
    return re.sub(r"[\s-]", "", (code or "").lower())


def looks_like_recovery(code: str | None) -> bool:
    return bool(code and _RECOVERY_RE.match(re.sub(r"\s", "", code.lower())))


def new_recovery_codes() -> tuple[list[str], list[str]]:
    """(codes to show ONCE, hashes to store)."""
    shown, stored = [], []
    for _ in range(RECOVERY_COUNT):
        raw = "".join(secrets.choice(_RECOVERY_ALPHABET) for _ in range(12))
        shown.append(f"{raw[:4]}-{raw[4:8]}-{raw[8:]}")
        stored.append(hashlib.sha256(raw.encode()).hexdigest())
    return shown, stored


def use_recovery_code(user: Any, code: str | None) -> bool:
    """Consume one recovery code. The caller commits the session."""
    if not looks_like_recovery(code):
        return False
    digest = hashlib.sha256(_norm_recovery(code).encode()).hexdigest()
    remaining = list(user.mfa_recovery_codes or [])
    hit = None
    for stored in remaining:
        if hmac.compare_digest(stored, digest):
            hit = stored
    if hit is None:
        return False
    remaining.remove(hit)
    user.mfa_recovery_codes = remaining
    return True
