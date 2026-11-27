"""Failed-credential accounting: who may try a credential again, and when.

Every place that checks something the person KNOWS -- the sign-in password and
second factor, and the current password that `/auth/password`,
`/auth/mfa/disable` and `/auth/mfa/recovery-codes` ask for -- charges a
failure here and asks `retry_after()` before checking anything.

The policy (risk register R-13, R-24)
-------------------------------------
The old rule was "ten failures lock the account for 15 minutes", and anybody
who knew an administrator's address could keep that account locked forever
from one machine. The rule now has two layers:

1. **Per source** -- one account seen from one client address. The first
   `SOURCE_FREE` (5) failures cost nothing. From then on each failure makes
   that source wait before its next attempt is even evaluated: 30 s, 60 s,
   2 min ... doubling to `SOURCE_CAP_SECONDS` (15 min). The counter is
   remembered for a day after the first failure. A guesser at one address is
   slowed to a handful of tries an hour and locks out nobody but itself.
2. **Per account** -- the tripwire for a guess spread over many addresses.
   Only a source's free failures count toward it, so a single address can
   never trip it: `ACCOUNT_THRESHOLD` (20) counted failures need at least four
   different sources. Then the account refuses every source for 1 min,
   doubling with each further counted failure up to `ACCOUNT_CAP_SECONDS`
   (1 h). Sources inside `VEYRS_LOCKOUT_EXEMPT_NETWORKS` are not refused by
   this layer (they still have their own per-source back-off), and an
   operator can clear both layers with `veyrs unlock --email`.

A success clears the source's counter and the account counter. A refused
attempt (source waiting or account locked) is not evaluated and not counted:
it neither reveals whether the password was right nor extends the wait.

Storage: the per-source counters live in the same Redis as the delivered MFA
codes (`mfa_delivery.store()`), shared by every application node. If it is
unreachable the per-source layer is skipped and every failure counts toward
the account layer instead -- the pre-0.41 behaviour, never "no limit".
"""
from __future__ import annotations

import datetime as dt
import hashlib
import ipaddress
import logging
from functools import lru_cache
from typing import Any

from ..config import settings

log = logging.getLogger("veyrs.lockout")

SOURCE_FREE = 5
SOURCE_BASE_SECONDS = 30
SOURCE_CAP_SECONDS = 900
SOURCE_MEMORY_SECONDS = 86400
ACCOUNT_THRESHOLD = 20
ACCOUNT_BASE_SECONDS = 60
ACCOUNT_CAP_SECONDS = 3600
_GENERATION_TTL = 30 * 86400


def _store():
    from . import mfa_delivery  # local: one shared Redis client, swapped by tests

    return mfa_delivery.store()


@lru_cache(maxsize=8)
def _networks(raw: str) -> tuple:
    nets = []
    for part in (p.strip() for p in (raw or "").split(",")):
        if not part:
            continue
        try:
            nets.append(ipaddress.ip_network(part, strict=False))
        except ValueError:
            log.warning("VEYRS_LOCKOUT_EXEMPT_NETWORKS: %r is not a network; ignored", part)
    return tuple(nets)


def exempt(ip: str | None) -> bool:
    """Is this source inside VEYRS_LOCKOUT_EXEMPT_NETWORKS?"""
    if not ip:
        return False
    try:
        address = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(address in net for net in _networks(settings.lockout_exempt_networks))


def _source(ip: str | None) -> str:
    return hashlib.sha256((ip or "unknown").encode()).hexdigest()[:24]


def _keys(st: Any, user_id: Any, ip: str | None) -> tuple[str, str]:
    # The generation lets `unlock` forget every source of one account without
    # scanning Redis: bump it and the old keys are never read again.
    generation = st.get(f"veyrs:lockout:gen:{user_id}") or "0"
    base = f"veyrs:lockout:{user_id}:{generation}:{_source(ip)}"
    return base + ":n", base + ":wait"


def _now() -> dt.datetime:
    return dt.datetime.now(dt.timezone.utc)


def retry_after(user: Any, ip: str | None) -> int:
    """Seconds before this source may try a credential for this account; 0 = now."""
    if user.is_locked and not exempt(ip):
        return max(1, int((user.locked_until - _now()).total_seconds()) + 1)
    try:
        st = _store()
        _, wait_key = _keys(st, user.id, ip)
        if st.get(wait_key):
            return max(1, st.ttl(wait_key))
    except Exception as exc:  # noqa: BLE001 - no Redis: the account layer still holds
        log.warning("lockout: per-source state unavailable (%s)", type(exc).__name__)
    return 0


def why_refused(user: Any, ip: str | None) -> str:
    """The audit reason for a refusal `retry_after()` reported."""
    return "locked" if user.is_locked and not exempt(ip) else "throttled"


def charge(session: Any, user: Any, ip: str | None) -> None:
    """One failed credential for `user` from `ip`. The caller commits."""
    counts = True
    try:
        st = _store()
        count_key, wait_key = _keys(st, user.id, ip)
        n = st.incr(count_key, SOURCE_MEMORY_SECONDS)   # atomic in Redis
        if n >= SOURCE_FREE:
            wait = min(SOURCE_BASE_SECONDS * 2 ** (n - SOURCE_FREE), SOURCE_CAP_SECONDS)
            st.set(wait_key, "1", wait)
        counts = n <= SOURCE_FREE
    except Exception as exc:  # noqa: BLE001
        log.warning("lockout: per-source state unavailable (%s); counting toward the account",
                    type(exc).__name__)
    if not counts:
        return
    from sqlalchemy import update
    from sqlalchemy.orm.attributes import set_committed_value

    from ..models.tenancy import User

    # Incremented in SQL: parallel failures must not read the same old count.
    failed = session.execute(
        update(User).where(User.id == user.id)
        .values(failed_logins=User.failed_logins + 1)
        .returning(User.failed_logins)
        .execution_options(synchronize_session=False)
    ).scalar_one_or_none()
    if failed is None:
        return          # not visible to this session's tenant binding: nothing to count
    set_committed_value(user, "failed_logins", failed)
    if failed >= ACCOUNT_THRESHOLD:
        seconds = min(ACCOUNT_BASE_SECONDS * 2 ** (failed - ACCOUNT_THRESHOLD), ACCOUNT_CAP_SECONDS)
        user.locked_until = _now() + dt.timedelta(seconds=seconds)


def succeeded(user: Any, ip: str | None) -> None:
    """The credential was right: forget this source's failures and the account's."""
    user.failed_logins = 0
    user.locked_until = None
    try:
        st = _store()
        for key in _keys(st, user.id, ip):
            st.delete(key)
    except Exception as exc:  # noqa: BLE001
        log.warning("lockout: per-source state unavailable (%s)", type(exc).__name__)


def unlock(user: Any) -> None:
    """Operator reset (`veyrs unlock`): the account lock and every source's wait."""
    user.failed_logins = 0
    user.locked_until = None
    _store().incr(f"veyrs:lockout:gen:{user.id}", _GENERATION_TTL)
