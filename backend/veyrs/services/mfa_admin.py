"""Operator commands for two-factor sign-in, run on the host.

    veyrs mfa-test  --method email|telegram --to DEST
    veyrs mfa-setup --email USER [--org SLUG] --method email|telegram [--chat-id N] --recovery-file PATH
    veyrs mfa-reset --email USER [--org SLUG] --reason TEXT
    veyrs unlock    --email USER [--org SLUG] --reason TEXT

`mfa-test` sends one message and touches no account: it is how an operator
proves the relay or the bot works before anybody depends on it.

`mfa-setup` is for the case the console cannot cover: setting up the second
factor FOR somebody (the first administrator of a fresh install). The console
path proves delivery with a code the person types back; here the proof is the
transport's own acceptance -- the relay took the message, or Telegram answered
`ok` for that chat. A wrong destination therefore fails BEFORE anything is
enabled. Recovery codes go to a 0600 file, never to the terminal.

`mfa-reset` is the way back for somebody who lost the phone, the mailbox and
the recovery codes. It is audited, needs a reason, and only exists on the host.
It also ends every session of the account (access tokens included): whoever
holds the lost device must not keep a session through the reset.

`unlock` lifts the sign-in lockout (security/lockout.py) for one account: the
account-wide lock and every source's back-off. For an administrator kept out by
a guessing attack; audited, needs a reason, host only.
"""
from __future__ import annotations

import os
from typing import Any

from sqlalchemy import select

from ..db import SessionLocal, set_tenant
from ..models import Organization, User
from ..security import lockout, mfa_delivery
from ..security.auth import end_sessions
from . import audit


class AccountLookupError(Exception):
    """No such account, or more than one: the message says which and what to do."""


def find_account(session: Any, email: str, org: str | None = None) -> User | None:
    """Look an account up for a host command.

    The e-mail is lower-cased (stored lower-case). ``users`` is unique per
    ORGANIZATION and e-mail, so the same address can exist in two
    organizations: without ``org`` that is an error naming the candidates,
    never an arbitrary pick and never a stack trace. Returns None when absent.
    """
    email = (email or "").strip().lower()
    statement = select(User).where(User.email == email, User.deleted_at.is_(None))
    if org:
        statement = statement.join(Organization, Organization.id == User.organization_id).where(
            Organization.slug == org.strip().lower())
    matches = session.execute(statement).scalars().all()
    if len(matches) > 1:
        slugs = sorted(
            session.execute(select(Organization.slug).where(
                Organization.id.in_([u.organization_id for u in matches]))).scalars().all())
        raise AccountLookupError(
            f"{email} exists in {len(matches)} organizations ({', '.join(slugs)}); "
            "repeat the command with --org <slug>")
    if not matches:
        return None
    set_tenant(session, matches[0].organization_id)
    return session.get(User, matches[0].id)


def _find(session: Any, email: str, org: str | None = None) -> User | None:
    return find_account(session, email, org)


def mfa_test(args: Any) -> int:
    try:
        mfa_delivery.deliver(
            args.method, args.to, "VEYRS delivery test",
            "This is a VEYRS delivery test. Two-factor codes for VEYRS will arrive the same way.\n"
            "No action is needed.\n")
    except mfa_delivery.DeliveryError as exc:
        print(f"FAILED: {exc}")
        return 1
    print(f"sent: {args.method} -> {mfa_delivery.mask_email(args.to) if args.method == 'email' else mfa_delivery.mask_chat(args.to)}")
    return 0


def mfa_setup(args: Any) -> int:
    if args.method == "telegram" and not mfa_delivery.valid_chat_id(args.chat_id):
        print("FAILED: --chat-id must be a numeric Telegram chat id")
        return 2
    with SessionLocal() as session:
        try:
            user = _find(session, args.email, getattr(args, "org", None))
        except AccountLookupError as exc:
            print(f"FAILED: {exc}")
            return 2
        if user is None:
            print(f"FAILED: no account {args.email}")
            return 2
        if user.mfa_enabled:
            print(f"FAILED: {args.email} already has two-factor sign-in ({user.mfa_method or 'totp'}); "
                  "reset it first with `veyrs mfa-reset`")
            return 2
        dest = user.email if args.method == "email" else args.chat_id
        try:
            mfa_delivery.deliver(
                args.method, dest, "VEYRS two-factor sign-in is now on",
                f"Two-factor sign-in for {user.email} on VEYRS now sends its codes here.\n"
                "If you did not expect this, tell your VEYRS administrator.\n")
        except mfa_delivery.DeliveryError as exc:
            print(f"FAILED, nothing changed: {exc}")
            return 1
        shown, stored = mfa_delivery.new_recovery_codes()
        path = args.recovery_file
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "w") as fh:
            fh.write(f"# VEYRS recovery codes for {user.email} -- each works once, keep them offline\n")
            fh.write("\n".join(shown) + "\n")
        os.chmod(path, 0o600)
        user.mfa_enabled = True
        user.mfa_method = args.method
        user.mfa_secret = None
        user.mfa_last_step = None
        user.mfa_telegram_chat_id = args.chat_id if args.method == "telegram" else None
        user.mfa_recovery_codes = stored
        audit.record(session, action="mfa.setup_by_operator", object_type="user", object_id=user.id,
                     object_label=user.email, organization_id=user.organization_id, actor_id=None,
                     actor_label="operator (veyrs mfa-setup on the host)",
                     changes={"method": args.method})
        session.commit()
    print(f"enabled: {args.email} -> {args.method}; {len(shown)} recovery codes written to {path} (0600)")
    return 0


def mfa_reset(args: Any) -> int:
    with SessionLocal() as session:
        try:
            user = _find(session, args.email, getattr(args, "org", None))
        except AccountLookupError as exc:
            print(f"FAILED: {exc}")
            return 2
        if user is None:
            print(f"FAILED: no account {args.email}")
            return 2
        previous = user.mfa_method or ("totp" if user.mfa_enabled else None)
        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_last_step = None
        user.mfa_method = None
        user.mfa_telegram_chat_id = None
        user.mfa_recovery_codes = None
        end_sessions(session, user)
        audit.record(session, action="mfa.reset_by_operator", object_type="user", object_id=user.id,
                     object_label=user.email, organization_id=user.organization_id, actor_id=None,
                     actor_label="operator (veyrs mfa-reset on the host)",
                     changes={"previous_method": previous, "reason": args.reason[:500]})
        session.commit()
    print(f"reset: {args.email} signs in with the password only until two-factor is set up again; "
          "every session of the account was ended")
    return 0


def unlock(args: Any) -> int:
    with SessionLocal() as session:
        user = _find(session, args.email, getattr(args, "org", None))
        if user is None:
            print(f"FAILED: no account {args.email}")
            return 2
        before = {"failed_logins": user.failed_logins,
                  "locked_until": user.locked_until.isoformat() if user.locked_until else None}
        try:
            lockout.unlock(user)
        except Exception as exc:  # noqa: BLE001 - Redis down: the account lock is still lifted
            print(f"warning: per-source back-off not cleared ({type(exc).__name__}); "
                  "it expires on its own within 15 minutes")
        audit.record(session, action="user.unlock_by_operator", object_type="user", object_id=user.id,
                     object_label=user.email, organization_id=user.organization_id, actor_id=None,
                     actor_label="operator (veyrs unlock on the host)",
                     changes={**before, "reason": args.reason[:500]})
        session.commit()
    print(f"unlocked: {args.email}")
    return 0


def add_parsers(sub: Any) -> None:
    t = sub.add_parser("mfa-test", help="send one test message by e-mail or Telegram (no account changes)")
    t.add_argument("--method", choices=mfa_delivery.DELIVERED, required=True)
    t.add_argument("--to", required=True, help="an e-mail address, or a Telegram chat id")
    s = sub.add_parser("mfa-setup", help="turn on e-mail or Telegram two-factor FOR an account")
    s.add_argument("--email", required=True, help="the account")
    s.add_argument("--org", help="organization slug (needed when the e-mail exists in several)")
    s.add_argument("--method", choices=mfa_delivery.DELIVERED, required=True)
    s.add_argument("--chat-id", help="Telegram chat id (method telegram)")
    s.add_argument("--recovery-file", required=True, help="where to write the recovery codes (0600)")
    r = sub.add_parser("mfa-reset", help="turn two-factor OFF for an account that lost every factor")
    r.add_argument("--email", required=True)
    r.add_argument("--org", help="organization slug (needed when the e-mail exists in several)")
    r.add_argument("--reason", required=True, help="recorded in the audit trail")
    u = sub.add_parser("unlock", help="lift the sign-in lockout of an account (account lock and "
                                      "every source's back-off)")
    u.add_argument("--email", required=True)
    u.add_argument("--org", help="organization slug (needed when the e-mail exists in several)")
    u.add_argument("--reason", required=True, help="recorded in the audit trail")


HANDLERS = {"mfa-test": mfa_test, "mfa-setup": mfa_setup, "mfa-reset": mfa_reset,
            "unlock": unlock}
