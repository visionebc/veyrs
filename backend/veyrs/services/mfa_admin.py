"""Operator commands for two-factor sign-in, run on the host.

    veyrs mfa-test  --method email|telegram --to DEST
    veyrs mfa-setup --email USER --method email|telegram [--chat-id N] --recovery-file PATH
    veyrs mfa-reset --email USER --reason TEXT

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
"""
from __future__ import annotations

import os
from typing import Any

from sqlalchemy import select

from ..db import SessionLocal, set_tenant
from ..models import User
from ..security import mfa_delivery
from . import audit


def _find(session: Any, email: str) -> User | None:
    user = session.execute(select(User).where(User.email == email, User.deleted_at.is_(None))).scalar_one_or_none()
    if user is not None:
        set_tenant(session, user.organization_id)
        user = session.get(User, user.id)
    return user


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
        user = _find(session, args.email)
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
        user = _find(session, args.email)
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
        audit.record(session, action="mfa.reset_by_operator", object_type="user", object_id=user.id,
                     object_label=user.email, organization_id=user.organization_id, actor_id=None,
                     actor_label="operator (veyrs mfa-reset on the host)",
                     changes={"previous_method": previous, "reason": args.reason[:500]})
        session.commit()
    print(f"reset: {args.email} signs in with the password only until two-factor is set up again")
    return 0


def add_parsers(sub: Any) -> None:
    t = sub.add_parser("mfa-test", help="send one test message by e-mail or Telegram (no account changes)")
    t.add_argument("--method", choices=mfa_delivery.DELIVERED, required=True)
    t.add_argument("--to", required=True, help="an e-mail address, or a Telegram chat id")
    s = sub.add_parser("mfa-setup", help="turn on e-mail or Telegram two-factor FOR an account")
    s.add_argument("--email", required=True, help="the account")
    s.add_argument("--method", choices=mfa_delivery.DELIVERED, required=True)
    s.add_argument("--chat-id", help="Telegram chat id (method telegram)")
    s.add_argument("--recovery-file", required=True, help="where to write the recovery codes (0600)")
    r = sub.add_parser("mfa-reset", help="turn two-factor OFF for an account that lost every factor")
    r.add_argument("--email", required=True)
    r.add_argument("--reason", required=True, help="recorded in the audit trail")


HANDLERS = {"mfa-test": mfa_test, "mfa-setup": mfa_setup, "mfa-reset": mfa_reset}
