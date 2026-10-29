"""Where stored credentials live, and moving them between local and an external vault.

`security/secrets.py` decides how ONE value is stored; this module knows
WHICH values exist. It backs `veyrs secrets status|migrate|gc` and the read-only
`GET /secret-storage` page.

Decisions worth knowing before changing anything here
-----------------------------------------------------
  * **`COLUMNS` is the registry, and a test enforces it.** Every `*_enc` column
    in the models (plus `users.mfa_secret` and the LDAP bind password inside
    `organizations.settings`) must be listed. A column added later and missed
    here would silently stay on the host after a migration that reported
    success.
  * **Every tenant is bound before it is read.** The tables are RLS-forced: as
    the application role, an unbound query returns zero rows and no error --
    a status page saying "0 credentials on this host" would be the most
    dangerous possible way for that to fail.
  * **Migration never blanks, never deletes.** A row that cannot be read is
    reported and skipped. Each row is written in its own savepoint and only if
    it still holds the value that was read (compare-and-swap), so a credential
    an operator replaced mid-run is left alone. Old vault entries are left for
    `gc`, which is what makes `--to local` a real rollback.
  * **No web write path.** Moving every credential of every tenant is a
    platform operation for whoever holds the host and the vault policy, not a
    button for a tenant administrator. The page shows the command.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import uuid
from collections.abc import Callable, Iterator
from typing import Any

from sqlalchemy import select, update
from sqlalchemy.exc import SQLAlchemyError
from sqlalchemy.orm import Session

from ..db import set_tenant
from ..models import Base, Organization
from ..security import secret_vault, secrets
from . import audit

KINDS = ("local", "mirror", "vault", "empty", "unknown")


@dataclasses.dataclass(frozen=True)
class Column:
    table: str
    column: str

    @property
    def label(self) -> str:
        return f"{self.table}.{self.column}"


#: Every column that holds an `encrypt()` result. Order is display order.
COLUMNS: tuple[Column, ...] = (
    Column("ai_providers", "api_key_enc"),
    Column("itsm_connectors", "credentials_enc"),
    Column("itsm_connectors", "inbound_secret_enc"),
    Column("scanner_connectors", "credentials_enc"),
    Column("asset_sources", "credentials_enc"),
    Column("threat_sources", "credentials_enc"),
    Column("webhook_endpoints", "secret_enc"),
    Column("users", "mfa_secret"),
)
LDAP_SETTINGS_KEY = "ldap"
LDAP_SECRET_FIELD = "bind_password_enc"   # == ldap_auth.SECRET_FIELD (asserted in tests)
LDAP_LABEL = f"organizations.settings.{LDAP_SETTINGS_KEY}.{LDAP_SECRET_FIELD}"
LABELS: tuple[str, ...] = tuple(c.label for c in COLUMNS) + (LDAP_LABEL,)

COMMANDS = {
    "status": "veyrs secrets status",
    "to_mirror": "veyrs secrets migrate --to mirror --apply",
    "to_vault": "veyrs secrets migrate --to vault --apply",
    "to_local": "veyrs secrets migrate --to local --apply",
    "dry_run": "veyrs secrets migrate --to vault",
    "gc": "veyrs secrets gc --apply",
}

MODE_MEANING = {
    "local": "Credentials are encrypted with VEYRS_ENCRYPTION_KEY and stored in the "
             "database. The key sits on the same host, so anyone who can read that "
             "host's disk can read every credential. No vault is contacted.",
    "mirror": "Credentials are written to the external vault AND kept encrypted in the "
              "database. The vault is read first; the local copy is the fallback. A "
              "migration step: the local copies are still on this host.",
    "vault": "The external vault holds the only copy; the database keeps a reference. "
             "Reading this host's disk no longer yields the credentials. If the vault "
             "is unreachable, features that need a credential fail instead of guessing.",
}


@dataclasses.dataclass
class Item:
    label: str
    row_id: Any
    value: str | None


class _Changed(Exception):
    """The row no longer holds the value that was read: somebody replaced it."""


# ---------------------------------------------------------------------------
# reading
# ---------------------------------------------------------------------------
def _organizations(session: Session, slugs: list[str] | None = None) -> list[tuple[uuid.UUID, str]]:
    stmt = select(Organization.id, Organization.slug).order_by(Organization.slug)
    if slugs:
        stmt = stmt.where(Organization.slug.in_(slugs))
    return [(row[0], row[1]) for row in session.execute(stmt).all()]


def items(session: Session, organization_id: uuid.UUID) -> Iterator[Item]:
    """Every registered secret of one tenant. The caller binds the tenant."""
    for col in COLUMNS:
        table = Base.metadata.tables[col.table]
        rows = session.execute(
            select(table.c.id, table.c[col.column])
            .where(table.c.organization_id == organization_id)
        ).all()
        for row_id, value in rows:
            yield Item(col.label, row_id, value)
    orgs = Organization.__table__
    blob = session.execute(
        select(orgs.c.settings).where(orgs.c.id == organization_id)
    ).scalar_one_or_none() or {}
    block = blob.get(LDAP_SETTINGS_KEY) if isinstance(blob, dict) else None
    if isinstance(block, dict):
        yield Item(LDAP_LABEL, organization_id, block.get(LDAP_SECRET_FIELD))


def _blank_counts() -> dict[str, dict[str, int]]:
    return {label: {kind: 0 for kind in KINDS} for label in LABELS}


def counts(session: Session, organization_id: uuid.UUID) -> dict[str, dict[str, int]]:
    set_tenant(session, organization_id)
    out = _blank_counts()
    for item in items(session, organization_id):
        out[item.label][secrets.storage_kind(item.value)] += 1
    return out


def counts_all(session: Session, slugs: list[str] | None = None
               ) -> tuple[dict[str, dict[str, int]], int]:
    """Counts across every organization (each bound in turn), and how many."""
    total = _blank_counts()
    orgs = _organizations(session, slugs)
    for org_id, _slug in orgs:
        for label, row in counts(session, org_id).items():
            for kind, n in row.items():
                total[label][kind] += n
    session.rollback()  # end the read transaction; nothing was written
    return total, len(orgs)


def totals(table: dict[str, dict[str, int]]) -> dict[str, int]:
    out = {kind: 0 for kind in KINDS}
    for row in table.values():
        for kind, n in row.items():
            out[kind] += n
    return out


def next_step(mode: str, total: dict[str, int], vault_ok: bool) -> str:
    """One sentence: what an operator in this state should do next."""
    on_host = total["local"] + total["mirror"]
    if mode == "local":
        if total["vault"] or total["mirror"]:
            return ("Some credentials still reference the vault. Pull them back with "
                    f"`{COMMANDS['to_local']}` before removing the vault settings.")
        return ("Nothing to do unless you want credentials off this host: configure "
                "VEYRS_VAULT_*, set VEYRS_SECRET_BACKEND=mirror, restart, then run "
                f"`{COMMANDS['to_mirror']}`.")
    if not vault_ok:
        return ("The vault is not usable from this process. Fix that first; run "
                f"`{COMMANDS['status']}` on the host for the reason.")
    if mode == "mirror":
        if total["local"]:
            return f"Copy the remaining local-only credentials into the vault: `{COMMANDS['to_mirror']}`."
        return ("Every credential is mirrored. When the vault has proved itself, set "
                "VEYRS_SECRET_BACKEND=vault, restart, then run "
                f"`{COMMANDS['to_vault']}` to drop the local copies.")
    if on_host:
        return (f"{on_host} credential(s) still have a copy on this host. Run "
                f"`{COMMANDS['to_vault']}`.")
    return f"Every credential lives only in the vault. Remove orphans with `{COMMANDS['gc']}`."


def status(session: Session, organization_id: uuid.UUID) -> dict[str, Any]:
    """The read-only page: mode, vault health, and this tenant's counts.

    Names no token, no secret-id path contents and no credential value.
    """
    cfg = secret_vault.current_config()
    mode = secrets.mode()
    probe = secret_vault.probe(cfg)
    table = counts(session, organization_id)
    total = totals(table)
    vault_ok = bool(probe.get("reachable") and probe.get("auth_ok"))
    return {
        "mode": mode,
        "meaning": MODE_MEANING[mode],
        "vault": {
            "addr": cfg.addr or None,
            "mount": cfg.mount or None,
            "auth_method": cfg.auth,
            "namespace": cfg.namespace or None,
            "ca_file_set": bool(cfg.ca_file),
            **probe,
        },
        "scope": "organization",
        "columns": [{"column": label, **table[label]} for label in LABELS],
        "totals": total,
        "on_host": total["local"] + total["mirror"],
        "next_step": next_step(mode, total, vault_ok),
        "commands": dict(COMMANDS),
        "web_migration": False,
    }


# ---------------------------------------------------------------------------
# writing
# ---------------------------------------------------------------------------
def _write(session: Session, item: Item, new_value: str) -> None:
    """Swap one stored value, only if it still holds what was read."""
    if item.label == LDAP_LABEL:
        orgs = Organization.__table__
        current = session.execute(
            select(orgs.c.settings).where(orgs.c.id == item.row_id)
        ).scalar_one()
        blob = dict(current or {})
        block = dict(blob.get(LDAP_SETTINGS_KEY) or {})
        if block.get(LDAP_SECRET_FIELD) != item.value:
            raise _Changed()
        block[LDAP_SECRET_FIELD] = new_value
        blob[LDAP_SETTINGS_KEY] = block
        session.execute(update(orgs).where(orgs.c.id == item.row_id).values(settings=blob))
        return
    table_name, column = item.label.split(".", 1)
    table = Base.metadata.tables[table_name]
    values: dict[str, Any] = {column: new_value}
    if "updated_at" in table.c:
        # Moving a credential's storage is not an edit of the connector; keep
        # "last changed" meaning what the operator thinks it means.
        values["updated_at"] = table.c.updated_at
    result = session.execute(
        update(table)
        .where(table.c.id == item.row_id, table.c[column] == item.value)
        .values(values)
    )
    if result.rowcount != 1:
        raise _Changed()


def migrate(session: Session, target: str, *, apply: bool = False,
            slugs: list[str] | None = None,
            out: Callable[[str], None] = print) -> dict[str, Any]:
    """Re-store every registered secret as `target` (local | mirror | vault).

    Dry run by default: every value is still READ (that is how an unreadable
    row is found before it matters) but nothing is written to the database or
    the vault.
    """
    if target not in secrets.MODES:
        raise ValueError(f"target must be one of {', '.join(secrets.MODES)}")
    if target != "local":
        problems = secret_vault.config_problems()
        if problems:
            raise secrets.SecretError("cannot migrate to the vault: " + "; ".join(problems))
        probe = secret_vault.probe()
        if not (probe["reachable"] and probe["auth_ok"]):
            raise secrets.SecretError(
                "cannot migrate to the vault: "
                + (probe.get("error") or ("vault is sealed" if probe.get("sealed")
                                          else "vault is not usable")))

    report: dict[str, Any] = {
        "target": target, "apply": apply, "organizations": 0,
        "unchanged": 0, "converted": 0, "empty": 0, "failed": [],
        "per_column": {label: {"unchanged": 0, "converted": 0, "failed": 0} for label in LABELS},
    }
    for org_id, slug in _organizations(session, slugs):
        report["organizations"] += 1
        set_tenant(session, org_id)
        converted_here = 0
        for item in list(items(session, org_id)):
            kind = secrets.storage_kind(item.value)
            row = report["per_column"][item.label]
            if kind == "empty":
                report["empty"] += 1
                continue
            if kind == target:
                report["unchanged"] += 1
                row["unchanged"] += 1
                continue
            try:
                if kind == "unknown":
                    raise secrets.SecretError("stored value is not VEYRS ciphertext")
                plaintext = secrets.decrypt(item.value)
                if not plaintext:
                    raise secrets.SecretError("stored value decrypted to nothing")
                if apply:
                    reuse = (secrets.vault_key(item.value)
                             if kind in ("mirror", "vault") and target != "local" else None)
                    new_value = secrets.seal_as(plaintext, target, reuse_key=reuse)
                    with session.begin_nested():
                        _write(session, item, new_value)
            except (secrets.SecretError, _Changed, SQLAlchemyError) as exc:
                reason = ("the value changed while migrating; run again"
                          if isinstance(exc, _Changed) else
                          str(exc) or type(exc).__name__)
                report["failed"].append({"organization": slug, "column": item.label,
                                         "row": str(item.row_id), "from": kind,
                                         "reason": reason})
                row["failed"] += 1
                out(f"  ! {slug} {item.label} {item.row_id}: {reason} (skipped, unchanged)")
                continue
            report["converted"] += 1
            row["converted"] += 1
            converted_here += 1
        if apply and converted_here:
            audit.record(
                session, action="organization.secret_storage_migrated",
                object_type="organization", object_id=org_id,
                object_label="secret storage", organization_id=org_id,
                actor_label="cli:veyrs secrets migrate",
                changes={"target": target, "converted": converted_here},
            )
        if apply:
            session.commit()
        else:
            session.rollback()
    return report


def gc(session: Session, *, apply: bool = False, min_age_minutes: int = 60,
       now: dt.datetime | None = None) -> dict[str, Any]:
    """Vault entries under the mount that no row references.

    The vault is listed BEFORE the database is scanned, so an entry written
    after the listing is never a candidate; `min_age_minutes` covers the other
    race -- an entry written just before the listing whose row had not been
    committed yet. Any failure while scanning aborts before anything is deleted.
    """
    problems = secret_vault.config_problems()
    if problems:
        raise secrets.SecretError("cannot list the vault: " + "; ".join(problems))
    listed = secret_vault.list_keys()
    referenced: set[str] = set()
    for org_id, _slug in _organizations(session):
        set_tenant(session, org_id)
        for item in items(session, org_id):
            key = secrets.vault_key(item.value)
            if key:
                referenced.add(key)
    session.rollback()

    listed_set = set(listed)
    cutoff = (now or dt.datetime.now(dt.timezone.utc)) - dt.timedelta(minutes=min_age_minutes)
    orphans, recent = [], []
    for key in listed:
        if key in referenced:
            continue
        if min_age_minutes > 0:
            created = secret_vault.created_at(key)
            if created is None or created > cutoff:
                recent.append(key)  # cannot prove it is old: keep it
                continue
        orphans.append(key)
    deleted = []
    if apply:
        for key in orphans:
            secret_vault.delete(key)
            deleted.append(key)
    return {
        "apply": apply,
        "listed": len(listed),
        "referenced": len(referenced & listed_set),
        "orphans": orphans,
        "too_recent": recent,
        "deleted": deleted,
        # A row pointing at an entry the vault does not have is a credential
        # that will fail the next time it is used -- worth shouting about here.
        "missing": sorted(referenced - listed_set),
    }


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def _yn(value: Any) -> str:
    return {True: "yes", False: "no", None: "-"}.get(value, str(value))


def _print_table(table: dict[str, dict[str, int]]) -> None:
    print(f"  {'column':<52}" + "".join(f"{k:>9}" for k in KINDS))
    for label in LABELS:
        print(f"  {label:<52}" + "".join(f"{table[label][k]:>9}" for k in KINDS))
    total = totals(table)
    print(f"  {'total':<52}" + "".join(f"{total[k]:>9}" for k in KINDS))


def cli_status(session: Session) -> int:
    cfg = secret_vault.current_config()
    mode = secrets.mode()
    print(f"secret backend: {mode}")
    print(f"  {MODE_MEANING[mode]}")
    if cfg.addr:
        probe = secret_vault.probe(cfg)
        print(f"vault: {cfg.addr} mount={cfg.mount} auth={cfg.auth}"
              + (f" namespace={cfg.namespace}" if cfg.namespace else ""))
        print(f"  reachable: {_yn(probe['reachable'])}  sealed: {_yn(probe['sealed'])}  "
              f"auth: {'ok' if probe['auth_ok'] else _yn(probe['auth_ok'])}")
        for problem in probe["problems"]:
            print(f"  ! {problem}")
        if probe["error"]:
            print(f"  ! {probe['error']}")
        vault_ok = bool(probe["reachable"] and probe["auth_ok"])
    else:
        print("vault: not configured (VEYRS_VAULT_ADDR is empty)")
        vault_ok = False
    table, n_orgs = counts_all(session)
    print(f"\nstored credentials across {n_orgs} organization(s):")
    _print_table(table)
    total = totals(table)
    print(f"\nstill on this host (local + mirror): {total['local'] + total['mirror']}")
    print(f"next: {next_step(mode, total, vault_ok)}")
    if mode != "local" and not vault_ok:
        return 1
    return 1 if total["unknown"] else 0


def cli_migrate(session: Session, target: str, apply: bool, slugs: list[str] | None) -> int:
    print(f"{'migrating' if apply else 'DRY RUN: would migrate'} stored credentials to {target}")
    try:
        report = migrate(session, target, apply=apply, slugs=slugs)
    except secrets.SecretError as exc:
        print(f"refused: {exc}")
        return 2
    print(f"\n{report['organizations']} organization(s): "
          f"{report['converted']} {'converted' if apply else 'to convert'}, "
          f"{report['unchanged']} already {target}, {report['empty']} empty, "
          f"{len(report['failed'])} unreadable (skipped, left as they were)")
    for label in LABELS:
        row = report["per_column"][label]
        if any(row.values()):
            print(f"  {label:<52} converted={row['converted']} "
                  f"unchanged={row['unchanged']} failed={row['failed']}")
    if not apply:
        print("\nNothing was written. Re-run with --apply to do it.")
    elif secrets.mode() != target:
        print(f"\nNOTE: VEYRS_SECRET_BACKEND is still {secrets.mode()}; credentials saved "
              f"from now on are stored that way. Set it to {target} and restart.")
    if apply and target == "local":
        print("Vault entries were NOT deleted (that is your rollback). "
              f"Remove them later with `{COMMANDS['gc']}`.")
    return 1 if report["failed"] else 0


def cli_gc(session: Session, apply: bool, min_age_minutes: int) -> int:
    try:
        report = gc(session, apply=apply, min_age_minutes=min_age_minutes)
    except secrets.SecretError as exc:
        print(f"refused: {exc}")
        return 2
    print(f"vault entries listed: {report['listed']}, referenced by a row: {report['referenced']}")
    for key in report["orphans"]:
        print(f"  {'deleted' if apply else 'orphan '} {secret_vault.FOLDER}/{key}")
    if report["too_recent"]:
        print(f"  {len(report['too_recent'])} unreferenced entr(y/ies) younger than "
              f"{min_age_minutes} min kept (may belong to a save still in flight)")
    for key in report["missing"]:
        print(f"  ! referenced but MISSING from the vault: {secret_vault.FOLDER}/{key}")
    if not apply and report["orphans"]:
        print("\nNothing was deleted. Re-run with --apply to delete the orphans.")
    return 1 if report["missing"] else 0


def run_cli(args) -> int:  # noqa: ANN001 - argparse.Namespace
    from ..db import SessionLocal

    with SessionLocal() as session:
        if args.secrets_command == "status":
            return cli_status(session)
        if args.secrets_command == "migrate":
            return cli_migrate(session, args.to, args.apply, args.org or None)
        if args.secrets_command == "gc":
            return cli_gc(session, args.apply, args.min_age_minutes)
    return 2
