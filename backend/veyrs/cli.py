"""VEYRS operational CLI.

    python -m veyrs init-db                     create schema + RLS + built-in roles
    python -m veyrs sync-schema                 add model columns missing from the DB
    python -m veyrs bootstrap --org acme ...    create the first organization + admin
    python -m veyrs sync-kev                    refresh the CISA KEV catalogue
    python -m veyrs sync-epss                   refresh EPSS scores
    python -m veyrs sync-cwe                    refresh the MITRE CWE dictionary
    python -m veyrs recompute-risk [--org SLUG] re-run the risk engine
    python -m veyrs run-sla                     evaluate SLA breaches + escalations
    python -m veyrs check                       self-test: config, DB, engines

Everything is idempotent: re-running never duplicates rows.
"""
from __future__ import annotations

import argparse
import getpass
import os
import sys
import uuid

from sqlalchemy import select, text

from .config import settings
from .db import SessionLocal, engine, set_tenant
from .models import Base, Organization, Role, User, UserRole
from .security import permissions as perms
from .security.auth import hash_password

RLS_TABLES_SKIP = {
    # global reference data + append-only logs handled explicitly
    "organizations", "roles", "cve", "cwe", "cpe", "epss_scores", "epss_history",
    "kev_entries", "vendors", "products", "product_versions",
    "compliance_frameworks", "compliance_controls", "cve_references", "cve_cpe_match",
    "auth_events",
}

# Credential-keyed tables. Authentication necessarily queries these BEFORE the
# tenant is known (login looks a user up by email; refresh by token hash; API
# keys by prefix), so a strict policy would make login impossible. They get a
# permissive-when-unbound policy instead: with `veyrs.current_org` unset the row
# is visible (pre-auth window only - get_principal binds it immediately after
# resolving the credential), and once bound the tenant predicate applies exactly
# as it does everywhere else. Documented in docs/THREAT_MODEL.md (T-TENANT-01).
RLS_TABLES_PREAUTH = {"users", "refresh_tokens", "api_keys", "exec_agents"}

STRICT_POLICY = (
    "organization_id::text = NULLIF(current_setting('veyrs.current_org', true), '')"
)
PREAUTH_POLICY = (
    "organization_id::text = COALESCE("
    "NULLIF(current_setting('veyrs.current_org', true), ''), organization_id::text)"
)


def sync_columns(*, verbose: bool = True) -> dict[str, int]:
    """Add columns, indexes and FKs that exist in the models but not in the DB.

    `Base.metadata.create_all()` creates missing TABLES and silently ignores
    missing COLUMNS on tables that already exist. VEYRS has no migration tool,
    so every model change after the first deployment was invisible to the
    database: the code would reference `findings.dedupe_algorithm`, the column
    would not be there, and the failure surfaced as an UndefinedColumn error at
    request time rather than at deploy time.

    This closes that gap for the additive case, which is the case that matters:

    * **Adds** columns, single-column indexes and foreign keys. Idempotent via
      `IF NOT EXISTS` and constraint-name checks.
    * **Never** drops, renames or retypes anything. A destructive change is a
      decision, not a reconciliation, and is reported for a human instead.
    * **Refuses** to add a NOT NULL column with no default to a non-empty table
      - Postgres cannot, and guessing a backfill value is exactly the kind of
      invention this codebase does not do. It prints the DDL the operator needs.
    """
    from sqlalchemy import UniqueConstraint, inspect
    from sqlalchemy.exc import IntegrityError
    from sqlalchemy.schema import CreateIndex

    inspector = inspect(engine)
    stats = {"columns": 0, "indexes": 0, "constraints": 0, "manual": 0}
    live_tables = set(inspector.get_table_names())

    with engine.begin() as conn:
        for name, table in Base.metadata.tables.items():
            if name not in live_tables:
                continue  # create_all() already made it, columns and all
            live_columns = {c["name"] for c in inspector.get_columns(name)}

            for column in table.columns:
                if column.name in live_columns:
                    continue
                type_sql = column.type.compile(dialect=engine.dialect)
                default_sql = _literal_default(column)
                if not column.nullable and default_sql is None:
                    stats["manual"] += 1
                    print(
                        f"  ! {name}.{column.name} is NOT NULL with no default; "
                        f"backfill it manually:\n"
                        f"      ALTER TABLE \"{name}\" ADD COLUMN {column.name} {type_sql};\n"
                        f"      UPDATE \"{name}\" SET {column.name} = <value>;\n"
                        f"      ALTER TABLE \"{name}\" ALTER COLUMN {column.name} SET NOT NULL;"
                    )
                    continue
                clause = f'ADD COLUMN IF NOT EXISTS "{column.name}" {type_sql}'
                if default_sql is not None:
                    clause += f" DEFAULT {default_sql}"
                if not column.nullable:
                    clause += " NOT NULL"
                conn.execute(text(f'ALTER TABLE "{name}" {clause}'))
                stats["columns"] += 1
                if verbose:
                    print(f"  + column {name}.{column.name} {type_sql}")

                for fk in column.foreign_keys:
                    constraint = f"fk_{name}_{column.name}_{fk.column.table.name}"
                    on_delete = (fk.ondelete or "NO ACTION").upper()
                    conn.execute(text(
                        f'ALTER TABLE "{name}" DROP CONSTRAINT IF EXISTS "{constraint}"'
                    ))
                    conn.execute(text(
                        f'ALTER TABLE "{name}" ADD CONSTRAINT "{constraint}" '
                        f'FOREIGN KEY ("{column.name}") '
                        f'REFERENCES "{fk.column.table.name}" ("{fk.column.name}") '
                        f"ON DELETE {on_delete}"
                    ))
                    stats["constraints"] += 1
                    if verbose:
                        print(f"  + fk {constraint}")

            live_indexes = {i["name"] for i in inspector.get_indexes(name)}
            for index in table.indexes:
                if index.name in live_indexes:
                    continue
                conn.execute(text(
                    str(CreateIndex(index, if_not_exists=True)
                        .compile(dialect=engine.dialect))
                ))
                stats["indexes"] += 1
                if verbose:
                    print(f"  + index {index.name}")

            # UNIQUE constraints declared on an ALREADY-EXISTING table were the
            # blind spot this loop shared with create_all(): the column landed,
            # the invariant did not, and nothing said so. `users.username`
            # shipped that way -- the model promised one username per tenant
            # while the database allowed a second, which the login route can
            # only answer with a 409 that neither account is able to satisfy.
            #
            # Built as a UNIQUE INDEX rather than ADD CONSTRAINT so that
            # `IF NOT EXISTS` makes it idempotent; Postgres backs a unique
            # constraint with exactly such an index either way.
            live_uniques = {u["name"] for u in inspector.get_unique_constraints(name)}
            live_uniques |= {i["name"] for i in inspector.get_indexes(name)}
            for uq in table.constraints:
                if not isinstance(uq, UniqueConstraint) or not uq.name:
                    continue
                if uq.name in live_uniques:
                    continue
                cols = ", ".join('"' + c.name + '"' for c in uq.columns)
                try:
                    conn.execute(text(
                        'CREATE UNIQUE INDEX IF NOT EXISTS "' + uq.name + '" '
                        'ON "' + name + '" (' + cols + ')'
                    ))
                except IntegrityError:
                    # Duplicate rows already exist. Reconciliation does not get
                    # to choose which one to delete; print the query and move on.
                    stats["manual"] += 1
                    print(
                        f"  ! {name} already holds duplicate ({cols}); the unique "
                        f"index was NOT created. Find them with:\n"
                        f"      SELECT {cols}, count(*) FROM \"{name}\" "
                        f"GROUP BY {cols} HAVING count(*) > 1;"
                    )
                    continue
                stats["constraints"] += 1
                if verbose:
                    print(f"  + unique {uq.name} on {name} ({cols})")

    print(
        f"schema reconcile: {stats['columns']} columns, {stats['indexes']} indexes, "
        f"{stats['constraints']} constraints added"
        + (f", {stats['manual']} need manual migration" if stats["manual"] else "")
    )
    return stats


def _literal_default(column) -> str | None:  # noqa: ANN001 - SQLAlchemy Column
    """SQL literal for a column's default, or None if there isn't a usable one.

    Only scalar defaults translate. A callable default (`lambda: now()`) runs in
    Python and cannot be expressed as DDL, so such a column is reported for
    manual migration rather than being added with a wrong constant.
    """
    server_default = getattr(column, "server_default", None)
    if server_default is not None and getattr(server_default, "arg", None) is not None:
        return str(server_default.arg.text if hasattr(server_default.arg, "text")
                   else server_default.arg)
    default = getattr(column, "default", None)
    if default is None:
        return None
    if not getattr(default, "is_scalar", False):
        # `default=dict` / `default=list` are the JSONB idiom used by every
        # tenant table in this schema. They are CALLABLES, so the scalar test
        # above rejects them - which meant every new NOT NULL JSONB column on
        # an existing table was reported as needing a manual migration, on
        # every deployment. They are also constant and deterministic, unlike
        # the `lambda: now()` case this guard exists for, so they translate
        # exactly. Identity checks, not duck-typing: an arbitrary callable that
        # happens to return {} must still be refused.
        # SQLAlchemy wraps a zero-argument callable so it can be invoked with
        # an execution context, so `default.arg` is that wrapper and the
        # original is on `__wrapped__`. Comparing the wrapper would silently
        # never match, which is how this fix would look applied and do nothing.
        argument = getattr(default, "arg", None)
        argument = getattr(argument, "__wrapped__", argument)
        if argument is dict:
            return "'{}'::jsonb"
        if argument is list:
            return "'[]'::jsonb"
        return None
    value = default.arg
    if isinstance(value, bool):
        return "true" if value else "false"
    if isinstance(value, (int, float)):
        return str(value)
    if isinstance(value, str):
        escaped = value.replace("'", "''")
        return f"'{escaped}'"
    if isinstance(value, dict):
        return "'{}'::jsonb"
    if isinstance(value, list):
        return "'[]'::jsonb"
    return None


def init_db(_: argparse.Namespace) -> int:
    """Create every table, reconcile added columns, then bind RLS."""
    Base.metadata.create_all(engine)
    print(f"schema: {len(Base.metadata.tables)} tables ensured")
    sync_columns()

    strict = preauth = 0
    with engine.begin() as conn:
        for name, table in Base.metadata.tables.items():
            if name in RLS_TABLES_SKIP or "organization_id" not in table.c:
                continue
            if table.c.organization_id.nullable and name not in RLS_TABLES_PREAUTH:
                # nullable tenant column = platform-level row (e.g. audit_log for
                # a superuser action); handled by the app layer, not RLS.
                continue
            is_preauth = name in RLS_TABLES_PREAUTH
            predicate = PREAUTH_POLICY if is_preauth else STRICT_POLICY
            conn.execute(text(f'ALTER TABLE "{name}" ENABLE ROW LEVEL SECURITY'))
            conn.execute(text(f'ALTER TABLE "{name}" FORCE ROW LEVEL SECURITY'))
            conn.execute(text(f'DROP POLICY IF EXISTS veyrs_tenant_isolation ON "{name}"'))
            conn.execute(text(
                f'CREATE POLICY veyrs_tenant_isolation ON "{name}" '
                f"USING ({predicate}) WITH CHECK ({predicate})"
            ))
            if is_preauth:
                preauth += 1
            else:
                strict += 1
    print(f"row level security: {strict} tables strictly isolated, "
          f"{preauth} credential-keyed (permissive only while unbound)")
    seed_roles()
    seed_compliance()
    return 0


def keygen(_: argparse.Namespace) -> int:
    """Print a Fernet key for VEYRS_ENCRYPTION_KEY.

    Deliberately prints and exits rather than writing .env: the operator
    decides where secrets live, and a tool that edits secret files without
    being asked is a tool people stop trusting.
    """
    from .security.secrets import generate_key

    print(generate_key())
    return 0


def seed_compliance() -> None:
    """Install the built-in framework catalogues (global reference data)."""
    from .services import compliance as compliance_service

    with SessionLocal() as session:
        stats = compliance_service.seed_frameworks(session)
        session.commit()
    print(f"compliance catalogues: {stats['frameworks']} frameworks, "
          f"{stats['controls']} controls created, {stats['updated']} updated")


def seed_roles() -> None:
    """Insert/refresh the built-in roles (organization_id NULL = global)."""
    with SessionLocal() as session:
        existing = {
            r.slug: r for r in session.execute(
                select(Role).where(Role.organization_id.is_(None))
            ).scalars().all()
        }
        created = updated = 0
        for slug, spec in perms.BUILTIN_ROLES.items():
            role = existing.get(slug)
            if role is None:
                session.add(Role(
                    slug=slug, name=spec["name"], description=spec["description"],
                    permissions=spec["permissions"], is_builtin=True, organization_id=None,
                ))
                created += 1
            elif role.permissions != spec["permissions"] or role.name != spec["name"]:
                role.permissions = spec["permissions"]
                role.name = spec["name"]
                role.description = spec["description"]
                updated += 1
        session.commit()
        print(f"builtin roles: {created} created, {updated} updated, "
              f"{len(perms.BUILTIN_ROLES)} total")


def bootstrap(args: argparse.Namespace) -> int:
    """Create the first organization and its administrator.

    The password is taken from --password, else from the environment variable
    VEYRS_BOOTSTRAP_PASSWORD, else prompted. The environment is how every
    installer passes it: an argument is readable by any local account in
    ps(1) for as long as the process lives -- and a container's processes are
    in the HOST's process table, so the init container is no exception.
    """
    password = (args.password or os.environ.get("VEYRS_BOOTSTRAP_PASSWORD")
                or getpass.getpass("admin password: "))
    if len(password) < settings.password_min_length:
        print(f"password must be at least {settings.password_min_length} characters",
              file=sys.stderr)
        return 2
    with SessionLocal() as session:
        org = session.execute(
            select(Organization).where(Organization.slug == args.org)
        ).scalar_one_or_none()
        if org is None:
            org = Organization(name=args.name or args.org.title(), slug=args.org,
                               invoicing_code=args.invoicing_code,
                               default_locale=args.locale)
            session.add(org)
            session.flush()
            print(f"organization created: {org.slug} ({org.id})")
        else:
            print(f"organization exists: {org.slug} ({org.id})")
        # every table touched below is RLS-forced; bind the tenant first
        set_tenant(session, org.id)

        user = session.execute(
            select(User).where(User.organization_id == org.id, User.email == args.email.lower())
        ).scalar_one_or_none()
        if user is None:
            user = User(organization_id=org.id, email=args.email.lower(),
                        full_name=args.full_name or args.email.split("@")[0],
                        password_hash=hash_password(password),
                        is_superuser=bool(args.superuser), locale=args.locale)
            session.add(user)
            session.flush()
            print(f"user created: {user.email} ({user.id})")
        else:
            user.password_hash = hash_password(password)
            print(f"user exists, password reset: {user.email}")

        admin_role = session.execute(
            select(Role).where(Role.slug == "org-admin", Role.organization_id.is_(None))
        ).scalar_one_or_none()
        if admin_role is None:
            seed_roles()
            admin_role = session.execute(
                select(Role).where(Role.slug == "org-admin", Role.organization_id.is_(None))
            ).scalar_one()
        already = session.execute(
            select(UserRole).where(UserRole.user_id == user.id,
                                   UserRole.role_id == admin_role.id,
                                   UserRole.team_id.is_(None))
        ).scalar_one_or_none()
        if already is None:
            session.add(UserRole(organization_id=org.id, user_id=user.id, role_id=admin_role.id))
            print("granted role: org-admin")
        session.commit()
    return 0


def check(_: argparse.Namespace) -> int:
    """Self-test that does not require a running API."""
    problems: list[str] = []
    print(f"VEYRS {settings.version} / {settings.environment}")

    try:
        with engine.connect() as conn:
            version = conn.execute(text("SHOW server_version")).scalar_one()
        print(f"  database          ok (postgres {version})")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"database: {exc}")
        print(f"  database          FAIL {type(exc).__name__}")

    try:
        import redis

        redis.Redis.from_url(settings.redis_url, socket_timeout=3).ping()
        print("  redis             ok")
    except Exception as exc:  # noqa: BLE001
        problems.append(f"redis: {exc}")
        print(f"  redis             FAIL {type(exc).__name__}")

    from .engines import cvss

    checks = [
        ("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H", 9.8),
        ("CVSS:4.0/AV:N/AC:L/AT:N/PR:N/UI:N/VC:H/VI:H/VA:H/SC:N/SI:N/SA:N", 9.3),
        ("AV:N/AC:L/Au:N/C:C/I:C/A:C", 10.0),
    ]
    for vector, expected in checks:
        got = cvss.score(vector).score
        state = "ok" if abs(got - expected) < 1e-9 else f"FAIL got {got}"
        if state != "ok":
            problems.append(f"cvss {vector}: {state}")
    print(f"  cvss engine       {'ok' if not any('cvss' in p for p in problems) else 'FAIL'}"
          f" ({len(checks)} spot checks)")

    perms.validate_builtins()
    print(f"  rbac              ok ({len(perms.ALL_PERMISSIONS)} permissions, "
          f"{len(perms.BUILTIN_ROLES)} builtin roles)")

    if problems:
        print("\nFAILED:")
        for problem in problems:
            print(f"  - {problem}")
        return 1
    print("\nall checks passed")
    return 0


def import_inventory(args) -> int:  # noqa: ANN001
    """`python -m veyrs import-inventory` - initial load from an existing CMDB.

    Exists because the correlation engine is only as good as the inventory
    underneath it, and nobody types a fleet in by hand. Takes the same payload
    shape as `POST /assets/inventory/import` so a one-off load and the ongoing
    API path cannot drift apart.
    """
    import json

    from sqlalchemy import select

    from .db import SessionLocal, set_tenant
    from .models import Organization
    from .services import correlation, inventory

    with open(args.file, encoding="utf-8") as handle:
        payload = json.load(handle)
    hosts = payload.get("hosts") if isinstance(payload, dict) else payload
    if not hosts:
        print(f"{args.file}: no hosts to import")
        return 1

    with SessionLocal() as session:
        org = session.execute(
            select(Organization).where(Organization.slug == args.org)
        ).scalars().first()
        if org is None:
            print(f"no organization with slug {args.org!r}")
            return 1
        set_tenant(session, org.id)

        totals = {"hosts": 0, "created": 0, "added": 0, "matched": 0,
                  "unmatched": 0, "findings": 0}
        for host in hosts:
            items = host.get("items") or []
            spec = {k: v for k, v in host.items() if k != "items"}
            asset, created = inventory.upsert_asset(session, org.id, spec)
            result = inventory.install(
                session, asset, items, detected_by=args.source,
                replace=args.replace,
            )
            findings = 0
            if items and not args.no_correlate:
                findings = correlation.correlate_asset(
                    session, org.id, asset
                )["created"]
            # Commit per host: a fleet load is long, and losing forty good hosts
            # because the forty-first had a malformed record helps nobody.
            session.commit()
            totals["hosts"] += 1
            totals["created"] += int(created)
            totals["added"] += result["added"]
            totals["matched"] += result["matched"]
            totals["unmatched"] += result["unmatched"]
            totals["findings"] += findings
            print(f"  {asset.name:28} {'new' if created else 'upd'} "
                  f"{result['added']:>4} installs  {result['matched']:>4} matchable  "
                  f"{findings:>3} findings")

        print(f"\n{totals['hosts']} hosts ({totals['created']} new), "
              f"{totals['added']} installations, {totals['matched']} matchable, "
              f"{totals['unmatched']} unmatched, {totals['findings']} findings raised")
        if totals["unmatched"]:
            print("Unmatched rows are recorded but inert. "
                  "GET /api/v1/assets/inventory/coverage lists them with suggestions.")
    return 0


def intel_due(args) -> int:  # noqa: ANN001
    """Print which feeds the current tick should run.

    Exit code is always 0, including when nothing is due: "no feed needs
    refreshing right now" is a correct outcome, and returning non-zero would
    paint every quiet hour red in `systemctl --failed`.

    The non-quiet form prints the REASON for every feed, due or not. A skip
    that prints nothing is indistinguishable from a run that crashed before it
    started -- which is exactly how `veyrs-intel-sync` went three nights
    without anybody noticing.
    """
    from .services import intel_schedule

    with SessionLocal() as session:
        decisions = intel_schedule.due_feeds(session)

    if args.quiet:
        for decision in decisions:
            if decision["due"]:
                print(decision["feed"])
        return 0

    for decision in decisions:
        mark = "DUE " if decision["due"] else "skip"
        print(f"{mark} {decision['feed']:<5} {decision['reason']}")
    return 0


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="veyrs", description=__doc__,
                                     formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = parser.add_subparsers(dest="command", required=True)

    sub.add_parser("init-db", help="create schema, RLS policies and built-in roles")
    sub.add_parser(
        "sync-schema",
        help="add columns/indexes/FKs present in the models but missing from the DB",
    )
    sub.add_parser("check", help="self-test configuration, storage and engines")
    sub.add_parser("keygen", help="print a fresh VEYRS_ENCRYPTION_KEY")

    boot = sub.add_parser("bootstrap", help="create the first organization + administrator")
    boot.add_argument("--org", required=True, help="organization slug")
    boot.add_argument("--name", help="organization display name")
    boot.add_argument("--email", required=True)
    boot.add_argument("--full-name")
    boot.add_argument("--password", help="visible in ps(1); prefer the "
                      "VEYRS_BOOTSTRAP_PASSWORD environment variable. "
                      "Omit both to be prompted")
    boot.add_argument("--invoicing-code")
    boot.add_argument("--locale", default="en", choices=["en", "es", "de", "fr", "it"])
    boot.add_argument("--superuser", action="store_true")

    for name, help_text in (
        ("sync-kev", "refresh the CISA KEV catalogue"),
        ("sync-epss", "refresh EPSS scores"),
        ("sync-nvd", "incrementally pull CVE records from NVD"),
        ("sync-cwe", "refresh the MITRE CWE weakness dictionary"),
    ):
        p = sub.add_parser(name, help=help_text)
        p.add_argument("--full", action="store_true", help="ignore watermarks, reload everything")
        p.add_argument(
            "--no-correlate", action="store_true",
            help="ingest only; skip raising/rescoring tenant findings. Use for a "
                 "bulk backfill you will correlate afterwards in one pass.",
        )

    risk = sub.add_parser("recompute-risk", help="re-run the risk engine")
    risk.add_argument("--org", help="limit to one organization slug")

    sub.add_parser("run-sla", help="evaluate SLA state and fire escalations")

    dig = sub.add_parser(
        "digest",
        help="queue and deliver the daily digest for every organization whose "
             "configured hour this is",
    )
    dig.add_argument("--dry-run", action="store_true",
                     help="build every recipient's digest and report, send nothing")
    dig.add_argument("--force", action="store_true",
                     help="ignore both the enabled flag and the hour. For an "
                          "operator asking for it now, not for the timer.")

    due = sub.add_parser(
        "intel-due",
        help="print which intelligence feeds are due to run right now",
    )
    due.add_argument(
        "--quiet", action="store_true",
        help="print only the due feed names, one per line, for a shell loop",
    )

    imp = sub.add_parser(
        "import-inventory",
        help="load assets and their installed software from a JSON file",
    )
    imp.add_argument("--file", required=True, help="JSON: {\"hosts\": [...]}")
    imp.add_argument("--org", required=True, help="organization slug")
    imp.add_argument("--source", default="cmdb",
                     help="detected_by label recorded on every installation")
    imp.add_argument("--replace", action="store_true",
                     help="treat this as the complete inventory from --source and "
                          "drop what it no longer lists")
    imp.add_argument("--no-correlate", action="store_true",
                     help="load only; do not raise findings yet")

    args = parser.parse_args(argv)
    handlers = {"init-db": init_db, "bootstrap": bootstrap, "check": check,
                "keygen": keygen,
                "sync-schema": lambda _: (sync_columns(), 0)[1]}
    if args.command in handlers:
        return handlers[args.command](args)

    # Feed/engine commands live in their own modules to keep imports lazy.
    if args.command in ("sync-kev", "sync-epss", "sync-nvd", "sync-cwe"):
        from .intel import feeds

        return feeds.run_cli(
            args.command,
            full=getattr(args, "full", False),
            correlate=not getattr(args, "no_correlate", False),
        )
    if args.command == "intel-due":
        return intel_due(args)
    if args.command == "recompute-risk":
        from .engines import risk

        return risk.run_cli(org_slug=args.org)
    if args.command == "import-inventory":
        return import_inventory(args)
    if args.command == "digest":
        from .services import digest

        return digest.run_cli(dry_run=args.dry_run, force=args.force)
    if args.command == "run-sla":
        # The engine lives in services, not engines — the old import pointed at
        # a module that never existed, so `run-sla` failed on import since v1.
        from .services import sla

        return sla.run_cli()
    parser.error(f"unhandled command {args.command}")
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
