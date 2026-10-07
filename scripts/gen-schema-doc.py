#!/usr/bin/env python3
"""Generate docs/DATABASE_SCHEMA.md from the SQLAlchemy models.

The prose manual lives in docs/DATABASE.md and is written by hand. THIS file
is the table-by-table reference, and it is generated, because a hand-written
one drifts: docs/DATABASE.md claimed "67 tables" for six weeks while the models
carried 87, and nothing failed.

    python3 scripts/gen-schema-doc.py            # rewrite docs/DATABASE_SCHEMA.md
    python3 scripts/gen-schema-doc.py --check    # exit 1 if the file is stale

`--check` is what tests/test_docs_schema_is_current.py runs, so a model change
that skips the regeneration fails a test with a name instead of quietly
publishing a schema reference that describes last month's database.

No database connection is made or needed: the models ARE the schema (init-db
builds the database from this same metadata), so a checkout can regenerate the
reference without access to a running deployment.
"""
from __future__ import annotations

import argparse
import re
import sys
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "backend"))

from sqlalchemy import Table  # noqa: E402

from veyrs.cli import (  # noqa: E402
    PREAUTH_POLICY,
    RLS_TABLES_PREAUTH,
    RLS_TABLES_SKIP,
    RLS_TABLES_STRICT_NULLABLE,
    STRICT_POLICY,
)
from veyrs.models import Base  # noqa: E402
from veyrs.models.base import GLOBAL_TABLES  # noqa: E402

TARGET = ROOT / "docs" / "DATABASE_SCHEMA.md"

#: Module -> (heading, one-line purpose). A module absent here still appears,
#: under its own name: a table that cannot be found in the reference reads as a
#: table that does not exist, which is worse than an unpolished heading.
MODULES = {
    "tenancy": ("Identity and tenancy", "Organizations, users, roles, teams, API keys."),
    "intelligence": (
        "Intelligence catalogues",
        "CVE/CWE/CPE, EPSS, CISA KEV, vendors and products. Global, not tenant-scoped.",
    ),
    "assets": ("Assets", "The estate: assets, groups, business services, installed software."),
    "cmdb": ("CMDB and asset sources", "External inventory sources and their staged records."),
    "vulnerability": (
        "Vulnerabilities and findings",
        "The tenant's view of a CVE, and that CVE on one asset at one location.",
    ),
    "ticketing": ("Ticketing (ITSM)", "Internal queue, counters, and external ITSM connectors."),
    "sla": ("SLA and escalation", "Due dates, breach events and escalation chains."),
    "risk_register": (
        "Risk register",
        "Security risks that are not attached to an asset, with their RACI.",
    ),
    "workflow": ("Workflow and notifications", "Rules, runs, templates, deliveries, webhooks."),
    "compliance": ("Compliance", "Frameworks, controls, implementations, evidence, assessments."),
    "knowledge": ("Knowledge and documents", "Runbooks, revisions, documents, threat sources."),
    "integration": ("Integrations", "Scanners, importers, external links, connector state."),
    "engagement": ("Engagements", "Pentest/assessment engagements and their findings."),
    "ai": ("AI gateway", "Providers, policy, conversations, messages."),
    "agent": ("Execution agents", "Scanner runners, their leases and jobs."),
    "audit": ("Audit trails", "Append-only: audit log, auth events, AI audit log."),
    "views": ("Saved views", "Per-user saved filters and column sets."),
}

PREFACE = """<!-- GENERATED FILE - do not edit by hand.
     Regenerate with: python3 scripts/gen-schema-doc.py
     Guarded by:      tests/test_docs_schema_is_current.py -->

# Database schema reference

Every table VEYRS creates, generated from the models that create them. The
prose manual - tenancy, RLS, the design decisions, operations - is
[DATABASE.md](DATABASE.md); this file is the reference you look a column up in.

**How to read the isolation column:**

| Marker | Meaning |
|---|---|
| **strict** | `ENABLE` + `FORCE ROW LEVEL SECURITY`, policy `veyrs_tenant_isolation`. A query with no tenant bound returns zero rows. |
| **pre-auth** | Same policy, permissive while `veyrs.current_org` is unset. Only the four tables a login must read before the tenant is known. |
| **global** | Shared reference data (the CVE catalogue and friends). Not tenant-owned, no policy. |
| **app-only** | Carries a nullable `organization_id` (a platform-level row is legal), so isolation is enforced by the application layer alone. |

Legend for column flags: `PK` primary key, `FK` foreign key (target shown),
`NOT NULL` required, `UQ` unique, `IDX` indexed, `enc` Fernet-encrypted at rest.
"""


def slugify(heading: str) -> str:
    """GitHub's heading anchor rules, which are not "lowercase and hyphenate".

    Punctuation is DROPPED, not replaced: "Ticketing (ITSM)" anchors as
    `ticketing-itsm`. Replacing it produces `ticketing-(itsm)`, whose closing
    paren also terminates the markdown link early - so the table of contents
    renders as text and nothing reports an error.
    """
    slug = re.sub(r"[^\w\s-]", "", heading.lower())
    return re.sub(r"\s+", "-", slug).strip("-")


def isolation_of(table: Table) -> str:
    name = table.name
    if name in GLOBAL_TABLES:
        return "global"
    if "organization_id" not in table.c or name in RLS_TABLES_SKIP:
        return "global" if "organization_id" not in table.c else "app-only"
    if name in RLS_TABLES_PREAUTH:
        return "pre-auth"
    if table.c.organization_id.nullable and name not in RLS_TABLES_STRICT_NULLABLE:
        return "app-only"
    return "strict"


def column_flags(table: Table, column) -> str:
    flags = []
    if column.primary_key:
        flags.append("PK")
    for fk in sorted(column.foreign_keys, key=lambda f: str(f.target_fullname)):
        flags.append(f"FK -> `{fk.target_fullname}`")
    if not column.nullable and not column.primary_key:
        flags.append("NOT NULL")
    if column.unique:
        flags.append("UQ")
    elif column.index:
        flags.append("IDX")
    if column.name.endswith("_enc"):
        flags.append("enc")
    return ", ".join(flags)


def render_table(table: Table) -> list[str]:
    out = [f"#### `{table.name}`", ""]
    doc = (table.comment or "").strip()
    if doc:
        out += [doc, ""]
    out += [f"*Isolation:* **{isolation_of(table)}**", ""]
    out += ["| Column | Type | Notes |", "|---|---|---|"]
    for column in table.columns:
        type_name = str(column.type).replace("|", "\\|")
        out.append(f"| `{column.name}` | `{type_name}` | {column_flags(table, column)} |")
    out.append("")

    multi = [
        idx for idx in sorted(table.indexes, key=lambda i: i.name or "")
        if len(idx.columns) > 1
    ]
    if multi:
        out.append("*Composite indexes:* " + ", ".join(
            f"`{idx.name}` ({', '.join(c.name for c in idx.columns)})" for idx in multi
        ))
        out.append("")
    # `table.constraints` is a SET: iterating it twice yields two different
    # orders, which makes the generated file differ from itself and turns the
    # --check guard into a coin flip. A flaky guard gets muted on day one.
    uniques = sorted(
        (
            c for c in table.constraints
            if c.__class__.__name__ == "UniqueConstraint" and len(c.columns) > 1
        ),
        key=lambda c: (c.name or "", tuple(col.name for col in c.columns)),
    )
    if uniques:
        out.append("*Composite unique:* " + ", ".join(
            f"`{c.name}` ({', '.join(col.name for col in c.columns)})" for c in uniques
        ))
        out.append("")
    return out


def module_of(table: Table) -> str:
    """Which models/*.py declared this table."""
    for mapper in Base.registry.mappers:
        if mapper.local_table is not None and mapper.local_table.name == table.name:
            return mapper.class_.__module__.rsplit(".", 1)[-1]
    return "other"


def build() -> str:
    by_module: dict[str, list[Table]] = defaultdict(list)
    for table in Base.metadata.tables.values():
        by_module[module_of(table)].append(table)

    total = len(Base.metadata.tables)
    counts = defaultdict(int)
    for table in Base.metadata.tables.values():
        counts[isolation_of(table)] += 1

    lines = [PREFACE, ""]
    lines += [
        f"**{total} tables**: {counts['strict']} strictly isolated, "
        f"{counts['pre-auth']} pre-auth, {counts['global']} global, "
        f"{counts['app-only']} application-enforced.",
        "",
        "The policy body, identical on every RLS table:",
        "",
        "```sql",
        "-- strict",
        f"USING ({STRICT_POLICY})",
        "-- pre-auth",
        f"USING ({PREAUTH_POLICY})",
        "```",
        "",
        "## Contents",
        "",
    ]

    ordered = [m for m in MODULES if m in by_module]
    ordered += sorted(m for m in by_module if m not in MODULES)
    for module in ordered:
        heading, _ = MODULES.get(module, (module.replace("_", " ").title(), ""))
        lines.append(f"- [{heading}](#{slugify(heading)}) - {len(by_module[module])} tables")
    lines.append("")

    for module in ordered:
        heading, purpose = MODULES.get(module, (module.replace("_", " ").title(), ""))
        lines += [f"## {heading}", ""]
        if purpose:
            lines += [purpose, ""]
        lines += [f"Declared in `backend/veyrs/models/{module}.py`.", ""]
        for table in sorted(by_module[module], key=lambda t: t.name):
            lines += render_table(table)

    return "\n".join(lines).rstrip() + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="exit 1 if the doc is stale")
    args = parser.parse_args()

    generated = build()
    if args.check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != generated:
            print(
                f"{TARGET.relative_to(ROOT)} is out of date with the models.\n"
                "Regenerate it: python3 scripts/gen-schema-doc.py",
                file=sys.stderr,
            )
            return 1
        print(f"{TARGET.relative_to(ROOT)} matches the models")
        return 0

    TARGET.write_text(generated, encoding="utf-8")
    print(f"wrote {TARGET.relative_to(ROOT)} ({len(generated.splitlines())} lines)")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
