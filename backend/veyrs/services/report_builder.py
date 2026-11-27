"""Report builder: ad-hoc tabular reports from a curated catalog, never from SQL.

The fixed reports (`services/reporting.py`) answer the questions the product
anticipated. Everything else -- "open critical findings per business service
and team, with their average age" -- used to mean an export into a spreadsheet
and a pivot table, which is a copy of the estate on somebody's laptop. This
module lets an operator ask that question in VEYRS, under VEYRS's
authorization, without ever handing the database a string the client wrote.

How it is safe, in the order a request meets it:

1. **The client sends a JSON spec, not SQL.** `validate()` checks every name in
   it against `CATALOG`: entity, columns, filter fields, operators, group-by
   fields, aggregate functions, sort keys. Anything unknown is a
   `ReportBuilderError` (HTTP 422) that names the offending key. Unknown keys
   are REJECTED, never dropped -- a report silently missing half its filters
   answers a different question under the same title (the rule
   `services/views.py` set for saved views).
2. **Values are bound parameters, always.** The compiler builds SQLAlchemy
   expressions from catalog entries; a filter value only ever reaches the
   database as a bind parameter, and `contains` escapes `%`, `_` and the escape
   character itself, so a value cannot widen a match either.
3. **Authorization is the list routes', not a new one.** Every entity declares
   the permission its own list route requires, and the compiler applies the
   same team-scope filter that route applies (`security/scope.py`), plus the
   tenant predicate on top of RLS. A restricted operator's report -- rows,
   group counts and exports alike -- covers their slice and says so in its
   provenance.
4. **Bounded.** Columns, filters, group-bys, aggregates and sort keys are
   capped; rows are capped (`RUN_LIMIT` on screen, `EXPORT_LIMIT` in a file);
   and the statement runs under `SET LOCAL statement_timeout`, so one heavy
   report cannot hold the shared database for everybody else.

Joins are LEFT OUTER and many-to-one only (finding -> asset -> business
service, finding -> team ...). A to-many join would multiply rows and make every
count wrong without an error, so the catalog does not offer one; to-many
questions ("open findings per asset") are derived fields computed as scoped,
correlated sub-selects instead.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import decimal
import math
import uuid
from typing import Any, Callable

from sqlalchemy import and_, case, false as sa_false, func, literal_column, or_, select, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import Session, aliased

from ..models import (
    Asset, BusinessService, Finding, OPEN_STATES, OPEN_TICKET_STATES, Team, Ticket,
    Vulnerability,
)
from ..models.risk_register import (
    OPEN_RISK_STATUSES, RACI_ROLES, RISK_BANDS, RISK_STATUSES, RISK_TREATMENTS,
    RiskEntry, RiskRaci,
)
from ..models.vulnerability import FindingState
from ..models.assets import AssetType, Criticality, DataClassification, Environment, Exposure
from ..models.ticketing import TicketState, TicketType
from ..security import scope as team_scope

# --- limits ----------------------------------------------------------------
MAX_COLUMNS = 25
MAX_FILTERS = 20
MAX_GROUP_BY = 3
MAX_AGGREGATES = 6
MAX_SORT = 3
MAX_IN_VALUES = 100
MAX_STRING_LEN = 200
MAX_DAYS = 3650
DEFAULT_LIMIT = 500
#: Rows returned to the screen. A table longer than this is not being read.
RUN_LIMIT = 5000
#: Rows written to a file. Beyond this the right tool is the API, paged.
EXPORT_LIMIT = 50000
#: Per-statement ceiling. The connection default is 30s (`db.py`); a report is
#: an interactive question and should fail fast rather than queue behind itself.
STATEMENT_TIMEOUT = "20s"

SPEC_KEYS = frozenset({"entity", "columns", "filters", "group_by", "aggregates",
                       "sort", "limit"})

SEVERITIES = ("critical", "high", "medium", "low", "informational")


class ReportBuilderError(ValueError):
    """A spec the catalog does not allow. The API turns this into a 422."""


# ---------------------------------------------------------------------------
# Catalog
# ---------------------------------------------------------------------------
@dataclasses.dataclass(frozen=True)
class Join:
    """A many-to-one LEFT OUTER join, keyed by name. `after` names its parent."""

    model: type
    on: Callable[["_Query"], Any]
    after: str | None = None


@dataclasses.dataclass(frozen=True)
class Field:
    key: str
    label: str
    type: str                                  # string|number|date|bool|enum
    expr: Callable[["_Query"], Any]
    joins: tuple[str, ...] = ()
    values: tuple[str, ...] | None = None      # enum vocabulary
    groupable: bool = True
    description: str | None = None


@dataclasses.dataclass(frozen=True)
class Entity:
    key: str
    label: str
    permission: str
    model: type
    fields: tuple[Field, ...]
    joins: dict[str, Join]
    #: (stmt, query) -> stmt. Tenant predicate, soft-delete, and team scope.
    restrict: Callable[[Any, "_Query"], Any]
    default_columns: tuple[str, ...]
    description: str = ""

    def field(self, key: str) -> Field | None:
        return next((f for f in self.fields if f.key == key), None)


@dataclasses.dataclass
class _Query:
    """Compile-time state: the aliases in play and whose authorization applies."""

    entity: Entity
    scope: team_scope.TeamScope
    organization_id: uuid.UUID
    user_id: uuid.UUID | None
    aliases: dict[str, Any] = dataclasses.field(default_factory=dict)
    order: list[str] = dataclasses.field(default_factory=list)

    @property
    def base(self):
        return self.entity.model

    def a(self, name: str):
        """The alias for join `name`, registering it (and its parents) on first use."""
        if name not in self.aliases:
            join = self.entity.joins[name]
            if join.after:
                self.a(join.after)
            self.aliases[name] = aliased(join.model, name=f"rb_{name}")
            self.order.append(name)
        return self.aliases[name]


def _col(attr: str, join: str | None = None) -> Callable[[_Query], Any]:
    if join is None:
        return lambda q: getattr(q.base, attr)
    return lambda q: getattr(q.a(join), attr)


def _f(key, label, type_, attr=None, join=None, *, expr=None, values=None,
       groupable=None, description=None) -> Field:
    """Terse field constructor: `attr` on the base model, or on join `join`."""
    if expr is None:
        expr = _col(attr or key.rsplit(".", 1)[-1], join)
    if groupable is None:
        # Grouping by a timestamp yields one group per row; it is offered for
        # aggregation (min/max) and filtering instead.
        groupable = type_ != "date"
    return Field(key=key, label=label, type=type_, expr=expr,
                 joins=(join,) if join else (), values=tuple(values) if values else None,
                 groupable=groupable, description=description)


def _enum(e) -> tuple[str, ...]:
    return tuple(m.value for m in e)


def _days_since(column_expr):
    return func.extract("epoch", func.now() - column_expr) / 86400.0


def _scoped_open_findings(where) -> Callable[[_Query], Any]:
    """Count of OPEN findings matching `where(q)`, narrowed to the reader's scope.

    A correlated sub-select rather than a join: a to-many join would multiply
    the parent's rows. The team-scope clause is applied INSIDE the count, so a
    restricted operator looking at a visible asset does not learn how many
    findings on it belong to somebody else's queue.
    """
    def build(q: _Query):
        stmt = select(func.count(Finding.id)).where(
            Finding.organization_id == q.organization_id,
            Finding.state.in_(tuple(OPEN_STATES)),
            where(q),
        )
        if q.scope.restricted:
            stmt = stmt.where(team_scope.finding_clause(q.scope))
        return stmt.correlate(q.base).scalar_subquery()
    return build


# --- findings ---------------------------------------------------------------
def _restrict_findings(stmt, q: _Query):
    stmt = stmt.where(Finding.organization_id == q.organization_id)
    return team_scope.findings(stmt, q.scope)


FINDINGS = Entity(
    key="findings", label="Findings", permission="finding:read", model=Finding,
    description="One row per affected place. Team scope by effective owner.",
    joins={
        "asset": Join(Asset, lambda q: q.a("asset").id == Finding.asset_id),
        "asset_service": Join(
            BusinessService,
            lambda q: q.a("asset_service").id == q.a("asset").business_service_id,
            after="asset"),
        "asset_team": Join(Team, lambda q: q.a("asset_team").id == q.a("asset").team_id,
                           after="asset"),
        "assigned_team": Join(Team,
                              lambda q: q.a("assigned_team").id == Finding.assigned_team_id),
        # Effective owner, the same definition as `teams.owning_team()`:
        # explicit assignment first, the asset's team as the fallback.
        "owning_team": Join(
            Team,
            lambda q: q.a("owning_team").id == func.coalesce(Finding.assigned_team_id,
                                                              q.a("asset").team_id),
            after="asset"),
        "vulnerability": Join(
            Vulnerability, lambda q: q.a("vulnerability").id == Finding.vulnerability_id),
    },
    restrict=_restrict_findings,
    default_columns=("title", "severity", "state", "risk_score", "asset.name",
                     "owning_team.name"),
    fields=(
        _f("title", "Title", "string"),
        _f("state", "State", "enum", values=_enum(FindingState)),
        _f("is_open", "Open", "bool", expr=lambda q: Finding.state.in_(tuple(OPEN_STATES)),
           description="True for every state still in the work queue."),
        _f("severity", "Severity", "enum", values=SEVERITIES),
        _f("risk_score", "Risk score", "number"),
        _f("risk_level", "Risk level", "enum", values=SEVERITIES),
        _f("cvss_score", "CVSS score", "number"),
        _f("epss_score", "EPSS score", "number"),
        _f("kev", "Known exploited (KEV)", "bool"),
        _f("sla_breached", "SLA breached", "bool"),
        _f("sla_due_at", "SLA due", "date"),
        _f("escalation_level", "Escalation level", "number"),
        _f("scanner", "Scanner", "string"),
        _f("port", "Port", "number"),
        _f("protocol", "Protocol", "string"),
        _f("detected_at", "Detected", "date"),
        _f("first_seen_at", "First seen", "date"),
        _f("last_seen_at", "Last seen", "date"),
        _f("remediated_at", "Remediated", "date"),
        _f("closed_at", "Closed", "date"),
        _f("age_days", "Age (days)", "number",
           expr=lambda q: _days_since(func.coalesce(Finding.first_seen_at,
                                                    Finding.detected_at)),
           groupable=False,
           description="Days since first seen (or detected, when never seen twice)."),
        _f("asset.name", "Asset", "string", join="asset"),
        _f("asset.hostname", "Asset hostname", "string", join="asset"),
        _f("asset.asset_type", "Asset type", "enum", join="asset", values=_enum(AssetType)),
        _f("asset.criticality", "Asset criticality", "enum", join="asset",
           values=_enum(Criticality)),
        _f("asset.exposure", "Asset exposure", "enum", join="asset", values=_enum(Exposure)),
        _f("asset.environment", "Asset environment", "enum", join="asset",
           values=_enum(Environment)),
        _f("asset.data_classification", "Asset data classification", "enum", join="asset",
           values=_enum(DataClassification)),
        _f("asset.business_service", "Business service", "string", "name",
           join="asset_service"),
        _f("asset.business_service_criticality", "Business service criticality", "enum",
           "criticality", join="asset_service", values=_enum(Criticality)),
        _f("asset.team", "Asset team", "string", "name", join="asset_team"),
        _f("assigned_team.name", "Assigned team", "string", join="assigned_team"),
        _f("owning_team.name", "Owning team", "string", join="owning_team",
           description="Explicit assignment, else the asset's team."),
        _f("vulnerability.cve_id", "CVE", "string", join="vulnerability"),
        _f("vulnerability.title", "Vulnerability", "string", join="vulnerability"),
    ),
)


# --- assets -----------------------------------------------------------------
def _restrict_assets(stmt, q: _Query):
    stmt = stmt.where(Asset.organization_id == q.organization_id,
                      Asset.deleted_at.is_(None))
    return team_scope.assets(stmt, q.scope)


ASSETS = Entity(
    key="assets", label="Assets", permission="asset:read", model=Asset,
    description="Inventory. Team scope by the asset's owning team.",
    joins={
        "team": Join(Team, lambda q: q.a("team").id == Asset.team_id),
        "service": Join(BusinessService,
                        lambda q: q.a("service").id == Asset.business_service_id),
    },
    restrict=_restrict_assets,
    default_columns=("name", "asset_type", "criticality", "exposure", "team.name",
                     "open_findings"),
    fields=(
        _f("name", "Name", "string"),
        _f("hostname", "Hostname", "string"),
        _f("fqdn", "FQDN", "string"),
        _f("asset_type", "Type", "enum", values=_enum(AssetType)),
        _f("criticality", "Criticality", "enum", values=_enum(Criticality)),
        _f("exposure", "Exposure", "enum", values=_enum(Exposure)),
        _f("environment", "Environment", "enum", values=_enum(Environment)),
        _f("data_classification", "Data classification", "enum",
           values=_enum(DataClassification)),
        _f("operating_system", "Operating system", "string"),
        _f("location", "Location", "string"),
        _f("source", "Source", "string"),
        _f("is_active", "Active", "bool"),
        _f("first_seen_at", "First seen", "date"),
        _f("last_seen_at", "Last seen", "date"),
        _f("created_at", "Created", "date"),
        _f("team.name", "Team", "string", join="team"),
        _f("business_service", "Business service", "string", "name", join="service"),
        _f("business_service_criticality", "Business service criticality", "enum",
           "criticality", join="service", values=_enum(Criticality)),
        _f("open_findings", "Open findings", "number",
           expr=_scoped_open_findings(lambda q: Finding.asset_id == Asset.id),
           groupable=False,
           description="Open findings on the asset that you can see."),
    ),
)


# --- vulnerabilities (the tenant's roll-up view) ------------------------------
def _restrict_vulnerabilities(stmt, q: _Query):
    stmt = stmt.where(Vulnerability.organization_id == q.organization_id)
    if q.scope.restricted:
        # Exactly the list route's rule: a roll-up is visible when at least one
        # of its findings is, so it cannot leak the shape of another team's estate.
        visible = team_scope.findings(
            select(Finding.vulnerability_id).where(
                Finding.organization_id == q.organization_id),
            q.scope,
        )
        stmt = stmt.where(Vulnerability.id.in_(visible))
    return stmt


VULNERABILITIES = Entity(
    key="vulnerabilities", label="Vulnerabilities", permission="vulnerability:read",
    model=Vulnerability,
    description="One row per CVE that matters to this organization.",
    joins={},
    restrict=_restrict_vulnerabilities,
    default_columns=("cve_id", "title", "severity", "kev", "epss_score", "open_findings"),
    fields=(
        _f("cve_id", "CVE", "string"),
        _f("title", "Title", "string"),
        _f("state", "State", "enum", values=_enum(FindingState)),
        _f("severity", "Severity", "enum", values=SEVERITIES),
        _f("source", "Source", "string"),
        _f("cvss_score", "CVSS score", "number"),
        _f("epss_score", "EPSS score", "number"),
        _f("epss_percentile", "EPSS percentile", "number"),
        _f("kev", "Known exploited (KEV)", "bool"),
        _f("risk_score", "Risk score", "number"),
        _f("risk_level", "Risk level", "enum", values=SEVERITIES),
        _f("created_at", "First recorded", "date"),
        _f("open_findings", "Open findings", "number",
           expr=_scoped_open_findings(lambda q: Finding.vulnerability_id == Vulnerability.id),
           groupable=False,
           description="Open findings of this vulnerability that you can see."),
    ),
)


# --- tickets ------------------------------------------------------------------
def _restrict_tickets(stmt, q: _Query):
    stmt = stmt.where(Ticket.organization_id == q.organization_id)
    return team_scope.tickets(stmt, q.scope)


TICKETS = Entity(
    key="tickets", label="Tickets", permission="ticket:read", model=Ticket,
    description="ITSM records. Team scope by own assignment, else the finding's owner.",
    joins={
        "assigned_team": Join(Team, lambda q: q.a("assigned_team").id == Ticket.assigned_team_id),
        "asset": Join(Asset, lambda q: q.a("asset").id == Ticket.asset_id),
        "service": Join(BusinessService,
                        lambda q: q.a("service").id == Ticket.business_service_id),
    },
    restrict=_restrict_tickets,
    default_columns=("reference", "ticket_type", "state", "priority", "title",
                     "assigned_team.name"),
    fields=(
        _f("reference", "Reference", "string"),
        _f("ticket_type", "Type", "enum", values=_enum(TicketType)),
        _f("state", "State", "enum", values=_enum(TicketState)),
        _f("is_open", "Open", "bool",
           expr=lambda q: Ticket.state.in_(tuple(OPEN_TICKET_STATES))),
        _f("priority", "Priority", "enum", values=SEVERITIES),
        _f("title", "Title", "string"),
        _f("due_at", "Due", "date"),
        _f("sla_breached", "SLA breached", "bool"),
        _f("created_at", "Created", "date"),
        _f("resolved_at", "Resolved", "date"),
        _f("closed_at", "Closed", "date"),
        _f("age_days", "Age (days)", "number",
           expr=lambda q: _days_since(Ticket.created_at), groupable=False),
        _f("external_system", "External system", "string"),
        _f("external_key", "External key", "string"),
        _f("assigned_team.name", "Assigned team", "string", join="assigned_team"),
        _f("asset.name", "Asset", "string", join="asset"),
        _f("business_service", "Business service", "string", "name", join="service"),
    ),
)


# --- risk register --------------------------------------------------------------
def _restrict_risks(stmt, q: _Query):
    stmt = stmt.where(RiskEntry.organization_id == q.organization_id,
                      RiskEntry.deleted_at.is_(None))
    if q.scope.restricted:
        # The register's own rule (`api/v1/risk_register._visible_ids`): a scoped
        # identity sees the entries it, or one of its teams, holds a RACI seat on.
        seat = RiskRaci.team_id.in_(tuple(q.scope.team_ids)) if q.scope.team_ids else None
        if q.user_id is not None:
            mine = RiskRaci.user_id == q.user_id
            seat = mine if seat is None else or_(mine, seat)
        if seat is None:
            return stmt.where(sa_false())
        seats = select(RiskRaci.risk_id).where(
            RiskRaci.organization_id == q.organization_id,
            RiskRaci.raci.in_(tuple(RACI_ROLES)), seat)
        stmt = stmt.where(RiskEntry.id.in_(seats))
    return stmt


def _band(column):
    return case(
        (column.is_(None), None),
        (column >= 15, "critical"), (column >= 10, "high"), (column >= 5, "medium"),
        else_="low",
    )


RISKS = Entity(
    key="risks", label="Risk register", permission="riskregister:read", model=RiskEntry,
    description="Register entries. Team scope by RACI seat.",
    joins={},
    restrict=_restrict_risks,
    default_columns=("code", "title", "status", "treatment", "score", "band"),
    fields=(
        _f("code", "Code", "string"),
        _f("title", "Title", "string"),
        _f("category", "Category", "string"),
        _f("source", "Source", "string"),
        _f("status", "Status", "enum", values=RISK_STATUSES),
        _f("is_open", "Open", "bool",
           expr=lambda q: RiskEntry.status.in_(tuple(OPEN_RISK_STATUSES))),
        _f("treatment", "Treatment", "enum", values=RISK_TREATMENTS),
        _f("likelihood", "Likelihood", "number"),
        _f("impact", "Impact", "number"),
        _f("score", "Inherent score", "number"),
        _f("band", "Inherent band", "enum", values=RISK_BANDS,
           expr=lambda q: _band(RiskEntry.score)),
        _f("residual_score", "Residual score", "number"),
        _f("residual_band", "Residual band", "enum", values=RISK_BANDS,
           expr=lambda q: _band(RiskEntry.residual_score)),
        _f("identified_at", "Identified", "date"),
        _f("review_due_at", "Review due", "date"),
        _f("review_overdue", "Review overdue", "bool",
           expr=lambda q: and_(RiskEntry.review_due_at.is_not(None),
                               RiskEntry.review_due_at < func.current_date(),
                               RiskEntry.status.in_(tuple(OPEN_RISK_STATUSES)))),
        _f("closed_at", "Closed", "date"),
        _f("created_at", "Created", "date"),
    ),
)


CATALOG: dict[str, Entity] = {e.key: e for e in (FINDINGS, ASSETS, VULNERABILITIES,
                                                  TICKETS, RISKS)}

#: Operators per field type. `in`/`not_in` take a list; `between` takes [lo, hi];
#: `last_days`/`older_than_days`/`next_days` take a whole number of days.
OPERATORS: dict[str, tuple[str, ...]] = {
    "string": ("eq", "ne", "in", "not_in", "contains", "not_contains", "starts_with",
               "is_null", "not_null"),
    "number": ("eq", "ne", "gt", "gte", "lt", "lte", "between", "in", "is_null", "not_null"),
    "date": ("gt", "gte", "lt", "lte", "between", "last_days", "older_than_days",
             "next_days", "is_null", "not_null"),
    "bool": ("eq", "is_null", "not_null"),
    "enum": ("eq", "ne", "in", "not_in", "is_null", "not_null"),
}
NO_VALUE_OPS = frozenset({"is_null", "not_null"})
LIST_OPS = frozenset({"in", "not_in"})
DAY_OPS = frozenset({"last_days", "older_than_days", "next_days"})

#: Aggregate functions and the field types each accepts. `count` takes no field.
AGGREGATES: dict[str, tuple[str, ...]] = {
    "count": (),
    "count_distinct": ("string", "number", "date", "bool", "enum"),
    "avg": ("number",),
    "sum": ("number",),
    "min": ("number", "date"),
    "max": ("number", "date"),
}
AGG_LABELS = {"count": "Count", "count_distinct": "Distinct", "avg": "Average",
              "sum": "Sum", "min": "Minimum", "max": "Maximum"}


def catalog(can: Callable[[str], bool] | None = None) -> dict:
    """The catalog as the console and API clients see it."""
    return {
        "entities": [
            {
                "key": e.key, "label": e.label, "description": e.description,
                "permission": e.permission,
                "available": True if can is None else bool(can(e.permission)),
                "default_columns": list(e.default_columns),
                "fields": [
                    {"key": f.key, "label": f.label, "type": f.type,
                     "values": list(f.values) if f.values else None,
                     "groupable": f.groupable, "description": f.description}
                    for f in e.fields
                ],
            }
            for e in CATALOG.values()
        ],
        "operators": {k: list(v) for k, v in OPERATORS.items()},
        "aggregates": {k: list(v) for k, v in AGGREGATES.items()},
        "limits": {
            "columns": MAX_COLUMNS, "filters": MAX_FILTERS, "group_by": MAX_GROUP_BY,
            "aggregates": MAX_AGGREGATES, "sort": MAX_SORT, "in_values": MAX_IN_VALUES,
            "run_rows": RUN_LIMIT, "export_rows": EXPORT_LIMIT,
            "default_rows": DEFAULT_LIMIT, "statement_timeout": STATEMENT_TIMEOUT,
        },
    }


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def _list(spec: dict, key: str, cap: int) -> list:
    raw = spec.get(key)
    if raw is None:
        return []
    if not isinstance(raw, list):
        raise ReportBuilderError(f"{key} must be a list")
    if len(raw) > cap:
        raise ReportBuilderError(f"at most {cap} {key.replace('_', '-')} entries")
    return raw


def _field(entity: Entity, key: Any, where: str) -> Field:
    if not isinstance(key, str):
        raise ReportBuilderError(f"{where}: field must be a string")
    found = entity.field(key)
    if found is None:
        raise ReportBuilderError(
            f"{where}: {entity.key} has no field {key!r}. Fields are offered by "
            "GET /report-builder/catalog; there is no free-form column access."
        )
    return found


def _is_number(value: Any) -> bool:
    return (isinstance(value, (int, float)) and not isinstance(value, bool)
            and math.isfinite(value))


def _parse_date(value: Any, where: str) -> str:
    if not isinstance(value, str) or len(value) > 40:
        raise ReportBuilderError(f"{where}: expected an ISO 8601 date, e.g. 2026-01-31")
    try:
        dt.datetime.fromisoformat(value)
    except ValueError:
        raise ReportBuilderError(f"{where}: {value!r} is not an ISO 8601 date") from None
    return value


def _scalar(field: Field, value: Any, where: str) -> Any:
    """Check one value against the field's type. Returns the normalised value."""
    if field.type == "number":
        if not _is_number(value):
            raise ReportBuilderError(f"{where}: {field.key} takes a number")
        return value
    if field.type == "bool":
        if not isinstance(value, bool):
            raise ReportBuilderError(f"{where}: {field.key} takes true or false")
        return value
    if field.type == "date":
        return _parse_date(value, where)
    if not isinstance(value, str):
        raise ReportBuilderError(f"{where}: {field.key} takes a string")
    if len(value) > MAX_STRING_LEN:
        raise ReportBuilderError(f"{where}: value longer than {MAX_STRING_LEN} characters")
    if field.type == "enum" and value not in (field.values or ()):
        raise ReportBuilderError(
            f"{where}: {value!r} is not a {field.key}; expected one of "
            f"{', '.join(field.values or ())}"
        )
    return value


def _filter(entity: Entity, raw: Any, index: int) -> dict:
    where = f"filters[{index}]"
    if not isinstance(raw, dict):
        raise ReportBuilderError(f"{where} must be an object")
    unknown = sorted(set(raw) - {"field", "op", "value"})
    if unknown:
        raise ReportBuilderError(f"{where}: unknown key(s) {', '.join(unknown)}")
    field = _field(entity, raw.get("field"), where)
    op = raw.get("op")
    allowed = OPERATORS[field.type]
    if op not in allowed:
        raise ReportBuilderError(
            f"{where}: operator {op!r} does not apply to {field.key} ({field.type}); "
            f"allowed: {', '.join(allowed)}"
        )
    value = raw.get("value")
    if op in NO_VALUE_OPS:
        if value is not None:
            raise ReportBuilderError(f"{where}: {op} takes no value")
        return {"field": field.key, "op": op}
    if op in LIST_OPS:
        if not isinstance(value, list) or not value:
            raise ReportBuilderError(f"{where}: {op} takes a non-empty list")
        if len(value) > MAX_IN_VALUES:
            raise ReportBuilderError(f"{where}: at most {MAX_IN_VALUES} values")
        value = [_scalar(field, v, where) for v in value]
    elif op == "between":
        if not isinstance(value, list) or len(value) != 2:
            raise ReportBuilderError(f"{where}: between takes [low, high]")
        value = [_scalar(field, v, where) for v in value]
    elif op in DAY_OPS:
        if not isinstance(value, int) or isinstance(value, bool) \
                or not 1 <= value <= MAX_DAYS:
            raise ReportBuilderError(f"{where}: {op} takes whole days, 1-{MAX_DAYS}")
    else:
        value = _scalar(field, value, where)
    return {"field": field.key, "op": op, "value": value}


def _aggregate(entity: Entity, raw: Any, index: int) -> dict:
    where = f"aggregates[{index}]"
    if not isinstance(raw, dict):
        raise ReportBuilderError(f"{where} must be an object")
    unknown = sorted(set(raw) - {"fn", "field"})
    if unknown:
        raise ReportBuilderError(f"{where}: unknown key(s) {', '.join(unknown)}")
    fn = raw.get("fn")
    if fn not in AGGREGATES:
        raise ReportBuilderError(
            f"{where}: unknown aggregate {fn!r}; allowed: {', '.join(AGGREGATES)}")
    if fn == "count":
        if raw.get("field") is not None:
            raise ReportBuilderError(f"{where}: count takes no field")
        return {"fn": "count"}
    field = _field(entity, raw.get("field"), where)
    if field.type not in AGGREGATES[fn]:
        raise ReportBuilderError(
            f"{where}: {fn} does not apply to {field.key} ({field.type})")
    return {"fn": fn, "field": field.key}


def aggregate_key(agg: dict) -> str:
    return agg["fn"] if agg["fn"] == "count" else f"{agg['fn']}:{agg['field']}"


def validate(spec: Any) -> dict:
    """Check a spec against the catalog and return its normalised form.

    Called on save AND on every run: a saved spec naming a field the catalog
    no longer has fails here with a sentence naming the field.
    """
    if not isinstance(spec, dict):
        raise ReportBuilderError("a report spec must be a JSON object")
    unknown = sorted(set(spec) - SPEC_KEYS)
    if unknown:
        raise ReportBuilderError(
            f"unknown spec key(s) {', '.join(unknown)}; allowed: {', '.join(sorted(SPEC_KEYS))}")
    entity = CATALOG.get(spec.get("entity"))   # type: ignore[arg-type]
    if entity is None:
        raise ReportBuilderError(
            f"unknown entity {spec.get('entity')!r}; expected one of {', '.join(CATALOG)}")

    columns = [_field(entity, c, f"columns[{i}]").key
               for i, c in enumerate(_list(spec, "columns", MAX_COLUMNS))]
    if len(set(columns)) != len(columns):
        raise ReportBuilderError("a column is listed twice")
    filters = [_filter(entity, f, i)
               for i, f in enumerate(_list(spec, "filters", MAX_FILTERS))]
    group_by = []
    for i, g in enumerate(_list(spec, "group_by", MAX_GROUP_BY)):
        field = _field(entity, g, f"group_by[{i}]")
        if not field.groupable:
            raise ReportBuilderError(
                f"group_by[{i}]: {field.key} cannot be grouped on; aggregate it instead")
        if field.key in group_by:
            raise ReportBuilderError(f"group_by[{i}]: {field.key} is listed twice")
        group_by.append(field.key)
    aggregates = [_aggregate(entity, a, i)
                  for i, a in enumerate(_list(spec, "aggregates", MAX_AGGREGATES))]
    agg_keys = [aggregate_key(a) for a in aggregates]
    if len(set(agg_keys)) != len(agg_keys):
        raise ReportBuilderError("an aggregate is listed twice")

    grouped = bool(group_by or aggregates)
    if grouped:
        if columns:
            raise ReportBuilderError(
                "columns must be empty in a grouped report: its columns are the "
                "group-by fields followed by the aggregates")
        if not aggregates:
            aggregates = [{"fn": "count"}]
            agg_keys = ["count"]
    elif not columns:
        raise ReportBuilderError("choose at least one column, or group and aggregate")

    sort = []
    for i, s in enumerate(_list(spec, "sort", MAX_SORT)):
        where = f"sort[{i}]"
        if not isinstance(s, dict) or sorted(set(s) - {"field", "dir"}):
            raise ReportBuilderError(f"{where} must be {{field, dir}}")
        key, direction = s.get("field"), s.get("dir", "asc")
        if direction not in ("asc", "desc"):
            raise ReportBuilderError(f"{where}: dir must be asc or desc")
        if grouped:
            if key not in group_by and key not in agg_keys:
                raise ReportBuilderError(
                    f"{where}: a grouped report sorts by a group-by field or an "
                    f"aggregate ({', '.join(group_by + agg_keys)}); got {key!r}")
        else:
            key = _field(entity, key, where).key
        sort.append({"field": key, "dir": direction})

    limit = spec.get("limit")
    if limit is not None and (not isinstance(limit, int) or isinstance(limit, bool)
                              or not 1 <= limit <= EXPORT_LIMIT):
        raise ReportBuilderError(f"limit must be a whole number, 1-{EXPORT_LIMIT}")

    return {"entity": entity.key, "columns": columns, "filters": filters,
            "group_by": group_by, "aggregates": aggregates, "sort": sort,
            "limit": limit}


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------
def _escape_like(value: str) -> str:
    """Make `%`, `_` and the escape character literal inside a LIKE pattern."""
    return value.replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")


def _as_datetime(value: str) -> dt.datetime:
    parsed = dt.datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


def _predicate(field: Field, expr, op: str, value: Any):
    """One filter as an expression. `value` reaches SQL only as a bind parameter."""
    if field.type == "date" and value is not None and op not in DAY_OPS:
        value = ([_as_datetime(v) for v in value] if isinstance(value, list)
                 else _as_datetime(value))
    now = dt.datetime.now(dt.timezone.utc)
    if op == "is_null":
        return expr.is_(None)
    if op == "not_null":
        return expr.is_not(None)
    if op == "eq":
        return expr.is_(value) if field.type == "bool" else expr == value
    if op == "ne":
        # NULL is "not equal" to a value as far as an operator is concerned;
        # SQL's three-valued `<>` would silently drop those rows.
        return or_(expr != value, expr.is_(None))
    if op == "in":
        return expr.in_(value)
    if op == "not_in":
        return or_(expr.not_in(value), expr.is_(None))
    if op == "contains":
        return expr.ilike(f"%{_escape_like(value)}%", escape="\\")
    if op == "not_contains":
        return or_(expr.not_ilike(f"%{_escape_like(value)}%", escape="\\"), expr.is_(None))
    if op == "starts_with":
        return expr.ilike(f"{_escape_like(value)}%", escape="\\")
    if op == "gt":
        return expr > value
    if op == "gte":
        return expr >= value
    if op == "lt":
        return expr < value
    if op == "lte":
        return expr <= value
    if op == "between":
        return expr.between(value[0], value[1])
    if op == "last_days":
        return and_(expr >= now - dt.timedelta(days=value), expr <= now)
    if op == "older_than_days":
        return expr < now - dt.timedelta(days=value)
    if op == "next_days":
        return and_(expr >= now, expr <= now + dt.timedelta(days=value))
    raise ReportBuilderError(f"operator {op!r} is not implemented")  # pragma: no cover


def _aggregate_expr(agg: dict, q: _Query):
    if agg["fn"] == "count":
        return func.count()
    expr = q.entity.field(agg["field"]).expr(q)
    return {
        "count_distinct": lambda e: func.count(func.distinct(e)),
        "avg": func.avg, "sum": func.sum, "min": func.min, "max": func.max,
    }[agg["fn"]](expr)


def compile(spec: dict, scope: team_scope.TeamScope, organization_id: uuid.UUID,
            *, user_id: uuid.UUID | None = None, limit: int = RUN_LIMIT):
    """Validated spec -> (statement, output columns). Never touches the database.

    `limit` is the hard ceiling for this use (screen or file); the statement
    fetches one row more so the caller can tell "exactly N" from "truncated".
    """
    spec = validate(spec)
    entity = CATALOG[spec["entity"]]
    q = _Query(entity=entity, scope=scope, organization_id=organization_id, user_id=user_id)
    grouped = bool(spec["group_by"] or spec["aggregates"])

    selected: list[tuple[str, Any]] = []
    columns: list[dict] = []
    if grouped:
        group_exprs = []
        for i, key in enumerate(spec["group_by"]):
            field = entity.field(key)
            expr = field.expr(q).label(f"g{i}")
            group_exprs.append(expr)
            selected.append((key, expr))
            columns.append({"key": key, "label": field.label, "type": field.type})
        for i, agg in enumerate(spec["aggregates"]):
            key = aggregate_key(agg)
            expr = _aggregate_expr(agg, q).label(f"a{i}")
            selected.append((key, expr))
            if agg["fn"] == "count":
                label, type_ = "Count", "number"
            else:
                field = entity.field(agg["field"])
                label = f"{AGG_LABELS[agg['fn']]} of {field.label}"
                type_ = field.type if agg["fn"] in ("min", "max") else "number"
            columns.append({"key": key, "label": label, "type": type_})
    else:
        for i, key in enumerate(spec["columns"]):
            field = entity.field(key)
            selected.append((key, field.expr(q).label(f"c{i}")))
            columns.append({"key": key, "label": field.label, "type": field.type})

    where = [_predicate(entity.field(f["field"]), entity.field(f["field"]).expr(q),
                        f["op"], f.get("value"))
             for f in spec["filters"]]

    by_key = dict(selected)
    ordering = []
    for s in spec["sort"]:
        expr = by_key.get(s["field"])
        if expr is None:                      # row mode: sort by an unselected field
            expr = entity.field(s["field"]).expr(q)
        ordering.append(expr.desc().nulls_last() if s["dir"] == "desc"
                        else expr.asc().nulls_last())

    stmt = select(*[e for _, e in selected]).select_from(entity.model)
    for name in q.order:                      # parents were registered before children
        stmt = stmt.outerjoin(q.aliases[name], entity.joins[name].on(q))
    stmt = entity.restrict(stmt, q)
    if where:
        stmt = stmt.where(*where)
    if grouped:
        if spec["group_by"]:
            # By output label, not by expression. psycopg 3 binds parameters
            # server-side, so a grouped expression carrying a bound value
            # (`state IN (...)`, the band CASE) would appear in SELECT and in
            # GROUP BY as two different parameter lists and PostgreSQL would
            # refuse the SELECT as "must appear in the GROUP BY clause". The
            # label is generated here (g0, g1...), never taken from the client.
            stmt = stmt.group_by(*[literal_column(f"g{i}")
                                   for i in range(len(spec["group_by"]))])
        if not ordering:
            ordering = [e.asc().nulls_last() for k, e in selected if k in spec["group_by"]]
    else:
        # A stable tie-breaker, so the same report run twice lists the same rows
        # before the cut-off rather than an arbitrary N of them.
        ordering.append(entity.model.id.asc())
    stmt = stmt.order_by(*ordering)

    effective = min(spec["limit"] or DEFAULT_LIMIT, limit)
    stmt = stmt.limit(effective + 1)
    return stmt, columns, spec, effective


def _json_safe(value: Any) -> Any:
    if isinstance(value, (dt.datetime, dt.date)):
        return value.isoformat()
    if isinstance(value, decimal.Decimal):
        value = float(value)
    if isinstance(value, float):
        return round(value, 4) if math.isfinite(value) else None
    if isinstance(value, uuid.UUID):
        return str(value)
    return value


def scope_note(scope: team_scope.TeamScope) -> str:
    if not scope.restricted:
        return "whole estate"
    if scope.is_empty:
        return "restricted to no team: this identity sees nothing"
    unowned = " plus unowned rows" if scope.include_unowned else ""
    return (f"restricted to {len(scope.team_ids)} team(s){unowned}; "
            "rows outside the reader's team scope are not included")


def run(session: Session, spec: dict, scope: team_scope.TeamScope,
        organization_id: uuid.UUID, *, user_id: uuid.UUID | None = None,
        limit: int = RUN_LIMIT, title: str | None = None) -> dict:
    """Compile, run under a statement timeout, and return the table + provenance."""
    from . import reporting   # local: reporting imports analytics, keep this module light

    stmt, columns, normalised, effective = compile(
        spec, scope, organization_id, user_id=user_id, limit=limit)
    entity = CATALOG[normalised["entity"]]
    # Transaction-local, like the tenant binding: it ends with this request's
    # transaction and cannot leak to the next user of the pooled connection.
    session.execute(text("SELECT set_config('statement_timeout', :v, true)"),
                    {"v": STATEMENT_TIMEOUT})
    try:
        raw = session.execute(stmt).all()
    except OperationalError as exc:
        if getattr(exc.orig, "sqlstate", None) != "57014":     # query_canceled
            raise
        session.rollback()
        raise ReportBuilderError(
            f"the report ran longer than {STATEMENT_TIMEOUT} and was stopped so it "
            "would not slow the database down for everybody else; narrow it with "
            "filters or a smaller limit") from None
    truncated = len(raw) > effective
    keys = [c["key"] for c in columns]
    rows = [{k: _json_safe(v) for k, v in zip(keys, r)} for r in raw[:effective]]

    provenance = reporting.provenance_for(
        session, organization_id, f"ad-hoc-{entity.key}",
        title or f"Ad-hoc report: {entity.label}", {"spec": normalised})
    provenance.update({
        "entity": entity.key,
        "scope": scope_note(scope),
        "row_count": len(rows),
        "truncated": truncated,
        "row_limit": effective,
    })
    return {"columns": columns, "rows": rows, "row_count": len(rows),
            "truncated": truncated, "limit": effective, "spec": normalised,
            "provenance": provenance}


def tabulate(result: dict) -> list[tuple[str, list[dict]]]:
    """A run result as the (sheet, rows) list the shared renderers take."""
    keys = [c["key"] for c in result["columns"]]
    rows = result["rows"] or []
    if not rows:
        # The renderers take column names from the first row; an empty result
        # still deserves a header row saying what was asked.
        return [("report", [])]
    return [("report", [{k: row.get(k) for k in keys} for row in rows])]


# ---------------------------------------------------------------------------
# Saved reports (`report_queries`)
# ---------------------------------------------------------------------------
# Ownership mirrors saved views (`services/views.py`): mine plus everything
# shared in my organization is readable; only the owner edits or deletes. The
# row grants nothing -- running it applies the reader's permissions and scope.
MAX_QUERIES_PER_USER = 100


def visible_queries(session: Session, organization_id: uuid.UUID,
                    user_id: uuid.UUID | None) -> list:
    from ..models import ReportQuery

    stmt = select(ReportQuery).where(ReportQuery.organization_id == organization_id)
    if user_id is not None:
        stmt = stmt.where(or_(ReportQuery.owner_id == user_id,
                              ReportQuery.is_shared.is_(True)))
    else:
        stmt = stmt.where(ReportQuery.is_shared.is_(True))
    return list(session.execute(stmt.order_by(ReportQuery.name)).scalars().all())


def get_visible(session: Session, organization_id: uuid.UUID, query_id: uuid.UUID,
                user_id: uuid.UUID | None):
    """The row if this caller may READ it (own or shared), else None."""
    from ..models import ReportQuery

    row = session.execute(
        select(ReportQuery).where(ReportQuery.organization_id == organization_id,
                                  ReportQuery.id == query_id)
    ).scalars().first()
    if row is None:
        return None
    if row.is_shared or (user_id is not None and row.owner_id == user_id):
        return row
    return None


def get_owned(session: Session, organization_id: uuid.UUID, query_id: uuid.UUID,
              user_id: uuid.UUID | None):
    """The row only if this caller may WRITE it."""
    row = get_visible(session, organization_id, query_id, user_id)
    if row is None or user_id is None or row.owner_id != user_id:
        return None
    return row


def _clean_name(name: Any) -> str:
    name = str(name or "").strip()
    if not name:
        raise ReportBuilderError("a saved report needs a name")
    return name[:120]


def create_query(session: Session, organization_id: uuid.UUID, owner_id: uuid.UUID, *,
                 name: str, spec: dict, description: str | None = None,
                 is_shared: bool = False):
    from ..models import ReportQuery

    name = _clean_name(name)
    normalised = validate(spec)
    owned = session.execute(
        select(func.count(ReportQuery.id)).where(
            ReportQuery.organization_id == organization_id,
            ReportQuery.owner_id == owner_id)
    ).scalar_one()
    if owned >= MAX_QUERIES_PER_USER:
        raise ReportBuilderError(f"at most {MAX_QUERIES_PER_USER} saved reports per user")
    clash = session.execute(
        select(ReportQuery.id).where(ReportQuery.organization_id == organization_id,
                                     ReportQuery.owner_id == owner_id,
                                     ReportQuery.name == name)
    ).first()
    if clash is not None:
        raise ReportBuilderError(f"you already have a saved report called {name!r}")
    row = ReportQuery(organization_id=organization_id, owner_id=owner_id, name=name,
                      description=(description or None), spec=normalised,
                      is_shared=bool(is_shared))
    session.add(row)
    session.flush()
    return row


def update_query(session: Session, row, payload: dict[str, Any]):
    from ..models import ReportQuery

    if payload.get("name") is not None:
        name = _clean_name(payload["name"])
        if name != row.name:
            clash = session.execute(
                select(ReportQuery.id).where(
                    ReportQuery.organization_id == row.organization_id,
                    ReportQuery.owner_id == row.owner_id, ReportQuery.name == name)
            ).first()
            if clash is not None:
                raise ReportBuilderError(f"you already have a saved report called {name!r}")
        row.name = name
    if "description" in payload:
        row.description = payload["description"] or None
    if payload.get("spec") is not None:
        row.spec = validate(payload["spec"])
    if payload.get("is_shared") is not None:
        row.is_shared = bool(payload["is_shared"])
    session.flush()
    return row


def query_as_dict(row, *, viewer_id: uuid.UUID | None = None) -> dict:
    """The row, plus whether its spec still matches today's catalog."""
    try:
        validate(row.spec)
        problem = None
    except ReportBuilderError as exc:
        problem = str(exc)
    return {
        "id": str(row.id),
        "name": row.name,
        "description": row.description,
        "spec": dict(row.spec or {}),
        "entity": (row.spec or {}).get("entity"),
        "is_shared": row.is_shared,
        "owner_id": str(row.owner_id),
        # A rendering hint for Edit/Delete; `get_owned` is the authorization.
        "is_mine": viewer_id is not None and row.owner_id == viewer_id,
        "valid": problem is None,
        "problem": problem,
        "created_at": row.created_at.isoformat() if row.created_at else None,
        "updated_at": row.updated_at.isoformat() if row.updated_at else None,
    }


__all__ = [
    "CATALOG", "OPERATORS", "AGGREGATES", "ReportBuilderError", "catalog", "validate",
    "compile", "run", "tabulate", "aggregate_key", "scope_note",
    "visible_queries", "get_visible", "get_owned", "create_query", "update_query",
    "query_as_dict", "MAX_QUERIES_PER_USER",
    "MAX_COLUMNS", "MAX_FILTERS", "MAX_GROUP_BY", "RUN_LIMIT", "EXPORT_LIMIT",
    "STATEMENT_TIMEOUT",
]
