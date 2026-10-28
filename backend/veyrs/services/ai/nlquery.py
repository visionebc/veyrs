"""Natural-language -> structured query translation (spec section 19).

The example the spec gives:

    "Show me all critical vulnerabilities affecting internet-facing FortiWeb
     appliances with EPSS above 0.5 and CISA KEV enabled."

The security-critical decision here is **what the model is allowed to produce**.
It does NOT produce SQL, and it does not produce SQLAlchemy. It produces a JSON
object against the closed grammar in `FIELDS` below, which is then validated
field-by-field and compiled by VEYRS code into a parameterised query that is
*additionally* scoped to the caller's tenant. A model that hallucinates a field,
an operator, a table or a tenant id yields a validation error, not a query.

There is also a deterministic parser (`heuristic_parse`) that handles the common
shapes without a model at all. It runs first; the model is only consulted when
the heuristic finds nothing useful. That ordering means the feature works in an
air-gapped install and that the cheap path is the default path.
"""
from __future__ import annotations

import dataclasses
import datetime as dt
import re
import uuid
from typing import Any, Callable

from sqlalchemy import and_, or_, select
from sqlalchemy.orm import Session

from ...models import (
    Asset, CLOSED_STATES, Finding, OPEN_STATES, Product, Vendor, Vulnerability,
)


class QueryError(ValueError):
    """The proposed query is not expressible in the grammar. Never a 500."""


@dataclasses.dataclass(frozen=True)
class FieldSpec:
    """One queryable field. `column` is resolved late to avoid import cycles."""

    kind: str  # number | string | bool | enum | date
    column: Callable[[], Any]
    operators: tuple[str, ...]
    values: tuple[str, ...] = ()
    join: str | None = None  # asset | vulnerability | product | vendor


NUMERIC_OPS = ("eq", "ne", "gt", "gte", "lt", "lte", "between")
STRING_OPS = ("eq", "ne", "contains", "startswith", "in")
BOOL_OPS = ("eq",)
ENUM_OPS = ("eq", "ne", "in")
DATE_OPS = ("gt", "gte", "lt", "lte", "within_days", "older_than_days")

SEVERITIES = ("critical", "high", "medium", "low", "informational")
RISK_LEVELS = ("critical", "high", "medium", "low", "informational")
EXPOSURES = ("internet", "partner", "internal", "isolated")
CRITICALITIES = ("critical", "high", "medium", "low")
ENVIRONMENTS = ("production", "staging", "test", "development", "dr")

#: The complete queryable surface. Anything absent here is unqueryable by AI,
#: by design -- adding a field is a code review, not a prompt change.
FIELDS: dict[str, FieldSpec] = {
    "severity": FieldSpec("enum", lambda: Finding.severity, ENUM_OPS, SEVERITIES),
    "risk_level": FieldSpec("enum", lambda: Finding.risk_level, ENUM_OPS, RISK_LEVELS),
    "risk_score": FieldSpec("number", lambda: Finding.risk_score, NUMERIC_OPS),
    "cvss_score": FieldSpec("number", lambda: Finding.cvss_score, NUMERIC_OPS),
    "epss_score": FieldSpec("number", lambda: Finding.epss_score, NUMERIC_OPS),
    "kev": FieldSpec("bool", lambda: Finding.kev, BOOL_OPS),
    "state": FieldSpec("string", lambda: Finding.state, STRING_OPS),
    "sla_breached": FieldSpec("bool", lambda: Finding.sla_breached, BOOL_OPS),
    "escalation_level": FieldSpec("number", lambda: Finding.escalation_level, NUMERIC_OPS),
    "scanner": FieldSpec("string", lambda: Finding.scanner, STRING_OPS),
    "detected_at": FieldSpec("date", lambda: Finding.detected_at, DATE_OPS),
    "title": FieldSpec("string", lambda: Finding.title, STRING_OPS),

    "cve_id": FieldSpec("string", lambda: Vulnerability.cve_id, STRING_OPS,
                        join="vulnerability"),
    "vulnerability_state": FieldSpec("string", lambda: Vulnerability.state, STRING_OPS,
                                     join="vulnerability"),

    "asset_name": FieldSpec("string", lambda: Asset.name, STRING_OPS, join="asset"),
    "hostname": FieldSpec("string", lambda: Asset.hostname, STRING_OPS, join="asset"),
    "asset_type": FieldSpec("string", lambda: Asset.asset_type, STRING_OPS, join="asset"),
    "exposure": FieldSpec("enum", lambda: Asset.exposure, ENUM_OPS, EXPOSURES, join="asset"),
    "criticality": FieldSpec("enum", lambda: Asset.criticality, ENUM_OPS, CRITICALITIES,
                             join="asset"),
    "environment": FieldSpec("enum", lambda: Asset.environment, ENUM_OPS, ENVIRONMENTS,
                             join="asset"),
    "data_classification": FieldSpec("string", lambda: Asset.data_classification, STRING_OPS,
                                     join="asset"),
    "operating_system": FieldSpec("string", lambda: Asset.operating_system, STRING_OPS,
                                  join="asset"),
    "location": FieldSpec("string", lambda: Asset.location, STRING_OPS, join="asset"),

    "product": FieldSpec("string", lambda: Product.name, STRING_OPS, join="product"),
    "vendor": FieldSpec("string", lambda: Vendor.name, STRING_OPS, join="vendor"),
}

SORTABLE = {
    "risk_score": lambda: Finding.risk_score,
    "cvss_score": lambda: Finding.cvss_score,
    "epss_score": lambda: Finding.epss_score,
    "detected_at": lambda: Finding.detected_at,
    "sla_due_at": lambda: Finding.sla_due_at,
}

MAX_FILTERS = 12
MAX_LIMIT = 200


@dataclasses.dataclass
class StructuredQuery:
    entity: str = "finding"
    filters: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    combine: str = "and"
    sort: str = "risk_score"
    order: str = "desc"
    limit: int = 50
    #: Human-readable restatement, shown to the analyst BEFORE results so they
    #: can see what the machine understood.
    explanation: str = ""

    def as_dict(self) -> dict[str, Any]:
        return dataclasses.asdict(self)


# ---------------------------------------------------------------------------
# Validation
# ---------------------------------------------------------------------------
def validate(payload: dict[str, Any]) -> StructuredQuery:
    """Turn an untrusted dict into a StructuredQuery or raise QueryError."""
    if not isinstance(payload, dict):
        raise QueryError("query must be an object")

    entity = str(payload.get("entity") or "finding").lower()
    if entity != "finding":
        raise QueryError(f"unsupported entity {entity!r}; only 'finding' is queryable")

    raw_filters = payload.get("filters") or []
    if not isinstance(raw_filters, list):
        raise QueryError("filters must be a list")
    if len(raw_filters) > MAX_FILTERS:
        raise QueryError(f"too many filters (max {MAX_FILTERS})")

    filters: list[dict[str, Any]] = []
    for item in raw_filters:
        filters.append(_validate_filter(item))

    combine = str(payload.get("combine") or "and").lower()
    if combine not in ("and", "or"):
        raise QueryError("combine must be 'and' or 'or'")

    sort = str(payload.get("sort") or "risk_score")
    if sort not in SORTABLE:
        raise QueryError(f"cannot sort by {sort!r}")
    order = str(payload.get("order") or "desc").lower()
    if order not in ("asc", "desc"):
        raise QueryError("order must be 'asc' or 'desc'")

    try:
        limit = int(payload.get("limit") or 50)
    except (TypeError, ValueError):
        raise QueryError("limit must be an integer") from None
    limit = max(1, min(limit, MAX_LIMIT))

    return StructuredQuery(
        entity=entity, filters=filters, combine=combine, sort=sort, order=order,
        limit=limit, explanation=str(payload.get("explanation") or "")[:500],
    )


def _validate_filter(item: Any) -> dict[str, Any]:
    if not isinstance(item, dict):
        raise QueryError("each filter must be an object")
    field = str(item.get("field") or "")
    spec = FIELDS.get(field)
    if spec is None:
        raise QueryError(f"unknown field {field!r}")
    operator = str(item.get("op") or item.get("operator") or "eq").lower()
    if operator not in spec.operators:
        raise QueryError(f"operator {operator!r} is not valid for field {field!r}")
    value = item.get("value")

    if spec.kind == "number":
        if operator == "between":
            if not isinstance(value, (list, tuple)) or len(value) != 2:
                raise QueryError(f"{field}: 'between' needs exactly two values")
            value = [_as_float(field, value[0]), _as_float(field, value[1])]
        else:
            value = _as_float(field, value)
    elif spec.kind == "bool":
        if isinstance(value, str):
            value = value.strip().lower() in ("true", "yes", "1", "enabled")
        value = bool(value)
    elif spec.kind == "date":
        if operator in ("within_days", "older_than_days"):
            value = int(_as_float(field, value))
        else:
            value = _as_date(field, value)
    elif spec.kind == "enum":
        values = [value] if not isinstance(value, list) else value
        lowered = [str(v).lower() for v in values]
        bad = [v for v in lowered if v not in spec.values]
        if bad:
            raise QueryError(
                f"{field}: {bad!r} not in allowed values {list(spec.values)!r}"
            )
        value = lowered if operator == "in" else lowered[0]
    else:  # string
        if operator == "in":
            if not isinstance(value, list) or not value:
                raise QueryError(f"{field}: 'in' needs a non-empty list")
            value = [str(v)[:200] for v in value]
        else:
            value = str(value)[:200]
    return {"field": field, "op": operator, "value": value}


def _as_float(field: str, value: Any) -> float:
    try:
        return float(value)
    except (TypeError, ValueError):
        raise QueryError(f"{field}: {value!r} is not a number") from None


def _as_date(field: str, value: Any) -> dt.datetime:
    if isinstance(value, dt.datetime):
        return value
    try:
        parsed = dt.datetime.fromisoformat(str(value).replace("Z", "+00:00"))
    except ValueError:
        raise QueryError(f"{field}: {value!r} is not an ISO date") from None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=dt.timezone.utc)
    return parsed


# ---------------------------------------------------------------------------
# Compilation
# ---------------------------------------------------------------------------
def compile_query(query: StructuredQuery, organization_id: uuid.UUID):
    """Build the SELECT. Tenant scoping is added HERE, not taken from input.

    Even a perfectly-crafted malicious filter set cannot reach another tenant:
    `Finding.organization_id == organization_id` is appended unconditionally and
    PostgreSQL RLS is a second, independent barrier underneath it.
    """
    from ...models import AssetProduct  # local import: cycle-free

    statement = select(Finding).where(Finding.organization_id == organization_id)

    needed = {FIELDS[f["field"]].join for f in query.filters} - {None}
    if "asset" in needed:
        statement = statement.join(Asset, Finding.asset_id == Asset.id)
    if "vulnerability" in needed:
        statement = statement.join(
            Vulnerability, Finding.vulnerability_id == Vulnerability.id
        )
    if needed & {"product", "vendor"}:
        statement = statement.join(
            AssetProduct, Finding.asset_product_id == AssetProduct.id
        ).join(Product, AssetProduct.product_id == Product.id)
        if "vendor" in needed:
            statement = statement.join(Vendor, Product.vendor_id == Vendor.id)

    clauses = [_clause(f) for f in query.filters]
    if clauses:
        statement = statement.where(
            and_(*clauses) if query.combine == "and" else or_(*clauses)
        )

    column = SORTABLE[query.sort]()
    statement = statement.order_by(column.desc().nullslast()
                                   if query.order == "desc" else column.asc().nullsfirst())
    return statement.limit(query.limit)


def _clause(item: dict[str, Any]):
    spec = FIELDS[item["field"]]
    column = spec.column()
    operator, value = item["op"], item["value"]

    if operator == "eq":
        return column == value
    if operator == "ne":
        return column != value
    if operator == "gt":
        return column > value
    if operator == "gte":
        return column >= value
    if operator == "lt":
        return column < value
    if operator == "lte":
        return column <= value
    if operator == "between":
        return column.between(value[0], value[1])
    if operator == "in":
        return column.in_(value)
    if operator == "contains":
        return column.ilike(f"%{value}%")
    if operator == "startswith":
        return column.ilike(f"{value}%")
    if operator == "within_days":
        return column >= dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=value)
    if operator == "older_than_days":
        return column <= dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=value)
    raise QueryError(f"unhandled operator {operator!r}")  # pragma: no cover


def run(session: Session, query: StructuredQuery, organization_id: uuid.UUID) -> list[Finding]:
    return list(session.execute(compile_query(query, organization_id)).scalars().unique().all())


# ---------------------------------------------------------------------------
# Deterministic parsing (tried before any model)
# ---------------------------------------------------------------------------
_NUM = r"(\d+(?:\.\d+)?)"

_HEURISTICS: tuple[tuple[re.Pattern[str], Callable[[re.Match[str]], dict]], ...] = (
    (re.compile(r"(?i)\bepss\b[^.\d]{0,30}?(?:above|over|greater than|>|>=|at least)\s*" + _NUM),
     lambda m: {"field": "epss_score", "op": "gte", "value": float(m.group(1))}),
    (re.compile(r"(?i)\bepss\b[^.\d]{0,30}?(?:below|under|less than|<|<=)\s*" + _NUM),
     lambda m: {"field": "epss_score", "op": "lte", "value": float(m.group(1))}),
    (re.compile(r"(?i)\bcvss\b[^.\d]{0,30}?(?:above|over|greater than|>|>=|at least)\s*" + _NUM),
     lambda m: {"field": "cvss_score", "op": "gte", "value": float(m.group(1))}),
    (re.compile(r"(?i)\bcvss\b[^.\d]{0,30}?(?:below|under|less than|<|<=)\s*" + _NUM),
     lambda m: {"field": "cvss_score", "op": "lte", "value": float(m.group(1))}),
    (re.compile(r"(?i)\b(?:cisa\s+)?kev\b|known.exploited"),
     lambda m: {"field": "kev", "op": "eq", "value": True}),
    (re.compile(r"(?i)\binternet[- ]?(?:facing|exposed)\b|\bexposed to the internet\b"),
     lambda m: {"field": "exposure", "op": "eq", "value": "internet"}),
    (re.compile(r"(?i)\bsla\b[^.\n]{0,20}\b(?:breach(?:ed|es)?|overdue|violated)\b"),
     lambda m: {"field": "sla_breached", "op": "eq", "value": True}),
    (re.compile(r"(?i)\b(critical|high|medium|low)\s+(?:severity|vulnerabilit|finding|risk)"),
     lambda m: {"field": "severity", "op": "eq", "value": m.group(1).lower()}),
    (re.compile(r"(?i)\bseverity\s+(?:is\s+)?(critical|high|medium|low)\b"),
     lambda m: {"field": "severity", "op": "eq", "value": m.group(1).lower()}),
    (re.compile(r"(?i)\b(production|staging|development|test)\b\s*(?:environment|systems?)?"),
     lambda m: {"field": "environment", "op": "eq", "value": m.group(1).lower()}),
    (re.compile(r"(?i)\b(CVE-\d{4}-\d{4,7})\b"),
     lambda m: {"field": "cve_id", "op": "eq", "value": m.group(1).upper()}),
    (re.compile(r"(?i)\bin the last\s+(\d+)\s+days?\b"),
     lambda m: {"field": "detected_at", "op": "within_days", "value": int(m.group(1))}),
    (re.compile(r"(?i)\bolder than\s+(\d+)\s+days?\b"),
     lambda m: {"field": "detected_at", "op": "older_than_days", "value": int(m.group(1))}),
)


def heuristic_parse(question: str, *, known_products: list[str] | None = None) -> StructuredQuery | None:
    """Rule-based translation. Returns None when it understood nothing.

    Product names are matched against the tenant's OWN catalogue rather than a
    hardcoded list, so "FortiWeb" resolves only for a tenant that actually has
    FortiWeb -- and a tenant cannot probe another tenant's inventory by naming it.
    """
    text = question or ""
    filters: list[dict[str, Any]] = []
    seen: set[str] = set()

    for pattern, build in _HEURISTICS:
        match = pattern.search(text)
        if not match:
            continue
        candidate = build(match)
        if candidate["field"] in seen:
            continue
        seen.add(candidate["field"])
        filters.append(candidate)

    for name in known_products or []:
        if name and len(name) >= 3 and re.search(rf"(?i)\b{re.escape(name)}\b", text):
            filters.append({"field": "product", "op": "eq", "value": name})
            break

    if re.search(r"(?i)\b(?:open|unresolved|outstanding|active)\b", text):
        filters.append({"field": "state", "op": "in", "value": list(OPEN_STATES)})
    elif re.search(r"(?i)\b(?:closed|resolved|remediated|fixed)\b", text):
        filters.append({"field": "state", "op": "in", "value": list(CLOSED_STATES)})

    if not filters:
        return None
    query = validate({"entity": "finding", "filters": filters[:MAX_FILTERS]})
    query.explanation = describe(query)
    return query


def describe(query: StructuredQuery) -> str:
    """Restate the structured query in English, for the 'I understood…' line."""
    if not query.filters:
        return "All findings."
    words = {
        "eq": "is", "ne": "is not", "gt": ">", "gte": ">=", "lt": "<", "lte": "<=",
        "in": "is one of", "contains": "contains", "startswith": "starts with",
        "between": "is between", "within_days": "detected within the last",
        "older_than_days": "older than",
    }
    parts = []
    for item in query.filters:
        value = item["value"]
        if isinstance(value, list):
            value = ", ".join(str(v) for v in value)
        suffix = " days" if item["op"].endswith("_days") else ""
        parts.append(f"{item['field']} {words.get(item['op'], item['op'])} {value}{suffix}")
    joiner = " AND " if query.combine == "and" else " OR "
    return (f"Findings where {joiner.join(parts)}, "
            f"sorted by {query.sort} {query.order}, limit {query.limit}.")


#: Prompt used when the heuristic is not enough. The grammar is inlined so the
#: model has no excuse to invent fields, and the reply must be JSON only.
TRANSLATION_PROMPT = """Translate the analyst's question into a VEYRS query object.

Reply with ONE JSON object and nothing else. Schema:
{{"entity":"finding","combine":"and"|"or","sort":<sortable>,"order":"asc"|"desc",
  "limit":<1-200>,"explanation":"<one sentence>",
  "filters":[{{"field":<field>,"op":<operator>,"value":<value>}}]}}

Allowed fields and operators:
{grammar}

Sortable: {sortable}

Rules:
- Use ONLY the fields listed. If the question needs a field that is not listed,
  omit that condition and say so in "explanation".
- Never invent CVE identifiers, product names or values.
- Do not include organization, tenant or user identifiers; scoping is automatic.

Question: {question}"""


def grammar_summary() -> str:
    lines = []
    for name, spec in FIELDS.items():
        allowed = f" values={list(spec.values)}" if spec.values else ""
        lines.append(f"- {name} ({spec.kind}) ops={list(spec.operators)}{allowed}")
    return "\n".join(lines)


def build_translation_prompt(question: str) -> str:
    return TRANSLATION_PROMPT.format(
        grammar=grammar_summary(),
        sortable=list(SORTABLE),
        question=question.strip()[:1000],
    )
