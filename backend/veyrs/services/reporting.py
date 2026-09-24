"""Report generation and export (spec section 29).

A report is a `ReportSpec`: a slug, the permission it needs, a builder that
returns structured data, and a table extractor that flattens that data for CSV
and Excel. Adding a report is one registry entry, and it inherits authorization,
every export format and the provenance header for free.

Provenance is mandatory on every export. A PDF that circulates for six months
without saying which organization, which moment and which VEYRS version produced
it is worse than no PDF -- people act on stale numbers believing they are
current.

Renderers degrade rather than fail: xlsx and pdf need optional libraries, and an
install without them still gets JSON and CSV, with a clear error naming the
missing package instead of a 500.
"""
from __future__ import annotations

import csv
import dataclasses
import datetime as dt
import io
import json
import uuid
from typing import Any, Callable

from sqlalchemy import select
from sqlalchemy.orm import Session

from ..config import settings
from ..models import (
    Asset, ComplianceFramework, Finding, OPEN_STATES, Organization, Ticket,
)
from . import analytics, compliance as compliance_service

FORMATS = ("json", "csv", "xlsx", "pdf")


class ReportError(RuntimeError):
    """A renderer could not run. Always names the reason."""


@dataclasses.dataclass(frozen=True)
class ReportSpec:
    slug: str
    title: str
    description: str
    permission: str
    build: Callable[..., dict]
    #: data -> [(sheet/table name, [row dicts])]
    tabulate: Callable[[dict], list[tuple[str, list[dict]]]]


def provenance(session: Session, org_id: uuid.UUID, spec: ReportSpec,
               parameters: dict | None = None) -> dict:
    organization = session.get(Organization, org_id)
    return {
        "report": spec.slug,
        "title": spec.title,
        "organization": organization.name if organization else str(org_id),
        "organization_slug": organization.slug if organization else None,
        "generated_at": dt.datetime.now(dt.timezone.utc).isoformat(),
        "generated_by": f"{settings.app_name} {settings.version}",
        "parameters": parameters or {},
        "note": (
            "Figures are a snapshot of the moment above. VEYRS data changes "
            "continuously; re-generate before relying on these numbers."
        ),
    }


# ---------------------------------------------------------------------------
# Builders
# ---------------------------------------------------------------------------
def _executive(session: Session, org_id: uuid.UUID, **kwargs) -> dict:
    return analytics.executive_dashboard(session, org_id, days=kwargs.get("days", 90))


def _technical(session: Session, org_id: uuid.UUID, **kwargs) -> dict:
    return analytics.technical_dashboard(session, org_id)


def _sla(session: Session, org_id: uuid.UUID, **kwargs) -> dict:
    return analytics.sla_report(session, org_id, days=kwargs.get("days", 90))


def _vulnerability_register(session: Session, org_id: uuid.UUID, **kwargs) -> dict:
    limit = int(kwargs.get("limit", 1000))
    rows = session.execute(
        select(Finding, Asset)
        .join(Asset, Finding.asset_id == Asset.id)
        .where(Finding.organization_id == org_id,
               Finding.state.in_(list(OPEN_STATES)))
        .order_by(Finding.risk_score.desc().nullslast())
        .limit(limit)
    ).all()
    findings = [
        {
            "finding_id": str(finding.id),
            "title": finding.title,
            "state": finding.state,
            "severity": finding.severity,
            "risk_score": finding.risk_score,
            "risk_level": finding.risk_level,
            "cvss_score": finding.cvss_score,
            "cvss_vector": finding.cvss_vector,
            "epss_score": finding.epss_score,
            "kev": finding.kev,
            "asset": asset.name,
            "hostname": asset.hostname,
            "criticality": asset.criticality,
            "exposure": asset.exposure,
            "environment": asset.environment,
            "sla_due_at": finding.sla_due_at.isoformat() if finding.sla_due_at else None,
            "sla_breached": finding.sla_breached,
            "detected_at": finding.detected_at.isoformat() if finding.detected_at else None,
            "scanner": finding.scanner,
        }
        for finding, asset in rows
    ]
    return {"count": len(findings), "truncated_at": limit if len(findings) == limit
            else None, "findings": findings}


def _asset_register(session: Session, org_id: uuid.UUID, **kwargs) -> dict:
    assets = session.execute(
        select(Asset).where(Asset.organization_id == org_id, Asset.deleted_at.is_(None))
        .order_by(Asset.name)
    ).scalars().all()
    rows = []
    for asset in assets:
        open_count = int(session.execute(
            select(analytics.func.count(Finding.id)).where(
                Finding.asset_id == asset.id,
                Finding.state.in_(list(OPEN_STATES)))
        ).scalar_one() or 0)
        max_risk = session.execute(
            select(analytics.func.max(Finding.risk_score)).where(
                Finding.asset_id == asset.id,
                Finding.state.in_(list(OPEN_STATES)))
        ).scalar_one()
        rows.append({
            "asset_id": str(asset.id), "name": asset.name, "hostname": asset.hostname,
            "type": asset.asset_type, "criticality": asset.criticality,
            "exposure": asset.exposure, "environment": asset.environment,
            "data_classification": asset.data_classification,
            "operating_system": asset.operating_system,
            "open_findings": open_count, "max_risk_score": max_risk,
        })
    return {"count": len(rows), "assets": rows}


def _team_performance(session: Session, org_id: uuid.UUID, **kwargs) -> dict:
    return {
        "teams": analytics.top_teams(session, org_id, limit=100),
        "mttr": analytics.mttr(session, org_id, days=kwargs.get("days", 90)),
    }


def _compliance(session: Session, org_id: uuid.UUID, **kwargs) -> dict:
    framework_id = kwargs.get("framework_id")
    if framework_id is None:
        raise ReportError("compliance report requires a framework_id parameter")
    framework = session.get(ComplianceFramework, uuid.UUID(str(framework_id)))
    if framework is None:
        raise ReportError("framework not found")
    if framework.organization_id not in (None, org_id):
        raise ReportError("framework not found")
    return compliance_service.coverage(session, org_id, framework)


def _ticket_report(session: Session, org_id: uuid.UUID, **kwargs) -> dict:
    tickets = session.execute(
        select(Ticket).where(Ticket.organization_id == org_id)
        .order_by(Ticket.created_at.desc()).limit(int(kwargs.get("limit", 1000)))
    ).scalars().all()
    return {
        "by_type_and_state": analytics.ticket_metrics(session, org_id),
        "tickets": [
            {"reference": t.reference, "type": t.ticket_type, "state": t.state,
             "priority": t.priority, "title": t.title,
             "due_at": t.due_at.isoformat() if t.due_at else None,
             "created_at": t.created_at.isoformat()}
            for t in tickets
        ],
    }


# ---------------------------------------------------------------------------
# Tabulators
# ---------------------------------------------------------------------------
def _tab_executive(data: dict) -> list[tuple[str, list[dict]]]:
    return [
        ("summary", [{
            "open_findings": data["totals"]["open_findings"],
            "assets": data["totals"]["assets"],
            "assets_with_open_findings": data["totals"]["assets_with_open_findings"],
            "average_risk_score": data.get("average_risk_score"),
            "kev_open": data["exploitation"]["kev_open"],
            "internet_facing_open": data["exploitation"]["internet_facing_open"],
            "sla_breached_open": data["sla"]["breached_open"],
            "mttr_hours": data["mttr"]["hours"],
            "mttr_sample": data["mttr"]["sample"],
            "mttr_reliable": data["mttr"]["reliable"],
        }]),
        ("by_severity", [{"severity": k, "open_findings": v}
                         for k, v in data["by_severity"].items()]),
        ("top_products", data["top_products"]),
        ("top_assets", data["top_assets"]),
        ("top_teams", data["top_teams"]),
        ("by_environment", data["by_environment"]),
        ("finding_trend", data["finding_trend"]),
    ]


def _tab_technical(data: dict) -> list[tuple[str, list[dict]]]:
    return [
        ("cvss_distribution", [{"band": k, "findings": v}
                               for k, v in data["cvss_distribution"].items()]),
        ("epss_distribution", [{"band": k, "findings": v}
                               for k, v in data["epss_distribution"].items()]),
        ("top_cwe", data["top_cwe"]),
        ("state_breakdown", [{"state": k, "findings": v}
                             for k, v in data["state_breakdown"].items()]),
        ("scanner_breakdown", data["scanner_breakdown"]),
    ]


def _tab_sla(data: dict) -> list[tuple[str, list[dict]]]:
    return [
        ("summary", [{k: v for k, v in data.items() if not isinstance(v, (list, dict))}]),
        ("by_severity", data["by_severity"]),
    ]


def _tab_findings(data: dict) -> list[tuple[str, list[dict]]]:
    return [("findings", data["findings"])]


def _tab_assets(data: dict) -> list[tuple[str, list[dict]]]:
    return [("assets", data["assets"])]


def _tab_teams(data: dict) -> list[tuple[str, list[dict]]]:
    return [
        ("teams", data["teams"]),
        ("mttr_by_severity", [{"severity": k, **v}
                              for k, v in data["mttr"]["by_severity"].items()]),
    ]


def _tab_compliance(data: dict) -> list[tuple[str, list[dict]]]:
    return [
        ("framework", [data["framework"]]),
        ("counts", [{"status": k, "controls": v} for k, v in data["counts"].items()]),
        ("controls", [{k: v for k, v in row.items() if k != "automated_result"}
                      for row in data["controls"]]),
    ]


def _tab_tickets(data: dict) -> list[tuple[str, list[dict]]]:
    return [("tickets", data["tickets"])]


REPORTS: dict[str, ReportSpec] = {
    spec.slug: spec for spec in (
        ReportSpec("executive", "Executive Risk Summary",
                   "Board-level view: risk posture, exploitation pressure, SLA "
                   "health and trend.", "report:read", _executive, _tab_executive),
        ReportSpec("technical", "Technical Vulnerability Report",
                   "CVSS/EPSS distributions, CWE rollup, exploitability and "
                   "scanner coverage.", "report:read", _technical, _tab_technical),
        ReportSpec("sla", "SLA Compliance Report",
                   "SLA attainment by severity, breaches and imminent breaches.",
                   "report:read", _sla, _tab_sla),
        ReportSpec("vulnerability-register", "Vulnerability Register",
                   "Every open finding with its asset context and risk scores.",
                   "finding:read", _vulnerability_register, _tab_findings),
        ReportSpec("asset-register", "Asset Register",
                   "Inventory with business context and current risk exposure.",
                   "asset:read", _asset_register, _tab_assets),
        ReportSpec("team-performance", "Team Performance",
                   "Queue size, SLA attainment and MTTR per owning team.",
                   "report:read", _team_performance, _tab_teams),
        ReportSpec("compliance", "Compliance Coverage",
                   "Control-by-control status and evidence for one framework.",
                   "compliance:read", _compliance, _tab_compliance),
        ReportSpec("tickets", "Ticket Report",
                   "ITSM records by type and state.", "ticket:read",
                   _ticket_report, _tab_tickets),
    )
}


def build(session: Session, org_id: uuid.UUID, slug: str, **parameters) -> dict:
    spec = REPORTS.get(slug)
    if spec is None:
        raise ReportError(f"unknown report {slug!r}; known: {sorted(REPORTS)}")
    data = spec.build(session, org_id, **parameters)
    return {"provenance": provenance(session, org_id, spec, parameters), "data": data}


# ---------------------------------------------------------------------------
# Renderers
# ---------------------------------------------------------------------------
def render(session: Session, org_id: uuid.UUID, slug: str, fmt: str,
           **parameters) -> tuple[bytes, str, str]:
    """Returns (payload, content_type, filename)."""
    if fmt not in FORMATS:
        raise ReportError(f"unknown format {fmt!r}; known: {list(FORMATS)}")
    spec = REPORTS.get(slug)
    if spec is None:
        raise ReportError(f"unknown report {slug!r}; known: {sorted(REPORTS)}")

    report = build(session, org_id, slug, **parameters)
    stamp = dt.datetime.now(dt.timezone.utc).strftime("%Y%m%d-%H%M%S")
    filename = f"veyrs-{slug}-{stamp}.{fmt}"

    if fmt == "json":
        payload = json.dumps(report, indent=2, default=str).encode()
        return payload, "application/json", filename
    tables = spec.tabulate(report["data"])
    if fmt == "csv":
        return _render_csv(report, tables), "text/csv", filename
    if fmt == "xlsx":
        return (_render_xlsx(report, tables),
                "application/vnd.openxmlformats-officedocument.spreadsheetml.sheet",
                filename)
    return _render_pdf(report, tables, spec), "application/pdf", filename


def _render_csv(report: dict, tables: list[tuple[str, list[dict]]]) -> bytes:
    """One file, tables separated by a header line.

    A zip of CSVs would be tidier but far less usable: people open these in a
    spreadsheet and expect one file.
    """
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    for key, value in report["provenance"].items():
        if key != "parameters":
            writer.writerow([f"# {key}", value])
    for name, rows in tables:
        writer.writerow([])
        writer.writerow([f"## {name}"])
        if not rows:
            writer.writerow(["(no rows)"])
            continue
        columns = list(rows[0].keys())
        writer.writerow(columns)
        for row in rows:
            writer.writerow([_flatten(row.get(column)) for column in columns])
    return buffer.getvalue().encode("utf-8-sig")


def _flatten(value: Any) -> Any:
    if isinstance(value, (dict, list)):
        return json.dumps(value, default=str)
    return value


def _render_xlsx(report: dict, tables: list[tuple[str, list[dict]]]) -> bytes:
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ReportError("xlsx export requires the 'openpyxl' package") from exc

    workbook = Workbook()
    sheet = workbook.active
    sheet.title = "provenance"
    sheet.append(["field", "value"])
    sheet["A1"].font = sheet["B1"].font = Font(bold=True)
    for key, value in report["provenance"].items():
        sheet.append([key, _flatten(value)])

    for name, rows in tables:
        # Excel sheet names are capped at 31 chars and reject several symbols.
        safe = "".join(c for c in name if c not in "[]:*?/\\")[:31] or "sheet"
        target = workbook.create_sheet(safe)
        if not rows:
            target.append(["(no rows)"])
            continue
        columns = list(rows[0].keys())
        target.append(columns)
        for cell in target[1]:
            cell.font = Font(bold=True)
        for row in rows:
            target.append([_flatten(row.get(column)) for column in columns])
        target.freeze_panes = "A2"

    buffer = io.BytesIO()
    workbook.save(buffer)
    return buffer.getvalue()


def _render_pdf(report: dict, tables: list[tuple[str, list[dict]]],
                spec: ReportSpec) -> bytes:
    try:
        from reportlab.lib import colors
        from reportlab.lib.pagesizes import A4, landscape
        from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
        from reportlab.lib.units import mm
        from reportlab.platypus import (
            PageBreak, Paragraph, SimpleDocTemplate, Spacer, Table, TableStyle,
        )
    except ImportError as exc:  # pragma: no cover - optional dependency
        raise ReportError("pdf export requires the 'reportlab' package") from exc

    # VEYRS brand palette (docs/BRAND.md): navy headers, blue accents, and
    # semantic severity colours that are NOT the brand blue.
    deep_navy = colors.HexColor("#001030")
    veyrs_blue = colors.HexColor("#0064D8")
    border = colors.HexColor("#D9E0EA")
    secondary = colors.HexColor("#526070")

    buffer = io.BytesIO()
    document = SimpleDocTemplate(
        buffer, pagesize=landscape(A4),
        leftMargin=14 * mm, rightMargin=14 * mm,
        topMargin=14 * mm, bottomMargin=14 * mm,
        title=f"VEYRS - {spec.title}", author="VEYRS",
    )
    styles = getSampleStyleSheet()
    title_style = ParagraphStyle("VeyrsTitle", parent=styles["Title"],
                                 textColor=deep_navy, fontSize=20, spaceAfter=2)
    tagline_style = ParagraphStyle("VeyrsTagline", parent=styles["Normal"],
                                   textColor=veyrs_blue, fontSize=9, spaceAfter=8)
    meta_style = ParagraphStyle("VeyrsMeta", parent=styles["Normal"],
                                textColor=secondary, fontSize=8)
    heading_style = ParagraphStyle("VeyrsHeading", parent=styles["Heading2"],
                                   textColor=deep_navy, fontSize=12, spaceBefore=10)

    story: list[Any] = [
        Paragraph(spec.title, title_style),
        Paragraph("VEYRS &mdash; Unified Cybersecurity Risk Management", tagline_style),
    ]
    for key, value in report["provenance"].items():
        if key in ("report", "title", "parameters"):
            continue
        story.append(Paragraph(f"<b>{key.replace('_', ' ')}:</b> {value}", meta_style))
    story.append(Spacer(1, 6 * mm))

    for name, rows in tables:
        story.append(Paragraph(name.replace("_", " ").title(), heading_style))
        if not rows:
            story.append(Paragraph("No rows.", meta_style))
            continue
        columns = list(rows[0].keys())
        # A landscape A4 stops being readable past ~10 columns; the remainder
        # is available in the CSV/XLSX export rather than rendered unreadably.
        shown = columns[:10]
        data = [[c.replace("_", " ") for c in shown]]
        for row in rows[:60]:
            data.append([str(_flatten(row.get(c)))[:60] for c in shown])
        table = Table(data, repeatRows=1)
        table.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (-1, 0), deep_navy),
            ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
            ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 7),
            ("GRID", (0, 0), (-1, -1), 0.25, border),
            ("VALIGN", (0, 0), (-1, -1), "TOP"),
            ("ROWBACKGROUNDS", (0, 1), (-1, -1),
             [colors.white, colors.HexColor("#F5F7FA")]),
        ]))
        story.append(table)
        if len(rows) > 60 or len(columns) > 10:
            story.append(Paragraph(
                f"Showing {min(len(rows), 60)} of {len(rows)} rows and "
                f"{len(shown)} of {len(columns)} columns. "
                "Export as XLSX or CSV for the complete data.", meta_style))
        story.append(Spacer(1, 4 * mm))

    document.build(story)
    return buffer.getvalue()


def catalogue() -> list[dict]:
    return [
        {"slug": spec.slug, "title": spec.title, "description": spec.description,
         "permission": spec.permission, "formats": list(FORMATS)}
        for spec in REPORTS.values()
    ]
