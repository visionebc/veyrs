"""The AI features themselves (spec section 19), all grounded in VEYRS data.

Every capability follows the same shape:

    gather facts from the database (already tenant- and permission-scoped)
        -> render them into a `VEYRS FACTS:` block
        -> ask the gateway to narrate/structure them
        -> return BOTH the computed facts and the narrative

That ordering is the anti-hallucination design: the numbers an analyst acts on
(CVSS, EPSS, KEV, risk score, affected asset count) are always computed by
VEYRS. The model contributes prose and prioritisation language. If the model is
unavailable the facts are returned unchanged and the caller is told the answer
is degraded -- the feature never fabricates and never disappears.
"""
from __future__ import annotations

import uuid
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ...models import (
    Asset, AssetProduct, Cve, EpssScore, Finding, KevEntry, Product, Team, ThreatArticle,
    Vendor, Vulnerability,
)
from ...models.ai import AiCapability
from . import nlquery
from .gateway import AiRequest, AiResult, invoke


def _line(label: str, value: Any) -> str:
    return f"- {label}: {value}"


def _fmt(value: Any, suffix: str = "") -> str:
    if value is None:
        return "not available"
    if isinstance(value, float):
        return f"{value:g}{suffix}"
    return f"{value}{suffix}"


# ---------------------------------------------------------------------------
# CVE analysis
# ---------------------------------------------------------------------------
def cve_facts(session: Session, cve_id: str, organization_id: uuid.UUID) -> dict[str, Any]:
    """Everything VEYRS knows about a CVE, including *this tenant's* exposure."""
    # `Cve.id` IS the identifier ("CVE-2021-44228"); there is no separate
    # cve_id column on this table -- only on the rows that reference it.
    cve = session.get(Cve, cve_id.upper())
    if cve is None:
        return {"cve_id": cve_id.upper(), "known": False}

    epss = session.get(EpssScore, cve.id)
    kev = session.get(KevEntry, cve.id)

    findings = list(session.execute(
        select(Finding)
        .join(Vulnerability, Finding.vulnerability_id == Vulnerability.id)
        .where(Finding.organization_id == organization_id,
               Vulnerability.cve_id == cve.id)
    ).scalars().unique().all())

    asset_ids = {f.asset_id for f in findings}
    assets = list(session.execute(
        select(Asset).where(Asset.id.in_(asset_ids))
    ).scalars().all()) if asset_ids else []

    # Every CVSS revision is kept side by side on the row; report the newest
    # available one as the headline and keep the others for the breakdown.
    if cve.cvss4_score is not None:
        version, score, vector = "4.0", cve.cvss4_score, cve.cvss4_vector
    elif cve.cvss3_base_score is not None:
        version = cve.cvss3_version or "3.1"
        score, vector = cve.cvss3_base_score, cve.cvss3_vector
    else:
        version, score, vector = "2.0", cve.cvss2_base_score, cve.cvss2_vector

    return {
        "cve_id": cve.id,
        "known": True,
        "title": cve.title,
        "description": (cve.description or "")[:2000],
        "published": cve.published_at.isoformat() if cve.published_at else None,
        "modified": cve.modified_at.isoformat() if cve.modified_at else None,
        "cvss_version": version,
        "cvss_score": score,
        "cvss_vector": vector,
        "cvss_all": {
            "v2": {"score": cve.cvss2_base_score, "vector": cve.cvss2_vector},
            "v3": {"score": cve.cvss3_base_score, "vector": cve.cvss3_vector,
                   "severity": cve.cvss3_severity},
            "v4": {"score": cve.cvss4_score, "vector": cve.cvss4_vector,
                   "severity": cve.cvss4_severity},
        },
        "exploit_known": cve.exploit_known,
        "exploit_maturity": cve.exploit_maturity,
        "fixed_versions": list(cve.fixed_versions or []),
        "cwe_ids": list(cve.cwe_ids or []),
        "epss_score": epss.score if epss else None,
        "epss_percentile": epss.percentile if epss else None,
        "kev": kev is not None,
        "kev_due_date": kev.due_date.isoformat() if kev and kev.due_date else None,
        "kev_required_action": kev.required_action if kev else None,
        "affected_assets": len(assets),
        "internet_facing_assets": sum(1 for a in assets if a.exposure == "internet"),
        "critical_assets": sum(1 for a in assets if a.criticality == "critical"),
        "open_findings": sum(1 for f in findings if f.closed_at is None),
        "max_risk_score": max((f.risk_score or 0) for f in findings) if findings else None,
    }


def _render_cve_facts(facts: dict[str, Any]) -> str:
    if not facts.get("known"):
        return f"{facts['cve_id']} is not present in the VEYRS CVE database."
    return "\n".join([
        _line("CVE", facts["cve_id"]),
        _line("Title", facts.get("title") or "-"),
        _line("Published", _fmt(facts.get("published"))),
        _line("CVSS", f"{_fmt(facts.get('cvss_score'))} "
                      f"(v{facts.get('cvss_version') or '?'}) {facts.get('cvss_vector') or ''}"),
        _line("CWE", ", ".join(facts.get("cwe_ids") or []) or "not mapped"),
        _line("Exploit known", "YES" if facts.get("exploit_known") else "no"),
        _line("Fixed versions", ", ".join(facts.get("fixed_versions") or []) or "not recorded"),
        _line("EPSS probability", _fmt(facts.get("epss_score"))),
        _line("EPSS percentile", _fmt(facts.get("epss_percentile"))),
        _line("CISA KEV", "YES - known exploited" if facts.get("kev") else "no"),
        _line("KEV remediation due", _fmt(facts.get("kev_due_date"))),
        _line("KEV required action", _fmt(facts.get("kev_required_action"))),
        _line("Assets affected in this organization", facts.get("affected_assets", 0)),
        _line("...of which internet-facing", facts.get("internet_facing_assets", 0)),
        _line("...of which business-critical", facts.get("critical_assets", 0)),
        _line("Open findings", facts.get("open_findings", 0)),
        _line("Highest VEYRS risk score", _fmt(facts.get("max_risk_score"))),
        "",
        "Description:",
        facts.get("description") or "(none)",
    ])


def analyze_cve(
    session: Session, *, organization_id: uuid.UUID, cve_id: str,
    permissions: frozenset[str] | set[str], is_superuser: bool = False,
    user_id: uuid.UUID | None = None, locale: str = "en",
) -> tuple[dict[str, Any], AiResult]:
    facts = cve_facts(session, cve_id, organization_id)
    result = invoke(
        session, organization_id=organization_id,
        request=AiRequest(
            capability=AiCapability.CVE_ANALYSIS.value,
            prompt=(
                "Explain this vulnerability to a security engineer in at most 200 "
                "words: what it is, whether it matters to THIS organization given "
                "the asset counts below, and what to do first. Use only the facts "
                "given; do not add CVEs, versions or scores that are not listed."
            ),
            facts=_render_cve_facts(facts),
            classification="internal",
            locale=locale,
            citations=[{"type": "cve", "id": facts["cve_id"]}],
        ),
        permissions=permissions, is_superuser=is_superuser, user_id=user_id,
    )
    return facts, result


# ---------------------------------------------------------------------------
# Risk explanation
# ---------------------------------------------------------------------------
def finding_facts(session: Session, finding: Finding) -> dict[str, Any]:
    asset = session.get(Asset, finding.asset_id)
    vulnerability = session.get(Vulnerability, finding.vulnerability_id)
    explanation = finding.risk_explanation or {}
    return {
        "finding_id": str(finding.id),
        "title": finding.title,
        "state": finding.state,
        "severity": finding.severity,
        "cve_id": vulnerability.cve_id if vulnerability else None,
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "epss_score": finding.epss_score,
        "kev": finding.kev,
        "risk_score": finding.risk_score,
        "risk_level": finding.risk_level,
        "technical_risk": finding.technical_risk,
        "exploitability_risk": finding.exploitability_risk,
        "business_risk": finding.business_risk,
        "exposure_risk": finding.exposure_risk,
        "drivers": explanation.get("drivers") or [],
        "adjustments": [a.get("reason") for a in (explanation.get("adjustments") or [])],
        "computed_summary": explanation.get("summary"),
        "asset_name": asset.name if asset else None,
        "asset_hostname": asset.hostname if asset else None,
        "asset_criticality": asset.criticality if asset else None,
        "asset_exposure": asset.exposure if asset else None,
        "asset_environment": asset.environment if asset else None,
        "asset_classification": asset.data_classification if asset else None,
        "sla_due_at": finding.sla_due_at.isoformat() if finding.sla_due_at else None,
        "sla_breached": finding.sla_breached,
        "recommendation": finding.recommendation,
    }


def _render_finding_facts(facts: dict[str, Any]) -> str:
    return "\n".join([
        _line("Finding", facts["title"]),
        _line("State", facts["state"]),
        _line("CVE", _fmt(facts.get("cve_id"))),
        _line("CVSS", f"{_fmt(facts.get('cvss_score'))} {facts.get('cvss_vector') or ''}"),
        _line("EPSS", _fmt(facts.get("epss_score"))),
        _line("CISA KEV", "YES" if facts.get("kev") else "no"),
        _line("VEYRS risk", f"{_fmt(facts.get('risk_score'))} ({facts.get('risk_level')})"),
        _line("  technical", _fmt(facts.get("technical_risk"))),
        _line("  exploitability", _fmt(facts.get("exploitability_risk"))),
        _line("  business", _fmt(facts.get("business_risk"))),
        _line("  exposure", _fmt(facts.get("exposure_risk"))),
        _line("Top drivers", "; ".join(facts.get("drivers") or []) or "none recorded"),
        _line("Policy adjustments", "; ".join(a for a in facts.get("adjustments") or [] if a)
              or "none"),
        _line("Asset", f"{facts.get('asset_name')} ({facts.get('asset_hostname') or 'no host'})"),
        _line("Asset criticality", _fmt(facts.get("asset_criticality"))),
        _line("Asset exposure", _fmt(facts.get("asset_exposure"))),
        _line("Environment", _fmt(facts.get("asset_environment"))),
        _line("Data classification", _fmt(facts.get("asset_classification"))),
        _line("SLA due", _fmt(facts.get("sla_due_at"))),
        _line("SLA breached", "YES" if facts.get("sla_breached") else "no"),
        _line("Computed summary", _fmt(facts.get("computed_summary"))),
    ])


def explain_risk(
    session: Session, *, organization_id: uuid.UUID, finding: Finding,
    permissions: frozenset[str] | set[str], is_superuser: bool = False,
    user_id: uuid.UUID | None = None, locale: str = "en",
) -> tuple[dict[str, Any], AiResult]:
    """Answer 'why is this critical?' -- the spec's section 26 requirement."""
    facts = finding_facts(session, finding)
    result = invoke(
        session, organization_id=organization_id,
        request=AiRequest(
            capability=AiCapability.RISK_EXPLANATION.value,
            prompt=(
                "Explain in at most 150 words WHY this finding carries the risk "
                "score shown, naming the specific factors that raised or lowered "
                "it. Do not restate every number; explain the causal chain. If the "
                "score is high mainly because of exploitation evidence rather than "
                "severity, say so explicitly."
            ),
            facts=_render_finding_facts(facts),
            classification="confidential",
            locale=locale,
            citations=[{"type": "finding", "id": facts["finding_id"]}],
        ),
        permissions=permissions, is_superuser=is_superuser, user_id=user_id,
    )
    return facts, result


def recommend_remediation(
    session: Session, *, organization_id: uuid.UUID, finding: Finding,
    permissions: frozenset[str] | set[str], is_superuser: bool = False,
    user_id: uuid.UUID | None = None, locale: str = "en",
) -> tuple[dict[str, Any], AiResult]:
    facts = finding_facts(session, finding)
    vulnerability = session.get(Vulnerability, finding.vulnerability_id)
    fixed_versions: list[str] = []
    if vulnerability is not None and vulnerability.cve_id:
        cve = session.get(Cve, vulnerability.cve_id)
        if cve is not None:
            fixed_versions = list(cve.fixed_versions or [])
    product_link = session.get(AssetProduct, finding.asset_product_id) \
        if finding.asset_product_id else None
    if product_link is not None:
        product = session.get(Product, product_link.product_id)
        if product is not None:
            facts["product"] = product.name
            facts["installed_version"] = product_link.version
    extra = "\n".join([
        _line("Product", _fmt(facts.get("product"))),
        _line("Installed version", _fmt(facts.get("installed_version"))),
        _line("Known fixed versions", ", ".join(fixed_versions) or "not recorded in VEYRS"),
        _line("Existing recommendation", _fmt(facts.get("recommendation"))),
    ])
    result = invoke(
        session, organization_id=organization_id,
        request=AiRequest(
            capability=AiCapability.REMEDIATION_ADVICE.value,
            prompt=(
                "Propose a remediation plan with three sections: (1) immediate "
                "mitigation that can be applied today without a maintenance "
                "window, (2) the durable fix, (3) how to verify the fix worked. "
                "If VEYRS does not record a fixed version, say that the fixed "
                "version must be confirmed with the vendor -- never guess one."
            ),
            facts=_render_finding_facts(facts) + "\n" + extra,
            classification="confidential",
            locale=locale,
            citations=[{"type": "finding", "id": facts["finding_id"]}],
        ),
        permissions=permissions, is_superuser=is_superuser, user_id=user_id,
    )
    return facts, result


# ---------------------------------------------------------------------------
# Team suggestion
# ---------------------------------------------------------------------------
def suggest_team(
    session: Session, *, organization_id: uuid.UUID, finding: Finding,
    permissions: frozenset[str] | set[str], is_superuser: bool = False,
    user_id: uuid.UUID | None = None,
) -> tuple[dict[str, Any], AiResult]:
    """Propose an owning team. Advisory only -- assignment rules still decide.

    The model picks from the tenant's ACTUAL team list; it cannot invent a team,
    and the caller applies the suggestion explicitly. That keeps ownership an
    auditable human/rule decision rather than a model side effect.
    """
    teams = list(session.execute(
        select(Team).where(Team.organization_id == organization_id)
    ).scalars().all())
    facts = finding_facts(session, finding)
    catalogue = "\n".join(
        f"- {t.slug}: {t.name} ({t.description or 'no description'})" for t in teams
    ) or "- (no teams defined)"
    result = invoke(
        session, organization_id=organization_id,
        request=AiRequest(
            capability=AiCapability.SUGGEST_TEAM.value,
            prompt=(
                "Choose the single most appropriate owning team for this finding "
                "from the list below. Reply with JSON only: "
                '{"team_slug": "...", "confidence": 0.0-1.0, "reason": "..."}. '
                "If no listed team fits, use team_slug null."
            ),
            facts=_render_finding_facts(facts) + "\n\nTeams available:\n" + catalogue,
            classification="internal",
            citations=[{"type": "finding", "id": facts["finding_id"]}],
        ),
        permissions=permissions, is_superuser=is_superuser, user_id=user_id,
    )
    suggestion = _parse_team_suggestion(result, {t.slug for t in teams})
    return suggestion, result


def _parse_team_suggestion(result: AiResult, valid_slugs: set[str]) -> dict[str, Any]:
    from .providers import ProviderError, parse_json_object

    if not result.allowed or result.degraded:
        return {"team_slug": None, "confidence": 0.0, "reason": "AI unavailable"}
    try:
        payload = parse_json_object(result.text)
    except ProviderError:
        return {"team_slug": None, "confidence": 0.0, "reason": "unparseable AI response"}
    slug = payload.get("team_slug")
    if slug is not None and slug not in valid_slugs:
        # Hallucinated team: refuse rather than silently create/ignore.
        return {"team_slug": None, "confidence": 0.0,
                "reason": f"AI proposed unknown team {slug!r}"}
    try:
        confidence = min(1.0, max(0.0, float(payload.get("confidence", 0))))
    except (TypeError, ValueError):
        confidence = 0.0
    return {"team_slug": slug, "confidence": confidence,
            "reason": str(payload.get("reason") or "")[:400]}


# ---------------------------------------------------------------------------
# Threat summary
# ---------------------------------------------------------------------------
def summarize_threats(
    session: Session, *, organization_id: uuid.UUID, days: int = 7, limit: int = 20,
    permissions: frozenset[str] | set[str], is_superuser: bool = False,
    user_id: uuid.UUID | None = None, locale: str = "en",
) -> tuple[dict[str, Any], AiResult]:
    import datetime as dt

    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    articles = list(session.execute(
        select(ThreatArticle)
        .where(ThreatArticle.organization_id == organization_id,
               ThreatArticle.published_at >= since)
        .order_by(ThreatArticle.relevance.desc().nullslast())
        .limit(limit)
    ).scalars().all())

    rendered = "\n".join(
        f"- [{a.published_at.date() if a.published_at else '?'}] {a.title} "
        f"(relevance {a.relevance:.2f}, CVEs: {', '.join(a.cve_ids or []) or 'none'})"
        for a in articles
    ) or "- (no articles in this window)"

    facts = {"window_days": days, "article_count": len(articles),
             "cve_ids": sorted({c for a in articles for c in (a.cve_ids or [])})}

    result = invoke(
        session, organization_id=organization_id,
        request=AiRequest(
            capability=AiCapability.THREAT_SUMMARY.value,
            prompt=(
                f"Write a {days}-day threat briefing of at most 250 words for a "
                "security manager. Lead with what changed for THIS organization. "
                "Group related items. Do not list every article."
            ),
            facts=f"Articles ranked by relevance to this organization's inventory:\n{rendered}",
            # Article bodies are third-party text: fenced, never instructions.
            untrusted="\n\n".join((a.summary or "")[:1500] for a in articles[:8]),
            classification="internal",
            locale=locale,
            citations=[{"type": "news", "id": str(a.id)} for a in articles[:10]],
        ),
        permissions=permissions, is_superuser=is_superuser, user_id=user_id,
    )
    return facts, result


# ---------------------------------------------------------------------------
# Natural-language search
# ---------------------------------------------------------------------------
def natural_language_search(
    session: Session, *, organization_id: uuid.UUID, question: str,
    permissions: frozenset[str] | set[str], is_superuser: bool = False,
    user_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """Question -> validated structured query -> results.

    Returns the query it ran alongside the rows, so the analyst can see and edit
    the interpretation. An opaque natural-language search in a security tool is
    a liability: the operator must be able to prove what was actually asked.
    """
    known_products = [
        name for (name,) in session.execute(
            select(Product.name)
            .join(AssetProduct, AssetProduct.product_id == Product.id)
            .join(Asset, AssetProduct.asset_id == Asset.id)
            .where(Asset.organization_id == organization_id)
            .distinct()
            .limit(500)
        ).all()
    ]

    query = nlquery.heuristic_parse(question, known_products=known_products)
    source = "heuristic"
    ai_result: AiResult | None = None
    error: str | None = None

    if query is None:
        ai_result = invoke(
            session, organization_id=organization_id,
            request=AiRequest(
                capability=AiCapability.NL_SEARCH.value,
                prompt=nlquery.build_translation_prompt(question),
                classification="internal",
            ),
            permissions=permissions, is_superuser=is_superuser, user_id=user_id,
        )
        if ai_result.allowed and not ai_result.degraded:
            from .providers import ProviderError, parse_json_object

            try:
                query = nlquery.validate(parse_json_object(ai_result.text))
                query.explanation = query.explanation or nlquery.describe(query)
                source = "ai"
            except (ProviderError, nlquery.QueryError) as exc:
                error = str(exc)
        else:
            error = ai_result.block_reason or "AI translation unavailable"

    if query is None:
        return {
            "question": question, "understood": False, "source": source,
            "error": error or "could not interpret the question",
            "query": None, "results": [], "total": 0,
            "hint": "Try naming a severity, EPSS/CVSS threshold, KEV, exposure "
                    "or a product from your inventory.",
        }

    if not is_superuser and "finding:read" not in set(permissions):
        return {"question": question, "understood": True, "source": source,
                "query": query.as_dict(), "results": [], "total": 0,
                "error": "caller lacks finding:read"}

    rows = nlquery.run(session, query, organization_id)
    return {
        "question": question,
        "understood": True,
        "source": source,
        "query": query.as_dict(),
        "explanation": query.explanation,
        "total": len(rows),
        "results": [
            {
                "id": str(f.id), "title": f.title, "state": f.state,
                "severity": f.severity, "risk_score": f.risk_score,
                "risk_level": f.risk_level, "cvss_score": f.cvss_score,
                "epss_score": f.epss_score, "kev": f.kev,
                "asset_id": str(f.asset_id), "sla_breached": f.sla_breached,
                "detected_at": f.detected_at.isoformat() if f.detected_at else None,
            }
            for f in rows
        ],
    }


# ---------------------------------------------------------------------------
# Ticket drafting
# ---------------------------------------------------------------------------
def draft_ticket(
    session: Session, *, organization_id: uuid.UUID, finding: Finding,
    permissions: frozenset[str] | set[str], is_superuser: bool = False,
    user_id: uuid.UUID | None = None, locale: str = "en",
) -> tuple[dict[str, Any], AiResult]:
    """Produce a ticket DRAFT. It is never created automatically.

    The spec asks for AI ticket generation; it does not ask for AI to mutate the
    ITSM record set on its own. The draft is returned to the caller, who creates
    the ticket through the normal authorized endpoint and inherits the normal
    audit trail.
    """
    facts = finding_facts(session, finding)
    result = invoke(
        session, organization_id=organization_id,
        request=AiRequest(
            capability=AiCapability.TICKET_DRAFT.value,
            prompt=(
                "Draft a remediation ticket. Reply with JSON only: "
                '{"summary": "<=120 chars", "description": "markdown", '
                '"acceptance_criteria": ["..."], "suggested_priority": '
                '"critical|high|medium|low"}. The description must state impact, '
                "affected asset, and verification steps."
            ),
            facts=_render_finding_facts(facts),
            classification="confidential",
            locale=locale,
            citations=[{"type": "finding", "id": facts["finding_id"]}],
        ),
        permissions=permissions, is_superuser=is_superuser, user_id=user_id,
    )
    return _parse_ticket_draft(result, facts), result


def _parse_ticket_draft(result: AiResult, facts: dict[str, Any]) -> dict[str, Any]:
    """Always returns a usable draft: falls back to a computed one."""
    from .providers import ProviderError, parse_json_object

    fallback = {
        "summary": f"Remediate: {facts['title']}"[:120],
        "description": (
            f"**Finding:** {facts['title']}\n\n"
            f"- CVE: {facts.get('cve_id') or 'n/a'}\n"
            f"- CVSS: {facts.get('cvss_score')}\n"
            f"- EPSS: {facts.get('epss_score')}\n"
            f"- CISA KEV: {'yes' if facts.get('kev') else 'no'}\n"
            f"- VEYRS risk: {facts.get('risk_score')} ({facts.get('risk_level')})\n"
            f"- Asset: {facts.get('asset_name')} "
            f"({facts.get('asset_exposure')}, {facts.get('asset_criticality')})\n"
        ),
        "acceptance_criteria": [
            "Fix applied to the affected asset",
            "Re-scan shows the finding is no longer present",
            "Finding moved to VERIFIED in VEYRS",
        ],
        "suggested_priority": facts.get("risk_level") or facts.get("severity") or "medium",
        "generated_by": "veyrs",
    }
    if not result.allowed or result.degraded:
        return fallback
    try:
        payload = parse_json_object(result.text)
    except ProviderError:
        return fallback
    priority = str(payload.get("suggested_priority") or "").lower()
    if priority not in ("critical", "high", "medium", "low"):
        priority = fallback["suggested_priority"]
    criteria = payload.get("acceptance_criteria")
    return {
        "summary": str(payload.get("summary") or fallback["summary"])[:120],
        "description": str(payload.get("description") or fallback["description"])[:8000],
        "acceptance_criteria": (
            [str(c)[:300] for c in criteria[:10]]
            if isinstance(criteria, list) and criteria else fallback["acceptance_criteria"]
        ),
        "suggested_priority": priority,
        "generated_by": f"ai:{result.provider}/{result.model}",
    }


# ---------------------------------------------------------------------------
# Document / advisory analysis
# ---------------------------------------------------------------------------
def analyze_document_text(
    session: Session, *, organization_id: uuid.UUID, text: str, title: str = "",
    permissions: frozenset[str] | set[str], is_superuser: bool = False,
    user_id: uuid.UUID | None = None, extracted: dict[str, Any] | None = None,
    locale: str = "en",
) -> AiResult:
    """Narrate what the deterministic extractor already found in a document.

    The entity extraction itself is regex/parser work in `services/documents.py`
    -- deliberately NOT a model task, because "which CVEs does this advisory
    mention" must be reproducible and complete, not probabilistic.
    """
    extracted = extracted or {}
    facts = "\n".join([
        _line("Document", title or "(untitled)"),
        _line("CVEs detected", ", ".join(extracted.get("cve_ids") or []) or "none"),
        _line("Products detected", ", ".join(extracted.get("products") or []) or "none"),
        _line("Affected versions", ", ".join(extracted.get("affected_versions") or []) or "none"),
        _line("Fixed versions", ", ".join(extracted.get("fixed_versions") or []) or "none"),
        _line("CVSS vectors", ", ".join(extracted.get("cvss_vectors") or []) or "none"),
        _line("Correlated assets", extracted.get("matched_assets", 0)),
    ])
    return invoke(
        session, organization_id=organization_id,
        request=AiRequest(
            capability=AiCapability.ADVISORY_ANALYSIS.value,
            prompt=(
                "Summarise this advisory for an operations team in at most 200 "
                "words: what is affected, what the vendor says to do, and how "
                "urgent it is for us given the correlated asset count. Use only "
                "the detected entities listed; if a fixed version is not listed, "
                "state that it must be confirmed with the vendor."
            ),
            facts=facts,
            untrusted=text[:12000],
            classification="internal",
            locale=locale,
        ),
        permissions=permissions, is_superuser=is_superuser, user_id=user_id,
    )
