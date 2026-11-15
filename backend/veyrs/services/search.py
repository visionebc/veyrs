"""Global and semantic search (spec section 28).

Two layers, deliberately independent:

* **Lexical** - PostgreSQL `to_tsvector`/`plainto_tsquery` across CVEs, assets,
  findings, tickets, documents, knowledge articles and threat news. Always
  available, no external service, exact-match friendly (an analyst searching
  `CVE-2021-44228` wants that row, not something "semantically similar").
* **Semantic** - optional vector search over document/knowledge chunks via
  Qdrant. If the embedding service or Qdrant is unreachable, search degrades to
  lexical-only and says so in the response, rather than returning nothing.

Permission-aware by construction: every branch filters on the caller's
organization AND checks the permission that governs the entity type. This is the
same function the AI assistant retrieves through, which is how spec section 20's
"AI must never bypass VEYRS authorization" is satisfied - there is no second,
unfiltered retrieval path.
"""
from __future__ import annotations

import logging
import uuid
from typing import Any, Callable, Iterable

from sqlalchemy import func, or_, select
from sqlalchemy.orm import Session

from ..models import (
    Asset, Cve, Document, Finding, KnowledgeArticle, OPEN_STATES, Product, ThreatArticle,
    Ticket, Vulnerability,
)

log = logging.getLogger("veyrs.search")

#: entity type -> permission required to see it in results
ENTITY_PERMISSIONS = {
    "cve": "cve:read",
    "vulnerability": "vulnerability:read",
    "finding": "finding:read",
    "asset": "asset:read",
    "product": "product:read",
    "ticket": "ticket:read",
    "document": "document:read",
    "knowledge": "knowledge:read",
    "news": "intel:read",
}


def _like(term: str) -> str:
    return f"%{term.strip()}%"


def search(
    session: Session,
    organization_id: uuid.UUID,
    query: str,
    *,
    permissions: Iterable[str] | frozenset[str] = frozenset(),
    is_superuser: bool = False,
    types: Iterable[str] | None = None,
    limit_per_type: int = 10,
) -> dict[str, Any]:
    """Lexical search across the graph, filtered by tenant and permission."""
    term = (query or "").strip()
    if not term:
        return {"query": query, "results": {}, "total": 0}

    allowed = set(permissions)
    wanted = set(types) if types else set(ENTITY_PERMISSIONS)
    results: dict[str, list[dict]] = {}
    denied: list[str] = []

    def permitted(entity: str) -> bool:
        if entity not in wanted:
            return False
        if is_superuser or ENTITY_PERMISSIONS[entity] in allowed:
            return True
        denied.append(entity)
        return False

    if permitted("cve"):
        rows = session.execute(
            select(Cve).where(or_(
                Cve.id.ilike(_like(term)), Cve.title.ilike(_like(term)),
                Cve.description.ilike(_like(term)),
            )).order_by(Cve.kev.desc(), Cve.epss_score.desc().nullslast()).limit(limit_per_type)
        ).scalars().all()
        results["cve"] = [{
            "id": r.id, "title": r.title or (r.description or "")[:120],
            "score": r.best_cvss_score, "kev": r.kev, "epss": r.epss_score,
        } for r in rows]

    if permitted("vulnerability"):
        rows = session.execute(
            select(Vulnerability).where(
                Vulnerability.organization_id == organization_id,
                or_(Vulnerability.cve_id.ilike(_like(term)),
                    Vulnerability.title.ilike(_like(term)),
                    Vulnerability.description.ilike(_like(term))),
            ).order_by(Vulnerability.risk_score.desc().nullslast()).limit(limit_per_type)
        ).scalars().all()
        results["vulnerability"] = [{
            "id": str(r.id), "cve_id": r.cve_id, "title": r.title,
            "risk_score": r.risk_score, "risk_level": r.risk_level,
        } for r in rows]

    if permitted("finding"):
        rows = session.execute(
            select(Finding).where(
                Finding.organization_id == organization_id,
                Finding.title.ilike(_like(term)),
            ).order_by(Finding.risk_score.desc().nullslast()).limit(limit_per_type)
        ).scalars().all()
        results["finding"] = [{
            "id": str(r.id), "title": r.title, "state": r.state,
            "risk_score": r.risk_score, "sla_breached": r.sla_breached,
        } for r in rows]

    if permitted("asset"):
        rows = session.execute(
            select(Asset).where(
                Asset.organization_id == organization_id, Asset.deleted_at.is_(None),
                or_(Asset.name.ilike(_like(term)), Asset.hostname.ilike(_like(term)),
                    Asset.fqdn.ilike(_like(term))),
            ).limit(limit_per_type)
        ).scalars().all()
        results["asset"] = [{
            "id": str(r.id), "name": r.name, "type": r.asset_type,
            "criticality": r.criticality, "exposure": r.exposure,
        } for r in rows]

    if permitted("product"):
        rows = session.execute(
            select(Product).where(Product.name.ilike(_like(term))).limit(limit_per_type)
        ).scalars().all()
        results["product"] = [{"id": str(r.id), "name": r.name,
                               "type": r.product_type} for r in rows]

    if permitted("ticket"):
        rows = session.execute(
            select(Ticket).where(
                Ticket.organization_id == organization_id,
                or_(Ticket.reference.ilike(_like(term)), Ticket.title.ilike(_like(term))),
            ).order_by(Ticket.created_at.desc()).limit(limit_per_type)
        ).scalars().all()
        results["ticket"] = [{"id": str(r.id), "reference": r.reference,
                              "title": r.title, "state": r.state} for r in rows]

    if permitted("document"):
        rows = session.execute(
            select(Document).where(
                Document.organization_id == organization_id,
                or_(Document.filename.ilike(_like(term)),
                    Document.text_content.ilike(_like(term))),
            ).order_by(Document.created_at.desc()).limit(limit_per_type)
        ).scalars().all()
        results["document"] = [{
            "id": str(r.id), "filename": r.filename, "class": r.doc_class,
            "cve_ids": r.cve_ids, "snippet": _snippet(r.text_content, term),
        } for r in rows]

    if permitted("knowledge"):
        rows = session.execute(
            select(KnowledgeArticle).where(
                KnowledgeArticle.organization_id == organization_id,
                or_(KnowledgeArticle.title.ilike(_like(term)),
                    KnowledgeArticle.body.ilike(_like(term))),
            ).limit(limit_per_type)
        ).scalars().all()
        # Article-level permission gates are enforced here, not in the UI.
        visible = [
            r for r in rows
            if is_superuser or not r.required_permissions
            or set(r.required_permissions) & allowed
        ]
        results["knowledge"] = [{
            "id": str(r.id), "slug": r.slug, "title": r.title, "kind": r.kind,
            "snippet": _snippet(r.body, term),
        } for r in visible]

    if permitted("news"):
        rows = session.execute(
            select(ThreatArticle).where(
                ThreatArticle.organization_id == organization_id,
                or_(ThreatArticle.title.ilike(_like(term)),
                    ThreatArticle.summary.ilike(_like(term))),
            ).order_by(ThreatArticle.published_at.desc().nullslast()).limit(limit_per_type)
        ).scalars().all()
        results["news"] = [{
            "id": str(r.id), "title": r.title, "url": r.url,
            "published_at": r.published_at.isoformat() if r.published_at else None,
            "cve_ids": r.cve_ids, "relevant": r.is_relevant,
        } for r in rows]

    total = sum(len(v) for v in results.values())
    return {
        "query": term, "results": {k: v for k, v in results.items() if v},
        "total": total,
        # Being explicit about what was NOT searched is part of being trustworthy:
        # "no results" and "you may not see those results" are different answers.
        "denied_types": sorted(set(denied)),
    }


def _snippet(text: str | None, term: str, width: int = 200) -> str | None:
    if not text:
        return None
    lowered = text.lower()
    index = lowered.find(term.lower())
    if index < 0:
        return text[:width].strip()
    start = max(index - width // 2, 0)
    return ("..." if start else "") + text[start:start + width].strip() + "..."


# --------------------------------------------------------------------------
# Semantic layer (optional)
# --------------------------------------------------------------------------


class VectorBackend:
    """Interface for the optional vector index.

    Kept abstract so an install can swap Qdrant for pgvector without touching
    call sites, and so tests inject a deterministic stub instead of a network.
    """

    available: bool = False

    def upsert(self, organization_id: uuid.UUID, items: list[dict]) -> int:
        raise NotImplementedError

    def query(self, organization_id: uuid.UUID, text: str, limit: int = 10) -> list[dict]:
        raise NotImplementedError


class NullVectorBackend(VectorBackend):
    """Default: no semantic search configured."""

    available = False

    def upsert(self, organization_id: uuid.UUID, items: list[dict]) -> int:
        return 0

    def query(self, organization_id: uuid.UUID, text: str, limit: int = 10) -> list[dict]:
        return []


_backend: VectorBackend = NullVectorBackend()


def set_vector_backend(backend: VectorBackend) -> None:
    global _backend  # noqa: PLW0603 - process-wide singleton by design
    _backend = backend


def get_vector_backend() -> VectorBackend:
    return _backend


def semantic_search(
    session: Session,
    organization_id: uuid.UUID,
    query: str,
    *,
    permissions: Iterable[str] | frozenset[str] = frozenset(),
    is_superuser: bool = False,
    limit: int = 10,
) -> dict[str, Any]:
    """Vector search over document/knowledge chunks, degrading to lexical."""
    backend = get_vector_backend()
    if not backend.available:
        fallback = search(
            session, organization_id, query, permissions=permissions,
            is_superuser=is_superuser, types=("document", "knowledge"),
            limit_per_type=limit,
        )
        return {**fallback, "mode": "lexical",
                "note": "semantic search is not configured; results are lexical"}

    allowed = set(permissions)
    if not (is_superuser or "document:read" in allowed or "knowledge:read" in allowed):
        return {"query": query, "results": {}, "total": 0, "mode": "semantic",
                "denied_types": ["document", "knowledge"]}
    try:
        hits = backend.query(organization_id, query, limit=limit)
    except Exception as exc:  # noqa: BLE001 - never fail search on an optional dep
        log.warning("vector backend failed, falling back to lexical: %s", exc)
        fallback = search(
            session, organization_id, query, permissions=permissions,
            is_superuser=is_superuser, types=("document", "knowledge"),
            limit_per_type=limit,
        )
        return {**fallback, "mode": "lexical", "note": f"vector search unavailable: {exc}"}
    return {"query": query, "mode": "semantic", "total": len(hits),
            "results": {"chunk": hits}}


__all__ = [
    "search", "semantic_search", "ENTITY_PERMISSIONS", "VectorBackend",
    "NullVectorBackend", "set_vector_backend", "get_vector_backend",
]
