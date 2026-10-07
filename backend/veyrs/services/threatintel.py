"""Threat-intelligence feeds and the knowledge base (spec sections 17 and 21).

Article ingestion answers a question a raw RSS reader cannot: **does this story
affect us?** Every ingested article is scanned for CVE ids and known products,
then checked against the tenant's own inventory, so the news feed is ordered by
"three of your internet-facing appliances" rather than by publication time.

Parsers take already-decoded structures (a list of entry dicts). Fetching lives
outside so an air-gapped install can drop files in, and so tests do not need a
network.
"""
from __future__ import annotations

import datetime as dt
import hashlib
import logging
import re
import uuid
from typing import Any, Iterable

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from ..models import (
    Asset, AssetProduct, Cve, CveCpeMatch, KnowledgeArticle, KnowledgeRevision, Product,
    ThreatArticle, ThreatSource,
)
from .documents import extract_entities
from .versions import normalize_name

log = logging.getLogger("veyrs.threatintel")


def article_hash(title: str, url: str | None, body: str | None) -> str:
    payload = f"{(title or '').strip().lower()}|{(url or '').strip().lower()}|{len(body or '')}"
    return hashlib.sha256(payload.encode("utf-8")).hexdigest()


def _parse_dt(value: Any) -> dt.datetime | None:
    if isinstance(value, dt.datetime):
        return value if value.tzinfo else value.replace(tzinfo=dt.timezone.utc)
    if not value:
        return None
    text = str(value).replace("Z", "+00:00")
    for parser in (dt.datetime.fromisoformat,):
        try:
            parsed = parser(text)
            return parsed if parsed.tzinfo else parsed.replace(tzinfo=dt.timezone.utc)
        except ValueError:
            continue
    return None


def relevance(
    session: Session, organization_id: uuid.UUID, cve_ids: list[str], product_ids: list[str]
) -> int:
    """How many of this tenant's assets the article could plausibly touch."""
    asset_ids: set[uuid.UUID] = set()

    if cve_ids:
        product_hits = session.execute(
            select(CveCpeMatch.product_id).where(
                CveCpeMatch.cve_id.in_(cve_ids), CveCpeMatch.product_id.is_not(None)
            ).distinct()
        ).scalars().all()
        product_ids = list({*product_ids, *[str(p) for p in product_hits]})

    if product_ids:
        rows = session.execute(
            select(AssetProduct.asset_id)
            .join(Asset, Asset.id == AssetProduct.asset_id)
            .where(
                AssetProduct.organization_id == organization_id,
                AssetProduct.product_id.in_([uuid.UUID(p) for p in product_ids]),
                Asset.is_active.is_(True), Asset.deleted_at.is_(None),
            ).distinct()
        ).scalars().all()
        asset_ids.update(rows)
    return len(asset_ids)


def ingest_articles(
    session: Session,
    organization_id: uuid.UUID,
    source: ThreatSource | None,
    entries: Iterable[dict],
) -> dict[str, int]:
    """Ingest feed entries. Idempotent on (organization, content hash)."""
    stats = {"seen": 0, "created": 0, "updated": 0, "relevant": 0}
    for entry in entries:
        title = (entry.get("title") or "").strip()
        if not title:
            continue
        stats["seen"] += 1
        url = entry.get("url") or entry.get("link")
        body = entry.get("body") or entry.get("content") or entry.get("summary")
        digest = article_hash(title, url, body)

        row = session.execute(
            select(ThreatArticle).where(
                ThreatArticle.organization_id == organization_id,
                ThreatArticle.content_hash == digest,
            )
        ).scalars().first()
        created = row is None
        if created:
            row = ThreatArticle(
                organization_id=organization_id,
                source_id=source.id if source is not None else None,
                content_hash=digest, title=title[:600],
            )
            session.add(row)

        row.url = url
        row.external_id = entry.get("id") or entry.get("guid")
        row.summary = (entry.get("summary") or "")[:4000] or None
        row.body = body
        row.author = entry.get("author")
        row.language = (entry.get("language") or "en")[:5]
        row.published_at = _parse_dt(entry.get("published") or entry.get("published_at"))

        haystack = "\n".join(filter(None, [title, row.summary, body]))
        entities = extract_entities(haystack, session)
        known = session.execute(
            select(Cve.id).where(Cve.id.in_(entities["cve_ids"] or ["-"]))
        ).scalars().all()
        row.cve_ids = sorted(known)
        row.product_ids = entities["product_ids"]
        row.vendors = entities["vendors"]
        row.severity = entities["severity"]
        # Trust flows from the source: a vendor PSIRT outranks an aggregator.
        row.confidence = round(
            (source.trust if source is not None else 0.5)
            * (1.0 if row.cve_ids else 0.6), 3,
        )
        row.relevant_asset_count = relevance(
            session, organization_id, row.cve_ids, row.product_ids
        )
        row.is_relevant = row.relevant_asset_count > 0
        if row.is_relevant:
            stats["relevant"] += 1
        stats["created" if created else "updated"] += 1

    if source is not None:
        source.last_polled_at = dt.datetime.now(dt.timezone.utc)
        source.last_error = None
    session.flush()
    return stats


def feed_digest(
    session: Session, organization_id: uuid.UUID, *, days: int = 7, limit: int = 50
) -> list[dict]:
    """Recent intelligence, relevant items first."""
    since = dt.datetime.now(dt.timezone.utc) - dt.timedelta(days=days)
    rows = session.execute(
        select(ThreatArticle).where(
            ThreatArticle.organization_id == organization_id,
            ThreatArticle.created_at >= since,
        ).order_by(
            ThreatArticle.is_relevant.desc(),
            ThreatArticle.relevant_asset_count.desc(),
            ThreatArticle.published_at.desc().nullslast(),
        ).limit(limit)
    ).scalars().all()
    return [{
        "id": str(r.id), "title": r.title, "url": r.url, "severity": r.severity,
        "cve_ids": r.cve_ids, "confidence": r.confidence,
        "relevant_asset_count": r.relevant_asset_count, "is_relevant": r.is_relevant,
        "published_at": r.published_at.isoformat() if r.published_at else None,
    } for r in rows]


# --------------------------------------------------------------------------
# Knowledge base
# --------------------------------------------------------------------------


def slugify(value: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", (value or "").strip().lower()).strip("-")
    return slug[:120] or "article"


def create_article(
    session: Session,
    organization_id: uuid.UUID,
    *,
    title: str,
    body: str,
    kind: str = "guide",
    slug: str | None = None,
    summary: str | None = None,
    locale: str = "en",
    tags: list[str] | None = None,
    cve_ids: list[str] | None = None,
    product_ids: list[str] | None = None,
    cwe_ids: list[str] | None = None,
    required_permissions: list[str] | None = None,
    author_id: uuid.UUID | None = None,
    is_published: bool = False,
) -> KnowledgeArticle:
    article = KnowledgeArticle(
        organization_id=organization_id, slug=slug or slugify(title), title=title[:400],
        body=body, kind=kind, summary=summary, locale=locale[:5],
        tags=tags or [], cve_ids=cve_ids or [], product_ids=product_ids or [],
        cwe_ids=cwe_ids or [], required_permissions=required_permissions or [],
        author_id=author_id, is_published=is_published, version=1,
    )
    session.add(article)
    session.flush()
    session.add(KnowledgeRevision(
        organization_id=organization_id, article_id=article.id, version=1,
        title=article.title, body=article.body, author_id=author_id,
        change_note="created",
    ))
    session.flush()
    return article


def update_article(
    session: Session,
    article: KnowledgeArticle,
    *,
    title: str | None = None,
    body: str | None = None,
    author_id: uuid.UUID | None = None,
    change_note: str | None = None,
    **fields: Any,
) -> KnowledgeArticle:
    """Edit an article, snapshotting the previous text first.

    The revision is written BEFORE the mutation, so a crash mid-update can never
    lose the prior version of a runbook.
    """
    changed = (title is not None and title != article.title) or (
        body is not None and body != article.body
    )
    if changed:
        article.version += 1
        session.add(KnowledgeRevision(
            organization_id=article.organization_id, article_id=article.id,
            version=article.version,
            title=title or article.title, body=body if body is not None else article.body,
            author_id=author_id, change_note=change_note,
        ))
    if title is not None:
        article.title = title[:400]
    if body is not None:
        article.body = body
    for key, value in fields.items():
        if value is not None and hasattr(article, key):
            setattr(article, key, value)
    session.flush()
    return article


def articles_for_cve(
    session: Session, organization_id: uuid.UUID, cve_id: str
) -> list[KnowledgeArticle]:
    return session.execute(
        select(KnowledgeArticle).where(
            KnowledgeArticle.organization_id == organization_id,
            KnowledgeArticle.is_published.is_(True),
            KnowledgeArticle.cve_ids.contains([cve_id.upper()]),
        )
    ).scalars().all()


def visible_to(article: KnowledgeArticle, permissions: set[str], is_superuser: bool) -> bool:
    if is_superuser or not article.required_permissions:
        return True
    return bool(set(article.required_permissions) & permissions)


__all__ = [
    "ingest_articles", "relevance", "feed_digest", "article_hash", "slugify",
    "create_article", "update_article", "articles_for_cve", "visible_to",
]
