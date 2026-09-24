"""Documents, threat intelligence feeds, knowledge base and global search."""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any

from fastapi import (
    Response, APIRouter, Depends, File, HTTPException, Query, Request, UploadFile, status,
)
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import func, or_, select

from ...config import settings
from ...models import (
    Cve, Document, DocumentChunk, KnowledgeArticle, KnowledgeRevision, Team, ThreatArticle,
    ThreatSource, Vendor,
)
from ...security.deps import CurrentPrincipal, Principal, TenantSession, require
from ...services import audit, documents as doc_service, search as search_service
from ...services import threatintel
from .schemas import Page

router = APIRouter(tags=["intelligence & knowledge"])

#: Refuse oversized uploads before reading them into memory.
MAX_UPLOAD_BYTES = 32 * 1024 * 1024


class DocumentOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    filename: str
    title: str | None = None
    notes: str | None = None
    content_type: str
    size_bytes: int
    status: str
    error: str | None
    doc_class: str | None
    page_count: int | None
    cve_ids: list[str]
    manual_cve_ids: list[str] = Field(default_factory=list)
    team_id: uuid.UUID | None = None
    vendor_id: uuid.UUID | None = None
    data_classification: str
    created_at: dt.datetime

    #: Resolved names, filled by one batched lookup per page. A list of raw
    #: UUIDs is a list nobody can read, which is what made the ownership
    #: columns unusable in phase 26 until the same treatment was applied there.
    team_name: str | None = None
    vendor_name: str | None = None
    #: `cve_ids` + `manual_cve_ids`, de-duplicated, order-stable. Clients that
    #: want "everything this document is about" read this instead of unioning
    #: two lists themselves and getting it subtly wrong.
    all_cve_ids: list[str] = Field(default_factory=list)


class DocumentDetail(DocumentOut):
    extracted: dict[str, Any] = Field(default_factory=dict)
    unknown_cves: list[str] = Field(default_factory=list)
    chunk_count: int = 0
    text_preview: str | None = None


class DocumentPatch(BaseModel):
    """Operator-editable metadata. Extraction output is NOT editable here.

    Every field is optional and the handler uses `exclude_unset`, so a client
    that sends only `title` cannot blank the notes it never mentioned -- the
    same rule the bulk-assign paths enforce with `clear`.
    """

    title: str | None = Field(default=None, max_length=400)
    notes: str | None = Field(default=None, max_length=20000)
    team_id: uuid.UUID | None = None
    vendor_id: uuid.UUID | None = None
    doc_class: str | None = Field(default=None, max_length=40)
    data_classification: str | None = None
    #: The full replacement list of hand-attached CVEs. Replacement rather
    #: than append because there has to be a way to remove one, and a
    #: `remove_cve_ids` twin is a second code path for the same decision.
    manual_cve_ids: list[str] | None = None
    #: Null both `team_id` and `vendor_id` by naming them here. An omitted
    #: optional and an explicit null are the same JSON, so without this a
    #: document could be given an owner and never have one taken away.
    clear: list[str] = Field(default_factory=list)


class ThreatSourceWrite(BaseModel):
    slug: str = Field(min_length=1, max_length=80)
    name: str = Field(min_length=1, max_length=200)
    kind: str = "rss"
    url: str | None = None
    is_enabled: bool = True
    trust: float = Field(default=0.5, ge=0.0, le=1.0)
    poll_interval_minutes: int = Field(default=60, ge=5, le=10080)
    tags: list[str] = Field(default_factory=list)


class ThreatSourceOut(ThreatSourceWrite):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    last_polled_at: dt.datetime | None
    last_error: str | None


class ArticleIngest(BaseModel):
    source_slug: str | None = None
    entries: list[dict[str, Any]] = Field(min_length=1, max_length=500)


class KnowledgeWrite(BaseModel):
    title: str = Field(min_length=1, max_length=400)
    body: str = Field(min_length=1)
    kind: str = "guide"
    slug: str | None = None
    summary: str | None = None
    locale: str = "en"
    tags: list[str] = Field(default_factory=list)
    cve_ids: list[str] = Field(default_factory=list)
    product_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[str] = Field(default_factory=list)
    required_permissions: list[str] = Field(default_factory=list)
    is_published: bool = False
    change_note: str | None = None


class KnowledgeOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    slug: str
    title: str
    kind: str
    summary: str | None
    locale: str
    version: int
    is_published: bool
    tags: list[str]
    cve_ids: list[str]
    required_permissions: list[str]
    view_count: int
    created_at: dt.datetime


class KnowledgeDetail(KnowledgeOut):
    body: str
    revisions: list[dict[str, Any]] = Field(default_factory=list)


def _actor(request: Request, principal: Principal) -> dict:
    return {
        "organization_id": principal.organization_id,
        "actor_id": principal.user_id,
        "actor_label": principal.label,
        "correlation_id": getattr(request.state, "correlation_id", None),
        "ip_address": request.client.host if request.client else None,
        "user_agent": (request.headers.get("User-Agent") or "")[:255] or None,
    }


# --------------------------------------------------------------------------
# Documents
# --------------------------------------------------------------------------


@router.post("/documents", response_model=DocumentDetail,
             status_code=status.HTTP_201_CREATED, summary="Upload and analyse a document")
async def upload_document(
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("document:write"))],
    file: UploadFile = File(...),
    data_classification: str = Query(default="internal"),
    correlate: bool = Query(default=True),
    title: str | None = Query(default=None, max_length=400),
    notes: str | None = Query(default=None, max_length=20000),
    team_id: uuid.UUID | None = Query(default=None),
    vendor_id: uuid.UUID | None = Query(default=None),
) -> DocumentDetail:
    """Upload, extract, and optionally file the document in one call.

    The metadata is accepted here as well as on `PATCH` because the moment
    somebody has the advisory in front of them is the moment they know which
    vendor and which team it belongs to. Forcing a second request is how a
    library ends up full of untitled, unowned PDFs.

    **An upload that DEDUPES does not overwrite existing metadata.** The same
    bytes uploaded twice return the first row (the content hash is unique per
    organization); silently replacing a title somebody wrote with whatever the
    second uploader happened to type would lose work with no trace.
    """
    data = await file.read(MAX_UPLOAD_BYTES + 1)
    if len(data) > MAX_UPLOAD_BYTES:
        raise HTTPException(
            status.HTTP_413_REQUEST_ENTITY_TOO_LARGE,
            f"document exceeds {MAX_UPLOAD_BYTES // (1024 * 1024)} MB",
        )
    if not data:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "empty upload")

    document, created = doc_service.ingest(
        session, principal.organization_id,
        filename=file.filename or "upload",
        data=data,
        content_type=file.content_type or "application/octet-stream",
        uploaded_by_id=principal.user_id,
        data_classification=data_classification,
        correlate=correlate,
    )
    if team_id is not None:
        team = session.get(Team, team_id)
        if team is None or team.organization_id != principal.organization_id:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unknown team")
    if vendor_id is not None and session.get(Vendor, vendor_id) is None:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unknown vendor")

    if created:
        for field, value in (("title", title), ("notes", notes),
                             ("team_id", team_id), ("vendor_id", vendor_id)):
            if value is not None:
                setattr(document, field, value)

    audit.record(session, action="document.upload", object_type="document",
                 object_id=str(document.id),
                 object_label=document.title or document.filename,
                 **_actor(request, principal), changes=audit.diff(None, {"filename": document.filename, "status": document.status,
                        "new": created}))
    session.commit()
    session.refresh(document)
    return _document_detail(session, document)


def _all_cves(document: Document) -> list[str]:
    """Extracted + hand-attached, de-duplicated, extraction first.

    Order is stable and meaningful: what the text itself says comes before what
    somebody decided it also relates to.
    """
    out: list[str] = []
    for cve_id in list(document.cve_ids or []) + list(document.manual_cve_ids or []):
        upper = str(cve_id).upper()
        if upper not in out:
            out.append(upper)
    return out


def _label_documents(session, rows: list[DocumentOut]) -> list[DocumentOut]:
    """Resolve team and vendor names with two batched lookups for the whole page.

    Done after serialisation rather than as a join so the filters keep their
    query plan; a page is at most 200 rows, so this is two `IN` lookups.
    """
    team_ids = {r.team_id for r in rows if r.team_id}
    vendor_ids = {r.vendor_id for r in rows if r.vendor_id}
    teams = {
        t.id: t.name for t in (
            session.execute(select(Team).where(Team.id.in_(team_ids))).scalars().all()
            if team_ids else []
        )
    }
    vendors = {
        v.id: v.name for v in (
            session.execute(select(Vendor).where(Vendor.id.in_(vendor_ids))).scalars().all()
            if vendor_ids else []
        )
    }
    for row in rows:
        row.team_name = teams.get(row.team_id)
        row.vendor_name = vendors.get(row.vendor_id)
    return rows


def _document_detail(session, document: Document) -> DocumentDetail:
    detail = DocumentDetail.model_validate(document)
    detail.unknown_cves = doc_service.unknown_cves(document)
    detail.chunk_count = session.execute(
        select(func.count()).select_from(DocumentChunk)
        .where(DocumentChunk.document_id == document.id)
    ).scalar_one()
    detail.text_preview = (document.text_content or "")[:2000] or None
    detail.all_cve_ids = _all_cves(document)
    _label_documents(session, [detail])
    return detail


@router.get("/documents", response_model=Page[DocumentOut], summary="List documents")
def list_documents(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("document:read"))],
    doc_class: str | None = None,
    status_filter: str | None = Query(default=None, alias="status"),
    team_id: uuid.UUID | None = None,
    vendor_id: uuid.UUID | None = None,
    cve_id: str | None = Query(
        default=None,
        description="Documents referencing this CVE, whether the extractor "
                    "found it or a person attached it.",
    ),
    q: str | None = Query(default=None, description="Substring of the title or filename."),
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> Page[DocumentOut]:
    stmt = select(Document).where(Document.organization_id == principal.organization_id)
    if doc_class:
        stmt = stmt.where(Document.doc_class == doc_class)
    if status_filter:
        stmt = stmt.where(Document.status == status_filter)
    if team_id is not None:
        stmt = stmt.where(Document.team_id == team_id)
    if vendor_id is not None:
        stmt = stmt.where(Document.vendor_id == vendor_id)
    if cve_id:
        # BOTH columns, always. Searching only the extracted list would answer
        # "no documents" for an advisory an analyst linked by hand -- which is
        # precisely the link somebody made because the text did not say it.
        upper = cve_id.strip().upper()
        stmt = stmt.where(or_(
            Document.cve_ids.contains([upper]),
            Document.manual_cve_ids.contains([upper]),
        ))
    if q:
        needle = f"%{q.strip()}%"
        stmt = stmt.where(or_(Document.title.ilike(needle), Document.filename.ilike(needle)))
    total = session.execute(select(func.count()).select_from(stmt.subquery())).scalar_one()
    rows = session.execute(
        stmt.order_by(Document.created_at.desc()).offset((page - 1) * size).limit(size)
    ).scalars().all()
    items = []
    for row in rows:
        out = DocumentOut.model_validate(row)
        out.all_cve_ids = _all_cves(row)
        items.append(out)
    return Page.of(_label_documents(session, items), total, page, size)


@router.get("/documents/{document_id}", response_model=DocumentDetail,
            summary="Document detail with extracted entities")
def get_document(
    document_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("document:read"))],
) -> DocumentDetail:
    row = session.get(Document, document_id)
    if row is None or row.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "document not found")
    return _document_detail(session, row)


@router.patch("/documents/{document_id}", response_model=DocumentDetail,
              summary="Edit a document's title, notes, owner, vendor and CVEs")
def patch_document(
    document_id: uuid.UUID,
    payload: DocumentPatch,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("document:write"))],
) -> DocumentDetail:
    """Edit the operator-owned metadata. Extraction output stays read-only.

    Three refusals worth naming, because each is a way this could quietly go
    wrong:

    * **An unknown team or vendor is rejected, not stored.** A dangling id
      renders as a blank column and looks like the field was never filled in.
    * **A CVE that is not in the catalogue is rejected.** `documents.py` has
      always validated extracted CVEs against the `cves` table for exactly this
      reason -- a document may reference a vulnerability, never invent one --
      and a hand-attached identifier is not more trustworthy than a parsed one.
      A typo would otherwise create a link that can never resolve.
    * **`filename` is not editable.** It is what the uploader's disk called the
      bytes the content hash was taken over; `title` is the field for a nicer
      name.
    """
    row = session.get(Document, document_id)
    if row is None or row.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "document not found")

    changes = payload.model_dump(exclude_unset=True)
    clear = set(changes.pop("clear", []) or [])
    unknown_clear = clear - {"team_id", "vendor_id", "title", "notes", "doc_class"}
    if unknown_clear:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"cannot clear {', '.join(sorted(unknown_clear))}",
        )
    if not changes and not clear:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "nothing to change")

    if changes.get("team_id") is not None:
        team = session.get(Team, changes["team_id"])
        if team is None or team.organization_id != principal.organization_id:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unknown team")
    if changes.get("vendor_id") is not None:
        # `vendors` is the GLOBAL CPE dictionary shared by every tenant, so
        # there is no organization to check here -- and that is deliberate:
        # see docs/USER_MANUAL.md, "Vendors and products are a dictionary".
        if session.get(Vendor, changes["vendor_id"]) is None:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, "unknown vendor")

    if "manual_cve_ids" in changes:
        wanted, missing = [], []
        for raw in changes["manual_cve_ids"] or []:
            upper = str(raw).strip().upper()
            if not upper:
                continue
            if session.get(Cve, upper) is None:
                missing.append(upper)
            elif upper not in wanted:
                wanted.append(upper)
        if missing:
            raise HTTPException(
                status.HTTP_422_UNPROCESSABLE_ENTITY,
                f"not in the CVE catalogue: {', '.join(missing)}. A document may "
                "reference a vulnerability, it cannot invent one.",
            )
        changes["manual_cve_ids"] = wanted

    before = {k: getattr(row, k) for k in list(changes) + sorted(clear)}
    for field, value in changes.items():
        setattr(row, field, value)
    for field in clear:
        setattr(row, field, None)

    audit.record(session, action="document.update", object_type="document",
                 object_id=str(row.id), object_label=row.title or row.filename,
                 **_actor(request, principal),
                 changes=audit.diff(before, {
                     k: getattr(row, k) for k in list(changes) + sorted(clear)
                 }))
    session.commit()
    session.refresh(row)
    return _document_detail(session, row)


@router.delete("/documents/{document_id}", status_code=204, response_model=None,
               response_class=Response, summary="Delete a document")
def delete_document(
    document_id: uuid.UUID,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("document:delete"))],
) -> None:
    row = session.get(Document, document_id)
    if row is None or row.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "document not found")
    audit.record(session, action="document.delete", object_type="document",
                 object_id=str(row.id),
                 **_actor(request, principal), changes=audit.diff({"filename": row.filename}, None))
    session.delete(row)
    session.commit()


# --------------------------------------------------------------------------
# Threat intelligence
# --------------------------------------------------------------------------


@router.get("/intel/sources", response_model=list[ThreatSourceOut], summary="List feeds")
def list_sources(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("intel:read"))],
) -> list[ThreatSourceOut]:
    rows = session.execute(
        select(ThreatSource).where(
            ThreatSource.organization_id == principal.organization_id
        ).order_by(ThreatSource.name)
    ).scalars().all()
    return [ThreatSourceOut.model_validate(r) for r in rows]


@router.post("/intel/sources", response_model=ThreatSourceOut,
             status_code=status.HTTP_201_CREATED, summary="Register a feed")
def create_source(
    payload: ThreatSourceWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("intel:write"))],
) -> ThreatSourceOut:
    if session.execute(
        select(ThreatSource).where(
            ThreatSource.organization_id == principal.organization_id,
            ThreatSource.slug == payload.slug,
        )
    ).scalars().first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "slug already exists")
    row = ThreatSource(organization_id=principal.organization_id, **payload.model_dump())
    session.add(row)
    session.commit()
    session.refresh(row)
    return ThreatSourceOut.model_validate(row)


@router.post("/intel/articles", status_code=status.HTTP_202_ACCEPTED,
             summary="Ingest feed entries")
def ingest_articles(
    payload: ArticleIngest,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("intel:write"))],
) -> dict:
    source = None
    if payload.source_slug:
        source = session.execute(
            select(ThreatSource).where(
                ThreatSource.organization_id == principal.organization_id,
                ThreatSource.slug == payload.source_slug,
            )
        ).scalars().first()
        if source is None:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "source not found")
    stats = threatintel.ingest_articles(
        session, principal.organization_id, source, payload.entries
    )
    session.commit()
    return stats


@router.get("/intel/news", summary="Relevance-ordered intelligence digest")
def news(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("intel:read"))],
    days: int = Query(default=7, ge=1, le=365),
    limit: int = Query(default=50, ge=1, le=200),
) -> dict:
    items = threatintel.feed_digest(
        session, principal.organization_id, days=days, limit=limit
    )
    return {"days": days, "count": len(items),
            "relevant": len([i for i in items if i["is_relevant"]]), "items": items}


# --------------------------------------------------------------------------
# Knowledge base
# --------------------------------------------------------------------------


@router.get("/knowledge", response_model=Page[KnowledgeOut], summary="List articles")
def list_articles(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("knowledge:read"))],
    kind: str | None = None,
    tag: str | None = None,
    cve_id: str | None = None,
    published_only: bool = True,
    page: int = Query(default=1, ge=1),
    size: int = Query(default=50, ge=1, le=200),
) -> Page[KnowledgeOut]:
    stmt = select(KnowledgeArticle).where(
        KnowledgeArticle.organization_id == principal.organization_id
    )
    if kind:
        stmt = stmt.where(KnowledgeArticle.kind == kind)
    if tag:
        stmt = stmt.where(KnowledgeArticle.tags.contains([tag]))
    if cve_id:
        stmt = stmt.where(KnowledgeArticle.cve_ids.contains([cve_id.upper()]))
    if published_only:
        stmt = stmt.where(KnowledgeArticle.is_published.is_(True))

    rows = session.execute(stmt.order_by(KnowledgeArticle.title)).scalars().all()
    # Article-level permissions are applied server-side, then paginated, so the
    # count the caller sees matches what they may actually open.
    visible = [
        r for r in rows
        if threatintel.visible_to(r, set(principal.permissions), principal.is_superuser)
    ]
    start = (page - 1) * size
    return Page.of([KnowledgeOut.model_validate(r) for r in visible[start:start + size]], len(visible), page, size)


@router.post("/knowledge", response_model=KnowledgeDetail,
             status_code=status.HTTP_201_CREATED, summary="Create an article")
def create_article(
    payload: KnowledgeWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("knowledge:write"))],
) -> KnowledgeDetail:
    data = payload.model_dump(exclude={"change_note"})
    slug = data.pop("slug", None) or threatintel.slugify(payload.title)
    if session.execute(
        select(KnowledgeArticle).where(
            KnowledgeArticle.organization_id == principal.organization_id,
            KnowledgeArticle.slug == slug,
        )
    ).scalars().first() is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, "slug already exists")
    article = threatintel.create_article(
        session, principal.organization_id, slug=slug,
        author_id=principal.user_id, **data,
    )
    session.commit()
    session.refresh(article)
    return _article_detail(session, article)


def _article_detail(session, article: KnowledgeArticle) -> KnowledgeDetail:
    # Validate the flat fields only. KnowledgeDetail.revisions is a list of
    # plain dicts, but the ORM object carries a `revisions` relationship of
    # KnowledgeRevision rows; validating the article directly made Pydantic
    # try to coerce those ORM objects into dicts and raise before this
    # function ever got the chance to replace them.
    revisions = session.execute(
        select(KnowledgeRevision).where(KnowledgeRevision.article_id == article.id)
        .order_by(KnowledgeRevision.version.desc())
    ).scalars().all()
    base = KnowledgeOut.model_validate(article)
    return KnowledgeDetail(
        **base.model_dump(),
        body=article.body,
        revisions=[{
            "version": r.version, "at": r.created_at.isoformat(),
            "change_note": r.change_note, "title": r.title,
        } for r in revisions],
    )


@router.get("/knowledge/{article_id}", response_model=KnowledgeDetail, summary="Article detail")
def get_article(
    article_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("knowledge:read"))],
) -> KnowledgeDetail:
    article = session.get(KnowledgeArticle, article_id)
    if article is None or article.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "article not found")
    if not threatintel.visible_to(article, set(principal.permissions), principal.is_superuser):
        # 404 rather than 403: existence itself can be sensitive.
        raise HTTPException(status.HTTP_404_NOT_FOUND, "article not found")
    article.view_count += 1
    session.commit()
    return _article_detail(session, article)


@router.patch("/knowledge/{article_id}", response_model=KnowledgeDetail,
              summary="Update an article (versioned)")
def update_article(
    article_id: uuid.UUID,
    payload: KnowledgeWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("knowledge:write"))],
) -> KnowledgeDetail:
    article = session.get(KnowledgeArticle, article_id)
    if article is None or article.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "article not found")
    data = payload.model_dump(exclude={"slug", "change_note"})
    threatintel.update_article(
        session, article, author_id=principal.user_id,
        change_note=payload.change_note, **data,
    )
    session.commit()
    session.refresh(article)
    return _article_detail(session, article)


@router.get("/knowledge/{article_id}/revisions/{version}", summary="Read a past revision")
def get_revision(
    article_id: uuid.UUID,
    version: int,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("knowledge:read"))],
) -> dict:
    row = session.execute(
        select(KnowledgeRevision).where(
            KnowledgeRevision.article_id == article_id,
            KnowledgeRevision.version == version,
            KnowledgeRevision.organization_id == principal.organization_id,
        )
    ).scalars().first()
    if row is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "revision not found")
    return {"version": row.version, "title": row.title, "body": row.body,
            "at": row.created_at.isoformat(), "change_note": row.change_note}


# --------------------------------------------------------------------------
# Search
# --------------------------------------------------------------------------


@router.get("/search", summary="Global search across the graph")
def global_search(
    session: TenantSession,
    principal: CurrentPrincipal,
    q: str = Query(min_length=1, max_length=200),
    types: str | None = Query(default=None, description="Comma-separated entity types"),
    limit_per_type: int = Query(default=10, ge=1, le=50),
) -> dict:
    return search_service.search(
        session, principal.organization_id, q,
        permissions=principal.permissions, is_superuser=principal.is_superuser,
        types=[t.strip() for t in types.split(",")] if types else None,
        limit_per_type=limit_per_type,
    )


@router.get("/search/semantic", summary="Semantic search (falls back to lexical)")
def semantic(
    session: TenantSession,
    principal: CurrentPrincipal,
    q: str = Query(min_length=1, max_length=500),
    limit: int = Query(default=10, ge=1, le=50),
) -> dict:
    return search_service.semantic_search(
        session, principal.organization_id, q,
        permissions=principal.permissions, is_superuser=principal.is_superuser,
        limit=limit,
    )


# ---------------------------------------------------------------------------
# Publishing a runbook into Confluence (phase 44)
# ---------------------------------------------------------------------------
def _publication_out(session, link) -> dict[str, Any]:
    from ...models import ItsmConnector

    connector = session.get(ItsmConnector, link.connector_id)
    return {
        "id": str(link.id),
        "connector_id": str(link.connector_id),
        "connector_name": connector.name if connector is not None else None,
        "system": connector.system if connector is not None else None,
        "space_key": link.remote_key,
        "page_id": link.remote_id,
        "url": link.remote_url,
        "remote_version": link.remote_status,
        "title": link.summary,
        "published_at": link.last_pushed_at,
        "first_published_at": link.remote_created_at,
        "is_active": link.is_active,
        "last_error": link.last_error,
    }


@router.post("/knowledge/{article_id}/publish", summary="Publish an article to the wiki")
def publish_article(
    article_id: uuid.UUID,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("knowledge:write"))],
    connector_id: uuid.UUID | None = None,
) -> dict[str, Any]:
    """One-way, idempotent, and VEYRS stays the system of record.

    Nothing is ever pulled back from Confluence. A wiki page anybody can edit
    is not a source of truth for a security procedure -- if it were, "who
    changed the remediation steps for CVE-2023-44487?" would have no answer,
    which is precisely the question a runbook exists to make answerable. The
    published page carries a footer saying so, so the first person to edit it
    there knows they are editing a mirror.

    Re-publishing an unchanged article is a no-op by digest: without that, a
    scheduled publish would put hundreds of empty revisions into the page's
    history and bury its real edits.

    `connector_id` is optional; with one documentation connector configured it
    is unambiguous, and naming it is only needed for a second space.
    """
    from ...models import ItsmConnector
    from ...services import docs as docs_service

    article = session.get(KnowledgeArticle, article_id)
    if article is None or article.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "article not found")

    stmt = select(ItsmConnector).where(
        ItsmConnector.organization_id == principal.organization_id,
        ItsmConnector.system.in_(tuple(docs_service.DOCS_SYSTEMS)),
    ).order_by(ItsmConnector.slug)
    if connector_id is not None:
        stmt = stmt.where(ItsmConnector.id == connector_id)
    candidates = session.execute(stmt).scalars().all()
    if not candidates:
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "no Confluence connector is configured for this organization; add "
            "one under Integrations -> Documentation")
    if connector_id is None and len(candidates) > 1:
        # Refused rather than resolved by picking the first row. Publishing a
        # runbook into the wrong space is not something an operator finds out
        # about quickly.
        raise HTTPException(
            status.HTTP_409_CONFLICT,
            "more than one documentation connector exists; name the one to "
            "publish to with ?connector_id=")
    connector = candidates[0]

    try:
        link = docs_service.publish_article(session, connector, article)
    except docs_service.ItsmError as exc:
        # 502: VEYRS is fine, the wiki refused or could not be reached. A 500
        # here would send the operator to read OUR logs.
        session.commit()          # keep `last_error` on the connector row
        raise HTTPException(status.HTTP_502_BAD_GATEWAY, str(exc)) from exc

    audit.record(session, action="knowledge.published", object_type="knowledge_article",
                 object_id=str(article.id), object_label=article.slug,
                 changes={"connector": connector.slug, "page_id": link.remote_id,
                          "version": article.version},
                 **_actor(request, principal))
    session.commit()
    session.refresh(link)
    return _publication_out(session, link)


@router.get("/knowledge/{article_id}/publications",
            summary="Where this article has been published")
def article_publications(
    article_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("knowledge:read"))],
) -> list[dict[str, Any]]:
    from ...models.integration import ExternalLink

    article = session.get(KnowledgeArticle, article_id)
    if article is None or article.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "article not found")
    rows = session.execute(
        select(ExternalLink).where(
            ExternalLink.organization_id == principal.organization_id,
            ExternalLink.object_type == "knowledge",
            ExternalLink.object_id == str(article.id),
        ).order_by(ExternalLink.created_at.desc())
    ).scalars().all()
    return [_publication_out(session, link) for link in rows]


@router.get("/knowledge-publishing", summary="Is wiki publishing configured?")
def publishing_state(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("knowledge:read"))],
) -> dict[str, Any]:
    """What the console needs to decide whether to draw a Publish button.

    `ready` means a connector exists AND carries a credential AND names a
    space -- not merely that a row exists. The phase 42 lesson: a source
    created disabled and with no token reported `ready: true`, and pressing the
    button surfaced the remote's bare 403, which reads as "the wiki is broken"
    rather than "you never gave VEYRS a token".
    """
    from ...models import ItsmConnector
    from ...services import docs as docs_service

    rows = session.execute(
        select(ItsmConnector).where(
            ItsmConnector.organization_id == principal.organization_id,
            ItsmConnector.system.in_(tuple(docs_service.DOCS_SYSTEMS)),
        ).order_by(ItsmConnector.slug)
    ).scalars().all()
    items = [{
        "id": str(c.id), "slug": c.slug, "name": c.name, "system": c.system,
        "base_url": c.base_url, "is_enabled": c.is_enabled,
        "credentials_set": bool(c.credentials_enc),
        "space_key": (c.field_mapping or {}).get("space_key"),
        "usable": bool(c.credentials_enc) and bool((c.field_mapping or {}).get("space_key")),
        "last_error": c.last_error,
    } for c in rows]
    return {
        "ready": any(i["usable"] for i in items),
        "connectors": items,
        "supported_markdown": docs_service.SUPPORTED_MARKDOWN,
    }
