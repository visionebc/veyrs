"""AI gateway, assistant and natural-language search endpoints (spec 19/20).

Authorization note that applies to every route here: the `require(...)` on the
decorator is the *route* gate, and `gateway.invoke()` independently re-checks
the capability's own permission against the live principal. Two checks, because
a future refactor that loosens a decorator must not silently loosen what the AI
can reach.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated, Any

from fastapi import APIRouter, Depends, HTTPException, Query, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from ...models import (
    AiCapability, AiConversation, AiMessage, AiPolicy, AiProvider, CAPABILITY_PERMISSION,
    Finding,
)
from ...models.audit import AiAuditLog
from ...security.deps import CurrentPrincipal, Principal, TenantSession, require
from ...security.secrets import encrypt, mask, try_decrypt
from ...services import audit
from ...services.ai import capabilities, gateway, guardrails, nlquery
from .schemas import Page

router = APIRouter(prefix="/ai", tags=["ai"])


# ---------------------------------------------------------------------------
# Schemas
# ---------------------------------------------------------------------------
class PolicyOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    allow_external: bool
    allow_local: bool
    allowed_providers: list[str]
    allowed_models: list[str]
    max_external_classification: str
    max_local_classification: str
    redact_secrets: bool
    redact_pii: bool
    block_on_injection: bool
    disabled_capabilities: list[str]
    max_prompt_chars: int
    daily_call_limit: int


class PolicyWrite(BaseModel):
    allow_external: bool | None = None
    allow_local: bool | None = None
    allowed_providers: list[str] | None = None
    allowed_models: list[str] | None = None
    max_external_classification: str | None = None
    max_local_classification: str | None = None
    redact_secrets: bool | None = None
    redact_pii: bool | None = None
    block_on_injection: bool | None = None
    disabled_capabilities: list[str] | None = None
    max_prompt_chars: int | None = Field(default=None, ge=500, le=200_000)
    daily_call_limit: int | None = Field(default=None, ge=0, le=1_000_000)


class ProviderOut(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    slug: str
    name: str
    kind: str
    base_url: str | None
    model: str
    is_external: bool
    is_enabled: bool
    is_default: bool
    capabilities: list[str]
    last_error: str | None
    last_used_at: dt.datetime | None


class ProviderDetail(ProviderOut):
    api_key_masked: str = ""


class ProviderWrite(BaseModel):
    slug: str = Field(min_length=1, max_length=60)
    name: str = Field(min_length=1, max_length=160)
    kind: str
    model: str = Field(min_length=1, max_length=160)
    base_url: str | None = None
    api_key: str | None = None
    is_external: bool
    is_enabled: bool = True
    is_default: bool = False
    capabilities: list[str] = Field(default_factory=list)
    timeout_seconds: int = Field(default=60, ge=1, le=600)
    temperature: float = Field(default=0.1, ge=0.0, le=2.0)
    max_output_tokens: int = Field(default=1500, ge=64, le=32_000)


class AskRequest(BaseModel):
    question: str = Field(min_length=1, max_length=4000)
    conversation_id: uuid.UUID | None = None
    locale: str = "en"


class NlSearchRequest(BaseModel):
    question: str = Field(min_length=1, max_length=1000)


class AiAnswer(BaseModel):
    text: str
    decision: str
    provider: str
    model: str
    external: bool
    degraded: bool
    block_reason: str | None = None
    citations: list[dict] = Field(default_factory=list)
    redactions: dict = Field(default_factory=dict)
    facts: dict[str, Any] = Field(default_factory=dict)


VALID_KINDS = ("deterministic", "openai", "openai_compatible", "anthropic", "gemini", "ollama")
VALID_CLASSIFICATIONS = ("public", "internal", "confidential", "restricted")


def _answer(result, facts: dict | None = None) -> AiAnswer:
    return AiAnswer(
        text=result.text, decision=result.decision, provider=result.provider,
        model=result.model, external=result.external, degraded=result.degraded,
        block_reason=result.block_reason, citations=result.citations,
        redactions=result.redactions, facts=facts or {},
    )


# ---------------------------------------------------------------------------
# Policy administration
# ---------------------------------------------------------------------------
@router.get("/policy", response_model=PolicyOut)
def read_policy(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ai:read"))],
) -> PolicyOut:
    return PolicyOut.model_validate(gateway.get_policy(session, principal.organization_id))


@router.put("/policy", response_model=PolicyOut)
def write_policy(
    payload: PolicyWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ai:admin"))],
) -> PolicyOut:
    for field in ("max_external_classification", "max_local_classification"):
        value = getattr(payload, field)
        if value is not None and value not in VALID_CLASSIFICATIONS:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"{field} must be one of {list(VALID_CLASSIFICATIONS)}")
    if payload.disabled_capabilities is not None:
        unknown = set(payload.disabled_capabilities) - set(CAPABILITY_PERMISSION)
        if unknown:
            raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                                f"unknown capabilities: {sorted(unknown)}")

    policy = session.execute(
        select(AiPolicy).where(AiPolicy.organization_id == principal.organization_id)
    ).scalar_one_or_none()
    created = policy is None
    if created:
        policy = gateway.get_policy(session, principal.organization_id)
        session.add(policy)

    before = policy.as_dict(exclude={"id", "organization_id", "created_at", "updated_at"})
    for field, value in payload.model_dump(exclude_unset=True).items():
        if value is not None:
            setattr(policy, field, value)
    session.flush()

    audit.record(
        session, action="ai.policy.updated" if not created else "ai.policy.created",
        object_type="ai_policy", object_id=policy.id,
        organization_id=principal.organization_id, actor_id=principal.user_id,
        actor_label=principal.label,
        changes=audit.diff(before, policy.as_dict(
            exclude={"id", "organization_id", "created_at", "updated_at"})),
    )
    session.commit()
    return PolicyOut.model_validate(policy)


# ---------------------------------------------------------------------------
# Providers
# ---------------------------------------------------------------------------
@router.get("/providers", response_model=list[ProviderDetail])
def list_providers(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ai:read"))],
) -> list[ProviderDetail]:
    rows = session.execute(
        select(AiProvider)
        .where(AiProvider.organization_id == principal.organization_id)
        .order_by(AiProvider.is_default.desc(), AiProvider.slug)
    ).scalars().all()
    out = []
    for row in rows:
        detail = ProviderDetail.model_validate(row)
        detail.api_key_masked = mask(try_decrypt(row.api_key_enc))
        out.append(detail)
    return out


@router.post("/providers", response_model=ProviderOut, status_code=status.HTTP_201_CREATED)
def create_provider(
    payload: ProviderWrite,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ai:admin"))],
) -> ProviderOut:
    if payload.kind not in VALID_KINDS:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"kind must be one of {list(VALID_KINDS)}")
    unknown = set(payload.capabilities) - set(CAPABILITY_PERMISSION)
    if unknown:
        raise HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY,
                            f"unknown capabilities: {sorted(unknown)}")
    exists = session.execute(
        select(AiProvider).where(AiProvider.organization_id == principal.organization_id,
                                 AiProvider.slug == payload.slug)
    ).scalar_one_or_none()
    if exists is not None:
        raise HTTPException(status.HTTP_409_CONFLICT, f"provider {payload.slug!r} already exists")

    if payload.is_default:
        _clear_default(session, principal.organization_id)

    data = payload.model_dump(exclude={"api_key"})
    provider = AiProvider(
        organization_id=principal.organization_id,
        api_key_enc=encrypt(payload.api_key),
        **data,
    )
    session.add(provider)
    session.flush()
    audit.record(
        session, action="ai.provider.created", object_type="ai_provider",
        object_id=provider.id, object_label=provider.slug,
        organization_id=principal.organization_id, actor_id=principal.user_id,
        actor_label=principal.label,
        changes={"kind": provider.kind, "model": provider.model,
                 "is_external": provider.is_external},
    )
    session.commit()
    return ProviderOut.model_validate(provider)


@router.delete("/providers/{provider_id}", status_code=204, response_model=None,
               response_class=Response)
def delete_provider(
    provider_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ai:admin"))],
) -> None:
    provider = session.get(AiProvider, provider_id)
    if provider is None or provider.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "provider not found")
    audit.record(
        session, action="ai.provider.deleted", object_type="ai_provider",
        object_id=provider.id, object_label=provider.slug,
        organization_id=principal.organization_id, actor_id=principal.user_id,
        actor_label=principal.label,
    )
    session.delete(provider)
    session.commit()


def _clear_default(session, organization_id: uuid.UUID) -> None:
    for row in session.execute(
        select(AiProvider).where(AiProvider.organization_id == organization_id,
                                 AiProvider.is_default.is_(True))
    ).scalars().all():
        row.is_default = False


# ---------------------------------------------------------------------------
# Capability endpoints
# ---------------------------------------------------------------------------
@router.get("/capabilities")
def list_capabilities(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ai:read"))],
) -> dict[str, Any]:
    """What this caller can actually use right now, and why not otherwise."""
    policy = gateway.get_policy(session, principal.organization_id)
    disabled = set(policy.disabled_capabilities or [])
    out = []
    for capability in AiCapability:
        needed = CAPABILITY_PERMISSION[capability.value]
        reasons = []
        if capability.value in disabled:
            reasons.append("disabled by organization policy")
        if not principal.can(needed):
            reasons.append(f"requires {needed}")
        out.append({
            "capability": capability.value,
            "permission": needed,
            "available": not reasons,
            "reasons": reasons,
        })
    provider, reason = gateway.select_provider(
        session, principal.organization_id, policy, AiCapability.ASSISTANT.value, "internal"
    )
    return {
        "capabilities": out,
        "provider": provider.slug if provider else None,
        "provider_available": provider is not None,
        "provider_reason": reason or None,
        "degraded": provider is None,
    }


@router.post("/cve/{cve_id}/analysis", response_model=AiAnswer)
def analyze_cve(
    cve_id: str,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("cve:read"))],
    locale: str = Query(default="en"),
) -> AiAnswer:
    facts, result = capabilities.analyze_cve(
        session, organization_id=principal.organization_id, cve_id=cve_id,
        permissions=principal.permissions, is_superuser=principal.is_superuser,
        user_id=principal.user_id, locale=locale,
    )
    session.commit()
    return _answer(result, facts)


@router.post("/findings/{finding_id}/explain", response_model=AiAnswer)
def explain_finding_risk(
    finding_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("risk:read"))],
    locale: str = Query(default="en"),
) -> AiAnswer:
    finding = _get_finding(session, principal, finding_id)
    facts, result = capabilities.explain_risk(
        session, organization_id=principal.organization_id, finding=finding,
        permissions=principal.permissions, is_superuser=principal.is_superuser,
        user_id=principal.user_id, locale=locale,
    )
    session.commit()
    return _answer(result, facts)


@router.post("/findings/{finding_id}/remediation", response_model=AiAnswer)
def recommend_remediation(
    finding_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:read"))],
    locale: str = Query(default="en"),
) -> AiAnswer:
    finding = _get_finding(session, principal, finding_id)
    facts, result = capabilities.recommend_remediation(
        session, organization_id=principal.organization_id, finding=finding,
        permissions=principal.permissions, is_superuser=principal.is_superuser,
        user_id=principal.user_id, locale=locale,
    )
    session.commit()
    return _answer(result, facts)


@router.post("/findings/{finding_id}/ticket-draft")
def draft_ticket(
    finding_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ticket:write"))],
    locale: str = Query(default="en"),
) -> dict[str, Any]:
    finding = _get_finding(session, principal, finding_id)
    draft, result = capabilities.draft_ticket(
        session, organization_id=principal.organization_id, finding=finding,
        permissions=principal.permissions, is_superuser=principal.is_superuser,
        user_id=principal.user_id, locale=locale,
    )
    session.commit()
    # Explicitly a DRAFT: the caller must POST /tickets to create anything.
    return {"draft": draft, "ai": _answer(result).model_dump()}


@router.post("/findings/{finding_id}/suggest-team")
def suggest_team(
    finding_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:read"))],
) -> dict[str, Any]:
    finding = _get_finding(session, principal, finding_id)
    suggestion, result = capabilities.suggest_team(
        session, organization_id=principal.organization_id, finding=finding,
        permissions=principal.permissions, is_superuser=principal.is_superuser,
        user_id=principal.user_id,
    )
    session.commit()
    return {"suggestion": suggestion, "ai": _answer(result).model_dump()}


@router.post("/threat-summary", response_model=AiAnswer)
def threat_summary(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("intel:read"))],
    days: int = Query(default=7, ge=1, le=90),
    locale: str = Query(default="en"),
) -> AiAnswer:
    facts, result = capabilities.summarize_threats(
        session, organization_id=principal.organization_id, days=days,
        permissions=principal.permissions, is_superuser=principal.is_superuser,
        user_id=principal.user_id, locale=locale,
    )
    session.commit()
    return _answer(result, facts)


@router.post("/search")
def natural_language_search(
    payload: NlSearchRequest,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ai:read"))],
) -> dict[str, Any]:
    out = capabilities.natural_language_search(
        session, organization_id=principal.organization_id, question=payload.question,
        permissions=principal.permissions, is_superuser=principal.is_superuser,
        user_id=principal.user_id,
    )
    session.commit()
    return out


@router.get("/search/grammar")
def search_grammar(
    principal: Annotated[Principal, Depends(require("ai:read"))],
) -> dict[str, Any]:
    """The closed query grammar, so the UI can offer it and users can verify it."""
    return {
        "fields": {
            name: {"kind": spec.kind, "operators": list(spec.operators),
                   "values": list(spec.values)}
            for name, spec in nlquery.FIELDS.items()
        },
        "sortable": list(nlquery.SORTABLE),
        "max_filters": nlquery.MAX_FILTERS,
        "max_limit": nlquery.MAX_LIMIT,
    }


# ---------------------------------------------------------------------------
# Assistant conversations
# ---------------------------------------------------------------------------
@router.post("/ask", response_model=AiAnswer)
def ask(
    payload: AskRequest,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ai:read"))],
) -> AiAnswer:
    """Free-form assistant turn, grounded in permission-aware search results."""
    from ...services import search as search_service

    conversation = _resolve_conversation(session, principal, payload)

    grounding = search_service.search(
        session, principal.organization_id, payload.question,
        permissions=principal.permissions, is_superuser=principal.is_superuser,
        limit_per_type=5,
    )
    facts, citations = _render_grounding(grounding)

    session.add(AiMessage(
        organization_id=principal.organization_id, conversation_id=conversation.id,
        role="user", content=payload.question[:8000],
    ))

    result = gateway.invoke(
        session, organization_id=principal.organization_id,
        request=gateway.AiRequest(
            capability=AiCapability.ASSISTANT.value,
            prompt=(
                "Answer the analyst's question using only the VEYRS records "
                "below. If they do not contain the answer, say what is missing "
                "and suggest which VEYRS page would have it.\n\n"
                f"Question: {payload.question}"
            ),
            facts=facts,
            classification="confidential",
            locale=payload.locale,
            citations=citations,
        ),
        permissions=principal.permissions, is_superuser=principal.is_superuser,
        user_id=principal.user_id,
    )

    session.add(AiMessage(
        organization_id=principal.organization_id, conversation_id=conversation.id,
        role="assistant", content=result.text or (result.block_reason or ""),
        citations=result.citations, provider=result.provider, model=result.model,
        blocked=result.blocked, block_reason=result.block_reason,
        redactions=result.redactions, duration_ms=result.duration_ms,
    ))
    session.commit()
    return _answer(result)


def _resolve_conversation(session, principal: Principal, payload: AskRequest) -> AiConversation:
    if payload.conversation_id is not None:
        conversation = session.get(AiConversation, payload.conversation_id)
        if conversation is None or conversation.organization_id != principal.organization_id:
            raise HTTPException(status.HTTP_404_NOT_FOUND, "conversation not found")
        if conversation.user_id not in (None, principal.user_id) and not principal.is_superuser:
            # Threads are private to their author: another user's questions can
            # reveal what they were investigating.
            raise HTTPException(status.HTTP_403_FORBIDDEN, "not your conversation")
        return conversation
    conversation = AiConversation(
        organization_id=principal.organization_id, user_id=principal.user_id,
        title=payload.question[:200], locale=payload.locale,
        permission_snapshot=sorted(principal.permissions),
    )
    session.add(conversation)
    session.flush()
    return conversation


def _render_grounding(grounding: dict[str, Any]) -> tuple[str, list[dict]]:
    lines: list[str] = []
    citations: list[dict] = []
    for entity, rows in (grounding.get("results") or {}).items():
        if not rows:
            continue
        lines.append(f"{entity.upper()}:")
        for row in rows[:5]:
            label = row.get("title") or row.get("name") or row.get("cve_id") or row.get("id")
            lines.append(f"  - {label}")
            citations.append({"type": entity, "id": str(row.get("id"))})
    if not lines:
        lines.append("(no matching VEYRS records for this question)")
    return "\n".join(lines), citations


@router.get("/conversations", response_model=Page[dict])
def list_conversations(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ai:read"))],
    limit: int = Query(default=50, ge=1, le=200),
    offset: int = Query(default=0, ge=0),
) -> Page[dict]:
    statement = select(AiConversation).where(
        AiConversation.organization_id == principal.organization_id
    )
    if not principal.is_superuser:
        statement = statement.where(AiConversation.user_id == principal.user_id)
    rows = session.execute(
        statement.order_by(AiConversation.updated_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return Page(
        items=[{"id": str(c.id), "title": c.title, "locale": c.locale,
                "created_at": c.created_at.isoformat(),
                "updated_at": c.updated_at.isoformat()} for c in rows],
        total=len(rows), limit=limit, offset=offset,
    )


@router.get("/conversations/{conversation_id}")
def read_conversation(
    conversation_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("ai:read"))],
) -> dict[str, Any]:
    conversation = session.get(AiConversation, conversation_id)
    if conversation is None or conversation.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "conversation not found")
    if conversation.user_id not in (None, principal.user_id) and not principal.is_superuser:
        raise HTTPException(status.HTTP_403_FORBIDDEN, "not your conversation")
    return {
        "id": str(conversation.id),
        "title": conversation.title,
        "locale": conversation.locale,
        "messages": [
            {"role": m.role, "content": m.content, "citations": m.citations,
             "provider": m.provider, "model": m.model, "blocked": m.blocked,
             "created_at": m.created_at.isoformat()}
            for m in conversation.messages
        ],
    }


# ---------------------------------------------------------------------------
# AI audit trail
# ---------------------------------------------------------------------------
@router.get("/audit", response_model=Page[dict])
def ai_audit(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("audit:read"))],
    decision: str | None = Query(default=None),
    limit: int = Query(default=100, ge=1, le=500),
    offset: int = Query(default=0, ge=0),
) -> Page[dict]:
    statement = select(AiAuditLog).where(
        AiAuditLog.organization_id == principal.organization_id
    )
    if decision:
        statement = statement.where(AiAuditLog.decision == decision)
    rows = session.execute(
        statement.order_by(AiAuditLog.created_at.desc()).limit(limit).offset(offset)
    ).scalars().all()
    return Page(
        items=[r.as_dict() for r in rows], total=len(rows), limit=limit, offset=offset
    )


@router.post("/scan")
def scan_text(
    payload: dict,
    principal: Annotated[Principal, Depends(require("ai:read"))],
) -> dict[str, Any]:
    """Dry-run the guardrails on arbitrary text.

    Operators use this to answer "would this document be allowed out?" before
    enabling an external provider. Returns the report only -- never the
    redacted text, so the endpoint cannot be used as a redaction oracle to
    confirm a guessed secret.
    """
    text = str(payload.get("text") or "")[:100_000]
    scan = guardrails.sanitize(text)
    return {
        "report": scan.report,
        "has_secrets": scan.has_secrets,
        "has_pii": scan.has_pii,
        "injection_score": scan.injection_score,
        "injection_detected": scan.injection_detected,
        "would_block": scan.injection_detected,
    }


def _get_finding(session, principal: Principal, finding_id: uuid.UUID) -> Finding:
    finding = session.get(Finding, finding_id)
    if finding is None or finding.organization_id != principal.organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "finding not found")
    return finding
