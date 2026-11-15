"""AI gateway configuration and conversation state (spec sections 19 and 20).

The design rule that shapes every table here: **AI is a client of VEYRS, never a
privileged path into it**. Concretely that means

* the per-tenant `AiPolicy` decides which providers/models may be used at all
  and what data classification may leave the perimeter -- an administrator
  setting, not a code constant;
* conversations record the *permissions snapshot* of the asking principal, so a
  later re-read of a thread cannot surface rows the reader may no longer see;
* every call is written to `ai_audit_log` (models/audit.py) before the answer is
  returned, including calls that were BLOCKED. A blocked call that leaves no
  trace is indistinguishable from a call that never happened.
"""
from __future__ import annotations

import datetime as dt
import enum
import uuid

from sqlalchemy import (
    Boolean, DateTime, Float, ForeignKey, Index, Integer, String, Text, UniqueConstraint,
)
from sqlalchemy.dialects.postgresql import JSONB, UUID as PgUUID
from sqlalchemy.orm import Mapped, mapped_column, relationship

from .assets import DataClassification
from .base import Base, TenantMixin, TimestampMixin, uuid_pk

# Classification is ONE concept in VEYRS: the label on an asset and the label on
# a prompt payload are the same ladder, so the enum is imported rather than
# redefined. A second copy would drift and the drift would be a data-leak bug.
CLASSIFICATION_RANK: dict[str, int] = {
    DataClassification.PUBLIC.value: 0,
    DataClassification.INTERNAL.value: 1,
    DataClassification.CONFIDENTIAL.value: 2,
    DataClassification.RESTRICTED.value: 3,
}


class AiCapability(str, enum.Enum):
    """The closed set of things AI may be asked to do.

    A capability that is not on this list cannot be invoked, which is what keeps
    "the assistant" from becoming an arbitrary code path with a model behind it.
    """

    CVE_ANALYSIS = "cve_analysis"
    ADVISORY_ANALYSIS = "advisory_analysis"
    DOCUMENT_ANALYSIS = "document_analysis"
    RISK_EXPLANATION = "risk_explanation"
    REMEDIATION_ADVICE = "remediation_advice"
    TICKET_DRAFT = "ticket_draft"
    ARTICLE_DRAFT = "article_draft"
    THREAT_SUMMARY = "threat_summary"
    NL_SEARCH = "nl_search"
    CLASSIFY_VULNERABILITY = "classify_vulnerability"
    CLASSIFY_PRODUCT = "classify_product"
    SUGGEST_TEAM = "suggest_team"
    ASSISTANT = "assistant"


#: Capability -> the VEYRS permission a caller must already hold.
#: The AI never widens authority: asking a model to explain a risk requires the
#: same `risk:read` a human needs to open the risk page.
CAPABILITY_PERMISSION: dict[str, str] = {
    AiCapability.CVE_ANALYSIS.value: "cve:read",
    AiCapability.ADVISORY_ANALYSIS.value: "intel:read",
    AiCapability.DOCUMENT_ANALYSIS.value: "document:read",
    AiCapability.RISK_EXPLANATION.value: "risk:read",
    AiCapability.REMEDIATION_ADVICE.value: "finding:read",
    AiCapability.TICKET_DRAFT.value: "ticket:write",
    AiCapability.ARTICLE_DRAFT.value: "knowledge:write",
    AiCapability.THREAT_SUMMARY.value: "intel:read",
    AiCapability.NL_SEARCH.value: "ai:read",
    AiCapability.CLASSIFY_VULNERABILITY.value: "vulnerability:read",
    AiCapability.CLASSIFY_PRODUCT.value: "product:read",
    AiCapability.SUGGEST_TEAM.value: "finding:read",
    AiCapability.ASSISTANT.value: "ai:read",
}


class AiPolicy(Base, TenantMixin, TimestampMixin):
    """One row per organization. Absent row == the restrictive defaults below."""

    __tablename__ = "ai_policies"
    __table_args__ = (UniqueConstraint("organization_id"),)

    id: Mapped[uuid.UUID] = uuid_pk()

    # Master switches. `allow_external` off means nothing ever leaves the
    # perimeter regardless of what a provider row says -- the deny is evaluated
    # at the gateway, not at the provider.
    allow_external: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    allow_local: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)

    # Allow-lists. Empty list means "no restriction beyond the switches above";
    # a non-empty list is authoritative.
    allowed_providers: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    allowed_models: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    #: Highest classification permitted to reach an EXTERNAL provider.
    max_external_classification: Mapped[str] = mapped_column(
        String(20), default=DataClassification.PUBLIC.value, nullable=False
    )
    #: Highest classification permitted to reach a LOCAL provider.
    max_local_classification: Mapped[str] = mapped_column(
        String(20), default=DataClassification.RESTRICTED.value, nullable=False
    )

    # Guardrails
    redact_secrets: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    redact_pii: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    block_on_injection: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    #: Disabled capability slugs (subset of AiCapability values).
    disabled_capabilities: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)

    # Cost / abuse control
    max_prompt_chars: Mapped[int] = mapped_column(Integer, default=24000, nullable=False)
    daily_call_limit: Mapped[int] = mapped_column(Integer, default=2000, nullable=False)

    notes: Mapped[str | None] = mapped_column(Text, default=None)


class AiProvider(Base, TenantMixin, TimestampMixin):
    """A configured model endpoint.

    `is_external` is a property of the *endpoint*, decided by an administrator,
    not sniffed from the URL: a self-hosted gateway in front of OpenAI is still
    external, and an on-prem Ollama on a public IP is still internal.
    """

    __tablename__ = "ai_providers"
    __table_args__ = (
        UniqueConstraint("organization_id", "slug"),
        Index("ix_ai_providers_org_enabled", "organization_id", "is_enabled"),
    )

    id: Mapped[uuid.UUID] = uuid_pk()
    slug: Mapped[str] = mapped_column(String(60), nullable=False)
    name: Mapped[str] = mapped_column(String(160), nullable=False)
    #: openai | anthropic | gemini | ollama | openai_compatible | deterministic
    kind: Mapped[str] = mapped_column(String(40), nullable=False)
    base_url: Mapped[str | None] = mapped_column(String(500), default=None)
    model: Mapped[str] = mapped_column(String(160), nullable=False)
    is_external: Mapped[bool] = mapped_column(Boolean, nullable=False)
    is_enabled: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    is_default: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    api_key_enc: Mapped[str | None] = mapped_column(Text, default=None)
    timeout_seconds: Mapped[int] = mapped_column(Integer, default=60, nullable=False)
    temperature: Mapped[float] = mapped_column(Float, default=0.1, nullable=False)
    max_output_tokens: Mapped[int] = mapped_column(Integer, default=1500, nullable=False)
    #: Capability slugs this endpoint may serve. Empty == all enabled ones.
    capabilities: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    last_error: Mapped[str | None] = mapped_column(Text, default=None)
    last_used_at: Mapped[dt.datetime | None] = mapped_column(
        DateTime(timezone=True), default=None
    )


class AiConversation(Base, TenantMixin, TimestampMixin):
    __tablename__ = "ai_conversations"
    __table_args__ = (Index("ix_ai_conv_org_user", "organization_id", "user_id"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    user_id: Mapped[uuid.UUID | None] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("users.id", ondelete="SET NULL"), default=None
    )
    title: Mapped[str] = mapped_column(String(240), default="New conversation", nullable=False)
    capability: Mapped[str] = mapped_column(
        String(40), default=AiCapability.ASSISTANT.value, nullable=False
    )
    #: Snapshot of the asker's permissions. Retrieval for THIS thread is capped
    #: by the intersection of this snapshot and the reader's live permissions.
    permission_snapshot: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    locale: Mapped[str] = mapped_column(String(5), default="en", nullable=False)
    is_archived: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)

    messages: Mapped[list["AiMessage"]] = relationship(
        back_populates="conversation",
        cascade="all, delete-orphan",
        order_by="AiMessage.created_at",
    )


class AiMessage(Base, TenantMixin, TimestampMixin):
    __tablename__ = "ai_messages"
    __table_args__ = (Index("ix_ai_messages_conv", "conversation_id", "created_at"),)

    id: Mapped[uuid.UUID] = uuid_pk()
    conversation_id: Mapped[uuid.UUID] = mapped_column(
        PgUUID(as_uuid=True), ForeignKey("ai_conversations.id", ondelete="CASCADE"),
        nullable=False,
    )
    role: Mapped[str] = mapped_column(String(20), nullable=False)  # user|assistant|system
    content: Mapped[str] = mapped_column(Text, nullable=False)
    #: Grounding: which VEYRS objects the answer was built from. An answer with
    #: an empty citation list is flagged in the UI as ungrounded.
    citations: Mapped[list] = mapped_column(JSONB, default=list, nullable=False)
    provider: Mapped[str | None] = mapped_column(String(60), default=None)
    model: Mapped[str | None] = mapped_column(String(160), default=None)
    blocked: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    block_reason: Mapped[str | None] = mapped_column(String(200), default=None)
    redactions: Mapped[dict] = mapped_column(JSONB, default=dict, nullable=False)
    duration_ms: Mapped[int | None] = mapped_column(Integer, default=None)

    conversation: Mapped[AiConversation] = relationship(back_populates="messages")
