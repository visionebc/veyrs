"""SQLAlchemy models. Importing this package registers every table on Base.metadata."""
from .base import GLOBAL_TABLES, Base
from .audit import AiAuditLog, AuditLog, AuthEvent
from .tenancy import (
    ApiKey, Department, Organization, RefreshToken, Role, Team, TeamMember, User, UserRole,
)
from .intelligence import (
    Cpe, Cve, CveCpeMatch, CveReference, Cwe, EpssHistory, EpssScore, FeedRun, KevEntry,
    Product, ProductVersion, Vendor,
)
from .assets import (
    Asset, AssetGroup, AssetProduct, AssetType, BusinessService, CLASSIFICATION_WEIGHT,
    CRITICALITY_WEIGHT, Criticality, DataClassification, ENVIRONMENT_WEIGHT, EXPOSURE_WEIGHT,
    Environment, Exposure,
)
from .sla import EscalationPolicy, SlaEvent, SlaPolicy
from .ticketing import (
    ItsmConnector, OPEN_TICKET_STATES, TICKET_TRANSITIONS, Ticket, TicketComment,
    TicketCounter, TicketEvent, TicketState, TicketType, allowed_ticket_transitions,
    can_transition_ticket,
)
from .knowledge import (
    Document, DocumentChunk, KnowledgeArticle, KnowledgeRevision, SourceKind,
    ThreatArticle, ThreatSource,
)
from .workflow import (
    Notification, NotificationPreference, NotificationTemplate, TriggerType,
    WebhookEndpoint, WorkflowDefinition, WorkflowRun,
)
from .vulnerability import (
    ALLOWED_TRANSITIONS, AssignmentRule, CLOSED_STATES, Finding, FindingEvent, FindingState,
    OPEN_STATES, RiskProfile, RiskScoreHistory, Vulnerability, can_transition,
)
from .ai import (
    AiCapability, AiConversation, AiMessage, AiPolicy, AiProvider, CAPABILITY_PERMISSION,
    CLASSIFICATION_RANK,
)
from .integration import ExternalLink, ImportRun, ImportStatus, ScannerConnector
from .cmdb import (
    COMPARABLE_FIELDS, PROMOTABLE_FIELDS, SET_FIELDS, AssetSource, AssetSourceRecord,
    AssetSourceRun, MatchStatus, SourceRunStatus,
)
from .views import VIEW_ENTITIES, SavedView
from .risk_register import (
    OPEN_RISK_STATUSES, PARTY_TYPES, RACI_LABELS, RACI_ROLES, RISK_BANDS,
    RISK_CATEGORIES, RISK_LINK_TYPES, RISK_SOURCES, RISK_STATUSES, RISK_TREATMENTS,
    RiskEntry, RiskEvent, RiskLink, RiskRaci, risk_band, risk_score,
)
from .engagement import (
    Endpoint, Engagement, EngagementStatus, EngagementType, FindingEndpoint, RiskAcceptance,
    RiskAcceptanceDecision, RiskAcceptanceFinding, RiskAcceptanceState, ScanTest, TestFinding,
    TestFindingStatus,
)
from .agent import (
    ACTIVE_AGENT_STATES, ACTIVE_JOB_STATES, AgentJob, AgentJobEvent, AgentStatus,
    AgentTool, ExecAgent, JobEventKind, JobState, TERMINAL_JOB_STATES,
)
from .compliance import (
    AssessmentGap, AssessmentStatus, ComplianceAssessment, ComplianceControl,
    ComplianceFramework, ControlImplementation, ControlRiskLink, Evidence, EvidenceKind,
    ImplementationStatus,
)

__all__ = [
    "RiskEntry", "RiskEvent", "RiskLink", "RiskRaci", "RISK_STATUSES",
    "OPEN_RISK_STATUSES", "RISK_TREATMENTS", "RACI_ROLES", "RACI_LABELS",
    "PARTY_TYPES", "RISK_LINK_TYPES", "RISK_CATEGORIES", "RISK_SOURCES",
    "RISK_BANDS", "risk_band", "risk_score",
    "Base", "GLOBAL_TABLES",
    # tenancy
    "Organization", "Department", "Team", "TeamMember", "User", "Role", "UserRole",
    "ApiKey", "RefreshToken",
    # audit
    "AuditLog", "AuthEvent", "AiAuditLog",
    # global intelligence
    "Cve", "Cwe", "Cpe", "CveReference", "CveCpeMatch", "EpssScore", "EpssHistory",
    "KevEntry", "Vendor", "Product", "ProductVersion", "FeedRun",
    # assets
    "Asset", "AssetProduct", "AssetGroup", "BusinessService", "AssetType", "Criticality",
    "DataClassification", "Exposure", "Environment", "CRITICALITY_WEIGHT",
    "CLASSIFICATION_WEIGHT", "EXPOSURE_WEIGHT", "ENVIRONMENT_WEIGHT",
    # vulnerability management
    "Vulnerability", "Finding", "FindingEvent", "FindingState", "RiskProfile",
    "RiskScoreHistory", "AssignmentRule", "ALLOWED_TRANSITIONS", "OPEN_STATES",
    "CLOSED_STATES", "can_transition",
    # sla
    "SlaPolicy", "EscalationPolicy", "SlaEvent",
    # ticketing / ITIL
    "Ticket", "TicketComment", "TicketEvent", "TicketCounter", "TicketType", "TicketState",
    "ItsmConnector", "OPEN_TICKET_STATES", "TICKET_TRANSITIONS",
    "allowed_ticket_transitions", "can_transition_ticket",
    # workflow / notifications
    "WorkflowDefinition", "WorkflowRun", "TriggerType", "NotificationTemplate",
    "Notification", "NotificationPreference", "WebhookEndpoint",
    # threat intel / documents / knowledge
    "ThreatSource", "ThreatArticle", "SourceKind", "Document", "DocumentChunk",
    "KnowledgeArticle", "KnowledgeRevision",
    # ai
    "AiPolicy", "AiProvider", "AiConversation", "AiMessage", "AiCapability",
    "CAPABILITY_PERMISSION", "CLASSIFICATION_RANK",
    # compliance
    "ComplianceFramework", "ComplianceControl", "ControlImplementation", "Evidence",
    "ComplianceAssessment", "AssessmentGap", "ControlRiskLink", "ImplementationStatus",
    "EvidenceKind", "AssessmentStatus",
    # external asset sources (CMDB / NetBox / generic JSON)
    "AssetSource", "AssetSourceRun", "AssetSourceRecord", "MatchStatus",
    "SourceRunStatus", "COMPARABLE_FIELDS", "PROMOTABLE_FIELDS", "SET_FIELDS",
    # integrations
    "ImportRun", "ImportStatus", "ExternalLink", "ScannerConnector",
    # execution agents
    "ExecAgent", "AgentTool", "AgentJob", "AgentJobEvent", "AgentStatus", "JobState",
    "JobEventKind", "ACTIVE_AGENT_STATES", "ACTIVE_JOB_STATES", "TERMINAL_JOB_STATES",
    # engagement scoping, endpoints and risk acceptance
    "Engagement", "EngagementStatus", "EngagementType", "ScanTest", "TestFinding",
    "TestFindingStatus", "Endpoint", "FindingEndpoint", "RiskAcceptance",
    "RiskAcceptanceFinding", "RiskAcceptanceState", "RiskAcceptanceDecision",
    # saved views (an operator's own queues)
    "SavedView", "VIEW_ENTITIES",
]
