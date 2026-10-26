"""The single source of truth for VEYRS permissions and built-in roles.

Every API route declares the permission it needs; the seeder builds roles from
the same constants. If a permission string is not listed here, `require()`
rejects it at import time rather than failing open at request time.
"""
from __future__ import annotations

RESOURCES = (
    "organization", "user", "team", "role", "apikey", "audit",
    "asset", "product", "vulnerability", "finding", "cve",
    "risk", "riskprofile", "riskregister", "ticket", "sla", "escalation", "workflow",
    "intel", "document", "knowledge", "compliance", "evidence",
    "report", "importer", "notification", "ai", "settings", "agent",
)
ACTIONS = ("read", "write", "delete", "admin")

ALL_PERMISSIONS: frozenset[str] = frozenset(
    f"{r}:{a}" for r in RESOURCES for a in ACTIONS
)

# Coarse-grained wildcards accepted in Role.permissions
WILDCARD = "*:*"


def is_valid(permission: str) -> bool:
    return permission == WILDCARD or permission in ALL_PERMISSIONS or (
        permission.endswith(":*") and permission.split(":")[0] in RESOURCES
    )


def expand(permissions: list[str]) -> frozenset[str]:
    """Resolve wildcards to the concrete permission set they stand for."""
    out: set[str] = set()
    for permission in permissions:
        if permission == WILDCARD:
            return ALL_PERMISSIONS
        if permission.endswith(":*"):
            resource = permission.split(":")[0]
            out.update(f"{resource}:{a}" for a in ACTIONS)
        elif permission in ALL_PERMISSIONS:
            out.add(permission)
    return frozenset(out)


def _read(*resources: str) -> list[str]:
    return [f"{r}:read" for r in resources]


def _write(*resources: str) -> list[str]:
    return [f"{r}:{a}" for r in resources for a in ("read", "write")]


# --- built-in roles -------------------------------------------------------
# Deliberately mapped to the operational personas in the spec (section 6/10/12)
# rather than generic admin/editor/viewer tiers.
BUILTIN_ROLES: dict[str, dict] = {
    "org-admin": {
        "name": "Organization Administrator",
        "description": "Full control inside one organization, including RBAC and settings.",
        "permissions": [WILDCARD],
    },
    "security-manager": {
        "name": "Security Manager",
        "description": "Owns risk posture: triage, risk profiles, SLA policy, escalation.",
        "permissions": [
            *_write("asset", "product", "vulnerability", "finding", "risk", "riskprofile",
                    "riskregister",
                    "ticket", "sla", "escalation", "workflow", "report", "importer",
                    "agent"),
            # Owns the register outright, including retiring an entry.
            "riskregister:delete",
            *_read("user", "team", "audit", "intel", "compliance", "evidence", "cve"),
            # Automatic ticket creation (`PUT /tickets/automation`) is guarded by
            # `ticket:admin`, which `_write` does not include. Granted here
            # explicitly rather than downgrading the route to `ticket:write`:
            # deciding that every high-risk finding opens a ticket by itself is
            # the same class of estate-wide decision as owning the SLA policy,
            # and this is the role that owns those. Without this line the only
            # identity able to configure it would be the wildcard org-admin.
            "ticket:admin",
            "ai:read", "ai:write",
        ],
    },
    "security-engineer": {
        "name": "Security Engineer",
        "description": "Day-to-day triage and remediation work on findings and tickets.",
        "permissions": [
            *_write("finding", "vulnerability", "ticket", "asset", "document"),
            *_read("asset", "product", "risk", "riskregister", "cve", "intel",
                   "knowledge", "report",
                   "compliance", "sla",
                   # needed to populate the team picker: you cannot route a
                   # finding to a team whose name you are not allowed to read.
                   "team"),
            "ai:read",
            # May queue and watch scans, but not enrol an agent or widen
            # what one may execute -- that is agent:admin, org-admin only.
            "agent:read", "agent:write",
        ],
    },
    "team-lead": {
        "name": "Team Lead",
        "description": "Accountable for their team's queue and SLA compliance.",
        "permissions": [
            *_write("ticket", "finding"),
            *_read("asset", "product", "vulnerability", "risk", "riskregister", "sla",
                   "escalation", "report", "team", "cve"),
        ],
    },
    "asset-owner": {
        "name": "Asset Owner",
        "description": "Business owner of assets; accepts risk and confirms remediation.",
        "permissions": [
            *_write("asset", "ticket"),
            *_read("vulnerability", "finding", "risk", "riskregister", "report", "cve",
               "team"),
        ],
    },
    "compliance-officer": {
        "name": "Compliance Officer",
        "description": "Control mapping, evidence collection and audit readiness.",
        "permissions": [
            *_write("compliance", "evidence", "document", "knowledge", "report",
                    # The register IS the compliance officer's working
                    # surface: an ISO 27001 statement of applicability is
                    # written against it, not against the CVE queue.
                    "riskregister"),
            *_read("asset", "vulnerability", "finding", "risk", "ticket", "audit", "sla"),
        ],
    },
    "executive": {
        "name": "Executive / CISO",
        "description": "Read-only executive view plus formal risk acceptance.",
        "permissions": [
            *_read("asset", "product", "vulnerability", "finding", "risk", "riskprofile",
                   "ticket", "sla", "compliance", "report", "intel", "audit"),
            "risk:write",
            # Accepting a risk is an executive act, and in the register it is
            # an ordinary field change -- so write, not just read. Deletion
            # stays out: retiring the record of an accepted risk is exactly
            # what the audit trail is for.
            "riskregister:read", "riskregister:write",
        ],
    },
    "auditor": {
        "name": "Auditor",
        "description": "Immutable read across evidence and audit trail. No writes at all.",
        "permissions": [
            *_read("asset", "vulnerability", "finding", "risk", "riskregister", "ticket",
                   "compliance", "evidence", "audit", "report", "sla", "workflow"),
        ],
    },
    "service-account": {
        "name": "Service Account",
        "description": "Machine identity for importers and ITSM webhooks.",
        "permissions": [
            *_write("finding", "asset", "importer"),
            *_read("product", "cve", "vulnerability", "ticket"),
        ],
    },
    "read-only": {
        "name": "Read Only",
        "description": "Baseline visibility with no mutation rights.",
        "permissions": _read("asset", "product", "vulnerability", "finding", "risk",
                             "riskregister", "ticket", "report", "cve", "compliance"),
    },
}


def validate_builtins() -> None:
    """Fail fast if a role references a permission that does not exist."""
    for slug, spec in BUILTIN_ROLES.items():
        for permission in spec["permissions"]:
            if not is_valid(permission):
                raise ValueError(f"builtin role {slug!r} references unknown permission {permission!r}")


validate_builtins()
