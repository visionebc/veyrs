"""v1 API router assembly."""
from fastapi import APIRouter

from . import attribution  # own line: keeps parallel feature merges trivial
from . import (
    admin, agents, ai, assets, auth, cmdb, compliance, cvss, engagements, findings,
    team_import,
    integrations, intel, knowledge, policies, reports, risk_register, tickets, views,
)
from . import report_builder

api_router = APIRouter()
api_router.include_router(auth.router)
api_router.include_router(team_import.router)
api_router.include_router(admin.router)
api_router.include_router(cvss.router)
api_router.include_router(intel.router)
api_router.include_router(assets.router)
api_router.include_router(cmdb.router)
api_router.include_router(attribution.router)  # before findings: /findings/changes
api_router.include_router(findings.router)
api_router.include_router(policies.router)
api_router.include_router(tickets.router)
api_router.include_router(knowledge.router)
api_router.include_router(ai.router)
api_router.include_router(compliance.router)
api_router.include_router(integrations.router)
api_router.include_router(engagements.router)
api_router.include_router(reports.router)
api_router.include_router(agents.router)
api_router.include_router(views.router)
api_router.include_router(risk_register.router)
api_router.include_router(report_builder.router)

from . import fix_plan  # noqa: E402 - one self-contained line per feature router
api_router.include_router(fix_plan.router)

from . import updates as _updates  # noqa: E402 - software update (phase 52)
api_router.include_router(_updates.router)
from . import system as _system  # noqa: E402 - installed software, network access (phase 53)
api_router.include_router(_system.router)
from . import trust_store as _trust_store  # noqa: E402 - TLS trust store (0.40.0)
api_router.include_router(_trust_store.router)
from . import web_tls as _web_tls  # noqa: E402 - served web certificate (0.41.0)
api_router.include_router(_web_tls.router)

__all__ = ["api_router"]
