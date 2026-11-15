"""Interactive CVSS calculator endpoints.

Backed by `veyrs.engines.cvss`, which is validated against the full official
vector corpora (729 v2 + 2592 v3 + 1058 v4) in tests/test_cvss_official.py.
These endpoints are read-only and cheap, so they need `vulnerability:read`
rather than a dedicated permission.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Query
from pydantic import BaseModel, Field

from ...engines import cvss
from ...security.deps import Principal, TenantSession, require
from ...services import cvss_assist
from .schemas import CvssCompareRequest, CvssGenerateRequest, CvssScoreRequest

router = APIRouter(prefix="/cvss", tags=["cvss"])
ReadCvss = Annotated[Principal, Depends(require("vulnerability:read"))]


@router.get("/versions", summary="Supported CVSS versions")
def versions(_: ReadCvss) -> dict:
    return {"versions": list(cvss.SUPPORTED_VERSIONS)}


@router.get("/metrics/{version}", summary="Metric definitions for a version")
def metric_definitions(version: str, _: ReadCvss) -> dict:
    if version not in cvss.SUPPORTED_VERSIONS:
        raise HTTPException(status_code=404, detail=f"unsupported version {version}")
    return cvss.metric_catalogue(version)


@router.post("/score", summary="Score a vector")
def score(payload: CvssScoreRequest, _: ReadCvss) -> dict:
    try:
        return cvss.score(payload.vector, payload.version).as_dict()
    except cvss.CVSSError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/explain", summary="Score a vector with a plain-language rationale")
def explain(payload: CvssScoreRequest, _: ReadCvss) -> dict:
    try:
        return cvss.explain(payload.vector, payload.version)
    except cvss.CVSSError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc


@router.post("/validate", summary="Validate a vector without scoring it")
def validate(payload: CvssScoreRequest, _: ReadCvss) -> dict:
    ok, error = cvss.validate(payload.vector, payload.version)
    return {"valid": ok, "error": error}


@router.post("/generate", summary="Build a canonical vector from a metric map")
def generate(payload: CvssGenerateRequest, _: ReadCvss) -> dict:
    try:
        vector = cvss.generate(payload.metrics, payload.version)
    except (cvss.CVSSError, KeyError) as exc:
        raise HTTPException(status_code=422, detail=f"cannot build vector: {exc}") from exc
    return {"vector": vector, **cvss.score(vector).as_dict()}


@router.post("/compare", summary="Score several vectors side by side")
def compare(payload: CvssCompareRequest, _: ReadCvss) -> dict:
    return cvss.compare(payload.vectors)


@router.get("/severity", summary="Qualitative rating for a numeric score")
def severity(score_value: float = Query(..., ge=0.0, le=10.0, alias="score"),
             version: str = Query("3.1"), _: ReadCvss = None) -> dict:
    return {"score": score_value, "version": version,
            "severity": cvss.severity_rating(score_value, version)}


# --------------------------------------------------------------------------
# Bulletin assistant
# --------------------------------------------------------------------------


class CvssAssistRequest(BaseModel):
    """A pasted advisory, plus which version's vector to fill in."""

    text: str = Field(min_length=20, max_length=200000)
    version: str = "3.1"
    #: Lets an analyst run the deterministic half alone -- extraction plus the
    #: inventory cross-check -- on an estate whose AI policy blocks external
    #: providers, or simply when they do not want a model's opinion.
    use_ai: bool = True


@router.post("/assist", summary="Prefill the calculator from a security bulletin")
def assist(
    payload: CvssAssistRequest,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("vulnerability:read"))],
) -> dict:
    """Read a bulletin, cross it against this tenant's inventory, prefill a vector.

    The response is a PROPOSAL and says so: `metric_source` names where each
    value came from (`bulletin` beats `model`, always), `needs_decision` lists
    what the analyst still has to answer, and the score -- when there is one --
    is computed by the same engine that scores everything else, never taken
    from the model.

    `vulnerability:read` and not a new permission: this reads the CVE
    catalogue and the tenant's own inventory, which is exactly what the
    calculator's other endpoints already require. The AI leg additionally goes
    through the gateway, which independently enforces `intel:read` for
    `advisory_analysis` and returns a *blocked* result rather than raising --
    so a caller without it still gets the deterministic half.
    """
    try:
        return cvss_assist.assist(
            session,
            organization_id=principal.organization_id,
            text=payload.text,
            version=payload.version,
            permissions=frozenset(principal.permissions),
            is_superuser=getattr(principal, "is_superuser", False),
            user_id=principal.user_id,
            locale=getattr(principal, "locale", "en") or "en",
            use_ai=payload.use_ai,
            scope=principal.scope,
        )
    except cvss.CVSSError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc)) from exc
