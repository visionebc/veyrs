"""Fix plan API, and the operator's vendor upgrade-path rules it applies.

Three surfaces, one router, each route tagged for the team-scope family it
belongs to (`security.scope.enforce_route_policy` reads the tag of the ROUTE):

* `GET /findings/{id}/fix-plan` -- "vulnerability management": the plan for
  the installation the finding sits on, with that finding highlighted.
* `GET /assets/{id}/fix-plan`   -- "assets": one plan per installed product
  with open findings.
* `/upgrade-path-rules`         -- "policies": organisation configuration.
  Reading is open to anyone who reads findings (an engineer has to see why the
  plan made them stop at an intermediate version); writing is the SLA
  policy's permission and an estate-wide grant, because a rule changes the
  plan every team is handed.

Both plan routes resolve their row through the SAME helpers the detail routes
use (`findings._get_finding`, `assets._get_asset`), so out-of-scope and
other-tenant rows answer 404 exactly as the detail screens do.
"""
from __future__ import annotations

import datetime as dt
import uuid
from typing import Annotated

from fastapi import APIRouter, Depends, HTTPException, Request, Response, status
from pydantic import BaseModel, ConfigDict, Field
from sqlalchemy import select

from ...models.upgrade import UpgradePathRule
from ...security import scope as team_scope
from ...security.deps import Principal, TenantSession, require
from ...services import audit
from ...services import fix_plan as fix_plan_service
from ...services.versions import compare, normalize_name, parse
from .assets import _get_asset
from .findings import _get_finding

router = APIRouter()

PLAN_TAG_FINDINGS = ["vulnerability management"]
PLAN_TAG_ASSETS = ["assets"]
RULES_TAG = ["policies"]


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
# Plans
# --------------------------------------------------------------------------


@router.get("/findings/{finding_id}/fix-plan", tags=PLAN_TAG_FINDINGS,
            summary="Which version fixes this finding's product, and the path there")
def finding_fix_plan(
    finding_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:read"))],
) -> dict:
    finding = _get_finding(session, principal.organization_id, finding_id, principal.scope)
    return fix_plan_service.plan_for_finding(session, finding, scope=principal.scope)


@router.get("/assets/{asset_id}/fix-plan", tags=PLAN_TAG_ASSETS,
            summary="One fix plan per installed product with open findings")
def asset_fix_plan(
    asset_id: uuid.UUID,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("asset:read", "finding:read"))],
) -> dict:
    asset = _get_asset(session, principal.organization_id, asset_id, principal.scope)
    return fix_plan_service.plans_for_asset(session, asset, scope=principal.scope)


# --------------------------------------------------------------------------
# Upgrade-path rules
# --------------------------------------------------------------------------

_VERSION_FIELDS = ("from_start_including", "from_start_excluding",
                   "from_end_including", "from_end_excluding", "via_version")


class UpgradePathRuleWrite(BaseModel):
    vendor: str = Field(min_length=1, max_length=200)
    product: str = Field(min_length=1, max_length=300)
    from_start_including: str | None = Field(default=None, max_length=120)
    from_start_excluding: str | None = Field(default=None, max_length=120)
    from_end_including: str | None = Field(default=None, max_length=120)
    from_end_excluding: str | None = Field(default=None, max_length=120)
    via_version: str | None = Field(default=None, max_length=120)
    prerequisite: str | None = Field(default=None, max_length=4000)
    source_url: str | None = Field(default=None, max_length=1000)
    is_enabled: bool = True


class UpgradePathRulePatch(BaseModel):
    vendor: str | None = Field(default=None, min_length=1, max_length=200)
    product: str | None = Field(default=None, min_length=1, max_length=300)
    from_start_including: str | None = Field(default=None, max_length=120)
    from_start_excluding: str | None = Field(default=None, max_length=120)
    from_end_including: str | None = Field(default=None, max_length=120)
    from_end_excluding: str | None = Field(default=None, max_length=120)
    via_version: str | None = Field(default=None, max_length=120)
    prerequisite: str | None = Field(default=None, max_length=4000)
    source_url: str | None = Field(default=None, max_length=1000)
    is_enabled: bool | None = None


class UpgradePathRuleOut(UpgradePathRuleWrite):
    model_config = ConfigDict(from_attributes=True)

    id: uuid.UUID
    vendor_key: str
    product_key: str
    created_by_id: uuid.UUID | None = None
    created_at: dt.datetime | None = None
    updated_at: dt.datetime | None = None


def _unprocessable(detail: str) -> HTTPException:
    return HTTPException(status.HTTP_422_UNPROCESSABLE_ENTITY, detail)


def _clean(values: dict) -> dict:
    """Normalise and validate one complete rule. Raises 422 on nonsense.

    Validation uses `versions.parse`/`compare` -- the same reading of a
    version the plan will apply -- so a rule cannot be accepted here and then
    mean something else when it runs.
    """
    out = dict(values)
    for key in ("vendor", "product"):
        out[key] = (out.get(key) or "").strip()
    out["vendor_key"] = normalize_name(out["vendor"])
    out["product_key"] = normalize_name(out["product"])
    if not out["vendor_key"] or not out["product_key"]:
        raise _unprocessable("vendor and product must contain letters or digits")

    for key in _VERSION_FIELDS:
        value = out.get(key)
        value = value.strip() if isinstance(value, str) else None
        if value in ("", "*", "-"):
            value = None
        if value is not None and not parse(value):
            raise _unprocessable(f"{key}: {value!r} is not a version")
        out[key] = value
    for key in ("prerequisite", "source_url"):
        value = out.get(key)
        out[key] = value.strip() if isinstance(value, str) and value.strip() else None

    if out["from_start_including"] and out["from_start_excluding"]:
        raise _unprocessable("give from_start_including OR from_start_excluding, not both")
    if out["from_end_including"] and out["from_end_excluding"]:
        raise _unprocessable("give from_end_including OR from_end_excluding, not both")
    start = out["from_start_including"] or out["from_start_excluding"]
    end = out["from_end_including"] or out["from_end_excluding"]
    if start and end:
        order = compare(start, end)
        both_inclusive = bool(out["from_start_including"] and out["from_end_including"])
        if order > 0 or (order == 0 and not both_inclusive):
            raise _unprocessable("the from range is empty: its start is not below its end")
    via = out["via_version"]
    if not via and not out["prerequisite"]:
        raise _unprocessable("a rule needs a via_version, a prerequisite, or both")
    if via and start and compare(via, start) <= 0:
        raise _unprocessable(
            "via_version must be newer than the start of the from range; an "
            "intermediate stop below the versions it applies to would send the "
            "upgrade backwards")
    url = out["source_url"]
    if url and not (url.lower().startswith("https://") or url.lower().startswith("http://")):
        raise _unprocessable("source_url must be an http(s) URL")
    return out


def _estate_only(principal: Principal) -> None:
    team_scope.refuse_if_restricted(
        principal.scope,
        "upgrade-path rules shape the fix plan every team is handed; changing "
        "one requires an estate-wide role grant",
    )


def _owned(session, organization_id: uuid.UUID, rule_id: uuid.UUID) -> UpgradePathRule:
    row = session.get(UpgradePathRule, rule_id)
    if row is None or row.organization_id != organization_id:
        raise HTTPException(status.HTTP_404_NOT_FOUND, "rule not found")
    return row


def _snapshot(row: UpgradePathRule) -> dict:
    return {k: getattr(row, k) for k in UpgradePathRuleWrite.model_fields}


@router.get("/upgrade-path-rules", tags=RULES_TAG, response_model=list[UpgradePathRuleOut],
            summary="List vendor upgrade-path rules")
def list_rules(
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("finding:read"))],
    vendor: str | None = None,
    product: str | None = None,
) -> list[UpgradePathRuleOut]:
    stmt = select(UpgradePathRule).where(
        UpgradePathRule.organization_id == principal.organization_id
    )
    if vendor:
        stmt = stmt.where(UpgradePathRule.vendor_key == normalize_name(vendor))
    if product:
        stmt = stmt.where(UpgradePathRule.product_key == normalize_name(product))
    rows = session.execute(
        stmt.order_by(UpgradePathRule.vendor_key, UpgradePathRule.product_key,
                      UpgradePathRule.created_at)
    ).scalars().all()
    return [UpgradePathRuleOut.model_validate(r) for r in rows]


@router.post("/upgrade-path-rules", tags=RULES_TAG, response_model=UpgradePathRuleOut,
             status_code=status.HTTP_201_CREATED, summary="Create an upgrade-path rule")
def create_rule(
    payload: UpgradePathRuleWrite,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("sla:write"))],
) -> UpgradePathRuleOut:
    _estate_only(principal)
    values = _clean(payload.model_dump())
    row = UpgradePathRule(organization_id=principal.organization_id,
                          created_by_id=principal.user_id, **values)
    session.add(row)
    session.flush()
    audit.record(session, action="upgrade_path_rule.create", object_type="upgrade_path_rule",
                 object_id=str(row.id), object_label=f"{row.vendor} {row.product}",
                 **_actor(request, principal),
                 changes=audit.diff(None, _snapshot(row)))
    session.commit()
    session.refresh(row)
    return UpgradePathRuleOut.model_validate(row)


@router.patch("/upgrade-path-rules/{rule_id}", tags=RULES_TAG,
              response_model=UpgradePathRuleOut, summary="Update an upgrade-path rule")
def update_rule(
    rule_id: uuid.UUID,
    payload: UpgradePathRulePatch,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("sla:write"))],
) -> UpgradePathRuleOut:
    _estate_only(principal)
    row = _owned(session, principal.organization_id, rule_id)
    before = _snapshot(row)
    changes = payload.model_dump(exclude_unset=True)
    if "is_enabled" in changes and changes["is_enabled"] is None:
        changes.pop("is_enabled")
    # Validate the rule as it will be AFTER the change, not the delta: a patch
    # that only moves the end bound can still empty the range.
    values = _clean({**before, **changes})
    for key, value in values.items():
        setattr(row, key, value)
    session.flush()
    audit.record(session, action="upgrade_path_rule.update", object_type="upgrade_path_rule",
                 object_id=str(row.id), object_label=f"{row.vendor} {row.product}",
                 **_actor(request, principal), changes=audit.diff(before, _snapshot(row)))
    session.commit()
    session.refresh(row)
    return UpgradePathRuleOut.model_validate(row)


@router.delete("/upgrade-path-rules/{rule_id}", tags=RULES_TAG, status_code=204,
               response_model=None, response_class=Response,
               summary="Delete an upgrade-path rule")
def delete_rule(
    rule_id: uuid.UUID,
    request: Request,
    session: TenantSession,
    principal: Annotated[Principal, Depends(require("sla:write"))],
) -> None:
    _estate_only(principal)
    row = _owned(session, principal.organization_id, rule_id)
    before = _snapshot(row)
    audit.record(session, action="upgrade_path_rule.delete", object_type="upgrade_path_rule",
                 object_id=str(row.id), object_label=f"{row.vendor} {row.product}",
                 **_actor(request, principal), changes=audit.diff(before, None))
    session.delete(row)
    session.commit()
