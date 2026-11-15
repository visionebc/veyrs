"""Installed software and network requirements of this installation.

Platform administrators only, like Software update (and through the same
dependency): the versions of everything a node runs are reconnaissance data,
and the network list names the internal hosts an installation depends on.
Both answers are read-only; nothing here changes the node.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import APIRouter, Depends, Query

from ...security.deps import Principal, TenantSession
from ...services import network_requirements, software_inventory
from .updates import platform_admin

router = APIRouter(prefix="/admin/system", tags=["administration"])


@router.get("/software", summary="OS components and Python packages installed on this node")
def get_software(
    principal: Annotated[Principal, Depends(platform_admin)],
    session: TenantSession,
    refresh: Annotated[bool, Query(description="bypass the one-minute cache")] = False,
) -> dict:
    data = software_inventory.inventory(refresh=refresh)
    # Per organization and never cached: an agent re-registers with new tools.
    data["agents"] = software_inventory.agent_tools(session, principal.organization_id)
    return data


@router.get("/network", summary="Every network destination VEYRS needs, and why")
def get_network(
    principal: Annotated[Principal, Depends(platform_admin)],
    session: TenantSession,
) -> dict:
    return network_requirements.overview(session, principal.organization_id)
