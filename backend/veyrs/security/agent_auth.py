"""Authentication for execution agents (spec section 33).

An agent is NOT a `Principal`. It has no permission set, cannot read findings,
cannot list assets and cannot reach any route outside `/agents/self/*`. It can
do exactly four things: say it is alive, claim work it is authorised for, stream
that work's progress, and submit that work's output.

Modelling it as a low-privilege user with a role would have been less code and a
worse idea: roles are unioned, wildcards expand, and one careless
`service-account` grant later the machine sitting in the DMZ can enumerate the
estate. A separate credential type with a separate dependency has no such path -
`get_principal()` never returns an agent, and `get_agent()` never returns a user.

The token lives in `X-Agent-Token`, not `Authorization`, so a proxy or log
scrubber configured for one is not silently unaware of the other.
"""
from __future__ import annotations

from typing import Annotated

from fastapi import Depends, Header, HTTPException, Request, status
from sqlalchemy.orm import Session

from ..db import get_session, set_tenant
from ..models import AgentStatus, ExecAgent
from ..services import agents as agent_service

AGENT_UNAUTHORIZED = HTTPException(
    status_code=status.HTTP_401_UNAUTHORIZED,
    detail="invalid agent token",
    headers={"WWW-Authenticate": "AgentToken"},
)


def get_agent(
    request: Request,
    session: Annotated[Session, Depends(get_session)],
    x_agent_token: Annotated[str | None, Header(alias="X-Agent-Token")] = None,
) -> ExecAgent:
    if not x_agent_token:
        raise AGENT_UNAUTHORIZED
    agent = agent_service.authenticate(session, x_agent_token)
    if agent is None:
        raise AGENT_UNAUTHORIZED
    # Bind RLS immediately: everything after this point must be tenant-scoped
    # at the database layer too, not merely filtered in Python.
    set_tenant(session, agent.organization_id)
    request.state.agent = agent

    if agent.status == AgentStatus.DISABLED.value:
        # 403 rather than 401 on purpose: the credential is valid, so an agent
        # can distinguish "rotate your token" from "an operator switched you
        # off" and stop hammering the queue.
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="this agent has been disabled by an operator",
        )
    return agent


CurrentAgent = Annotated[ExecAgent, Depends(get_agent)]


def agent_session(
    agent: CurrentAgent,
    session: Annotated[Session, Depends(get_session)],
) -> Session:
    set_tenant(session, agent.organization_id)
    return session


AgentSession = Annotated[Session, Depends(agent_session)]
