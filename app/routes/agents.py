from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select
from typing import Literal

from app.agents.base import AgentResult
from app.agents.catalog import AGENT_CATALOGUE, AgentFactory, PLATFORM_TOOLS
from app.core.security import CurrentUser, get_current_user, require_roles
from app.dependencies import get_tenant_session
from app.models.entities import Agent, AgentDecision
from app.routes._shared import STANDARD_ERROR_RESPONSES, bad_request, not_found
from app.schemas.common import AuditLogCreate
from app.services.audit_writer import AuditWriter

router = APIRouter(prefix="/agents", tags=["agents"])


class AgentCreateRequest(BaseModel):
    name: str
    agent_type: str
    tool_whitelist: list[str] = Field(default_factory=list)
    safety_ceiling: int
    schedule: str | None = None
    trigger: str | None = None


class AgentRunRequest(BaseModel):
    goal: str
    finding_id: str | None = None
    cve_id: str | None = None
    target_ip: str | None = None


class AgentStatusPatch(BaseModel):
    status: Literal["active", "inactive", "decommissioned"]


class AgentResponse(BaseModel):
    id: str
    name: str
    agent_type: str | None
    tool_whitelist: list[str]
    safety_ceiling: int
    schedule: str | None
    trigger: str | None
    is_active: bool
    status: str
    created_at: str | None
    config: dict


class AgentListResponse(BaseModel):
    items: list[AgentResponse]


class AgentDecisionResponse(BaseModel):
    id: str
    goal: str
    reasoning_chain: dict
    decision: str
    confidence_score: float
    outcome: str
    created_at: str | None


class AgentDecisionListResponse(BaseModel):
    items: list[AgentDecisionResponse]
    limit: int
    offset: int


class AgentCatalogResponse(BaseModel):
    agent_types: list[dict]
    platform_tools: list[str]


class AgentDetailResponse(AgentResponse):
    recent_decisions: list[AgentDecisionResponse] = Field(default_factory=list)


class AgentDecommissionResponse(BaseModel):
    id: str
    name: str
    is_active: bool
    status: str
    message: str


def _serialize_agent(agent: Agent) -> dict:
    return {
        "id": str(agent.id),
        "name": agent.name,
        "agent_type": agent.config_json.get("agent_type"),
        "tool_whitelist": agent.tool_whitelist,
        "safety_ceiling": agent.safety_ceiling,
        "schedule": agent.config_json.get("schedule"),
        "trigger": agent.config_json.get("trigger"),
        "is_active": agent.is_active,
        "status": getattr(agent, "status", "active"),
        "created_at": agent.created_at.isoformat() if agent.created_at else None,
        "config": agent.config_json,
    }


def _serialize_catalogue() -> dict:
    return {
        "agent_types": [
            {
                "id": agent_type,
                "default_tools": spec["tools"],
                "default_safety_ceiling": spec["default_ceiling"],
            }
            for agent_type, spec in AGENT_CATALOGUE.items()
        ],
        "platform_tools": PLATFORM_TOOLS,
    }


def _serialize_decision(decision: AgentDecision) -> dict:
    return {
        "id": str(decision.id),
        "goal": decision.goal,
        "reasoning_chain": decision.reasoning_chain,
        "decision": decision.decision,
        "confidence_score": decision.confidence_score,
        "outcome": decision.outcome,
        "created_at": decision.created_at.isoformat() if decision.created_at else None,
    }


@router.post("", status_code=201, response_model=AgentResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def create_agent(
    payload: AgentCreateRequest,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    if payload.agent_type not in AGENT_CATALOGUE:
        raise bad_request(f"Invalid agent_type: {payload.agent_type}")
    invalid_tools = [tool for tool in payload.tool_whitelist if tool not in PLATFORM_TOOLS]
    if invalid_tools:
        raise bad_request(f"Invalid tools: {invalid_tools}")
    agent = Agent(
        name=payload.name,
        tool_whitelist=payload.tool_whitelist or AGENT_CATALOGUE[payload.agent_type]["tools"],
        safety_ceiling=payload.safety_ceiling,
        is_active=True,
        status="active",
        config_json={
            "agent_type": payload.agent_type,
            "schedule": payload.schedule,
            "trigger": payload.trigger,
        },
    )
    session.add(agent)
    await session.flush()
    await AuditWriter().write(
        session,
        str(current_user.tenant_id),
        AuditLogCreate(
            action="agent_created",
            resource_type="agent",
            resource_id=str(agent.id),
            user_id=current_user.user_id,
            details={"name": agent.name, "agent_type": payload.agent_type},
        ),
    )
    await session.commit()
    return _serialize_agent(agent)


@router.get("", response_model=AgentListResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "platform_admin", "security_analyst"))])
async def list_agents(session=Depends(get_tenant_session)):
    agents = (await session.execute(select(Agent).order_by(Agent.created_at.desc()))).scalars().all()
    return {"items": [_serialize_agent(agent) for agent in agents]}


@router.get("/catalog", response_model=AgentCatalogResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "platform_admin", "security_analyst"))])
async def get_agent_catalogue():
    return _serialize_catalogue()


@router.get("/{agent_id}", response_model=AgentDetailResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "platform_admin", "security_analyst"))])
async def get_agent(agent_id: str, session=Depends(get_tenant_session)):
    agent = await session.get(Agent, agent_id)
    if agent is None:
        raise not_found("Agent not found.")
    decisions = (
        await session.execute(
            select(AgentDecision)
            .where(AgentDecision.agent_id == agent.id)
            .order_by(AgentDecision.created_at.desc())
            .limit(10)
        )
    ).scalars().all()
    return _serialize_agent(agent) | {"recent_decisions": [_serialize_decision(item) for item in decisions]}


@router.patch("/{agent_id}/status", response_model=AgentResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def patch_agent_status(
    agent_id: str,
    payload: AgentStatusPatch,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    agent = await session.get(Agent, agent_id)
    if agent is None:
        raise not_found("Agent not found.")
    old_status = getattr(agent, "status", "active")
    agent.status = payload.status
    agent.is_active = payload.status == "active"
    await AuditWriter().write(
        session,
        str(current_user.tenant_id),
        AuditLogCreate(
            action=f"agent_{payload.status}",
            resource_type="agent",
            resource_id=str(agent.id),
            user_id=current_user.user_id,
            details={"name": agent.name, "from": old_status, "to": payload.status},
        ),
    )
    await session.commit()
    return _serialize_agent(agent)


@router.post("/{agent_id}/decommission", response_model=AgentDecommissionResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def decommission_agent(
    agent_id: str,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    """Convenience wrapper — equivalent to PATCH /{agent_id}/status with status=decommissioned."""
    agent = await session.get(Agent, agent_id)
    if agent is None:
        raise not_found("Agent not found.")
    agent.is_active = False
    agent.status = "decommissioned"
    await AuditWriter().write(
        session,
        str(current_user.tenant_id),
        AuditLogCreate(
            action="agent_decommissioned",
            resource_type="agent",
            resource_id=str(agent.id),
            user_id=current_user.user_id,
            details={"agent_id": str(agent.id), "name": agent.name},
        ),
    )
    await session.commit()
    return {
        "id": str(agent.id),
        "name": agent.name,
        "is_active": False,
        "status": "decommissioned",
        "message": "Agent decommissioned. Config and history preserved.",
    }


@router.get("/{agent_id}/decisions", response_model=AgentDecisionListResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "platform_admin", "security_analyst", "auditor"))])
async def list_agent_decisions(
    agent_id: str,
    limit: int = 50,
    offset: int = 0,
    session=Depends(get_tenant_session),
):
    agent = await session.get(Agent, agent_id)
    if agent is None:
        raise not_found("Agent not found.")
    decisions = (
        await session.execute(
            select(AgentDecision)
            .where(AgentDecision.agent_id == agent.id)
            .order_by(AgentDecision.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).scalars().all()
    return {"items": [_serialize_decision(item) for item in decisions], "limit": limit, "offset": offset}


@router.post("/run/{agent_id}", response_model=AgentResult, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "platform_admin", "security_analyst"))])
async def run_agent(
    agent_id: str,
    payload: AgentRunRequest,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
) -> AgentResult:
    agent = await session.get(Agent, agent_id)
    if agent is None:
        raise not_found("Agent not found.")
    if not agent.is_active:
        raise conflict("Agent is decommissioned.")
    agent_impl = AgentFactory.create(
        agent_type=agent.config_json.get("agent_type"),
        tenant_id=str(current_user.tenant_id),
        tool_whitelist=agent.tool_whitelist,
        safety_ceiling=agent.safety_ceiling,
        agent_id=str(agent.id),
    )
    result = await agent_impl.run(
        goal=payload.goal,
        session=session,
        tenant_id=str(current_user.tenant_id),
        metadata={
            "finding_id": payload.finding_id,
            "cve_id": payload.cve_id,
            "target_ip": payload.target_ip,
        },
    )
    await session.commit()
    return result
