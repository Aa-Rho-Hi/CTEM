import ipaddress
import shutil

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from app.core.security import CurrentUser, get_current_user, require_roles
from app.dependencies import get_redis, get_tenant_session
from app.models.entities import PtEvidence, PtSession, RoeRecord
from app.schemas.common import AuditLogCreate
from app.services.audit_writer import AuditWriter
from app.services.asset_service import AssetService
from app.services.errors import (
    ConfidenceBelowCeilingError,
    CrownJewelLockError,
    InvalidIPError,
    OutOfScopeError,
    ROEExpiredError,
    ROENotFoundError,
    TenantBoundaryViolationError,
    ToolNotWhitelistedError,
)
from app.services.evidence_writer import EvidenceWriter
from app.services.kill_switch import KillSwitchActiveError, KillSwitchService
from app.services.roe_service import ROEService
from app.services.validation_service import ValidationService

router = APIRouter(prefix="/validate", tags=["validate"])


class PTSessionCreate(BaseModel):
    roe_id: str
    target_assets: list[str] = []
    objective: str = ""


class PTProbeRequest(BaseModel):
    session_id: str
    target_ip: str
    target_asset_id: str
    technique: str
    tool: str
    payload: str = ""


@router.get("/pt/tools", dependencies=[Depends(require_roles("security_analyst", "approver", "super_admin"))])
async def pt_tool_status():
    return {
        "tools": {
            "nmap": {"available": shutil.which("nmap") is not None},
            "burp_suite": {"available": True, "note": "Requires ZAP API at configured local endpoint."},
        }
    }


@router.post("/auto/{finding_id}", dependencies=[Depends(require_roles("security_analyst", "super_admin"))])
async def auto_validate(
    finding_id: str,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    try:
        result = await ValidationService().auto_validate(session, finding_id, str(current_user.tenant_id))
        await session.commit()
        return result
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))


@router.post("/pt/session", dependencies=[Depends(require_roles("security_analyst", "super_admin"))])
async def create_pt_session(
    payload: PTSessionCreate,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    roe = await session.get(RoeRecord, payload.roe_id)
    if roe is None or roe.status != "active":
        raise HTTPException(status_code=403, detail="ROE not found or not active.")

    pt_session = PtSession(
        tenant_id=str(current_user.tenant_id),
        roe_id=payload.roe_id,
        target_assets=payload.target_assets,
        objective=payload.objective,
        status="active",
    )
    session.add(pt_session)
    await session.flush()
    await AuditWriter().write(session, str(current_user.tenant_id), AuditLogCreate(
        action="pt_session_created",
        resource_type="pt_session",
        resource_id=str(pt_session.id),
        user_id=current_user.user_id,
        details={"roe_id": payload.roe_id, "objective": payload.objective},
    ))
    await session.commit()
    return {
        "id": str(pt_session.id),
        "roe_id": payload.roe_id,
        "objective": pt_session.objective,
        "status": pt_session.status,
    }


@router.post("/pt/probe", dependencies=[Depends(require_roles("security_analyst", "super_admin"))])
async def run_probe(
    payload: PTProbeRequest,
    session=Depends(get_tenant_session),
    redis=Depends(get_redis),
    current_user: CurrentUser = Depends(get_current_user),
):
    try:
        ipaddress.ip_address(payload.target_ip)
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=f"Invalid IP: {payload.target_ip}") from exc

    from app.agents.base import PTProbe, BaseAgent
    agent = BaseAgent(
        tenant_id=current_user.tenant_id,
        tool_whitelist=["nmap", "metasploit", "burp_suite", "burpsuite", "nessus", "openvas", "sqlmap", "nikto", "hydra", "snyk"],
        safety_ceiling=70,
        agent_id=None,
    )

    probe = PTProbe(
        session_id=payload.session_id,
        target_ip=payload.target_ip,
        target_asset_id=payload.target_asset_id,
        technique=payload.technique,
        tool=payload.tool,
        payload=payload.payload,
        tenant_id=str(current_user.tenant_id),
    )

    kill_switch_svc = KillSwitchService(redis)
    roe_svc = ROEService()
    asset_svc = AssetService()
    evidence_writer = EvidenceWriter()

    try:
        result = await agent.execute(
            goal=f"PT probe: {payload.technique} on {payload.target_ip}",
            probe=probe,
            kill_switch_svc=kill_switch_svc,
            roe_svc=roe_svc,
            asset_svc=asset_svc,
            evidence_writer=evidence_writer,
            session=session,
            tenant_id=str(current_user.tenant_id),
        )
        await session.commit()
        return {"decision": result.decision, "confidence": result.confidence, "outcome": result.outcome}
    except KillSwitchActiveError as exc:
        raise HTTPException(status_code=503, detail=str(exc))
    except ValueError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    except (ROEExpiredError, ROENotFoundError, OutOfScopeError,
            TenantBoundaryViolationError, CrownJewelLockError,
            ToolNotWhitelistedError, ConfidenceBelowCeilingError) as exc:
        raise HTTPException(status_code=403, detail=str(exc))


@router.get("/pt/evidence/{session_id}", dependencies=[Depends(require_roles(
    "security_analyst", "approver", "auditor", "super_admin"
))])
async def get_evidence(session_id: str, session=Depends(get_tenant_session)):
    records = (
        await session.execute(select(PtEvidence).where(PtEvidence.pt_session_id == session_id))
    ).scalars().all()
    return [
        {
            "id": str(r.id),
            "exploit_type": r.exploit_type,
            "tool_used": r.tool_used,
            "payload": r.payload,
            "response": r.response,
            "exploitation_confirmed": r.exploitation_confirmed,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in records
    ]


@router.get("/pt/sessions", dependencies=[Depends(require_roles("security_analyst", "approver", "super_admin"))])
async def list_pt_sessions(session=Depends(get_tenant_session)):
    sessions = (
        await session.execute(select(PtSession).order_by(PtSession.created_at.desc()))
    ).scalars().all()
    items = [
        {
            "id": str(s.id),
            "roe_id": str(s.roe_id) if s.roe_id else None,
            "objective": s.objective,
            "status": s.status,
            "created_at": s.created_at.isoformat() if s.created_at else None,
        }
        for s in sessions
    ]
    return {"items": items}
