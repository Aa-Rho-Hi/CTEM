from datetime import datetime, time, timezone

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from app.core.security import CurrentUser, get_current_user, require_roles
from app.dependencies import get_redis, get_tenant_session
from app.models.entities import Asset, AuditLog, Remediation, Vulnerability
from app.services.change_window import ChangeWindowService
from app.services.errors import ChangeWindowBlockedError
from app.services.kill_switch import KillSwitchService
from app.services.tanium import TaniumService
from app.tasks.remediation_exec import execute_remediation_task

router = APIRouter(prefix="/remediation", tags=["remediation"])


@router.post("/execute/{remediation_id}", dependencies=[Depends(require_roles("security_analyst", "super_admin"))])
async def execute_remediation(
    remediation_id: str,
    session=Depends(get_tenant_session),
    redis=Depends(get_redis),
    current_user: CurrentUser = Depends(get_current_user),
):
    remediation = await session.get(Remediation, remediation_id)
    if remediation is None:
        raise HTTPException(status_code=404, detail="Remediation not found.")
    if remediation.status != "approved":
        raise HTTPException(status_code=409, detail="Remediation is not approved yet.")
    finding = await session.get(Vulnerability, remediation.vulnerability_id)
    asset = await session.get(Asset, finding.asset_id) if finding and finding.asset_id else None
    try:
        if asset is not None:
            await ChangeWindowService().is_execution_allowed(session, str(asset.id), str(current_user.tenant_id))
    except ChangeWindowBlockedError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    if await KillSwitchService(redis).is_active():
        raise HTTPException(status_code=503, detail="Kill switch active.")
    remediation.status = "in_progress"
    remediation.execution_status = "in_progress"
    if finding is not None:
        finding.status = "in_progress"
    await session.commit()
    execute_remediation_task.delay(remediation_id, str(current_user.tenant_id))
    return {"action_id": "mock-tanium-001", "status": "in_progress", "message": "Execution queued"}


@router.get("/status/{remediation_id}", dependencies=[Depends(require_roles("security_analyst", "approver", "super_admin"))])
async def remediation_status(remediation_id: str, session=Depends(get_tenant_session), current_user: CurrentUser = Depends(get_current_user)):
    remediation = await session.get(Remediation, remediation_id)
    if remediation is None:
        raise HTTPException(status_code=404, detail="Remediation not found.")
    logs = (
        await session.execute(select(AuditLog).where(AuditLog.resource_id == remediation_id).order_by(AuditLog.created_at.desc()))
    ).scalars().all()
    return {"status": remediation.status, "audit_logs": [{"action": log.action, "details": log.details} for log in logs[:10]]}


@router.post("/verify/{remediation_id}", dependencies=[Depends(require_roles("security_analyst", "super_admin"))])
async def verify(
    remediation_id: str,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    from app.tasks.remediation_exec import verify_remediation_task
    remediation = await session.get(Remediation, remediation_id)
    if remediation is None:
        raise HTTPException(status_code=404, detail="Remediation not found.")
    if remediation.status not in ("in_progress", "fixed"):
        raise HTTPException(
            status_code=409,
            detail=f"Cannot verify: status is '{remediation.status}', expected 'in_progress' or 'fixed'.",
        )
    task = verify_remediation_task.delay(remediation_id, str(current_user.tenant_id))
    return {"status": "verification_queued", "task_id": task.id}


@router.get("/history", dependencies=[Depends(require_roles("security_analyst", "approver", "super_admin"))])
async def remediation_history(
    status: str | None = None,
    asset_id: str | None = None,
    sla_tier: str | None = None,
    date_from: str | None = None,
    date_to: str | None = None,
    limit: int = 50,
    offset: int = 0,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    statement = select(Remediation)
    if status:
        statement = statement.where(Remediation.status == status)
    if date_from:
        try:
            start = datetime.fromisoformat(date_from).replace(tzinfo=timezone.utc)
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid date_from. Use ISO format YYYY-MM-DD.") from exc
        statement = statement.where(Remediation.created_at >= start)
    if date_to:
        try:
            end_date = datetime.fromisoformat(date_to).date()
        except ValueError as exc:
            raise HTTPException(status_code=400, detail="Invalid date_to. Use ISO format YYYY-MM-DD.") from exc
        end = datetime.combine(end_date, time.max, tzinfo=timezone.utc)
        statement = statement.where(Remediation.created_at <= end)
    statement = statement.order_by(Remediation.created_at.desc()).limit(limit).offset(offset)
    remediations = (await session.execute(statement)).scalars().all()
    items = []
    for remediation in remediations:
        finding = await session.get(Vulnerability, remediation.vulnerability_id)
        if asset_id and (finding is None or str(finding.asset_id) != asset_id):
            continue
        if sla_tier and (finding is None or finding.sla_tier != sla_tier):
            continue
        items.append(
            {
                "id": str(remediation.id),
                "status": remediation.status,
                "finding_id": str(remediation.vulnerability_id),
                "asset_id": str(finding.asset_id) if finding and finding.asset_id else None,
                "sla_tier": finding.sla_tier if finding else None,
                "created_at": remediation.created_at.isoformat() if remediation.created_at else None,
            }
        )
    return {"items": items, "limit": limit, "offset": offset}
