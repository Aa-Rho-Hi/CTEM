from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import func, select

from app.core.security import CurrentUser, get_current_user, require_roles
from app.dependencies import get_tenant_session
from app.models.entities import Asset, BlastRadiusSnapshot, DryRunOutput, Remediation, RemediationApproval, Vulnerability
from app.schemas.common import AuditLogCreate
from app.schemas.mobilize import RemediationDecisionRequest
from app.services.approval_service import ApprovalService
from app.services.audit_writer import AuditWriter
from app.services.blast_radius import BlastRadiusService
from app.services.dry_run import DryRunService
from app.services.remediation_service import RemediationService

router = APIRouter(prefix="/mobilize", tags=["mobilize"])


async def _serialize_plan_response(session, remediation: Remediation):
    finding = await session.get(Vulnerability, remediation.vulnerability_id)
    asset = await session.get(Asset, finding.asset_id) if finding and finding.asset_id else None
    approval = (
        await session.execute(
            select(RemediationApproval)
            .where(RemediationApproval.remediation_id == remediation.id)
            .order_by(RemediationApproval.created_at.desc())
        )
    ).scalars().first()
    blast = (
        await session.execute(select(BlastRadiusSnapshot).where(BlastRadiusSnapshot.remediation_id == remediation.id))
    ).scalars().first()
    dry_run = (
        await session.execute(select(DryRunOutput).where(DryRunOutput.remediation_id == remediation.id))
    ).scalars().first()
    plan_data = remediation.plan or {}
    return {
        "remediation_plan": {
            "id": str(remediation.id),
            "fix_type": remediation.fix_type,
            "fix_steps": remediation.fix_steps,
            "rollback_steps": remediation.rollback_steps,
            "risk_narrative": remediation.risk_narrative,
            "business_impact": remediation.business_impact,
            "compliance_impact": remediation.compliance_impact,
            "estimated_effort": f"{remediation.estimated_effort_hours}h",
            "requires_downtime": remediation.requires_downtime,
            "status": remediation.status,
            "execution_status": remediation.execution_status,
            "approved_by": remediation.approved_by,
            "approval_reason": (
                approval.rationale
                if approval is not None and approval.status == "approved" and approval.rationale != "auto_approved"
                else None
            ),
            "rejection_reason": remediation.rejection_reason,
            "finding_id": str(remediation.vulnerability_id),
            "plan_source": plan_data.get("plan_source"),
            "plan": plan_data,
        },
        "finding": {"id": str(finding.id), "cve_id": finding.cve_id, "risk_score": finding.risk_score} if finding else None,
        "asset": {"id": str(asset.id), "ip": asset.ip_address} if asset else None,
        "blast_radius": blast.snapshot_json if blast else None,
        "dry_run": dry_run.output_json if dry_run else None,
        "approval_status": remediation.status,
    }


@router.get("/plan/{finding_id}", dependencies=[Depends(require_roles("security_analyst", "approver", "super_admin"))])
async def get_plan(
    finding_id: str,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    remediation = (
        await session.execute(
            select(Remediation)
            .where(Remediation.vulnerability_id == finding_id)
            .order_by(Remediation.created_at.desc())
        )
    ).scalars().first()
    if remediation is None:
        raise HTTPException(status_code=404, detail="Remediation plan not found.")
    return await _serialize_plan_response(session, remediation)


@router.post("/plan/{finding_id}", dependencies=[Depends(require_roles("security_analyst", "super_admin"))])
async def create_plan(
    finding_id: str,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    finding = await session.get(Vulnerability, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    remediation = await RemediationService().generate_plan(session, finding_id, str(current_user.tenant_id))
    asset = await session.get(Asset, finding.asset_id) if finding.asset_id else None
    blast = await BlastRadiusService().compute(session, str(asset.id), str(current_user.tenant_id), remediation_id=remediation.id) if asset else None
    dry_run = await DryRunService().generate(session, str(remediation.id), str(current_user.tenant_id))
    remediation = await ApprovalService().route_for_approval(session, str(remediation.id), str(current_user.tenant_id))
    await AuditWriter().write(
        session,
        current_user.tenant_id,
        AuditLogCreate(action="mobilize_plan_generated", resource_type="remediation", resource_id=str(remediation.id), details={"finding_id": finding_id}, user_id=current_user.user_id),
    )
    await session.commit()
    return await _serialize_plan_response(session, remediation)


@router.get("/queue", dependencies=[Depends(require_roles("approver", "super_admin"))])
async def approval_queue(
    limit: int = Query(default=100, ge=1, le=1000),
    offset: int = Query(default=0, ge=0),
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    total = (
        await session.execute(
            select(func.count(Remediation.id)).where(Remediation.status == "awaiting_approval")
        )
    ).scalar_one()
    rows = (
        await session.execute(
            select(Remediation, Vulnerability, Asset, BlastRadiusSnapshot, DryRunOutput)
            .join(Vulnerability, Vulnerability.id == Remediation.vulnerability_id)
            .outerjoin(Asset, Asset.id == Vulnerability.asset_id)
            .outerjoin(BlastRadiusSnapshot, BlastRadiusSnapshot.remediation_id == Remediation.id)
            .outerjoin(DryRunOutput, DryRunOutput.remediation_id == Remediation.id)
            .where(Remediation.status == "awaiting_approval")
            .order_by(Vulnerability.risk_score.desc(), Remediation.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
    ).all()
    items = []
    for remediation, finding, asset, blast, dry_run in rows:
        items.append(
            {
                "remediation_id": str(remediation.id),
                "finding_id": str(finding.id) if finding else None,
                "finding": {"cve_id": finding.cve_id, "risk_score": finding.risk_score, "sla_tier": finding.sla_tier},
                "asset": {"id": str(asset.id), "ip": asset.ip_address} if asset else None,
                "blast_radius": blast.snapshot_json if blast else None,
                "dry_run": dry_run.output_json if dry_run else None,
            }
        )
    return {"items": items, "limit": limit, "offset": offset, "total": total}


@router.get("/queue/{remediation_id}", dependencies=[Depends(require_roles("approver", "super_admin"))])
async def queue_detail(remediation_id: str, session=Depends(get_tenant_session), current_user: CurrentUser = Depends(get_current_user)):
    remediation = await session.get(Remediation, remediation_id)
    if remediation is None:
        raise HTTPException(status_code=404, detail="Remediation not found.")
    finding = await session.get(Vulnerability, remediation.vulnerability_id)
    asset = await session.get(Asset, finding.asset_id) if finding and finding.asset_id else None
    blast = (
        await session.execute(select(BlastRadiusSnapshot).where(BlastRadiusSnapshot.remediation_id == remediation.id))
    ).scalars().first()
    dry_run = (
        await session.execute(select(DryRunOutput).where(DryRunOutput.remediation_id == remediation.id))
    ).scalars().first()
    return {
        "remediation": remediation.plan,
        "finding": {"id": str(finding.id), "cve_id": finding.cve_id, "risk_score": finding.risk_score} if finding else None,
        "asset": {"id": str(asset.id), "ip": asset.ip_address} if asset else None,
        "blast_radius": blast.snapshot_json if blast else None,
        "dry_run": dry_run.output_json if dry_run else None,
    }


@router.post("/approve/{remediation_id}", dependencies=[Depends(require_roles("approver", "super_admin"))])
async def approve_route(
    remediation_id: str,
    payload: RemediationDecisionRequest,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    remediation = await ApprovalService().approve(
        session,
        remediation_id,
        str(current_user.user_id),
        payload.reason,
        str(current_user.tenant_id),
    )
    return {
        "id": str(remediation.id),
        "status": remediation.status,
        "approved_by": remediation.approved_by,
        "approval_reason": payload.reason,
    }


@router.post("/reject/{remediation_id}", dependencies=[Depends(require_roles("approver", "super_admin"))])
async def reject_route(
    remediation_id: str,
    payload: RemediationDecisionRequest,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    remediation = await ApprovalService().reject(session, remediation_id, str(current_user.user_id), payload.reason, str(current_user.tenant_id))
    return {"id": str(remediation.id), "status": remediation.status, "rejection_reason": remediation.rejection_reason}
