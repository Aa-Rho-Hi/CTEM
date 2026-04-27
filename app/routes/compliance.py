from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy import select

from app.core.security import CurrentUser, get_current_user, require_roles
from app.dependencies import get_tenant_session
from app.models.entities import ComplianceControl, ComplianceFramework, Vulnerability, VulnerabilityControl
from app.services.compliance_mapper import ComplianceMapper
from app.services.compliance_scoring import framework_score_breakdown

router = APIRouter(prefix="/compliance", tags=["compliance"])


async def _framework_breakdown(session, framework_id):
    breakdown = await framework_score_breakdown(session, framework_id)
    return breakdown["score"], breakdown["controls"]


@router.get("/posture", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor"))])
async def posture(session=Depends(get_tenant_session), current_user: CurrentUser = Depends(get_current_user)):
    mapper = ComplianceMapper()
    await mapper.ensure_frameworks_and_controls(session)
    frameworks = (await session.execute(select(ComplianceFramework))).scalars().all()
    posture_rows = []
    for framework in frameworks:
        score, controls = await _framework_breakdown(session, framework.id)
        open_findings = sum(control["open_findings"] for control in controls)
        posture_rows.append(
            {
                "framework": framework.name,
                "score": score,
                "open_findings": open_findings,
                "failing_controls": sum(1 for control in controls if not control["passing"]),
            }
        )
    return {"frameworks": posture_rows}


@router.get("/posture/{framework}", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor"))])
async def posture_detail(framework: str, session=Depends(get_tenant_session), current_user: CurrentUser = Depends(get_current_user)):
    mapper = ComplianceMapper()
    await mapper.ensure_frameworks_and_controls(session)
    framework_row = (
        await session.execute(select(ComplianceFramework).where(ComplianceFramework.name == framework))
    ).scalar_one_or_none()
    if framework_row is None:
        raise HTTPException(status_code=404, detail="Framework not found.")
    score, control_breakdown = await _framework_breakdown(session, framework_row.id)
    return {
        "framework": framework_row.name,
        "score": score,
        "failing_controls": [
            {
                "control_id": control["control_id"],
                "title": control["title"],
                "finding_count": control["open_findings"],
            }
            for control in control_breakdown
            if not control["passing"]
        ],
        "controls": control_breakdown,
    }


@router.get("/findings/{framework}", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor"))])
async def framework_findings(framework: str, session=Depends(get_tenant_session), current_user: CurrentUser = Depends(get_current_user)):
    mapper = ComplianceMapper()
    await mapper.ensure_frameworks_and_controls(session)
    framework_row = (
        await session.execute(select(ComplianceFramework).where(ComplianceFramework.name == framework))
    ).scalar_one_or_none()
    if framework_row is None:
        raise HTTPException(status_code=404, detail="Framework not found.")
    findings = (
        await session.execute(
            select(Vulnerability, ComplianceControl)
            .join(VulnerabilityControl, Vulnerability.id == VulnerabilityControl.vulnerability_id)
            .join(ComplianceControl, ComplianceControl.id == VulnerabilityControl.control_id)
            .where(ComplianceControl.framework_id == framework_row.id)
        )
    ).all()
    return {
        "framework": framework,
        "items": [
            {
                "finding_id": str(vulnerability.id),
                "cve_id": vulnerability.cve_id,
                "control_id": control.control_id,
                "severity": vulnerability.severity,
                "status": vulnerability.status.value if hasattr(vulnerability.status, "value") else vulnerability.status,
            }
            for vulnerability, control in findings
        ],
    }
