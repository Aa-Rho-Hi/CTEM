from collections import defaultdict

from fastapi import APIRouter, Depends, Query
from sqlalchemy import select

from app.core.security import CurrentUser, get_current_user, require_roles
from app.dependencies import get_tenant_session
from app.models.entities import ComplianceFramework, FindingStatus, Vulnerability
from app.services.compliance_mapper import ComplianceMapper
from app.services.compliance_scoring import framework_score_breakdown

router = APIRouter(prefix="/dashboard", tags=["dashboard"])


@router.get("/exposure", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor", "client_viewer"))])
async def exposure(session=Depends(get_tenant_session), current_user: CurrentUser = Depends(get_current_user)):
    findings = (
        await session.execute(select(Vulnerability).where(Vulnerability.status != FindingStatus.closed))
    ).scalars().all()
    score = round(sum(item.risk_score for item in findings) / len(findings), 2) if findings else 0.0
    return {"exposure_score": score}


@router.get("/trend", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor", "client_viewer"))])
async def trend(
    days: int = Query(default=30),
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    findings = (await session.execute(select(Vulnerability))).scalars().all()
    buckets = defaultdict(list)
    for finding in findings:
        buckets[finding.created_at.date().isoformat()].append(finding.risk_score)
    data = [{"date": day, "score": round(sum(values) / len(values), 2)} for day, values in sorted(buckets.items())][-days:]
    return {"days": days, "points": data}


@router.get("/risk-dollars", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor", "client_viewer"))])
async def risk_dollars(session=Depends(get_tenant_session), current_user: CurrentUser = Depends(get_current_user)):
    findings = (await session.execute(select(Vulnerability))).scalars().all()
    weights = {"Critical": 50000, "High": 10000, "Medium": 1000, "Low": 100}
    breakdown = {severity: {"count": 0, "dollars": 0} for severity in weights}
    for finding in findings:
        if finding.severity not in breakdown:
            breakdown[finding.severity] = {"count": 0, "dollars": 0}
        breakdown[finding.severity]["count"] += 1
        breakdown[finding.severity]["dollars"] += weights.get(finding.severity, 0)
    return {
        "by_severity": breakdown,
        "total_dollars": sum(item["dollars"] for item in breakdown.values()),
    }


@router.get("/compliance-summary", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor", "client_viewer"))])
async def compliance_summary(session=Depends(get_tenant_session), current_user: CurrentUser = Depends(get_current_user)):
    await ComplianceMapper().ensure_frameworks_and_controls(session)
    frameworks = (await session.execute(select(ComplianceFramework))).scalars().all()
    rows = []
    for framework in frameworks:
        breakdown = await framework_score_breakdown(session, framework.id)
        rows.append({"framework": framework.name, "score": breakdown["score"]})
    return {"frameworks": rows}
