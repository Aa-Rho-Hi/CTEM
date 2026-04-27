from fastapi import APIRouter, Depends, HTTPException, Query, Request
import msgpack
from pydantic import BaseModel
from sqlalchemy import func, select
from sqlalchemy.orm import joinedload, load_only

from app.core.security import CurrentUser, get_current_user, require_roles
from app.dependencies import get_redis, get_tenant_session
from app.models.entities import Asset, ComplianceControl, ComplianceFramework, FindingStatus, NetworkZone, Remediation, ScanFinding, Vulnerability, VulnerabilityControl
from app.schemas.common import AuditLogCreate
from app.services.attack_graph import AttackGraphService
from app.services.audit_writer import AuditWriter
from app.services.risk_engine import RiskEngine
from app.tasks.risk_scoring import rescore_vulnerability

router = APIRouter(prefix="/prioritize", tags=["prioritize"])


async def _latest_remediation_for_finding(session, finding_id: str):
    return (
        await session.execute(
            select(Remediation)
            .where(Remediation.vulnerability_id == finding_id)
            .order_by(Remediation.created_at.desc())
            .limit(1)
        )
    ).scalars().first()


def _risk_breakdown(item: Vulnerability, asset: Asset | None, zone: NetworkZone | None) -> dict[str, int]:
    business_context = (asset.business_context or {}) if asset else {}
    engine = RiskEngine()
    exploitability_score = engine._score_exploitability(
        cvss_base=float(item.cvss_score or 0),
        epss_prob=float(item.epss_score or 0),
        kev_flag=bool(item.is_kev),
        exploit_confirmed=False,
    )
    exposure_score = engine._score_exposure(
        asset_ip=asset.ip_address if asset else None,
        port=item.port,
        exposure_context={
            "internet_exposed": bool(business_context.get("external_attack_surface")),
            "external_attack_surface": bool(business_context.get("external_attack_surface")),
            "regulated_zone": bool(zone and (zone.pci or zone.hipaa)),
            "high_lateral_movement": bool(zone is not None),
        },
    )
    business_impact_score = engine._score_business_impact(
        asset_criticality_score=float(asset.criticality_score if asset else 0),
        crown_jewel_tier=(business_context.get("crown_jewel_tier") if isinstance(business_context, dict) else None)
        or None,
        business_context=business_context,
    )
    return {
        "exploitability_score": exploitability_score,
        "exposure_score": exposure_score,
        "business_impact_score": business_impact_score,
    }


def _display_finding_name(cve_id: str, normalized_payload: dict | None) -> str:
    if cve_id and not cve_id.startswith("GENERIC-"):
        return cve_id
    payload = normalized_payload or {}
    for key in ("description", "vulnerability", "title", "issue", "name"):
        value = payload.get(key)
        if isinstance(value, str) and value.strip():
            return value.strip()
    return cve_id


def _apply_finding_filters(
    statement,
    *,
    severity: str | None,
    status: str | None,
    sla_tier: str | None,
    asset_id: str | None,
    source_tool: str | None,
    cve_id: str | None,
):
    if severity:
        statement = statement.where(Vulnerability.severity == severity)
    if status:
        statement = statement.where(Vulnerability.status == status)
    if sla_tier:
        statement = statement.where(Vulnerability.sla_tier == sla_tier)
    if asset_id:
        statement = statement.where(Vulnerability.asset_id == asset_id)
    if source_tool:
        statement = statement.where(Vulnerability.source_tool == source_tool)
    if cve_id:
        statement = statement.where(Vulnerability.cve_id.ilike(f"%{cve_id.strip()}%"))
    return statement


@router.get("/findings", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor", "client_viewer"))])
async def list_findings(
    request: Request,
    cve_id: str | None = None,
    severity: str | None = None,
    status: str | None = None,
    sla_tier: str | None = None,
    asset_id: str | None = None,
    source_tool: str | None = None,
    scan_id: str | None = None,
    sort_by: str = Query(default="found_desc", pattern="^(found_desc|risk_desc)$"),
    limit: int = Query(default=50, le=200),
    offset: int = 0,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    order_column = Vulnerability.created_at.desc() if sort_by == "found_desc" else Vulnerability.risk_score.desc()
    id_statement = select(Vulnerability.id)
    count_statement = select(func.count()).select_from(Vulnerability)
    if scan_id:
        id_statement = (
            select(Vulnerability.id)
            .join(ScanFinding, ScanFinding.id == Vulnerability.scan_finding_id)
            .where(ScanFinding.scan_id == scan_id)
        )
        count_statement = (
            select(func.count())
            .select_from(Vulnerability)
            .join(ScanFinding, ScanFinding.id == Vulnerability.scan_finding_id)
            .where(ScanFinding.scan_id == scan_id)
        )
    id_statement = _apply_finding_filters(
        id_statement,
        severity=severity,
        status=status,
        sla_tier=sla_tier,
        asset_id=asset_id,
        source_tool=source_tool,
        cve_id=cve_id,
    )
    count_statement = _apply_finding_filters(
        count_statement,
        severity=severity,
        status=status,
        sla_tier=sla_tier,
        asset_id=asset_id,
        source_tool=source_tool,
        cve_id=cve_id,
    )
    id_statement = id_statement.order_by(order_column).limit(limit).offset(offset)
    total = (await session.execute(count_statement)).scalar_one()
    finding_ids = (await session.execute(id_statement)).scalars().all()
    if not finding_ids:
        return {
            "items": [],
            "limit": limit,
            "offset": offset,
            "total": total,
        }

    findings_statement = (
        select(Vulnerability)
        .where(Vulnerability.id.in_(finding_ids))
        .options(
            joinedload(Vulnerability.asset)
            .load_only(
                Asset.id,
                Asset.ip_address,
                Asset.hostname,
                Asset.zone_id,
                Asset.criticality_score,
                Asset.business_context,
            )
            .joinedload(Asset.zone)
            .load_only(NetworkZone.id, NetworkZone.pci, NetworkZone.hipaa),
        )
    )
    findings = (await session.execute(findings_statement)).scalars().unique().all()
    findings_by_id = {str(item.id): item for item in findings}
    ordered_findings = [findings_by_id[str(finding_id)] for finding_id in finding_ids if str(finding_id) in findings_by_id]
    scan_finding_ids = [item.scan_finding_id for item in ordered_findings if item.scan_finding_id is not None]
    scan_findings = (
        await session.execute(select(ScanFinding).where(ScanFinding.id.in_(scan_finding_ids)))
    ).scalars().all() if scan_finding_ids else []
    scan_finding_by_id = {str(item.id): item for item in scan_findings}

    latest_remediation_ranked = (
        select(
            Remediation.vulnerability_id.label("vulnerability_id"),
            Remediation.status.label("status"),
            Remediation.execution_status.label("execution_status"),
            func.row_number().over(
                partition_by=Remediation.vulnerability_id,
                order_by=(Remediation.created_at.desc(), Remediation.id.desc()),
            ).label("rownum"),
        )
        .where(Remediation.vulnerability_id.in_(finding_ids))
        .subquery()
    )
    latest_remediations = (
        await session.execute(
            select(
                latest_remediation_ranked.c.vulnerability_id,
                latest_remediation_ranked.c.status,
                latest_remediation_ranked.c.execution_status,
            ).where(latest_remediation_ranked.c.rownum == 1)
        )
    ).all()
    remediation_by_finding_id = {
        str(vulnerability_id): {"status": remediation_status, "execution_status": execution_status}
        for vulnerability_id, remediation_status, execution_status in latest_remediations
    }
    return {
        "items": [
            {
                "id": str(item.id),
                "cve_id": item.cve_id,
                "display_name": _display_finding_name(
                    item.cve_id,
                    (scan_finding_by_id.get(str(item.scan_finding_id)).normalized_payload if item.scan_finding_id else None),
                ),
                "risk_score": item.risk_score,
                "severity": item.severity,
                "status": item.status.value if hasattr(item.status, "value") else item.status,
                "sla_tier": item.sla_tier,
                "source_tool": item.source_tool,
                "found_at": item.first_seen.isoformat() if item.first_seen else (item.created_at.isoformat() if item.created_at else None),
                "asset": (
                    {
                        "ip_address": item.asset.ip_address,
                        "hostname": item.asset.hostname,
                    }
                    if item.asset
                    else None
                ),
                **_risk_breakdown(
                    item,
                    item.asset,
                    item.asset.zone if item.asset and item.asset.zone_id else None,
                ),
                "remediation_status": remediation_by_finding_id.get(str(item.id), {}).get("status"),
                "remediation_execution_status": remediation_by_finding_id.get(str(item.id), {}).get("execution_status"),
            }
            for item in ordered_findings
        ],
        "limit": limit,
        "offset": offset,
        "total": total,
    }


@router.get("/findings/{finding_id}", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor", "client_viewer"))])
async def get_finding_detail(
    finding_id: str,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    finding = await session.get(Vulnerability, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    attack_paths = []
    asset = await session.get(Asset, finding.asset_id) if finding.asset_id else None
    control_rows = (
        await session.execute(
            select(ComplianceControl, ComplianceFramework)
            .join(VulnerabilityControl, VulnerabilityControl.control_id == ComplianceControl.id)
            .join(ComplianceFramework, ComplianceFramework.id == ComplianceControl.framework_id)
            .where(VulnerabilityControl.vulnerability_id == finding.id)
        )
    ).all()
    mapped_controls = [
        {
            "framework": framework.name,
            "control_id": control.control_id,
            "title": control.title,
        }
        for control, framework in control_rows
    ]
    scan_finding = await session.get(ScanFinding, finding.scan_finding_id) if finding.scan_finding_id else None
    latest_remediation = await _latest_remediation_for_finding(session, finding.id)
    zone = await session.get(NetworkZone, asset.zone_id) if asset and asset.zone_id else None
    normalized_payload = scan_finding.normalized_payload if scan_finding else None
    return {
        "id": str(finding.id),
        "cve_id": finding.cve_id,
        "display_name": _display_finding_name(finding.cve_id, normalized_payload),
        "cvss_score": finding.cvss_score,
        "cvss_vector": finding.cvss_vector,
        "epss_score": finding.epss_score,
        "is_kev": finding.is_kev,
        "risk_score": finding.risk_score,
        "severity": finding.severity,
        "sla_tier": finding.sla_tier,
        "status": finding.status.value if hasattr(finding.status, "value") else finding.status,
        "remediation_status": latest_remediation.status if latest_remediation else None,
        "remediation_execution_status": latest_remediation.execution_status if latest_remediation else None,
        "verified_at": finding.verified_at.isoformat() if finding.verified_at else None,
        "attack_paths": attack_paths,
        "cwe_id": finding.cwe_id,
        "controls": mapped_controls,
        "asset": (
            {
                "ip_address": asset.ip_address,
                "hostname": asset.hostname,
            }
            if asset
            else None
        ),
        "source_tool": finding.source_tool,
        "sla_due_date": finding.sla_due_date.isoformat() if finding.sla_due_date else None,
        "scan_finding": normalized_payload,
        **_risk_breakdown(finding, asset, zone),
    }


@router.get("/choke-points", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor", "client_viewer"))])
async def choke_points(
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    data = await AttackGraphService().get_choke_points(session)
    return {"items": data}


@router.get("/attack-surface", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor", "client_viewer"))])
async def attack_surface(
    session=Depends(get_tenant_session),
    redis=Depends(get_redis),
    current_user: CurrentUser = Depends(get_current_user),
):
    cache_key = f"attack_surface:v4:{current_user.tenant_id}"
    legacy_cache_key = f"attack_surface:{current_user.tenant_id}"
    prior_cache_key = f"attack_surface:v2:{current_user.tenant_id}"
    previous_cache_key = f"attack_surface:v3:{current_user.tenant_id}"
    try:
        cached = await redis.get(cache_key)
    except Exception:
        cached = None
    if cached:
        try:
            return msgpack.unpackb(cached, raw=False)
        except Exception:
            pass
    data = await AttackGraphService().get_attack_surface(session, current_user.tenant_id)
    try:
        await redis.delete(legacy_cache_key)
        await redis.delete(prior_cache_key)
        await redis.delete(previous_cache_key)
        await redis.set(cache_key, msgpack.packb(data, use_bin_type=True), ex=300)
    except Exception:
        pass
    return data


@router.get("/attack-paths/{asset_id}", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver", "auditor", "client_viewer"))])
async def attack_paths(
    asset_id: str,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    crown_assets = (await session.execute(select(Asset).where(Asset.crown_jewel_tier_id.is_not(None), Asset.id != asset_id))).scalars().all()
    service = AttackGraphService()
    all_paths = []
    for target in crown_assets:
        all_paths.extend(await service.get_attack_path_details(session, asset_id, str(target.id)))
    return {"asset_id": asset_id, "paths": all_paths}


class FindingStatusPatch(BaseModel):
    status: str


@router.patch("/findings/{finding_id}/status", dependencies=[Depends(require_roles("super_admin"))])
async def patch_finding_status(
    finding_id: str,
    payload: FindingStatusPatch,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    valid = {"open", "approved", "in_progress", "fixed", "verified", "closed", "rejected"}
    if payload.status not in valid:
        raise HTTPException(status_code=400, detail=f"Invalid status. Must be one of: {sorted(valid)}")
    finding = await session.get(Vulnerability, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    old_status = finding.status.value if hasattr(finding.status, "value") else finding.status
    finding.status = FindingStatus(payload.status)
    await AuditWriter().write(
        session,
        current_user.tenant_id,
        AuditLogCreate(
            action="finding_status_override",
            resource_type="vulnerability",
            resource_id=finding_id,
            user_id=current_user.user_id,
            details={"from": old_status, "to": payload.status},
        ),
    )
    await session.commit()
    return {"id": finding_id, "status": payload.status}


@router.post("/rescore/{finding_id}", dependencies=[Depends(require_roles("super_admin", "security_analyst", "approver"))])
async def rescore(
    finding_id: str,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    finding = await session.get(Vulnerability, finding_id)
    if finding is None:
        raise HTTPException(status_code=404, detail="Finding not found.")
    rescore_vulnerability.delay(finding_id, str(current_user.tenant_id))
    await AuditWriter().write(
        session,
        current_user.tenant_id,
        AuditLogCreate(action="prioritize_rescore", resource_type="vulnerability", resource_id=finding_id, details={}, user_id=current_user.user_id),
    )
    await session.commit()
    return {"status": "queued", "finding_id": finding_id}
