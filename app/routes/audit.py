from datetime import date, datetime, time, timezone

from fastapi import APIRouter, Depends, HTTPException, Query
from sqlalchemy import String, cast, or_, select

from app.core.security import CurrentUser, get_current_user, require_roles
from app.dependencies import get_tenant_session
from app.models.entities import AuditLog, Remediation, User

router = APIRouter(prefix="/audit", tags=["audit"])


def _normalize_start_boundary(value: date | datetime | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.combine(value, time.min, tzinfo=timezone.utc)


def _normalize_end_boundary(value: date | datetime | None) -> datetime | None:
    if value is None or isinstance(value, datetime):
        return value
    return datetime.combine(value, time.max, tzinfo=timezone.utc)


def _entry_matches_finding(entry: AuditLog, finding_id: str, remediation_ids: set[str]) -> bool:
    if entry.resource_type == "vulnerability" and entry.resource_id == finding_id:
        return True
    if entry.resource_type == "remediation" and entry.resource_id in remediation_ids:
        return True
    details = entry.details or {}
    if details.get("finding_id") == finding_id:
        return True
    if details.get("remediation_id") in remediation_ids:
        return True
    return False


def _format_summary(action: str, resource_type: str, details: dict) -> str:
    """Return one human-readable sentence describing what happened."""
    d = details or {}
    templates: dict[str, str] = {
        "agent_created": f"Agent \"{d.get('name', resource_type)}\" created (type: {d.get('agent_type', '?')})",
        "agent_decommissioned": f"Agent decommissioned",
        "kill_switch_activated": "Kill switch activated — all PT activity halted",
        "kill_switch_deactivated": "Kill switch deactivated — PT activity resumed",
        "pt_session_created": f"PT session started (ROE: {str(d.get('roe_id','?'))[:8]}…, goal: {d.get('objective') or '?'})",
        "pt_probe_attempt": f"Probe attempted: {d.get('technique','?')} on {d.get('target_ip','?')} using {d.get('tool','?')}",
        "tanium_patch_initiated": f"Patch execution initiated on {d.get('asset_ip') or 'unknown asset'} (approved by {str(d.get('approved_by','?'))[:8]}…)",
        "remediation_approved": (
            f"Remediation approved for {d.get('cve_id') or resource_type}"
            + (f": {d.get('reason')}" if d.get("reason") else "")
        ),
        "remediation_rejected": f"Remediation rejected: {d.get('reason') or 'no reason given'}",
        "itsm_ticket_created": f"Ticket {d.get('ticket_id','?')} created for finding {str(d.get('finding_id','?'))[:8]}…",
        "graphrag_approval_edge_written": f"GraphRAG confidence boosted (approval on finding {str(d.get('finding_id','?'))[:8]}…)",
        "graphrag_rejection_edge_written": f"GraphRAG confidence penalised (rejection: {d.get('reason','?')})",
        "finding_verified_closed": f"Finding {str(d.get('finding_id') or resource_type)[:8]}… verified and closed",
        "roe_created": f"ROE created — CIDR {d.get('authorized_cidr','?')} valid until {d.get('valid_until','?')}",
        "roe_expired": f"ROE manually expired",
        "user_created": f"User {d.get('email','?')} registered with role {d.get('role','?')}",
        "user_deactivated": f"User account deactivated",
        "user_activated": f"User account reactivated",
        "pt_session_closed": f"PT session closed — status: {d.get('status','?')}",
        "sla_breach_in_2_days": f"SLA breach approaching within 2 days for {d.get('cve_id') or str(d.get('finding_id', resource_type))[:8]}…",
        "sla_breach_in_12_hours": f"SLA breach approaching within 12 hours for {d.get('cve_id') or str(d.get('finding_id', resource_type))[:8]}…",
        "sla_breached": f"SLA breached for {d.get('cve_id') or str(d.get('finding_id', resource_type))[:8]}…",
        "sla_escalation_queued": f"SLA escalation queued to ITSM for {d.get('cve_id') or str(d.get('finding_id', resource_type))[:8]}…",
        "sla_escalation_required": f"SLA escalation requires governance action for {d.get('cve_id') or str(d.get('finding_id', resource_type))[:8]}…",
    }
    return templates.get(action, f"{action.replace('_', ' ').capitalize()} on {resource_type}")


@router.get("/log", dependencies=[Depends(require_roles("auditor", "super_admin"))])
async def get_audit_log(
    user_id: str | None = Query(default=None),
    user: str | None = Query(default=None),
    action: str | None = Query(default=None),
    start_date: date | datetime | None = Query(default=None),
    end_date: date | datetime | None = Query(default=None),
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0),
    session=Depends(get_tenant_session),
):
    statement = select(AuditLog)
    start_at = _normalize_start_boundary(start_date)
    end_at = _normalize_end_boundary(end_date)
    if user_id:
        statement = statement.where(AuditLog.user_id == user_id)
    if user:
        normalized_user = user.strip()
        if normalized_user.lower() == "system":
            statement = statement.where(AuditLog.user_id.is_(None))
        elif normalized_user:
            user_search = f"%{normalized_user}%"
            statement = (
                statement
                .outerjoin(User, User.id == AuditLog.user_id)
                .where(
                    or_(
                        cast(AuditLog.user_id, String).ilike(user_search),
                        User.email.ilike(user_search),
                    )
                )
            )
    if action:
        statement = statement.where(AuditLog.action.ilike(f"%{action}%"))
    if start_at:
        statement = statement.where(AuditLog.created_at >= start_at)
    if end_at:
        statement = statement.where(AuditLog.created_at <= end_at)
    statement = statement.order_by(AuditLog.created_at.desc()).limit(limit).offset(offset)
    entries = (await session.execute(statement)).scalars().all()

    # resolve user emails in one query
    user_ids = {e.user_id for e in entries if e.user_id}
    user_map: dict[str, str] = {}
    if user_ids:
        users = (await session.execute(select(User).where(User.id.in_(user_ids)))).scalars().all()
        user_map = {str(u.id): u.email for u in users}

    return [
        {
            "id": str(e.id),
            "action": e.action,
            "summary": _format_summary(e.action, e.resource_type, e.details or {}),
            "resource_type": e.resource_type,
            "resource_id": e.resource_id,
            "user_id": str(e.user_id) if e.user_id else None,
            "actor": user_map.get(str(e.user_id)) if e.user_id else "system",
            "details": e.details,
            "created_at": e.created_at.isoformat() if e.created_at else None,
            "signature": e.signature,
        }
        for e in entries
    ]


@router.get("/log/{entry_id}", dependencies=[Depends(require_roles("auditor", "super_admin"))])
async def get_audit_entry(entry_id: str, session=Depends(get_tenant_session)):
    entry = await session.get(AuditLog, entry_id)
    if entry is None:
        raise HTTPException(status_code=404, detail="Audit log entry not found.")
    return {
        "id": str(entry.id),
        "action": entry.action,
        "resource_type": entry.resource_type,
        "resource_id": entry.resource_id,
        "user_id": str(entry.user_id) if entry.user_id else None,
        "details": entry.details,
        "created_at": entry.created_at.isoformat() if entry.created_at else None,
        "signature": entry.signature,
    }


@router.get("/pt-activity", dependencies=[Depends(require_roles("auditor", "super_admin"))])
async def get_pt_activity(
    limit: int = Query(default=50, le=500),
    offset: int = Query(default=0),
    session=Depends(get_tenant_session),
):
    statement = (
        select(AuditLog)
        .where(AuditLog.action.like("pt_%"))
        .order_by(AuditLog.created_at.desc())
        .limit(limit)
        .offset(offset)
    )
    entries = (await session.execute(statement)).scalars().all()
    return [
        {
            "id": str(e.id),
            "action": e.action,
            "resource_id": e.resource_id,
            "details": e.details,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in entries
    ]


@router.get("/finding/{finding_id}", dependencies=[Depends(require_roles(
    "security_analyst", "auditor", "super_admin"
))])
async def get_finding_audit(finding_id: str, session=Depends(get_tenant_session)):
    remediation_ids = {
        str(remediation.id)
        for remediation in (
            await session.execute(select(Remediation).where(Remediation.vulnerability_id == finding_id))
        ).scalars().all()
    }
    entries = (
        await session.execute(select(AuditLog).order_by(AuditLog.created_at.desc()).limit(500))
    ).scalars().all()
    entries = [entry for entry in entries if _entry_matches_finding(entry, finding_id, remediation_ids)]
    return [
        {
            "id": str(e.id),
            "resource_type": e.resource_type,
            "resource_id": e.resource_id,
            "action": e.action,
            "details": e.details,
            "created_at": e.created_at.isoformat() if e.created_at else None,
        }
        for e in entries
    ]
