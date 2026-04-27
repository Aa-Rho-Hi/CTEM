from datetime import datetime

from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel
from sqlalchemy import select

from app.core.security import CurrentUser, get_current_user, require_roles
from app.dependencies import get_tenant_session
from app.models.entities import RoeRecord
from app.services.roe_service import ROEService

router = APIRouter(prefix="/roe", tags=["roe"])


class ROECreate(BaseModel):
    authorized_cidr: str
    authorized_techniques: list[str]
    valid_from: datetime
    valid_until: datetime
    scope_notes: str = ""


@router.post("", status_code=201, dependencies=[Depends(require_roles("approver", "super_admin"))])
async def create_roe(
    payload: ROECreate,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    try:
        roe = await ROEService().create(session, payload, current_user.user_id, str(current_user.tenant_id))
        await session.commit()
    except ValueError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    return {
        "id": str(roe.id),
        "authorized_cidr": roe.authorized_cidr,
        "authorized_techniques": roe.authorized_techniques,
        "authorized_by": roe.authorized_by,
        "valid_from": roe.valid_from.isoformat() if roe.valid_from else None,
        "valid_until": roe.valid_until.isoformat() if roe.valid_until else None,
        "scope_notes": roe.scope_notes,
        "status": roe.status,
    }


@router.get("", dependencies=[Depends(require_roles(
    "super_admin", "security_analyst", "approver", "auditor", "client_viewer"
))])
async def list_roe(session=Depends(get_tenant_session)):
    records = (await session.execute(select(RoeRecord).order_by(RoeRecord.created_at.desc()))).scalars().all()
    return [
        {
            "id": str(r.id),
            "authorized_cidr": r.authorized_cidr,
            "authorized_techniques": r.authorized_techniques,
            "status": r.status,
            "valid_until": r.valid_until.isoformat() if r.valid_until else None,
            "scope_notes": r.scope_notes,
            "created_at": r.created_at.isoformat() if r.created_at else None,
        }
        for r in records
    ]


@router.get("/{roe_id}", dependencies=[Depends(require_roles(
    "super_admin", "security_analyst", "approver", "auditor", "client_viewer"
))])
async def get_roe(roe_id: str, session=Depends(get_tenant_session)):
    roe = await session.get(RoeRecord, roe_id)
    if roe is None:
        raise HTTPException(status_code=404, detail="ROE not found.")
    return {
        "id": str(roe.id),
        "authorized_cidr": roe.authorized_cidr,
        "authorized_techniques": roe.authorized_techniques,
        "authorized_by": roe.authorized_by,
        "valid_from": roe.valid_from.isoformat() if roe.valid_from else None,
        "valid_until": roe.valid_until.isoformat() if roe.valid_until else None,
        "scope_notes": roe.scope_notes,
        "status": roe.status,
    }


@router.post("/{roe_id}/expire", dependencies=[Depends(require_roles("super_admin"))])
async def expire_roe(
    roe_id: str,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    from app.services.errors import ROENotFoundError
    try:
        roe = await ROEService().expire(session, roe_id, current_user.user_id, str(current_user.tenant_id))
        await session.commit()
    except ROENotFoundError as exc:
        raise HTTPException(status_code=404, detail=str(exc))
    return {"id": str(roe.id), "status": roe.status}
