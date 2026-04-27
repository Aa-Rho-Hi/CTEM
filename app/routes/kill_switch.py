from fastapi import APIRouter, Depends
from pydantic import BaseModel

from app.core.security import CurrentUser, get_current_user, require_roles
from app.dependencies import get_redis, get_tenant_session
from app.routes._shared import STANDARD_ERROR_RESPONSES
from app.services.audit_writer import AuditWriter
from app.services.kill_switch import KillSwitchService

router = APIRouter(prefix="/kill-switch", tags=["kill-switch"])


class KillSwitchStatusResponse(BaseModel):
    active: bool
    redis_reachable: bool


@router.post("/activate", response_model=KillSwitchStatusResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "security_analyst"))])
async def activate(
    current_user: CurrentUser = Depends(get_current_user),
    redis=Depends(get_redis),
    session=Depends(get_tenant_session),
):
    svc = KillSwitchService(redis)
    await svc.activate(current_user.user_id, str(current_user.tenant_id), AuditWriter(), session)
    await session.commit()
    return await svc.get_status()


@router.post("/deactivate", response_model=KillSwitchStatusResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin"))])
async def deactivate(
    current_user: CurrentUser = Depends(get_current_user),
    redis=Depends(get_redis),
    session=Depends(get_tenant_session),
):
    svc = KillSwitchService(redis)
    await svc.deactivate(current_user.user_id, str(current_user.tenant_id), AuditWriter(), session)
    await session.commit()
    return await svc.get_status()


@router.get("/status", response_model=KillSwitchStatusResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles(
    "super_admin", "security_analyst", "approver", "auditor", "client_viewer"
))])
async def status(redis=Depends(get_redis)):
    return await KillSwitchService(redis).get_status()
