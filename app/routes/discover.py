from pathlib import Path

from fastapi import APIRouter, Depends, File, HTTPException, UploadFile
from pydantic import BaseModel

from celery_app import celery_app

from app.application.discovery.use_cases import (
    GetScanStatusUseCase,
    RefreshExternalDiscoveryUseCase,
    ScanNotFoundError,
    StartActiveScanUseCase,
    UploadScanUseCase,
    external_discovery_options_for_environment,
)
from app.config import get_settings
from app.core.security import require_roles
from app.dependencies import get_tenant_session
from app.infrastructure.persistence.discovery_repository import DiscoveryRepository
from app.routes._shared import STANDARD_ERROR_RESPONSES
from app.schemas.common import MessageResponse
from app.schemas.discover import ActiveScanRequest
from app.services.discover_service import canonical_tool_name, infer_source_tool

router = APIRouter(prefix="/discover", tags=["discover"])


class ScanStatusResponse(BaseModel):
    id: str
    source_tool: str
    status: str
    created_at: str | None
    finding_count: int
    vulnerability_count: int
    vulnerability_ids: list[str]
    duplicate_count: int
    skipped_no_cve_count: int
    generic_finding_count: int
    error: str | None = None


def _external_discovery_options() -> dict:
    return external_discovery_options_for_environment(get_settings().environment)


@router.post("/scan/active", response_model=MessageResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "security_analyst"))])
async def start_active_scan(payload: ActiveScanRequest, session=Depends(get_tenant_session)) -> MessageResponse:
    use_case = StartActiveScanUseCase(
        DiscoveryRepository(session),
        celery_app,
        canonical_tool_name=canonical_tool_name,
    )
    return MessageResponse(message=await use_case.execute(payload))


@router.post("/scan/upload", response_model=MessageResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "security_analyst"))])
async def upload_scan(file: UploadFile = File(...), session=Depends(get_tenant_session)) -> MessageResponse:
    content = await file.read()
    content_str = content.decode("utf-8", errors="ignore")
    use_case = UploadScanUseCase(
        DiscoveryRepository(session),
        celery_app,
        infer_source_tool=infer_source_tool,
    )
    return MessageResponse(
        message=await use_case.execute(filename=file.filename or Path("upload").name, content=content_str)
    )


@router.get("/scan/{scan_id}", response_model=ScanStatusResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "security_analyst"))])
async def get_scan_status(scan_id: str, session=Depends(get_tenant_session)) -> ScanStatusResponse:
    use_case = GetScanStatusUseCase(DiscoveryRepository(session))
    try:
        result = await use_case.execute(scan_id)
    except ScanNotFoundError:
        raise HTTPException(status_code=404, detail="Scan not found.")
    return ScanStatusResponse(
        id=result.id,
        source_tool=result.source_tool,
        status=result.status,
        created_at=result.created_at,
        finding_count=result.finding_count,
        vulnerability_count=result.vulnerability_count,
        vulnerability_ids=result.vulnerability_ids,
        duplicate_count=result.duplicate_count,
        skipped_no_cve_count=result.skipped_no_cve_count,
        generic_finding_count=result.generic_finding_count,
        error=result.error,
    )


@router.post("/external/refresh", response_model=MessageResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "security_analyst"))])
async def refresh_external_discovery(session=Depends(get_tenant_session)) -> MessageResponse:
    use_case = RefreshExternalDiscoveryUseCase(
        DiscoveryRepository(session),
        celery_app,
        environment=get_settings().environment,
    )
    return MessageResponse(message=await use_case.execute())
