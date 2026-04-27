from datetime import datetime

from fastapi import APIRouter, Depends, Query
from fastapi.responses import Response

from app.application.governance.use_cases import GovernanceSlaExportUseCase, GovernanceSlaReportUseCase
from app.core.security import require_roles
from app.dependencies import get_tenant_session
from app.infrastructure.persistence.governance_repository import GovernanceRepository
from app.routes._shared import STANDARD_ERROR_RESPONSES
from app.schemas.governance import SlaReportResponse

router = APIRouter(prefix="/governance", tags=["governance"])


def _build_csv_filename() -> str:
    return f"sla-governance-report-{datetime.utcnow().strftime('%Y%m%d-%H%M%S')}.csv"


@router.get(
    "/sla-report",
    response_model=SlaReportResponse,
    responses=STANDARD_ERROR_RESPONSES,
    dependencies=[Depends(require_roles("super_admin", "platform_admin", "approver", "auditor"))],
)
async def sla_report(
    limit: int = Query(default=250, ge=1, le=5000),
    session=Depends(get_tenant_session),
) -> SlaReportResponse:
    return SlaReportResponse.model_validate(
        await GovernanceSlaReportUseCase(GovernanceRepository(session)).execute(limit=limit)
    )


@router.get(
    "/sla-report/export",
    responses=STANDARD_ERROR_RESPONSES,
    dependencies=[Depends(require_roles("super_admin", "platform_admin", "approver", "auditor"))],
)
async def export_sla_report(
    limit: int = Query(default=1000, ge=1, le=10000),
    session=Depends(get_tenant_session),
) -> Response:
    csv_text = await GovernanceSlaExportUseCase(
        GovernanceSlaReportUseCase(GovernanceRepository(session))
    ).execute(limit=limit)
    return Response(
        content=csv_text,
        media_type="text/csv",
        headers={"Content-Disposition": f'attachment; filename="{_build_csv_filename()}"'},
    )
