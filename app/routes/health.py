import asyncio

from fastapi import APIRouter, Depends

from app.dependencies import get_db_session, get_redis
from app.schemas.common import HealthResponse
from app.services.health import HealthService

router = APIRouter(tags=["health"])


@router.get("/health", response_model=HealthResponse)
async def healthcheck(session=Depends(get_db_session), redis=Depends(get_redis)) -> HealthResponse:
    service = HealthService(redis)
    postgres, redis_status, celery_queue_depth = await asyncio.gather(
        service.check_postgres(session),
        service.check_redis(),
        service.celery_queue_depth(),
    )
    return HealthResponse(
        status="ok",
        postgres=postgres,
        redis=redis_status,
        celery_queue_depth=celery_queue_depth,
    )
