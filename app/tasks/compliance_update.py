import asyncio
from datetime import datetime, timezone

try:
    from celery import shared_task
except ImportError:  # pragma: no cover
    def shared_task(*args, **kwargs):
        def decorator(func):
            return func

        return decorator
from sqlalchemy import select

from app.models.base import get_scoped_session, reset_async_db_state
from app.models.entities import ComplianceFramework, ComplianceScore
from app.services.compliance_scoring import framework_score_breakdown
from app.tasks.runtime import run_async_task


async def recalculate_scores_in_session(session, tenant_id: str) -> dict:
    frameworks = (await session.execute(select(ComplianceFramework))).scalars().all()
    results = {}
    for framework in frameworks:
        breakdown = await framework_score_breakdown(session, framework.id)
        score_pct = breakdown["score"]
        existing = (
            await session.execute(select(ComplianceScore).where(ComplianceScore.framework_id == framework.id))
        ).scalar_one_or_none()
        metadata_json = {
            "calculated_at": datetime.now(timezone.utc).isoformat(),
            "mode": "synchronous",
            "total_controls": breakdown["total_controls"],
            "passing_controls": breakdown["passing_controls"],
            "failing_controls": breakdown["failing_controls"],
        }
        if existing is None:
            existing = ComplianceScore(
                tenant_id=tenant_id,
                framework_id=framework.id,
                score=score_pct,
                metadata_json=metadata_json,
            )
            session.add(existing)
        else:
            existing.score = score_pct
            existing.metadata_json = metadata_json
        results[framework.name] = score_pct
    await session.flush()
    return results


async def _recalculate_all_scores(tenant_id: str) -> dict:
    async with get_scoped_session(tenant_id) as session:
        results = await recalculate_scores_in_session(session, tenant_id)
        await session.commit()
        return results


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def recalculate_all_scores(self, tenant_id: str) -> dict:
    reset_async_db_state()
    return run_async_task(_recalculate_all_scores(tenant_id))


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def update_scores_for_status_change(self, tenant_id: str) -> dict:
    reset_async_db_state()
    return run_async_task(_recalculate_all_scores(tenant_id))
