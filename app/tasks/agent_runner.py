import logging

try:
    from celery import shared_task
except ImportError:  # pragma: no cover
    def shared_task(*args, **kwargs):
        def decorator(func):
            return func
        return decorator

from app.models.base import get_scoped_session, reset_async_db_state
from app.tasks.runtime import run_async_task

logger = logging.getLogger(__name__)


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def run_agent_task(self, agent_id: str, tenant_id: str, goal: str) -> dict:
    """
    Execute a persisted agent by ID, writing decision to agent_decisions table.
    Can be triggered on a schedule or via API.
    """
    reset_async_db_state()

    async def _run():
        from app.agents.catalog import AgentFactory

        async with get_scoped_session(tenant_id) as session:
            try:
                impl, agent_row = await AgentFactory.load_from_db(session, agent_id)
            except ValueError as exc:
                logger.warning("agent_runner: %s", exc)
                return {"agent_id": agent_id, "status": "skipped", "reason": str(exc)}

            if not agent_row.is_active:
                return {"agent_id": agent_id, "status": "skipped_inactive"}

            result = await impl.run(goal=goal, session=session, tenant_id=tenant_id)
            await session.commit()
            logger.info(
                "agent_runner.done agent_id=%s confidence=%d outcome=%s",
                agent_id, result.confidence, result.outcome,
            )
            return {
                "agent_id": agent_id,
                "status": "completed",
                "decision": result.decision,
                "confidence": result.confidence,
                "outcome": result.outcome,
            }

    return run_async_task(_run())
