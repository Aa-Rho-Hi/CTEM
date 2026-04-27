try:
    from celery import shared_task
except ImportError:  # pragma: no cover
    def shared_task(*args, **kwargs):
        def decorator(func):
            return func

        return decorator

from app.application.governance.maintenance import SlaMaintenanceUseCase
from app.infrastructure.persistence.governance_repository import GovernanceRepository
from app.models.base import get_scoped_session, reset_async_db_state
from app.services.audit_writer import AuditWriter
from app.services.splunk import SplunkService
from app.tasks.runtime import run_async_task


async def _monitor_tenant_slas(tenant_id: str) -> dict[str, int | str]:
    async with get_scoped_session(tenant_id) as session:
        summary = await SlaMaintenanceUseCase(
            GovernanceRepository(session),
            audit_writer=AuditWriter(),
            alert_sender=lambda event: SplunkService().send_event("atlas:sla_alert", event),
            queue_itsm_ticket=_queue_itsm_ticket,
        ).execute(tenant_id=tenant_id)
        return {
            "tenant_id": summary.tenant_id,
            "total_tracked": summary.total_tracked,
            "breach_in_2_days": summary.breach_in_2_days,
            "breach_in_12_hours": summary.breach_in_12_hours,
            "breached": summary.breached,
            "alerts_emitted": summary.alerts_emitted,
            "escalations_queued": summary.escalations_queued,
            "escalations_required": summary.escalations_required,
        }


async def _queue_itsm_ticket(remediation_id: str, tenant_id: str) -> None:
    from app.tasks.remediation_exec import create_itsm_ticket_task

    create_itsm_ticket_task.delay(remediation_id, tenant_id)


async def _monitor_all_tenant_slas() -> dict[str, object]:
    async with get_scoped_session(None) as session:
        tenant_ids = await GovernanceRepository(session).list_active_tenant_ids()

    tenants: list[dict[str, int | str]] = []
    totals = {
        "total_tracked": 0,
        "breach_in_2_days": 0,
        "breach_in_12_hours": 0,
        "breached": 0,
        "alerts_emitted": 0,
        "escalations_queued": 0,
        "escalations_required": 0,
    }
    for tenant_id in tenant_ids:
        tenant_summary = await _monitor_tenant_slas(tenant_id)
        tenants.append(tenant_summary)
        for key in totals:
            totals[key] += int(tenant_summary[key])
    return {"tenant_count": len(tenant_ids), "tenants": tenants, "totals": totals}


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def monitor_tenant_slas(self, tenant_id: str) -> dict[str, int | str]:
    reset_async_db_state()
    return run_async_task(_monitor_tenant_slas(tenant_id))


@shared_task(bind=True, autoretry_for=(Exception,), retry_backoff=True, retry_kwargs={"max_retries": 3})
def monitor_all_tenant_slas(self) -> dict[str, object]:
    reset_async_db_state()
    return run_async_task(_monitor_all_tenant_slas())
