try:
    from celery import shared_task
except ImportError:  # pragma: no cover
    def shared_task(*args, **kwargs):
        def decorator(func):
            return func

        return decorator

try:
    from redis.asyncio import Redis
except ImportError:  # pragma: no cover
    class Redis:
        @staticmethod
        def from_url(url):
            raise RuntimeError("redis package is not installed")

from sqlalchemy import select

from app.config import get_settings
from app.models.base import get_scoped_session, reset_async_db_state
from app.models.entities import Asset, Remediation, Vulnerability
from app.schemas.common import AuditLogCreate
from app.services.audit_writer import AuditWriter
from app.services.errors import ChangeWindowBlockedError
from app.services.itsm import ITSMService
from app.services.kill_switch import KillSwitchActiveError
from app.services.scanner_service import ScannerService
from app.services.tanium import TaniumService
from app.tasks.compliance_update import recalculate_scores_in_session
from app.tasks.runtime import run_async_task


@shared_task(bind=True, max_retries=3)
def create_itsm_ticket_task(self, remediation_id: str, tenant_id: str):
    reset_async_db_state()

    async def _run():
        async with get_scoped_session(tenant_id) as session:
            remediation = await session.get(Remediation, remediation_id)
            finding = await session.get(Vulnerability, remediation.vulnerability_id) if remediation else None
            if remediation is None or finding is None:
                return {"status": "missing"}
            return await ITSMService().create_ticket(session, finding, remediation, tenant_id)

    try:
        return run_async_task(_run())
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))


@shared_task(bind=True, max_retries=3)
def execute_remediation_task(self, remediation_id, tenant_id):
    reset_async_db_state()

    async def _run():
        settings = get_settings()
        redis = Redis.from_url(settings.redis_url)
        async with get_scoped_session(tenant_id) as session:
            try:
                result = await TaniumService(redis).execute_patch(session, remediation_id, tenant_id)
                remediation = await session.get(Remediation, remediation_id)
                finding = (
                    await session.get(Vulnerability, remediation.vulnerability_id)
                    if remediation is not None else None
                )
                if remediation is not None:
                    remediation.status = "fixed"
                    remediation.execution_status = "fixed"
                if finding is not None:
                    finding.status = "fixed"
                await session.commit()
                verify_remediation_task.apply_async(args=[remediation_id, tenant_id], countdown=300)
                await redis.aclose()
                return result
            except (KillSwitchActiveError, ChangeWindowBlockedError) as exc:
                remediation = await session.get(Remediation, remediation_id)
                finding = (
                    await session.get(Vulnerability, remediation.vulnerability_id)
                    if remediation is not None else None
                )
                if remediation is not None:
                    remediation.status = "blocked"
                    remediation.execution_status = "blocked"
                await AuditWriter().write(
                    session,
                    tenant_id,
                    AuditLogCreate(
                        action="remediation_execution_blocked",
                        resource_type="remediation",
                        resource_id=str(remediation_id),
                        details={
                            "finding_id": str(finding.id) if finding is not None else None,
                            "remediation_id": str(remediation_id),
                            "error": str(exc),
                        },
                    ),
                )
                await session.commit()
                await redis.aclose()
                raise
            except Exception as exc:
                await redis.aclose()
                raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))

    return run_async_task(_run())


@shared_task(bind=True, max_retries=3)
def verify_remediation_task(self, remediation_id: str, tenant_id: str):
    reset_async_db_state()

    async def _run():
        from datetime import datetime, timezone

        async with get_scoped_session(tenant_id) as session:
            remediation = await session.get(Remediation, remediation_id)
            if remediation is None:
                return {"status": "not_found"}

            finding = await session.get(Vulnerability, remediation.vulnerability_id)
            if finding is None:
                return {"status": "finding_not_found"}

            asset = await session.get(Asset, finding.asset_id) if finding.asset_id else None
            asset_ip = asset.ip_address if asset else "unknown"

            rescan = await ScannerService().rescan(
                asset_ip=asset_ip,
                cve_id=finding.cve_id,
                source_tool=finding.source_tool,
                tenant_id=tenant_id,
            )

            still_vulnerable = any(
                f.get("cve_id") == finding.cve_id
                for f in (rescan.findings or [])
            )

            if not rescan.verification_succeeded:
                finding.status = "fixed"
                remediation.status = "fixed"
                remediation.execution_status = "fixed"
                await AuditWriter().write(session, tenant_id, AuditLogCreate(
                    action="finding_verification_deferred",
                    resource_type="vulnerability",
                    resource_id=str(finding.id),
                    details={
                        "remediation_id": remediation_id,
                        "scanner_evidence": rescan.raw_output,
                        "verification_error": rescan.verification_error,
                        "approver": remediation.approved_by,
                    },
                ))
                result = {"status": "fixed", "finding_id": str(finding.id)}
            elif not still_vulnerable:
                finding.status = "verified"
                finding.verified_at = datetime.now(timezone.utc)
                remediation.status = "verified"
                remediation.execution_status = "verified"
                verified_at_iso = finding.verified_at.isoformat()
                await AuditWriter().write(session, tenant_id, AuditLogCreate(
                    action="finding_verified_closed",
                    resource_type="vulnerability",
                    resource_id=str(finding.id),
                    details={
                        "remediation_id": remediation_id,
                        "verified_at": verified_at_iso,
                        "scanner_evidence": rescan.raw_output,
                        "approver": remediation.approved_by,
                    },
                ))
                await recalculate_scores_in_session(session, tenant_id)
                result = {"status": "verified", "finding_id": str(finding.id)}
            else:
                finding.status = "fixed"
                remediation.status = "failed"
                remediation.execution_status = "failed"
                await AuditWriter().write(session, tenant_id, AuditLogCreate(
                    action="finding_verification_failed",
                    resource_type="vulnerability",
                    resource_id=str(finding.id),
                    details={
                        "remediation_id": remediation_id,
                        "scanner_evidence": rescan.raw_output,
                        "approver": remediation.approved_by,
                    },
                ))
                result = {"status": "failed", "finding_id": str(finding.id)}

            await session.commit()
            return result

    try:
        return run_async_task(_run())
    except Exception as exc:
        raise self.retry(exc=exc, countdown=60 * (2 ** self.request.retries))
