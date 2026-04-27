from collections import defaultdict
from uuid import UUID

from sqlalchemy import select

from app.models.entities import Asset, AuditLog, FindingStatus, Integration, Remediation, Tenant, Vulnerability

ACTIVE_SLA_STATUSES = (
    FindingStatus.open,
    FindingStatus.approved,
    FindingStatus.in_progress,
    FindingStatus.fixed,
)

REPORTABLE_SLA_STATUSES = (
    FindingStatus.open,
    FindingStatus.approved,
    FindingStatus.in_progress,
    FindingStatus.fixed,
    FindingStatus.rejected,
    FindingStatus.verified,
    FindingStatus.closed,
)


class GovernanceRepository:
    def __init__(self, session):
        self.session = session

    async def list_sla_report_findings(self, *, limit: int | None = 250) -> list[tuple[Vulnerability, Asset | None]]:
        statement = (
            select(Vulnerability, Asset)
            .outerjoin(Asset, Vulnerability.asset_id == Asset.id)
            .where(
                Vulnerability.sla_due_date.is_not(None),
                Vulnerability.status.in_(REPORTABLE_SLA_STATUSES),
            )
            .order_by(Vulnerability.sla_due_date.asc())
        )
        if limit is not None and limit > 0:
            statement = statement.limit(limit)
        rows = (await self.session.execute(statement)).all()
        return [(row[0], row[1]) for row in rows]

    async def list_sla_tracked_findings(self, *, limit: int | None = 250) -> list[tuple[Vulnerability, Asset | None]]:
        statement = (
            select(Vulnerability, Asset)
            .outerjoin(Asset, Vulnerability.asset_id == Asset.id)
            .where(
                Vulnerability.sla_due_date.is_not(None),
                Vulnerability.status.in_(ACTIVE_SLA_STATUSES),
            )
            .order_by(Vulnerability.sla_due_date.asc())
        )
        if limit is not None and limit > 0:
            statement = statement.limit(limit)
        rows = (await self.session.execute(statement)).all()
        return [(row[0], row[1]) for row in rows]

    async def list_active_tenant_ids(self) -> list[str]:
        tenant_ids = (
            await self.session.execute(
                select(Tenant.id).where(Tenant.is_active.is_(True)).order_by(Tenant.created_at.asc())
            )
        ).scalars().all()
        return [str(tenant_id) for tenant_id in tenant_ids]

    async def list_latest_sla_audits(
        self,
        *,
        finding_ids: list[str],
        actions: list[str] | tuple[str, ...],
    ) -> dict[tuple[str, str], AuditLog]:
        if not finding_ids or not actions:
            return {}
        audits = (
            await self.session.execute(
                select(AuditLog)
                .where(
                    AuditLog.resource_type == "vulnerability",
                    AuditLog.resource_id.in_(finding_ids),
                    AuditLog.action.in_(actions),
                )
                .order_by(AuditLog.created_at.desc())
            )
        ).scalars().all()
        latest: dict[tuple[str, str], AuditLog] = {}
        for audit in audits:
            key = (audit.resource_id, audit.action)
            latest.setdefault(key, audit)
        return latest

    async def list_remediations_by_finding(
        self,
        *,
        finding_ids: list[UUID],
    ) -> dict[str, list[Remediation]]:
        if not finding_ids:
            return {}
        remediations = (
            await self.session.execute(
                select(Remediation)
                .where(Remediation.vulnerability_id.in_(finding_ids))
                .order_by(Remediation.vulnerability_id.asc(), Remediation.created_at.desc())
            )
        ).scalars().all()
        grouped: dict[str, list[Remediation]] = defaultdict(list)
        for remediation in remediations:
            grouped[str(remediation.vulnerability_id)].append(remediation)
        return dict(grouped)

    async def has_itsm_integration(self) -> bool:
        integration = (
            await self.session.execute(
                select(Integration.id).where(Integration.integration_type.in_(["servicenow", "jira"]))
            )
        ).scalars().first()
        return integration is not None

    async def commit(self) -> None:
        await self.session.commit()
