from sqlalchemy import select

from app.models.entities import Asset, ComplianceControl, ScanFinding, Tenant, Vulnerability, VulnerabilityControl, Remediation
from app.schemas.common import AuditLogCreate
from app.services.audit_writer import AuditWriter
from app.services.llm_router import LLMRouter


class RemediationService:
    @staticmethod
    def _normalize_fix_type(value: str | None) -> str:
        raw = (value or "").strip().lower()
        if any(token in raw for token in ("patch", "upgrade", "hotfix")):
            return "patch"
        if any(token in raw for token in ("config", "hardening", "compensating")):
            return "configuration"
        if any(token in raw for token in ("code", "application", "dependency")):
            return "code"
        return "manual"

    async def generate_plan(self, session, finding_id: str, tenant_id: str) -> Remediation:
        finding = await session.get(Vulnerability, finding_id)
        if finding is None:
            raise ValueError("Finding not found.")
        asset = await session.get(Asset, finding.asset_id) if finding.asset_id else None
        controls = (
            await session.execute(
                select(ComplianceControl.control_id)
                .join(VulnerabilityControl, VulnerabilityControl.control_id == ComplianceControl.id)
                .where(VulnerabilityControl.vulnerability_id == finding.id)
            )
        ).scalars().all()
        tenant = await session.get(Tenant, tenant_id)
        business_context = {}
        if asset is not None:
            business_context.update(asset.business_context or {})
        if tenant is not None:
            business_context.setdefault("industry_sector", getattr(tenant, "industry_sector", None))
            business_context.setdefault("annual_revenue", getattr(tenant, "annual_revenue", None))

        plan = await LLMRouter().generate_remediation_plan(finding, asset, controls, business_context)
        normalized_fix_type = self._normalize_fix_type(plan.get("fix_type"))
        plan["fix_type"] = normalized_fix_type
        remediation = Remediation(
            tenant_id=tenant_id,
            vulnerability_id=finding.id,
            fix_type=normalized_fix_type,
            fix_steps=plan["fix_steps"],
            rollback_steps=plan["rollback_steps"],
            risk_narrative=plan["risk_narrative"],
            business_impact=plan["business_impact"],
            compliance_impact=plan["compliance_impact"],
            estimated_effort_hours=plan["estimated_effort_hours"],
            requires_downtime=plan["requires_downtime"],
            status="pending",
            execution_status="pending",
            plan=plan,
        )
        session.add(remediation)
        await session.flush()
        await AuditWriter().write(
            session,
            tenant_id,
            AuditLogCreate(
                action="remediation_plan_generated",
                resource_type="remediation",
                resource_id=str(remediation.id),
                details={"finding_id": finding_id},
            ),
        )
        await session.commit()
        return remediation
