import httpx
from sqlalchemy import select

from app.config import get_settings
from app.models.entities import Asset, AuditLog, Remediation, RemediationApproval, Vulnerability
from app.schemas.common import AuditLogCreate
from app.services.audit_writer import AuditWriter
from app.services.change_window import ChangeWindowService
from app.services.errors import MissingApprovalAuditError, NotApprovedError
from app.services.kill_switch import KillSwitchService, KillSwitchActiveError


class TaniumService:
    def __init__(self, redis):
        self.settings = get_settings()
        self.redis = redis

    async def execute_patch(self, session, remediation_id: str, tenant_id: str) -> dict:
        remediation = await session.get(Remediation, remediation_id)
        if remediation is None:
            raise ValueError("Remediation not found.")
        if remediation.status != "approved":
            raise NotApprovedError("Remediation is not approved.")
        approval = (
            await session.execute(select(RemediationApproval).where(RemediationApproval.remediation_id == remediation.id))
        ).scalar_one_or_none()
        if approval is None or approval.status != "approved":
            raise NotApprovedError("Missing approval record.")
        audit = (
            await session.execute(
                select(AuditLog).where(AuditLog.action == "remediation_approved", AuditLog.resource_id == str(remediation.id))
            )
        ).scalar_one_or_none()
        if audit is None:
            raise MissingApprovalAuditError("No approval audit record.")
        audit_details = audit.details or {}
        is_auto_approved = bool(audit_details.get("auto_approved"))
        if remediation.approved_by is None and not is_auto_approved:
            raise NotApprovedError("Remediation has no approver.")
        if approval.approver_user_id is None and not is_auto_approved:
            raise NotApprovedError("Missing approval record.")
        finding = await session.get(Vulnerability, remediation.vulnerability_id)
        asset = await session.get(Asset, finding.asset_id) if finding and finding.asset_id else None
        if asset is not None:
            await ChangeWindowService().is_execution_allowed(session, str(asset.id), tenant_id)
        if await KillSwitchService(self.redis).is_active():
            raise KillSwitchActiveError("Kill switch active.")
        await AuditWriter().write(
            session,
            tenant_id,
            AuditLogCreate(
                action="tanium_patch_initiated",
                resource_type="remediation",
                resource_id=str(remediation.id),
                details={
                    "finding_id": str(finding.id) if finding is not None else None,
                    "remediation_id": str(remediation.id),
                    "approved_by": remediation.approved_by or "system:auto-approval",
                    "auto_approved": is_auto_approved,
                    "asset_ip": asset.ip_address if asset else None,
                },
            ),
        )
        if self.settings.environment == "development":
            return {"action_id": "mock-tanium-001", "status": "initiated"}
        async with httpx.AsyncClient(timeout=10.0, verify=True) as client:
            response = await client.post(
                f"{self.settings.tanium_url}/plugin/products/live-response/connections",
                headers={"Authorization": f"Bearer {self.settings.tanium_api_key}"},
                json={"package_name": remediation.fix_type, "asset_ip": asset.ip_address if asset else None},
            )
            response.raise_for_status()
            payload = response.json()
        return {"action_id": payload.get("action_id"), "status": "initiated"}
