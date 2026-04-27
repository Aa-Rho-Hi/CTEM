from datetime import datetime, timezone

from sqlalchemy import select

from app.models.entities import FindingStatus, Remediation, RemediationApproval, Vulnerability
from app.schemas.common import AuditLogCreate
from app.services.audit_writer import AuditWriter
from app.services.graphrag import GraphRAGService


class ApprovalService:
    @staticmethod
    def _requires_human_approval(finding: Vulnerability) -> bool:
        approval_tier = (
            getattr(finding, "severity", None)
            or getattr(finding, "sla_tier", None)
            or ""
        ).strip().lower()
        return approval_tier not in {"low", "medium"}

    @staticmethod
    def _normalize_reason(reason: str) -> str:
        normalized = reason.strip()
        if not normalized:
            raise ValueError("Reason is required.")
        return normalized

    def _enqueue_itsm_ticket(self, remediation_id: str, tenant_id: str) -> None:
        from app.tasks.remediation_exec import create_itsm_ticket_task

        create_itsm_ticket_task.delay(remediation_id, tenant_id)

    async def route_for_approval(self, session, remediation_id: str, tenant_id: str) -> Remediation:
        remediation = await session.get(Remediation, remediation_id)
        finding = await session.get(Vulnerability, remediation.vulnerability_id) if remediation else None
        if remediation is None or finding is None:
            raise ValueError("Remediation not found.")

        if self._requires_human_approval(finding):
            remediation.status = "awaiting_approval"
            remediation.execution_status = "awaiting_approval"
            remediation.approved_by = None
            remediation.approved_at = None
            approval = RemediationApproval(
                tenant_id=tenant_id,
                remediation_id=remediation.id,
                approver_user_id=None,
                status=remediation.status,
                rationale=None,
            )
            audit_action = "remediation_routed_for_approval"
            audit_details = {
                "finding_id": str(finding.id),
                "remediation_id": str(remediation.id),
                "severity": getattr(finding, "severity", None),
                "sla_tier": finding.sla_tier,
            }
            session.add(approval)
        else:
            remediation.status = "approved"
            remediation.execution_status = "approved"
            remediation.approved_by = None
            remediation.approved_at = datetime.now(timezone.utc)
            finding.status = FindingStatus.approved
            approval = RemediationApproval(
                tenant_id=tenant_id,
                remediation_id=remediation.id,
                approver_user_id=None,
                status="approved",
                rationale="auto_approved",
            )
            audit_action = "remediation_approved"
            audit_details = {
                "finding_id": str(finding.id),
                "remediation_id": str(remediation.id),
                "severity": getattr(finding, "severity", None),
                "sla_tier": finding.sla_tier,
                "auto_approved": True,
            }
            session.add(approval)
        await AuditWriter().write(
            session,
            tenant_id,
            AuditLogCreate(
                action=audit_action,
                resource_type="remediation",
                resource_id=str(remediation.id),
                details=audit_details,
            ),
        )
        await session.commit()
        if not self._requires_human_approval(finding):
            self._enqueue_itsm_ticket(str(remediation.id), tenant_id)
        return remediation

    async def approve(self, session, remediation_id: str, approver_user_id: str, reason: str, tenant_id: str) -> Remediation:
        reason = self._normalize_reason(reason)
        remediation = await session.get(Remediation, remediation_id)
        if remediation is None:
            raise ValueError("Remediation not found.")
        remediation.status = "approved"
        remediation.execution_status = "approved"
        remediation.approved_by = approver_user_id
        remediation.approved_at = datetime.now(timezone.utc)
        remediation.rejection_reason = None
        approval = (
            await session.execute(select(RemediationApproval).where(RemediationApproval.remediation_id == remediation.id))
        ).scalar_one_or_none()
        if approval is None:
            approval = RemediationApproval(
                tenant_id=tenant_id,
                remediation_id=remediation.id,
                approver_user_id=approver_user_id,
                status="approved",
                rationale=reason,
            )
            session.add(approval)
        else:
            approval.approver_user_id = approver_user_id
            approval.status = "approved"
            approval.rationale = reason
        finding = await session.get(Vulnerability, remediation.vulnerability_id)
        if finding is not None:
            finding.status = FindingStatus.approved
        await AuditWriter().write(
            session,
            tenant_id,
            AuditLogCreate(
                action="remediation_approved",
                resource_type="remediation",
                resource_id=str(remediation.id),
                details={
                    "finding_id": str(finding.id) if finding is not None else None,
                    "cve_id": finding.cve_id if finding is not None else None,
                    "remediation_id": str(remediation.id),
                    "approver_user_id": approver_user_id,
                    "reason": reason,
                    "auto_approved": False,
                },
                user_id=approver_user_id,
            ),
        )
        if finding is not None:
            await GraphRAGService().record_approval(
                session,
                finding_id=str(finding.id),
                remediation_id=str(remediation.id),
                approver_id=approver_user_id,
                tenant_id=tenant_id,
            )
        await session.commit()
        self._enqueue_itsm_ticket(str(remediation.id), tenant_id)
        return remediation

    async def reject(self, session, remediation_id: str, approver_user_id: str, reason: str, tenant_id: str) -> Remediation:
        reason = self._normalize_reason(reason)
        remediation = await session.get(Remediation, remediation_id)
        if remediation is None:
            raise ValueError("Remediation not found.")
        remediation.status = "rejected"
        remediation.execution_status = "rejected"
        remediation.approved_by = None
        remediation.approved_at = None
        remediation.rejection_reason = reason
        approval = (
            await session.execute(select(RemediationApproval).where(RemediationApproval.remediation_id == remediation.id))
        ).scalar_one_or_none()
        if approval is None:
            approval = RemediationApproval(
                tenant_id=tenant_id,
                remediation_id=remediation.id,
                approver_user_id=approver_user_id,
                status="rejected",
                rationale=reason,
            )
            session.add(approval)
        else:
            approval.approver_user_id = approver_user_id
            approval.status = "rejected"
            approval.rationale = reason
        finding = await session.get(Vulnerability, remediation.vulnerability_id)
        if finding is not None:
            finding.status = FindingStatus.rejected
        await AuditWriter().write(
            session,
            tenant_id,
            AuditLogCreate(
                action="remediation_rejected",
                resource_type="remediation",
                resource_id=str(remediation.id),
                details={
                    "finding_id": str(finding.id) if finding is not None else None,
                    "remediation_id": str(remediation.id),
                    "approver_user_id": approver_user_id,
                    "reason": reason,
                },
                user_id=approver_user_id,
            ),
        )
        if finding is not None:
            await GraphRAGService().record_rejection(
                session,
                finding_id=str(finding.id),
                remediation_id=str(remediation.id),
                approver_id=approver_user_id,
                reason=reason,
                tenant_id=tenant_id,
            )
        await session.commit()
        return remediation
