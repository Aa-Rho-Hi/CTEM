from dataclasses import dataclass
from datetime import datetime, timezone
from inspect import isawaitable

from app.domain.governance.sla import BREACHED, BREACH_IN_12_HOURS, BREACH_IN_2_DAYS, compute_sla_window, ensure_utc
from app.schemas.common import AuditLogCreate

SLA_ALERT_ACTIONS = {
    BREACH_IN_2_DAYS: "sla_breach_in_2_days",
    BREACH_IN_12_HOURS: "sla_breach_in_12_hours",
    BREACHED: "sla_breached",
}
SLA_ESCALATION_QUEUED = "sla_escalation_queued"
SLA_ESCALATION_REQUIRED = "sla_escalation_required"
INACTIVE_ESCALATION_STATUSES = {"rejected", "verified", "closed"}
SUMMARY_BUCKET_FIELDS = {BREACH_IN_2_DAYS, BREACH_IN_12_HOURS, BREACHED}


async def _maybe_await(result):
    if isawaitable(result):
        return await result
    return result


@dataclass(slots=True)
class SlaMaintenanceSummary:
    tenant_id: str
    total_tracked: int = 0
    breach_in_2_days: int = 0
    breach_in_12_hours: int = 0
    breached: int = 0
    alerts_emitted: int = 0
    escalations_queued: int = 0
    escalations_required: int = 0


class SlaMaintenanceUseCase:
    def __init__(
        self,
        repository,
        *,
        audit_writer,
        alert_sender=None,
        queue_itsm_ticket=None,
        now_provider=None,
    ):
        self.repository = repository
        self.audit_writer = audit_writer
        self.alert_sender = alert_sender
        self.queue_itsm_ticket = queue_itsm_ticket
        self.now_provider = now_provider or (lambda: datetime.now(timezone.utc))

    async def execute(self, *, tenant_id: str) -> SlaMaintenanceSummary:
        now = ensure_utc(self.now_provider())
        findings = await self.repository.list_sla_tracked_findings(limit=None)
        summary = SlaMaintenanceSummary(tenant_id=tenant_id, total_tracked=len(findings))
        if not findings:
            return summary

        finding_ids = [finding.id for finding, _ in findings]
        finding_id_strings = [str(finding_id) for finding_id in finding_ids]
        audit_actions = tuple(SLA_ALERT_ACTIONS.values()) + (SLA_ESCALATION_QUEUED, SLA_ESCALATION_REQUIRED)
        latest_audits = await self.repository.list_latest_sla_audits(
            finding_ids=finding_id_strings,
            actions=audit_actions,
        )
        remediations_by_finding = await self.repository.list_remediations_by_finding(finding_ids=finding_ids)
        has_itsm_integration = await self.repository.has_itsm_integration()

        for finding, asset in findings:
            if finding.sla_due_date is None:
                continue
            window = compute_sla_window(finding.sla_due_date, now=now)
            if window["bucket"] in SUMMARY_BUCKET_FIELDS:
                setattr(summary, window["bucket"], getattr(summary, window["bucket"]) + 1)

            alert_action = SLA_ALERT_ACTIONS.get(window["bucket"])
            if alert_action is None:
                continue

            finding_id = str(finding.id)
            details = self._build_sla_details(
                finding=finding,
                asset=asset,
                window=window,
                due_date=finding.sla_due_date,
                now=now,
            )

            if self._should_emit(
                latest_audits.get((finding_id, alert_action)),
                due_date=finding.sla_due_date,
            ):
                await self.audit_writer.write(
                    self.repository.session,
                    tenant_id,
                    AuditLogCreate(
                        action=alert_action,
                        resource_type="vulnerability",
                        resource_id=finding_id,
                        details=details,
                    ),
                )
                summary.alerts_emitted += 1
                if self.alert_sender is not None:
                    await _maybe_await(
                        self.alert_sender(
                            {
                                "tenant_id": tenant_id,
                                "action": alert_action,
                                "finding_id": finding_id,
                                "cve_id": finding.cve_id,
                                "severity": finding.severity,
                                "sla_due_date": details["sla_due_date"],
                                "window": details["window"],
                                "countdown_label": details["countdown_label"],
                                "asset_hostname": details["asset_hostname"],
                                "asset_ip": details["asset_ip"],
                            }
                        )
                    )

            if window["bucket"] == BREACHED:
                remediation = self._select_escalation_remediation(remediations_by_finding.get(finding_id, []))
                await self._process_breached_finding(
                    tenant_id=tenant_id,
                    finding=finding,
                    details=details,
                    remediation=remediation,
                    latest_audits=latest_audits,
                    has_itsm_integration=has_itsm_integration,
                    summary=summary,
                )

        await self.repository.commit()
        return summary

    async def _process_breached_finding(
        self,
        *,
        tenant_id: str,
        finding,
        details: dict[str, object],
        remediation,
        latest_audits: dict[tuple[str, str], object],
        has_itsm_integration: bool,
        summary: SlaMaintenanceSummary,
    ) -> None:
        finding_id = str(finding.id)
        escalation_details = dict(details)
        escalation_details["integration_available"] = has_itsm_integration
        escalation_details["remediation_id"] = str(remediation.id) if remediation is not None else None
        escalation_details["remediation_status"] = remediation.status if remediation is not None else None
        escalation_details["ticket_id"] = remediation.ticket_id if remediation is not None else None

        if remediation is not None and remediation.ticket_id:
            return

        if (
            remediation is not None
            and remediation.status not in INACTIVE_ESCALATION_STATUSES
            and has_itsm_integration
            and self.queue_itsm_ticket is not None
        ):
            queued_action = SLA_ESCALATION_QUEUED
            if not self._should_emit(
                latest_audits.get((finding_id, queued_action)),
                due_date=finding.sla_due_date,
            ):
                return
            await _maybe_await(self.queue_itsm_ticket(str(remediation.id), tenant_id))
            await self.audit_writer.write(
                self.repository.session,
                tenant_id,
                AuditLogCreate(
                    action=queued_action,
                    resource_type="vulnerability",
                    resource_id=finding_id,
                    details=escalation_details,
                ),
            )
            summary.escalations_queued += 1
            return

        required_action = SLA_ESCALATION_REQUIRED
        if not self._should_emit(
            latest_audits.get((finding_id, required_action)),
            due_date=finding.sla_due_date,
        ):
            return
        await self.audit_writer.write(
            self.repository.session,
            tenant_id,
            AuditLogCreate(
                action=required_action,
                resource_type="vulnerability",
                resource_id=finding_id,
                details=escalation_details,
            ),
        )
        summary.escalations_required += 1

    def _build_sla_details(self, *, finding, asset, window: dict[str, object], due_date, now: datetime) -> dict[str, object]:
        status = finding.status.value if hasattr(finding.status, "value") else finding.status
        due_at = ensure_utc(due_date)
        return {
            "finding_id": str(finding.id),
            "cve_id": finding.cve_id,
            "severity": finding.severity,
            "risk_score": finding.risk_score,
            "status": status,
            "sla_tier": finding.sla_tier,
            "sla_due_date": due_at.isoformat(),
            "source_tool": finding.source_tool,
            "window": window["bucket"],
            "window_label": window["window_label"],
            "countdown_label": window["countdown_label"],
            "hours_remaining": window["hours_remaining"],
            "asset_hostname": getattr(asset, "hostname", None),
            "asset_ip": getattr(asset, "ip_address", None),
            "observed_at": now.isoformat(),
        }

    def _should_emit(self, latest_audit, *, due_date) -> bool:
        if latest_audit is None:
            return True
        details = latest_audit.details or {}
        return details.get("sla_due_date") != ensure_utc(due_date).isoformat()

    def _select_escalation_remediation(self, remediations):
        if not remediations:
            return None
        for remediation in remediations:
            if remediation.ticket_id:
                return remediation
        for remediation in remediations:
            if remediation.status not in INACTIVE_ESCALATION_STATUSES:
                return remediation
        return remediations[0]
