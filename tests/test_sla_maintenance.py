import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.application.governance.maintenance import (
    SLA_ESCALATION_QUEUED,
    SLA_ESCALATION_REQUIRED,
    SlaMaintenanceUseCase,
)


class FakeRepository:
    def __init__(self, rows, *, audits=None, remediations=None, has_itsm_integration=False):
        self.rows = rows
        self.audits = audits or {}
        self.remediations = remediations or {}
        self.has_itsm = has_itsm_integration
        self.session = object()
        self.committed = False

    async def list_sla_tracked_findings(self, *, limit=None):
        return list(self.rows)

    async def list_latest_sla_audits(self, *, finding_ids, actions):
        return dict(self.audits)

    async def list_remediations_by_finding(self, *, finding_ids):
        return dict(self.remediations)

    async def has_itsm_integration(self):
        return self.has_itsm

    async def commit(self):
        self.committed = True


class AuditRecorder:
    def __init__(self):
        self.payloads = []

    async def write(self, session, tenant_id, payload):
        self.payloads.append((tenant_id, payload))


def _finding(*, due_date, status="open", severity="High", cve_id="CVE-2026-1001"):
    return SimpleNamespace(
        id=uuid4(),
        cve_id=cve_id,
        severity=severity,
        risk_score=88,
        status=status,
        sla_tier=severity,
        sla_due_date=due_date,
        source_tool="nessus",
    )


def _asset(hostname="web-01", ip_address="10.0.0.10"):
    return SimpleNamespace(hostname=hostname, ip_address=ip_address)


def _audit_entry(*, due_date):
    return SimpleNamespace(details={"sla_due_date": due_date.isoformat()})


def _remediation(finding_id, *, status="approved", ticket_id=None):
    return SimpleNamespace(
        id=uuid4(),
        vulnerability_id=finding_id,
        status=status,
        ticket_id=ticket_id,
    )


def test_sla_maintenance_emits_due_soon_alert_once_per_due_date():
    now = datetime(2026, 4, 7, 12, 0, tzinfo=timezone.utc)
    finding = _finding(due_date=now + timedelta(hours=10))
    repo = FakeRepository([(finding, _asset())])
    audit = AuditRecorder()
    alerts = []

    use_case = SlaMaintenanceUseCase(
        repo,
        audit_writer=audit,
        alert_sender=lambda event: alerts.append(event),
        now_provider=lambda: now,
    )
    summary = asyncio.run(use_case.execute(tenant_id="tenant-1"))

    assert summary.alerts_emitted == 1
    assert repo.committed is True
    assert audit.payloads[0][1].action == "sla_breach_in_12_hours"
    assert alerts[0]["action"] == "sla_breach_in_12_hours"

    repo = FakeRepository(
        [(finding, _asset())],
        audits={(str(finding.id), "sla_breach_in_12_hours"): _audit_entry(due_date=finding.sla_due_date)},
    )
    audit = AuditRecorder()
    use_case = SlaMaintenanceUseCase(
        repo,
        audit_writer=audit,
        now_provider=lambda: now,
    )
    summary = asyncio.run(use_case.execute(tenant_id="tenant-1"))

    assert summary.alerts_emitted == 0
    assert audit.payloads == []


def test_sla_maintenance_queues_itsm_escalation_for_new_breach():
    now = datetime(2026, 4, 7, 12, 0, tzinfo=timezone.utc)
    finding = _finding(due_date=now - timedelta(hours=3), severity="Critical", cve_id="CVE-2026-2001")
    remediation = _remediation(finding.id)
    repo = FakeRepository(
        [(finding, _asset("db-01", "10.0.0.25"))],
        remediations={str(finding.id): [remediation]},
        has_itsm_integration=True,
    )
    audit = AuditRecorder()
    queued = []

    summary = asyncio.run(
        SlaMaintenanceUseCase(
            repo,
            audit_writer=audit,
            queue_itsm_ticket=lambda remediation_id, tenant_id: queued.append((remediation_id, tenant_id)),
            now_provider=lambda: now,
        ).execute(tenant_id="tenant-77")
    )

    assert summary.breached == 1
    assert summary.escalations_queued == 1
    assert queued == [(str(remediation.id), "tenant-77")]
    assert [payload.action for _, payload in audit.payloads] == ["sla_breached", SLA_ESCALATION_QUEUED]


def test_sla_maintenance_records_manual_escalation_when_no_ticket_path_exists():
    now = datetime(2026, 4, 7, 12, 0, tzinfo=timezone.utc)
    finding = _finding(due_date=now - timedelta(days=1), cve_id="CVE-2026-3001")
    repo = FakeRepository([(finding, _asset())], has_itsm_integration=False)
    audit = AuditRecorder()

    summary = asyncio.run(
        SlaMaintenanceUseCase(
            repo,
            audit_writer=audit,
            now_provider=lambda: now,
        ).execute(tenant_id="tenant-88")
    )

    assert summary.escalations_required == 1
    actions = [payload.action for _, payload in audit.payloads]
    assert actions == ["sla_breached", SLA_ESCALATION_REQUIRED]
    assert audit.payloads[-1][1].details["integration_available"] is False


def test_sla_maintenance_skips_repeated_breach_escalation_for_same_due_date():
    now = datetime(2026, 4, 7, 12, 0, tzinfo=timezone.utc)
    finding = _finding(due_date=now - timedelta(hours=6), cve_id="CVE-2026-4001")
    remediation = _remediation(finding.id)
    repo = FakeRepository(
        [(finding, _asset())],
        audits={
            (str(finding.id), "sla_breached"): _audit_entry(due_date=finding.sla_due_date),
            (str(finding.id), SLA_ESCALATION_QUEUED): _audit_entry(due_date=finding.sla_due_date),
        },
        remediations={str(finding.id): [remediation]},
        has_itsm_integration=True,
    )
    audit = AuditRecorder()
    queued = []

    summary = asyncio.run(
        SlaMaintenanceUseCase(
            repo,
            audit_writer=audit,
            queue_itsm_ticket=lambda remediation_id, tenant_id: queued.append((remediation_id, tenant_id)),
            now_provider=lambda: now,
        ).execute(tenant_id="tenant-99")
    )

    assert summary.alerts_emitted == 0
    assert summary.escalations_queued == 0
    assert queued == []
    assert audit.payloads == []
