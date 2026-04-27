import asyncio
from datetime import datetime
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.models.entities import FindingStatus
from app.schemas.common import AuditLogCreate
from app.services.approval_service import ApprovalService


class FakeExecuteResult:
    def __init__(self, obj=None, rows=None):
        self.obj = obj
        self.rows = list(rows or [])

    def scalar_one_or_none(self):
        return self.obj

    def scalars(self):
        return self

    def all(self):
        return self.rows


class FakeSession:
    def __init__(self, remediation, vulnerability, approval=None):
        self.data = {("remediation", remediation.id): remediation, ("vulnerability", vulnerability.id): vulnerability}
        self.approval = approval
        self.added = []

    async def get(self, model, key):
        name = model.__name__.lower()
        if name == "remediation":
            return next(v for (k, _), v in self.data.items() if k == "remediation")
        if name == "vulnerability":
            return next(v for (k, _), v in self.data.items() if k == "vulnerability")
        return None

    async def execute(self, statement):
        entity = statement.column_descriptions[0]["entity"]
        name = entity.__name__.lower()
        if name == "remediationapproval":
            return FakeExecuteResult(self.approval)
        if name in {"attackgraphnode", "agentdecision", "attackgraphedge"}:
            return FakeExecuteResult(rows=[])
        return FakeExecuteResult()

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        return None

    async def commit(self):
        return None


class AuditRecorder:
    def __init__(self):
        self.payloads = []

    async def write(self, session, tenant_id, payload: AuditLogCreate):
        self.payloads.append(payload)
        return None


def _make_pair(sla_tier):
    remediation = SimpleNamespace(
        id=uuid4(),
        vulnerability_id=uuid4(),
        status="pending",
        execution_status="pending",
        approved_by=None,
        approved_at=None,
        rejection_reason=None,
    )
    vulnerability = SimpleNamespace(
        id=remediation.vulnerability_id,
        cve_id="CVE-2026-0001",
        severity=sla_tier,
        sla_tier=sla_tier,
        status="open",
    )
    return remediation, vulnerability


def test_critical_routes_to_queue():
    remediation, vulnerability = _make_pair("Critical")
    session = FakeSession(remediation, vulnerability)
    updated = asyncio.run(ApprovalService().route_for_approval(session, str(remediation.id), str(uuid4())))
    assert updated.status == "awaiting_approval"


def test_high_routes_to_queue():
    remediation, vulnerability = _make_pair("High")
    session = FakeSession(remediation, vulnerability)
    updated = asyncio.run(ApprovalService().route_for_approval(session, str(remediation.id), str(uuid4())))
    assert updated.status == "awaiting_approval"
    assert updated.approved_by is None


def test_low_auto_approves():
    remediation, vulnerability = _make_pair("Low")
    session = FakeSession(remediation, vulnerability)
    ticket_calls = []
    service = ApprovalService()
    service._enqueue_itsm_ticket = lambda remediation_id, tenant_id: ticket_calls.append((remediation_id, tenant_id))
    tenant_id = str(uuid4())
    updated = asyncio.run(service.route_for_approval(session, str(remediation.id), tenant_id))
    assert updated.status == "approved"
    assert updated.execution_status == "approved"
    assert updated.approved_by is None
    assert updated.approved_at is not None
    assert vulnerability.status == "approved"
    assert ticket_calls == [(str(remediation.id), tenant_id)]


def test_medium_auto_approves():
    remediation, vulnerability = _make_pair("Medium")
    session = FakeSession(remediation, vulnerability)
    service = ApprovalService()
    service._enqueue_itsm_ticket = lambda remediation_id, tenant_id: None
    updated = asyncio.run(service.route_for_approval(session, str(remediation.id), str(uuid4())))
    assert updated.status == "approved"
    assert updated.execution_status == "approved"
    assert updated.approved_by is None
    assert updated.approved_at is not None
    assert vulnerability.status == "approved"


def test_approve_sets_correct_fields():
    remediation, vulnerability = _make_pair("Critical")
    session = FakeSession(remediation, vulnerability)
    approver_id = str(uuid4())
    reason = "Approved after reviewing rollback steps."
    ticket_calls = []
    service = ApprovalService()
    service._enqueue_itsm_ticket = lambda remediation_id, tenant_id: ticket_calls.append((remediation_id, tenant_id))
    tenant_id = str(uuid4())
    updated = asyncio.run(service.approve(session, str(remediation.id), approver_id, reason, tenant_id))
    assert updated.approved_by == approver_id
    assert updated.approved_at is not None
    assert updated.rejection_reason is None
    assert vulnerability.status == "approved"
    assert any(getattr(obj, "rationale", None) == reason for obj in session.added)
    assert ticket_calls == [(str(remediation.id), tenant_id)]


def test_reject_records_reason():
    remediation, vulnerability = _make_pair("Critical")
    session = FakeSession(remediation, vulnerability)
    updated = asyncio.run(ApprovalService().reject(session, str(remediation.id), str(uuid4()), "too risky", str(uuid4())))
    assert updated.rejection_reason == "too risky"
    assert updated.status == "rejected"
    assert vulnerability.status == FindingStatus.rejected


def test_approve_requires_reason():
    remediation, vulnerability = _make_pair("Critical")
    session = FakeSession(remediation, vulnerability)

    with pytest.raises(ValueError, match="Reason is required"):
        asyncio.run(ApprovalService().approve(session, str(remediation.id), str(uuid4()), "   ", str(uuid4())))


def test_reject_requires_reason():
    remediation, vulnerability = _make_pair("Critical")
    session = FakeSession(remediation, vulnerability)

    with pytest.raises(ValueError, match="Reason is required"):
        asyncio.run(ApprovalService().reject(session, str(remediation.id), str(uuid4()), "   ", str(uuid4())))


def test_route_for_approval_audit_links_finding(monkeypatch):
    remediation, vulnerability = _make_pair("Critical")
    session = FakeSession(remediation, vulnerability)
    recorder = AuditRecorder()
    monkeypatch.setattr("app.services.approval_service.AuditWriter", lambda: recorder)

    asyncio.run(ApprovalService().route_for_approval(session, str(remediation.id), str(uuid4())))

    assert recorder.payloads[-1].details["finding_id"] == str(vulnerability.id)
    assert recorder.payloads[-1].details["remediation_id"] == str(remediation.id)


def test_low_route_auto_approval_audit(monkeypatch):
    remediation, vulnerability = _make_pair("Low")
    session = FakeSession(remediation, vulnerability)
    recorder = AuditRecorder()
    monkeypatch.setattr("app.services.approval_service.AuditWriter", lambda: recorder)
    service = ApprovalService()
    service._enqueue_itsm_ticket = lambda remediation_id, tenant_id: None

    asyncio.run(service.route_for_approval(session, str(remediation.id), str(uuid4())))

    assert recorder.payloads[-1].action == "remediation_approved"
    assert recorder.payloads[-1].details["finding_id"] == str(vulnerability.id)
    assert recorder.payloads[-1].details["auto_approved"] is True


def test_approve_audit_links_finding(monkeypatch):
    remediation, vulnerability = _make_pair("Critical")
    session = FakeSession(remediation, vulnerability)
    approver_id = str(uuid4())
    reason = "Approved during CAB review."
    recorder = AuditRecorder()
    monkeypatch.setattr("app.services.approval_service.AuditWriter", lambda: recorder)

    service = ApprovalService()
    service._enqueue_itsm_ticket = lambda remediation_id, tenant_id: None
    asyncio.run(service.approve(session, str(remediation.id), approver_id, reason, str(uuid4())))

    assert recorder.payloads[-1].details["finding_id"] == str(vulnerability.id)
    assert recorder.payloads[-1].details["remediation_id"] == str(remediation.id)
    assert recorder.payloads[-1].details["approver_user_id"] == approver_id
    assert recorder.payloads[-1].details["reason"] == reason


def test_reject_audit_links_finding(monkeypatch):
    remediation, vulnerability = _make_pair("Critical")
    session = FakeSession(remediation, vulnerability)
    approver_id = str(uuid4())
    recorder = AuditRecorder()
    monkeypatch.setattr("app.services.approval_service.AuditWriter", lambda: recorder)

    asyncio.run(ApprovalService().reject(session, str(remediation.id), approver_id, "too risky", str(uuid4())))

    assert recorder.payloads[-1].details["finding_id"] == str(vulnerability.id)
    assert recorder.payloads[-1].details["remediation_id"] == str(remediation.id)
    assert recorder.payloads[-1].details["reason"] == "too risky"
