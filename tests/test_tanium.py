import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.services.errors import ChangeWindowBlockedError, MissingApprovalAuditError, NotApprovedError
from app.services.kill_switch import KillSwitchActiveError
from app.services.tanium import TaniumService


class FakeRedis:
    async def get(self, key):
        return b"0"


class ActiveRedis:
    async def get(self, key):
        return b"1"


class FakeExecuteResult:
    def __init__(self, obj):
        self.obj = obj

    def scalar_one_or_none(self):
        return self.obj


class FakeSession:
    def __init__(self, remediation, approval=None, audit=None, asset=None, finding=None):
        self.remediation = remediation
        self.approval = approval
        self.audit = audit
        self.asset = asset
        self.finding = finding

    async def get(self, model, key):
        if model.__name__ == "Remediation":
            return self.remediation
        if model.__name__ == "Vulnerability":
            return self.finding
        if model.__name__ == "Asset":
            return self.asset
        return None

    async def execute(self, statement):
        text = str(statement)
        if "remediation_approvals" in text:
            return FakeExecuteResult(self.approval)
        if "audit_log" in text:
            return FakeExecuteResult(self.audit)
        return FakeExecuteResult(None)

    def add(self, obj):
        return None

    async def flush(self):
        return None

    async def commit(self):
        return None


def _build_inputs(status="approved", approved_by="approver-1", approval_status="approved", auto_approved=False):
    remediation = SimpleNamespace(id=uuid4(), vulnerability_id=uuid4(), status=status, approved_by=approved_by)
    approval = SimpleNamespace(approver_user_id=approved_by, status=approval_status)
    audit = SimpleNamespace(id=uuid4(), details={"auto_approved": auto_approved})
    asset = SimpleNamespace(id=uuid4(), ip_address="10.0.0.10", zone_id=None)
    finding = SimpleNamespace(id=remediation.vulnerability_id, asset_id=asset.id)
    return remediation, approval, audit, asset, finding


def test_blocks_without_approval():
    remediation, approval, audit, asset, finding = _build_inputs(status="pending", approved_by=None)
    with pytest.raises(NotApprovedError):
        asyncio.run(TaniumService(FakeRedis()).execute_patch(FakeSession(remediation, approval, audit, asset, finding), str(remediation.id), str(uuid4())))


def test_blocks_on_kill_switch():
    remediation, approval, audit, asset, finding = _build_inputs()
    with pytest.raises(KillSwitchActiveError):
        asyncio.run(TaniumService(ActiveRedis()).execute_patch(FakeSession(remediation, approval, audit, asset, finding), str(remediation.id), str(uuid4())))


def test_blocks_outside_change_window(monkeypatch):
    remediation, approval, audit, asset, finding = _build_inputs()

    async def blocked(*args, **kwargs):
        raise ChangeWindowBlockedError("prod", "10:00", "12:00")

    from app.services import tanium as tanium_module

    tanium_module.ChangeWindowService.is_execution_allowed = blocked
    with pytest.raises(ChangeWindowBlockedError):
        asyncio.run(TaniumService(FakeRedis()).execute_patch(FakeSession(remediation, approval, audit, asset, finding), str(remediation.id), str(uuid4())))


def test_dev_mock_returns_action_id(monkeypatch):
    remediation, approval, audit, asset, finding = _build_inputs()
    from app.services import tanium as tanium_module

    async def allowed(*args, **kwargs):
        return True

    tanium_module.ChangeWindowService.is_execution_allowed = allowed
    service = TaniumService(FakeRedis())
    service.settings.environment = "development"
    result = asyncio.run(service.execute_patch(FakeSession(remediation, approval, audit, asset, finding), str(remediation.id), str(uuid4())))
    assert result["action_id"] == "mock-tanium-001"


def test_dev_mock_allows_auto_approved_plan(monkeypatch):
    remediation, approval, audit, asset, finding = _build_inputs(approved_by=None, auto_approved=True)
    from app.services import tanium as tanium_module

    async def allowed(*args, **kwargs):
        return True

    tanium_module.ChangeWindowService.is_execution_allowed = allowed
    service = TaniumService(FakeRedis())
    service.settings.environment = "development"
    result = asyncio.run(service.execute_patch(FakeSession(remediation, approval, audit, asset, finding), str(remediation.id), str(uuid4())))
    assert result["action_id"] == "mock-tanium-001"
