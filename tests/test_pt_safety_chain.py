import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.agents.base import BaseAgent, PTProbe
from app.services.errors import (
    ConfidenceBelowCeilingError,
    CrownJewelLockError,
    OutOfScopeError,
    ROEExpiredError,
    TenantBoundaryViolationError,
    ToolNotWhitelistedError,
)
from app.services.kill_switch import KillSwitchActiveError


TENANT_ID = str(uuid4())
AGENT_ID = str(uuid4())


def _make_agent(**kwargs):
    defaults = dict(
        tenant_id=TENANT_ID,
        tool_whitelist=["nmap"],
        safety_ceiling=70,
        agent_id=AGENT_ID,
        confidence_score=85,
    )
    defaults.update(kwargs)
    return BaseAgent(**defaults)


def _make_probe(**kwargs):
    defaults = dict(
        session_id=str(uuid4()),
        target_ip="10.0.0.5",
        target_asset_id=str(uuid4()),
        technique="T1059",
        tool="nmap",
        payload="nmap -sV",
        tenant_id=TENANT_ID,
    )
    defaults.update(kwargs)
    return PTProbe(**defaults)


class ActiveKillSwitch:
    async def is_active(self):
        return True


class InactiveKillSwitch:
    async def is_active(self):
        return False


class ValidROE:
    async def assert_valid(self, session, session_id, tenant_id):
        return SimpleNamespace(authorized_cidr="10.0.0.0/24",
                               valid_until=datetime.now(timezone.utc) + timedelta(days=1),
                               status="active")

    async def assert_in_scope(self, target_ip, roe):
        pass  # always in scope


class ExpiredROE:
    async def assert_valid(self, session, session_id, tenant_id):
        raise ROEExpiredError("roe-1")

    async def assert_in_scope(self, target_ip, roe):
        pass


class OutOfScopeROE:
    async def assert_valid(self, session, session_id, tenant_id):
        return SimpleNamespace(authorized_cidr="192.168.0.0/24")

    async def assert_in_scope(self, target_ip, roe):
        raise OutOfScopeError(target_ip, roe.authorized_cidr)


class SafeAsset:
    async def get(self, session, asset_id, tenant_id):
        return SimpleNamespace(crown_jewel_tier=None)


class CrownJewelAsset:
    async def get(self, session, asset_id, tenant_id):
        return SimpleNamespace(crown_jewel_tier="tier_1")


class MockEvidenceWriter:
    def __init__(self):
        self.calls = []

    async def write(self, session, **kwargs):
        self.calls.append(kwargs)


class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        pass


class NoopAW:
    async def write(self, *a, **kw):
        pass


def test_kill_switch_blocks_first():
    agent = _make_agent()
    probe = _make_probe()
    with pytest.raises(KillSwitchActiveError):
        asyncio.run(agent.execute("goal", probe, ActiveKillSwitch(), ValidROE(),
                                  SafeAsset(), MockEvidenceWriter(), FakeSession(), TENANT_ID))


def test_audit_written_before_probe(monkeypatch):
    import app.agents.base as base_module
    calls = []

    class TrackingAW:
        async def write(self, session, tenant_id, payload):
            calls.append(payload.action)

    monkeypatch.setattr(base_module, "AuditWriter", TrackingAW)

    agent = _make_agent()
    probe = _make_probe()
    asyncio.run(agent.execute("goal", probe, InactiveKillSwitch(), ValidROE(),
                              SafeAsset(), MockEvidenceWriter(), FakeSession(), TENANT_ID))
    assert calls[0] == "pt_probe_attempt"


def test_roe_expired_blocks(monkeypatch):
    import app.agents.base as base_module
    monkeypatch.setattr(base_module, "AuditWriter", NoopAW)

    agent = _make_agent()
    probe = _make_probe()
    with pytest.raises(ROEExpiredError):
        asyncio.run(agent.execute("goal", probe, InactiveKillSwitch(), ExpiredROE(),
                                  SafeAsset(), MockEvidenceWriter(), FakeSession(), TENANT_ID))


def test_out_of_scope_blocks(monkeypatch):
    import app.agents.base as base_module
    monkeypatch.setattr(base_module, "AuditWriter", NoopAW)

    agent = _make_agent()
    probe = _make_probe()
    with pytest.raises(OutOfScopeError):
        asyncio.run(agent.execute("goal", probe, InactiveKillSwitch(), OutOfScopeROE(),
                                  SafeAsset(), MockEvidenceWriter(), FakeSession(), TENANT_ID))


def test_tenant_wall_blocks(monkeypatch):
    import app.agents.base as base_module
    monkeypatch.setattr(base_module, "AuditWriter", NoopAW)

    agent = _make_agent(tenant_id=str(uuid4()))  # different tenant
    probe = _make_probe(tenant_id=TENANT_ID)
    with pytest.raises(TenantBoundaryViolationError):
        asyncio.run(agent.execute("goal", probe, InactiveKillSwitch(), ValidROE(),
                                  SafeAsset(), MockEvidenceWriter(), FakeSession(), TENANT_ID))


def test_crown_jewel_blocks(monkeypatch):
    import app.agents.base as base_module
    monkeypatch.setattr(base_module, "AuditWriter", NoopAW)

    agent = _make_agent()
    probe = _make_probe()
    with pytest.raises(CrownJewelLockError):
        asyncio.run(agent.execute("goal", probe, InactiveKillSwitch(), ValidROE(),
                                  CrownJewelAsset(), MockEvidenceWriter(), FakeSession(), TENANT_ID))


def test_tool_not_whitelisted(monkeypatch):
    import app.agents.base as base_module
    monkeypatch.setattr(base_module, "AuditWriter", NoopAW)

    agent = _make_agent(tool_whitelist=["nessus"])
    probe = _make_probe(tool="metasploit")
    with pytest.raises(ToolNotWhitelistedError):
        asyncio.run(agent.execute("goal", probe, InactiveKillSwitch(), ValidROE(),
                                  SafeAsset(), MockEvidenceWriter(), FakeSession(), TENANT_ID))


def test_confidence_below_ceiling(monkeypatch):
    import app.agents.base as base_module
    monkeypatch.setattr(base_module, "AuditWriter", NoopAW)

    agent = _make_agent(confidence_score=50, safety_ceiling=80)
    probe = _make_probe()
    with pytest.raises(ConfidenceBelowCeilingError):
        asyncio.run(agent.execute("goal", probe, InactiveKillSwitch(), ValidROE(),
                                  SafeAsset(), MockEvidenceWriter(), FakeSession(), TENANT_ID))


def test_full_chain_success(monkeypatch):
    import app.agents.base as base_module
    monkeypatch.setattr(base_module, "AuditWriter", NoopAW)

    async def fake_run_probe(self, probe):
        return base_module.AgentResult(
            decision=f"probe_executed:{probe.technique}",
            confidence=90,
            outcome="exploitation_confirmed | mocked",
        )

    monkeypatch.setattr(base_module.BaseAgent, "_run_probe", fake_run_probe)

    agent = _make_agent()
    probe = _make_probe()
    ew = MockEvidenceWriter()
    result = asyncio.run(agent.execute("goal", probe, InactiveKillSwitch(), ValidROE(),
                                       SafeAsset(), ew, FakeSession(), TENANT_ID))
    assert "probe_executed" in result.decision
    assert len(ew.calls) == 1
