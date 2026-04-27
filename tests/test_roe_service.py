import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.services.errors import InvalidIPError, OutOfScopeError, ROEExpiredError, ROENotFoundError
from app.services.roe_service import ROEService


class FakeSession:
    def __init__(self, roe=None, pt_session=None):
        self._roe = roe
        self._pt_session = pt_session
        self.added = []

    async def get(self, model, key):
        if model.__name__ in ("RoeRecord",):
            return self._roe
        return None

    async def execute(self, stmt):
        class R:
            def __init__(self, obj):
                self._obj = obj
            def scalar_one_or_none(self):
                return self._obj
        return R(self._pt_session)

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        pass


class MockAuditWriter:
    async def write(self, *args, **kwargs):
        pass


class FakeROEData:
    def __init__(self, cidr, techniques=None, valid_from=None, valid_until=None, scope_notes=""):
        self.authorized_cidr = cidr
        self.authorized_techniques = techniques or []
        self.valid_from = valid_from or datetime.now(timezone.utc)
        self.valid_until = valid_until or (datetime.now(timezone.utc) + timedelta(days=365))
        self.scope_notes = scope_notes


def test_invalid_cidr_rejected():
    svc = ROEService()
    with pytest.raises(ValueError, match="Invalid CIDR"):
        asyncio.run(svc.create(FakeSession(), FakeROEData("not_a_cidr"), "user-1", "tenant-1"))
    # No DB writes should occur
    assert FakeSession().added == []


def test_valid_cidr_creates_roe(monkeypatch):
    import app.services.roe_service as roe_module

    class NoopAW:
        async def write(self, *a, **kw):
            pass

    monkeypatch.setattr(roe_module, "AuditWriter", NoopAW)
    session = FakeSession()
    roe = asyncio.run(ROEService().create(session, FakeROEData("10.0.0.0/24"), "user-1", "tenant-1"))
    assert roe.authorized_cidr == "10.0.0.0/24"
    assert len(session.added) >= 1


def test_expired_roe_raises():
    past = datetime.now(timezone.utc) - timedelta(seconds=1)
    roe = SimpleNamespace(id=uuid4(), status="active", authorized_cidr="10.0.0.0/24", valid_until=past)
    pt_session = SimpleNamespace(id=uuid4(), roe_id=str(roe.id))
    session = FakeSession(roe=roe, pt_session=pt_session)
    with pytest.raises(ROEExpiredError):
        asyncio.run(ROEService().assert_valid(session, str(pt_session.id), "tenant-1"))


def test_out_of_scope_raises():
    roe = SimpleNamespace(id=uuid4(), status="active", authorized_cidr="10.0.0.0/24",
                          valid_until=datetime.now(timezone.utc) + timedelta(days=1))
    with pytest.raises(OutOfScopeError):
        asyncio.run(ROEService().assert_in_scope("192.168.1.1", roe))


def test_in_scope_passes():
    roe = SimpleNamespace(authorized_cidr="10.0.0.0/24")
    # Should not raise
    asyncio.run(ROEService().assert_in_scope("10.0.0.5", roe))


def test_invalid_ip_raises():
    roe = SimpleNamespace(authorized_cidr="10.0.0.0/24")
    with pytest.raises(InvalidIPError):
        asyncio.run(ROEService().assert_in_scope("not_an_ip", roe))
