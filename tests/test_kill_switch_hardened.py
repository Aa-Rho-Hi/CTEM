import asyncio

import pytest

from app.services.kill_switch import KillSwitchService


class FakeRedis:
    def __init__(self, value=None):
        self._store = {}
        if value is not None:
            self._store[KillSwitchService.REDIS_KEY] = value

    async def get(self, key):
        return self._store.get(key)

    async def set(self, key, value):
        self._store[key] = value


class DownRedis:
    async def get(self, key):
        raise ConnectionError("redis down")

    async def set(self, key, value):
        raise ConnectionError("redis down")


class TimeoutRedis:
    async def get(self, key):
        raise TimeoutError("timeout")

    async def set(self, key, value):
        raise TimeoutError("timeout")


class FakeSession:
    def __init__(self):
        self.added = []

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        pass


class MockAuditWriter:
    def __init__(self):
        self.calls = []

    async def write(self, session, tenant_id, payload):
        self.calls.append(payload)


def test_namespaced_key():
    assert KillSwitchService.REDIS_KEY == b"atlas:kill_switch"


def test_redis_connection_error_returns_true():
    svc = KillSwitchService(DownRedis())
    assert asyncio.run(svc.is_active()) is True


def test_redis_timeout_returns_true():
    svc = KillSwitchService(TimeoutRedis())
    assert asyncio.run(svc.is_active()) is True


def test_activate_writes_audit():
    redis = FakeRedis()
    aw = MockAuditWriter()
    asyncio.run(KillSwitchService(redis).activate("user-123", "tenant-1", aw, FakeSession()))
    assert len(aw.calls) == 1
    assert aw.calls[0].action == "kill_switch_activated"
    assert redis._store[KillSwitchService.REDIS_KEY] == b"1"


def test_deactivate_writes_audit():
    redis = FakeRedis(b"1")
    aw = MockAuditWriter()
    asyncio.run(KillSwitchService(redis).deactivate("user-123", "tenant-1", aw, FakeSession()))
    assert len(aw.calls) == 1
    assert aw.calls[0].action == "kill_switch_deactivated"
    assert redis._store[KillSwitchService.REDIS_KEY] == b"0"


def test_get_status_redis_down():
    result = asyncio.run(KillSwitchService(DownRedis()).get_status())
    assert result == {"active": True, "redis_reachable": False}
