import asyncio
from datetime import datetime, timezone
from types import SimpleNamespace
from uuid import uuid4

import pytest

from app.services.change_window import ChangeWindowService
from app.services.errors import ChangeWindowBlockedError


class FakeSession:
    def __init__(self, asset, zone):
        self.asset = asset
        self.zone = zone

    async def get(self, model, key):
        if model.__name__ == "Asset":
            return self.asset
        return self.zone


def test_inside_window_allowed():
    asset = SimpleNamespace(id=uuid4(), zone_id=uuid4())
    zone = SimpleNamespace(name="prod", change_windows={"change_window_days": [2], "change_window_start": "10:00", "change_window_end": "12:00"})
    svc = ChangeWindowService(now_provider=lambda: datetime(2026, 4, 1, 10, 30, tzinfo=timezone.utc))
    assert asyncio.run(svc.is_execution_allowed(FakeSession(asset, zone), str(asset.id), str(uuid4()))) is True


def test_outside_window_blocked():
    asset = SimpleNamespace(id=uuid4(), zone_id=uuid4())
    zone = SimpleNamespace(name="prod", change_windows={"change_window_days": [2], "change_window_start": "10:00", "change_window_end": "12:00"})
    svc = ChangeWindowService(now_provider=lambda: datetime(2026, 4, 1, 13, 0, tzinfo=timezone.utc))
    with pytest.raises(ChangeWindowBlockedError):
        asyncio.run(svc.is_execution_allowed(FakeSession(asset, zone), str(asset.id), str(uuid4())))


def test_no_window_always_allowed():
    asset = SimpleNamespace(id=uuid4(), zone_id=uuid4())
    zone = SimpleNamespace(name="prod", change_windows={})
    svc = ChangeWindowService()
    assert asyncio.run(svc.is_execution_allowed(FakeSession(asset, zone), str(asset.id), str(uuid4()))) is True
