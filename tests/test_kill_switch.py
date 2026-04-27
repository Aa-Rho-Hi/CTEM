import asyncio

from app.services.kill_switch import KillSwitchService, RedisConnectionError


class HealthyRedis:
    def __init__(self, value):
        self.value = value

    async def get(self, key):
        return self.value


class BrokenRedis:
    async def get(self, key):
        raise RedisConnectionError("down")


async def _assert_kill_switch_returns_true_when_flag_set():
    service = KillSwitchService(HealthyRedis(b"1"))
    assert await service.is_active() is True


async def _assert_kill_switch_fails_closed_when_redis_unreachable():
    service = KillSwitchService(BrokenRedis())
    assert await service.is_active() is True


def test_run_async_kill_switch_cases():
    asyncio.run(_assert_kill_switch_returns_true_when_flag_set())
    asyncio.run(_assert_kill_switch_fails_closed_when_redis_unreachable())
