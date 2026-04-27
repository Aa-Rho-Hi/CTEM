from collections.abc import AsyncGenerator

from fastapi import Depends
try:
    from redis.asyncio import Redis
except ImportError:  # pragma: no cover
    class Redis:
        @staticmethod
        def from_url(url):
            raise RuntimeError("redis package is not installed")

from app.config import get_settings
from app.core.security import CurrentUser, get_current_user
from app.models.base import get_scoped_session, get_session_factory


async def get_db_session() -> AsyncGenerator:
    async with get_session_factory()() as session:
        yield session


async def get_tenant_session(current_user: CurrentUser = Depends(get_current_user)) -> AsyncGenerator:
    async with get_scoped_session(current_user.tenant_id) as session:
        yield session


def get_redis() -> Redis:
    settings = get_settings()
    return Redis.from_url(settings.redis_url)
