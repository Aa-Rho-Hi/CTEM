from redis.asyncio import Redis
from sqlalchemy import text


class HealthService:
    def __init__(self, redis: Redis):
        self.redis = redis

    async def check_postgres(self, session) -> str:
        try:
            await session.execute(text("SELECT 1"))
            return "ok"
        except Exception:
            return "error"

    async def check_redis(self) -> str:
        try:
            await self.redis.ping()
            return "ok"
        except Exception:
            return "error"

    async def celery_queue_depth(self) -> int:
        try:
            return await self.redis.llen("celery")
        except Exception:
            return -1

