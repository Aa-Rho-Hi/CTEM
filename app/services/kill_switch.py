try:
    from redis.asyncio import Redis
    from redis.exceptions import RedisError as RedisConnectionError
except ImportError:  # pragma: no cover
    Redis = object

    class RedisConnectionError(Exception):
        pass


class KillSwitchActiveError(RuntimeError):
    pass


class KillSwitchService:
    REDIS_KEY = b"atlas:kill_switch"

    def __init__(self, redis):
        self.redis = redis

    async def is_active(self) -> bool:
        try:
            return await self.redis.get(self.REDIS_KEY) == b"1"
        except Exception:
            return True  # fail-closed: any error = halt PT

    async def activate(self, activated_by: str, tenant_id: str, audit_writer, session) -> None:
        await self.redis.set(self.REDIS_KEY, b"1")
        from app.schemas.common import AuditLogCreate
        await audit_writer.write(session, tenant_id, AuditLogCreate(
            action="kill_switch_activated",
            resource_type="system",
            resource_id="kill_switch",
            user_id=activated_by,
            details={"activated_by": activated_by},
        ))

    async def deactivate(self, deactivated_by: str, tenant_id: str, audit_writer, session) -> None:
        await self.redis.set(self.REDIS_KEY, b"0")
        from app.schemas.common import AuditLogCreate
        await audit_writer.write(session, tenant_id, AuditLogCreate(
            action="kill_switch_deactivated",
            resource_type="system",
            resource_id="kill_switch",
            user_id=deactivated_by,
            details={"deactivated_by": deactivated_by},
        ))

    async def get_status(self) -> dict:
        try:
            val = await self.redis.get(self.REDIS_KEY)
            return {"active": val == b"1", "redis_reachable": True}
        except Exception:
            return {"active": True, "redis_reachable": False}
