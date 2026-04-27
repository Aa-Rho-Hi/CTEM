import asyncio
import hashlib
import hmac

from app.models.entities import AuditLog
from app.schemas.common import AuditLogCreate


def _sign_audit_entry(action: str, resource_type: str, resource_id: str, tenant_id: str, created_at: str, secret: str) -> str:
    """HMAC-SHA256 over canonical fields — tamper-evident audit trail (BR-3)."""
    message = f"{action}:{resource_type}:{resource_id}:{tenant_id}:{created_at}".encode()
    return hmac.new(secret.encode(), message, hashlib.sha256).hexdigest()


class AuditWriter:
    async def write(self, session, tenant_id, payload: AuditLogCreate) -> AuditLog:
        from app.config import get_settings
        from datetime import datetime, timezone

        created_at = datetime.now(timezone.utc)
        sig = _sign_audit_entry(
            action=payload.action,
            resource_type=payload.resource_type,
            resource_id=str(payload.resource_id or ""),
            tenant_id=str(tenant_id),
            created_at=created_at.isoformat(),
            secret=get_settings().jwt_secret_key,
        )
        entry = AuditLog(
            tenant_id=tenant_id,
            user_id=payload.user_id,
            action=payload.action,
            resource_type=payload.resource_type,
            resource_id=payload.resource_id,
            details=payload.details,
            created_at=created_at,
            signature=sig,
        )
        session.add(entry)
        await session.flush()

        from app.services.splunk import SplunkService
        asyncio.ensure_future(
            SplunkService().send_event(
                sourcetype="atlas:audit_log",
                event={
                    "action": entry.action,
                    "resource_type": entry.resource_type,
                    "resource_id": entry.resource_id,
                    "tenant_id": str(entry.tenant_id),
                    "user_id": str(entry.user_id) if entry.user_id else None,
                    "details": entry.details,
                },
            )
        )
        return entry

