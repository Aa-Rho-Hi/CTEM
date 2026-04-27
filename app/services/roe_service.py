import ipaddress
from datetime import datetime, timezone

from sqlalchemy import select

from app.models.entities import PtSession, RoeRecord
from app.schemas.common import AuditLogCreate
from app.services.audit_writer import AuditWriter
from app.services.errors import InvalidIPError, OutOfScopeError, ROEExpiredError, ROENotFoundError


class ROEService:

    async def create(self, session, roe_data, created_by: str, tenant_id: str) -> RoeRecord:
        try:
            ipaddress.ip_network(roe_data.authorized_cidr, strict=False)
        except ValueError:
            raise ValueError(f"Invalid CIDR: {roe_data.authorized_cidr}")

        roe = RoeRecord(
            tenant_id=tenant_id,
            authorized_cidr=roe_data.authorized_cidr,
            authorized_techniques=roe_data.authorized_techniques,
            authorized_by=created_by,
            valid_from=roe_data.valid_from,
            valid_until=roe_data.valid_until,
            scope_notes=roe_data.scope_notes,
            status="active",
        )
        session.add(roe)
        await session.flush()
        await AuditWriter().write(session, tenant_id, AuditLogCreate(
            action="roe_created",
            resource_type="roe",
            resource_id=str(roe.id),
            user_id=created_by,
            details={"authorized_cidr": roe_data.authorized_cidr},
        ))
        return roe

    async def assert_valid(self, session, session_id: str, tenant_id: str) -> RoeRecord:
        pt_session = (await session.execute(
            select(PtSession).where(PtSession.id == session_id)
        )).scalar_one_or_none()
        if pt_session is None:
            raise ROENotFoundError(f"PT session {session_id} not found")

        roe = await session.get(RoeRecord, pt_session.roe_id)
        if roe is None:
            raise ROENotFoundError(f"ROE not found for session {session_id}")
        if roe.status != "active":
            raise ROEExpiredError(str(roe.id))
        if datetime.now(timezone.utc) > roe.valid_until:
            roe.status = "expired"
            await session.flush()
            raise ROEExpiredError(str(roe.id))
        return roe

    async def assert_in_scope(self, target_ip: str, roe: RoeRecord) -> None:
        try:
            ip = ipaddress.ip_address(target_ip)
        except ValueError:
            raise InvalidIPError(target_ip)
        try:
            network = ipaddress.ip_network(roe.authorized_cidr, strict=False)
        except ValueError:
            raise InvalidIPError(roe.authorized_cidr)
        if ip not in network:
            raise OutOfScopeError(target_ip, roe.authorized_cidr)

    async def expire(self, session, roe_id: str, expired_by: str, tenant_id: str) -> RoeRecord:
        roe = await session.get(RoeRecord, roe_id)
        if roe is None:
            raise ROENotFoundError(roe_id)
        roe.status = "expired"
        await AuditWriter().write(session, tenant_id, AuditLogCreate(
            action="roe_expired",
            resource_type="roe",
            resource_id=str(roe.id),
            user_id=expired_by,
            details={"expired_by": expired_by},
        ))
        return roe
