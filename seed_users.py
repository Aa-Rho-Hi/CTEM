import asyncio
from uuid import UUID
import sys
sys.path.insert(0, '/app')
from app.models.base import get_session_factory
from app.models.entities import User, Role, UserRole, RoleName
from app.core.security import get_password_hash
from sqlalchemy import select

TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")

USERS = [
    ("admin@atlas.local",    "AdminPass123!",    RoleName.super_admin),
    ("platform@atlas.local", "PlatformPass123!", RoleName.platform_admin),
    ("analyst@atlas.local",  "AnalystPass123!",  RoleName.security_analyst),
    ("approver@atlas.local", "ApproverPass123!", RoleName.approver),
    ("auditor@atlas.local",  "AuditorPass123!",  RoleName.auditor),
    ("viewer@atlas.local",   "ViewerPass123!",   RoleName.client_viewer),
]

async def seed():
    async with get_session_factory()() as session:
        for email, password, role_name in USERS:
            result = await session.execute(select(User).where(User.email == email))
            existing = result.scalar_one_or_none()
            if existing:
                print(f"User {email} already exists, skipping.")
                continue
            user = User(
                email=email,
                hashed_password=get_password_hash(password),
                tenant_id=TENANT_ID,
                is_active=True,
            )
            session.add(user)
            await session.flush()
            role = Role(name=role_name)
            session.add(role)
            await session.flush()
            ur = UserRole(user_id=user.id, role_id=role.id, tenant_id=TENANT_ID)
            session.add(ur)
        await session.commit()
        print("Seeded users successfully.")

asyncio.run(seed())
