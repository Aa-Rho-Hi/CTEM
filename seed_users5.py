import asyncio
from uuid import UUID
from sqlalchemy import select

TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")

USERS = [
    ("admin@atlas-ctem.com",    "AdminPass123!",    "super_admin"),
    ("platform@atlas-ctem.com", "PlatformPass123!", "platform_admin"),
    ("analyst@atlas-ctem.com",  "AnalystPass123!",  "security_analyst"),
    ("approver@atlas-ctem.com", "ApproverPass123!", "approver"),
    ("auditor@atlas-ctem.com",  "AuditorPass123!",  "auditor"),
    ("viewer@atlas-ctem.com",   "ViewerPass123!",   "client_viewer"),
]

async def seed():
    from app.models.base import get_session_factory
    from app.models.entities import User, Role, UserRole, RoleName
    from app.core.security import get_password_hash
    async with get_session_factory()() as session:
        role_map = {}
        for _, _, role_name_str in USERS:
            result = await session.execute(select(Role).where(Role.name == RoleName(role_name_str)))
            role = result.scalar_one_or_none()
            if not role:
                role = Role(name=RoleName(role_name_str))
                session.add(role)
                await session.flush()
            role_map[role_name_str] = role

        for email, password, role_name_str in USERS:
            result = await session.execute(select(User).where(User.email == email))
            user = result.scalar_one_or_none()
            if not user:
                user = User(
                    email=email,
                    hashed_password=get_password_hash(password),
                    tenant_id=TENANT_ID,
                    is_active=True,
                )
                session.add(user)
                await session.flush()
                print(f"Created user: {email}")
            else:
                print(f"User {email} already exists")

            result2 = await session.execute(select(UserRole).where(UserRole.user_id == user.id))
            ur_existing = result2.scalar_one_or_none()
            if not ur_existing:
                ur = UserRole(user_id=user.id, role_id=role_map[role_name_str].id, tenant_id=TENANT_ID)
                session.add(ur)
                print(f"  -> Linked to role: {role_name_str}")

        await session.commit()
        print("Done seeding users.")

asyncio.run(seed())
