import asyncio
from uuid import UUID
import bcrypt
from sqlalchemy import select, text

TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")

USERS = [
    ("admin@atlas.local",    "AdminPass123!",    "super_admin"),
    ("analyst@atlas.local",  "AnalystPass123!",  "security_analyst"),
    ("approver@atlas.local", "ApproverPass123!", "approver"),
    ("auditor@atlas.local",  "AuditorPass123!",  "auditor"),
    ("viewer@atlas.local",   "ViewerPass123!",   "client_viewer"),
]

def hash_password(password: str) -> str:
    return bcrypt.hashpw(password.encode(), bcrypt.gensalt()).decode()

async def seed():
    from app.models.base import get_session_factory
    from app.models.entities import User, Role, UserRole, RoleName
    async with get_session_factory()() as session:
        # Get or create roles
        role_map = {}
        for _, _, role_name_str in USERS:
            result = await session.execute(select(Role).where(Role.name == RoleName(role_name_str)))
            role = result.scalar_one_or_none()
            if not role:
                role = Role(name=RoleName(role_name_str))
                session.add(role)
                await session.flush()
                print(f"Created role: {role_name_str}")
            else:
                print(f"Role {role_name_str} already exists, id={role.id}")
            role_map[role_name_str] = role

        # Get or create users
        for email, password, role_name_str in USERS:
            result = await session.execute(select(User).where(User.email == email))
            user = result.scalar_one_or_none()
            if not user:
                user = User(
                    email=email,
                    hashed_password=hash_password(password),
                    tenant_id=TENANT_ID,
                    is_active=True,
                )
                session.add(user)
                await session.flush()
                print(f"Created user: {email}")
            else:
                print(f"User {email} already exists")

            # Check if user-role mapping exists
            result2 = await session.execute(
                select(UserRole).where(UserRole.user_id == user.id)
            )
            ur_existing = result2.scalar_one_or_none()
            if not ur_existing:
                ur = UserRole(user_id=user.id, role_id=role_map[role_name_str].id, tenant_id=TENANT_ID)
                session.add(ur)
                print(f"  -> Linked to role: {role_name_str}")

        await session.commit()
        print("Done seeding users.")

asyncio.run(seed())
