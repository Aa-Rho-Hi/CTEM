import asyncio
from uuid import UUID
import bcrypt
from sqlalchemy import select

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
        for email, password, role_name_str in USERS:
            result = await session.execute(select(User).where(User.email == email))
            existing = result.scalar_one_or_none()
            if existing:
                print(f"User {email} already exists, skipping.")
                continue
            user = User(
                email=email,
                hashed_password=hash_password(password),
                tenant_id=TENANT_ID,
                is_active=True,
            )
            session.add(user)
            await session.flush()
            role = Role(name=RoleName(role_name_str))
            session.add(role)
            await session.flush()
            from app.models.entities import UserRole
            ur = UserRole(user_id=user.id, role_id=role.id, tenant_id=TENANT_ID)
            session.add(ur)
            print(f"Created user: {email} with role: {role_name_str}")
        await session.commit()
        print("Done seeding users.")

asyncio.run(seed())
