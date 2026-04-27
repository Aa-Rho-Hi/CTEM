from sqlalchemy import func, select

from app.models.entities import Role, RoleName, Tenant, User, UserRole


class AuthRepository:
    def __init__(self, session):
        self.session = session

    async def get_user_by_email(self, email: str) -> User | None:
        return (await self.session.execute(select(User).where(User.email == email))).scalar_one_or_none()

    async def get_tenant_by_name(self, name: str) -> Tenant | None:
        return (
            await self.session.execute(
                select(Tenant).where(func.lower(Tenant.name) == name.strip().lower())
            )
        ).scalar_one_or_none()

    async def get_or_create_role(self, role_name: RoleName) -> Role:
        role = (await self.session.execute(select(Role).where(Role.name == role_name))).scalar_one_or_none()
        if role is None:
            role = Role(name=role_name)
            self.session.add(role)
            await self.session.flush()
        return role

    async def assign_role(self, *, user_id, role_id, tenant_id) -> UserRole:
        user_role = UserRole(user_id=user_id, role_id=role_id, tenant_id=tenant_id)
        self.session.add(user_role)
        return user_role

    async def get_role_name_for_user(self, user_id, tenant_id) -> str | None:
        role_name_result = (
            await self.session.execute(
                select(Role.name)
                .join(UserRole, UserRole.role_id == Role.id)
                .where(UserRole.user_id == user_id, UserRole.tenant_id == tenant_id)
                .limit(1)
            )
        ).scalar_one_or_none()
        return role_name_result.value if role_name_result else None

    def add(self, model) -> None:
        self.session.add(model)

    async def flush(self) -> None:
        await self.session.flush()

    async def commit(self) -> None:
        await self.session.commit()
