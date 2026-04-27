from dataclasses import dataclass
from uuid import UUID

from app.models.entities import RoleName, Tenant


class AuthConflictError(ValueError):
    pass


class AuthValidationError(ValueError):
    pass


class AuthUnauthorizedError(ValueError):
    pass


@dataclass(slots=True)
class RegisteredUserResult:
    id: str
    email: str
    role: str


@dataclass(slots=True)
class LoginResult:
    access_token: str
    tenant_id: UUID


class RegisterUserUseCase:
    def __init__(self, repository, *, build_user):
        self.repository = repository
        self.build_user = build_user

    async def execute(self, *, email: str, password: str, role: str, tenant_id: UUID) -> RegisteredUserResult:
        existing = await self.repository.get_user_by_email(email)
        if existing is not None:
            raise AuthConflictError("Email already registered.")

        try:
            role_name = RoleName(role)
        except ValueError as exc:
            valid = [item.value for item in RoleName]
            raise AuthValidationError(f"Invalid role. Must be one of: {valid}") from exc

        try:
            user = self.build_user(email, password, tenant_id)
        except ValueError as exc:
            raise AuthValidationError(str(exc)) from exc

        self.repository.add(user)
        await self.repository.flush()

        resolved_role = await self.repository.get_or_create_role(role_name)
        await self.repository.assign_role(user_id=user.id, role_id=resolved_role.id, tenant_id=tenant_id)
        await self.repository.commit()

        return RegisteredUserResult(id=str(user.id), email=user.email, role=role)


class SignupTenantUseCase:
    def __init__(self, repository, *, build_user, create_access_token):
        self.repository = repository
        self.build_user = build_user
        self.create_access_token = create_access_token

    async def execute(
        self,
        *,
        organization_name: str,
        email: str,
        password: str,
        confirm_password: str,
    ) -> LoginResult:
        if password != confirm_password:
            raise AuthValidationError("Passwords do not match.")

        existing_user = await self.repository.get_user_by_email(email)
        if existing_user is not None:
            raise AuthConflictError("Email already registered.")

        existing_tenant = await self.repository.get_tenant_by_name(organization_name)
        if existing_tenant is not None:
            raise AuthConflictError("Organization name already registered.")

        tenant = Tenant(name=organization_name)
        self.repository.add(tenant)
        await self.repository.flush()

        try:
            user = self.build_user(email, password, tenant.id)
        except ValueError as exc:
            raise AuthValidationError(str(exc)) from exc

        self.repository.add(user)
        await self.repository.flush()

        resolved_role = await self.repository.get_or_create_role(RoleName.super_admin)
        await self.repository.assign_role(user_id=user.id, role_id=resolved_role.id, tenant_id=tenant.id)
        await self.repository.commit()

        token = self.create_access_token(str(user.id), tenant.id, RoleName.super_admin.value)
        return LoginResult(access_token=token, tenant_id=tenant.id)


class LoginUseCase:
    def __init__(self, repository, *, verify_user_credentials, create_access_token):
        self.repository = repository
        self.verify_user_credentials = verify_user_credentials
        self.create_access_token = create_access_token

    async def execute(self, *, email: str, password: str) -> LoginResult:
        user = await self.repository.get_user_by_email(email)
        if not self.verify_user_credentials(user, password):
            raise AuthUnauthorizedError("Invalid credentials.")

        role = await self.repository.get_role_name_for_user(user.id, user.tenant_id)
        token = self.create_access_token(str(user.id), user.tenant_id, role or "security_analyst")
        return LoginResult(access_token=token, tenant_id=user.tenant_id)
