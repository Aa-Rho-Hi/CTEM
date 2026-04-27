from fastapi import APIRouter, Depends
from pydantic import BaseModel
from sqlalchemy import select

from app.core.security import CurrentUser, get_current_user, get_password_hash, require_roles
from app.dependencies import get_tenant_session
from app.models.entities import Role, RoleName, User, UserRole
from app.routes._shared import STANDARD_ERROR_RESPONSES, bad_request, conflict, not_found
from app.schemas.common import AuditLogCreate
from app.services.auth_service import validate_password_policy
from app.services.audit_writer import AuditWriter

router = APIRouter(prefix="/users", tags=["users"])


class RoleUpdateRequest(BaseModel):
    role: str


class UserUpdateRequest(BaseModel):
    email: str | None = None
    password: str | None = None
    role: str | None = None
    is_active: bool | None = None


class UserResponse(BaseModel):
    id: str
    email: str
    role: str | None
    is_active: bool
    created_at: str | None


class UserListResponse(BaseModel):
    items: list[UserResponse]


def _normalize_email(email: str) -> str:
    normalized = email.strip().lower()
    if "@" not in normalized:
        raise bad_request("Invalid email address.")
    return normalized


async def _load_role_name(session, user_id, tenant_id) -> str | None:
    role_name = (
        await session.execute(
            select(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user_id, UserRole.tenant_id == tenant_id)
            .limit(1)
        )
    ).scalar_one_or_none()
    return role_name.value if role_name else None


def _serialize_user(user: User, role: str | None) -> dict:
    return {
        "id": str(user.id),
        "email": user.email,
        "role": role,
        "is_active": user.is_active,
        "created_at": user.created_at.isoformat() if user.created_at else None,
    }


async def _get_or_create_role(session, role_name: RoleName) -> Role:
    role = (await session.execute(select(Role).where(Role.name == role_name))).scalar_one_or_none()
    if role is None:
        role = Role(name=role_name)
        session.add(role)
        await session.flush()
    return role


async def _load_user_role(session, user_id):
    return (
        await session.execute(select(UserRole).where(UserRole.user_id == user_id).limit(1))
    ).scalar_one_or_none()


@router.get("", response_model=UserListResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def list_users(session=Depends(get_tenant_session)):
    users = (await session.execute(select(User).order_by(User.created_at.desc()))).scalars().all()
    items = []
    for user in users:
        items.append(_serialize_user(user, await _load_role_name(session, user.id, user.tenant_id)))
    return {"items": items}


@router.get("/{user_id}", response_model=UserResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def get_user(user_id: str, session=Depends(get_tenant_session)):
    user = await session.get(User, user_id)
    if user is None:
        raise not_found("User not found.")
    return _serialize_user(user, await _load_role_name(session, user.id, user.tenant_id))


@router.post("/{user_id}/deactivate", response_model=UserResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def deactivate_user(
    user_id: str,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    user = await session.get(User, user_id)
    if user is None:
        raise not_found("User not found.")
    user.is_active = False
    await AuditWriter().write(
        session,
        str(current_user.tenant_id),
        AuditLogCreate(
            action="user_deactivated",
            resource_type="user",
            resource_id=str(user.id),
            user_id=current_user.user_id,
            details={"email": user.email},
        ),
    )
    await session.commit()
    return _serialize_user(user, await _load_role_name(session, user.id, user.tenant_id))


@router.post("/{user_id}/activate", response_model=UserResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def activate_user(
    user_id: str,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    user = await session.get(User, user_id)
    if user is None:
        raise not_found("User not found.")
    user.is_active = True
    await AuditWriter().write(
        session,
        str(current_user.tenant_id),
        AuditLogCreate(
            action="user_activated",
            resource_type="user",
            resource_id=str(user.id),
            user_id=current_user.user_id,
            details={"email": user.email},
        ),
    )
    await session.commit()
    return _serialize_user(user, await _load_role_name(session, user.id, user.tenant_id))


@router.put("/{user_id}/role", response_model=UserResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def change_user_role(
    user_id: str,
    payload: RoleUpdateRequest,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    if current_user.user_id == user_id:
        raise conflict("Users cannot change their own role.")
    user = await session.get(User, user_id)
    if user is None:
        raise not_found("User not found.")
    try:
        new_role_name = RoleName(payload.role)
    except ValueError as exc:
        raise bad_request(f"Invalid role: {payload.role}") from exc

    user_role = await _load_user_role(session, user.id)
    old_role = await _load_role_name(session, user.id, user.tenant_id)

    role = await _get_or_create_role(session, new_role_name)

    if user_role is None:
        user_role = UserRole(user_id=user.id, role_id=role.id, tenant_id=str(current_user.tenant_id))
        session.add(user_role)
    else:
        user_role.role_id = role.id

    await AuditWriter().write(
        session,
        str(current_user.tenant_id),
        AuditLogCreate(
            action="user_role_changed",
            resource_type="user",
            resource_id=str(user.id),
            user_id=current_user.user_id,
            details={"old_role": old_role, "new_role": new_role_name.value},
        ),
    )
    await session.commit()
    return _serialize_user(user, new_role_name.value)


@router.put("/{user_id}", response_model=UserResponse, responses=STANDARD_ERROR_RESPONSES, dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def update_user(
    user_id: str,
    payload: UserUpdateRequest,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    user = await session.get(User, user_id)
    if user is None:
        raise not_found("User not found.")

    body = payload.model_dump(exclude_none=True)
    if not body:
        raise bad_request("At least one editable field must be provided.")

    old_role = await _load_role_name(session, user.id, user.tenant_id)
    details: dict[str, object] = {"email": user.email}

    if "email" in body:
        new_email = _normalize_email(body["email"])
        if new_email != user.email:
            existing = (await session.execute(select(User).where(User.email == new_email))).scalar_one_or_none()
            if existing and str(existing.id) != str(user.id):
                raise conflict("Email already registered.")
            details["old_email"] = user.email
            user.email = new_email
            details["new_email"] = new_email

    if "password" in body:
        try:
            password = validate_password_policy(body["password"])
        except ValueError as exc:
            raise bad_request(str(exc)) from exc
        user.hashed_password = get_password_hash(password)
        details["password_reset"] = True

    if "is_active" in body:
        user.is_active = body["is_active"]
        details["is_active"] = user.is_active

    final_role = old_role
    if "role" in body:
        try:
            new_role_name = RoleName(body["role"])
        except ValueError as exc:
            raise bad_request(f"Invalid role: {body['role']}") from exc
        if current_user.user_id == user_id and new_role_name.value != old_role:
            raise conflict("Users cannot change their own role.")
        role = await _get_or_create_role(session, new_role_name)
        user_role = await _load_user_role(session, user.id)
        if user_role is None:
            user_role = UserRole(user_id=user.id, role_id=role.id, tenant_id=str(current_user.tenant_id))
            session.add(user_role)
        else:
            user_role.role_id = role.id
        final_role = new_role_name.value
        details["old_role"] = old_role
        details["new_role"] = final_role

    await AuditWriter().write(
        session,
        str(current_user.tenant_id),
        AuditLogCreate(
            action="user_updated",
            resource_type="user",
            resource_id=str(user.id),
            user_id=current_user.user_id,
            details=details,
        ),
    )
    await session.commit()
    return _serialize_user(user, final_role)
