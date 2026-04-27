from datetime import datetime, timedelta, timezone
from dataclasses import dataclass
from functools import wraps
from typing import Any
from uuid import UUID

from fastapi import Depends, HTTPException, Request, status
from sqlalchemy import select
try:
    from jose import JWTError, jwt
except ImportError:  # pragma: no cover
    class JWTError(Exception):
        pass

    class _MissingJWTModule:
        def encode(self, *args, **kwargs):
            raise RuntimeError("python-jose is required for JWT encoding.")

        def decode(self, *args, **kwargs):
            raise RuntimeError("python-jose is required for JWT decoding.")

    jwt = _MissingJWTModule()
try:
    from passlib.context import CryptContext
except ImportError:  # pragma: no cover
    class CryptContext:
        def __init__(self, *args, **kwargs):
            pass

        def verify(self, plain_password: str, hashed_password: str) -> bool:
            return plain_password == hashed_password

        def hash(self, password: str) -> str:
            return password

from app.config import get_settings
from app.models.base import get_session_factory
from app.models.entities import Role, User, UserRole

pwd_context = CryptContext(schemes=["bcrypt"], deprecated="auto")


@dataclass
class CurrentUser:
    user_id: str
    tenant_id: UUID
    role: str


def verify_password(plain_password: str, hashed_password: str) -> bool:
    return pwd_context.verify(plain_password, hashed_password)


def get_password_hash(password: str) -> str:
    return pwd_context.hash(password)


def create_access_token(subject: str, tenant_id: UUID, role: str) -> str:
    settings = get_settings()
    expire = datetime.now(timezone.utc) + timedelta(minutes=settings.jwt_expire_minutes)
    payload: dict[str, Any] = {
        "sub": subject,
        "tenant_id": str(tenant_id),
        "role": role,
        "exp": expire,
    }
    return jwt.encode(payload, settings.jwt_secret_key, algorithm=settings.jwt_algorithm)


def decode_token(token: str) -> dict[str, Any]:
    settings = get_settings()
    try:
        return jwt.decode(token, settings.jwt_secret_key, algorithms=[settings.jwt_algorithm])
    except JWTError as exc:
        raise ValueError("Invalid JWT token.") from exc


async def _load_current_role(session, user: User) -> str:
    role_name_result = (
        await session.execute(
            select(Role.name)
            .join(UserRole, UserRole.role_id == Role.id)
            .where(UserRole.user_id == user.id, UserRole.tenant_id == user.tenant_id)
            .limit(1)
        )
    ).scalar_one_or_none()
    return role_name_result.value if role_name_result else "security_analyst"


async def get_current_user(request: Request) -> CurrentUser:
    user_id = getattr(request.state, "user_id", None)
    token_tenant_id = getattr(request.state, "tenant_id", None)
    if user_id is None or token_tenant_id is None:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")

    async with get_session_factory()() as session:
        user = await session.get(User, user_id)
        if user is None or not user.is_active or user.tenant_id != token_tenant_id:
            raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="Authentication required.")
        role = await _load_current_role(session, user)

    return CurrentUser(user_id=str(user.id), tenant_id=user.tenant_id, role=role)


def require_roles(*roles: str):
    async def checker(current_user: CurrentUser = Depends(get_current_user)) -> CurrentUser:
        if current_user.role not in roles:
            raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role.")
        return current_user

    return checker


def require_roles_decorator(*roles: str):
    def decorator(func):
        @wraps(func)
        async def wrapper(*args, current_user: CurrentUser = Depends(get_current_user), **kwargs):
            if current_user.role not in roles:
                raise HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail="Insufficient role.")
            return await func(*args, current_user=current_user, **kwargs)

        return wrapper

    return decorator
