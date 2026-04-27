import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.core.security import get_current_user, require_roles
from app.models.entities import User


class FakeScalarResult:
    def __init__(self, rows):
        self.rows = rows

    def scalar_one_or_none(self):
        return self.rows[0] if self.rows else None


class AuthLookupSession:
    def __init__(self, user: User | None, role: str | None):
        self.user = user
        self.role = role

    async def __aenter__(self):
        return self

    async def __aexit__(self, exc_type, exc, tb):
        return False

    async def get(self, model, user_id):
        if self.user is not None and model is User and str(self.user.id) == str(user_id):
            return self.user
        return None

    async def execute(self, statement):
        compiled = str(statement)
        assert "user_roles.tenant_id" in compiled
        rows = [SimpleNamespace(value=self.role)] if self.role else []
        return FakeScalarResult(rows)


class AuthSessionFactory:
    def __init__(self, session):
        self.session = session

    def __call__(self):
        return self.session


async def _run_role_checks(monkeypatch):
    tenant_id = uuid4()
    user = User(
        id=uuid4(),
        tenant_id=tenant_id,
        email="analyst@example.com",
        hashed_password="hash",
        is_active=True,
    )
    monkeypatch.setattr(
        "app.core.security.get_session_factory",
        lambda: AuthSessionFactory(AuthLookupSession(user, "security_analyst")),
    )
    request = SimpleNamespace(state=SimpleNamespace(user_id=str(user.id), tenant_id=tenant_id, role="super_admin"))
    current_user = await get_current_user(request)
    checker = require_roles("security_analyst", "super_admin")
    allowed = await checker(current_user=current_user)
    assert allowed.role == "security_analyst"

    denied = require_roles("super_admin")
    try:
        await denied(current_user=current_user)
    except HTTPException as exc:
        assert exc.status_code == 403
    else:
        raise AssertionError("Expected role check to fail.")


async def _run_platform_admin_checks(monkeypatch):
    tenant_id = uuid4()
    user = User(
        id=uuid4(),
        tenant_id=tenant_id,
        email="platform@example.com",
        hashed_password="hash",
        is_active=True,
    )
    monkeypatch.setattr(
        "app.core.security.get_session_factory",
        lambda: AuthSessionFactory(AuthLookupSession(user, "platform_admin")),
    )
    request = SimpleNamespace(state=SimpleNamespace(user_id=str(user.id), tenant_id=tenant_id, role="security_analyst"))
    current_user = await get_current_user(request)
    checker = require_roles("super_admin", "platform_admin")
    allowed = await checker(current_user=current_user)
    assert allowed.role == "platform_admin"


def test_require_roles_enforces_allowed_roles(monkeypatch):
    asyncio.run(_run_role_checks(monkeypatch))


def test_require_roles_allows_platform_admin(monkeypatch):
    asyncio.run(_run_platform_admin_checks(monkeypatch))


def test_get_current_user_rejects_inactive_users(monkeypatch):
    tenant_id = uuid4()
    user = User(
        id=uuid4(),
        tenant_id=tenant_id,
        email="inactive@example.com",
        hashed_password="hash",
        is_active=False,
    )
    monkeypatch.setattr(
        "app.core.security.get_session_factory",
        lambda: AuthSessionFactory(AuthLookupSession(user, "security_analyst")),
    )
    request = SimpleNamespace(state=SimpleNamespace(user_id=str(user.id), tenant_id=tenant_id))

    with pytest.raises(HTTPException) as exc:
        asyncio.run(get_current_user(request))

    assert exc.value.status_code == 401
