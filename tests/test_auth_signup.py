import asyncio
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.models.entities import Role, RoleName, Tenant, User, UserRole
from app.routes.auth import signup
from app.schemas.auth import TenantSignupRequest


class FakeScalarResult:
    def __init__(self, rows):
        self.rows = rows

    def scalar_one_or_none(self):
        return self.rows[0] if self.rows else None


class SignupSession:
    def __init__(self, *, existing_user=None, existing_tenant=None, existing_role=None):
        self.existing_user = existing_user
        self.existing_tenant = existing_tenant
        self.existing_role = existing_role
        self.created_tenant = None
        self.created_user = None
        self.created_role = None
        self.created_user_role = None

    async def execute(self, statement):
        entity = statement.column_descriptions[0]["entity"]
        if entity is User:
            return FakeScalarResult([self.existing_user] if self.existing_user else [])
        if entity is Tenant:
            return FakeScalarResult([self.existing_tenant] if self.existing_tenant else [])
        if entity is Role:
            role = self.existing_role or self.created_role
            return FakeScalarResult([role] if role else [])
        return FakeScalarResult([])

    def add(self, model):
        if getattr(model, "id", None) is None:
            model.id = uuid4()
        if isinstance(model, Tenant):
            self.created_tenant = model
        elif isinstance(model, User):
            self.created_user = model
        elif isinstance(model, Role):
            self.created_role = model
        elif isinstance(model, UserRole):
            self.created_user_role = model

    async def flush(self):
        return None

    async def commit(self):
        return None


def test_signup_creates_tenant_and_first_super_admin(monkeypatch):
    session = SignupSession()
    monkeypatch.setattr("app.routes.auth.create_access_token", lambda subject, tenant_id, role: f"token:{tenant_id}:{role}")

    response = asyncio.run(
        signup(
            TenantSignupRequest(
                organization_name="Acme Corp",
                email="admin@acme.local",
                password="AdminPass123!",
                confirm_password="AdminPass123!",
            ),
            session=session,
        )
    )

    assert session.created_tenant is not None
    assert session.created_tenant.name == "Acme Corp"
    assert session.created_user is not None
    assert session.created_user.email == "admin@acme.local"
    assert session.created_user.tenant_id == session.created_tenant.id
    assert session.created_user_role is not None
    assert session.created_user_role.tenant_id == session.created_tenant.id
    assert response.tenant_id == session.created_tenant.id
    assert response.access_token == f"token:{session.created_tenant.id}:super_admin"


def test_signup_rejects_mismatched_passwords():
    session = SignupSession()

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            signup(
                TenantSignupRequest(
                    organization_name="Acme Corp",
                    email="admin@acme.local",
                    password="AdminPass123!",
                    confirm_password="WrongPass123!",
                ),
                session=session,
            )
        )

    assert exc.value.status_code == 400
    assert exc.value.detail == "Passwords do not match."
