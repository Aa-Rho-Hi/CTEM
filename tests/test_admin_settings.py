import asyncio
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.models.entities import Role, RoleName, User, UserRole
from app.routes.integrations import _validate_integration_payload, get_integration_catalog
from app.routes.users import UserUpdateRequest, activate_user, deactivate_user, update_user


class FakeScalarResult:
    def __init__(self, value):
        self.value = value

    def scalar_one_or_none(self):
        return self.value


class UserUpdateSession:
    def __init__(self, user: User, current_role: RoleName = RoleName.security_analyst):
        self.user = user
        self.current_role = current_role
        self.user_role = UserRole(user_id=user.id, role_id=uuid4(), tenant_id=str(user.tenant_id))
        self.role_row = Role(id=uuid4(), name=RoleName.approver)
        self.committed = False

    async def get(self, model, user_id):
        if model is User and str(self.user.id) == str(user_id):
            return self.user
        return None

    async def execute(self, statement):
        compiled = str(statement)
        if "SELECT roles.name" in compiled:
            return FakeScalarResult(SimpleNamespace(value=self.current_role.value))
        entity = statement.column_descriptions[0]["entity"]
        if entity is User:
            return FakeScalarResult(None)
        if entity is Role:
            return FakeScalarResult(self.role_row)
        if entity is UserRole:
            return FakeScalarResult(self.user_role)
        raise AssertionError(f"Unexpected statement: {compiled}")

    def add(self, value):
        self.last_added = value

    async def flush(self):
        pass

    async def commit(self):
        self.committed = True


class UserActivationSession(UserUpdateSession):
    def __init__(self, user: User, current_role: RoleName = RoleName.security_analyst):
        super().__init__(user, current_role=current_role)
        self.audit_payloads = []


class FakeAuditWriter:
    def __init__(self, calls: list | None = None):
        self.calls = calls if calls is not None else []

    async def write(self, session, tenant_id, payload):
        self.calls.append((tenant_id, payload))


def test_validate_integration_payload_requires_tool_specific_fields():
    spec = _validate_integration_payload("jira", {"project_key": "SEC"})
    assert spec["category"] == "itsm"

    with pytest.raises(HTTPException) as exc:
        _validate_integration_payload("servicenow", {})

    assert exc.value.status_code == 400
    assert "assignment_group" in exc.value.detail


def test_get_integration_catalog_exposes_itsm_entries():
    payload = asyncio.run(get_integration_catalog())
    tool_types = {item["tool_type"]: item for item in payload["items"]}
    assert tool_types["servicenow"]["category"] == "itsm"
    assert tool_types["jira"]["category"] == "itsm"


def test_update_user_allows_admin_account_edits(monkeypatch):
    user = User(
        id=uuid4(),
        tenant_id=uuid4(),
        email="old@example.com",
        hashed_password="old-hash",
        is_active=True,
    )
    session = UserUpdateSession(user)
    audit_calls = []

    monkeypatch.setattr("app.routes.users.get_password_hash", lambda password: f"hashed:{password}")
    monkeypatch.setattr("app.routes.users.AuditWriter", lambda: FakeAuditWriter(audit_calls))

    response = asyncio.run(
        update_user(
            str(user.id),
            UserUpdateRequest(
                email="new@example.com",
                password="UpdatedPass123",
                role="approver",
                is_active=False,
            ),
            session=session,
            current_user=SimpleNamespace(user_id=str(uuid4()), tenant_id=user.tenant_id),
        )
    )

    assert session.committed is True
    assert user.email == "new@example.com"
    assert user.hashed_password == "hashed:UpdatedPass123"
    assert user.is_active is False
    assert response["role"] == "approver"
    assert audit_calls


def test_deactivate_user_returns_full_user_payload(monkeypatch):
    user = User(
        id=uuid4(),
        tenant_id=uuid4(),
        email="ops@example.com",
        hashed_password="hash",
        is_active=True,
    )
    session = UserActivationSession(user, current_role=RoleName.platform_admin)
    audit_calls = []
    monkeypatch.setattr("app.routes.users.AuditWriter", lambda: FakeAuditWriter(audit_calls))

    response = asyncio.run(
        deactivate_user(
            str(user.id),
            session=session,
            current_user=SimpleNamespace(user_id=str(uuid4()), tenant_id=user.tenant_id),
        )
    )

    assert session.committed is True
    assert user.is_active is False
    assert response["role"] == "platform_admin"
    assert "created_at" in response
    assert response["created_at"] == (user.created_at.isoformat() if user.created_at else None)
    assert audit_calls[-1][1].action == "user_deactivated"


def test_activate_user_returns_full_user_payload(monkeypatch):
    user = User(
        id=uuid4(),
        tenant_id=uuid4(),
        email="ops@example.com",
        hashed_password="hash",
        is_active=False,
    )
    session = UserActivationSession(user, current_role=RoleName.platform_admin)
    audit_calls = []
    monkeypatch.setattr("app.routes.users.AuditWriter", lambda: FakeAuditWriter(audit_calls))

    response = asyncio.run(
        activate_user(
            str(user.id),
            session=session,
            current_user=SimpleNamespace(user_id=str(uuid4()), tenant_id=user.tenant_id),
        )
    )

    assert session.committed is True
    assert user.is_active is True
    assert response["role"] == "platform_admin"
    assert "created_at" in response
    assert response["created_at"] == (user.created_at.isoformat() if user.created_at else None)
    assert audit_calls[-1][1].action == "user_activated"
