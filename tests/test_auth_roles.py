import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.models.entities import User
from app.routes.auth import login
from app.routes.users import _load_role_name
from app.schemas.auth import LoginRequest
from app.services.auth_service import verify_user_credentials


class FakeScalarResult:
    def __init__(self, rows):
        self.rows = rows

    def scalar_one_or_none(self):
        return self.rows[0] if self.rows else None


class LoginSession:
    def __init__(self, user):
        self.user = user
        self.seen_role_query = False

    async def execute(self, statement):
        entity = statement.column_descriptions[0]["entity"]
        if entity is User:
            return FakeScalarResult([self.user])

        compiled = str(statement)
        assert "user_roles.tenant_id" in compiled
        self.seen_role_query = True
        return FakeScalarResult([SimpleNamespace(value="approver")])


class RoleLookupSession:
    async def execute(self, statement):
        compiled = str(statement)
        assert "user_roles.tenant_id" in compiled
        return FakeScalarResult([SimpleNamespace(value="auditor")])


def test_verify_user_credentials_rejects_inactive_users():
    user = User(
        id=uuid4(),
        tenant_id=uuid4(),
        email="inactive@example.com",
        hashed_password="pw",
        is_active=False,
    )
    assert verify_user_credentials(user, "pw") is False


def test_login_scopes_role_lookup_to_user_tenant(monkeypatch):
    tenant_id = uuid4()
    user = User(
        id=uuid4(),
        tenant_id=tenant_id,
        email="person@example.com",
        hashed_password="pw",
        is_active=True,
    )
    session = LoginSession(user)

    monkeypatch.setattr("app.routes.auth.create_access_token", lambda subject, tenant_id, role: f"token:{tenant_id}:{role}")
    monkeypatch.setattr("app.routes.auth.verify_user_credentials", lambda user, password: True)

    response = asyncio.run(login(LoginRequest(email=user.email, password="pw"), session=session))

    assert session.seen_role_query is True
    assert response.tenant_id == tenant_id
    assert response.access_token == f"token:{tenant_id}:approver"


def test_load_role_name_scopes_lookup_to_tenant():
    role = asyncio.run(_load_role_name(RoleLookupSession(), uuid4(), uuid4()))
    assert role == "auditor"
