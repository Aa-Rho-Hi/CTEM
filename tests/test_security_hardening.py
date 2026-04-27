import asyncio
import hashlib
from pathlib import Path
from types import SimpleNamespace
from uuid import uuid4

import pytest
from fastapi import HTTPException

from app.config import Settings
from app.models.base import _enforce_tenant_id
from app.models.entities import AuditLog, Integration, User
from app.routes.auth import register
from app.routes.integrations import IntegrationCreateRequest, create_integration, test_integration as run_integration_test
from app.routes.users import list_users
from app.routes.validate import PTProbeRequest, run_probe
from app.schemas.auth import RegisterRequest
from app.services.auth_service import build_user


class FakeScalarResult:
    def __init__(self, rows):
        self.rows = rows

    def scalars(self):
        return self

    def all(self):
        return list(self.rows)

    def scalar_one_or_none(self):
        return self.rows[0] if self.rows else None


class FakeSession:
    def __init__(self, users=None):
        self.users = list(users or [])
        self.added = []

    async def execute(self, statement):
        entity = statement.column_descriptions[0]["entity"]
        if entity is User:
            return FakeScalarResult(self.users)
        if entity.__name__ == "Role":
            return FakeScalarResult([SimpleNamespace(value="security_analyst")])
        raise AssertionError(f"Unexpected entity: {entity}")

    def add(self, obj):
        self.added.append(obj)

    async def flush(self):
        return None

    async def commit(self):
        return None


def test_no_plaintext_api_key_in_response():
    session = FakeSession()
    current_user = SimpleNamespace(user_id=str(uuid4()), tenant_id=uuid4())
    payload = IntegrationCreateRequest(
        name="splunk",
        tool_type="splunk",
        base_url="http://mock",
        api_key="super-secret-key",
        config_json={"hec_index": "main"},
    )
    response = asyncio.run(create_integration(payload, session=session, current_user=current_user))
    assert "api_key" not in response
    assert "super-secret-key" not in str(response)


def test_hashed_key_is_sha256():
    session = FakeSession()
    current_user = SimpleNamespace(user_id=str(uuid4()), tenant_id=uuid4())
    payload = IntegrationCreateRequest(
        name="splunk",
        tool_type="splunk",
        base_url="http://mock",
        api_key="super-secret-key",
        config_json={"hec_index": "main"},
    )
    asyncio.run(create_integration(payload, session=session, current_user=current_user))
    integration = next(item for item in session.added if isinstance(item, Integration))
    assert integration.credential_hash == hashlib.sha256(b"super-secret-key").hexdigest()
    assert len(integration.credential_hash) == 64


def test_no_hashed_password_in_user_response():
    user = User(
        id=uuid4(),
        tenant_id=uuid4(),
        email="a@example.com",
        hashed_password="secret-hash",
        api_key_hash="x" * 64,
        is_active=True,
    )
    session = FakeSession(users=[user])
    response = asyncio.run(list_users(session=session))
    assert "hashed_password" not in str(response)


def test_invalid_ip_rejected_at_route():
    payload = PTProbeRequest(
        session_id=str(uuid4()),
        target_ip="not_an_ip",
        target_asset_id=str(uuid4()),
        technique="T1059",
        tool="nmap",
        payload="",
    )
    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            run_probe(
                payload,
                session=FakeSession(),
                redis=object(),
                current_user=SimpleNamespace(user_id=str(uuid4()), tenant_id=uuid4()),
            )
        )
    assert exc.value.status_code == 422


def test_audit_log_no_delete():
    root = Path(__file__).resolve().parents[1] / "app"
    offenders = []
    for path in root.rglob("*.py"):
        for line in path.read_text().splitlines():
            lowered = line.lower()
            if "auditlog" in lowered and ("delete" in lowered or ".update" in lowered):
                offenders.append(path)
                break
    assert offenders == []


def test_jwt_secret_no_default():
    assert Settings.model_fields["jwt_secret_key"].is_required()


def test_build_user_rejects_short_password():
    with pytest.raises(ValueError, match="at least 8 characters"):
        build_user("admin@example.com", "short", uuid4())


def test_register_rejects_short_password():
    session = FakeSession()

    with pytest.raises(HTTPException) as exc:
        asyncio.run(
            register(
                RegisterRequest(
                    email="admin@example.com",
                    password="short",
                    role="security_analyst",
                    tenant_id=uuid4(),
                ),
                session=session,
            )
        )

    assert exc.value.status_code == 400
    assert "at least 8 characters" in exc.value.detail


class IntegrationLookupSession:
    def __init__(self, integration: Integration):
        self.integration = integration

    async def get(self, model, integration_id):
        if model is Integration and str(self.integration.id) == str(integration_id):
            return self.integration
        return None

    async def commit(self):
        return None


def test_integration_health_check_blocks_private_ip_targets(monkeypatch):
    integration = Integration(
        id=uuid4(),
        tenant_id=uuid4(),
        name="splunk",
        integration_type="splunk",
        config_json={"base_url": "http://10.0.0.5", "hec_index": "main"},
        credential_hash=None,
    )
    monkeypatch.setattr("app.routes.integrations.get_settings", lambda: SimpleNamespace(environment="production"))

    with pytest.raises(HTTPException) as exc:
        asyncio.run(run_integration_test(str(integration.id), session=IntegrationLookupSession(integration)))

    assert exc.value.status_code == 400
    assert "publicly routable addresses" in exc.value.detail or "private" in exc.value.detail


def test_audit_log_updates_blocked_before_flush():
    class FakeSessionState:
        def __init__(self, dirty=None, deleted=None, new=None):
            self.info = {}
            self.dirty = dirty or []
            self.deleted = deleted or []
            self.new = new or []

    audit_entry = AuditLog(
        id=uuid4(),
        tenant_id=uuid4(),
        user_id=None,
        action="x",
        resource_type="y",
        resource_id="z",
        details={},
        signature="sig",
    )
    with pytest.raises(ValueError, match="immutable"):
        _enforce_tenant_id(FakeSessionState(dirty=[audit_entry]), None, None)
