import hashlib
import time
from datetime import datetime, timezone

import httpx
from fastapi import APIRouter, Depends, HTTPException
from pydantic import BaseModel, Field
from sqlalchemy import select

from app.config import get_settings
from app.core.security import CurrentUser, get_current_user, require_roles
from app.dependencies import get_tenant_session
from app.models.entities import Integration
from app.schemas.common import AuditLogCreate
from app.services.audit_writer import AuditWriter
from app.services.network_validation import normalize_public_http_url, validate_public_http_destination

router = APIRouter(prefix="/integrations", tags=["integrations"])

INTEGRATION_CATALOG = {
    "tanium": {
        "category": "endpoint_remediation",
        "description": "Endpoint patching and remediation execution.",
        "required_config_fields": ["action_group"],
        "optional_config_fields": ["package_name", "environment"],
    },
    "servicenow": {
        "category": "itsm",
        "description": "ITS / ITSM change approvals and ticket workflow.",
        "required_config_fields": ["assignment_group"],
        "optional_config_fields": ["assignee", "table"],
    },
    "jira": {
        "category": "itsm",
        "description": "ITS / engineering workflow tracking.",
        "required_config_fields": ["project_key"],
        "optional_config_fields": ["assignee", "issue_type"],
    },
    "splunk": {
        "category": "telemetry",
        "description": "Search, alerting, and detection telemetry.",
        "required_config_fields": ["hec_index"],
        "optional_config_fields": ["source", "source_type"],
    },
    "neo4j": {
        "category": "graph",
        "description": "Graph-backed attack path and crown jewel context.",
        "required_config_fields": ["database"],
        "optional_config_fields": ["username"],
    },
}


class IntegrationCreateRequest(BaseModel):
    name: str
    tool_type: str
    base_url: str
    api_key: str | None = None
    config_json: dict = Field(default_factory=dict)


class IntegrationUpdateRequest(BaseModel):
    name: str
    base_url: str
    api_key: str | None = None
    config_json: dict = Field(default_factory=dict)


def _validate_integration_payload(tool_type: str, config_json: dict) -> dict:
    normalized_tool = tool_type.strip().lower()
    spec = INTEGRATION_CATALOG.get(normalized_tool)
    if spec is None:
        raise HTTPException(status_code=400, detail=f"Unsupported integration type: {tool_type}")
    missing = [
        field
        for field in spec["required_config_fields"]
        if config_json.get(field) in (None, "", [])
    ]
    if missing:
        raise HTTPException(
            status_code=400,
            detail=f"Missing required config for {normalized_tool}: {', '.join(missing)}",
        )
    return spec


def _serialize_integration(integration: Integration) -> dict:
    config = integration.config_json or {}
    spec = INTEGRATION_CATALOG.get(integration.integration_type, {})
    return {
        "id": str(integration.id),
        "name": integration.name,
        "tool_type": integration.integration_type,
        "category": spec.get("category"),
        "description": spec.get("description"),
        "required_config_fields": spec.get("required_config_fields", []),
        "base_url": config.get("base_url"),
        "is_active": config.get("is_active", True),
        "created_at": integration.created_at.isoformat() if integration.created_at else None,
        "last_tested_at": config.get("last_tested_at"),
        "last_test_status": config.get("last_test_status"),
        "last_test_latency_ms": config.get("last_test_latency_ms"),
        "last_test_error": config.get("last_test_error"),
        "credential_configured": bool(integration.credential_hash),
        "config_json": {
            key: value
            for key, value in config.items()
            if key not in {"last_tested_at", "last_test_status", "last_test_latency_ms", "last_test_error"}
        },
    }


def _merge_config(*, current: dict, base_url: str, extra: dict, is_active: bool) -> dict:
    return current | extra | {"base_url": base_url, "is_active": is_active}


def _record_test_result(integration: Integration, *, status: str, latency_ms: int, error: str | None = None) -> None:
    tested_at = datetime.now(timezone.utc).isoformat()
    integration.config_json = (integration.config_json or {}) | {
        "last_tested_at": tested_at,
        "last_test_status": status,
        "last_test_latency_ms": latency_ms,
        "last_test_error": error,
    }


@router.get("", dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def list_integrations(session=Depends(get_tenant_session)):
    integrations = (await session.execute(select(Integration).order_by(Integration.created_at.desc()))).scalars().all()
    return {"items": [_serialize_integration(item) for item in integrations]}


@router.get("/catalog", dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def get_integration_catalog():
    return {
        "items": [
            {"tool_type": tool_type} | spec
            for tool_type, spec in INTEGRATION_CATALOG.items()
        ]
    }


@router.post("", dependencies=[Depends(require_roles("super_admin", "platform_admin"))], status_code=201)
async def create_integration(
    payload: IntegrationCreateRequest,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    body = payload.model_dump()
    spec = _validate_integration_payload(body["tool_type"], body.get("config_json", {}))
    try:
        base_url = normalize_public_http_url(body["base_url"], field_name="base_url")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    api_key_hash = hashlib.sha256(body["api_key"].encode()).hexdigest() if body.get("api_key") else None
    integration = Integration(
        name=body["name"],
        integration_type=body["tool_type"].strip().lower(),
        credential_hash=api_key_hash,
        config_json=_merge_config(
            current={},
            base_url=base_url,
            extra=body.get("config_json", {}),
            is_active=True,
        ),
    )
    session.add(integration)
    await session.flush()
    await AuditWriter().write(
        session,
        str(current_user.tenant_id),
        AuditLogCreate(
            action="integration_created",
            resource_type="integration",
            resource_id=str(integration.id),
            user_id=current_user.user_id,
            details={"name": integration.name, "tool_type": integration.integration_type, "category": spec["category"]},
        ),
    )
    await session.commit()
    return _serialize_integration(integration)


@router.put("/{integration_id}", dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def update_integration(
    integration_id: str,
    payload: IntegrationUpdateRequest,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    integration = await session.get(Integration, integration_id)
    if integration is None:
        raise HTTPException(status_code=404, detail="Integration not found.")
    body = payload.model_dump()
    spec = _validate_integration_payload(integration.integration_type, body.get("config_json", {}))
    try:
        base_url = normalize_public_http_url(body["base_url"], field_name="base_url")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    integration.name = body["name"]
    integration.config_json = _merge_config(
        current=integration.config_json or {},
        base_url=base_url,
        extra=body.get("config_json", {}),
        is_active=(integration.config_json or {}).get("is_active", True),
    )
    if body.get("api_key"):
        integration.credential_hash = hashlib.sha256(body["api_key"].encode()).hexdigest()
    await AuditWriter().write(
        session,
        str(current_user.tenant_id),
        AuditLogCreate(
            action="integration_updated",
            resource_type="integration",
            resource_id=str(integration.id),
            user_id=current_user.user_id,
            details={"name": integration.name, "tool_type": integration.integration_type, "category": spec["category"]},
        ),
    )
    await session.commit()
    return _serialize_integration(integration)


@router.post("/{integration_id}/test", dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def test_integration(
    integration_id: str,
    session=Depends(get_tenant_session),
):
    integration = await session.get(Integration, integration_id)
    if integration is None:
        raise HTTPException(status_code=404, detail="Integration not found.")
    settings = get_settings()
    configured_base_url = str((integration.config_json or {}).get("base_url", ""))
    if settings.environment == "development":
        try:
            normalize_public_http_url(configured_base_url, field_name="base_url")
        except ValueError as exc:
            raise HTTPException(status_code=400, detail=str(exc)) from exc
        _record_test_result(integration, status="ok", latency_ms=1)
        await session.commit()
        return {"status": "ok", "latency_ms": 1, "mock": True, "message": "Mock health check passed."}

    try:
        base_url = validate_public_http_destination(configured_base_url, field_name="base_url")
    except ValueError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc
    start = time.monotonic()
    try:
        async with httpx.AsyncClient(timeout=5.0, verify=True) as client:
            response = await client.get(f"{base_url}/health")
            response.raise_for_status()
        latency_ms = int((time.monotonic() - start) * 1000)
        _record_test_result(integration, status="ok", latency_ms=latency_ms)
        await session.commit()
        return {"status": "ok", "latency_ms": latency_ms, "message": "Health endpoint reachable."}
    except Exception as exc:
        latency_ms = int((time.monotonic() - start) * 1000)
        _record_test_result(integration, status="error", latency_ms=latency_ms, error=str(exc))
        await session.commit()
        return {"status": "error", "latency_ms": latency_ms, "message": str(exc)}


@router.post("/{integration_id}/deactivate", dependencies=[Depends(require_roles("super_admin", "platform_admin"))])
async def deactivate_integration(
    integration_id: str,
    session=Depends(get_tenant_session),
    current_user: CurrentUser = Depends(get_current_user),
):
    integration = await session.get(Integration, integration_id)
    if integration is None:
        raise HTTPException(status_code=404, detail="Integration not found.")
    integration.config_json = integration.config_json | {"is_active": False}
    await AuditWriter().write(
        session,
        str(current_user.tenant_id),
        AuditLogCreate(
            action="integration_deactivated",
            resource_type="integration",
            resource_id=str(integration.id),
            user_id=current_user.user_id,
            details={"name": integration.name},
        ),
    )
    await session.commit()
    return _serialize_integration(integration)
