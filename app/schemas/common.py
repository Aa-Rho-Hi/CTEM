from datetime import datetime
from typing import Any
from uuid import UUID

from pydantic import BaseModel, ConfigDict


class AtlasBaseModel(BaseModel):
    model_config = ConfigDict(from_attributes=True)


class MessageResponse(AtlasBaseModel):
    message: str


class ErrorResponse(AtlasBaseModel):
    detail: str


class HealthResponse(AtlasBaseModel):
    status: str
    postgres: str
    redis: str
    celery_queue_depth: int


class AuditLogCreate(AtlasBaseModel):
    action: str
    resource_type: str
    resource_id: str
    details: dict[str, Any]
    user_id: str | None = None
