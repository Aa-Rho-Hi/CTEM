from uuid import UUID

from pydantic import BaseModel, field_validator


class LoginRequest(BaseModel):
    email: str
    password: str

    @field_validator("email")
    @classmethod
    def _normalise_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v:
            raise ValueError("Invalid email address")
        return v


class RegisterRequest(BaseModel):
    email: str
    password: str
    role: str = "security_analyst"
    tenant_id: UUID

    @field_validator("email")
    @classmethod
    def _normalise_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v:
            raise ValueError("Invalid email address")
        return v


class TenantSignupRequest(BaseModel):
    organization_name: str
    email: str
    password: str
    confirm_password: str

    @field_validator("organization_name")
    @classmethod
    def _normalise_organization_name(cls, v: str) -> str:
        normalized = v.strip()
        if not normalized:
            raise ValueError("Organization name is required")
        return normalized

    @field_validator("email")
    @classmethod
    def _normalise_email(cls, v: str) -> str:
        v = v.strip().lower()
        if "@" not in v:
            raise ValueError("Invalid email address")
        return v


class TokenResponse(BaseModel):
    access_token: str
    token_type: str = "bearer"
    tenant_id: UUID
