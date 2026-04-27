from ipaddress import ip_address, ip_network
from uuid import UUID

from pydantic import BaseModel, field_validator


class ZoneCreate(BaseModel):
    name: str
    cidr: str
    pci: bool = False
    hipaa: bool = False
    tags: dict = {}
    change_windows: dict = {}

    @field_validator("cidr")
    @classmethod
    def validate_cidr(cls, value: str) -> str:
        ip_network(value, strict=False)
        return value


class AssetCreate(BaseModel):
    hostname: str
    ip_address: str
    zone_id: UUID | None = None
    criticality_score: int = 0
    business_context: dict = {}

    @field_validator("ip_address")
    @classmethod
    def validate_ip(cls, value: str) -> str:
        ip_address(value)
        return value


class BusinessContextCreate(BaseModel):
    asset_id: UUID
    business_context: dict


class ChangeWindowCreate(BaseModel):
    zone_id: UUID
    change_windows: dict
