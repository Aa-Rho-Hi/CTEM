from typing import Any, Literal

from pydantic import BaseModel


class ActiveScanRequest(BaseModel):
    source_tool: Literal["nmap", "snyk", "nessus", "qualys", "checkmarx", "sonarqube", "rapid7", "veracode", "burp_suite"]
    targets: list[str]
    options: dict[str, Any] = {}


class NormalizedFinding(BaseModel):
    cve_id: str | None = None
    asset_ip: str | None = None
    port: int | None = None
    observed_at: str | None = None
    severity: str = "unknown"
    description: str = ""
    raw_output: dict[str, Any]
    source_tool: str
    tenant_id: str
