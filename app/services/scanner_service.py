from dataclasses import dataclass, field
from typing import Any

import httpx

from app.config import get_settings


@dataclass
class RescanResult:
    cve_id: str
    asset_ip: str
    source_tool: str
    findings: list = field(default_factory=list)
    raw_output: str = ""
    verification_succeeded: bool = False
    verification_error: str | None = None


class ScannerService:
    SUPPORTED_HTTP_TOOLS = {
        "nessus": "nessus",
        "qualys": "qualys",
        "rapid7": "rapid7",
        "snyk": "snyk",
        "checkmarx": "checkmarx",
        "sonarqube": "sonarqube",
        "veracode": "veracode",
        "burp_suite": "burp_suite",
    }

    def __init__(self):
        self.settings = get_settings()

    @staticmethod
    def _normalize_tool(source_tool: str) -> str:
        tool = (source_tool or "").strip().lower().replace(" ", "_")
        aliases = {
            "burp": "burp_suite",
            "burpsuite": "burp_suite",
            "rapid_7": "rapid7",
            "sonarqube_scan": "sonarqube",
        }
        return aliases.get(tool, tool)

    async def _http_rescan(self, *, endpoint: str, payload: dict[str, Any]) -> RescanResult:
        async with httpx.AsyncClient(timeout=20.0, verify=True) as client:
            response = await client.post(endpoint, json=payload)
            response.raise_for_status()
            body = response.json()
        return RescanResult(
            cve_id=payload["cve_id"],
            asset_ip=payload["asset_ip"],
            source_tool=payload["source_tool"],
            findings=body.get("findings", []),
            raw_output=body.get("raw_output", ""),
            verification_succeeded=True,
        )

    async def rescan(
        self,
        *,
        asset_ip: str,
        cve_id: str,
        source_tool: str,
        tenant_id: str,
    ) -> RescanResult:
        normalized_tool = self._normalize_tool(source_tool)
        payload = {
            "asset_ip": asset_ip,
            "cve_id": cve_id,
            "source_tool": normalized_tool,
            "tenant_id": tenant_id,
        }

        if self.settings.environment == "development":
            return RescanResult(
                cve_id=cve_id,
                asset_ip=asset_ip,
                source_tool=normalized_tool,
                findings=[{"cve_id": cve_id, "reason": "verification_unavailable_in_development"}],
                raw_output=f"[DEV MOCK] Verification unavailable for {normalized_tool} rescan of {asset_ip} / {cve_id}",
                verification_succeeded=False,
                verification_error="verification_unavailable_in_development",
            )

        endpoint = None
        if normalized_tool in self.SUPPORTED_HTTP_TOOLS:
            base_url = self.settings.nist_nvd_base_url.rstrip("/")
            endpoint = f"{base_url}/rescan/{normalized_tool}"
        if endpoint is None:
            return RescanResult(
                cve_id=cve_id,
                asset_ip=asset_ip,
                source_tool=normalized_tool,
                findings=[{"cve_id": cve_id, "reason": "unsupported_rescan_tool"}],
                raw_output=f"[UNSUPPORTED] No targeted rescan integration for {normalized_tool}",
                verification_succeeded=False,
                verification_error="unsupported_rescan_tool",
            )

        try:
            return await self._http_rescan(endpoint=endpoint, payload=payload)
        except Exception as exc:
            return RescanResult(
                cve_id=cve_id,
                asset_ip=asset_ip,
                source_tool=normalized_tool,
                findings=[{"cve_id": cve_id, "reason": "rescan_failed"}],
                raw_output=f"[ERROR] Targeted rescan failed: {exc}",
                verification_succeeded=False,
                verification_error=str(exc),
            )
