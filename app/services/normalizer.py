from typing import Any, Callable

from app.schemas.discover import NormalizedFinding


class NormalizerService:
    @staticmethod
    def _extract_cve(raw: dict[str, Any]) -> str | None:
        for key in ("cve_id", "cve"):
            value = raw.get(key)
            if value:
                return str(value).strip().upper()
        return None

    @staticmethod
    def _normalize_severity(raw: dict[str, Any]) -> str:
        value = str(raw.get("severity", "unknown") or "unknown").strip().lower()
        aliases = {
            "informational": "info",
            "information": "info",
            "critical severity": "critical",
            "moderate": "medium",
        }
        return aliases.get(value, value)

    @staticmethod
    def _extract_asset(raw: dict[str, Any]) -> str | None:
        for key in ("asset_ip", "ip", "host", "asset", "hostname", "device", "name"):
            value = raw.get(key)
            if value:
                return str(value).strip()
        return None

    @staticmethod
    def _extract_description(raw: dict[str, Any]) -> str:
        for key in ("description", "vulnerability", "title", "issue", "name"):
            value = raw.get(key)
            if value:
                return str(value).strip()
        return ""

    def _build_finding(self, raw: dict[str, Any], source_tool: str, tenant_id: str) -> NormalizedFinding:
        return NormalizedFinding(
            cve_id=self._extract_cve(raw),
            asset_ip=self._extract_asset(raw),
            port=raw.get("port"),
            observed_at=(
                raw.get("observed_at")
                or raw.get("first_seen")
                or raw.get("last_seen")
                or raw.get("timestamp")
                or raw.get("detected_at")
                or raw.get("discovered_at")
            ),
            severity=self._normalize_severity(raw),
            description=self._extract_description(raw),
            raw_output=raw,
            source_tool=source_tool,
            tenant_id=tenant_id,
        )

    def parse_nessus(self, raw: dict[str, Any], tenant_id: str) -> NormalizedFinding:
        return self._build_finding(raw, "nessus", tenant_id)

    def parse_qualys(self, raw: dict[str, Any], tenant_id: str) -> NormalizedFinding:
        return self._build_finding(raw, "qualys", tenant_id)

    def parse_nmap(self, raw: dict[str, Any], tenant_id: str) -> NormalizedFinding:
        return self._build_finding(raw, "nmap", tenant_id)

    def parse_checkmarx(self, raw: dict[str, Any], tenant_id: str) -> NormalizedFinding:
        return self._build_finding(raw, "checkmarx", tenant_id)

    def parse_sonarqube(self, raw: dict[str, Any], tenant_id: str) -> NormalizedFinding:
        return self._build_finding(raw, "sonarqube", tenant_id)

    def parse_rapid7(self, raw: dict[str, Any], tenant_id: str) -> NormalizedFinding:
        return self._build_finding(raw, "rapid7", tenant_id)

    def parse_veracode(self, raw: dict[str, Any], tenant_id: str) -> NormalizedFinding:
        return self._build_finding(raw, "veracode", tenant_id)

    def parse_burp(self, raw: dict[str, Any], tenant_id: str) -> NormalizedFinding:
        return self._build_finding(raw, "burp", tenant_id)

    def parse_snyk(self, raw: dict[str, Any], tenant_id: str) -> NormalizedFinding:
        return self._build_finding(raw, "snyk", tenant_id)

    @property
    def supported_formats(self) -> dict[str, Callable[[dict[str, Any], str], NormalizedFinding]]:
        return {
            "nessus": self.parse_nessus,
            "qualys": self.parse_qualys,
            "nmap": self.parse_nmap,
            "checkmarx": self.parse_checkmarx,
            "sonarqube": self.parse_sonarqube,
            "rapid7": self.parse_rapid7,
            "veracode": self.parse_veracode,
            "burp": self.parse_burp,
            "snyk": self.parse_snyk,
        }

    def normalize(self, raw: dict[str, Any], source_tool: str, tenant_id: str) -> NormalizedFinding:
        parser = self.supported_formats.get(source_tool)
        if parser is None:
            # Fall back to generic builder for unknown/upload tools (json, csv, upload, etc.)
            return self._build_finding(raw, source_tool, tenant_id)
        return parser(raw, tenant_id)
