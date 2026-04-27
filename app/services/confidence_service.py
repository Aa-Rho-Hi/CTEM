from datetime import datetime, timezone


SOURCE_RELIABILITY = {
    "nmap": 0.7,
    "nessus": 0.9,
    "qualys": 0.9,
    "rapid7": 0.88,
    "snyk": 0.84,
    "checkmarx": 0.82,
    "sonarqube": 0.78,
    "veracode": 0.86,
    "burp": 0.8,
    "burp_suite": 0.8,
    "openvas": 0.75,
    "generic": 0.55,
}


class ConfidenceService:
    def _freshness_score(self, observed_at: str | None) -> float:
        if not observed_at:
            return 0.6
        try:
            parsed = datetime.fromisoformat(observed_at.replace("Z", "+00:00"))
        except ValueError:
            return 0.5
        age_days = max((datetime.now(timezone.utc) - parsed.astimezone(timezone.utc)).total_seconds() / 86400, 0)
        if age_days <= 1:
            return 1.0
        if age_days <= 7:
            return 0.85
        if age_days <= 30:
            return 0.7
        return 0.45

    def _completeness_score(self, finding) -> float:
        present = 0
        total = 5
        present += 1 if getattr(finding, "cve_id", None) not in (None, "", "UNKNOWN") else 0
        present += 1 if getattr(finding, "asset_ip", None) else 0
        present += 1 if getattr(finding, "port", None) is not None else 0
        present += 1 if getattr(finding, "description", "").strip() else 0
        present += 1 if getattr(finding, "severity", "").strip().lower() not in ("", "unknown") else 0
        return present / total

    def _consistency_score(self, corroborating_sources: int) -> float:
        if corroborating_sources >= 3:
            return 1.0
        if corroborating_sources == 2:
            return 0.9
        if corroborating_sources == 1:
            return 0.75
        return 0.55

    def score(self, finding, *, corroborating_sources: int = 0, observed_at: str | None = None) -> int:
        source_tool = str(getattr(finding, "source_tool", "generic") or "generic").lower()
        reliability = SOURCE_RELIABILITY.get(source_tool, 0.6)
        completeness = self._completeness_score(finding)
        freshness = self._freshness_score(observed_at)
        consistency = self._consistency_score(corroborating_sources)
        weighted = (reliability * 0.35) + (completeness * 0.25) + (freshness * 0.2) + (consistency * 0.2)
        return max(1, min(100, round(weighted * 100)))
