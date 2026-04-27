from dataclasses import dataclass
from datetime import datetime, timedelta, timezone
from math import prod

from app.models.entities import FindingStatus


@dataclass
class RiskScoreResult:
    score: int
    severity: str
    sla_days: int
    false_positive_score: float
    exploitability_score: int = 0
    exposure_score: int = 0
    business_impact_score: int = 0


class RiskEngine:
    MULTIPLIERS = {"tier_1": 1.5, "tier_2": 1.3, "tier_3": 1.1}
    CROWN_JEWEL_IMPACT = {"tier_1": 95, "tier_2": 85, "tier_3": 75}
    REVENUE_IMPACT = {
        ">100m": 20,
        "100m+": 20,
        "50m-100m": 15,
        "10m-50m": 10,
        "1m-10m": 5,
    }

    @staticmethod
    def _clamp(value: float, minimum: float = 0.0, maximum: float = 100.0) -> int:
        return int(round(min(max(value, minimum), maximum)))

    def _normalize_cvss(self, cvss_base: float) -> int:
        return self._clamp(max(cvss_base, 0.0) * 10.0)

    def _severity_from_score(self, score: int) -> tuple[str, int]:
        if score >= 85:
            return "Critical", 1
        if score >= 65:
            return "High", 7
        if score >= 40:
            return "Medium", 30
        return "Low", 90

    def _score_exploitability(
        self,
        *,
        cvss_base: float,
        epss_prob: float,
        kev_flag: bool,
        exploit_confirmed: bool,
    ) -> int:
        value = (
            (cvss_base * 6.0)
            + (epss_prob * 30.0)
            + (15.0 if kev_flag else 0.0)
            + (20.0 if exploit_confirmed else 0.0)
        )
        return self._clamp(value)

    def _score_exposure(
        self,
        *,
        asset_ip: str | None = None,
        port: int | None = None,
        exposure_context: dict[str, object] | None = None,
    ) -> int:
        context = exposure_context or {}
        internet_facing = bool(
            context.get("internet_exposed")
            or context.get("external_attack_surface")
            or context.get("public_ip")
        )
        privileged_access = port in {22, 3389, 5900}
        common_app_port = port in {80, 443, 8080, 8443}
        regulated_zone = bool(context.get("regulated_zone"))
        high_lateral_movement = bool(context.get("high_lateral_movement"))

        value = 10.0
        if internet_facing:
            value += 40.0
        if common_app_port:
            value += 18.0
        if privileged_access:
            value += 22.0
        if regulated_zone:
            value += 10.0
        if high_lateral_movement:
            value += 10.0
        if asset_ip and not internet_facing and asset_ip.startswith(("10.", "192.168.", "172.")):
            value += 5.0
        return self._clamp(value)

    def _score_business_impact(
        self,
        *,
        asset_criticality_score: float,
        crown_jewel_tier: str | None = None,
        business_context: dict[str, object] | None = None,
    ) -> int:
        context = business_context or {}
        value = float(asset_criticality_score)

        if crown_jewel_tier in self.CROWN_JEWEL_IMPACT:
            value = max(value, float(self.CROWN_JEWEL_IMPACT[crown_jewel_tier]))

        frameworks = context.get("applicable_regulatory_frameworks") or []
        if isinstance(frameworks, list):
            value += min(len(frameworks) * 4.0, 16.0)

        annual_revenue = str(context.get("annual_revenue", "")).strip().lower()
        if annual_revenue in self.REVENUE_IMPACT:
            value += self.REVENUE_IMPACT[annual_revenue]

        sector = str(context.get("industry_sector", "")).strip().lower()
        if sector in {"financial services", "finance", "healthcare", "government", "energy"}:
            value += 10.0

        if bool(context.get("customer_data")) or bool(context.get("regulated_data")):
            value += 8.0

        return self._clamp(value)

    def _score_attack_path(
        self,
        *,
        attack_path_context: dict[str, object] | None = None,
    ) -> int:
        context = attack_path_context or {}
        centrality_score = float(context.get("centrality_score") or 0.0)
        is_choke_point = bool(context.get("is_choke_point"))
        path_count = int(context.get("attack_path_count") or 0)
        near_crown_jewel = bool(context.get("near_crown_jewel"))

        value = centrality_score * 100.0
        if is_choke_point:
            value += 20.0
        if near_crown_jewel:
            value += 15.0
        value += min(path_count * 5.0, 20.0)
        return self._clamp(value)

    def _exploit_availability_multiplier(
        self,
        *,
        kev_flag: bool,
        exploit_confirmed: bool,
        exploit_available: bool,
    ) -> float:
        multiplier = 1.0
        if kev_flag:
            multiplier *= 1.08
        if exploit_available:
            multiplier *= 1.12
        if exploit_confirmed:
            multiplier *= 1.18
        return multiplier

    def _internet_exposure_multiplier(
        self,
        *,
        exposure_context: dict[str, object] | None = None,
    ) -> float:
        context = exposure_context or {}
        internet_facing = bool(
            context.get("internet_exposed")
            or context.get("external_attack_surface")
            or context.get("public_ip")
        )
        return 1.18 if internet_facing else 1.0

    def _epss_multiplier(self, *, epss_prob: float) -> float:
        bounded = min(max(epss_prob, 0.0), 1.0)
        return 1.0 + (bounded * 0.20)

    def _crown_jewel_multiplier(
        self,
        *,
        asset_criticality_score: float,
    ) -> float:
        return 1.15 if asset_criticality_score >= 90 else 1.0

    def score(
        self,
        *,
        cvss_base: float,
        epss_prob: float,
        kev_flag: bool,
        exploit_confirmed: bool,
        asset_criticality_score: float,
        crown_jewel_tier: str | None = None,
        false_positive_score: float = 0.0,
        asset_ip: str | None = None,
        port: int | None = None,
        exposure_context: dict[str, object] | None = None,
        business_context: dict[str, object] | None = None,
        attack_path_context: dict[str, object] | None = None,
        exploit_available: bool = False,
    ) -> RiskScoreResult:
        cvss_score = self._normalize_cvss(cvss_base)
        normalized_asset_criticality = self._clamp(asset_criticality_score)
        exploitability_score = self._score_exploitability(
            cvss_base=cvss_base,
            epss_prob=epss_prob,
            kev_flag=kev_flag,
            exploit_confirmed=exploit_confirmed,
        )
        exposure_score = self._score_exposure(
            asset_ip=asset_ip,
            port=port,
            exposure_context=exposure_context,
        )
        business_impact_score = self._score_business_impact(
            asset_criticality_score=asset_criticality_score,
            crown_jewel_tier=crown_jewel_tier,
            business_context=business_context,
        )
        attack_path_score = self._score_attack_path(
            attack_path_context=attack_path_context,
        )

        value = (
            (cvss_score * 0.15)
            + (exploitability_score * 0.25)
            + (exposure_score * 0.15)
            + (business_impact_score * 0.20)
            + (attack_path_score * 0.10)
            + (normalized_asset_criticality * 0.15)
        )
        boost_factor = prod(
            [
                self._exploit_availability_multiplier(
                    kev_flag=kev_flag,
                    exploit_confirmed=exploit_confirmed,
                    exploit_available=exploit_available,
                ),
                self._internet_exposure_multiplier(
                    exposure_context=exposure_context,
                ),
                self._epss_multiplier(epss_prob=epss_prob),
                self._crown_jewel_multiplier(
                    asset_criticality_score=asset_criticality_score,
                ),
            ]
        )
        if crown_jewel_tier in self.MULTIPLIERS:
            boost_factor *= 1 + ((self.MULTIPLIERS[crown_jewel_tier] - 1) * 0.35)
        boost_factor = min(boost_factor, 1.5)
        value *= boost_factor
        value *= max(0.5, 1.0 - (false_positive_score * 0.25))
        score = self._clamp(value)
        severity, sla_days = self._severity_from_score(score)
        return RiskScoreResult(
            score=score,
            severity=severity,
            sla_days=sla_days,
            false_positive_score=false_positive_score,
            exploitability_score=exploitability_score,
            exposure_score=exposure_score,
            business_impact_score=business_impact_score,
        )

    def compute_false_positive_score(
        self,
        *,
        asset_type_match: float,
        port_context: float,
        cve_age: float,
        cross_source_confirmation: float,
    ) -> float:
        score = (asset_type_match + port_context + cve_age + cross_source_confirmation) / 4
        return round(min(max(score, 0.0), 1.0), 4)

    async def apply_to_vulnerability(
        self,
        vulnerability,
        *,
        cvss_base: float,
        epss_prob: float,
        kev_flag: bool,
        exploit_confirmed: bool,
        asset_criticality: float,
        crown_jewel_tier: str | None,
        false_positive_inputs: dict[str, float],
        exposure_context: dict[str, object] | None = None,
        business_context: dict[str, object] | None = None,
        attack_path_context: dict[str, object] | None = None,
        exploit_available: bool = False,
        audit_writer=None,
        session=None,
        tenant_id=None,
    ) -> RiskScoreResult:
        false_positive_score = self.compute_false_positive_score(**false_positive_inputs)
        result = self.score(
            cvss_base=cvss_base,
            epss_prob=epss_prob,
            kev_flag=kev_flag,
            exploit_confirmed=exploit_confirmed,
            asset_criticality_score=asset_criticality,
            crown_jewel_tier=crown_jewel_tier,
            false_positive_score=false_positive_score,
            asset_ip=getattr(vulnerability, "asset_ip", None),
            port=getattr(vulnerability, "port", None),
            exposure_context=exposure_context,
            business_context=business_context,
            attack_path_context=attack_path_context,
            exploit_available=exploit_available,
        )
        vulnerability.risk_score = result.score
        vulnerability.severity = result.severity
        vulnerability.sla_tier = result.severity
        vulnerability.sla_due_date = datetime.now(timezone.utc) + timedelta(days=result.sla_days)
        vulnerability.false_positive_score = false_positive_score
        if false_positive_score > 0.85:
            vulnerability.status = FindingStatus.closed
            if audit_writer is not None and session is not None and tenant_id is not None:
                from app.schemas.common import AuditLogCreate

                await audit_writer.write(
                    session,
                    tenant_id,
                    AuditLogCreate(
                        action="finding_auto_closed_false_positive",
                        resource_type="vulnerability",
                        resource_id=str(vulnerability.id),
                        details={"false_positive_score": false_positive_score},
                    ),
                )
        return result
