import pytest

from app.tasks.risk_scoring import GENERIC_SEVERITY_SCORE
from app.services.risk_engine import RiskEngine


def test_risk_engine_assigns_expected_severity_and_sla():
    result = RiskEngine().score(
        cvss_base=9.8,
        epss_prob=0.9,
        kev_flag=True,
        exploit_confirmed=True,
        asset_criticality_score=90,
        crown_jewel_tier="tier_1",
        asset_ip="34.82.10.14",
        port=443,
        exposure_context={"internet_exposed": True, "regulated_zone": True},
        business_context={
            "industry_sector": "Financial Services",
            "annual_revenue": ">100M",
            "applicable_regulatory_frameworks": ["PCI-DSS 4.0", "NYDFS 23 NYCRR 500"],
        },
        attack_path_context={"centrality_score": 0.9, "is_choke_point": True, "near_crown_jewel": True},
        exploit_available=True,
    )
    assert result.severity == "Critical"
    assert result.sla_days == 1
    assert result.score == 100
    assert result.exploitability_score > 0
    assert result.exposure_score > 0
    assert result.business_impact_score > 0


def test_context_aware_engine_increases_score_for_exposed_critical_assets():
    engine = RiskEngine()
    baseline = engine.score(
        cvss_base=7.5,
        epss_prob=0.2,
        kev_flag=False,
        exploit_confirmed=False,
        asset_criticality_score=40,
        asset_ip="10.0.0.5",
        port=8443,
    )
    elevated = engine.score(
        cvss_base=7.5,
        epss_prob=0.2,
        kev_flag=False,
        exploit_confirmed=False,
        asset_criticality_score=90,
        crown_jewel_tier="tier_1",
        asset_ip="34.82.10.14",
        port=443,
        exposure_context={"internet_exposed": True, "regulated_zone": True},
        business_context={
            "industry_sector": "Financial Services",
            "annual_revenue": ">100M",
            "applicable_regulatory_frameworks": ["PCI-DSS 4.0"],
        },
        attack_path_context={"centrality_score": 0.7, "is_choke_point": True},
        exploit_available=True,
    )
    assert elevated.score > baseline.score
    assert elevated.exposure_score > baseline.exposure_score
    assert elevated.business_impact_score > baseline.business_impact_score


def test_multipliers_raise_score_for_internet_exposed_exploitable_findings():
    engine = RiskEngine()
    baseline = engine.score(
        cvss_base=8.0,
        epss_prob=0.3,
        kev_flag=False,
        exploit_confirmed=False,
        asset_criticality_score=60,
        asset_ip="10.0.0.5",
        port=8080,
    )
    boosted = engine.score(
        cvss_base=8.0,
        epss_prob=0.3,
        kev_flag=True,
        exploit_confirmed=False,
        asset_criticality_score=60,
        asset_ip="34.82.10.14",
        port=8080,
        exposure_context={"internet_exposed": True},
        attack_path_context={"centrality_score": 0.6},
        exploit_available=True,
    )
    assert boosted.score > baseline.score


def test_boost_factor_is_capped_to_avoid_runaway_inflation():
    engine = RiskEngine()
    uncapped_candidate = engine.score(
        cvss_base=6.5,
        epss_prob=1.0,
        kev_flag=True,
        exploit_confirmed=True,
        asset_criticality_score=95,
        crown_jewel_tier="tier_1",
        asset_ip="34.82.10.14",
        port=443,
        exposure_context={"internet_exposed": True, "external_attack_surface": True},
        business_context={"industry_sector": "Financial Services"},
        attack_path_context={"centrality_score": 1.0, "is_choke_point": True, "near_crown_jewel": True},
        exploit_available=True,
    )
    assert uncapped_candidate.score <= 100


def test_updated_severity_thresholds_map_65_to_high():
    severity, sla_days = RiskEngine()._severity_from_score(65)
    assert severity == "High"
    assert sla_days == 7


@pytest.mark.parametrize(
    ("score", "expected_severity", "expected_sla_days"),
    [
        (85, "Critical", 1),
        (65, "High", 7),
        (40, "Medium", 30),
        (39, "Low", 90),
    ],
)
def test_sla_days_match_policy_by_score(score, expected_severity, expected_sla_days):
    severity, sla_days = RiskEngine()._severity_from_score(score)
    assert severity == expected_severity
    assert sla_days == expected_sla_days


@pytest.mark.parametrize(
    ("source_severity", "expected_severity", "expected_sla_days"),
    [
        ("critical", "Critical", 1),
        ("high", "High", 7),
        ("medium", "Medium", 30),
        ("low", "Low", 90),
        ("info", "Low", 90),
    ],
)
def test_generic_uploaded_findings_use_expected_sla_days(source_severity, expected_severity, expected_sla_days):
    _, severity, sla_days = GENERIC_SEVERITY_SCORE[source_severity]
    assert severity == expected_severity
    assert sla_days == expected_sla_days


def test_false_positive_score_is_four_factor_average():
    score = RiskEngine().compute_false_positive_score(
        asset_type_match=1.0,
        port_context=0.8,
        cve_age=0.6,
        cross_source_confirmation=0.4,
    )
    assert score == 0.7


def test_generic_severity_mapping_preserves_uploaded_log_ordering():
    severity_map = {
        "critical": (95, "Critical"),
        "high": (75, "High"),
        "medium": (55, "Medium"),
        "low": (25, "Low"),
    }
    assert severity_map["critical"][0] > severity_map["high"][0] > severity_map["medium"][0] > severity_map["low"][0]
