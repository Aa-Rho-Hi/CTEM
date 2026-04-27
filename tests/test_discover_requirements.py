from types import SimpleNamespace

from app.services.confidence_service import ConfidenceService
from app.services.discover_service import (
    ACTIVE_SCAN_TOOLS,
    canonical_tool_name,
    detect_shadow_assets,
    infer_source_tool,
)


def test_active_scan_supports_all_nine_tools():
    assert ACTIVE_SCAN_TOOLS == [
        "nmap",
        "snyk",
        "nessus",
        "qualys",
        "checkmarx",
        "sonarqube",
        "rapid7",
        "veracode",
        "burp_suite",
    ]


def test_upload_tool_inference_recognizes_json_tool_exports():
    assert infer_source_tool("checkmarx-report.json", "{}") == "checkmarx"
    assert infer_source_tool("scan.csv", "Burp issue export") == "burp_suite"
    assert infer_source_tool("results.nessus", "") == "nessus"


def test_canonical_tool_name_normalizes_burp_aliases():
    assert canonical_tool_name("burp") == "burp_suite"
    assert canonical_tool_name("burpsuite") == "burp_suite"


def test_confidence_score_uses_multiple_factors():
    service = ConfidenceService()
    high = service.score(
        SimpleNamespace(
            cve_id="CVE-2026-0001",
            asset_ip="10.0.0.5",
            port=443,
            description="Critical remotely exploitable issue",
            severity="critical",
            source_tool="nessus",
        ),
        corroborating_sources=2,
        observed_at="2026-04-05T00:00:00+00:00",
    )
    low = service.score(
        SimpleNamespace(
            cve_id=None,
            asset_ip=None,
            port=None,
            description="",
            severity="unknown",
            source_tool="generic",
        ),
        corroborating_sources=0,
        observed_at="2025-01-01T00:00:00+00:00",
    )

    assert high > low
    assert high >= 80
    assert low < 60


def test_shadow_assets_detect_unknown_cloud_resources():
    known_assets = [
        SimpleNamespace(hostname="known.example.com", ip_address="1.2.3.4"),
    ]
    cloud_resources = [
        {"hostname": "known.example.com", "public_ip": "1.2.3.4", "provider": "aws"},
        {"hostname": "shadow.example.com", "public_ip": "5.6.7.8", "provider": "aws", "account": "prod"},
    ]

    shadow = detect_shadow_assets(cloud_resources, known_assets)

    assert len(shadow) == 1
    assert shadow[0]["hostname"] == "shadow.example.com"
    assert shadow[0]["public_ip"] == "5.6.7.8"
