from app.services.normalizer import NormalizerService


def test_normalizer_supports_nine_scanners():
    service = NormalizerService()
    assert set(service.supported_formats.keys()) == {
        "nessus",
        "qualys",
        "nmap",
        "checkmarx",
        "sonarqube",
        "rapid7",
        "veracode",
        "burp",
        "snyk",
    }


def test_normalizer_returns_shared_schema():
    service = NormalizerService()
    finding = service.normalize(
        {
            "cve_id": "CVE-2026-0001",
            "asset_ip": "10.0.0.10",
            "port": 443,
            "severity": "HIGH",
            "description": "TLS issue",
        },
        "qualys",
        "tenant-123",
    )
    assert finding.cve_id == "CVE-2026-0001"
    assert finding.asset_ip == "10.0.0.10"
    assert finding.port == 443
    assert finding.severity == "high"
    assert finding.source_tool == "qualys"
    assert finding.tenant_id == "tenant-123"


def test_normalizer_preserves_generic_log_fields():
    service = NormalizerService()
    finding = service.normalize(
        {
            "timestamp": "2026-04-07T09:15:00Z",
            "severity": "Low",
            "asset": "web-server-01",
            "vulnerability": "Missing Security Headers",
            "status": "Open",
        },
        "generic",
        "tenant-123",
    )
    assert finding.cve_id is None
    assert finding.asset_ip == "web-server-01"
    assert finding.description == "Missing Security Headers"
    assert finding.severity == "low"
