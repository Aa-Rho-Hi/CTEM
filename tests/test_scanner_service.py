import asyncio

from app.services.scanner_service import RescanResult, ScannerService


def test_development_rescan_fails_closed():
    service = ScannerService()
    service.settings.environment = "development"

    result = asyncio.run(
        service.rescan(
            asset_ip="10.0.0.5",
            cve_id="CVE-2026-0001",
            source_tool="nessus",
            tenant_id="tenant-1",
        )
    )

    assert result.verification_succeeded is False
    assert result.findings[0]["cve_id"] == "CVE-2026-0001"
    assert "verification unavailable" in result.raw_output.lower()


def test_supported_rescan_provider_can_confirm_absence():
    service = ScannerService()
    service.settings.environment = "production"

    async def fake_http_rescan(*, endpoint, payload):
        assert endpoint.endswith("/rescan/nessus")
        return RescanResult(
            cve_id=payload["cve_id"],
            asset_ip=payload["asset_ip"],
            source_tool=payload["source_tool"],
            findings=[],
            raw_output="scan complete",
            verification_succeeded=True,
        )

    service._http_rescan = fake_http_rescan
    result = asyncio.run(
        service.rescan(
            asset_ip="10.0.0.5",
            cve_id="CVE-2026-0001",
            source_tool="nessus",
            tenant_id="tenant-1",
        )
    )

    assert result.verification_succeeded is True
    assert result.findings == []


def test_unsupported_rescan_tool_fails_closed():
    service = ScannerService()
    service.settings.environment = "production"

    result = asyncio.run(
        service.rescan(
            asset_ip="10.0.0.5",
            cve_id="CVE-2026-0001",
            source_tool="unknown_scanner",
            tenant_id="tenant-1",
        )
    )

    assert result.verification_succeeded is False
    assert result.findings[0]["reason"] == "unsupported_rescan_tool"
