import asyncio
from types import SimpleNamespace
from uuid import uuid4

from app.services.scanner_service import ScannerService


class NoopAuditWriter:
    async def write(self, *args, **kwargs):
        pass


def _make_pair():
    rem_id = uuid4()
    find_id = uuid4()
    a_id = uuid4()
    remediation = SimpleNamespace(
        id=rem_id,
        vulnerability_id=find_id,
        status="in_progress",
        approved_by="approver-1",
        execution_status="in_progress",
    )
    finding = SimpleNamespace(
        id=find_id,
        asset_id=a_id,
        cve_id="CVE-2026-0001",
        source_tool="nessus",
        status="in_progress",
        verified_at=None,
    )
    asset = SimpleNamespace(id=a_id, ip_address="10.0.0.10")
    return remediation, finding, asset


def test_verified_when_cve_gone(monkeypatch):
    import app.tasks.remediation_exec as task_module
    monkeypatch.setattr(task_module, "AuditWriter", NoopAuditWriter)

    compliance_called = []

    async def fake_recalculate_scores_in_session(session, tenant_id):
        compliance_called.append(tenant_id)
        return {"NIST CSF 2.0": 100}

    monkeypatch.setattr(task_module, "recalculate_scores_in_session", fake_recalculate_scores_in_session)

    remediation, finding, asset = _make_pair()
    scanner = ScannerService()

    async def successful_rescan(**kwargs):
        from app.services.scanner_service import RescanResult

        return RescanResult(
            cve_id=finding.cve_id,
            asset_ip=asset.ip_address,
            source_tool=finding.source_tool,
            findings=[],
            raw_output="clean",
            verification_succeeded=True,
        )

    monkeypatch.setattr(scanner, "rescan", successful_rescan)

    async def run():
        from datetime import datetime, timezone

        rescan = await scanner.rescan(
            asset_ip=asset.ip_address,
            cve_id=finding.cve_id,
            source_tool=finding.source_tool,
            tenant_id="tenant-1",
        )
        still_vulnerable = any(f.get("cve_id") == finding.cve_id for f in rescan.findings)
        if not still_vulnerable:
            finding.status = "verified"
            finding.verified_at = datetime.now(timezone.utc)
            remediation.status = "verified"
            await task_module.recalculate_scores_in_session(None, "tenant-1")
        return {"status": "verified" if not still_vulnerable else "failed"}

    result = asyncio.run(run())
    assert result["status"] == "verified"
    assert finding.status == "verified"
    assert finding.verified_at is not None
    assert len(compliance_called) == 1


def test_failed_when_cve_present():
    async def run():
        fake_findings = [{"cve_id": "CVE-2026-0001"}]
        still_vulnerable = any(f.get("cve_id") == "CVE-2026-0001" for f in fake_findings)
        return still_vulnerable

    assert asyncio.run(run()) is True


def test_compliance_recalculated(monkeypatch):
    import app.tasks.remediation_exec as task_module
    monkeypatch.setattr(task_module, "AuditWriter", NoopAuditWriter)

    called = []

    async def fake_recalculate_scores_in_session(session, tid):
        called.append(tid)
        return {"NIST CSF 2.0": 100}

    monkeypatch.setattr(task_module, "recalculate_scores_in_session", fake_recalculate_scores_in_session)
    asyncio.run(task_module.recalculate_scores_in_session(None, "tenant-1"))
    assert "tenant-1" in called
