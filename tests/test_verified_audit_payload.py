import asyncio
from types import SimpleNamespace
from uuid import uuid4


class RecorderAuditWriter:
    def __init__(self):
        self.payloads = []

    async def write(self, session, tenant_id, payload):
        self.payloads.append(payload)


def test_verified_audit_payload_includes_verified_timestamp(monkeypatch):
    import app.tasks.remediation_exec as task_module
    from app.services.scanner_service import RescanResult

    recorder = RecorderAuditWriter()
    monkeypatch.setattr(task_module, "AuditWriter", lambda: recorder)

    async def fake_recalculate_scores_in_session(session, tenant_id):
      return {"NIST CSF 2.0": 100}

    monkeypatch.setattr(task_module, "recalculate_scores_in_session", fake_recalculate_scores_in_session)

    remediation = SimpleNamespace(
        id=uuid4(),
        vulnerability_id=uuid4(),
        status="in_progress",
        approved_by="approver-1",
        execution_status="in_progress",
    )
    finding = SimpleNamespace(
        id=remediation.vulnerability_id,
        asset_id=uuid4(),
        cve_id="CVE-2026-0001",
        source_tool="nessus",
        status="in_progress",
        verified_at=None,
    )
    asset = SimpleNamespace(id=finding.asset_id, ip_address="10.0.0.10")

    class FakeSession:
        async def get(self, model, key):
            if str(key) == str(remediation.id):
                return remediation
            if str(key) == str(finding.id):
                return finding
            if str(key) == str(asset.id):
                return asset
            return None

        async def commit(self):
            return None

    class FakeScopedSession:
        async def __aenter__(self):
            return FakeSession()

        async def __aexit__(self, exc_type, exc, tb):
            return None

    monkeypatch.setattr(task_module, "get_scoped_session", lambda tenant_id: FakeScopedSession())

    class FakeScannerService:
        async def rescan(self, **kwargs):
            return RescanResult(
                cve_id=finding.cve_id,
                asset_ip=asset.ip_address,
                source_tool=finding.source_tool,
                findings=[],
                raw_output="clean",
                verification_succeeded=True,
            )

    monkeypatch.setattr(task_module, "ScannerService", lambda: FakeScannerService())
    monkeypatch.setattr(task_module, "run_async_task", lambda coro: asyncio.run(coro))

    result = task_module.verify_remediation_task.__wrapped__(str(remediation.id), "tenant-1")

    assert result["status"] == "verified"
    assert recorder.payloads
    assert recorder.payloads[0].details["verified_at"]
    assert recorder.payloads[0].details["scanner_evidence"] == "clean"
    assert recorder.payloads[0].details["approver"] == "approver-1"
