import asyncio
from uuid import uuid4, UUID, uuid4
from datetime import datetime, timezone, timedelta

TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")

async def main():
    from app.models.base import get_session_factory
    from app.models.entities import Vulnerability, FindingStatus, RemediationPlan, AgentDecision
    async with get_session_factory()() as session:
        # Create finding
        v = Vulnerability(
            id=uuid4(), tenant_id=TENANT_ID, asset_id=None, cve_id="CVE-2024-5555",
            source_tool="test", port=None, risk_score=70, cvss_score=7.0,
            epss_score=0.7, false_positive_score=0.1, is_kev=False,
            status=FindingStatus.open, fingerprint_hash=f"conf-hash-{uuid4().hex[:16]}",
            sla_tier="High", severity="High",
            sla_due_date=datetime.now(timezone.utc) + timedelta(days=7),
        )
        session.add(v)
        await session.flush()
        print(f"FINDING_ID={v.id}")

asyncio.run(main())
