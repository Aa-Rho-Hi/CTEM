import asyncio
from uuid import uuid4, UUID
from datetime import datetime, timezone, timedelta

TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")

async def seed():
    from app.models.base import get_session_factory
    from app.models.entities import Vulnerability, FindingStatus
    async with get_session_factory()() as session:
        v = Vulnerability(
            id=uuid4(), tenant_id=TENANT_ID, asset_id=None, cve_id="CVE-2024-E2E-DIRECT",
            source_tool="nessus", port=443, risk_score=76, cvss_score=8.5,
            epss_score=0.85, false_positive_score=0.1, is_kev=True,
            status=FindingStatus.open, fingerprint_hash=f"e2e-hash-{uuid4().hex[:16]}",
            sla_tier="High", severity="High",
            sla_due_date=datetime.now(timezone.utc) + timedelta(days=7),
        )
        session.add(v)
        await session.commit()
        print(f"E2E_FINDING_ID={v.id}")

asyncio.run(seed())
