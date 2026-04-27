import asyncio
from uuid import uuid4, UUID
from datetime import datetime, timezone, timedelta

TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")

async def seed():
    from app.models.base import get_session_factory
    from app.models.entities import Vulnerability, FindingStatus
    async with get_session_factory()() as session:
        v = Vulnerability(
            id=uuid4(), tenant_id=TENANT_ID, asset_id=None, cve_id="CVE-2024-LOW",
            source_tool="nessus", port=None, risk_score=8, cvss_score=3.0,
            epss_score=0.05, false_positive_score=0.05, is_kev=False,
            status=FindingStatus.open, fingerprint_hash=f"low-find-{uuid4().hex[:16]}",
            sla_tier="Low", severity="Low",
            sla_due_date=datetime.now(timezone.utc) + timedelta(days=90),
        )
        session.add(v)
        await session.commit()
        print(f"LOW_ID={v.id}")

asyncio.run(seed())
