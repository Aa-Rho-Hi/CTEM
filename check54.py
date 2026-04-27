import asyncio
from uuid import uuid4, UUID
from datetime import datetime, timezone, timedelta

TENANT_ID = UUID("00000000-0000-0000-0000-000000000001")
AGENT2_ID = UUID("628b63db-0640-40db-9c40-61af0d031c5f")

async def main():
    from app.models.base import get_session_factory
    from app.models.entities import Vulnerability, FindingStatus, AgentDecision
    async with get_session_factory()() as session:
        v = Vulnerability(
            id=uuid4(), tenant_id=TENANT_ID, asset_id=None, cve_id="CVE-2024-3333",
            source_tool="test", port=None, risk_score=68, cvss_score=6.8,
            epss_score=0.6, false_positive_score=0.1, is_kev=False,
            status=FindingStatus.open, fingerprint_hash=f"reject-hash-{uuid4().hex[:16]}",
            sla_tier="High", severity="High",
            sla_due_date=datetime.now(timezone.utc) + timedelta(days=7),
        )
        session.add(v)
        await session.flush()
        
        d = AgentDecision(
            agent_id=AGENT2_ID,
            tenant_id=TENANT_ID,
            goal=f"analyze rejection test finding {v.id}",
            reasoning_chain={"finding_id": str(v.id), "summary": "analyzed for rejection test"},
            decision="execute_plan",
            confidence_score=0.75,
            outcome="plan_formed",
            created_at=datetime.now(timezone.utc),
        )
        session.add(d)
        await session.commit()
        print(f"REJECT_FINDING_ID={v.id}")
        print(f"REJECT_DECISION_ID={d.id}")

asyncio.run(main())
