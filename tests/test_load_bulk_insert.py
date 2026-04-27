import asyncio
import time
from uuid import uuid4

import pytest

from app.models.base import get_session_factory
from app.models.entities import Asset, FindingStatus, Tenant, Vulnerability

TENANT_ID = uuid4()
ASSET_ID = uuid4()


async def _insert_findings(n: int):
    async with get_session_factory()() as session:
        tenant = Tenant(
            id=TENANT_ID,
            name=f"load-test-{TENANT_ID}",
            is_active=True,
        )
        session.add(tenant)
        await session.flush()

        asset = Asset(
            id=ASSET_ID,
            tenant_id=TENANT_ID,
            hostname="load-test-host",
            ip_address="10.0.0.1",
            criticality_score=50,
            business_context={},
        )
        session.add(asset)
        await session.flush()

        findings = [
            Vulnerability(
                id=uuid4(),
                tenant_id=TENANT_ID,
                asset_id=ASSET_ID,
                cve_id=f"CVE-2026-{i:05d}",
                source_tool="nessus",
                risk_score=50,
                cvss_score=5.0,
                epss_score=0.1,
                false_positive_score=0.0,
                is_kev=False,
                status=FindingStatus.open,
                fingerprint_hash=f"hash-{uuid4()}",
                sla_tier="Medium",
                severity="Medium",
                compliance_framework_id=None,
            )
            for i in range(n)
        ]
        for idx in range(0, len(findings), 1000):
            batch = findings[idx : idx + 1000]
            session.add_all(batch)
            await session.flush()
        await session.commit()


@pytest.mark.requires_db
def test_bulk_insert_10k_findings():
    start = time.monotonic()
    asyncio.run(_insert_findings(10_000))
    elapsed = time.monotonic() - start
    assert elapsed < 60, f"Bulk insert took {elapsed:.1f}s - check batch size"
    print(f"10,000 findings inserted in {elapsed:.2f}s")
