import asyncio
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from uuid import uuid4

from app.application.governance.use_cases import GovernanceSlaExportUseCase, GovernanceSlaReportUseCase
from app.domain.governance.sla import (
    BREACHED,
    BREACH_IN_12_HOURS,
    BREACH_IN_2_DAYS,
    DUE_LATER,
    compute_sla_window,
)


def test_compute_sla_window_classifies_breached_and_due_soon_buckets():
    now = datetime(2026, 4, 7, 12, 0, tzinfo=timezone.utc)

    assert compute_sla_window(now - timedelta(hours=2), now=now)["bucket"] == BREACHED
    assert compute_sla_window(now + timedelta(hours=6), now=now)["bucket"] == BREACH_IN_12_HOURS
    assert compute_sla_window(now + timedelta(hours=36), now=now)["bucket"] == BREACH_IN_2_DAYS
    assert compute_sla_window(now + timedelta(days=5), now=now)["bucket"] == DUE_LATER


def test_compute_sla_window_uses_one_day_label_within_final_24_hours():
    now = datetime(2026, 4, 7, 12, 0, tzinfo=timezone.utc)

    window = compute_sla_window(now + timedelta(hours=14.4), now=now)

    assert window["bucket"] == BREACH_IN_2_DAYS
    assert window["window_label"] == "Breach In 1 Day"
    assert window["countdown_label"] == "Breaches in 14.4h"


class FakeGovernanceRepository:
    def __init__(self, rows, remediations_by_finding=None):
        self.rows = rows
        self.remediations_by_finding = remediations_by_finding or {}

    async def list_sla_report_findings(self, *, limit: int = 250):
        return self.rows[:limit]

    async def list_sla_tracked_findings(self, *, limit: int = 250):
        return self.rows[:limit]

    async def list_remediations_by_finding(self, *, finding_ids):
        return self.remediations_by_finding


def test_governance_sla_report_summarizes_counts_and_sorts_earliest_breach_first():
    now = datetime(2026, 4, 7, 12, 0, tzinfo=timezone.utc)
    rows = [
        (
            SimpleNamespace(
                id=uuid4(),
                cve_id="CVE-2026-0003",
                severity="Medium",
                risk_score=61,
                status="open",
                sla_tier="Medium",
                sla_due_date=now + timedelta(days=3),
                source_tool="nessus",
            ),
            SimpleNamespace(hostname="app-03", ip_address="10.0.0.30"),
        ),
        (
            SimpleNamespace(
                id=uuid4(),
                cve_id="CVE-2026-0001",
                severity="Critical",
                risk_score=99,
                status="open",
                sla_tier="Critical",
                sla_due_date=now - timedelta(hours=4),
                source_tool="qualys",
            ),
            SimpleNamespace(hostname="db-01", ip_address="10.0.0.10"),
        ),
        (
            SimpleNamespace(
                id=uuid4(),
                cve_id="CVE-2026-0002",
                severity="High",
                risk_score=82,
                status="in_progress",
                sla_tier="High",
                sla_due_date=now + timedelta(hours=8),
                source_tool="rapid7",
            ),
            SimpleNamespace(hostname="web-01", ip_address="10.0.0.20"),
        ),
    ]

    report = asyncio.run(
        GovernanceSlaReportUseCase(
            FakeGovernanceRepository(rows),
            now_provider=lambda: now,
        ).execute()
    )

    assert report["summary"]["total_tracked"] == 3
    assert report["summary"]["breached"] == 1
    assert report["summary"]["breach_in_12_hours"] == 1
    assert report["summary"]["breach_in_2_days"] == 0
    assert report["summary"]["due_later"] == 1
    assert report["items"][0]["cve_id"] == "CVE-2026-0001"
    assert report["items"][1]["cve_id"] == "CVE-2026-0002"


def test_governance_sla_export_outputs_csv_rows():
    now = datetime(2026, 4, 7, 12, 0, tzinfo=timezone.utc)
    rows = [
        (
            SimpleNamespace(
                id=uuid4(),
                cve_id="CVE-2026-0009",
                severity="High",
                risk_score=77,
                status="open",
                sla_tier="High",
                sla_due_date=now + timedelta(hours=10),
                source_tool="nessus",
            ),
            SimpleNamespace(hostname="gateway-01", ip_address="10.0.0.99"),
        )
    ]

    csv_text = asyncio.run(
        GovernanceSlaExportUseCase(
            GovernanceSlaReportUseCase(FakeGovernanceRepository(rows), now_provider=lambda: now)
        ).execute()
    )

    assert "finding_id,cve_id,asset_hostname,asset_ip" in csv_text
    assert "CVE-2026-0009" in csv_text
    assert "gateway-01" in csv_text


def test_governance_sla_report_includes_rejected_and_verified_rows():
    now = datetime(2026, 4, 7, 12, 0, tzinfo=timezone.utc)
    rows = [
        (
            SimpleNamespace(
                id=uuid4(),
                cve_id="CVE-2026-0010",
                severity="High",
                risk_score=71,
                status="rejected",
                sla_tier="High",
                sla_due_date=now + timedelta(hours=10),
                source_tool="nessus",
            ),
            SimpleNamespace(hostname="app-10", ip_address="10.0.1.10"),
        ),
        (
            SimpleNamespace(
                id=uuid4(),
                cve_id="CVE-2026-0011",
                severity="Medium",
                risk_score=48,
                status="verified",
                sla_tier="Medium",
                sla_due_date=now + timedelta(days=2),
                source_tool="qualys",
            ),
            SimpleNamespace(hostname="app-11", ip_address="10.0.1.11"),
        ),
    ]

    report = asyncio.run(
        GovernanceSlaReportUseCase(
            FakeGovernanceRepository(rows),
            now_provider=lambda: now,
        ).execute()
    )

    assert {item["status"] for item in report["items"]} == {"rejected", "verified"}


def test_governance_sla_report_prefers_latest_remediation_status():
    now = datetime(2026, 4, 7, 12, 0, tzinfo=timezone.utc)
    finding_id = uuid4()
    rows = [
        (
            SimpleNamespace(
                id=finding_id,
                cve_id="CVE-2026-0012",
                severity="High",
                risk_score=72,
                status="open",
                sla_tier="High",
                sla_due_date=now + timedelta(hours=6),
                source_tool="nessus",
            ),
            SimpleNamespace(hostname="app-12", ip_address="10.0.1.12"),
        ),
    ]
    remediations_by_finding = {
        str(finding_id): [SimpleNamespace(status="rejected")],
    }

    report = asyncio.run(
        GovernanceSlaReportUseCase(
            FakeGovernanceRepository(rows, remediations_by_finding=remediations_by_finding),
            now_provider=lambda: now,
        ).execute()
    )

    assert report["items"][0]["status"] == "rejected"
