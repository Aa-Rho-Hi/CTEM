import csv
import io
from dataclasses import asdict, dataclass
from datetime import datetime, timezone

from app.domain.governance.sla import (
    BREACHED,
    BREACH_IN_12_HOURS,
    BREACH_IN_2_DAYS,
    DUE_LATER,
    compute_sla_window,
)


@dataclass(slots=True)
class SlaReportSummary:
    total_tracked: int
    breached: int
    breach_in_12_hours: int
    breach_in_2_days: int
    due_later: int


class GovernanceSlaReportUseCase:
    def __init__(self, repository, *, now_provider=None):
        self.repository = repository
        self.now_provider = now_provider or (lambda: datetime.now(timezone.utc))

    @staticmethod
    def _resolve_status(*, finding, latest_remediation=None) -> str:
        remediation_status = getattr(latest_remediation, "status", None)
        if remediation_status:
            return remediation_status
        return finding.status.value if hasattr(finding.status, "value") else finding.status

    async def execute(self, *, limit: int = 250) -> dict[str, object]:
        now = self.now_provider()
        findings = await self.repository.list_sla_report_findings(limit=limit)
        finding_ids = [finding.id for finding, _ in findings]
        remediations_by_finding = await self.repository.list_remediations_by_finding(finding_ids=finding_ids)

        summary = {
            "total_tracked": 0,
            "breached": 0,
            "breach_in_12_hours": 0,
            "breach_in_2_days": 0,
            "due_later": 0,
        }
        items: list[dict[str, object]] = []

        for finding, asset in findings:
            if finding.sla_due_date is None:
                continue
            latest_remediation = (remediations_by_finding.get(str(finding.id)) or [None])[0]
            window = compute_sla_window(finding.sla_due_date, now=now)
            summary["total_tracked"] += 1
            summary[window["bucket"]] += 1
            items.append(
                {
                    "id": str(finding.id),
                    "cve_id": finding.cve_id,
                    "severity": finding.severity,
                    "risk_score": finding.risk_score,
                    "status": self._resolve_status(finding=finding, latest_remediation=latest_remediation),
                    "sla_tier": finding.sla_tier,
                    "sla_due_date": finding.sla_due_date.isoformat() if finding.sla_due_date else None,
                    "source_tool": finding.source_tool,
                    "window": window["bucket"],
                    "window_label": window["window_label"],
                    "countdown_label": window["countdown_label"],
                    "hours_remaining": window["hours_remaining"],
                    "asset": {
                        "hostname": getattr(asset, "hostname", None),
                        "ip_address": getattr(asset, "ip_address", None),
                    }
                    if asset is not None
                    else None,
                }
            )

        items.sort(key=lambda item: item["hours_remaining"])
        return {
            "generated_at": now.isoformat(),
            "summary": asdict(SlaReportSummary(**summary)),
            "items": items,
        }


class GovernanceSlaExportUseCase:
    def __init__(self, report_use_case: GovernanceSlaReportUseCase):
        self.report_use_case = report_use_case

    async def execute(self, *, limit: int = 1000) -> str:
        report = await self.report_use_case.execute(limit=limit)
        buffer = io.StringIO()
        writer = csv.writer(buffer)
        writer.writerow(
            [
                "finding_id",
                "cve_id",
                "asset_hostname",
                "asset_ip",
                "severity",
                "risk_score",
                "status",
                "sla_tier",
                "sla_due_date",
                "window",
                "countdown",
                "source_tool",
            ]
        )
        for item in report["items"]:
            asset = item.get("asset") or {}
            writer.writerow(
                [
                    item["id"],
                    item["cve_id"],
                    asset.get("hostname"),
                    asset.get("ip_address"),
                    item["severity"],
                    item["risk_score"],
                    item["status"],
                    item["sla_tier"],
                    item["sla_due_date"],
                    item["window_label"],
                    item["countdown_label"],
                    item["source_tool"],
                ]
            )
        return buffer.getvalue()
