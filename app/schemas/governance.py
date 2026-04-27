from app.schemas.common import AtlasBaseModel


class SlaAssetSummary(AtlasBaseModel):
    hostname: str | None = None
    ip_address: str | None = None


class SlaReportSummary(AtlasBaseModel):
    total_tracked: int
    breached: int
    breach_in_12_hours: int
    breach_in_2_days: int
    due_later: int


class SlaReportItem(AtlasBaseModel):
    id: str
    cve_id: str
    severity: str
    risk_score: int
    status: str
    sla_tier: str
    sla_due_date: str | None = None
    source_tool: str
    window: str
    window_label: str
    countdown_label: str
    hours_remaining: float
    asset: SlaAssetSummary | None = None


class SlaReportResponse(AtlasBaseModel):
    generated_at: str
    summary: SlaReportSummary
    items: list[SlaReportItem]

