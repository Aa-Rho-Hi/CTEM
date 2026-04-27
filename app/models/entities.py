from datetime import datetime, timezone
from enum import Enum
from uuid import uuid4

from sqlalchemy import JSON, Boolean, DateTime, Enum as SqlEnum, Float, ForeignKey, Index, Integer, LargeBinary, String, Text, Uuid
from sqlalchemy.orm import Mapped, mapped_column, relationship

from app.models.base import Base, TenantMixin, TimestampMixin


class RoleName(str, Enum):
    super_admin = "super_admin"
    platform_admin = "platform_admin"
    security_analyst = "security_analyst"
    approver = "approver"
    auditor = "auditor"
    client_viewer = "client_viewer"


class FindingStatus(str, Enum):
    open = "open"
    approved = "approved"
    in_progress = "in_progress"
    fixed = "fixed"
    verified = "verified"
    rejected = "rejected"
    closed = "closed"


class Tenant(Base, TimestampMixin):
    __tablename__ = "tenants"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class User(Base, TenantMixin, TimestampMixin):
    __tablename__ = "users"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    email: Mapped[str] = mapped_column(String(255), nullable=False, unique=True)
    hashed_password: Mapped[str] = mapped_column(String(255), nullable=False)
    api_key_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)


class Role(Base, TimestampMixin):
    __tablename__ = "roles"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[RoleName] = mapped_column(SqlEnum(RoleName), nullable=False, unique=True)


class UserRole(Base, TenantMixin, TimestampMixin):
    __tablename__ = "user_roles"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[Uuid] = mapped_column(ForeignKey("users.id"), nullable=False)
    role_id: Mapped[Uuid] = mapped_column(ForeignKey("roles.id"), nullable=False)


class NetworkZone(Base, TenantMixin, TimestampMixin):
    __tablename__ = "network_zones"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    cidr: Mapped[str] = mapped_column(String(64), nullable=False)
    pci: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    hipaa: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    change_windows: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    tags: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class CrownJewelTier(Base, TenantMixin, TimestampMixin):
    __tablename__ = "crown_jewel_tiers"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(50), nullable=False, unique=True)
    multiplier: Mapped[int] = mapped_column(Integer, nullable=False)
    revenue_tier: Mapped[str] = mapped_column(String(32), nullable=False, default="")
    data_sensitivity: Mapped[str] = mapped_column(String(32), nullable=False, default="")


class Asset(Base, TenantMixin, TimestampMixin):
    __tablename__ = "assets"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    hostname: Mapped[str] = mapped_column(String(255), nullable=False)
    ip_address: Mapped[str] = mapped_column(String(64), nullable=False)
    zone_id: Mapped[Uuid | None] = mapped_column(ForeignKey("network_zones.id"), nullable=True)
    crown_jewel_tier_id: Mapped[Uuid | None] = mapped_column(ForeignKey("crown_jewel_tiers.id"), nullable=True)
    criticality_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    business_context: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    zone = relationship("NetworkZone", foreign_keys=[zone_id], lazy="selectin")


class Scan(Base, TenantMixin, TimestampMixin):
    __tablename__ = "scans"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    source_tool: Mapped[str] = mapped_column(String(64), nullable=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class ScanFinding(Base, TenantMixin, TimestampMixin):
    __tablename__ = "scan_findings"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    scan_id: Mapped[Uuid] = mapped_column(ForeignKey("scans.id"), nullable=False)
    asset_id: Mapped[Uuid | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    raw_payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    normalized_payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class Vulnerability(Base, TenantMixin, TimestampMixin):
    __tablename__ = "vulnerabilities"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    asset_id: Mapped[Uuid | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    scan_finding_id: Mapped[Uuid | None] = mapped_column(ForeignKey("scan_findings.id"), nullable=True)
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False)
    source_tool: Mapped[str] = mapped_column(String(64), nullable=False)
    port: Mapped[int | None] = mapped_column(Integer, nullable=True)
    status: Mapped[FindingStatus] = mapped_column(SqlEnum(FindingStatus), nullable=False, default=FindingStatus.open)
    fingerprint_hash: Mapped[str] = mapped_column(String(64), nullable=False, unique=True)
    risk_score: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    severity: Mapped[str] = mapped_column(String(32), default="Low", nullable=False)
    sla_tier: Mapped[str] = mapped_column(String(32), default="Low", nullable=False)
    sla_due_date: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    epss_score: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    cvss_score: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    cvss_vector: Mapped[str | None] = mapped_column(String(255), nullable=True)
    cwe_id: Mapped[str | None] = mapped_column(String(32), nullable=True)
    mitre_attack_ttp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    is_kev: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    false_positive_score: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    compliance_framework_id: Mapped[Uuid | None] = mapped_column(ForeignKey("compliance_frameworks.id"), nullable=True)
    confidence_score: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    first_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    last_seen: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    # Day 4 validation/verification columns
    validation_status: Mapped[str | None] = mapped_column(String(32), nullable=True)
    validation_signals: Mapped[list | None] = mapped_column(JSON, nullable=True)
    validated_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    exploit_db_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    matched_campaign_id: Mapped[Uuid | None] = mapped_column(Uuid, nullable=True)
    verified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    asset = relationship("Asset", foreign_keys=[asset_id], lazy="selectin")
    remediations = relationship(
        "Remediation",
        foreign_keys="Remediation.vulnerability_id",
        lazy="selectin",
        order_by="Remediation.created_at",
    )

    __table_args__ = (
        Index("ix_vulnerabilities_tenant_status", "tenant_id", "status"),
        Index("ix_vulnerabilities_tenant_risk_score_desc", "tenant_id", "risk_score"),
        Index("ix_vulnerabilities_tenant_sla_due_date", "tenant_id", "sla_due_date"),
        Index("ix_vulnerabilities_tenant_asset_id", "tenant_id", "asset_id"),
        Index("ix_vulnerabilities_tenant_cve_id", "tenant_id", "cve_id"),
        Index("ix_vulnerabilities_tenant_source_tool", "tenant_id", "source_tool"),
        Index("ix_vulnerabilities_tenant_created_at_desc", "tenant_id", "created_at"),
        Index("ix_vulnerabilities_fingerprint_hash", "fingerprint_hash"),
        Index("ix_vulnerabilities_epss_score_desc", "epss_score"),
        Index("ix_vulnerabilities_cvss_score_desc", "cvss_score"),
        Index("ix_vulnerabilities_is_kev", "is_kev"),
        Index("ix_vulnerabilities_false_positive_score", "false_positive_score"),
        Index("ix_vulnerabilities_compliance_framework_id", "compliance_framework_id"),
    )


class NvdEnrichmentCache(Base, TimestampMixin):
    __tablename__ = "nvd_enrichment_cache"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    cve_id: Mapped[str] = mapped_column(String(32), nullable=False, unique=True)
    payload: Mapped[bytes] = mapped_column(LargeBinary, nullable=False)
    expires_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), nullable=False)


class AttackGraphNode(Base, TenantMixin, TimestampMixin):
    __tablename__ = "attack_graph_nodes"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    node_type: Mapped[str] = mapped_column(String(64), nullable=False)
    reference_id: Mapped[str] = mapped_column(String(255), nullable=False)
    is_choke_point: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    centrality_score: Mapped[float] = mapped_column(Float, default=0, nullable=False)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class AttackGraphEdge(Base, TenantMixin, TimestampMixin):
    __tablename__ = "attack_graph_edges"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    from_node_id: Mapped[Uuid] = mapped_column(ForeignKey("attack_graph_nodes.id"), nullable=False)
    to_node_id: Mapped[Uuid] = mapped_column(ForeignKey("attack_graph_nodes.id"), nullable=False)
    edge_type: Mapped[str] = mapped_column(String(64), nullable=False)
    attributes: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class ThreatActorCampaign(Base, TenantMixin, TimestampMixin):
    __tablename__ = "threat_actor_campaigns"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    industry_sector: Mapped[str | None] = mapped_column(String(128), nullable=True)
    mitre_attack_ttp: Mapped[str | None] = mapped_column(String(64), nullable=True)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class VulnerabilityCampaignMapping(Base, TenantMixin, TimestampMixin):
    __tablename__ = "vulnerability_campaign_mappings"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    vulnerability_id: Mapped[Uuid] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=False)
    campaign_id: Mapped[Uuid] = mapped_column(ForeignKey("threat_actor_campaigns.id"), nullable=False)


class Remediation(Base, TenantMixin, TimestampMixin):
    __tablename__ = "remediations"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    vulnerability_id: Mapped[Uuid] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=False)
    fix_type: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    fix_steps: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    rollback_steps: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    risk_narrative: Mapped[str] = mapped_column(Text, nullable=False, default="")
    business_impact: Mapped[str] = mapped_column(Text, nullable=False, default="")
    compliance_impact: Mapped[str] = mapped_column(Text, nullable=False, default="")
    estimated_effort_hours: Mapped[int] = mapped_column(Integer, nullable=False, default=1)
    requires_downtime: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    status: Mapped[str] = mapped_column(String(64), nullable=False, default="pending")
    execution_status: Mapped[str] = mapped_column(String(64), nullable=False, default="pending")
    approved_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    approved_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    rejection_reason: Mapped[str | None] = mapped_column(Text, nullable=True)
    ticket_id: Mapped[str | None] = mapped_column(String(128), nullable=True)
    ticket_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    plan: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)

    __table_args__ = (
        Index("ix_remediations_vulnerability_id", "vulnerability_id"),
    )


class RemediationApproval(Base, TenantMixin, TimestampMixin):
    __tablename__ = "remediation_approvals"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    remediation_id: Mapped[Uuid] = mapped_column(ForeignKey("remediations.id"), nullable=False)
    approver_user_id: Mapped[Uuid | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False)
    rationale: Mapped[str | None] = mapped_column(Text, nullable=True)


class BlastRadiusSnapshot(Base, TenantMixin, TimestampMixin):
    __tablename__ = "blast_radius_snapshots"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    remediation_id: Mapped[Uuid] = mapped_column(ForeignKey("remediations.id"), nullable=False)
    asset_id: Mapped[Uuid | None] = mapped_column(ForeignKey("assets.id"), nullable=True)
    downstream_dependency_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    crown_jewel_count: Mapped[int] = mapped_column(Integer, default=0, nullable=False)
    affected_zones: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    high_blast_radius: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    snapshot_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class DryRunOutput(Base, TenantMixin, TimestampMixin):
    __tablename__ = "dry_run_outputs"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    remediation_id: Mapped[Uuid] = mapped_column(ForeignKey("remediations.id"), nullable=False)
    fix_type: Mapped[str] = mapped_column(String(32), nullable=False, default="manual")
    estimated_duration_minutes: Mapped[int] = mapped_column(Integer, nullable=False, default=0)
    requires_downtime: Mapped[bool] = mapped_column(Boolean, nullable=False, default=False)
    services_affected: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    output_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class RoeRecord(Base, TenantMixin, TimestampMixin):
    __tablename__ = "roe_records"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    # Legacy columns (Day 1) — kept for migration continuity
    pt_session_id: Mapped[Uuid | None] = mapped_column(ForeignKey("pt_sessions.id"), nullable=True)
    cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    expires_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    # Day 4 columns — standalone ROE referenced by pt_sessions
    authorized_cidr: Mapped[str | None] = mapped_column(String(64), nullable=True)
    authorized_techniques: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    authorized_by: Mapped[str | None] = mapped_column(String(255), nullable=True)
    valid_from: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    valid_until: Mapped[datetime | None] = mapped_column(DateTime(timezone=True), nullable=True)
    scope_notes: Mapped[str | None] = mapped_column(Text, nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")


class PtSession(Base, TenantMixin, TimestampMixin):
    __tablename__ = "pt_sessions"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    target_ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="pending")
    # Day 4 columns
    roe_id: Mapped[Uuid | None] = mapped_column(ForeignKey("roe_records.id"), nullable=True)
    objective: Mapped[str | None] = mapped_column(Text, nullable=True)
    target_assets: Mapped[list] = mapped_column(JSON, default=list, nullable=False)


class PtEvidence(Base, TenantMixin, TimestampMixin):
    __tablename__ = "pt_evidence"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    pt_session_id: Mapped[Uuid] = mapped_column(ForeignKey("pt_sessions.id"), nullable=False)
    exploit_type: Mapped[str] = mapped_column(String(128), nullable=False)
    payload: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    response: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)
    # Day 4 columns
    agent_id: Mapped[str | None] = mapped_column(String(255), nullable=True)
    tool_used: Mapped[str | None] = mapped_column(String(128), nullable=True)
    exploitation_confirmed: Mapped[bool] = mapped_column(Boolean, default=False, nullable=False)


class Agent(Base, TenantMixin, TimestampMixin):
    __tablename__ = "agents"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), nullable=False)
    tool_whitelist: Mapped[list] = mapped_column(JSON, default=list, nullable=False)
    safety_ceiling: Mapped[int] = mapped_column(Integer, nullable=False, default=70)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True, nullable=False)
    status: Mapped[str] = mapped_column(String(32), nullable=False, default="active")
    config_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class AgentDecision(Base, TenantMixin):
    __tablename__ = "agent_decisions"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    agent_id: Mapped[Uuid] = mapped_column(ForeignKey("agents.id"), nullable=False)
    goal: Mapped[str] = mapped_column(Text, nullable=False)
    reasoning_chain: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    decision: Mapped[str] = mapped_column(Text, nullable=False)
    confidence_score: Mapped[float] = mapped_column(Float, nullable=False)
    outcome: Mapped[str] = mapped_column(Text, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))


class ComplianceFramework(Base, TimestampMixin):
    __tablename__ = "compliance_frameworks"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(255), unique=True, nullable=False)
    version: Mapped[str] = mapped_column(String(64), nullable=False)


class ComplianceControl(Base, TimestampMixin):
    __tablename__ = "compliance_controls"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    framework_id: Mapped[Uuid] = mapped_column(ForeignKey("compliance_frameworks.id"), nullable=False)
    control_id: Mapped[str] = mapped_column(String(128), nullable=False)
    title: Mapped[str] = mapped_column(String(255), nullable=False)
    cwe_tags: Mapped[list] = mapped_column(JSON, default=list, nullable=False)


class VulnerabilityControl(Base, TenantMixin, TimestampMixin):
    __tablename__ = "vulnerability_controls"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    vulnerability_id: Mapped[Uuid] = mapped_column(ForeignKey("vulnerabilities.id"), nullable=False)
    control_id: Mapped[Uuid] = mapped_column(ForeignKey("compliance_controls.id"), nullable=False)


class ComplianceScore(Base, TenantMixin, TimestampMixin):
    __tablename__ = "compliance_scores"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    framework_id: Mapped[Uuid] = mapped_column(ForeignKey("compliance_frameworks.id"), nullable=False)
    score: Mapped[int] = mapped_column(Integer, default=100, nullable=False)
    metadata_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)


class AuditLog(Base, TenantMixin):
    __tablename__ = "audit_log"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    user_id: Mapped[Uuid | None] = mapped_column(ForeignKey("users.id"), nullable=True)
    action: Mapped[str] = mapped_column(String(255), nullable=False)
    resource_type: Mapped[str] = mapped_column(String(64), nullable=False)
    resource_id: Mapped[str] = mapped_column(String(255), nullable=False)
    details: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    created_at: Mapped[datetime] = mapped_column(DateTime(timezone=True), default=lambda: datetime.now(timezone.utc))
    signature: Mapped[str] = mapped_column(String(64), nullable=False, default="")


class Integration(Base, TenantMixin, TimestampMixin):
    __tablename__ = "integrations"
    id: Mapped[Uuid] = mapped_column(Uuid, primary_key=True, default=uuid4)
    name: Mapped[str] = mapped_column(String(128), nullable=False)
    integration_type: Mapped[str] = mapped_column(String(64), nullable=False)
    config_json: Mapped[dict] = mapped_column(JSON, default=dict, nullable=False)
    credential_hash: Mapped[str | None] = mapped_column(String(64), nullable=True)
