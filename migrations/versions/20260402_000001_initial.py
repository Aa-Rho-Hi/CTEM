"""initial schema

Revision ID: 20260402_000001
Revises:
Create Date: 2026-04-02 18:40:00.000000
"""

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql


revision = "20260402_000001"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "tenants",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    for table_name in [
        "roles",
        "compliance_frameworks",
        "compliance_controls",
        "nvd_enrichment_cache",
    ]:
        pass

    op.create_table(
        "roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.Enum("super_admin", "security_analyst", "approver", "auditor", "client_viewer", name="rolename"), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )

    tenant_columns = [
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
    ]

    op.create_table(
        "users",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("email", sa.String(length=255), nullable=False),
        sa.Column("hashed_password", sa.String(length=255), nullable=False),
        sa.Column("api_key_hash", sa.String(length=64), nullable=True),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("email"),
    )
    op.create_index("ix_users_tenant_id", "users", ["tenant_id"])

    op.create_table(
        "user_roles",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=False),
        sa.Column("role_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["role_id"], ["roles.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_user_roles_tenant_id", "user_roles", ["tenant_id"])

    op.create_table(
        "network_zones",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("cidr", sa.String(length=64), nullable=False),
        sa.Column("pci", sa.Boolean(), nullable=False),
        sa.Column("hipaa", sa.Boolean(), nullable=False),
        sa.Column("change_windows", sa.JSON(), nullable=False),
        sa.Column("tags", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_network_zones_tenant_id", "network_zones", ["tenant_id"])

    op.create_table(
        "crown_jewel_tiers",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=50), nullable=False),
        sa.Column("multiplier", sa.Integer(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_index("ix_crown_jewel_tiers_tenant_id", "crown_jewel_tiers", ["tenant_id"])

    op.create_table(
        "assets",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("hostname", sa.String(length=255), nullable=False),
        sa.Column("ip_address", sa.String(length=64), nullable=False),
        sa.Column("zone_id", sa.Uuid(), nullable=True),
        sa.Column("crown_jewel_tier_id", sa.Uuid(), nullable=True),
        sa.Column("criticality_score", sa.Integer(), nullable=False),
        sa.Column("business_context", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["crown_jewel_tier_id"], ["crown_jewel_tiers.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["zone_id"], ["network_zones.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_assets_tenant_id", "assets", ["tenant_id"])

    op.create_table(
        "scans",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("source_tool", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=64), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scans_tenant_id", "scans", ["tenant_id"])

    op.create_table(
        "scan_findings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("scan_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("raw_payload", sa.JSON(), nullable=False),
        sa.Column("normalized_payload", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.ForeignKeyConstraint(["scan_id"], ["scans.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_scan_findings_tenant_id", "scan_findings", ["tenant_id"])

    op.create_table(
        "compliance_frameworks",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("version", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("name"),
    )
    op.create_table(
        "vulnerabilities",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("asset_id", sa.Uuid(), nullable=True),
        sa.Column("scan_finding_id", sa.Uuid(), nullable=True),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("source_tool", sa.String(length=64), nullable=False),
        sa.Column("port", sa.Integer(), nullable=True),
        sa.Column("status", sa.Enum("open", "approved", "in_progress", "fixed", "verified", "rejected", "closed", name="findingstatus"), nullable=False),
        sa.Column("fingerprint_hash", sa.String(length=64), nullable=False),
        sa.Column("risk_score", sa.Integer(), nullable=False),
        sa.Column("sla_due_date", sa.DateTime(timezone=True), nullable=True),
        sa.Column("epss_score", sa.Integer(), nullable=False),
        sa.Column("cvss_score", sa.Integer(), nullable=False),
        sa.Column("is_kev", sa.Boolean(), nullable=False),
        sa.Column("false_positive_score", sa.Integer(), nullable=False),
        sa.Column("compliance_framework_id", sa.Uuid(), nullable=True),
        sa.Column("confidence_score", sa.Integer(), nullable=False),
        sa.Column("first_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("last_seen", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["asset_id"], ["assets.id"]),
        sa.ForeignKeyConstraint(["compliance_framework_id"], ["compliance_frameworks.id"]),
        sa.ForeignKeyConstraint(["scan_finding_id"], ["scan_findings.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("fingerprint_hash"),
    )
    op.create_index("ix_vulnerabilities_tenant_status", "vulnerabilities", ["tenant_id", "status"])
    op.create_index("ix_vulnerabilities_tenant_risk_score_desc", "vulnerabilities", ["tenant_id", sa.text("risk_score DESC")])
    op.create_index("ix_vulnerabilities_tenant_sla_due_date", "vulnerabilities", ["tenant_id", "sla_due_date"])
    op.create_index("ix_vulnerabilities_tenant_asset_id", "vulnerabilities", ["tenant_id", "asset_id"])
    op.create_index("ix_vulnerabilities_tenant_cve_id", "vulnerabilities", ["tenant_id", "cve_id"])
    op.create_index("ix_vulnerabilities_tenant_source_tool", "vulnerabilities", ["tenant_id", "source_tool"])
    op.create_index("ix_vulnerabilities_tenant_created_at_desc", "vulnerabilities", ["tenant_id", sa.text("created_at DESC")])
    op.create_index("ix_vulnerabilities_fingerprint_hash", "vulnerabilities", ["fingerprint_hash"])
    op.create_index("ix_vulnerabilities_epss_score_desc", "vulnerabilities", [sa.text("epss_score DESC")])
    op.create_index("ix_vulnerabilities_cvss_score_desc", "vulnerabilities", [sa.text("cvss_score DESC")])
    op.create_index("ix_vulnerabilities_is_kev", "vulnerabilities", ["is_kev"])
    op.create_index("ix_vulnerabilities_false_positive_score", "vulnerabilities", ["false_positive_score"])
    op.create_index("ix_vulnerabilities_compliance_framework_id", "vulnerabilities", ["compliance_framework_id"])

    op.create_table(
        "nvd_enrichment_cache",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("cve_id", sa.String(length=32), nullable=False),
        sa.Column("payload", sa.LargeBinary(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("cve_id"),
    )

    op.create_table(
        "attack_graph_nodes",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("node_type", sa.String(length=64), nullable=False),
        sa.Column("reference_id", sa.String(length=255), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_attack_graph_nodes_tenant_id", "attack_graph_nodes", ["tenant_id"])

    op.create_table(
        "attack_graph_edges",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("from_node_id", sa.Uuid(), nullable=False),
        sa.Column("to_node_id", sa.Uuid(), nullable=False),
        sa.Column("edge_type", sa.String(length=64), nullable=False),
        sa.Column("attributes", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["from_node_id"], ["attack_graph_nodes.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["to_node_id"], ["attack_graph_nodes.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_attack_graph_edges_tenant_id", "attack_graph_edges", ["tenant_id"])

    op.create_table(
        "threat_actor_campaigns",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_threat_actor_campaigns_tenant_id", "threat_actor_campaigns", ["tenant_id"])

    op.create_table(
        "vulnerability_campaign_mappings",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=False),
        sa.Column("campaign_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["campaign_id"], ["threat_actor_campaigns.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["vulnerability_id"], ["vulnerabilities.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vulnerability_campaign_mappings_tenant_id", "vulnerability_campaign_mappings", ["tenant_id"])

    op.create_table(
        "remediations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=False),
        sa.Column("plan", sa.JSON(), nullable=False),
        sa.Column("execution_status", sa.String(length=64), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["vulnerability_id"], ["vulnerabilities.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_remediations_tenant_id", "remediations", ["tenant_id"])

    op.create_table(
        "remediation_approvals",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("remediation_id", sa.Uuid(), nullable=False),
        sa.Column("approver_user_id", sa.Uuid(), nullable=True),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("rationale", sa.Text(), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["approver_user_id"], ["users.id"]),
        sa.ForeignKeyConstraint(["remediation_id"], ["remediations.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_remediation_approvals_tenant_id", "remediation_approvals", ["tenant_id"])

    op.create_table(
        "blast_radius_snapshots",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("remediation_id", sa.Uuid(), nullable=False),
        sa.Column("downstream_dependency_count", sa.Integer(), nullable=False),
        sa.Column("snapshot_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["remediation_id"], ["remediations.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_blast_radius_snapshots_tenant_id", "blast_radius_snapshots", ["tenant_id"])

    op.create_table(
        "dry_run_outputs",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("remediation_id", sa.Uuid(), nullable=False),
        sa.Column("output_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["remediation_id"], ["remediations.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_dry_run_outputs_tenant_id", "dry_run_outputs", ["tenant_id"])

    op.create_table(
        "pt_sessions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("target_ip", sa.String(length=64), nullable=False),
        sa.Column("status", sa.String(length=32), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_pt_sessions_tenant_id", "pt_sessions", ["tenant_id"])

    op.create_table(
        "roe_records",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("pt_session_id", sa.Uuid(), nullable=False),
        sa.Column("cidr", sa.String(length=64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["pt_session_id"], ["pt_sessions.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_roe_records_tenant_id", "roe_records", ["tenant_id"])

    op.create_table(
        "pt_evidence",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("pt_session_id", sa.Uuid(), nullable=False),
        sa.Column("exploit_type", sa.String(length=128), nullable=False),
        sa.Column("payload", sa.JSON(), nullable=False),
        sa.Column("response", sa.JSON(), nullable=False),
        sa.Column("confirmed", sa.Boolean(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["pt_session_id"], ["pt_sessions.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_pt_evidence_tenant_id", "pt_evidence", ["tenant_id"])

    op.create_table(
        "agents",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=255), nullable=False),
        sa.Column("tool_whitelist", sa.JSON(), nullable=False),
        sa.Column("safety_ceiling", sa.Integer(), nullable=False),
        sa.Column("is_active", sa.Boolean(), nullable=False),
        sa.Column("config_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agents_tenant_id", "agents", ["tenant_id"])

    op.create_table(
        "agent_decisions",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("agent_id", sa.Uuid(), nullable=False),
        sa.Column("goal", sa.Text(), nullable=False),
        sa.Column("reasoning_chain", sa.JSON(), nullable=False),
        sa.Column("decision", sa.Text(), nullable=False),
        sa.Column("confidence_score", sa.Integer(), nullable=False),
        sa.Column("outcome", sa.Text(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["agent_id"], ["agents.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_agent_decisions_tenant_id", "agent_decisions", ["tenant_id"])

    op.create_table(
        "compliance_controls",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("framework_id", sa.Uuid(), nullable=False),
        sa.Column("control_id", sa.String(length=128), nullable=False),
        sa.Column("title", sa.String(length=255), nullable=False),
        sa.Column("cwe_tags", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["framework_id"], ["compliance_frameworks.id"]),
        sa.PrimaryKeyConstraint("id"),
    )

    op.create_table(
        "vulnerability_controls",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("vulnerability_id", sa.Uuid(), nullable=False),
        sa.Column("control_id", sa.Uuid(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["control_id"], ["compliance_controls.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["vulnerability_id"], ["vulnerabilities.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_vulnerability_controls_tenant_id", "vulnerability_controls", ["tenant_id"])

    op.create_table(
        "compliance_scores",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("framework_id", sa.Uuid(), nullable=False),
        sa.Column("score", sa.Integer(), nullable=False),
        sa.Column("metadata_json", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["framework_id"], ["compliance_frameworks.id"]),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_compliance_scores_tenant_id", "compliance_scores", ["tenant_id"])

    op.create_table(
        "audit_log",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("user_id", sa.Uuid(), nullable=True),
        sa.Column("action", sa.String(length=255), nullable=False),
        sa.Column("resource_type", sa.String(length=64), nullable=False),
        sa.Column("resource_id", sa.String(length=255), nullable=False),
        sa.Column("details", sa.JSON(), nullable=False),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.ForeignKeyConstraint(["user_id"], ["users.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_audit_log_tenant_id", "audit_log", ["tenant_id"])
    op.execute("REVOKE UPDATE, DELETE ON TABLE audit_log FROM PUBLIC")

    op.create_table(
        "integrations",
        sa.Column("id", sa.Uuid(), nullable=False),
        sa.Column("tenant_id", sa.Uuid(), nullable=False),
        sa.Column("name", sa.String(length=128), nullable=False),
        sa.Column("integration_type", sa.String(length=64), nullable=False),
        sa.Column("config_json", sa.JSON(), nullable=False),
        sa.Column("credential_hash", sa.String(length=64), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False),
        sa.ForeignKeyConstraint(["tenant_id"], ["tenants.id"]),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("ix_integrations_tenant_id", "integrations", ["tenant_id"])


def downgrade() -> None:
    for table_name in [
        "integrations",
        "audit_log",
        "compliance_scores",
        "vulnerability_controls",
        "compliance_controls",
        "agent_decisions",
        "agents",
        "pt_evidence",
        "roe_records",
        "pt_sessions",
        "dry_run_outputs",
        "blast_radius_snapshots",
        "remediation_approvals",
        "remediations",
        "vulnerability_campaign_mappings",
        "threat_actor_campaigns",
        "attack_graph_edges",
        "attack_graph_nodes",
        "nvd_enrichment_cache",
        "vulnerabilities",
        "compliance_frameworks",
        "scan_findings",
        "scans",
        "assets",
        "crown_jewel_tiers",
        "network_zones",
        "user_roles",
        "users",
        "roles",
        "tenants",
    ]:
        op.drop_table(table_name)
    op.execute("DROP TYPE IF EXISTS rolename")
    op.execute("DROP TYPE IF EXISTS findingstatus")

