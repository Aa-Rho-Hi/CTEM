"""day3 mobilize remediation fields

Revision ID: 20260403_000003
Revises: 20260402_000002
Create Date: 2026-04-03 02:10:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260403_000003"
down_revision = "20260402_000002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("remediations", sa.Column("fix_type", sa.String(length=32), nullable=False, server_default="manual"))
    op.add_column("remediations", sa.Column("fix_steps", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("remediations", sa.Column("rollback_steps", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("remediations", sa.Column("risk_narrative", sa.Text(), nullable=False, server_default=""))
    op.add_column("remediations", sa.Column("business_impact", sa.Text(), nullable=False, server_default=""))
    op.add_column("remediations", sa.Column("compliance_impact", sa.Text(), nullable=False, server_default=""))
    op.add_column("remediations", sa.Column("estimated_effort_hours", sa.Integer(), nullable=False, server_default="1"))
    op.add_column("remediations", sa.Column("requires_downtime", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("remediations", sa.Column("status", sa.String(length=64), nullable=False, server_default="pending"))
    op.add_column("remediations", sa.Column("approved_by", sa.String(length=255), nullable=True))
    op.add_column("remediations", sa.Column("approved_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("remediations", sa.Column("rejection_reason", sa.Text(), nullable=True))
    op.add_column("remediations", sa.Column("ticket_id", sa.String(length=128), nullable=True))
    op.add_column("remediations", sa.Column("ticket_url", sa.String(length=512), nullable=True))
    op.add_column("blast_radius_snapshots", sa.Column("asset_id", sa.Uuid(), nullable=True))
    op.add_column("blast_radius_snapshots", sa.Column("crown_jewel_count", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("blast_radius_snapshots", sa.Column("affected_zones", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("blast_radius_snapshots", sa.Column("high_blast_radius", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.create_foreign_key("fk_blast_radius_snapshots_asset_id_assets", "blast_radius_snapshots", "assets", ["asset_id"], ["id"])
    op.add_column("dry_run_outputs", sa.Column("fix_type", sa.String(length=32), nullable=False, server_default="manual"))
    op.add_column("dry_run_outputs", sa.Column("estimated_duration_minutes", sa.Integer(), nullable=False, server_default="0"))
    op.add_column("dry_run_outputs", sa.Column("requires_downtime", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("dry_run_outputs", sa.Column("services_affected", sa.JSON(), nullable=False, server_default="[]"))


def downgrade() -> None:
    op.drop_column("dry_run_outputs", "services_affected")
    op.drop_column("dry_run_outputs", "requires_downtime")
    op.drop_column("dry_run_outputs", "estimated_duration_minutes")
    op.drop_column("dry_run_outputs", "fix_type")
    op.drop_constraint("fk_blast_radius_snapshots_asset_id_assets", "blast_radius_snapshots", type_="foreignkey")
    op.drop_column("blast_radius_snapshots", "high_blast_radius")
    op.drop_column("blast_radius_snapshots", "affected_zones")
    op.drop_column("blast_radius_snapshots", "crown_jewel_count")
    op.drop_column("blast_radius_snapshots", "asset_id")
    op.drop_column("remediations", "ticket_url")
    op.drop_column("remediations", "ticket_id")
    op.drop_column("remediations", "rejection_reason")
    op.drop_column("remediations", "approved_at")
    op.drop_column("remediations", "approved_by")
    op.drop_column("remediations", "status")
    op.drop_column("remediations", "requires_downtime")
    op.drop_column("remediations", "estimated_effort_hours")
    op.drop_column("remediations", "compliance_impact")
    op.drop_column("remediations", "business_impact")
    op.drop_column("remediations", "risk_narrative")
    op.drop_column("remediations", "rollback_steps")
    op.drop_column("remediations", "fix_steps")
    op.drop_column("remediations", "fix_type")
