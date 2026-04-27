"""day4 validate and pt safety fields

Revision ID: 20260403_000004
Revises: 20260403_000003
Create Date: 2026-04-03 09:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260403_000004"
down_revision = "20260403_000003"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Vulnerability: auto-validation and verification columns
    op.add_column("vulnerabilities", sa.Column("validation_status", sa.String(32), nullable=True))
    op.add_column("vulnerabilities", sa.Column("validation_signals", sa.JSON(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("validated_at", sa.DateTime(timezone=True), nullable=True))
    op.add_column("vulnerabilities", sa.Column("exploit_db_id", sa.String(128), nullable=True))
    op.add_column("vulnerabilities", sa.Column("matched_campaign_id", sa.Uuid(), nullable=True))
    op.add_column("vulnerabilities", sa.Column("verified_at", sa.DateTime(timezone=True), nullable=True))

    # ROE records: standalone design (referenced by pt_sessions)
    op.alter_column("roe_records", "pt_session_id", nullable=True)
    op.alter_column("roe_records", "cidr", nullable=True)
    op.alter_column("roe_records", "expires_at", nullable=True)
    op.add_column("roe_records", sa.Column("authorized_cidr", sa.String(64), nullable=True))
    op.add_column("roe_records", sa.Column("authorized_techniques", sa.JSON(), nullable=False, server_default="[]"))
    op.add_column("roe_records", sa.Column("authorized_by", sa.String(255), nullable=True))
    op.add_column("roe_records", sa.Column("valid_from", sa.DateTime(timezone=True), nullable=True))
    op.add_column("roe_records", sa.Column("valid_until", sa.DateTime(timezone=True), nullable=True))
    op.add_column("roe_records", sa.Column("scope_notes", sa.Text(), nullable=True))
    op.add_column("roe_records", sa.Column("status", sa.String(32), nullable=False, server_default="active"))

    # PT sessions: roe_id reference, objective, target_assets
    op.alter_column("pt_sessions", "target_ip", nullable=True)
    op.add_column("pt_sessions", sa.Column("roe_id", sa.Uuid(), nullable=True))
    op.add_column("pt_sessions", sa.Column("objective", sa.Text(), nullable=True))
    op.add_column("pt_sessions", sa.Column("target_assets", sa.JSON(), nullable=False, server_default="[]"))
    op.create_foreign_key(
        "fk_pt_sessions_roe_id_roe_records",
        "pt_sessions", "roe_records", ["roe_id"], ["id"]
    )

    # PT evidence: agent tracking columns
    op.add_column("pt_evidence", sa.Column("agent_id", sa.String(255), nullable=True))
    op.add_column("pt_evidence", sa.Column("tool_used", sa.String(128), nullable=True))
    op.add_column("pt_evidence", sa.Column("exploitation_confirmed", sa.Boolean(), nullable=False, server_default=sa.false()))


def downgrade() -> None:
    op.drop_column("pt_evidence", "exploitation_confirmed")
    op.drop_column("pt_evidence", "tool_used")
    op.drop_column("pt_evidence", "agent_id")
    op.drop_constraint("fk_pt_sessions_roe_id_roe_records", "pt_sessions", type_="foreignkey")
    op.drop_column("pt_sessions", "target_assets")
    op.drop_column("pt_sessions", "objective")
    op.drop_column("pt_sessions", "roe_id")
    op.alter_column("pt_sessions", "target_ip", nullable=False)
    op.drop_column("roe_records", "status")
    op.drop_column("roe_records", "scope_notes")
    op.drop_column("roe_records", "valid_until")
    op.drop_column("roe_records", "valid_from")
    op.drop_column("roe_records", "authorized_by")
    op.drop_column("roe_records", "authorized_techniques")
    op.drop_column("roe_records", "authorized_cidr")
    op.drop_column("vulnerabilities", "verified_at")
    op.drop_column("vulnerabilities", "matched_campaign_id")
    op.drop_column("vulnerabilities", "exploit_db_id")
    op.drop_column("vulnerabilities", "validated_at")
    op.drop_column("vulnerabilities", "validation_signals")
    op.drop_column("vulnerabilities", "validation_status")
