"""runtime schema alignment for audit signatures and agent status

Revision ID: 20260405_000008
Revises: 20260405_000007
Create Date: 2026-04-05 21:10:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260405_000008"
down_revision = "20260405_000007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column(
        "audit_log",
        sa.Column("signature", sa.String(length=64), nullable=False, server_default=""),
    )
    op.add_column(
        "agents",
        sa.Column("status", sa.String(length=32), nullable=False, server_default="active"),
    )
    op.alter_column("audit_log", "signature", server_default=None)
    op.alter_column("agents", "status", server_default=None)


def downgrade() -> None:
    op.drop_column("agents", "status")
    op.drop_column("audit_log", "signature")
