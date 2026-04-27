"""scope requirements gaps

Revision ID: 20260405_000006
Revises: 20260403_000005
Create Date: 2026-04-05 12:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260405_000006"
down_revision = "20260403_000005"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("crown_jewel_tiers", sa.Column("revenue_tier", sa.String(length=32), nullable=False, server_default=""))
    op.add_column("crown_jewel_tiers", sa.Column("data_sensitivity", sa.String(length=32), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("crown_jewel_tiers", "data_sensitivity")
    op.drop_column("crown_jewel_tiers", "revenue_tier")
