"""widen cve_id columns to varchar(64)

Revision ID: 20260527_000009
Revises: 20260405_000008
Create Date: 2026-05-27
"""
from alembic import op
import sqlalchemy as sa

revision = "20260527_000009"
down_revision = "20260405_000008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column("vulnerabilities", "cve_id", type_=sa.String(64), existing_nullable=False)
    op.alter_column("nvd_enrichment_cache", "cve_id", type_=sa.String(64), existing_nullable=False)


def downgrade() -> None:
    op.alter_column("nvd_enrichment_cache", "cve_id", type_=sa.String(32), existing_nullable=False)
    op.alter_column("vulnerabilities", "cve_id", type_=sa.String(32), existing_nullable=False)
