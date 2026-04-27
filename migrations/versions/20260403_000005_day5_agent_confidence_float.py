"""day5 agent decision confidence float

Revision ID: 20260403_000005
Revises: 20260403_000004
Create Date: 2026-04-03 12:00:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260403_000005"
down_revision = "20260403_000004"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.alter_column(
        "agent_decisions",
        "confidence_score",
        existing_type=sa.Integer(),
        type_=sa.Float(),
        existing_nullable=False,
        postgresql_using="confidence_score::double precision",
    )


def downgrade() -> None:
    op.alter_column(
        "agent_decisions",
        "confidence_score",
        existing_type=sa.Float(),
        type_=sa.Integer(),
        existing_nullable=False,
        postgresql_using="ROUND(confidence_score)::integer",
    )
