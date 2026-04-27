"""day2 risk and compliance fields

Revision ID: 20260402_000002
Revises: 20260402_000001
Create Date: 2026-04-02 21:20:00.000000
"""

from alembic import op
import sqlalchemy as sa


revision = "20260402_000002"
down_revision = "20260402_000001"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("vulnerabilities", sa.Column("severity", sa.String(length=32), nullable=False, server_default="Low"))
    op.add_column("vulnerabilities", sa.Column("sla_tier", sa.String(length=32), nullable=False, server_default="Low"))
    op.add_column("vulnerabilities", sa.Column("cvss_vector", sa.String(length=255), nullable=True))
    op.add_column("vulnerabilities", sa.Column("cwe_id", sa.String(length=32), nullable=True))
    op.add_column("vulnerabilities", sa.Column("mitre_attack_ttp", sa.String(length=64), nullable=True))
    op.alter_column("vulnerabilities", "epss_score", existing_type=sa.Integer(), type_=sa.Float(), existing_nullable=False)
    op.alter_column("vulnerabilities", "cvss_score", existing_type=sa.Integer(), type_=sa.Float(), existing_nullable=False)
    op.alter_column("vulnerabilities", "false_positive_score", existing_type=sa.Integer(), type_=sa.Float(), existing_nullable=False)

    op.add_column("attack_graph_nodes", sa.Column("is_choke_point", sa.Boolean(), nullable=False, server_default=sa.false()))
    op.add_column("attack_graph_nodes", sa.Column("centrality_score", sa.Float(), nullable=False, server_default="0"))

    op.add_column("threat_actor_campaigns", sa.Column("industry_sector", sa.String(length=128), nullable=True))
    op.add_column("threat_actor_campaigns", sa.Column("mitre_attack_ttp", sa.String(length=64), nullable=True))


def downgrade() -> None:
    op.drop_column("threat_actor_campaigns", "mitre_attack_ttp")
    op.drop_column("threat_actor_campaigns", "industry_sector")

    op.drop_column("attack_graph_nodes", "centrality_score")
    op.drop_column("attack_graph_nodes", "is_choke_point")

    op.alter_column("vulnerabilities", "false_positive_score", existing_type=sa.Float(), type_=sa.Integer(), existing_nullable=False)
    op.alter_column("vulnerabilities", "cvss_score", existing_type=sa.Float(), type_=sa.Integer(), existing_nullable=False)
    op.alter_column("vulnerabilities", "epss_score", existing_type=sa.Float(), type_=sa.Integer(), existing_nullable=False)
    op.drop_column("vulnerabilities", "mitre_attack_ttp")
    op.drop_column("vulnerabilities", "cwe_id")
    op.drop_column("vulnerabilities", "cvss_vector")
    op.drop_column("vulnerabilities", "sla_tier")
    op.drop_column("vulnerabilities", "severity")
