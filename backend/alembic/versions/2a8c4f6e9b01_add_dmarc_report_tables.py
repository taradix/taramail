"""Add dmarc report tables

Revision ID: 2a8c4f6e9b01
Revises: 688be1178ef6
Create Date: 2026-05-22 17:50:00.000000

"""

from collections.abc import Sequence

import sqlalchemy as sa

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "2a8c4f6e9b01"
down_revision: str | None = "688be1178ef6"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.create_table(
        "dmarc_report",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("report_id", sa.String(length=255), nullable=False),
        sa.Column("org_name", sa.String(length=255), nullable=False),
        sa.Column("org_email", sa.String(length=255), server_default="", nullable=False),
        sa.Column("domain", sa.String(length=255), nullable=False),
        sa.Column("policy", sa.String(length=20), nullable=False),
        sa.Column("begin_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("end_date", sa.DateTime(timezone=True), nullable=False),
        sa.Column("created", sa.DateTime(timezone=True), server_default=sa.text("CURRENT_TIMESTAMP"), nullable=False),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("dmarc_report_report_id_key", "dmarc_report", ["report_id"], unique=True)
    op.create_index("dmarc_report_domain_key", "dmarc_report", ["domain"], unique=False)
    op.create_index("dmarc_report_begin_date_key", "dmarc_report", ["begin_date"], unique=False)

    op.create_table(
        "dmarc_record",
        sa.Column("id", sa.Integer(), autoincrement=True, nullable=False),
        sa.Column("report_id", sa.Integer(), nullable=False),
        sa.Column("source_ip", sa.String(length=64), nullable=False),
        sa.Column("count", sa.Integer(), nullable=False),
        sa.Column("disposition", sa.String(length=20), nullable=False),
        sa.Column("dkim_result", sa.String(length=20), nullable=False),
        sa.Column("spf_result", sa.String(length=20), nullable=False),
        sa.Column("dmarc_result", sa.String(length=20), nullable=False),
        sa.Column("header_from", sa.String(length=255), nullable=False),
        sa.Column("envelope_from", sa.String(length=255), server_default="", nullable=False),
        sa.ForeignKeyConstraint(["report_id"], ["dmarc_report.id"], ondelete="CASCADE"),
        sa.PrimaryKeyConstraint("id"),
    )
    op.create_index("dmarc_record_report_id_key", "dmarc_record", ["report_id"], unique=False)
    op.create_index("dmarc_record_source_ip_key", "dmarc_record", ["source_ip"], unique=False)
    op.create_index("dmarc_record_header_from_key", "dmarc_record", ["header_from"], unique=False)


def downgrade() -> None:
    op.drop_index("dmarc_record_header_from_key", table_name="dmarc_record")
    op.drop_index("dmarc_record_source_ip_key", table_name="dmarc_record")
    op.drop_index("dmarc_record_report_id_key", table_name="dmarc_record")
    op.drop_table("dmarc_record")
    op.drop_index("dmarc_report_begin_date_key", table_name="dmarc_report")
    op.drop_index("dmarc_report_domain_key", table_name="dmarc_report")
    op.drop_index("dmarc_report_report_id_key", table_name="dmarc_report")
    op.drop_table("dmarc_report")
