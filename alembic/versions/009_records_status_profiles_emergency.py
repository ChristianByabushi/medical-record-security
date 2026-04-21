"""Add record draft/publish status, patient_profiles, emergency_contact_links.

Revision ID: 009
Revises: 008
Create Date: 2026-04-21
"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

revision = "009"
down_revision = "008"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ── medical_records: add status + published_at ──────────────────────
    op.add_column("medical_records", sa.Column("status", sa.String(10), nullable=False, server_default="published"))
    op.add_column("medical_records", sa.Column("published_at", sa.DateTime(timezone=True), nullable=True))
    op.create_check_constraint("ck_medical_records_status", "medical_records", "status IN ('draft','published')")
    op.create_index("idx_mr_status", "medical_records", ["status"])
    # Existing records are already visible — mark them published
    op.execute("UPDATE medical_records SET published_at = created_at WHERE status = 'published'")

    # ── patient_profiles ────────────────────────────────────────────────
    op.create_table(
        "patient_profiles",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False, unique=True),
        sa.Column("date_of_birth", sa.Date(), nullable=True),
        sa.Column("sex", sa.String(20), nullable=True),
        sa.Column("nationality", sa.String(100), nullable=True),
        sa.Column("phone_number", sa.String(30), nullable=True),
        sa.Column("insurance_provider", sa.String(100), nullable=True),
        sa.Column("blood_type", sa.String(10), nullable=True),
        sa.Column("known_allergies", sa.Text(), nullable=True),
        sa.Column("known_conditions", sa.Text(), nullable=True),
        sa.Column("dnr_status", sa.Boolean(), nullable=True, server_default=sa.text("FALSE")),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.Column("updated_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
    )

    # ── emergency_contact_links ─────────────────────────────────────────
    op.create_table(
        "emergency_contact_links",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("patient_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("contact_user_id", postgresql.UUID(as_uuid=True),
                  sa.ForeignKey("users.id", ondelete="CASCADE"), nullable=False),
        sa.Column("relationship", sa.String(50), nullable=True),
        sa.Column("created_at", sa.DateTime(timezone=True), nullable=False, server_default=sa.text("now()")),
        sa.UniqueConstraint("patient_id", "contact_user_id", name="uq_ecl_patient_contact"),
    )
    op.create_index("idx_ecl_patient_id", "emergency_contact_links", ["patient_id"])


def downgrade() -> None:
    op.drop_index("idx_ecl_patient_id", table_name="emergency_contact_links")
    op.drop_table("emergency_contact_links")
    op.drop_table("patient_profiles")
    op.drop_index("idx_mr_status", table_name="medical_records")
    op.drop_constraint("ck_medical_records_status", "medical_records", type_="check")
    op.drop_column("medical_records", "published_at")
    op.drop_column("medical_records", "status")
