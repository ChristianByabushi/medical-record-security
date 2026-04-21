"""Add Front_Desk and Emergency_Contact roles, rename consent duration to hours.

Revision ID: 007
Revises: 006
Create Date: 2026-04-21
"""
from alembic import op
import sqlalchemy as sa

revision = "007"
down_revision = "006"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Update role constraint
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.create_check_constraint(
        "ck_users_role",
        "users",
        "role IN ('Patient','Doctor','Nurse','Lab_Technician','Admin','SuperAdmin','Front_Desk','Emergency_Contact')",
    )

    # Rename consent duration column and convert days to hours
    op.add_column("consent_grants", sa.Column("requested_duration_hours", sa.Integer(), nullable=True))
    op.execute("UPDATE consent_grants SET requested_duration_hours = requested_duration_days * 24")
    op.alter_column("consent_grants", "requested_duration_hours", nullable=False)
    op.drop_column("consent_grants", "requested_duration_days")


def downgrade() -> None:
    op.add_column("consent_grants", sa.Column("requested_duration_days", sa.Integer(), nullable=True))
    op.execute("UPDATE consent_grants SET requested_duration_days = requested_duration_hours / 24")
    op.alter_column("consent_grants", "requested_duration_days", nullable=False)
    op.drop_column("consent_grants", "requested_duration_hours")

    op.drop_constraint("ck_users_role", "users", type_="check")
    op.create_check_constraint(
        "ck_users_role",
        "users",
        "role IN ('Patient','Doctor','Nurse','Lab_Technician','Admin','SuperAdmin')",
    )
