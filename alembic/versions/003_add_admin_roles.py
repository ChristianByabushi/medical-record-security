"""Add Admin and SuperAdmin roles to users check constraint.

Revision ID: 003
Revises: 002
Create Date: 2026-04-20
"""
from alembic import op

revision = "003"
down_revision = "002"
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Drop old constraint and add new one with Admin/SuperAdmin
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.create_check_constraint(
        "ck_users_role",
        "users",
        "role IN ('Patient','Doctor','Nurse','Lab_Technician','Admin','SuperAdmin')",
    )


def downgrade() -> None:
    op.drop_constraint("ck_users_role", "users", type_="check")
    op.create_check_constraint(
        "ck_users_role",
        "users",
        "role IN ('Patient','Doctor','Nurse','Lab_Technician')",
    )
