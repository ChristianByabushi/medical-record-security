"""Add full_name column to users table.

Revision ID: 008
Revises: 007
Create Date: 2026-04-21
"""
from alembic import op
import sqlalchemy as sa

revision = "008"
down_revision = "007"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.add_column("users", sa.Column("full_name", sa.String(255), nullable=False, server_default=""))


def downgrade() -> None:
    op.drop_column("users", "full_name")
