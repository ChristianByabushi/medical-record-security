"""initial_schema

Revision ID: 001
Revises:
Create Date: 2024-01-01 00:00:00.000000

"""
from __future__ import annotations

from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = "001"
down_revision: Union[str, None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # ------------------------------------------------------------------
    # users
    # ------------------------------------------------------------------
    op.create_table(
        "users",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column("email", sa.String(255), nullable=False),
        sa.Column("password_hash", sa.String(72), nullable=False),
        sa.Column(
            "role",
            sa.String(20),
            nullable=False,
        ),
        sa.Column("is_active", sa.Boolean(), nullable=False, server_default=sa.text("TRUE")),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=False, server_default=sa.text("FALSE")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "role IN ('Patient','Doctor','Nurse','Lab_Technician')",
            name="ck_users_role",
        ),
        sa.UniqueConstraint("email", name="uq_users_email"),
    )
    op.create_index("idx_users_email", "users", ["email"], unique=True)
    op.create_index("idx_users_role", "users", ["role"])

    # ------------------------------------------------------------------
    # mfa_secrets
    # ------------------------------------------------------------------
    op.create_table(
        "mfa_secrets",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
            unique=True,
        ),
        sa.Column("encrypted_secret", sa.LargeBinary(), nullable=False),
        sa.Column("iv", sa.LargeBinary(), nullable=False),
        sa.Column("tag", sa.LargeBinary(), nullable=False),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )

    # ------------------------------------------------------------------
    # refresh_tokens
    # ------------------------------------------------------------------
    op.create_table(
        "refresh_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("revoked", sa.Boolean(), nullable=False, server_default=sa.text("FALSE")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("idx_refresh_tokens_user_id", "refresh_tokens", ["user_id"])
    op.create_index("idx_refresh_tokens_token_hash", "refresh_tokens", ["token_hash"], unique=True)

    # ------------------------------------------------------------------
    # password_reset_tokens
    # ------------------------------------------------------------------
    op.create_table(
        "password_reset_tokens",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "user_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("token_hash", sa.String(64), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
        sa.Column("used", sa.Boolean(), nullable=False, server_default=sa.text("FALSE")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("idx_prt_token_hash", "password_reset_tokens", ["token_hash"], unique=True)
    op.create_index("idx_prt_user_id", "password_reset_tokens", ["user_id"])

    # ------------------------------------------------------------------
    # consent_grants
    # ------------------------------------------------------------------
    op.create_table(
        "consent_grants",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "doctor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column(
            "patient_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("status", sa.String(10), nullable=False, server_default="pending"),
        sa.Column("requested_duration_days", sa.Integer(), nullable=False),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=True),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.CheckConstraint(
            "status IN ('pending','active','rejected','revoked','expired')",
            name="ck_consent_grants_status",
        ),
    )
    op.create_index("idx_cg_doctor_patient", "consent_grants", ["doctor_id", "patient_id"])
    op.create_index("idx_cg_patient_status", "consent_grants", ["patient_id", "status"])

    # ------------------------------------------------------------------
    # medical_records
    # ------------------------------------------------------------------
    op.create_table(
        "medical_records",
        sa.Column("id", postgresql.UUID(as_uuid=True), primary_key=True),
        sa.Column(
            "patient_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("record_type", sa.String(50), nullable=False),
        sa.Column(
            "created_by",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id", ondelete="CASCADE"),
            nullable=False,
        ),
        sa.Column("encrypted_data", sa.LargeBinary(), nullable=False),
        sa.Column("iv", sa.LargeBinary(), nullable=False),
        sa.Column("tag", sa.LargeBinary(), nullable=False),
        sa.Column("is_deleted", sa.Boolean(), nullable=False, server_default=sa.text("FALSE")),
        sa.Column(
            "created_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column(
            "updated_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
    )
    op.create_index("idx_mr_patient_id", "medical_records", ["patient_id"])
    op.create_index("idx_mr_created_by", "medical_records", ["created_by"])
    op.create_index("idx_mr_record_type", "medical_records", ["record_type"])

    # ------------------------------------------------------------------
    # audit_log  (BIGSERIAL PK — append-only)
    # ------------------------------------------------------------------
    op.create_table(
        "audit_log",
        sa.Column(
            "id",
            sa.BigInteger(),
            primary_key=True,
            autoincrement=True,
        ),
        sa.Column("event_type", sa.String(30), nullable=False),
        sa.Column(
            "actor_id",
            postgresql.UUID(as_uuid=True),
            sa.ForeignKey("users.id"),
            nullable=False,
        ),
        sa.Column("resource_id", postgresql.UUID(as_uuid=True), nullable=False),
        sa.Column("resource_type", sa.String(30), nullable=False),
        # Stored as VARCHAR(45) — INET not portable across SQLAlchemy dialects
        sa.Column("client_ip", sa.String(45), nullable=False),
        sa.Column(
            "occurred_at",
            sa.DateTime(timezone=True),
            nullable=False,
            server_default=sa.text("now()"),
        ),
        sa.Column("chain_hash", sa.String(64), nullable=False),
        sa.Column("extra", sa.JSON(), nullable=True),
    )
    op.create_index("idx_al_actor_id", "audit_log", ["actor_id"])
    op.create_index("idx_al_resource_id", "audit_log", ["resource_id"])
    op.create_index("idx_al_occurred_at", "audit_log", ["occurred_at"])

    # ------------------------------------------------------------------
    # nonce_store
    # ------------------------------------------------------------------
    op.create_table(
        "nonce_store",
        sa.Column("nonce", sa.String(128), primary_key=True),
        sa.Column("expires_at", sa.DateTime(timezone=True), nullable=False),
    )
    op.create_index("idx_ns_expires_at", "nonce_store", ["expires_at"])


def downgrade() -> None:
    op.drop_index("idx_al_occurred_at", table_name="audit_log")
    op.drop_index("idx_al_resource_id", table_name="audit_log")
    op.drop_index("idx_al_actor_id", table_name="audit_log")
    op.drop_table("nonce_store")
    op.drop_table("audit_log")
    op.drop_table("medical_records")
    op.drop_table("consent_grants")
    op.drop_table("password_reset_tokens")
    op.drop_table("refresh_tokens")
    op.drop_table("mfa_secrets")
    op.drop_table("users")
