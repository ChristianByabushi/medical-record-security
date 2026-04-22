"""Widen audit_log.event_type to 50 chars and drop actor_id FK constraint.

Revision ID: 010
Revises: 009
Create Date: 2026-04-22

Reason:
- event_type String(30) silently truncated REPLAY_TIMESTAMP_SKEW (31 chars),
  causing security alert queries to return 0 results.
- actor_id FK to users.id rejected nil UUID inserts from unauthenticated
  events (replay blocks, unknown-email login failures), causing those audit
  entries to be silently dropped.
"""
from alembic import op
import sqlalchemy as sa

revision = '010'
down_revision = '009'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # Widen event_type column
    op.alter_column(
        'audit_log', 'event_type',
        existing_type=sa.String(length=30),
        type_=sa.String(length=50),
        existing_nullable=False,
    )

    # Drop the FK constraint on actor_id so nil UUIDs can be stored.
    # The constraint name varies by DB; use batch_alter_table for portability.
    with op.batch_alter_table('audit_log') as batch_op:
        # Try to drop FK — ignore if it doesn't exist (SQLite has no named FKs)
        try:
            batch_op.drop_constraint('audit_log_actor_id_fkey', type_='foreignkey')
        except Exception:
            pass


def downgrade() -> None:
    op.alter_column(
        'audit_log', 'event_type',
        existing_type=sa.String(length=50),
        type_=sa.String(length=30),
        existing_nullable=False,
    )
    # Re-adding the FK on downgrade is intentionally skipped —
    # existing nil-UUID rows would violate it.
