"""audit_log_permissions

Revision ID: 002
Revises: 001
Create Date: 2024-01-01 00:01:00.000000

PRODUCTION NOTE
---------------
In a production PostgreSQL environment the application DB role should be
granted INSERT and SELECT only on the audit_log table — no UPDATE or DELETE.
This enforces the append-only guarantee at the database privilege level,
independent of application logic.

Example SQL to run as a superuser / DB owner after deploying this migration:

    REVOKE ALL ON audit_log FROM app_role;
    GRANT SELECT, INSERT ON audit_log TO app_role;

This migration file serves as documentation and a reminder to apply those
grants. The GRANT/REVOKE statements are intentionally omitted here because:
  1. The application DB user may not have GRANT OPTION in all environments.
  2. SQLite (used in the test environment) does not support GRANT syntax.
  3. The grants must be applied by a privileged DB administrator, not the
     application migration runner.
"""
from __future__ import annotations

from typing import Sequence, Union

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "002"
down_revision: Union[str, None] = "001"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # No DDL changes — privilege grants must be applied manually by a DB admin.
    # See the module docstring above for the required SQL.
    pass


def downgrade() -> None:
    # No DDL to reverse.
    pass
