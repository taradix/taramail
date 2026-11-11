"""Drop sogo_view and the sogo_update_password trigger

The trigger updated mailbox from _sogo_static_view, so refreshing the
static view failed with MySQL error 1442. Like mailcow, the static view
is now refreshed by the backend instead of from sogo_view.

Revision ID: 7d3e1b5a9c42
Revises: 2a8c4f6e9b01
Create Date: 2026-11-10 21:45:00.000000

"""

from collections.abc import Sequence

from alembic import op

# revision identifiers, used by Alembic.
revision: str = "7d3e1b5a9c42"
down_revision: str | None = "2a8c4f6e9b01"
branch_labels: str | Sequence[str] | None = None
depends_on: str | Sequence[str] | None = None


def upgrade() -> None:
    op.execute("DROP TRIGGER IF EXISTS sogo_update_password")
    op.execute("DROP VIEW IF EXISTS sogo_view")


def downgrade() -> None:
    pass
