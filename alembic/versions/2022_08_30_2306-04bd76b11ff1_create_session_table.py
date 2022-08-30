"""create session table

Revision ID: 04bd76b11ff1
Create Date: 2022-08-30 23:06:09.597478
"""

from alembic import op

import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "04bd76b11ff1"
down_revision = "4dc40d8f2443"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "session",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("device_name", sa.Text(), nullable=True),
        sa.Column("last_update", sa.DateTime(), nullable=True),
        sa.Column("refresh_token", sa.String(length=64), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id"),
        sa.UniqueConstraint("refresh_token"),
        mysql_collate="utf8mb4_bin",
    )


def downgrade() -> None:
    op.drop_table("session")
