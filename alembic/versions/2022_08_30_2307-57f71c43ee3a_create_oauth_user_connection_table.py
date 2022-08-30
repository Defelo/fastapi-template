"""create oauth_user_connection table

Revision ID: 57f71c43ee3a
Create Date: 2022-08-30 23:07:38.819057
"""

from alembic import op

import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "57f71c43ee3a"
down_revision = "04bd76b11ff1"
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "oauth_user_connection",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("user_id", sa.String(length=36), nullable=True),
        sa.Column("provider_id", sa.String(length=64), nullable=True),
        sa.Column("remote_user_id", sa.Text(), nullable=True),
        sa.Column("display_name", sa.Text(), nullable=True),
        sa.ForeignKeyConstraint(["user_id"], ["user.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id"),
        mysql_collate="utf8mb4_bin",
    )


def downgrade() -> None:
    op.drop_table("oauth_user_connection")
