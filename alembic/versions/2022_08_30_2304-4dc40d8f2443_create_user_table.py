"""create user table

Revision ID: 4dc40d8f2443
Create Date: 2022-08-30 23:04:05.610717
"""

from alembic import op

import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = "4dc40d8f2443"
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    op.create_table(
        "user",
        sa.Column("id", sa.String(length=36), nullable=False),
        sa.Column("name", sa.String(length=32), nullable=True),
        sa.Column("password", sa.String(length=128), nullable=True),
        sa.Column("registration", sa.DateTime(), nullable=True),
        sa.Column("last_login", sa.DateTime(), nullable=True),
        sa.Column("enabled", sa.Boolean(), nullable=True),
        sa.Column("admin", sa.Boolean(), nullable=True),
        sa.Column("mfa_secret", sa.String(length=32), nullable=True),
        sa.Column("mfa_enabled", sa.Boolean(), nullable=True),
        sa.Column("mfa_recovery_code", sa.String(length=64), nullable=True),
        sa.PrimaryKeyConstraint("id"),
        sa.UniqueConstraint("id"),
        sa.UniqueConstraint("name"),
        mysql_collate="utf8mb4_bin",
    )


def downgrade() -> None:
    op.drop_table("user")
