"""Add accountExpires attr

Revision ID: aab3b0e949d9
Revises: 002bf88959c5
Create Date: 2024-06-19 09:58:24.873026

"""
from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision = 'aab3b0e949d9'
down_revision = '002bf88959c5'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('Users', sa.Column('accountExpires', sa.DateTime(timezone=True), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('Users', 'accountExpires')
    # ### end Alembic commands ###
