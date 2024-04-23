"""attributes bvalue

Revision ID: aaa8ca2cb70e
Revises: 9fc1aad1b5d0
Create Date: 2024-04-09 11:14:13.078700

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'aaa8ca2cb70e'
down_revision = '9fc1aad1b5d0'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.add_column('Attributes', sa.Column('bvalue', sa.LargeBinary(), nullable=True))
    op.alter_column('Attributes', 'value',
               existing_type=sa.VARCHAR(),
               nullable=True)
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.alter_column('Attributes', 'value',
               existing_type=sa.VARCHAR(),
               nullable=False)
    op.drop_column('Attributes', 'bvalue')
    # ### end Alembic commands ###
