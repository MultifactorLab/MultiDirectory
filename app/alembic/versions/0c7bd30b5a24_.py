"""empty message

Revision ID: 0c7bd30b5a24
Revises: f4a7fde509d4
Create Date: 2024-02-22 08:06:09.716671

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '0c7bd30b5a24'
down_revision = 'f4a7fde509d4'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_constraint('name_parent_uc', 'Directory', type_='unique')
    op.create_unique_constraint('name_parent_uc', 'Directory', ['parentId', 'name'], postgresql_nulls_not_distinct=True)
    op.add_column('Users', sa.Column('lastLogon', sa.DateTime(timezone=True), nullable=True))
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_column('Users', 'lastLogon')
    op.drop_constraint('name_parent_uc', 'Directory', type_='unique')
    op.create_unique_constraint('name_parent_uc', 'Directory', ['parentId', 'name'])
    # ### end Alembic commands ###
