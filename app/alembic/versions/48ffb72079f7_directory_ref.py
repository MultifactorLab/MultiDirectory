"""directory_ref

Revision ID: 48ffb72079f7
Revises: 93d18fa59534
Create Date: 2022-12-08 07:18:41.458834

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '48ffb72079f7'
down_revision = '93d18fa59534'
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('Attributes',
    sa.Column('id', sa.NullType(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('value', sa.String(), nullable=False),
    sa.Column('directoryId', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['directoryId'], ['Directories.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Computers',
    sa.Column('id', sa.NullType(), nullable=False),
    sa.Column('directoryId', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['directoryId'], ['Directories.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Groups',
    sa.Column('id', sa.NullType(), nullable=False),
    sa.Column('directoryId', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['directoryId'], ['Directories.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Users',
    sa.Column('id', sa.NullType(), nullable=False),
    sa.Column('sAMAccountName', sa.String(), nullable=False),
    sa.Column('userPrincipalName', sa.String(), nullable=False),
    sa.Column('displayName', sa.String(), nullable=True),
    sa.Column('password', sa.String(), nullable=True),
    sa.Column('directoryId', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['directoryId'], ['Directories.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('sAMAccountName'),
    sa.UniqueConstraint('userPrincipalName')
    )
    # ### end Alembic commands ###


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('Users')
    op.drop_table('Groups')
    op.drop_table('Computers')
    op.drop_table('Attributes')
    # ### end Alembic commands ###
