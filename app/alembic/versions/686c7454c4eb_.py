"""empty message

Revision ID: 686c7454c4eb
Revises: 
Create Date: 2022-12-13 10:41:50.392275

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '686c7454c4eb'
down_revision = None
branch_labels = None
depends_on = None


def upgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    op.create_table('Directory',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('parentId', sa.Integer(), nullable=True),
    sa.Column('objectClass', sa.String(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('whenCreated', sa.DateTime(timezone=True), server_default=sa.text('now()'), nullable=False),
    sa.Column('whenChanged', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['parentId'], ['Directory.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('parentId', 'name', name='name_parent_uc')
    )
    op.create_index(op.f('ix_Directory_parentId'), 'Directory', ['parentId'], unique=False)
    op.create_table('Settings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('value', sa.String(), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_Settings_name'), 'Settings', ['name'], unique=False)
    op.create_table('Attributes',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(), nullable=False),
    sa.Column('value', sa.String(), nullable=False),
    sa.Column('directoryId', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['directoryId'], ['Directory.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Computers',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('directoryId', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['directoryId'], ['Directory.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Groups',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('directoryId', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['directoryId'], ['Directory.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('Users',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('sAMAccountName', sa.String(), nullable=False),
    sa.Column('userPrincipalName', sa.String(), nullable=False),
    sa.Column('displayName', sa.String(), nullable=True),
    sa.Column('password', sa.String(), nullable=True),
    sa.Column('directoryId', sa.Integer(), nullable=False),
    sa.ForeignKeyConstraint(['directoryId'], ['Directory.id'], ),
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
    op.drop_index(op.f('ix_Settings_name'), table_name='Settings')
    op.drop_table('Settings')
    op.drop_index(op.f('ix_Directory_parentId'), table_name='Directory')
    op.drop_table('Directory')
    # ### end Alembic commands ###