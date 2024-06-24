"""add objectSid attr

Revision ID: 6355e97cd073
Revises: aab3b0e949d9
Create Date: 2024-06-23 14:54:29.941486

"""
import random
import uuid
from alembic import op
import sqlalchemy as sa
from sqlalchemy import orm, select, exists

from models.ldap3 import CatalogueSetting, Directory

# revision identifiers, used by Alembic.
revision = '6355e97cd073'
down_revision = 'aab3b0e949d9'
branch_labels = None
depends_on = None


def upgrade() -> None:
    bind = op.get_bind()
    session = orm.Session(bind=bind)
    op.add_column('Directory', sa.Column('objectSid', sa.String(), nullable=True))

    result = session.scalar(select(
        exists(CatalogueSetting)
        .where(CatalogueSetting.name == 'defaultNamingContext')))

    if bool(result):
        domain_sid = f'S-1-5-21-{random.randint(1000000000, 4294967295)}' +\
            f'-{random.randint(1000000000, 4294967295)}' +\
            f'-{random.randint(100000000, 999999999)}'

        session.add(CatalogueSetting(name='objectSid', value=domain_sid))
        session.add(CatalogueSetting(name='objectGUID', value=str(uuid.uuid4())))

        for directory in session.query(Directory):
            if directory.name == 'domain admins':
                directory.object_sid = domain_sid + '-512'
            else:
                directory.object_sid = domain_sid + f'-{1000+directory.id}'

        session.commit()


def downgrade() -> None:
    # ### commands auto generated by Alembic - please adjust! ###
    bind = op.get_bind()
    session = orm.Session(bind=bind)

    op.drop_column('Directory', 'objectSid')

    result = session.scalar(select(
        exists(CatalogueSetting)
        .where(CatalogueSetting.name == 'defaultNamingContext')))

    if bool(result):
        op.execute('delete from "Settings" where "name" = \'objectSid\'')
        op.execute('delete from "Settings" where "name" = \'objectGUID\'')
    # ### end Alembic commands ###
