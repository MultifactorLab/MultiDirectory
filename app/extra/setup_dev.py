"""Dev data creation.

DC=multifactor
  OU=IT
    CN=User 1
    CN=User 2
  CN=Users
    CN=User 3
    CN=User 4
  OU="2FA"
    CN=Service Accounts
      CN=User 5
"""
import asyncio

from loguru import logger
from sqlalchemy.future import select

from models.database import async_session
from models.ldap3 import CatalogueSetting, Directory, User

DATA = [  # noqa
    {
        "name": "IT",
        "object_class": "organizationUnit",
        "children": [
            {"name": "User 1", "object_class": "User", "user": {
                "sam_accout_name": "username1",
                "user_principal_name": "username1@multifactor.dev",
                "display_name": "User 1",
                "password": "password"}},

            {"name": "User 2", "object_class": "User", "user": {
                "sam_accout_name": "username2",
                "user_principal_name": "username2@multifactor.dev",
                "display_name": "User 2",
                "password": "password"}},
        ],
    },
    {
        "name": "Users",
        "object_class": "Users",
        "children": [
            {"name": "User 3", "object_class": "User", "user": {
                "sam_accout_name": "username3",
                "user_principal_name": "username3@multifactor.dev",
                "display_name": "User 3",
                "password": "password"}},

            {"name": "User 4", "object_class": "User", "user": {
                "sam_accout_name": "username4",
                "user_principal_name": "username4@multifactor.dev",
                "display_name": "User 4",
                "password": "password"}},
        ],
    },
    {
        "name": "2FA",
        "object_class": "organizationUnit",
        "children": [
            {"name": "Service Accounts", "object_class": "User", "children": [
                {"name": "User 5", "object_class": "User", "user": {
                    "sam_accout_name": "username5",
                    "user_principal_name": "username5@multifactor.dev",
                    "display_name": "User 5",
                    "password": "password"}},
            ]},
        ],
    },
]


async def create_dir(data, session, parent: Directory | None = None):
    """Create data recursively."""
    if not parent:
        dir_ = Directory(
            object_class=data['object_class'], name=data['name'])
        path = dir_.create_path()

        async with session.begin_nested():
            logger.debug(f"creating {dir_.object_class}:{dir_.name}")
            session.add_all([dir_, path])
            dir_.paths.append(path)

    else:
        dir_ = Directory(
            object_class=data['object_class'],
            name=data['name'],
            parent=parent)
        path = dir_.create_path(parent)

        async with session.begin_nested():
            logger.debug(
                f"creating {dir_.object_class}:{dir_.name}:{dir_.parent.id}")
            session.add_all([dir_, path])
            dir_.paths.extend(parent.paths + [path])

    if 'user' in data:
        user_data = data['user']
        session.add(User(
            directory=dir_,
            sam_accout_name=user_data['sam_accout_name'],
            user_principal_name=user_data['user_principal_name'],
            display_name=user_data['display_name'],
            password=user_data['password'],
        ))
    await session.commit()

    if 'children' in data:
        for n_data in data['children']:
            await create_dir(n_data, session, dir_)


async def setup_dev_enviroment() -> None:
    """Create directories and users for development enviroment."""
    async with async_session() as session:
        cat_result = await session.execute(
            select(CatalogueSetting)
            .filter(CatalogueSetting.name == 'defaultNamingContext')
        )
        if cat_result.scalar():
            logger.warning('dev data already set up')
            return

        catalogue = CatalogueSetting(
            name='defaultNamingContext', value='multifactor.dev')

        async with session.begin_nested():
            session.add(catalogue)
        await session.commit()

    async with async_session() as session:
        try:
            for data in DATA:
                await create_dir(data, session)
        except Exception as err:
            logger.error(err)  # noqa


if __name__ == '__main__':
    asyncio.run(setup_dev_enviroment())
