"""Utils module for different functions.

Windows filetime reference:
https://github.com/jleclanche/winfiletime/blob/master/winfiletime/filetime.py
"""
import hashlib
import re
from calendar import timegm
from datetime import datetime

import pytz
from asyncstdlib.functools import cache
from sqlalchemy import func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from models.ldap3 import (
    CatalogueSetting,
    Directory,
    Group,
    NetworkPolicy,
    Path,
    User,
)

email_re = re.compile(
    r"([A-Za-z0-9]+[.-_])*[A-Za-z0-9]+@[A-Za-z0-9-]+(\.[A-Z|a-z]{2,})+")


@cache
async def get_base_dn(session: AsyncSession, normal: bool = False) -> str:
    """Get base dn for e.g. DC=multifactor,DC=dev.

    :return str: name for the base distinguished name.
    """
    cat_result = await session.execute(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == 'defaultNamingContext'),
    )
    if normal:
        return cat_result.scalar_one().value

    return ','.join((
        f'dc={value}' for value in
        cat_result.scalar_one().value.split('.')))


def get_attribute_types() -> list[str]:
    """Get attribute types from file.

    :return list[list[str]]: attrs
    """
    with open('extra/adTypes.txt', 'r') as file:
        return [line.replace(')\n', ' )') for line in file]


def get_object_classes() -> list[str]:
    """Get attribute types from file.

    :return list[list[str]]: attrs
    """
    with open('extra/adClasses.txt', 'r') as file:
        return list(file)


def get_generalized_now() -> str:
    """Get generalized time (formated) with tz."""
    return datetime.now(  # NOTE: possible setting
        pytz.timezone('Europe/Moscow')).strftime('%Y%m%d%H%M%S.%f%z')


def _get_path(name: str) -> list[str]:
    """Get path from name."""
    return [
        item.lower() for item in reversed(name.split(','))
        if not item[:2] in ('DC', 'dc')
    ]


def _get_domain(name: str) -> str:
    """Get domain from name."""
    return '.'.join([
        item[3:].lower() for item in name.split(',')
        if item[:2] in ('DC', 'dc')
    ])


async def get_user(session: AsyncSession, name: str) -> User | None:
    """Get user with username.

    :param AsyncSession session: sqlalchemy session
    :param str name: any name: dn, email or upn
    :return User | None: user from db
    """
    if '=' not in name:
        if email_re.fullmatch(name):
            cond = User.user_principal_name.ilike(name) | User.mail.ilike(name)
        else:
            cond = User.sam_accout_name.ilike(name)

        return await session.scalar(select(User).where(cond))

    path = await session.scalar(
        select(Path).where(Path.path == _get_path(name)))

    domain = await session.scalar(
        select(CatalogueSetting)
        .where(
            CatalogueSetting.name == 'defaultNamingContext',
            CatalogueSetting.value == _get_domain(name),
        ))

    if not domain or not path:
        return None

    return await session.scalar(
        select(User).where(User.directory == path.endpoint))


def validate_entry(entry: str) -> bool:
    """Validate entry str.

    cn=first,dc=example,dc=com -> valid
    cn=first,dc=example,dc=com -> valid
    :param str entry: any str
    :return bool: result
    """
    return all(
        re.match(r'^[a-zA-Z\-]+$',
                 part.split('=')[0]) and len(part.split('=')) == 2
        for part in entry.split(','))


async def get_groups(
    dn_list: list[str],
    session: AsyncSession,
) -> list[Group]:
    """Get dirs with groups by dn list."""
    base_dn = await get_base_dn(session)

    paths = []

    for dn in dn_list:
        if dn.lower() == base_dn.lower():  # dn_is_base
            continue

        base_obj = dn.lower().removesuffix(
            ',' + base_dn.lower()).split(',')

        paths.append([path for path in reversed(base_obj) if path])

    query = select(   # noqa: ECE001
        Directory)\
        .join(Directory.path)\
        .filter(Path.path.in_(paths))\
        .options(
            selectinload(Directory.path),
            selectinload(Directory.group).selectinload(
                Group.parent_groups).selectinload(
                    Group.directory).selectinload(Directory.path))

    result = await session.stream_scalars(query)

    return [
        directory.group
        async for directory in result
        if directory.group is not None]


async def get_group(dn: str, session: AsyncSession) -> Directory:
    """Get dir with group by dn.

    :param str dn: Distinguished Name
    :param AsyncSession session: SA session
    :raises AttributeError: on invalid dn
    :return Directory: dir with group
    """
    base_dn = await get_base_dn(session)
    dn_is_base = dn.lower() == base_dn.lower()

    if dn_is_base:
        raise ValueError('Cannot set memberOf with base dn')

    path = list(reversed(
        dn.lower().removesuffix(',' + base_dn.lower()).split(',')))

    directory = await session.scalar(
        select(Directory)
        .join(Directory.path).filter(Path.path == path)
        .options(selectinload(Directory.group), selectinload(Directory.path)))

    if not directory:
        raise ValueError("Group not found")

    return directory


def get_path_dn(path: Path, base_dn: str) -> str:
    """Get DN from path."""
    return ','.join(reversed(path.path)) + ',' + base_dn


async def is_user_group_valid(
    user: User,
    policy: NetworkPolicy,
    session: AsyncSession,
) -> bool:
    """Validate user groups, is it including to policy.

    :param User user: db user
    :param NetworkPolicy policy: db policy
    :param AsyncSession session: db
    :return bool: status
    """
    if user is None:
        return False

    if not policy.groups:
        return True

    group = await session.scalar((  # noqa: ECE001
        select(Group)
        .join(Group.users)
        .join(Group.policies, isouter=True)
        .filter(Group.users.contains(user) & Group.policies.contains(policy))
        .limit(1)
    ))
    return bool(group)


def create_integer_hash(text: str, size: int = 9) -> int:
    """Create integer hash from text.

    :param str text: any string
    :param int size: fixed size of hash, defaults to 15
    :return int: hash
    """
    return int(hashlib.sha256(text.encode('utf-8')).hexdigest(), 16) % 10**size


async def set_last_logon_user(user: User, session: AsyncSession) -> None:
    """Update lastLogon attr."""
    await session.execute(
        update(User).values(
            {"last_logon": func.now()},
        ).where(
            User.id == user.id,
        ),
    )
    await session.commit()


def get_windows_timestamp(value: datetime) -> int:
    """Get the Windows timestamp from the value."""
    return (int(value.timestamp()) + 11644473600) * 10000000


_EPOCH_AS_FILETIME = 116444736000000000  # January 1, 1970 as MS file time
_HUNDREDS_OF_NS = 10000000


def dt_to_ft(dt: datetime) -> int:
    """Convert a datetime to a Windows filetime.

    If the object is time zone-naive, it is forced to UTC before conversion.
    """
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) is None:
        dt = dt.replace(tzinfo=pytz.utc)

    filetime = _EPOCH_AS_FILETIME + (timegm(dt.timetuple()) * _HUNDREDS_OF_NS)
    return filetime + (dt.microsecond * 10)


def ft_to_dt(filetime: int) -> datetime:
    """Convert a Windows filetime number to a Python datetime.

    The new datetime object is timezone-naive but is equivalent to tzinfo=utc.
    1) Get seconds and remainder in terms of Unix epoch
    2) Convert to datetime object, with remainder as microseconds.
    """
    s, ns100 = divmod(filetime - _EPOCH_AS_FILETIME, _HUNDREDS_OF_NS)
    return datetime.utcfromtimestamp(s).replace(microsecond=(ns100 // 10))
