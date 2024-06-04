"""Utils module for different functions.

Windows filetime reference:
License: https://github.com/jleclanche/winfiletime/blob/master/LICENSE

```
CC0 1.0 Universal

Statement of Purpose

The laws of most jurisdictions throughout the world automatically confer
exclusive Copyright and Related Rights (defined below) upon the creator and
subsequent owner(s) (each and all, an "owner") of an original work of
authorship and/or a database (each, a "Work").

Certain owners wish to permanently relinquish those rights to a Work for the
purpose of contributing to a commons of creative, cultural and scientific
works ("Commons") that the public can reliably and without fear of later
claims of infringement build upon, modify, incorporate in other works, reuse
and redistribute as freely as possible in any form whatsoever and for any
purposes, including without limitation commercial purposes. These owners may
contribute to the Commons to promote the ideal of a free culture and the
further production of creative, cultural and scientific works, or to gain
reputation or greater distribution for their Work in part through the use and
efforts of others.

For these and/or other purposes and motivations, and without any expectation
of additional consideration or compensation, the person associating CC0 with a
Work (the "Affirmer"), to the extent that he or she is an owner of Copyright
and Related Rights in the Work, voluntarily elects to apply CC0 to the Work
and publicly distribute the Work under its terms, with knowledge of his or her
Copyright and Related Rights in the Work and the meaning and intended legal
effect of CC0 on those rights.

1. Copyright and Related Rights. A Work made available under CC0 may be
protected by copyright and related or neighboring rights ("Copyright and
Related Rights"). Copyright and Related Rights include, but are not limited
to, the following:

  i. the right to reproduce, adapt, distribute, perform, display, communicate,
  and translate a Work;

  ii. moral rights retained by the original author(s) and/or performer(s);

  iii. publicity and privacy rights pertaining to a person's image or likeness
  depicted in a Work;

  iv. rights protecting against unfair competition in regards to a Work,
  subject to the limitations in paragraph 4(a), below;

  v. rights protecting the extraction, dissemination, use and reuse of data in
  a Work;

  vi. database rights (such as those arising under Directive 96/9/EC of the
  European Parliament and of the Council of 11 March 1996 on the legal
  protection of databases, and under any national implementation thereof,
  including any amended or successor version of such directive); and

  vii. other similar, equivalent or corresponding rights throughout the world
  based on applicable law or treaty, and any national implementations thereof.

2. Waiver. To the greatest extent permitted by, but not in contravention of,
applicable law, Affirmer hereby overtly, fully, permanently, irrevocably and
unconditionally waives, abandons, and surrenders all of Affirmer's Copyright
and Related Rights and associated claims and causes of action, whether now
known or unknown (including existing as well as future claims and causes of
action), in the Work (i) in all territories worldwide, (ii) for the maximum
duration provided by applicable law or treaty (including future time
extensions), (iii) in any current or future medium and for any number of
copies, and (iv) for any purpose whatsoever, including without limitation
commercial, advertising or promotional purposes (the "Waiver"). Affirmer makes
the Waiver for the benefit of each member of the public at large and to the
detriment of Affirmer's heirs and successors, fully intending that such Waiver
shall not be subject to revocation, rescission, cancellation, termination, or
any other legal or equitable action to disrupt the quiet enjoyment of the Work
by the public as contemplated by Affirmer's express Statement of Purpose.

3. Public License Fallback. Should any part of the Waiver for any reason be
judged legally invalid or ineffective under applicable law, then the Waiver
shall be preserved to the maximum extent permitted taking into account
Affirmer's express Statement of Purpose. In addition, to the extent the Waiver
is so judged Affirmer hereby grants to each affected person a royalty-free,
non transferable, non sublicensable, non exclusive, irrevocable and
unconditional license to exercise Affirmer's Copyright and Related Rights in
the Work (i) in all territories worldwide, (ii) for the maximum duration
provided by applicable law or treaty (including future time extensions), (iii)
in any current or future medium and for any number of copies, and (iv) for any
purpose whatsoever, including without limitation commercial, advertising or
promotional purposes (the "License"). The License shall be deemed effective as
of the date CC0 was applied by Affirmer to the Work. Should any part of the
License for any reason be judged legally invalid or ineffective under
applicable law, such partial invalidity or ineffectiveness shall not
invalidate the remainder of the License, and in such case Affirmer hereby
affirms that he or she will not (i) exercise any of his or her remaining
Copyright and Related Rights in the Work or (ii) assert any associated claims
and causes of action with respect to the Work, in either case contrary to
Affirmer's express Statement of Purpose.

4. Limitations and Disclaimers.

  a. No trademark or patent rights held by Affirmer are waived, abandoned,
  surrendered, licensed or otherwise affected by this document.

  b. Affirmer offers the Work as-is and makes no representations or warranties
  of any kind concerning the Work, express, implied, statutory or otherwise,
  including without limitation warranties of title, merchantability, fitness
  for a particular purpose, non infringement, or the absence of latent or
  other defects, accuracy, or the present or absence of errors, whether or not
  discoverable, all to the greatest extent permissible under applicable law.

  c. Affirmer disclaims responsibility for clearing rights of other persons
  that may apply to the Work or any use thereof, including without limitation
  any person's Copyright and Related Rights in the Work. Further, Affirmer
  disclaims responsibility for obtaining any necessary consents, permissions
  or other rights required for any use of the Work.

  d. Affirmer understands and acknowledges that Creative Commons is not a
  party to this document and has no duty or obligation with respect to this
  CC0 or use of the Work.

For more information, please see
<https://creativecommons.org/publicdomain/zero/1.0/>
```
Author link: https://github.com/jleclanche

Reference:
https://github.com/jleclanche/winfiletime/blob/master/winfiletime/filetime.py

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""
import hashlib
import random
import re
import struct
from calendar import timegm
from datetime import datetime
from operator import attrgetter
from zoneinfo import ZoneInfo

from asyncstdlib.functools import cache
from sqlalchemy import Column, func, select, update
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload
from sqlalchemy.sql.expression import ColumnElement

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


def get_generalized_now(tz: ZoneInfo) -> str:
    """Get generalized time (formated) with tz."""
    return datetime.now(tz).strftime('%Y%m%d%H%M%S.%f%z')


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
        select(Path).where(get_path_filter(_get_path(name))))

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
        re.match(r'^[a-zA-Z\-]+$', part.split('=')[0])
        and len(part.split('=')) == 2
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

        base_obj = get_search_path(dn, base_dn)

        paths.append([path for path in base_obj if path])

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

    path = get_search_path(dn, base_dn)

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


async def set_last_logon_user(
        user: User, session: AsyncSession, tz: ZoneInfo) -> None:
    """Update lastLogon attr."""
    await session.execute(
        update(User).values(
            {"last_logon": datetime.now(tz=tz)},
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
    if dt.tzinfo is None or dt.tzinfo.utcoffset(dt) != 0:
        dt = dt.astimezone(ZoneInfo('UTC'))

    filetime = _EPOCH_AS_FILETIME + (timegm(dt.timetuple()) * _HUNDREDS_OF_NS)
    return filetime + (dt.microsecond * 10)


def ft_to_dt(filetime: int) -> datetime:
    """Convert a Windows filetime number to a Python datetime.

    The new datetime object is timezone-naive but is equivalent to tzinfo=utc.
    1) Get seconds and remainder in terms of Unix epoch
    2) Convert to datetime object, with remainder as microseconds.
    """
    s, ns100 = divmod(filetime - _EPOCH_AS_FILETIME, _HUNDREDS_OF_NS)
    return datetime.fromtimestamp(
        s, tz=ZoneInfo('UTC')).replace(microsecond=(ns100 // 10))


def get_search_path(dn: str, base_dn: str) -> list[str]:
    """Get search path for dn.

    :param str dn: any DN, dn syntax
    :param str base_dn: domain dn
    :return list[str]: reversed list of dn values
    """
    search_path = dn.lower().removesuffix(
        ',' + base_dn.lower()).split(',')
    search_path.reverse()
    return search_path


def get_path_filter(
        path: list[str], *, column: Column = Path.path) -> ColumnElement:
    """Get filter condition for path equality.

    :param list[str] path: dn
    :param Column field: path column, defaults to Path.path
    :return ColumnElement: filter (where) element
    """
    return func.array_lowercase(column) == path


@cache
async def get_domain_sid(session: AsyncSession) -> str:
    """Get domain sid."""
    sid = await session.scalar(select(CatalogueSetting).filter(
        CatalogueSetting.name == 'domain_object_sid'))

    return sid.value


@cache
async def get_domain_guid(session: AsyncSession) -> str:
    """Get domain objectGUID."""
    guid = await session.scalar(select(CatalogueSetting).filter(
        CatalogueSetting.name == 'domain_object_guid'))

    return guid.value


def string_to_sid(sid_string: str) -> bytes:
    """Convert a string representation of a SID to its binary form.

    The conversion process includes:
    1. Parsing the string to extract the SID components (revision,
    identifier authority, and sub-authorities).
    2. Packing these components into a byte sequence:
        - The revision is packed as a single byte.
        - The number of sub-authorities is packed as a single byte.
        - The identifier authority is packed as a 6-byte sequence.
        - Each sub-authority is packed as a 4-byte sequence.

    :param sid_string: The string representation of the SID
    :return bytes: The binary representation of the SID
    """
    parts = sid_string.split('-')

    revision = int(parts[1])
    identifier_authority = int(parts[2])

    sub_authorities = [int(part) for part in parts[3:]]
    sub_auth_count = len(sub_authorities)

    sid = struct.pack('<B', revision)
    sid += struct.pack('B', sub_auth_count)

    sid += struct.pack('>Q', identifier_authority)[2:]

    for sub_auth in sub_authorities:
        sid += struct.pack('<I', sub_auth)

    return sid


async def create_object_sid(
        session: AsyncSession, rid: int, reserved: bool = False) -> str:
    """Generate the objectSid attribute for an object.

    :param session: db
    :param int rid: relative identifier
    :param bool reserved: A flag indicating whether the RID is reserved.
                          If `True`, the given RID is used directly. If
                          `False`, 1000 is added to the given RID to generate
                          the final RID
    :return str: the complete objectSid as a string
    """
    return await get_domain_sid(session) + f"-{rid if reserved else 1000+rid}"


def generate_domain_sid() -> str:
    """Generate domain objectSid attr."""
    sub_authorities = [
        random.randint(1000000000, (1 << 32) - 1),
        random.randint(1000000000, (1 << 32) - 1),
        random.randint(100000000, 999999999),
    ]
    return 'S-1-5-21-' + '-'.join(str(part) for part in sub_authorities)


get_class_name = attrgetter('__class__.__name__')


async def get_dn_by_id(id_: int, session: AsyncSession) -> str:
    """Get dn by id.

    >>> await get_dn_by_id(0, session)
    >>> 'cn=groups,dc=example,dc=com'
    """
    query = select(Directory)\
        .join(Directory.path)\
        .filter(Directory.id == id_)\
        .options(selectinload(Directory.path))

    result = await session.scalar(query)

    return get_path_dn(result.path, await get_base_dn(session))



