"""Test search with ldaputil."""

import asyncio
from ipaddress import IPv4Address

import pytest
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from app.__main__ import PoolClientHandler
from app.config import Settings
from app.ldap_protocol.utils import get_group, get_groups, is_user_group_valid
from app.models.ldap3 import User
from tests.conftest import TestCreds


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ldap_search(settings: Settings, creds: TestCreds) -> None:
    """Test ldapsearch on server."""
    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-x', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
        '-D', creds.un,
        '-w', creds.pw,
        '-b', 'dc=md,dc=test', 'objectclass=*',
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    raw_data, _ = await proc.communicate()
    data = raw_data.decode().split('\n')
    result = await proc.wait()

    assert result == 0
    assert "dn: cn=groups,dc=md,dc=test" in data
    assert "dn: ou=users,dc=md,dc=test" in data
    assert "dn: cn=user0,ou=users,dc=md,dc=test" in data


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_bind_policy(
        handler: PoolClientHandler,
        session: AsyncSession,
        settings: Settings,
        creds: TestCreds) -> None:
    """Bind with policy."""
    policy = await handler.get_policy(IPv4Address('127.0.0.1'))
    assert policy

    group_dir = await get_group(
        'cn=domain admins,cn=groups,dc=md,dc=test', session)
    policy.groups.append(group_dir.group)
    await session.commit()

    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
        '-D', creds.un, '-x', '-w', creds.pw)

    result = await proc.wait()
    assert result == 0


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_bind_policy_missing_group(
        handler: PoolClientHandler,
        session: AsyncSession,
        settings: Settings,
        creds: TestCreds) -> None:
    """Bind policy fail."""
    policy = await handler.get_policy(IPv4Address('127.0.0.1'))

    assert policy

    user = await session.scalar(
        select(User).filter_by(display_name="user0")
        .options(selectinload(User.groups)))

    policy.groups = await get_groups(
        ['cn=domain admins,cn=groups,dc=md,dc=test'],
        session,
    )
    user.groups.clear()
    await session.commit()

    assert not await is_user_group_valid(user, policy, session)

    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
        '-D', creds.un, '-x', '-w', creds.pw)

    result = await proc.wait()
    assert result == 49


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
@pytest.mark.usefixtures('session')
async def test_ldap_bind(settings: Settings, creds: TestCreds) -> None:
    """Test ldapsearch on server."""
    proc = await asyncio.create_subprocess_exec(
        'ldapsearch',
        '-vvv', '-x', '-h', f'{settings.HOST}', '-p', f'{settings.PORT}',
        '-D', creds.un,
        '-w', creds.pw,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE)

    result = await proc.wait()
    assert result == 0
