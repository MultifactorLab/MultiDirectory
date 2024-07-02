"""Codes mapping.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from contextlib import AsyncExitStack, asynccontextmanager, suppress
from enum import IntEnum
from ipaddress import IPv4Address, ip_address
from types import TracebackType
from typing import TYPE_CHECKING, AsyncIterator

import httpx
from loguru import logger
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings
from ldap_protocol.kerberos import KerberosMDAPIClient
from ldap_protocol.multifactor import MultifactorAPI, get_auth_ldap
from models.ldap3 import NetworkPolicy, User

if TYPE_CHECKING:
    from .messages import LDAPRequestMessage


class Operation(IntEnum):
    """Changes enum for modify request."""

    ADD = 0
    DELETE = 1
    REPLACE = 2


class LDAPCodes(IntEnum):
    """LDAP protocol codes mapping.

    SUCCESS = 0
    OPERATIONS_ERROR = 1
    PROTOCOL_ERROR = 2
    TIME_LIMIT_EXCEEDED = 3
    SIZE_LIMIT_EXCEEDED = 4
    COMPARE_FALSE = 5
    COMPARE_TRUE = 6
    AUTH_METHOD_NOT_SUPPORTED = 7
    STRONGER_AUTH_REQUIRED = 8
    # -- 9 reserved --
    REFERRAL = 10
    ADMIN_LIMIT_EXCEEDED = 11
    UNAVAILABLE_CRITICAL_EXTENSION = 12
    CONFIDENTIALITY_REQUIRED = 13
    SASL_BIND_IN_PROGRESS = 14
    NO_SUCH_ATTRIBUTE = 16
    UNDEFINED_ATTRIBUTE_TYPE = 17
    INAPPROPRIATE_MATCHING = 18
    CONSTRAINT_VIOLATION = 19
    ATTRIBUTE_OR_VALUE_EXISTS = 20
    INVALID_ATTRIBUTE_SYNTAX = 21
    # -- 22-31 unused --
    NO_SUCH_OBJECT = 32
    ALIAS_PROBLEM = 33
    INVALID_DN_SYNTAX = 34
    # -- 35 reserved for undefined isLeaf --
    ALIAS_DEREFERENCING_PROBLEM = 36
    # -- 37-47 unused --
    INAPPROPRIATE_AUTHENTICATION = 48
    INVALID_CREDENTIALS = 49
    INSUFFICIENT_ACCESS_RIGHTS = 50
    BUSY = 51
    UNAVAILABLE = 52
    UNWILLING_TO_PERFORM = 53
    LOOP_DETECT = 54
    # -- 55-63 unused --
    NAMING_VIOLATION = 64
    OBJECT_CLASS_VIOLATION = 65
    NOT_ALLOWED_ON_NON_LEAF = 66
    NOT_ALLOWED_ON_RDN = 67
    ENTRY_ALREADY_EXISTS = 68
    OBJECT_CLASS_MODS_PROHIBITED = 69
    # -- 70 reserved for CLDAP --
    AFFECTS_MULTIPLE_DS_AS = 71
    # -- 72-79 unused --
    OTHER = 80
    """

    SUCCESS = 0
    OPERATIONS_ERROR = 1
    PROTOCOL_ERROR = 2
    TIME_LIMIT_EXCEEDED = 3
    SIZE_LIMIT_EXCEEDED = 4
    COMPARE_FALSE = 5
    COMPARE_TRUE = 6
    AUTH_METHOD_NOT_SUPPORTED = 7
    STRONGER_AUTH_REQUIRED = 8
    # -- 9 reserved --
    REFERRAL = 10
    ADMIN_LIMIT_EXCEEDED = 11
    UNAVAILABLE_CRITICAL_EXTENSION = 12
    CONFIDENTIALITY_REQUIRED = 13
    SASL_BIND_IN_PROGRESS = 14
    NO_SUCH_ATTRIBUTE = 16
    UNDEFINED_ATTRIBUTE_TYPE = 17
    INAPPROPRIATE_MATCHING = 18
    CONSTRAINT_VIOLATION = 19
    ATTRIBUTE_OR_VALUE_EXISTS = 20
    INVALID_ATTRIBUTE_SYNTAX = 21
    # -- 22-31 unused --
    NO_SUCH_OBJECT = 32
    ALIAS_PROBLEM = 33
    INVALID_DN_SYNTAX = 34
    # -- 35 reserved for undefined isLeaf --
    ALIAS_DEREFERENCING_PROBLEM = 36
    # -- 37-47 unused --
    INAPPROPRIATE_AUTHENTICATION = 48
    INVALID_CREDENTIALS = 49
    INSUFFICIENT_ACCESS_RIGHTS = 50
    BUSY = 51
    UNAVAILABLE = 52
    UNWILLING_TO_PERFORM = 53
    LOOP_DETECT = 54
    # -- 55-63 unused --
    NAMING_VIOLATION = 64
    OBJECT_CLASS_VIOLATION = 65
    NOT_ALLOWED_ON_NON_LEAF = 66
    NOT_ALLOWED_ON_RDN = 67
    ENTRY_ALREADY_EXISTS = 68
    OBJECT_CLASS_MODS_PROHIBITED = 69
    # -- 70 reserved for CLDAP --
    AFFECTS_MULTIPLE_DS_AS = 71
    # -- 72-79 unused --
    OTHER = 80


class Session:
    """Session for one client handling."""

    ip: IPv4Address
    addr: str
    reader: asyncio.StreamReader
    writer: asyncio.StreamWriter
    policy: NetworkPolicy | None
    client: httpx.AsyncClient
    settings: Settings

    _mfa_api_class: type[MultifactorAPI] = MultifactorAPI
    _kerberos_api_class: type[KerberosMDAPIClient] = KerberosMDAPIClient

    def __init__(
        self,
        reader: asyncio.StreamReader | None = None,
        writer: asyncio.StreamWriter | None = None,
        user: User | None = None,
        settings: Settings | None = None,
    ) -> None:
        """Set lock."""
        self._lock = asyncio.Lock()
        self._user: User | None = user
        self.queue: asyncio.Queue['LDAPRequestMessage'] = asyncio.Queue()

        if settings:
            self.settings = settings

        if reader and writer:
            self.reader = reader
            self.writer = writer

            self.addr = ':'.join(
                map(str, self.writer.get_extra_info('peername')))
            self.ip = ip_address(self.addr.split(':')[0])  # type: ignore

    @property
    def user(self) -> User | None:
        """User getter, not implemented."""
        return self._user

    @user.setter
    def user(self, user: User) -> None:
        raise NotImplementedError(
            'Cannot manually set user, use `set_user()` instead')

    async def set_user(self, user: User) -> None:
        """Bind user to session concurrently save."""
        async with self._lock:
            self._user = user

    async def delete_user(self) -> None:
        """Unbind user from session concurrently save."""
        async with self._lock:
            self._user = None

    async def get_user(self) -> User:
        """Get user from session concurrently save."""
        async with self._lock:
            return self._user

    @asynccontextmanager
    async def lock(self) -> AsyncIterator[User]:
        """Lock session, user cannot be deleted or get while lock is set."""
        async with self._lock:
            yield self._user

    async def __aenter__(self) -> 'Session':  # noqa
        self.stack = await AsyncExitStack().__aenter__()
        self.client = await self.stack.enter_async_context(httpx.AsyncClient())
        self.kadmin = await self.stack.enter_async_context(
            self._kerberos_api_class.get_krb_ldap_client(self.settings))
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Close writer and queue."""
        with suppress(RuntimeError):
            await self.queue.join()
            self.writer.close()
            await self.writer.wait_closed()

        await self.stack.__aexit__(exc_type, exc, tb)
        logger.success(f'Connection {self.addr} closed')

    async def check_mfa(
        self,
        identity: str,
        otp: str,
        session: AsyncSession,
    ) -> bool:
        """Check mfa api.

        :param User user: db user
        :param Session ldap_session: ldap session
        :param AsyncSession session: db session
        :return bool: response
        """
        creds = await get_auth_ldap(session)

        if creds is None:
            return False

        api = self._mfa_api_class(
            creds.key, creds.secret,
            client=self.client,
            settings=self.settings,
        )
        try:
            return await api.ldap_validate_mfa(identity, otp)
        except MultifactorAPI.MultifactorError as err:
            logger.critical(f'MFA failed with {err}')
            return False
