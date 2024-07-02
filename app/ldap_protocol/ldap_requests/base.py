"""LDAP message abstract structure.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from abc import ABC, abstractmethod
from typing import TYPE_CHECKING, AsyncGenerator, Protocol

from loguru import logger
from pydantic import BaseModel
from sqlalchemy.ext.asyncio import AsyncSession

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import Session, User
from ldap_protocol.ldap_responses import BaseResponse
from ldap_protocol.utils import get_class_name

log_api = logger.bind(name='admin')

log_api.add(
    "logs/admin_{time:DD-MM-YYYY}.log",
    filter=lambda rec: rec["extra"].get("name") == 'admin',
    retention="10 days",
    rotation="1d",
    colorize=False)


if TYPE_CHECKING:
    class _APIProtocol(Protocol):
        """Protocol for API handling."""

        async def _handle_api(
            self, user: User,
            session: AsyncSession,
        ) -> list[BaseResponse] | BaseResponse: ...
else:
    class _APIProtocol: ...  # noqa


class BaseRequest(ABC, BaseModel, _APIProtocol):
    """Base request builder."""

    @property
    @abstractmethod
    def PROTOCOL_OP(self) -> int:  # noqa: N802, D102
        """Protocol OP response code."""

    @classmethod
    @abstractmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> 'BaseRequest':
        """Create structure from ASN1Row dataclass list."""
        raise NotImplementedError(f'Tried to access {cls.PROTOCOL_OP}')

    @abstractmethod
    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[BaseResponse, None]:
        """Handle message with current user."""
        yield BaseResponse()

    async def _handle_api(
        self, ldap_session: Session,
        session: AsyncSession,
    ) -> list[BaseResponse]:
        """Hanlde response with api user.

        :param DBUser user: user from db
        :param AsyncSession session: db session
        :return list[BaseResponse]: list of handled responses
        """
        un = getattr(ldap_session.user, 'user_principal_name', 'ANONYMOUS')

        if ldap_session.settings.DEBUG:
            log_api.info(self.model_dump_json(indent=4))
        else:
            log_api.info(f"{get_class_name(self)}[{un}]")

        responses = [
            response async for response in self.handle(ldap_session, session)]

        if ldap_session.settings.DEBUG:
            for response in responses:
                log_api.info(response.model_dump_json(indent=4))
        else:
            for response in responses:
                log_api.info(f"{get_class_name(response)}[{un}]")

        return responses

    async def handle_api(
        self, ldap_session: Session,
        session: AsyncSession,
    ) -> BaseResponse:
        """Get single response."""
        return (await self._handle_api(ldap_session, session))[0]


class APIMultipleResponseMixin(_APIProtocol):
    """Get multiple responses."""

    async def handle_api(
        self, user: User,
        session: AsyncSession,
    ) -> list[BaseResponse]:
        """Get all responses."""
        return await self._handle_api(user, session)
