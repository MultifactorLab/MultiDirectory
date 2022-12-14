"""LDAP requests structure bind."""

import asyncio
import sys
from abc import ABC, abstractmethod
from collections import defaultdict
from typing import AsyncGenerator, ClassVar

from pydantic import BaseModel, Field, validator
from sqlalchemy.future import select

from config import settings
from models.database import async_session
from models.ldap3 import CatalogueSetting, Path, User

from .asn1parser import ASN1Row
from .dialogue import LDAPCodes, Session
from .ldap_responses import (
    BaseResponse,
    BindResponse,
    PartialAttribute,
    SearchResultDone,
    SearchResultEntry,
    SearchResultReference,
)
from .objects import DerefAliases, Scope


class BaseRequest(ABC, BaseModel):
    """Base request builder."""

    @property
    @abstractmethod
    def PROTOCOL_OP(self) -> int:  # noqa: N802, D102
        """Protocol OP response code."""

    @classmethod
    @abstractmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> 'BaseRequest':
        """Create structure from ASN1Row dataclass list."""
        raise NotImplementedError()

    @abstractmethod
    async def handle(self, ldap_session: Session) -> \
            AsyncGenerator[BaseResponse, None]:
        """Handle message with current user."""
        yield BaseResponse()  # type: ignore


class AuthChoice(ABC, BaseModel):
    """Auth base class."""

    @abstractmethod
    def is_valid(self, user: User):
        """Validate state."""


class SimpleAuthentication(AuthChoice):
    """Simple auth form."""

    password: str

    def is_valid(self, user: User):
        return self.password == user.password


class SaslAuthentication(AuthChoice):
    """Sasl auth form."""

    mechanism: str
    credentials: bytes


class BindRequest(BaseRequest):
    """Bind request fields mapping."""

    PROTOCOL_OP: ClassVar[int] = 0x0

    version: int
    name: str
    authentication_choice: SimpleAuthentication | SaslAuthentication =\
        Field(..., alias='AuthenticationChoice')

    @classmethod
    def from_data(cls, data) -> 'BindRequest':
        """Get bind from data dict."""
        auth = data['field-1'][1].tag_id.value
        auth_data = data['field-2']

        if auth == 0:
            auth_choice = SimpleAuthentication(password=auth_data[2].value)
        elif auth == 3:  # noqa: R506
            raise NotImplementedError('Sasl not supported')  # TODO: Add SASL
        else:
            raise ValueError('Auth version not supported')

        return cls(
            version=auth_data[0].value,
            name=auth_data[1].value,
            AuthenticationChoice=auth_choice,
        )

    def get_domain(self):
        """Get domain from name."""
        return '.'.join([
            item[3:].lower() for item in self.name.split(',')
            if item[:2] in ('DC', 'dc')
        ])

    def get_path(self):
        """Get path from name."""
        return [
            item.lower() for item in reversed(self.name.split(','))
            if not item[:2] in ('DC', 'dc')
        ]

    async def handle(self, ldap_session: Session) -> \
            AsyncGenerator[BindResponse, None]:
        """Handle bind request, check user and password."""
        if ldap_session.name:
            raise ValueError('User authed')

        async with async_session() as session:
            res = await session.execute(
                select(Path).where(Path.path == self.get_path()))
            path = res.scalar()
            domain_res = await session.execute(
                select(CatalogueSetting)
                .where(CatalogueSetting.name == 'defaultNamingContext'))

            domain = domain_res.scalar()

            if not domain or not path:
                yield BindResponse(
                    resultCode=LDAPCodes.INVALID_CREDENTIALS,
                    matchedDN=domain.value if domain else '',
                    errorMessage='Path is invalid',
                )
                return

            user_res = await session.execute(
                select(User).where(User.directory == path.endpoint))
            user = user_res.scalar()

            if not user:
                yield BindResponse(
                    resultCode=LDAPCodes.INVALID_CREDENTIALS,
                    matchedDN=domain.value,
                    errorMessage='User not found',
                )
                return

            if not self.authentication_choice.is_valid(user):
                yield BindResponse(
                    resultCode=LDAPCodes.INVALID_CREDENTIALS,
                    matchedDN=domain.value,
                    errorMessage='Invalid password',
                )
                return

        ldap_session.name = domain.value
        ldap_session.user = user
        yield BindResponse(
            resultCode=LDAPCodes.SUCCESS,
            matchedDn=domain.value)


class UnbindRequest(BaseRequest):
    """Remove user from ldap_session."""

    PROTOCOL_OP: ClassVar[int] = 2

    @classmethod
    def from_data(cls, data: dict[str, list[ASN1Row]]) -> 'UnbindRequest':
        """Unbind request has no body."""
        return cls()

    async def handle(self, ldap_session: Session) -> \
            AsyncGenerator[BaseResponse, None]:
        """Handle unbind request, no need to send response."""
        if not ldap_session.user:
            raise ValueError('User not authed')
        ldap_session.name = None
        ldap_session.user = None
        return  # declare empty async generator and exit
        yield


class SearchRequest(BaseRequest):
    """Search request schema.

    SearchRequest ::= [APPLICATION 3] SEQUENCE {
    baseObject      LDAPDN,
    scope           ENUMERATED {
        baseObject              (0),
        singleLevel             (1),
        wholeSubtree            (2),
        subordinateSubtree      (3),
    },
    derefAliases    ENUMERATED {
        neverDerefAliases       (0),
        derefInSearching        (1),
        derefFindingBaseObj     (2),
        derefAlways             (3) },
    sizeLimit       INTEGER (0 ..  maxInt),
    timeLimit       INTEGER (0 ..  maxInt),
    typesOnly       BOOLEAN,
    filter          Filter,
    attributes      AttributeSelection
    }
    """

    PROTOCOL_OP: ClassVar[int] = 3

    base_object: str | None
    scope: Scope
    deref_aliases: DerefAliases
    size_limit: int = Field(ge=0, le=sys.maxsize)
    time_limit: int = Field(ge=0, le=sys.maxsize)
    types_only: bool
    filter: str  # noqa: A003
    attributes: list[str]

    @classmethod
    def from_data(cls, data):  # noqa: D102
        (
            base_object,
            scope,
            deref_aliases,
            size_limit,
            time_limit,
            types_only,
            filter_,
            attributes_link,
        ) = data['field-2'][:8]

        return cls(
            base_object=base_object.value,
            scope=int(scope.value),
            deref_aliases=int(deref_aliases.value),
            size_limit=size_limit.value,
            time_limit=time_limit.value,
            types_only=types_only.value,
            filter=filter_.value,
            attributes=[field.value for field in data[attributes_link.value]],
        )

    @validator('base_object')
    def empty_str_to_none(cls, v):  # noqa: N805
        """Set base_object value to None if it's value is empty str."""
        if v == '':
            return None
        return v

    @staticmethod
    async def get_root_dse(attributes: list[str])\
            -> defaultdict[str, list[str]]:
        """Get RootDSE.

        :param list[str] attributes: list of requested attrs
        :return defaultdict[str, list[str]]: queried attrs
        """
        async with async_session() as session:
            data = defaultdict(list)
            clause = [CatalogueSetting.name == name for name in attributes]
            res = await session.execute(
                select(CatalogueSetting).where(*clause))
            for setting in res.scalar():
                data[setting.name].append(setting.value)

        if 'vendorName' in attributes:
            data['vendorName'].append(settings.VENDOR_NAME)

        if 'vendorVersion' in attributes:
            data['vendorVersion'].append(settings.VENDOR_VERSION)

        return data

    async def handle(
        self, ldap_session: Session,
    ) -> AsyncGenerator[
        SearchResultDone | SearchResultReference | SearchResultEntry, None,
    ]:
        """Search tree.

        Provides following responses:
        Entry -> Reference (optional) -> Done
        """
        await asyncio.sleep(0)
        if self.filter == "objectClass=*":
            attrs = await self.get_root_dse(self.attributes)

            yield SearchResultEntry(
                object_name='',
                partial_attributes=[
                    PartialAttribute(type=name, vals=values)
                    for name, values in attrs.items()],
            )
        yield SearchResultDone(resultCode=0)


class ModifyRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 6


class AddRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 8


class DeleteRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 10


class ModifyDNRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 12


class CompareRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 14


class AbandonRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 16


class ExtendedRequest(BaseRequest):
    PROTOCOL_OP: ClassVar[int] = 23


protocol_id_map: dict[int, type[BaseRequest]] = \
    {request.PROTOCOL_OP: request  # type: ignore
        for request in BaseRequest.__subclasses__()}


#     7: 'Modify Response',
#     9: 'Add Response',
#     11: 'Delete Response',
#     13: 'Modify DN Response',
#     15: 'compare Response',
#     19: 'Search Result Reference',
#     24: 'Extended Response',
#     25: 'intermediate Response',
