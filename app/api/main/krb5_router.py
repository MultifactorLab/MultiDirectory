from asyncio import gather
from typing import Annotated

from fastapi import Body
from fastapi.params import Depends
from fastapi.routing import APIRouter
from pydantic import EmailStr

from ldap_protocol.dialogue import Session as LDAPSession
from ldap_protocol.ldap_requests import AddRequest
from ldap_protocol.utils import get_base_dn
from models.database import AsyncSession, get_session

from .utils import ldap_session

krb5_router = APIRouter(prefix='/kerberos', tags=['KRB5 API'])


@krb5_router.post('setup')
async def setup_kdc(
    session: Annotated[AsyncSession, Depends(get_session)],
    ldap_session: Annotated[LDAPSession, Depends(ldap_session)],
    mail: Annotated[EmailStr, Body(example='admin')],
    password: Annotated[str, Body(example='password')],
) -> None:
    """Set up KDC server.

    Create data structure in catalogue, generate config files, trigger commands

    - **mail**: krbadmin mail
    - **password**: krbadmin password

    \f
    :param Annotated[EmailStr, Body mail: json, defaults to 'admin')]
    :param Annotated[str, Body password: json, defaults to 'password')]
    :param Annotated[AsyncSession, Depends session: _description_
    :param Annotated[LDAPSession, Depends ldap_session: _description_
    """  # noqa: D301
    base_dn = get_base_dn(session)

    group = AddRequest.from_dict(
        'cn=krbadmin,ou=groups,' + base_dn,
        {
            "objectClass": ["group", "top", 'posixGroup'],
            'groupType': ['-2147483646'],
            'instanceType': ['4'],
            'sAMAccountName': ['krbadmin'],
            'sAMAccountType': ['268435456'],
            'description': ["Kerberos administrator's group."],
            'gidNumber': ["800"],
        },
    )

    services = AddRequest.from_dict(
        'ou=services,' + base_dn,
        {"objectClass": ["organizationalUnit", "top", "container"]},
    )

    user = AddRequest.from_dict(
        'cn=krbadmin,ou=users' + base_dn,
        password=password,
        attributes={
            "mail": mail,
            "objectClass": [
                "user", "top", "person",
                "organizationalPerson",
                "posixAccount",
                "shadowAccount",
                "inetOrgPerson",
            ],
            "loginShell": ["/bin/false"],
            "uidNumber": ["800"],
            "gidNumber": ["800"],
            "givenName": ["Kerberos Administrator"],
            "sn": ["krbadmin"],
            "uid": ["krbadmin"],
            "homeDirectory": ["/home/krbadmin"],
            "groups": ['krbadmin'],
            "sAMAccountName": ['krbadmin'],
            "userPrincipalName": ['krbadmin'],
            "displayName": ["Kerberos Administrator"],
        },
    )

    async with session.begin_nested():
        results = await gather(
            anext(group.handle(ldap_session, session)),
            anext(user.handle(ldap_session, session)),
            anext(services.handle(ldap_session, session)),
        )
        if not all(result.result_code == 0 for result in results):
            await session.rollback()
