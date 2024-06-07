"""KRB5 router."""

from typing import Annotated
from urllib.parse import urljoin

import httpx
import jinja2
from fastapi import Body, HTTPException, Response, status
from fastapi.params import Depends
from fastapi.routing import APIRouter
from pydantic import EmailStr

from api.auth import User, get_current_user
from config import Settings, get_settings
from ldap_protocol.dialogue import Session as LDAPSession
from ldap_protocol.ldap_requests import AddRequest
from ldap_protocol.utils import get_base_dn, get_dn_by_id
from models.database import AsyncSession, get_session

from .utils import get_krb_http_client, ldap_session

krb5_router = APIRouter(prefix='/kerberos', tags=['KRB5 API'])

TEMPLATES = jinja2.Environment(
    loader=jinja2.FileSystemLoader('extra'),
    enable_async=True, autoescape=True)


@krb5_router.post('/setup', response_class=Response)
async def setup_kdc(
    user: Annotated[User, Depends(get_current_user)],
    session: Annotated[AsyncSession, Depends(get_session)],
    ldap_session: Annotated[LDAPSession, Depends(ldap_session)],
    mail: Annotated[EmailStr, Body(example='admin')],
    krbadmin_password: Annotated[str, Body(example='password')],
    admin_password: Annotated[str, Body(example='password')],
    stash_password: Annotated[str, Body(example='password')],
    settings: Annotated[Settings, Depends(get_settings)],
    client: Annotated[httpx.AsyncClient, Depends(get_krb_http_client)],
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
    base_dn = await get_base_dn(session)
    domain = await get_base_dn(session, normal=True)

    krbadmin = 'cn=krbadmin,ou=users,' + base_dn
    services_container = 'ou=services,' + base_dn
    krbgroup = 'cn=krbadmin,cn=groups,' + base_dn

    group = AddRequest.from_dict(krbgroup, {
        "objectClass": ["group", "top", 'posixGroup'],
        'groupType': ['-2147483646'],
        'instanceType': ['4'],
        'description': ["Kerberos administrator's group."],
        'gidNumber': ["800"],
    })

    services = AddRequest.from_dict(
        services_container,
        {"objectClass": ["organizationalUnit", "top", "container"]},
    )

    rkb_user = AddRequest.from_dict(
        krbadmin, password=krbadmin_password,
        attributes={
            "mail": [mail],
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
            "memberOf": [group],
            "sAMAccountName": ['krbadmin'],
            "userPrincipalName": ['krbadmin'],
            "displayName": ["Kerberos Administrator"],
        },
    )

    async with session.begin_nested():
        results = (
            await anext(services.handle(ldap_session, session)),
            await anext(group.handle(ldap_session, session)),
            await anext(rkb_user.handle(ldap_session, session)),
        )
        await session.commit()
        if not all(result.result_code == 0 for result in results):
            await session.rollback()
            raise HTTPException(status.HTTP_409_CONFLICT)

    template = TEMPLATES.get_template('krb5.conf')

    config = await template.render_async(
        domain=domain,
        krbadmin=krbadmin,
        services_container=services_container,
        ldap_uri=settings.KRB5_LDAP_URI,
    )
    krb_config_server = urljoin(str(settings.KRB5_CONFIG_SERVER), 'setup')
    response = await client.post(krb_config_server, json={
        "domain": domain,
        "admin_dn": await get_dn_by_id(user.directory_id, session),
        "services_dn": services_container,
        "krbadmin_dn": krbadmin,
        "krbadmin_password": krbadmin_password,
        "admin_password": admin_password,
        "stash_password": stash_password,
        'krb5_config': config.encode().hex()})

    if response.status_code != status.HTTP_201_CREATED:
        raise HTTPException(status.HTTP_304_NOT_MODIFIED)
