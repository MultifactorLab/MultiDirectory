"""Kerberos config server for MultiDirectory integration.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from contextlib import asynccontextmanager
from enum import StrEnum
from typing import Annotated, AsyncIterator

import httpx
from fastapi import Depends
from sqlalchemy import select, update
from sqlalchemy.ext.asyncio import AsyncSession

from config import Settings, get_settings
from models import CatalogueSetting

KERBEROS_STATE_NAME = 'KerberosState'


class KerberosState(StrEnum):
    """KRB state enum."""

    NOT_CONFIGURED = '0'
    READY = '1'
    WAITING_FOR_RELOAD = '2'
    DENIED = '3'


class KerberosMDAPIClient:
    """KRB server integration."""

    client: httpx.AsyncClient

    class KRBAPIError(Exception):
        """API Error."""

    def __init__(self, client: httpx.AsyncClient) -> None:
        """Set client.

        :param httpx.AsyncClient client: httpx
        """
        self.client = client

    async def setup(
        self,
        domain: str,
        admin_dn: str,
        services_dn: str,
        krbadmin_dn: str,
        krbadmin_password: str,
        admin_password: str,
        stash_password: str,
        krb5_config: str,
    ) -> None:
        """Request Setup."""
        response = await self.client.post('setup', json={
            "domain": domain,
            "admin_dn": admin_dn,
            "services_dn": services_dn,
            "krbadmin_dn": krbadmin_dn,
            "krbadmin_password": krbadmin_password,
            "admin_password": admin_password,
            "stash_password": stash_password,
            'krb5_config': krb5_config.encode().hex(),
        })
        if response != 201:
            raise self.KRBAPIError(response.text)

    async def add_principal(self, name: str, password: str) -> None:
        """Add request."""
        response = await self.client.post('principal', json={
            'name': name, 'password': password})

        if response != 201:
            raise self.KRBAPIError(response.json())

    async def get_principal(self, name: str) -> dict:
        """Get request."""
        response = await self.client.post('principal', data={'name': name})
        if response != 200:
            raise self.KRBAPIError(response.json())
        return response.json()

    async def change_principal_password(
            self, name: str, password: str) -> None:
        """Change password request."""
        response = await self.client.patch('principal', json={
            'name': name, 'password': password})
        if response != 201:
            raise self.KRBAPIError(response.json())

    async def create_or_update_principal_pw(
            self, name: str, password: str) -> None:
        """Change password request."""
        response = await self.client.post(
            '/principal/create_or_update', json={
                'name': name, 'password': password})
        if response != 201:
            raise self.KRBAPIError(response.json())

    async def rename_princ(self, name: str, new_name: str) -> None:
        """Rename request."""
        response = await self.client.patch('principal', json={
            'name': name, 'new_name': new_name})
        if response != 200:
            raise self.KRBAPIError(response.json())

    @classmethod
    async def get_krb_http_client(
        cls, settings: Annotated[Settings, Depends(get_settings)],
    ) -> AsyncIterator['KerberosMDAPIClient']:
        """Get async client for DI."""
        async with cls.get_krb_ldap_client(settings) as client:
            yield client

    @classmethod
    @asynccontextmanager
    async def get_krb_ldap_client(
            cls, settings: Settings) -> AsyncIterator['KerberosMDAPIClient']:
        """Get krb client."""
        async with httpx.AsyncClient(
            timeout=30,
            verify="/certs/krbcert.pem",
            base_url=str(settings.KRB5_CONFIG_SERVER),
        ) as client:
            yield cls(client)


class StubKadminMDADPIClient(KerberosMDAPIClient):
    """Stub client for non set up dirs."""

    async def add_principal(self, name: str, password: str) -> None: ...  # noqa

    async def get_principal(self, name: str) -> None: ...  # type: ignore  # noqa

    async def change_principal_password(  # noqa
        self, name: str, password: str) -> None: ...  # noqa

    async def create_or_update_principal_pw(  # noqa
        self, name: str, password: str) -> None: ...  # noqa

    async def rename_princ(self, name: str, new_name: str) -> None: ... # noqa


async def get_krb_server_state(session: AsyncSession) -> 'KerberosState':
    """Get or create server state."""
    state = await session.scalar(
        select(CatalogueSetting)
        .filter(CatalogueSetting.name == KERBEROS_STATE_NAME),
    )

    if state is None:
        session.add(
            CatalogueSetting(
                name=KERBEROS_STATE_NAME,
                value=KerberosState.NOT_CONFIGURED,
            ),
        )
        return KerberosState.NOT_CONFIGURED
    return state.value


async def set_state(session: AsyncSession, state: 'KerberosState') -> None:
    """Set server state in database."""
    await session.execute(
        update(CatalogueSetting)
        .values({"value": state})
        .where(CatalogueSetting.name == KERBEROS_STATE_NAME),
    )


async def get_kerberos_class(
    session: AsyncSession,
) -> type[KerberosMDAPIClient] | type[StubKadminMDADPIClient]:
    """Get kerberos server state.

    :param AsyncSession session: db
    :return type[KerberosMDAPIClient] | type[StubKadminMDADPIClient]: api
    """
    if await get_krb_server_state(session) == KerberosState.READY:
        return KerberosMDAPIClient
    return StubKadminMDADPIClient
