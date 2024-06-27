"""Kerberos config server for MultiDirectory integration.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from contextlib import asynccontextmanager
from typing import Annotated, AsyncIterator

import httpx
from fastapi import Depends

from config import Settings, get_settings


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
        async with httpx.AsyncClient(
            timeout=30,
            verify="/certs/krbcert.pem",
            base_url=settings.KRB5_CONFIG_SERVER,
        ) as client:
            yield cls(client)

    get_krb_ldap_client = asynccontextmanager(get_krb_http_client)


class StubKadminMDADPIClient(KerberosMDAPIClient):
    """Stub client for non set up dirs."""

    async def get_principal(*args, **kwargs) -> ...: ...
    async def change_principal_password(*args, **kwargs) -> ...: ...
    async def create_or_update_principal_pw(*args, **kwargs) -> ...: ...
    async def rename_princ(*args, **kwargs) -> ...: ...
