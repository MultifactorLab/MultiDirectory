"""MFA integration."""
import asyncio
from collections import namedtuple
from json import JSONDecodeError
from typing import Annotated

import httpx
from fastapi import Depends
from loguru import logger
from sqlalchemy import select
from starlette.datastructures import URL

from config import Settings, get_settings
from models.database import AsyncSession, get_session
from models.ldap3 import CatalogueSetting

Creds = namedtuple('Creds', ['key', 'secret'])


class _MultifactorError(Exception):
    """MFA exc."""


async def get_auth(
    session: Annotated[AsyncSession, Depends(get_session)],
) -> Creds | None:
    """Get API creds.

    :return tuple[str, str]: api key and secret
    """
    q1 = select(CatalogueSetting).filter_by(name='mfa_key')
    q2 = select(CatalogueSetting).filter_by(name='mfa_secret')

    key, secret = await asyncio.gather(session.scalar(q1), session.scalar(q2))

    if not key or not secret:
        return None

    return Creds(key.value, secret.value)


async def get_client():
    """Get async client for DI."""
    async with httpx.AsyncClient() as client:
        yield client


class MultifactorAPI:
    """Multifactor integration."""

    MultifactorError = _MultifactorError

    CHECK_URL = "/requests/ra"
    CREATE_URL = "/requests"

    client: httpx.AsyncClient
    settings: Settings

    def __init__(
            self, key: str, secret: str,
            client: httpx.AsyncClient, settings: Settings):
        """Set creds and web client.

        :param str key: _description_
        :param str secret: _description_
        :param httpx.AsyncClient client: _description_
        :param Settings settings: _description_
        """
        self.client = client
        self.settings = settings
        self.auth: tuple[str] = (key, secret)

    async def ldap_validate_mfa(self, username: str, password: str) -> bool:
        """Validate multifactor.

        :param str username: un
        :param str password: pwd
        :raises MultifactorError: connect timeout
        :raises MultifactorError: invalid json
        :raises MultifactorError: Invalid status
        :return bool: status
        """
        try:
            response = await self.client.post(
                self.settings.MFA_API_URI + self.CHECK_URL,
                auth=self.auth,
                json={"Identity": username, "passCode": password}, timeout=42)

            data = response.json()
        except httpx.ConnectTimeout as err:
            raise self.MultifactorError('API Timeout') from err
        except JSONDecodeError as err:
            raise self.MultifactorError('Invalid json') from err

        if response.status_code != 200:
            raise self.MultifactorError('Status error')

        if data['success'] is not True:
            return False
        return True

    async def get_create_mfa(
            self, username: str, callback_url: URL, uid: int) -> str:
        """Create mfa link.

        :param str username: un
        :param str callback_url: callback uri to send token
        :param int uid: user id
        :raises self.MultifactorError: on invalid json, Key or timeout
        :return str: url to open in new page
        """
        data = {
            "identity": username,
            "claims": {
                "uid": str(uid),
                "grant_type": "multifactor",
            },
            "callback": {
                "action": str(callback_url),
                "target": "_self",
            },
        }
        try:
            logger.debug(data)

            response = await self.client.post(
                self.settings.MFA_API_URI + self.CREATE_URL,
                auth=self.auth,
                json=data)

            response_data = response.json()
            logger.info(response_data)
            return response_data['model']['url']

        except (httpx.TimeoutException, JSONDecodeError, KeyError) as err:
            raise self.MultifactorError(f'MFA API error: {err}') from err

    @classmethod
    async def from_di(
        cls,
        credentials: Annotated[Creds, Depends(get_auth)],
        client: Annotated[httpx.AsyncClient, Depends(get_client)],
        settings: Annotated[Settings, Depends(get_settings)],
    ) -> 'MultifactorAPI':
        """Get api from DI.

        :param httpx.AsyncClient client: httpx client
        :param Creds credentials: creds
        :return MultifactorAPI: mfa integration
        """
        if credentials is None:
            return None
        return cls(credentials.key, credentials.secret, client, settings)