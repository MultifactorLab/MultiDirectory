"""MFA methods."""

import asyncio
from asyncio import Queue
from typing import Any, Iterable

import httpx
import pytest
from fastapi import FastAPI, WebSocket
from sqlalchemy import select
from sqlalchemy.ext.asyncio import AsyncSession
from starlette.datastructures import URL

from app.api.auth.oauth2 import authenticate_user, create_token
from app.api.auth.router_mfa import get_queue_pool, two_factor_protocol
from app.config import Settings
from app.ldap_protocol.multifactor import MultifactorAPI, get_auth
from app.models import CatalogueSetting


class StubWebSocket(WebSocket):
    """Stub interface for WebSocket."""

    def __init__(self) -> None:
        """Set 3 channels."""
        self.q: Queue[dict] = Queue(maxsize=1)
        self.q1: Queue[dict] = Queue(maxsize=1)
        self.q2: Queue[tuple[int, str | None]] = Queue(maxsize=1)

    async def accept(
        self,
        subprotocol: str | None = ...,
        headers: Iterable[tuple[bytes, bytes]] | None = ...,
    ) -> None:
        """Stub signal method."""

    async def close(self, code: int = 1000, reason: str | None = None) -> None:
        """Server side interface."""
        await self.q2.put((code, reason))

    async def send_json(self, data: Any, mode: str = "text") -> None:
        """Server side interface."""
        await self.q1.put(data)

    async def receive_json(self, mode: str = "text") -> dict:
        """Server side interface."""
        return await self.q.get()

    async def catch_close(self) -> tuple[int, str | None]:
        """Client side interface."""
        return await self.q2.get()

    async def client_send_json(self, data: dict) -> None:
        """Client side interface."""
        await self.q.put(data)

    async def client_receive_json(self) -> dict:
        """Client side interface."""
        return await self.q1.get()

    def url_for(self, __name: str, **path_params: Any) -> URL:
        """Get url."""
        return __name  # type: ignore


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_set_mfa(
        http_client: httpx.AsyncClient,
        session: AsyncSession,
        login_headers: dict) -> None:
    """Set mfa."""
    response = await http_client.post(
        "/multifactor/setup",
        headers=login_headers,
        json={
            'mfa_key': "123",
            'mfa_secret': "123",
            'is_ldap_scope': False,
        },
    )

    assert response.json() is True
    assert response.status_code == 201

    assert await session.scalar(select(CatalogueSetting).filter_by(
        name="mfa_key", value="123"))
    assert await session.scalar(select(CatalogueSetting).filter_by(
        name="mfa_secret", value="123"))


@pytest.mark.asyncio()
@pytest.mark.usefixtures('setup_session')
async def test_connect_mfa(
        app: FastAPI,
        session: AsyncSession,
        http_client: httpx.AsyncClient,
        settings: Settings) -> None:
    """Test websocket mfa."""
    session.add(
        CatalogueSetting(name='mfa_secret', value=settings.SECRET_KEY),
    )
    session.add(CatalogueSetting(name='mfa_key', value='123'))
    await session.commit()

    redirect_url = "example.com"

    class TestMultifactorAPI(MultifactorAPI):
        async def get_create_mfa(
                self,
                username: str,
                callback_url: str,
                uid: int) -> str:
            nonlocal redirect_url
            return redirect_url

    ws = StubWebSocket()

    mfa = await TestMultifactorAPI.from_di(
        await get_auth(session), http_client, settings)

    pool: dict[str, Queue] = {}

    app.dependency_overrides[get_queue_pool] = lambda: pool

    user = await authenticate_user(session, 'user0', 'password')

    assert user

    token = create_token(
        user.id,
        settings.SECRET_KEY,
        settings.ACCESS_TOKEN_EXPIRE_MINUTES,
        grant_type='multifactor',  # type: ignore
        extra_data={'aud': '123'})

    async with asyncio.TaskGroup() as tg:
        tg.create_task(two_factor_protocol(ws, session, mfa, pool, settings))
        message1 = tg.create_task(ws.client_receive_json())

        tg.create_task(ws.client_send_json(
            {'username': 'user0', 'password': 'password'}))
        message2 = tg.create_task(ws.client_receive_json())

        response = await http_client.post('/multifactor/create', data={
            'accessToken': token})

        assert response.json() == {'success': True}

        message3 = tg.create_task(ws.client_receive_json())

    assert message1.result() == {'status': 'connected', 'message': ''}
    assert message2.result() == {'status': 'pending', 'message': redirect_url}
    assert message3.result() == {'status': 'success', 'message': token}
    assert await ws.catch_close() == (1000, None)
