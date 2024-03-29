"""Network policies."""

import asyncio
import operator
import traceback
from json import JSONDecodeError
from typing import Annotated
from urllib.parse import urlsplit, urlunsplit

from fastapi import (
    Depends,
    Form,
    HTTPException,
    WebSocket,
    WebSocketDisconnect,
    status,
)
from fastapi.routing import APIRouter
from jose import JWTError, jwt
from jose.exceptions import JWKError
from loguru import logger
from pydantic import ValidationError
from sqlalchemy import delete

from api.auth import get_current_user
from config import Settings, get_queue_pool, get_settings
from ldap_protocol.multifactor import (
    Creds,
    MultifactorAPI,
    get_auth,
    get_auth_ldap,
)
from models.database import AsyncSession, get_session
from models.ldap3 import CatalogueSetting
from models.ldap3 import User as DBUser

from .oauth2 import ALGORITHM, authenticate_user
from .schema import Login, MFACreateRequest, MFAGetResponse

mfa_router = APIRouter(prefix='/multifactor', tags=['Multifactor'])


@mfa_router.post(
    '/setup', status_code=status.HTTP_201_CREATED,
    dependencies=[Depends(get_current_user)])
async def setup_mfa(
    mfa: MFACreateRequest,
    session: Annotated[AsyncSession, Depends(get_session)],
) -> bool:
    """Set mfa credentials, rewrites if exists.

    \f
    :param str mfa_key: multifactor key
    :param Annotated[bool, Body is_ldap_scope: _description_, defaults to True
    :param str mfa_secret: multifactor api secret
    :return bool: status
    """  # noqa: D205, D301
    async with session.begin_nested():
        await session.execute((
            delete(CatalogueSetting)
            .filter(operator.or_(
                CatalogueSetting.name == mfa.key_name,
                CatalogueSetting.name == mfa.secret_name,
            ))
        ))
        await session.flush()
        session.add(CatalogueSetting(name=mfa.key_name, value=mfa.mfa_key))
        session.add(
            CatalogueSetting(name=mfa.secret_name, value=mfa.mfa_secret))
        await session.commit()

    return True


@mfa_router.post('/get', dependencies=[Depends(get_current_user)])
async def get_mfa(
    mfa_creds: Annotated[Creds | None, Depends(get_auth)],
    mfa_creds_ldap: Annotated[Creds | None, Depends(get_auth_ldap)],
) -> MFAGetResponse:
    """Get MFA creds.

    \f
    :return MFAGetResponse: response
    """  # noqa: D205, D301
    if not mfa_creds:
        mfa_creds = Creds(None, None)
    if not mfa_creds_ldap:
        mfa_creds_ldap = Creds(None, None)

    return MFAGetResponse(
        mfa_key=mfa_creds.key,
        mfa_secret=mfa_creds.secret,
        mfa_key_ldap=mfa_creds_ldap.key,
        mfa_secret_ldap=mfa_creds_ldap.secret,
    )


@mfa_router.post('/create', name='callback_mfa', include_in_schema=False)
async def callback_mfa(
    access_token: Annotated[str, Form(alias='accessToken')],
    pool: Annotated[dict[str, asyncio.Queue[str]], Depends(get_queue_pool)],
    session: Annotated[AsyncSession, Depends(get_session)],
    mfa_creds: Annotated[Creds | None, Depends(get_auth)],
) -> dict:
    """Disassemble mfa token and send it to websocket.

    Callback endpoint for MFA.

    \f
    :param Annotated[str, Form access_token: access token from multifactor
    :param str | None mfa_secret: multifactor secret from settings
    :raises HTTPException: 404
    :return dict: status
    """  # noqa: D205, D301
    if not mfa_creds:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    logger.debug((access_token, mfa_creds.secret, mfa_creds.key))
    try:
        payload = jwt.decode(
            access_token,
            mfa_creds.secret,
            audience=mfa_creds.key,
            algorithms=ALGORITHM)
    except (JWTError, AttributeError, JWKError) as err:
        raise HTTPException(
            status.HTTP_422_UNPROCESSABLE_ENTITY,
            f"Invalid token {err}",
        )

    user_id: int = int(payload.get("uid"))
    if user_id is None:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    user = await session.get(DBUser, user_id)

    if not user:
        raise HTTPException(status.HTTP_404_NOT_FOUND)

    queue = pool.get(user.user_principal_name)
    if not queue:
        raise HTTPException(status.HTTP_408_REQUEST_TIMEOUT)

    await queue.put(access_token)
    logger.debug(access_token)

    return {'success': True}


@mfa_router.websocket('/connect')
async def two_factor_protocol(
    websocket: WebSocket,
    session: Annotated[AsyncSession, Depends(get_session)],
    api: Annotated[MultifactorAPI, Depends(MultifactorAPI.from_di)],
    pool: Annotated[dict[str, asyncio.Queue[str]], Depends(get_queue_pool)],
    settings: Annotated[Settings, Depends(get_settings)],
) -> None:
    """Authenticate with two factor app.

    Protocol description:
    1. Sends `{'status': 'connected', 'message': ''}`;
    2. Recieves json `{'username': 'un', 'password': 'pwd'}`;
    3. Sends `{'status': 'pending', 'message': 'https://example.com'}`
        where message is an any redirect url;
    4. Websocket goes to pending state and waits for MFA api callback send;
    5. Sends `{'status': 'success', 'message': token}` where token is
        a mfa access and refresh token;

    \f
    :param WebSocket websocket: websocket
    :param MultifactorAPI api: MF API, depends
    :param dict[str, Queue[str]] pool: queue pool for async comms, depends
    """  # noqa: D205, D301
    await websocket.accept()
    if not api:
        await websocket.close(
            status.WS_1002_PROTOCOL_ERROR, 'Missing API credentials')
        return

    await websocket.send_json({'status': 'connected', 'message': ''})

    try:
        creds = Login.model_validate(await websocket.receive_json())
        user = await authenticate_user(session, creds.username, creds.password)
    except (ValidationError, UnicodeDecodeError, JSONDecodeError) as err:
        await websocket.close(
            status.WS_1007_INVALID_FRAME_PAYLOAD_DATA,
            f'Invalid data: {err}',
        )
        return

    if not user:
        await websocket.close(
            status.WS_1002_PROTOCOL_ERROR, 'Invalid credentials')
        return

    try:
        url = list(urlsplit(str(websocket.url_for('callback_mfa'))))
        url[0] = "https" if settings.USE_CORE_TLS else "http"

        redirect_url = await api.get_create_mfa(
            user.user_principal_name, urlunsplit(url), user.id)

    except MultifactorAPI.MultifactorError:
        logger.critical(f"API error {traceback.format_exc()}")
        await websocket.close(
            status.WS_1013_TRY_AGAIN_LATER, 'Multifactor error')
        return

    await websocket.send_json({'status': 'pending', 'message': redirect_url})

    queue: asyncio.Queue[str] = asyncio.Queue(maxsize=1)
    pool[user.user_principal_name] = queue

    try:
        token = await asyncio.wait_for(
            queue.get(),
            timeout=settings.MFA_TIMEOUT_SECONDS,
        )
    except TimeoutError:
        await websocket.close(
            status.WS_1013_TRY_AGAIN_LATER, 'To factor timeout')
        return
    except WebSocketDisconnect:
        logger.warning(f'Two factor interrupt for {user.user_principal_name}')
        return
    finally:
        del pool[user.user_principal_name]

    await websocket.send_json({'status': 'success', 'message': token})

    await websocket.close()
