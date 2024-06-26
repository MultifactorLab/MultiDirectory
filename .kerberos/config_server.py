"""Simple server for executing krb5 commands.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import asyncio
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import datetime, timedelta
from types import TracebackType
from typing import Annotated, AsyncIterator, Protocol

import kadmin_local as kadmin
from fastapi import (
    Body,
    Depends,
    FastAPI,
    HTTPException,
    Request,
    Response,
    status,
)
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel


class KAdminProtocol(Protocol):
    """Stub for kadmin.KAdmin."""


class PrincipalProtocol(Protocol):
    """Stub for kadmin.Principal."""


class ConfigSchema(BaseModel):
    """Main Config."""

    domain: str
    admin_dn: str
    krbadmin_dn: str
    services_dn: str
    krbadmin_password: str
    admin_password: str
    stash_password: str
    krb5_config: str


class Principal(BaseModel):
    """Principal kadmin object."""

    kvno: int
    name: str
    failures: int
    last_failure: datetime | None
    last_pwd_change: datetime | None
    last_success: datetime | None
    maxrenewlife: timedelta
    mod_date: datetime
    pwexpire: datetime | None


class AbstractKRBManager(AbstractAsyncContextManager, ABC):
    """Kadmin manager."""

    class PrincipalNotFoundError(Exception):
        """Not found error."""

    @abstractmethod
    async def add_princ(
            self, name: str, password: str | None, **dbargs) -> None:
        """Create principal.

        :param str name: principal
        :param str | None password: if empty - uses randkey.
        """

    @abstractmethod
    async def get_princ(self, name: str) -> Principal | None:
        """Get principal.

        :param str name: principal
        :return kadmin.Principal: Principal
        """

    @abstractmethod
    async def change_password(self, name: str, new_password: str) -> None:
        """Chanage principal's password.

        :param str name: principal
        :param str new_password: ...
        """

    @abstractmethod
    async def del_princ(self, name: str) -> None:
        """Delete principal by name.

        :param str name: principal
        """

    @abstractmethod
    async def rename_princ(self, name: str, new_name: str) -> None:
        """Rename principal.

        :param str name: original name
        :param str new_name: new name
        """


class KAdminLocalManager(AbstractKRBManager):
    """Kadmin manager."""

    client: KAdminProtocol

    def __init__(self, loop: asyncio.AbstractEventLoop | None = None) -> None:
        """Create threadpool and get loop."""
        self.loop = loop or asyncio.get_running_loop()

    async def __aenter__(self) -> "KAdminLocalManager":
        """Create threadpool for kadmin client."""
        self.pool = ThreadPoolExecutor(max_workers=500).__enter__()
        self.client = await self.init_client()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Destroy threadpool."""
        self.pool.__exit__(exc_type, exc, tb)

    async def init_client(self) -> KAdminProtocol:
        """Init kadmin local connection."""
        return await self.loop.run_in_executor(self.pool, kadmin.local)

    async def add_princ(
            self, name: str, password: str | None, **dbargs) -> None:
        """Create principal.

        :param str name: principal
        :param str | None password: if empty - uses randkey.
        """
        await self.loop.run_in_executor(
            self.pool,
            self.client.add_principal, name, password)

    async def _get_raw_principal(self, name: str) -> PrincipalProtocol:
        principal = await self.loop.run_in_executor(
            self.pool, self.client.getprinc, name)

        if not principal:
            raise self.PrincipalNotFoundError(f'{name} not found')

        return principal

    async def get_princ(self, name: str) -> Principal:
        """Get principal.

        :param str name: principal
        :return kadmin.Principal: Principal
        """
        principal = await self._get_raw_principal(name)
        return Principal.model_validate(principal, from_attributes=True)

    async def change_password(self, name: str, new_password: str) -> None:
        """Chanage principal's password.

        :param str name: principal
        :param str new_password: ...
        """
        princ = await self._get_raw_principal(name)
        await self.loop.run_in_executor(
            self.pool, princ.change_password, new_password)

    async def del_princ(self, name: str) -> None:
        """Delete principal by name.

        :param str name: principal
        """
        await self.loop.run_in_executor(
            self.pool, self.client.delprinc, name)

    async def rename_princ(self, name: str, new_name: str) -> None:
        """Rename principal.

        :param str name: original name
        :param str new_name: new name
        """
        await self.loop.run_in_executor(
            self.pool, self.client.rename_principal, name, new_name)


@asynccontextmanager
async def kadmin_lifespan(app: FastAPI) -> AsyncIterator[KAdminLocalManager]:
    """Create kadmin instance."""
    async with KAdminLocalManager() as kadmind:
        app.state.kadmind = kadmind
        yield


def get_kadmin() -> KAdminLocalManager:
    """Stub."""
    raise NotImplementedError


def get_app() -> FastAPI:
    """Create FastAPI app."""
    app = FastAPI(
        name="MultiDirectory",
        title="MultiDirectory",
        lifespan=kadmin_lifespan,
    )

    app.dependency_overrides = {
        get_kadmin: lambda: app.state.kadmind,
    }
    app.add_middleware(
        CORSMiddleware,
        allow_origins=['*'],
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return app


app = get_app()


@app.exception_handler(kadmin.KDBAccessError)
def handle_db_error(request: Request, exc: BaseException):
    """Handle duplicate."""
    raise HTTPException(
        status.HTTP_424_FAILED_DEPENDENCY, detail='Database Error')


@app.exception_handler(kadmin.DuplicateError)
def handle_duplicate(request: Request, exc: BaseException):
    """Handle duplicate."""
    raise HTTPException(
        status.HTTP_409_CONFLICT, detail='Principal already exists')


@app.exception_handler(kadmin.KDBNoEntryError)
def handle_not_found_kadmin(request: Request, exc: BaseException):
    """Handle duplicate."""
    raise HTTPException(
        status.HTTP_404_NOT_FOUND, detail='Principal does not exist')


@app.exception_handler(AbstractKRBManager.PrincipalNotFoundError)
def handle_not_found(request: Request, exc: BaseException):
    """Handle duplicate."""
    raise HTTPException(
        status.HTTP_404_NOT_FOUND, detail='Principal does not exist')


@app.post('/setup', response_class=Response, status_code=201)
async def run_setup(schema: ConfigSchema) -> None:
    """Set up server."""
    with open('/etc/krb5.conf', 'wb') as f:
        f.write(bytes.fromhex(schema.krb5_config))

    proc = await asyncio.create_subprocess_exec(
        "kdb5_ldap_util",
        "-D", schema.admin_dn,
        "stashsrvpw", "-f", "/etc/krb5.d/stash.keyfile", schema.krbadmin_dn,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    data = b'\n'.join([
        schema.admin_password.encode(),
        schema.krbadmin_password.encode(),
        schema.krbadmin_password.encode(),
    ]) + b'\n'

    await proc.communicate(input=data)

    if await proc.wait() != 0:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, 'failed stash')

    create_proc = await asyncio.create_subprocess_exec(
        "kdb5_ldap_util", "-D", schema.admin_dn,
        "create", "-subtrees", schema.services_dn,
        "-r", schema.domain.upper(), "-s",
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )
    data = b'\n'.join([
        schema.admin_password.encode(),
        schema.stash_password.encode(),
        schema.stash_password.encode(), b'',
    ])
    _, stderr = await create_proc.communicate(input=data)

    if await create_proc.wait() != 0:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY, stderr.decode())


@app.post('/principal', response_class=Response, status_code=201)
async def add_princ(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: Annotated[str, Body()],
    password: Annotated[str, Body()],
) -> None:
    """Add principal.

    :param Annotated[AbstractKRBManager, Depends kadmin: kadmin abstract
    :param Annotated[str, Body name: principal name
    :param Annotated[str, Body password: principal password
    """
    await kadmin.add_princ(name, password)


@app.get('/principal')
async def get_princ(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: str,
) -> Principal:
    """Add principal.

    :param Annotated[AbstractKRBManager, Depends kadmin: kadmin abstract
    :param Annotated[str, Body name: principal name
    :param Annotated[str, Body password: principal password
    """
    return await kadmin.get_princ(name)


@app.patch('/principal', status_code=201, response_class=Response)
async def change_princ_password(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: Annotated[str, Body()],
    password: Annotated[str, Body()],
) -> None:
    """Add principal.

    :param Annotated[AbstractKRBManager, Depends kadmin: kadmin abstract
    :param Annotated[str, Body name: principal name
    :param Annotated[str, Body password: principal password
    """
    await kadmin.change_password(name, password)


@app.put(
    '/principal',
    status_code=status.HTTP_202_ACCEPTED,
    response_class=Response)
async def rename_princ(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: Annotated[str, Body()],
    new_name: Annotated[str, Body()],
) -> None:
    """Rename principal.

    :param Annotated[AbstractKRBManager, Depends kadmin: kadmin abstract
    :param Annotated[str, Body name: principal name
    :param Annotated[str, Body new_name: principal new name
    """
    """"""
    await kadmin.rename_princ(name, new_name)
