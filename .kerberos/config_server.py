"""Simple server for executing krb5 commands."""

import asyncio
from abc import ABC, abstractmethod
from concurrent.futures import ThreadPoolExecutor
from contextlib import AbstractAsyncContextManager, asynccontextmanager
from datetime import datetime, timedelta
from types import TracebackType
from typing import Annotated, AsyncIterator

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
    mkvno: int
    failures: int
    last_failure: datetime
    last_pwd_change: datetime
    last_success: datetime
    maxrenewlife: timedelta
    mod_date: datetime
    pwexpire: datetime | None


class AbstractKRBManager(ABC, AbstractAsyncContextManager):
    """Kadmin manager."""

    @abstractmethod
    async def init_client() -> "AbstractKRBManager":
        """Init kadmin instance."""

    @abstractmethod
    async def add_princ(
            self, name: str, password: str | None, **dbargs) -> None:
        """Create principal.

        :param str name: principal
        :param str | None password: if empty - uses randkey.
        """

    @abstractmethod
    async def get_princ(self, name: str) -> kadmin.Principal | None:
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

    client: kadmin.KAdmin

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        """Create threadpool and get loop."""
        self.loop = loop or asyncio.get_running_loop()

    async def __aenter__(self) -> "KAdminLocalManager":
        """Create threadpool for kadmin client."""
        self.client = await self.init_client()
        self.pool = ThreadPoolExecutor(max_workers=500).__enter__()
        return self

    async def __aexit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        """Destroy threadpool."""
        self.pool.__exit__(exc_type, exc, tb)

    async def init_client(self) -> kadmin.KAdmin:
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
            self.client.add_principal, name, password, dbargs)

    async def get_princ(self, name: str) -> kadmin.Principal:
        """Get principal.

        :param str name: principal
        :return kadmin.Principal: Principal
        """
        return await self.loop.run_in_executor(
            self.pool, self.client.getprinc, name)

    async def change_password(self, name: str, new_password: str) -> None:
        """Chanage principal's password.

        :param str name: principal
        :param str new_password: ...
        """
        princ = await self.get_principal(name)
        if not princ:
            raise KeyError
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


def get_kadmin(request: Request) -> KAdminLocalManager:
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
        get_kadmin: lambda request: request.app.state.kadmind,
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


@app.exception_handler(kadmin.DuplicateError)
def handle_duplicate(request: Request, exc: BaseException):
    """Handle duplicate."""
    raise HTTPException(
        status.HTTP_409_CONFLICT, detail='Principal already exists')


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


@app.post('/principal', status_code=201)
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


@app.get('/principal', status_code=status.HTTP_302_FOUND)
async def get_princ(
    kadmin: Annotated[AbstractKRBManager, Depends(get_kadmin)],
    name: Annotated[str, Body()],
) -> Principal:
    """Add principal.

    :param Annotated[AbstractKRBManager, Depends kadmin: kadmin abstract
    :param Annotated[str, Body name: principal name
    :param Annotated[str, Body password: principal password
    """
    principal = await kadmin.get_princ(name)
    if not principal:
        raise HTTPException(status.HTTP_404_NOT_FOUND)
    return Principal.model_validate(principal, from_attributes=True)


@app.put('/principal', status_code=201)
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
    try:
        await kadmin.change_password(name, password)
    except KeyError:
        raise HTTPException(status.HTTP_404_NOT_FOUND)


@app.patch('/principal', status_code=status.HTTP_202_ACCEPTED)
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
