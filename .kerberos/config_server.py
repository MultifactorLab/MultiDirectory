"""Simple server for executing krb5 commands."""

import asyncio
from concurrent.futures import ThreadPoolExecutor

import kadmin_local as kadmin
from fastapi import FastAPI, HTTPException, Response, status
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel

app = FastAPI(
    name="MultiDirectory",
    title="MultiDirectory",
)
app.add_middleware(
    CORSMiddleware,
    allow_origins=['*'],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)


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


class KRBManager:
    """Kadmin manager."""

    client: kadmin.KAdmin

    def __init__(self, loop: asyncio.AbstractEventLoop) -> None:
        """Create threadpool and get loop."""
        self.pool = ThreadPoolExecutor(max_workers=500)
        self.loop = loop or asyncio.get_running_loop()

    async def init_client(self) -> None:
        """Init kadmin local connection."""
        self.client = await self.loop.run_in_executor(self.pool, kadmin.local)

    @classmethod
    async def init_kadmin(cls) -> "KRBManager":
        """Connect to kadmin and get class instance."""
        kdm = cls()
        await kdm.init_client()
        return kdm

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
