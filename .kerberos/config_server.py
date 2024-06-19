"""Simple server for executing krb5 commands."""

import asyncio

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
