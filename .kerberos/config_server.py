"""Simple server for executing krb5 commands."""

import asyncio
from typing import Annotated

from fastapi import Body, FastAPI, HTTPException, Response, UploadFile, status

app = FastAPI()


@app.post('/setup', response_class=Response, status_code=201)
async def run_setup(
    domain: Annotated[str, Body()],
    admin_dn: Annotated[str, Body()],
    krbadmin_dn: Annotated[str, Body()],
    krbadmin_password: Annotated[str, Body()],
    admin_password: Annotated[str, Body()],
    stash_password: Annotated[str, Body()],
    krb5_config: UploadFile,
) -> None:
    """Set up server."""
    with open('/etc/krb5.conf', 'wb') as f:
        f.write(krb5_config.read())

    stash = await asyncio.create_subprocess_exec(
        "kdb5_ldap_util",
        "-D", admin_dn,
        "stashsrvpw", "-f", "/etc/krb5.d/stash.keyfile", krbadmin_dn,
    )

    await stash.communicate(admin_password.encode())
    await stash.communicate(krbadmin_password.encode())
    await stash.communicate(krbadmin_password.encode())
    if await stash.wait() != 0:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY)

    create = await asyncio.create_subprocess_exec(
        "kdb5_ldap_util",
        "-D", admin_dn,
        "create", "-subtrees", krbadmin_dn, "-r", domain.upper(), "-s",
    )
    await create.communicate(admin_password.encode())
    await create.communicate(stash_password.encode())
    await create.communicate(stash_password.encode())

    if await stash.wait() != 0:
        raise HTTPException(status.HTTP_424_FAILED_DEPENDENCY)
