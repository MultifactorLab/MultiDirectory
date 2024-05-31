"""API module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from .auth.router import auth_router
from .auth.router_mfa import mfa_router
from .auth.router_pwd_policy import pwd_router
from .main.krb5_router import krb5_router
from .main.router import entry_router
from .network.router import network_router

__all__ = [
    'auth_router',
    'entry_router',
    'network_router',
    'mfa_router',
    'pwd_router',
    'krb5_router',
]
