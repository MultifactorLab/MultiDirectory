"""Multidirectory api module.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware

from api import (
    auth_router,
    entry_router,
    krb5_router,
    mfa_router,
    network_router,
    pwd_router,
)
from config import VENDOR_VERSION, Settings, get_settings
from models.database import create_get_async_session, get_session


def create_app(settings: Settings | None = None) -> FastAPI:
    """Create FastAPI app with dependencies overrides."""
    settings = settings or Settings()

    app = FastAPI(
        name="MultiDirectory",
        title="MultiDirectory",
        debug=settings.DEBUG,
        root_path="/api",
        version=VENDOR_VERSION,
    )
    origins = ["*"]
    app.dependency_overrides = {
        get_settings: lambda: settings,
        get_session: create_get_async_session(settings),
    }
    app.include_router(auth_router)
    app.include_router(entry_router)
    app.include_router(network_router)
    app.include_router(mfa_router)
    app.include_router(pwd_router)
    app.include_router(krb5_router)
    app.add_middleware(
        CORSMiddleware,
        allow_origins=origins,
        allow_credentials=True,
        allow_methods=["*"],
        allow_headers=["*"],
    )
    return app
