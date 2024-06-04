"""Module with settings.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import tomllib
from functools import cached_property
from typing import Literal
from zoneinfo import ZoneInfo, ZoneInfoNotFoundError

from pydantic import (
    Field,
    HttpUrl,
    IPvAnyAddress,
    PostgresDsn,
    computed_field,
    field_validator,
    validator,
)
from pydantic_settings import BaseSettings

with open("/pyproject.toml", "rb") as f:
    VENDOR_VERSION = tomllib.load(f)['tool']['poetry']['version']


VENDOR_NAME = "MultiFactor"


class Settings(BaseSettings):
    """Settigns with database dsn."""

    DEBUG: bool = False
    HOST: IPvAnyAddress = "0.0.0.0"  # type: ignore  # noqa
    PORT: int = 389
    TLS_PORT: int = 636
    USE_CORE_TLS: bool = False

    POSTGRES_SCHEMA: str = 'postgresql+asyncpg'
    POSTGRES_DB: str = 'postgres'

    POSTGRES_HOST: str = "postgres"
    POSTGRES_USER: str
    POSTGRES_PASSWORD: str

    POSTGRES_URI: PostgresDsn = None  # type: ignore

    HOSTNAME: str | None = None

    SSL_CERT: str = '/certs/cert.pem'
    SSL_KEY: str = '/certs/privkey.pem'

    @validator('POSTGRES_URI', pre=True, always=True)
    def create_postgres(cls, v: str, values: dict) -> str:  # noqa: N805
        """Build postgres DSN."""
        return (
            f"{values['POSTGRES_SCHEMA']}://"  # type: ignore
            f"{values['POSTGRES_USER']}:"
            f"{values['POSTGRES_PASSWORD']}@"
            f"{values['POSTGRES_HOST']}/"
            f"{values['POSTGRES_DB']}"
        )

    VENDOR_NAME: str = VENDOR_NAME
    VENDOR_VERSION: str = VENDOR_VERSION
    # to get a string run: `openssl rand -hex 32`
    SECRET_KEY: str
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 20
    REFRESH_TOKEN_EXPIRE_MINUTES: int = 60 * 24 * 14

    MFA_TIMEOUT_SECONDS: int = 60
    MFA_TOKEN_LEEWAY: int = 15
    MFA_API_SOURCE: Literal['dev', 'ru'] = 'ru'

    TIMEZONE: ZoneInfo = Field(
        ZoneInfo('UTC'), alias='TZ')

    KRB5_LDAP_URI: str = 'ldap://md'
    KRB5_CONFIG_SERVER: HttpUrl = 'http://krb5:8000'  # type: ignore

    @field_validator('TIMEZONE', mode='before')
    def create_tz(cls, tz: str) -> ZoneInfo:  # noqa: N805
        """Get timezone from a string."""
        try:
            value = ZoneInfo(tz)
        except ZoneInfoNotFoundError as err:
            raise ValueError(str(err)) from err
        except TypeError:
            return tz  # type: ignore
        else:
            return value

    @computed_field  # type: ignore
    @cached_property
    def MFA_API_URI(self) -> str:  # noqa: N802
        """Multifactor API url.

        :return str: url
        """
        if self.MFA_API_SOURCE == 'dev':
            return 'https://api.multifactor.dev'
        return 'https://api.multifactor.ru'

    def get_copy_4_tls(self) -> 'Settings':
        """Create a copy for TLS bind."""
        from copy import copy
        tls_settings = copy(self)
        tls_settings.USE_CORE_TLS = True
        tls_settings.PORT = tls_settings.TLS_PORT
        return tls_settings


def get_settings() -> Settings:  # noqa: D103
    raise NotImplementedError()
