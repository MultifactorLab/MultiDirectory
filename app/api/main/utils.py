"""Common utils for ldap api."""

from typing import Annotated

from fastapi import Depends

from api.auth import User, get_current_user
from config import Settings, get_settings
from ldap_protocol.dialogue import Session as LDAPSession


def ldap_session(
        user: Annotated[User, Depends(get_current_user)],
        settings: Annotated[Settings, Depends(get_settings)]) -> LDAPSession:
    """Create LDAP session."""
    return LDAPSession(user=user, settings=settings)