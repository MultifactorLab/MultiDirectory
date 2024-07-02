"""Schemas for main router.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from pydantic import BaseModel, EmailStr, Field, SecretStr
from sqlalchemy.sql.expression import Select

from ldap_protocol.filter_interpreter import (
    BoundQ,
    Filter,
    cast_str_filter2sql,
)
from ldap_protocol.ldap_requests import SearchRequest as LDAPSearchRequest
from ldap_protocol.ldap_requests.base import APIMultipleResponseMixin
from ldap_protocol.ldap_responses import SearchResultDone, SearchResultEntry


class SearchRequest(APIMultipleResponseMixin, LDAPSearchRequest):  # noqa: D101
    filter: str = Field(..., examples=["(objectClass=*)"])  # noqa: A003

    def cast_filter(
        self, filter_: str, query: Select, base_dn: str,
    ) -> BoundQ:
        """Cast str filter to sa sql."""
        filter_ = filter_.lower().replace('objectcategory', 'objectclass')
        return cast_str_filter2sql(
            Filter.parse(filter_).simplify(), query, base_dn)


class SearchResponse(SearchResultDone):  # noqa: D101
    search_result: list[SearchResultEntry]


class KerberosSetupRequest(BaseModel):
    """Kerberos setup data."""

    mail: EmailStr
    krbadmin_password: SecretStr
    admin_password: SecretStr
    stash_password: SecretStr
