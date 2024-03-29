"""Schemas for main router."""

from pydantic import Field
from sqlalchemy.sql.expression import Select

from ldap_protocol.filter_interpreter import (
    BoundQ,
    Filter,
    cast_str_filter2sql,
)
from ldap_protocol.ldap_requests import SearchRequest as LDAPSearchRequest
from ldap_protocol.ldap_responses import SearchResultDone, SearchResultEntry


class SearchRequest(LDAPSearchRequest):  # noqa: D101
    filter: str = Field(..., examples=["(objectClass=*)"])  # noqa: A003

    def cast_filter(self, filter_: str, query: Select) -> BoundQ:
        """Cast str filter to sa sql."""
        filter_ = filter_.lower().replace('objectcategory', 'objectclass')
        return cast_str_filter2sql(Filter.parse(filter_).simplify(), query)


class SearchResponse(SearchResultDone):  # noqa: D101
    search_result: list[SearchResultEntry]
