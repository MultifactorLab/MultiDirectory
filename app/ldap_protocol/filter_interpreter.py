"""LDAP filter asn1 syntax to sqlalchemy conditions interpreter.

RFC 4511 reference.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from operator import eq, ge, le, ne

from ldap_filter import Filter
from sqlalchemy import and_, func, not_, or_, select
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import aliased
from sqlalchemy.sql.elements import UnaryExpression
from sqlalchemy.sql.expression import Select

from models.ldap3 import (
    Attribute,
    Directory,
    Group,
    GroupMembership,
    User,
    UserMembership,
)

from .asn1parser import ASN1Row
from .utils import get_base_dn, get_path_filter, get_search_path

BoundQ = tuple[UnaryExpression, Select]


def _get_substring(right: ASN1Row) -> str:  # RFC 4511
    expr = right.value[0]
    value = expr.value
    index = expr.tag_id.value
    return [f"{value}%", f"%{value}%", f"%{value}"][index]


def _from_filter(
    model: type, item: ASN1Row, attr: str, right: ASN1Row,
) -> UnaryExpression:
    is_substring = item.tag_id.value == 4
    col = getattr(model, attr)

    if is_substring:
        return col.ilike(_get_substring(right))
    op_method = {3: eq, 5: ge, 6: le, 8: ne}[item.tag_id.value]
    return op_method(func.lower(col), right.value.lower())


async def _filter_memberof(
    item: ASN1Row, right: ASN1Row, session: AsyncSession,
) -> UnaryExpression:
    """Retrieve query conditions with the memberOF attribute."""
    if item.tag_id.value == 3:
        method = Directory.id.in_
    elif item.tag_id.value == 8:
        method = Directory.id.not_in
    else:
        raise ValueError('Incorrect operation method')

    group_path = get_search_path(right.value, await get_base_dn(session))
    path_filter = get_path_filter(group_path)

    group_id_subquery = select(Group.id).join(  # noqa: ECE001
        Directory.group).join(Directory.path).where(
            path_filter).scalar_subquery()

    users_with_group = select(User.directory_id).where(
        User.id.in_(select(UserMembership.user_id).where(
            UserMembership.group_id == group_id_subquery).scalar_subquery()))

    child_groups = select(Group.directory_id).where(
        Group.id.in_(select(GroupMembership.group_child_id).where(
            GroupMembership.group_id == group_id_subquery).scalar_subquery()))

    return method(users_with_group) | method(child_groups)


async def _cast_item(
    item: ASN1Row, query: Select, session: AsyncSession,
) -> BoundQ:
    # present, for e.g. `attibuteName=*`, `(attibuteName)`
    if item.tag_id.value == 7:
        attr = item.value.lower().replace('objectcategory', 'objectclass')

        if attr in User.search_fields:
            return not_(eq(getattr(User, attr), None)), query

        if attr in Directory.search_fields:
            return not_(eq(getattr(Directory, attr), None)), query

        return func.lower(Attribute.name) == item.value.lower(), query

    left, right = item.value
    attr = left.value.lower().replace('objectcategory', 'objectclass')

    is_substring = item.tag_id.value == 4

    if attr in User.search_fields:  # noqa: R505
        return _from_filter(User, item, attr, right), query
    elif attr in Directory.search_fields:
        return _from_filter(Directory, item, attr, right), query
    elif attr == 'memberof':
        return await _filter_memberof(item, right, session), query
    else:
        attribute_q = aliased(Attribute)
        query = query.join(
            attribute_q, and_(
                attribute_q.directory_id == Directory.id,
                func.lower(attribute_q.name) == attr),
            isouter=True,
        )

        if is_substring:
            cond = attribute_q.value.ilike(_get_substring(right))
        else:
            if isinstance(right.value, str):
                cond = func.lower(attribute_q.value) == right.value.lower()
            else:
                cond = func.lower(attribute_q.bvalue) == right.value

        return cond, query


async def cast_filter2sql(
    expr: ASN1Row, query: Select, session: AsyncSession,
) -> BoundQ:
    """Recursively cast Filter to SQLAlchemy conditions."""
    if expr.tag_id.value in range(3):
        conditions = []
        for item in expr.value:
            if item.tag_id.value in range(3):  # &|!
                cond, query = await cast_filter2sql(item, query, session)
                conditions.append(cond)
                continue

            cond, query = await _cast_item(item, query, session)
            conditions.append(cond)

        return [and_, or_, not_][expr.tag_id.value](*conditions), query

    return await _cast_item(expr, query, session)


def _from_str_filter(
        model: type, is_substring: bool, item: Filter) -> UnaryExpression:
    col = getattr(model, item.attr)

    if is_substring:
        return col.ilike(item.val.replace('*', '%'))
    op_method = {'=': eq, '>=': ge, '<=': le, '~=': ne}[item.comp]
    return op_method(func.lower(col), item.val)


def _cast_filt_item(item: Filter, query: Select) -> BoundQ:
    if item.val == '*':
        if item.attr in User.search_fields:
            return not_(eq(getattr(User, item.attr), None)), query

        if item.attr in Directory.search_fields:
            return not_(eq(getattr(Directory, item.attr), None)), query

        return func.lower(Attribute.name) == item.attr, query

    is_substring = item.val.startswith('*') or item.val.endswith('*')

    if item.attr in User.search_fields:  # noqa: R505
        return _from_str_filter(User, is_substring, item), query
    elif item.attr in Directory.search_fields:
        return _from_str_filter(Directory, is_substring, item), query

    else:
        attribute_q = aliased(Attribute)
        query = query.join(
            attribute_q, and_(
                attribute_q.directory_id == Directory.id,
                func.lower(attribute_q.name) == item.attr),
            isouter=True,
        )

        if is_substring:
            cond = attribute_q.value.ilike(item.val.replace('*', '%'))
        else:
            cond = func.lower(attribute_q.value) == item.val

        return cond, query


def cast_str_filter2sql(expr: Filter, query: Select) -> BoundQ:
    """Cast ldap filter to sa query."""
    if expr.type == "group":
        conditions = []
        for item in expr.filters:
            if expr.type == "group":
                cond, query = cast_str_filter2sql(item, query)
                conditions.append(cond)
                continue

            cond, query = _cast_filt_item(item, query)
            conditions.append(cond)

        return {  # type: ignore
            '&': and_,
            '|': or_,
            '!': not_,
        }[expr.comp](*conditions), query

    return _cast_filt_item(expr, query)
