"""LDAP filter asn1 syntax to sqlalchemy conditions interpreter.

RFC 4511 reference.
"""

from operator import eq, ge, le, ne

from ldap_filter import Filter
from sqlalchemy import and_, func, not_, or_
from sqlalchemy.orm import aliased
from sqlalchemy.sql.elements import UnaryExpression
from sqlalchemy.sql.expression import Select

from models.ldap3 import Attribute, Directory, User

from .asn1parser import ASN1Row

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


def _cast_item(item: ASN1Row, query: Select) -> BoundQ:
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
            cond = func.lower(attribute_q.value) == right.value.lower()

        return cond, query


def cast_filter2sql(expr: ASN1Row, query: Select) -> BoundQ:
    """Recursively cast Filter to SQLAlchemy conditions."""
    if expr.tag_id.value in range(3):
        conditions = []
        for item in expr.value:
            if item.tag_id.value in range(3):  # &|!
                cond, query = cast_filter2sql(item, query)
                conditions.append(cond)
                continue

            cond, query = _cast_item(item, query)
            conditions.append(cond)

        return [and_, or_, not_][expr.tag_id.value](*conditions), query

    return _cast_item(expr, query)


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
