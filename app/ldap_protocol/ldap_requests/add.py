"""Add protocol.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

from typing import AsyncGenerator, ClassVar

from pydantic import Field, SecretStr
from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.orm import selectinload

from ldap_protocol.asn1parser import ASN1Row
from ldap_protocol.dialogue import LDAPCodes, Session
from ldap_protocol.ldap_responses import (
    INVALID_ACCESS_RESPONSE,
    AddResponse,
    PartialAttribute,
)
from ldap_protocol.password_policy import PasswordPolicySchema
from ldap_protocol.utils import (
    create_integer_hash,
    create_object_sid,
    get_base_dn,
    get_groups,
    get_path_filter,
    get_search_path,
    validate_entry,
)
from models.ldap3 import Attribute, Directory, Group, User
from security import get_password_hash

from .base import BaseRequest


class AddRequest(BaseRequest):
    """Add new entry.

    ```
    AddRequest ::= [APPLICATION 8] SEQUENCE {
        entry           LDAPDN,
        attributes      AttributeList
    }

    AttributeList ::= SEQUENCE OF attribute Attribute

    password - only JSON API field, added only for user creation,
    skips validation if target entity is not user.
    ```
    """

    PROTOCOL_OP: ClassVar[int] = 8

    entry: str = Field(..., description='Any `DistinguishedName`')
    attributes: list[PartialAttribute]

    password: SecretStr | None = Field(None, examples=['password'])

    @property
    def attr_names(self) -> dict[str, list[str]]:  # noqa
        return {attr.type: attr.vals for attr in self.attributes}

    @classmethod
    def from_data(cls, data: ASN1Row) -> 'AddRequest':  # noqa: D102
        entry, attributes = data
        attributes = [
            PartialAttribute(
                type=attr.value[0].value,
                vals=[val.value for val in attr.value[1].value])
            for attr in attributes.value
        ]
        return cls(entry=entry.value, attributes=attributes)

    async def handle(self, ldap_session: Session, session: AsyncSession) -> \
            AsyncGenerator[AddResponse, None]:
        """Add request handler."""
        if not ldap_session.user:
            yield AddResponse(**INVALID_ACCESS_RESPONSE)
            return

        if not validate_entry(self.entry.lower()):
            yield AddResponse(result_code=LDAPCodes.INVALID_DN_SYNTAX)
            return

        root_dn = get_search_path(
            self.entry, await get_base_dn(session))

        exists_q = select(select(Directory).join(Directory.path).filter(
            get_path_filter(root_dn)).exists())

        if await session.scalar(exists_q) is True:
            yield AddResponse(result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
            return

        parent_dn = root_dn[:-1]
        has_no_parent = len(parent_dn) == 0

        new_dn, name = self.entry.split(',')[0].split('=')

        if has_no_parent:
            new_dir = Directory(
                object_class='',
                name=name,
            )
            path = new_dir.create_path(dn=new_dn)

        else:
            query = select(Directory)\
                .join(Directory.path)\
                .options(selectinload(Directory.paths))\
                .filter(get_path_filter(parent_dn))
            parent = await session.scalar(query)

            if not parent:
                yield AddResponse(result_code=LDAPCodes.NO_SUCH_OBJECT)
                return

            new_dir = Directory(
                object_class='',
                name=name,
                parent=parent,
            )
            path = new_dir.create_path(parent, new_dn)

        group = None
        user = None
        items_to_add = []
        attributes = []
        parent_groups: list[Group] = []
        user_attributes = {}
        group_attributes: list[str] = []
        user_fields = User.search_fields.values()

        for attr in self.attributes:
            lname = attr.type.lower()
            for value in attr.vals:
                if lname in Directory.ro_fields or lname in (
                        "userpassword", 'unicodepwd'):
                    continue

                if attr.type in user_fields:
                    user_attributes[attr.type] = value

                elif attr.type == 'memberOf':
                    group_attributes.append(value)

                else:
                    attributes.append(
                        Attribute(
                            name=attr.type,
                            value=value if isinstance(value, str) else None,
                            bvalue=value if isinstance(value, bytes) else None,
                            directory=new_dir,
                        ),
                    )

        parent_groups = await get_groups(group_attributes, session)

        is_user = 'sAMAccountName' in user_attributes\
            or 'userPrincipalName' in user_attributes

        is_group = 'group' in self.attr_names.get('objectClass', [])

        if is_user:
            user = User(
                sam_accout_name=user_attributes.get('sAMAccountName'),
                user_principal_name=user_attributes.get('userPrincipalName'),
                mail=user_attributes.get('mail'),
                display_name=user_attributes.get('displayName'),
                directory=new_dir,
                password_history=[],
            )

            if self.password is not None:
                validator = await PasswordPolicySchema\
                    .get_policy_settings(session)
                raw_password = self.password.get_secret_value()
                errors = await validator.validate_password_with_policy(
                    raw_password, user, session)

                if errors:
                    yield AddResponse(
                        result_code=LDAPCodes.OPERATIONS_ERROR,
                        errorMessage='; '.join(errors),
                    )
                    return
                user.password = get_password_hash(raw_password)

            items_to_add.append(user)
            user.groups.extend(parent_groups)

            attributes.append(Attribute(
                name='uidNumber',
                value=str(create_integer_hash(user.sam_accout_name)),
                directory=new_dir))

            attributes.append(Attribute(
                name='homeDirectory',
                value=f'/home/{user.sam_accout_name}',
                directory=new_dir))

            attributes.append(Attribute(
                name='loginShell',
                value='/bin/bash',
                directory=new_dir))

        elif is_group:
            group = Group(directory=new_dir)
            items_to_add.append(group)
            group.parent_groups.extend(parent_groups)

        if is_user or is_group:
            attributes.append(Attribute(
                name='gidNumber',  # reverse dir name if it matches samAN
                value=str(create_integer_hash(new_dir.name[::-1])),
                directory=new_dir))

        try:
            new_dir.depth = len(path.path)
            items_to_add.extend([new_dir, path] + attributes)

            session.add_all(items_to_add)

            if has_no_parent:
                new_dir.paths.append(path)
            else:
                path.directories.extend(
                    [p.endpoint for p in parent.paths + [path]])
            await session.flush()

            new_dir.object_sid = await create_object_sid(
                    session, new_dir.id)
            await session.flush()
        except IntegrityError:
            await session.rollback()
            yield AddResponse(result_code=LDAPCodes.ENTRY_ALREADY_EXISTS)
        else:
            yield AddResponse(result_code=LDAPCodes.SUCCESS)

    @classmethod
    def from_dict(
        cls, entry: str,
        attributes: dict[str, list[str]],
        password: str | None = None,
    ) -> 'AddRequest':
        """Create AddRequest from dict.

        :param str entry: entry
        :param dict[str, list[str]] attributes: dict of attrs
        :return AddRequest: instance
        """
        return AddRequest(
            entry=entry,
            password=password,
            attributes=[
                PartialAttribute(type=name, vals=vals)
                for name, vals in attributes.items()],
        )
