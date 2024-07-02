"""Password policies tools and CRUD.

Copyright (c) 2024 MultiFactor
License: https://github.com/MultiDirectoryLab/MultiDirectory/blob/main/LICENSE
"""

import re
from datetime import datetime
from itertools import islice
from typing import Iterable
from zoneinfo import ZoneInfo

from pydantic import BaseModel, Field, model_validator
from sqlalchemy import exists, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models import Attribute, PasswordPolicy, User
from security import verify_password

from .utils import dt_to_ft, ft_to_dt

with open('extra/common_pwds.txt') as f:
    _COMMON_PASSWORDS = set(f.read().split('\n'))


async def post_save_password_actions(
        user: User, session: AsyncSession) -> None:
    """Post save actions for password update.

    :param User user: user from db
    :param AsyncSession session: db
    """
    new_dt = str(dt_to_ft(datetime.now(tz=ZoneInfo('UTC'))))
    await session.execute(  # update bind reject attribute
        update(Attribute)
        .values({'value': new_dt})
        .where(
            Attribute.directory_id == user.directory_id,
            Attribute.name == 'pwdLastSet',
            Attribute.value == '0'))
    user.password_history.append(user.password)
    await session.flush()


class PasswordPolicySchema(BaseModel):
    """PasswordPolicy schema."""

    name: str = Field(
        "Default domain password policy", min_length=3, max_length=255)
    password_history_length: int = Field(4, ge=0, le=24)
    maximum_password_age_days: int = Field(0, ge=0, le=999)
    minimum_password_age_days: int = Field(0, ge=0, le=999)
    minimum_password_length: int = Field(7, ge=0, le=256)
    password_must_meet_complexity_requirements: bool = True

    @model_validator(mode='after')
    def _validate_minimum_pwd_age(self) -> 'PasswordPolicySchema':
        if self.minimum_password_age_days > self.maximum_password_age_days:
            raise ValueError(
                'Minimum password age days must be '
                'lower or equal than maximum password age days')
        return self

    async def create_policy_settings(
            self, session: AsyncSession) -> 'PasswordPolicySchema':
        """Create policies settings.

        :param AsyncSession session: db session
        :return PasswordPolicySchema: password policy.
        """
        existing_policy = await session.scalar(select(exists(PasswordPolicy)))
        if existing_policy:
            raise PermissionError('Policy already exists')
        session.add(PasswordPolicy(**self.model_dump(mode='json')))
        await session.flush()
        return self

    @classmethod
    async def get_policy_settings(
            cls, session: AsyncSession) -> 'PasswordPolicySchema':
        """Get policy settings.

        :param AsyncSession session: db
        :return PasswordPolicySchema: policy
        """
        policy = await session.scalar(select(PasswordPolicy))
        if not policy:
            return cls()
        return cls.model_validate(policy, from_attributes=True)

    async def update_policy_settings(self, session: AsyncSession) -> None:
        """Update policy.

        :param AsyncSession session: db
        """
        await session.execute((
            update(PasswordPolicy)
            .values(self.model_dump(mode='json'))
        ))
        await session.commit()

    @classmethod
    async def delete_policy_settings(
            cls, session: AsyncSession) -> 'PasswordPolicySchema':
        """Reset (delete) default policy.

        :param AsyncSession session: db
        :return PasswordPolicySchema: schema policy
        """
        default_policy = cls()
        await default_policy.update_policy_settings(session)
        return default_policy

    async def validate_password_with_policy(
        self, password: str,
        user: User | None,
        session: AsyncSession,
    ) -> list[str]:
        """Validate password with chosen policy.

        :param str password: new raw password
        :param User user: db user
        :param AsyncSession session: db
        :return bool: status
        """
        errors = []

        last_pwd_set = None
        history: Iterable = []

        if user is not None:
            last_pwd_set = await session.scalar(select(Attribute).where(
                Attribute.directory_id == user.directory_id,
                Attribute.name == 'pwdLastSet',
            ))
            history = islice(
                reversed(user.password_history),
                self.password_history_length)

        tz = ZoneInfo('UTC')
        now = datetime.now(tz=tz)

        last_pwd_set = (
            ft_to_dt(int(last_pwd_set.value)).astimezone(tz)
            if last_pwd_set else now)
        password_exists = (now - last_pwd_set).days

        for pwd_hash in history:
            if verify_password(password, pwd_hash):
                errors.append('password history violation')
                break

        if password_exists > self.maximum_password_age_days:
            errors.append('password maximum age violation')

        if password_exists < self.minimum_password_age_days:
            errors.append('password minimum age violation')

        if len(password) <= self.minimum_password_length:
            errors.append('password minimum length violation')

        if self.password_must_meet_complexity_requirements and not all((
            re.search('[A-ZА-Я]', password) is not None,
            re.search('[a-zа-я]', password) is not None,
            re.search('[0-9]', password) is not None,
            password.lower() not in _COMMON_PASSWORDS,
        )):
            errors.append('password complexity violation')

        return errors
