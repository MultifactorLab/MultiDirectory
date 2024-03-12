"""Password policies tools and CRUD."""

import re
from datetime import datetime
from itertools import islice

from pydantic import BaseModel, Field, model_validator
from pytz import timezone
from sqlalchemy import exists, select, update
from sqlalchemy.ext.asyncio import AsyncSession

from models import Attribute, PasswordPolicy, User
from security import get_password_hash

from .utils import dt_to_ft, ft_to_dt

with open('extra/common_pwds.txt') as f:
    _COMMON_PASSWORDS = set(f.read().split('\n'))


async def post_save_password_actions(
        user: User, session: AsyncSession) -> None:
    """Post save actions for password update.

    :param User user: user from db
    :param AsyncSession session: db
    """
    new_dt = dt_to_ft(datetime.now(tz=timezone('Europe/Moscow')))
    await session.execute(  # update bind reject attribute
        update(Attribute)
        .values({'value': new_dt})
        .where(
            Attribute.directory_id == user.directory_id,
            Attribute.name == 'pwdLastSet',
            Attribute.value == '0'))
    user.password_history.append(user.password)  # type: ignore  # noqa
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
        await session.commit()
        return self

    @classmethod
    async def get_policy_settings(
            cls, session: AsyncSession) -> 'PasswordPolicySchema':
        """Get policy settings.

        :param AsyncSession session: db
        :return PasswordPolicySchema: policy
        """
        policy = await session.scalar(select(PasswordPolicy))
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
        user: User,
        session: AsyncSession,
    ) -> list[str]:
        """Validate password with chosen policy.

        :param str password: new raw password
        :param User user: db user
        :param AsyncSession session: db
        :return bool: status
        """
        errors = []
        new_password_hash = get_password_hash(password)

        last_pwd_set = await session.scalar(select(Attribute).where(
            Attribute.directory_id == user.directory_id,
            Attribute.name == 'pwdLastSet',
        ))  # type: ignore

        tz = timezone('Europe/Moscow')
        now = datetime.now(tz=tz)

        last_pwd_set = (
            tz.localize(ft_to_dt(int(last_pwd_set.value)))
            if last_pwd_set else now)
        password_exists = (now - last_pwd_set).days

        if new_password_hash in islice(
                reversed(user.password_history), self.password_history_length):
            errors.append('password history violation')

        if password_exists > self.maximum_password_age_days:
            errors.append('password maximum age violation')

        if password_exists < self.minimum_password_age_days:
            errors.append('password minimum age violation')

        if len(password) <= self.minimum_password_length:
            errors.append('password minimum length violation')

        if self.password_must_meet_complexity_requirements and not all((
            re.search('[A-Z]', password) is not None,
            re.search('[a-z]', password) is not None,
            re.search('[0-9]', password) is not None,
            password.lower() not in _COMMON_PASSWORDS,
        )):
            errors.append('password complexity violation')

        return errors
