import hashlib
from typing import Any

from fastapi import APIRouter, Query, Body, Request
from pyotp import random_base32
from sqlalchemy import asc

from .. import models
from ..auth import get_user, admin_auth, is_admin, user_auth
from ..database import db, select, filter_by
from ..environment import OPEN_REGISTRATION, OPEN_OAUTH_REGISTRATION
from ..exceptions.auth import user_responses, PermissionDeniedError
from ..exceptions.oauth import RemoteAlreadyLinkedError, InvalidOAuthTokenError
from ..exceptions.user import (
    UserNotFoundError,
    UserAlreadyExistsError,
    MFAAlreadyEnabledError,
    MFANotInitializedError,
    InvalidCodeError,
    MFANotEnabledError,
    NoLoginMethodError,
    CannotDeleteLastLoginMethodError,
    RegistrationDisabledError,
    OAuthRegistrationDisabledError,
)
from ..redis import redis
from ..schemas.session import LoginResponse
from ..schemas.user import User, UsersResponse, CreateUser, UpdateUser, MFA_CODE_REGEX
from ..utils import check_mfa_code

router = APIRouter(tags=["users"])


@router.get("/users", dependencies=[admin_auth], responses=user_responses(UsersResponse))
async def get_users(limit: int = Query(100, ge=1, le=100), offset: int = Query(0, ge=0)) -> Any:
    """Get all users"""

    total: int = await db.count(select(models.User))
    return {
        "total": total,
        "users": [
            user.serialize
            async for user in await db.stream(
                select(models.User).order_by(asc(models.User.registration)).limit(limit).offset(offset),
            )
        ],
    }


@router.get("/users/{user_id}", responses=user_responses(User, UserNotFoundError))
async def get_user_by_id(user: models.User = get_user(require_self_or_admin=True)) -> Any:
    """Get user by id"""

    return user.serialize


@router.post(
    "/users",
    responses=user_responses(LoginResponse, UserAlreadyExistsError, RemoteAlreadyLinkedError, NoLoginMethodError),
)
async def create_user(data: CreateUser, request: Request, admin: bool = is_admin) -> Any:
    """Create a new user"""

    if not data.oauth_register_token and not data.password:
        raise NoLoginMethodError
    if data.password and not OPEN_REGISTRATION and not admin:
        raise RegistrationDisabledError
    if data.oauth_register_token and not OPEN_OAUTH_REGISTRATION and not admin:
        raise OAuthRegistrationDisabledError

    if await db.exists(filter_by(models.User, name=data.name)):
        raise UserAlreadyExistsError

    if data.oauth_register_token:
        async with redis.pipeline() as pipe:
            await pipe.get(key1 := f"oauth_register_token:{data.oauth_register_token}:provider")
            await pipe.get(key2 := f"oauth_register_token:{data.oauth_register_token}:user_id")
            await pipe.get(key3 := f"oauth_register_token:{data.oauth_register_token}:display_name")
            provider_id, remote_user_id, display_name = await pipe.execute()

        if not provider_id or not remote_user_id:
            raise InvalidOAuthTokenError

        await redis.delete(key1, key2, key3)

        if await db.exists(
            filter_by(models.OAuthUserConnection, provider_id=provider_id, remote_user_id=remote_user_id),
        ):
            raise RemoteAlreadyLinkedError

    user = await models.User.create(data.name, data.password, data.enabled, data.admin and admin)

    if data.oauth_register_token:
        await models.OAuthUserConnection.create(user.id, provider_id, remote_user_id, display_name)

    session, access_token, refresh_token = await user.create_session(request.headers.get("User-agent", "")[:256])
    return {
        "user": user.serialize,
        "session": session.serialize,
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@router.patch("/users/{user_id}", responses=user_responses(User, UserAlreadyExistsError))
async def update_user(
    data: UpdateUser,
    user: models.User = get_user(models.User.sessions, models.User.oauth_connections, require_self_or_admin=True),
    admin: bool = is_admin,
    session: models.Session = user_auth,
) -> Any:
    """Update a user"""

    if data.name is not None and data.name != user.name:
        if not admin:
            raise PermissionDeniedError
        if await db.exists(filter_by(models.User, name=data.name)):
            raise UserAlreadyExistsError

        user.name = data.name

    if data.password is not None:
        if not data.password and not user.oauth_connections:
            raise CannotDeleteLastLoginMethodError

        await user.change_password(data.password)

    if data.enabled is not None and data.enabled != user.enabled:
        if user.id == session.user_id:
            raise PermissionDeniedError

        user.enabled = data.enabled
        if not user.enabled:
            await user.logout()

    if data.admin is not None and data.admin != user.admin:
        if user.id == session.user_id:
            raise PermissionDeniedError

        user.admin = data.admin

    return user.serialize


@router.post("/users/{user_id}/mfa", responses=user_responses(str, UserNotFoundError, MFAAlreadyEnabledError))
async def initialize_mfa(user: models.User = get_user(require_self_or_admin=True)) -> Any:
    """Generate mfa secret"""

    if user.mfa_enabled:
        raise MFAAlreadyEnabledError

    user.mfa_secret = random_base32(32)
    return user.mfa_secret


@router.put(
    "/users/{user_id}/mfa",
    responses=user_responses(str, UserNotFoundError, MFAAlreadyEnabledError, MFANotInitializedError, InvalidCodeError),
)
async def enable_mfa(
    code: str = Body(..., embed=True, regex=MFA_CODE_REGEX),
    user: models.User = get_user(require_self_or_admin=True),
) -> Any:
    """Enable mfa and generate recovery code"""

    if user.mfa_enabled:
        raise MFAAlreadyEnabledError
    if not user.mfa_secret:
        raise MFANotInitializedError
    if not await check_mfa_code(code, user.mfa_secret):
        raise InvalidCodeError

    recovery_code = "-".join(random_base32()[:6] for _ in range(4))
    user.mfa_recovery_code = hashlib.sha256(recovery_code.encode()).hexdigest()
    user.mfa_enabled = True

    return recovery_code


@router.delete("/users/{user_id}/mfa", responses=user_responses(bool, UserNotFoundError, MFANotEnabledError))
async def disable_mfa(user: models.User = get_user(require_self_or_admin=True)) -> Any:
    """Disable mfa"""

    if not user.mfa_secret and not user.mfa_enabled:
        raise MFANotEnabledError

    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_recovery_code = None
    return True


@router.delete("/users/{user_id}", responses=user_responses(bool, PermissionDeniedError))
async def delete_user(
    user: models.User = get_user(models.User.sessions, require_self_or_admin=True),
    admin: bool = is_admin,
) -> Any:
    """Delete a user"""

    if not (OPEN_REGISTRATION or OPEN_OAUTH_REGISTRATION) and not admin:
        raise PermissionDeniedError

    if user.admin and not await db.exists(filter_by(models.User, admin=True).filter(models.User.id != user.id)):
        raise PermissionDeniedError

    await user.logout()
    await db.delete(user)
    return True
