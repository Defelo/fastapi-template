import hashlib
from typing import Any

from fastapi import APIRouter, Body, Query, Request
from pyotp import random_base32
from sqlalchemy import asc, func

from .. import models
from ..auth import admin_auth, get_user, is_admin, user_auth
from ..database import db, filter_by, select
from ..environment import OPEN_OAUTH_REGISTRATION, OPEN_REGISTRATION
from ..exceptions.auth import PermissionDeniedError, admin_responses, user_responses
from ..exceptions.oauth import InvalidOAuthTokenError, RemoteAlreadyLinkedError
from ..exceptions.user import (
    CannotDeleteLastLoginMethodError,
    InvalidCodeError,
    MFAAlreadyEnabledError,
    MFANotEnabledError,
    MFANotInitializedError,
    NoLoginMethodError,
    OAuthRegistrationDisabledError,
    RecaptchaError,
    RegistrationDisabledError,
    UserAlreadyExistsError,
    UserNotFoundError,
)
from ..redis import redis
from ..schemas.session import LoginResponse
from ..schemas.user import MFA_CODE_REGEX, CreateUser, UpdateUser, User, UsersResponse
from ..utils import check_mfa_code, check_recaptcha, recaptcha_enabled


router = APIRouter(tags=["users"])


@router.get("/users", dependencies=[admin_auth], responses=admin_responses(UsersResponse))
async def get_users(
    limit: int = Query(100, ge=1, le=100),
    offset: int = Query(0, ge=0),
    name: str | None = Query(None, max_length=256),
    enabled: bool | None = Query(None),
    admin: bool | None = Query(None),
    mfa_enabled: bool | None = Query(None),
) -> Any:
    """Get all users"""

    query = select(models.User)
    order = []
    if name:
        query = query.where(func.lower(models.User.name).contains(name.lower(), autoescape=True))
        order.append(asc(func.length(models.User.name)))
    if enabled is not None:
        query = query.where(models.User.enabled == enabled)
    if admin is not None:
        query = query.where(models.User.admin == admin)
    if mfa_enabled is not None:
        query = query.where(models.User.mfa_enabled == mfa_enabled)

    total: int = await db.count(query)
    return {
        "total": total,
        "users": [
            user.serialize
            async for user in await db.stream(
                query.order_by(*order, asc(models.User.registration)).limit(limit).offset(offset)
            )
        ],
    }


@router.get("/users/{user_id}", responses=admin_responses(User, UserNotFoundError))
async def get_user_by_id(user: models.User = get_user(require_self_or_admin=True)) -> Any:
    """Get user by id"""

    return user.serialize


@router.post(
    "/users",
    responses=user_responses(
        LoginResponse,
        UserAlreadyExistsError,
        RemoteAlreadyLinkedError,
        NoLoginMethodError,
        RegistrationDisabledError,
        OAuthRegistrationDisabledError,
        RecaptchaError,
        InvalidOAuthTokenError,
    ),
)
async def create_user(data: CreateUser, request: Request, admin: bool = is_admin) -> Any:
    """Create a new user"""

    if not data.oauth_register_token and not data.password:
        raise NoLoginMethodError
    if not admin:
        if data.password and not OPEN_REGISTRATION:
            raise RegistrationDisabledError
        if data.oauth_register_token and not OPEN_OAUTH_REGISTRATION:
            raise OAuthRegistrationDisabledError

        if recaptcha_enabled() and not (data.recaptcha_response and await check_recaptcha(data.recaptcha_response)):
            raise RecaptchaError

    if await db.exists(models.User.filter_by_name(data.name)):
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
            filter_by(models.OAuthUserConnection, provider_id=provider_id, remote_user_id=remote_user_id)
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


@router.patch(
    "/users/{user_id}",
    responses=admin_responses(User, UserNotFoundError, UserAlreadyExistsError, CannotDeleteLastLoginMethodError),
)
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
        if await db.exists(models.User.filter_by_name(data.name).where(models.User.id != user.id)):
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


@router.post("/users/{user_id}/mfa", responses=admin_responses(str, UserNotFoundError, MFAAlreadyEnabledError))
async def initialize_mfa(user: models.User = get_user(require_self_or_admin=True)) -> Any:
    """Generate mfa secret"""

    if user.mfa_enabled:
        raise MFAAlreadyEnabledError

    user.mfa_secret = random_base32(32)
    return user.mfa_secret


@router.put(
    "/users/{user_id}/mfa",
    responses=admin_responses(str, UserNotFoundError, MFAAlreadyEnabledError, MFANotInitializedError, InvalidCodeError),
)
async def enable_mfa(
    code: str = Body(..., embed=True, regex=MFA_CODE_REGEX), user: models.User = get_user(require_self_or_admin=True)
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


@router.delete("/users/{user_id}/mfa", responses=admin_responses(bool, UserNotFoundError, MFANotEnabledError))
async def disable_mfa(user: models.User = get_user(require_self_or_admin=True)) -> Any:
    """Disable mfa"""

    if not user.mfa_secret and not user.mfa_enabled:
        raise MFANotEnabledError

    user.mfa_enabled = False
    user.mfa_secret = None
    user.mfa_recovery_code = None
    return True


@router.delete("/users/{user_id}", responses=admin_responses(bool, UserNotFoundError))
async def delete_user(
    user: models.User = get_user(models.User.sessions, require_self_or_admin=True), admin: bool = is_admin
) -> Any:
    """Delete a user"""

    if not (OPEN_REGISTRATION or OPEN_OAUTH_REGISTRATION) and not admin:
        raise PermissionDeniedError

    if user.admin and not await db.exists(filter_by(models.User, admin=True).filter(models.User.id != user.id)):
        raise PermissionDeniedError

    await user.logout()
    await db.delete(user)
    return True
