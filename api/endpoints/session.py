import hashlib
from typing import Optional, Any
from uuid import uuid4

from fastapi import APIRouter, Request, Body

from .oauth import resolve_code
from .. import models
from ..auth import get_user, user_auth, admin_auth
from ..database import db, filter_by
from ..environment import OAUTH_REGISTER_TOKEN_TTL, LOGIN_FAILS_BEFORE_CAPTCHA
from ..exceptions import responses
from ..exceptions.auth import user_responses, admin_responses
from ..exceptions.oauth import ProviderNotFoundError, InvalidOAuthCodeError
from ..exceptions.session import (
    InvalidCredentialsError,
    SessionNotFoundError,
    InvalidRefreshTokenError,
    UserDisabledError,
)
from ..exceptions.user import UserNotFoundError, InvalidCodeError, RecaptchaError
from ..models.session import SessionExpiredError
from ..redis import redis
from ..schemas.oauth import OAuthLogin
from ..schemas.session import Login, LoginResponse, Session, OAuthLoginResponse
from ..utils import check_mfa_code, check_recaptcha, recaptcha_enabled

router = APIRouter(tags=["sessions"])


async def _check_mfa(user: models.User, mfa_code: Optional[str], recovery_code: Optional[str]) -> bool:
    if not user.mfa_enabled or not user.mfa_secret:
        return True

    if recovery_code:
        if hashlib.sha256(recovery_code.encode()).hexdigest() != user.mfa_recovery_code:
            return False

        user.mfa_secret = None
        user.mfa_enabled = False
        user.mfa_recovery_code = None
        return True

    return mfa_code is not None and await check_mfa_code(mfa_code, user.mfa_secret)


@router.get("/session", responses=user_responses(Session))
async def get_current_session(session: models.Session = user_auth) -> Any:
    """Get current session"""

    return session.serialize


@router.get("/sessions/{user_id}", responses=admin_responses(list[Session], UserNotFoundError))
async def get_sessions(user: models.User = get_user(require_self_or_admin=True)) -> Any:
    """Get sessions of a given user"""

    return [session.serialize async for session in await db.stream(filter_by(models.Session, user_id=user.id))]


@router.post(
    "/sessions",
    responses=responses(LoginResponse, RecaptchaError, InvalidCredentialsError, UserDisabledError, InvalidCodeError),
)
async def login(data: Login, request: Request) -> Any:
    """Create a new session"""

    name_hash: str = hashlib.sha256(data.name.lower().encode()).hexdigest()
    failed_attempts = int(await redis.get(key := f"failed_login_attempts:{name_hash}") or "0")
    if (
        recaptcha_enabled()
        and (0 <= LOGIN_FAILS_BEFORE_CAPTCHA <= failed_attempts)
        and not (data.recaptcha_response and await check_recaptcha(data.recaptcha_response))
    ):
        raise RecaptchaError

    user: Optional[models.User] = await db.first(models.User.filter_by_name(data.name))
    if not user or not await user.check_password(data.password):
        await redis.incr(key)
        raise InvalidCredentialsError

    if user.mfa_enabled and not await _check_mfa(user, data.mfa_code, data.recovery_code):
        await redis.incr(key)
        raise InvalidCodeError

    await redis.delete(key)

    if not user.enabled:
        raise UserDisabledError

    session, access_token, refresh_token = await user.create_session(request.headers.get("User-agent", "")[:256])
    return {
        "user": user.serialize,
        "session": session.serialize,
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@router.post(
    "/sessions/oauth",
    responses=responses(OAuthLoginResponse, ProviderNotFoundError, InvalidOAuthCodeError, UserDisabledError),
)
async def oauth_login(data: OAuthLogin, request: Request) -> Any:
    """Create a new session"""

    remote_user_id, display_name = await resolve_code(data)
    connection: Optional[models.OAuthUserConnection] = await db.get(
        models.OAuthUserConnection,
        models.OAuthUserConnection.user,
        provider_id=data.provider_id,
        remote_user_id=remote_user_id,
    )
    if not connection:
        token = str(uuid4())
        async with redis.pipeline() as pipe:
            await pipe.setex(f"oauth_register_token:{token}:provider", OAUTH_REGISTER_TOKEN_TTL, data.provider_id)
            await pipe.setex(f"oauth_register_token:{token}:user_id", OAUTH_REGISTER_TOKEN_TTL, remote_user_id)
            await pipe.setex(f"oauth_register_token:{token}:display_name", OAUTH_REGISTER_TOKEN_TTL, display_name or "")
            await pipe.execute()

        return {"register_token": token}

    user = connection.user
    if not user.enabled:
        raise UserDisabledError

    session, access_token, refresh_token = await user.create_session(request.headers.get("User-agent", "")[:256])
    return {
        "login": {
            "user": user.serialize,
            "session": session.serialize,
            "access_token": access_token,
            "refresh_token": refresh_token,
        },
    }


@router.post(
    "/sessions/{user_id}",
    dependencies=[admin_auth],
    responses=admin_responses(LoginResponse, UserNotFoundError),
)
async def impersonate(request: Request, user: models.User = get_user()) -> Any:
    """Impersonate a specific user"""

    session, access_token, refresh_token = await user.create_session(request.headers.get("User-agent", "")[:256])
    return {
        "user": user.serialize,
        "session": session.serialize,
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@router.put("/session", responses=responses(LoginResponse, InvalidRefreshTokenError))
async def refresh(refresh_token: str = Body(..., embed=True)) -> Any:
    """Refresh access token and refresh token"""

    try:
        session, access_token, refresh_token = await models.Session.refresh(refresh_token)
    except (ValueError, SessionExpiredError):
        raise InvalidRefreshTokenError

    return {
        "user": session.user.serialize,
        "session": session.serialize,
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@router.delete("/session", responses=user_responses(bool))
async def logout_current_session(session: models.Session = user_auth) -> Any:
    """Delete current session"""

    await session.logout()
    return True


@router.delete("/sessions/{user_id}", responses=admin_responses(bool, UserNotFoundError))
async def logout(user: models.User = get_user(models.User.sessions, require_self_or_admin=True)) -> Any:
    """Delete all sessions of a given user"""

    await user.logout()
    return True


@router.delete(
    "/sessions/{user_id}/{session_id}",
    responses=admin_responses(bool, UserNotFoundError, SessionNotFoundError),
)
async def logout_session(session_id: str, user: models.User = get_user(require_self_or_admin=True)) -> Any:
    """Delete a specific session of a given user"""

    session: Optional[models.Session] = await db.get(models.Session, id=session_id, user_id=user.id)
    if not session:
        raise SessionNotFoundError

    await session.logout()
    return True
