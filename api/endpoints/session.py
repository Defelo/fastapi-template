import hashlib
from typing import Optional

from fastapi import APIRouter, Request, Body

from .. import models
from ..auth import get_user, user_auth, admin_auth
from ..database import db, filter_by
from ..exceptions import responses
from ..exceptions.auth import user_responses
from ..exceptions.session import InvalidCredentialsError, SessionNotFoundError, InvalidRefreshTokenError
from ..exceptions.user import UserNotFoundError, InvalidCodeError
from ..models.session import SessionExpiredError
from ..schemas.sessions import Login, LoginResponse, Session
from ..utils import check_mfa_code

router = APIRouter(tags=["sessions"])


async def _check_mfa(user: models.User, mfa_code: Optional[str], recovery_code: Optional[str]):
    if recovery_code:
        if hashlib.sha256(recovery_code.encode()).hexdigest() != user.mfa_recovery_code:
            raise InvalidCodeError

        user.mfa_secret = None
        user.mfa_enabled = False
        user.mfa_recovery_code = None
        return

    if not mfa_code or not await check_mfa_code(mfa_code, user.mfa_secret):
        raise InvalidCodeError


@router.get("/session", responses=user_responses(Session))
async def get_current_session(session: models.Session = user_auth):
    """Get current session"""

    return session.serialize


@router.get("/sessions/{user_id}", responses=user_responses(list[Session], UserNotFoundError))
async def get_sessions(user: models.User = get_user(require_self_or_admin=True)):
    """Get sessions of a given user"""

    return [session.serialize async for session in await db.stream(filter_by(models.Session, user_id=user.id))]


@router.post("/session", responses=responses(LoginResponse, InvalidCredentialsError, InvalidCodeError))
async def login(data: Login, request: Request):
    """Create a new session"""

    user: Optional[models.User] = await models.User.authenticate(data.name, data.password)
    if not user:
        raise InvalidCredentialsError

    if user.mfa_enabled:
        await _check_mfa(user, data.mfa_code, data.recovery_code)

    session, access_token, refresh_token = await user.create_session(request.headers.get("User-agent", "")[:256])
    return {
        "user": user.serialize,
        "session": session.serialize,
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@router.post("/sessions/{user_id}", dependencies=[admin_auth], responses=user_responses(LoginResponse))
async def impersonate(request: Request, user: models.User = get_user()):
    """Impersonate a specific user"""

    session, access_token, refresh_token = await user.create_session(request.headers.get("User-agent", "")[:256])
    return {
        "user": user.serialize,
        "session": session.serialize,
        "access_token": access_token,
        "refresh_token": refresh_token,
    }


@router.put("/session", responses=responses(LoginResponse, InvalidRefreshTokenError))
async def refresh(refresh_token: str = Body(..., embed=True)):
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
async def logout_current_session(session: models.Session = user_auth):
    """Delete all sessions of a given user"""

    await session.logout()
    return True


@router.delete("/sessions/{user_id}", responses=user_responses(bool, UserNotFoundError))
async def logout(user: models.User = get_user(models.User.sessions, require_self_or_admin=True)):
    """Delete all sessions of a given user"""

    await user.logout()
    return True


@router.delete(
    "/sessions/{user_id}/{session_id}",
    responses=user_responses(bool, UserNotFoundError, SessionNotFoundError),
)
async def logout_session(session_id: str, user: models.User = get_user(require_self_or_admin=True)):
    """Delete a specific session of a given user"""

    session: Optional[models.Session] = await db.get(models.Session, id=session_id, user_id=user.id)
    if not session:
        raise SessionNotFoundError

    await session.logout()
    return True
