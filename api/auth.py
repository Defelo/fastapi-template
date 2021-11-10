from enum import Enum, auto
from typing import Optional, Any, cast

from fastapi import Request, Depends
from fastapi.openapi.models import HTTPBearer
from fastapi.security.base import SecurityBase
from sqlalchemy import Column

from .database import db
from .exceptions.auth import InvalidTokenError, PermissionDeniedError
from .exceptions.user import UserNotFoundError
from .models import User, Session


def get_token(request: Request) -> str:
    authorization: str = request.headers.get("Authorization", "")
    return authorization.removeprefix("Bearer ")


class PermissionLevel(Enum):
    PUBLIC = auto()
    USER = auto()
    ADMIN = auto()


class HTTPAuth(SecurityBase):
    def __init__(self) -> None:
        self.model = HTTPBearer()
        self.scheme_name = self.__class__.__name__

    async def _get_session(self, token: str) -> Optional[Session]:
        raise NotImplementedError

    async def __call__(self, request: Request) -> Optional[Session]:
        if not (session := await self._get_session(get_token(request))):
            raise InvalidTokenError

        return session


class UserAuth(HTTPAuth):
    def __init__(self, min_level: PermissionLevel) -> None:
        super().__init__()

        self.min_level: PermissionLevel = min_level

    async def _get_session(self, token: str) -> Optional[Session]:
        return await Session.from_access_token(token)

    async def __call__(self, request: Request) -> Optional[Session]:
        if self.min_level == PermissionLevel.PUBLIC:
            try:
                return await super().__call__(request)
            except InvalidTokenError:
                return None

        session: Session = cast(Session, await super().__call__(request))

        if self.min_level == PermissionLevel.ADMIN and not session.user.admin:
            raise PermissionDeniedError

        return session


public_auth = Depends(UserAuth(PermissionLevel.PUBLIC))
user_auth = Depends(UserAuth(PermissionLevel.USER))
admin_auth = Depends(UserAuth(PermissionLevel.ADMIN))


@Depends
async def is_admin(session: Optional[Session] = public_auth) -> bool:
    return session is not None and session.user.admin


def get_user(*args: Column[Any], require_self_or_admin: bool = False) -> Any:
    async def default_dependency(user_id: str, session: Optional[Session] = public_auth) -> User:
        if user_id.lower() in ["me", "self"] and session:
            user_id = session.user_id
        if not (user := await db.get(User, *args, id=user_id)):
            raise UserNotFoundError

        return user

    if not require_self_or_admin:
        return Depends(default_dependency)

    async def self_or_admin_dependency(user_id: str, session: Session = user_auth) -> User:
        if user_id.lower() in ["me", "self"]:
            user_id = session.user_id
        if session.user_id != user_id and not session.user.admin:
            raise PermissionDeniedError

        return await default_dependency(user_id)

    return Depends(self_or_admin_dependency)
