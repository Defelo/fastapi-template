from typing import Any

from fastapi import Depends, Request
from fastapi.openapi.models import HTTPBearer
from fastapi.security.base import SecurityBase

from .exceptions.auth import InvalidTokenError
from .utils.jwt import decode_jwt


def get_token(request: Request) -> str:
    authorization: str = request.headers.get("Authorization", "")
    return authorization.removeprefix("Bearer ")


class HTTPAuth(SecurityBase):
    def __init__(self) -> None:
        self.model = HTTPBearer()
        self.scheme_name = self.__class__.__name__

    async def __call__(self, request: Request) -> Any:
        raise NotImplementedError


class StaticTokenAuth(HTTPAuth):
    def __init__(self, token: str) -> None:
        super().__init__()

        self._token = token

    async def _check_token(self, token: str) -> bool:
        return token == self._token

    async def __call__(self, request: Request) -> bool:
        if not await self._check_token(get_token(request)):
            raise InvalidTokenError
        return True


class JWTAuth(HTTPAuth):
    async def __call__(self, request: Request) -> dict[Any, Any]:
        if (data := decode_jwt(get_token(request))) is None:
            raise InvalidTokenError
        return data


static_token_auth = Depends(StaticTokenAuth("secret token"))
jwt_auth = Depends(JWTAuth())
