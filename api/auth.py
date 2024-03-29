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
    def __init__(self, *, audience: list[str] | None = None, force_valid: bool = True):
        super().__init__()
        self.audience: list[str] | None = audience
        self.force_valid: bool = force_valid

    async def __call__(self, request: Request) -> dict[Any, Any] | None:
        if (data := decode_jwt(get_token(request), audience=self.audience)) is None and self.force_valid:
            raise InvalidTokenError
        return data


class InternalAuth(JWTAuth):
    def __init__(self, audience: list[str] | None = None):
        super().__init__(audience=audience, force_valid=True)


static_token_auth = Depends(StaticTokenAuth("secret token"))
jwt_auth = Depends(JWTAuth())
internal_auth = Depends(InternalAuth(audience=["service_xyz"]))
