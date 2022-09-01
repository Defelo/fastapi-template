from fastapi import Depends, Request
from fastapi.openapi.models import HTTPBearer
from fastapi.security.base import SecurityBase

from .exceptions.auth import InvalidTokenError


def get_token(request: Request) -> str:
    authorization: str = request.headers.get("Authorization", "")
    return authorization.removeprefix("Bearer ")


class HTTPAuth(SecurityBase):
    def __init__(self) -> None:
        self.model = HTTPBearer()
        self.scheme_name = self.__class__.__name__

    async def __call__(self, request: Request) -> bool:
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


auth = Depends(StaticTokenAuth("secret token"))
