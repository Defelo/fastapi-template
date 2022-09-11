from datetime import datetime, timedelta
from typing import Any

import jwt

from ..settings import settings


def encode_jwt(data: dict[Any, Any], ttl: timedelta) -> str:
    return jwt.encode({**data, "exp": datetime.utcnow() + ttl}, settings.jwt_secret, "HS256")


def decode_jwt(
    token: str, *, require: list[str] | None = None, audience: list[str] | None = None
) -> dict[Any, Any] | None:
    try:
        return jwt.decode(
            token,
            settings.jwt_secret,
            ["HS256"],
            audience=audience,
            options={"require": [*{*(require or []), "exp"}], "verify_aud": bool(audience)},
        )
    except jwt.InvalidTokenError:
        return None
