import hashlib
from asyncio import get_event_loop
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta, datetime
from functools import wraps
from typing import Callable, Awaitable, Optional, Any, cast, Type

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHash
from pydantic import BaseModel, BaseConfig
from pyotp import TOTP

from .environment import HASH_TIME_COST, HASH_MEMORY_COST, JWT_SECRET, MFA_VALID_WINDOW
from .redis import redis

password_hasher = PasswordHasher(HASH_TIME_COST, HASH_MEMORY_COST)
executor = ThreadPoolExecutor()


def run_in_thread(func) -> Callable[..., Awaitable]:
    @wraps(func)
    async def inner(*args, **kwargs):
        return await get_event_loop().run_in_executor(executor, lambda: func(*args, **kwargs))

    return inner


@run_in_thread
def hash_password(password: str) -> str:
    return password_hasher.hash(password)


@run_in_thread
def verify_password(password: str, pw_hash: str) -> bool:
    try:
        return password_hasher.verify(pw_hash, password)
    except (VerificationError, InvalidHash):
        return False


def encode_jwt(data: dict, ttl: timedelta) -> str:
    return jwt.encode({**data, "exp": datetime.utcnow() + ttl}, JWT_SECRET, "HS256")


def decode_jwt(token: str, require: list[str] = None) -> Optional[dict]:
    try:
        return jwt.decode(token, JWT_SECRET, ["HS256"], options={"require": [*{*(require or []), "exp"}]})
    except jwt.InvalidTokenError:
        return None


async def check_mfa_code(code: str, secret: str) -> bool:
    if await redis.exists(key := f"mfa_block:{hashlib.sha256(secret.encode()).hexdigest()}:{code}"):
        return False

    if not TOTP(secret).verify(code, valid_window=MFA_VALID_WINDOW):
        return False

    await redis.setex(key, 30 * (2 * MFA_VALID_WINDOW + 2), 1)
    return True


def get_example(arg: Type[BaseModel]) -> dict[str, Any]:
    # noinspection PyUnresolvedReferences
    return cast(dict[str, dict[str, Any]], arg.Config.schema_extra)["example"]


def example(*args: Type[BaseModel], **kwargs: Any) -> Type[BaseConfig]:
    ex = dict(e for arg in args for e in get_example(arg).items())
    return cast(Type[BaseConfig], type("Config", (BaseConfig,), {"schema_extra": {"example": ex | kwargs}}))
