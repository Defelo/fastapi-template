from asyncio import get_event_loop
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta, datetime
from functools import wraps
from typing import Callable, Awaitable, Optional

import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHash

from .environment import HASH_TIME_COST, HASH_MEMORY_COST, JWT_SECRET

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


def get_example(arg: type) -> dict:
    # noinspection PyUnresolvedReferences
    return arg.Config.schema_extra["example"]


def example(*args, **kwargs) -> type:
    ex = dict(e for arg in args for e in get_example(arg).items())
    return type("Config", (), {"schema_extra": {"example": ex | kwargs}})
