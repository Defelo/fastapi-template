import hashlib
from asyncio import get_event_loop
from concurrent.futures import ThreadPoolExecutor
from datetime import timedelta, datetime
from functools import wraps
from typing import Callable, Awaitable, Any, cast, Type, TypeVar

import aiohttp
import jwt
from argon2 import PasswordHasher
from argon2.exceptions import VerificationError, InvalidHash
from pydantic import BaseModel, BaseConfig
from pyotp import TOTP
from uvicorn.protocols.http.h11_impl import STATUS_PHRASES

from .environment import (
    HASH_TIME_COST,
    HASH_MEMORY_COST,
    JWT_SECRET,
    MFA_VALID_WINDOW,
    RECAPTCHA_SECRET,
    RECAPTCHA_SITEKEY,
)
from .exceptions.api_exception import APIException
from .redis import redis

T = TypeVar("T")

password_hasher = PasswordHasher(HASH_TIME_COST, HASH_MEMORY_COST)
executor = ThreadPoolExecutor()


def run_in_thread(func: Callable[..., T]) -> Callable[..., Awaitable[T]]:
    @wraps(func)
    async def inner(*args: Any, **kwargs: Any) -> T:
        return await get_event_loop().run_in_executor(executor, lambda: func(*args, **kwargs))

    return inner


@run_in_thread
def hash_password(password: str) -> str:
    return password_hasher.hash(password)


@run_in_thread
def verify_password(password: str, pw_hash: str) -> bool:
    try:
        return cast(bool, password_hasher.verify(pw_hash, password))
    except (VerificationError, InvalidHash):
        return False


def encode_jwt(data: dict[Any, Any], ttl: timedelta) -> str:
    return jwt.encode({**data, "exp": datetime.utcnow() + ttl}, JWT_SECRET, "HS256")


def decode_jwt(token: str, require: list[str] | None = None) -> dict[Any, Any] | None:
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


def responses(default: type, *args: Type[APIException]) -> dict[int | str, dict[str, Any]]:
    exceptions: dict[int, list[Type[APIException]]] = {}
    for exc in args:
        exceptions.setdefault(exc.status_code, []).append(exc)

    out: dict[int | str, dict[str, Any]] = {}
    for code, excs in exceptions.items():
        examples = {}
        for i, exc in enumerate(excs):
            name = exc.__name__ if len(excs) == 1 else f"{exc.__name__} ({i + 1}/{len(excs)})"
            examples[name] = {"description": exc.description, "value": {"detail": exc.detail}}

        out[code] = {"description": STATUS_PHRASES[code], "content": {"application/json": {"examples": examples}}}

    return out | {200: {"model": default}}


def get_example(arg: Type[BaseModel]) -> dict[str, Any]:
    return cast(dict[str, dict[str, Any]], arg.Config.schema_extra)["example"]


def example(*args: Type[BaseModel], **kwargs: Any) -> Type[BaseConfig]:
    ex = dict(e for arg in args for e in get_example(arg).items())
    return cast(Type[BaseConfig], type("Config", (BaseConfig,), {"schema_extra": {"example": ex | kwargs}}))


def recaptcha_enabled() -> bool:
    return bool(RECAPTCHA_SECRET and RECAPTCHA_SITEKEY)


async def check_recaptcha(response: str) -> bool:
    async with aiohttp.ClientSession() as session:
        async with session.post(
            "https://www.google.com/recaptcha/api/siteverify", data={"secret": RECAPTCHA_SECRET, "response": response}
        ) as resp:
            return cast(bool, (await resp.json())["success"])
