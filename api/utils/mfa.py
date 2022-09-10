import hashlib

from pyotp import TOTP

from ..redis import redis
from ..settings import settings


async def check_mfa_code(code: str, secret: str) -> bool:
    if await redis.exists(key := f"mfa_block:{hashlib.sha256(secret.encode()).hexdigest()}:{code}"):
        return False

    if not TOTP(secret).verify(code, valid_window=settings.mfa_valid_window):
        return False

    await redis.setex(key, 30 * (2 * settings.mfa_valid_window + 2), 1)
    return True
