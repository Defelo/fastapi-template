import hashlib

from pyotp import TOTP

from ..environment import MFA_VALID_WINDOW
from ..redis import redis


async def check_mfa_code(code: str, secret: str) -> bool:
    if await redis.exists(key := f"mfa_block:{hashlib.sha256(secret.encode()).hexdigest()}:{code}"):
        return False

    if not TOTP(secret).verify(code, valid_window=MFA_VALID_WINDOW):
        return False

    await redis.setex(key, 30 * (2 * MFA_VALID_WINDOW + 2), 1)
    return True
