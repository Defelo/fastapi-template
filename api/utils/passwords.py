from typing import cast

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError

from api.settings import settings
from api.utils.async_thread import run_in_thread


password_hasher = PasswordHasher(settings.hash_time_cost, settings.hash_memory_cost)


@run_in_thread
def hash_password(password: str) -> str:
    return password_hasher.hash(password)


@run_in_thread
def verify_password(password: str, pw_hash: str) -> bool:
    try:
        return cast(bool, password_hasher.verify(pw_hash, password))
    except (VerificationError, InvalidHash):
        return False
