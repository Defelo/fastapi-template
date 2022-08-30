from typing import cast

from argon2 import PasswordHasher
from argon2.exceptions import InvalidHash, VerificationError

from ..environment import HASH_MEMORY_COST, HASH_TIME_COST
from api.utils.async_thread import run_in_thread


password_hasher = PasswordHasher(HASH_TIME_COST, HASH_MEMORY_COST)


@run_in_thread
def hash_password(password: str) -> str:
    return password_hasher.hash(password)


@run_in_thread
def verify_password(password: str, pw_hash: str) -> bool:
    try:
        return cast(bool, password_hasher.verify(pw_hash, password))
    except (VerificationError, InvalidHash):
        return False
