import hashlib
from unittest.mock import AsyncMock

from pytest_mock import MockerFixture

from api.utils import mfa


async def test__check_mfa_code__blocked(mocker: MockerFixture) -> None:
    redis_patch = mocker.patch("api.utils.mfa.redis")

    code = "421337"
    secret = "tRtD1eq5oMJydVA6zxUsohZdMIKTGgoj"
    key = f"mfa_block:{hashlib.sha256(secret.encode()).hexdigest()}:{code}"
    redis_patch.exists.return_value = True

    assert await mfa.check_mfa_code(code, secret) is False

    redis_patch.exists.assert_called_once_with(key)


async def test__check_mfa_code__invalid(mocker: MockerFixture) -> None:
    redis_patch = mocker.patch("api.utils.mfa.redis", new_callable=AsyncMock)
    totp_patch = mocker.patch("api.utils.mfa.TOTP")
    mocker.patch("api.utils.mfa.MFA_VALID_WINDOW", 42)

    code = "421337"
    secret = "tRtD1eq5oMJydVA6zxUsohZdMIKTGgoj"
    key = f"mfa_block:{hashlib.sha256(secret.encode()).hexdigest()}:{code}"
    redis_patch.exists.return_value = False
    totp_patch.return_value.verify.return_value = False

    assert await mfa.check_mfa_code(code, secret) is False

    redis_patch.exists.assert_called_once_with(key)
    totp_patch.assert_called_once_with(secret)
    totp_patch.return_value.verify.assert_called_once_with(code, valid_window=42)


async def test__check_mfa_code__valid(mocker: MockerFixture) -> None:
    redis_patch = mocker.patch("api.utils.mfa.redis", new_callable=AsyncMock)
    totp_patch = mocker.patch("api.utils.mfa.TOTP")
    mocker.patch("api.utils.mfa.MFA_VALID_WINDOW", 42)

    code = "421337"
    secret = "tRtD1eq5oMJydVA6zxUsohZdMIKTGgoj"
    key = f"mfa_block:{hashlib.sha256(secret.encode()).hexdigest()}:{code}"
    redis_patch.exists.return_value = False
    totp_patch.return_value.verify.return_value = True

    assert await mfa.check_mfa_code(code, secret) is True

    redis_patch.exists.assert_called_once_with(key)
    totp_patch.assert_called_once_with(secret)
    totp_patch.return_value.verify.assert_called_once_with(code, valid_window=42)
    redis_patch.setex.assert_called_once_with(key, 2580, 1)
