from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.security.base import SecurityBase
from pytest_mock import MockerFixture

from api import auth
from api.exceptions.auth import InvalidTokenError


@pytest.mark.parametrize("auth_header,token", [("test", "test"), (None, ""), ("Bearer asDF1234", "asDF1234")])
def test__get_token(auth_header: str | None, token: str) -> None:
    request = MagicMock()
    request.headers = {"Authorization": auth_header} if auth_header is not None else {}

    assert auth.get_token(request) == token


async def test__httpauth_constructor(mocker: MockerFixture) -> None:
    httpbearer_patch = mocker.patch("api.auth.HTTPBearer")

    http_auth = auth.HTTPAuth()

    httpbearer_patch.assert_called_once_with()
    assert http_auth.model == httpbearer_patch()
    assert http_auth.scheme_name == http_auth.__class__.__name__
    assert issubclass(auth.HTTPAuth, SecurityBase)


async def test__httpauth_call() -> None:
    request = MagicMock()
    http_auth = MagicMock()
    with pytest.raises(NotImplementedError):
        await auth.HTTPAuth.__call__(http_auth, request)


@pytest.mark.parametrize("token,ok", [("S3cr3t Token!", True), ("asdf1234", False)])
async def test__statictokenauth_check_token(token: str, ok: bool) -> None:
    http_auth = MagicMock()
    http_auth._token = "S3cr3t Token!"
    assert await auth.StaticTokenAuth._check_token(http_auth, token) == ok


async def test__statictokenauth_call__invalid_token(mocker: MockerFixture) -> None:
    get_token = mocker.patch("api.auth.get_token")

    request = MagicMock()
    http_auth = MagicMock()
    http_auth._check_token = AsyncMock(return_value=False)

    with pytest.raises(InvalidTokenError):
        await auth.StaticTokenAuth.__call__(http_auth, request)

    get_token.assert_called_once_with(request)
    http_auth._check_token.assert_called_once_with(get_token())


async def test__statictokenauth_call__valid_token(mocker: MockerFixture) -> None:
    get_token = mocker.patch("api.auth.get_token")

    request = MagicMock()
    http_auth = MagicMock()
    http_auth._check_token = AsyncMock(return_value=True)

    assert await auth.StaticTokenAuth.__call__(http_auth, request) is True

    get_token.assert_called_once_with(request)
    http_auth._check_token.assert_called_once_with(get_token())


async def test__jwtauth_call__invalid_token(mocker: MockerFixture) -> None:
    get_token = mocker.patch("api.auth.get_token")
    mocker.patch("api.auth.decode_jwt", MagicMock(return_value=None))

    request = MagicMock()
    http_auth = MagicMock(force_valid=False)

    assert await auth.JWTAuth.__call__(http_auth, request) is None

    get_token.assert_called_once_with(request)


async def test__jwtauth_call__invalid_token__force_valid(mocker: MockerFixture) -> None:
    get_token = mocker.patch("api.auth.get_token")
    mocker.patch("api.auth.decode_jwt", MagicMock(return_value=None))

    request = MagicMock()
    http_auth = MagicMock(force_valid=True)

    with pytest.raises(InvalidTokenError):
        await auth.JWTAuth.__call__(http_auth, request)

    get_token.assert_called_once_with(request)


async def test__jwtauth_call__valid_token(mocker: MockerFixture) -> None:
    get_token = mocker.patch("api.auth.get_token")
    mocker.patch("api.auth.decode_jwt", MagicMock(return_value={"foo": "bar"}))

    request = MagicMock()
    http_auth = MagicMock()

    assert await auth.JWTAuth.__call__(http_auth, request) == {"foo": "bar"}

    get_token.assert_called_once_with(request)
