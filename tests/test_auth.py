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

    result = auth.get_token(request)

    assert result == token


async def test__constructor(mocker: MockerFixture) -> None:
    httpbearer_patch = mocker.patch("api.auth.HTTPBearer")

    token = MagicMock()

    http_auth = auth.HTTPAuth(token)

    httpbearer_patch.assert_called_once_with()
    assert token == http_auth._token
    assert httpbearer_patch() == http_auth.model
    assert http_auth.__class__.__name__ == http_auth.scheme_name
    assert issubclass(auth.HTTPAuth, SecurityBase)


@pytest.mark.parametrize("token,ok", [("S3cr3t Token!", True), ("asdf1234", False)])
async def test__check_token(token: str, ok: bool) -> None:
    http_auth = MagicMock()
    http_auth._token = "S3cr3t Token!"
    assert await auth.HTTPAuth._check_token(http_auth, token) == ok


async def test__call__invalid_token(mocker: MockerFixture) -> None:
    get_token = mocker.patch("api.auth.get_token")

    request = MagicMock()
    http_auth = MagicMock()
    http_auth._check_token = AsyncMock(return_value=False)

    with pytest.raises(InvalidTokenError):
        await auth.HTTPAuth.__call__(http_auth, request)

    get_token.assert_called_once_with(request)
    http_auth._check_token.assert_called_once_with(get_token())


async def test__call__valid_token(mocker: MockerFixture) -> None:
    get_token = mocker.patch("api.auth.get_token")

    request = MagicMock()
    http_auth = MagicMock()
    http_auth._check_token = AsyncMock(return_value=True)

    assert await auth.HTTPAuth.__call__(http_auth, request) is True

    get_token.assert_called_once_with(request)
    http_auth._check_token.assert_called_once_with(get_token())
