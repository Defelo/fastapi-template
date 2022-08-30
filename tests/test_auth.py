from typing import Any, Type
from unittest.mock import AsyncMock, MagicMock

import pytest
from fastapi.security.base import SecurityBase
from pytest_mock import MockerFixture

from ._utils import mock_list
from api import auth
from api.auth import PermissionLevel
from api.exceptions.auth import InvalidTokenError, PermissionDeniedError
from api.exceptions.user import UserNotFoundError
from api.models import User


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


async def test__httpauth_get_session() -> None:
    http_auth = auth.HTTPAuth()

    with pytest.raises(NotImplementedError):
        await http_auth._get_session("test")


async def test__httpauth_call__invalid_token(mocker: MockerFixture) -> None:
    get_token = mocker.patch("api.auth.get_token")

    request = MagicMock()
    http_auth = MagicMock()
    http_auth._get_session = AsyncMock(return_value=None)

    with pytest.raises(InvalidTokenError):
        await auth.HTTPAuth.__call__(http_auth, request)

    get_token.assert_called_once_with(request)
    http_auth._get_session.assert_called_once_with(get_token())


async def test__httpauth_call__valid_token(mocker: MockerFixture) -> None:
    get_token = mocker.patch("api.auth.get_token")

    request = MagicMock()
    http_auth = MagicMock()
    http_auth._get_session = AsyncMock(return_value=MagicMock())

    result = await auth.HTTPAuth.__call__(http_auth, request)

    get_token.assert_called_once_with(request)
    http_auth._get_session.assert_called_once_with(get_token())
    assert result == http_auth._get_session.return_value


async def test__userauth_constructor() -> None:
    min_level = MagicMock()

    user_auth = auth.UserAuth(min_level)

    assert user_auth.min_level == min_level
    assert issubclass(auth.UserAuth, auth.HTTPAuth)


async def test__userauth_get_session(mocker: MockerFixture) -> None:
    from_access_token = mocker.patch("api.auth.Session.from_access_token", AsyncMock())

    result = await auth.UserAuth._get_session(MagicMock(), "my access token")

    from_access_token.assert_called_once_with("my access token")
    assert result == await from_access_token()


@pytest.mark.parametrize("valid", [True, False])
async def test__userauth_call__public(valid: bool, mocker: MockerFixture) -> None:
    request = MagicMock()
    session = MagicMock()

    async def super_call(_: Any, r: Any) -> Any:
        assert r == request
        if valid:
            return session
        raise InvalidTokenError

    mocker.patch("api.auth.HTTPAuth.__call__", super_call)

    result = await auth.UserAuth(PermissionLevel.PUBLIC)(request)

    assert result == (session if valid else None)


@pytest.mark.parametrize(
    "permission_level,valid,admin,exc",
    [
        (PermissionLevel.USER, False, False, InvalidTokenError),
        (PermissionLevel.ADMIN, False, False, InvalidTokenError),
        (PermissionLevel.USER, True, False, None),
        (PermissionLevel.ADMIN, True, False, PermissionDeniedError),
        (PermissionLevel.USER, True, True, None),
        (PermissionLevel.ADMIN, True, True, None),
    ],
)
async def test__userauth_call(
    permission_level: PermissionLevel, valid: bool, admin: bool, exc: Type[Exception] | None, mocker: MockerFixture
) -> None:
    request = MagicMock()
    session = MagicMock()
    session.user.admin = admin

    async def super_call(_: Any, r: Any) -> Any:
        assert r == request
        if valid:
            return session
        raise InvalidTokenError

    mocker.patch("api.auth.HTTPAuth.__call__", super_call)

    user_auth = auth.UserAuth(permission_level)

    if exc is None:
        result = await user_auth(request)
        assert result == session
    else:
        with pytest.raises(exc):
            await user_auth(request)


@pytest.mark.parametrize("valid,admin", [(False, False), (True, False), (True, True)])
async def test__is_admin(valid: bool, admin: bool) -> None:
    session = MagicMock(user=MagicMock(admin=admin)) if valid else None

    assert await auth.is_admin.dependency(session) == (valid and admin)
    assert auth.is_admin.dependency.__defaults__ == (auth.public_auth,)


async def test__get_user_dependency__not_found(mocker: MockerFixture) -> None:
    db = mocker.patch("api.auth.db")
    db.get = AsyncMock(return_value=None)

    args = mock_list(5)

    with pytest.raises(UserNotFoundError):
        await auth._get_user_dependency(*args)("some_user_id", None)

    db.get.assert_called_once_with(User, *args, id="some_user_id")


async def test__get_user_dependency__by_id(mocker: MockerFixture) -> None:
    user = MagicMock()
    db = mocker.patch("api.auth.db")
    db.get = AsyncMock(return_value=user)

    args = mock_list(5)

    assert await auth._get_user_dependency(*args)("some_user_id", None) == user

    db.get.assert_called_once_with(User, *args, id="some_user_id")


@pytest.mark.parametrize("alias", ["self", "me"])
async def test__get_user_dependency__self(alias: str, mocker: MockerFixture) -> None:
    user = MagicMock()
    session = MagicMock(user_id="some_user_id")
    db = mocker.patch("api.auth.db")
    db.get = AsyncMock(return_value=user)

    args = mock_list(5)

    assert await auth._get_user_dependency(*args)(alias, session) == user

    db.get.assert_called_once_with(User, *args, id="some_user_id")


@pytest.mark.parametrize(
    "user_id,session_user_id,admin,ok",
    [
        ("me", "some_user_id", False, True),
        ("self", "some_user_id", False, True),
        ("some_user_id", "some_user_id", False, True),
        ("some_user_id", "other_user_id", True, True),
        ("some_user_id", "other_user_id", False, False),
    ],
)
async def test__get_user_privileged(
    session_user_id: str, user_id: str, admin: bool, ok: bool, mocker: MockerFixture
) -> None:
    user = MagicMock(id=user_id, admin=admin)
    session = MagicMock(user_id=session_user_id, user=user)

    get_user_dependency = mocker.patch("api.auth._get_user_dependency")
    get_user_dependency.return_value = AsyncMock(return_value=user)

    args = mock_list(5)

    if ok:
        assert await auth._get_user_privileged_dependency(*args)(user_id, session) == user
        get_user_dependency.assert_called_once_with(*args)
        get_user_dependency().assert_called_once_with(session_user_id if user_id in ["self", "me"] else user_id, None)
    else:
        with pytest.raises(PermissionDeniedError):
            await auth._get_user_privileged_dependency(*args)(user_id, session)


@pytest.mark.parametrize("require_self_or_admin", [True, False])
async def test__get_user(require_self_or_admin: bool, mocker: MockerFixture) -> None:
    get_user_dependency = mocker.patch("api.auth._get_user_dependency")
    get_user_privileged_dependency = mocker.patch("api.auth._get_user_privileged_dependency")
    depends = mocker.patch("api.auth.Depends")

    args = mock_list(5)

    result = auth.get_user(*args, require_self_or_admin=require_self_or_admin)

    if require_self_or_admin:
        get_user_privileged_dependency.assert_called_once_with(*args)
        depends.assert_called_once_with(get_user_privileged_dependency())
    else:
        get_user_dependency.assert_called_once_with(*args)
        depends.assert_called_once_with(get_user_dependency())

    assert result == depends()
