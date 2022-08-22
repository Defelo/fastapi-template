from datetime import datetime
from typing import Any, Literal, Type
from unittest.mock import AsyncMock, MagicMock

import pytest
from httpx import AsyncClient
from pytest_mock import MockerFixture

from ..utils import mock_asynccontextmanager
from api import models
from api.database import db, db_wrapper, select
from api.exceptions.api_exception import APIException
from api.exceptions.oauth import InvalidOAuthTokenError, RemoteAlreadyLinkedError
from api.exceptions.user import (
    NoLoginMethodError,
    OAuthRegistrationDisabledError,
    RecaptchaError,
    RegistrationDisabledError,
    UserAlreadyExistsError,
)
from api.models.session import _hash_token
from api.utils import decode_jwt, verify_password


async def _get_users() -> list[models.User]:
    admin = await models.User.create("admin", "admin_password", True, True)
    admin.id = "admin"

    foo = await models.User.create("foo", "foo_password", True, False)
    foo.id = "foo"
    foo.mfa_enabled = True

    bar = await models.User.create("bar", None, True, False)
    bar.id = "bar"

    disabled = await models.User.create("disabled", None, False, False)
    disabled.id = "disabled"

    return [admin, foo, bar, disabled]


async def test__get_users__forbidden(user_client: AsyncClient) -> None:
    response = await user_client.get("/users")
    assert response.status_code == 403


@pytest.mark.parametrize(
    "limit,offset,name,enabled,admin,mfa_enabled,total,indices",
    [
        (100, 0, None, None, None, None, 4, [0, 1, 2, 3]),  # all users
        (2, 0, None, None, None, None, 4, [0, 1]),  # first page
        (2, 2, None, None, None, None, 4, [2, 3]),  # second page
        (100, 0, "foo", None, None, None, 1, [1]),  # filter by name
        (100, 0, "a", None, None, None, 3, [2, 0, 3]),  # filter by name
        (100, 0, None, True, None, None, 3, [0, 1, 2]),  # filter by enabled (True)
        (100, 0, None, False, None, None, 1, [3]),  # filter by enabled (False)
        (100, 0, None, None, True, None, 1, [0]),  # filter by admin (True)
        (100, 0, None, None, False, None, 3, [1, 2, 3]),  # filter by admin (False)
        (100, 0, None, None, None, True, 1, [1]),  # filter by mfa_enabled (True)
        (100, 0, None, None, None, False, 3, [0, 2, 3]),  # filter by mfa_enabled (False)
    ],
)
@db_wrapper
async def test__get_users(
    limit: int,
    offset: int,
    name: str | None,
    enabled: bool | None,
    admin: bool | None,
    mfa_enabled: bool | None,
    total: int,
    indices: list[int],
    admin_client: AsyncClient,
) -> None:
    users = await _get_users()

    params: dict[str, Any] = {"limit": limit, "offset": offset}
    if name is not None:
        params["name"] = name
    if enabled is not None:
        params["enabled"] = enabled
    if admin is not None:
        params["admin"] = admin
    if mfa_enabled is not None:
        params["mfa_enabled"] = mfa_enabled

    response = await admin_client.get("/users", params=params)
    assert response.status_code == 200
    data = response.json()
    assert data["total"] == total
    assert data["users"] == [users[i].serialize for i in indices]


@pytest.mark.user_params(id="foo")
@db_wrapper
async def test__get_user_by_id(user_client: AsyncClient, session: MagicMock) -> None:
    users = await _get_users()

    response = await user_client.get("/users/foo")
    assert response.status_code == 200
    assert response.json() == users[1].serialize

    assert (await user_client.get("/users/bar")).status_code == 403
    session.user.admin = True
    assert (await user_client.get("/users/bar")).status_code == 200


@pytest.mark.parametrize(
    "name_exists,password,oauth_token,admin,enabled,is_admin,open_registration,open_oauth_registration,"
    "recaptcha,expected_error",
    [
        (False, False, "none", False, True, False, True, True, "disabled", NoLoginMethodError),
        (False, True, "none", False, True, False, False, True, "disabled", RegistrationDisabledError),
        (False, False, "valid", False, True, False, True, False, "disabled", OAuthRegistrationDisabledError),
        (False, True, "none", False, True, False, True, True, "invalid", RecaptchaError),
        (True, True, "none", False, True, False, True, True, "disabled", UserAlreadyExistsError),
        (False, False, "invalid", False, True, False, True, True, "disabled", InvalidOAuthTokenError),
        (False, False, "linked", False, True, False, True, True, "disabled", RemoteAlreadyLinkedError),
        (False, True, "none", False, True, False, True, True, "valid", None),
        (False, False, "valid", False, True, False, True, True, "valid", None),
        (False, True, "valid", False, True, False, True, True, "valid", None),
        (False, True, "none", True, True, False, True, True, "valid", None),
        (False, True, "none", True, False, False, True, True, "valid", None),
        (False, True, "none", False, False, False, True, True, "valid", None),
        (False, True, "none", False, True, True, True, True, "valid", None),
        (False, True, "none", True, True, True, True, True, "valid", None),
        (False, True, "none", True, False, True, True, True, "valid", None),
        (False, True, "none", False, False, True, True, True, "valid", None),
    ],
)
@db_wrapper
async def test__create_user(
    name_exists: bool,
    password: bool,
    oauth_token: Literal["valid", "invalid", "linked", "none"],
    admin: bool,
    enabled: bool,
    is_admin: bool,
    open_registration: bool,
    open_oauth_registration: bool,
    recaptcha: Literal["valid", "invalid", "disabled"],
    expected_error: Type[APIException] | None,
    user_client: AsyncClient,
    session: MagicMock,
    mocker: MockerFixture,
) -> None:
    _cnt = len(await _get_users())

    data: dict[str, Any] = {"name": "username" if not name_exists else "admin", "admin": admin, "enabled": enabled}
    if password:
        data["password"] = "Password1234"
    if oauth_token != "none":
        data["oauth_register_token"] = "token"
    if recaptcha != "disabled":
        data["recaptcha_response"] = "correct_response" if recaptcha == "valid" else "incorrect_response"

    mocker.patch("api.endpoints.user.recaptcha_enabled", MagicMock(return_value=recaptcha != "disabled"))
    mocker.patch("api.endpoints.user.check_recaptcha", AsyncMock(side_effect="correct_response".__eq__))

    session.user.admin = is_admin
    mocker.patch("api.endpoints.user.OPEN_REGISTRATION", open_registration)
    mocker.patch("api.endpoints.user.OPEN_OAUTH_REGISTRATION", open_oauth_registration)

    pipe = AsyncMock()
    pipeline, *_ = mock_asynccontextmanager(0, pipe)
    mocker.patch("api.endpoints.user.redis.pipeline", pipeline)
    calls: list[str] = []
    pipe.get = AsyncMock(side_effect=calls.append)

    async def _pipe_execute() -> tuple[str | None, str | None, str | None]:
        assert calls == [f"oauth_register_token:token:{k}" for k in ["provider", "user_id", "display_name"]]
        if oauth_token == "invalid":
            return None, None, None
        return "provider_id", "remote_user_id", "display_name"

    pipe.execute = _pipe_execute

    redis_delete = mocker.patch("api.endpoints.user.redis.delete", AsyncMock())

    if oauth_token == "linked":
        await models.OAuthUserConnection.create("admin", "provider_id", "remote_user_id", "display_name")

    response = await user_client.post("/users", json=data, headers={"User-agent": "my device"})

    users = await db.all(select(models.User, models.User.sessions))

    if expected_error is not None:
        assert response.status_code == expected_error.status_code
        assert response.text == expected_error.detail
        assert len(users) == _cnt
    else:
        assert response.status_code == 200
        assert len(users) == _cnt + 1
        json = response.json()
        user: models.User = users[-1]
        assert json["user"] == user.serialize

        assert user.name == data["name"]
        if password:
            assert await verify_password("Password1234", user.password)
        else:
            assert user.password is None
        assert abs(datetime.utcnow() - user.registration).total_seconds() < 10
        assert user.last_login is not None
        assert abs(datetime.utcnow() - user.last_login).total_seconds() < 10
        if is_admin:
            assert user.admin is admin
            assert user.enabled is enabled
        else:
            assert user.admin is False
            assert user.enabled is True
        assert user.mfa_enabled is False
        assert user.mfa_secret is None
        assert user.mfa_recovery_code is None

        assert len(user.sessions) == 1
        sess = user.sessions[0]
        assert json["session"] == sess.serialize
        jwt = decode_jwt(json["access_token"])
        assert jwt is not None
        assert jwt["uid"] == user.id
        assert jwt["sid"] == sess.id
        assert jwt["rt"] == sess.refresh_token
        assert _hash_token(json["refresh_token"]) == sess.refresh_token
        assert sess.device_name == "my device"

        connections = await db.all(select(models.OAuthUserConnection))
        if oauth_token == "none":
            assert len(connections) == 0
        else:
            assert len(connections) == 1
            assert connections[0].user_id == users[-1].id
            assert connections[0].provider_id == "provider_id"
            assert connections[0].remote_user_id == "remote_user_id"
            assert connections[0].display_name == "display_name"

    if calls and expected_error is not InvalidOAuthTokenError:
        redis_delete.assert_called_once_with(*calls)
