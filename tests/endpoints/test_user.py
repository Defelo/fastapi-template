import hashlib
from datetime import datetime
from typing import Any, Literal, Type
from unittest.mock import AsyncMock, MagicMock

import pytest
from _pytest.monkeypatch import MonkeyPatch
from httpx import AsyncClient
from pytest_mock import MockerFixture

from .._utils import mock_asynccontextmanager
from api import models
from api.database import db, db_wrapper, select
from api.exceptions.api_exception import APIException
from api.exceptions.auth import PermissionDeniedError
from api.exceptions.oauth import InvalidOAuthTokenError, RemoteAlreadyLinkedError
from api.exceptions.user import (
    CannotDeleteLastLoginMethodError,
    InvalidCodeError,
    MFAAlreadyEnabledError,
    MFANotEnabledError,
    MFANotInitializedError,
    NoLoginMethodError,
    OAuthRegistrationDisabledError,
    RecaptchaError,
    RegistrationDisabledError,
    UserAlreadyExistsError,
)
from api.models.session import _hash_token
from api.settings import settings
from api.utils.jwt import decode_jwt
from api.utils.passwords import verify_password


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
    monkeypatch: MonkeyPatch,
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
    monkeypatch.setattr(settings, "open_registration", open_registration)
    monkeypatch.setattr(settings, "open_oauth_registration", open_oauth_registration)

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


@pytest.mark.parametrize(
    "name,password,enabled,admin,is_self,is_enabled,is_admin,oauth,expected_error",
    [
        # change username
        ("set", "unchanged", True, False, True, True, False, False, PermissionDeniedError),
        ("conflict", "unchanged", True, False, True, True, True, False, UserAlreadyExistsError),
        ("set", "unchanged", True, True, True, True, True, False, None),
        # change password
        ("unchanged", "clear", True, False, True, True, False, False, CannotDeleteLastLoginMethodError),
        ("unchanged", "clear", True, False, True, True, False, True, None),
        ("unchanged", "set", True, False, True, True, False, False, None),
        ("unchanged", "set", True, False, True, True, False, True, None),
        # change enabled
        ("unchanged", "unchanged", False, False, True, True, False, False, PermissionDeniedError),
        ("unchanged", "unchanged", False, False, False, True, True, False, None),
        ("unchanged", "unchanged", True, False, False, False, True, False, None),
        # change admin
        ("unchanged", "unchanged", True, True, True, True, False, False, PermissionDeniedError),
        ("unchanged", "unchanged", True, True, False, True, False, False, PermissionDeniedError),
        ("unchanged", "unchanged", True, True, False, True, True, False, None),
        # combined
        ("set", "clear", False, False, False, True, True, True, None),
        ("set", "set", True, True, False, True, True, False, None),
        ("unchanged", "set", True, False, False, True, True, False, None),
    ],
)
@db_wrapper
async def test__update_user(
    name: Literal["unchanged", "set", "conflict"],
    password: Literal["unchanged", "set", "clear"],
    enabled: bool,
    admin: bool,
    is_self: bool,
    is_enabled: bool,
    is_admin: bool,
    oauth: bool,
    expected_error: Type[APIException] | None,
    user_client: AsyncClient,
    session: MagicMock,
) -> None:
    user = (await _get_users())[1]
    user.enabled = is_enabled
    user.admin = is_admin
    user.logout = AsyncMock()  # type: ignore
    serialized = user.serialize

    data: dict[str, Any] = {"enabled": enabled, "admin": admin}
    serialized |= data

    if name != "unchanged":
        serialized["name"] = data["name"] = "test123" if name == "set" else "admin"
    if password != "unchanged":
        data["password"] = "Password1234" if password == "set" else ""
        serialized["password"] = password == "set"

    if is_self:
        session.user.id = session.user_id = user.id
    if is_admin:
        session.user.admin = True

    if oauth:
        await models.OAuthUserConnection.create(user.id, "provider_id", "remote_user_id", "display_name")

    response = await user_client.patch(f"/users/{user.id}", json=data)

    if expected_error is not None:
        assert response.status_code == expected_error.status_code
        assert response.text == expected_error.detail
    else:
        assert response.status_code == 200
        assert response.json() == serialized
        if not enabled:
            user.logout.assert_called_once_with()


@pytest.mark.parametrize("enabled", [True, False])
@pytest.mark.user_params(id="foo")
@db_wrapper
async def test__initialize_mfa(enabled: bool, user_client: AsyncClient, session: MagicMock) -> None:
    user = (await _get_users())[1]
    if not enabled:
        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_recovery_code = None

    response = await user_client.post(f"/users/{user.id}/mfa")

    if enabled:
        assert response.status_code == MFAAlreadyEnabledError.status_code
        assert response.text == MFAAlreadyEnabledError.detail
        return

    assert response.status_code == 200
    assert response.json() == user.mfa_secret
    assert user.mfa_enabled is False
    assert user.mfa_secret is not None and len(user.mfa_secret) >= 16
    assert user.mfa_recovery_code is None

    assert (await user_client.post("/users/admin/mfa")).status_code == 403
    session.user.admin = True
    assert (await user_client.post("/users/admin/mfa")).status_code == 200


@pytest.mark.parametrize(
    "state,code_valid,expected_error",
    [
        ("enabled", True, MFAAlreadyEnabledError),
        ("disabled", True, MFANotInitializedError),
        ("initialized", False, InvalidCodeError),
        ("initialized", True, None),
    ],
)
@pytest.mark.user_params(id="bar")
@db_wrapper
async def test__enable_mfa(
    state: Literal["enabled", "initialized", "disabled"],
    code_valid: bool,
    expected_error: Type[APIException] | None,
    user_client: AsyncClient,
    mocker: MockerFixture,
    session: MagicMock,
) -> None:
    user = (await _get_users())[2]

    if state != "disabled":
        user.mfa_secret = "secret"
    if state == "enabled":
        user.mfa_enabled = True
        user.mfa_recovery_code = "recovery_code"

    mocker.patch("api.endpoints.user.check_mfa_code", return_value=code_valid)

    response = await user_client.put(f"/users/{user.id}/mfa", json={"code": "123456"})

    if expected_error is not None:
        assert response.status_code == expected_error.status_code
        assert response.text == expected_error.detail
    else:
        assert response.status_code == 200
        assert hashlib.sha256(response.json().encode()).hexdigest() == user.mfa_recovery_code
        assert user.mfa_enabled is True
        assert user.mfa_secret == "secret"
        assert user.mfa_recovery_code is not None and len(user.mfa_recovery_code) >= 16

        assert (await user_client.put("/users/admin/mfa", json={"code": "123456"})).status_code == 403
        session.user.admin = True
        assert (await user_client.put("/users/admin/mfa", json={"code": "123456"})).status_code == 412


@pytest.mark.parametrize("enabled", [True, False])
@pytest.mark.user_params(id="foo")
@db_wrapper
async def test__disable_mfa(enabled: bool, user_client: AsyncClient, session: MagicMock) -> None:
    user = (await _get_users())[1]
    if not enabled:
        user.mfa_enabled = False
        user.mfa_secret = None
        user.mfa_recovery_code = None

    response = await user_client.delete(f"/users/{user.id}/mfa")

    if not enabled:
        assert response.status_code == MFANotEnabledError.status_code
        assert response.text == MFANotEnabledError.detail
        return

    assert response.status_code == 200
    assert response.json() is True
    assert user.mfa_enabled is False
    assert user.mfa_secret is None
    assert user.mfa_recovery_code is None

    assert (await user_client.delete("/users/admin/mfa")).status_code == 403
    session.user.admin = True
    assert (await user_client.delete("/users/admin/mfa")).status_code == 412


@pytest.mark.parametrize(
    "open_registration,open_oauth_registration,admin,is_self,is_admin,other_admins,expected_error",
    [
        (False, False, False, True, False, True, PermissionDeniedError),
        (True, True, True, True, True, False, PermissionDeniedError),
        (True, True, False, True, False, True, None),
        (False, True, False, True, False, True, None),
        (True, False, False, True, False, True, None),
        (True, True, True, True, True, True, None),
        (True, True, False, False, True, True, None),
    ],
)
@db_wrapper
async def test__delete(
    open_registration: bool,
    open_oauth_registration: bool,
    admin: bool,
    is_self: bool,
    is_admin: bool,
    other_admins: bool,
    expected_error: Type[APIException] | None,
    user_client: AsyncClient,
    session: MagicMock,
    mocker: MockerFixture,
    monkeypatch: MonkeyPatch,
) -> None:
    admin_user, user, *other_users = await _get_users()
    user.admin = admin
    user.logout = AsyncMock()  # type: ignore

    if not other_admins:
        admin_user.admin = False

    monkeypatch.setattr(settings, "open_registration", open_registration)
    monkeypatch.setattr(settings, "open_oauth_registration", open_oauth_registration)

    session.user.admin = is_admin
    if is_self:
        session.user_id = session.user.id = user.id

    response = await user_client.delete(f"/users/{user.id}")
    user_ids = {u.id for u in await db.all(select(models.User))}

    if expected_error is not None:
        assert response.status_code == expected_error.status_code
        assert response.text == expected_error.detail
        assert user_ids == {u.id for u in other_users} | {admin_user.id, user.id}
    else:
        assert response.status_code == 200
        assert response.json() is True
        assert user_ids == {u.id for u in other_users} | {admin_user.id}
