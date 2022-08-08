from datetime import datetime
from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest_mock import MockerFixture
from sqlalchemy import func

from api.database import select
from api.models import User


@pytest.mark.parametrize(
    "enabled,admin,password,mfa", [(True, False, "asdf", False), (False, True, None, True), (True, True, None, False)]
)
async def test__serialize(enabled: bool, admin: bool, password: str | None, mfa: bool) -> None:
    obj = User(
        id="user_id",
        name="user_name",
        registration=datetime.fromtimestamp(123456),
        last_login=datetime.fromtimestamp(345678),
        enabled=enabled,
        admin=admin,
        password=password,
        mfa_enabled=mfa,
    )

    assert obj.serialize == {
        "id": "user_id",
        "name": "user_name",
        "registration": 123456,
        "last_login": 345678,
        "enabled": enabled,
        "admin": admin,
        "password": bool(password),
        "mfa_enabled": mfa,
    }


@pytest.mark.parametrize("enabled,admin,password", [(True, False, "asdf"), (False, True, None), (True, True, None)])
async def test__create(enabled: bool, admin: bool, password: str | None, mocker: MockerFixture) -> None:
    hash_password = mocker.patch("api.models.user.hash_password", new_callable=AsyncMock)
    dt = mocker.patch("api.models.user.datetime")
    db = mocker.patch("api.models.user.db", new_callable=AsyncMock)

    obj = await User.create("user_name", password, enabled, admin)

    if password:
        hash_password.assert_called_once_with(password)
    dt.utcnow.assert_called_once()
    db.add.assert_called_once_with(obj)

    assert obj.name == "user_name"
    assert obj.password == (await hash_password() if password else None)
    assert obj.registration == dt.utcnow()
    assert obj.last_login is None
    assert obj.enabled == enabled
    assert obj.admin == admin
    assert obj.mfa_secret is None
    assert obj.mfa_enabled is False
    assert obj.mfa_recovery_code is None


async def test__filter_by_name() -> None:
    assert User.filter_by_name("UserName") == select(User).where(func.lower(User.name) == "username")


async def test__initialize__no_users(mocker: MockerFixture) -> None:
    mocker.patch("api.models.user.ADMIN_USERNAME", "admin_username")
    mocker.patch("api.models.user.ADMIN_PASSWORD", "admin_password")
    db = mocker.patch("api.models.user.db", new_callable=AsyncMock)
    db.exists.return_value = False
    create = mocker.patch("api.models.user.User.create", new_callable=AsyncMock)

    await User.initialize()

    db.exists.assert_called_once_with(select(User))
    create.assert_called_once_with("admin_username", "admin_password", True, True)


async def test__initialize__with_users(mocker: MockerFixture) -> None:
    db = mocker.patch("api.models.user.db", new_callable=AsyncMock)
    db.exists.return_value = True
    create = mocker.patch("api.models.user.User.create", new_callable=AsyncMock)

    await User.initialize()

    db.exists.assert_called_once_with(select(User))
    create.assert_not_called()


@pytest.mark.parametrize("arg,db,ok", [("foo", "foo", True), ("foo", "bar", False), ("foo", None, False)])
async def test__check_password(arg: str, db: str | None, ok: bool, mocker: MockerFixture) -> None:
    mocker.patch("api.models.user.verify_password", AsyncMock(side_effect=str.__eq__))

    user = User(password=db)
    assert await user.check_password(arg) == ok


@pytest.mark.parametrize("pw", ["asdf", None])
async def test__change_password(pw: str | None, mocker: MockerFixture) -> None:
    hash_password = mocker.patch("api.models.user.hash_password", new_callable=AsyncMock)

    user = User(password="foobar")  # noqa: S106
    await user.change_password(pw)

    if pw:
        hash_password.assert_called_once_with(pw)
        assert user.password == await hash_password()
    else:
        hash_password.assert_not_called()
        assert user.password is None


async def test__create_session(mocker: MockerFixture) -> None:
    dt = mocker.patch("api.models.user.datetime")
    create = mocker.patch("api.models.session.Session.create", new_callable=AsyncMock)

    user = User(id="my_user_id")
    session = await user.create_session("my device name")

    dt.utcnow.assert_called_once()
    create.assert_called_once_with("my_user_id", "my device name")
    assert session == await create()
    assert user.last_login == dt.utcnow()


async def test__from_access_token__invalid_jwt(mocker: MockerFixture) -> None:
    decode_jwt = mocker.patch("api.models.user.decode_jwt", MagicMock(return_value=None))

    assert await User.from_access_token("my_token") is None
    decode_jwt.assert_called_once_with("my_token", ["uid", "sid", "rt"])


async def test__from_access_token__logout(mocker: MockerFixture) -> None:
    data = {"rt": "my_refresh_token"}
    decode_jwt = mocker.patch("api.models.user.decode_jwt", MagicMock(return_value=data))
    exists = mocker.patch("api.models.user.redis.exists", AsyncMock(return_value=True))

    assert await User.from_access_token("my_token") is None
    decode_jwt.assert_called_once_with("my_token", ["uid", "sid", "rt"])
    exists.assert_called_once_with("session_logout:my_refresh_token")


async def test__from_access_token__valid(mocker: MockerFixture) -> None:
    data = {"rt": "my_refresh_token", "uid": "my_uid"}
    decode_jwt = mocker.patch("api.models.user.decode_jwt", MagicMock(return_value=data))
    exists = mocker.patch("api.models.user.redis.exists", AsyncMock(return_value=False))
    db = mocker.patch("api.models.user.db", new_callable=AsyncMock)

    result = await User.from_access_token("my_token")

    decode_jwt.assert_called_once_with("my_token", ["uid", "sid", "rt"])
    exists.assert_called_once_with("session_logout:my_refresh_token")
    db.get.assert_called_once_with(User, id="my_uid", enabled=True)

    assert result == await db.get()


async def test__logout() -> None:
    user = MagicMock()
    user.sessions = [AsyncMock() for _ in range(5)]

    await User.logout(user)

    for session in user.sessions:
        session.logout.assert_called_once_with()
