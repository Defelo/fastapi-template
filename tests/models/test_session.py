from datetime import datetime, timedelta
from typing import Awaitable, Callable
from unittest.mock import AsyncMock, MagicMock

import pytest
from pytest_mock import MockerFixture

from api.database import delete
from api.models import Session
from api.models import session as _session
from api.models.session import SessionExpiredError, clean_expired_sessions


TEST_HASH = "9f86d081884c7d659a2feaa0c55ad015a3bf4f1b2b0b822cd15d6c15b0f00a08"


async def test__hash_token() -> None:
    assert _session._hash_token("test") == TEST_HASH


async def test__serialize() -> None:
    obj = Session(
        id="my_id", user_id="my_user_id", device_name="my_device_name", last_update=datetime.fromtimestamp(1234567)
    )

    assert obj.serialize == {
        "id": "my_id",
        "user_id": "my_user_id",
        "device_name": "my_device_name",
        "last_update": 1234567,
    }


async def test__create(mocker: MockerFixture) -> None:
    db = mocker.patch("api.models.session.db", new_callable=AsyncMock)
    dt = mocker.patch("api.models.session.datetime")
    generate_access_token = mocker.patch("api.models.session.Session._generate_access_token")

    obj, at, rt = await Session.create("my_user_id", "my_device_name")

    generate_access_token.assert_called_once_with()
    db.add.assert_called_once_with(obj)

    assert obj.user_id == "my_user_id"
    assert obj.device_name == "my_device_name"
    assert obj.last_update == dt.utcnow()
    assert obj.refresh_token == _session._hash_token(rt)
    assert at == generate_access_token()


async def test__generate_access_token(mocker: MockerFixture) -> None:
    mocker.patch("api.models.session.ACCESS_TOKEN_TTL", 42)
    encode_jwt = mocker.patch("api.models.session.encode_jwt")

    session = Session(user_id="my_user_id", id="my_id", refresh_token="my_refresh_token")  # noqa: S106

    result = session._generate_access_token()

    encode_jwt.assert_called_once_with(
        {"uid": "my_user_id", "sid": "my_id", "rt": "my_refresh_token"}, timedelta(seconds=42)
    )
    assert result == encode_jwt()


async def test__from_access_token__invalid_jwt(mocker: MockerFixture) -> None:
    decode_jwt = mocker.patch("api.models.session.decode_jwt", MagicMock(return_value=None))

    assert await Session.from_access_token("my_token") is None
    decode_jwt.assert_called_once_with("my_token", ["uid", "sid", "rt"])


async def test__from_access_token__logout(mocker: MockerFixture) -> None:
    data = {"rt": "my_refresh_token"}
    decode_jwt = mocker.patch("api.models.session.decode_jwt", MagicMock(return_value=data))
    exists = mocker.patch("api.models.session.redis.exists", AsyncMock(return_value=True))

    assert await Session.from_access_token("my_token") is None
    decode_jwt.assert_called_once_with("my_token", ["uid", "sid", "rt"])
    exists.assert_called_once_with("session_logout:my_refresh_token")


async def test__from_access_token__valid(mocker: MockerFixture) -> None:
    data = {"rt": "my_refresh_token", "sid": "my_sid"}
    decode_jwt = mocker.patch("api.models.session.decode_jwt", MagicMock(return_value=data))
    exists = mocker.patch("api.models.session.redis.exists", AsyncMock(return_value=False))
    db = mocker.patch("api.models.session.db", new_callable=AsyncMock)

    result = await Session.from_access_token("my_token")

    decode_jwt.assert_called_once_with("my_token", ["uid", "sid", "rt"])
    exists.assert_called_once_with("session_logout:my_refresh_token")
    db.get.assert_called_once_with(Session, Session.user, id="my_sid")

    assert result == await db.get()


async def test__refresh__invalid_refresh_token(mocker: MockerFixture) -> None:
    db = mocker.patch("api.models.session.db", new_callable=AsyncMock)
    db.get.return_value = None

    with pytest.raises(ValueError):
        await Session.refresh("test")

    db.get.assert_called_once_with(Session, Session.user, refresh_token=TEST_HASH)


async def test__refresh__session_expired(mocker: MockerFixture) -> None:
    db = mocker.patch("api.models.session.db", new_callable=AsyncMock)
    session = db.get.return_value = AsyncMock()
    session.last_update = datetime.fromtimestamp(40)
    mocker.patch("api.models.session.REFRESH_TOKEN_TTL", 2)
    dt = mocker.patch("api.models.session.datetime")
    dt.utcnow.return_value = datetime.fromtimestamp(43)

    with pytest.raises(SessionExpiredError):
        await Session.refresh("test")

    db.get.assert_called_once_with(Session, Session.user, refresh_token=TEST_HASH)
    session.logout.assert_called_once_with()


async def test__refresh__ok(mocker: MockerFixture) -> None:
    db = mocker.patch("api.models.session.db", new_callable=AsyncMock)
    session = db.get.return_value = MagicMock(refresh_token="old_refresh_token", logout=AsyncMock())  # noqa: S106
    session.last_update = datetime.fromtimestamp(40)
    mocker.patch("api.models.session.ACCESS_TOKEN_TTL", 1337)
    mocker.patch("api.models.session.REFRESH_TOKEN_TTL", 2)
    dt = mocker.patch("api.models.session.datetime")
    dt.utcnow.return_value = datetime.fromtimestamp(42)
    redis = mocker.patch("api.models.session.redis", new_callable=AsyncMock)

    result, at, rt = await Session.refresh("test")

    redis.setex.assert_called_once_with("session_logout:old_refresh_token", 1337, 1)
    db.get.assert_called_once_with(Session, Session.user, refresh_token=TEST_HASH)
    session._generate_access_token.assert_called_once_with()

    assert result == session
    assert result.last_update == datetime.fromtimestamp(42)
    assert result.refresh_token == _session._hash_token(rt)
    assert at == session._generate_access_token()


async def test__logout(mocker: MockerFixture) -> None:
    redis = mocker.patch("api.models.session.redis", new_callable=AsyncMock)
    mocker.patch("api.models.session.ACCESS_TOKEN_TTL", 1337)
    session = Session(refresh_token="my_refresh_token")  # noqa: S106
    db = mocker.patch("api.models.session.db", new_callable=AsyncMock)

    await session.logout()

    redis.setex.assert_called_once_with("session_logout:my_refresh_token", 1337, 1)
    db.delete.assert_called_once_with(session)


async def test__clean_expired_sessions(mocker: MockerFixture) -> None:
    ces: Callable[[], Awaitable[None]] = clean_expired_sessions.__wrapped__  # type: ignore

    db = mocker.patch("api.models.session.db", new_callable=AsyncMock)
    mocker.patch("api.models.session.REFRESH_TOKEN_TTL", 2)
    dt = mocker.patch("api.models.session.datetime")
    dt.utcnow.return_value = datetime.fromtimestamp(42)

    await ces()

    db.exec.assert_called_once_with(delete(Session).where(Session.last_update < datetime.fromtimestamp(40)))
