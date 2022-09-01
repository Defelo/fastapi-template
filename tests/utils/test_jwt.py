import re
from datetime import datetime, timedelta
from typing import Any, cast
from unittest.mock import MagicMock

import jwt as _jwt
import pytest
from pytest_mock import MockerFixture

from api.utils import jwt


@pytest.mark.parametrize(
    "data,now,ttl,expected",
    [
        ({}, 42, 10, {"exp": 52}),
        ({"foo": "bar", "x": 42, "y": 1337}, 123, 456, {"foo": "bar", "x": 42, "y": 1337, "exp": 579}),
        ({"foo": {"bar": [{"x": 42}, {"y": 1337}]}}, 123, 456, {"foo": {"bar": [{"x": 42}, {"y": 1337}]}, "exp": 579}),
    ],
)
async def test__jwt_encode(
    data: dict[str, Any], now: int, ttl: int, expected: dict[str, Any], mocker: MockerFixture
) -> None:
    mocker.patch("api.utils.jwt.datetime", MagicMock(utcnow=lambda: datetime.utcfromtimestamp(now)))
    mocker.patch("api.utils.jwt.JWT_SECRET", "My JWT secret")

    token = jwt.encode_jwt(data, timedelta(seconds=ttl))

    match = re.match(r"^([a-zA-Z\d\-_]+)\.([a-zA-Z\d\-_]+)\.[a-zA-Z\d\-_]+$", token)
    assert match, "Invalid JWT format"

    assert _jwt.get_unverified_header(token) == {"typ": "JWT", "alg": "HS256"}  # type: ignore
    assert _jwt.decode(token, "My JWT secret", ["HS256"], {"verify_exp": False}) == expected


@pytest.mark.parametrize(
    "data,ttl,require,expected",
    [
        ({}, 1, [], True),
        ({}, -1, [], False),
        ({}, 1, ["foo"], False),
        ({"foo": "bar"}, 1, [], True),
        ({"foo": "bar"}, 1, ["foo"], True),
        ({"foo": "bar"}, 1, ["foo", "bar"], False),
        ({"foo": "bar"}, -1, ["foo"], False),
    ],
)
async def test__jwt_decode(
    data: dict[str, Any], ttl: int, require: list[str], expected: bool, mocker: MockerFixture
) -> None:
    exp = (datetime.utcnow() + timedelta(seconds=ttl)).replace(microsecond=0)
    token = _jwt.encode(data | {"exp": exp}, "My JWT secret", "HS256")
    mocker.patch("api.utils.jwt.JWT_SECRET", "My JWT secret")
    result = jwt.decode_jwt(token, require)

    if expected:
        assert isinstance(result, dict)
        exp_ = cast(dict[str, Any], result).pop("exp")
        assert result == data
        assert exp == datetime.utcfromtimestamp(exp_)
    else:
        assert result is None
