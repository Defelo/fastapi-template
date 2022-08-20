import hashlib
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from typing import Any, AsyncIterator, cast
from unittest.mock import AsyncMock, MagicMock

import jwt
import pytest
from fastapi import FastAPI
from pydantic import BaseModel, Field
from pytest_mock import MockerFixture

from .utils import mock_asynccontextmanager, mock_dict, mock_list
from api import utils


async def test__run_in_thread() -> None:
    out = []
    res = MagicMock()
    args = tuple(mock_list(5))
    kwargs = mock_dict(5, True)

    @utils.run_in_thread
    def func(*_args: MagicMock, **_kwargs: MagicMock) -> MagicMock:
        out.append((_args, _kwargs))
        return res

    assert await func(*args, **kwargs) == res
    assert out == [(args, kwargs)]


@pytest.mark.parametrize("password", ["", "foobar42", "Ai,982d$" * 256, "π"])
async def test__hash_password(password: str) -> None:
    res1 = await utils.hash_password(password)
    res2 = await utils.hash_password(password)

    assert res1 != res2
    assert utils.password_hasher.verify(res1, password)
    assert utils.password_hasher.verify(res1, password)


@pytest.mark.parametrize(
    "pw,guess,ok",
    [
        ("", "", True),
        ("", "x", False),
        ("foobar42", "foobar42", True),
        ("fooBar42", "foobar42", False),
        ("Ai,982d$" * 256, "Ai,982d$" * 256, True),
        ("Ai,982d$" * 256, "Ai,982d$" * 255, False),
        ("π", "π", True),
        ("π", "∞", False),
    ],
)
async def test__verify_password(pw: str, guess: str, ok: bool) -> None:
    pwhash = utils.password_hasher.hash(pw)
    assert await utils.verify_password(guess, pwhash) is ok


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
    mocker.patch("api.utils.datetime", MagicMock(utcnow=lambda: datetime.utcfromtimestamp(now)))
    mocker.patch("api.utils.JWT_SECRET", "My JWT secret")

    token = utils.encode_jwt(data, timedelta(seconds=ttl))

    match = re.match(r"^([a-zA-Z\d\-_]+)\.([a-zA-Z\d\-_]+)\.[a-zA-Z\d\-_]+$", token)
    assert match, "Invalid JWT format"

    assert jwt.get_unverified_header(token) == {"typ": "JWT", "alg": "HS256"}  # type: ignore
    assert jwt.decode(token, "My JWT secret", ["HS256"], {"verify_exp": False}) == expected


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
    token = jwt.encode(data | {"exp": exp}, "My JWT secret", "HS256")
    mocker.patch("api.utils.JWT_SECRET", "My JWT secret")
    result = utils.decode_jwt(token, require)

    if expected:
        assert isinstance(result, dict)
        exp_ = cast(dict[str, Any], result).pop("exp")
        assert result == data
        assert exp == datetime.utcfromtimestamp(exp_)
    else:
        assert result is None


async def test__check_mfa_code__blocked(mocker: MockerFixture) -> None:
    redis_patch = mocker.patch("api.utils.redis")

    code = "421337"
    secret = "tRtD1eq5oMJydVA6zxUsohZdMIKTGgoj"
    key = f"mfa_block:{hashlib.sha256(secret.encode()).hexdigest()}:{code}"
    redis_patch.exists.return_value = True

    assert await utils.check_mfa_code(code, secret) is False

    redis_patch.exists.assert_called_once_with(key)


async def test__check_mfa_code__invalid(mocker: MockerFixture) -> None:
    redis_patch = mocker.patch("api.utils.redis", new_callable=AsyncMock)
    totp_patch = mocker.patch("api.utils.TOTP")
    mocker.patch("api.utils.MFA_VALID_WINDOW", 42)

    code = "421337"
    secret = "tRtD1eq5oMJydVA6zxUsohZdMIKTGgoj"
    key = f"mfa_block:{hashlib.sha256(secret.encode()).hexdigest()}:{code}"
    redis_patch.exists.return_value = False
    totp_patch.return_value.verify.return_value = False

    assert await utils.check_mfa_code(code, secret) is False

    redis_patch.exists.assert_called_once_with(key)
    totp_patch.assert_called_once_with(secret)
    totp_patch.return_value.verify.assert_called_once_with(code, valid_window=42)


async def test__check_mfa_code__valid(mocker: MockerFixture) -> None:
    redis_patch = mocker.patch("api.utils.redis", new_callable=AsyncMock)
    totp_patch = mocker.patch("api.utils.TOTP")
    mocker.patch("api.utils.MFA_VALID_WINDOW", 42)

    code = "421337"
    secret = "tRtD1eq5oMJydVA6zxUsohZdMIKTGgoj"
    key = f"mfa_block:{hashlib.sha256(secret.encode()).hexdigest()}:{code}"
    redis_patch.exists.return_value = False
    totp_patch.return_value.verify.return_value = True

    assert await utils.check_mfa_code(code, secret) is True

    redis_patch.exists.assert_called_once_with(key)
    totp_patch.assert_called_once_with(secret)
    totp_patch.return_value.verify.assert_called_once_with(code, valid_window=42)
    redis_patch.setex.assert_called_once_with(key, 2580, 1)


async def test__responses() -> None:
    default = MagicMock()

    def make_exception(status_code: int) -> MagicMock:
        out = MagicMock()
        out.__name__ = MagicMock()
        out.status_code = status_code
        return out

    args = [a := make_exception(401), b := make_exception(403), c := make_exception(403), d := make_exception(404)]

    result = utils.responses(default, *args)

    assert result == {
        200: {"model": default},
        401: {
            "description": b"Unauthorized",
            "content": {
                "application/json": {
                    "examples": {a.__name__: {"description": a.description, "value": {"detail": a.detail}}}
                }
            },
        },
        403: {
            "description": b"Forbidden",
            "content": {
                "application/json": {
                    "examples": {
                        f"{b.__name__} (1/2)": {"description": b.description, "value": {"detail": b.detail}},
                        f"{c.__name__} (2/2)": {"description": c.description, "value": {"detail": c.detail}},
                    }
                }
            },
        },
        404: {
            "description": b"Not Found",
            "content": {
                "application/json": {
                    "examples": {d.__name__: {"description": d.description, "value": {"detail": d.detail}}}
                }
            },
        },
    }


async def test__get_example() -> None:
    arg = MagicMock()
    arg.Config.schema_extra = {"example": (expected := MagicMock())}

    assert utils.get_example(arg) == expected


async def test__example(mocker: MockerFixture) -> None:
    get_example_patch = mocker.patch("api.utils.get_example")

    args = [a := MagicMock(), b := MagicMock()]
    get_example_patch.side_effect = lambda x: MagicMock(
        items=lambda: [(x.first.key, x.first.value), (x.second.key, x.second.value)]
    )
    kwargs = mock_dict(5, True)

    result = utils.example(*args, **kwargs)

    assert result.schema_extra == {
        "example": {
            a.first.key: a.first.value,
            a.second.key: a.second.value,
            b.first.key: b.first.value,
            b.second.key: b.second.value,
            **kwargs,
        }
    }


async def test__add_endpoint_links_to_openapi_docs() -> None:
    app = FastAPI(
        description="`GET /test` test `POST /foobar`",
        openapi_tags=[{"name": "test", "description": "asdf `GET /test`"}],
    )

    class Model(BaseModel):
        test: str = Field(description="xyz `POST /foobar`")

    @app.get("/test", tags=["test"], responses=utils.responses(Model))
    async def test() -> None:
        """Test endpoint. `POST /foobar`"""
        pass

    @app.post("/foobar", tags=["test"])
    async def foobar() -> None:
        """Foobar endpoint. `GET /test`"""
        pass

    utils.add_endpoint_links_to_openapi_docs(app.openapi())
    schema = app.openapi()
    assert (
        schema["info"]["description"]
        == "[`GET /test`](docs#/test/test_test_get) test [`POST /foobar`](docs#/test/foobar_foobar_post)"
    )
    assert schema["tags"][0]["description"] == "asdf [`GET /test`](docs#/test/test_test_get)"
    assert (
        schema["paths"]["/test"]["get"]["description"]
        == "Test endpoint. [`POST /foobar`](docs#/test/foobar_foobar_post)"
    )
    assert (
        schema["paths"]["/foobar"]["post"]["description"] == "Foobar endpoint. [`GET /test`](docs#/test/test_test_get)"
    )
    assert (
        schema["components"]["schemas"]["Model"]["properties"]["test"]["description"]
        == "xyz [`POST /foobar`](docs#/test/foobar_foobar_post)"
    )


@pytest.mark.parametrize(
    "secret,sitekey,expected",
    [("", "", False), (None, None, False), ("foo", "", False), ("", "bar", False), ("foo", "bar", True)],
)
async def test__recaptcha_enabled(
    secret: str | None, sitekey: str | None, expected: bool, mocker: MockerFixture
) -> None:
    mocker.patch("api.utils.RECAPTCHA_SITEKEY", sitekey)
    mocker.patch("api.utils.RECAPTCHA_SECRET", secret)

    assert utils.recaptcha_enabled() == expected


async def test__check_recaptcha(mocker: MockerFixture) -> None:
    client_patch = mocker.patch("aiohttp.ClientSession")

    secret = MagicMock()
    token = MagicMock()
    expected = MagicMock()

    session = MagicMock()
    response = AsyncMock()

    client_patch.side_effect, func_callbacks, assert_calls = mock_asynccontextmanager(3, session)

    @asynccontextmanager
    async def session_context(url: str, data: dict[str, Any]) -> AsyncIterator[AsyncMock]:
        assert url == "https://www.google.com/recaptcha/api/siteverify"
        assert data == {"secret": secret, "response": token}

        func_callbacks[0]()
        yield response
        func_callbacks[2]()

    session.post.side_effect = session_context
    response.json.side_effect = lambda: func_callbacks[1]() or {"success": expected}

    mocker.patch("api.utils.RECAPTCHA_SECRET", secret)
    assert await utils.check_recaptcha(token) == expected

    assert_calls()
    client_patch.assert_called_once()
    session.post.assert_called_once()
    response.json.assert_called_once()
