import base64
import hashlib
import json
import re
from contextlib import asynccontextmanager
from datetime import datetime, timedelta
from re import Match
from typing import Any, AsyncIterator, cast
from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock, patch

from api import utils

import jwt
from parameterized import parameterized
from utils import AsyncMock, mock_dict, mock_list


class TestUtils(IsolatedAsyncioTestCase):
    async def test__run_in_thread(self) -> None:
        out = []
        res = MagicMock()
        args = tuple(mock_list(5))
        kwargs = mock_dict(5, True)

        @utils.run_in_thread
        def func(*_args: MagicMock, **_kwargs: MagicMock) -> MagicMock:
            out.append((_args, _kwargs))
            return res

        self.assertEqual(res, await func(*args, **kwargs))
        self.assertEqual([(args, kwargs)], out)

    @parameterized.expand([("",), ("foobar42",), ("Ai,982d$" * 256,), ("π",)])  # type: ignore
    async def test__hash_password(self, password: str) -> None:
        res1 = await utils.hash_password(password)
        res2 = await utils.hash_password(password)

        self.assertNotEqual(res1, res2)
        self.assertTrue(utils.password_hasher.verify(res1, password))
        self.assertTrue(utils.password_hasher.verify(res1, password))

    @parameterized.expand(
        [
            ("", "", True),
            ("", "x", False),
            ("foobar42", "foobar42", True),
            ("fooBar42", "foobar42", False),
            ("Ai,982d$" * 256, "Ai,982d$" * 256, True),
            ("Ai,982d$" * 256, "Ai,982d$" * 255, False),
            ("π", "π", True),
            ("π", "∞", False),
        ]
    )  # type: ignore
    async def test__verify_password(self, pw: str, guess: str, ok: bool) -> None:
        pwhash = utils.password_hasher.hash(pw)
        self.assertEqual(ok, await utils.verify_password(guess, pwhash))

    @parameterized.expand(
        [
            ({}, 42, 10, {"exp": 52}),
            ({"foo": "bar", "x": 42, "y": 1337}, 123, 456, {"foo": "bar", "x": 42, "y": 1337, "exp": 579}),
            (
                {"foo": {"bar": [{"x": 42}, {"y": 1337}]}},
                123,
                456,
                {"foo": {"bar": [{"x": 42}, {"y": 1337}]}, "exp": 579},
            ),
        ]
    )  # type: ignore
    async def test__jwt_encode(self, data: dict[str, Any], now: int, ttl: int, expected: dict[str, Any]) -> None:
        with patch("api.utils.JWT_SECRET", "My JWT secret"), patch(
            "api.utils.datetime", MagicMock(utcnow=lambda: datetime.utcfromtimestamp(now))
        ):
            token = utils.encode_jwt(data, timedelta(seconds=ttl))

        match = re.match(r"^([a-zA-Z0-9\-_]+)\.([a-zA-Z0-9\-_]+)\.[a-zA-Z0-9\-_]+$", token)
        self.failIf(not match, "Invalid JWT format")

        header, payload = [json.loads(base64.b64decode(x + "==").decode()) for x in cast(Match[str], match).groups()]
        self.assertEqual({"typ": "JWT", "alg": "HS256"}, header)
        self.assertEqual(expected, payload)

    @parameterized.expand(
        [
            ({}, 1, [], True),
            ({}, -1, [], False),
            ({}, 1, ["foo"], False),
            ({"foo": "bar"}, 1, [], True),
            ({"foo": "bar"}, 1, ["foo"], True),
            ({"foo": "bar"}, 1, ["foo", "bar"], False),
            ({"foo": "bar"}, -1, ["foo"], False),
        ]
    )  # type: ignore
    async def test__jwt_decode(self, data: dict[str, Any], ttl: int, require: list[str], expected: bool) -> None:
        exp = (datetime.utcnow() + timedelta(seconds=ttl)).replace(microsecond=0)
        token = jwt.encode(data | {"exp": exp}, "My JWT secret", "HS256")
        with patch("api.utils.JWT_SECRET", "My JWT secret"):
            result = utils.decode_jwt(token, require)

        if expected:
            self.assertIsInstance(result, dict)
            exp_ = cast(dict[str, Any], result).pop("exp")
            self.assertEqual(data, result)
            self.assertEqual(datetime.utcfromtimestamp(exp_), exp)
        else:
            self.assertIsNone(result)

    @patch("api.utils.redis", new_callable=AsyncMock)
    async def test__check_mfa_code__blocked(self, redis_patch: AsyncMock) -> None:
        code = "421337"
        secret = "tRtD1eq5oMJydVA6zxUsohZdMIKTGgoj"
        key = f"mfa_block:{hashlib.sha256(secret.encode()).hexdigest()}:{code}"
        redis_patch.exists.return_value = True

        self.assertFalse(await utils.check_mfa_code(code, secret))

        redis_patch.exists.assert_called_once_with(key)

    @patch("api.utils.MFA_VALID_WINDOW")
    @patch("api.utils.TOTP")
    @patch("api.utils.redis", new_callable=AsyncMock)
    async def test__check_mfa_code__invalid(
        self, redis_patch: AsyncMock, totp_patch: MagicMock, mfa_valid_window_patch: MagicMock
    ) -> None:
        code = "421337"
        secret = "tRtD1eq5oMJydVA6zxUsohZdMIKTGgoj"
        key = f"mfa_block:{hashlib.sha256(secret.encode()).hexdigest()}:{code}"
        redis_patch.exists.return_value = False
        totp_patch.return_value.verify.return_value = False

        self.assertFalse(await utils.check_mfa_code(code, secret))

        redis_patch.exists.assert_called_once_with(key)
        totp_patch.assert_called_once_with(secret)
        totp_patch.return_value.verify.assert_called_once_with(code, valid_window=mfa_valid_window_patch)

    @patch("api.utils.MFA_VALID_WINDOW", 42)
    @patch("api.utils.TOTP")
    @patch("api.utils.redis", new_callable=AsyncMock)
    async def test__check_mfa_code__valid(self, redis_patch: AsyncMock, totp_patch: MagicMock) -> None:
        code = "421337"
        secret = "tRtD1eq5oMJydVA6zxUsohZdMIKTGgoj"
        key = f"mfa_block:{hashlib.sha256(secret.encode()).hexdigest()}:{code}"
        redis_patch.exists.return_value = False
        totp_patch.return_value.verify.return_value = True

        self.assertTrue(await utils.check_mfa_code(code, secret))

        redis_patch.exists.assert_called_once_with(key)
        totp_patch.assert_called_once_with(secret)
        totp_patch.return_value.verify.assert_called_once_with(code, valid_window=42)
        redis_patch.setex.assert_called_once_with(key, 2580, 1)

    async def test__responses(self) -> None:
        default = MagicMock()

        def make_exception(status_code: int) -> MagicMock:
            out = MagicMock()
            out.__name__ = MagicMock()
            out.status_code = status_code
            return out

        args = [a := make_exception(401), b := make_exception(403), c := make_exception(403), d := make_exception(404)]

        # noinspection PyTypeChecker
        result = utils.responses(default, *args)

        self.assertEqual(
            {
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
            },
            result,
        )

    async def test__get_example(self) -> None:
        arg = MagicMock()
        arg.Config.schema_extra = {"example": (expected := MagicMock())}

        result = utils.get_example(arg)  # noqa

        self.assertEqual(expected, result)

    @patch("api.utils.get_example")
    async def test__example(self, get_example_patch: MagicMock) -> None:
        args = [a := MagicMock(), b := MagicMock()]
        get_example_patch.side_effect = lambda x: MagicMock(
            items=lambda: [(x.first.key, x.first.value), (x.second.key, x.second.value)]
        )
        kwargs = mock_dict(5, True)

        result = utils.example(*args, **kwargs)

        # noinspection PyUnresolvedReferences
        self.assertEqual(
            {
                "example": {
                    a.first.key: a.first.value,
                    a.second.key: a.second.value,
                    b.first.key: b.first.value,
                    b.second.key: b.second.value,
                    **kwargs,
                }
            },
            result.schema_extra,
        )

    @parameterized.expand(
        [("", "", False), (None, None, False), ("foo", "", False), ("", "bar", False), ("foo", "bar", True)]
    )  # type: ignore
    async def test__recaptcha_enabled(self, secret: str | None, sitekey: str | None, expected: bool) -> None:
        with patch("api.utils.RECAPTCHA_SITEKEY", sitekey), patch("api.utils.RECAPTCHA_SECRET", secret):
            self.assertEqual(expected, utils.recaptcha_enabled())

    @patch("aiohttp.ClientSession")
    async def test__check_recaptcha(self, client_patch: MagicMock) -> None:
        secret = MagicMock()
        token = MagicMock()
        expected = MagicMock()

        events = []
        session = MagicMock()
        response = AsyncMock()

        @asynccontextmanager
        async def client_context() -> AsyncIterator[MagicMock]:
            events.append(0)
            yield session
            events.append(4)

        @asynccontextmanager
        async def session_context(url: str, data: dict[str, Any]) -> AsyncIterator[AsyncMock]:
            self.assertEqual("https://www.google.com/recaptcha/api/siteverify", url)
            self.assertEqual({"secret": secret, "response": token}, data)

            events.append(1)
            yield response
            events.append(3)

        client_patch.side_effect = client_context
        session.post.side_effect = session_context
        response.json.side_effect = lambda: events.append(2) or {"success": expected}  # type: ignore

        with patch("api.utils.RECAPTCHA_SECRET", secret):
            self.assertEqual(expected, await utils.check_recaptcha(token))

        self.assertEqual([0, 1, 2, 3, 4], events)
        client_patch.assert_called_once()
        session.post.assert_called_once()
        response.json.assert_called_once()
