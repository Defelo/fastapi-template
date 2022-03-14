from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock, patch, AsyncMock

from fastapi.security.base import SecurityBase

from api import auth

from parameterized import parameterized

from api.exceptions.auth import InvalidTokenError


class TestAuth(IsolatedAsyncioTestCase):
    @parameterized.expand([("test", "test"), (None, ""), ("Bearer asDF1234", "asDF1234")])  # type: ignore
    def test__get_token(self, auth_header: str | None, token: str) -> None:
        request = MagicMock()
        request.headers = {"Authorization": auth_header} if auth_header is not None else {}

        result = auth.get_token(request)

        self.assertEqual(token, result)

    @patch("api.auth.HTTPBearer")
    async def test__constructor(self, httpbearer_patch: MagicMock) -> None:
        token = MagicMock()

        http_auth = auth.HTTPAuth(token)

        httpbearer_patch.assert_called_once_with()
        self.assertEqual(token, http_auth._token)
        self.assertEqual(httpbearer_patch(), http_auth.model)
        self.assertEqual(http_auth.__class__.__name__, http_auth.scheme_name)
        self.assertTrue(issubclass(auth.HTTPAuth, SecurityBase))

    @parameterized.expand([("S3cr3t Token!", True), ("asdf1234", False)])  # type: ignore
    async def test__check_token(self, token: str, ok: bool) -> None:
        http_auth = MagicMock()
        http_auth._token = "S3cr3t Token!"
        self.assertEqual(ok, await auth.HTTPAuth._check_token(http_auth, token))

    @patch("api.auth.get_token")
    async def test__call__invalid_token(self, get_token: MagicMock) -> None:
        request = MagicMock()
        http_auth = MagicMock()
        http_auth._check_token = AsyncMock(return_value=False)

        with self.assertRaises(InvalidTokenError):
            await auth.HTTPAuth.__call__(http_auth, request)

        get_token.assert_called_once_with(request)
        http_auth._check_token.assert_called_once_with(get_token())

    @patch("api.auth.get_token")
    async def test__call__valid_token(self, get_token: MagicMock) -> None:
        request = MagicMock()
        http_auth = MagicMock()
        http_auth._check_token = AsyncMock(return_value=True)

        self.assertTrue(await auth.HTTPAuth.__call__(http_auth, request))

        get_token.assert_called_once_with(request)
        http_auth._check_token.assert_called_once_with(get_token())
