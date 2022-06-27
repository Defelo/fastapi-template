from unittest import IsolatedAsyncioTestCase
from unittest.mock import AsyncMock, MagicMock, patch

from api import auth
from api.exceptions.auth import InvalidTokenError

from fastapi.security.base import SecurityBase
from parameterized import parameterized


class TestAuth(IsolatedAsyncioTestCase):
    @parameterized.expand([("test", "test"), (None, ""), ("Bearer asDF1234", "asDF1234")])  # type: ignore
    def test__get_token(self, auth_header: str | None, token: str) -> None:
        request = MagicMock()
        request.headers = {"Authorization": auth_header} if auth_header is not None else {}

        result = auth.get_token(request)

        self.assertEqual(token, result)

    @patch("api.auth.HTTPBearer")
    async def test__httpauth_constructor(self, httpbearer_patch: MagicMock) -> None:
        http_auth = auth.HTTPAuth()

        httpbearer_patch.assert_called_once_with()
        self.assertEqual(httpbearer_patch(), http_auth.model)
        self.assertEqual(http_auth.__class__.__name__, http_auth.scheme_name)
        self.assertTrue(issubclass(auth.HTTPAuth, SecurityBase))

    async def test__httpauth_get_session(self) -> None:
        http_auth = auth.HTTPAuth()

        with self.assertRaises(NotImplementedError):
            await http_auth._get_session("test")

    @patch("api.auth.get_token")
    async def test__httpauth_call__invalid_token(self, get_token: MagicMock) -> None:
        request = MagicMock()
        http_auth = MagicMock()
        http_auth._get_session = AsyncMock(return_value=None)

        with self.assertRaises(InvalidTokenError):
            await auth.HTTPAuth.__call__(http_auth, request)

        get_token.assert_called_once_with(request)
        http_auth._get_session.assert_called_once_with(get_token())

    @patch("api.auth.get_token")
    async def test__httpauth_call__valid_token(self, get_token: MagicMock) -> None:
        request = MagicMock()
        http_auth = MagicMock()
        http_auth._get_session = AsyncMock(return_value=MagicMock())

        result = await auth.HTTPAuth.__call__(http_auth, request)

        get_token.assert_called_once_with(request)
        http_auth._get_session.assert_called_once_with(get_token())
        self.assertEqual(http_auth._get_session.return_value, result)
