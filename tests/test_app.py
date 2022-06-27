from typing import Any, Callable
from unittest import IsolatedAsyncioTestCase
from unittest.mock import MagicMock, patch

from api import app

from utils import AsyncMock, import_module, mock_list


class TestApp(IsolatedAsyncioTestCase):
    def get_decorated_function(
        self, fastapi_patch: MagicMock, decorator_name: str, *decorator_args: Any, **decorator_kwargs: Any
    ) -> tuple[Any, Callable[..., Any]]:
        functions: list[Callable[..., Any]] = []
        decorator = MagicMock(side_effect=functions.append)
        getattr(fastapi_patch(), decorator_name).side_effect = (
            lambda *args, **kwargs: decorator if (args, kwargs) == (decorator_args, decorator_kwargs) else MagicMock()
        )
        fastapi_patch.reset_mock()

        module = import_module("api.app")

        decorator.assert_called_once()
        self.assertEqual(1, len(functions))
        return module, functions[0]

    @patch("api.app.ROUTERS")
    @patch("api.app.app")
    @patch("api.app.SENTRY_DSN", None)
    @patch("api.app.DEBUG", False)
    async def test__setup_app(self, app_mock: MagicMock, routers_mock: MagicMock) -> None:
        routers = mock_list(5)
        routers_mock.__iter__.return_value = iter(routers.copy())
        app_mock.include_router.side_effect = routers.remove

        app.setup_app()

        self.assertFalse(routers)

    @patch("api.app.get_version")
    @patch("api.app.setup_sentry")
    @patch("api.app.ROUTERS")
    @patch("api.app.app")
    @patch("api.app.SENTRY_DSN")
    @patch("api.app.DEBUG", False)
    async def test__setup_app__sentry(
        self,
        sentry_dsn_mock: MagicMock,
        app_mock: MagicMock,
        routers_mock: MagicMock,
        setup_sentry_mock: MagicMock,
        get_version_mock: MagicMock,
    ) -> None:
        routers = mock_list(5)
        routers_mock.__iter__.return_value = iter(routers.copy())
        app_mock.include_router.side_effect = routers.remove

        app.setup_app()

        get_version_mock.assert_called_once_with()
        setup_sentry_mock.assert_called_once_with(app_mock, sentry_dsn_mock, "FastAPI", get_version_mock().description)
        self.assertFalse(routers)

    @patch("api.app.ROUTERS")
    @patch("api.app.CORSMiddleware")
    @patch("api.app.app")
    @patch("api.app.SENTRY_DSN", None)
    @patch("api.app.DEBUG", True)
    async def test__setup_app__debug(
        self, app_mock: MagicMock, cors_middleware_mock: MagicMock, routers_mock: MagicMock
    ) -> None:
        routers = mock_list(5)
        routers_mock.__iter__.return_value = iter(routers.copy())
        app_mock.include_router.side_effect = routers.remove

        app.setup_app()

        app_mock.add_middleware.assert_called_once_with(
            cors_middleware_mock, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
        )
        self.assertFalse(routers)

    @patch("api.database.db")
    @patch("fastapi.FastAPI")
    async def test__db_session(self, fastapi_patch: MagicMock, db_patch: MagicMock) -> None:
        _, db_session = self.get_decorated_function(fastapi_patch, "middleware", "http")

        events = []
        db_patch.create_session.side_effect = lambda: events.append(0)
        expected = MagicMock()
        call_next = AsyncMock(side_effect=lambda _: events.append(1) or expected)  # type: ignore
        request = MagicMock()
        db_patch.commit = AsyncMock(side_effect=lambda: events.append(2))
        db_patch.close = AsyncMock(side_effect=lambda: events.append(3))

        result = await db_session(request, call_next)

        self.assertEqual([0, 1, 2, 3], events)
        call_next.assert_called_once_with(request)
        self.assertEqual(expected, result)

    @patch("api.database.db")
    @patch("fastapi.FastAPI")
    async def test__on_startup(self, fastapi_patch: MagicMock, db_patch: MagicMock) -> None:
        module, on_startup = self.get_decorated_function(fastapi_patch, "on_event", "startup")
        db_patch.create_tables = AsyncMock()
        _setup_app = module.setup_app
        module.setup_app = MagicMock()

        try:
            await on_startup()

            module.setup_app.assert_called_once_with()
            db_patch.create_tables.assert_called_once_with()
        finally:
            module.setup_app = _setup_app

    @patch("fastapi.FastAPI")
    async def test__on_shutdown(self, fastapi_patch: MagicMock) -> None:
        _, on_shutdown = self.get_decorated_function(fastapi_patch, "on_event", "shutdown")

        await on_shutdown()

    @patch("fastapi.FastAPI")
    async def test__status(self, fastapi_patch: MagicMock) -> None:
        _, status = self.get_decorated_function(fastapi_patch, "head", "/status", tags=["status"])

        result = await status()

        self.assertIsNone(result)
