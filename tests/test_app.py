from typing import Any, Callable
from unittest.mock import AsyncMock, MagicMock

from pytest_mock import MockerFixture

from .utils import import_module
from api import app


def get_decorated_function(
    fastapi_patch: MagicMock, decorator_name: str, *decorator_args: Any, **decorator_kwargs: Any
) -> tuple[Any, Callable[..., Any]]:
    functions: list[Callable[..., Any]] = []
    decorator = MagicMock(side_effect=functions.append)
    getattr(fastapi_patch(), decorator_name).side_effect = (
        lambda *args, **kwargs: decorator if (args, kwargs) == (decorator_args, decorator_kwargs) else MagicMock()
    )
    fastapi_patch.reset_mock()

    module = import_module("api.app")

    decorator.assert_called_once()
    assert len(functions) == 1
    return module, functions[0]


async def test__setup_app__sentry(mocker: MockerFixture) -> None:
    mocker.patch("api.app.SENTRY_DSN", "some_sentry_dsn")
    mocker.patch("api.app.DEBUG", False)
    setup_sentry_mock = mocker.patch("api.app.setup_sentry")
    app_mock = mocker.patch("api.app.app")
    get_version_mock = mocker.patch("api.app.get_version")
    get_version_mock.return_value = MagicMock(description="some description")

    app.setup_app()

    setup_sentry_mock.assert_called_once_with(app_mock, "some_sentry_dsn", "FastAPI", "some description")


async def test__setup_app__debug(mocker: MockerFixture) -> None:
    mocker.patch("api.app.SENTRY_DSN", None)
    mocker.patch("api.app.DEBUG", True)
    app_mock = mocker.patch("api.app.app")
    cors_middleware_mock = mocker.patch("api.app.CORSMiddleware")

    app.setup_app()

    app_mock.add_middleware.assert_called_once_with(
        cors_middleware_mock, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
    )


async def test__db_session(mocker: MockerFixture) -> None:
    fastapi_patch = mocker.patch("fastapi.FastAPI")
    db_patch = mocker.patch("api.database.db")

    _, db_session = get_decorated_function(fastapi_patch, "middleware", "http")

    events = []
    db_patch.create_session.side_effect = lambda: events.append(0)
    expected = MagicMock()
    call_next = AsyncMock(side_effect=lambda _: events.append(1) or expected)  # type: ignore
    request = MagicMock()
    db_patch.commit = AsyncMock(side_effect=lambda: events.append(2))
    db_patch.close = AsyncMock(side_effect=lambda: events.append(3))

    result = await db_session(request, call_next)

    assert events == [0, 1, 2, 3]
    call_next.assert_called_once_with(request)
    assert result == expected


async def test__on_startup(mocker: MockerFixture) -> None:
    fastapi_patch = mocker.patch("fastapi.FastAPI")
    db_patch = mocker.patch("api.database.db")

    module, on_startup = get_decorated_function(fastapi_patch, "on_event", "startup")

    db_patch.create_tables = AsyncMock()
    _setup_app = module.setup_app
    module.setup_app = MagicMock()

    try:
        await on_startup()

        module.setup_app.assert_called_once_with()
        db_patch.create_tables.assert_called_once_with()
    finally:
        module.setup_app = _setup_app


async def test__on_shutdown(mocker: MockerFixture) -> None:
    fastapi_patch = mocker.patch("fastapi.FastAPI")

    _, on_shutdown = get_decorated_function(fastapi_patch, "on_event", "shutdown")

    await on_shutdown()


async def test__status(mocker: MockerFixture) -> None:
    fastapi_patch = mocker.patch("fastapi.FastAPI")

    _, status = get_decorated_function(fastapi_patch, "head", "/status", tags=["status"])

    assert await status() is None
