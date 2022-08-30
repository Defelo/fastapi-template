import json
from typing import Any, AsyncIterator, Callable
from unittest.mock import AsyncMock, MagicMock

import pytest
from _pytest.logging import LogCaptureFixture
from _pytest.monkeypatch import MonkeyPatch
from httpx import AsyncClient
from pydantic import create_model
from pytest_mock import MockerFixture

from .utils import import_module, mock_asynccontextmanager
from api import app
from api.app import _check_response_schema, check_responses


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
    get_version_mock = mocker.patch("api.app.get_version")
    setup_sentry_mock = mocker.patch("api.app.setup_sentry")
    app_mock = mocker.patch("api.app.app")
    sentry_dsn_mock = mocker.patch("api.app.SENTRY_DSN")
    mocker.patch("api.app.DEBUG", False)

    app.setup_app()

    get_version_mock.assert_called_once_with()
    setup_sentry_mock.assert_called_once_with(app_mock, sentry_dsn_mock, "FastAPI", get_version_mock().description)


async def test__setup_app__debug(mocker: MockerFixture) -> None:
    app_mock = mocker.patch("api.app.app")
    cors_middleware_mock = mocker.patch("api.app.CORSMiddleware")
    mocker.patch("api.app.SENTRY_DSN", None)
    mocker.patch("api.app.DEBUG", True)

    app.setup_app()

    app_mock.add_middleware.assert_called_once_with(
        cors_middleware_mock, allow_origins=["*"], allow_credentials=True, allow_methods=["*"], allow_headers=["*"]
    )


async def test__db_session(mocker: MockerFixture) -> None:
    fastapi_patch = mocker.patch("fastapi.FastAPI")
    expected = MagicMock()
    request = MagicMock()

    module, db_session = get_decorated_function(fastapi_patch, "middleware", "http")

    module.db_context, [func_callback], assert_calls = mock_asynccontextmanager(1, None)
    call_next = AsyncMock(side_effect=lambda _: func_callback() or expected)

    result = await db_session(request, call_next)

    assert_calls()
    call_next.assert_called_once_with(request)
    assert result == expected


@pytest.mark.parametrize(
    "responses,status_code,body,ok",
    [
        ({}, 200, {"foo": "bar"}, False),
        ({200: {"model": create_model("test", foo=(str, ...))}}, 200, {}, False),
        ({200: {"model": create_model("test", foo=(int, ...))}}, 200, {"foo": "bar"}, False),
        ({200: {"model": create_model("test", foo=(str, ...))}}, 200, {"foo": "bar"}, True),
        ({404: {"content": {"application/json": {"examples": {}}}}}, 404, {"detail": "Not Found"}, False),
        (
            {404: {"content": {"application/json": {"examples": {"1": {"value": {"detail": "Not Found"}}}}}}},
            404,
            {"detail": "blubb"},
            False,
        ),
        (
            {404: {"content": {"application/json": {"examples": {"1": {"value": {"detail": "Not Found"}}}}}}},
            404,
            {"detail": "Not Found"},
            True,
        ),
    ],
)
async def test___check_response_schema(
    responses: Any, status_code: int, body: Any, ok: bool, mocker: MockerFixture
) -> None:
    logger = mocker.patch("api.app.logger")

    _check_response_schema("GET", MagicMock(responses=responses), status_code, json.dumps(body).encode())

    if ok:
        logger.error.assert_not_called()
    else:
        logger.error.assert_called_once()


@pytest.mark.parametrize("json,has_route", [(False, True), (True, False), (True, True)])
async def test__check_responses(json: bool, has_route: bool, mocker: MockerFixture) -> None:
    route = MagicMock() if has_route else None
    request = MagicMock(scope={"route": route})
    response = MagicMock(headers={"Content-type": "application/json" if json else MagicMock()})
    call_next = AsyncMock(return_value=response)
    check_response_schema = mocker.patch("api.app._check_response_schema")
    streaming_response = mocker.patch("api.app.StreamingResponse")

    async def body_iterator() -> AsyncIterator[bytes]:
        yield b"foo"
        yield b"bar"
        yield b"12345"

    response.body_iterator = body_iterator()

    result = await check_responses(request, call_next)

    call_next.assert_called_once_with(request)
    if not json:
        assert result is response
        check_response_schema.assert_not_called()
        return

    streaming_response.assert_called_once_with(
        content=b"foobar12345",
        status_code=response.status_code,
        headers=response.headers,
        media_type=response.media_type,
    )
    assert result == streaming_response()

    if has_route:
        check_response_schema.assert_called_once_with(request.method, route, response.status_code, b"foobar12345")
    else:
        check_response_schema.assert_not_called()


async def test__rollback_on_exception(mocker: MockerFixture) -> None:
    fastapi_patch = mocker.patch("fastapi.FastAPI")
    db_patch = mocker.patch("api.database.db")
    db_patch.session.rollback = AsyncMock()
    http_exception_patch = mocker.patch("starlette.exceptions.HTTPException")
    http_exception_handler_patch = mocker.patch("fastapi.exception_handlers.http_exception_handler", AsyncMock())

    _, rollback_on_exception = get_decorated_function(fastapi_patch, "exception_handler", http_exception_patch)

    result = await rollback_on_exception(request := MagicMock(), exc := MagicMock())

    db_patch.session.rollback.assert_called_once_with()
    http_exception_handler_patch.assert_called_once_with(request, exc)
    assert result == await http_exception_handler_patch()


async def test__on_startup(mocker: MockerFixture, monkeypatch: MonkeyPatch) -> None:
    fastapi_patch = mocker.patch("fastapi.FastAPI")
    db_patch = mocker.patch("api.database.db")

    module, on_startup = get_decorated_function(fastapi_patch, "on_event", "startup")
    db_patch.create_tables = AsyncMock()
    monkeypatch.setattr(module, "setup_app", MagicMock())

    await on_startup()

    module.setup_app.assert_called_once_with()
    db_patch.create_tables.assert_called_once_with()


async def test__on_shutdown(mocker: MockerFixture) -> None:
    fastapi_patch = mocker.patch("fastapi.FastAPI")

    _, on_shutdown = get_decorated_function(fastapi_patch, "on_event", "shutdown")

    await on_shutdown()


async def test__status(client: AsyncClient) -> None:
    response = await client.head("/status")
    assert response.status_code == 200
