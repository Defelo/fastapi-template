import json
from typing import Any, AsyncIterator
from unittest.mock import AsyncMock, MagicMock

import pytest
from pydantic import create_model
from pytest_mock import MockerFixture

from api.utils.debug import _check_response_schema, check_responses


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
    logger = mocker.patch("api.utils.debug.logger")

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
    check_response_schema = mocker.patch("api.utils.debug._check_response_schema")
    streaming_response = mocker.patch("api.utils.debug.StreamingResponse")

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
